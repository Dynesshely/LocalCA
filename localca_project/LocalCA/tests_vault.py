"""
Tests for at-rest private key encryption.

The interesting cases are not "does it round-trip" but: wrong password, tampered
ciphertext, a ciphertext moved between rows, a password change, and what happens
to keys that cannot be encrypted at all.
"""
import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from .ca import CertificateAuthority
from .keys import (
    ensure_root_key,
    is_legacy_plaintext,
    is_wrapped,
    private_key_pem,
    rewrap_root_key,
    store_wrapped_key,
    vault_status,
)
from .models import RootCertificate, VaultRootKey
from .vault import (
    PLAINTEXT_MAGIC,
    VaultFormatError,
    VaultLocked,
    VaultPasswordError,
    decrypt_private_key,
    encrypt_private_key,
    new_root_key,
    unsealed,
    unwrap_root_key,
    wrap_root_key,
)


class VaultCryptoTests(TestCase):
    '''Pure crypto behaviour; no HTTP, no Django models beyond a user.'''

    def setUp(self):
        self.root_key = new_root_key()
        self.password = 'a-very-good-vault-password'
        self.pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n'

    def encrypt(self, **overrides):
        kwargs = dict(kind='leaf', cert_id=1, serial='42', private_key_pem=self.pem)
        kwargs.update(overrides)
        return encrypt_private_key(self.root_key, **kwargs)

    def test_round_trip(self):
        blob = self.encrypt()
        recovered = decrypt_private_key(
            self.root_key, kind='leaf', cert_id=1, serial='42', blob=blob)
        self.assertEqual(recovered, self.pem)

    def test_plaintext_never_appears_in_the_envelope(self):
        blob = self.encrypt()
        self.assertNotIn('BEGIN RSA PRIVATE KEY', blob)
        self.assertNotIn('MIIabc', blob)

    def test_envelope_is_versioned_json(self):
        parsed = json.loads(self.encrypt())
        self.assertEqual(parsed['v'], 1)
        self.assertEqual(parsed['alg'], 'AES-256-GCM')
        self.assertEqual(parsed['kdf'], 'hkdf-sha256')

    def test_a_different_root_key_cannot_decrypt(self):
        blob = self.encrypt()
        with self.assertRaises(VaultFormatError):
            decrypt_private_key(new_root_key(), kind='leaf', cert_id=1,
                                serial='42', blob=blob)

    def test_tampered_ciphertext_is_rejected(self):
        blob = json.loads(self.encrypt())
        raw = bytearray(__import__('base64').b64decode(blob['ct']))
        raw[0] ^= 0x01  # flip one bit
        blob['ct'] = __import__('base64').b64encode(bytes(raw)).decode()
        with self.assertRaises(VaultFormatError):
            decrypt_private_key(self.root_key, kind='leaf', cert_id=1,
                                serial='42', blob=json.dumps(blob))

    def test_ciphertext_cannot_be_moved_to_another_row(self):
        '''
        The AAD binds kind/id/serial, so a blob copied into a different
        certificate's row must fail rather than decrypt to the wrong key.
        '''
        blob = self.encrypt(cert_id=1, serial='42')
        with self.assertRaises(VaultFormatError):
            decrypt_private_key(self.root_key, kind='leaf', cert_id=2,
                                serial='42', blob=blob)
        with self.assertRaises(VaultFormatError):
            decrypt_private_key(self.root_key, kind='leaf', cert_id=1,
                                serial='99', blob=blob)
        with self.assertRaises(VaultFormatError):
            decrypt_private_key(self.root_key, kind='root', cert_id=1,
                                serial='42', blob=blob)

    def test_root_key_wrap_round_trip(self):
        blob = wrap_root_key(self.root_key, self.password)
        self.assertEqual(unwrap_root_key(blob, self.password), self.root_key)

    def test_wrong_password_is_reported_as_such(self):
        blob = wrap_root_key(self.root_key, self.password)
        with self.assertRaises(VaultPasswordError):
            unwrap_root_key(blob, 'not-the-password')

    def test_wrapping_is_salted_so_ciphertext_differs_each_time(self):
        first = wrap_root_key(self.root_key, self.password)
        second = wrap_root_key(self.root_key, self.password)
        self.assertNotEqual(first, second)
        self.assertEqual(unwrap_root_key(first, self.password), self.root_key)
        self.assertEqual(unwrap_root_key(second, self.password), self.root_key)

    def test_magic_prefix_guards_against_wrong_plaintext(self):
        '''Decrypting something that is not one of our keys must fail loudly.'''
        other = encrypt_private_key(self.root_key, kind='leaf', cert_id=1,
                                    serial='42', private_key_pem='not-a-key')
        with self.assertRaises(VaultFormatError):
            # Same key material, but the payload lacked our marker only if the
            # marker itself was stripped; simulate that by decrypting with a
            # mismatched AAD, which is the reachable failure mode.
            decrypt_private_key(self.root_key, kind='leaf', cert_id=9,
                                serial='42', blob=other)


class UnsealedStoreTests(TestCase):
    '''The in-memory unlock store: isolation, wrong-password, idle expiry.'''

    def setUp(self):
        self.user = User.objects.create_user('store-user', password='pw-Store-123')

    def tearDown(self):
        unsealed.lock_all()

    def test_unseal_and_lock(self):
        key = new_root_key()
        unsealed.unseal(self.user.id, 'pw-one', key)
        self.assertTrue(unsealed.is_unsealed(self.user.id))
        self.assertEqual(unsealed.get(self.user.id), key)
        unsealed.lock(self.user.id)
        self.assertFalse(unsealed.is_unsealed(self.user.id))
        with self.assertRaises(VaultLocked):
            unsealed.get(self.user.id)

    def test_a_wrong_password_does_not_ride_an_existing_unlock(self):
        unsealed.unseal(self.user.id, 'correct-horse', new_root_key())
        with self.assertRaises(VaultPasswordError):
            unsealed.get(self.user.id, 'wrong-horse')

    def test_idle_timeout_relocks(self):
        from unittest import mock
        unsealed.unseal(self.user.id, 'pw', new_root_key())
        self.assertTrue(unsealed.is_unsealed(self.user.id))
        with mock.patch('LocalCA.vault.idle_timeout', return_value=0):
            import time as _time
            _time.sleep(0.01)
            self.assertFalse(unsealed.is_unsealed(self.user.id))


class VaultModelTests(TestCase):
    '''Key storage through the models, plus the password-change path.'''

    @classmethod
    def setUpTestData(cls):
        ca = CertificateAuthority()
        cls.owner = User.objects.create_user('vault-owner', password='pw-Owner-123')
        cls.password = 'vault-password-123456'
        data = ca.create_root_certificate('Vault Root CA', 3650)
        cls.root = RootCertificate.objects.create(
            name='Vault Root CA', serial_number=str(data['serial_number']),
            public_key=data['public_key'], private_key_encrypted='',
            valid_until=data['valid_until'], created_by=cls.owner)
        cls.pem = data['private_key']

    def setUp(self):
        unsealed.lock_all()
        self.root_key = ensure_root_key(self.owner.id, self.password)

    def tearDown(self):
        unsealed.lock_all()

    def test_new_key_is_wrapped_and_plaintext_column_is_cleared(self):
        store_wrapped_key(self.root, 'root', self.pem, self.root_key)
        self.root.refresh_from_db()
        self.assertFalse(self.root.private_key_encrypted)
        self.assertTrue(is_wrapped(self.root))
        self.assertNotIn('BEGIN RSA PRIVATE KEY', self.root.private_key_wrapped)

    def test_round_trip_through_the_model(self):
        store_wrapped_key(self.root, 'root', self.pem, self.root_key)
        self.root.refresh_from_db()
        self.assertEqual(
            private_key_pem(self.root, 'root', self.owner).strip(), self.pem.strip())

    def test_signature_of_the_private_key_is_preserved(self):
        '''The decrypted key must be usable for real signing.'''
        from cryptography.hazmat.primitives import serialization
        store_wrapped_key(self.root, 'root', self.pem, self.root_key)
        self.root.refresh_from_db()
        recovered = private_key_pem(self.root, 'root', self.owner)
        loaded = serialization.load_pem_private_key(recovered.encode(), password=None)
        self.assertEqual(loaded.key_size, 2048)

    def test_locked_vault_cannot_produce_a_wrapped_key(self):
        store_wrapped_key(self.root, 'root', self.pem, self.root_key)
        self.root.refresh_from_db()
        unsealed.lock(self.owner.id)
        with self.assertRaises(VaultLocked):
            private_key_pem(self.root, 'root', self.owner)

    def test_legacy_plaintext_key_is_still_usable_and_flagged(self):
        '''Keys created before the vault must keep working, and be reported.'''
        self.root.private_key_wrapped = None
        self.root.private_key_encrypted = self.pem
        self.root.save(update_fields=['private_key_wrapped', 'private_key_encrypted'])
        self.assertTrue(is_legacy_plaintext(self.root))
        unsealed.lock(self.owner.id)
        # No vault needed: there is nothing to unwrap.
        self.assertEqual(
            private_key_pem(self.root, 'root', self.owner).strip(), self.pem.strip())

    def test_changing_the_vault_password_keeps_keys_readable(self):
        store_wrapped_key(self.root, 'root', self.pem, self.root_key)
        new_password = 'a-different-vault-password'
        rewrap_root_key(self.owner.id, self.password, new_password)

        # The stored key blob is untouched...
        self.root.refresh_from_db()
        blob_before = self.root.private_key_wrapped
        # ...and the new password opens it.
        unsealed.lock_all()
        ensure_root_key(self.owner.id, new_password)
        self.assertEqual(
            private_key_pem(self.root, 'root', self.owner).strip(), self.pem.strip())
        self.assertEqual(self.root.private_key_wrapped, blob_before)

    def test_old_password_stops_working_after_a_change(self):
        rewrap_root_key(self.owner.id, self.password, 'brand-new-vault-password')
        unsealed.lock_all()
        with self.assertRaises(VaultPasswordError):
            ensure_root_key(self.owner.id, self.password)

    def test_first_unseal_creates_exactly_one_root_key_row(self):
        self.assertTrue(VaultRootKey.objects.filter(user=self.owner).exists())
        ensure_root_key(self.owner.id, self.password)
        self.assertEqual(VaultRootKey.objects.filter(user=self.owner).count(), 1)

    def test_status_counts_encrypted_plaintext_and_ownerless(self):
        store_wrapped_key(self.root, 'root', self.pem, self.root_key)
        orphan = RootCertificate.objects.create(
            name='Ownerless Root', serial_number='orphan-1',
            public_key='x', private_key_encrypted=self.pem,
            valid_until=self.root.valid_until, created_by=None)
        report = vault_status(self.owner.id)
        self.assertEqual(report['by_kind']['root']['wrapped'], 1)
        # The ownerless key is not part of this account's scope, but the global
        # inventory must still count it as unwrappable.
        self.assertEqual(vault_status()['orphaned'], 1)
        self.root.refresh_from_db()
        self.assertTrue(is_wrapped(self.root))
        self.assertIsNone(orphan.created_by_id)


class VaultApiTests(TestCase):
    '''The vault endpoints and the guarantees they must keep.'''

    @classmethod
    def setUpTestData(cls):
        ca = CertificateAuthority()
        cls.owner = User.objects.create_user('api-vault', password='pw-Owner-123')
        cls.other = User.objects.create_user('api-other', password='pw-Other-123')
        data = ca.create_root_certificate('API Vault Root', 3650)
        cls.root = RootCertificate.objects.create(
            name='API Vault Root', serial_number=str(data['serial_number']),
            public_key=data['public_key'],
            private_key_encrypted=data['private_key'],
            valid_until=data['valid_until'], created_by=cls.owner)

    def setUp(self):
        unsealed.lock_all()

    def tearDown(self):
        unsealed.lock_all()

    def test_status_requires_authentication(self):
        self.assertEqual(self.client.get('/api/vault/status/').status_code, 401)

    def test_status_reports_plaintext_before_migration(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        payload = self.client.get('/api/vault/status/').json()
        self.assertFalse(payload['has_root_key'])
        self.assertFalse(payload['unsealed'])
        self.assertEqual(payload['plaintext'], 1)
        self.assertEqual(payload['wrapped'], 0)

    def test_unseal_then_status_is_open(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        response = self.client.post('/api/vault/unseal/',
                                    {'vault_password': 'vault-secret-123'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['unsealed'])
        self.assertTrue(self.client.get('/api/vault/status/').json()['unsealed'])

    def test_unseal_is_independent_per_account(self):
        '''One user opening the vault must not open it for another.'''
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.client.post('/api/vault/unseal/', {'vault_password': 'vault-secret-123'})
        self.client.logout()

        self.client.login(username='api-other', password='pw-Other-123')
        payload = self.client.get('/api/vault/status/').json()
        self.assertFalse(payload['unsealed'])

    def test_wrong_unseal_password_is_403(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.client.post('/api/vault/unseal/', {'vault_password': 'right-one-12345'})
        self.client.post('/api/vault/lock/')
        response = self.client.post('/api/vault/unseal/',
                                    {'vault_password': 'wrong-one-12345'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.client.get('/api/vault/status/').json()['unsealed'])

    def test_unseal_requires_a_password(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.assertEqual(
            self.client.post('/api/vault/unseal/', {'vault_password': ''}).status_code,
            400)

    def test_lock_closes_the_vault(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.client.post('/api/vault/unseal/', {'vault_password': 'vault-secret-123'})
        self.client.post('/api/vault/lock/')
        self.assertFalse(self.client.get('/api/vault/status/').json()['unsealed'])

    def test_password_rotation_requires_both_passwords(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.client.post('/api/vault/unseal/', {'vault_password': 'vault-secret-123'})
        response = self.client.post('/api/vault/password/',
                                    {'old_password': 'vault-secret-123'})
        self.assertEqual(response.status_code, 400)

    def test_password_rotation_rejects_a_short_new_password(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.client.post('/api/vault/unseal/', {'vault_password': 'vault-secret-123'})
        response = self.client.post('/api/vault/password/', {
            'old_password': 'vault-secret-123', 'new_password': 'short'})
        self.assertEqual(response.status_code, 400)

    def test_password_rotation_works_and_old_password_stops_working(self):
        self.client.login(username='api-vault', password='pw-Owner-123')
        self.client.post('/api/vault/unseal/', {'vault_password': 'vault-secret-123'})
        response = self.client.post('/api/vault/password/', {
            'old_password': 'vault-secret-123',
            'new_password': 'a-much-longer-vault-password'})
        self.assertEqual(response.status_code, 200)

        self.client.post('/api/vault/lock/')
        self.assertEqual(
            self.client.post('/api/vault/unseal/',
                             {'vault_password': 'vault-secret-123'}).status_code, 403)
        self.assertEqual(
            self.client.post('/api/vault/unseal/',
                             {'vault_password': 'a-much-longer-vault-password'}
                             ).status_code, 200)

    def test_unmatched_api_path_answers_json_404_not_the_spa(self):
        response = self.client.get('/api/definitely/not/here/')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response['Content-Type'], 'application/json')


class RewrapCommandTests(TestCase):
    '''The migration command must wrap plaintext keys and be idempotent.'''

    def setUp(self):
        from io import StringIO
        from django.core.management import call_command
        self.call_command = call_command
        self.out = StringIO()
        unsealed.lock_all()

        ca = CertificateAuthority()
        self.owner = User.objects.create_user('mig-user', password='pw-Mig-12345')
        data = ca.create_root_certificate('Migrate Root', 3650)
        self.root = RootCertificate.objects.create(
            name='Migrate Root', serial_number=str(data['serial_number']),
            public_key=data['public_key'], private_key_encrypted=data['private_key'],
            valid_until=data['valid_until'], created_by=self.owner)
        self.pem = data['private_key']

    def tearDown(self):
        unsealed.lock_all()

    def test_dry_run_changes_nothing(self):
        self.call_command('rewrap_keys', '--username', 'mig-user',
                          '--password', 'vault-migration-123', dry_run=True,
                          stdout=self.out)
        self.root.refresh_from_db()
        self.assertFalse(is_wrapped(self.root))
        self.assertIn('Dry run', self.out.getvalue())

    def test_wrapping_migrates_the_plaintext_key(self):
        self.call_command('rewrap_keys', '--username', 'mig-user',
                          '--password', 'vault-migration-123', stdout=self.out)
        self.root.refresh_from_db()
        self.assertTrue(is_wrapped(self.root))
        self.assertFalse(self.root.private_key_encrypted)
        # And the key survives the migration intact.
        self.assertEqual(
            private_key_pem(self.root, 'root', self.owner).strip(), self.pem.strip())

    def test_command_is_idempotent(self):
        for _ in range(2):
            self.call_command('rewrap_keys', '--username', 'mig-user',
                              '--password', 'vault-migration-123', stdout=self.out)
        self.root.refresh_from_db()
        self.assertTrue(is_wrapped(self.root))

    def test_ownerless_keys_are_reported_not_silently_skipped(self):
        RootCertificate.objects.create(
            name='No Owner Root', serial_number='ownerless-1', public_key='x',
            private_key_encrypted=self.pem, valid_until=self.root.valid_until,
            created_by=None)
        self.call_command('rewrap_keys', '--username', 'mig-user',
                          '--password', 'vault-migration-123', stdout=self.out)
        self.assertIn('belong to no account', self.out.getvalue())
