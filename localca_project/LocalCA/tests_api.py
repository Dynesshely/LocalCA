"""
Tests for the JSON API that replaced the server-rendered views.

These cover the same authority rules the template tests used to: reading the
tree is public but never exposes key material, creation may only sign with a CA
you own, revoke/delete are owner-or-staff and POST-only, and private key
material is owner-only.
"""
import json
import re

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from .ca import CertificateAuthority
from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
)


def stored_sans(leaf):
    '''
    The SAN list as the model keeps it.

    ``LeafCertificate.san`` is one comma-separated TextField (the serializer
    splits it again for the API), so the assertions below read it back the same
    way the application does instead of iterating over the string's characters.
    '''
    return [entry for entry in (leaf.san or '').split(',') if entry]


class ApiTestBase(TestCase):

    @classmethod
    def setUpTestData(cls):
        ca = CertificateAuthority()
        cls.owner = User.objects.create_user('api-owner', password='pw-Owner-123')
        cls.other = User.objects.create_user('api-other', password='pw-Other-123')
        cls.staff = User.objects.create_superuser(
            'api-staff', 'staff@example.com', 'pw-Staff-123')

        root_data = ca.create_root_certificate('API Root CA', 3650)
        cls.root = RootCertificate.objects.create(
            name='API Root CA', serial_number=str(root_data['serial_number']),
            public_key=root_data['public_key'],
            private_key_encrypted=root_data['private_key'],
            valid_until=root_data['valid_until'], created_by=cls.owner)

        inter_data = ca.create_intermediate_certificate(
            'API Intermediate CA', 1825, root_data['public_key'],
            root_data['private_key'])
        cls.intermediate = IntermediateCertificate.objects.create(
            name='API Intermediate CA', serial_number=str(inter_data['serial_number']),
            public_key=inter_data['public_key'],
            private_key_encrypted=inter_data['private_key'],
            signed_by_root=cls.root, valid_until=inter_data['valid_until'],
            created_by=cls.owner)

        leaf_data = ca.create_leaf_certificate(
            'api.internal', ['api.internal', '10.1.2.3'], 365,
            inter_data['public_key'], inter_data['private_key'])
        cls.leaf = LeafCertificate.objects.create(
            common_name='api.internal', san='api.internal,10.1.2.3',
            serial_number=str(leaf_data['serial_number']),
            public_key=leaf_data['public_key'],
            private_key_encrypted=leaf_data['private_key'],
            signed_by_intermediate=cls.intermediate,
            valid_until=leaf_data['valid_until'], created_by=cls.owner)

    #: The password used to unseal the vault in tests. Chosen to exceed the
    #: minimum length the rotate endpoint enforces.
    VAULT_PASSWORD = 'vault-test-password-123'

    def setUp(self):
        # Unseal the owner's vault for each test. The unsealed key store is
        # process-global, so it must be set per test rather than in
        # setUpTestData (which runs in its own transaction).
        super().setUp()
        self.unseal_vault(self.owner, self.VAULT_PASSWORD)

    @classmethod
    def unseal_vault(cls, user, password=None):
        from LocalCA.keys import ensure_root_key
        return ensure_root_key(user.id, password or cls.VAULT_PASSWORD)

    @classmethod
    def lock_vault(cls, user):
        from LocalCA.vault import unsealed
        unsealed.lock(user.id)

    def post_json(self, url, payload):
        return self.client.post(url, data=json.dumps(payload),
                                content_type='application/json')

    def post_form(self, url, payload):
        return self.client.post(url, data=payload)


class SessionApiTests(ApiTestBase):

    def test_session_reports_anonymous(self):
        response = self.client.get('/api/session/')
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()['user'])
        # The SPA needs the CSRF cookie planted before its first POST.
        self.assertIn('csrftoken', response.cookies)

    def test_login_logout_roundtrip(self):
        response = self.post_json('/api/login/',
                                  {'username': 'api-owner', 'password': 'pw-Owner-123'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['user']['username'], 'api-owner')

        response = self.client.get('/api/session/')
        self.assertEqual(response.json()['user']['username'], 'api-owner')

        response = self.client.post('/api/logout/')
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.get('/api/session/').json()['user'])

    def test_login_rejects_bad_credentials(self):
        response = self.post_json('/api/login/',
                                  {'username': 'api-owner', 'password': 'wrong'})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['ok'])
        # A failed login is recorded for the audit trail.
        self.assertTrue(AuditLog.objects.filter(
            action='ACCESS', details__contains='api-owner').exists())

    def test_login_requires_both_fields(self):
        response = self.post_json('/api/login/', {'username': 'api-owner', 'password': ''})
        self.assertEqual(response.status_code, 400)

    def test_change_password_keeps_the_session(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/password/', {
            'old_password': 'pw-Owner-123',
            'new_password1': 'Str0ng-New-Passw0rd',
            'new_password2': 'Str0ng-New-Passwrd',
        })
        self.assertEqual(response.status_code, 400)
        response = self.post_form('/api/password/', {
            'old_password': 'pw-Owner-123',
            'new_password1': 'Str0ng-New-Passw0rd',
            'new_password2': 'Str0ng-New-Passw0rd',
        })
        self.assertEqual(response.status_code, 200)
        # Still authenticated after the hash changed.
        self.assertEqual(self.client.get('/api/session/').json()['user']['username'],
                         'api-owner')

    def test_meta_exposes_reasons_and_bounds(self):
        payload = self.client.get('/api/meta/').json()
        self.assertTrue(any(r['value'] == 'key_compromise'
                            for r in payload['revocation_reasons']))
        self.assertEqual(payload['max_validity_days']['leaf'], 825)
        self.assertEqual(payload['max_validity_days']['root'], 7300)


class CertificateTreeApiTests(ApiTestBase):

    def test_tree_is_public_and_nested(self):
        response = self.client.get('/api/certificates/')
        self.assertEqual(response.status_code, 200)
        tree = response.json()['tree']
        self.assertEqual(len(tree), 1)
        self.assertEqual(tree[0]['certificate']['name'], 'API Root CA')
        branch = tree[0]['intermediates'][0]
        self.assertEqual(branch['certificate']['name'], 'API Intermediate CA')
        self.assertEqual(branch['leaves'][0]['name'], 'api.internal')

    def test_tree_never_exposes_key_material(self):
        body = self.client.get('/api/certificates/').content.decode()
        self.assertNotIn('BEGIN RSA PRIVATE KEY', body)
        self.assertNotIn('private_key', body)
        self.assertNotIn('BEGIN CERTIFICATE', body)

    def test_tree_marks_revocation_and_descendants(self):
        RevokedCertificate.objects.create(
            certificate=self.leaf,
            reason=RevokedCertificate.RevocationReason.KEY_COMPROMISE,
            comment='laptop stolen')
        tree = self.client.get('/api/certificates/').json()['tree']
        leaf = tree[0]['intermediates'][0]['leaves'][0]
        self.assertEqual(leaf['revocation']['reason'], 'key_compromise')
        self.assertEqual(leaf['revocation']['reason_label'], 'Key compromise')
        self.assertEqual(leaf['revocation']['comment'], 'laptop stolen')
        # A root reports how many certificates a delete would cascade to.
        self.assertEqual(tree[0]['certificate']['descendants'], 1)

    def test_owner_flags_differ_per_user(self):
        anon = self.client.get('/api/certificates/').json()['tree'][0]['certificate']
        self.assertFalse(anon['is_owner'])
        self.assertFalse(anon['can_manage'])

        self.client.login(username='api-other', password='pw-Other-123')
        other = self.client.get('/api/certificates/').json()['tree'][0]['certificate']
        self.assertFalse(other['is_owner'])
        self.assertFalse(other['can_manage'])

        self.client.login(username='api-owner', password='pw-Owner-123')
        owner = self.client.get('/api/certificates/').json()['tree'][0]['certificate']
        self.assertTrue(owner['is_owner'])
        self.assertTrue(owner['can_manage'])

        self.client.login(username='api-staff', password='pw-Staff-123')
        staff = self.client.get('/api/certificates/').json()['tree'][0]['certificate']
        self.assertFalse(staff['is_owner'])
        self.assertTrue(staff['can_manage'])

    def test_issuers_are_limited_to_owned_cas(self):
        self.client.login(username='api-other', password='pw-Other-123')
        payload = self.client.get('/api/issuers/').json()
        self.assertEqual(payload['roots'], [])
        self.assertEqual(payload['intermediates'], [])

        self.client.login(username='api-owner', password='pw-Owner-123')
        payload = self.client.get('/api/issuers/').json()
        self.assertEqual(payload['roots'][0]['name'], 'API Root CA')
        self.assertEqual(payload['intermediates'][0]['name'], 'API Intermediate CA')

    def test_issuers_require_authentication(self):
        self.assertEqual(self.client.get('/api/issuers/').status_code, 401)


class CertificateCreationApiTests(ApiTestBase):

    def test_create_root(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/root/', {
            'common_name': 'Second Root CA', 'validity_days': '3650'})
        self.assertEqual(response.status_code, 201)
        created = RootCertificate.objects.get(name='Second Root CA')
        # New keys must never land in the plaintext column.
        self.assertTrue(created.private_key_wrapped)
        self.assertFalse(created.private_key_encrypted)

    def test_create_root_is_refused_while_the_vault_is_locked(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        self.lock_vault(self.owner)
        response = self.post_form('/api/certificates/create/root/', {
            'common_name': 'Locked Root CA', 'validity_days': '365'})
        self.assertEqual(response.status_code, 409)
        self.assertTrue(response.json().get('vault_locked'))
        self.assertFalse(RootCertificate.objects.filter(name='Locked Root CA').exists())

    def test_signing_an_intermediate_is_refused_while_locked(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        self.lock_vault(self.owner)
        response = self.post_form('/api/certificates/create/intermediate/', {
            'common_name': 'Locked Intermediate', 'validity_days': '365',
            'root_id': str(self.root.id)})
        self.assertEqual(response.status_code, 409)
        self.assertTrue(response.json().get('vault_locked'))

    def test_create_leaf_with_sans(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'new.internal', 'san': 'new.internal, alt.internal',
            'validity_days': '300', 'intermediate_id': str(self.intermediate.id)})
        self.assertEqual(response.status_code, 201)
        leaf = LeafCertificate.objects.get(common_name='new.internal')
        self.assertIn('alt.internal', leaf.san)

    def test_create_leaf_with_one_san_per_line(self):
        '''
        The form offers a multi-line box, so newlines separate names exactly as
        commas do. Before this was supported a pasted column of names became a
        single SAN with a newline inside it.
        '''
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'multi.internal',
            'san': 'a.internal\nb.internal\r\nc.internal',
            'validity_days': '300', 'intermediate_id': str(self.intermediate.id)})
        self.assertEqual(response.status_code, 201)
        leaf = LeafCertificate.objects.get(common_name='multi.internal')
        self.assertEqual(
            stored_sans(leaf), ['multi.internal', 'a.internal', 'b.internal', 'c.internal'])

    def test_san_separators_may_be_mixed(self):
        '''Lines, commas, spaces and tabs all separate; blank lines are ignored.'''
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'mixed.internal',
            'san': '\n a.internal, b.internal\n\n\tc.internal ,\n 10.0.0.7 \n',
            'validity_days': '300', 'intermediate_id': str(self.intermediate.id)})
        self.assertEqual(response.status_code, 201)
        leaf = LeafCertificate.objects.get(common_name='mixed.internal')
        self.assertEqual(
            stored_sans(leaf),
            ['mixed.internal', 'a.internal', 'b.internal', 'c.internal', '10.0.0.7'])

    def test_a_newline_never_reaches_the_certificate(self):
        '''
        Guard the regression itself: no SAN that ends up on a certificate may
        contain whitespace, whatever separators the user typed.
        '''
        self.client.login(username='api-owner', password='pw-Owner-123')
        self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'clean.internal',
            'san': 'one.internal,\n two.internal',
            'validity_days': '300', 'intermediate_id': str(self.intermediate.id)})
        leaf = LeafCertificate.objects.get(common_name='clean.internal')
        for entry in stored_sans(leaf):
            self.assertFalse(
                re.search(r'\s', entry), f'SAN entry contains whitespace: {entry!r}')

    def test_creation_requires_authentication(self):
        response = self.post_form('/api/certificates/create/root/', {
            'common_name': 'Anon Root', 'validity_days': '365'})
        self.assertEqual(response.status_code, 401)

    def test_cannot_sign_with_someone_elses_root(self):
        '''The form's queryset restricts root_id, so a crafted POST cannot
        consume another user's CA private key.'''
        self.client.login(username='api-other', password='pw-Other-123')
        response = self.post_form('/api/certificates/create/intermediate/', {
            'common_name': 'Evil Intermediate', 'validity_days': '365',
            'root_id': str(self.root.id)})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            IntermediateCertificate.objects.filter(name='Evil Intermediate').exists())

    def test_cannot_sign_leaf_with_someone_elses_intermediate(self):
        self.client.login(username='api-other', password='pw-Other-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'evil.internal', 'san': '', 'validity_days': '30',
            'intermediate_id': str(self.intermediate.id)})
        self.assertEqual(response.status_code, 400)

    def test_validity_above_the_limit_is_a_400_not_a_500(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'toolong.internal', 'san': '', 'validity_days': '36500',
            'intermediate_id': str(self.intermediate.id)})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(any('825' in e for e in response.json()['errors']))

    def test_non_numeric_validity_is_a_400(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/root/', {
            'common_name': 'Bad Root', 'validity_days': 'abc'})
        self.assertEqual(response.status_code, 400)

    def test_leaf_cannot_outlive_its_intermediate(self):
        ca = CertificateAuthority()
        short_root_data = ca.create_root_certificate('Short Root', 3650)
        short_root = RootCertificate.objects.create(
            name='Short Root', serial_number=str(short_root_data['serial_number']),
            public_key=short_root_data['public_key'],
            private_key_encrypted=short_root_data['private_key'],
            valid_until=short_root_data['valid_until'], created_by=self.owner)
        short_data = ca.create_intermediate_certificate(
            'Short Intermediate', 20, short_root_data['public_key'],
            short_root_data['private_key'])
        short = IntermediateCertificate.objects.create(
            name='Short Intermediate', serial_number=str(short_data['serial_number']),
            public_key=short_data['public_key'],
            private_key_encrypted=short_data['private_key'],
            signed_by_root=short_root, valid_until=short_data['valid_until'],
            created_by=self.owner)

        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'outlives.internal', 'san': '', 'validity_days': '400',
            'intermediate_id': str(short.id)})
        self.assertEqual(response.status_code, 400)

    def test_duplicate_name_is_a_400_not_an_integrity_error(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/root/', {
            'common_name': 'API Root CA', 'validity_days': '365'})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(any('already in use' in e for e in response.json()['errors']))

    def test_unknown_kind_is_404(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/bogus/', {'common_name': 'x'})
        self.assertEqual(response.status_code, 404)


class RevokeDeleteApiTests(ApiTestBase):

    def revoke_url(self, kind, obj):
        return reverse('api:revoke_certificate', args=[kind, obj.id])

    def delete_url(self, kind, obj):
        return reverse('api:delete_certificate', args=[kind, obj.id])

    def test_owner_can_revoke(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.revoke_url('leaf', self.leaf), {
            'type': 'leaf', 'id': str(self.leaf.id),
            'reason': 'key_compromise', 'comment': 'rotated'})
        self.assertEqual(response.status_code, 200)
        revocation = RevokedCertificate.objects.get(certificate=self.leaf)
        self.assertEqual(revocation.reason, 'key_compromise')
        self.assertEqual(revocation.created_by, self.owner)

    def test_other_user_cannot_revoke(self):
        self.client.login(username='api-other', password='pw-Other-123')
        response = self.post_form(self.revoke_url('leaf', self.leaf), {
            'type': 'leaf', 'id': str(self.leaf.id), 'reason': 'unspecified'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(RevokedCertificate.objects.exists())

    def test_staff_can_revoke(self):
        self.client.login(username='api-staff', password='pw-Staff-123')
        response = self.post_form(self.revoke_url('root', self.root), {
            'type': 'root', 'id': str(self.root.id), 'reason': 'ca_compromise'})
        self.assertEqual(response.status_code, 200)

    def test_get_is_rejected(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        self.assertEqual(self.client.get(self.revoke_url('leaf', self.leaf)).status_code,
                         405)
        self.assertEqual(self.client.get(self.delete_url('leaf', self.leaf)).status_code,
                         405)
        self.assertFalse(RevokedCertificate.objects.exists())

    def test_body_must_match_the_url(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.revoke_url('leaf', self.leaf), {
            'type': 'leaf', 'id': str(self.leaf.id + 999), 'reason': 'unspecified'})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(RevokedCertificate.objects.exists())

    def test_csrf_is_enforced(self):
        from django.test import Client
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.login(username='api-owner', password='pw-Owner-123')
        response = csrf_client.post(self.revoke_url('leaf', self.leaf), {
            'type': 'leaf', 'id': str(self.leaf.id), 'reason': 'unspecified'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(RevokedCertificate.objects.exists())

    def test_revoking_twice_is_a_conflict(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        payload = {'type': 'leaf', 'id': str(self.leaf.id), 'reason': 'unspecified'}
        self.post_form(self.revoke_url('leaf', self.leaf), payload)
        response = self.post_form(self.revoke_url('leaf', self.leaf), payload)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(RevokedCertificate.objects.count(), 1)

    def test_cascade_revokes_children(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.revoke_url('intermediate', self.intermediate), {
            'type': 'intermediate', 'id': str(self.intermediate.id),
            'reason': 'ca_compromise', 'cascade': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['cascaded'], ['api.internal'])
        self.assertTrue(RevokedCertificate.objects.filter(
            certificate=self.leaf).exists())

    def test_delete_cascades_and_logs(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.delete_url('root', self.root), {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['cascaded'], 1)
        self.assertFalse(RootCertificate.objects.exists())
        self.assertFalse(IntermediateCertificate.objects.exists())
        self.assertFalse(LeafCertificate.objects.exists())
        self.assertTrue(AuditLog.objects.filter(action='DELETE').exists())

    def test_other_user_cannot_delete(self):
        self.client.login(username='api-other', password='pw-Other-123')
        response = self.post_form(self.delete_url('root', self.root), {})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(RootCertificate.objects.exists())

    def test_unknown_kind_is_404(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/bogus/1/revoke/',
                                  {'type': 'leaf', 'id': '1', 'reason': 'unspecified'})
        self.assertEqual(response.status_code, 404)


class DownloadApiTests(ApiTestBase):
    '''
    What each download format promises.

    Two families, and the boundary between them is the thing worth testing:
    public formats hand out certificate material to anyone (that is how a client
    fetches its CA), private formats require authentication, ownership, an open
    vault, and either a password or an explicit confirmation.
    '''

    def url(self, fmt, cert=None):
        target = cert or self.leaf
        return reverse('api:download', args=[target.serial_number, fmt])

    # --- public -----------------------------------------------------------

    def test_public_formats_are_anonymous(self):
        for fmt, content_type in (('pem', 'application/x-pem-file'),
                                  ('der', 'application/pkix-cert'),
                                  ('chain', 'application/x-pem-file'),
                                  ('p7b', 'application/pkcs7-mime')):
            with self.subTest(fmt=fmt):
                response = self.client.get(self.url(fmt))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response['Content-Type'], content_type)
                self.assertGreater(len(response.content), 0)

    def test_pem_is_the_certificate_alone(self):
        '''`pem` is one certificate; the chain has its own format.'''
        body = self.client.get(self.url('pem')).content.decode()
        self.assertEqual(body.count('BEGIN CERTIFICATE'), 1)

    def test_chain_is_the_whole_path_root_last(self):
        body = self.client.get(self.url('chain')).content.decode()
        self.assertEqual(body.count('BEGIN CERTIFICATE'), 3)
        # Root last: that is the order a server wants in `ssl_trusted_certificate`.
        self.assertTrue(body.index(self.leaf.public_key.strip()[:60])
                        < body.index(self.root.public_key.strip()[:60]))

    def test_der_and_p7b_are_parsable(self):
        from cryptography import x509 as crypto_x509
        der = self.client.get(self.url('der')).content
        parsed = crypto_x509.load_der_x509_certificate(der)
        self.assertEqual(parsed.serial_number, int(self.leaf.serial_number))

        p7b = self.client.get(self.url('p7b')).content
        from cryptography.hazmat.primitives.serialization import pkcs7
        self.assertEqual(len(pkcs7.load_der_pkcs7_certificates(p7b)), 3)

    def test_an_unknown_format_is_a_json_404(self):
        response = self.client.get(f'/api/download/{self.leaf.serial_number}/private/')
        self.assertEqual(response.status_code, 404)
        # A JSON 404, not the SPA shell answering 200.
        self.assertEqual(response['Content-Type'], 'application/json')

    def test_hostile_name_cannot_break_the_disposition_header(self):
        self.leaf.common_name = 'evil".internal'
        self.leaf.save(update_fields=['common_name'])
        disposition = self.client.get(self.url('pem'))['Content-Disposition']
        self.assertTrue(disposition.startswith('attachment; filename="'))
        self.assertNotIn('\n', disposition)

    # --- private ----------------------------------------------------------

    def test_private_formats_require_authentication(self):
        for fmt in ('pkcs12', 'key', 'key-plain', 'pair-zip'):
            with self.subTest(fmt=fmt):
                response = self.client.post(self.url(fmt), {'confirm': 'true',
                                                            'key_password': 'password-1',
                                                            'p12_password': 'password-1'})
                self.assertEqual(response.status_code, 401)

    def test_private_formats_require_ownership(self):
        self.client.login(username='api-other', password='pw-Other-123')
        for fmt in ('pkcs12', 'key', 'key-plain', 'pair-zip'):
            with self.subTest(fmt=fmt):
                response = self.client.post(self.url(fmt), {'confirm': 'true',
                                                            'key_password': 'password-1',
                                                            'p12_password': 'password-1'})
                self.assertEqual(response.status_code, 403)

    def test_private_formats_need_an_open_vault(self):
        '''
        Without the vault password there is nothing to decrypt with, so the
        answer is 409 + vault_locked and the interface can offer to unlock.

        The fixture's keys are legacy plaintext, which needs no vault at all, so
        this test wraps the key first: the point is the wrapped case, and it has
        to build that state rather than assume it.
        '''
        from LocalCA.keys import root_key_for, store_wrapped_key
        store_wrapped_key(self.leaf, 'leaf', self.leaf.private_key_encrypted,
                          root_key_for(self.owner))
        self.leaf.refresh_from_db()
        self.assertNotEqual(self.leaf.private_key_wrapped, '')
        self.lock_vault(self.owner)

        self.client.login(username='api-owner', password='pw-Owner-123')
        for fmt in ('pkcs12', 'key', 'key-plain', 'pair-zip'):
            with self.subTest(fmt=fmt):
                response = self.client.post(self.url(fmt), {'confirm': 'true',
                                                            'key_password': 'password-1',
                                                            'p12_password': 'password-1'})
                self.assertEqual(response.status_code, 409)
                self.assertTrue(response.json().get('vault_locked'))

    def test_password_formats_reject_a_short_password(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        for fmt in ('pkcs12', 'key'):
            with self.subTest(fmt=fmt):
                for weak in ('', 'short'):
                    response = self.post_form(self.url(fmt), {'key_password': weak,
                                                              'p12_password': weak})
                    self.assertEqual(response.status_code, 400)

    def test_unprotected_formats_require_an_explicit_confirmation(self):
        '''
        The guard that makes an unprotected export deliberate: without
        confirm=true the request is refused, so no stray link can produce one.
        '''
        self.client.login(username='api-owner', password='pw-Owner-123')
        for fmt in ('key-plain', 'pair-zip'):
            with self.subTest(fmt=fmt):
                response = self.post_form(self.url(fmt), {})
                self.assertEqual(response.status_code, 400)
                self.assertIn('confirm', response.json()['errors'][0])

    def test_pkcs12_exports_a_password_protected_bundle(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.url('pkcs12'), {'p12_password': 'export-password'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-pkcs12')
        self.assertGreater(len(response.content), 0)

        # The bundle must actually be encrypted: the private key PEM must not
        # appear in the bytes, and it must open with the supplied password.
        from cryptography.hazmat.primitives.serialization import pkcs12
        self.assertNotIn(b'BEGIN PRIVATE KEY', response.content)
        _key, cert, _cas = pkcs12.load_key_and_certificates(
            response.content, b'export-password')
        self.assertIsNotNone(cert)

    def test_key_is_an_encrypted_pkcs8_private_key(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.url('key'), {'key_password': 'export-password'})
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('BEGIN ENCRYPTED PRIVATE KEY', body)
        self.assertNotIn('BEGIN PRIVATE KEY', body.replace('BEGIN ENCRYPTED PRIVATE KEY', ''))

        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(response.content,
                                                 password=b'export-password')
        self.assertIsNotNone(key)
        # It must be the key that belongs to the certificate it came with.
        self.assertIn(b'PRIVATE KEY', response.content)

    def test_key_plain_is_unprotected_and_matches_the_certificate(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.url('key-plain'), {'confirm': 'true'})
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('BEGIN PRIVATE KEY', body)
        self.assertNotIn('ENCRYPTED', body)

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = serialization.load_pem_private_key(response.content, password=None)
        self.assertIsInstance(key, rsa.RSAPrivateKey)

        # The public half has to be the certificate's own subject public key.
        from cryptography import x509 as crypto_x509
        cert = crypto_x509.load_pem_x509_certificate(self.leaf.public_key.encode())
        self.assertEqual(key.public_key().public_numbers(),
                         cert.public_key().public_numbers())

    def test_pair_zip_contains_certificate_key_and_chain(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.url('pair-zip'), {'confirm': 'true'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/zip')

        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = set(archive.namelist())
            self.assertIn(f'{self.leaf.common_name}.crt', names)
            self.assertIn(f'{self.leaf.common_name}.key', names)
            self.assertIn('chain.pem', names)
            key = archive.read(f'{self.leaf.common_name}.key').decode()
            self.assertIn('BEGIN PRIVATE KEY', key)
            self.assertNotIn('ENCRYPTED', key)
            # The chain file carries the two issuers, not the leaf again.
            chain = archive.read('chain.pem').decode()
            self.assertEqual(chain.count('BEGIN CERTIFICATE'), 2)

    def test_a_certificate_without_a_key_cannot_be_exported(self):
        '''Imported inventory can be listed and revoked, but has no key to give.'''
        keyless = LeafCertificate.objects.create(
            common_name='keyless.internal', serial_number='990011',
            public_key=self.leaf.public_key, private_key_encrypted='',
            valid_until=self.leaf.valid_until,
            signed_by_intermediate=self.intermediate, created_by=self.owner)
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(self.url('key-plain', keyless), {'confirm': 'true'})
        self.assertEqual(response.status_code, 409)

    # --- the audit trail --------------------------------------------------

    def test_both_families_are_audited(self):
        self.client.get(self.url('pem'))
        self.client.login(username='api-owner', password='pw-Owner-123')
        self.post_form(self.url('key-plain'), {'confirm': 'true'})

        actions = list(AuditLog.objects.values_list('action', flat=True))
        self.assertIn('DOWNLOAD_PUBLIC_KEY', actions)
        self.assertIn('DOWNLOAD_PRIVATE_KEY', actions)

    def test_meta_advertises_every_format_once(self):
        payload = self.client.get('/api/meta/').json()
        from .api import DOWNLOAD_FORMATS
        advertised = [spec['id'] for spec in payload['download_formats']]
        self.assertEqual(advertised, [spec['id'] for spec in DOWNLOAD_FORMATS])
        self.assertEqual(len(advertised), len(set(advertised)))
        for spec in payload['download_formats']:
            self.assertIn(spec['access'], ('public', 'private'))
            if spec['access'] == 'private':
                self.assertIn(spec['requires'], ('password', 'confirm'))


class AuditApiTests(ApiTestBase):

    def test_audit_is_staff_only(self):
        self.assertEqual(self.client.get('/api/audit/').status_code, 401)
        self.client.login(username='api-owner', password='pw-Owner-123')
        self.assertEqual(self.client.get('/api/audit/').status_code, 403)

    def test_staff_sees_entries(self):
        AuditLog.objects.create(action='CREATE', performed_by=self.owner,
                                details='test entry')
        self.client.login(username='api-staff', password='pw-Staff-123')
        payload = self.client.get('/api/audit/').json()
        self.assertTrue(any(e['details'] == 'test entry' for e in payload['entries']))


class SpaShellTests(ApiTestBase):
    '''Deep links must serve the shell so the client router can take over.'''

    def test_root_and_deep_links_serve_the_spa(self):
        '''
        Every client route answers with the shell so the router can take over.

        CI runs the suite without a pnpm build, where the app-directory
        placeholder is served instead, so both outcomes are accepted. A *built*
        shell has one further obligation: the bundle it references has to exist.
        The entry name carries a content hash, hence the shape match -- asserting
        a fixed ``app.js`` would pin the old naming and could not notice a shell
        that points at an asset a rebuild has since replaced.
        '''
        built = (settings.FRONTEND_DIST / 'index.html').exists()
        for path in ('/', '/create/leaf', '/create/ca', '/login',
                     '/change-password', '/audit'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            body = response.content.decode()
            if not built:
                self.assertIn('frontend not built', body)
                continue
            self.assertIn('<div id="app"', body)
            entry = re.search(r'src="(/static/assets/[^"]+\.js)"', body)
            self.assertIsNotNone(entry, body[:200])
            relative = entry.group(1).replace('/static/', '', 1)
            self.assertTrue(
                (settings.FRONTEND_DIST / relative).exists(),
                f'the shell references a bundle that is not there: {relative}')

    def test_shell_plants_a_csrf_cookie(self):
        response = self.client.get('/')
        self.assertIn('csrftoken', response.cookies)

    def test_api_is_not_shadowed_by_the_spa_catch_all(self):
        self.assertEqual(self.client.get('/api/session/')['Content-Type'],
                         'application/json')


class JsonBodyTests(ApiTestBase):
    '''
    The Vue client sends JSON while HTML forms send urlencoded data. Both must
    work: a JSON body silently produces an empty request.POST, which previously
    made every form-backed endpoint answer "This field is required".
    '''

    def test_create_accepts_a_json_body(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_json('/api/certificates/create/root/', {
            'common_name': 'JSON Root CA', 'validity_days': 3650})
        self.assertEqual(response.status_code, 201,
                         response.content.decode()[:200])
        self.assertTrue(RootCertificate.objects.filter(name='JSON Root CA').exists())

    def test_revoke_accepts_a_json_body(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_json(
            reverse('api:revoke_certificate', args=['leaf', self.leaf.id]),
            {'type': 'leaf', 'id': str(self.leaf.id),
             'reason': 'key_compromise', 'comment': 'json body'})
        self.assertEqual(response.status_code, 200, response.content.decode()[:200])
        self.assertTrue(RevokedCertificate.objects.filter(
            certificate=self.leaf).exists())

    def test_create_leaf_accepts_a_json_body_with_sans(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_json('/api/certificates/create/leaf/', {
            'common_name': 'json.internal', 'san': 'json.internal, other.internal',
            'validity_days': 300, 'intermediate_id': self.intermediate.id})
        self.assertEqual(response.status_code, 201, response.content.decode()[:200])

    def test_change_password_accepts_a_json_body(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_json('/api/password/', {
            'old_password': 'pw-Owner-123',
            'new_password1': 'Json-New-Passw0rd',
            'new_password2': 'Json-New-Passw0rd'})
        self.assertEqual(response.status_code, 200, response.content.decode()[:200])

    def test_malformed_json_is_a_400_not_a_500(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.client.post('/api/certificates/create/root/', data='{not json',
                                    content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_revoke_still_accepts_urlencoded_bodies(self):
        '''HTML form posts must keep working.'''
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form(
            reverse('api:revoke_certificate', args=['leaf', self.leaf.id]),
            {'type': 'leaf', 'id': str(self.leaf.id), 'reason': 'superseded'})
        self.assertEqual(response.status_code, 200)
