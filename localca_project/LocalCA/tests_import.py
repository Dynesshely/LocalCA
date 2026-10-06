"""
Tests for certificate import.

The parser touches no database, so the format matrix runs as a plain test case.
The planner and API tests then cover the invariants that actually matter: a dry
run writes nothing, an uploaded private key is never stored in cleartext, a CA
imported without a key is never offered as a signer, importing cannot attach to
somebody else's CA, and one bad entry does not lose the rest of a migration.
"""
import datetime
import io
import json
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase

from . import import_service, importers
from .ca import CertificateAuthority
from .keys import create_credential, default_credential, is_wrapped, unlock_credential
from .vault import unsealed
from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RootCertificate,
)

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
NO_ENCRYPTION = serialization.NoEncryption()
PKCS8 = serialization.PrivateFormat.PKCS8
TRADITIONAL = serialization.PrivateFormat.TraditionalOpenSSL


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_certificate(subject_cn, issuer_cn, public_key, signer_key, serial, *,
                     ca, sans=()):
    '''Build a certificate carrying the SKI/AKI pair real tooling emits.'''
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()),
            critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    elif sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in sans]), critical=False)
    return builder.sign(signer_key, hashes.SHA256())


class Chain:
    '''A root, an intermediate and a leaf, each with its own key.'''

    def __init__(self, prefix='Import', serials=(9001, 9002, 9003)):
        self.root_key = make_key()
        root_name = f'{prefix} Root CA'
        self.root = make_certificate(
            root_name, root_name, self.root_key.public_key(), self.root_key,
            serials[0], ca=True)

        self.intermediate_key = make_key()
        self.intermediate_name = f'{prefix} Intermediate CA'
        self.intermediate = make_certificate(
            self.intermediate_name, root_name, self.intermediate_key.public_key(),
            self.root_key, serials[1], ca=True)

        self.leaf_key = make_key()
        self.leaf_name = f'{prefix.lower()}.example.lan'
        self.leaf = make_certificate(
            self.leaf_name, self.intermediate_name, self.leaf_key.public_key(),
            self.intermediate_key, serials[2], ca=False,
            sans=(self.leaf_name, '10.20.30.40'))

    # -- serialisation helpers -------------------------------------------

    @staticmethod
    def cert_pem(*certs):
        return b''.join(cert.public_bytes(PEM) for cert in certs)

    @staticmethod
    def cert_der(cert):
        return cert.public_bytes(DER)

    @staticmethod
    def key_pem(key, password=None):
        return key.private_bytes(
            PEM, PKCS8,
            serialization.BestAvailableEncryption(password.encode())
            if password else NO_ENCRYPTION)

    @staticmethod
    def key_der(key, traditional=False):
        return key.private_bytes(
            DER, TRADITIONAL if traditional else PKCS8, NO_ENCRYPTION)


# --------------------------------------------------------------------------
# Parsing: the format matrix
# --------------------------------------------------------------------------

class ImporterFormatTests(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.chain = Chain()

    def parse(self, sources, password=None):
        return importers.parse_sources(sources, password=password)

    def test_pem_single_certificate(self):
        bundle = self.parse([('root.pem', self.chain.cert_pem(self.chain.root))])
        self.assertEqual(len(bundle.certs), 1)
        self.assertTrue(bundle.certs[0].is_self_signed)
        self.assertTrue(bundle.certs[0].is_ca)
        self.assertEqual(bundle.certs[0].kind_hint, 'root')

    def test_pem_chain_is_read_in_order(self):
        bundle = self.parse([('chain.pem', self.chain.cert_pem(
            self.chain.root, self.chain.intermediate, self.chain.leaf))])
        self.assertEqual([c.kind_hint for c in bundle.certs],
                         ['root', 'intermediate', 'leaf'])

    def test_pem_certificate_and_key_in_one_file(self):
        data = self.chain.cert_pem(self.chain.intermediate) + self.chain.key_pem(
            self.chain.intermediate_key)
        bundle = self.parse([('bundle.pem', data)])
        self.assertEqual(len(bundle.certs), 1)
        self.assertEqual(len(bundle.keys), 1)

    def test_pem_certificate_and_key_in_separate_files(self):
        bundle = self.parse([
            ('cert.pem', self.chain.cert_pem(self.chain.leaf)),
            ('key.pem', self.chain.key_pem(self.chain.leaf_key)),
        ])
        self.assertEqual(len(bundle.certs), 1)
        self.assertEqual(len(bundle.keys), 1)

    def test_der_certificate(self):
        bundle = self.parse([('root.der', self.chain.cert_der(self.chain.root))])
        self.assertEqual(bundle.certs[0].kind_hint, 'root')

    def test_der_private_key_pkcs8_and_pkcs1(self):
        for name, traditional in (('k8.der', False), ('k1.der', True)):
            with self.subTest(name=name):
                bundle = self.parse([(name, self.chain.key_der(
                    self.chain.intermediate_key, traditional=traditional))])
                self.assertEqual(len(bundle.keys), 1)
                self.assertIn('BEGIN PRIVATE KEY', bundle.keys[0].pem)

    def test_pkcs7_der_and_pem(self):
        certs = [self.chain.root, self.chain.intermediate]
        for name, encoding in (('chain.p7b', PEM), ('chain.p7c', DER)):
            with self.subTest(name=name):
                bundle = self.parse(
                    [(name, pkcs7.serialize_certificates(certs, encoding))])
                self.assertEqual(len(bundle.certs), 2)
                self.assertEqual(len(bundle.keys), 0)

    def test_pkcs12_with_password(self):
        blob = pkcs12.serialize_key_and_certificates(
            b'alias', self.chain.intermediate_key, self.chain.intermediate,
            [self.chain.root], serialization.BestAvailableEncryption(b'sesame'))
        bundle = self.parse([('bundle.p12', blob)], password='sesame')
        self.assertEqual(len(bundle.certs), 2)
        self.assertEqual(len(bundle.keys), 1)
        self.assertTrue(bundle.keys[0].encrypted_in_source)

    def test_pkcs12_without_a_password(self):
        blob = pkcs12.serialize_key_and_certificates(
            b'alias', self.chain.intermediate_key, self.chain.intermediate,
            [self.chain.root], NO_ENCRYPTION)
        bundle = self.parse([('bundle.p12', blob)])
        self.assertEqual(len(bundle.certs), 2)
        self.assertEqual(len(bundle.keys), 1)

    def test_pkcs12_wrong_password_is_rejected(self):
        blob = pkcs12.serialize_key_and_certificates(
            b'alias', self.chain.intermediate_key, self.chain.intermediate,
            [self.chain.root], serialization.BestAvailableEncryption(b'sesame'))
        with self.assertRaises(importers.BadPassword):
            self.parse([('bundle.p12', blob)], password='wrong')

    def test_pkcs12_needing_a_password_explains_itself(self):
        blob = pkcs12.serialize_key_and_certificates(
            b'alias', self.chain.intermediate_key, self.chain.intermediate,
            [self.chain.root], serialization.BestAvailableEncryption(b'sesame'))
        bundle = self.parse([('bundle.p12', blob)])
        self.assertEqual(len(bundle.certs), 0)
        self.assertEqual(len(bundle.keys), 0)
        self.assertTrue(any('password' in warning for warning in bundle.warnings))

    def test_encrypted_pkcs8(self):
        bundle = self.parse(
            [('key.pem', self.chain.key_pem(self.chain.intermediate_key, 'pw'))],
            password='pw')
        self.assertEqual(len(bundle.keys), 1)
        self.assertTrue(bundle.keys[0].encrypted_in_source)

    def test_traditional_openssl_encrypted_pem(self):
        data = self.chain.intermediate_key.private_bytes(
            PEM, TRADITIONAL, serialization.BestAvailableEncryption(b'pw'))
        self.assertIn(b'Proc-Type: 4,ENCRYPTED', data)
        bundle = self.parse([('key.pem', data)], password='pw')
        self.assertEqual(len(bundle.keys), 1)

    def test_wrong_password_on_a_pem_key_is_rejected(self):
        data = self.chain.intermediate_key.private_bytes(
            PEM, TRADITIONAL, serialization.BestAvailableEncryption(b'pw'))
        with self.assertRaises(importers.BadPassword):
            self.parse([('key.pem', data)], password='nope')

    def test_password_given_for_a_plain_key_is_harmless(self):
        bundle = self.parse(
            [('key.pem', self.chain.key_pem(self.chain.intermediate_key))],
            password='unnecessary')
        self.assertEqual(len(bundle.keys), 1)

    def test_trusted_certificate_label(self):
        body = self.chain.cert_der(self.chain.root)
        wrapped = (b'-----BEGIN TRUSTED CERTIFICATE-----\n'
                   + __import__('base64').encodebytes(body)
                   + b'-----END TRUSTED CERTIFICATE-----\n')
        bundle = self.parse([('trusted.pem', wrapped)])
        self.assertEqual(len(bundle.certs), 1)

    def test_trusted_certificate_with_trailing_trust_data(self):
        body = self.chain.cert_der(self.chain.root) + b'\x30\x03\x01\x01\xff'
        wrapped = (b'-----BEGIN TRUSTED CERTIFICATE-----\n'
                   + __import__('base64').encodebytes(body)
                   + b'-----END TRUSTED CERTIFICATE-----\n')
        bundle = self.parse([('trusted.pem', wrapped)])
        self.assertEqual(len(bundle.certs), 1)

    def test_zip_container(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('root.pem', self.chain.cert_pem(self.chain.root))
            archive.writestr('inter.pem', self.chain.cert_pem(self.chain.intermediate)
                             + self.chain.key_pem(self.chain.intermediate_key))
            archive.writestr('leaf.der', self.chain.cert_der(self.chain.leaf))
        bundle = self.parse([('migration.zip', buffer.getvalue())])
        self.assertEqual(len(bundle.certs), 3)
        self.assertEqual(len(bundle.keys), 1)

    def test_unsupported_zip_member_is_reported_not_fatal(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('root.pem', self.chain.cert_pem(self.chain.root))
            archive.writestr('notes.txt', 'this is not a certificate')
        bundle = self.parse([('migration.zip', buffer.getvalue())])
        self.assertEqual(len(bundle.certs), 1)
        self.assertTrue(bundle.errors)

    def test_zip_expansion_bomb_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('zeros.bin', b'\x00' * (3 * 1024 * 1024))
        with self.assertRaises(importers.UploadTooLarge):
            self.parse([('bomb.zip', buffer.getvalue())])

    def test_zip_entry_count_limit(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for index in range(importers.MAX_ARCHIVE_ENTRIES + 1):
                archive.writestr(f'c{index}.pem', self.chain.cert_pem(self.chain.root))
        with self.assertRaises(importers.UploadTooLarge):
            self.parse([('many.zip', buffer.getvalue())])

    def test_csr_and_ssh_keys_are_explained(self):
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'x')]))
               .sign(self.chain.leaf_key, hashes.SHA256()))
        bundle = self.parse([('req.pem', csr.public_bytes(PEM))])
        self.assertEqual(len(bundle.certs), 0)
        self.assertTrue(any('CSR' in w or 'request' in w for w in bundle.warnings))

        ssh = b'-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n'
        bundle = self.parse([('id_ed25519', ssh)])
        self.assertTrue(any('SSH' in w for w in bundle.warnings))

    def test_garbage_is_rejected(self):
        with self.assertRaises(importers.UnusableUpload):
            self.parse([('x.bin', b'\x00\x01\x02 not a certificate')])

    def test_no_files_is_rejected(self):
        with self.assertRaises(importers.UnusableUpload):
            self.parse([])

    def test_per_file_size_limit(self):
        with self.assertRaises(importers.UploadTooLarge):
            self.parse([('big.pem', b'x' * (importers.MAX_FILE_BYTES + 1))])

    def test_total_size_limit(self):
        chunk = b'x' * importers.MAX_FILE_BYTES
        sources = [(f'part{i}.bin', chunk) for i in range(6)]
        with self.assertRaises(importers.UploadTooLarge):
            self.parse(sources)

    def test_file_count_limit(self):
        sources = [(f'f{i}.pem', self.chain.cert_pem(self.chain.root))
                   for i in range(importers.MAX_FILES + 1)]
        with self.assertRaises(importers.UploadTooLarge):
            self.parse(sources)

    def test_object_count_limit(self):
        data = self.chain.cert_pem(self.chain.root) * (importers.MAX_OBJECTS + 1)
        with self.assertRaises(importers.UploadTooLarge):
            self.parse([('many.pem', data)])

    def test_duplicate_certificates_are_deduplicated(self):
        data = self.chain.cert_pem(self.chain.root) * 3
        bundle = self.parse([('dup.pem', data)])
        self.assertEqual(len(bundle.certs), 1)

    def test_upload_adapter_reads_django_files(self):
        upload = SimpleUploadedFile('root.pem', self.chain.cert_pem(self.chain.root))
        bundle = importers.parse_uploads([upload])
        self.assertEqual(len(bundle.certs), 1)


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------

class ImportTestBase(TestCase):
    VAULT_PASSWORD = 'vault-import-password-123'

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('importer', password='pw-Importer-1')
        cls.other = User.objects.create_user('other', password='pw-Other-1')
        cls.staff = User.objects.create_superuser('importer-staff', 's@example.com',
                                                  'pw-Staff-1')
        cls.chain = Chain()

    def setUp(self):
        super().setUp()
        # The unsealed-key store is process-global and outlives a test, so every
        # test starts with the vault locked and unlocks explicitly when it needs to.
        unsealed.lock_all()
        self.client.force_login(self.user)

    def unseal(self, user=None):
        '''Open (or create) the account's credential, and return it.

        Imports wrap their keys with a *credential* rather than a bare root key, so
        this helper returns the object a plan needs.
        '''
        account = user or self.user
        credential = default_credential(account)
        if credential is None:
            return create_credential(account, 'Import test', self.VAULT_PASSWORD)
        unlock_credential(credential, self.VAULT_PASSWORD)
        return credential

    def plan(self, sources, password=None, user=None, overrides=None):
        bundle = importers.parse_sources(sources, password=password)
        return import_service.plan_import(
            bundle, user or self.user, overrides=overrides)

    def sources_root(self):
        return [('root.pem', self.chain.cert_pem(self.chain.root)
                 + self.chain.key_pem(self.chain.root_key))]

    def sources_chain(self):
        return [('chain.pem', self.chain.cert_pem(
            self.chain.root, self.chain.intermediate, self.chain.leaf)
            + self.chain.key_pem(self.chain.root_key)
            + self.chain.key_pem(self.chain.intermediate_key)
            + self.chain.key_pem(self.chain.leaf_key))]


class ImportPlanTests(ImportTestBase):

    def test_root_with_key_requires_the_vault(self):
        plan = self.plan(self.sources_root())
        self.assertEqual(plan.counts['create'], 1)
        self.assertTrue(plan.requires_vault_unlock)

    def test_root_without_key_does_not_require_the_vault(self):
        plan = self.plan([('root.pem', self.chain.cert_pem(self.chain.root))])
        self.assertEqual(plan.counts['create'], 1)
        self.assertFalse(plan.requires_vault_unlock)

    def test_chain_rebuilds_the_hierarchy(self):
        plan = self.plan(self.sources_chain())
        actions = [(item.kind, item.action) for item in plan.items]
        self.assertEqual(actions, [('root', 'create'), ('intermediate', 'create'),
                                   ('leaf', 'create')])
        by_kind = {item.kind: item for item in plan.items}
        self.assertIsNone(by_kind['root'].parent)
        self.assertEqual(by_kind['intermediate'].parent[0], 'import')
        self.assertEqual(by_kind['leaf'].parent[0], 'import')
        # Each child names the parent it will hang off.
        self.assertIn('Import Root CA', by_kind['intermediate'].parent_label)
        self.assertIn('Import Intermediate CA', by_kind['leaf'].parent_label)

    def test_chain_links_to_a_stored_root(self):
        '''A root that is already stored becomes the parent of a new intermediate.'''
        self.unseal()
        root_plan = self.plan(self.sources_root())
        import_service.apply_plan(root_plan, self.user, self.unseal())

        bundle = importers.parse_sources([('inter.pem', self.chain.cert_pem(
            self.chain.intermediate) + self.chain.key_pem(self.chain.intermediate_key))])
        plan = import_service.plan_import(bundle, self.user)
        self.assertEqual(plan.counts['create'], 1)
        self.assertEqual(plan.items[0].parent[0], 'existing')
        self.assertEqual(plan.items[0].parent[1], 'root')

    def test_missing_issuer_is_a_conflict(self):
        plan = self.plan([('leaf.pem', self.chain.cert_pem(self.chain.leaf))])
        self.assertEqual(plan.counts['conflict'], 1)
        self.assertIn('issuing', plan.items[0].reason)

    def test_leaf_issued_by_a_root_is_unsupported(self):
        leaf_key = make_key()
        leaf = make_certificate(
            'direct.example.lan', 'Import Root CA', leaf_key.public_key(),
            self.chain.root_key, 9100, ca=False, sans=('direct.example.lan',))
        plan = self.plan([('direct.pem', self.chain.cert_pem(
            self.chain.root, leaf) + self.chain.key_pem(self.chain.root_key))])
        by_name = {item.cert.common_name: item for item in plan.items}
        self.assertEqual(by_name['direct.example.lan'].action, 'unsupported')
        self.assertIn('root CA', by_name['direct.example.lan'].reason)

    def test_self_signed_end_entity_is_unsupported(self):
        key = make_key()
        cert = make_certificate('self.example.lan', 'self.example.lan',
                                key.public_key(), key, 9200, ca=False,
                                sans=('self.example.lan',))
        plan = self.plan([('self.pem', self.chain.cert_pem(cert))])
        self.assertEqual(plan.items[0].action, 'unsupported')

    def test_already_stored_certificate_is_skipped(self):
        self.unseal()
        import_service.apply_plan(self.plan(self.sources_root()), self.user, self.unseal())
        plan = self.plan(self.sources_root())
        self.assertEqual(plan.counts['skip'], 1)

    def test_a_skipped_entry_keeps_the_stored_name(self):
        '''
        A plan entry that will not be written must not be shown under an invented
        name: the operator is looking at the row that already exists.
        '''
        self.unseal()
        import_service.apply_plan(self.plan(self.sources_root()), self.user, self.unseal())
        plan = self.plan(self.sources_root())
        item = plan.items[0]
        self.assertEqual(item.action, 'skip')
        self.assertEqual(item.name, 'Import Root CA')
        self.assertFalse(item.renamed)

    def test_missing_key_on_a_stored_certificate_is_attached(self):
        self.unseal()
        import_service.apply_plan(
            self.plan([('root.pem', self.chain.cert_pem(self.chain.root))]),
            self.user, self.unseal())
        plan = self.plan(self.sources_root())
        self.assertEqual(plan.counts['attach_key'], 1)
        self.assertTrue(plan.requires_vault_unlock)

    def test_serial_collision_is_a_conflict(self):
        # A different certificate that reuses the root's serial number.
        other_key = make_key()
        twin = make_certificate('Twin Root CA', 'Twin Root CA',
                                other_key.public_key(), other_key,
                                self.chain.root.serial_number, ca=True)
        RootCertificate.objects.create(
            name='Twin Root CA', serial_number=str(twin.serial_number),
            public_key=twin.public_bytes(PEM).decode(), private_key_encrypted='',
            valid_until=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=10), created_by=self.user)
        plan = self.plan([('root.pem', self.chain.cert_pem(self.chain.root))])
        self.assertEqual(plan.counts['conflict'], 1)
        self.assertIn('Serial number', plan.items[0].reason)

    def test_name_collision_renames_instead_of_failing(self):
        other_key = make_key()
        twin = make_certificate('Import Root CA', 'Import Root CA',
                                other_key.public_key(), other_key, 9300, ca=True)
        RootCertificate.objects.create(
            name='Import Root CA', serial_number=str(twin.serial_number),
            public_key=twin.public_bytes(PEM).decode(), private_key_encrypted='',
            valid_until=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=10), created_by=self.user)
        plan = self.plan([('root.pem', self.chain.cert_pem(self.chain.root))])
        item = plan.items[0]
        self.assertEqual(item.action, 'create')
        self.assertTrue(item.renamed)
        self.assertNotEqual(item.name, 'Import Root CA')

    def test_parent_owned_by_another_account_is_a_conflict(self):
        self.unseal()
        import_service.apply_plan(self.plan(self.sources_root()), self.user, self.unseal())
        bundle = importers.parse_sources([('inter.pem', self.chain.cert_pem(
            self.chain.intermediate) + self.chain.key_pem(self.chain.intermediate_key))])
        plan = import_service.plan_import(bundle, self.other)
        self.assertEqual(plan.counts['conflict'], 1)
        self.assertIn('another account', plan.items[0].reason)

    def test_staff_may_extend_another_accounts_ca(self):
        self.unseal()
        import_service.apply_plan(self.plan(self.sources_root()), self.user, self.unseal())
        bundle = importers.parse_sources([('inter.pem', self.chain.cert_pem(
            self.chain.intermediate) + self.chain.key_pem(self.chain.intermediate_key))])
        plan = import_service.plan_import(bundle, self.staff)
        self.assertEqual(plan.counts['create'], 1)

    def test_override_can_rename_and_skip(self):
        fingerprint = None
        bundle = importers.parse_sources(
            [('root.pem', self.chain.cert_pem(self.chain.root))])
        fingerprint = bundle.certs[0].fingerprint
        plan = import_service.plan_import(bundle, self.user, overrides={
            fingerprint: {'name': 'Renamed Root', 'action': 'skip'}})
        self.assertEqual(plan.items[0].name, 'Renamed Root')
        self.assertEqual(plan.items[0].action, 'skip')

    def test_unpaired_key_is_reported(self):
        data = self.chain.key_pem(self.chain.intermediate_key)
        bundle = importers.parse_sources([('key.pem', data)])
        plan = import_service.plan_import(bundle, self.user)
        self.assertTrue(plan.key_warnings)
        self.assertEqual(plan.counts['create'], 0)


# --------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------

class ImportApplyTests(ImportTestBase):

    def test_root_key_is_wrapped_and_never_stored_in_cleartext(self):
        self.unseal()
        plan = self.plan(self.sources_root())
        summary = import_service.apply_plan(plan, self.user, self.unseal())
        self.assertEqual(summary['created']['root'], 1)
        self.assertEqual(summary['keys_wrapped'], 1)

        root = RootCertificate.objects.get(name='Import Root CA')
        self.assertTrue(is_wrapped(root))
        self.assertEqual(root.private_key_encrypted, '')
        self.assertNotIn('BEGIN PRIVATE KEY', root.private_key_wrapped)
        self.assertNotIn(root.private_key_wrapped, self.chain.key_pem(self.chain.root_key).decode())

    def test_chain_is_linked(self):
        self.unseal()
        summary = import_service.apply_plan(
            self.plan(self.sources_chain()), self.user, self.unseal())
        self.assertEqual(summary['created'],
                         {'root': 1, 'intermediate': 1, 'leaf': 1})
        root = RootCertificate.objects.get(name='Import Root CA')
        intermediate = IntermediateCertificate.objects.get(name='Import Intermediate CA')
        leaf = LeafCertificate.objects.get(common_name=self.chain.leaf_name)
        self.assertEqual(intermediate.signed_by_root_id, root.id)
        self.assertEqual(leaf.signed_by_intermediate_id, intermediate.id)
        self.assertEqual(leaf.san, f'{self.chain.leaf_name},10.20.30.40')

    def test_keyless_certificate_is_stored_and_flagged(self):
        plan = self.plan([('root.pem', self.chain.cert_pem(self.chain.root))])
        import_service.apply_plan(plan, self.user, None)
        root = RootCertificate.objects.get(name='Import Root CA')
        self.assertFalse(is_wrapped(root))
        self.assertEqual(root.private_key_encrypted, '')

    def test_attach_key_wraps_an_existing_row(self):
        self.unseal()
        import_service.apply_plan(
            self.plan([('root.pem', self.chain.cert_pem(self.chain.root))]),
            self.user, self.unseal())
        summary = import_service.apply_plan(
            self.plan(self.sources_root()), self.user, self.unseal())
        self.assertEqual(summary['keys_attached'], 1)
        root = RootCertificate.objects.get(name='Import Root CA')
        self.assertTrue(is_wrapped(root))

    def test_import_is_audited(self):
        self.unseal()
        import_service.apply_plan(self.plan(self.sources_root()), self.user, self.unseal())
        entry = AuditLog.objects.filter(action='IMPORT', details__startswith='Imported').first()
        self.assertIsNotNone(entry)
        self.assertIn('Import Root CA', entry.details)
        self.assertNotIn('PRIVATE KEY', entry.details)

    def test_failure_of_one_entry_does_not_lose_the_others(self):
        '''
        A serial number that appears between the dry run and the commit breaks only
        that entry. The rest of the upload still goes in, which is the point of
        applying per item instead of in one all-or-nothing transaction.
        '''
        self.unseal()
        second_key = make_key()
        second = make_certificate('Second Root CA', 'Second Root CA',
                                  second_key.public_key(), second_key, 9501, ca=True)
        plan = self.plan([('two-roots.pem',
                           self.chain.cert_pem(self.chain.root)
                           + self.chain.cert_pem(second)
                           + self.chain.key_pem(self.chain.root_key)
                           + self.chain.key_pem(second_key))])
        self.assertEqual(plan.counts['create'], 2)

        # The collision appears after the plan was made.
        target = next(item for item in plan.items
                      if item.cert.common_name == 'Second Root CA')
        squatter_key = make_key()
        squatter = make_certificate(
            'Squatter CA', 'Squatter CA', squatter_key.public_key(), squatter_key,
            int(target.cert.serial_number), ca=True)
        RootCertificate.objects.create(
            name='Squatter CA', serial_number=str(squatter.serial_number),
            public_key=squatter.public_bytes(PEM).decode(), private_key_encrypted='',
            valid_until=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=10), created_by=self.user)

        summary = import_service.apply_plan(plan, self.user, self.unseal())
        self.assertEqual(summary['created']['root'], 1)
        self.assertEqual([failure['name'] for failure in summary['failed']],
                         ['Second Root CA'])
        self.assertTrue(RootCertificate.objects.filter(name='Import Root CA').exists())
        self.assertEqual(RootCertificate.objects.count(), 2)   # the squatter and the import


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

class ImportApiTests(ImportTestBase):

    def upload(self, sources, dry_run=True, password=None, overrides=None):
        files = [SimpleUploadedFile(name, data) for name, data in sources]
        data = {'files': files, 'dry_run': '1' if dry_run else '0'}
        if password:
            data['password'] = password
        if overrides is not None:
            data['overrides'] = json.dumps(overrides)
        return self.client.post('/api/import/', data=data)

    def test_requires_authentication(self):
        self.client.logout()
        response = self.upload(self.sources_root())
        self.assertEqual(response.status_code, 401)

    def test_dry_run_writes_nothing(self):
        response = self.upload(self.sources_root(), dry_run=True)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['dry_run'])
        self.assertEqual(payload['plan']['counts']['create'], 1)
        self.assertTrue(payload['plan']['requires_vault_unlock'])
        self.assertEqual(RootCertificate.objects.count(), 0)

    def test_commit_without_unlocking_the_vault_is_refused(self):
        response = self.upload(self.sources_root(), dry_run=False)
        self.assertEqual(response.status_code, 409)
        self.assertTrue(response.json()['vault_locked'])
        self.assertEqual(RootCertificate.objects.count(), 0)

    def test_commit_imports_and_appears_in_the_tree(self):
        self.unseal()
        response = self.upload(self.sources_chain(), dry_run=False)
        self.assertEqual(response.status_code, 200)
        result = response.json()['result']
        self.assertEqual(result['created'], {'root': 1, 'intermediate': 1, 'leaf': 1})

        tree = self.client.get('/api/certificates/').json()['tree']
        node = next(n for n in tree if n['certificate']['name'] == 'Import Root CA')
        self.assertEqual(node['intermediates'][0]['certificate']['name'],
                         'Import Intermediate CA')
        self.assertEqual(node['intermediates'][0]['leaves'][0]['name'],
                         self.chain.leaf_name)

    def test_imported_key_is_encrypted_at_rest(self):
        self.unseal()
        self.upload(self.sources_root(), dry_run=False)
        root = RootCertificate.objects.get(name='Import Root CA')
        self.assertTrue(is_wrapped(root))
        self.assertEqual(root.private_key_encrypted, '')
        self.assertIn('"v":1', root.private_key_wrapped)

    def test_keyless_import_is_visible_but_not_offered_as_an_issuer(self):
        response = self.upload([('root.pem', self.chain.cert_pem(self.chain.root))],
                               dry_run=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['result']['keys_wrapped'], 0)

        tree = self.client.get('/api/certificates/').json()['tree']
        self.assertEqual(tree[0]['certificate']['has_key'], False)

        issuers = self.client.get('/api/issuers/').json()
        self.assertEqual(issuers['roots'], [])

        form = self.client.post('/api/certificates/create/intermediate/', data=json.dumps({
            'common_name': 'Child CA', 'validity_days': 365,
            'root_id': RootCertificate.objects.get().id,
        }), content_type='application/json')
        self.assertEqual(form.status_code, 400)

    def test_staff_sees_another_users_imported_key_state(self):
        self.unseal()
        self.upload(self.sources_root(), dry_run=False)
        self.client.force_login(self.staff)
        tree = self.client.get('/api/certificates/').json()['tree']
        self.assertEqual(tree[0]['certificate']['owner'], 'importer')
        self.assertTrue(tree[0]['certificate']['can_manage'])

    def test_unsupported_upload_is_refused_with_a_message(self):
        response = self.upload([('x.bin', b'not a certificate at all')])
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['errors'])

    def test_missing_files_is_refused(self):
        response = self.client.post('/api/import/', data={'dry_run': '1'})
        self.assertEqual(response.status_code, 400)

    def test_bad_overrides_json_is_refused(self):
        files = [SimpleUploadedFile('root.pem', self.chain.cert_pem(self.chain.root))]
        response = self.client.post('/api/import/', data={
            'files': files, 'dry_run': '1', 'overrides': 'not json'})
        self.assertEqual(response.status_code, 400)

    def test_override_skips_an_entry(self):
        self.unseal()
        bundle = importers.parse_sources(self.sources_root())
        fingerprint = bundle.certs[0].fingerprint
        response = self.upload(self.sources_root(), dry_run=False,
                               overrides={fingerprint: {'action': 'skip'}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['result']['created']['root'], 0)
        self.assertEqual(RootCertificate.objects.count(), 0)

    def test_audit_log_records_the_import(self):
        self.unseal()
        self.upload(self.sources_root(), dry_run=False)
        self.assertTrue(AuditLog.objects.filter(
            action='IMPORT', performed_by=self.user).exists())

    def test_meta_exposes_the_supported_formats(self):
        payload = self.client.get('/api/meta/').json()
        self.assertTrue(payload['import_formats']['supported'])
        self.assertTrue(payload['import_formats']['unsupported'])
        self.assertEqual(payload['import_formats']['limits']['max_files'],
                         importers.MAX_FILES)

    def test_tampered_ciphertext_of_an_imported_key_is_not_readable(self):
        '''The wrapped key is bound to the row, so moving it breaks decryption.'''
        self.unseal()
        self.upload(self.sources_root(), dry_run=False)
        root = RootCertificate.objects.get(name='Import Root CA')
        other = RootCertificate.objects.create(
            name='Another Root', serial_number='777', public_key=root.public_key,
            private_key_encrypted='', private_key_wrapped=root.private_key_wrapped,
            valid_until=root.valid_until, created_by=self.user)
        from .keys import private_key_pem
        from .vault import VaultError
        with self.assertRaises(VaultError):
            private_key_pem(other, 'root', self.user)


# --------------------------------------------------------------------------
# The signing path still works with an imported CA
# --------------------------------------------------------------------------

class ImportedIssuerTests(ImportTestBase):

    def test_an_imported_root_can_sign_a_new_intermediate(self):
        self.unseal()
        import_service.apply_plan(self.plan(self.sources_root()), self.user, self.unseal())

        ca = CertificateAuthority()
        root = RootCertificate.objects.get(name='Import Root CA')
        from .keys import private_key_pem
        issuer_key = private_key_pem(root, 'root', self.user)
        data = ca.create_intermediate_certificate('Signed By Imported Root', 365,
                                                  root.public_key, issuer_key)
        self.assertTrue(data['public_key'])
