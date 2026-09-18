"""
Model-level invariants for revocation records.

The HTTP-facing behaviour that used to live in this module is covered by
tests_api.py, which exercises the JSON API the Vue frontend consumes. What
remains here needs no request layer at all.
"""
from django.contrib.auth.models import User
from django.test import TestCase

from .ca import CertificateAuthority
from .models import (
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
)


class ModelInvariantTests(TestCase):
    '''A revocation must point at exactly one certificate.'''

    @classmethod
    def setUpTestData(cls):
        ca = CertificateAuthority()
        cls.owner = User.objects.create_user('inv-owner', password='pw-Owner-123')

        root_data = ca.create_root_certificate('Invariant Root CA', 3650)
        cls.root = RootCertificate.objects.create(
            name='Invariant Root CA', serial_number=str(root_data['serial_number']),
            public_key=root_data['public_key'],
            private_key_encrypted=root_data['private_key'],
            valid_until=root_data['valid_until'], created_by=cls.owner)

        inter_data = ca.create_intermediate_certificate(
            'Invariant Intermediate CA', 1825, root_data['public_key'],
            root_data['private_key'])
        cls.intermediate = IntermediateCertificate.objects.create(
            name='Invariant Intermediate CA',
            serial_number=str(inter_data['serial_number']),
            public_key=inter_data['public_key'],
            private_key_encrypted=inter_data['private_key'],
            signed_by_root=cls.root, valid_until=inter_data['valid_until'],
            created_by=cls.owner)

        leaf_data = ca.create_leaf_certificate(
            'host.internal', ['host.internal'], 365, inter_data['public_key'],
            inter_data['private_key'])
        cls.leaf = LeafCertificate.objects.create(
            common_name='host.internal', san='host.internal',
            serial_number=str(leaf_data['serial_number']),
            public_key=leaf_data['public_key'],
            private_key_encrypted=leaf_data['private_key'],
            signed_by_intermediate=cls.intermediate,
            valid_until=leaf_data['valid_until'], created_by=cls.owner)

    def test_a_revocation_needs_exactly_one_target(self):
        with self.assertRaises(ValueError):
            RevokedCertificate.objects.create(
                reason=RevokedCertificate.RevocationReason.UNSPECIFIED)
        with self.assertRaises(ValueError):
            RevokedCertificate.objects.create(
                certificate=self.leaf,
                root_certificate=self.root,
                reason=RevokedCertificate.RevocationReason.UNSPECIFIED)

    def test_target_name_and_label(self):
        revocation = RevokedCertificate.objects.create(
            certificate=self.leaf,
            reason=RevokedCertificate.RevocationReason.KEY_COMPROMISE)
        self.assertEqual(revocation.target_name, 'host.internal')
        self.assertEqual(revocation.reason_label, 'Key compromise')

    def test_legacy_free_text_reason_still_renders(self):
        '''Rows written before the reason field became an enum must not break.'''
        revocation = RevokedCertificate.objects.create(
            certificate=self.leaf, reason='Revoked by admin')
        self.assertEqual(revocation.reason_label, 'Revoked by admin')

    def test_deleting_a_certificate_removes_its_revocation(self):
        RevokedCertificate.objects.create(
            certificate=self.leaf,
            reason=RevokedCertificate.RevocationReason.UNSPECIFIED)
        self.leaf.delete()
        self.assertFalse(RevokedCertificate.objects.exists())
