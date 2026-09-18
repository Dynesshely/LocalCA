"""
Tests for the JSON API that replaced the server-rendered views.

These cover the same authority rules the template tests used to: reading the
tree is public but never exposes key material, creation may only sign with a CA
you own, revoke/delete are owner-or-staff and POST-only, and private key
material is owner-only.
"""
import json

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
        self.assertTrue(RootCertificate.objects.filter(name='Second Root CA').exists())

    def test_create_leaf_with_sans(self):
        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.post_form('/api/certificates/create/leaf/', {
            'common_name': 'new.internal', 'san': 'new.internal, alt.internal',
            'validity_days': '300', 'intermediate_id': str(self.intermediate.id)})
        self.assertEqual(response.status_code, 201)
        leaf = LeafCertificate.objects.get(common_name='new.internal')
        self.assertIn('alt.internal', leaf.san)

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

    def test_public_pem_is_anonymous_and_returns_a_chain_for_leaves(self):
        response = self.client.get(
            reverse('api:download_pem', args=[self.leaf.serial_number]))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertEqual(body.count('BEGIN CERTIFICATE'), 2)

    def test_private_pem_requires_ownership(self):
        url = reverse('api:download_private', args=[self.leaf.serial_number])
        self.assertEqual(self.client.get(url).status_code, 401)

        self.client.login(username='api-other', password='pw-Other-123')
        self.assertEqual(self.client.get(url).status_code, 403)

        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('BEGIN RSA PRIVATE KEY', response.content.decode())
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_pkcs12_requires_ownership(self):
        url = reverse('api:download_pkcs12', args=[self.leaf.serial_number])
        self.assertEqual(self.client.get(url).status_code, 401)
        self.client.login(username='api-other', password='pw-Other-123')
        self.assertEqual(self.client.get(url).status_code, 403)

        self.client.login(username='api-owner', password='pw-Owner-123')
        response = self.client.post(url, {'p12_password': 'secret'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-pkcs12')
        self.assertGreater(len(response.content), 0)

    def test_hostile_name_cannot_break_the_disposition_header(self):
        self.leaf.common_name = 'evil".internal'
        self.leaf.save(update_fields=['common_name'])
        response = self.client.get(
            reverse('api:download_pem', args=[self.leaf.serial_number]))
        disposition = response['Content-Disposition']
        self.assertTrue(disposition.startswith('attachment; filename="'))
        self.assertNotIn('\n', disposition)


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
        for path in ('/', '/create/leaf', '/create/ca', '/login',
                     '/change-password', '/audit'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            body = response.content.decode()
            self.assertIn('<div id="app"', body)
            self.assertIn('app.js', body)

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
