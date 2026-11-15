"""
Tests for personal access tokens and the bearer-authenticated API.

The interesting cases are the boundary between the two authentication modes:
a bearer request must work without a CSRF cookie, a session request must still
require CSRF, and a PAT must not be allowed to mint or revoke tokens.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import json

from django.test import Client
from django.utils import timezone

from .access_tokens import generate_token, hash_token
from .models import AuditLog, LeafCertificate, PersonalAccessToken
from .tests_api import ApiTestBase


def issue_token(user, name='API token'):
    """Create a token directly, bypassing the create endpoint's session rule."""
    raw = generate_token()
    token = PersonalAccessToken.objects.create(
        user=user,
        name=name,
        token_prefix=raw[:12],
        token_hash=hash_token(raw),
    )
    return raw, token


def bearer(raw):
    return {'HTTP_AUTHORIZATION': 'Bearer ' + raw}


class PatApiTests(ApiTestBase):

    def login_owner(self):
        self.assertTrue(self.client.login(
            username='api-owner', password='pw-Owner-123'))

    def test_create_token_returns_raw_once_and_stores_only_hash(self):
        self.login_owner()
        response = self.post_json('/api/tokens/', {'name': 'CI bot'})
        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload['ok'])
        raw = payload['token']
        self.assertTrue(raw.startswith('lca_pat_'))
        self.assertEqual(payload['access_token']['prefix'], raw[:12])

        token = PersonalAccessToken.objects.get(user=self.owner, name='CI bot')
        self.assertEqual(token.token_hash, hash_token(raw))
        self.assertNotEqual(token.token_hash, raw)
        self.assertIsNone(token.last_used_at)
        self.assertFalse(token.revoked)

        listed = self.client.get('/api/tokens/').json()
        self.assertEqual(len(listed['tokens']), 1)
        self.assertNotIn('token', listed['tokens'][0])
        self.assertNotIn('token_hash', listed['tokens'][0])

        self.assertTrue(AuditLog.objects.filter(
            action='ACCESS', performed_by=self.owner,
            details__contains='CI bot').exists())

    def test_rejects_duplicate_token_name(self):
        self.login_owner()
        self.assertEqual(self.post_json('/api/tokens/', {'name': 'dup'}).status_code, 201)
        response = self.post_json('/api/tokens/', {'name': 'dup'})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()['ok'])

    def test_rejects_blank_name(self):
        self.login_owner()
        response = self.post_json('/api/tokens/', {'name': '   '})
        self.assertEqual(response.status_code, 400)

    def test_bearer_request_needs_no_csrf_cookie(self):
        raw, _token = issue_token(self.owner)
        client = Client(enforce_csrf_checks=True)
        response = client.post(
            '/api/certificates/create/leaf/',
            data=json.dumps({
                'common_name': 'pat.internal',
                'san': 'pat.internal,10.9.9.9',
                'validity_days': 30,
                'intermediate_id': self.intermediate.id,
            }),
            content_type='application/json',
            **bearer(raw))
        self.assertEqual(response.status_code, 201)
        leaf = LeafCertificate.objects.get(common_name='pat.internal')
        self.assertEqual(leaf.created_by_id, self.owner.id)
        self.assertTrue(AuditLog.objects.filter(
            action='CREATE', performed_by=self.owner,
            details__contains='pat.internal').exists())

    def test_session_request_still_needs_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.owner)
        response = client.post(
            '/api/tokens/', data=json.dumps({'name': 'no-csrf'}),
            content_type='application/json')
        self.assertEqual(response.status_code, 403)

    def test_invalid_and_revoked_tokens_are_refused(self):
        response = self.client.get('/api/certificates/', **bearer('lca_pat_nope'))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response['WWW-Authenticate'], 'Bearer')

        raw, token = issue_token(self.owner)
        token.revoked_at = timezone.now()
        token.save(update_fields=['revoked_at'])
        response = self.client.get('/api/certificates/', **bearer(raw))
        self.assertEqual(response.status_code, 401)

    def test_last_used_is_recorded(self):
        raw, token = issue_token(self.owner)
        self.assertIsNone(token.last_used_at)
        response = self.client.get('/api/session/', **bearer(raw))
        self.assertEqual(response.status_code, 200)
        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)

    def test_pat_cannot_manage_tokens(self):
        raw, _token = issue_token(self.owner)
        response = self.client.get('/api/tokens/', **bearer(raw))
        self.assertEqual(response.status_code, 403)
        response = self.client.post(
            '/api/tokens/', data=json.dumps({'name': 'escalated'}),
            content_type='application/json', **bearer(raw))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PersonalAccessToken.objects.filter(
            user=self.owner, name='escalated').exists())

    def test_pat_inherits_owner_permissions(self):
        raw, _token = issue_token(self.other)
        response = self.client.post(
            f'/api/certificates/leaf/{self.leaf.id}/renew/',
            data=json.dumps({'san': 'api.internal', 'validity_days': 30}),
            content_type='application/json', **bearer(raw))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(LeafCertificate.objects.filter(pk=self.leaf.id).exists())

    def test_staff_pat_can_manage_any_certificate(self):
        raw, _token = issue_token(self.staff)
        response = self.client.post(
            f'/api/certificates/leaf/{self.leaf.id}/delete/',
            data='{}', content_type='application/json', **bearer(raw))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(LeafCertificate.objects.filter(pk=self.leaf.id).exists())

    def test_pat_can_read_and_revoke_own_certificate(self):
        raw, _token = issue_token(self.owner)
        listed = self.client.get('/api/certificates/mine/', **bearer(raw))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()['leaves'][0]['id'], self.leaf.id)

        response = self.client.post(
            f'/api/certificates/leaf/{self.leaf.id}/revoke/',
            data=json.dumps({
                'type': 'leaf',
                'id': self.leaf.id,
                'reason': 'superseded',
                'comment': 'PAT test',
            }),
            content_type='application/json', **bearer(raw))
        self.assertEqual(response.status_code, 200)

    def test_revoke_token_blocks_future_requests(self):
        self.login_owner()
        created = self.post_json('/api/tokens/', {'name': 'to revoke'}).json()
        token_id = created['access_token']['id']
        raw = created['token']

        response = self.post_json(
            f'/api/tokens/{token_id}/revoke/', {})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['access_token']['revoked'])

        response = self.client.get('/api/certificates/', **bearer(raw))
        self.assertEqual(response.status_code, 401)
        # The record survives the revocation; it is not a delete.
        self.assertTrue(PersonalAccessToken.objects.filter(pk=token_id).exists())
