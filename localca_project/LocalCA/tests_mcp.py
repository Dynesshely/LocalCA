"""
End-to-end test for the MCP stdio server: a real PAT against a live test server.

The MCP server is a separate process, so this exercises the whole path rather
than calling the tool functions in-process: stdin/stdout JSON-RPC, PAT auth, the
CSRF bypass for bearer requests, the LocalCA API, the vault, and the database.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import json
import os
import subprocess
import sys
from pathlib import Path

from django.contrib.auth.models import User
from django.test import LiveServerTestCase

from .access_tokens import generate_token, hash_token
from .keys import create_credential, unlock_credential
from .models import PersonalAccessToken

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SCRIPT = REPO_ROOT / 'scripts' / 'localca_mcp.py'
VAULT_PASSWORD = 'mcp-test-vault-password'


class McpLiveServerTests(LiveServerTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            'mcp-user', password='pw-Mcp-User-123')
        raw = generate_token()
        PersonalAccessToken.objects.create(
            user=self.user,
            name='MCP integration',
            token_prefix=raw[:12],
            token_hash=hash_token(raw),
        )
        credential = create_credential(self.user, 'MCP credential', VAULT_PASSWORD)
        unlock_credential(credential, VAULT_PASSWORD)
        self.pat = raw

    def run_mcp(self, messages):
        env = os.environ.copy()
        env.update({
            'LOCALCA_URL': self.live_server_url,
            'LOCALCA_PAT': self.pat,
        })
        payload = '\n'.join(json.dumps(message) for message in messages) + '\n'
        with subprocess.Popen(
                [sys.executable, str(MCP_SCRIPT)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1,
                env=env) as proc:
            stdout, stderr = proc.communicate(payload, timeout=60)
            returncode = proc.returncode
        return returncode, stdout, stderr

    @staticmethod
    def responses(stdout):
        return [json.loads(line) for line in stdout.splitlines() if line.strip()]

    @staticmethod
    def content(result):
        return json.loads(result['result']['content'][0]['text'])

    def test_handshake_and_certificate_create_over_http(self):
        self.assertTrue(MCP_SCRIPT.exists())
        messages = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
             'params': {'protocolVersion': '2024-11-05',
                        'capabilities': {},
                        'clientInfo': {'name': 'test', 'version': '0'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
             'params': {'name': 'list_certificates', 'arguments': {}}},
            {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
             'params': {'name': 'create_root_ca', 'arguments': {
                 'common_name': 'MCP Root CA', 'validity_days': 30}}},
            {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call',
             'params': {'name': 'list_certificates', 'arguments': {}}},
        ]
        returncode, stdout, stderr = self.run_mcp(messages)
        self.assertEqual(returncode, 0, stderr)
        responses = self.responses(stdout)
        # The notification produces no response: initialize, tools/list,
        # list, create, list.
        self.assertEqual(len(responses), 5)
        by_id = {response['id']: response for response in responses}

        self.assertEqual(by_id[1]['result']['protocolVersion'], '2024-11-05')
        self.assertIn('tools', by_id[1]['result']['capabilities'])

        names = [tool['name'] for tool in by_id[2]['result']['tools']]
        self.assertEqual(len(names), 9)
        self.assertIn('create_leaf_certificate', names)
        self.assertIn('delete_certificate', names)

        empty = self.content(by_id[3])
        self.assertTrue(empty['ok'])
        self.assertEqual(empty['count'], 0)

        created = self.content(by_id[4])
        self.assertTrue(created['ok'])
        certificate = created['certificate']
        self.assertEqual(certificate['kind'], 'root')
        self.assertEqual(certificate['name'], 'MCP Root CA')

        listed = self.content(by_id[5])
        self.assertEqual(listed['count'], 1)
        self.assertEqual(listed['certificates'][0]['kind'], 'root')
        self.assertEqual(listed['certificates'][0]['name'], 'MCP Root CA')
