"""
Tests for the translation layer.

The point of these is not that a particular Chinese sentence is spelled a
particular way — it is that the *plumbing* works: the locale the client asks for
is honoured, the catalogue is compiled and complete, field-level validation is
addressed by field name rather than by matching a translated label, and a
translation cannot silently fall behind the code.
"""
import importlib.util
import json
import re
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import translation

from .ca import CertificateAuthority
from .models import IntermediateCertificate, RevokedCertificate, RootCertificate

PROJECT_ROOT = Path(settings.BASE_DIR).parent
I18N_TOOL = PROJECT_ROOT / 'scripts' / 'i18n.py'


def load_i18n_tool():
    '''Import scripts/i18n.py, which is a script and not a package.'''
    spec = importlib.util.spec_from_file_location('localca_i18n_tool', I18N_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CatalogueTests(SimpleTestCase):
    '''The committed catalogues, checked as data.'''

    def test_the_tool_is_where_the_test_expects(self):
        self.assertTrue(I18N_TOOL.is_file(), f'{I18N_TOOL} is missing')

    def test_every_msgid_in_the_code_is_translated(self):
        report = load_i18n_tool().coverage()
        self.assertTrue(report, 'no .po files were found')
        for po, result in report.items():
            self.assertEqual(
                result['missing'], [],
                f'{po.name} is missing translations for: {result["missing"]}')
            self.assertEqual(
                result['stale'], [],
                f'{po.name} has entries no longer used by the code: {result["stale"]}')

    def test_the_compiled_catalogue_ships_with_its_source(self):
        '''
        The .mo is committed because neither this machine nor the runtime image
        has GNU gettext. A .po that was edited without recompiling would leave
        the two out of step, which is invisible until a page renders English.
        '''
        mo = Path(settings.BASE_DIR) / 'locale' / 'zh_Hans' / 'LC_MESSAGES' / 'django.mo'
        self.assertTrue(mo.is_file(), 'django.mo is missing; run scripts/i18n.py compile')

        po = mo.with_suffix('.po')
        self.assertGreaterEqual(
            mo.stat().st_mtime, po.stat().st_mtime,
            'django.mo is older than django.po; run scripts/i18n.py compile')

    def test_the_compiled_catalogue_is_loadable(self):
        from django.utils.translation import gettext
        with translation.override('zh-hans'):
            self.assertNotEqual(gettext('Authentication required.'), 'Authentication required.')

    def test_chinese_plural_rule_is_the_single_form(self):
        '''
        Chinese has one form. A catalog compiled with the germanic plural rule
        would still work for `gettext` but would pick the wrong branch of any
        future ngettext, so the metadata is worth asserting.
        '''
        mo = Path(settings.BASE_DIR) / 'locale' / 'zh_Hans' / 'LC_MESSAGES' / 'django.mo'
        raw = mo.read_bytes()
        self.assertIn(b'nplurals=1; plural=0;', raw)


class ApiLanguageTests(TestCase):
    '''The API answers in the language the caller asks for.'''

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('i18n-owner', password='pw-i18n-123')

    def post(self, url, payload, language=None):
        extra = {'HTTP_ACCEPT_LANGUAGE': language} if language else {}
        return self.client.post(url, payload, content_type='application/json', **extra)

    def test_english_is_the_default(self):
        response = self.post('/api/login/', {'username': 'i18n-owner', 'password': 'wrong'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['errors'], ['Invalid username or password.'])

    def test_chinese_when_accept_language_asks_for_it(self):
        response = self.post('/api/login/', {'username': 'i18n-owner', 'password': 'wrong'},
                             language='zh-hans')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['errors'], ['用户名或密码不正确。'])

    def test_a_region_tag_still_selects_the_chinese_catalogue(self):
        '''`zh-CN` from a browser must land on the zh_Hans catalogue.'''
        response = self.post('/api/login/', {'username': 'i18n-owner', 'password': 'wrong'},
                             language='zh-CN,zh;q=0.9,en;q=0.5')
        self.assertEqual(response.json()['errors'], ['用户名或密码不正确。'])

    def test_an_unsupported_language_falls_back_to_english(self):
        response = self.post('/api/login/', {'username': 'i18n-owner', 'password': 'wrong'},
                             language='de-DE')
        self.assertEqual(response.json()['errors'], ['Invalid username or password.'])


class ValidationErrorShapeTests(TestCase):
    '''
    Field errors travel as a field-name map.

    The interface attaches a message to the input it came from, which only works
    if the key is the form field's name: a client that matched on the label
    would break the moment the label was translated.
    '''

    @classmethod
    def setUpTestData(cls):
        ca = CertificateAuthority()
        cls.user = User.objects.create_user('i18n-form', password='pw-form-123')
        root = ca.create_root_certificate('I18N Root CA', 3650)
        cls.root = RootCertificate.objects.create(
            name='I18N Root CA', serial_number=str(root['serial_number']),
            public_key=root['public_key'], private_key_encrypted='',
            valid_until=root['valid_until'], created_by=cls.user)
        intermediate = ca.create_intermediate_certificate(
            'I18N Intermediate CA', 1825, cls.root.public_key, root['private_key'])
        cls.intermediate = IntermediateCertificate.objects.create(
            name='I18N Intermediate CA',
            serial_number=str(intermediate['serial_number']),
            public_key=intermediate['public_key'], private_key_encrypted='',
            valid_until=intermediate['valid_until'],
            signed_by_root=cls.root, created_by=cls.user)

    def test_a_missing_common_name_is_keyed_by_field_name(self):
        self.client.login(username='i18n-form', password='pw-form-123')
        response = self.client.post('/api/certificates/create/leaf/', {
            'common_name': '', 'san': 'a.internal',
            'validity_days': '30', 'intermediate_id': str(self.intermediate.id)},
            content_type='application/json')
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertIn('common_name', payload['field_errors'])
        self.assertTrue(payload['field_errors']['common_name'])

    def test_the_readable_list_keeps_its_label_prefix(self):
        self.client.login(username='i18n-form', password='pw-form-123')
        response = self.client.post('/api/certificates/create/leaf/', {
            'common_name': '', 'san': 'a.internal',
            'validity_days': '30', 'intermediate_id': str(self.intermediate.id)},
            content_type='application/json')
        # For a human reading the response by hand; the SPA uses field_errors.
        self.assertTrue(any(': ' in message for message in response.json()['errors']))

    def test_field_names_are_stable_across_languages(self):
        '''The key is the field name, so it must not change with the locale.'''
        self.client.login(username='i18n-form', password='pw-form-123')
        keys = set()
        for language in (None, 'zh-hans'):
            extra = {'HTTP_ACCEPT_LANGUAGE': language} if language else {}
            response = self.client.post('/api/certificates/create/leaf/', {
                'common_name': '', 'san': '', 'validity_days': '30',
                'intermediate_id': str(self.intermediate.id)},
                content_type='application/json', **extra)
            keys.add(tuple(sorted(response.json()['field_errors'])))
        self.assertEqual(len(keys), 1, f'field names differ per language: {keys}')


class ServerAuthoredTextTests(TestCase):
    '''Model labels that the interface renders are translated too.'''

    def test_revocation_reasons_follow_the_request_language(self):
        response = self.client.get('/api/meta/', HTTP_ACCEPT_LANGUAGE='zh-hans')
        labels = {item['value']: item['label'] for item in response.json()['revocation_reasons']}
        self.assertEqual(labels['key_compromise'], '私钥泄露')
        self.assertEqual(labels['unspecified'], '未指定')

        response = self.client.get('/api/meta/')
        labels = {item['value']: item['label'] for item in response.json()['revocation_reasons']}
        self.assertEqual(labels['key_compromise'], 'Key compromise')

    def test_revocation_reason_values_are_never_translated(self):
        '''
        The value is stored in the database and matched against RFC 5280; only
        the label is interface copy.
        '''
        response = self.client.get('/api/meta/', HTTP_ACCEPT_LANGUAGE='zh-hans')
        values = [item['value'] for item in response.json()['revocation_reasons']]
        self.assertIn('key_compromise', values)
        self.assertEqual(
            sorted(values),
            sorted(RevokedCertificate.RevocationReason.values))
