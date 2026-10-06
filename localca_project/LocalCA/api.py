"""
JSON API for the LocalCA single-page frontend.

Django no longer renders application pages: it authenticates (session cookie +
CSRF) and serves data. Every endpoint returns JSON except the download
endpoints, which stream certificate material.

Authority rules, unchanged from the template era and covered by the test suite:

* reading the certificate tree: public (no private key material is exposed)
* creating a certificate: any authenticated user, but the signing CA must be
  one they own
* revoking / deleting: the owner of that certificate, or staff
* private key and PKCS12 downloads: the owner only
"""
import json
from urllib.parse import quote

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, transaction
from django.http import Http404, JsonResponse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs7,
)
from cryptography import x509

from .ca import CertificateAuthority
from .forms import (
    IntermediateCertificateForm,
    LeafCertificateForm,
    RevokeForm,
    RootCertificateForm,
)
from .keys import (
    KIND_LABELS,
    KeyUnavailable,
    change_credential_password,
    create_credential,
    credential_key_count,
    credential_root_key,
    credentials_for,
    default_credential,
    get_credential,
    is_legacy_plaintext,
    is_wrapped,
    issuers_with_key,
    key_status,
    keystore_report,
    lock_credential,
    move_to_credential,
    private_key_pem,
    set_default_credential,
    store_wrapped_key,
    unlock_credential,
    wrap_legacy_keys,
)
from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
    VaultCredential,
)
from . import import_service, importers, throttle
from .serializers import (
    intermediate_to_dict,
    leaf_to_dict,
    revocation_reasons,
    root_to_dict,
    user_to_dict,
)
from .vault import (
    VaultError,
    VaultLocked,
    VaultPasswordError,
    unsealed,
)


#: Certificate kinds addressable through the management endpoints. A whitelist:
#: the value is never used to build an import path.
CERTIFICATE_KINDS = {
    'root': RootCertificate,
    'intermediate': IntermediateCertificate,
    'leaf': LeafCertificate,
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _error(message, status=400, **extra):
    payload = {'ok': False, 'errors': [message] if isinstance(message, str) else message}
    payload.update(extra)
    return JsonResponse(payload, status=status)


def _payload(request):
    """
    Request data as a dict, whichever way the client encoded it.

    The Vue client sends JSON, but Django's form classes bind from
    ``request.POST`` (which is empty for a JSON body) and HTML forms post
    urlencoded data. Accepting both keeps the endpoints usable from either
    side, and the API, not the caller, owns this detail.
    """
    if request.content_type and 'application/json' in request.content_type:
        try:
            data = json.loads(request.body or b'{}')
        except (ValueError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}
    return request.POST


def _form_errors(form):
    '''
    Flatten a bound form's errors into a list of readable strings.

    The ``Label: message`` shape is for a human reading a response by hand. The
    SPA does not parse it: labels are translated, so a client that matched on
    them would break the moment the UI switched language. It reads
    :func:`_form_field_errors` instead.
    '''
    messages = []
    for field, errors in form.errors.items():
        for error in errors:
            if field == '__all__':
                messages.append(str(error))
            else:
                messages.append(f'{form.fields[field].label or field}: {error}')
    return messages or [_('The submitted data was not valid.')]


def _form_field_errors(form):
    '''
    A bound form's errors keyed by *field name* (``common_name``), not by label.

    Field names are stable identifiers from the form definition, so the SPA can
    attach a message to the input it came from without knowing either the
    language or the wording.
    '''
    return {field: [str(error) for error in errors]
            for field, errors in form.errors.items()}


def _form_error_response(form):
    '''400 carrying both the readable list and the per-field map.'''
    return _error(_form_errors(form), field_errors=_form_field_errors(form))


def _ok(payload=None, status=200):
    body = {'ok': True}
    body.update(payload or {})
    return JsonResponse(body, status=status)


def certificate_display_name(cert):
    '''Human readable name for any certificate kind.'''
    if isinstance(cert, LeafCertificate):
        return cert.common_name
    return cert.name


def is_owner(user, cert):
    '''
    Whether ``user`` owns ``cert``.

    Compares primary keys, never model instances: ``AnonymousUser`` and a NULL
    ``created_by`` must both fail, independent of lazy-object comparison.
    '''
    return (user.is_authenticated
            and cert.created_by_id is not None
            and cert.created_by_id == user.id)


def can_manage_certificate(user, cert):
    '''Owners manage their own certificates; staff manage any.'''
    if not user.is_authenticated:
        return False
    if user.is_staff:
        return True
    return is_owner(user, cert)


def _revocation_field(cert_type):
    '''Name of the RevokedCertificate field pointing at ``cert_type``.'''
    return {
        'root': 'root_certificate',
        'intermediate': 'intermediate_certificate',
    }.get(cert_type, 'certificate')


def child_certificates(cert):
    '''Certificates signed by ``cert`` (roots sign intermediates, and so on).'''
    if isinstance(cert, RootCertificate):
        return list(IntermediateCertificate.objects.filter(signed_by_root=cert))
    if isinstance(cert, IntermediateCertificate):
        return list(LeafCertificate.objects.filter(signed_by_intermediate=cert))
    return []


def _descendant_counts():
    '''Map of (kind, id) to how many certificates a delete would cascade to.'''
    counts = {}
    for intermediate in IntermediateCertificate.objects.all():
        counts[('intermediate', intermediate.id)] = \
            LeafCertificate.objects.filter(signed_by_intermediate=intermediate).count()
    for root in RootCertificate.objects.all():
        counts[('root', root.id)] = \
            IntermediateCertificate.objects.filter(signed_by_root=root).count()
    return counts


def _revocations_by_kind():
    '''All revocations grouped by certificate kind, keyed by target id.'''
    revocations = list(RevokedCertificate.objects.select_related(
        'certificate', 'intermediate_certificate', 'root_certificate'))
    grouped = {'root': {}, 'intermediate': {}, 'leaf': {}}
    for kind, attr in (('root', 'root_certificate_id'),
                       ('intermediate', 'intermediate_certificate_id'),
                       ('leaf', 'certificate_id')):
        grouped[kind] = {getattr(rev, attr): rev for rev in revocations
                         if getattr(rev, attr) is not None}
    return grouped


def _attachment_disposition(filename):
    '''
    A Content-Disposition header that survives hostile filenames. Certificate
    names are user input, so quote the ASCII form and add the RFC 6266
    ``filename*`` form for anything outside ASCII.
    '''
    safe_ascii = ''.join(c for c in filename
                         if 32 <= ord(c) < 127 and c not in '"\\')
    header = f'attachment; filename="{safe_ascii}"'
    if safe_ascii != filename:
        header += f"; filename*=UTF-8''{quote(filename, safe='')}"
    return header


def _find_by_serial(serial_number):
    '''Locate a certificate of any kind by serial number.'''
    for model in (RootCertificate, IntermediateCertificate, LeafCertificate):
        cert = model.objects.filter(serial_number=serial_number).first()
        if cert is not None:
            return cert
    raise Http404('Certificate not found')


# --------------------------------------------------------------------------
# session / authentication
# --------------------------------------------------------------------------

@ensure_csrf_cookie
@require_GET
def api_session(request):
    '''
    Current session state. Also plants the CSRF cookie, so a freshly loaded SPA
    can immediately issue a login POST.
    '''
    return _ok({'user': user_to_dict(request.user)})


@require_POST
def api_login(request):
    '''
    Session login, rate limited per client address and per account.

    The limit is checked before authentication so a refused request costs no
    password hashing, and the counters are cleared only on success.
    '''
    payload = _payload(request)
    if not payload:
        return _error(_('Malformed request body.'))

    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    if not username or not password:
        return _error(_('Username and password are required.'))

    try:
        throttle.check_login_allowed(request, username)
    except throttle.LoginRateLimited as exc:
        response = _error(exc.reason, status=429)
        response['Retry-After'] = str(exc.retry_after)
        AuditLog.objects.create(
            action='ACCESS', performed_by=None,
            details=f'Login refused by rate limit for username: {username[:150]}')
        return response

    user = authenticate(request, username=username, password=password)
    if user is None:
        AuditLog.objects.create(
            action='ACCESS', performed_by=None,
            details=f'Failed login attempt for username: {username[:150]}')
        throttle.record_login_failure(request, username)
        return _error(_('Invalid username or password.'), status=401)

    throttle.record_login_success(request, username)
    auth_login(request, user)
    return _ok({'user': user_to_dict(user)})


@require_POST
def api_logout(request):
    auth_logout(request)
    return _ok()


@require_POST
def api_change_password(request):
    '''Change the signed-in user's password.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    form = PasswordChangeForm(request.user, _payload(request))
    if not form.is_valid():
        return _form_error_response(form)

    user = form.save()
    # Keep the current session valid after the password hash changes.
    update_session_auth_hash(request, user)
    AuditLog.objects.create(
        action='ACCESS', performed_by=user,
        details='Password changed')
    return _ok()


# --------------------------------------------------------------------------
# keystore (private key encryption)
# --------------------------------------------------------------------------

def _vault_locked(message, credential=None, **extra):
    '''
    The one shape a locked credential is reported in.

    ``credential_id``/``credential_name`` are what the interface needs in order to
    ask for the right password instead of guessing which credential to open. When
    the account has no credential at all, both are null and the caller is expected
    to offer to create one.
    '''
    return _error(message, status=409, vault_locked=True,
                  credential_id=credential.id if credential else None,
                  credential_name=credential.name if credential else None,
                  **extra)


def _credential_or_error(request, credential_id, *, required=True):
    '''This account's credential, or a response explaining why not.'''
    credential = get_credential(request.user, credential_id)
    if credential is None and not credential_id:
        credential = default_credential(request.user)
    if credential is None:
        if not required:
            return None, None
        return None, _vault_locked(_(
            'No keystore credential exists yet, so private keys cannot be '
            'stored. Create one (a name and a password) first.'))
    return credential, None


def _credential_to_dict(credential):
    return {
        'id': credential.id,
        'name': credential.name,
        'is_default': credential.is_default,
        'unlocked': unsealed.is_unsealed(credential.id),
        'unseal_remaining_seconds': unsealed.remaining_seconds(credential.id),
        'key_count': credential_key_count(credential),
    }


def _key_to_dict(cert, kind, credential=None):
    '''One row of the keystore's key inventory. Never key material.'''
    return {
        'kind': kind,
        'id': cert.pk,
        'name': cert.common_name if kind == 'leaf' else cert.name,
        'serial_number': str(cert.serial_number),
        'status': key_status(cert),
        'credential_id': credential.id if credential else None,
        'credential_name': credential.name if credential else None,
    }


def _cert_kinds():
    return (('root', RootCertificate),
            ('intermediate', IntermediateCertificate),
            ('leaf', LeafCertificate))


def _vault_payload(request):
    '''Read a vault password from either JSON or form encoding.'''
    data = _payload(request)
    return str(data.get('vault_password') or ''), data


@require_GET
def api_keystore(request):
    '''
    The keystore page: this account's credentials, and every key it owns with the
    state that key is in.

    Read-only, and it never returns key material -- only which credential wraps
    which certificate, and whether that credential is currently open.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    return _ok(keystore_report(request.user))


@require_POST
def api_keystore_create(request):
    '''Add a credential: a name, a password, and a fresh root key behind them.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    data = _payload(request)
    name = str(data.get('name') or '').strip()
    password = str(data.get('vault_password') or '')
    if not name:
        return _error(_('A credential name is required.'))
    if len(password) < 8:
        return _error(_('A vault password of at least 8 characters is required.'))
    if VaultCredential.objects.filter(user=request.user, name=name).exists():
        return _error(_('A credential with that name already exists.'))

    credential = create_credential(request.user, name, password)

    # An account that already had cleartext keys should not keep them just because
    # the operator picked a name and a password: this is the moment they can be
    # encrypted, and `manage.py rewrap_keys` remains for whatever fails here.
    encrypted = 0
    if str(data.get('encrypt_existing') or '').lower() in ('1', 'true', 'yes', 'on'):
        wrapped, _failures = wrap_legacy_keys(request.user.id, credential)
        encrypted = wrapped

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=(f'Created keystore credential "{name}"'
                 + (f'; encrypted {encrypted} existing private key(s)'
                    if encrypted else '')))
    return _ok({'credential': _credential_to_dict(credential),
                'encrypted_existing': encrypted}, status=201)


@require_POST
def api_keystore_unlock(request, credential_id):
    '''Open one credential with its own password.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    credential, error = _credential_or_error(request, credential_id)
    if error:
        return error

    password, _ignored = _vault_payload(request)
    if not password:
        return _error(_('A vault password is required.'))
    try:
        unlock_credential(credential, password)
    except VaultPasswordError:
        AuditLog.objects.create(
            action='ACCESS', performed_by=request.user,
            details=f'Failed unlock of keystore credential "{credential.name}"')
        return _error(_('The vault password is incorrect.'), status=403)
    except VaultError as exc:
        return _error(_('Could not open the credential: %(error)s') % {'error': exc})

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Opened keystore credential "{credential.name}"')
    return _ok({'credential': _credential_to_dict(credential)})


@require_POST
def api_keystore_lock(request, credential_id=None):
    '''Forget one credential's root key immediately, or all of them.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    if credential_id is None:
        for credential in credentials_for(request.user):
            lock_credential(credential)
        AuditLog.objects.create(
            action='ACCESS', performed_by=request.user,
            details='Locked every keystore credential')
        return _ok({'credentials': [_credential_to_dict(c)
                                    for c in credentials_for(request.user)]})

    credential, error = _credential_or_error(request, credential_id)
    if error:
        return error
    lock_credential(credential)
    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Locked keystore credential "{credential.name}"')
    return _ok({'credential': _credential_to_dict(credential)})


@require_POST
def api_keystore_password(request, credential_id):
    '''
    Change a credential's password.

    Only the wrapping changes; the stored private keys are untouched, which is
    why the envelope design exists.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    credential, error = _credential_or_error(request, credential_id)
    if error:
        return error

    data = _payload(request)
    old_password = str(data.get('old_password') or '')
    new_password = str(data.get('new_password') or '')
    if not old_password or not new_password:
        return _error(_('Both the current and the new vault password are required.'))
    if len(new_password) < 8:
        return _error(_('The new vault password must be at least 8 characters.'))

    try:
        change_credential_password(credential, old_password, new_password)
    except VaultPasswordError:
        return _error(_('The current vault password is incorrect.'), status=403)
    except VaultError as exc:
        return _error(_('Could not change the vault password: %(error)s')
                      % {'error': exc})

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Changed the password of keystore credential "{credential.name}"')
    return _ok({'credential': _credential_to_dict(credential)})


@require_POST
def api_keystore_rename(request, credential_id):
    '''Rename a credential. Purely cosmetic: the wrapping does not change.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    credential, error = _credential_or_error(request, credential_id)
    if error:
        return error

    name = str(_payload(request).get('name') or '').strip()
    if not name:
        return _error(_('A credential name is required.'))
    if VaultCredential.objects.filter(
            user=request.user, name=name).exclude(pk=credential.pk).exists():
        return _error(_('A credential with that name already exists.'))

    old_name = credential.name
    credential.name = name
    credential.save(update_fields=['name', 'updated_at'])
    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Renamed keystore credential "{old_name}" to "{name}"')
    return _ok({'credential': _credential_to_dict(credential)})


@require_POST
def api_keystore_default(request, credential_id):
    '''Choose which credential new private keys are wrapped with.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    credential, error = _credential_or_error(request, credential_id)
    if error:
        return error
    set_default_credential(credential)
    return _ok({'credential': _credential_to_dict(credential)})


@require_POST
def api_keystore_delete(request, credential_id):
    '''
    Delete a credential.

    Refused while keys still point at it: they would become undecryptable, and
    deleting the wrapping key is not something a button should be able to do by
    accident. Move the keys, or delete them, first.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    credential, error = _credential_or_error(request, credential_id)
    if error:
        return error

    in_use = credential_key_count(credential)
    if in_use:
        return _error(
            _('%(count)s private key(s) are still encrypted with "%(name)s". '
              'Move them to another credential first.')
            % {'count': in_use, 'name': credential.name}, status=409)

    name = credential.name
    was_default = credential.is_default
    with transaction.atomic():
        credential.delete()
        if was_default:
            replacement = credentials_for(request.user).first()
            if replacement is not None:
                set_default_credential(replacement)

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Deleted keystore credential "{name}"')
    return _ok({'deleted': True})


@require_POST
def api_keystore_assign(request):
    '''
    Encrypt one certificate's key with a credential.

    The keystore page's per-key action, and it covers both directions: a cleartext
    key is encrypted for the first time, and a wrapped key is moved between
    credentials. Either way the key is decrypted with whatever holds it now and
    re-encrypted with the target, so nothing is copied.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    data = _payload(request)
    credential, error = _credential_or_error(request, data.get('credential_id'))
    if error:
        return error

    kind = str(data.get('kind') or '')
    model = dict(_cert_kinds()).get(kind)
    if model is None:
        return _error(_('Unknown certificate kind.'), status=404)
    cert = model.objects.filter(pk=data.get('id'), created_by=request.user).first()
    if cert is None:
        return _error(_('Certificate not found.'), status=404)

    try:
        move_to_credential(cert, kind, credential)
    except VaultLocked as exc:
        return _vault_locked(str(exc), exc.credential)
    except KeyUnavailable as exc:
        return _error(str(exc), status=409)

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=(f'Encrypted the private key of {kind} "{_download_name(cert)}" '
                 f'with keystore credential "{credential.name}"'))
    return _ok({'key': _key_to_dict(cert, kind, credential)})


@require_GET
def api_meta(_request):
    '''Static metadata the UI needs: revocation reasons, validity bounds, import formats.'''
    from .forms import MAX_CA_VALIDITY_DAYS, MAX_LEAF_VALIDITY_DAYS

    return _ok({
        'revocation_reasons': revocation_reasons(),
        'max_validity_days': {
            'root': MAX_CA_VALIDITY_DAYS,
            'intermediate': MAX_CA_VALIDITY_DAYS,
            'leaf': MAX_LEAF_VALIDITY_DAYS,
        },
        # The SPA renders its download menu from this list, so a format the
        # server does not serve cannot be offered, and vice versa.
        'download_formats': download_formats(),
        'import_formats': {
            'supported': list(importers.SUPPORTED_FORMATS),
            'unsupported': list(importers.UNSUPPORTED_FORMATS),
            'limits': {
                'max_files': importers.MAX_FILES,
                'max_file_bytes': importers.MAX_FILE_BYTES,
                'max_total_bytes': importers.MAX_TOTAL_BYTES,
                'max_objects': importers.MAX_OBJECTS,
            },
        },
    })


# --------------------------------------------------------------------------
# read: certificate tree and creation options
# --------------------------------------------------------------------------

@require_GET
def api_certificates(request):
    '''
    The whole certificate hierarchy, with revocation state and filtered by what
    this user may see: public names, but only their own private-key affordances.
    '''
    revocations = _revocations_by_kind()
    counts = _descendant_counts()
    user = request.user

    tree = []
    for root in RootCertificate.objects.all().order_by('-created_at'):
        intermediates = []
        for intermediate in IntermediateCertificate.objects.filter(
                signed_by_root=root).order_by('-created_at'):
            leaves = [
                leaf_to_dict(leaf, user, revocations['leaf'].get(leaf.id))
                for leaf in LeafCertificate.objects.filter(
                    signed_by_intermediate=intermediate).order_by('-created_at')
            ]
            intermediates.append({
                'certificate': intermediate_to_dict(
                    intermediate, user, revocations['intermediate'].get(intermediate.id),
                    counts.get(('intermediate', intermediate.id), 0)),
                'leaves': leaves,
            })
        tree.append({
            'certificate': root_to_dict(
                root, user, revocations['root'].get(root.id),
                counts.get(('root', root.id), 0)),
            'intermediates': intermediates,
        })

    return _ok({'tree': tree})


@require_GET
def api_issuers(request):
    '''
    Certificate authorities the requesting user may sign with.

    Only their own, and only those that still have a private key: signing consumes
    that key, and a certificate imported without one cannot sign at all.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    roots = [root_to_dict(root, request.user)
             for root in issuers_with_key(RootCertificate, request.user)
             .order_by('-created_at')]
    intermediates = [intermediate_to_dict(intermediate, request.user)
                     for intermediate in issuers_with_key(
                         IntermediateCertificate, request.user).order_by('-created_at')]
    return _ok({'roots': roots, 'intermediates': intermediates})


@require_GET
def api_my_certificates(request):
    '''The certificates this user owns, for the management tables.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    revocations = _revocations_by_kind()
    user = request.user
    return _ok({
        'roots': [root_to_dict(root, user, revocations['root'].get(root.id))
                  for root in RootCertificate.objects.filter(
                      created_by=user).order_by('-created_at')],
        'intermediates': [
            intermediate_to_dict(intermediate, user,
                                 revocations['intermediate'].get(intermediate.id))
            for intermediate in IntermediateCertificate.objects.filter(
                created_by=user).order_by('-created_at')],
        'leaves': [leaf_to_dict(leaf, user, revocations['leaf'].get(leaf.id))
                   for leaf in LeafCertificate.objects.filter(
                       created_by=user).order_by('-created_at')],
    })


# --------------------------------------------------------------------------
# write: creation
# --------------------------------------------------------------------------

@require_POST
def api_create_certificate(request, cert_type):
    '''
    Create a root, intermediate or leaf certificate.

    The signing authority is restricted by the form's queryset, so a crafted
    request cannot consume another user's CA private key.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    ca = CertificateAuthority()

    def target_credential():
        '''
        Which credential the *new* key is wrapped with.

        Resolved after the form, so a request naming somebody else's issuing CA is
        still refused as a bad request rather than as a keystore problem. A
        request may name a credential; without one it is the account's default, and
        an account with none is asked to create one rather than silently writing a
        plaintext key.
        '''
        credential, error = _credential_or_error(
            request, _payload(request).get('credential_id'))
        if error:
            return None, error
        try:
            credential_root_key(credential)
        except VaultLocked as exc:
            return None, _vault_locked(
                _('The keystore credential "%(name)s" is locked. Open it to store '
                  'the private key that is about to be created.')
                % {'name': credential.name}, exc.credential)
        return credential, None

    # A root is self-signed, so creating one needs no stored key. Signing an
    # intermediate or a leaf consumes the issuer's private key, which requires
    # that key's own credential to be open.
    try:
        if cert_type == 'root':
            form = RootCertificateForm(_payload(request))
            if not form.is_valid():
                return _form_error_response(form)
            credential, error = target_credential()
            if error:
                return error
            name = form.cleaned_data['common_name']
            data = ca.create_root_certificate(name, form.cleaned_data['validity_days'])
            certificate = RootCertificate.objects.create(
                name=name,
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted='',
                valid_until=data['valid_until'],
                created_by=request.user,
            )
            store_wrapped_key(certificate, 'root', data['private_key'], credential)

        elif cert_type == 'intermediate':
            form = IntermediateCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _form_error_response(form)
            name = form.cleaned_data['common_name']
            root = form.cleaned_data['root_id']
            try:
                issuer_key = private_key_pem(root, 'root', request.user)
            except KeyUnavailable as exc:
                return _error(str(exc), status=409)
            except VaultLocked as exc:
                return _vault_locked(str(exc), exc.credential)
            credential, error = target_credential()
            if error:
                return error
            data = ca.create_intermediate_certificate(
                name, form.cleaned_data['validity_days'],
                root.public_key, issuer_key)
            certificate = IntermediateCertificate.objects.create(
                name=name,
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted='',
                signed_by_root=root,
                valid_until=data['valid_until'],
                created_by=request.user,
            )
            store_wrapped_key(certificate, 'intermediate', data['private_key'],
                              credential)

        elif cert_type == 'leaf':
            form = LeafCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _form_error_response(form)
            name = form.cleaned_data['common_name']
            intermediate = form.cleaned_data['intermediate_id']
            sans = form.san_list()
            try:
                issuer_key = private_key_pem(intermediate, 'intermediate', request.user)
            except KeyUnavailable as exc:
                return _error(str(exc), status=409)
            except VaultLocked as exc:
                return _vault_locked(str(exc), exc.credential)
            credential, error = target_credential()
            if error:
                return error
            data = ca.create_leaf_certificate(
                common_name=name,
                san_list=sans,
                validity_days=form.cleaned_data['validity_days'],
                intermediate_public_key=intermediate.public_key,
                intermediate_private_key=issuer_key,
            )
            certificate = LeafCertificate.objects.create(
                common_name=name,
                san=','.join(sans),
                valid_until=data['valid_until'],
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted='',
                signed_by_intermediate=intermediate,
                created_by=request.user,
            )
            store_wrapped_key(certificate, 'leaf', data['private_key'], credential)
        else:
            raise Http404('Unknown certificate kind')

    except ValueError as exc:
        return _error(_('Could not create the certificate: %(error)s') % {'error': exc})
    except IntegrityError:
        # Unique constraints on the name columns; the forms check first, so this
        # is a race between two concurrent submissions.
        return _error(_('A certificate with that name already exists.'))

    AuditLog.objects.create(
        action='CREATE', performed_by=request.user,
        details=f'Created {cert_type} certificate: {name}')

    return _ok({'certificate': {
        'kind': cert_type,
        'id': certificate.id,
        'name': name,
        'serial_number': certificate.serial_number,
        'valid_until': certificate.valid_until.isoformat(),
    }}, status=201)


# --------------------------------------------------------------------------
# write: revoke / delete
# --------------------------------------------------------------------------

@require_POST
def api_revoke_certificate(request, cert_type, cert_id):
    '''
    Revoke a certificate. The URL carries the target; the reason, comment and
    cascade flag come from the body, and the two must agree so a stale dialog
    cannot revoke the wrong object.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    model = CERTIFICATE_KINDS.get(cert_type)
    if model is None:
        raise Http404('Unknown certificate kind')

    form = RevokeForm(_payload(request))
    if not form.is_valid():
        return _form_error_response(form)
    if form.cleaned_data['type'] != cert_type or form.cleaned_data['id'] != cert_id:
        return _error(_('The request did not match the certificate it was sent for.'))

    with transaction.atomic():
        cert = get_object_or_404(model, id=cert_id)
        if not can_manage_certificate(request.user, cert):
            raise PermissionDenied(
                'You do not have permission to revoke this certificate')

        name = certificate_display_name(cert)
        field = _revocation_field(cert_type)
        if RevokedCertificate.objects.filter(**{field: cert}).exists():
            return _error(_('Certificate "%(name)s" is already revoked.')
                          % {'name': name},
                          status=409, already_revoked=True)

        RevokedCertificate.objects.create(
            created_by=request.user,
            reason=form.cleaned_data['reason'],
            comment=form.cleaned_data.get('comment', ''),
            **{field: cert},
        )

        cascaded = []
        if form.cleaned_data.get('cascade') and cert_type != 'leaf':
            for child in child_certificates(cert):
                child_name = certificate_display_name(child)
                child_field = ('intermediate_certificate'
                               if isinstance(child, IntermediateCertificate)
                               else 'certificate')
                # The discarded half must not be called `_`: that would shadow
                # gettext for the whole function body (Python scopes a name to
                # the entire function), and every `_('...')` in it would raise.
                _existing, created = RevokedCertificate.objects.get_or_create(
                    **{child_field: child},
                    defaults={
                        'created_by': request.user,
                        'reason': RevokedCertificate.RevocationReason.CA_COMPROMISE,
                        'comment': f'Signed by revoked {cert_type} "{name}".',
                    })
                if created:
                    cascaded.append(child_name)
                AuditLog.objects.create(
                    action='REVOKE', performed_by=request.user,
                    details=f'Revoked {child_name} (cascade from {cert_type} "{name}")')

        AuditLog.objects.create(
            action='REVOKE', performed_by=request.user,
            details=(f"Revoked {cert_type} certificate: {name} "
                     f"(reason: {form.cleaned_data['reason']}, cascaded: {len(cascaded)})"))

    return _ok({'revoked': name, 'cascaded': cascaded})


@require_POST
def api_delete_certificate(request, cert_type, cert_id):
    '''
    Delete a certificate and everything it signed.

    Destructive and irreversible: the private key material is removed. A
    certificate that still has children is recorded as revoked first, so the
    audit trail survives the cascade.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    model = CERTIFICATE_KINDS.get(cert_type)
    if model is None:
        raise Http404('Unknown certificate kind')

    with transaction.atomic():
        cert = get_object_or_404(model, id=cert_id)
        if not can_manage_certificate(request.user, cert):
            raise PermissionDenied(
                'You do not have permission to delete this certificate')

        name = certificate_display_name(cert)
        children = child_certificates(cert)
        field = _revocation_field(cert_type)

        if children and not RevokedCertificate.objects.filter(
                **{field: cert}).exists():
            RevokedCertificate.objects.create(
                created_by=request.user,
                reason=(RevokedCertificate.RevocationReason.CA_COMPROMISE
                        if cert_type != 'leaf'
                        else RevokedCertificate.RevocationReason.CESSATION_OF_OPERATION),
                comment='Deleted with dependent certificates.',
                **{field: cert})

        AuditLog.objects.create(
            action='DELETE', performed_by=request.user,
            details=(f'Deleted {cert_type} certificate: {name} '
                     f'(serial: {cert.serial_number}, cascaded: {len(children)})'))
        cert.delete()

    return _ok({'deleted': name, 'cascaded': len(children)})


# --------------------------------------------------------------------------
# downloads
# --------------------------------------------------------------------------

#: Everything that can be downloaded, and what each format asks of the caller.
#:
#: The interface builds its download menu from this table (served by
#: /api/meta/), so a format cannot exist in one place and not the other.
#:
#: ``access``:
#:   public  -- the certificate, or the chain built from public certificates.
#:              Anyone who can see the name may have the bytes; this is how a
#:              client fetches the CA it is meant to trust.
#:   private -- the response contains private key material.
#:
#: ``requires``:
#:   password -- an export password, so the key is never written unprotected.
#:   confirm  -- the caller must say outright that it wants the *unprotected*
#:               form. A stray link or an accidental GET cannot produce one.
#:
#: Deliberate: the unprotected formats exist because real servers need them
#: (nginx cannot read a passphrase-protected key), and refusing them just moves
#: the same bytes through `openssl pkcs12 -nodes` on the operator's laptop. What
#: the guards buy is that it is never accidental, always authenticated, always
#: the owner's own key, and always in the audit log.
DOWNLOAD_FORMATS = (
    {'id': 'pem', 'access': 'public'},
    {'id': 'der', 'access': 'public'},
    {'id': 'chain', 'access': 'public'},
    {'id': 'p7b', 'access': 'public'},
    {'id': 'pkcs12', 'access': 'private', 'requires': 'password'},
    {'id': 'key', 'access': 'private', 'requires': 'password'},
    {'id': 'key-plain', 'access': 'private', 'requires': 'confirm'},
    {'id': 'pair-zip', 'access': 'private', 'requires': 'confirm'},
)

_DOWNLOAD_BY_ID = {spec['id']: spec for spec in DOWNLOAD_FORMATS}


def download_formats():
    '''The download menu, as the interface needs it.'''
    return [dict(spec) for spec in DOWNLOAD_FORMATS]


def _download_name(cert):
    '''The name a downloaded file is based on.'''
    return cert.common_name if isinstance(cert, LeafCertificate) else cert.name


def _download_kind(cert):
    return ('root' if isinstance(cert, RootCertificate)
            else 'intermediate' if isinstance(cert, IntermediateCertificate)
            else 'leaf')


def _chain_certificates(cert):
    '''``cert`` followed by every issuer, root last.'''
    chain = [cert]
    if isinstance(cert, LeafCertificate):
        intermediate = cert.signed_by_intermediate
        chain += [intermediate, intermediate.signed_by_root]
    elif isinstance(cert, IntermediateCertificate):
        chain.append(cert.signed_by_root)
    return chain


def _file_response(content, filename, content_type, cacheable=False):
    '''An attachment that a browser will not cache or sniff.'''
    from django.http import HttpResponse

    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = _attachment_disposition(filename)
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = ('public, max-age=300' if cacheable else 'no-store')
    return response


def _audit_download(request, cert, action, note):
    AuditLog.objects.create(
        action=action, performed_by=request.user if request.user.is_authenticated else None,
        details=(f'Downloaded {note} for: {certificate_display_name(cert)} '
                 f'(serial: {cert.serial_number})'))


def api_download(request, serial_number, download_format):
    '''
    Download a certificate, its chain, or its private key in a named format.

    One endpoint rather than one per format, because the format table above is
    the single place that decides which of them are public and what the private
    ones need; a second route would let those two views drift.
    '''
    spec = _DOWNLOAD_BY_ID.get(download_format)
    if spec is None:
        return api_not_found(request)

    try:
        cert = _find_by_serial(serial_number)
    except Http404:
        return api_not_found(request)

    if spec['access'] == 'public':
        return _download_public(request, cert, spec)
    return _download_private(request, cert, spec)


def _download_public(request, cert, spec):
    '''
    Certificate material that is not secret.

    Unauthenticated on purpose, and unchanged in that respect: these bytes are
    handed to every client that has to trust this CA.
    '''
    name = _download_name(cert)
    fmt = spec['id']

    if fmt == 'pem':
        content = cert.public_key
        filename, content_type = f'{name}.pem', 'application/x-pem-file'
        note = 'public certificate'
    elif fmt == 'der':
        content = x509.load_pem_x509_certificate(cert.public_key.encode()).public_bytes(
            Encoding.DER)
        filename, content_type = f'{name}.der', 'application/pkix-cert'
        note = 'public certificate (DER)'
    elif fmt == 'chain':
        content = ''.join(node.public_key for node in _chain_certificates(cert))
        filename, content_type = f'{name}-chain.pem', 'application/x-pem-file'
        note = 'certificate chain'
    elif fmt == 'p7b':
        content = pkcs7.serialize_certificates(
            [x509.load_pem_x509_certificate(node.public_key.encode())
             for node in _chain_certificates(cert)],
            Encoding.DER)
        filename, content_type = f'{name}-chain.p7b', 'application/pkcs7-mime'
        note = 'certificate chain (PKCS#7)'
    else:  # pragma: no cover - the table above is the only source of formats
        raise Http404('Unknown public download format')

    _audit_download(request, cert, 'DOWNLOAD_PUBLIC_KEY', note)
    return _file_response(content, filename, content_type, cacheable=True)


def _download_private(request, cert, spec):
    '''
    Private key material: owner or staff, an open vault, and a stated intent.

    Every path here calls :func:`private_key_pem`, which needs the vault to be
    unsealed, so a locked vault is a 409 with ``vault_locked`` and the interface
    can offer to unlock rather than showing a dead end.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    if not can_manage_certificate(request.user, cert):
        # A JSON refusal, not Django's HTML 403 page: the client can then show the
        # sentence instead of "download failed with status 403".
        return _error(
            _('You can only export the private key of a certificate you own.'),
            status=403)
    if not is_owner(request.user, cert) and is_wrapped(cert):
        # Staff may revoke and delete somebody else's certificate, but they can
        # never read its key: the vault root key is per account and there is no
        # escrow, so unwrapping with the *caller's* root key can only fail. Say
        # that, instead of surfacing "ciphertext failed authentication", which
        # reads like corruption rather than a permission boundary.
        #
        # Only wrapped keys: a legacy plaintext key needs no vault at all, so the
        # old rule -- owner, or staff -- still applies to it.
        return _error(
            _("This certificate belongs to another account. Its private key is "
              "wrapped with that account's vault password, so nobody else, "
              "including an administrator, can export it."),
            status=409)

    name = _download_name(cert)
    kind = _download_kind(cert)
    payload = _payload(request)

    if spec['id'] == 'pkcs12':
        password = str(payload.get('p12_password') or '').strip()
        if len(password) < 8:
            return _error(
                _('An export password of at least 8 characters is required: the '
                  'bundle contains a private key and is never written unencrypted.'),
                status=400)
    elif spec['requires'] == 'password':
        password = str(payload.get('key_password') or '').strip()
        if len(password) < 8:
            return _error(
                _('An export password of at least 8 characters is required: the '
                  'key is never written unencrypted without one.'),
                status=400)
    else:
        # `confirm` formats: the response *is* the unprotected key, so the caller
        # has to say so explicitly. Anything else is a 400, never a silent export.
        if str(payload.get('confirm') or '').lower() not in ('1', 'true', 'yes', 'on'):
            return _error(
                _('Exporting an unprotected private key has to be confirmed: '
                  'resend with confirm=true, or choose a password-protected '
                  'format instead.'),
                status=400)
        password = None

    try:
        key_pem = private_key_pem(cert, kind, request.user)
    except VaultLocked as exc:
        return _vault_locked(
            _('The keystore credential "%(name)s" is locked. Open it to export '
              'this private key.')
            % {'name': exc.credential.name if exc.credential else '?'},
            exc.credential)
    except KeyUnavailable as exc:
        return _error(str(exc), status=409)

    if spec['id'] == 'pkcs12':
        intermediate = (cert.signed_by_intermediate
                        if isinstance(cert, LeafCertificate) else None)
        bundle = CertificateAuthority().create_pkcs12(
            cert_pem=cert.public_key,
            private_key_pem=key_pem,
            ca_cert_pem=intermediate.public_key if intermediate else None,
            friendly_name=name,
            password=password,
        )
        _audit_download(request, cert, 'DOWNLOAD_PKCS12',
                        'PKCS12 bundle (encrypted)')
        return _file_response(bundle, f'{name}.p12', 'application/x-pkcs12')

    # Everything below re-encodes or packages the same key.
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)

    if spec['id'] == 'key':
        content = key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8,
            BestAvailableEncryption(password.encode()))
        _audit_download(request, cert, 'DOWNLOAD_PRIVATE_KEY',
                        'private key (PKCS#8, encrypted)')
        return _file_response(content, f'{name}.key', 'application/x-pem-file')

    plain = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    if spec['id'] == 'key-plain':
        _audit_download(request, cert, 'DOWNLOAD_PRIVATE_KEY',
                        'private key (PKCS#8, UNENCRYPTED)')
        return _file_response(plain, f'{name}.key', 'application/x-pem-file')

    # pair-zip: what an operator actually pastes onto a web server. The chain is
    # included because that is the file nginx and apache are pointed at too.
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f'{name}.crt', cert.public_key)
        archive.writestr(f'{name}.key', plain)
        archive.writestr(
            'chain.pem',
            ''.join(node.public_key for node in _chain_certificates(cert)[1:]))
        archive.writestr(
            'README.txt',
            f'{name}\n\n'
            f'{name}.crt  the certificate\n'
            f'{name}.key  its private key, NOT encrypted — keep it readable only '
            f'by the service that uses it\n'
            f'chain.pem   the issuing certificates, if the service wants a chain\n\n'
            f'Downloaded from LocalCA on {timezone.now().isoformat()}\n')
    _audit_download(request, cert, 'DOWNLOAD_PRIVATE_KEY',
                    'certificate and UNENCRYPTED private key (ZIP)')
    return _file_response(buffer.getvalue(), f'{name}-pair.zip', 'application/zip')


# NOTE: the unprotected formats above exist because the operator asked for them
# and because the alternative is `openssl pkcs12 -nodes` on a laptop, which is
# strictly worse: no authentication, no ownership check, no audit entry. What is
# deliberately still absent is any *unauthenticated* path to a private key, and
# any that writes one to disk without being asked for it in so many words.


# --------------------------------------------------------------------------
# single-page app shell
# --------------------------------------------------------------------------

@ensure_csrf_cookie
@require_GET
def spa_index(_request, **_ignored):
    '''
    Serve the built Vue shell.

    The SPA is server-routed to a single template so that deep links such as
    /create/leaf work; the client router takes over from there. The CSRF cookie
    is planted here so the app can issue state-changing requests immediately
    after load, including the login POST.
    '''
    from django.shortcuts import render

    return render(_request, 'index.html')


@require_GET
def api_not_found(_request, **_ignored):
    """
    JSON 404 for unmatched /api/ paths.

    Without this the SPA catch-all would answer with an HTML 200, which makes a
    mistyped or removed endpoint look successful to an API client. Kept free of
    authentication so it cannot be used to probe for existing routes.
    """
    from django.http import JsonResponse as _JsonResponse

    return _JsonResponse(
        {'ok': False, 'errors': ['No such API endpoint.']}, status=404)


# --------------------------------------------------------------------------
# write: certificate import
# --------------------------------------------------------------------------

@require_POST
def api_import_certificates(request):
    '''
    Import certificates from an uploaded bundle, in two steps.

    ``dry_run=1`` returns the plan -- what would be created, skipped or refused --
    and writes nothing. The client then re-uploads the same files with
    ``dry_run=0`` to commit. Nothing is staged between the two calls, so no
    uploaded key material outlives a request.

    Files are parsed in memory. A private key that came with its certificate is
    wrapped by the vault, exactly like a generated one, which is why an import
    that carries a key needs the vault to be open (409 ``vault_locked``, the same
    signal the SPA already handles for signing). Certificates imported without a
    key are stored as inventory and cannot sign or export a PKCS#12.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    uploads = request.FILES.getlist('files')
    if not uploads:
        return _error(_('Attach at least one file to import.'))

    password = (request.POST.get('password') or '').strip() or None
    dry_run = str(request.POST.get('dry_run', '0')).strip().lower() in (
        '1', 'true', 'yes', 'on')

    try:
        overrides = json.loads(request.POST.get('overrides') or '{}')
    except (TypeError, ValueError):
        return _error(_('The overrides field must be a JSON object.'))
    if not isinstance(overrides, dict):
        return _error(_('The overrides field must be a JSON object.'))

    try:
        bundle = importers.parse_uploads(uploads, password=password)
    except importers.ImportError as exc:
        return _error(str(exc))

    plan = import_service.plan_import(bundle, request.user, overrides=overrides)
    payload = {
        'plan': plan.to_dict(),
        'formats': {
            'supported': list(importers.SUPPORTED_FORMATS),
            'unsupported': list(importers.UNSUPPORTED_FORMATS),
        },
    }

    if dry_run:
        return _ok({'dry_run': True, **payload})

    credential = None
    if plan.requires_vault_unlock:
        # The same rule as creating a certificate: an import that carries keys has
        # to say which credential wraps them, and an account with none is asked to
        # create one rather than dropping the keys on the floor.
        credential, error = _credential_or_error(request, overrides.get('credential_id')
                                                or _payload(request).get('credential_id'))
        if error:
            return error
        if not unsealed.is_unsealed(credential.id):
            return _vault_locked(
                _('The keystore credential "%(name)s" is locked. Open it to store '
                  'the private keys carried by this import.')
                % {'name': credential.name}, credential)

    result = import_service.apply_plan(plan, request.user, credential)
    AuditLog.objects.create(
        action='IMPORT',
        performed_by=request.user,
        details=(f'Import finished: {result["created"]["root"]} root, '
                 f'{result["created"]["intermediate"]} intermediate, '
                 f'{result["created"]["leaf"]} leaf created; '
                 f'{result["keys_wrapped"]} key(s) wrapped, '
                 f'{result["keys_attached"]} attached; '
                 f'{len(result["failed"])} failed.'))
    return _ok({'dry_run': False, 'result': result, **payload})


# --------------------------------------------------------------------------
# audit log (staff only)
# --------------------------------------------------------------------------

@require_GET
def api_audit_log(request):
    '''Recent audit entries. Staff only: it exposes other users' activity.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    if not request.user.is_staff:
        raise PermissionDenied('Staff access required')

    limit = min(int(request.GET.get('limit', 100)), 500)
    entries = AuditLog.objects.select_related('performed_by').order_by('-timestamp')[:limit]
    return _ok({'entries': [{
        'id': entry.id,
        'action': entry.action,
        'performed_by': entry.performed_by.username if entry.performed_by_id else None,
        'timestamp': entry.timestamp.isoformat(),
        'details': entry.details,
    } for entry in entries]})
