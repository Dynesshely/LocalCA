"""
The keystore: named credentials, and the private keys they wrap.
"""

from django.db import transaction
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET, require_POST
from ..keys import (
    KeyUnavailable,
    change_credential_password,
    create_credential,
    credential_key_count,
    credentials_for,
    default_credential,
    get_credential,
    key_status,
    keystore_report,
    lock_credential,
    move_to_credential,
    set_default_credential,
    unlock_credential,
    wrap_legacy_keys,
)
from ..models import AuditLog, VaultCredential
from ..vault import VaultError, VaultLocked, VaultPasswordError, unsealed
from .common import CERTIFICATE_KINDS, _error, _ok, _payload, certificate_display_name


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
    model = CERTIFICATE_KINDS.get(kind)
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
        details=(f'Encrypted the private key of {kind} "{certificate_display_name(cert)}" '
                 f'with keystore credential "{credential.name}"'))
    return _ok({'key': _key_to_dict(cert, kind, credential)})
