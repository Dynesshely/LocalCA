"""
Access helpers for vault-wrapped private keys.

Keeps the "is this key encrypted, with which credential, and is that credential
open?" decision in one place so the API layer cannot accidentally read the legacy
plaintext column without noticing that it is doing so.

A *credential* is a named password plus the root key it wraps. An account may
hold several; every stored private key points at the one that wraps it, so
locking (or losing) one credential never touches keys under another.
"""
from django.db import transaction
from django.utils.translation import gettext as _

from .models import VaultCredential
from .vault import (
    VaultError,
    VaultLocked,
    VaultPasswordError,
    decrypt_private_key,
    encrypt_private_key,
    new_root_key,
    unsealed,
    unwrap_root_key,
    wrap_root_key,
)

#: Certificate kind -> model attribute holding the wrapped key / the credential.
WRAPPED_FIELD = 'private_key_wrapped'
CREDENTIAL_FIELD = 'key_credential'

#: Human-facing names used in errors and the status report.
KIND_LABELS = {
    'root': 'root CA',
    'intermediate': 'intermediate CA',
    'leaf': 'leaf certificate',
}


class KeyUnavailable(VaultError):
    '''The private key exists but cannot be produced right now.'''


def _serial(cert) -> str:
    return str(cert.serial_number)


def _kinds():
    '''
    ``((kind, model), ...)``.

    Imported lazily so this module stays importable from migrations.
    '''
    from .models import (
        IntermediateCertificate,
        LeafCertificate,
        RootCertificate,
    )
    return (('root', RootCertificate),
            ('intermediate', IntermediateCertificate),
            ('leaf', LeafCertificate))


def is_wrapped(cert) -> bool:
    '''Whether this certificate's private key is stored encrypted.'''
    return bool(getattr(cert, WRAPPED_FIELD, None))


def is_legacy_plaintext(cert) -> bool:
    '''
    Whether this certificate still has its key in the legacy plaintext column.

    Such a key predates the keystore (or belongs to a certificate with no owner,
    so it has no credential to derive from). Callers must surface this rather than
    pretend it is protected.
    '''
    return not is_wrapped(cert) and bool(cert.private_key_encrypted)


def credential_of(cert):
    '''
    The credential wrapping this certificate's key, or None.

    A wrapped key whose owner was deleted keeps its ciphertext but loses the
    credential, and nothing can unwrap it any more; that is reported as such
    rather than as "encrypted".
    '''
    return getattr(cert, 'key_credential', None)


def encrypt_for_storage(root_key: bytes, cert, kind: str, pem: str) -> str:
    '''Produce the stored envelope for a newly generated private key.'''
    return encrypt_private_key(
        root_key, kind=kind, cert_id=cert.pk, serial=_serial(cert),
        private_key_pem=pem)


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------

def credentials_for(user):
    '''This account's credentials, oldest first (the default, in practice).'''
    return VaultCredential.objects.filter(user=user).order_by('created_at', 'id')


def default_credential(user):
    '''The credential new keys go to, or None when none is configured yet.'''
    return (VaultCredential.objects.filter(user=user, is_default=True).first()
            or credentials_for(user).first())


def get_credential(user, credential_id):
    '''One of *this account's* credentials, or None. Never another account's.'''
    if not credential_id:
        return None
    return VaultCredential.objects.filter(user=user, pk=credential_id).first()


def create_credential(user, name: str, password: str) -> VaultCredential:
    '''
    Make a new credential: a fresh root key, wrapped with ``password``.

    The first credential of an account becomes its default, so a new key has
    somewhere to go without the caller having to choose.
    '''
    name = (name or '').strip() or _('Default')
    if not password:
        raise VaultPasswordError(_('A vault password is required.'))
    root_key = new_root_key()
    with transaction.atomic():
        credential = VaultCredential.objects.create(
            user=user, name=name,
            wrapped_root_key=wrap_root_key(root_key, password),
            is_default=not VaultCredential.objects.filter(user=user).exists(),
        )
    unsealed.unseal(credential.id, password, root_key)
    return credential


def unlock_credential(credential: VaultCredential, password: str) -> bytes:
    '''
    Open a credential with its password, and keep the root key in memory.

    The password is only used to unwrap the stored root key; neither it nor the
    root key is written to the session, a cookie or the database.
    '''
    root_key = unwrap_root_key(credential.wrapped_root_key, password)
    unsealed.unseal(credential.id, password, root_key)
    return root_key


def credential_root_key(credential: VaultCredential) -> bytes:
    '''The unsealed root key of a credential, or raise VaultLocked.'''
    try:
        return unsealed.get(credential.id)
    except VaultLocked as exc:
        raise VaultLocked(
            _('The keystore credential "%(name)s" is locked.')
            % {'name': credential.name},
            credential=credential) from exc


def change_credential_password(credential: VaultCredential, old_password: str,
                               new_password: str) -> None:
    '''
    Change a credential's password.

    Only the root key is re-wrapped; the private keys themselves are untouched,
    which is the point of the envelope design.
    '''
    root_key = unwrap_root_key(credential.wrapped_root_key, old_password)
    credential.wrapped_root_key = wrap_root_key(root_key, new_password)
    credential.save(update_fields=['wrapped_root_key', 'updated_at'])
    unsealed.unseal(credential.id, new_password, root_key)


def lock_credential(credential: VaultCredential) -> None:
    unsealed.lock(credential.id)


def set_default_credential(credential: VaultCredential) -> None:
    '''Make ``credential`` the one new keys are wrapped with.'''
    with transaction.atomic():
        VaultCredential.objects.filter(
            user_id=credential.user_id, is_default=True).update(is_default=False)
        credential.is_default = True
        credential.save(update_fields=['is_default'])


def credential_key_count(credential: VaultCredential) -> int:
    '''How many stored private keys this credential wraps.'''
    total = 0
    for _kind, model in _kinds():
        total += model.objects.filter(key_credential=credential).count()
    return total


# --------------------------------------------------------------------------
# one certificate's key
# --------------------------------------------------------------------------

def private_key_pem(cert, kind: str, user) -> str:
    '''
    The decrypted private key for a certificate.

    An encrypted certificate needs the credential that wraps it to be unlocked.
    Legacy plaintext keys are returned with no keystore involvement, because
    there is nothing to unwrap. The caller is responsible for having checked that
    ``user`` may use this key.
    '''
    if is_wrapped(cert):
        credential = credential_of(cert)
        if credential is None:
            raise KeyUnavailable(_(
                'This private key is no longer linked to a credential, so '
                'nothing can unwrap it.'))
        root_key = credential_root_key(credential)
        try:
            return decrypt_private_key(
                root_key, kind=kind, cert_id=cert.pk, serial=_serial(cert),
                blob=cert.private_key_wrapped)
        except VaultError as exc:
            raise KeyUnavailable(str(exc)) from exc
    if cert.private_key_encrypted:
        return cert.private_key_encrypted
    raise KeyUnavailable(_('This certificate has no stored private key.'))


def store_wrapped_key(cert, kind: str, pem: str, credential: VaultCredential) -> None:
    '''
    Persist a private key under ``credential`` and clear the plaintext column.

    Both happen in one transaction so a failure cannot leave a certificate with
    no readable key at all.
    '''
    root_key = credential_root_key(credential)
    wrapped = encrypt_for_storage(root_key, cert, kind, pem)
    with transaction.atomic():
        cert.private_key_wrapped = wrapped
        cert.private_key_encrypted = ''
        cert.key_credential = credential
        cert.save(update_fields=['private_key_wrapped', 'private_key_encrypted',
                                 'key_credential'])


def pending_legacy_keys(user_id: int):
    '''``(kind, cert)`` for every plaintext key this account still owns.'''
    pairs = []
    for kind, model in _kinds():
        rows = (model.objects
                .filter(created_by_id=user_id, private_key_wrapped__isnull=True)
                .exclude(private_key_encrypted=''))
        pairs.extend((kind, cert) for cert in rows)
    return pairs


def wrap_legacy_keys(user_id: int, credential: VaultCredential):
    '''
    Encrypt every plaintext key this account owns under ``credential``.

    Returns `(wrapped_count, failures)`, where a failure is a
    `(kind, certificate, exception)` triple. A row that cannot be wrapped is
    reported rather than raised -- one unreadable certificate must not fail the
    action that triggered the sweep, and `manage.py rewrap_keys` retries.
    '''
    wrapped, failures = 0, []
    for kind, cert in pending_legacy_keys(user_id):
        try:
            store_wrapped_key(cert, kind, cert.private_key_encrypted, credential)
            wrapped += 1
        except Exception as exc:  # noqa: BLE001 - reported by the caller, never fatal
            failures.append((kind, cert, exc))
    return wrapped, failures


def move_to_credential(cert, kind: str, target: VaultCredential) -> None:
    '''
    Re-wrap a key under another credential of the same account.

    Both credentials must be open: the key is decrypted with the current one and
    re-encrypted with the target, so this is a move rather than a copy.
    '''
    pem = private_key_pem(cert, kind, target.user)
    store_wrapped_key(cert, kind, pem, target)


def has_private_key(cert) -> bool:
    '''
    Whether any private key is stored for this certificate, wrapped or legacy.

    Certificates imported without a key are valid inventory -- they can be listed,
    revoked and re-exported as PEM -- but they cannot sign and cannot be exported
    as PKCS#12. Callers use this instead of assuming a key exists.
    '''
    return bool(is_wrapped(cert) or cert.private_key_encrypted)


def issuers_with_key(model, user):
    '''
    The certificates of ``model`` that ``user`` may sign with.

    Excludes certificates with no stored key: offering one in a signing menu would
    only produce a 409 after the operator filled the form in.
    '''
    queryset = (model.objects.filter(created_by=user)
                if user is not None else model.objects.none())
    return queryset.exclude(private_key_encrypted='', private_key_wrapped__isnull=True)


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def key_status(cert) -> str:
    '''
    One word for the state of a certificate's private key.

    * ``no_key``       -- nothing stored (an imported certificate)
    * ``orphaned``     -- cleartext, and nobody owns it, so nothing can wrap it
    * ``plaintext``    -- cleartext, owned, not yet encrypted
    * ``locked``       -- encrypted, and its credential is closed
    * ``unlocked``     -- encrypted, and its credential is open
    * ``unwrappable``  -- encrypted, but its credential is gone
    '''
    if is_wrapped(cert):
        credential = credential_of(cert)
        if credential is None:
            return 'unwrappable'
        return 'unlocked' if unsealed.is_unsealed(credential.id) else 'locked'
    if not cert.private_key_encrypted:
        return 'no_key'
    return 'orphaned' if cert.created_by_id is None else 'plaintext'


def keystore_report(user) -> dict:
    '''
    Everything the keystore page needs: the credentials, and every key with the
    state it is in.
    '''
    from .models import IntermediateCertificate, LeafCertificate, RootCertificate

    # Kind -> model, plus how to name a row in the interface.
    models_by_kind = (
        ('root', RootCertificate),
        ('intermediate', IntermediateCertificate),
        ('leaf', LeafCertificate),
    )

    credentials = []
    for credential in credentials_for(user):
        credentials.append({
            'id': credential.id,
            'name': credential.name,
            'is_default': credential.is_default,
            'unlocked': unsealed.is_unsealed(credential.id),
            'unseal_remaining_seconds': unsealed.remaining_seconds(credential.id),
            'key_count': credential_key_count(credential),
            'created_at': credential.created_at.isoformat(),
            'updated_at': credential.updated_at.isoformat(),
        })

    keys = []
    counts = {'total': 0, 'unlocked': 0, 'locked': 0, 'plaintext': 0,
              'orphaned': 0, 'unwrappable': 0, 'no_key': 0}
    for kind, model in models_by_kind:
        rows = (model.objects.filter(created_by=user)
                .select_related(CREDENTIAL_FIELD)
                .exclude(private_key_encrypted='', private_key_wrapped__isnull=True))
        for cert in rows:
            state = key_status(cert)
            counts['total'] += 1
            counts[state] = counts.get(state, 0) + 1
            credential = credential_of(cert)
            keys.append({
                'kind': kind,
                'id': cert.pk,
                'name': cert.common_name if kind == 'leaf' else cert.name,
                'serial_number': _serial(cert),
                'status': state,
                'credential_id': credential.id if credential else None,
                'credential_name': credential.name if credential else None,
            })

    return {'credentials': credentials, 'keys': keys, 'counts': counts}


def vault_status(user_id: int = None) -> dict:
    '''
    Report which private keys are encrypted, which are still plaintext, and which
    belong to no one (so they can never be encrypted).

    Used by the `vault_status` management command; the API uses
    :func:`keystore_report` instead, which is per-account and names credentials.
    '''
    from .models import IntermediateCertificate, LeafCertificate, RootCertificate

    kinds = (
        ('root', RootCertificate),
        ('intermediate', IntermediateCertificate),
        ('leaf', LeafCertificate),
    )
    report = {'wrapped': 0, 'plaintext': 0, 'orphaned': 0, 'no_key': 0, 'by_kind': {}}
    for kind, model in kinds:
        qs = model.objects.all()
        if user_id is not None:
            qs = qs.filter(created_by_id=user_id)
        bucket = {'wrapped': 0, 'plaintext': 0, 'orphaned': 0, 'no_key': 0}
        for cert in qs.only('id', 'serial_number', 'created_by_id',
                            'private_key_encrypted', WRAPPED_FIELD, CREDENTIAL_FIELD):
            if is_wrapped(cert):
                bucket['wrapped'] += 1
            elif not cert.private_key_encrypted:
                bucket['no_key'] += 1
            elif cert.created_by_id is None:
                # No owner means no credential to derive from: this key cannot be
                # wrapped, now or ever, unless ownership is assigned.
                bucket['orphaned'] += 1
            else:
                bucket['plaintext'] += 1
        report['by_kind'][kind] = bucket
        for key in bucket:
            report[key] += bucket[key]

    credentials = []
    if user_id is not None:
        credentials = list(credentials_for_id(user_id))
    report['credentials'] = len(credentials)
    report['has_root_key'] = bool(credentials)
    report['unsealed'] = any(unsealed.is_unsealed(c.id) for c in credentials)
    report['unseal_remaining_seconds'] = max(
        (unsealed.remaining_seconds(c.id) for c in credentials), default=0)
    return report


def credentials_for_id(user_id: int):
    return VaultCredential.objects.filter(user_id=user_id).order_by('created_at', 'id')


def needs_unlock(user_id: int) -> bool:
    '''Whether a wrapped key exists for this user but its credential is closed.'''
    return _any_wrapped_for_user(user_id) and not any(
        unsealed.is_unsealed(c.id) for c in credentials_for_id(user_id))


def _any_wrapped_for_user(user_id: int) -> bool:
    from .models import IntermediateCertificate, LeafCertificate, RootCertificate
    for model in (RootCertificate, IntermediateCertificate, LeafCertificate):
        if model.objects.filter(
                created_by_id=user_id,
                private_key_wrapped__isnull=False).exists():
            return True
    return False


__all__ = [
    'KeyUnavailable', 'VaultLocked', 'VaultPasswordError',
    'KIND_LABELS', 'WRAPPED_FIELD', 'CREDENTIAL_FIELD',
    'change_credential_password', 'create_credential', 'credential_key_count',
    'credential_of', 'credential_root_key', 'credentials_for', 'default_credential',
    'encrypt_for_storage', 'get_credential', 'has_private_key', 'is_legacy_plaintext',
    'is_wrapped', 'issuers_with_key', 'key_status', 'keystore_report',
    'lock_credential', 'move_to_credential', 'needs_unlock', 'pending_legacy_keys',
    'private_key_pem', 'set_default_credential', 'store_wrapped_key',
    'unlock_credential', 'vault_status', 'wrap_legacy_keys',
]
