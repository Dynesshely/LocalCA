"""
Access helpers for vault-wrapped private keys.

Keeps the "is this key encrypted, and is the vault open?" decision in one place
so the API layer cannot accidentally read the legacy plaintext column without
noticing that it is doing so.
"""
from django.db import transaction
from django.utils.translation import gettext as _

from .models import VaultRootKey
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

#: Certificate kind -> (model attribute holding the wrapped key)
WRAPPED_FIELD = 'private_key_wrapped'

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


def is_wrapped(cert) -> bool:
    '''Whether this certificate's private key is stored encrypted.'''
    return bool(getattr(cert, WRAPPED_FIELD, None))


def is_legacy_plaintext(cert) -> bool:
    '''
    Whether this certificate still has its key in the legacy plaintext column.

    Such a key predates the vault (or belongs to a certificate with no owner, so
    it has no password to derive from). Callers must surface this rather than
    pretend it is protected.
    '''
    return not is_wrapped(cert) and bool(cert.private_key_encrypted)


def encrypt_for_storage(root_key: bytes, cert, kind: str, pem: str) -> str:
    '''Produce the stored envelope for a newly generated private key.'''
    return encrypt_private_key(
        root_key, kind=kind, cert_id=cert.pk, serial=_serial(cert),
        private_key_pem=pem)


def ensure_root_key(user_id: int, password: str) -> bytes:
    '''
    Unseal (or first-time create) the vault root key for a user.

    Returns the root key and leaves it in memory for the idle timeout.
    '''
    record = VaultRootKey.objects.filter(user_id=user_id).first()
    if record is None:
        # First unlock for this account: create the root key now. Doing it here
        # rather than at first certificate means a user who has never chosen a
        # vault password sees no surprise state.
        root_key = new_root_key()
        VaultRootKey.objects.create(
            user_id=user_id, wrapped_root_key=wrap_root_key(root_key, password))
        unsealed.unseal(user_id, password, root_key)
        return root_key

    root_key = unwrap_root_key(record.wrapped_root_key, password)
    unsealed.unseal(user_id, password, root_key)
    return root_key


def rewrap_root_key(user_id: int, old_password: str, new_password: str) -> None:
    '''
    Change the vault password.

    Only the root key is re-wrapped; the private keys themselves are untouched,
    which is the point of the envelope design.
    '''
    record = VaultRootKey.objects.filter(user_id=user_id).first()
    if record is None:
        # Nothing wrapped yet: just adopt the new password.
        ensure_root_key(user_id, new_password)
        return
    root_key = unwrap_root_key(record.wrapped_root_key, old_password)
    record.wrapped_root_key = wrap_root_key(root_key, new_password)
    record.save(update_fields=['wrapped_root_key', 'updated_at'])
    unsealed.unseal(user_id, new_password, root_key)


def root_key_for(user) -> bytes:
    '''The unsealed root key for a user, or raise VaultLocked.'''
    if not user or not user.is_authenticated:
        raise VaultLocked(_('Authentication is required to use private keys.'))
    return unsealed.get(user.id)


def private_key_pem(cert, kind: str, user) -> str:
    '''
    The decrypted private key for a certificate.

    Encrypted certificates require an unsealed vault; legacy plaintext keys are
    returned with no vault involvement, because there is nothing to unwrap. The
    caller is responsible for having checked that ``user`` may use this key.
    '''
    if is_wrapped(cert):
        root_key = root_key_for(user)
        try:
            return decrypt_private_key(
                root_key, kind=kind, cert_id=cert.pk, serial=_serial(cert),
                blob=cert.private_key_wrapped)
        except VaultError as exc:
            raise KeyUnavailable(str(exc)) from exc
    if cert.private_key_encrypted:
        return cert.private_key_encrypted
    raise KeyUnavailable(_('This certificate has no stored private key.'))


def store_wrapped_key(cert, kind: str, pem: str, root_key: bytes) -> None:
    '''
    Persist a private key in wrapped form and clear the legacy plaintext column.

    Both happen in one transaction so a failure cannot leave a certificate with
    no readable key at all.
    '''
    wrapped = encrypt_for_storage(root_key, cert, kind, pem)
    with transaction.atomic():
        cert.private_key_wrapped = wrapped
        cert.private_key_encrypted = ''
        cert.save(update_fields=['private_key_wrapped', 'private_key_encrypted'])


#: Certificate kind -> model, for the sweep that encrypts existing cleartext keys.
#: Imported lazily inside the function so this module stays importable from
#: migrations and from the models themselves.
def _kinds():
    from .models import (
        IntermediateCertificate,
        LeafCertificate,
        RootCertificate,
    )
    return (('root', RootCertificate),
            ('intermediate', IntermediateCertificate),
            ('leaf', LeafCertificate))


def pending_legacy_keys(user_id: int):
    '''``(kind, cert)`` for every plaintext key this account still owns.'''
    pairs = []
    for kind, model in _kinds():
        rows = (model.objects
                .filter(created_by_id=user_id, private_key_wrapped__isnull=True)
                .exclude(private_key_encrypted=''))
        pairs.extend((kind, cert) for cert in rows)
    return pairs


def wrap_legacy_keys(user_id: int, root_key: bytes):
    '''
    Encrypt every plaintext key this account owns.

    Returns `(wrapped_count, failures)`, where a failure is a
    `(kind, certificate, exception)` triple. Called when an account creates its
    vault password: the moment a password exists, leaving keys in cleartext is
    the surprising state, not the safe one. A row that cannot be wrapped is
    reported rather than raised -- one unreadable certificate must not fail the
    unlock that triggered the sweep, and `manage.py rewrap_keys` retries.
    '''
    wrapped, failures = 0, []
    for kind, cert in pending_legacy_keys(user_id):
        try:
            store_wrapped_key(cert, kind, cert.private_key_encrypted, root_key)
            wrapped += 1
        except Exception as exc:  # noqa: BLE001 - reported by the caller, never fatal
            failures.append((kind, cert, exc))
    return wrapped, failures


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


def needs_unlock(user_id: int) -> bool:
    '''Whether a wrapped key exists for this user but the vault is closed.'''
    wrapped_exists = (
        _any_wrapped_for_user(user_id)
    )
    return wrapped_exists and not unsealed.is_unsealed(user_id)


def _any_wrapped_for_user(user_id: int) -> bool:
    from .models import IntermediateCertificate, LeafCertificate, RootCertificate
    for model in (RootCertificate, IntermediateCertificate, LeafCertificate):
        if model.objects.filter(
                created_by_id=user_id,
                private_key_wrapped__isnull=False).exists():
            return True
    return False


def vault_status(user_id: int = None) -> dict:
    '''
    Report which private keys are encrypted, which are still plaintext, and
    which belong to no one (so they can never be encrypted).

    Used by the API and the ``vault_status`` management command; this is the
    honest inventory that stops "we encrypt keys" from being an overstatement.
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
                            'private_key_encrypted', WRAPPED_FIELD):
            if is_wrapped(cert):
                bucket['wrapped'] += 1
            elif not cert.private_key_encrypted:
                bucket['no_key'] += 1
            elif cert.created_by_id is None:
                # No owner means no password to derive from: this key cannot be
                # wrapped, now or ever, unless ownership is assigned.
                bucket['orphaned'] += 1
            else:
                bucket['plaintext'] += 1
        report['by_kind'][kind] = bucket
        for key in bucket:
            report[key] += bucket[key]

    record = None
    if user_id is not None:
        record = VaultRootKey.objects.filter(user_id=user_id).first()
    report['has_root_key'] = record is not None
    report['unsealed'] = unsealed.is_unsealed(user_id) if user_id else False
    report['unseal_remaining_seconds'] = (
        unsealed.remaining_seconds(user_id) if user_id else 0)
    return report


__all__ = [
    'KeyUnavailable', 'VaultLocked', 'VaultPasswordError',
    'KIND_LABELS', 'WRAPPED_FIELD',
    'encrypt_for_storage', 'ensure_root_key', 'has_private_key', 'is_legacy_plaintext',
    'is_wrapped', 'issuers_with_key', 'needs_unlock', 'private_key_pem',
    'rewrap_root_key', 'root_key_for', 'store_wrapped_key', 'vault_status',
]
