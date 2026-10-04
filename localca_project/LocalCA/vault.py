"""
At-rest encryption for certificate private keys.

Threat model
------------
This protects the *stored* key material. Someone who obtains the database file
or a backup of it (docker cp, a volume snapshot, an accidental commit, a disk
image) cannot recover a private key, and therefore cannot forge certificates
under this CA.

It does NOT protect against someone who controls the running server (the
in-memory root key is reachable there, and so is the unseal file), nor against a
user who is entitled to use a key, nor against anyone who knows an operator's
password. It is at-rest confidentiality, not an intrusion defence.

Key hierarchy
-------------
    password --scrypt(salt)--> KEK          (never stored)
    KEK      --AES-GCM-------> root key     (root key wrapped and stored, per user)
    root key --HKDF(info)----> per-cert key (derived on demand, never stored)
    per-cert key --AES-GCM(AAD)--> PEM      (AAD binds kind + id, see below)

Why a root key rather than encrypting each key straight from the password:
changing the password re-wraps one 32-byte value instead of re-encrypting every
private key in the database. It also means a future HSM/KMS would only have to
take over the wrap step.

Why HKDF per certificate rather than a single key for everything: each private
key gets an independent key, and the AAD (certificate kind + id + serial) is
authenticated with the ciphertext, so a ciphertext cannot be moved from one row
to another -- swapping rows makes decryption fail rather than silently handing
back the wrong key.
"""
import base64
import json
import os
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from django.utils.translation import gettext as _

#: Bumped only if the on-disk format changes incompatibly.
ENVELOPE_VERSION = 1

#: scrypt parameters. N=2^15 with r=8 needs ~32 MiB and ~0.1s, which is a
#: deliberately uncomfortable cost for an offline guessing attack while staying
#: responsive for an interactive unlock. Stored in the envelope so the cost can
#: be raised later without invalidating existing ciphertext.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32

#: Marks a decrypted payload as ours before trusting it. AES-GCM already
#: authenticates, so this is belt-and-braces: it catches "decrypted fine but is
#: not actually a private key", e.g. an operator pointing the tool at the wrong
#: column.
PLAINTEXT_MAGIC = b'LocalCA-vault-v1:'

#: How long an unsealed root key stays in memory without use. The lock is
#: enforced by plucking a salted hash of the supplied password, so a wrong
#: password cannot extend or break another user's unlocked state.
DEFAULT_IDLE_TIMEOUT_SECONDS = 15 * 60

#: Set by applications that need a stable, explicit unlock policy.
ENV_IDLE_TIMEOUT = 'LOCALCA_VAULT_IDLE_TIMEOUT'


class VaultError(Exception):
    '''Base class for vault failures.'''


class VaultLocked(VaultError):
    '''The root key for this user is not available in memory.'''


class VaultPasswordError(VaultError):
    '''The supplied password does not unwrap the root key.'''


class VaultFormatError(VaultError):
    '''Stored ciphertext is malformed or was tampered with.'''


# --------------------------------------------------------------------------
# envelope helpers
# --------------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001 - any decode failure is a format error
        raise VaultFormatError('Stored ciphertext is not valid base64.') from exc


def _dump(envelope: dict) -> str:
    return json.dumps(envelope, separators=(',', ':'), sort_keys=True)


def _load(blob: str) -> dict:
    try:
        envelope = json.loads(blob)
    except (TypeError, ValueError) as exc:
        raise VaultFormatError('Stored ciphertext is not valid JSON.') from exc
    if not isinstance(envelope, dict):
        raise VaultFormatError('Stored ciphertext has an unexpected shape.')
    if envelope.get('v') != ENVELOPE_VERSION:
        raise VaultFormatError(
            'Unsupported vault envelope version: %r' % envelope.get('v'))
    # Only the fields every envelope has. 'salt' belongs to the password-derived
    # (root key) envelope alone: per-key envelopes use HKDF from the root key, so
    # they deliberately carry no salt.
    for field in ('kdf', 'nonce', 'ct'):
        if field not in envelope:
            raise VaultFormatError('Vault envelope is missing %r.' % field)
    return envelope


def derive_kek(password: str, salt: bytes, *, n=SCRYPT_N, r=SCRYPT_R,
               p=SCRYPT_P) -> bytes:
    '''Derive the key-encryption key from a password. Never store the result.'''
    if not password:
        raise VaultPasswordError(_('A vault password is required.'))
    return Scrypt(salt=salt, length=SCRYPT_LENGTH, n=n, r=r, p=p).derive(
        password.encode('utf-8'))


def _aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def _aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise VaultFormatError(
            'Ciphertext failed authentication: wrong key or tampered data.'
        ) from exc


# --------------------------------------------------------------------------
# root key wrapping (password <-> root key)
# --------------------------------------------------------------------------

def wrap_root_key(root_key: bytes, password: str) -> str:
    '''
    Wrap a root key with a password-derived KEK, returning the stored envelope.

    A fresh salt per wrap means re-wrapping (a password change) produces
    different ciphertext for the same root key, which is what we want.
    '''
    if len(root_key) != 32:
        raise VaultError('Root key must be 32 bytes.')
    salt = os.urandom(16)
    kek = derive_kek(password, salt)
    nonce, ciphertext = _aead_encrypt(kek, root_key, b'localca-vault-root-v1')
    return _dump({
        'v': ENVELOPE_VERSION,
        'kdf': 'scrypt',
        'n': SCRYPT_N, 'r': SCRYPT_R, 'p': SCRYPT_P,
        'salt': _b64(salt),
        'nonce': _b64(nonce),
        'ct': _b64(ciphertext),
    })


def unwrap_root_key(blob: str, password: str) -> bytes:
    '''
    Recover a root key from its envelope.

    Raises VaultPasswordError when the password is wrong (indistinguishable from
    tampering by design: both mean "this password does not open this envelope").
    '''
    envelope = _load(blob)
    if envelope.get('kdf') != 'scrypt':
        raise VaultFormatError('Unsupported KDF in vault envelope.')
    if 'salt' not in envelope:
        raise VaultFormatError('Root key envelope is missing its salt.')
    salt = _unb64(envelope['salt'])
    kek = derive_kek(password, salt,
                     n=int(envelope.get('n', SCRYPT_N)),
                     r=int(envelope.get('r', SCRYPT_R)),
                     p=int(envelope.get('p', SCRYPT_P)))
    try:
        return _aead_decrypt(kek, _unb64(envelope['nonce']), _unb64(envelope['ct']),
                             b'localca-vault-root-v1')
    except VaultFormatError as exc:
        raise VaultPasswordError(
            'The vault password is incorrect, or the stored key was modified.'
        ) from exc


def new_root_key() -> bytes:
    '''A fresh 256-bit root key.'''
    return secrets.token_bytes(32)


# --------------------------------------------------------------------------
# private key encryption (root key <-> PEM)
# --------------------------------------------------------------------------

def _aad(kind: str, cert_id: int, serial: str) -> bytes:
    '''
    Additional authenticated data binding a ciphertext to one certificate.

    Because this is authenticated, taking the blob from row A and pasting it
    into row B makes decryption fail. Without it, a swapped ciphertext would
    quietly decrypt to the wrong private key.
    '''
    return ('localca-vault-key-v1|%s|%s|%s' % (kind, cert_id, serial)).encode('utf-8')


def _derive_key_for(root_key: bytes, kind: str, cert_id: int, serial: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_aad(kind, cert_id, serial),
    ).derive(root_key)


def encrypt_private_key(root_key: bytes, *, kind: str, cert_id: int, serial: str,
                        private_key_pem: str) -> str:
    '''Encrypt a PEM private key for storage. Returns the stored envelope.'''
    aad = _aad(kind, cert_id, serial)
    key = _derive_key_for(root_key, kind, cert_id, serial)
    payload = PLAINTEXT_MAGIC + private_key_pem.encode('utf-8')
    nonce, ciphertext = _aead_encrypt(key, payload, aad)
    return _dump({
        'v': ENVELOPE_VERSION,
        'alg': 'AES-256-GCM',
        'kdf': 'hkdf-sha256',
        'nonce': _b64(nonce),
        'ct': _b64(ciphertext),
    })


def decrypt_private_key(root_key: bytes, *, kind: str, cert_id: int, serial: str,
                        blob: str) -> str:
    '''Recover a PEM private key from its envelope.'''
    envelope = _load(blob)
    if envelope.get('alg') != 'AES-256-GCM':
        raise VaultFormatError('Unsupported cipher in vault envelope.')
    aad = _aad(kind, cert_id, serial)
    key = _derive_key_for(root_key, kind, cert_id, serial)
    payload = _aead_decrypt(key, _unb64(envelope['nonce']), _unb64(envelope['ct']), aad)
    if not payload.startswith(PLAINTEXT_MAGIC):
        raise VaultFormatError(
            'Decrypted payload is not a LocalCA private key; refusing to use it.')
    return payload[len(PLAINTEXT_MAGIC):].decode('utf-8')


# --------------------------------------------------------------------------
# unlocked-key cache (process memory only)
# --------------------------------------------------------------------------

def idle_timeout() -> int:
    '''How long an unsealed root key survives without use, in seconds.'''
    raw = os.environ.get(ENV_IDLE_TIMEOUT)
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return DEFAULT_IDLE_TIMEOUT_SECONDS


def _fingerprint(user_id: int, password: str) -> str:
    '''
    A value that identifies "this user, with this password" without keeping the
    password. Used only to decide whether a request may keep an existing unlock
    alive, so a wrong password cannot extend another session's unlock.

    This is not a password hash and is never persisted.
    '''
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(user_id).encode('ascii'))
    digest.update(b'\x00')
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex()


class UnsealedKeys:
    '''
    In-memory store of unsealed root keys, one per user.

    Deliberately process-local: nothing here is written to the session, a cookie
    or the disk. A restart re-locks the vault, which is the desired behaviour.

    With multiple gunicorn workers each worker has its own store, so a request
    can land on a worker that has not been unsealed. The management command
    ``manage.py vault_unseal_file`` exists for that case.
    '''

    def __init__(self):
        self._root_keys = {}
        self._fingerprints = {}
        self._last_used = {}

    def _expire(self, user_id: int) -> None:
        timeout = idle_timeout()
        last = self._last_used.get(user_id)
        if last is not None and timeout >= 0 and (time.time() - last) > timeout:
            self.lock(user_id)

    def unseal(self, user_id: int, password: str, root_key: bytes) -> None:
        self._root_keys[user_id] = root_key
        self._fingerprints[user_id] = _fingerprint(user_id, password)
        self._last_used[user_id] = time.time()

    def lock(self, user_id: int) -> None:
        self._root_keys.pop(user_id, None)
        self._fingerprints.pop(user_id, None)
        self._last_used.pop(user_id, None)

    def lock_all(self) -> None:
        self._root_keys.clear()
        self._fingerprints.clear()
        self._last_used.clear()

    def is_unsealed(self, user_id: int) -> bool:
        self._expire(user_id)
        return user_id in self._root_keys

    def get(self, user_id: int, password: str = None) -> bytes:
        '''
        The unsealed root key for a user.

        When ``password`` is supplied it must match the one that unsealed it;
        this is how a wrong password is rejected instead of silently extending an
        existing unlock.
        '''
        self._expire(user_id)
        root_key = self._root_keys.get(user_id)
        if root_key is None:
            raise VaultLocked(_('The vault is locked for this account.'))
        if password is not None and \
                self._fingerprints.get(user_id) != _fingerprint(user_id, password):
            raise VaultPasswordError(
                _('The vault password does not match the unlock.'))
        self._last_used[user_id] = time.time()
        return root_key

    def remaining_seconds(self, user_id: int) -> int:
        self._expire(user_id)
        if user_id not in self._root_keys:
            return 0
        timeout = idle_timeout()
        if timeout < 0:
            return -1
        return max(0, int(timeout - (time.time() - self._last_used[user_id])))


#: The process-wide store. Import this rather than constructing your own.
unsealed = UnsealedKeys()
