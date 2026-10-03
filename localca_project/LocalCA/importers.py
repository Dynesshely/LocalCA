"""
Parse uploaded certificate material in the formats operators actually have.

This module is deliberately pure: bytes in, parsed objects out. It never touches
the database and never writes anything, so the API can show a *plan* ("this is
what I would create") before a single row changes, and no uploaded key material
outlives the request that carried it.

What is accepted (detected by content, never by file extension):

  * PEM — one or many objects per file, certificate and key either in the same
    file or in separate files of one submission. ``TRUSTED CERTIFICATE`` labels
    are accepted too; OpenSSL appends auxiliary trust data after the DER, which
    is trimmed here because ``cryptography`` rejects the trailing bytes.
  * DER — certificate, private key (PKCS#8 / PKCS#1 / SEC1) or PKCS#7 bundle.
  * PKCS#7 / P7B / P7C — DER and PEM. Certificates only, by construction.
  * PKCS#12 / PFX — key plus certificate plus any additional chain certificates.
    A single key entry; ``cryptography`` cannot enumerate multiple entries.
  * ZIP — a container for any of the above, which is what a bulk migration off
    another CA looks like.

Private keys may be unencrypted or encrypted (PKCS#8 ``ENCRYPTED PRIVATE KEY``
or traditional OpenSSL ``Proc-Type: 4,ENCRYPTED``). Encryption is honoured: the
password is required to read them and is never stored.

Deliberately not supported: JKS/JCEKS (Java keystores — convert with
``keytool -importkeystore -destkeystore bundle.p12``), SSH keys and SSH
certificates, and PGP keys. None of those are X.509 PKI material this
application could sign or export with.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

# --------------------------------------------------------------------------
# Limits. Every one of these exists so a signed-in user cannot turn an upload
# into an out-of-memory or CPU exhaustion on the server.
# --------------------------------------------------------------------------

#: Largest single uploaded file.
MAX_FILE_BYTES = 1024 * 1024
#: Most files in one submission.
MAX_FILES = 8
#: Largest combined upload.
MAX_TOTAL_BYTES = 5 * 1024 * 1024
#: Most certificates plus keys parsed from one submission.
MAX_OBJECTS = 200
#: Zip guards: entry count, total uncompressed size and compression ratio.
MAX_ARCHIVE_ENTRIES = 50
MAX_ARCHIVE_TOTAL_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_RATIO = 200
#: How deep a zip inside a zip is followed.
MAX_ARCHIVE_DEPTH = 2

#: Shown in the UI and the README.
SUPPORTED_FORMATS = (
    'PEM (certificate, chain, private key, encrypted private key)',
    'DER (certificate, private key, PKCS#7)',
    'PKCS#7 / P7B / P7C (DER and PEM)',
    'PKCS#12 / PFX (password protected or empty password)',
    'ZIP containing any of the above',
)
UNSUPPORTED_FORMATS = (
    'JKS / JCEKS Java keystores — convert with '
    'keytool -importkeystore -destkeystore bundle.p12',
    'SSH keys and SSH certificates',
    'PGP keys',
)


class ImportError_(Exception):
    """Base class for a rejected submission."""


# ``ImportError`` is a Python builtin, so the public name is aliased below.
class UploadTooLarge(ImportError_):
    '''A file, the submission, or the object count exceeded a limit.'''


class BadPassword(ImportError_):
    '''The supplied password did not decrypt an encrypted private key.'''


class UnusableUpload(ImportError_):
    '''Nothing in the submission could be parsed at all.'''


# --------------------------------------------------------------------------
# Parsed shapes
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ParsedCert:
    '''A certificate read out of an upload.'''
    cert: x509.Certificate
    pem: str
    fingerprint: str
    common_name: str
    is_ca: bool
    is_self_signed: bool
    sans: tuple
    subject_dn: str
    issuer_dn: str
    subject_key_id: str
    authority_key_id: str
    source: str

    @property
    def serial_number(self) -> str:
        return str(self.cert.serial_number)

    @property
    def not_valid_after(self):
        return self.cert.not_valid_after_utc

    @property
    def kind_hint(self) -> str:
        '''Best guess at which model this certificate belongs in.'''
        if self.is_self_signed:
            return 'root'
        return 'intermediate' if self.is_ca else 'leaf'


@dataclass(frozen=True)
class ParsedKey:
    '''A private key read out of an upload, re-encoded as plain PKCS#8 PEM.'''
    pem: str
    spki_fingerprint: str
    algorithm: str
    encrypted_in_source: bool
    source: str


@dataclass
class ParsedBundle:
    '''Everything successfully read from one submission.'''
    certs: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def add_warning(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def add_error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

_PEM_RE = re.compile(
    rb'-----BEGIN ([A-Z0-9][A-Z0-9 .#-]*)-----(.*?)-----END \1-----', re.S)

#: DER encoding of OID 1.2.840.113549.1.7.1 (id-data), the ContentInfo type a
#: PFX wrapped in. Together with the version-3 INTEGER at the start of the outer
#: SEQUENCE this identifies a PKCS#12 bundle, which matters because
#: ``cryptography`` reports "not a PKCS#12" and "wrong password" as the same
#: ValueError -- a plain certificate must not be blamed on a password.
_PKCS12_DATA_OID = bytes.fromhex('06092a864886f70d010701')

_CERTIFICATE_LABELS = {'CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'}
_PKCS7_LABELS = {'PKCS7', 'PKCS #7 SIGNED DATA', 'PKCS #7'}
_KEY_LABELS = {
    'PRIVATE KEY': 'pkcs8',
    'ENCRYPTED PRIVATE KEY': 'pkcs8-encrypted',
    'RSA PRIVATE KEY': 'pkcs1',
    'EC PRIVATE KEY': 'sec1',
    'DSA PRIVATE KEY': 'dsa',
}
_IGNORED_LABELS = {
    'X509 CRL': 'certificate revocation lists are not imported (LocalCA serves no CRL)',
    'CRL': 'certificate revocation lists are not imported (LocalCA serves no CRL)',
    'CERTIFICATE REQUEST': 'certificate requests (CSR) are not certificates; sign them instead',
    'NEW CERTIFICATE REQUEST': 'certificate requests (CSR) are not certificates; sign them instead',
    'OPENSSH PRIVATE KEY': 'SSH keys are not X.509 material and are not supported',
    'SSH2 PUBLIC KEY': 'SSH keys are not X.509 material and are not supported',
    'PGP PRIVATE KEY BLOCK': 'PGP keys are not X.509 material and are not supported',
    'PGP PUBLIC KEY BLOCK': 'PGP keys are not X.509 material and are not supported',
}


def _looks_like_pkcs12(der: bytes) -> bool:
    '''
    Whether ``der`` has the shape of a PFX.

    RFC 7292 defines ``PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo,
    macData MacData OPTIONAL }`` and the version is always 3, so the first
    element inside the outer SEQUENCE is ``INTEGER 3``. A certificate starts with
    its own SEQUENCE and PKCS#7 starts with an OID, so neither can be mistaken for
    a PFX -- which matters because ``cryptography`` reports "not a PFX" and "wrong
    password" as the same ValueError.
    '''
    if len(der) < 16 or der[0] != 0x30:
        return False
    first = der[1]
    if first < 0x80:
        offset = 2
    else:
        count = first & 0x7F
        if count == 0 or len(der) < 2 + count:
            return False
        offset = 2 + count
    return der[offset:offset + 3] == b'\x02\x01\x03'


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _first_der_object(data: bytes) -> bytes:
    '''
    Return the first DER element of ``data``.

    Needed for ``TRUSTED CERTIFICATE`` blocks: OpenSSL appends trust metadata
    after the certificate's DER, and ``cryptography`` refuses to parse a buffer
    with trailing bytes.
    '''
    if len(data) < 2 or data[0] != 0x30:
        return data
    first = data[1]
    if first < 0x80:
        header, length = 2, first
    else:
        count = first & 0x7F
        if count == 0 or len(data) < 2 + count:
            return data
        header = 2 + count
        length = int.from_bytes(data[2:2 + count], 'big')
    end = header + length
    return data[:end] if 0 < end <= len(data) else data


def _spki_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return _sha256_hex(der)


def _extension(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _common_name(cert) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return ''
    value = attrs[0].value
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    return str(value)[:255]


def _san_strings(cert) -> tuple:
    '''SAN entries as plain strings, the way the LeafCertificate.san column holds them.'''
    san = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san is None:
        return ()
    out = []
    for entry in san:
        value = getattr(entry, 'value', entry)
        if isinstance(value, bytes):
            value = value.decode('utf-8', 'replace')
        text = str(value)
        if text not in out:
            out.append(text)
    return tuple(out)


def _key_identifier(cert, oid) -> str:
    if oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
        value = _extension(cert, oid)
        return value.key_identifier.hex() if value is not None else ''
    value = _extension(cert, oid)
    if value is None:
        return ''
    identifier = getattr(value, 'key_identifier', None)
    return identifier.hex() if identifier else ''


def _is_self_signed(cert) -> bool:
    '''
    Whether the certificate is its own issuer.

    Names alone are not enough (a cross-signed pair can share a subject), so the
    signature is verified when the name check passes.
    '''
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except Exception:  # noqa: BLE001 - any verification failure means "no"
        return False
    return True


def _is_ca(cert) -> bool:
    constraints = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    return bool(constraints is not None and constraints.ca)


def _normalise_private_key(private_key, *, encrypted_in_source: bool, source: str) -> ParsedKey:
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode('ascii')
    return ParsedKey(
        pem=pem,
        spki_fingerprint=_spki_fingerprint(private_key.public_key()),
        algorithm=type(private_key).__name__,
        encrypted_in_source=encrypted_in_source,
        source=source)


def _build_parsed_cert(cert: x509.Certificate, source: str) -> ParsedCert:
    return ParsedCert(
        cert=cert,
        pem=cert.public_bytes(serialization.Encoding.PEM).decode('ascii'),
        fingerprint=_sha256_hex(cert.public_bytes(serialization.Encoding.DER)),
        common_name=_common_name(cert),
        is_ca=_is_ca(cert),
        is_self_signed=_is_self_signed(cert),
        sans=_san_strings(cert),
        subject_dn=cert.subject.rfc4514_string(),
        issuer_dn=cert.issuer.rfc4514_string(),
        subject_key_id=_key_identifier(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER),
        authority_key_id=_key_identifier(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER),
        source=source)


# --------------------------------------------------------------------------
# Per-shape parsing
# --------------------------------------------------------------------------

def _load_private_key_pem(block: bytes, label: str, password, bundle, source):
    '''Load one PEM private-key block, or explain why it could not be.'''
    password_bytes = password.encode('utf-8') if password else None
    try:
        private_key = serialization.load_pem_private_key(block, password=password_bytes)
    except TypeError:
        if password_bytes:
            # TypeError also means "a password was given but this key is not
            # encrypted", so retry without before giving up.
            try:
                private_key = serialization.load_pem_private_key(block, password=None)
            except (TypeError, ValueError):
                bundle.add_warning(
                    f'A private key in {source} could not be read (unsupported or damaged).')
                return None
        else:
            # Raised by cryptography when the key is encrypted and no password came.
            bundle.add_warning(
                'An encrypted private key in this upload was skipped because no '
                'password was provided.')
            return None
    except ValueError:
        encrypted = (label == 'ENCRYPTED PRIVATE KEY'
                     or b'ENCRYPTED' in block
                     or b'Proc-Type: 4,ENCRYPTED' in block)
        if encrypted and password_bytes:
            raise BadPassword(
                'The password did not decrypt the encrypted private key. Check it '
                'and try again.')
        bundle.add_warning(
            'A private key in this upload could not be read'
            + (' (it is encrypted).' if encrypted else ' (unsupported or damaged).'))
        return None
    return _normalise_private_key(private_key,
                                  encrypted_in_source=(label == 'ENCRYPTED PRIVATE KEY'
                                                       or b'Proc-Type: 4,ENCRYPTED' in block),
                                  source=source)


def _parse_pem(data: bytes, bundle: ParsedBundle, source: str, password) -> None:
    for match in _PEM_RE.finditer(data):
        label = match.group(1).decode('ascii', 'replace').strip()
        if label in _IGNORED_LABELS:
            bundle.add_warning(f'Ignored {label} in {source}: {_IGNORED_LABELS[label]}.')
            continue

        # Private keys are dispatched before any base64 decoding: a traditional
        # OpenSSL encrypted key carries Proc-Type/DEK-Info headers *inside* the
        # block, so its body is not pure base64. The loader gets the whole block.
        if label in _KEY_LABELS:
            key = _load_private_key_pem(match.group(0), label, password, bundle, source)
            if key is not None:
                bundle.keys.append(key)
            continue

        body = re.sub(rb'\s+', b'', match.group(2))
        try:
            der = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            bundle.add_warning(f'Ignored a malformed {label} block in {source}.')
            continue

        if label in _CERTIFICATE_LABELS:
            try:
                cert = x509.load_der_x509_certificate(_first_der_object(der))
            except ValueError:
                bundle.add_warning(f'Ignored an unreadable {label} block in {source}.')
                continue
            bundle.certs.append(_build_parsed_cert(cert, source))
            continue

        if label in _PKCS7_LABELS:
            bundle.certs.extend(_parse_pkcs7(der, bundle, source))
            continue

        if label == 'PKCS12':
            bundle.certs.extend(_parse_pkcs12(der, bundle, source, password))
            continue

        bundle.add_warning(f'Ignored an unsupported PEM block ({label}) in {source}.')


def _parse_pkcs7(der: bytes, bundle: ParsedBundle, source: str) -> list:
    try:
        certs = pkcs7.load_der_pkcs7_certificates(der)
    except ValueError:
        bundle.add_warning(f'Ignored an unreadable PKCS#7 bundle in {source}.')
        return []
    return [_build_parsed_cert(cert, source) for cert in certs]


def _parse_pkcs12(der: bytes, bundle: ParsedBundle, source: str, password) -> list:
    # Not a PFX at all: say nothing and let the other DER loaders have it.
    if not _looks_like_pkcs12(der):
        return []
    password_bytes = password.encode('utf-8') if password else None
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(der, password_bytes)
    except ValueError as exc:
        if password_bytes:
            raise BadPassword(
                'The password did not open the PKCS#12 bundle. Check it and try '
                'again.') from exc
        bundle.add_warning(
            f'The PKCS#12 bundle in {source} needs a password, so it was skipped.')
        return []
    out = []
    if cert is not None:
        out.append(_build_parsed_cert(cert, source))
    for item in extra or []:
        out.append(_build_parsed_cert(item, source))
    if key is not None:
        bundle.keys.append(_normalise_private_key(
            key, encrypted_in_source=bool(password), source=source))
    if not out and key is None:
        bundle.add_warning(f'The PKCS#12 bundle in {source} contained nothing usable.')
    return out


def _parse_der(data: bytes, bundle: ParsedBundle, source: str, password) -> bool:
    '''Try every DER shape. Returns True when something was recognised.'''
    certs_before = len(bundle.certs)
    keys_before = len(bundle.keys)
    found = False

    try:
        bundle.certs.append(_build_parsed_cert(
            x509.load_der_x509_certificate(data), source))
        return True
    except ValueError:
        pass

    try:
        certs = pkcs7.load_der_pkcs7_certificates(data)
    except ValueError:
        certs = []
    if certs:
        bundle.certs.extend(_build_parsed_cert(cert, source) for cert in certs)
        found = True

    password_bytes = password.encode('utf-8') if password else None
    try:
        private_key = serialization.load_der_private_key(data, password=password_bytes)
    except TypeError:
        if password_bytes:
            try:
                private_key = serialization.load_der_private_key(data, password=None)
            except (TypeError, ValueError):
                private_key = None
        else:
            bundle.add_warning(
                'An encrypted private key in this upload was skipped because no '
                'password was provided.')
            private_key = None
    except ValueError:
        private_key = None
    if private_key is not None:
        bundle.keys.append(_normalise_private_key(
            private_key, encrypted_in_source=bool(password), source=source))
        return True

    # PKCS#12 last: its wrong-password error is indistinguishable from "not a
    # PFX", so every other shape gets a chance to claim the bytes first.
    bundle.certs.extend(_parse_pkcs12(data, bundle, source, password))
    return (found
            or len(bundle.certs) > certs_before
            or len(bundle.keys) > keys_before)


def _parse_zip(data: bytes, bundle: ParsedBundle, source: str, password, depth: int) -> bool:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False

    with archive:
        entries = [info for info in archive.infolist() if not info.is_dir()]
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise UploadTooLarge(
                f'{source} contains {len(entries)} files; the limit is '
                f'{MAX_ARCHIVE_ENTRIES}.')
        total = 0
        for info in entries:
            if info.file_size > MAX_ARCHIVE_TOTAL_BYTES:
                raise UploadTooLarge(
                    f'{source}: {info.filename} is larger than the '
                    f'{MAX_ARCHIVE_TOTAL_BYTES // (1024 * 1024)} MiB archive limit.')
            if info.compress_size > 0 and info.file_size / info.compress_size > MAX_ARCHIVE_RATIO:
                raise UploadTooLarge(
                    f'{source}: {info.filename} expands too far '
                    f'(ratio above {MAX_ARCHIVE_RATIO}:1).')
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise UploadTooLarge(
                    f'{source} expands to more than '
                    f'{MAX_ARCHIVE_TOTAL_BYTES // (1024 * 1024)} MiB.')
        for info in entries:
            member = archive.read(info)
            _parse_blob(member, bundle, f'{source}:{info.filename}', password, depth + 1)
    return True


def _parse_blob(data: bytes, bundle: ParsedBundle, source: str, password, depth: int) -> None:
    '''Route one blob to the right parser based on its content.'''
    if not data or not data.strip():
        return

    certs_before = len(bundle.certs)
    keys_before = len(bundle.keys)
    warnings_before = len(bundle.warnings)

    if data[:2] == b'PK' and depth < MAX_ARCHIVE_DEPTH:
        if _parse_zip(data, bundle, source, password, depth):
            return

    if b'-----BEGIN ' in data[:8192]:
        _parse_pem(data, bundle, source, password)
        # A file can carry PEM blocks *and* trailing DER; only stop here when the
        # PEM pass actually produced something.
        if len(bundle.certs) > certs_before or len(bundle.keys) > keys_before:
            return

    if _parse_der(data, bundle, source, password):
        return

    # When a warning already explains the rejection (an encrypted key with no
    # password, a CSR, an SSH key) a second "unrecognised format" line would only
    # mislead the operator.
    if len(bundle.warnings) > warnings_before:
        return

    bundle.add_error(
        f'{source}: unrecognised format. Supported: PEM, DER, PKCS#7, PKCS#12 and '
        'ZIP of those.')


# --------------------------------------------------------------------------
# Public entry points
# --------------------------------------------------------------------------

def parse_sources(sources, password=None) -> ParsedBundle:
    '''
    Parse ``(name, bytes)`` pairs into a :class:`ParsedBundle`.

    Structural limits raise :class:`UploadTooLarge`; everything else is collected
    as a warning or error on the bundle so one bad file does not hide the rest.
    '''
    bundle = ParsedBundle()
    if not sources:
        raise UnusableUpload('No files were uploaded.')
    if len(sources) > MAX_FILES:
        raise UploadTooLarge(
            f'{len(sources)} files were uploaded; the limit is {MAX_FILES}.')

    total = 0
    for name, data in sources:
        if len(data) > MAX_FILE_BYTES:
            raise UploadTooLarge(
                f'{name} is larger than the {MAX_FILE_BYTES // 1024} KiB per-file '
                'limit.')
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise UploadTooLarge(
                f'The upload exceeds the {MAX_TOTAL_BYTES // (1024 * 1024)} MiB '
                'total limit.')
        _parse_blob(data, bundle, name, password, 0)
        if len(bundle.certs) + len(bundle.keys) > MAX_OBJECTS:
            raise UploadTooLarge(
                f'More than {MAX_OBJECTS} certificates and keys were found in this '
                'submission.')

    # Deduplicate: the same certificate often appears twice in a chain (leaf's
    # issuer is also the bundle's intermediate).
    seen = set()
    unique_certs = []
    for cert in bundle.certs:
        if cert.fingerprint in seen:
            continue
        seen.add(cert.fingerprint)
        unique_certs.append(cert)
    bundle.certs = unique_certs

    seen_keys = set()
    unique_keys = []
    for key in bundle.keys:
        if key.spki_fingerprint in seen_keys:
            continue
        seen_keys.add(key.spki_fingerprint)
        unique_keys.append(key)
    bundle.keys = unique_keys

    # A submission that produced only explanations (an encrypted key with no
    # password, a CSR, an SSH key) is not "unusable": the caller needs those
    # warnings to tell the operator what to do. Only silence is a hard failure.
    if not bundle.certs and not bundle.keys and not bundle.warnings:
        raise UnusableUpload(
            'Nothing could be parsed from this upload. Supported formats: '
            + '; '.join(SUPPORTED_FORMATS) + '.')
    return bundle


def parse_uploads(uploads, password=None) -> ParsedBundle:
    '''Django ``UploadedFile`` adapter that enforces the size limits while reading.'''
    sources = []
    total = 0
    for upload in uploads:
        data = upload.read()
        if len(data) > MAX_FILE_BYTES:
            raise UploadTooLarge(
                f'{getattr(upload, "name", "a file")} is larger than the '
                f'{MAX_FILE_BYTES // 1024} KiB per-file limit.')
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise UploadTooLarge(
                f'The upload exceeds the {MAX_TOTAL_BYTES // (1024 * 1024)} MiB '
                'total limit.')
        sources.append((getattr(upload, 'name', 'upload'), data))
    return parse_sources(sources, password=password)


#: Exported under the name the API and tests use. ``ImportError`` is a builtin,
#: so the class above is deliberately spelled with a trailing underscore.
ImportError = ImportError_


def describe_cert(cert, source: str = '') -> ParsedCert:
    '''
    Describe an already-loaded certificate.

    Used by the import planner to index what is already in the database, so both
    sides of a duplicate check are produced by the same code.
    '''
    return _build_parsed_cert(cert, source)


__all__ = [
    'BadPassword', 'ImportError', 'MAX_FILE_BYTES', 'MAX_FILES', 'MAX_OBJECTS',
    'MAX_TOTAL_BYTES', 'ParsedBundle', 'ParsedCert', 'ParsedKey',
    'SUPPORTED_FORMATS', 'UNSUPPORTED_FORMATS', 'UnusableUpload', 'UploadTooLarge',
    'describe_cert', 'parse_sources', 'parse_uploads',
]
