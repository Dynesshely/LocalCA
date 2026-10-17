"""
Certificate and key downloads.

The format table decides what is public and what a private format
requires, and it is served to the SPA, so a menu cannot offer a format
these endpoints do not answer.
"""

from urllib.parse import quote
from django.http import Http404
from django.utils import timezone
from django.utils.translation import gettext as _
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat, pkcs7
from cryptography import x509
from ..ca import CertificateAuthority
from ..keys import KeyUnavailable, is_wrapped, private_key_pem
from ..models import AuditLog, IntermediateCertificate, LeafCertificate, RootCertificate
from ..vault import VaultLocked
from .common import _error, _payload, api_not_found, can_manage_certificate, certificate_display_name, is_owner, kind_of
from .keystore import _vault_locked


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
    name = certificate_display_name(cert)
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

    name = certificate_display_name(cert)
    kind = kind_of(cert)
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
        key_pem = private_key_pem(cert, kind)
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
