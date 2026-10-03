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
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_http_methods, require_POST

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
    ensure_root_key,
    is_legacy_plaintext,
    is_wrapped,
    issuers_with_key,
    private_key_pem,
    rewrap_root_key,
    root_key_for,
    store_wrapped_key,
    vault_status,
)
from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
    VaultRootKey,
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
    '''Flatten a bound form's errors into a list of readable strings.'''
    messages = []
    for field, errors in form.errors.items():
        for error in errors:
            if field == '__all__':
                messages.append(str(error))
            else:
                messages.append(f'{form.fields[field].label or field}: {error}')
    return messages or ['The submitted data was not valid.']


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
        return _error('Malformed request body.')

    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    if not username or not password:
        return _error('Username and password are required.')

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
        return _error('Invalid username or password.', status=401)

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
        return _error('Authentication required.', status=401)

    form = PasswordChangeForm(request.user, _payload(request))
    if not form.is_valid():
        return _error(_form_errors(form))

    user = form.save()
    # Keep the current session valid after the password hash changes.
    update_session_auth_hash(request, user)
    AuditLog.objects.create(
        action='ACCESS', performed_by=user,
        details='Password changed')
    return _ok()


# --------------------------------------------------------------------------
# vault (private key encryption)
# --------------------------------------------------------------------------

def _vault_payload(request):
    '''Read a vault password from either JSON or form encoding.'''
    data = _payload(request)
    return str(data.get('vault_password') or ''), data


@require_GET
def api_vault_status(request):
    '''
    Whether this account's private keys are encrypted, and whether the vault is
    currently open.

    Reports plaintext and ownerless keys honestly: an operator should be able to
    see exactly which keys the encryption does not cover.
    '''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    status = vault_status(request.user.id)
    return _ok({
        'has_root_key': status['has_root_key'],
        'unsealed': status['unsealed'],
        'unseal_remaining_seconds': status['unseal_remaining_seconds'],
        'wrapped': status['wrapped'],
        'plaintext': status['plaintext'],
        'orphaned': status['orphaned'],
        'by_kind': status['by_kind'],
    })


@require_POST
def api_vault_unseal(request):
    '''
    Open the vault with the account's vault password.

    The password is only used to unwrap the stored root key; neither it nor the
    root key is written to the session, a cookie or the database.
    '''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    password, _ = _vault_payload(request)
    if not password:
        return _error('A vault password is required.')

    try:
        ensure_root_key(request.user.id, password)
    except VaultPasswordError:
        AuditLog.objects.create(
            action='ACCESS', performed_by=request.user,
            details='Failed vault unseal attempt')
        return _error('The vault password is incorrect.', status=403)
    except VaultError as exc:
        return _error('Could not open the vault: %s' % exc)

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user, details='Vault unsealed')
    status = vault_status(request.user.id)
    return _ok({
        'unsealed': True,
        'unseal_remaining_seconds': status['unseal_remaining_seconds'],
        'wrapped': status['wrapped'],
        'plaintext': status['plaintext'],
        'orphaned': status['orphaned'],
    })


@require_POST
def api_vault_lock(request):
    '''Forget the unsealed root key immediately.'''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    unsealed.lock(request.user.id)
    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user, details='Vault locked')
    return _ok({'unsealed': False})


@require_POST
def api_vault_rotate(request):
    '''
    Change the vault password.

    Only the wrapping changes; the stored private keys are untouched, which is
    why the envelope design exists.
    '''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    data = _payload(request)
    old_password = str(data.get('old_password') or '')
    new_password = str(data.get('new_password') or '')
    if not old_password or not new_password:
        return _error('Both the current and the new vault password are required.')
    if len(new_password) < 12:
        return _error('The new vault password must be at least 12 characters.')

    try:
        rewrap_root_key(request.user.id, old_password, new_password)
    except VaultPasswordError:
        return _error('The current vault password is incorrect.', status=403)
    except VaultError as exc:
        return _error('Could not change the vault password: %s' % exc)

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details='Vault password changed')
    return _ok({'unsealed': True})


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
        return _error('Authentication required.', status=401)

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
        return _error('Authentication required.', status=401)

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
        return _error('Authentication required.', status=401)

    ca = CertificateAuthority()

    # A root is self-signed, so creating one needs no stored key and no open
    # vault. Signing an intermediate or a leaf consumes the issuer's private
    # key, which requires the vault to be open for this account.
    try:
        if cert_type == 'root':
            form = RootCertificateForm(_payload(request))
            if not form.is_valid():
                return _error(_form_errors(form))
            name = form.cleaned_data['common_name']
            data = ca.create_root_certificate(name, form.cleaned_data['validity_days'])
            # Root keys are stored wrapped. Opening the vault here rather than
            # lazily means a brand-new deployment never writes a plaintext CA key,
            # not even for a moment.
            try:
                root_key = root_key_for(request.user)
            except VaultLocked:
                return _error(
                    'Create a vault password before generating CA keys: certificate '
                    'private keys are stored encrypted and the vault is locked.',
                    status=409, vault_locked=True)
            certificate = RootCertificate.objects.create(
                name=name,
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted='',
                valid_until=data['valid_until'],
                created_by=request.user,
            )
            store_wrapped_key(certificate, 'root', data['private_key'], root_key)

        elif cert_type == 'intermediate':
            form = IntermediateCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _error(_form_errors(form))
            name = form.cleaned_data['common_name']
            root = form.cleaned_data['root_id']
            try:
                root_key = root_key_for(request.user)
            except VaultLocked:
                return _error(
                    'The vault is locked. Unlock it to sign with this root CA.',
                    status=409, vault_locked=True)
            try:
                issuer_key = private_key_pem(root, 'root', request.user)
            except KeyUnavailable as exc:
                return _error(str(exc), status=409)
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
            store_wrapped_key(certificate, 'intermediate', data['private_key'], root_key)

        elif cert_type == 'leaf':
            form = LeafCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _error(_form_errors(form))
            name = form.cleaned_data['common_name']
            intermediate = form.cleaned_data['intermediate_id']
            sans = form.san_list()
            try:
                root_key = root_key_for(request.user)
            except VaultLocked:
                return _error(
                    'The vault is locked. Unlock it to sign with this intermediate CA.',
                    status=409, vault_locked=True)
            try:
                issuer_key = private_key_pem(intermediate, 'intermediate', request.user)
            except KeyUnavailable as exc:
                return _error(str(exc), status=409)
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
            store_wrapped_key(certificate, 'leaf', data['private_key'], root_key)
        else:
            raise Http404('Unknown certificate kind')

    except ValueError as exc:
        return _error('Could not create the certificate: %s' % exc)
    except IntegrityError:
        # Unique constraints on the name columns; the forms check first, so this
        # is a race between two concurrent submissions.
        return _error('A certificate with that name already exists.')

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
        return _error('Authentication required.', status=401)

    model = CERTIFICATE_KINDS.get(cert_type)
    if model is None:
        raise Http404('Unknown certificate kind')

    form = RevokeForm(_payload(request))
    if not form.is_valid():
        return _error(_form_errors(form))
    if form.cleaned_data['type'] != cert_type or form.cleaned_data['id'] != cert_id:
        return _error('The request did not match the certificate it was sent for.')

    with transaction.atomic():
        cert = get_object_or_404(model, id=cert_id)
        if not can_manage_certificate(request.user, cert):
            raise PermissionDenied(
                'You do not have permission to revoke this certificate')

        name = certificate_display_name(cert)
        field = _revocation_field(cert_type)
        if RevokedCertificate.objects.filter(**{field: cert}).exists():
            return _error(f'Certificate "{name}" is already revoked.',
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
                _, created = RevokedCertificate.objects.get_or_create(
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
        return _error('Authentication required.', status=401)

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

@require_GET
def api_download_pem(request, serial_number):
    '''Raw PEM file download for the public certificate or chain.'''
    from django.http import HttpResponse

    cert = _find_by_serial(serial_number)
    if isinstance(cert, LeafCertificate):
        content = f'{cert.public_key}{cert.signed_by_intermediate.public_key}'
        filename = f'{cert.common_name}_chain.pem'
    else:
        content = cert.public_key
        filename = f'{certificate_display_name(cert)}.pem'

    AuditLog.objects.create(
        action='DOWNLOAD_PUBLIC_KEY',
        performed_by=request.user if request.user.is_authenticated else None,
        details=f'Downloaded public certificate for: {certificate_display_name(cert)}')

    response = HttpResponse(content, content_type='text/plain')
    response['Content-Disposition'] = _attachment_disposition(filename)
    response['X-Content-Type-Options'] = 'nosniff'
    return response


# NOTE: there is deliberately no endpoint that returns a private key as plain
# PEM. Removing it is what makes encrypting keys at rest meaningful: otherwise a
# single click would write the key to the browser's download directory, and the
# stored ciphertext would protect nothing. Operators export a password-protected
# PKCS12 bundle instead (see api_download_pkcs12).


@require_http_methods(['POST'])
def api_download_pkcs12(request, serial_number):
    '''
    PKCS12 bundle (certificate + private key). Owner only.

    POST-only and password-protected, both deliberately:

    * There is no longer an endpoint that returns a private key as plain PEM.
      Such an endpoint would undo the point of encrypting keys at rest -- one
      click would put the key in the browser's download directory.
    * The export password is required, so the private key inside the bundle is
      never written to disk unencrypted. This is the password the operator will
      be prompted for when importing the bundle.

    Requires the vault to be open for this account.
    '''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    from django.http import HttpResponse

    cert = _find_by_serial(serial_number)
    if not is_owner(request.user, cert):
        raise PermissionDenied('You do not have permission')

    if isinstance(cert, LeafCertificate):
        name = cert.common_name
        ca_cert_pem = cert.signed_by_intermediate.public_key
        kind = 'leaf'
    else:
        name = cert.name
        ca_cert_pem = None
        kind = 'root' if isinstance(cert, RootCertificate) else 'intermediate'

    password = str(_payload(request).get('p12_password') or '').strip()
    if len(password) < 8:
        return _error(
            'An export password of at least 8 characters is required: the bundle '
            'contains a private key and is never written unencrypted.',
            status=400)

    try:
        key_pem = private_key_pem(cert, kind, request.user)
    except VaultLocked:
        return _error(
            'The vault is locked. Unlock it to export this private key.',
            status=409, vault_locked=True)
    except KeyUnavailable as exc:
        return _error(str(exc), status=409)

    bundle = CertificateAuthority().create_pkcs12(
        cert_pem=cert.public_key,
        private_key_pem=key_pem,
        ca_cert_pem=ca_cert_pem,
        friendly_name=name,
        password=password,
    )

    AuditLog.objects.create(
        action='DOWNLOAD_PKCS12', performed_by=request.user,
        details=(f'Exported PKCS12 bundle for certificate: {name} '
                 f'(Serial: {cert.serial_number}, encrypted)'))

    response = HttpResponse(bundle, content_type='application/x-pkcs12')
    response['Content-Disposition'] = _attachment_disposition(f'{name}.p12')
    response['Cache-Control'] = 'no-store'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


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
        return _error('Authentication required.', status=401)

    uploads = request.FILES.getlist('files')
    if not uploads:
        return _error('Attach at least one file to import.')

    password = (request.POST.get('password') or '').strip() or None
    dry_run = str(request.POST.get('dry_run', '0')).strip().lower() in (
        '1', 'true', 'yes', 'on')

    try:
        overrides = json.loads(request.POST.get('overrides') or '{}')
    except (TypeError, ValueError):
        return _error('The overrides field must be a JSON object.')
    if not isinstance(overrides, dict):
        return _error('The overrides field must be a JSON object.')

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

    root_key = None
    if plan.requires_vault_unlock:
        try:
            root_key = root_key_for(request.user)
        except VaultLocked:
            return _error(
                'The vault is locked. Unlock it to store the private keys carried '
                'by this import.', status=409, vault_locked=True)

    result = import_service.apply_plan(plan, request.user, root_key)
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
        return _error('Authentication required.', status=401)
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
