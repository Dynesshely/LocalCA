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
from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
)
from .serializers import (
    intermediate_to_dict,
    leaf_to_dict,
    revocation_reasons,
    root_to_dict,
    user_to_dict,
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
    '''Session login.'''
    payload = _payload(request)
    if not payload:
        return _error('Malformed request body.')

    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    if not username or not password:
        return _error('Username and password are required.')

    user = authenticate(request, username=username, password=password)
    if user is None:
        AuditLog.objects.create(
            action='ACCESS', performed_by=None,
            details=f'Failed login attempt for username: {username[:150]}')
        return _error('Invalid username or password.', status=401)

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


@require_GET
def api_meta(_request):
    '''Static metadata the UI needs: revocation reasons and validity bounds.'''
    from .forms import MAX_CA_VALIDITY_DAYS, MAX_LEAF_VALIDITY_DAYS

    return _ok({
        'revocation_reasons': revocation_reasons(),
        'max_validity_days': {
            'root': MAX_CA_VALIDITY_DAYS,
            'intermediate': MAX_CA_VALIDITY_DAYS,
            'leaf': MAX_LEAF_VALIDITY_DAYS,
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

    Only their own: signing consumes that CA's private key.
    '''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    roots = [root_to_dict(root, request.user)
             for root in RootCertificate.objects.filter(
                 created_by=request.user).order_by('-created_at')]
    intermediates = [intermediate_to_dict(intermediate, request.user)
                     for intermediate in IntermediateCertificate.objects.filter(
                         created_by=request.user).order_by('-created_at')]
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

    try:
        if cert_type == 'root':
            form = RootCertificateForm(_payload(request))
            if not form.is_valid():
                return _error(_form_errors(form))
            name = form.cleaned_data['common_name']
            data = ca.create_root_certificate(name, form.cleaned_data['validity_days'])
            certificate = RootCertificate.objects.create(
                name=name,
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted=data['private_key'],
                valid_until=data['valid_until'],
                created_by=request.user,
            )

        elif cert_type == 'intermediate':
            form = IntermediateCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _error(_form_errors(form))
            name = form.cleaned_data['common_name']
            root = form.cleaned_data['root_id']
            data = ca.create_intermediate_certificate(
                name, form.cleaned_data['validity_days'],
                root.public_key, root.private_key_encrypted)
            certificate = IntermediateCertificate.objects.create(
                name=name,
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted=data['private_key'],
                signed_by_root=root,
                valid_until=data['valid_until'],
                created_by=request.user,
            )

        elif cert_type == 'leaf':
            form = LeafCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _error(_form_errors(form))
            name = form.cleaned_data['common_name']
            intermediate = form.cleaned_data['intermediate_id']
            sans = form.san_list()
            data = ca.create_leaf_certificate(
                common_name=name,
                san_list=sans,
                validity_days=form.cleaned_data['validity_days'],
                intermediate_public_key=intermediate.public_key,
                intermediate_private_key=intermediate.private_key_encrypted,
            )
            certificate = LeafCertificate.objects.create(
                common_name=name,
                san=','.join(sans),
                valid_until=data['valid_until'],
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted=data['private_key'],
                signed_by_intermediate=intermediate,
                created_by=request.user,
            )
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


@require_GET
def api_download_private(request, serial_number):
    '''Private key PEM. Owner only.'''
    if not request.user.is_authenticated:
        return _error('Authentication required.', status=401)

    from django.http import HttpResponse

    cert = _find_by_serial(serial_number)
    if not is_owner(request.user, cert):
        raise PermissionDenied('You do not have permission')

    name = certificate_display_name(cert)
    AuditLog.objects.create(
        action='DOWNLOAD_PRIVATE_KEY', performed_by=request.user,
        details=f'Downloaded private key for certificate: {name} (Serial: {cert.serial_number})')

    response = HttpResponse(cert.private_key_encrypted, content_type='text/plain')
    response['Content-Disposition'] = _attachment_disposition(f'{name}_private.pem')
    response['Cache-Control'] = 'no-store'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@require_http_methods(['GET', 'POST'])
def api_download_pkcs12(request, serial_number):
    '''
    PKCS12 bundle (certificate + private key). Owner only.

    Accepts GET (no export password) or POST with ``p12_password``.
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
    else:
        name = cert.name
        ca_cert_pem = None

    password = None
    if request.method == 'POST':
        raw = (str(_payload(request).get('p12_password') or '')).strip()
        password = raw or None

    bundle = CertificateAuthority().create_pkcs12(
        cert_pem=cert.public_key,
        private_key_pem=cert.private_key_encrypted,
        ca_cert_pem=ca_cert_pem,
        friendly_name=name,
        password=password,
    )

    AuditLog.objects.create(
        action='DOWNLOAD_PKCS12', performed_by=request.user,
        details=f'Downloaded PKCS12 bundle for certificate: {name} (Serial: {cert.serial_number})')

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
