"""
Request/response plumbing, permissions and the certificate-kind map.

Shared by more than one endpoint group; nothing here answers a request
on its own.
"""

import json
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET
from ..models import IntermediateCertificate, LeafCertificate, RevokedCertificate, RootCertificate


#: Certificate kinds addressable through the management endpoints. A whitelist:
#: the value is never used to build an import path.
CERTIFICATE_KINDS = {
    'root': RootCertificate,
    'intermediate': IntermediateCertificate,
    'leaf': LeafCertificate,
}


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


@require_GET
def api_not_found(_request, **_ignored):
    """
    JSON 404 for unmatched /api/ paths.

    Without this the SPA catch-all would answer with an HTML 200, which makes a
    mistyped or removed endpoint look successful to an API client. Kept free of
    authentication so it cannot be used to probe for existing routes.
    """
    return JsonResponse(
        {'ok': False, 'errors': ['No such API endpoint.']}, status=404)


def kind_of(cert) -> str:
    '''The URL kind of a certificate object.'''
    if isinstance(cert, LeafCertificate):
        return 'leaf'
    if isinstance(cert, IntermediateCertificate):
        return 'intermediate'
    return 'root'
