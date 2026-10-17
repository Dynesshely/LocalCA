"""
Retiring certificates: revocation, and deletion with its cascade.
"""

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import Http404
from django.utils.translation import gettext as _
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST
from ..forms import RevokeForm
from ..models import AuditLog, IntermediateCertificate, RevokedCertificate
from .common import (
    CERTIFICATE_KINDS,
    _error,
    _form_error_response,
    _ok,
    _payload,
    _revocation_field,
    can_manage_certificate,
    certificate_display_name,
    child_certificates,
)


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
