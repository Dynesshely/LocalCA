"""
Minting certificates: create a root, intermediate or leaf, and renew a
leaf with an edited SAN list.
"""

from django.db import IntegrityError, transaction
from django.http import Http404
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST
from ..ca import CertificateAuthority
from ..forms import IntermediateCertificateForm, LeafCertificateForm, RootCertificateForm
from ..keys import KeyUnavailable, credential_of, credential_root_key, default_credential, private_key_pem, store_wrapped_key
from ..models import AuditLog, IntermediateCertificate, LeafCertificate, RevokedCertificate, RootCertificate
from ..vault import VaultLocked
from .common import _error, _form_error_response, _ok, _payload, can_manage_certificate
from .keystore import _credential_or_error, _credential_to_dict, _vault_locked


@require_POST
def api_create_certificate(request, cert_type):
    '''
    Create a root, intermediate or leaf certificate.

    The signing authority is restricted by the form's queryset, so a crafted
    request cannot consume another user's CA private key.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    ca = CertificateAuthority()

    def target_credential():
        '''
        Which credential the *new* key is wrapped with.

        Resolved after the form, so a request naming somebody else's issuing CA is
        still refused as a bad request rather than as a keystore problem. A
        request may name a credential; without one it is the account's default, and
        an account with none is asked to create one rather than silently writing a
        plaintext key.
        '''
        credential, error = _credential_or_error(
            request, _payload(request).get('credential_id'))
        if error:
            return None, error
        try:
            credential_root_key(credential)
        except VaultLocked as exc:
            return None, _vault_locked(
                _('The keystore credential "%(name)s" is locked. Open it to store '
                  'the private key that is about to be created.')
                % {'name': credential.name}, exc.credential)
        return credential, None

    # A root is self-signed, so creating one needs no stored key. Signing an
    # intermediate or a leaf consumes the issuer's private key, which requires
    # that key's own credential to be open.
    try:
        if cert_type == 'root':
            form = RootCertificateForm(_payload(request))
            if not form.is_valid():
                return _form_error_response(form)
            credential, error = target_credential()
            if error:
                return error
            name = form.cleaned_data['common_name']
            data = ca.create_root_certificate(name, form.cleaned_data['validity_days'])
            certificate = RootCertificate.objects.create(
                name=name,
                serial_number=str(data['serial_number']),
                public_key=data['public_key'],
                private_key_encrypted='',
                valid_until=data['valid_until'],
                created_by=request.user,
            )
            store_wrapped_key(certificate, 'root', data['private_key'], credential)

        elif cert_type == 'intermediate':
            form = IntermediateCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _form_error_response(form)
            name = form.cleaned_data['common_name']
            root = form.cleaned_data['root_id']
            try:
                issuer_key = private_key_pem(root, 'root')
            except KeyUnavailable as exc:
                return _error(str(exc), status=409)
            except VaultLocked as exc:
                return _vault_locked(str(exc), exc.credential)
            credential, error = target_credential()
            if error:
                return error
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
            store_wrapped_key(certificate, 'intermediate', data['private_key'],
                              credential)

        elif cert_type == 'leaf':
            form = LeafCertificateForm(_payload(request), user=request.user)
            if not form.is_valid():
                return _form_error_response(form)
            name = form.cleaned_data['common_name']
            intermediate = form.cleaned_data['intermediate_id']
            sans = form.san_list()
            try:
                issuer_key = private_key_pem(intermediate, 'intermediate')
            except KeyUnavailable as exc:
                return _error(str(exc), status=409)
            except VaultLocked as exc:
                return _vault_locked(str(exc), exc.credential)
            credential, error = target_credential()
            if error:
                return error
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
            store_wrapped_key(certificate, 'leaf', data['private_key'], credential)
        else:
            raise Http404('Unknown certificate kind')

    except ValueError as exc:
        return _error(_('Could not create the certificate: %(error)s') % {'error': exc})
    except IntegrityError:
        # Unique constraints on the name columns; the forms check first, so this
        # is a race between two concurrent submissions.
        return _error(_('A certificate with that name already exists.'))

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


@require_POST
def api_renew_leaf_certificate(request, cert_id):
    '''
    Re-issue a leaf certificate with an edited SAN list.

    Renewal is a *new* certificate, not an edit: a certificate is what it was
    signed as, so rewriting this row's SANs or serial would leave every deployed
    copy describing something that never existed. The old row keeps its bytes,
    gains a pointer to its replacement (`renewed_by`), and is revoked as
    `superseded` unless it already was -- so the answer to "which certificate is
    live for this name?" stays unambiguous.

    The common name and the signing intermediate are inherited, and the key pair
    is always regenerated: re-issuing around a key that may have leaked is the
    point of renewal.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    leaf = LeafCertificate.objects.filter(pk=cert_id).first()
    if leaf is None:
        return _error(_('That certificate does not exist.'), status=404)
    if not can_manage_certificate(request.user, leaf):
        return _error(_('You can only renew a certificate you own.'), status=403)
    if leaf.renewed_by_id:
        return _error(
            _('This certificate was already renewed as %(serial)s. Renew that '
              'one instead.')
            % {'serial': leaf.renewed_by.serial_number}, status=409,
            renewed_by=leaf.renewed_by_id)

    data = _payload(request)
    # The common name is inherited rather than accepted: changing it is issuing a
    # different certificate, which is what Create Leaf is for. `renewing` tells the
    # form that this one row is allowed to keep the name it already has.
    form = LeafCertificateForm(
        {
            'common_name': leaf.common_name,
            'san': data.get('san', ''),
            'validity_days': data.get('validity_days'),
            'intermediate_id': leaf.signed_by_intermediate_id,
        },
        user=request.user,
        renewing=leaf,
    )
    if not form.is_valid():
        return _form_error_response(form)

    intermediate = form.cleaned_data['intermediate_id']
    sans = form.san_list()

    # Signing consumes the intermediate's key, so *its* credential has to be open
    # -- which is not necessarily the one the new key will be stored under.
    try:
        issuer_key = private_key_pem(intermediate, 'intermediate')
    except KeyUnavailable as exc:
        return _error(str(exc), status=409)
    except VaultLocked as exc:
        return _vault_locked(str(exc), exc.credential)

    # The replacement key stays where the old one was: an operator who filed this
    # certificate under "Production" did not ask for it to move. An explicit
    # `credential_id` still wins, and a cleartext or credential-less old key falls
    # back to the account's default.
    requested = data.get('credential_id')
    if requested:
        credential, error = _credential_or_error(request, requested)
    else:
        credential = credential_of(leaf) or default_credential(request.user)
        error = None if credential is not None else _vault_locked(_(
            'No keystore credential exists yet, so private keys cannot be '
            'stored. Create one (a name and a password) first.'))
    if error:
        return error
    try:
        credential_root_key(credential)
    except VaultLocked as exc:
        return _vault_locked(
            _('The keystore credential "%(name)s" is locked. Open it to store '
              'the renewed private key.') % {'name': credential.name},
            exc.credential)

    ca = CertificateAuthority()
    try:
        issued = ca.create_leaf_certificate(
            common_name=leaf.common_name,
            san_list=sans,
            validity_days=form.cleaned_data['validity_days'],
            intermediate_public_key=intermediate.public_key,
            intermediate_private_key=issuer_key,
        )
    except ValueError as exc:
        return _error(_('Could not create the certificate: %(error)s')
                      % {'error': exc})

    with transaction.atomic():
        replacement = LeafCertificate.objects.create(
            common_name=leaf.common_name,
            san=','.join(sans),
            valid_until=issued['valid_until'],
            serial_number=str(issued['serial_number']),
            public_key=issued['public_key'],
            private_key_encrypted='',
            signed_by_intermediate=intermediate,
            created_by=request.user,
        )
        store_wrapped_key(replacement, 'leaf', issued['private_key'], credential)

        # Supersede the old one, but never rewrite a revocation that is already
        # there: a certificate revoked for key compromise stays revoked for that
        # reason, and a renewal is not a way to launder that history.
        revoked_previous = not RevokedCertificate.objects.filter(
            certificate=leaf).exists()
        if revoked_previous:
            RevokedCertificate.objects.create(
                created_by=request.user,
                reason=RevokedCertificate.RevocationReason.SUPERSEDED,
                comment=(f'Renewed as {replacement.serial_number} '
                         f'({", ".join(sans)})'),
                certificate=leaf,
            )
        leaf.renewed_by = replacement
        leaf.save(update_fields=['renewed_by'])

    AuditLog.objects.create(
        action='CREATE', performed_by=request.user,
        details=(f'Renewed leaf certificate "{leaf.common_name}" '
                 f'({leaf.serial_number} -> {replacement.serial_number})'))
    if revoked_previous:
        AuditLog.objects.create(
            action='REVOKE', performed_by=request.user,
            details=(f'Revoked leaf certificate: {leaf.common_name} '
                     f'(reason: superseded, renewed as {replacement.serial_number})'))

    return _ok({
        'certificate': {
            'kind': 'leaf',
            'id': replacement.id,
            'name': replacement.common_name,
            'serial_number': replacement.serial_number,
            'valid_until': replacement.valid_until.isoformat(),
            'sans': sans,
        },
        'previous': {
            'id': leaf.id,
            'serial_number': leaf.serial_number,
            'revoked': revoked_previous,
        },
        'credential': _credential_to_dict(credential),
    }, status=201)
