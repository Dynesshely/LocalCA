"""
Importing existing certificate material: analyse, then apply.
"""

import json
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST
from ..models import AuditLog
from .. import import_service, importers
from ..vault import unsealed
from .common import _error, _ok, _payload
from .keystore import _credential_or_error, _vault_locked


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
        return _error(_('Authentication required.'), status=401)

    uploads = request.FILES.getlist('files')
    if not uploads:
        return _error(_('Attach at least one file to import.'))

    password = (request.POST.get('password') or '').strip() or None
    dry_run = str(request.POST.get('dry_run', '0')).strip().lower() in (
        '1', 'true', 'yes', 'on')

    try:
        overrides = json.loads(request.POST.get('overrides') or '{}')
    except (TypeError, ValueError):
        return _error(_('The overrides field must be a JSON object.'))
    if not isinstance(overrides, dict):
        return _error(_('The overrides field must be a JSON object.'))

    try:
        bundle = importers.parse_uploads(uploads, password=password)
    except importers.ImportProblem as exc:
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

    credential = None
    if plan.requires_vault_unlock:
        # The same rule as creating a certificate: an import that carries keys has
        # to say which credential wraps them, and an account with none is asked to
        # create one rather than dropping the keys on the floor.
        credential, error = _credential_or_error(request, overrides.get('credential_id')
                                                or _payload(request).get('credential_id'))
        if error:
            return error
        if not unsealed.is_unsealed(credential.id):
            return _vault_locked(
                _('The keystore credential "%(name)s" is locked. Open it to store '
                  'the private keys carried by this import.')
                % {'name': credential.name}, credential)

    result = import_service.apply_plan(plan, request.user, credential)
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
