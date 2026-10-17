"""
Static metadata the interface needs: reasons, bounds, format tables.
"""

from django.views.decorators.http import require_GET
from .. import importers
from ..serializers import revocation_reasons
from .common import _ok
from .downloads import download_formats


@require_GET
def api_meta(_request):
    '''Static metadata the UI needs: revocation reasons, validity bounds, import formats.'''
    from ..forms import MAX_CA_VALIDITY_DAYS, MAX_LEAF_VALIDITY_DAYS

    return _ok({
        'revocation_reasons': revocation_reasons(),
        'max_validity_days': {
            'root': MAX_CA_VALIDITY_DAYS,
            'intermediate': MAX_CA_VALIDITY_DAYS,
            'leaf': MAX_LEAF_VALIDITY_DAYS,
        },
        # The SPA renders its download menu from this list, so a format the
        # server does not serve cannot be offered, and vice versa.
        'download_formats': download_formats(),
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
