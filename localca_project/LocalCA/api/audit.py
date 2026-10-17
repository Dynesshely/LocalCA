"""
The audit log (staff only).
"""

from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET
from ..models import AuditLog
from .common import _error, _ok


@require_GET
def api_audit_log(request):
    '''Recent audit entries. Staff only: it exposes other users' activity.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
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
