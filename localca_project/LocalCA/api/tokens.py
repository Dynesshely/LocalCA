"""
Personal access tokens: list, create and revoke.

Token management is intentionally session-only. A PAT can act as its owner on
the certificate API, but it cannot mint another PAT or revoke its siblings: a
leaked token must not be able to extend its own lifetime or create a cleaner
replacement.
"""

from django.db import IntegrityError
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST, require_http_methods

from ..access_tokens import display_prefix, generate_token, hash_token
from ..models import AuditLog, PersonalAccessToken
from .common import _error, _ok, _payload


def _token_to_dict(token):
    """Non-secret representation of a token, for lists and responses."""
    return {
        'id': token.id,
        'name': token.name,
        'prefix': token.token_prefix,
        'created_at': token.created_at.isoformat() if token.created_at else None,
        'last_used_at': (token.last_used_at.isoformat()
                         if token.last_used_at else None),
        'revoked_at': (token.revoked_at.isoformat()
                       if token.revoked_at else None),
        'revoked': token.revoked,
    }


def _session_only(request):
    """
    Token management is a session action, not a token action.

    Returning an error here, rather than simply falling through to request.user,
    is what stops a leaked PAT from creating more tokens.
    """
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)
    if getattr(request, 'personal_access_token', None) is not None:
        return _error(
            _('Access tokens can only be managed from a signed-in session.'),
            status=403)
    return None


@require_http_methods(['GET', 'POST'])
def api_tokens(request):
    """
    GET  /api/tokens/  list this account's tokens (revoked ones included)
    POST /api/tokens/  create one; the raw token is returned exactly once
    """
    denied = _session_only(request)
    if denied:
        return denied

    if request.method == 'GET':
        tokens = PersonalAccessToken.objects.filter(user=request.user)
        return _ok({'tokens': [_token_to_dict(token) for token in tokens]})

    payload = _payload(request)
    name = (payload.get('name') or '').strip()
    if not name:
        return _error(_('A name is required for the access token.'))
    if len(name) > 100:
        return _error(_('The token name cannot be longer than 100 characters.'))

    raw = generate_token()
    try:
        token = PersonalAccessToken.objects.create(
            user=request.user,
            name=name,
            token_prefix=display_prefix(raw),
            token_hash=hash_token(raw),
        )
    except IntegrityError:
        return _error(_('An access token with that name already exists.'))

    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Created personal access token: {name} ({token.token_prefix}...)')

    return _ok({'token': raw, 'access_token': _token_to_dict(token)}, status=201)


@require_POST
def api_token_revoke(request, token_id):
    """Revoke one of this account's tokens. Revocation is kept, not deleted."""
    denied = _session_only(request)
    if denied:
        return denied

    token = PersonalAccessToken.objects.filter(
        user=request.user, pk=token_id).first()
    if token is None:
        return _error(_('That access token does not exist.'), status=404)
    if token.revoked:
        return _error(_('That access token is already revoked.'), status=409)

    token.revoked_at = timezone.now()
    token.save(update_fields=['revoked_at'])
    AuditLog.objects.create(
        action='ACCESS', performed_by=request.user,
        details=f'Revoked personal access token: {token.name} ({token.token_prefix}...)')

    return _ok({'access_token': _token_to_dict(token)})
