"""
Bearer-token (personal access token) authentication for the JSON API.

Two small middlewares rather than one, because the default middleware order
checks CSRF before AuthenticationMiddleware. A bearer request has no session and
no CSRF cookie, so the check has to be waived before Django reaches
CsrfViewMiddleware; the token itself is then resolved after
AuthenticationMiddleware, which is the middleware that would otherwise overwrite
request.user with the session user.

Only /api/ paths are affected. Session-authenticated browser requests keep the
normal CSRF behaviour.
"""

from django.http import JsonResponse
from django.utils import timezone
from django.utils.translation import gettext as _

from .access_tokens import hash_token
from .models import PersonalAccessToken


def bearer_token(request):
    """The raw bearer token from the Authorization header, or None."""
    header = request.headers.get('Authorization', '')
    scheme, separator, value = header.partition(' ')
    if not separator or scheme.lower() != 'bearer':
        return None
    value = value.strip()
    return value or None


class PATCsrfBypassMiddleware:  # pylint: disable=too-few-public-methods
    """
    Skip CSRF for bearer-authenticated API requests.

    This runs before CsrfViewMiddleware. It deliberately does not validate the
    token: an invalid token is refused by PATAuthMiddleware before any view runs,
    and the flag only matters for unsafe methods.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/api/') and bearer_token(request):
            request._dont_enforce_csrf_checks = True
        return self.get_response(request)


class PATAuthMiddleware:  # pylint: disable=too-few-public-methods
    """
    Resolve a bearer token to its owner and make that the request user.

    The token carries the owner's full permissions; there is no separate scope.
    Only a non-revoked token belonging to an active account is accepted. The
    last-used timestamp is updated so the token list can show stale tokens.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw = bearer_token(request)
        if not raw or not request.path.startswith('/api/'):
            return self.get_response(request)

        token = (PersonalAccessToken.objects
                 .select_related('user')
                 .filter(token_hash=hash_token(raw), revoked_at__isnull=True)
                 .first())
        if token is None or not token.user.is_active:
            response = JsonResponse(
                {'ok': False,
                 'errors': [_('Invalid or revoked personal access token.')]},
                status=401)
            response['WWW-Authenticate'] = 'Bearer'
            return response

        request.user = token.user
        request.personal_access_token = token
        PersonalAccessToken.objects.filter(pk=token.pk).update(
            last_used_at=timezone.now())
        return self.get_response(request)
