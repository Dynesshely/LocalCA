"""
Session, login, logout and password change.
"""

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.translation import gettext as _
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST
from ..models import AuditLog
from .. import throttle
from ..serializers import user_to_dict
from .common import _error, _form_error_response, _ok, _payload


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
        return _error(_('Malformed request body.'))

    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    if not username or not password:
        return _error(_('Username and password are required.'))

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
        return _error(_('Invalid username or password.'), status=401)

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
        return _error(_('Authentication required.'), status=401)

    form = PasswordChangeForm(request.user, _payload(request))
    if not form.is_valid():
        return _form_error_response(form)

    user = form.save()
    # Keep the current session valid after the password hash changes.
    update_session_auth_hash(request, user)
    AuditLog.objects.create(
        action='ACCESS', performed_by=user,
        details='Password changed')
    return _ok()
