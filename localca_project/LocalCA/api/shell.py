"""
The single-page app shell.
"""

from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET


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
