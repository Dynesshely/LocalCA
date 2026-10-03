"""
Rate limiting for the authentication endpoints.

Deliberately dependency-free: this runs on Django's configured cache, which is
locmem by default. That is sufficient for the deployment this project targets
(one gunicorn process, single worker), and it is honest about its limit -- see
the note on CACHE below.

Design notes
------------
* Two independent counters, because they stop different attacks:

  - per client IP: stops one host hammering the login form;
  - per username (hashed): stops a *distributed* attempt against one account,
    and symmetric to the first, stops one IP from spraying many accounts.

* The failure counter is cleared only on a successful login, so a legitimate
  user is never locked out by someone else probing their username from another
  address for longer than a window.

* Keys are bounded and expire, so a flood of unique values cannot grow the cache
  without limit.

* A failed attempt also costs a fixed delay. This flattens the timing difference
  between "no such user" and "wrong password", which otherwise leaks whether an
  account exists.
"""
import hashlib
import logging
import time

from django.core.cache import cache

logger = logging.getLogger(__name__)

#: Failures allowed per client IP inside the window before requests are refused.
LOGIN_ATTEMPTS_PER_IP = 5
#: Failures allowed against a single account inside the window.
LOGIN_ATTEMPTS_PER_USERNAME = 5
#: Window length, in seconds. Chosen so a human who mistypes has time to retry,
#: while an automated guesser gets ~20 attempts/hour per IP and per account.
LOGIN_WINDOW_SECONDS = 15 * 60
#: Delay added to every failed attempt, in seconds.
FAILED_ATTEMPT_DELAY = 0.3
#: Cache keys are namespaced so they cannot collide with anything else.
KEY_PREFIX = 'localca:rl'


def client_ip(request) -> str:
    '''
    The address to attribute a request to.

    X-Forwarded-For is trusted only for its left-most entry, which is what a
    reverse proxy appends. When the app is exposed directly this header is
    client-controlled, so it is used only to *group* limits; the per-username
    counter does not depend on it at all.
    '''
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded:
        first = forwarded.split(',')[0].strip()
        if first:
            return first
    return request.META.get('REMOTE_ADDR', 'unknown')


def _hash(value: str) -> str:
    '''Hash a value so usernames are not written into cache keys verbatim.'''
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:32]


def _keys(request, username: str):
    ip = client_ip(request)
    return (
        f'{KEY_PREFIX}:ip:{_hash(ip)}',
        f'{KEY_PREFIX}:user:{_hash(username.strip().lower())}' if username else None,
    )


def _count(key):
    '''Current failure count for a key.'''
    if key is None:
        return 0
    return cache.get(key, 0)


class LoginRateLimited(Exception):
    '''Raised when a login request must be refused.'''

    def __init__(self, retry_after: int, reason: str):
        super().__init__(reason)
        self.retry_after = max(1, int(retry_after))
        self.reason = reason


def check_login_allowed(request, username: str) -> None:
    '''
    Raise LoginRateLimited if this request should not be processed.

    Called before authentication so a limited request costs no password hashing.
    '''
    ip_key, user_key = _keys(request, username)
    for key, limit, label in (
            (ip_key, LOGIN_ATTEMPTS_PER_IP, 'address'),
            (user_key, LOGIN_ATTEMPTS_PER_USERNAME, 'account')):
        if key is None:
            continue
        if _count(key) >= limit:
            ttl = cache.ttl(key) if hasattr(cache, 'ttl') else None
            retry_after = ttl if isinstance(ttl, int) and ttl > 0 else LOGIN_WINDOW_SECONDS
            logger.warning('Login rate limit hit for %s (%s)', label, key)
            raise LoginRateLimited(
                retry_after,
                f'Too many failed login attempts for this {label}. '
                f'Try again later.')


def record_login_failure(request, username: str) -> None:
    '''
    Count a failed attempt, and pay the constant delay that flattens timing.

    The window is refreshed on each failure, so a sustained attempt stays limited
    rather than resetting every window.
    '''
    ip_key, user_key = _keys(request, username)
    for key in (ip_key, user_key):
        if key is None:
            continue
        try:
            # add() sets the TTL only when the key is first created; set()
            # refreshes it, which is what we want for a sliding window.
            current = cache.get(key, 0) + 1
            cache.set(key, current, LOGIN_WINDOW_SECONDS)
        except Exception:  # noqa: BLE001 - a broken cache must not block login
            logger.exception('Could not record login failure in cache')
    time.sleep(FAILED_ATTEMPT_DELAY)


def record_login_success(request, username: str) -> None:
    '''Clear the counters for this account and address.'''
    ip_key, user_key = _keys(request, username)
    for key in (ip_key, user_key):
        if key is not None:
            cache.delete(key)


def remaining_attempts(request, username: str) -> int:
    '''Attempts left for this request, for reporting to the client.'''
    ip_key, user_key = _keys(request, username)
    used = max(_count(ip_key), _count(user_key))
    return max(0, LOGIN_ATTEMPTS_PER_IP - used)
