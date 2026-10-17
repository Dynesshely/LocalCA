"""Settings for the LocalCA Django project.

Environment variables are the only source of deployment-specific values; see
README ("Configuration") for the full list.
"""

from pathlib import Path
import os

from django.core.exceptions import ImproperlyConfigured

# The localca_project/ package directory: managing.py, the SQLite path and the
# WSGI module are all relative to it.
BASE_DIR = Path(__file__).resolve().parent.parent

# The Vue sources sit beside localca_project/, not inside it.
FRONTEND_DIR = BASE_DIR.parent / 'frontend'
FRONTEND_DIST = FRONTEND_DIR / 'dist'


def _env_bool(name, default=False):
    '''Read a boolean environment variable.'''
    return os.environ.get(name, str(default)).strip().lower() in (
        '1', 'true', 'yes', 'on')


#: Running the test suite: narrower than DEBUG, it only supplies a throwaway key
#: and relaxes host validation for the test client.
TESTING = _env_bool('DJANGO_TESTING')

# No usable default: the fallback below is a published constant and is only
# installed for tests, where nothing real is issued.
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if TESTING:
        SECRET_KEY = 'django-insecure-testing-only-not-a-real-key'
    else:
        raise ImproperlyConfigured(
            'DJANGO_SECRET_KEY is not set. LocalCA refuses to start without '
            'it. Generate one and export it, e.g.:\n'
            '  export DJANGO_SECRET_KEY=$(python3 -c "import secrets; '
            'print(secrets.token_urlsafe(50))")\n'
            'See .env.example for the docker deployment.'
        )

# With DEBUG on, an unhandled exception renders a page containing SECRET_KEY,
# the settings module and local variables.
DEBUG = _env_bool('DJANGO_DEBUG') or TESTING

# A wildcard is only tolerated with DEBUG: otherwise it disables Django's Host
# header validation.
_hosts = [h.strip() for h in os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')
          if h.strip()]
ALLOWED_HOSTS = _hosts or (['*'] if DEBUG else [])
if TESTING and not _hosts:
    ALLOWED_HOSTS = ['testserver', 'localhost']
if not DEBUG and not ALLOWED_HOSTS:
    raise ImproperlyConfigured(
        'DJANGO_ALLOWED_HOSTS must list the hostnames this deployment is '
        'served under when DEBUG is off (comma separated).')


# Applications

INSTALLED_APPS = [
    'LocalCA',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # Reads Accept-Language. The SPA sends the locale the user picked, so API
    # messages match the language on screen. Order matters: after Session
    # middleware, before Common.
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'localca_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # Only the built Vue shell (index.html); Django renders no app pages.
        # APP_DIRS stays on for Django's own admin.
        'DIRS': [str(FRONTEND_DIST)],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'localca_project.wsgi.application'


# Database

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db' / 'db.sqlite3',
    }
}


# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# English is the default because msgids are written in English: an untranslated
# string then degrades to the source text rather than to an empty label.
LANGUAGE_CODE = 'en-us'

# Languages the API can answer in. LocaleMiddleware only activates a locale from
# this list, so a stray Accept-Language cannot select a half-translated one.
LANGUAGES = [
    ('en', 'English'),
    ('zh-hans', '简体中文'),
]

# Catalogues live next to the project (localca_project/locale/<locale>/LC_MESSAGES),
# which is where `manage.py makemessages -l zh_Hans` writes them.
LOCALE_PATHS = [BASE_DIR / 'locale']

TIME_ZONE = os.environ.get('TZ', 'UTC')

USE_I18N = True

USE_TZ = True


# Static files.

# Behind a reverse proxy that strips a path prefix (TRAEFIK_DEPLOYMENT.md), the
# prefix is only needed for URL generation -- the proxy has already removed it from
# the request path, so this is FORCE_SCRIPT_NAME rather than WSGI's SCRIPT_NAME.
FORCE_SCRIPT_NAME = os.environ.get('URL_PREFIX', None)
if FORCE_SCRIPT_NAME:
    STATIC_URL = FORCE_SCRIPT_NAME + '/static/'
else:
    STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# The Vue build: index.html is the SPA shell, dist/assets the hashed bundle.
# Point at the dist root -- the static finder maps requested paths onto it, so
# assets/ here would look for assets/assets/*.
STATICFILES_DIRS = [
    FRONTEND_DIST,
]


# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication settings
# The app UI is a Vue SPA served at '/', so Django's own auth redirects (used
# only by the admin) point at the admin login, which still exists.
LOGIN_REDIRECT_URL = '/admin/'
LOGOUT_REDIRECT_URL = '/'
LOGIN_URL = '/admin/login/'

csrf_env = os.environ.get('CSRF_TRUSTED_ORIGINS')
CSRF_TRUSTED_ORIGINS = [o.strip() for o in csrf_env.split(",") if o.strip()] if csrf_env else []

# The Vue frontend is served from the same origin as the API, so it authenticates
# with the session cookie and sends the CSRF token back in the X-CSRFToken
# header. The CSRF cookie must therefore stay readable from JavaScript (Django's
# default); it is not marked HttpOnly, and that is intentional. The session
# cookie, which is the actual credential, stays HttpOnly.
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SAMESITE = 'Lax'

# Transport / cookie hardening. These are no-ops while the app is served over
# plain HTTP (the default docker deployment), but they take effect as soon as
# DJANGO_SECURE_COOKIES is enabled behind HTTPS, and they keep a misconfigured
# deployment from silently running with insecure cookies.
if _env_bool('DJANGO_SECURE_COOKIES'):
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = _env_bool('DJANGO_SECURE_SSL_REDIRECT', True)
    SECURE_HSTS_SECONDS = int(os.environ.get('DJANGO_HSTS_SECONDS', 31536000))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
