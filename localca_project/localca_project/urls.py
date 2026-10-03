"""
Root URL configuration.

Django serves the JSON API under /api/ and the built Vue single-page app for
everything else. The application templates were removed when the frontend moved
to Vue 3; only Django's own admin still uses templates.
"""
from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from LocalCA.api import api_not_found, spa_index

urlpatterns = [
    # Concrete API routes first.
    path('api/', include('LocalCA.api_urls')),

    # Any other /api/ path answers JSON 404. Without this it would fall through
    # to the SPA shell below and an API client would receive an HTML 200 for a
    # mistyped or removed endpoint -- exactly the wrong signal.
    path('api/<path:resource>', api_not_found, name='api-not-found'),

    # Browsers probe /favicon.ico on their own, and anything cached before the
    # shell declared its icons still does. Without these the SPA catch-all would
    # answer with index.html: a 200 that no browser can render as an icon.
    path('favicon.ico',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon.ico', permanent=False)),
    path('favicon.svg',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon.svg', permanent=False)),

    # Django's admin is independent of the app UI and keeps its own login page.
    path('admin/', admin.site.urls),
]

# Single-page app shell. The catch-all lets the client router handle deep links
# such as /create/leaf; it is listed last so it cannot shadow /api/ or /admin/.
urlpatterns += [
    path('', spa_index, name='spa-root'),
    path('<path:resource>', spa_index, name='spa'),
]
