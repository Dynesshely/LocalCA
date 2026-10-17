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
    path('api/', include('LocalCA.api_urls')),

    # Any other /api/ path is a JSON 404: falling through to the SPA shell would
    # answer a mistyped endpoint with an HTML 200.
    path('api/<path:resource>', api_not_found, name='api-not-found'),

    # Browsers ask for these on their own; the SPA shell would answer with a 200
    # that no browser can render as an icon.
    path('favicon.ico',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon.ico', permanent=False)),
    path('favicon.svg',
         RedirectView.as_view(url=settings.STATIC_URL + 'favicon.svg', permanent=False)),

    path('admin/', admin.site.urls),
]

# The catch-all lets the client router handle deep links; it is last so it cannot
# shadow /api/ or /admin/.
urlpatterns += [
    path('', spa_index, name='spa-root'),
    path('<path:resource>', spa_index, name='spa'),
]
