"""
Root URL configuration.

Django serves the JSON API under /api/ and the built Vue single-page app for
everything else. The application templates were removed when the frontend moved
to Vue 3; only Django's own admin still uses templates.
"""
from django.contrib import admin
from django.urls import include, path

from LocalCA.api import spa_index

urlpatterns = [
    path('api/', include('LocalCA.api_urls')),

    # Django's admin is independent of the app UI and keeps its own login page.
    path('admin/', admin.site.urls),
]

# Single-page app shell. The catch-all lets the client router handle deep links
# such as /create/leaf; it is listed last so it cannot shadow /api/ or /admin/.
urlpatterns += [
    path('', spa_index, name='spa-root'),
    path('<path:resource>', spa_index, name='spa'),
]
