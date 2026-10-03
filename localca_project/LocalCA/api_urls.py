"""
URL map for the LocalCA JSON API.

Every application page is rendered by the Vue single-page app; these endpoints
only serve data and certificate material.
"""
from django.urls import path

from . import api

app_name = 'api'

urlpatterns = [
    # session / auth
    path('session/', api.api_session, name='session'),
    path('login/', api.api_login, name='login'),
    path('logout/', api.api_logout, name='logout'),
    path('password/', api.api_change_password, name='change_password'),
    path('meta/', api.api_meta, name='meta'),

    # vault: private key encryption
    path('vault/status/', api.api_vault_status, name='vault_status'),
    path('vault/unseal/', api.api_vault_unseal, name='vault_unseal'),
    path('vault/lock/', api.api_vault_lock, name='vault_lock'),
    path('vault/password/', api.api_vault_rotate, name='vault_rotate'),

    # certificate tree and creation options
    path('certificates/', api.api_certificates, name='certificates'),
    path('certificates/mine/', api.api_my_certificates, name='my_certificates'),
    path('issuers/', api.api_issuers, name='issuers'),

    # writes
    path('import/', api.api_import_certificates, name='import_certificates'),
    path('certificates/create/<str:cert_type>/', api.api_create_certificate,
         name='create_certificate'),
    path('certificates/<str:cert_type>/<int:cert_id>/revoke/',
         api.api_revoke_certificate, name='revoke_certificate'),
    path('certificates/<str:cert_type>/<int:cert_id>/delete/',
         api.api_delete_certificate, name='delete_certificate'),

    # downloads. There is no plaintext private key endpoint by design; see the
    # note in api.py above api_download_pkcs12.
    path('download/<str:serial_number>/pem/', api.api_download_pem, name='download_pem'),
    path('download/<str:serial_number>/pkcs12/', api.api_download_pkcs12,
         name='download_pkcs12'),

    # audit (staff)
    path('audit/', api.api_audit_log, name='audit_log'),
]
