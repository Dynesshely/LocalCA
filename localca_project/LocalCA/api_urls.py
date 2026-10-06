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

    # keystore: named credentials, and the private keys they wrap. Credential
    # actions are POST verbs under the credential rather than a REST-ish PATCH,
    # matching the rest of this API (revoke/delete) and keeping the CSRF story
    # uniform.
    path('keystore/', api.api_keystore, name='keystore'),
    path('keystore/assign/', api.api_keystore_assign, name='keystore_assign'),
    path('keystore/credentials/', api.api_keystore_create, name='keystore_create'),
    path('keystore/credentials/<int:credential_id>/unlock/',
         api.api_keystore_unlock, name='keystore_unlock'),
    path('keystore/credentials/<int:credential_id>/lock/',
         api.api_keystore_lock, name='keystore_lock'),
    path('keystore/credentials/<int:credential_id>/password/',
         api.api_keystore_password, name='keystore_password'),
    path('keystore/credentials/<int:credential_id>/rename/',
         api.api_keystore_rename, name='keystore_rename'),
    path('keystore/credentials/<int:credential_id>/default/',
         api.api_keystore_default, name='keystore_default'),
    path('keystore/credentials/<int:credential_id>/delete/',
         api.api_keystore_delete, name='keystore_delete'),
    path('keystore/lock/', api.api_keystore_lock, name='keystore_lock_all'),

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

    # downloads. The format is part of the URL and one view serves them all:
    # api.DOWNLOAD_FORMATS is what decides which formats are public and what the
    # private ones require, so a separate route per format would be a second
    # place for that rule to drift.
    path('download/<str:serial_number>/<str:download_format>/', api.api_download,
         name='download'),

    # audit (staff)
    path('audit/', api.api_audit_log, name='audit_log'),
]
