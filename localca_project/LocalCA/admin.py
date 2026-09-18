'''
This module contains the admin configuration for the LocalCA application.
'''

from django.contrib import admin

from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
)


class CertificateAdminMixin:
    '''
    Shared admin behaviour for certificate models.

    Private key material is never rendered into an editable form field and is
    never written through the admin: it is shown masked instead. The admin is
    for inspecting metadata, not for hand-editing keys.
    '''
    readonly_fields = ('private_key_display', 'created_at')
    exclude = ('private_key_encrypted',)

    @admin.display(description='Private key')
    def private_key_display(self, obj):
        '''Masked indicator instead of the PEM body.'''
        if not obj.private_key_encrypted:
            return '—'
        return f'stored ({len(obj.private_key_encrypted)} bytes, not shown)'


@admin.register(RootCertificate)
class RootCertificateAdmin(CertificateAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'serial_number', 'created_by', 'valid_until', 'created_at')
    search_fields = ('name', 'serial_number')
    list_filter = ('created_by',)


@admin.register(IntermediateCertificate)
class IntermediateCertificateAdmin(CertificateAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'signed_by_root', 'serial_number', 'created_by', 'valid_until')
    search_fields = ('name', 'serial_number')
    list_filter = ('created_by',)


@admin.register(LeafCertificate)
class LeafCertificateAdmin(CertificateAdminMixin, admin.ModelAdmin):
    list_display = ('common_name', 'signed_by_intermediate', 'serial_number',
                    'created_by', 'valid_until')
    search_fields = ('common_name', 'serial_number', 'san')
    list_filter = ('created_by',)


@admin.register(RevokedCertificate)
class RevokedCertificateAdmin(admin.ModelAdmin):
    list_display = ('target_name', 'reason', 'created_by', 'revoked_at')
    search_fields = ('reason', 'comment')
    list_filter = ('reason',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'action', 'performed_by', 'details')
    list_filter = ('action',)
    search_fields = ('details',)
    readonly_fields = ('action', 'performed_by', 'timestamp', 'details')

    def has_add_permission(self, request):
        # Audit entries are written by the application only.
        return False
