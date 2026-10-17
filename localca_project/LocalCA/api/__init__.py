"""
The LocalCA JSON API, split by what the endpoints do.

    common        request/response plumbing, permissions, the kind map
    auth          session, login, logout, password change
    keystore      named credentials and the keys they wrap
    meta          static tables the interface renders from
    certificates  reading the hierarchy
    issuance      creating and renewing certificates
    lifecycle     revoking and deleting certificates
    downloads     certificate and key downloads (and the format table)
    imports       importing existing certificate material
    audit         the audit log
    shell         the SPA shell

Every view is re-exported here, so ``api_urls`` and the tests keep
referring to ``api.api_*``.
"""
from .common import (
    CERTIFICATE_KINDS,
    api_not_found,
    can_manage_certificate,
    certificate_display_name,
    child_certificates,
    is_owner,
    kind_of,
)
from .auth import (
    api_change_password,
    api_login,
    api_logout,
    api_session,
)
from .keystore import (
    api_keystore,
    api_keystore_assign,
    api_keystore_create,
    api_keystore_default,
    api_keystore_delete,
    api_keystore_lock,
    api_keystore_password,
    api_keystore_rename,
    api_keystore_unlock,
)
from .meta import (
    api_meta,
)
from .certificates import (
    api_certificates,
    api_issuers,
    api_my_certificates,
)
from .issuance import (
    api_create_certificate,
    api_renew_leaf_certificate,
)
from .lifecycle import (
    api_delete_certificate,
    api_revoke_certificate,
)
from .downloads import (
    DOWNLOAD_FORMATS,
    api_download,
    download_formats,
)
from .imports import (
    api_import_certificates,
)
from .audit import (
    api_audit_log,
)
from .shell import (
    spa_index,
)

__all__ = [
    'CERTIFICATE_KINDS',
    'DOWNLOAD_FORMATS',
    'api_audit_log',
    'api_certificates',
    'api_change_password',
    'api_create_certificate',
    'api_delete_certificate',
    'api_download',
    'api_import_certificates',
    'api_issuers',
    'api_keystore',
    'api_keystore_assign',
    'api_keystore_create',
    'api_keystore_default',
    'api_keystore_delete',
    'api_keystore_lock',
    'api_keystore_password',
    'api_keystore_rename',
    'api_keystore_unlock',
    'api_login',
    'api_logout',
    'api_meta',
    'api_my_certificates',
    'api_not_found',
    'api_renew_leaf_certificate',
    'api_revoke_certificate',
    'api_session',
    'can_manage_certificate',
    'certificate_display_name',
    'child_certificates',
    'download_formats',
    'is_owner',
    'kind_of',
    'spa_index',
]
