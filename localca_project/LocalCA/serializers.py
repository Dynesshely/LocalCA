"""
Serializers for the LocalCA JSON API.

Deliberately hand-written rather than DRF: the payloads are small, the project
has no other DRF usage, and keeping the permission decisions in the views (where
they already are, and are tested) avoids two sources of truth.

Nothing here ever emits private key material. Private keys leave the system only
through the dedicated download endpoints, which check ownership themselves.
"""
from django.utils import timezone

from .models import RevokedCertificate


def certificate_common(cert, kind, user):
    """
    Fields shared by every certificate kind, plus the per-user rights the UI
    needs to decide which actions to offer.

    ``can_manage`` mirrors :func:`LocalCA.views.can_manage_certificate`:
    owners manage their own certificates, staff manage any.
    """
    is_owner = (user.is_authenticated
                and cert.created_by_id is not None
                and cert.created_by_id == user.id)
    is_staff = user.is_authenticated and user.is_staff
    expires_in_days = None
    if cert.valid_until:
        expires_in_days = (cert.valid_until - timezone.now()).days
    return {
        'kind': kind,
        'id': cert.id,
        'serial_number': cert.serial_number,
        'name': cert.common_name if kind == 'leaf' else cert.name,
        'created_at': cert.created_at.isoformat() if cert.created_at else None,
        'valid_until': cert.valid_until.isoformat() if cert.valid_until else None,
        'expires_in_days': expires_in_days,
        'owner': cert.created_by.username if cert.created_by_id else None,
        'is_owner': is_owner,
        'can_manage': is_staff or is_owner,
    }


def revocation_summary(revocation):
    '''Compact representation of a revocation, or None.'''
    if revocation is None:
        return None
    return {
        'id': revocation.id,
        'reason': revocation.reason,
        'reason_label': revocation.reason_label,
        'comment': revocation.comment,
        'revoked_at': revocation.revoked_at.isoformat(),
        'revoked_by': (revocation.created_by.username
                       if revocation.created_by_id else None),
    }


def root_to_dict(root, user, revocation=None, descendants=None):
    data = certificate_common(root, 'root', user)
    data['revocation'] = revocation_summary(revocation)
    data['descendants'] = descendants or 0
    return data


def intermediate_to_dict(intermediate, user, revocation=None, descendants=None):
    data = certificate_common(intermediate, 'intermediate', user)
    data['signed_by'] = {
        'id': intermediate.signed_by_root_id,
        'name': intermediate.signed_by_root.name,
    }
    data['revocation'] = revocation_summary(revocation)
    data['descendants'] = descendants or 0
    return data


def leaf_to_dict(leaf, user, revocation=None):
    data = certificate_common(leaf, 'leaf', user)
    data['sans'] = [s for s in (leaf.san or '').split(',') if s]
    data['signed_by'] = {
        'id': leaf.signed_by_intermediate_id,
        'name': leaf.signed_by_intermediate.name,
    }
    data['revocation'] = revocation_summary(revocation)
    return data


def revocation_reasons():
    '''RFC 5280 CRLReason values, for the revoke dialog.'''
    return [{'value': value, 'label': label}
            for value, label in RevokedCertificate.RevocationReason.choices]


def user_to_dict(user):
    '''The signed-in user, as the SPA needs it.'''
    if not user.is_authenticated:
        return None
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
    }
