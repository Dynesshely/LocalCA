"""
Reading the hierarchy: the public tree, an account's own certificates, and
the authorities it may sign with.
"""

from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET
from ..keys import issuers_with_key
from ..models import IntermediateCertificate, LeafCertificate, RootCertificate
from ..serializers import intermediate_to_dict, leaf_to_dict, root_to_dict
from .common import _descendant_counts, _error, _ok, _revocations_by_kind


@require_GET
def api_certificates(request):
    '''
    The whole certificate hierarchy, with revocation state and filtered by what
    this user may see: public names, but only their own private-key affordances.
    '''
    revocations = _revocations_by_kind()
    counts = _descendant_counts()
    user = request.user

    tree = []
    for root in RootCertificate.objects.all().order_by('-created_at'):
        intermediates = []
        for intermediate in IntermediateCertificate.objects.filter(
                signed_by_root=root).order_by('-created_at'):
            leaves = [
                leaf_to_dict(leaf, user, revocations['leaf'].get(leaf.id))
                for leaf in LeafCertificate.objects.filter(
                    signed_by_intermediate=intermediate).order_by('-created_at')
            ]
            intermediates.append({
                'certificate': intermediate_to_dict(
                    intermediate, user, revocations['intermediate'].get(intermediate.id),
                    counts.get(('intermediate', intermediate.id), 0)),
                'leaves': leaves,
            })
        tree.append({
            'certificate': root_to_dict(
                root, user, revocations['root'].get(root.id),
                counts.get(('root', root.id), 0)),
            'intermediates': intermediates,
        })

    return _ok({'tree': tree})


@require_GET
def api_issuers(request):
    '''
    Certificate authorities the requesting user may sign with.

    Only their own, and only those that still have a private key: signing consumes
    that key, and a certificate imported without one cannot sign at all.
    '''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    roots = [root_to_dict(root, request.user)
             for root in issuers_with_key(RootCertificate, request.user)
             .order_by('-created_at')]
    intermediates = [intermediate_to_dict(intermediate, request.user)
                     for intermediate in issuers_with_key(
                         IntermediateCertificate, request.user).order_by('-created_at')]
    return _ok({'roots': roots, 'intermediates': intermediates})


@require_GET
def api_my_certificates(request):
    '''The certificates this user owns, for the management tables.'''
    if not request.user.is_authenticated:
        return _error(_('Authentication required.'), status=401)

    revocations = _revocations_by_kind()
    user = request.user
    return _ok({
        'roots': [root_to_dict(root, user, revocations['root'].get(root.id))
                  for root in RootCertificate.objects.filter(
                      created_by=user).order_by('-created_at')],
        'intermediates': [
            intermediate_to_dict(intermediate, user,
                                 revocations['intermediate'].get(intermediate.id))
            for intermediate in IntermediateCertificate.objects.filter(
                created_by=user).order_by('-created_at')],
        'leaves': [leaf_to_dict(leaf, user, revocations['leaf'].get(leaf.id))
                   for leaf in LeafCertificate.objects.filter(
                       created_by=user).order_by('-created_at')],
    })
