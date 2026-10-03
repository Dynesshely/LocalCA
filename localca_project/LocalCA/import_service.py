"""
Turn a parsed upload into a plan, then apply it.

This sits between the parser (:mod:`LocalCA.importers`, which touches no
database) and the API layer. The dry run and the commit run exactly the same
code, so what the operator approves is what gets written.

Two invariants:

* Imported private keys go through :func:`LocalCA.keys.store_wrapped_key`, the
  same call generated keys use. There is therefore no path that writes an
  uploaded key into the legacy plaintext column, and an import that carries a key
  needs the vault to be open. Certificates imported without a key are stored with
  both key columns empty, which the UI reports as "no private key".
* A certificate may only be attached under a CA the importing account already
  owns (any CA, for staff). Without that rule any signed-in user could hang rows
  off somebody else's hierarchy, which the shared tree view would then show as
  that CA's children.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.db import transaction

from . import keys
from .importers import describe_cert
from .models import (
    AuditLog,
    IntermediateCertificate,
    LeafCertificate,
    RootCertificate,
)

#: kind -> model, in the order a hierarchy has to be created.
KINDS = (
    ('root', RootCertificate),
    ('intermediate', IntermediateCertificate),
    ('leaf', LeafCertificate),
)
MODELS = dict(KINDS)
KIND_LABELS = dict(keys.KIND_LABELS)
_ORDER = {'root': 0, 'intermediate': 1, 'leaf': 2}

CREATE = 'create'
SKIP = 'skip'
ATTACH_KEY = 'attach_key'
CONFLICT = 'conflict'
UNSUPPORTED = 'unsupported'

#: Actions an operator may force from the UI.
OVERRIDABLE_ACTIONS = {SKIP}


class PlanError(Exception):
    '''The plan cannot be applied as written.'''


# --------------------------------------------------------------------------
# Plan shapes
# --------------------------------------------------------------------------

@dataclass
class PlanItem:
    '''One certificate in the plan, and what will happen to it.'''
    kind: str
    action: str
    cert: object = None
    key: object = None
    name: str = ''
    renamed: bool = False
    #: Whether ``name`` came from the operator rather than being derived here.
    name_from_override: bool = False
    reason: str = ''
    parent: tuple = None
    parent_label: str = ''
    existing_id: int = None
    warnings: list = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return self.cert.fingerprint if self.cert is not None else ''

    @property
    def will_store_key(self) -> bool:
        return self.key is not None and self.action in (CREATE, ATTACH_KEY)

    def to_dict(self) -> dict:
        cert = self.cert
        return {
            'fingerprint': self.fingerprint,
            'kind': self.kind,
            'kind_label': KIND_LABELS.get(self.kind, self.kind),
            'action': self.action,
            'reason': self.reason,
            'name': self.name,
            'renamed': self.renamed,
            'has_key': self.key is not None,
            'key_encrypted_in_source': bool(self.key and self.key.encrypted_in_source),
            'key_algorithm': self.key.algorithm if self.key else None,
            'serial_number': cert.serial_number if cert else None,
            'subject': cert.common_name if cert else None,
            'subject_dn': cert.subject_dn if cert else None,
            'issuer_dn': cert.issuer_dn if cert else None,
            'not_after': cert.not_valid_after.isoformat() if cert else None,
            'sans': list(cert.sans) if cert else [],
            'parent': self.parent_label or None,
            'existing_id': self.existing_id,
            'warnings': list(self.warnings),
        }


@dataclass
class ImportPlan:
    items: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    key_warnings: list = field(default_factory=list)

    def add_warning(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    @property
    def requires_vault_unlock(self) -> bool:
        return any(item.will_store_key for item in self.items)

    @property
    def counts(self) -> dict:
        counts = {CREATE: 0, SKIP: 0, ATTACH_KEY: 0, CONFLICT: 0, UNSUPPORTED: 0}
        for item in self.items:
            counts[item.action] = counts.get(item.action, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            'items': [item.to_dict() for item in self.items],
            'counts': self.counts,
            'requires_vault_unlock': self.requires_vault_unlock,
            'warnings': list(self.warnings),
            'errors': list(self.errors),
            'key_warnings': list(self.key_warnings),
        }


# --------------------------------------------------------------------------
# What is already stored
# --------------------------------------------------------------------------

@dataclass
class ExistingIndex:
    '''What is already stored, keyed the four ways a duplicate check needs.'''

    by_fingerprint: dict = field(default_factory=dict)
    by_serial: dict = field(default_factory=dict)
    by_subject: dict = field(default_factory=dict)
    by_key_id: dict = field(default_factory=dict)
    names: dict = field(default_factory=dict)


def _existing_index() -> ExistingIndex:
    '''
    Index the stored certificates by fingerprint, serial, subject and key id.

    Certificates are stored as PEM, so each one is parsed here. At this
    application's scale that costs a few milliseconds and it keeps the schema free
    of derived columns that could drift out of sync.
    '''
    index = ExistingIndex()
    for kind, model in KINDS:
        index.by_serial[kind] = {}
        index.names[kind] = {}
        for obj in model.objects.all():
            try:
                parsed = describe_cert(
                    x509.load_pem_x509_certificate(obj.public_key.encode('utf-8')))
            except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
                # One damaged row must not block an import.
                continue
            index.by_fingerprint[parsed.fingerprint] = (kind, obj)
            index.by_serial[kind].setdefault(parsed.serial_number, (parsed.fingerprint, obj))
            index.by_subject.setdefault(parsed.subject_dn, []).append((kind, obj, parsed))
            if parsed.subject_key_id:
                index.by_key_id.setdefault(parsed.subject_key_id, (kind, obj, parsed))
            name = parsed.common_name if kind == 'leaf' else obj.name
            if name:
                index.names[kind][name] = obj
    return index


def _spki_fingerprint(public_key) -> str:
    '''SHA-256 of the SubjectPublicKeyInfo, which is what pairs a key with a cert.'''
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _kind_of(parsed) -> str:
    if parsed.is_self_signed:
        return 'root' if parsed.is_ca else 'leaf'
    return 'intermediate' if parsed.is_ca else 'leaf'


def _match_issuer(child, candidates):
    '''
    Pick the issuer of ``child`` out of ``candidates``.

    Returns ``(match, ambiguous)``. The Authority Key Identifier is authoritative
    when present; subject/issuer names are the fallback.
    '''
    if child.authority_key_id:
        by_key_id = [c for c in candidates if c.subject_key_id == child.authority_key_id]
        if len(by_key_id) == 1:
            return by_key_id[0], False
        if len(by_key_id) > 1:
            return None, True
    by_name = [c for c in candidates if c.subject_dn == child.issuer_dn]
    if len(by_name) == 1:
        return by_name[0], False
    if len(by_name) > 1:
        return None, True
    return None, False


def _find_parent(cert, want, index, same_kind):
    '''
    Locate the issuing certificate for ``cert``.

    Returns ``(ref, obj, ambiguous, root_issuer)`` where ``ref`` is either
    ``('import', fingerprint)`` for something in this same upload or
    ``('existing', kind, id)`` for something already stored.
    '''
    local = [c for c in same_kind[want] if c.fingerprint != cert.fingerprint]
    candidate, ambiguous = _match_issuer(cert, local)
    if candidate is not None:
        return ('import', candidate.fingerprint), None, False, False
    if ambiguous:
        return None, None, True, False

    same_dn = index.by_subject.get(cert.issuer_dn, [])
    stored = [(kind, obj, parsed) for kind, obj, parsed in same_dn
              if _kind_of(parsed) == want]
    candidate, ambiguous = _match_issuer(cert, [parsed for _k, _o, parsed in stored])
    if candidate is not None:
        for kind, obj, parsed in stored:
            if parsed.fingerprint == candidate.fingerprint:
                return ('existing', kind, obj.id), obj, False, False
    if ambiguous:
        return None, None, True, False

    # Whether this certificate was issued directly by a root CA -- looked for both
    # in the upload and in the store, because "signed by a root" is a case the
    # leaf model cannot represent and has to be explained as such rather than as
    # a missing issuer.
    bundle_root, _ambiguous = _match_issuer(cert, same_kind.get('root', []))
    root_issuer = bundle_root is not None or any(
        _kind_of(parsed) == 'root' for _k, _o, parsed in same_dn)
    return None, None, False, root_issuer


def _unique_name(base: str, taken: set) -> tuple:
    '''A name that is free in ``taken``, plus whether it had to be changed.'''
    base = (base or 'Imported certificate')[:200]
    if base not in taken:
        taken.add(base)
        return base, False
    candidate = f'{base} (imported)'
    suffix = 2
    while candidate in taken and suffix < 1000:
        candidate = f'{base} (imported {suffix})'
        suffix += 1
    taken.add(candidate)
    return candidate, True


def _stored_name(obj) -> str:
    '''The name a stored certificate carries, whichever kind it is.'''
    if obj is None:
        return ''
    return getattr(obj, 'name', None) or getattr(obj, 'common_name', '')


def _parent_label(parent_kind, parent_obj) -> str:
    if parent_obj is None:
        return ''
    label = _stored_name(parent_obj)
    return f'{KIND_LABELS.get(parent_kind, parent_kind)} "{label}"'


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------

def plan_import(bundle, user, overrides: dict = None) -> ImportPlan:
    '''
    Decide what would happen to every certificate in ``bundle``.

    Nothing is written; the returned plan is safe to show. ``overrides`` maps a
    fingerprint to ``{'name': ...}`` and/or ``{'action': 'skip'}`` so an operator
    can rename or drop individual entries before committing.
    '''
    overrides = overrides or {}
    index = _existing_index()
    plan = ImportPlan()
    plan.warnings.extend(bundle.warnings)
    plan.errors.extend(bundle.errors)

    keys_by_spki = {key.spki_fingerprint: key for key in bundle.keys}
    kind_of = {cert.fingerprint: _kind_of(cert) for cert in bundle.certs}
    same_kind = {kind: [c for c in bundle.certs if kind_of[c.fingerprint] == kind]
                 for kind, _ in KINDS}
    taken_names = {kind: set(index.names[kind]) for kind, _ in KINDS}
    claimed_serials = {kind: dict(index.by_serial[kind]) for kind, _ in KINDS}
    item_by_fingerprint = {}
    paired_keys = set()

    for cert in sorted(bundle.certs, key=lambda c: _ORDER[kind_of[c.fingerprint]]):
        kind = kind_of[cert.fingerprint]
        item = PlanItem(kind=kind, action=CREATE, cert=cert)
        item.key = keys_by_spki.get(_spki_fingerprint(cert.cert.public_key()))
        if item.key is not None:
            paired_keys.add(item.key.spki_fingerprint)
        _classify(item, cert, kind, index, same_kind, user)
        _apply_overrides(item, overrides)
        item_by_fingerprint[cert.fingerprint] = item
        plan.items.append(item)

    for item in plan.items:
        if item.action in (CONFLICT, UNSUPPORTED):
            continue
        cert = item.cert
        serial_map = claimed_serials[item.kind]
        existing_serial = serial_map.get(cert.serial_number)
        if existing_serial and existing_serial[0] != cert.fingerprint:
            item.action = CONFLICT
            item.reason = (
                f'Serial number {cert.serial_number} is already used by a different '
                'certificate. Serial numbers are unique across this application, so '
                'this one has to be resolved by hand.')
            continue
        serial_map[cert.serial_number] = (cert.fingerprint, None)

        if item.action in (SKIP, ATTACH_KEY):
            # The row already exists, so report the name it actually carries --
            # unless the operator typed one, which is explicit intent, not an
            # invention of this planner. Running the collision-avoidance below
            # would rename a certificate that will not be renamed at all.
            if not item.name_from_override:
                stored = MODELS[item.kind].objects.filter(pk=item.existing_id).first()
                item.name = (_stored_name(stored) or cert.common_name
                             or f'Imported {KIND_LABELS[item.kind]} {cert.serial_number}')
            item.renamed = False
            continue

        if item.kind in ('root', 'intermediate'):
            if not item.name:
                base = (cert.common_name
                        or f'Imported {KIND_LABELS[item.kind]} {cert.serial_number}')
                item.name, item.renamed = _unique_name(base, taken_names[item.kind])
            else:
                taken_names[item.kind].add(item.name)
        else:
            item.name = item.name or cert.common_name or f'Imported leaf {cert.serial_number}'

    _resolve_import_parents(plan, item_by_fingerprint)

    for spki, key in keys_by_spki.items():
        if spki not in paired_keys:
            plan.key_warnings.append(
                f'A private key from {key.source} does not match any certificate in '
                'this upload, so it was not imported. Include the certificate with its '
                'key, or import the pair from a PKCS#12 bundle.')

    return plan


def _classify(item, cert, kind, index, same_kind, user) -> None:
    '''Set the action, the parent reference and the reason for one certificate.'''
    if cert.is_self_signed and not cert.is_ca:
        item.action = UNSUPPORTED
        item.reason = (
            'A self-signed end-entity certificate does not fit the root / '
            'intermediate / leaf hierarchy, and signing with it would be unsafe.')
        return

    existing = index.by_fingerprint.get(cert.fingerprint)
    if existing is not None:
        existing_kind, obj = existing
        item.kind = existing_kind
        item.existing_id = obj.id
        if item.key is not None and not obj.private_key_wrapped and not obj.private_key_encrypted:
            item.action = ATTACH_KEY
            item.reason = ('Already present, but stored without a private key: the key '
                           'from this upload will be added to it.')
        else:
            item.action = SKIP
            item.reason = 'Already present in this application.'
        return

    if kind == 'root':
        return

    want = 'root' if kind == 'intermediate' else 'intermediate'
    parent_ref, parent_obj, ambiguous, root_issuer = _find_parent(
        cert, want, index, same_kind)

    if ambiguous:
        item.action = CONFLICT
        item.reason = ('More than one stored certificate could be the issuer of this '
                       'one (the same subject exists more than once), so the parent '
                       'cannot be chosen automatically.')
        return

    if parent_ref is None:
        if kind == 'leaf' and root_issuer:
            item.action = UNSUPPORTED
            item.reason = ('This end-entity certificate was issued directly by a root '
                           'CA. A leaf in this application must hang off an intermediate '
                           'CA, so it cannot be stored as it is.')
        else:
            item.action = CONFLICT
            item.reason = (f'The issuing {KIND_LABELS[want]} is neither in this upload '
                           f'nor in this application. Import it as well, or import a '
                           f'bundle that contains the whole chain.')
        return

    item.parent = parent_ref
    if parent_ref[0] == 'existing':
        item.parent_label = _parent_label(parent_ref[1], parent_obj)
        owner_id = getattr(parent_obj, 'created_by_id', None)
        if (owner_id is not None
                and owner_id != getattr(user, 'id', None)
                and not getattr(user, 'is_staff', False)):
            item.action = CONFLICT
            item.reason = (f'The issuing {KIND_LABELS[parent_ref[1]]} belongs to another '
                           f'account. Only its owner, or an administrator, can extend it.')


def _apply_overrides(item, overrides: dict) -> None:
    override = overrides.get(item.fingerprint)
    if not isinstance(override, dict):
        return
    name = override.get('name')
    if isinstance(name, str) and name.strip():
        item.name = name.strip()[:255]
        item.name_from_override = True
    action = override.get('action')
    if action in OVERRIDABLE_ACTIONS and item.action == CREATE:
        item.action = action
        item.reason = 'Skipped at your request.'


def _resolve_import_parents(plan, item_by_fingerprint) -> None:
    '''
    Point parents that live in the same upload at their plan item.

    A parent that is itself skipped ("already present") resolves to the stored
    row, so importing a chain whose root already exists still links up.
    '''
    for item in plan.items:
        if not item.parent or item.parent[0] != 'import':
            continue
        parent_item = item_by_fingerprint.get(item.parent[1])
        if parent_item is None:
            item.action = CONFLICT
            item.reason = 'The issuing certificate is missing from the upload.'
            continue
        label = (f'{KIND_LABELS[parent_item.kind]} '
                 f'"{parent_item.name or parent_item.cert.common_name}"')
        if parent_item.existing_id:
            item.parent = ('existing', parent_item.kind, parent_item.existing_id)
        item.parent_label = label


# --------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------

def apply_plan(plan: ImportPlan, user, root_key=None) -> dict:
    '''
    Write the plan.

    Each certificate is applied in its own transaction: a failure on one entry (a
    duplicate that appeared after the dry run, a key that will not wrap) is
    recorded and the rest still go in, which is what a bulk migration wants.
    '''
    summary = {
        'created': {'root': 0, 'intermediate': 0, 'leaf': 0},
        'keys_wrapped': 0,
        'keys_attached': 0,
        'skipped': 0,
        'failed': [],
    }
    created_by_fingerprint = {}

    for item in plan.items:
        if item.action == SKIP:
            summary['skipped'] += 1
            continue
        if item.action in (CONFLICT, UNSUPPORTED):
            continue
        if item.will_store_key and root_key is None:
            summary['failed'].append({
                'fingerprint': item.fingerprint,
                'name': item.name,
                'error': 'The vault is locked, so the private key cannot be stored.',
            })
            continue
        try:
            with transaction.atomic():
                if item.action == ATTACH_KEY:
                    obj = MODELS[item.kind].objects.filter(pk=item.existing_id).first()
                    if obj is None:
                        raise PlanError('The certificate disappeared while importing.')
                    keys.store_wrapped_key(obj, item.kind, item.key.pem, root_key)
                    summary['keys_attached'] += 1
                else:
                    parent_obj = _parent_object(item, created_by_fingerprint)
                    obj = _create_certificate(item, user, parent_obj)
                    if item.key is not None:
                        keys.store_wrapped_key(obj, item.kind, item.key.pem, root_key)
                        summary['keys_wrapped'] += 1
                    summary['created'][item.kind] += 1
                created_by_fingerprint[item.fingerprint] = obj
                AuditLog.objects.create(
                    action='IMPORT',
                    performed_by=user if getattr(user, 'is_authenticated', False) else None,
                    details=(f'Imported {KIND_LABELS[item.kind]} "{item.name}" '
                             f'(sha256 {item.fingerprint[:16]}…, '
                             f'{"with" if item.key else "without"} private key)'))
        except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            # Recorded against this entry; the rest of the upload still goes in.
            summary['failed'].append({
                'fingerprint': item.fingerprint,
                'name': item.name,
                'error': str(exc),
            })
    return summary


def _parent_object(item, created_by_fingerprint):
    if not item.parent:
        return None
    # Two shapes: ('import', fingerprint) for something earlier in this same
    # upload, ('existing', kind, id) for a row that was already stored.
    if item.parent[0] == 'import':
        obj = created_by_fingerprint.get(item.parent[1])
        if obj is None:
            raise PlanError('The issuing certificate was not imported, so this one '
                            'cannot be either.')
        return obj
    _source, kind, identifier = item.parent
    obj = MODELS[kind].objects.filter(pk=identifier).first()
    if obj is None:
        raise PlanError('The issuing certificate no longer exists.')
    return obj


def _create_certificate(item, user, parent_obj):
    parsed = item.cert
    common = {
        'serial_number': parsed.serial_number,
        'public_key': parsed.pem,
        'private_key_encrypted': '',
        'valid_until': parsed.not_valid_after,
        'created_by': user if getattr(user, 'is_authenticated', False) else None,
    }
    if item.kind == 'root':
        return RootCertificate.objects.create(name=item.name, **common)
    if item.kind == 'intermediate':
        if parent_obj is None:
            raise PlanError('An intermediate CA needs its root CA.')
        return IntermediateCertificate.objects.create(
            name=item.name, signed_by_root=parent_obj, **common)
    if parent_obj is None:
        raise PlanError('A leaf certificate needs its intermediate CA.')
    return LeafCertificate.objects.create(
        common_name=item.name, san=','.join(parsed.sans),
        signed_by_intermediate=parent_obj, **common)
