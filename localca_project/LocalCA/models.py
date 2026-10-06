'''
This module contains the models for the LocalCA application.
'''

from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _


class RootCertificate(models.Model):
    """
    This class represents the root certificate.
    """
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='root_certificates',
        null=True)
    name = models.CharField(max_length=255, unique=True)
    serial_number = models.CharField(
        max_length=255, unique=True)  # Unique serial number
    public_key = models.TextField()
    private_key_encrypted = models.TextField()  # Encrypted private key
    # Vault-wrapped private key (see LocalCA/vault.py). Null means the
    # key has not been migrated yet and is still stored in the legacy
    # column above; readers must check this field first.
    private_key_wrapped = models.TextField(null=True, blank=True)
    # Which keystore credential (name + password) wraps that ciphertext. Null
    # alongside a wrapped key means the owner is gone and nothing can unwrap it.
    # PROTECT: a credential in use cannot be deleted out from under its keys.
    key_credential = models.ForeignKey(
        'VaultCredential',
        on_delete=models.PROTECT,
        related_name='+',
        null=True,
        blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()

    def __str__(self):
        return f"Root Certificate: {self.name}"


class IntermediateCertificate(models.Model):
    """
    This class represents the intermediate certificate.
    """
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='intermediate_certificates',
        null=True)
    name = models.CharField(max_length=255, unique=True)
    serial_number = models.CharField(
        max_length=255, unique=True)  # Unique serial number
    public_key = models.TextField()
    private_key_encrypted = models.TextField()  # Encrypted private key
    # Vault-wrapped private key (see LocalCA/vault.py). Null means the
    # key has not been migrated yet and is still stored in the legacy
    # column above; readers must check this field first.
    private_key_wrapped = models.TextField(null=True, blank=True)
    # Which keystore credential (name + password) wraps that ciphertext. Null
    # alongside a wrapped key means the owner is gone and nothing can unwrap it.
    # PROTECT: a credential in use cannot be deleted out from under its keys.
    key_credential = models.ForeignKey(
        'VaultCredential',
        on_delete=models.PROTECT,
        related_name='+',
        null=True,
        blank=True)
    signed_by_root = models.ForeignKey(
        RootCertificate, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()

    def __str__(self):
        return f"Intermediate Certificate: {self.name}"


class LeafCertificate(models.Model):
    '''
    This class represents the leaf certificate.
    '''
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='leaf_certificates',
        null=True)
    common_name = models.CharField(max_length=255)
    san = models.TextField()  # Comma-separated SANs
    valid_until = models.DateTimeField()
    serial_number = models.CharField(
        max_length=255, unique=True)  # Unique serial number
    public_key = models.TextField()
    private_key_encrypted = models.TextField()  # Encrypted private key
    # Vault-wrapped private key (see LocalCA/vault.py). Null means the
    # key has not been migrated yet and is still stored in the legacy
    # column above; readers must check this field first.
    private_key_wrapped = models.TextField(null=True, blank=True)
    # Which keystore credential (name + password) wraps that ciphertext. Null
    # alongside a wrapped key means the owner is gone and nothing can unwrap it.
    # PROTECT: a credential in use cannot be deleted out from under its keys.
    key_credential = models.ForeignKey(
        'VaultCredential',
        on_delete=models.PROTECT,
        related_name='+',
        null=True,
        blank=True)
    signed_by_intermediate = models.ForeignKey(
        IntermediateCertificate, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Leaf Certificate: {self.common_name}"


class RevokedCertificate(models.Model):
    '''
    This class represents the revoked certificate.

    Exactly one of `certificate` / `intermediate_certificate` /
    `root_certificate` is set. The original schema only supported leaf
    certificates; roots and intermediates are revocable too because a
    compromised CA key must be recorded even though the parent itself is
    not re-issuable.

    OneToOne fields (rather than a generic foreign key) keep referential
    integrity and make "revoked twice" impossible at the database level.
    '''
    class RevocationReason(models.TextChoices):
        '''
        RFC 5280 section 5.3.1 CRLReason values.

        The labels are the human-readable text the revoke dialog shows, so they
        are translated. The values are stored in the database and never are.
        '''
        UNSPECIFIED = 'unspecified', _('Unspecified')
        KEY_COMPROMISE = 'key_compromise', _('Key compromise')
        CA_COMPROMISE = 'ca_compromise', _('CA compromise')
        AFFILIATION_CHANGED = 'affiliation_changed', _('Affiliation changed')
        SUPERSEDED = 'superseded', _('Superseded')
        CESSATION_OF_OPERATION = 'cessation_of_operation', _('Cessation of operation')
        CERTIFICATE_HOLD = 'certificate_hold', _('Certificate hold')
        PRIVILEGE_WITHDRAWN = 'privilege_withdrawn', _('Privilege withdrawn')

    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='revoked_certificates',
        null=True)
    certificate = models.OneToOneField(
        LeafCertificate,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='revocation')
    intermediate_certificate = models.OneToOneField(
        IntermediateCertificate,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='revocation')
    root_certificate = models.OneToOneField(
        RootCertificate,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='revocation')
    reason = models.TextField()  # Reason for revocation
    comment = models.TextField(blank=True, default='')
    revoked_at = models.DateTimeField(auto_now_add=True)

    @property
    def target(self):
        '''The revoked certificate, whichever kind it is.'''
        return (self.certificate
                or self.intermediate_certificate
                or self.root_certificate)

    @property
    def target_name(self):
        '''Display name of the revoked certificate.'''
        target = self.target
        if target is None:
            return _('(deleted)')  # only possible transiently, before cascade
        if isinstance(target, LeafCertificate):
            return target.common_name
        return target.name

    @property
    def reason_label(self):
        '''Human readable reason, tolerating free-text legacy rows.'''
        return self.RevocationReason(self.reason).label \
            if self.reason in self.RevocationReason.values else self.reason

    def save(self, *args, **kwargs):
        targets = [self.certificate, self.intermediate_certificate,
                   self.root_certificate]
        if sum(1 for t in targets if t is not None) != 1:
            raise ValueError(
                'A revocation must reference exactly one certificate.')
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"Revoked: {self.target_name}"


class AuditLog(models.Model):
    '''
    This class represents the audit log.
    '''
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('REVOKE', 'Revoke'),
        ('DELETE', 'Delete'),
        ('DOWNLOAD', 'Download'),
        ('ACCESS', 'Access'),
    ]

    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField()

    def __str__(self):
        return f"{self.action} by {self.performed_by} at {self.timestamp}"


class VaultCredential(models.Model):
    """
    A named password that wraps one root key.

    Credentials are the unit an operator actually thinks in: "the CA key is under
    *Production*, the lab keys are under *Lab*". Each one holds its own password,
    and every stored private key names the credential that wraps it, so a
    compromise (or a forgotten password) is scoped to one credential instead of
    to the whole account.

    The password itself is never stored: the root key is wrapped with a
    scrypt-derived key-encryption key at wrap time and can only be unwrapped by
    supplying that password again. Losing it therefore makes every private key
    under that credential unrecoverable; there is deliberately no recovery path.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='vault_credentials')
    name = models.CharField(max_length=100)
    wrapped_root_key = models.TextField()
    #: The credential new keys are stored under unless a request names another.
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'name'], name='unique_credential_name_per_user'),
        ]

    def __str__(self):
        return f"VaultCredential(user={self.user_id}, name={self.name!r})"

