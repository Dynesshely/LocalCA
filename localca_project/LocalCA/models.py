'''
This module contains the models for the LocalCA application.
'''

from django.db import models
from django.contrib.auth.models import User


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
        '''
        UNSPECIFIED = 'unspecified', 'Unspecified'
        KEY_COMPROMISE = 'key_compromise', 'Key compromise'
        CA_COMPROMISE = 'ca_compromise', 'CA compromise'
        AFFILIATION_CHANGED = 'affiliation_changed', 'Affiliation changed'
        SUPERSEDED = 'superseded', 'Superseded'
        CESSATION_OF_OPERATION = 'cessation_of_operation', 'Cessation of operation'
        CERTIFICATE_HOLD = 'certificate_hold', 'Certificate hold'
        PRIVILEGE_WITHDRAWN = 'privilege_withdrawn', 'Privilege withdrawn'

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
            return '(deleted)'  # only possible transiently, before cascade
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
