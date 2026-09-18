"""
Forms for the LocalCA application.

All certificate parameters are validated here, on the server. The HTML
``min``/``max`` attributes are only a convenience for the browser: they must
never be the only bound on how long a certificate lives or on which CA is
allowed to sign it.
"""

from django import forms
from django.core.validators import MaxValueValidator, MinValueValidator
from django.utils import timezone

from .models import (
    IntermediateCertificate,
    LeafCertificate,
    RevokedCertificate,
    RootCertificate,
)


#: Upper bound for CA certificates. Kept identical to the value the templates
#: advertise so the UI and the server agree.
MAX_CA_VALIDITY_DAYS = 7300
#: Upper bound for end-entity certificates. Mirrors the CA/Browser Forum
#: baseline requirement the templates refer to.
MAX_LEAF_VALIDITY_DAYS = 825


def _validity_field(max_days):
    '''A bounded integer field for a validity period, in days.'''
    return forms.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(max_days)],
        error_messages={
            'required': 'A validity period is required.',
            'invalid': 'Validity must be a whole number of days.',
            'min_value': 'Validity must be at least 1 day.',
            'max_value': f'Validity cannot exceed {max_days} days.',
        },
    )


class CertificateForm(forms.Form):
    '''
    Common fields for the certificate creation forms.
    '''
    common_name = forms.CharField(
        max_length=255,
        strip=True,
        error_messages={'required': 'A common name is required.'},
    )
    validity_days = _validity_field(MAX_CA_VALIDITY_DAYS)

    #: Model whose ``name`` column this form writes to, and the field that
    #: column is populated from. Both certificate names and leaf common names
    #: are declared UNIQUE in the models, so the value has to be checked before
    #: the insert: an IntegrityError here is an unhandled 500, not an error
    #: message.
    name_model = None
    name_field = 'name'

    def clean_common_name(self):
        common_name = self.cleaned_data['common_name']
        if not common_name.strip():
            raise forms.ValidationError('Common name cannot be empty.')
        if self.name_model is not None and self.name_model.objects.filter(
                **{self.name_field: common_name}).exists():
            raise forms.ValidationError(
                f'"{common_name}" is already in use by another certificate. '
                f'Certificate names must be unique.'
            )
        return common_name


class RootCertificateForm(CertificateForm):
    '''
    Form for creating a root CA.
    '''
    name_model = RootCertificate


class IntermediateCertificateForm(CertificateForm):
    '''
    Form for creating an intermediate CA.

    ``root_id`` is restricted to the roots the requesting user owns: the
    queryset is set by the view, so a crafted POST cannot select somebody
    else's root and have it sign with that owner's private key.
    '''
    name_model = IntermediateCertificate

    root_id = forms.ModelChoiceField(
        queryset=RootCertificate.objects.none(),
        error_messages={
            'required': 'Select the root CA that should sign this certificate.',
            'invalid_choice': 'That root CA is not available to you.',
        },
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['root_id'].queryset = (
            RootCertificate.objects.filter(created_by=user)
            if user is not None else RootCertificate.objects.none()
        )
        self.fields['root_id'].label_from_instance = lambda obj: obj.name

    def clean(self):
        '''
        An intermediate must not outlive the root that signs it.

        This lives in ``clean()`` rather than ``clean_validity_days()`` on
        purpose: fields are cleaned in declaration order, so a ``clean_<field>``
        hook can still see a later field (``root_id``) as absent.
        '''
        cleaned_data = super().clean()
        validity_days = cleaned_data.get('validity_days')
        root = cleaned_data.get('root_id')
        if validity_days is not None and root is not None:
            root_days = (root.valid_until - timezone.now()).days
            # An already-expired root imposes no additional limit.
            root_is_usable = root_days > 0
            if root_is_usable and validity_days > root_days:
                raise forms.ValidationError(
                    f'Validity cannot exceed the signing root CA '
                    f'({root_days} days remaining on "{root.name}").')
        return cleaned_data


class LeafCertificateForm(CertificateForm):
    '''
    Form for creating a leaf certificate: SANs plus the signing intermediate.
    '''
    name_model = LeafCertificate
    name_field = 'common_name'
    validity_days = _validity_field(MAX_LEAF_VALIDITY_DAYS)
    san = forms.CharField(required=False, widget=forms.TextInput)
    intermediate_id = forms.ModelChoiceField(
        queryset=IntermediateCertificate.objects.none(),
        error_messages={
            'required': 'Select the intermediate CA that should sign this certificate.',
            'invalid_choice': 'That intermediate CA is not available to you.',
        },
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['intermediate_id'].queryset = (
            IntermediateCertificate.objects.filter(created_by=user)
            if user is not None else IntermediateCertificate.objects.none()
        )
        self.fields['intermediate_id'].label_from_instance = lambda obj: obj.name

    def clean_san(self):
        return self.cleaned_data.get('san', '')

    def clean(self):
        '''
        A leaf must not outlive the intermediate that signs it.

        In ``clean()`` rather than ``clean_validity_days()`` because
        ``intermediate_id`` is cleaned after ``validity_days``.
        '''
        cleaned_data = super().clean()
        validity_days = cleaned_data.get('validity_days')
        intermediate = cleaned_data.get('intermediate_id')
        if validity_days is not None and intermediate is not None:
            remaining = (intermediate.valid_until - timezone.now()).days
            # An already-expired intermediate imposes no additional limit.
            intermediate_is_usable = remaining > 0
            if intermediate_is_usable and validity_days > remaining:
                raise forms.ValidationError(
                    f'Validity cannot exceed the signing intermediate CA '
                    f'({remaining} days remaining on "{intermediate.name}").')
        return cleaned_data

    def san_list(self):
        '''
        The SAN list for the CSR: explicit entries plus the common name,
        de-duplicated with the order preserved.
        '''
        raw = self.cleaned_data.get('san') or ''
        entries = [item.strip() for item in raw.split(',') if item.strip()]
        common_name = self.cleaned_data.get('common_name')
        if common_name and common_name not in entries:
            entries.insert(0, common_name)
        seen = set()
        ordered = []
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                ordered.append(entry)
        return ordered


class RevokeForm(forms.Form):
    '''
    Form for revoking a certificate.
    '''
    type = forms.ChoiceField(choices=[
        ('root', 'Root CA'),
        ('intermediate', 'Intermediate CA'),
        ('leaf', 'Leaf certificate'),
    ])
    id = forms.IntegerField(min_value=1)
    reason = forms.ChoiceField(
        choices=RevokedCertificate.RevocationReason.choices,
        initial=RevokedCertificate.RevocationReason.UNSPECIFIED,
    )
    comment = forms.CharField(required=False, max_length=500, strip=True)
    cascade = forms.BooleanField(required=False)
    next = forms.CharField(required=False, max_length=200)
