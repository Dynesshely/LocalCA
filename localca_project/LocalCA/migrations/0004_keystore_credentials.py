"""Introduce keystore credentials, and fold the per-account root key into one.

Before this, an account had exactly one vault root key, so the wrap step was
per-user. Credentials make it per-purpose: a named password wrapping one root
key, with every stored private key pointing at the credential that wraps it.

Existing state maps onto the new shape exactly one way: each account's root key
becomes a credential named "Default", and every already-wrapped certificate of
that account is stamped with it. Nothing is re-encrypted -- the ciphertext does
not mention the credential, only which root key derived the per-certificate key,
and that root key is unchanged.
"""
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


DEFAULT_NAME = 'Default'


def root_keys_to_credentials(apps, schema_editor):
    VaultRootKey = apps.get_model('LocalCA', 'VaultRootKey')
    VaultCredential = apps.get_model('LocalCA', 'VaultCredential')
    models_by_kind = {
        kind: apps.get_model('LocalCA', model)
        for kind, model in (('root', 'RootCertificate'),
                            ('intermediate', 'IntermediateCertificate'),
                            ('leaf', 'LeafCertificate'))
    }

    for record in VaultRootKey.objects.all().iterator():
        credential = VaultCredential.objects.create(
            user_id=record.user_id,
            name=DEFAULT_NAME,
            wrapped_root_key=record.wrapped_root_key,
            is_default=True,
        )
        for model in models_by_kind.values():
            model.objects.filter(
                created_by_id=record.user_id,
                private_key_wrapped__isnull=False,
            ).update(key_credential=credential)


def credentials_to_root_keys(apps, schema_editor):
    '''Reverse: only a one-credential account can be represented again.'''
    VaultRootKey = apps.get_model('LocalCA', 'VaultRootKey')
    VaultCredential = apps.get_model('LocalCA', 'VaultCredential')
    seen = set()
    for credential in VaultCredential.objects.order_by('id').iterator():
        if credential.user_id in seen:
            continue
        seen.add(credential.user_id)
        VaultRootKey.objects.create(
            user_id=credential.user_id,
            wrapped_root_key=credential.wrapped_root_key,
        )


class Migration(migrations.Migration):

    dependencies = [
        ('LocalCA', '0003_vault_private_keys'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='VaultCredential',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('wrapped_root_key', models.TextField()),
                ('is_default', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='vault_credentials',
                    to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.AddConstraint(
            model_name='vaultcredential',
            constraint=models.UniqueConstraint(
                fields=('user', 'name'),
                name='unique_credential_name_per_user'),
        ),
        migrations.AddField(
            model_name='intermediatecertificate',
            name='key_credential',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='+', to='LocalCA.vaultcredential'),
        ),
        migrations.AddField(
            model_name='leafcertificate',
            name='key_credential',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='+', to='LocalCA.vaultcredential'),
        ),
        migrations.AddField(
            model_name='rootcertificate',
            name='key_credential',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='+', to='LocalCA.vaultcredential'),
        ),
        migrations.RunPython(root_keys_to_credentials, credentials_to_root_keys),
        migrations.DeleteModel(name='VaultRootKey'),
    ]
