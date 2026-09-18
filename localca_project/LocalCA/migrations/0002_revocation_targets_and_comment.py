# Revocation coverage for roots and intermediates, plus a comment field.
#
# This is purely additive: `certificate` becomes optional (existing rows keep
# their value), two nullable one-to-one links are added, and `comment` defaults
# to an empty string. No column is dropped or rewritten, so an existing
# deployment keeps every revocation it had.
#
# Split out of 0001_initial on purpose -- see the note at the top of that file.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LocalCA', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='revokedcertificate',
            name='comment',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='revokedcertificate',
            name='intermediate_certificate',
            field=models.OneToOneField(
                blank=True, null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='revocation',
                to='LocalCA.intermediatecertificate'),
        ),
        migrations.AddField(
            model_name='revokedcertificate',
            name='root_certificate',
            field=models.OneToOneField(
                blank=True, null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='revocation',
                to='LocalCA.rootcertificate'),
        ),
        migrations.AlterField(
            model_name='revokedcertificate',
            name='certificate',
            field=models.OneToOneField(
                blank=True, null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='revocation',
                to='LocalCA.leafcertificate'),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(
                choices=[('CREATE', 'Create'), ('REVOKE', 'Revoke'),
                         ('DELETE', 'Delete'), ('DOWNLOAD', 'Download'),
                         ('ACCESS', 'Access')],
                max_length=50),
        ),
    ]
