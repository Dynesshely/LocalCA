"""Link a renewed certificate to the one it replaced.

Renewal issues a new certificate; the old row keeps its own bytes and gains a
forward pointer to the replacement, so a renewal chain can be walked and a second
renewal of the same certificate can be refused. No existing row is rewritten and
nothing is re-encrypted.
"""
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LocalCA', '0004_keystore_credentials'),
    ]

    operations = [
        migrations.AddField(
            model_name='leafcertificate',
            name='renewed_by',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='replaces',
                to='LocalCA.leafcertificate'),
        ),
    ]
