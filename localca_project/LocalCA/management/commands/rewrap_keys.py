"""
Migrate existing plaintext private keys into the vault.

Keys created before the vault existed sit in the legacy plaintext column. This
command wraps them, so the deployment actually benefits from at-rest encryption
instead of keeping the old cleartext rows forever.

It is opt-in and idempotent: it only touches keys that are still plaintext, can
be re-run safely, and reports per-certificate failures instead of aborting, so a
single unreadable row cannot block the rest.
"""
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from LocalCA.keys import ensure_root_key, store_wrapped_key, vault_status
from LocalCA.models import (
    IntermediateCertificate,
    LeafCertificate,
    RootCertificate,
)

KINDS = (
    ('root', RootCertificate),
    ('intermediate', IntermediateCertificate),
    ('leaf', LeafCertificate),
)


class Command(BaseCommand):
    help = 'Wrap plaintext certificate private keys with the vault (opt-in).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username', required=True,
            help='Account whose keys should be wrapped.')
        parser.add_argument(
            '--password', default=None,
            help='Vault password. Omit to be prompted (recommended: it stays out '
                 'of shell history).')
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Report what would be wrapped without changing anything.')

    def handle(self, *args, **options):
        username = options['username']
        password = options['password']
        dry_run = options['dry_run']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError(f'No such user: {username}') from exc

        if password is None and not dry_run:
            import getpass
            password = getpass.getpass('Vault password: ')
        if not dry_run and not password:
            raise CommandError('A vault password is required.')

        status = vault_status(user.id)
        self.stdout.write(
            f'Before: wrapped={status["wrapped"]} plaintext={status["plaintext"]} '
            f'orphaned={status["orphaned"]} no_key={status["no_key"]}')

        if dry_run:
            self.stdout.write(self.style.WARNING('Dry run: nothing written.'))
            return

        root_key = ensure_root_key(user.id, password)

        wrapped = failed = 0
        for kind, model in KINDS:
            # Snapshot the ids: wrapping a row changes the filter this loop uses.
            pending_ids = list(
                model.objects.filter(created_by=user, private_key_wrapped__isnull=True)
                .exclude(private_key_encrypted='')
                .values_list('id', flat=True))
            for cert_id in pending_ids:
                cert = model.objects.get(pk=cert_id)
                try:
                    self._wrap(cert, kind, root_key)
                    wrapped += 1
                except Exception as exc:  # noqa: BLE001 - report, keep going
                    failed += 1
                    self.stderr.write(self.style.ERROR(
                        f'  {kind} {cert_id} ({cert.serial_number}): {exc}'))

        after = vault_status(user.id)
        self.stdout.write(self.style.SUCCESS(
            f'Wrapped {wrapped} key(s); {failed} failed.'))
        self.stdout.write(
            f'After:  wrapped={after["wrapped"]} plaintext={after["plaintext"]} '
            f'orphaned={after["orphaned"]} no_key={after["no_key"]}')
        # Ownerless keys are outside this user's scope, so they never appear in
        # the per-user report above. They are exactly the keys that can never be
        # encrypted, so report them from the global inventory instead of letting
        # the summary imply that everything is now covered.
        global_orphans = vault_status()['orphaned']
        if global_orphans:
            self.stdout.write(self.style.WARNING(
                f'{global_orphans} private key(s) in this database belong to no '
                f'account and cannot be wrapped (there is no password to derive '
                f'from). Assign an owner or delete them; they remain readable as '
                f'plaintext until then. Run `manage.py vault_status` to see them.'))

    def _wrap(self, cert, kind, root_key):
        pem = cert.private_key_encrypted
        if not pem:
            raise ValueError('no plaintext key to wrap')
        # store_wrapped_key encrypts and clears the plaintext column in one
        # transaction, so a crash cannot leave the certificate keyless.
        store_wrapped_key(cert, kind, pem, root_key)
