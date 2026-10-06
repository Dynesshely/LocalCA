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

from LocalCA.keys import ensure_root_key, vault_status, wrap_legacy_keys


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

        # The same sweep also runs on first-time setup (see api_vault_unseal);
        # this command is the retry path for whatever could not be wrapped then.
        wrapped, failures = wrap_legacy_keys(user.id, root_key)
        for kind, cert, exc in failures:
            self.stderr.write(self.style.ERROR(
                f'  {kind} {cert.pk} ({cert.serial_number}): {exc}'))
        failed = len(failures)

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

