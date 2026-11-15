"""
Apply committed migrations, with a safety backup of the SQLite database first.

This is the single upgrade entry point used by the container start script. It is
idempotent: when the database is already current it does nothing (and writes no
backup). When migrations are pending it writes a timestamped, consistent copy
beside the database before running them, so a bad migration is recoverable
without a manual step the operator forgot to take.
"""

from pathlib import Path

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from LocalCA.upgrade import (
    DEFAULT_KEEP,
    backup_sqlite_database,
    database_path,
    is_sqlite,
    pending_migrations,
    prune_backups,
)


class Command(BaseCommand):
    """Apply committed migrations, with a pre-upgrade SQLite backup."""

    help = ('Apply committed migrations, with a SQLite backup before changing '
            'the database.')

    def add_arguments(self, parser):
        parser.add_argument(
            '--no-backup', action='store_true',
            help='Apply migrations without writing a backup (not recommended).')
        parser.add_argument(
            '--keep', type=int, default=DEFAULT_KEEP,
            help=f'Number of backups to retain (default {DEFAULT_KEEP}).')
        parser.add_argument(
            '--backup-dir', default=None,
            help='Directory for backups (default: a backups/ directory beside '
                 'the database).')

    def handle(self, *args, **options):
        keep = options['keep']
        if keep < 1:
            raise CommandError('--keep must be at least 1.')
        no_backup = options['no_backup']

        plan = pending_migrations()
        if not plan:
            self.stdout.write(self.style.SUCCESS(
                'Database is up to date; no backup needed.'))
            return

        self.stdout.write(f'Pending migrations: {len(plan)}')
        backup = None
        db_path = database_path()

        if not is_sqlite():
            self.stdout.write(self.style.WARNING(
                'The database is not SQLite; no automatic backup is available. '
                'Take a database-native backup before upgrading.'))
        elif no_backup:
            self.stdout.write(self.style.WARNING(
                'Skipping the pre-migration backup (--no-backup).'))
        elif db_path is not None and db_path.exists() and db_path.stat().st_size:
            backup_dir = (Path(options['backup_dir']) if options['backup_dir']
                          else db_path.parent / 'backups')
            try:
                backup = backup_sqlite_database(db_path, backup_dir)
            except Exception as exc:
                raise CommandError(
                    f'Could not back up the database before migrating: {exc}. '
                    'Refusing to continue without a backup. Use --no-backup only '
                    'if you already have a copy.') from exc
            self.stdout.write(f'Backup: {backup}')
        else:
            self.stdout.write('No existing database file; starting from empty.')

        try:
            call_command('migrate', interactive=False, verbosity=1)
        except Exception:
            if backup is not None:
                self.stderr.write(self.style.ERROR(
                    f'Migration failed. The pre-upgrade database is at: {backup}'))
            raise

        if backup is not None:
            kept = prune_backups(backup.parent, keep)
            self.stdout.write(f'Kept {len(kept)} backup(s) in {backup.parent}')

        self.stdout.write(self.style.SUCCESS('Database upgraded.'))
