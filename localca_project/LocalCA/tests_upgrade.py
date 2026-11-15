"""
Tests for the upgrade command and the SQLite backup helpers.

The command itself is a no-op on a current database; the interesting parts are
the backup copy and its retention, which are tested against real temporary
SQLite files rather than a mock.
"""

# pylint: disable=missing-function-docstring

import sqlite3
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from .upgrade import backup_sqlite_database, prune_backups


class UpgradeCommandTests(TestCase):
    """The command is idempotent and validates its options."""

    def test_current_database_is_a_noop(self):
        user = User.objects.create_user('upgrade-user', password='pw-Upgrade-123')
        output = StringIO()
        call_command('upgrade', stdout=output)
        self.assertIn('up to date', output.getvalue().lower())
        self.assertTrue(User.objects.filter(pk=user.pk).exists())

    def test_keep_must_be_positive(self):
        with self.assertRaises(CommandError):
            call_command('upgrade', keep=0, stdout=StringIO())

    def test_pending_migrations_back_up_before_migrating(self):
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / 'db.sqlite3'
            db_path.write_bytes(b'database')
            backup_path = Path(temporary) / 'backups' / 'db-test.sqlite3'
            with patch('LocalCA.management.commands.upgrade.pending_migrations',
                       return_value=[object()]), \
                 patch('LocalCA.management.commands.upgrade.is_sqlite',
                       return_value=True), \
                 patch('LocalCA.management.commands.upgrade.database_path',
                       return_value=db_path), \
                 patch('LocalCA.management.commands.upgrade.backup_sqlite_database',
                       return_value=backup_path) as backup, \
                 patch('LocalCA.management.commands.upgrade.prune_backups',
                       return_value=[]) as prune, \
                 patch('LocalCA.management.commands.upgrade.call_command') as migrate:
                output = StringIO()
                call_command('upgrade', stdout=output)
            backup.assert_called_once_with(db_path, db_path.parent / 'backups')
            migrate.assert_called_once_with('migrate', interactive=False, verbosity=1)
            prune.assert_called_once_with(backup_path.parent, 5)
            self.assertIn('Backup:', output.getvalue())

    def test_backup_failure_refuses_to_migrate(self):
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / 'db.sqlite3'
            db_path.write_bytes(b'database')
            with patch('LocalCA.management.commands.upgrade.pending_migrations',
                       return_value=[object()]), \
                 patch('LocalCA.management.commands.upgrade.is_sqlite',
                       return_value=True), \
                 patch('LocalCA.management.commands.upgrade.database_path',
                       return_value=db_path), \
                 patch('LocalCA.management.commands.upgrade.backup_sqlite_database',
                       side_effect=OSError('disk full')), \
                 patch('LocalCA.management.commands.upgrade.call_command') as migrate:
                with self.assertRaises(CommandError):
                    call_command('upgrade', stdout=StringIO())
            migrate.assert_not_called()


class BackupTests(TestCase):
    """SQLite backup contents, permissions and retention."""

    def test_backup_copies_data_and_is_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'db.sqlite3'
            connection = sqlite3.connect(source)
            connection.execute('CREATE TABLE sample (value TEXT)')
            connection.execute("INSERT INTO sample VALUES ('kept')")
            connection.commit()
            connection.close()

            backup = backup_sqlite_database(source, root / 'backups')
            self.assertTrue(backup.exists())
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            copied = sqlite3.connect(backup)
            try:
                row = copied.execute('SELECT value FROM sample').fetchone()
            finally:
                copied.close()
            self.assertEqual(row, ('kept',))

    def test_prune_keeps_the_newest_backups(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            names = [
                'db-20260101T000000Z.sqlite3',
                'db-20260102T000000Z.sqlite3',
                'db-20260103T000000Z.sqlite3',
                'db-20260104T000000Z.sqlite3',
            ]
            for name in names:
                (directory / name).write_bytes(b'backup')
            kept = prune_backups(directory, keep=2)
            self.assertEqual(
                [path.name for path in kept],
                ['db-20260103T000000Z.sqlite3',
                 'db-20260104T000000Z.sqlite3'])
            self.assertEqual(len(list(directory.glob('db-*.sqlite3'))), 2)
