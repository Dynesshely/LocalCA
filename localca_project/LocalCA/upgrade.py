"""
Upgrade plumbing: pending-migration detection and a consistent SQLite backup.

The container's start script has always run committed migrations; what was
missing was a safety net. A migration that turns out wrong is recoverable only if
there is a copy of the database from just before it ran, and an operator should
not have to remember to take one. The upgrade command uses these helpers to
write a timestamped backup before the first pending migration and to prune old
copies afterwards.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from django.db import connection
from django.db.migrations.executor import MigrationExecutor

#: Prefix and suffix used for backup files. The timestamp makes them sortable
#: and the suffix keeps stray files out of the prune glob.
BACKUP_PREFIX = 'db-'
BACKUP_SUFFIX = '.sqlite3'
DEFAULT_KEEP = 5


def database_path():
    """The SQLite database path from settings, or None if it has no path."""
    name = connection.settings_dict.get('NAME')
    if not name:
        return None
    return Path(name)


def is_sqlite():
    """Whether the default database is SQLite (the only backend with a backup)."""
    return connection.vendor == 'sqlite'


def pending_migrations():
    """The migration plan between the database and the code, as a list."""
    executor = MigrationExecutor(connection)
    targets = executor.loader.graph.leaf_nodes()
    return executor.migration_plan(targets)


def backup_sqlite_database(source, backup_dir):
    """
    Copy a SQLite database with the online backup API and return the new path.

    The source is opened read-only so a typo or a missing file cannot create an
    empty database as a side effect. The backup is written to a temporary file
    and renamed only after a successful copy, so an interrupted process never
    leaves a half-written file that looks like a usable backup.
    """
    source = Path(source)
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    target = backup_dir / f'{BACKUP_PREFIX}{stamp}{BACKUP_SUFFIX}'
    counter = 1
    while target.exists():
        target = backup_dir / f'{BACKUP_PREFIX}{stamp}-{counter}{BACKUP_SUFFIX}'
        counter += 1

    temporary = target.with_name(target.name + '.tmp')
    uri = f'file:{source}?mode=ro'
    source_connection = sqlite3.connect(uri, uri=True)
    destination_connection = sqlite3.connect(temporary)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    except Exception:
        source_connection.close()
        destination_connection.close()
        temporary.unlink(missing_ok=True)
        raise
    source_connection.close()
    destination_connection.close()

    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
    return target


def prune_backups(backup_dir, keep=DEFAULT_KEEP):
    """
    Keep the newest N backups and delete the rest.

    Names sort chronologically because the timestamp is ISO-8601. Only files
    matching the backup pattern are touched, so a stray file in the directory is
    never deleted.
    """
    if keep < 1:
        return []
    backup_dir = Path(backup_dir)
    candidates = sorted(backup_dir.glob(f'{BACKUP_PREFIX}*{BACKUP_SUFFIX}'))
    stale = candidates[:-keep] if len(candidates) > keep else []
    for path in stale:
        path.unlink(missing_ok=True)
    return candidates[-keep:]
