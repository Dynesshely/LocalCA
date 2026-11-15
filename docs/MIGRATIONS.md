# Migrations and upgrades

> Part of the [Local CA](../README.md) documentation. This page is the policy for schema and data changes, and the operator-facing description of what happens on upgrade.

LocalCA ships its schema history as committed Django migrations. A deployment does not run `makemigrations` and does not need a manual database step: `start.sh` calls `manage.py upgrade`, which checks for pending migrations, writes a consistent SQLite backup, and only then applies them. Replacing the image and restarting is the whole upgrade; the database and the application configuration survive.

## What the upgrade command does

The command is idempotent and fail-closed:

1. It reads the migration plan between the code and the database.
2. If there is nothing pending, it prints `Database is up to date; no backup needed.` and exits without touching the database.
3. If migrations are pending and the database is SQLite, it writes a consistent online backup under `localca_project/db/backups/` using SQLite's backup API. A fresh database has nothing to back up and is skipped.
4. It applies the committed migrations with `migrate --noinput`.
5. It keeps the newest five backups (configurable) and removes older ones only after a successful migration.

If the backup fails, the command refuses to migrate. If a migration fails, the container exits non-zero and the pre-upgrade backup remains. There is no path where the application silently starts on a half-migrated database.

```bash
# The same command in a checkout or container
python manage.py upgrade

# Explicit controls, mainly for recovery or constrained deployments
python manage.py upgrade --no-backup       # only if you already have a copy
python manage.py upgrade --keep 10
python manage.py upgrade --backup-dir /backups
```

The start script and the Traefik example compose file both call `upgrade`; no compose file calls `migrate` directly.

## Backups and restore

Backups are named for the UTC instant they were taken:

```text
localca_project/db/backups/db-20261116T003000Z.sqlite3
```

They live beside the SQLite database, so they are inside the database volume and survive a container replacement. They are mode `0600` and are ignored by Git with the rest of `localca_project/db/`.

To restore:

1. Stop the container (or the service).
2. Copy the chosen backup over `db.sqlite3` on the host or in the volume.
3. Start the container again. `upgrade` reapplies any migrations that the restored database does not yet have, taking a fresh backup first.

A backup is a complete database copy, not a schema-only file: accounts, certificates, private keys, keystore credentials, audit log and personal access tokens are all in it.

## Adding a migration

Every change that alters a model, a stored value, a default or a data shape ships a migration in the same change set.

1. Change the model, then generate the migration:

   ```bash
   python localca_project/manage.py makemigrations LocalCA
   ```

2. For a data-only change, create an empty migration and add a `RunPython` operation. Make it idempotent (safe to run twice) and keep a reverse function, or `RunPython.noop` when the data loss on reverse is acceptable and documented.

3. Run the suite and the migration check:

   ```bash
   DJANGO_TESTING=true python localca_project/manage.py test LocalCA
   DJANGO_TESTING=true python localca_project/manage.py makemigrations --check --dry-run
   ```

4. Commit the migration with the code. A released migration is never edited; fix a mistake with a new migration.

CI runs the same suite and the `makemigrations --check` gate. A model change without a migration fails the pull request before review.

## Compatibility rules

These rules are what "upgrade without breaking the configuration" means in practice.

* **Add before remove.** Add columns and tables first; make them nullable or give them a safe default. Remove or rename only after the new shape has shipped and a later migration can copy the data.
* **Rename in steps.** Add the new column, backfill it in a data migration, switch reads and writes, then drop the old column in a later release. Do not rename a column in one release.
* **Data migrations are explicit.** A schema change never silently discards rows. `RunPython` backfills are idempotent and tested against a database from the previous release where possible.
* **Environment variables are a public contract.** A new name must keep reading the old name as a fallback for at least one release. Never rewrite or delete a user's `.env` file, and never make a previously optional variable mandatory without a documented upgrade path.
* **Volume paths stay stable.** A data path change needs an explicit migration or a documented one-time move; the application must never mount a fresh empty path and call it an upgrade. The historical single-container layout in [UPGRADING.md](UPGRADING.md) is the one manual move that predates this policy.
* **No network work in migrations.** Migrations are local and deterministic: no downloads, no remote registries, no host-specific values.
* **Backup first.** Any migration that can rewrite data runs behind the automatic pre-migration backup. Use `--no-backup` only when an external backup already exists.
* **SQLite only for now.** The automatic copy uses SQLite's online backup API. A future non-SQLite backend must provide its own pre-migration backup before it is offered as a supported deployment.

## CI gate

`.github/workflows/django.yml` runs two migration-specific commands:

```bash
python localca_project/manage.py test LocalCA
python localca_project/manage.py makemigrations --check --dry-run
```

The first runs the real test suite (the explicit `LocalCA` label matters: a bare `manage.py test` from the repository root discovers no tests). The second fails when a model change has no matching migration.

## Failure and recovery

* **Container exits during upgrade.** Read the log; the backup path is printed before `migrate` starts. Restore that copy, or fix the migration and redeploy.
* **The backup is missing.** A fresh database has no backup; a database that was already current has none either, by design. If the database is not SQLite, the command warns that no automatic backup was taken.
* **Disk is full.** The backup is written before migration; a failed backup aborts the upgrade rather than leaving less room for the migration.
