# Upgrading from an earlier version

> Part of the [Local CA](../README.md) documentation.

If you already run an earlier LocalCA — the upstream layout, where the whole
project sat directly in `/app` — then **replacing the image is not a drop-in
swap**. Your certificates, accounts and audit log are compatible and survive the
upgrade; what changed is the container's contract, in three ways, and each one
misbehaves if you skip it.

## 1. Two environment variables are now required

`DJANGO_SECRET_KEY` is mandatory: LocalCA refuses to start without it. With
`DJANGO_DEBUG=false` (the default) `DJANGO_ALLOWED_HOSTS` is mandatory too. Put
`.env` next to your compose file, generate a key, and list every hostname you
browse LocalCA under:

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(50))"   # into DJANGO_SECRET_KEY
```

## 2. The paths inside the container moved

The image now mirrors the repository layout: the Django project lives in
`/app/localca_project`, and the database and the collected static files moved
with it.

| What | Earlier images | Current image |
| --- | --- | --- |
| SQLite database | `/app/db` | `/app/localca_project/db` |
| Collected static files | `/app/staticfiles` | `/app/localca_project/staticfiles` |

**Update the `web` service's volume targets.** The volume keeps its contents;
only the path it is mounted at changes, so nothing is copied or converted:

```yaml
  web:
    volumes:
      - db:/app/localca_project/db                      # was db:/app/db
      - static_volume:/app/localca_project/staticfiles  # was static_volume:/app/staticfiles
```

nginx keeps `/app/staticfiles`: it mounts the same named volume, and `nginx.conf`
aliases that path. If you skip this step the container still starts — but it
creates a **new, empty database** in its own filesystem layer and serves no
CSS/JS. Your data is not gone, it is simply not mounted.

## 3. The container no longer runs as root

It runs as uid/gid 10001 by default, so the database and the collected static
files have to be **writable by that uid**. A database written by an earlier
root-running image is owned by root, and a bind-mounted one is owned by your own
host account; in either case the new container cannot write it.

SQLite's wording for this is worth knowing, because the two cases produce
different errors and neither one names the real problem:

| What is not writable | What you see |
| --- | --- |
| the `db` **directory** (no database file yet) | `unable to open database file` |
| an existing `db.sqlite3` **file** | `attempt to write a readonly database` |

`start.sh` checks both — and the static directory — before it starts Django, and
reports the path, its owner and the uid it runs as instead of a traceback. Fix it
on the host, once:

```bash
# a) build the image to run as the volume's owner (best for bind mounts)
docker build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g) -t localca .

# b) or give the existing volume to the container's user, once
docker volume inspect <project>_db            # find the mountpoint
docker run --rm -v <project>_db:/db alpine chown -R 10001:10001 /db
```

### A *fresh* deployment on a bind mount needs the directory to exist first

If your compose file bind-mounts `./db` and that directory is not there yet,
docker creates it for you — as `root`, mode 0755. The container can read it but
not write in it, and the very first `migrate` fails with `unable to open database
file`. Create and hand over the directory before the first start:

```bash
mkdir -p db && sudo chown -R 10001:10001 db
docker compose up -d
```

`docker-compose-harbor.yml` sidesteps this entirely by using named volumes, which
docker initialises from the image and therefore already owns.

## What happens to your data

Migrations `0002` (revocation targets and comment), `0003` (private key
encryption) and `0004` (keystore credentials) apply in place on the existing
database, and `0005` only adds a nullable column for renewal links. The upgrade
was verified end to end against a database from the previous version: accounts and
their password hashes, roots/intermediates/leaves with their SANs, revocations —
including pre-RFC 5280 free-text reasons — and the audit log all survive, and you
sign in with your existing password.

An account that had a single vault password keeps it: migration `0004` turns that
root key into a credential named **Default** and stamps every already-wrapped key
with it, without re-encrypting anything.

Private keys created by an even earlier version stay in the legacy plaintext
column until a credential wraps them:

```bash
python manage.py vault_status                       # which keys are encrypted, and by what
python manage.py rewrap_keys --username <user>      # wrap the rest (idempotent)
python manage.py rewrap_keys --username <user> --credential Production
```

There is no key import in this version — it only issues certificates, it never
ingests them. So exporting every PKCS12 from the old site and importing it into a
fresh one is not an available route; upgrading the database in place is the
supported path.

Before you start, copy `db.sqlite3` (or the named volume) somewhere safe. Rolling
back means restoring that copy: the migrations add columns and tables, and the
older code is not tested against the newer schema.
