#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# Preflight: the two mounted directories have to be writable before Django runs.
#
# A mount arrives owned by whoever created it -- a host bind mount is owned by
# your own account, and a named volume left behind by an image that ran as root
# is owned by root. This process runs unprivileged (uid 10001 by default and
# never root), so it cannot repair that itself, and the message SQLite gives is
# actively misleading:
#
#     a directory it cannot write to -> "unable to open database file"
#     an existing file it cannot write -> "attempt to write a readonly database"
#
# Both mean the same thing. Without this check the user sees a sixty-line Django
# traceback repeated by the restart policy, which never says that a `chown` on
# the host is what is missing. Check first, state it once, and stop.
# ---------------------------------------------------------------------------
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DB_FILE="$PROJECT_DIR/db/db.sqlite3"

check_writable() {
    _path=$1
    _what=$2

    if [ -w "$_path" ]; then
        return 0
    fi

    cat >&2 <<EOF

start.sh: $_what is not writable, so LocalCA cannot start.

  path   : $_path
  owner  : uid:gid $(stat -c '%u:%g' "$_path" 2>/dev/null || echo unknown)
  running: uid:gid $(id -u):$(id -g)

The container is unprivileged and cannot change this itself. On the host:

  # a bind-mounted ./db (or a named volume from an earlier root-running image):
  sudo chown -R 10001:10001 ./db

  # ...or build an image that runs as the account owning the bind mount:
  docker build --build-arg APP_UID=\$(id -u) --build-arg APP_GID=\$(id -g) -t localca .

docker-compose-harbor.yml uses named volumes that the image already owns, so it
needs none of this. Building a *fresh* deployment against a bind mount almost
always hits this: docker creates the missing host directory as root, so the
container can read it but not write in it.

EOF
    exit 1
}

mkdir -p "$PROJECT_DIR/db" "$PROJECT_DIR/staticfiles" 2>/dev/null || true

check_writable "$PROJECT_DIR/db" 'the SQLite database directory'
if [ -e "$DB_FILE" ]; then
    check_writable "$DB_FILE" 'the SQLite database file'
fi
check_writable "$PROJECT_DIR/staticfiles" 'the static files directory (STATIC_ROOT)'

# Migrations are committed to the repository, so the container only applies
# them. Running makemigrations here used to generate schema changes at startup,
# which cannot be reviewed and races when more than one replica starts.
python manage.py migrate --noinput
python manage.py initadmin
python manage.py collectstatic --noinput

# Start Gunicorn
exec gunicorn localca_project.wsgi --bind ${BIND_ADDRESS:-0.0.0.0:8000} --worker-class=gthread --threads=4
