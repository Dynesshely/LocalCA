#!/bin/sh
set -e

# Migrations are committed to the repository, so the container only applies
# them. Running makemigrations here used to generate schema changes at startup,
# which cannot be reviewed and races when more than one replica starts.
python manage.py migrate --noinput
python manage.py initadmin
python manage.py collectstatic --noinput

# Start Gunicorn
exec gunicorn localca_project.wsgi --bind ${BIND_ADDRESS:-0.0.0.0:8000} --worker-class=gthread --threads=4
