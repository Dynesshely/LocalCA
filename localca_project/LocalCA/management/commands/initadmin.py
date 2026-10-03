"""
Create the initial superuser on a fresh deployment.

There is deliberately no built-in password. A published default like
`admin/password` is the first thing an attacker tries, and a container that
starts with one is compromised before its owner sees the console. Instead:

* if DJANGO_SUPERUSER_PASSWORD is set, it is used (deployments that provision
  credentials from their own secret store);
* otherwise a random password is generated and printed once.
"""
import logging
import os
import secrets

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db.utils import IntegrityError

logger = logging.getLogger(__name__)

#: Environment variable holding a caller-supplied initial password.
ENV_PASSWORD = 'DJANGO_SUPERUSER_PASSWORD'
#: Environment variable overriding the initial username.
ENV_USERNAME = 'DJANGO_SUPERUSER_USERNAME'
ENV_EMAIL = 'DJANGO_SUPERUSER_EMAIL'

DEFAULT_USERNAME = 'admin'
DEFAULT_EMAIL = 'admin@example.com'


class Command(BaseCommand):
    '''
    Create a superuser when the database has none yet.

    This runs on every container start, so it does nothing once a user exists.
    '''
    help = 'Create the initial superuser if no users exist'

    def handle(self, *args, **options):
        if User.objects.exists():
            self.stdout.write(self.style.WARNING(
                'Users already exist; no initial superuser created.'))
            return

        username = os.environ.get(ENV_USERNAME) or DEFAULT_USERNAME
        email = os.environ.get(ENV_EMAIL) or DEFAULT_EMAIL
        supplied = os.environ.get(ENV_PASSWORD)
        password = supplied or secrets.token_urlsafe(18)

        try:
            User.objects.create_superuser(
                username=username, email=email, password=password)
        except IntegrityError:
            self.stdout.write(self.style.ERROR(
                f'Could not create the initial superuser; {username!r} may already '
                f'exist.'))
            logger.error('Failed to create the initial superuser')
            return

        logger.info('Initial superuser %r created', username)

        if supplied:
            # Caller-provided: do not echo it, their secret store already has it.
            self.stdout.write(self.style.SUCCESS(
                f'Initial superuser created (password from {ENV_PASSWORD}).'))
            self.stdout.write(f'  Username: {username}')
        else:
            self.stdout.write(self.style.SUCCESS('Initial superuser created.'))
            self.stdout.write(f'  Username: {username}')
            self.stdout.write(f'  Password: {password}')
            self.stdout.write(self.style.WARNING(
                'This password is shown once and is not stored anywhere. Record it '
                'now, then change it in the UI. To choose your own instead, set '
                f'{ENV_PASSWORD} before the first start.'))
