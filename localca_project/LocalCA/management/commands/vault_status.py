"""
Report which certificate private keys are encrypted, which are not, and why.

This exists so "private keys are encrypted" can be checked rather than assumed.
It is read-only and needs no vault password: it reports state, never key
material.
"""
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from LocalCA.keys import vault_status
from LocalCA.vault import idle_timeout
from LocalCA.models import IntermediateCertificate, LeafCertificate, RootCertificate

KINDS = (
    ('root', RootCertificate),
    ('intermediate', IntermediateCertificate),
    ('leaf', LeafCertificate),
)


class Command(BaseCommand):
    help = 'Show vault status: encrypted vs plaintext private keys.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username', default=None,
            help='Limit the inventory to one account (in-memory unlock state is '
                 'only reported when this is given).')

    def handle(self, *args, **options):
        username = options['username']
        user = None
        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist as exc:
                raise CommandError(f'No such user: {username}') from exc

        report = vault_status(user.id if user else None)

        if user:
            state = 'unsealed' if report['unsealed'] else 'locked'
            remaining = report['unseal_remaining_seconds']
            self.stdout.write(f'Vault for {username}: {state}')
            if report['unsealed']:
                self.stdout.write(
                    f'  auto-locks after {idle_timeout()}s idle '
                    f'({remaining}s remaining)')
            if not report['has_root_key']:
                self.stdout.write(self.style.WARNING(
                    '  No vault password has been set for this account yet.'))
        else:
            self.stdout.write('Vault status (all accounts)')

        self.stdout.write('')
        self.stdout.write(f'  {"kind":<14}{"encrypted":>11}{"plaintext":>11}'
                          f'{"no owner":>11}{"no key":>9}')
        for kind, _model in KINDS:
            bucket = report['by_kind'][kind]
            self.stdout.write(
                f'  {kind:<14}{bucket["wrapped"]:>11}{bucket["plaintext"]:>11}'
                f'{bucket["orphaned"]:>11}{bucket["no_key"]:>9}')
        self.stdout.write(
            f'  {"TOTAL":<14}{report["wrapped"]:>11}{report["plaintext"]:>11}'
            f'{report["orphaned"]:>11}{report["no_key"]:>9}')

        if report['plaintext']:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                f'{report["plaintext"]} private key(s) are still stored in the '
                f'legacy plaintext column. Wrap them with:\n'
                f'  python manage.py rewrap_keys --username <user>'))
        if report['orphaned']:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                f'{report["orphaned"]} private key(s) belong to no account, so no '
                f'password can wrap them. They stay readable as plaintext.'))
        if report['plaintext'] or report['orphaned']:
            self.stdout.write('')
            self.stdout.write(
                'Encryption at rest only covers rows counted as "encrypted".')
        else:
            self.stdout.write('')
            self.stdout.write(self.style.SUCCESS(
                'All private keys with an owner are encrypted.'))
