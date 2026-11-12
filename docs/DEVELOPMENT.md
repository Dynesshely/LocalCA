# Architecture and development

> Part of the [Local CA](../README.md) documentation.

## Architecture

LocalCA is split into a JSON API and a single-page frontend:

```
localca_project/          Django: JSON API, ORM, auth, certificate operations
  LocalCA/
    api_urls.py           The API's URL map
    api/                  The endpoints, one module per thing they do:
      common.py             request/response plumbing, permissions, kind map
      auth.py               session, login, logout, password change
      keystore.py           named credentials and the keys they wrap
      meta.py               static tables the interface renders from
      certificates.py       reading the hierarchy
      issuance.py           creating and renewing certificates
      lifecycle.py          revoking and deleting certificates
      downloads.py          downloads, and the format table they answer from
      imports.py            importing existing certificate material
      audit.py              the audit log
      shell.py              the SPA shell
    serializers.py        Certificate -> JSON, including per-user rights
    ca.py                 Certificate generation (cryptography; never shells out to openssl)
    forms.py              Server-side validation for every certificate input
    models.py             Roots, intermediates, leaves, revocations, credentials, audit log
    keys.py               Which key lives under which credential, and how to use it
    vault.py              The envelope format: scrypt KEK, root key, HKDF per key
    importers.py          Parsing uploaded bundles (content, not filenames)
    import_service.py     Planning and applying an import
    throttle.py           Login attempt limits
frontend/                 Vue 3 SPA (Vite + Tailwind CSS 4)
  src/
    api/                  Endpoint wrappers, CSRF, error shape, downloads
    stores/               Pinia: session, certificates, keystore, toasts
    views/                One component per page
    components/           Shell, certificate tree, dialogs, form controls
    composables/          Shared behaviour (the download flow)
    i18n/                 Catalogs and locale handling, one file per namespace
```

Django renders no application pages. It authenticates (session cookie plus CSRF
token), serves the API under `/api/`, and serves the built SPA for every other
path so client-side deep links such as `/create/leaf` work.

## Development

Backend:

```bash
git clone https://github.com/Dynesshely/LocalCA.git
cd LocalCA
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd localca_project
export CSRF_TRUSTED_ORIGINS="http://localhost:5173"
export DJANGO_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
export DJANGO_DEBUG=true
export DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost

# Migrations are committed, so apply them rather than regenerating.
python manage.py migrate
python manage.py runserver 8000
```

Frontend, in a second terminal. Vite proxies `/api` to Django, so the SPA and
the API share an origin and session/CSRF behave exactly as in production:

```bash
cd frontend
pnpm install
pnpm dev            # http://localhost:5173, proxies /api to :8000
```

To build the bundle that Django serves, run `pnpm build` from `frontend/`: it
writes `frontend/dist`, which `settings.py` picks up automatically. Without a
build, `/` returns a short placeholder page explaining how to make one.

## Translations

The interface is translated in `frontend/src/i18n/messages/<locale>/`, one JSON
file per namespace; the file's top-level key *is* the namespace, so
`en/leaf.json` provides `leaf.*` and adding a feature means adding a file. The
loader merges them, so no index needs editing.

Server-authored text — validation errors, rate limits, revocation reason labels —
is translated with Django's gettext from `localca_project/locale/`. The SPA sends
its current locale in `Accept-Language`, so an error always comes back in the
language the page is drawn in:

```bash
python3 scripts/i18n.py check     # every msgid in the code has a translation
python3 scripts/i18n.py compile   # .po -> .mo (no GNU gettext needed)
python3 scripts/i18n.py extract   # what is translatable, and where
```

Both the `.po` and the generated `.mo` are committed, because neither the
`python:3.12-slim` image nor a bare dev machine ships `msgfmt`. Where GNU gettext
*is* available, `manage.py makemessages` / `compilemessages` remain a drop-in
replacement for the first two commands.

`LocalCA/tests_i18n.py` asserts the catalogues are complete and that the same
request answers in the requested language, so a translation cannot silently fall
behind the code it belongs to.

Every asset name carries a content hash, so a rebuilt bundle can never be served
from a stale browser cache. Django does cache the parsed shell template, though:
if `runserver` was started with `--noreload` (as the development setup here does)
restart it after a rebuild, otherwise it keeps serving the previous asset names.

Run the test suite (it does not need a real key):

```bash
DJANGO_TESTING=true python manage.py test LocalCA
```

Build and deploy locally with the above instructions. LocalCA is under active development and contributions are welcome!
