# Deployment and configuration

> Part of the [Local CA](../README.md) documentation. For the environment variables themselves, see the table in the [README](../README.md#configuration).

## Behind a reverse proxy

LocalCA supports deployment behind reverse proxies with custom path prefixes. For example, to deploy at `https://yourdomain.com/localca`:

1. Set the `URL_PREFIX` environment variable: `URL_PREFIX=/localca`
2. Configure your reverse proxy to strip the path prefix before forwarding to LocalCA
3. Add your domain to `CSRF_TRUSTED_ORIGINS`

For detailed instructions on deploying behind Traefik, see [TRAEFIK_DEPLOYMENT.md](../TRAEFIK_DEPLOYMENT.md) or use the included `docker-compose-traefik.yml` example configuration.

## Configuration

### Time zone

By default, LocalCA uses UTC timezone for all timestamps and certificate expiry dates. You can customize this by setting the `TZ` environment variable in your docker-compose file:

```yaml
environment:
  - TZ=America/New_York  # Set to your desired timezone
```

Common timezone examples:
- `UTC` (default)
- `America/New_York`
- `America/Los_Angeles`
- `Europe/London`
- `Asia/Tokyo`

For a complete list of valid timezone names, see the [IANA Time Zone Database](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).

## Building and publishing images

`docker compose up --build` builds both images locally. To publish them to a
registry of your own, [scripts/image-push.sh](../scripts/image-push.sh) tags and
pushes the application image, retrying the large layers (a registry proxy in front
can time out on them):

```bash
export HARBOR_HOST=registry.example.net
export HARBOR_PROJECT=myproject
./scripts/image-push.sh 2.2.3        # or: ./scripts/image-push.sh
```

The tag defaults to the version in `frontend/package.json`. The 8000-port image
does not serve static files, so a deployment also needs nginx — either
`nginx:alpine` with [nginx.conf](../nginx.conf), or the small
[Dockerfile.nginx](../Dockerfile.nginx) image built from it. Never commit the
registry coordinates: put them in `scripts/harbor.env`, which is gitignored.

The application image runs unprivileged (`APP_UID`/`APP_GID`, default 10001). If
your bind-mounted `db` is owned by another account, either `chown` it or build
with `--build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g)`.

### GitHub Container Registry

The [`Release image`](../.github/workflows/release-image.yml) workflow publishes both images when
a version tag is pushed. The tag must match the version in `frontend/package.json`, otherwise the
run stops before building anything:

```bash
# frontend/package.json is 2.2.3
git tag v2.2.3
git push origin v2.2.3
```

| Image | Contents |
| --- | --- |
| `ghcr.io/dynesshely/localca` | The Django application and the built SPA (port 8000) |
| `ghcr.io/dynesshely/localca-nginx` | `nginx:alpine` with this repository's `nginx.conf` |

Each image is tagged with the release version (`2.2.3`), `2.2`, `2`, `sha-<short>`, and
`latest` for stable tags. Pre-release tags (for example `v2.2.3-rc1`) do not move `latest`.
Both images are built for `linux/amd64` and `linux/arm64`.

The workflow authenticates to GHCR with the repository's `GITHUB_TOKEN` (`packages: write`), so no
registry secret is required. New packages are private by default; make them public in the package
settings if you want anonymous pulls, or authenticate before pulling:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u <username> --password-stdin
docker pull ghcr.io/dynesshely/localca:2.2.3
```

`docker-compose-harbor.yml` can run these images through `LOCALCA_IMAGE` / `LOCALCA_TAG`; the
nginx image is optional, since the compose file already embeds the same configuration.

The local `scripts/image-push.sh` path remains available for publishing to another registry.

## Required configuration

Django refuses to start without a secret key. Copy `.env.example` to `.env`
next to the compose file you use and set at least:

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(50))"   # paste into DJANGO_SECRET_KEY
```

- `DJANGO_SECRET_KEY` — required, must stay secret and must not be committed.
- `DJANGO_ALLOWED_HOSTS` — the hostnames/IPs you reach LocalCA under.
- `DJANGO_DEBUG` — leave `false`. With debugging on, any unhandled error renders
  a page that includes the secret key, settings and local variables.
- `DJANGO_SECURE_COOKIES=true` — enable once served over HTTPS; this turns on
  secure cookies, HSTS and an HTTP-to-HTTPS redirect.
