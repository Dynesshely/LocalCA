# ---------------------------------------------------------------------------
# Stage 1: build the Vue single-page frontend.
#
# The frontend must be built before the Python image copies it, because Django
# serves the compiled bundle from frontend/dist (settings.FRONTEND_DIST).
# ---------------------------------------------------------------------------
FROM node:22-alpine AS frontend

WORKDIR /frontend

# corepack provides the pnpm version pinned in package.json's packageManager
# field, so the build uses the same package manager as development.
RUN corepack enable

# Dependency manifests first: this layer is cached until the lockfile changes.
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm build


# ---------------------------------------------------------------------------
# Stage 2: the application image.
#
# The layout mirrors the repository exactly:
#
#     /app/localca_project/...    the Django project  (BASE_DIR)
#     /app/frontend/dist/...      the compiled SPA
#
# Keeping that shape matters: settings.py derives FRONTEND_DIST from
# BASE_DIR.parent / 'frontend' / 'dist'. A flat layout (app files directly in
# /app) makes BASE_DIR.parent resolve to '/' instead, the frontend is never
# found, and the container silently serves the "frontend not built" page.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# The uid/gid the container runs as. Override these when the database is a bind
# mount owned by a different account -- an upgrade from a root-running image
# leaves the SQLite file owned by root, and this image will not be able to write
# to it otherwise:
#
#     docker build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g) -t localca .
#
# This exists so the image does not have to run as root to work with an existing
# volume.
ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Runtime dependencies only. requirements.txt no longer contains the linters
# (they live in requirements-dev.txt), so no filtering is needed here.
#
# --no-cache-dir matters more than it looks: pip otherwise keeps every downloaded
# wheel under /root/.cache/pip, which baked ~80 MB into this layer and pushed the
# image to 327 MB. Nothing in the runtime image needs that cache.
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Application code, including the committed migrations.
COPY localca_project /app/localca_project/

# Compiled frontend, at the path settings.FRONTEND_DIST resolves to.
COPY --from=frontend /frontend/dist /app/frontend/dist

# Run as an unprivileged user. The SQLite database and collected static files
# are the only things that need to be writable.
#
# Note the group is created explicitly: `useradd --system` would otherwise put the
# user in the wheel group, which is wider than intended.
RUN groupadd --system --gid "${APP_GID}" localca \
    && useradd --system --uid "${APP_UID}" --gid "${APP_GID}" \
       --create-home --home-dir /home/localca localca \
    && mkdir -p /app/localca_project/db /app/localca_project/staticfiles /home/localca \
    && chown -R "${APP_UID}:${APP_GID}" /app /home/localca
USER ${APP_UID}:${APP_GID}

# Run from the Django project directory: this is where manage.py and start.sh
# live, and it keeps the layout the same as the repository.
WORKDIR /app/localca_project

EXPOSE 8000

# Migrate, collect static, then serve through gunicorn. docker-compose may
# override this, and a bare `docker run` still gets a working container.
CMD ["sh", "start.sh"]
