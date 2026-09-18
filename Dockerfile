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
# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/

# Runtime dependencies only: the linters in requirements.txt are development
# tools, so they are stripped from the production image.
RUN pip install --upgrade pip \
    && grep -vE '^(pylint|autopep8)' requirements.txt > /tmp/runtime.txt \
    && pip install -r /tmp/runtime.txt \
    && rm /tmp/runtime.txt

# Application code (includes the committed migrations).
COPY localca_project /app/

# Compiled frontend, laid out exactly where settings.py expects it:
# FRONTEND_DIST = <repo>/frontend/dist, and BASE_DIR is /app/localca_project.
COPY --from=frontend /frontend/dist /app/frontend/dist

# Run as an unprivileged user; the CA database is the only thing that needs to
# be writable, and that is mounted as a volume.
RUN useradd --system --create-home --uid 10001 localca \
    && mkdir -p /app/db /app/staticfiles \
    && chown -R localca:localca /app
USER localca

EXPOSE 8000

# Start the server; docker-compose overrides this with start.sh.
# RUN python manage.py runserver 0.0.0.0:8000
