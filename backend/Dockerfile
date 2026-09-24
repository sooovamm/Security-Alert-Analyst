# syntax=docker/dockerfile:1
#
# Multi-stage build.
#   base    - interpreter + runtime dependencies + the non-root user
#   runtime - the production image: application code only, no tests, no tooling
#   dev     - test/lint tooling; the source is bind-mounted at run time
#
# No secret is ever copied in: .env is excluded by .dockerignore and every
# credential is supplied as an environment variable by the orchestrator.

# ---------------------------------------------------------------- base -----
FROM python:3.12-slim AS base

# No .pyc files (the source is read-only at run time) and unbuffered stdout so
# container logs appear immediately instead of being held in a pipe buffer.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/app/data \
    DATABASE_URL=sqlite:////app/var/app.db

WORKDIR /app

# Dependencies first: this layer is rebuilt only when requirements.txt changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The container runs as a non-root user. /app stays root-owned, so the
# application cannot modify its own code; /app/var is the single writable
# path and holds the SQLite database.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/var \
    && chown appuser:appuser /app/var

# ------------------------------------------------------------- runtime -----
FROM base AS runtime

COPY app ./app

USER appuser
EXPOSE 8000

# Liveness only: /health touches no dependency, so a slow LLM or an empty
# database never restarts a healthy container. start-period covers dataset
# seeding and the RAG index warm-up on first boot.
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# --no-access-log: the app's own middleware already logs every request with its
# request id, so uvicorn's access log would print each line a second time.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

# ----------------------------------------------------------------- dev -----
# Test runner. Dependencies live in the image, the code is mounted read-only
# from the host, so `pytest` needs no local Python install.
FROM base AS dev

COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

# The repository is mounted here; tests resolve the repo root relative to it.
WORKDIR /repo/backend
USER appuser

# -p no:cacheprovider: the mount is read-only, so pytest must not try to write
# a .pytest_cache directory into it.
CMD ["pytest", "-p", "no:cacheprovider"]
