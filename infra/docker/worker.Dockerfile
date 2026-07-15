# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

RUN groupadd --gid 1000 sigmaforge && \
    useradd --uid 1000 --gid sigmaforge --shell /bin/bash --create-home sigmaforge

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=sigmaforge:sigmaforge . .

USER sigmaforge

# Liveness proven via `celery inspect ping`, not an HTTP endpoint -- the
# worker has no HTTP server (ARCHITECTURE.md §5: it's a queue consumer).
HEALTHCHECK --interval=15s --timeout=10s --start-period=15s --retries=3 \
    CMD celery -A app.celery_app inspect ping -d celery@$HOSTNAME || exit 1

CMD ["celery", "-A", "app.celery_app", "worker", "--loglevel=info"]
