# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Non-root user for the entire image, per THREAT_MODEL.md §5 (least privilege,
# container hardening). Created early so ownership is right for every
# subsequent COPY.
RUN groupadd --gid 1000 sigmaforge && \
    useradd --uid 1000 --gid sigmaforge --shell /bin/bash --create-home sigmaforge

WORKDIR /app

# System deps needed to build asyncpg/argon2-cffi wheels, removed from the
# final layer's apt cache to keep the image lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=sigmaforge:sigmaforge . .

USER sigmaforge

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
