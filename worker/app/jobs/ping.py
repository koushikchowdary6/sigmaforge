"""The one real E0 job: a liveness/round-trip check.

This exists to prove the worker process, Celery app, and broker connection
all actually function end-to-end -- exercised by docker-compose's worker
healthcheck (infra/docker-compose.yml) and by tests/test_ping.py. It is not
a placeholder for a future job; it is itself a real, useful diagnostic task
that a production deployment keeps around permanently.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.celery_app import celery_app


@celery_app.task(name="app.jobs.ping")
def ping() -> dict:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
