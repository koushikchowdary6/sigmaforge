"""Real test: runs the ping task synchronously (Celery's eager-execution
mode) and checks the actual return value/shape -- not a mock, the real task
function registered on the real Celery app."""
from __future__ import annotations

from app.celery_app import celery_app
from app.jobs.ping import ping


def test_ping_task_is_registered_on_the_app():
    assert "app.jobs.ping" in celery_app.tasks


def test_ping_returns_ok_status_and_iso_timestamp():
    celery_app.conf.task_always_eager = True
    result = ping.delay()
    payload = result.get(timeout=5)

    assert payload["status"] == "ok"
    from datetime import datetime

    # Raises if not a valid ISO-8601 timestamp -- proves it's real, not a stub string.
    datetime.fromisoformat(payload["timestamp"])
