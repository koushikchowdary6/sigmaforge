"""Celery application factory.

E0 scope is intentionally narrow: prove the worker process boots, connects
to the broker, and can execute a real (not stubbed) task end-to-end. The
validation/deployment/AI-generation/experiment-orchestration jobs described
in ARCHITECTURE.md §5 and §11 are E1/R1+ work -- adding an empty stub task
per job type now would be exactly the placeholder implementation the project
rules forbid.
"""
from __future__ import annotations

from celery import Celery

from app.config import settings

celery_app = Celery(
    "sigmaforge_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Explicit routing keeps future job types (validation, deployment,
    # ai_generation, experiment_orchestration) each on their own named queue,
    # matching ARCHITECTURE.md §11's separation of AI job concurrency from
    # validation job concurrency -- set up now so E1/R1 additions don't
    # require reworking queue topology.
    task_routes={
        "app.jobs.*": {"queue": "default"},
    },
)

celery_app.autodiscover_tasks(["app.jobs"])
