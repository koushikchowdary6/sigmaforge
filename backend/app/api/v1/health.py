"""Liveness/readiness probes (ARCHITECTURE.md §11 Observability,
API_SPECIFICATION.md §13). /healthz never touches the database -- it only
proves the process is up. /readyz checks real dependencies and degrades
gracefully (returns 503, doesn't crash) if they're unreachable."""
from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.core.database import db_manager

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(response: Response) -> dict:
    db_ok = await db_manager.check_connection()
    ready = db_ok
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready else "not_ready", "checks": {"database": db_ok}}
