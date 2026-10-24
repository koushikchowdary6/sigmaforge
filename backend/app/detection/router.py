"""Authenticated, read-only Sigma draft structural preflight endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import require_permission
from app.detection.validation import RulePreflightRequest
from app.models.user import User

router = APIRouter(prefix="/rules", tags=["rules"])


@router.post("/preflight")
async def preflight_rule(
    body: RulePreflightRequest,
    _user: User = Depends(require_permission("rule:create")),
) -> dict[str, object]:
    return {
        "valid": True,
        "validation_level": "structural_only",
        "selector_count": len(body.selector_names),
        "selector_names": body.selector_names,
    }
