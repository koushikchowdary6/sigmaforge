"""Authenticated structural preflight and draft creation endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.detection.service import create_rule_draft, get_owned_rule_draft, list_owned_rule_drafts
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


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RulePreflightRequest,
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Persist a draft with version 1; no semantic approval or deployment."""
    return await create_rule_draft(db, body, user.id)


@router.get("")
async def list_rules(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Return only the requester's structurally validated drafts."""
    return await list_owned_rule_drafts(db, user.id, limit, offset)


@router.get("/{rule_id}")
async def read_owned_rule(
    rule_id: uuid.UUID,
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Return the current version of a draft belonging to this user only."""
    return await get_owned_rule_draft(db, rule_id, user.id)
