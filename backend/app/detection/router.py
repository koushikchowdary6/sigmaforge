"""Authenticated structural preflight and draft creation endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.detection.service import (
    create_rule_draft,
    diff_owned_rule_version,
    get_owned_rule_draft,
    get_owned_rule_version,
    list_owned_rule_drafts,
    list_owned_rule_versions,
    revise_owned_rule_draft,
)
from app.detection.semantic import parse_rule_with_pysigma
from app.detection.validation import RulePreflightRequest
from app.models.user import User

router = APIRouter(prefix="/rules", tags=["rules"])


class RuleDraftRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    draft: RulePreflightRequest



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


@router.post("/semantic-preflight")
async def semantic_preflight_rule(
    body: RulePreflightRequest,
    _user: User = Depends(require_permission("rule:create")),
) -> dict[str, object]:
    """Opt-in upstream Sigma parsing; no conversion, approval, or deployment."""
    try:
        return parse_rule_with_pysigma(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


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


@router.patch("/{rule_id}")
async def revise_rule(
    rule_id: uuid.UUID,
    body: RuleDraftRevisionRequest,
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Create the next immutable draft version; reject stale or foreign edits."""
    return await revise_owned_rule_draft(db, rule_id, user.id, body.expected_version, body.draft)


@router.get("/{rule_id}/versions")
async def list_rule_versions(
    rule_id: uuid.UUID,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """List the owner's immutable versions without exposing Sigma bodies."""
    return await list_owned_rule_versions(db, rule_id, user.id, limit, offset)


@router.get("/{rule_id}/versions/{version_number}")
async def read_rule_version(
    rule_id: uuid.UUID,
    version_number: int = Path(ge=1),
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Retrieve an authorized historical Sigma snapshot by version number."""
    return await get_owned_rule_version(db, rule_id, user.id, version_number)


@router.get("/{rule_id}/versions/{version_number}/diff")
async def diff_rule_version(
    rule_id: uuid.UUID,
    version_number: int = Path(ge=2),
    user: User = Depends(require_permission("rule:create")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Summarize changed draft fields versus N-1; owner-scoped, not semantic."""
    return await diff_owned_rule_version(db, rule_id, user.id, version_number)
