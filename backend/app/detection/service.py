"""Atomic creation of structurally validated Sigma rule drafts.

JSON is a valid YAML 1.2 representation. Persist the validated mapping in
that form without a lossy conversion or introducing a YAML serializer. This
is not pySigma semantic validation; drafts are not approved or deployable.
"""
from __future__ import annotations

import json
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRule, DetectionRuleVersion


async def create_rule_draft(
    session: AsyncSession, draft: RulePreflightRequest, owner_id: uuid.UUID
) -> dict[str, object]:
    """Create a rule and version 1 together, or roll both back on failure."""
    rule_id = uuid.uuid4()
    version_id = uuid.uuid4()
    rule = DetectionRule(
        id=rule_id,
        rule_uid=str(uuid.uuid4()),
        title=draft.title,
        log_source=next(
            (draft.logsource[key] for key in ("product", "category", "service") if key in draft.logsource),
            None,
        ),
        owner_id=owner_id,
        current_version_id=None,
    )
    version = DetectionRuleVersion(
        id=version_id,
        rule_id=rule_id,
        version_number=1,
        sigma_yaml=json.dumps(draft.model_dump(), ensure_ascii=True, sort_keys=True),
        created_by=owner_id,
    )
    try:
        session.add(rule)
        await session.flush()
        session.add(version)
        await session.flush()
        rule.current_version_id = version_id
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    return {
        "id": str(rule_id),
        "rule_uid": rule.rule_uid,
        "version_id": str(version_id),
        "version_number": 1,
        "status": "draft",
        "validation_level": "structural_only",
    }


async def get_owned_rule_draft(
    session: AsyncSession, rule_id: uuid.UUID, owner_id: uuid.UUID
) -> dict[str, object]:
    """Read only the requester's draft; hide other users' rule existence."""
    rule = await session.get(DetectionRule, rule_id)
    if rule is None or rule.owner_id != owner_id or rule.current_version_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    version = await session.get(DetectionRuleVersion, rule.current_version_id)
    if version is None or version.rule_id != rule.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return {
        "id": str(rule.id),
        "rule_uid": rule.rule_uid,
        "title": rule.title,
        "version_id": str(version.id),
        "version_number": version.version_number,
        "sigma": json.loads(version.sigma_yaml),
        "validation_level": "structural_only",
    }


async def list_owned_rule_drafts(
    session: AsyncSession, owner_id: uuid.UUID, limit: int, offset: int
) -> dict[str, object]:
    """List only the authenticated owner's drafts, without loading Sigma bodies.

    A stable (title, id) order makes offset pagination deterministic for an
    unchanged dataset. Fetch one extra row to determine whether more results
    exist, without an expensive count or exposing other owners' records.
    """
    statement = (
        select(DetectionRule, DetectionRuleVersion)
        .join(DetectionRuleVersion, DetectionRule.current_version_id == DetectionRuleVersion.id)
        .where(
            DetectionRule.owner_id == owner_id,
            DetectionRuleVersion.rule_id == DetectionRule.id,
        )
        .order_by(DetectionRule.title.asc(), DetectionRule.id.asc())
        .offset(offset)
        .limit(limit + 1)
    )
    rows = (await session.execute(statement)).all()
    items = [
        {
            "id": str(rule.id),
            "rule_uid": rule.rule_uid,
            "title": rule.title,
            "version_id": str(version.id),
            "version_number": version.version_number,
            "validation_level": "structural_only",
        }
        for rule, version in rows[:limit]
    ]
    return {
        "items": items,
        "limit": limit,
        "offset": offset,
        "has_more": len(rows) > limit,
    }
