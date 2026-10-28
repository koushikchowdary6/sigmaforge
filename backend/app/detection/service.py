"""Atomic creation of structurally validated Sigma rule drafts.

JSON is a valid YAML 1.2 representation. Persist the validated mapping in
that form without a lossy conversion or introducing a YAML serializer. This
is not pySigma semantic validation; drafts are not approved or deployable.
"""
from __future__ import annotations

import json
import uuid

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
