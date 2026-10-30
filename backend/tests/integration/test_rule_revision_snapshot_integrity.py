"""Revision integrity tests for corrupted and noncanonical stored snapshots."""
import json
import uuid

import pytest
from fastapi import HTTPException

from app.detection.service import create_rule_draft, revise_owned_rule_draft
from app.detection.validation import RulePreflightRequest
from tests.integration.test_rule_create_api import DRAFT
from tests.integration.test_rule_revision_api import RevisionSession, revised_draft


@pytest.mark.asyncio
@pytest.mark.parametrize("corrupt_snapshot", [
    "{invalid json",
    '{"title":"one","title":"two","logsource":{},"detection":{}}',
    '{"title":"bad","logsource":{"product":"windows"},"detection":{"condition":"missing"}}',
])
async def test_revision_rejects_corrupt_current_history_without_writing(corrupt_snapshot):
    owner = uuid.uuid4()
    session = RevisionSession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    rule, version = session.objects
    version.sigma_yaml = corrupt_snapshot

    with pytest.raises(HTTPException) as exc:
        await revise_owned_rule_draft(
            session, uuid.UUID(created["id"]), owner, 1, revised_draft()
        )
    assert exc.value.status_code == 404
    assert rule.current_version_id == version.id
    assert len(session.objects) == 2
    assert session.commits == 1


@pytest.mark.asyncio
async def test_semantically_unchanged_noncanonical_json_does_not_create_version():
    owner = uuid.uuid4()
    session = RevisionSession()
    draft = RulePreflightRequest(**DRAFT)
    created = await create_rule_draft(session, draft, owner)
    session.objects[1].sigma_yaml = json.dumps(draft.model_dump(), indent=2)

    with pytest.raises(HTTPException) as exc:
        await revise_owned_rule_draft(
            session, uuid.UUID(created["id"]), owner, 1, draft
        )
    assert exc.value.status_code == 409
    assert len(session.objects) == 2
    assert session.commits == 1


@pytest.mark.asyncio
async def test_legitimate_change_after_noncanonical_snapshot_still_appends_version():
    owner = uuid.uuid4()
    session = RevisionSession()
    draft = RulePreflightRequest(**DRAFT)
    created = await create_rule_draft(session, draft, owner)
    session.objects[1].sigma_yaml = json.dumps(draft.model_dump(), indent=2)

    result = await revise_owned_rule_draft(
        session, uuid.UUID(created["id"]), owner, 1, revised_draft()
    )
    assert result["version_number"] == 2
    assert len(session.objects) == 3
    assert session.commits == 2
