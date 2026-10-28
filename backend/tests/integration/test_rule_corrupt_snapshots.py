"""Corrupted stored Sigma snapshots must not leak 500s or misleading diffs."""

import uuid

import pytest
from fastapi import HTTPException

from app.detection.service import (
    create_rule_draft,
    diff_owned_rule_version,
    get_owned_rule_draft,
    get_owned_rule_version,
    revise_owned_rule_draft,
)
from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRuleVersion
from tests.integration.test_rule_create_api import DRAFT
from tests.integration.test_rule_history_api import HistorySession
from tests.integration.test_rule_revision_api import revised_draft


@pytest.mark.asyncio
@pytest.mark.parametrize("corrupt", [
    "{not-json",
    "[]",
    "{}",
    '{"title":"x","logsource":{},"detection":[]}',
    '{"title":"x","logsource":{},"detection":{"condition":7}}',
])
async def test_corrupt_current_snapshot_returns_404_for_owner_reads(corrupt):
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    rule_id = uuid.UUID(created["id"])
    version = next(obj for obj in session.objects if isinstance(obj, DetectionRuleVersion))
    version.sigma_yaml = corrupt

    for request in (
        get_owned_rule_draft(session, rule_id, owner),
        get_owned_rule_version(session, rule_id, owner, 1),
    ):
        with pytest.raises(HTTPException) as exc:
            await request
        assert exc.value.status_code == 404
        assert exc.value.detail == "Rule not found"


@pytest.mark.asyncio
async def test_corrupt_historical_snapshot_cannot_generate_misleading_diff():
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    rule_id = uuid.UUID(created["id"])
    await revise_owned_rule_draft(session, rule_id, owner, 1, revised_draft())

    historical = next(
        obj for obj in session.objects
        if isinstance(obj, DetectionRuleVersion) and obj.version_number == 1
    )
    historical.sigma_yaml = '{"title":"bad","detection":{}}'

    with pytest.raises(HTTPException) as exc:
        await diff_owned_rule_version(session, rule_id, owner, 2)
    assert exc.value.status_code == 404
    assert exc.value.detail == "Rule not found"
