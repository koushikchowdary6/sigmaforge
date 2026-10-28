"""Syntactically valid JSON must still satisfy persisted Sigma draft structure."""

import copy
import json
import uuid

import pytest
from fastapi import HTTPException

from app.detection.service import (
    _decode_stored_rule_snapshot,
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


@pytest.mark.parametrize("damage", [
    lambda rule: rule["detection"]["selection"].update({"EventID": {"nested": 4625}}),
    lambda rule: rule["detection"].update({"condition": "missing_selector"}),
    lambda rule: rule["detection"].update({"condition": ["selection", 42]}),
    lambda rule: rule["detection"].update({"timeframe": "99Q"}),
    lambda rule: rule["logsource"].update({"product": ""}),
])
def test_structurally_invalid_stored_json_is_rejected(damage):
    damaged = copy.deepcopy(DRAFT)
    damage(damaged)
    with pytest.raises(HTTPException) as exc:
        _decode_stored_rule_snapshot(json.dumps(damaged))
    assert exc.value.status_code == 404
    assert exc.value.detail == "Rule not found"


def test_valid_stored_snapshot_preserves_original_representation():
    serialized = json.dumps(DRAFT, sort_keys=True)
    assert _decode_stored_rule_snapshot(serialized) == DRAFT


@pytest.mark.asyncio
async def test_invalid_selector_value_is_hidden_on_current_version_reads():
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    version = next(obj for obj in session.objects if isinstance(obj, DetectionRuleVersion))
    damaged = copy.deepcopy(DRAFT)
    damaged["detection"]["selection"] = {"EventID": {"nested": 4625}}
    version.sigma_yaml = json.dumps(damaged)

    for request in (
        get_owned_rule_draft(session, uuid.UUID(created["id"]), owner),
        get_owned_rule_version(session, uuid.UUID(created["id"]), owner, 1),
    ):
        with pytest.raises(HTTPException) as exc:
            await request
        assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_invalid_historical_selector_cannot_generate_version_diff():
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    rule_id = uuid.UUID(created["id"])
    await revise_owned_rule_draft(session, rule_id, owner, 1, revised_draft())
    historical = next(
        obj for obj in session.objects
        if isinstance(obj, DetectionRuleVersion) and obj.version_number == 1
    )
    damaged = copy.deepcopy(DRAFT)
    damaged["detection"]["condition"] = "missing_selector"
    historical.sigma_yaml = json.dumps(damaged)

    with pytest.raises(HTTPException) as exc:
        await diff_owned_rule_version(session, rule_id, owner, 2)
    assert exc.value.status_code == 404
