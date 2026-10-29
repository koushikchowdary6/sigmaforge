"""Corrupt stored rule history must not exhaust parsing or return a server error."""

import json
import uuid

import pytest
from fastapi import HTTPException

from app.detection.service import (
    _MAX_STORED_SNAPSHOT_CHARS,
    _decode_stored_rule_snapshot,
    create_rule_draft,
    get_owned_rule_draft,
    get_owned_rule_version,
)
from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRuleVersion
from tests.integration.test_rule_create_api import DRAFT
from tests.integration.test_rule_history_api import HistorySession


@pytest.mark.parametrize("corrupt", [
    "[" * 2000 + "0" + "]" * 2000,  # json.loads can raise RecursionError
    " " * (_MAX_STORED_SNAPSHOT_CHARS + 1),
    None,
    42,
])
def test_invalid_or_oversized_stored_json_returns_not_found(corrupt):
    with pytest.raises(HTTPException) as exc:
        _decode_stored_rule_snapshot(corrupt)
    assert exc.value.status_code == 404
    assert exc.value.detail == "Rule not found"


def test_valid_unicode_snapshot_survives_ascii_escaped_storage():
    draft = dict(DRAFT)
    draft["title"] = "Unicode detection 世界"
    encoded = json.dumps(draft, ensure_ascii=True, sort_keys=True)
    assert _decode_stored_rule_snapshot(encoded) == draft


@pytest.mark.asyncio
async def test_oversized_history_is_hidden_on_current_and_version_reads():
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    version = next(obj for obj in session.objects if isinstance(obj, DetectionRuleVersion))
    version.sigma_yaml = " " * (_MAX_STORED_SNAPSHOT_CHARS + 1)

    rule_id = uuid.UUID(created["id"])
    for request in (
        get_owned_rule_draft(session, rule_id, owner),
        get_owned_rule_version(session, rule_id, owner, 1),
    ):
        with pytest.raises(HTTPException) as exc:
            await request
        assert exc.value.status_code == 404
