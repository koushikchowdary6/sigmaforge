"""Offline transaction and schema tests for Sigma draft persistence."""
import json
import uuid

import pytest

from app.detection.service import create_rule_draft
from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRule, DetectionRuleVersion


class RecordingSession:
    def __init__(self, fail_on_flush=None):
        self.objects = []
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.fail_on_flush = fail_on_flush

    def add(self, obj):
        self.objects.append(obj)

    async def flush(self):
        self.flushes += 1
        if self.flushes == self.fail_on_flush:
            raise RuntimeError("simulated database failure")

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


def sample_draft():
    return RulePreflightRequest(
        title="Suspicious login",
        logsource={"product": "windows", "service": "security"},
        detection={"selection": {"EventID": 4625}, "condition": "selection"},
    )


@pytest.mark.asyncio
async def test_persisted_rule_has_one_version_and_owner():
    session = RecordingSession()
    owner_id = uuid.uuid4()
    draft = sample_draft()
    result = await create_rule_draft(session, draft, owner_id)
    assert session.flushes == 2
    assert session.commits == 1
    assert session.rollbacks == 0
    rule, version = session.objects
    assert isinstance(rule, DetectionRule)
    assert isinstance(version, DetectionRuleVersion)
    assert rule.id == version.rule_id
    assert rule.current_version_id == version.id
    assert rule.owner_id == version.created_by == owner_id
    assert rule.log_source == "windows"
    assert version.version_number == 1
    assert json.loads(version.sigma_yaml) == draft.model_dump()
    assert result["status"] == "draft"
    assert result["validation_level"] == "structural_only"
    assert result["id"] == str(rule.id)
    assert result["version_id"] == str(version.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_flush", [1, 2])
async def test_failed_write_rolls_back_without_commit(failed_flush):
    session = RecordingSession(fail_on_flush=failed_flush)
    with pytest.raises(RuntimeError, match="simulated database failure"):
        await create_rule_draft(session, sample_draft(), uuid.uuid4())
    assert session.commits == 0
    assert session.rollbacks == 1


def test_draft_log_source_must_fit_existing_database_column():
    with pytest.raises(ValueError, match="logsource"):
        RulePreflightRequest(
            title="Example",
            logsource={"product": "x" * 101},
            detection={"selection": {"EventID": 4625}, "condition": "selection"},
        )
