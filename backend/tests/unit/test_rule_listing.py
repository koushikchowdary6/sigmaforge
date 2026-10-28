"""Offline regression tests for owner-scoped Sigma draft listing."""

import uuid
from types import SimpleNamespace

import pytest

from app.detection.service import list_owned_rule_drafts
from app.models.detection import DetectionRule, DetectionRuleVersion


class FakeSession:
    def __init__(self, rows):
        self.rows = rows
        self.statement = None

    async def execute(self, statement):
        self.statement = statement
        return SimpleNamespace(all=lambda: self.rows)


def make_row(title, owner_id):
    rule_id, version_id = uuid.uuid4(), uuid.uuid4()
    return (
        DetectionRule(id=rule_id, rule_uid=str(uuid.uuid4()), title=title,
                      owner_id=owner_id, current_version_id=version_id),
        DetectionRuleVersion(id=version_id, rule_id=rule_id,
                             version_number=1, sigma_yaml="{}", created_by=owner_id),
    )


@pytest.mark.asyncio
async def test_list_projection_is_bounded_and_does_not_include_rule_body():
    owner = uuid.uuid4()
    session = FakeSession([make_row(name, owner) for name in ("Alpha", "Beta", "Gamma")])
    result = await list_owned_rule_drafts(session, owner, limit=2, offset=0)
    assert [item["title"] for item in result["items"]] == ["Alpha", "Beta"]
    assert result["has_more"] is True
    assert result["limit"] == 2 and result["offset"] == 0
    assert all("sigma" not in item for item in result["items"])
    statement = str(session.statement)
    assert "detection_rules.owner_id" in statement
    assert "detection_rule_versions.rule_id = detection_rules.id" in statement
    assert "ORDER BY detection_rules.title ASC, detection_rules.id ASC" in statement


@pytest.mark.asyncio
async def test_empty_list_has_no_next_page():
    result = await list_owned_rule_drafts(FakeSession([]), uuid.uuid4(), limit=20, offset=0)
    assert result == {"items": [], "limit": 20, "offset": 0, "has_more": False}
