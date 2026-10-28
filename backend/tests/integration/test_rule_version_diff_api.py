"""Owner-scoped, bounded structural diffs of immutable Sigma draft versions."""

import uuid

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.core.database import get_db
from app.detection.service import (
    create_rule_draft,
    diff_owned_rule_version,
    revise_owned_rule_draft,
    summarize_rule_version_changes,
)
from app.detection.validation import RulePreflightRequest
from app.models.rbac import Role
from tests.integration.test_auth_api import app_and_repo  # noqa: F401
from tests.integration.test_rule_create_api import DRAFT
from tests.integration.test_rule_history_api import HistorySession
from tests.integration.test_rule_revision_api import revised_draft


def test_structural_diff_detects_selector_changes_and_ignores_key_order():
    previous = {
        "title": "Rule",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4625},
            "old": {"EventID": 1},
            "condition": "selection",
        },
    }
    current = {
        "detection": {
            "new": {"EventID": 3},
            "selection": {"EventID": 4624},
            "condition": "selection or new",
            "timeframe": "5m",
        },
        "logsource": {"product": "linux"},
        "title": "Revised rule",
    }
    summary = summarize_rule_version_changes(previous, current)
    assert summary == {
        "fields_changed": [
            "title", "logsource", "detection.condition", "detection.timeframe"
        ],
        "selectors_added": ["new"],
        "selectors_removed": ["old"],
        "selectors_modified": ["selection"],
        "has_changes": True,
    }
    assert "4624" not in str(summary)
    assert summarize_rule_version_changes(previous, dict(reversed(list(previous.items())))) == {
        "fields_changed": [], "selectors_added": [], "selectors_removed": [],
        "selectors_modified": [], "has_changes": False,
    }


@pytest.mark.asyncio
async def test_diff_is_owner_scoped_and_missing_versions_fail_closed():
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    rule_id = uuid.UUID(created["id"])
    await revise_owned_rule_draft(session, rule_id, owner, 1, revised_draft())

    result = await diff_owned_rule_version(session, rule_id, owner, 2)
    assert result["previous_version_number"] == 1
    assert result["version_number"] == 2
    assert result["is_current"] is True
    assert result["fields_changed"] == ["title"]
    assert result["selectors_modified"] == ["selection"]
    assert result["has_changes"] is True
    assert result["validation_level"] == "structural_only"
    assert "sigma" not in result

    for requested_owner, version in (
        (uuid.uuid4(), 2), (owner, 1), (owner, 3)
    ):
        with pytest.raises(HTTPException) as error:
            await diff_owned_rule_version(session, rule_id, requested_owner, version)
        assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_diff_http_requires_auth_permission_and_valid_version(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), user.id)
    await revise_owned_rule_draft(
        session, uuid.UUID(created["id"]), user.id, 1, revised_draft()
    )

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    base = f"/api/v1/rules/{created['id']}/versions"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get(base + "/2/diff")).status_code == 401
        login = await client.post("/api/v1/auth/login", json={
            "email": "engineer@corp.com", "password": "correct-horse-battery-staple",
        })
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = await client.get(base + "/2/diff", headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["selectors_modified"] == ["selection"]
        assert (await client.get(base + "/1/diff", headers=headers)).status_code == 422
        assert (await client.get(base + "/3/diff", headers=headers)).status_code == 404
        user.role = Role(id=4, name="analyst")
        assert (await client.get(base + "/2/diff", headers=headers)).status_code == 403
