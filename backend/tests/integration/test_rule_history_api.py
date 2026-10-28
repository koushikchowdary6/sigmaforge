"""HTTP and offline regression tests for owner-scoped Sigma draft history."""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.core.database import get_db
from app.detection.service import (
    create_rule_draft,
    get_owned_rule_version,
    list_owned_rule_versions,
    revise_owned_rule_draft,
)
from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRule, DetectionRuleVersion
from app.models.rbac import Role
from tests.integration.test_auth_api import app_and_repo  # noqa: F401
from tests.integration.test_rule_create_api import DRAFT
from tests.integration.test_rule_revision_api import RevisionSession, revised_draft


class HistorySession(RevisionSession):
    async def execute(self, statement):
        self.history_statement = str(statement)
        versions = sorted(
            (obj for obj in self.objects if isinstance(obj, DetectionRuleVersion)),
            key=lambda obj: obj.version_number,
            reverse=True,
        )
        offset = statement._offset_clause.value
        limit = statement._limit_clause.value
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: versions[offset:offset + limit])
        )

    async def scalar(self, statement):
        if "detection_rule_versions" in str(statement):
            params = statement.compile().params
            number = next(value for value in params.values() if isinstance(value, int))
            return next(
                (obj for obj in self.objects
                 if isinstance(obj, DetectionRuleVersion) and obj.version_number == number),
                None,
            )
        return await super().scalar(statement)


@pytest.mark.asyncio
async def test_history_is_newest_first_bounded_and_excludes_bodies():
    owner = uuid.uuid4()
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    await revise_owned_rule_draft(
        session, uuid.UUID(created["id"]), owner, 1, revised_draft()
    )
    history = await list_owned_rule_versions(
        session, uuid.UUID(created["id"]), owner, limit=1, offset=0
    )
    assert [item["version_number"] for item in history["items"]] == [2]
    assert history["items"][0]["is_current"] is True
    assert history["has_more"] is True
    assert "sigma" not in history["items"][0]
    assert "ORDER BY detection_rule_versions.version_number DESC" in session.history_statement
    assert "detection_rule_versions.rule_id" in session.history_statement

    next_page = await list_owned_rule_versions(
        session, uuid.UUID(created["id"]), owner, limit=1, offset=1
    )
    assert [item["version_number"] for item in next_page["items"]] == [1]
    assert next_page["items"][0]["is_current"] is False
    assert next_page["has_more"] is False

    original = await get_owned_rule_version(
        session, uuid.UUID(created["id"]), owner, 1
    )
    assert original["sigma"] == DRAFT
    assert original["is_current"] is False
    assert original["version_id"] == created["version_id"]
    with pytest.raises(HTTPException) as missing:
        await get_owned_rule_version(session, uuid.UUID(created["id"]), owner, 3)
    assert missing.value.status_code == 404

    for operation in (
        list_owned_rule_versions(session, uuid.UUID(created["id"]), uuid.uuid4(), 10, 0),
        get_owned_rule_version(session, uuid.UUID(created["id"]), uuid.uuid4(), 1),
    ):
        with pytest.raises(HTTPException) as forbidden:
            await operation
        assert forbidden.value.status_code == 404


@pytest.mark.asyncio
async def test_history_http_requires_auth_permission_and_valid_bounds(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    session = HistorySession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), user.id)
    await revise_owned_rule_draft(
        session, uuid.UUID(created["id"]), user.id, 1, revised_draft()
    )

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    url = f"/api/v1/rules/{created['id']}/versions"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get(url)).status_code == 401
        login = await client.post("/api/v1/auth/login", json={
            "email": "engineer@corp.com", "password": "correct-horse-battery-staple",
        })
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        listing = await client.get(url + "?limit=1", headers=headers)
        assert listing.status_code == 200, listing.text
        assert listing.json()["items"][0]["version_number"] == 2
        assert listing.json()["has_more"] is True
        old = await client.get(url + "/1", headers=headers)
        assert old.status_code == 200, old.text
        assert old.json()["sigma"] == DRAFT
        assert old.json()["is_current"] is False
        assert (await client.get(url + "/3", headers=headers)).status_code == 404
        assert (await client.get(url + "/0", headers=headers)).status_code == 422
        for query in ("limit=0", "limit=101", "offset=-1", "offset=10001"):
            assert (await client.get(url + "?" + query, headers=headers)).status_code == 422
        user.role = Role(id=4, name="analyst")
        assert (await client.get(url, headers=headers)).status_code == 403
        assert (await client.get(url + "/1", headers=headers)).status_code == 403
