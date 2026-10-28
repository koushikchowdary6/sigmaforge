"""HTTP coverage for owner-scoped reads of persisted Sigma drafts."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import get_db
from app.detection.service import create_rule_draft
from app.detection.validation import RulePreflightRequest
from app.models.rbac import Role
from tests.integration.test_auth_api import app_and_repo  # noqa: F401
from tests.integration.test_rule_create_api import DRAFT
from tests.unit.test_rule_persistence import RecordingSession


class ReadSession(RecordingSession):
    async def get(self, model, object_id):
        return next(
            (obj for obj in self.objects if isinstance(obj, model) and obj.id == object_id),
            None,
        )


async def _request(app, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path, headers=headers)


async def _login(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "engineer@corp.com", "password": "correct-horse-battery-staple"},
        )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_owner_reads_committed_current_version(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    session = ReadSession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), user.id)

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    token = await _login(app)
    response = await _request(app, f"/api/v1/rules/{created['id']}", token)
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["version_id"] == created["version_id"]
    assert body["version_number"] == 1
    assert body["sigma"] == DRAFT
    assert body["validation_level"] == "structural_only"
    assert session.commits == 1


@pytest.mark.asyncio
async def test_other_owners_rule_is_hidden_with_404(app_and_repo):
    app, _users, _tokens, _user = app_and_repo
    session = ReadSession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), uuid.uuid4())

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    token = await _login(app)
    response = await _request(app, f"/api/v1/rules/{created['id']}", token)
    assert response.status_code == 404
    assert response.json()["detail"] == "Rule not found"
    missing = await _request(app, f"/api/v1/rules/{uuid.uuid4()}", token)
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_read_requires_authentication_and_rule_permission(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    session = ReadSession()

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    path = f"/api/v1/rules/{uuid.uuid4()}"
    assert (await _request(app, path)).status_code == 401
    token = await _login(app)
    user.role = Role(id=4, name="analyst")
    assert (await _request(app, path, token)).status_code == 403
