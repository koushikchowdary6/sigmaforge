"""HTTP auth/RBAC and atomic-write contract for rule draft creation."""
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import get_db
from app.models.rbac import Role
from tests.integration.test_auth_api import app_and_repo  # noqa: F401
from tests.unit.test_rule_persistence import RecordingSession


DRAFT = {
    "title": "Failed logins",
    "logsource": {"product": "windows"},
    "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
}


@pytest.mark.asyncio
async def test_rule_create_requires_auth(app_and_repo):
    app, *_ = app_and_repo
    session = RecordingSession()

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/rules", json=DRAFT)
    assert response.status_code == 401
    assert not session.objects


@pytest.mark.asyncio
async def test_rule_create_persists_one_version_for_engineer(app_and_repo):
    app, *_ = app_and_repo
    session = RecordingSession()

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login = await client.post("/api/v1/auth/login", json={
            "email": "engineer@corp.com", "password": "correct-horse-battery-staple",
        })
        response = await client.post("/api/v1/rules", json=DRAFT, headers={
            "Authorization": f"Bearer {login.json()['access_token']}",
        })
    assert response.status_code == 201
    assert response.json()["version_number"] == 1
    assert response.json()["validation_level"] == "structural_only"
    assert session.commits == 1
    assert len(session.objects) == 2


@pytest.mark.asyncio
async def test_rule_create_denies_analyst_role(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    user.role = Role(id=4, name="analyst")
    session = RecordingSession()

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login = await client.post("/api/v1/auth/login", json={
            "email": "engineer@corp.com", "password": "correct-horse-battery-staple",
        })
        response = await client.post("/api/v1/rules", json=DRAFT, headers={
            "Authorization": f"Bearer {login.json()['access_token']}",
        })
    assert response.status_code == 403
    assert not session.objects
