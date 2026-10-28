"""HTTP and offline regression coverage for versioned Sigma draft editing."""
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import get_db
from app.detection.service import create_rule_draft, revise_owned_rule_draft
from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRule, DetectionRuleVersion
from app.models.rbac import Role
from tests.integration.test_auth_api import app_and_repo  # noqa: F401
from tests.integration.test_rule_create_api import DRAFT
from tests.unit.test_rule_persistence import RecordingSession


class RevisionSession(RecordingSession):
    def __init__(self, fail_on_flush=None):
        super().__init__(fail_on_flush=fail_on_flush)
        self.lock_statement = None

    async def scalar(self, statement):
        self.lock_statement = str(statement)
        return next((obj for obj in self.objects if isinstance(obj, DetectionRule)), None)

    async def get(self, model, object_id):
        return next(
            (obj for obj in self.objects if isinstance(obj, model) and obj.id == object_id),
            None,
        )


def revised_draft():
    return RulePreflightRequest(
        **{**DRAFT, "title": "Failed logins - revised",
           "detection": {"selection": {"EventID": 4624}, "condition": "selection"}}
    )


@pytest.mark.asyncio
async def test_revision_appends_immutable_version_and_updates_current_pointer():
    owner = uuid.uuid4()
    session = RevisionSession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    original = session.objects[1]
    result = await revise_owned_rule_draft(
        session, uuid.UUID(created["id"]), owner, 1, revised_draft()
    )
    rule, _, current = session.objects
    assert rule.current_version_id == current.id
    assert rule.title == "Failed logins - revised"
    assert original.version_number == 1
    assert original.sigma_yaml != current.sigma_yaml
    assert current.version_number == 2
    assert result["version_number"] == 2
    assert result["version_id"] == str(current.id)
    assert session.commits == 2
    assert "FOR UPDATE" in session.lock_statement


@pytest.mark.asyncio
async def test_stale_unchanged_foreign_and_nondraft_revisions_do_not_write():
    owner = uuid.uuid4()
    session = RevisionSession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    rule_id = uuid.UUID(created["id"])
    from fastapi import HTTPException

    for attempted_owner, version, draft, expected_status in (
        (uuid.uuid4(), 1, revised_draft(), 404),
        (owner, 2, revised_draft(), 409),
        (owner, 1, RulePreflightRequest(**DRAFT), 409),
    ):
        with pytest.raises(HTTPException) as exc:
            await revise_owned_rule_draft(session, rule_id, attempted_owner, version, draft)
        assert exc.value.status_code == expected_status
    session.objects[0].status = "approved"
    with pytest.raises(HTTPException) as exc:
        await revise_owned_rule_draft(session, rule_id, owner, 1, revised_draft())
    assert exc.value.status_code == 409
    assert session.commits == 1 and len(session.objects) == 2


@pytest.mark.asyncio
async def test_failed_revision_flush_rolls_back_without_advancing_version():
    owner = uuid.uuid4()
    session = RevisionSession(fail_on_flush=3)
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), owner)
    with pytest.raises(RuntimeError, match="simulated database failure"):
        await revise_owned_rule_draft(
            session, uuid.UUID(created["id"]), owner, 1, revised_draft()
        )
    assert session.commits == 1
    assert session.rollbacks == 1
    assert session.objects[0].current_version_id == uuid.UUID(created["version_id"])


@pytest.mark.asyncio
async def test_revision_http_auth_rbac_validation_and_conflict(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    session = RevisionSession()
    created = await create_rule_draft(session, RulePreflightRequest(**DRAFT), user.id)

    async def fake_db():
        yield session

    app.dependency_overrides[get_db] = fake_db
    url = f"/api/v1/rules/{created['id']}"
    body = {"expected_version": 1, "draft": revised_draft().model_dump()}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.patch(url, json=body)).status_code == 401
        login = await client.post("/api/v1/auth/login", json={
            "email": "engineer@corp.com", "password": "correct-horse-battery-staple",
        })
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        assert (await client.patch(url, headers=headers, json={
            **body, "unexpected": "secret"
        })).status_code == 422
        assert (await client.patch(url, headers=headers, json={
            **body, "expected_version": 0
        })).status_code == 422
        assert (await client.patch(url, headers=headers, json=body)).status_code == 200
        assert (await client.patch(url, headers=headers, json=body)).status_code == 409
        user.role = Role(id=4, name="analyst")
        assert (await client.patch(url, headers=headers, json=body)).status_code == 403
