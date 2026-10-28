"""PostgreSQL-backed contract for Sigma draft creation.

Runs only in the dedicated CI PostgreSQL job. The regular offline suite
continues using RecordingSession; this suite verifies actual FK constraints,
transaction commits, and version relationships after an HTTP request.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, insert, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.detection.service import create_rule_draft
from app.detection.validation import RulePreflightRequest
from app.models.detection import DetectionRule, DetectionRuleVersion
from app.models.rbac import Role
from app.models.user import User
from tests.integration.test_auth_api import app_and_repo  # noqa: F401

pytestmark = pytest.mark.skipif(
    not os.getenv("SIGMAFORGE_TEST_POSTGRES_URL"),
    reason="Requires a migrated disposable PostgreSQL test database",
)

DRAFT = {
    "title": "Failed logins",
    "logsource": {"product": "windows"},
    "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
}


@pytest.mark.asyncio
async def test_authenticated_create_persists_rule_and_version_in_postgres(app_and_repo):
    app, _users, _tokens, user = app_and_repo
    engine = create_async_engine(os.environ["SIGMAFORGE_TEST_POSTGRES_URL"])
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def real_db():
        async with sessions() as session:
            yield session

    app.dependency_overrides[get_db] = real_db
    try:
        # Auth uses the existing fake repository, but the owner also exists in
        # the real database so PostgreSQL must enforce the production FKs.
        async with sessions() as session:
            role_id = await session.scalar(
                select(Role.id).where(Role.name == "detection_engineer")
            )
            assert role_id is not None, "Alembic migration did not seed the role"
            await session.execute(
                insert(User).values(
                    id=user.id,
                    email=user.email,
                    hashed_password=user.hashed_password,
                    full_name=user.full_name,
                    role_id=role_id,
                )
            )
            await session.commit()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            login = await client.post(
                "/api/v1/auth/login",
                json={"email": "engineer@corp.com", "password": "correct-horse-battery-staple"},
            )
            assert login.status_code == 200
            response = await client.post(
                "/api/v1/rules",
                json=DRAFT,
                headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            )

        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["validation_level"] == "structural_only"
        assert payload["version_number"] == 1

        # Exercise the read API against a new real database session, not
        # merely the in-memory objects used during creation.
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            read = await client.get(
                f"/api/v1/rules/{payload['id']}",
                headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            )
            assert (await client.get(f"/api/v1/rules/{payload['id']}")).status_code == 401
        assert read.status_code == 200, read.text
        assert read.json()["sigma"] == DRAFT
        assert read.json()["version_id"] == payload["version_id"]

        # Real database owner filtering and stable pagination: another user's
        # draft must never appear, even when it sorts before ours.
        other_owner = uuid.uuid4()
        async with sessions() as session:
            await session.execute(
                insert(User).values(
                    id=other_owner,
                    email=f"other-{other_owner.hex}@corp.com",
                    hashed_password=user.hashed_password,
                    full_name="Other Engineer",
                    role_id=role_id,
                )
            )
            await session.commit()
            other_owner_draft = await create_rule_draft(
                session, RulePreflightRequest(**{**DRAFT, "title": "A hidden draft"}), other_owner
            )
            await create_rule_draft(
                session, RulePreflightRequest(**{**DRAFT, "title": "A first draft"}), user.id
            )

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            first = await client.get("/api/v1/rules?limit=1&offset=0", headers=headers)
            second = await client.get("/api/v1/rules?limit=1&offset=1", headers=headers)
            full = await client.get("/api/v1/rules?limit=100", headers=headers)
        assert first.status_code == second.status_code == full.status_code == 200
        assert [r["title"] for r in first.json()["items"]] == ["A first draft"]
        assert first.json()["has_more"] is True
        assert [r["title"] for r in second.json()["items"]] == ["Failed logins"]
        assert second.json()["has_more"] is False
        assert [r["title"] for r in full.json()["items"]] == ["A first draft", "Failed logins"]
        assert all("sigma" not in item for item in full.json()["items"])

        # A revision creates an immutable second version; stale writes cannot
        # overwrite the winner and other owners cannot edit the draft.
        updated_draft = {
            **DRAFT,
            "title": "Failed logins - reviewed draft",
            "detection": {"selection": {"EventID": 4624}, "condition": "selection"},
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            patch = await client.patch(
                f"/api/v1/rules/{payload['id']}",
                headers=headers,
                json={"expected_version": 1, "draft": updated_draft},
            )
            assert patch.status_code == 200, patch.text
            assert patch.json()["version_number"] == 2
            stale = await client.patch(
                f"/api/v1/rules/{payload['id']}",
                headers=headers,
                json={"expected_version": 1, "draft": DRAFT},
            )
            assert stale.status_code == 409
            foreign = await client.patch(
                f"/api/v1/rules/{other_owner_draft['id']}",
                headers=headers,
                json={"expected_version": 1, "draft": updated_draft},
            )
            assert foreign.status_code == 404
            revised_read = await client.get(f"/api/v1/rules/{payload['id']}", headers=headers)
        assert revised_read.status_code == 200
        assert revised_read.json()["version_number"] == 2
        assert revised_read.json()["sigma"] == updated_draft
        async with sessions() as session:
            original = await session.get(DetectionRuleVersion, uuid.UUID(payload["version_id"]))
            assert original is not None and json.loads(original.sigma_yaml) == DRAFT
            revised = await session.get(DetectionRuleVersion, uuid.UUID(patch.json()["version_id"]))
            assert revised is not None and json.loads(revised.sigma_yaml) == updated_draft

        # Read in an independent session to prove commit durability, not just
        # identity-map visibility in the request's session.
        async with sessions() as session:
            rule_id = uuid.UUID(payload["id"])
            version_id = uuid.UUID(payload["version_id"])
            rule = await session.get(DetectionRule, rule_id)
            version = await session.get(DetectionRuleVersion, version_id)
            assert rule is not None and version is not None
            assert rule.owner_id == user.id
            assert rule.current_version_id == uuid.UUID(patch.json()["version_id"])
            assert version.rule_id == rule.id
            assert version.created_by == user.id
            assert version.version_number == 1
            assert json.loads(version.sigma_yaml) == DRAFT
            status = await session.scalar(
                text("SELECT status::text FROM detection_rules WHERE id = :rule_id"),
                {"rule_id": rule_id},
            )
            assert status == "draft"
    finally:
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()


@pytest.mark.asyncio
async def test_invalid_owner_rolls_back_real_postgres_transaction():
    engine = create_async_engine(os.environ["SIGMAFORGE_TEST_POSTGRES_URL"])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session:
            before_rules = await session.scalar(select(func.count()).select_from(DetectionRule))
            before_versions = await session.scalar(
                select(func.count()).select_from(DetectionRuleVersion)
            )
            with pytest.raises(IntegrityError):
                await create_rule_draft(
                    session, RulePreflightRequest(**DRAFT), uuid.uuid4()
                )

        # A failed foreign-key insert must leave no partial draft or version.
        async with sessions() as session:
            assert await session.scalar(
                select(func.count()).select_from(DetectionRule)
            ) == before_rules
            assert await session.scalar(
                select(func.count()).select_from(DetectionRuleVersion)
            ) == before_versions
    finally:
        await engine.dispose()
