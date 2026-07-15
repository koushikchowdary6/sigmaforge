"""API-level tests: real FastAPI app, real HTTP request/response cycle via
httpx's ASGI transport, but the auth service's repositories are swapped for
the in-memory fakes via FastAPI's dependency_overrides -- so this proves the
routing, request validation, status codes, and header handling all work
correctly, without needing a live Postgres in this environment.

app/main.py:create_app() wires get_auth_service/get_current_user to the real
SQLAlchemy repos; the equivalent wiring against a real Postgres is exercised
by CI's docker-compose-backed integration suite (REPO_STRUCTURE.md §4 stage 5).
"""
from __future__ import annotations

import os
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
os.environ["JWT_PRIVATE_KEY"] = _key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()
os.environ["JWT_PUBLIC_KEY"] = _key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

from app.auth.service import AuthService  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.database import db_manager  # noqa: E402
from app.core.dependencies import get_auth_service, get_user_repository  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.rbac import Role  # noqa: E402
from app.models.user import User  # noqa: E402
from tests.fixtures.fake_repository import FakeRefreshTokenRepository, FakeUserRepository  # noqa: E402

# SQLAlchemy's async engine connects lazily -- init() here does not attempt a
# real connection, it only makes get_db()'s context manager constructible so
# dependency resolution succeeds for routes we're not overriding (e.g. the
# validation-error test below never reaches a query).
db_manager.init(os.environ["DATABASE_URL"])


@pytest.fixture
def app_and_repo():
    app = create_app()
    settings = get_settings()
    user_repo = FakeUserRepository()
    refresh_repo = FakeRefreshTokenRepository()

    async def _override_auth_service() -> AuthService:
        return AuthService(user_repo=user_repo, refresh_repo=refresh_repo, settings=settings)

    app.dependency_overrides[get_auth_service] = _override_auth_service

    async def _override_user_repo():
        return user_repo

    app.dependency_overrides[get_user_repository] = _override_user_repo

    user = User(
        id=uuid.uuid4(),
        email="engineer@corp.com",
        hashed_password=hash_password("correct-horse-battery-staple"),
        full_name="Test Engineer",
        role_id=1,
        is_active=True,
        mfa_enabled=False,
        failed_login_count=0,
        locked_until=None,
    )
    user.role = Role(id=1, name="detection_engineer")
    user_repo.add(user)

    return app, user_repo, refresh_repo, user


@pytest.mark.asyncio
async def test_healthz_returns_ok():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readyz_reports_not_ready_without_db():
    """No real DB in this environment -- proves the readiness probe degrades
    to 503 instead of crashing, exactly as designed (ARCHITECTURE.md §11)."""
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["checks"]["database"] is False


@pytest.mark.asyncio
async def test_login_success_returns_token_pair(app_and_repo):
    app, *_ = app_and_repo
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "engineer@corp.com", "password": "correct-horse-battery-staple"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body and "refresh_token" in body
    assert body["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password_returns_generic_401(app_and_repo):
    app, *_ = app_and_repo
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login", json={"email": "engineer@corp.com", "password": "wrong"}
        )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_me_requires_bearer_token(app_and_repo):
    app, *_ = app_and_repo
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_full_login_then_me_flow(app_and_repo):
    app, *_ = app_and_repo
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "engineer@corp.com", "password": "correct-horse-battery-staple"},
        )
        access_token = login_resp.json()["access_token"]

        me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})

    assert me_resp.status_code == 200
    body = me_resp.json()
    assert body["email"] == "engineer@corp.com"
    assert body["role"] == "detection_engineer"


@pytest.mark.asyncio
async def test_refresh_then_old_token_rejected(app_and_repo):
    app, *_ = app_and_repo
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "engineer@corp.com", "password": "correct-horse-battery-staple"},
        )
        old_refresh = login_resp.json()["refresh_token"]

        refresh_resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert refresh_resp.status_code == 200

        replay_resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert replay_resp.status_code == 401


@pytest.mark.asyncio
async def test_security_headers_present_on_every_response():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/healthz")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert "x-request-id" in resp.headers


@pytest.mark.asyncio
async def test_malformed_login_body_returns_rfc7807_shape():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/auth/login", json={"email": "not-an-email"})
    assert resp.status_code == 422
    body = resp.json()
    assert body["type"] == "https://sigmaforge.dev/errors/validation-error"
    assert body["status"] == 422
