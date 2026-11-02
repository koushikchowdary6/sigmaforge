"""Regression: outer ServerErrorMiddleware must not bypass API cache policy."""
from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

from tests.fixtures.test_keys import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY

# The application factory validates its required settings at import time.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_PRIVATE_KEY", TEST_PRIVATE_KEY)
os.environ.setdefault("JWT_PUBLIC_KEY", TEST_PUBLIC_KEY)

from app.main import create_app  # noqa: E402


@pytest.mark.asyncio
async def test_unhandled_500_preserves_security_headers_and_generic_body():
    app = create_app()

    @app.get("/__test_unhandled")
    async def fail():
        raise RuntimeError("INTERNAL_SECRET_MUST_NOT_LEAK")

    # A real ASGI exception passes through Starlette's outer error middleware,
    # which generates the response after the inner security middleware unwinds.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        failure = await client.get("/__test_unhandled")
        success = await client.get("/healthz")

    assert failure.status_code == 500
    assert failure.headers["cache-control"] == "no-store"
    assert failure.headers["x-content-type-options"] == "nosniff"
    assert failure.headers["x-frame-options"] == "DENY"
    assert failure.headers["referrer-policy"] == "no-referrer"
    assert failure.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"
    assert failure.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert failure.json()["title"] == "Internal Server Error"
    assert "INTERNAL_SECRET_MUST_NOT_LEAK" not in failure.text

    # Ordinary responses still receive the same centralized header policy.
    assert success.status_code == 200
    assert success.headers["cache-control"] == "no-store"
