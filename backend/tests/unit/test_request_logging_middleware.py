"""Request logging must correlate successful and exceptional requests."""
from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_ctx
from app.core.middleware import RequestLoggingMiddleware


def _request(path: str = "/healthz") -> Request:
    return Request({
        "type": "http", "method": "GET", "path": path,
        "raw_path": path.encode("utf-8"), "query_string": b"secret=NEVER_LOG_THIS",
        "headers": [], "scheme": "http", "server": ("testserver", 80),
    })


def _middleware() -> RequestLoggingMiddleware:
    async def unused_app(scope, receive, send):
        raise AssertionError("ASGI app should not be invoked")

    return RequestLoggingMiddleware(unused_app)


@pytest.mark.asyncio
async def test_successful_request_logs_id_and_resets_context(caplog):
    seen = []

    async def respond(request):
        request.scope["route"] = SimpleNamespace(path="/users/{user_id}")
        seen.append(request_id_ctx.get())
        return Response("ok", status_code=201)

    with caplog.at_level(logging.INFO, logger="app.request"):
        response = await _middleware().dispatch(_request(), respond)
    record = next(r for r in caplog.records if r.message == "request handled")
    assert seen == [response.headers["x-request-id"]]
    assert str(uuid.UUID(seen[0])) == seen[0]
    assert record.extra_fields["request_id"] == seen[0]
    assert record.extra_fields["status_code"] == 201
    assert record.extra_fields["path"] == "/users/{user_id}"
    assert request_id_ctx.get() is None
    assert "NEVER_LOG_THIS" not in caplog.text


@pytest.mark.asyncio
async def test_exception_is_logged_without_sensitive_data_and_context_is_reset(caplog):
    seen = []

    async def fail(request):
        request.scope["route"] = SimpleNamespace(path="/healthz")
        seen.append(request_id_ctx.get())
        raise RuntimeError("SENSITIVE_EXCEPTION_DETAILS")

    with caplog.at_level(logging.ERROR, logger="app.request"):
        with pytest.raises(RuntimeError, match="SENSITIVE_EXCEPTION_DETAILS"):
            await _middleware().dispatch(_request(), fail)
    record = next(r for r in caplog.records if r.message == "request raised an exception")
    assert record.extra_fields["request_id"] == seen[0]
    assert record.extra_fields["outcome"] == "exception"
    assert record.extra_fields["path"] == "/healthz"
    assert "status_code" not in record.extra_fields  # Outer middleware chooses final response.
    assert record.exc_info is None
    assert request_id_ctx.get() is None
    assert "SENSITIVE_EXCEPTION_DETAILS" not in caplog.text
    assert "NEVER_LOG_THIS" not in caplog.text


@pytest.mark.asyncio
async def test_unmatched_request_path_does_not_leak_secrets_or_control_chars(caplog):
    # Unknown routes can carry tokens and attacker-controlled text. They must
    # not be logged verbatim, even when no FastAPI route was resolved.
    async def respond(request):
        return Response("not found", status_code=404)

    with caplog.at_level(logging.INFO, logger="app.request"):
        response = await _middleware().dispatch(
            _request("/private/ACCESS_TOKEN_123%0Aforged"), respond
        )
    assert response.status_code == 404
    record = next(r for r in caplog.records if r.message == "request handled")
    assert record.extra_fields["path"] == "<unmatched>"
    assert "ACCESS_TOKEN_123" not in caplog.text
    assert "forged" not in caplog.text


@pytest.mark.asyncio
async def test_matched_dynamic_route_logs_template_not_sensitive_identifier(caplog):
    async def respond(request):
        request.scope["route"] = SimpleNamespace(path="/api/v1/users/{user_id}")
        return Response("ok")

    with caplog.at_level(logging.INFO, logger="app.request"):
        response = await _middleware().dispatch(
            _request("/api/v1/users/PRIVATE_ACCOUNT_ID_123"), respond
        )
    assert response.status_code == 200
    record = next(r for r in caplog.records if r.message == "request handled")
    assert record.extra_fields["path"] == "/api/v1/users/{user_id}"
    assert "PRIVATE_ACCOUNT_ID_123" not in caplog.text


@pytest.mark.asyncio
async def test_exception_before_route_resolution_uses_safe_sentinel(caplog):
    async def fail(request):
        raise RuntimeError("internal error")

    with caplog.at_level(logging.ERROR, logger="app.request"):
        with pytest.raises(RuntimeError, match="internal error"):
            await _middleware().dispatch(_request("/private/RESET_SECRET_123"), fail)
    record = next(r for r in caplog.records if r.message == "request raised an exception")
    assert record.extra_fields["path"] == "<unmatched>"
    assert "RESET_SECRET_123" not in caplog.text


def test_real_fastapi_router_exposes_template_without_logging_identifier(caplog):
    # A real ASGI request checks the routing/middleware integration, not
    # merely a mocked scope populated by a unit-test callback.
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/api/v1/users/{user_id}")
    def read_user(user_id: str):
        return {"ok": True}

    with caplog.at_level(logging.INFO, logger="app.request"):
        with TestClient(app) as client:
            response = client.get("/api/v1/users/SENSITIVE_USER_987")
    assert response.status_code == 200
    record = next(r for r in caplog.records if r.message == "request handled")
    assert record.extra_fields["path"] == "/api/v1/users/{user_id}"
    assert "SENSITIVE_USER_987" not in caplog.text
