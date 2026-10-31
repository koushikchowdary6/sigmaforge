"""Request logging must correlate successful and exceptional requests."""
from __future__ import annotations

import logging
import uuid

import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_ctx
from app.core.middleware import RequestLoggingMiddleware


def _request() -> Request:
    return Request({
        "type": "http", "method": "GET", "path": "/healthz",
        "raw_path": b"/healthz", "query_string": b"secret=NEVER_LOG_THIS",
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
        seen.append(request_id_ctx.get())
        return Response("ok", status_code=201)

    with caplog.at_level(logging.INFO, logger="app.request"):
        response = await _middleware().dispatch(_request(), respond)
    record = next(r for r in caplog.records if r.message == "request handled")
    assert seen == [response.headers["x-request-id"]]
    assert str(uuid.UUID(seen[0])) == seen[0]
    assert record.extra_fields["request_id"] == seen[0]
    assert record.extra_fields["status_code"] == 201
    assert request_id_ctx.get() is None
    assert "NEVER_LOG_THIS" not in caplog.text


@pytest.mark.asyncio
async def test_exception_is_logged_without_sensitive_data_and_context_is_reset(caplog):
    seen = []

    async def fail(request):
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
