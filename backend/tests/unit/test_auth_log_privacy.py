"""Failed authentication must not put user-supplied identifiers into log records."""
from __future__ import annotations

import logging

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.auth.router import login
from app.auth.service import AccountLockedError, InvalidCredentialsError
from app.schemas.auth import LoginRequest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "outcome", "message"),
    [
        (InvalidCredentialsError, "invalid_credentials", "login failed: invalid credentials"),
        (AccountLockedError, "locked", "login blocked: account locked"),
    ],
)
async def test_failed_login_logs_outcome_without_email_or_password(
    caplog, failure, outcome, message
):
    class RejectingService:
        async def login(self, **kwargs):
            assert kwargs["email"] == "sensitive.person@example.com"
            raise failure()

    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
    })
    body = LoginRequest(email="sensitive.person@example.com", password="private-password")
    with caplog.at_level(logging.INFO, logger="app.auth.router"):
        with pytest.raises(HTTPException) as exc:
            await login(body=body, request=request, service=RejectingService())

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid email or password"
    records = [record for record in caplog.records if record.name == "app.auth.router"]
    assert len(records) == 1
    assert records[0].getMessage() == message
    assert records[0].extra_fields == {"auth_outcome": outcome}
    assert "sensitive.person@example.com" not in repr(records[0].__dict__)
    assert "private-password" not in repr(records[0].__dict__)
