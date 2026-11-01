"""Optional peer metadata must not break successful authentication.

PostgreSQL's INET column accepts IP literals, not arbitrary ASGI host strings.
These unit tests exercise the real AuthService with its in-memory repositories;
the integration suite separately exercises PostgreSQL persistence.
"""
from __future__ import annotations

import uuid

import pytest

from app.auth.service import AuthService, _bounded_device_info, _validated_ip_address
from app.core.security import hash_password
from app.models.rbac import Role
from app.models.user import User
from tests.fixtures.fake_repository import FakeRefreshTokenRepository, FakeUserRepository


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.0.2.8", "192.0.2.8"),
        ("2001:0db8::1", "2001:db8::1"),
        ("testclient", None),
        ("198.51.100.999", None),
        ("fe80::1%eth0", None),
        ("192.0.2.8, 203.0.113.9", None),
        ("", None),
        (None, None),
    ],
)
def test_only_valid_peer_addresses_are_persisted(raw, expected):
    assert _validated_ip_address(raw) == expected



@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("\x00\n\r", None),
        ("client\x00/1.0", "client/1.0"),
        ("agent\ud800\udfff/2", "agent/2"),
        ("client\n\t/3", "client/3"),
        ("browser/" + "x" * 300, "browser/" + "x" * 247),
        ("café/1.0", "café/1.0"),
    ],
)
def test_device_info_is_safe_for_postgres_text_and_bounded(raw, expected):
    assert _bounded_device_info(raw) == expected


@pytest.mark.asyncio
async def test_login_and_refresh_ignore_invalid_optional_peer_metadata(settings):
    users = FakeUserRepository()
    tokens = FakeRefreshTokenRepository()
    user = User(
        id=uuid.uuid4(),
        email="metadata@example.com",
        hashed_password=hash_password("correct-password"),
        full_name="Metadata Test",
        role_id=1,
        is_active=True,
        mfa_enabled=False,
        failed_login_count=0,
        locked_until=None,
    )
    user.role = Role(id=1, name="detection_engineer")
    users.add(user)
    service = AuthService(user_repo=users, refresh_repo=tokens, settings=settings)

    first = await service.login(
        email=user.email,
        password="correct-password",
        device_info="browser/\\x00" + "x" * 400,
        ip_address="untrusted-hostname",
    )
    original = next(token for token in tokens.tokens.values() if token.revoked_at is None)
    assert original.ip_address is None
    assert len(original.device_info) == 255
    assert "\\x00" not in original.device_info

    rotated = await service.refresh(
        raw_refresh_token=first.refresh_token,
        ip_address="2001:0db8::1",
        device_info="refreshed-\\ud800client\\n",
    )
    assert rotated.refresh_token != first.refresh_token
    active = [token for token in tokens.tokens.values() if token.revoked_at is None]
    assert len(active) == 1
    assert active[0].ip_address == "2001:db8::1"
    assert active[0].device_info == "refreshed-client"
