"""Regression tests for single-use refresh tokens under concurrent requests."""
from __future__ import annotations

import asyncio
from copy import copy
from datetime import datetime, timedelta, timezone
import uuid

import pytest

from app.auth.service import AuthService, RefreshTokenInvalidError, TokenPair
from app.core.security import hash_password
from app.models.rbac import Role
from app.models.user import User
from tests.fixtures.fake_repository import FakeRefreshTokenRepository, FakeUserRepository


class RacingRefreshRepository(FakeRefreshTokenRepository):
    """Give two refresh requests the same stale pre-consumption snapshot."""

    def __init__(self):
        super().__init__()
        self.reads = 0
        self.ready = asyncio.Event()
        self.successful_consumptions = 0

    async def get_by_hash(self, token_hash):
        token = await super().get_by_hash(token_hash)
        self.reads += 1
        if self.reads <= 2:
            snapshot = copy(token)
            if self.reads == 2:
                self.ready.set()
            await self.ready.wait()
            return snapshot
        return token

    async def rotate_if_active(self, token_id, **kwargs):
        rotated = await super().rotate_if_active(token_id, **kwargs)
        if rotated:
            self.successful_consumptions += 1
        return rotated


def _make_service(settings, refresh_repo=None):
    users = FakeUserRepository()
    refresh = refresh_repo or FakeRefreshTokenRepository()
    user = User(
        id=uuid.uuid4(),
        email="engineer@corp.com",
        hashed_password=hash_password("correct-password"),
        full_name="Test Engineer",
        role_id=1,
        is_active=True,
        mfa_enabled=False,
        failed_login_count=0,
        locked_until=None,
    )
    user.role = Role(id=1, name="detection_engineer")
    users.add(user)
    return AuthService(user_repo=users, refresh_repo=refresh, settings=settings), refresh


@pytest.mark.asyncio
async def test_simultaneous_refreshes_cannot_both_rotate_one_token(settings):
    refresh = RacingRefreshRepository()
    service, _ = _make_service(settings, refresh)
    original = await service.login(email="engineer@corp.com", password="correct-password")

    results = await asyncio.gather(
        service.refresh(raw_refresh_token=original.refresh_token),
        service.refresh(raw_refresh_token=original.refresh_token),
        return_exceptions=True,
    )

    assert sum(isinstance(result, TokenPair) for result in results) == 1
    assert sum(isinstance(result, RefreshTokenInvalidError) for result in results) == 1
    assert refresh.reads == 2
    assert refresh.successful_consumptions == 1


@pytest.mark.asyncio
async def test_expired_token_is_not_consumed_or_rotated(settings):
    service, refresh = _make_service(settings)
    original = await service.login(email="engineer@corp.com", password="correct-password")
    token = next(iter(refresh.tokens.values()))
    token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    with pytest.raises(RefreshTokenInvalidError, match="expired"):
        await service.refresh(raw_refresh_token=original.refresh_token)

    assert token.revoked_at is None
    assert len(refresh.tokens) == 1


@pytest.mark.asyncio
async def test_atomic_consume_rejects_token_that_expired_after_snapshot(settings):
    service, refresh = _make_service(settings)
    original = await service.login(email="engineer@corp.com", password="correct-password")
    token = next(iter(refresh.tokens.values()))
    old_id = token.id

    class ExpiringRepository(FakeRefreshTokenRepository):
        async def get_by_hash(self, token_hash):
            snapshot = copy(await super().get_by_hash(token_hash))
            self.tokens[old_id].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            return snapshot

    expiring = ExpiringRepository()
    expiring.tokens = refresh.tokens
    service._refresh_tokens = expiring

    with pytest.raises(RefreshTokenInvalidError):
        await service.refresh(raw_refresh_token=original.refresh_token)
    assert len(expiring.tokens) == 1
