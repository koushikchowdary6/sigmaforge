"""Real unit tests for AuthService business logic, against the in-memory
fake repositories (tests/fixtures/fake_repository.py). No database involved --
these test the logic itself, fast and deterministically.
"""
from __future__ import annotations

import uuid

import pytest

from app.auth.service import (
    AccountLockedError,
    AuthService,
    InvalidCredentialsError,
    RefreshTokenInvalidError,
)
from app.core.security import decode_access_token, hash_password
from app.models.rbac import Role
from app.models.user import User
from tests.fixtures.fake_repository import FakeRefreshTokenRepository, FakeUserRepository


def make_user(email: str, password: str, role_name: str = "detection_engineer") -> User:
    role = Role(id=1, name=role_name)
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=hash_password(password),
        full_name="Test User",
        role_id=1,
        is_active=True,
        mfa_enabled=False,
        failed_login_count=0,
        locked_until=None,
    )
    user.role = role  # type: ignore[assignment]
    return user


@pytest.fixture
def service(settings):
    user_repo = FakeUserRepository()
    refresh_repo = FakeRefreshTokenRepository()
    return AuthService(user_repo=user_repo, refresh_repo=refresh_repo, settings=settings), user_repo, refresh_repo


class TestLogin:
    @pytest.mark.asyncio
    async def test_successful_login_returns_valid_token_pair(self, service, settings):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct horse battery staple")
        user_repo.add(user)

        pair = await svc.login(email="engineer@corp.com", password="correct horse battery staple")

        assert pair.access_token
        assert pair.refresh_token
        claims = decode_access_token(pair.access_token, settings=settings)
        assert claims.sub == str(user.id)
        assert claims.role == "detection_engineer"

    @pytest.mark.asyncio
    async def test_wrong_password_raises_generic_invalid_credentials(self, service):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)

        with pytest.raises(InvalidCredentialsError):
            await svc.login(email="engineer@corp.com", password="wrong-password")

    @pytest.mark.asyncio
    async def test_nonexistent_user_raises_same_generic_error_as_wrong_password(self, service):
        """Regression test for account-enumeration prevention (THREAT_MODEL.md §4.1):
        both cases must raise the exact same exception type."""
        svc, _, _ = service

        with pytest.raises(InvalidCredentialsError) as exc_info:
            await svc.login(email="nobody@corp.com", password="anything")

        assert exc_info.type is InvalidCredentialsError

    @pytest.mark.asyncio
    async def test_account_locks_after_max_failed_attempts(self, service, settings):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)

        # settings fixture sets max_failed_login_attempts=3
        for _ in range(settings.max_failed_login_attempts):
            with pytest.raises(InvalidCredentialsError):
                await svc.login(email="engineer@corp.com", password="wrong")

        # Next attempt, even with the correct password, must be locked out.
        with pytest.raises(AccountLockedError):
            await svc.login(email="engineer@corp.com", password="correct-password")

    @pytest.mark.asyncio
    async def test_successful_login_resets_failed_count(self, service):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)

        for _ in range(2):
            with pytest.raises(InvalidCredentialsError):
                await svc.login(email="engineer@corp.com", password="wrong")
        assert user.failed_login_count == 2

        await svc.login(email="engineer@corp.com", password="correct-password")
        assert user.failed_login_count == 0

    @pytest.mark.asyncio
    async def test_inactive_account_cannot_login(self, service):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user.is_active = False
        user_repo.add(user)

        with pytest.raises(InvalidCredentialsError):
            await svc.login(email="engineer@corp.com", password="correct-password")


class TestRefreshRotation:
    @pytest.mark.asyncio
    async def test_refresh_rotates_token_and_invalidates_old_one(self, service):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)
        pair1 = await svc.login(email="engineer@corp.com", password="correct-password")

        pair2 = await svc.refresh(raw_refresh_token=pair1.refresh_token)
        assert pair2.refresh_token != pair1.refresh_token

        # The old refresh token must now be rejected.
        with pytest.raises(RefreshTokenInvalidError):
            await svc.refresh(raw_refresh_token=pair1.refresh_token)

    @pytest.mark.asyncio
    async def test_reused_revoked_token_burns_all_sessions(self, service):
        """This is the token-theft-detection control: presenting an
        already-rotated token revokes every active session for that user,
        not just the one being reused."""
        svc, user_repo, refresh_repo = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)

        pair1 = await svc.login(email="engineer@corp.com", password="correct-password")
        pair2 = await svc.refresh(raw_refresh_token=pair1.refresh_token)  # rotates pair1 away

        # Attacker replays the now-revoked pair1 refresh token.
        with pytest.raises(RefreshTokenInvalidError, match="reuse detected"):
            await svc.refresh(raw_refresh_token=pair1.refresh_token)

        # The legitimate pair2 refresh token must also now be dead.
        with pytest.raises(RefreshTokenInvalidError):
            await svc.refresh(raw_refresh_token=pair2.refresh_token)

    @pytest.mark.asyncio
    async def test_unknown_refresh_token_rejected(self, service):
        svc, _, _ = service
        with pytest.raises(RefreshTokenInvalidError):
            await svc.refresh(raw_refresh_token="not-a-real-token")


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_revokes_the_presented_token(self, service):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)
        pair = await svc.login(email="engineer@corp.com", password="correct-password")

        await svc.logout(raw_refresh_token=pair.refresh_token)

        with pytest.raises(RefreshTokenInvalidError):
            await svc.refresh(raw_refresh_token=pair.refresh_token)

    @pytest.mark.asyncio
    async def test_logout_all_revokes_every_session(self, service):
        svc, user_repo, _ = service
        user = make_user("engineer@corp.com", "correct-password")
        user_repo.add(user)
        pair_a = await svc.login(email="engineer@corp.com", password="correct-password")
        pair_b = await svc.login(email="engineer@corp.com", password="correct-password")

        await svc.logout_all(user_id=user.id)

        with pytest.raises(RefreshTokenInvalidError):
            await svc.refresh(raw_refresh_token=pair_a.refresh_token)
        with pytest.raises(RefreshTokenInvalidError):
            await svc.refresh(raw_refresh_token=pair_b.refresh_token)
