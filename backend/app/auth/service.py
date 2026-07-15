"""Auth business logic. Depends only on the repository Protocols
(app/auth/repository.py) -- see tests/unit/test_auth_service.py for the
in-memory-fake-backed tests this enables.

Controls implemented here, each tied to a THREAT_MODEL.md §4.1 entry:
- Generic "invalid credentials" error regardless of whether the account
  exists, whether the password was wrong, or whether the account is locked
  (prevents account enumeration).
- Account lockout after settings.max_failed_login_attempts, for
  settings.lockout_duration_seconds.
- Refresh-token rotation: presenting a refresh token consumes it and issues a
  new one. Presenting an already-revoked token is treated as detected reuse
  (a strong signal of token theft) and revokes every active refresh token for
  that user, forcing re-authentication everywhere.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.auth.repository import RefreshTokenRepository, UserRepository
from app.core.config import Settings
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    verify_password,
)
from app.models.user import User


class InvalidCredentialsError(Exception):
    """Raised for any authentication failure. The API layer must map this to
    a single generic 401 response -- never branch on the specific reason."""


class AccountLockedError(InvalidCredentialsError):
    """Subclasses InvalidCredentialsError deliberately: the HTTP layer treats
    it identically (generic message), so this exists only for server-side
    logging/metrics, never to change what the client sees."""


class RefreshTokenInvalidError(Exception):
    pass


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 0


class AuthService:
    def __init__(
        self,
        *,
        user_repo: UserRepository,
        refresh_repo: RefreshTokenRepository,
        settings: Settings,
    ) -> None:
        self._users = user_repo
        self._refresh_tokens = refresh_repo
        self._settings = settings

    async def login(
        self, *, email: str, password: str, device_info: str | None = None, ip_address: str | None = None
    ) -> TokenPair:
        user = await self._users.get_by_email(email)

        # Constant-shape control flow: we still "check" a password-like value
        # even when the user doesn't exist, so response timing doesn't leak
        # account existence. verify_password against a fixed dummy hash costs
        # roughly the same as a real check.
        if user is None:
            verify_password(password, _DUMMY_HASH)
            raise InvalidCredentialsError("invalid credentials")

        if user.locked_until is not None and user.locked_until > datetime.now(timezone.utc):
            raise AccountLockedError("account locked")

        if not user.is_active:
            raise InvalidCredentialsError("invalid credentials")

        if not verify_password(password, user.hashed_password):
            new_failed_count = await self._users.increment_failed_login(user.id)
            if new_failed_count >= self._settings.max_failed_login_attempts:
                locked_until = datetime.now(timezone.utc) + timedelta(
                    seconds=self._settings.lockout_duration_seconds
                )
                await self._users.set_locked_until(user.id, locked_until)
            raise InvalidCredentialsError("invalid credentials")

        await self._users.reset_failed_login(user.id, last_login_at=datetime.now(timezone.utc))
        return await self._issue_token_pair(user, device_info=device_info, ip_address=ip_address)

    async def refresh(
        self, *, raw_refresh_token: str, device_info: str | None = None, ip_address: str | None = None
    ) -> TokenPair:
        token_hash = hash_refresh_token(raw_refresh_token)
        existing = await self._refresh_tokens.get_by_hash(token_hash)

        if existing is None:
            raise RefreshTokenInvalidError("unknown refresh token")

        if existing.revoked_at is not None:
            # Reuse of an already-rotated/revoked token: treat as compromise,
            # burn every active token for this user.
            await self._refresh_tokens.revoke_all_for_user(existing.user_id)
            raise RefreshTokenInvalidError("refresh token reuse detected; all sessions revoked")

        if existing.expires_at < datetime.now(timezone.utc):
            raise RefreshTokenInvalidError("refresh token expired")

        user = await self._users.get_by_id(existing.user_id)
        if user is None or not user.is_active:
            raise RefreshTokenInvalidError("account no longer active")

        await self._refresh_tokens.revoke(existing.id)
        return await self._issue_token_pair(user, device_info=device_info, ip_address=ip_address)

    async def logout(self, *, raw_refresh_token: str) -> None:
        token_hash = hash_refresh_token(raw_refresh_token)
        existing = await self._refresh_tokens.get_by_hash(token_hash)
        if existing is not None and existing.revoked_at is None:
            await self._refresh_tokens.revoke(existing.id)

    async def logout_all(self, *, user_id: uuid.UUID) -> None:
        await self._refresh_tokens.revoke_all_for_user(user_id)

    async def _issue_token_pair(
        self, user: User, *, device_info: str | None, ip_address: str | None
    ) -> TokenPair:
        access_token = create_access_token(user_id=str(user.id), role=user.role.name, settings=self._settings)
        raw_refresh, refresh_hash = generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._settings.jwt_refresh_token_ttl_seconds)
        await self._refresh_tokens.create(
            user_id=user.id,
            token_hash=refresh_hash,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )
        return TokenPair(
            access_token=access_token,
            refresh_token=raw_refresh,
            expires_in=self._settings.jwt_access_token_ttl_seconds,
        )


# A genuine Argon2 hash, computed once at import time from a fixed dummy
# value -- used only to equalize timing for nonexistent-user login attempts
# (see login() above). A hardcoded fake-looking string would fail Argon2
# parsing instantly and defeat the timing-equalization purpose entirely; this
# must be real hash work.
from app.core.security import hash_password as _hash_password  # noqa: E402

_DUMMY_HASH = _hash_password("not-a-real-password-used-only-for-timing-equalization")
