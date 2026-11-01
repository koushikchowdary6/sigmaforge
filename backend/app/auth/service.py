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

import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

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


def _bounded_device_info(value: str | None) -> str | None:
    """Keep untrusted User-Agent metadata within refresh_tokens VARCHAR(255).

    An oversized header must not turn an otherwise valid login or refresh
    into a PostgreSQL string-length error. Preserve the beginning of the
    user agent for troubleshooting without persisting arbitrary header size.
    """
    if value is None:
        return None
    # PostgreSQL text columns reject NUL bytes and UTF-16 surrogate code
    # points cannot be encoded as UTF-8. Header metadata is untrusted and
    # optional: remove unsafe controls before persisting, then bound length.
    cleaned = "".join(
        char for char in value
        if unicodedata.category(char) not in {"Cc", "Cs"}
    )[:255]
    return cleaned or None


def _validated_ip_address(value: str | None) -> str | None:
    """Store only real IPv4/IPv6 addresses in PostgreSQL's INET column.

    ASGI client metadata is normally an IP, but test clients, custom proxies,
    or unusual server adapters can supply hostnames, zone-qualified IPv6, or
    malformed values. Drop invalid optional telemetry rather than turning a
    successful login/refresh into a database error. Never trust forwarding
    headers as a replacement for the ASGI peer address.
    """
    if not isinstance(value, str) or not value or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


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

        now = datetime.now(timezone.utc)
        if user.locked_until is not None:
            if user.locked_until > now:
                # Do equivalent Argon2 work for locked and unknown accounts.
                # Skipping password verification here makes lockout status
                # distinguishable through response latency.
                verify_password(password, _DUMMY_HASH)
                raise AccountLockedError("account locked")
            # Expiration begins a fresh attempt window. Keeping the old count
            # would re-lock the account after a single wrong password.
            # This must not update last_login_at: no login has succeeded.
            await self._users.reset_expired_lockout(user.id, now=now)

        if not user.is_active:
            # Disabled accounts must not reveal their existence via a
            # faster response than an unknown or wrong-password account.
            verify_password(password, _DUMMY_HASH)
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

        now = datetime.now(timezone.utc)
        if existing.expires_at <= now:
            raise RefreshTokenInvalidError("refresh token expired")

        user = await self._users.get_by_id(existing.user_id)
        if user is None or not user.is_active:
            raise RefreshTokenInvalidError("account no longer active")

        # The old token and its replacement must commit together. The
        # repository serializes this transaction with user-wide revocation,
        # preventing a replay from revoking sessions just before a late
        # replacement is inserted.
        raw_refresh, refresh_hash = generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self._settings.jwt_refresh_token_ttl_seconds
        )
        rotated = await self._refresh_tokens.rotate_if_active(
            existing.id,
            user_id=existing.user_id,
            now=now,
            token_hash=refresh_hash,
            expires_at=expires_at,
            device_info=_bounded_device_info(device_info),
            ip_address=_validated_ip_address(ip_address),
        )
        if not rotated:
            # A competing request may have consumed or revoked this token.
            await self._refresh_tokens.revoke_all_for_user(existing.user_id)
            raise RefreshTokenInvalidError("refresh token reuse detected; all sessions revoked")
        return TokenPair(
            access_token=create_access_token(
                user_id=str(user.id), role=user.role.name, settings=self._settings
            ),
            refresh_token=raw_refresh,
            expires_in=self._settings.jwt_access_token_ttl_seconds,
        )

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
            device_info=_bounded_device_info(device_info),
            ip_address=_validated_ip_address(ip_address),
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
