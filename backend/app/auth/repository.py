"""Repository interfaces for the auth domain.

The auth service (service.py) depends only on these Protocols, never on
SQLAlchemy directly. This is what lets us unit-test real business logic
(lockout thresholds, refresh-token rotation, generic-error-on-bad-credentials)
against a fast in-memory fake with zero database involved, while production
runs against the real Postgres-backed implementation. Same pattern the
codebase spec asked for under "Repository Pattern where appropriate."
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from app.models.user import RefreshToken, User


class UserRepository(Protocol):
    async def get_by_email(self, email: str) -> User | None: ...
    async def get_by_id(self, user_id: uuid.UUID) -> User | None: ...
    async def increment_failed_login(self, user_id: uuid.UUID) -> int:
        """Returns the new failed_login_count after incrementing -- the
        caller must use this return value, not re-read the user object,
        since implementations are free to mutate or not mutate any
        in-memory object they were handed."""
        ...
    async def reset_failed_login(self, user_id: uuid.UUID, *, last_login_at: datetime) -> None: ...
    async def set_locked_until(self, user_id: uuid.UUID, locked_until: datetime | None) -> None: ...


class RefreshTokenRepository(Protocol):
    async def create(
        self,
        *,
        user_id: uuid.UUID,
        token_hash: str,
        expires_at: datetime,
        device_info: str | None,
        ip_address: str | None,
    ) -> RefreshToken: ...

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None: ...
    async def revoke(self, token_id: uuid.UUID) -> None: ...
    async def revoke_all_for_user(self, user_id: uuid.UUID) -> None: ...
