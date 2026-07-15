"""In-memory fakes implementing the auth Protocols (app/auth/repository.py).

These exist so unit tests exercise the *real* service logic (app/auth/service.py)
at full speed with no database, while still being honest: they implement the
exact same interface production code depends on, so a test passing here is
evidence about the service logic, not about a mock that happens to return
whatever the test wants.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from app.models.user import RefreshToken, User


class FakeUserRepository:
    def __init__(self) -> None:
        self.users: dict[uuid.UUID, User] = {}

    def add(self, user: User) -> None:
        self.users[user.id] = user

    async def get_by_email(self, email: str) -> User | None:
        for user in self.users.values():
            if user.email.lower() == email.lower():
                return user
        return None

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self.users.get(user_id)

    async def increment_failed_login(self, user_id: uuid.UUID) -> int:
        user = self.users[user_id]
        user.failed_login_count += 1
        return user.failed_login_count

    async def reset_failed_login(self, user_id: uuid.UUID, *, last_login_at: datetime) -> None:
        user = self.users[user_id]
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = last_login_at

    async def set_locked_until(self, user_id: uuid.UUID, locked_until: datetime | None) -> None:
        self.users[user_id].locked_until = locked_until


class FakeRefreshTokenRepository:
    def __init__(self) -> None:
        self.tokens: dict[uuid.UUID, RefreshToken] = {}

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        token_hash: str,
        expires_at: datetime,
        device_info: str | None,
        ip_address: str | None,
    ) -> RefreshToken:
        token = RefreshToken(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )
        self.tokens[token.id] = token
        return token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        for token in self.tokens.values():
            if token.token_hash == token_hash:
                return token
        return None

    async def revoke(self, token_id: uuid.UUID) -> None:
        from datetime import timezone

        self.tokens[token_id].revoked_at = datetime.now(timezone.utc)

    async def revoke_all_for_user(self, user_id: uuid.UUID) -> None:
        from datetime import timezone

        for token in self.tokens.values():
            if token.user_id == user_id and token.revoked_at is None:
                token.revoked_at = datetime.now(timezone.utc)
