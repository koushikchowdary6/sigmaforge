"""Production repository implementation, backed by Postgres via SQLAlchemy."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import RefreshToken, User


class SqlAlchemyUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email(self, email: str) -> User | None:
        result = await self._session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        result = await self._session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def increment_failed_login(self, user_id: uuid.UUID) -> int:
        result = await self._session.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_count=User.failed_login_count + 1)
            .returning(User.failed_login_count)
        )
        await self._session.commit()
        return result.scalar_one()

    async def reset_failed_login(self, user_id: uuid.UUID, *, last_login_at: datetime) -> None:
        await self._session.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_count=0, locked_until=None, last_login_at=last_login_at)
        )
        await self._session.commit()

    async def set_locked_until(self, user_id: uuid.UUID, locked_until: datetime | None) -> None:
        await self._session.execute(update(User).where(User.id == user_id).values(locked_until=locked_until))
        await self._session.commit()

    async def reset_expired_lockout(self, user_id: uuid.UUID, *, now: datetime) -> None:
        # Compare and reset in one statement so an active lockout cannot be
        # cleared by a stale request. Do not update last_login_at on failure.
        await self._session.execute(
            update(User)
            .where(User.id == user_id, User.locked_until.is_not(None), User.locked_until <= now)
            .values(failed_login_count=0, locked_until=None)
        )
        await self._session.commit()


class SqlAlchemyRefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
        self._session.add(token)
        await self._session.commit()
        await self._session.refresh(token)
        return token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        result = await self._session.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        return result.scalar_one_or_none()

    async def consume_if_active(self, token_id: uuid.UUID, *, now: datetime) -> bool:
        # One conditional UPDATE is the concurrency boundary. Two requests
        # that read the same live token cannot both consume it: PostgreSQL
        # rechecks the predicate after acquiring the row lock.
        result = await self._session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.id == token_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .values(revoked_at=now)
            .returning(RefreshToken.id)
        )
        consumed = result.scalar_one_or_none() is not None
        await self._session.commit()
        return consumed

    async def revoke(self, token_id: uuid.UUID) -> None:
        from datetime import timezone

        await self._session.execute(
            update(RefreshToken).where(RefreshToken.id == token_id).values(revoked_at=datetime.now(timezone.utc))
        )
        await self._session.commit()

    async def revoke_all_for_user(self, user_id: uuid.UUID) -> None:
        from datetime import timezone

        await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc))
        )
        await self._session.commit()
