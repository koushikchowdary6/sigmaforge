"""Real PostgreSQL regression tests for atomic, single-use refresh tokens.

The fake-repository unit tests exercise AuthService behavior. These tests use
independent async database sessions and PostgreSQL row locking to verify the
production repository's compare-and-consume guarantee.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.auth.repository_sqlalchemy import SqlAlchemyRefreshTokenRepository
from app.models.rbac import Role
from app.models.user import RefreshToken, User

pytestmark = pytest.mark.skipif(
    not os.getenv("SIGMAFORGE_TEST_POSTGRES_URL"),
    reason="Requires a migrated disposable PostgreSQL test database",
)


@pytest.mark.asyncio
async def test_two_sessions_cannot_consume_same_refresh_token():
    """Both transactions observe an active token; exactly one can rotate it."""
    engine = create_async_engine(os.environ["SIGMAFORGE_TEST_POSTGRES_URL"])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    user_id = uuid.uuid4()
    token_id = uuid.uuid4()
    token_hash = f"postgres-race-{token_id.hex}"
    try:
        async with sessions() as session:
            role_id = await session.scalar(
                select(Role.id).where(Role.name == "detection_engineer")
            )
            assert role_id is not None, "Alembic migration did not seed roles"
            session.add(
                User(
                    id=user_id,
                    email=f"refresh-race-{user_id.hex}@example.test",
                    hashed_password="not-used-for-repository-contract",
                    full_name="Refresh Race Test",
                    role_id=role_id,
                )
            )
            session.add(
                RefreshToken(
                    id=token_id,
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                )
            )
            await session.commit()

        # The barrier ensures each independent connection has already read the
        # unrevoked row before either conditional UPDATE is attempted.
        both_read = asyncio.Barrier(2)

        async def consume_from_independent_session() -> bool:
            async with sessions() as session:
                repo = SqlAlchemyRefreshTokenRepository(session)
                snapshot = await repo.get_by_hash(token_hash)
                assert snapshot is not None and snapshot.revoked_at is None
                await both_read.wait()
                return await repo.consume_if_active(
                    token_id, now=datetime.now(timezone.utc)
                )

        outcomes = await asyncio.wait_for(
            asyncio.gather(
                consume_from_independent_session(),
                consume_from_independent_session(),
            ),
            timeout=20,
        )
        assert sorted(outcomes) == [False, True]

        async with sessions() as session:
            persisted = await session.get(RefreshToken, token_id)
            assert persisted is not None and persisted.revoked_at is not None
            repo = SqlAlchemyRefreshTokenRepository(session)
            assert not await repo.consume_if_active(
                token_id, now=datetime.now(timezone.utc)
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_refresh_token_cannot_be_consumed_in_postgres():
    """The expiry predicate must be enforced by PostgreSQL, not a stale read."""
    engine = create_async_engine(os.environ["SIGMAFORGE_TEST_POSTGRES_URL"])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    user_id = uuid.uuid4()
    token_id = uuid.uuid4()
    try:
        async with sessions() as session:
            role_id = await session.scalar(
                select(Role.id).where(Role.name == "detection_engineer")
            )
            assert role_id is not None
            session.add(
                User(
                    id=user_id,
                    email=f"refresh-expired-{user_id.hex}@example.test",
                    hashed_password="not-used-for-repository-contract",
                    full_name="Expired Refresh Test",
                    role_id=role_id,
                )
            )
            session.add(
                RefreshToken(
                    id=token_id,
                    user_id=user_id,
                    token_hash=f"postgres-expired-{token_id.hex}",
                    expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
                )
            )
            await session.commit()

        async with sessions() as session:
            repo = SqlAlchemyRefreshTokenRepository(session)
            assert not await repo.consume_if_active(
                token_id, now=datetime.now(timezone.utc)
            )

        async with sessions() as session:
            persisted = await session.get(RefreshToken, token_id)
            assert persisted is not None and persisted.revoked_at is None
    finally:
        await engine.dispose()
