"""Async SQLAlchemy engine/session management.

One process-wide async engine, one session-per-request via a FastAPI
dependency (get_db). Sessions are never shared across requests or held open
longer than a request's lifetime -- this is what makes the API layer safely
horizontally scalable (ARCHITECTURE.md §10): no connection/session state is
pinned to a worker process beyond a single request.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class DatabaseSessionManager:
    def __init__(self) -> None:
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

    def init(self, database_url: str) -> None:
        self._engine = create_async_engine(database_url, pool_pre_ping=True)
        self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()

    async def check_connection(self) -> bool:
        """Used by /readyz. Returns False rather than raising, so a DB outage
        degrades the readiness probe instead of crashing the request."""
        if self._engine is None:
            return False
        try:
            from sqlalchemy import text

            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def session(self) -> AsyncSession:
        if self._sessionmaker is None:
            raise RuntimeError("DatabaseSessionManager.init() was not called")
        return self._sessionmaker()


db_manager = DatabaseSessionManager()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with db_manager.session() as session:
        yield session
