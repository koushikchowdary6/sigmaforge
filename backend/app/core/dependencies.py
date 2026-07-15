"""FastAPI dependency-injection wiring.

get_auth_service constructs a real AuthService backed by the SQLAlchemy
repositories for every request -- the same AuthService class the unit tests
exercise against the in-memory fakes (tests/unit/test_auth_service.py), so
production and test code paths share the exact same business logic.

get_current_user + require_permission implement the RBAC enforcement
described in API_SPECIFICATION.md §14 -- declarative permission checks, never
role-name string comparisons scattered through route handlers.
"""
from __future__ import annotations

from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.repository_sqlalchemy import SqlAlchemyRefreshTokenRepository, SqlAlchemyUserRepository
from app.auth.service import AuthService
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User

_bearer_scheme = HTTPBearer(auto_error=False)

# Declarative role -> permission map (API_SPECIFICATION.md §14 authorization
# matrix). This is the single source of truth require_permission() consults;
# nothing else in the codebase is allowed to branch on role name directly.
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    "detection_lead": {
        "rule:create", "rule:submit_review", "rule:approve", "rule:deploy",
        "fp:report", "ai:generate_rule", "ai:summarize_alert", "coverage:view",
    },
    "detection_engineer": {
        "rule:create", "rule:submit_review", "fp:report", "ai:generate_rule", "coverage:view",
    },
    "analyst": {"fp:report", "ai:summarize_alert", "coverage:view"},
    "researcher": {
        "research:manage_corpus", "research:run_experiments", "ai:generate_rule",
        "research:view_reports", "coverage:view",
    },
}


def _generic_unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_user_repository(db: AsyncSession = Depends(get_db)):
    """Separate, overridable provider -- lets tests substitute the
    in-memory fake for get_current_user the same way get_auth_service is
    overridden for the auth flows, instead of get_current_user constructing
    a SqlAlchemyUserRepository directly and being untestable without a real DB."""
    return SqlAlchemyUserRepository(db)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
    user_repo=Depends(get_user_repository),
) -> User:
    if credentials is None:
        raise _generic_unauthorized() from None
    try:
        claims = decode_access_token(credentials.credentials, settings=settings)
    except jwt.InvalidTokenError:
        raise _generic_unauthorized() from None

    import uuid

    user = await user_repo.get_by_id(uuid.UUID(claims.sub))
    if user is None or not user.is_active:
        raise _generic_unauthorized() from None
    return user


def require_permission(permission_code: str) -> Callable:
    async def _checker(user: User = Depends(get_current_user)) -> User:
        role_name = user.role.name
        granted = ROLE_PERMISSIONS.get(role_name, set())
        if "*" not in granted and permission_code not in granted:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return _checker


async def get_auth_service(
    db: AsyncSession = Depends(get_db), settings: Settings = Depends(get_settings)
) -> AuthService:
    return AuthService(
        user_repo=SqlAlchemyUserRepository(db),
        refresh_repo=SqlAlchemyRefreshTokenRepository(db),
        settings=settings,
    )
