"""Auth HTTP endpoints (API_SPECIFICATION.md §2).

Every handler catches the service-layer exceptions and maps them to a
generic response -- the specific failure reason never crosses the HTTP
boundary except as a structured, non-revealing detail string.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.service import (
    AccountLockedError,
    AuthService,
    InvalidCredentialsError,
    RefreshTokenInvalidError,
)
from app.core.dependencies import get_auth_service, get_current_user
from app.core.logging import get_logger
from app.models.user import User
from app.schemas.auth import LoginRequest, LogoutRequest, MeResponse, RefreshRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger(__name__)

_GENERIC_AUTH_ERROR = "Invalid email or password"


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest, request: Request, service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    client_ip = request.client.host if request.client else None
    try:
        pair = await service.login(
            email=body.email,
            password=body.password,
            device_info=request.headers.get("user-agent"),
            ip_address=client_ip,
        )
    except AccountLockedError:
        logger.warning("login blocked: account locked", extra={"extra_fields": {"email": body.email}})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_AUTH_ERROR) from None
    except InvalidCredentialsError:
        logger.info("login failed: invalid credentials", extra={"extra_fields": {"email": body.email}})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_AUTH_ERROR) from None

    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type=pair.token_type,
        expires_in=pair.expires_in,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest, request: Request, service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    client_ip = request.client.host if request.client else None
    try:
        pair = await service.refresh(
            raw_refresh_token=body.refresh_token,
            device_info=request.headers.get("user-agent"),
            ip_address=client_ip,
        )
    except RefreshTokenInvalidError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token") from None

    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type=pair.token_type,
        expires_in=pair.expires_in,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout(body: LogoutRequest, service: AuthService = Depends(get_auth_service)) -> None:
    await service.logout(raw_refresh_token=body.refresh_token)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout_all(
    current_user: User = Depends(get_current_user), service: AuthService = Depends(get_auth_service)
) -> None:
    await service.logout_all(user_id=current_user.id)


@router.get("/me", response_model=MeResponse)
async def me(current_user: User = Depends(get_current_user)) -> MeResponse:
    return MeResponse(
        id=str(current_user.id),
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role.name,
        is_active=current_user.is_active,
        mfa_enabled=current_user.mfa_enabled,
    )
