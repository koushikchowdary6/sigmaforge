"""Pydantic request/response schemas for the auth endpoints
(API_SPECIFICATION.md §2). Response schemas never include a password field,
by construction -- there is no shared base schema with User's hashed_password
in it, so it structurally cannot leak."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MeResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool


class ProblemDetail(BaseModel):
    """RFC 7807 problem+json error shape (API_SPECIFICATION.md §1)."""

    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None
    trace_id: str | None = None
