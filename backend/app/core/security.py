"""Password hashing and JWT issuance/verification.

Design decisions (see docs/THREAT_MODEL.md §4.1 for the threats these address):

- Argon2id for password hashing, not bcrypt: memory-hard, resists GPU/ASIC
  cracking better than bcrypt at equivalent settings, and is the OWASP
  Password Storage Cheat Sheet's current first recommendation.
- RS256 (asymmetric) for JWTs, not HS256: the API and worker only ever need
  the public key to verify a token; only the issuing auth module holds the
  private key. This means a service that only verifies tokens can never be
  used to forge one, even if that service is compromised.
- Access tokens are short-lived (15 min default) and carry no sensitive data
  beyond user id, role, and a token-family id used for refresh rotation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

from app.core.config import Settings

_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Returns False on any mismatch or malformed hash -- never raises to the caller.

    Callers must not use this to distinguish "wrong password" from "account
    doesn't exist" -- that distinction is exactly what enables account
    enumeration (THREAT_MODEL.md §4.1), so the auth service always returns a
    generic error regardless of which case occurred.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHash):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """True if the stored hash was made with outdated parameters and should
    be re-hashed on next successful login (a standard Argon2 hygiene practice)."""
    return _hasher.check_needs_rehash(hashed_password)


class TokenPayload:
    """Typed accessor for the claims we put in an access token."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self.sub: str = claims["sub"]
        self.role: str = claims["role"]
        self.jti: str = claims["jti"]
        self.exp: int = claims["exp"]
        self.iat: int = claims["iat"]
        self.iss: str = claims["iss"]


def create_access_token(*, user_id: str, role: str, settings: Settings) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user_id,
        "role": role,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_access_token_ttl_seconds)).timestamp()),
        "iss": settings.jwt_issuer,
        "type": "access",
    }
    return jwt.encode(claims, settings.jwt_private_key, algorithm="RS256")


def decode_access_token(token: str, *, settings: Settings) -> TokenPayload:
    """Raises jwt.InvalidTokenError (or a subclass) on any verification failure.

    Callers must catch this broadly and return a generic 401 -- the specific
    failure reason (expired vs. malformed vs. bad signature) is never surfaced
    to the client, only to server-side logs, per THREAT_MODEL.md §5.4.
    """
    claims = jwt.decode(
        token,
        settings.jwt_public_key,
        algorithms=["RS256"],
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "role", "jti"]},
    )
    if claims.get("type") != "access":
        raise jwt.InvalidTokenError("not an access token")
    return TokenPayload(claims)


def generate_refresh_token() -> tuple[str, str]:
    """Returns (raw_token, token_hash). The raw token is returned to the
    client and never stored; only its SHA-256 hash is persisted
    (DATABASE_SCHEMA.md §2.4), so a database read alone can never yield a
    usable refresh token."""
    import hashlib
    import secrets

    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, token_hash


def hash_refresh_token(raw_token: str) -> str:
    import hashlib

    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
