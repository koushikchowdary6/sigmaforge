"""Signed JWT claims and corrupted password hashes must fail closed."""

from datetime import datetime, timedelta, timezone
import uuid

import jwt
import pytest
from argon2.exceptions import VerificationError

from app.core import security


@pytest.mark.parametrize("override", [
    {"sub": "not-a-uuid"},
    {"sub": ["not", "a", "string"]},
    {"role": []},
    {"role": ""},
    {"jti": "not-a-uuid"},
    {"jti": None},
])
def test_signed_token_with_invalid_claims_is_rejected(settings, override):
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
        "iss": settings.jwt_issuer,
        "type": "access",
    }
    claims.update(override)
    token = jwt.encode(claims, settings.jwt_private_key, algorithm="RS256")

    with pytest.raises(jwt.InvalidTokenError):
        security.decode_access_token(token, settings=settings)


def test_corrupted_argon2_hash_fails_closed():
    assert security.verify_password("secret", "not-an-argon2-hash") is False


def test_argon2_backend_verification_error_fails_closed(monkeypatch):
    def fail_verify(*args, **kwargs):
        raise VerificationError("malformed stored hash")

    monkeypatch.setattr(type(security._hasher), "verify", fail_verify)
    assert security.verify_password("secret", "invalid-stored-hash") is False


def test_valid_signed_access_token_still_decodes(settings):
    user_id = str(uuid.uuid4())
    token = security.create_access_token(
        user_id=user_id, role="analyst", settings=settings
    )
    payload = security.decode_access_token(token, settings=settings)
    assert payload.sub == user_id
    assert payload.role == "analyst"
