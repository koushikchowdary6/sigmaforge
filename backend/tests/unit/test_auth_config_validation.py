"""Invalid auth settings must fail startup rather than disable security controls."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("jwt_access_token_ttl_seconds", 0),
        ("jwt_access_token_ttl_seconds", -1),
        ("jwt_refresh_token_ttl_seconds", 0),
        ("jwt_refresh_token_ttl_seconds", -60),
        ("max_failed_login_attempts", 0),
        ("max_failed_login_attempts", -3),
        ("lockout_duration_seconds", 0),
        ("lockout_duration_seconds", -900),
        ("jwt_issuer", ""),
    ],
)
def test_invalid_security_configuration_fails_fast(settings, field, invalid):
    config = settings.model_dump()
    config[field] = invalid
    with pytest.raises(ValidationError):
        Settings(**config)


def test_minimal_positive_security_configuration_is_valid(settings):
    config = settings.model_dump()
    for field in (
        "jwt_access_token_ttl_seconds",
        "jwt_refresh_token_ttl_seconds",
        "max_failed_login_attempts",
        "lockout_duration_seconds",
    ):
        config[field] = 1
    validated = Settings(**config)
    assert validated.max_failed_login_attempts == 1
    assert validated.lockout_duration_seconds == 1
