import pytest

from app.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    # Deterministic RSA test keypair so tests never depend on real secrets.
    from tests.fixtures.test_keys import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY

    return Settings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/test",
        jwt_private_key=TEST_PRIVATE_KEY,
        jwt_public_key=TEST_PUBLIC_KEY,
        max_failed_login_attempts=3,
        lockout_duration_seconds=900,
    )
