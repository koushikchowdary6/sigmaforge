"""Application configuration.

All configuration is sourced from environment variables via pydantic-settings.
No secret ever has a hardcoded default that would work in production -- the
JWT signing keys and database URL have no default at all, so the app refuses
to start rather than silently running with an insecure/dev value in an
environment where someone forgot to set them.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    app_name: str = "SigmaForge API"
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    # --- Database ---
    database_url: str = Field(
        ...,
        description="Async SQLAlchemy DSN, e.g. postgresql+asyncpg://user:pass@host:5432/sigmaforge",
    )

    # --- Auth / JWT (RS256) ---
    jwt_private_key: str = Field(..., description="PEM-encoded RSA private key, used to sign access tokens")
    jwt_public_key: str = Field(..., description="PEM-encoded RSA public key, used to verify access tokens")
    jwt_access_token_ttl_seconds: int = Field(default=900)  # 15 minutes
    jwt_refresh_token_ttl_seconds: int = Field(default=60 * 60 * 24 * 14)  # 14 days
    jwt_issuer: str = Field(default="sigmaforge")

    # --- Account lockout ---
    max_failed_login_attempts: int = Field(default=5)
    lockout_duration_seconds: int = Field(default=15 * 60)

    # --- CORS (frontend origin, dev default only) ---
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton -- avoids re-parsing env vars on every request."""
    # Required fields (database_url, jwt_private_key, jwt_public_key) have no
    # default and are sourced from environment variables by pydantic-settings
    # at runtime -- mypy can't see that, hence the ignore. If those env vars
    # are genuinely missing, this raises pydantic.ValidationError at startup,
    # which is exactly the fail-fast behavior we want (config.py module docstring).
    return Settings()  # type: ignore[call-arg]
