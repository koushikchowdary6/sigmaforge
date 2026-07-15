"""Worker configuration -- deliberately minimal in E0. Only the Redis broker
URL is required; DATABASE_URL etc. get added as real jobs (validation,
deployment, AI) land in E1+ (ROADMAP.md)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    redis_url: str = "redis://localhost:6379/0"
    environment: str = "development"


settings = WorkerSettings()
