from functools import lru_cache
from typing import Annotated

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="AUTH_VAULT_", extra="ignore")

    app_name: str = "Auth Vault Service"
    environment: str = "development"
    database_url: str = "sqlite:///./auth_vault.db"
    jwt_secret: str = "development-only-change-this-secret-before-deploying"
    jwt_algorithm: str = "HS256"
    access_token_minutes: Annotated[int, Field(ge=1, le=120)] = 15
    refresh_token_days: Annotated[int, Field(ge=1, le=90)] = 7
    # If omitted, a deterministic development key is derived from jwt_secret. Set explicitly in deployments.
    encryption_key: str | None = None
    cors_origins: list[str] = ["http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
