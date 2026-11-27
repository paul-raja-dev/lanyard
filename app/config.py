from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Application ---
    app_title: str = "Lanyard Auth Service"
    app_version: str = "0.2.0"

    # --- Database ---
    database_url: str = "postgresql+psycopg2://user:password@localhost:5432/lanyard"

    # --- JWT ---
    issuer: str = "http://localhost:8000"
    key_id: str = "auth-key-1"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # --- Key paths ---
    private_key_path: Path = Path("private.pem")
    public_key_path: Path = Path("public.pem")

    # --- Rate Limiting / Redis ---
    rate_limit_enabled: bool = True
    redis_url: str = "redis://localhost:6379/0"
    rate_limit_login: str = "10/minute"
    rate_limit_register: str = "5/minute"
    rate_limit_refresh: str = "30/minute"
    rate_limit_logout: str = "20/minute"
    rate_limit_apps: str = "5/minute"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
