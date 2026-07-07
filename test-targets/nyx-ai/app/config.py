from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Nyx AI"
    debug: bool = False

    # Auth
    jwt_secret: str = "nyx-dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    jwt_public_key: str = ""  # PEM public key for RS256 / SSO tokens

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = 300

    # Database
    database_url: str = "postgresql+asyncpg://nyx:nyx@localhost/nyx"

    # Webhooks
    webhook_timeout_seconds: float = 10.0

    class Config:
        env_prefix = "NYX_"
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
