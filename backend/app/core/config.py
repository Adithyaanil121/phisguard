"""
Application configuration loaded from environment variables.
Uses pydantic-settings for validation and type coercion.

Design decisions:
- API key is mandatory: the app will not start without it.
- Model path is configured but the model may be absent at startup.
  A missing model produces degraded state, not a crash.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"

    # Security — mandatory, no default
    api_key: str

    # Origin validation
    allowed_origins: list[str] = [
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ]

    # Rate limits
    rate_limit_quick: str = "60/minute"
    rate_limit_deep: str = "5/minute"

    # Model
    model_path: str = "models/phishguard_v1.joblib"
    model_version: str = "v1.0.0"

    # Cache
    cache_ttl_seconds: int = 300
    cache_max_size: int = 10000

    # Timeouts
    quick_scan_timeout: float = 10.0
    deep_scan_timeout: float = 30.0
    reputation_timeout: float = 5.0
    tls_timeout: float = 5.0

    model_config = {"env_prefix": "PHISHGUARD_", "env_file": ".env"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
