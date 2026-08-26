from __future__ import annotations

import os

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env from either backend/ or repo root
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))


def _default_database_url() -> str:
    # Prefer explicit env
    if os.getenv("DATABASE_URL"):
        return os.getenv("DATABASE_URL")  # type: ignore

    # Local dev default (docker-compose)
    return "postgresql://tesht:tesht_dev_password@localhost:5432/tesht"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(default_factory=_default_database_url, validation_alias="DATABASE_URL")

    api_secret_key: str = Field(default="change-me", validation_alias="API_SECRET_KEY")
    api_host: str = Field(default="0.0.0.0", validation_alias="API_HOST")
    api_port: int = Field(default=8000, validation_alias="API_PORT")

    # did:web method expects percent-encoding for ':' in ports (e.g. localhost%3A8000)
    tesht_domain: str = Field(default="localhost%3A8000", validation_alias="TESHT_DOMAIN")
    tesht_scheme: str = Field(default="http", validation_alias="TESHT_SCHEME")

    allowed_origins_raw: str = Field(
        default="http://127.0.0.1:6080,http://localhost:6080,http://127.0.0.1:8000,http://localhost:8000",
        validation_alias="ALLOWED_ORIGINS",
    )
    cors_enabled: bool = Field(default=True, validation_alias="CORS_ENABLED")

    debug: bool = Field(default=True, validation_alias="DEBUG")
    env: str = Field(default="dev", validation_alias="ENV")
    migrations_strict: bool = Field(default=False, validation_alias="MIGRATIONS_STRICT")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")

    # Auth (JWT bearer stub)
    auth_mode: str = Field(default="hs256", validation_alias="AUTH_MODE")
    oidc_issuer: str = Field(default="", validation_alias="OIDC_ISSUER")
    oidc_audience: str = Field(default="", validation_alias="OIDC_AUDIENCE")
    oidc_jwks_url: str = Field(default="", validation_alias="OIDC_JWKS_URL")
    oidc_jwks_json: str = Field(default="", validation_alias="OIDC_JWKS_JSON")
    oidc_client_id: str = Field(default="", validation_alias="OIDC_CLIENT_ID")
    auth_jwt_secret: str = Field(default="dev-secret-change", validation_alias="AUTH_JWT_SECRET")
    auth_jwt_issuer: str = Field(default="tesht", validation_alias="AUTH_JWT_ISSUER")
    tesht_dev_mode: bool = Field(default=False, validation_alias="TESHT_DEV_MODE")

    # Demo mode (per-session demo tokens -> isolated tenants). Set DEMO_MODE=true explicitly.
    demo_mode: bool = Field(default=False, validation_alias="DEMO_MODE")
    demo_jwt_secret: str = Field(default="demo-secret-change", validation_alias="DEMO_JWT_SECRET")
    demo_token_ttl_seconds: int = Field(default=3600, validation_alias="DEMO_TOKEN_TTL_SECONDS")
    demo_auto_seed: bool = Field(default=bool(os.getenv("DEMO_AUTO_SEED", "").lower() in ("1", "true", "yes")), validation_alias="DEMO_AUTO_SEED")
    demo_seed_profile: str = Field(default=os.getenv("DEMO_SEED_PROFILE", "standard"), validation_alias="DEMO_SEED_PROFILE")

    max_body_bytes: int = Field(default=1_000_000, validation_alias="MAX_BODY_BYTES")
    rate_limit_enabled: bool = Field(default=False, validation_alias="RATE_LIMIT_ENABLED")
    rate_limit_per_minute: int = Field(default=120, validation_alias="RATE_LIMIT_PER_MINUTE")

    # Connection pool settings (PostgreSQL only)
    db_pool_size: int = Field(default=10, validation_alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, validation_alias="DB_MAX_OVERFLOW")
    db_pool_timeout: int = Field(default=30, validation_alias="DB_POOL_TIMEOUT")
    db_pool_recycle: int = Field(default=1800, validation_alias="DB_POOL_RECYCLE")

    # DID resolver cache settings
    did_cache_ttl_seconds: int = Field(default=300, validation_alias="DID_CACHE_TTL_SECONDS")
    did_cache_max_size: int = Field(default=10000, validation_alias="DID_CACHE_MAX_SIZE")

    # JTI deduplication
    jti_dedup_enabled: bool = Field(default=True, validation_alias="JTI_DEDUP_ENABLED")
    jti_dedup_window_seconds: int = Field(default=3600, validation_alias="JTI_DEDUP_WINDOW_SECONDS")

    def model_post_init(self, __context: object) -> None:
        if self.env == "production" and not self.database_url.startswith("postgresql"):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL URL when ENV=production. "
                f"Got: {self.database_url!r}"
            )

    @property
    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins_raw.split(",") if o.strip()]


settings = Settings()
