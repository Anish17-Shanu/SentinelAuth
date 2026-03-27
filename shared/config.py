from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: Literal["development", "test", "production"] = "development"
    service_name: str = "sentinelauth"
    issuer: str = "https://auth.sentinel.local"
    auth_server_url: str = "http://auth-server:8000"
    user_service_url: str = "http://user-service:8001"
    policy_engine_url: str = "http://policy-engine:8002"
    audit_service_url: str = "http://audit-service:8003"
    redis_url: str = "memory://"
    private_key_pem: str | None = None
    public_key_pem: str | None = None
    access_token_ttl_seconds: int = Field(default=300, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=60 * 60 * 24 * 30, ge=600, le=60 * 60 * 24 * 90)
    authorization_code_ttl_seconds: int = Field(default=180, ge=30, le=600)
    login_rate_limit_window_seconds: int = Field(default=900, ge=60, le=3600)
    login_max_attempts: int = Field(default=5, ge=3, le=20)
    refresh_cookie_name: str = "sentinel_refresh"
    csrf_cookie_name: str = "sentinel_csrf"
    web_client_id: str = "sentinel-web"
    web_redirect_uri: str = "https://app.sentinel.local/callback"
    machine_client_id: str = "sentinel-machine"
    machine_client_secret: str = "dev-machine-secret"
    gateway_service_secret: str = "dev-gateway-secret"
    audit_service_secret: str = "dev-audit-secret"
    policy_service_secret: str = "dev-policy-secret"
    user_service_secret: str = "dev-user-secret"
    allowed_origins: str = "https://app.sentinel.local,http://localhost:3000,http://localhost:5173"
    docs_enabled: bool = True
    enforce_https_cookies: bool = False

    model_config = SettingsConfigDict(env_prefix="SENTINELAUTH_", env_file=".env", extra="ignore")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
