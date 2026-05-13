"""Centralized environment-driven settings."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    api_token: str | None
    cors_origins: list[str]
    audit_log_path: str | None
    rate_limit_default: str
    rate_limit_generate: str
    require_engagement_id: bool
    log_level: str


def _split_csv(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return list(default)
    return [v.strip() for v in value.split(",") if v.strip()]


def load_settings() -> Settings:
    return Settings(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 8080)),
        api_token=os.environ.get("API_TOKEN") or None,
        cors_origins=_split_csv(
            os.environ.get("CORS_ORIGINS"),
            default=[
                "http://localhost",
                "http://localhost:8080",
                "http://127.0.0.1",
                "http://127.0.0.1:8080",
            ],
        ),
        audit_log_path=os.environ.get("AUDIT_LOG") or None,
        rate_limit_default=os.environ.get("RATE_LIMIT_DEFAULT", "120/minute"),
        rate_limit_generate=os.environ.get("RATE_LIMIT_GENERATE", "60/minute"),
        require_engagement_id=os.environ.get("REQUIRE_ENGAGEMENT_ID", "0").lower() in ("1", "true", "yes"),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    )


SETTINGS = load_settings()
