"""Centralized input validation. Keep one source of truth for what counts as valid."""
import re

from fastapi import HTTPException

_LHOST_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]]+$")  # IPv4 / IPv6 with brackets / FQDN
_ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def validate_lhost(v: str) -> str:
    """Raise ValueError on invalid host. Suitable as a pydantic field_validator."""
    if not _LHOST_RE.match(v):
        raise ValueError(
            "lhost must contain only alphanumeric characters, dots, hyphens, colons, or brackets"
        )
    return v


def assert_lhost(v: str) -> str:
    """HTTP-aware variant for GET handlers — raises HTTPException(422)."""
    try:
        return validate_lhost(v)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


def assert_engagement_id(v: str | None) -> str | None:
    if v is None:
        return None
    if not _ENGAGEMENT_RE.match(v):
        raise HTTPException(status_code=422, detail="X-Engagement-ID must match ^[A-Za-z0-9_-]{1,64}$")
    return v
