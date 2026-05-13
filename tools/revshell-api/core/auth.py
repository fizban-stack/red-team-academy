"""
Bearer-token auth as a FastAPI dependency.

When `API_TOKEN` env is unset, the dependency is a no-op (dev-friendly).
When set, every protected endpoint requires `Authorization: Bearer <token>`.

Use hmac.compare_digest to avoid timing attacks.
"""
import hmac

from fastapi import Header, HTTPException

from .settings import SETTINGS


def require_token(authorization: str | None = Header(default=None)) -> None:
    """
    FastAPI dependency. Enforces bearer auth when API_TOKEN is configured.
    Raises 401 on missing/invalid token. Returns silently otherwise.
    """
    expected = SETTINGS.api_token
    if not expected:
        return  # auth disabled (no token configured)

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization: Bearer <token> required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid API token")
