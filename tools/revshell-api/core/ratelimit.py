"""
slowapi-based rate limiting.

Gracefully degrades when slowapi isn't installed (e.g. in trimmed test environments)
so the rest of the API can still be imported and exercised.
"""
from .settings import SETTINGS

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[SETTINGS.rate_limit_default],
    )
    HAS_LIMITER = True
except Exception:  # pragma: no cover — exercised only when slowapi missing
    class _NoopLimiter:
        def limit(self, *_a, **_kw):
            def deco(fn):
                return fn
            return deco

    limiter = _NoopLimiter()
    SlowAPIMiddleware = None  # type: ignore
    RateLimitExceeded = Exception  # type: ignore
    HAS_LIMITER = False
