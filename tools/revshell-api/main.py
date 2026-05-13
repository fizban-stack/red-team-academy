"""
RevShell API — application entrypoint.

The bulk of behavior lives in routers/ and generators/. This module wires them
together, configures middleware, and exposes lifecycle endpoints.
"""
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.audit import enabled as audit_enabled
from core.ratelimit import HAS_LIMITER, RateLimitExceeded, SlowAPIMiddleware, limiter
from core.settings import SETTINGS
from routers import (
    c2 as c2_router,
    c2_channels as c2_channels_router,
    chain as chain_router,
    cloud as cloud_router,
    diff as diff_router,
    evasion_extended as evasion_extended_router,
    initial_access as initial_access_router,
    ioc as ioc_router,
    linux_postex as linux_router,
    recommend as recommend_router,
    reporting as reporting_router,
    shell as shell_router,
    stack as stack_router,
    webshell as webshell_router,
    windows_postex as windows_router,
)

logging.basicConfig(level=SETTINGS.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("revshell")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info(
        "revshell-api starting on %s:%d — auth=%s, audit=%s, rate_limit=%s, cors=%s",
        SETTINGS.host, SETTINGS.port,
        "enabled" if SETTINGS.api_token else "DISABLED (set API_TOKEN to enable)",
        "enabled" if audit_enabled() else "DISABLED (set AUDIT_LOG to enable)",
        "enabled" if HAS_LIMITER else "DISABLED (install slowapi to enable)",
        SETTINGS.cors_origins,
    )
    yield


app = FastAPI(
    title="RevShell API",
    description=(
        "Reverse-shell and red-team command generator for authorized engagements.\n\n"
        "Auth: set `API_TOKEN` env var to enable bearer-token auth on all endpoints.\n"
        "Audit: set `AUDIT_LOG=/path/to/audit.jsonl` to record every generation event.\n"
        "Engagement tagging: send `X-Engagement-ID: <id>` header to tag log entries."
    ),
    version="4.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=SETTINGS.cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*", "X-Engagement-ID", "Authorization"],
    allow_credentials=False,
)

if HAS_LIMITER and SlowAPIMiddleware is not None:
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    @app.exception_handler(RateLimitExceeded)
    async def _ratelimit_handler(request, exc):  # pragma: no cover
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=429, content={"detail": "rate_limited"})


app.include_router(shell_router.router)
app.include_router(c2_router.router)
app.include_router(c2_channels_router.router)
app.include_router(windows_router.router)
app.include_router(linux_router.router)
app.include_router(cloud_router.router)
app.include_router(webshell_router.router)
app.include_router(initial_access_router.router)
app.include_router(evasion_extended_router.router)
app.include_router(stack_router.router)
app.include_router(diff_router.router)
app.include_router(recommend_router.router)
app.include_router(ioc_router.router)
app.include_router(chain_router.router)
app.include_router(reporting_router.router)


@app.get("/health", tags=["meta"])
def health():
    return {
        "status": "ok",
        "version": "4.5.0",
        "auth_enabled": bool(SETTINGS.api_token),
        "audit_log_enabled": audit_enabled(),
        "rate_limit_enabled": HAS_LIMITER,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host=SETTINGS.host, port=SETTINGS.port, reload=False)
