"""C2 profile + redirector endpoints."""
import dataclasses
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import C2ProfileResponse, RedirectorRequest, RedirectorResponse
from core.validation import assert_lhost
from generators.c2profile import SUPPORTED_PLATFORMS, generate_profile
from generators.redirector import generate_redirector

from ._helpers import audit

router = APIRouter(tags=["c2"], dependencies=[Depends(require_token)])


@router.get("/c2profile", response_model=C2ProfileResponse)
def c2profile_get(
    request: Request,
    platform: Annotated[str, Query(description=f"SaaS platform to mimic: {', '.join(SUPPORTED_PLATFORMS)}")],
    lhost: Annotated[str, Query(min_length=1, description="C2 listener host")],
    lport: Annotated[int, Query(ge=1, le=65535)],
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported platform '{platform}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}",
        )
    profile = generate_profile(platform, lhost, lport)
    resp = C2ProfileResponse(**dataclasses.asdict(profile))
    audit(request, "c2", platform,
          {"platform": platform, "lhost": lhost, "lport": lport},
          profile.havoc_profile, x_engagement_id)
    return resp


@router.get("/redirector", response_model=RedirectorResponse)
def redirector_get(
    request: Request,
    platform: Annotated[str, Query(description=f"C2 platform: {', '.join(SUPPORTED_PLATFORMS)}")],
    lhost: Annotated[str, Query(min_length=1)],
    lport: Annotated[int, Query(ge=1, le=65535)],
    decoy: Annotated[str, Query(min_length=1, description="Decoy URL for non-matching traffic")],
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=422, detail=f"Unsupported platform '{platform}'.")
    result = generate_redirector(platform, lhost, lport, decoy)
    audit(request, "redirector", platform,
          {"platform": platform, "lhost": lhost, "lport": lport, "decoy": decoy},
          result.apache_htaccess, x_engagement_id)
    return RedirectorResponse(
        platform=result.platform,
        apache_htaccess=result.apache_htaccess,
        nginx_config=result.nginx_config,
    )


@router.post("/redirector", response_model=RedirectorResponse)
def redirector_post(
    request: Request,
    req: RedirectorRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_redirector(req.platform, req.lhost, req.lport, req.decoy)
    audit(request, "redirector", req.platform, req.model_dump(),
          result.apache_htaccess, x_engagement_id)
    return RedirectorResponse(
        platform=result.platform,
        apache_htaccess=result.apache_htaccess,
        nginx_config=result.nginx_config,
    )
