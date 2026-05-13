"""Web shell generator endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import WebShellRequest, WebShellResponse
from generators.webshell import (
    SUPPORTED_VARIANTS as WEBSHELL_VARIANTS, generate_webshell,
)

from ._helpers import audit

router = APIRouter(tags=["webshell"], dependencies=[Depends(require_token)])


@router.post("/webshell", response_model=WebShellResponse)
def webshell_post(
    request: Request,
    req: WebShellRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_webshell(req.variant, req.obfuscate, req.token)
    audit(request, "webshell", req.variant, req.model_dump(), result.shell, x_engagement_id)
    return WebShellResponse(
        shell=result.shell, variant=result.variant,
        upload_hint=result.upload_hint, access_example=result.access_example,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@router.get("/webshell", response_model=WebShellResponse)
def webshell_get(
    request: Request,
    variant: Annotated[str, Query(description=f"Web shell variant: {', '.join(WEBSHELL_VARIANTS)}")],
    obfuscate: Annotated[bool, Query()] = True,
    token: Annotated[str, Query(min_length=6)] = "S3cr3tT0k3n",
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    if variant not in WEBSHELL_VARIANTS:
        raise HTTPException(status_code=422, detail=f"Unsupported variant '{variant}'.")
    result = generate_webshell(variant, obfuscate, token)
    audit(request, "webshell", variant,
          {"variant": variant, "obfuscate": obfuscate, "token": token},
          result.shell, x_engagement_id)
    return WebShellResponse(
        shell=result.shell, variant=result.variant,
        upload_hint=result.upload_hint, access_example=result.access_example,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )
