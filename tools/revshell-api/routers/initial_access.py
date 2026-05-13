"""Initial access endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import InitialAccessRequest, InitialAccessResponse
from core.validation import assert_lhost
from generators.initial_access import (
    SUPPORTED_TECHNIQUES as INITIAL_ACCESS_TECHNIQUES, generate_initial_access,
)

from ._helpers import audit

router = APIRouter(tags=["initial-access"], dependencies=[Depends(require_token)])


@router.post("/initial_access", response_model=InitialAccessResponse)
def initial_access_post(
    request: Request,
    req: InitialAccessRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_initial_access(req.technique, req.lhost, req.lport, req.obfuscate)
    audit(request, "initial_access", req.technique, req.model_dump(), result.payload, x_engagement_id)
    return InitialAccessResponse(
        payload=result.payload, technique=result.technique,
        delivery_hint=result.delivery_hint, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@router.get("/initial_access", response_model=InitialAccessResponse)
def initial_access_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Initial access technique: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")],
    lhost: Annotated[str, Query(min_length=1)],
    lport: Annotated[int, Query(ge=1, le=65535)],
    obfuscate: Annotated[bool, Query()] = True,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in INITIAL_ACCESS_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_initial_access(technique, lhost, lport, obfuscate)
    audit(request, "initial_access", technique,
          {"technique": technique, "lhost": lhost, "lport": lport, "obfuscate": obfuscate},
          result.payload, x_engagement_id)
    return InitialAccessResponse(
        payload=result.payload, technique=result.technique,
        delivery_hint=result.delivery_hint, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )
