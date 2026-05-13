"""Cloud post-exploitation endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import CloudRequest, CloudResponse
from core.validation import assert_lhost
from generators.cloud import SUPPORTED_TECHNIQUES as CLOUD_TECHNIQUES, generate_cloud

from ._helpers import audit

router = APIRouter(tags=["cloud"], dependencies=[Depends(require_token)])


@router.post("/cloud", response_model=CloudResponse)
def cloud_post(
    request: Request,
    req: CloudRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_cloud(req.technique, req.outfile, req.lhost)
    audit(request, "cloud", req.technique, req.model_dump(), result.command, x_engagement_id)
    return CloudResponse(
        command=result.command, technique=result.technique,
        platform=result.platform, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@router.get("/cloud", response_model=CloudResponse)
def cloud_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Cloud technique: {', '.join(CLOUD_TECHNIQUES)}")],
    outfile: Annotated[str, Query()] = "/tmp/cloud_loot.json",
    lhost: Annotated[str, Query()] = "192.168.1.100",
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in CLOUD_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_cloud(technique, outfile, lhost)
    audit(request, "cloud", technique,
          {"technique": technique, "outfile": outfile, "lhost": lhost},
          result.command, x_engagement_id)
    return CloudResponse(
        command=result.command, technique=result.technique,
        platform=result.platform, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )
