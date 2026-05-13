"""Linux/macOS post-exploitation: persist, harvest, privesc."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import (
    LinuxHarvestRequest, LinuxPersistRequest, LinuxPrivescRequest, TechniqueResponse,
)
from core.validation import assert_lhost
from generators.linux_harvest import (
    SUPPORTED_TECHNIQUES as LINUX_HARVEST_TECHNIQUES, generate_linux_harvest,
)
from generators.linux_persist import (
    SUPPORTED_TECHNIQUES as LINUX_PERSIST_TECHNIQUES, generate_linux_persist,
)
from generators.linux_privesc import (
    SUPPORTED_TECHNIQUES as LINUX_PRIVESC_TECHNIQUES, generate_linux_privesc,
)

from ._helpers import audit

router = APIRouter(prefix="/linux", tags=["linux-postex"], dependencies=[Depends(require_token)])


def _resp(result) -> TechniqueResponse:
    return TechniqueResponse(
        command=result.command,
        technique=result.technique,
        notes=result.notes,
        techniques=getattr(result, "techniques", []),
        risk=getattr(result, "risk", "HIGH"),
        detections=getattr(result, "detections", []),
    )


@router.post("/persist", response_model=TechniqueResponse)
def linux_persist_post(
    request: Request,
    req: LinuxPersistRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_linux_persist(req.technique, req.payload, req.name, req.lhost, req.lport)
    audit(request, "linux_persist", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


@router.get("/persist", response_model=TechniqueResponse)
def linux_persist_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Persistence technique: {', '.join(LINUX_PERSIST_TECHNIQUES)}")],
    payload: Annotated[str, Query()] = "/tmp/payload.sh",
    name: Annotated[str, Query()] = "sysupdate",
    lhost: Annotated[str, Query()] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535)] = 4444,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in LINUX_PERSIST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_linux_persist(technique, payload, name, lhost, lport)
    audit(request, "linux_persist", technique,
          {"technique": technique, "payload": payload, "name": name, "lhost": lhost, "lport": lport},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/harvest", response_model=TechniqueResponse)
def linux_harvest_post(
    request: Request,
    req: LinuxHarvestRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_linux_harvest(req.technique, req.outfile, req.lhost, req.lport)
    audit(request, "linux_harvest", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


@router.get("/harvest", response_model=TechniqueResponse)
def linux_harvest_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Harvest technique: {', '.join(LINUX_HARVEST_TECHNIQUES)}")],
    outfile: Annotated[str, Query()] = "/tmp/loot.txt",
    lhost: Annotated[str, Query()] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535)] = 8080,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in LINUX_HARVEST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_linux_harvest(technique, outfile, lhost, lport)
    audit(request, "linux_harvest", technique,
          {"technique": technique, "outfile": outfile, "lhost": lhost, "lport": lport},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/privesc", response_model=TechniqueResponse)
def linux_privesc_post(
    request: Request,
    req: LinuxPrivescRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_linux_privesc(req.technique, req.payload, req.name)
    audit(request, "linux_privesc", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


@router.get("/privesc", response_model=TechniqueResponse)
def linux_privesc_get(
    request: Request,
    technique: Annotated[str, Query(description=f"PrivEsc technique: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")],
    payload: Annotated[str, Query()] = "/tmp/payload.sh",
    name: Annotated[str, Query()] = "sysupdate",
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    if technique not in LINUX_PRIVESC_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_linux_privesc(technique, payload, name)
    audit(request, "linux_privesc", technique,
          {"technique": technique, "payload": payload, "name": name},
          result.command, x_engagement_id)
    return _resp(result)
