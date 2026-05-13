"""Windows post-exploitation: harvest, persist, lateral, adattack, privesc, evasion."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import (
    ADAttackRequest, EvasionRequest, HarvestRequest,
    LateralRequest, PersistRequest, PrivescRequest, TechniqueResponse,
)
from core.validation import assert_lhost
from generators.adattack import (
    SUPPORTED_TECHNIQUES as ADATTACK_TECHNIQUES, generate_adattack,
)
from generators.evasion import (
    SUPPORTED_TECHNIQUES as EVASION_TECHNIQUES, generate_evasion,
)
from generators.harvest import (
    SUPPORTED_TECHNIQUES as HARVEST_TECHNIQUES, generate_harvest,
)
from generators.lateral import (
    SUPPORTED_TECHNIQUES as LATERAL_TECHNIQUES, generate_lateral,
)
from generators.persist import (
    SUPPORTED_TECHNIQUES as PERSIST_TECHNIQUES, generate_persist,
)
from generators.privesc import (
    SUPPORTED_TECHNIQUES as PRIVESC_TECHNIQUES, generate_privesc,
)

from ._helpers import audit

router = APIRouter(tags=["windows-postex"], dependencies=[Depends(require_token)])


def _resp(result, default_risk: str = "HIGH") -> TechniqueResponse:
    return TechniqueResponse(
        command=result.command,
        technique=result.technique,
        notes=result.notes,
        techniques=getattr(result, "techniques", []),
        risk=getattr(result, "risk", default_risk),
        detections=getattr(result, "detections", []),
    )


# ── Harvest ────────────────────────────────────────────────────────────────────

@router.get("/harvest", response_model=TechniqueResponse)
def harvest_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Harvest technique: {', '.join(HARVEST_TECHNIQUES)}")],
    outfile: Annotated[str, Query()] = "C:\\Windows\\Temp\\lsass.dmp",
    obfuscate: Annotated[bool, Query()] = True,
    lhost: Annotated[str, Query()] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535)] = 8080,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in HARVEST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_harvest(technique, outfile, obfuscate, lhost, lport)
    resp = _resp(result)
    audit(request, "harvest", technique,
          {"technique": technique, "outfile": outfile, "lhost": lhost, "lport": lport},
          result.command, x_engagement_id)
    return resp


@router.post("/harvest", response_model=TechniqueResponse)
def harvest_post(
    request: Request,
    req: HarvestRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_harvest(req.technique, req.outfile, req.obfuscate, req.lhost, req.lport)
    audit(request, "harvest", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


# ── Persist ────────────────────────────────────────────────────────────────────

@router.get("/persist", response_model=TechniqueResponse)
def persist_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Persistence technique: {', '.join(PERSIST_TECHNIQUES)}")],
    payload: Annotated[str, Query()] = "C:\\Windows\\Temp\\payload.exe",
    name: Annotated[str, Query()] = "WindowsUpdater",
    obfuscate: Annotated[bool, Query()] = True,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    if technique not in PERSIST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_persist(technique, payload, name, obfuscate)
    audit(request, "persist", technique,
          {"technique": technique, "payload": payload, "name": name},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/persist", response_model=TechniqueResponse)
def persist_post(
    request: Request,
    req: PersistRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_persist(req.technique, req.payload, req.name, req.obfuscate)
    audit(request, "persist", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


# ── Lateral ────────────────────────────────────────────────────────────────────

@router.get("/lateral", response_model=TechniqueResponse)
def lateral_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Lateral movement technique: {', '.join(LATERAL_TECHNIQUES)}")],
    target: Annotated[str, Query()] = "TARGET_HOST",
    command: Annotated[str, Query()] = "whoami",
    username: Annotated[str, Query()] = "DOMAIN\\USER",
    password: Annotated[str, Query()] = "PASS",
    hash_nt: Annotated[str, Query()] = "",
    obfuscate: Annotated[bool, Query()] = True,
    lhost: Annotated[str, Query()] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535)] = 8080,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in LATERAL_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_lateral(technique, target, command, username, password, hash_nt, obfuscate, lhost, lport)
    audit(request, "lateral", technique,
          {"technique": technique, "target": target, "command": command,
           "username": username, "password": password, "hash_nt": hash_nt,
           "lhost": lhost, "lport": lport},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/lateral", response_model=TechniqueResponse)
def lateral_post(
    request: Request,
    req: LateralRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_lateral(
        req.technique, req.target, req.command, req.username, req.password,
        req.hash_nt, req.obfuscate, req.lhost, req.lport,
    )
    audit(request, "lateral", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


# ── ADAttack ───────────────────────────────────────────────────────────────────

@router.get("/adattack", response_model=TechniqueResponse)
def adattack_get(
    request: Request,
    technique: Annotated[str, Query(description=f"AD attack technique: {', '.join(ADATTACK_TECHNIQUES)}")],
    domain: Annotated[str, Query()] = "DOMAIN.LOCAL",
    dc_host: Annotated[str, Query()] = "DC01",
    dc_ip: Annotated[str | None, Query()] = None,
    username: Annotated[str, Query()] = "USER",
    password: Annotated[str, Query()] = "PASS",
    hash_nt: Annotated[str, Query()] = "",
    outfile: Annotated[str, Query()] = "C:\\Windows\\Temp\\ad_out.txt",
    obfuscate: Annotated[bool, Query()] = True,
    lhost: Annotated[str, Query()] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535)] = 8080,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in ADATTACK_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_adattack(
        technique, domain, dc_host, username, password, hash_nt, outfile,
        obfuscate, lhost, lport, dc_ip=dc_ip,
    )
    audit(request, "adattack", technique,
          {"technique": technique, "domain": domain, "dc_host": dc_host, "dc_ip": dc_ip,
           "username": username, "password": password, "hash_nt": hash_nt,
           "outfile": outfile, "lhost": lhost, "lport": lport},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/adattack", response_model=TechniqueResponse)
def adattack_post(
    request: Request,
    req: ADAttackRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_adattack(
        req.technique, req.domain, req.dc_host, req.username, req.password,
        req.hash_nt, req.outfile, req.obfuscate, req.lhost, req.lport,
        dc_ip=req.dc_ip,
    )
    audit(request, "adattack", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


# ── Privesc ────────────────────────────────────────────────────────────────────

@router.get("/privesc", response_model=TechniqueResponse)
def privesc_get(
    request: Request,
    technique: Annotated[str, Query(description=f"PrivEsc technique: {', '.join(PRIVESC_TECHNIQUES)}")],
    payload: Annotated[str, Query()] = "C:\\Windows\\Temp\\payload.exe",
    name: Annotated[str, Query()] = "WindowsUpdate",
    obfuscate: Annotated[bool, Query()] = True,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    if technique not in PRIVESC_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_privesc(technique, payload, name, obfuscate)
    audit(request, "privesc", technique,
          {"technique": technique, "payload": payload, "name": name},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/privesc", response_model=TechniqueResponse)
def privesc_post(
    request: Request,
    req: PrivescRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_privesc(req.technique, req.payload, req.name, req.obfuscate)
    audit(request, "privesc", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


# ── Evasion ────────────────────────────────────────────────────────────────────

@router.get("/evasion", response_model=TechniqueResponse)
def evasion_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Evasion technique: {', '.join(EVASION_TECHNIQUES)}")],
    payload: Annotated[str, Query()] = "powershell.exe",
    obfuscate: Annotated[bool, Query()] = True,
    lhost: Annotated[str, Query()] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535)] = 8080,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    if technique not in EVASION_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_evasion(technique, payload, obfuscate, lhost, lport)
    audit(request, "evasion", technique,
          {"technique": technique, "payload": payload, "lhost": lhost, "lport": lport},
          result.command, x_engagement_id)
    return _resp(result)


@router.post("/evasion", response_model=TechniqueResponse)
def evasion_post(
    request: Request,
    req: EvasionRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    result = generate_evasion(req.technique, req.payload, req.obfuscate, req.lhost, req.lport)
    audit(request, "evasion", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)
