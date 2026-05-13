"""Anti-forensics + sandbox/VM evasion endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.schemas import (
    AntiForensicsRequest, SandboxEvasionRequest, TechniqueResponse,
)
from generators.anti_forensics import (
    SUPPORTED_TECHNIQUES as ANTI_FORENSICS_TECHNIQUES, generate_anti_forensics,
)
from generators.sandbox_evasion import (
    SUPPORTED_TECHNIQUES as SANDBOX_TECHNIQUES, generate_sandbox_evasion,
)

from ._helpers import audit

router = APIRouter(tags=["evasion-extended"], dependencies=[Depends(require_token)])


def _resp(result) -> TechniqueResponse:
    return TechniqueResponse(
        command=result.command,
        technique=result.technique,
        notes=result.notes,
        techniques=getattr(result, "techniques", []),
        risk=getattr(result, "risk", "MEDIUM"),
        detections=getattr(result, "detections", []),
    )


# ── Anti-forensics ────────────────────────────────────────────────────────────

@router.post("/anti_forensics", response_model=TechniqueResponse)
def anti_forensics_post(
    request: Request,
    req: AntiForensicsRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """Generate post-engagement artifact-clearing / anti-forensics commands."""
    result = generate_anti_forensics(req.technique, req.target, req.obfuscate)
    audit(request, "anti_forensics", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


@router.get("/anti_forensics", response_model=TechniqueResponse)
def anti_forensics_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Technique: {', '.join(ANTI_FORENSICS_TECHNIQUES)}")],
    target: Annotated[str, Query()] = "auto",
    obfuscate: Annotated[bool, Query()] = True,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    if technique not in ANTI_FORENSICS_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_anti_forensics(technique, target, obfuscate)
    audit(request, "anti_forensics", technique,
          {"technique": technique, "target": target, "obfuscate": obfuscate},
          result.command, x_engagement_id)
    return _resp(result)


# ── Sandbox evasion ───────────────────────────────────────────────────────────

@router.post("/sandbox_evasion", response_model=TechniqueResponse)
def sandbox_evasion_post(
    request: Request,
    req: SandboxEvasionRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """Generate sandbox / VM / analysis-environment gate snippets."""
    result = generate_sandbox_evasion(req.technique, req.threshold, req.obfuscate)
    audit(request, "sandbox_evasion", req.technique, req.model_dump(), result.command, x_engagement_id)
    return _resp(result)


@router.get("/sandbox_evasion", response_model=TechniqueResponse)
def sandbox_evasion_get(
    request: Request,
    technique: Annotated[str, Query(description=f"Technique: {', '.join(SANDBOX_TECHNIQUES)}")],
    threshold: Annotated[int, Query(ge=0)] = 0,
    obfuscate: Annotated[bool, Query()] = True,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    if technique not in SANDBOX_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'.")
    result = generate_sandbox_evasion(technique, threshold, obfuscate)
    audit(request, "sandbox_evasion", technique,
          {"technique": technique, "threshold": threshold, "obfuscate": obfuscate},
          result.command, x_engagement_id)
    return _resp(result)
