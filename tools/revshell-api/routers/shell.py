"""Reverse-shell generation endpoints."""
import dataclasses
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_token
from core.ratelimit import limiter
from core.schemas import (
    ARCH_VALUES, BatchGenerateRequest, C2ProfileResponse,
    ShellRequest, ShellResponse,
)
from core.validation import assert_lhost
from generators import REGISTRY, SUPPORTED_LANGUAGES
from generators.base import ShellOptions
from generators.c2profile import (
    SUPPORTED_PLATFORMS, generate_profile,
)
from generators.encode import (
    SUPPORTED_TECHNIQUES as ENCODE_TECHNIQUES, encode_command,
)

from ._helpers import audit

router = APIRouter(tags=["shell"], dependencies=[Depends(require_token)])


def _build_shell(req: ShellRequest) -> ShellResponse:
    opts = ShellOptions(
        lhost=req.lhost,
        lport=req.lport,
        arch=req.arch,
        obfuscate=req.obfuscate,
        retry=req.retry,
        egress_port=req.egress_port,
        seed=req.seed,
    )
    generator = REGISTRY[req.language]()
    result = generator.generate(opts)

    command = result.command
    encode_key: str | None = None
    if req.encode:
        command, encode_key = encode_command(command, req.encode, req.language)
        encode_key = encode_key or None

    c2_resp: C2ProfileResponse | None = None
    if req.c2_platform:
        profile = generate_profile(req.c2_platform, req.lhost, req.lport)
        c2_resp = C2ProfileResponse(**dataclasses.asdict(profile))

    listener_setup: dict | None = None
    if result.listener_setup is not None:
        listener_setup = dataclasses.asdict(result.listener_setup)

    return ShellResponse(
        command=command,
        language=result.language,
        arch=result.arch,
        lhost=req.lhost,
        lport=req.lport,
        variant=result.variant,
        listener=result.listener,
        tty_upgrade=result.tty_upgrade,
        msf_compat=result.msf_compat,
        listener_setup=listener_setup,
        encode_key=encode_key,
        c2_profile=c2_resp,
        techniques=result.techniques,
        risk=result.risk,
        detections=result.detections,
    )


@router.get("/languages")
def list_languages() -> dict:
    return {"languages": SUPPORTED_LANGUAGES}


@router.get("/generate", response_model=ShellResponse)
@limiter.limit("60/minute")
def generate_get(
    request: Request,
    lhost: Annotated[str, Query(min_length=1, description="Listener host IP")],
    lport: Annotated[int, Query(ge=1, le=65535)],
    language: Annotated[str, Query(description="Shell language")],
    arch: Annotated[ARCH_VALUES, Query(description="Target architecture")] = "any",
    obfuscate: Annotated[bool, Query()] = True,
    retry: Annotated[bool, Query()] = False,
    egress_port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    encode: Annotated[str | None, Query(description=f"Encode technique: {', '.join(ENCODE_TECHNIQUES)}")] = None,
    c2_platform: Annotated[str | None, Query(description=f"C2 platform: {', '.join(SUPPORTED_PLATFORMS)}")] = None,
    seed: Annotated[int | None, Query(description="Deterministic seed for reproducible output")] = None,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    assert_lhost(lhost)
    normalized = language.lower()
    if normalized not in REGISTRY:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported language '{language}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}",
        )
    req = ShellRequest(
        lhost=lhost, lport=lport, language=normalized, arch=arch,
        obfuscate=obfuscate, retry=retry, egress_port=egress_port,
        encode=encode, c2_platform=c2_platform, seed=seed,
    )
    resp = _build_shell(req)
    audit(request, "shell", normalized, req.model_dump(), resp.command, x_engagement_id)
    return resp


@router.post("/generate", response_model=ShellResponse)
@limiter.limit("60/minute")
def generate_post(
    request: Request,
    req: ShellRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    resp = _build_shell(req)
    audit(request, "shell", req.language, req.model_dump(), resp.command, x_engagement_id)
    return resp


@router.post("/batch/generate", response_model=list[ShellResponse])
@limiter.limit("20/minute")
def batch_generate(
    request: Request,
    req: BatchGenerateRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """Generate multiple shell payloads in a single call. Max 20 requests per batch."""
    out = []
    for r in req.requests:
        resp = _build_shell(r)
        audit(request, "shell", r.language, r.model_dump(), resp.command, x_engagement_id)
        out.append(resp)
    return out
