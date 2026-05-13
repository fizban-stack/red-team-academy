"""
/stack — EDR-aware evasion stack orchestrator.

Operator supplies target EDR + listener + language. We compose a sequenced
evasion playbook tuned to that vendor and return it with rationale per step.
"""
import dataclasses
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request

from core.auth import require_token
from core.schemas import (
    ShellRequest, StackEntryResponse, StackRequest, StackResponse,
)
from generators.evasion_stack import build_stack

from ._helpers import audit
from .shell import _build_shell

router = APIRouter(tags=["stack"], dependencies=[Depends(require_token)])


@router.post("/stack", response_model=StackResponse)
def stack_post(
    request: Request,
    req: StackRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """
    Build an EDR-tuned evasion stack.

    Order is load-bearing: sandbox gates run first (skip the payload entirely if
    the host looks like a sandbox), then evasion bypasses tamper with detection
    surfaces, then the payload fires, then anti-forensics cleanup runs at the
    end.
    """
    # Build the actual shell payload via the shared shell builder so seed +
    # encode + obfuscate flags work identically to /generate.
    shell_req = ShellRequest(
        lhost=req.lhost, lport=req.lport, language=req.language,
        obfuscate=req.obfuscate, seed=req.seed,
    )
    shell_resp = _build_shell(shell_req)

    result = build_stack(
        edr=req.edr,
        lhost=req.lhost,
        lport=req.lport,
        language=req.language,
        obfuscate=req.obfuscate,
        include_anti_forensics=req.include_anti_forensics,
        include_sandbox_evasion=req.include_sandbox_evasion,
        shell_command=shell_resp.command,
    )

    audit(
        request, "stack", req.edr, req.model_dump(),
        "\n---\n".join(entry.command for entry in result.chain),
        x_engagement_id,
    )

    return StackResponse(
        edr=result.edr,
        listener=result.listener,
        chain=[StackEntryResponse(**dataclasses.asdict(e)) for e in result.chain],
        total_steps=result.total_steps,
        summary=result.summary,
    )
