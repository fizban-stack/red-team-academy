"""Multi-step attack chain endpoint with typed step models."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from core.auth import require_token
from core.schemas import (
    ADAttackStep, AntiForensicsStep, ChainRequest, ChainResponse, ChainStep,
    CloudStep, EvasionStep, GenerateStep, HarvestStep, InitialAccessStep,
    LateralStep, LinuxPersistStep, PersistStep, SandboxEvasionStep, ShellRequest,
)
from generators import REGISTRY
from generators.adattack import generate_adattack
from generators.anti_forensics import generate_anti_forensics
from generators.cloud import generate_cloud
from generators.evasion import generate_evasion
from generators.harvest import generate_harvest
from generators.initial_access import generate_initial_access
from generators.lateral import generate_lateral
from generators.linux_persist import generate_linux_persist
from generators.persist import generate_persist
from generators.sandbox_evasion import generate_sandbox_evasion

from .shell import _build_shell
from ._helpers import audit

router = APIRouter(tags=["chain"], dependencies=[Depends(require_token)])


@router.post("/chain", response_model=ChainResponse)
def chain_build(
    request: Request,
    req: ChainRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """
    Build an ordered attack chain across multiple technique modules. Each step
    is validated by pydantic at request time via the discriminated `module` field,
    so unknown modules / mismatched parameters fail at the boundary.
    """
    results: list[ChainStep] = []

    for i, step in enumerate(req.steps, 1):
        try:
            if isinstance(step, GenerateStep):
                if step.language not in REGISTRY:
                    raise ValueError(f"Unsupported language: {step.language}")
                shell_req = ShellRequest(
                    lhost=req.lhost, lport=req.lport, language=step.language,
                    obfuscate=step.obfuscate,
                )
                resp = _build_shell(shell_req)
                results.append(ChainStep(
                    step=i, module="generate", technique=resp.variant,
                    command=resp.command, notes=f"{step.language} reverse shell",
                    techniques=resp.techniques, risk=resp.risk,
                ))

            elif isinstance(step, HarvestStep):
                r = generate_harvest(
                    step.technique, step.outfile, step.obfuscate, req.lhost, req.lport,
                )
                results.append(_to_chain_step(i, "harvest", r))

            elif isinstance(step, PersistStep):
                r = generate_persist(step.technique, step.payload, step.name, step.obfuscate)
                results.append(_to_chain_step(i, "persist", r))

            elif isinstance(step, ADAttackStep):
                r = generate_adattack(
                    step.technique, step.domain, step.dc_host, step.username,
                    step.password, step.hash_nt, step.outfile, step.obfuscate,
                    req.lhost, req.lport, dc_ip=step.dc_ip,
                )
                results.append(_to_chain_step(i, "adattack", r))

            elif isinstance(step, LinuxPersistStep):
                r = generate_linux_persist(step.technique, step.payload, step.name, req.lhost, req.lport)
                results.append(_to_chain_step(i, "linux_persist", r))

            elif isinstance(step, CloudStep):
                r = generate_cloud(step.technique, step.outfile, req.lhost)
                results.append(_to_chain_step(i, "cloud", r))

            elif isinstance(step, InitialAccessStep):
                r = generate_initial_access(step.technique, req.lhost, req.lport, step.obfuscate)
                results.append(ChainStep(
                    step=i, module="initial_access", technique=r.technique,
                    command=r.payload, notes=r.notes,
                    techniques=r.techniques, risk=r.risk,
                ))

            elif isinstance(step, LateralStep):
                r = generate_lateral(
                    step.technique, step.target, step.command, step.username,
                    step.password, step.hash_nt, step.obfuscate, req.lhost, req.lport,
                )
                results.append(_to_chain_step(i, "lateral", r))

            elif isinstance(step, EvasionStep):
                r = generate_evasion(
                    step.technique, step.payload, step.obfuscate, req.lhost, req.lport,
                )
                results.append(_to_chain_step(i, "evasion", r))

            elif isinstance(step, AntiForensicsStep):
                r = generate_anti_forensics(step.technique, step.target, step.obfuscate)
                results.append(_to_chain_step(i, "anti_forensics", r))

            elif isinstance(step, SandboxEvasionStep):
                r = generate_sandbox_evasion(step.technique, step.threshold, step.obfuscate)
                results.append(_to_chain_step(i, "sandbox_evasion", r))

            else:
                # Unreachable — pydantic discriminator would have raised already.
                raise HTTPException(status_code=422, detail=f"Step {i}: unknown module.")

        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"Step {i}: {e}")

    audit(request, "chain", "multi", req.model_dump(),
          "\n---\n".join(s.command for s in results), x_engagement_id)

    return ChainResponse(
        lhost=req.lhost, lport=req.lport,
        steps=results, total_steps=len(results),
    )


def _to_chain_step(i: int, module: str, r) -> ChainStep:
    return ChainStep(
        step=i, module=module, technique=r.technique,
        command=r.command, notes=r.notes,
        techniques=getattr(r, "techniques", []),
        risk=getattr(r, "risk", "MEDIUM"),
    )
