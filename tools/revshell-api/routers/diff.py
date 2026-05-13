"""
/stack/diff — compare two EDR evasion stacks side-by-side.

POST /stack/diff   — accepts {edr_a, edr_b, lhost, lport, language}
                     returns shared_techniques, only_a, only_b with rationales

For authorized use on systems you own or have explicit written permission to test.
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from core.auth import require_token
from core.schemas import DiffTechniqueItem, StackDiffRequest, StackDiffResponse
from generators.stack_diff import diff_stacks

from ._helpers import audit

router = APIRouter(tags=["stack"], dependencies=[Depends(require_token)])


@router.post("/stack/diff", response_model=StackDiffResponse)
def compare_stacks(
    req: StackDiffRequest,
    request: Request,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """
    Compare two EDR evasion stacks.

    Returns three lists:
    - `shared`: techniques present in both stacks (your common baseline)
    - `only_a`: techniques unique to edr_a
    - `only_b`: techniques unique to edr_b

    Deterministic — same (edr_a, edr_b) pair always returns the same result.
    """
    try:
        result = diff_stacks(
            edr_a=req.edr_a,
            edr_b=req.edr_b,
            lhost=req.lhost,
            lport=req.lport,
            language=req.language,
            obfuscate=req.obfuscate,
        )
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit(
        request, "stack_diff", req.edr_a + "_vs_" + req.edr_b,
        req.model_dump(), result.summary, x_engagement_id,
    )

    def _to_item(d) -> DiffTechniqueItem:
        return DiffTechniqueItem(
            technique=d.technique,
            module=d.module,
            rationale_a=d.rationale_a,
            rationale_b=d.rationale_b,
        )

    return StackDiffResponse(
        edr_a=result.edr_a,
        edr_b=result.edr_b,
        shared=[_to_item(d) for d in result.shared],
        only_a=[_to_item(d) for d in result.only_a],
        only_b=[_to_item(d) for d in result.only_b],
        summary=result.summary,
        shared_count=result.shared_count,
        only_a_count=result.only_a_count,
        only_b_count=result.only_b_count,
    )
