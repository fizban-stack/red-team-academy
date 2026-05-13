"""/recommend — constraint-driven technique selector."""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request

from core.auth import require_token
from core.schemas import RecommendationItem, RecommendRequest, RecommendResponse
from generators.recommender import recommend as do_recommend

from ._helpers import audit

router = APIRouter(tags=["recommend"], dependencies=[Depends(require_token)])


@router.post("/recommend", response_model=RecommendResponse)
def recommend_post(
    request: Request,
    req: RecommendRequest,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """
    Return an ordered list of evasion technique recommendations that satisfy
    the operator's constraints.

    Scoring is deterministic for a fixed constraint set, so this endpoint is
    safe to call repeatedly during planning. Highest-scoring techniques first,
    capped at `max_techniques`.
    """
    result = do_recommend(
        has_admin=req.has_admin,
        target_os=req.target_os,
        blocks_amsi=req.blocks_amsi,
        blocks_etw=req.blocks_etw,
        has_userland_hooks=req.has_userland_hooks,
        has_memory_scanner=req.has_memory_scanner,
        has_callstack_inspection=req.has_callstack_inspection,
        target_edrs=req.target_edrs,
        families=req.families,
        max_techniques=req.max_techniques,
    )

    audit(
        request, "recommend", "constraints", req.model_dump(),
        result.constraints_summary, x_engagement_id,
    )

    return RecommendResponse(
        constraints_summary=result.constraints_summary,
        recommendations=[
            RecommendationItem(
                technique=r.technique, rationale=r.rationale,
                family=r.family, risk=r.risk, counters=r.counters,
            )
            for r in result.recommendations
        ],
        total=result.total,
    )
