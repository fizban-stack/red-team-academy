"""Engagement reporting endpoints — generate markdown summaries from the audit log."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from core.audit import enabled, render_markdown_report
from core.auth import require_token

router = APIRouter(tags=["reporting"], dependencies=[Depends(require_token)])


@router.get("/report", response_class=Response)
def report(
    engagement_id: Annotated[str | None, Query(description="Filter by engagement (matches X-Engagement-ID).")] = None,
):
    """
    Returns a Markdown report summarising the audit log.

    Useful at the end of an engagement: pipe the response directly into your
    client deliverable. Requires AUDIT_LOG env to be configured.
    """
    if not enabled():
        raise HTTPException(
            status_code=404,
            detail="Audit log is disabled. Set AUDIT_LOG=/path/to/audit.jsonl in the environment.",
        )
    return Response(
        content=render_markdown_report(engagement_id),
        media_type="text/markdown",
    )
