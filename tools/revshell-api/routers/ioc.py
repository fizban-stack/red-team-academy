"""/ioc_export — emit Sigma rules from the audit log."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from core.audit import enabled as audit_enabled
from core.auth import require_token
from generators.ioc_export import build_rules_from_audit

router = APIRouter(tags=["ioc"], dependencies=[Depends(require_token)])


@router.get("/ioc_export", response_class=Response)
def ioc_export(
    engagement_id: Annotated[str | None, Query(description="Filter rules by engagement (X-Engagement-ID).")] = None,
):
    """
    Returns a YAML document containing one Sigma rule per (module, technique)
    seen in the audit log. Hand to the blue team at engagement teardown.

    Requires AUDIT_LOG to be configured at server startup.
    """
    if not audit_enabled():
        raise HTTPException(
            status_code=404,
            detail="Audit log disabled. Set AUDIT_LOG=/path/to/audit.jsonl to enable.",
        )
    rules, yaml_text = build_rules_from_audit(engagement_id)
    return Response(
        content=yaml_text,
        media_type="application/x-yaml",
        headers={
            "X-Rule-Count": str(len(rules)),
            "Content-Disposition": "attachment; filename=\"revshell-academy.sigma.yml\"",
        },
    )
