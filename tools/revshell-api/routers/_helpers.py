"""Shared router helpers — request → audit → response plumbing."""
from typing import Any

from fastapi import Header, Request

from core.audit import log_event
from core.validation import assert_engagement_id


def _client_ip(request: Request) -> str | None:
    if not request:
        return None
    return request.client.host if request.client else None


def audit(
    request: Request,
    module: str,
    technique: str,
    params: dict,
    payload: str,
    x_engagement_id: str | None,
) -> None:
    """Log a generation event. No-op when audit log disabled."""
    log_event(
        route=str(request.url.path) if request else "",
        module=module,
        technique=technique,
        params=params,
        payload=payload,
        engagement_id=assert_engagement_id(x_engagement_id),
        client_ip=_client_ip(request),
    )


EngagementHeader = Header(default=None, alias="X-Engagement-ID", description="Optional engagement tag for audit logging.")
