"""
/c2_channel — modern C2 transport channel profiles.

GET  /c2_channel           — list supported channels
POST /c2_channel           — generate implant config + listener setup for a channel
GET  /c2_channel/{channel} — quick single-channel fetch (lhost/lport as query params)

For authorized use on systems you own or have explicit written permission to test.
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from core.auth import require_token
from core.schemas import C2ChannelRequest, C2ChannelResponse
from core.validation import validate_lhost
from generators.c2_channels import SUPPORTED_CHANNELS, generate_channel

from ._helpers import audit

router = APIRouter(prefix="/c2_channel", tags=["c2_channel"], dependencies=[Depends(require_token)])


@router.get("")
def list_channels():
    """List all supported C2 transport channels."""
    return {"channels": list(SUPPORTED_CHANNELS)}


@router.post("", response_model=C2ChannelResponse)
def create_channel(
    req: C2ChannelRequest,
    request: Request,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """Generate implant config and listener setup for a C2 transport channel."""
    try:
        result = generate_channel(
            channel=req.channel,
            lhost=req.lhost,
            lport=req.lport,
            options=req.options,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit(request, "c2_channel", req.channel, req.model_dump(), result.implant_config, x_engagement_id)

    return C2ChannelResponse(
        channel=result.channel,
        implant_config=result.implant_config,
        listener_setup=result.listener_setup,
        notes=result.notes,
        techniques=result.techniques,
        risk=result.risk,
        detections=result.detections,
    )


@router.get("/{channel}", response_model=C2ChannelResponse)
def get_channel(
    channel: str,
    request: Request,
    lhost: str = "192.168.1.100",
    lport: int = 443,
    x_engagement_id: Annotated[str | None, Header(alias="X-Engagement-ID")] = None,
):
    """Quick GET variant — lhost/lport as query params, no body required."""
    if channel not in SUPPORTED_CHANNELS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported channel '" + channel + "'. Supported: " + ", ".join(SUPPORTED_CHANNELS),
        )
    try:
        lhost = validate_lhost(lhost)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = generate_channel(channel=channel, lhost=lhost, lport=lport)
    audit(request, "c2_channel", channel, {"channel": channel, "lhost": lhost, "lport": lport}, result.implant_config, x_engagement_id)

    return C2ChannelResponse(
        channel=result.channel,
        implant_config=result.implant_config,
        listener_setup=result.listener_setup,
        notes=result.notes,
        techniques=result.techniques,
        risk=result.risk,
        detections=result.detections,
    )
