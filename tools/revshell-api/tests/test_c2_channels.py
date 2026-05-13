"""Tests for the generators/c2_channels.py module (Phase A)."""
import pytest

from generators.c2_channels import (
    SUPPORTED_CHANNELS,
    C2ChannelResult,
    generate_channel,
)

LHOST = "10.10.10.10"
LPORT = 443


# ── Smoke tests — one per channel ────────────────────────────────────────────

@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_returns_result_dataclass(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert isinstance(result, C2ChannelResult)


@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_has_nonempty_implant_config(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert result.implant_config, f"{channel} implant_config is empty"


@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_has_nonempty_listener_setup(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert result.listener_setup, f"{channel} listener_setup is empty"


@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_has_nonempty_notes(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert result.notes, f"{channel} notes is empty"


@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_has_mitre_techniques(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert result.techniques, f"{channel} has no MITRE techniques"


@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_has_detections(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert result.detections, f"{channel} has no detections"


@pytest.mark.parametrize("channel", SUPPORTED_CHANNELS)
def test_channel_risk_is_valid(channel):
    result = generate_channel(channel, LHOST, LPORT)
    assert result.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}, f"{channel} risk invalid: {result.risk}"


# ── Content assertions ────────────────────────────────────────────────────────

def test_doh_c2_embeds_lhost_in_listener():
    r = generate_channel("doh_c2", LHOST, LPORT)
    assert LHOST in r.listener_setup


def test_doh_c2_custom_provider_appears():
    r = generate_channel("doh_c2", LHOST, LPORT, options={"doh_provider": "google"})
    assert "dns.google" in r.implant_config


def test_doh_c2_custom_c2_domain():
    r = generate_channel("doh_c2", LHOST, LPORT, options={"c2_domain": "evil.corp"})
    assert "evil.corp" in r.implant_config


def test_domain_fronting_cdn_host_in_config():
    r = generate_channel("domain_fronting", LHOST, LPORT, options={"cdn_host": "mycdn.example.com"})
    assert "mycdn.example.com" in r.implant_config


def test_domain_fronting_nginx_in_listener():
    r = generate_channel("domain_fronting", LHOST, LPORT)
    assert "nginx" in r.listener_setup or "server" in r.listener_setup.lower()


def test_named_pipe_c2_pipe_name_in_config():
    r = generate_channel("named_pipe_c2", LHOST, LPORT, options={"pipe_name": "custom_pipe_name"})
    assert "custom_pipe_name" in r.implant_config


def test_named_pipe_c2_lhost_in_config():
    r = generate_channel("named_pipe_c2", LHOST, LPORT)
    assert LHOST in r.implant_config


def test_icmp_tunnel_server_ip_in_config():
    r = generate_channel("icmp_tunnel", LHOST, LPORT)
    assert LHOST in r.implant_config


def test_icmp_tunnel_listener_mentions_ptunnel_or_icmpsh():
    r = generate_channel("icmp_tunnel", LHOST, LPORT)
    assert "ptunnel" in r.listener_setup or "icmpsh" in r.listener_setup


def test_websocket_c2_uri_in_config():
    r = generate_channel("websocket_c2", LHOST, LPORT)
    assert LHOST in r.implant_config
    assert "websocket" in r.implant_config.lower() or "ws" in r.implant_config


def test_websocket_c2_wss_for_443():
    r = generate_channel("websocket_c2", LHOST, 443)
    assert "wss://" in r.implant_config


def test_websocket_c2_ws_for_non_tls():
    r = generate_channel("websocket_c2", LHOST, 8080)
    assert "ws://" in r.implant_config


def test_cloud_blend_discord_no_hardcoded_token():
    r = generate_channel("cloud_blend_discord", LHOST, LPORT)
    # Token must be loaded from env, never embedded
    assert "DISCORD_BOT_TOKEN" in r.implant_config
    assert "never hardcode" in r.implant_config.lower() or "from env" in r.implant_config.lower()


def test_cloud_blend_discord_guild_id_in_config():
    r = generate_channel("cloud_blend_discord", LHOST, LPORT, options={"guild_id": "987654321"})
    assert "987654321" in r.implant_config


def test_cloud_blend_s3_bucket_in_config():
    r = generate_channel("cloud_blend_s3", LHOST, LPORT, options={"bucket": "my-ops-bucket"})
    assert "my-ops-bucket" in r.implant_config


def test_cloud_blend_s3_no_hardcoded_credentials():
    r = generate_channel("cloud_blend_s3", LHOST, LPORT)
    assert "credential_env" in r.implant_config
    assert "AWS_ACCESS_KEY_ID" in r.implant_config


def test_cloud_blend_github_gist_mode_in_config():
    r = generate_channel("cloud_blend_github", LHOST, LPORT)
    assert "gist" in r.implant_config.lower()


def test_cloud_blend_github_no_hardcoded_token():
    r = generate_channel("cloud_blend_github", LHOST, LPORT)
    assert "GITHUB_TOKEN" in r.implant_config
    assert "never" in r.implant_config.lower() or "from env" in r.implant_config.lower()


def test_unsupported_channel_raises_valueerror():
    with pytest.raises(ValueError, match="Unsupported channel"):
        generate_channel("not_a_real_channel", LHOST, LPORT)


def test_empty_options_dict_does_not_raise():
    for channel in SUPPORTED_CHANNELS:
        generate_channel(channel, LHOST, LPORT, options={})


def test_channel_field_matches_name():
    for channel in SUPPORTED_CHANNELS:
        r = generate_channel(channel, LHOST, LPORT)
        assert r.channel == channel
