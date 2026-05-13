"""Tests for the v4.5 advanced tradecraft techniques (Phase B)."""
import pytest

from generators.evasion import SUPPORTED_TECHNIQUES, generate_evasion

V45_TECHNIQUES = (
    "call_stack_desync",
    "byovd",
    "dll_redirection",
    "peb_imagepath_spoof",
)


def test_all_v45_techniques_registered():
    missing = set(V45_TECHNIQUES) - set(SUPPORTED_TECHNIQUES)
    assert not missing, f"Missing v4.5 techniques: {missing}"


@pytest.mark.parametrize("tech", V45_TECHNIQUES)
def test_v45_technique_returns_nonempty_command(tech):
    r = generate_evasion(tech, lhost="10.0.0.5", lport=4444)
    assert r.command, f"{tech} returned empty command"


@pytest.mark.parametrize("tech", V45_TECHNIQUES)
def test_v45_technique_has_mitre_ids(tech):
    r = generate_evasion(tech)
    assert r.techniques, f"{tech} has no MITRE techniques"
    for t in r.techniques:
        assert "T" in t, f"{tech} MITRE entry '{t}' doesn't look like a T-ID"


@pytest.mark.parametrize("tech", V45_TECHNIQUES)
def test_v45_technique_has_detections(tech):
    r = generate_evasion(tech)
    assert r.detections, f"{tech} has no detections"
    assert len(r.detections) >= 2, f"{tech} has fewer than 2 detections"


@pytest.mark.parametrize("tech", V45_TECHNIQUES)
def test_v45_technique_risk_valid(tech):
    r = generate_evasion(tech)
    assert r.risk in {"HIGH", "CRITICAL"}, f"{tech} risk '{r.risk}' unexpected for advanced tradecraft"


@pytest.mark.parametrize("tech", V45_TECHNIQUES)
def test_v45_technique_name_matches(tech):
    r = generate_evasion(tech)
    assert r.technique == tech


# ── Content-level assertions ──────────────────────────────────────────────────

def test_call_stack_desync_mentions_syscall():
    r = generate_evasion("call_stack_desync")
    assert "syscall" in r.command.lower()


def test_call_stack_desync_mentions_cfg_or_callstack():
    r = generate_evasion("call_stack_desync")
    assert "CFG" in r.command or "callstack" in r.command.lower() or "stack" in r.command.lower()


def test_byovd_mentions_driver():
    r = generate_evasion("byovd")
    assert "driver" in r.command.lower() or "sys" in r.command.lower()


def test_byovd_mentions_ioctl_or_exploit():
    r = generate_evasion("byovd")
    assert "IOCTL" in r.command or "exploit" in r.command.lower() or "kernel" in r.command.lower()


def test_dll_redirection_mentions_local_or_sxs():
    r = generate_evasion("dll_redirection")
    assert ".local" in r.command or "SxS" in r.command or "manifest" in r.command.lower()


def test_dll_redirection_mentions_dll():
    r = generate_evasion("dll_redirection")
    assert "dll" in r.command.lower() or "DLL" in r.command


def test_peb_imagepath_spoof_mentions_peb():
    r = generate_evasion("peb_imagepath_spoof")
    assert "PEB" in r.command or "peb" in r.command.lower()


def test_peb_imagepath_spoof_mentions_imagepath():
    r = generate_evasion("peb_imagepath_spoof")
    assert "ImagePathName" in r.command or "ImagePath" in r.command


def test_total_technique_count_is_at_least_53():
    assert len(SUPPORTED_TECHNIQUES) >= 53, (
        f"Expected at least 53 techniques, got {len(SUPPORTED_TECHNIQUES)}"
    )
