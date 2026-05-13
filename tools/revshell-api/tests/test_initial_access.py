"""
Tests for v4.5 initial access techniques (ISC-17 through ISC-28).
All 8 new generators: clickfix, search_ms_webdav, url_ntlm_capture, xll_addin,
svg_phishing, chm_dropper, teams_phishing, msix_installer.
"""
import pytest
from generators.initial_access import generate_initial_access, SUPPORTED_TECHNIQUES

NEW_TECHNIQUES = [
    "clickfix",
    "search_ms_webdav",
    "url_ntlm_capture",
    "xll_addin",
    "svg_phishing",
    "chm_dropper",
    "teams_phishing",
    "msix_installer",
]

LHOST = "10.10.10.10"
LPORT = 4444


# ── ISC-17: parametrized smoke — all techniques return non-empty payload ──────

@pytest.mark.parametrize("technique", NEW_TECHNIQUES)
def test_smoke_non_empty_payload(technique):
    result = generate_initial_access(technique, LHOST, LPORT, False)
    assert result.payload, f"{technique}: payload is empty"


# ── ISC-18: parametrized — all have MITRE techniques list ────────────────────

@pytest.mark.parametrize("technique", NEW_TECHNIQUES)
def test_has_mitre_techniques(technique):
    result = generate_initial_access(technique, LHOST, LPORT, False)
    assert result.techniques, f"{technique}: techniques list is empty"
    assert len(result.techniques) >= 1


# ── ISC-19: parametrized — all have detections list ──────────────────────────

@pytest.mark.parametrize("technique", NEW_TECHNIQUES)
def test_has_detections(technique):
    result = generate_initial_access(technique, LHOST, LPORT, False)
    assert result.detections, f"{technique}: detections list is empty"
    assert len(result.detections) >= 3


# ── ISC-20: parametrized — all have delivery_hint ────────────────────────────

@pytest.mark.parametrize("technique", NEW_TECHNIQUES)
def test_has_delivery_hint(technique):
    result = generate_initial_access(technique, LHOST, LPORT, False)
    assert result.delivery_hint, f"{technique}: delivery_hint is empty"
    assert len(result.delivery_hint) > 10


# ── ISC-21: clickfix — payload contains clipboard / powershell / Win+R ───────

def test_clickfix_payload_content():
    result = generate_initial_access("clickfix", LHOST, LPORT, False)
    payload_lower = result.payload.lower()
    assert any(
        kw in payload_lower
        for kw in ("clipboard", "powershell", "win", "ctrl+v")
    ), "clickfix payload missing clipboard/powershell/Win+R instruction"


def test_clickfix_obfuscated_uses_encoded_command():
    result = generate_initial_access("clickfix", LHOST, LPORT, True)
    assert "EncodedCommand" in result.payload or "encodedcommand" in result.payload.lower()


# ── ISC-22: search_ms_webdav — payload contains search-ms:// URI ─────────────

def test_search_ms_webdav_payload_contains_uri():
    result = generate_initial_access("search_ms_webdav", LHOST, LPORT, False)
    assert "search-ms:" in result.payload


def test_search_ms_webdav_contains_lhost():
    result = generate_initial_access("search_ms_webdav", LHOST, LPORT, False)
    assert LHOST in result.payload


# ── ISC-23: url_ntlm_capture — payload contains UNC path (\\) ────────────────

def test_url_ntlm_capture_contains_unc():
    result = generate_initial_access("url_ntlm_capture", LHOST, LPORT, False)
    assert "\\\\" in result.payload or "UNC" in result.payload or "IconFile" in result.payload


def test_url_ntlm_capture_contains_lhost():
    result = generate_initial_access("url_ntlm_capture", LHOST, LPORT, False)
    assert LHOST in result.payload


# ── ISC-24: xll_addin — payload contains xlAutoOpen or XLL ──────────────────

def test_xll_addin_payload_contains_xlautoopen():
    result = generate_initial_access("xll_addin", LHOST, LPORT, False)
    assert "xlAutoOpen" in result.payload or "XLL" in result.payload


def test_xll_addin_payload_contains_c_code():
    result = generate_initial_access("xll_addin", LHOST, LPORT, False)
    assert "#include" in result.payload or "XLOPER" in result.payload


# ── ISC-25: svg_phishing — payload contains <svg or SVG ─────────────────────

def test_svg_phishing_payload_contains_svg():
    result = generate_initial_access("svg_phishing", LHOST, LPORT, False)
    assert "<svg" in result.payload or "SVG" in result.payload


def test_svg_phishing_obfuscated_uses_base64():
    result = generate_initial_access("svg_phishing", LHOST, LPORT, True)
    assert "base64" in result.payload.lower() or "atob" in result.payload


# ── ISC-26: chm_dropper — payload contains hh.exe or ShortCut or OBJECT ─────

def test_chm_dropper_payload_contains_hh():
    result = generate_initial_access("chm_dropper", LHOST, LPORT, False)
    assert any(
        kw in result.payload
        for kw in ("hh.exe", "ShortCut", "OBJECT", "adb880a6")
    ), "chm_dropper payload missing expected CHM-related content"


def test_chm_dropper_payload_contains_lhost():
    result = generate_initial_access("chm_dropper", LHOST, LPORT, False)
    assert LHOST in result.payload


# ── ISC-27: teams_phishing — payload mentions Teams ─────────────────────────

def test_teams_phishing_mentions_teams():
    result = generate_initial_access("teams_phishing", LHOST, LPORT, False)
    assert "Teams" in result.payload or "teams" in result.payload.lower()


def test_teams_phishing_has_multiple_techniques():
    result = generate_initial_access("teams_phishing", LHOST, LPORT, False)
    assert len(result.techniques) >= 2


# ── ISC-28: msix_installer — payload contains .msix or AppInstaller ─────────

def test_msix_installer_payload_contains_msix():
    result = generate_initial_access("msix_installer", LHOST, LPORT, False)
    assert ".msix" in result.payload or "AppInstaller" in result.payload or "ms-appinstaller" in result.payload


def test_msix_installer_payload_contains_manifest():
    result = generate_initial_access("msix_installer", LHOST, LPORT, False)
    assert "AppxManifest" in result.payload or "Publisher" in result.payload


# ── Additional: SUPPORTED_TECHNIQUES includes all new entries ────────────────

def test_supported_techniques_includes_all_new():
    for t in NEW_TECHNIQUES:
        assert t in SUPPORTED_TECHNIQUES, f"{t} missing from SUPPORTED_TECHNIQUES"


# ── Additional: obfuscate=True still returns valid results ───────────────────

@pytest.mark.parametrize("technique", NEW_TECHNIQUES)
def test_obfuscate_true_returns_result(technique):
    result = generate_initial_access(technique, LHOST, LPORT, True)
    assert result.payload
    assert result.technique == technique
