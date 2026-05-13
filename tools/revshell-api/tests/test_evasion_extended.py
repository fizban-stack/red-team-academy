"""
Smoke tests for the expanded evasion catalog + new anti-forensics +
sandbox-evasion modules.
"""
import pytest

from generators.anti_forensics import SUPPORTED_TECHNIQUES as AF_TECHNIQUES, generate_anti_forensics
from generators.evasion import SUPPORTED_TECHNIQUES as EVASION_TECHNIQUES, generate_evasion
from generators.sandbox_evasion import SUPPORTED_TECHNIQUES as SBX_TECHNIQUES, generate_sandbox_evasion


# ── Evasion catalog growth ────────────────────────────────────────────────────

def test_evasion_catalog_includes_new_techniques():
    """v4.2 must include the modern tradecraft additions."""
    required = {
        "amsi_hwbp", "etw_hwbp", "amsi_provider_unregister", "amsi_wldp_downgrade",
        "direct_syscalls", "indirect_syscalls", "ntdll_unhook",
        "sleep_obfuscation_ekko",
        "ppid_spoof", "process_hollowing", "module_stomping", "thread_hijack",
        "lolbas_msbuild", "lolbas_installutil", "lolbas_cmstp",
        "lolbas_msxsl", "lolbas_wmic_xsl", "lolbas_syncappv", "lolbas_pubprn",
    }
    missing = required - set(EVASION_TECHNIQUES)
    assert not missing, f"Missing new evasion techniques: {missing}"


@pytest.mark.parametrize("tech", EVASION_TECHNIQUES)
def test_every_evasion_technique_produces_output(tech):
    r = generate_evasion(tech, lhost="10.0.0.5", lport=4444)
    assert r.command, f"{tech} produced empty command"
    assert r.technique == tech
    assert r.notes, f"{tech} has no notes"
    assert r.techniques, f"{tech} has no MITRE T-IDs"
    assert r.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert r.detections, f"{tech} has no detections list"


def test_lolbas_msbuild_threads_lhost():
    r = generate_evasion("lolbas_msbuild", lhost="10.10.10.10", lport=9999)
    assert "10.10.10.10" in r.command
    assert "9999" in r.command


def test_ppid_spoof_outputs_powershell():
    r = generate_evasion("ppid_spoof")
    assert r.command.startswith("powershell")
    assert "OpenProcess" in r.command


def test_amsi_hwbp_outputs_hardware_breakpoint_code():
    r = generate_evasion("amsi_hwbp")
    assert "amsi.dll" in r.command.lower()
    assert "AmsiScanBuffer" in r.command


# ── Anti-forensics ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("tech", AF_TECHNIQUES)
def test_every_anti_forensics_technique_produces_output(tech):
    r = generate_anti_forensics(tech)
    assert r.command
    assert r.technique == tech
    assert r.techniques
    assert r.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert r.detections


def test_clear_event_logs_mentions_wevtutil():
    r = generate_anti_forensics("clear_event_logs")
    assert "wevtutil" in r.command


def test_time_stomp_uses_kernel32_as_reference():
    r = generate_anti_forensics("time_stomp", target="C:\\Windows\\Temp\\x.exe")
    assert "kernel32" in r.command
    assert "C:\\Windows\\Temp\\x.exe" in r.command


def test_self_delete_is_csharp_stub():
    r = generate_anti_forensics("self_delete")
    assert "SetFileInformationByHandle" in r.command
    assert "FileDispositionInfo" in r.command


def test_anti_forensics_rejects_unknown_technique():
    with pytest.raises(ValueError):
        generate_anti_forensics("not-a-real-technique")


# ── Sandbox evasion ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("tech", SBX_TECHNIQUES)
def test_every_sandbox_evasion_technique_produces_output(tech):
    r = generate_sandbox_evasion(tech)
    assert r.command
    assert r.technique == tech
    assert r.techniques
    assert r.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_sandbox_check_ram_uses_explicit_threshold():
    r = generate_sandbox_evasion("sandbox_check_ram", threshold=16)
    assert "16" in r.command


def test_sandbox_time_delay_uses_explicit_seconds():
    r = generate_sandbox_evasion("sandbox_time_delay", threshold=300)
    assert "300" in r.command


def test_sandbox_check_user_interaction_loads_winforms():
    # Obfuscation inserts backticks into keywords; test the un-obfuscated form
    # since this test asserts API surface, not obfuscation behavior.
    r = generate_sandbox_evasion("sandbox_check_user_interaction", obfuscate=False)
    assert "System.Windows.Forms" in r.command
    assert "Cursor" in r.command


def test_sandbox_evasion_rejects_unknown_technique():
    with pytest.raises(ValueError):
        generate_sandbox_evasion("not-real")
