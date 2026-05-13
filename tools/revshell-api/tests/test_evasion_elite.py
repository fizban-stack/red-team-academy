"""Tests for the v4.3 elite evasion techniques + /stack orchestrator."""
import pytest

from generators.evasion import SUPPORTED_TECHNIQUES, generate_evasion

# The 12 v4.3 additions.
ELITE_TECHNIQUES = (
    "rop_sleep",
    "set_windows_hook_loader",
    "com_rot_injection",
    "environment_keying",
    "in_memory_pe_loader",
    "dll_sideload",
    "apc_injection",
    "early_bird_apc",
    "heaven_gate",
    "process_ghosting",
    "process_doppelganging",
    "process_herpaderping",
)


def test_all_elite_techniques_registered():
    missing = set(ELITE_TECHNIQUES) - set(SUPPORTED_TECHNIQUES)
    assert not missing, f"Missing elite techniques: {missing}"


@pytest.mark.parametrize("tech", ELITE_TECHNIQUES)
def test_elite_technique_produces_full_metadata(tech):
    r = generate_evasion(tech, lhost="10.0.0.5", lport=4444)
    assert r.command, f"{tech} empty command"
    assert r.technique == tech
    assert r.notes
    assert r.techniques, f"{tech} no MITRE T-IDs"
    assert r.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert r.detections, f"{tech} no detections list"


def test_rop_sleep_mentions_ntcontinue():
    r = generate_evasion("rop_sleep")
    assert "NtContinue" in r.command
    assert r.risk == "CRITICAL"


def test_set_windows_hook_threads_lhost():
    r = generate_evasion("set_windows_hook_loader", lhost="10.0.0.99", lport=8888)
    assert "10.0.0.99" in r.command
    assert "8888" in r.command


def test_environment_keying_uses_machine_facts():
    r = generate_evasion("environment_keying")
    assert "Win32_BIOS" in r.command
    assert "SHA256" in r.command or "SHA-256" in r.command


def test_in_memory_pe_loader_mentions_assembly_load():
    r = generate_evasion("in_memory_pe_loader")
    assert "Assembly.Load" in r.command


def test_dll_sideload_lists_known_vectors():
    r = generate_evasion("dll_sideload", lhost="10.0.0.5", lport=4444)
    assert "OneDrive" in r.command
    assert "hijacklibs" in r.command


def test_apc_injection_mentions_nt_queue_apc():
    r = generate_evasion("apc_injection", lhost="10.0.0.5", lport=4444)
    assert "NtQueueApcThread" in r.command


def test_early_bird_apc_creates_suspended_process():
    r = generate_evasion("early_bird_apc", lhost="10.0.0.5", lport=4444)
    assert "CREATE_SUSPENDED" in r.command or "SUSPENDED" in r.command


def test_heaven_gate_mentions_long_mode_selector():
    r = generate_evasion("heaven_gate")
    assert "0x33" in r.command


def test_process_ghosting_describes_section_lifecycle():
    r = generate_evasion("process_ghosting")
    assert "NtCreateSection" in r.command


def test_process_doppelganging_uses_transaction():
    r = generate_evasion("process_doppelganging")
    assert "Transaction" in r.command
    assert "RollbackTransaction" in r.command


def test_process_herpaderping_writes_after_section():
    r = generate_evasion("process_herpaderping")
    assert "NtCreateSection" in r.command
    assert "WriteFile" in r.command or "SetFilePointer" in r.command
