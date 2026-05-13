"""Tests for the v4.4 frontier evasion techniques."""
import pytest

from generators.evasion import SUPPORTED_TECHNIQUES, generate_evasion

FRONTIER_TECHNIQUES = (
    "peb_unlink",
    "phantom_dll_hollow",
    "threadless_injection",
    "stack_spoof",
    "manual_map_header_erase",
    "function_level_encryption",
)


def test_all_frontier_techniques_registered():
    missing = set(FRONTIER_TECHNIQUES) - set(SUPPORTED_TECHNIQUES)
    assert not missing, f"Missing frontier techniques: {missing}"


@pytest.mark.parametrize("tech", FRONTIER_TECHNIQUES)
def test_frontier_technique_emits_full_metadata(tech):
    r = generate_evasion(tech, lhost="10.0.0.5", lport=4444)
    assert r.command
    assert r.technique == tech
    assert r.techniques
    assert r.risk in {"HIGH", "CRITICAL"}
    assert r.detections


def test_peb_unlink_walks_ldr_lists():
    r = generate_evasion("peb_unlink")
    assert "PEB" in r.command
    assert "Ldr" in r.command or "InMemoryOrder" in r.command


def test_phantom_dll_hollow_uses_section():
    r = generate_evasion("phantom_dll_hollow")
    assert "NtCreateSection" in r.command


def test_threadless_injection_threads_lhost():
    r = generate_evasion("threadless_injection", lhost="172.16.0.5", lport=9999)
    assert "172.16.0.5" in r.command
    assert "9999" in r.command


def test_stack_spoof_mentions_rsp():
    r = generate_evasion("stack_spoof")
    assert "RSP" in r.command or "rsp" in r.command


def test_manual_map_header_erase_zeroes_headers():
    r = generate_evasion("manual_map_header_erase")
    assert "sizeOfHeaders" in r.command
    assert "memset" in r.command or "zero" in r.command.lower()


def test_function_level_encryption_describes_decrypt_cycle():
    r = generate_evasion("function_level_encryption")
    assert "decrypt" in r.command.lower()
    assert "encrypt" in r.command.lower()
