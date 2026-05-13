"""Tests for the /stack orchestrator."""
import importlib
import os

import pytest
from fastapi.testclient import TestClient

from generators.evasion_stack import SUPPORTED_EDRS, build_stack


@pytest.fixture
def client(monkeypatch):
    """
    Other test modules reload core.settings with API_TOKEN set; we have to
    explicitly unset and reload so /stack runs without auth in these tests.
    """
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.delenv("AUDIT_LOG", raising=False)
    import core.settings as s
    importlib.reload(s)
    import core.auth as a
    importlib.reload(a)
    for name in [
        "routers._helpers", "routers.shell", "routers.c2",
        "routers.windows_postex", "routers.linux_postex", "routers.cloud",
        "routers.webshell", "routers.initial_access", "routers.evasion_extended",
        "routers.stack", "routers.chain", "routers.reporting", "main",
    ]:
        if name in importlib.sys.modules:
            importlib.reload(importlib.sys.modules[name])
    import main as m
    return TestClient(m.app)


# ── Unit tests on the builder ─────────────────────────────────────────────────

@pytest.mark.parametrize("edr", SUPPORTED_EDRS)
def test_build_stack_per_edr(edr):
    r = build_stack(edrs=edr, lhost="10.0.0.5", lport=4444,
                    shell_command="# placeholder shell")
    assert r.edr == edr
    assert r.total_steps > 0
    assert r.chain
    # Every chain must include the payload step.
    shell_steps = [e for e in r.chain if e.module == "shell"]
    assert len(shell_steps) == 1, f"{edr} stack should have exactly one shell step"


def test_build_stack_rejects_unknown_edr():
    with pytest.raises(ValueError):
        build_stack(edrs="acme-magic-edr", lhost="10.0.0.5", lport=4444)


def test_build_stack_deterministic_order():
    a = build_stack(edrs="defender", lhost="10.0.0.5", lport=4444, shell_command="X")
    b = build_stack(edrs="defender", lhost="10.0.0.5", lport=4444, shell_command="X")
    assert [e.technique for e in a.chain] == [e.technique for e in b.chain]


def test_build_stack_skips_anti_forensics_when_disabled():
    r = build_stack(edrs="generic", lhost="10.0.0.5", lport=4444,
                    include_anti_forensics=False, shell_command="X")
    assert not any(e.module == "anti_forensics" for e in r.chain)


def test_build_stack_skips_sandbox_evasion_when_disabled():
    r = build_stack(edrs="generic", lhost="10.0.0.5", lport=4444,
                    include_sandbox_evasion=False, shell_command="X")
    assert not any(e.module == "sandbox_evasion" for e in r.chain)


def test_build_stack_orders_sandbox_first_payload_middle_cleanup_last():
    r = build_stack(edrs="defender", lhost="10.0.0.5", lport=4444, shell_command="X")
    modules = [e.module for e in r.chain]
    shell_idx = modules.index("shell")
    # Every sandbox check should come before the shell.
    for i, m in enumerate(modules):
        if m == "sandbox_evasion":
            assert i < shell_idx, "sandbox_evasion must come before shell payload"
    # Every anti_forensics step should come after the shell.
    for i, m in enumerate(modules):
        if m == "anti_forensics":
            assert i > shell_idx, "anti_forensics must come after shell payload"


def test_each_entry_has_nonempty_rationale():
    r = build_stack(edrs="crowdstrike", lhost="10.0.0.5", lport=4444, shell_command="X")
    for e in r.chain:
        assert e.rationale, f"step {e.step} ({e.technique}) has empty rationale"


# ── End-to-end API tests ──────────────────────────────────────────────────────

def test_stack_endpoint_defender(client):
    r = client.post("/stack", json={
        "edr": "defender", "lhost": "10.0.0.5", "lport": 4444,
        "language": "powershell",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["edr"] == "defender"
    assert body["total_steps"] >= 5
    assert any(s["module"] == "shell" for s in body["chain"])
    assert "nc" in body["listener"]


def test_stack_endpoint_rejects_invalid_edr(client):
    r = client.post("/stack", json={
        "edr": "made-up-edr", "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 422


def test_stack_endpoint_rejects_lhost_injection(client):
    r = client.post("/stack", json={
        "edr": "generic", "lhost": "10.0.0.5;rm -rf /", "lport": 4444,
    })
    assert r.status_code == 422


def test_stack_endpoint_supports_seed_for_reproducibility(client):
    body = {"edr": "generic", "lhost": "10.0.0.5", "lport": 4444,
            "language": "powershell", "seed": 42}
    a = client.post("/stack", json=body).json()
    b = client.post("/stack", json=body).json()
    a_shell = next(s for s in a["chain"] if s["module"] == "shell")
    b_shell = next(s for s in b["chain"] if s["module"] == "shell")
    assert a_shell["command"] == b_shell["command"]


def test_stack_endpoint_include_flags(client):
    r = client.post("/stack", json={
        "edr": "generic", "lhost": "10.0.0.5", "lport": 4444,
        "include_anti_forensics": False, "include_sandbox_evasion": False,
    })
    assert r.status_code == 200
    chain = r.json()["chain"]
    assert not any(s["module"] in {"anti_forensics", "sandbox_evasion"} for s in chain)
