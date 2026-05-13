"""Multi-EDR /stack tests."""
import importlib

import pytest
from fastapi.testclient import TestClient

from generators.evasion_stack import build_stack


@pytest.fixture
def client(monkeypatch):
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
        "routers.stack", "routers.recommend", "routers.ioc",
        "routers.chain", "routers.reporting", "main",
    ]:
        if name in importlib.sys.modules:
            importlib.reload(importlib.sys.modules[name])
    import main as m
    return TestClient(m.app)


# ── Builder-level tests ───────────────────────────────────────────────────────

def test_builder_accepts_single_edr_string_for_backcompat():
    r = build_stack(edrs="defender", lhost="10.0.0.5", lport=4444, shell_command="X")
    assert r.total_steps > 0


def test_builder_multi_edr_dedupes_techniques():
    """Techniques shared across profiles must appear once with merged counters."""
    r = build_stack(
        edrs=["defender", "sentinelone"],
        lhost="10.0.0.5", lport=4444, shell_command="X",
    )
    techniques = [e.technique for e in r.chain]
    assert len(techniques) == len(set(techniques)), "duplicates in merged stack"


def test_builder_multi_edr_records_counters():
    r = build_stack(
        edrs=["defender", "crowdstrike", "sentinelone"],
        lhost="10.0.0.5", lport=4444, shell_command="X",
    )
    # Every step lists at least one EDR it counters.
    for entry in r.chain:
        assert entry.counters, f"step {entry.step} has empty counters"
        assert all(c in {"defender", "crowdstrike", "sentinelone"} for c in entry.counters)


def test_builder_rejects_empty_list():
    with pytest.raises(ValueError):
        build_stack(edrs=[], lhost="10.0.0.5", lport=4444)


def test_builder_rejects_unknown_edr_in_list():
    with pytest.raises(ValueError):
        build_stack(edrs=["defender", "lol-nope"], lhost="10.0.0.5", lport=4444)


def test_builder_multi_edr_section_ordering_preserved():
    """sandbox → evasion → shell → anti_forensics."""
    r = build_stack(
        edrs=["defender", "crowdstrike"],
        lhost="10.0.0.5", lport=4444, shell_command="X",
    )
    section_order = {"sandbox_evasion": 0, "evasion": 1, "shell": 2, "anti_forensics": 3}
    seen_order = [section_order[e.module] for e in r.chain]
    assert seen_order == sorted(seen_order), f"sections out of order: {seen_order}"


def test_builder_multi_edr_more_steps_than_single():
    """Defender + CrowdStrike combined must have ≥ max(individual) steps."""
    d = build_stack(edrs=["defender"], lhost="10.0.0.5", lport=4444, shell_command="X")
    c = build_stack(edrs=["crowdstrike"], lhost="10.0.0.5", lport=4444, shell_command="X")
    combo = build_stack(edrs=["defender", "crowdstrike"], lhost="10.0.0.5", lport=4444, shell_command="X")
    assert combo.total_steps >= max(d.total_steps, c.total_steps)


# ── API-level tests ───────────────────────────────────────────────────────────

def test_api_accepts_edrs_list(client):
    r = client.post("/stack", json={
        "edrs": ["defender", "crowdstrike"],
        "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["edr"] == "defender,crowdstrike"
    assert body["total_steps"] >= 8
    assert all(s["counters"] for s in body["chain"])


def test_api_legacy_single_edr_still_works(client):
    r = client.post("/stack", json={
        "edr": "defender", "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["edr"] == "defender"


def test_api_rejects_when_neither_edr_nor_edrs(client):
    r = client.post("/stack", json={"lhost": "10.0.0.5", "lport": 4444})
    assert r.status_code == 422


def test_api_rejects_empty_edrs_list(client):
    r = client.post("/stack", json={
        "edrs": [], "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 422


def test_api_full_combo_works(client):
    r = client.post("/stack", json={
        "edrs": ["defender", "crowdstrike", "sentinelone", "carbonblack"],
        "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["total_steps"] >= 12
    assert "Multi-EDR stack" in body["summary"]
