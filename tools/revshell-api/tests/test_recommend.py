"""/recommend constraint solver tests."""
import importlib

import pytest
from fastapi.testclient import TestClient

from generators.recommender import recommend


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.delenv("AUDIT_LOG", raising=False)
    import core.settings as s
    importlib.reload(s)
    import core.auth as a
    importlib.reload(a)
    for name in ["routers.recommend", "main"]:
        if name in importlib.sys.modules:
            importlib.reload(importlib.sys.modules[name])
    import main as m
    return TestClient(m.app)


# ── Unit tests ────────────────────────────────────────────────────────────────

def test_default_constraints_returns_something():
    r = recommend()
    assert r.total > 0
    assert r.recommendations[0].technique


def test_target_edrs_filters_to_works_against():
    r = recommend(target_edrs=["crowdstrike"], max_techniques=20)
    # Every recommendation must be effective against crowdstrike.
    for rec in r.recommendations:
        assert "crowdstrike" in rec.counters


def test_target_edrs_excludes_breaks_under():
    """Process hollowing breaks under crowdstrike — should never be recommended for it."""
    r = recommend(target_edrs=["crowdstrike"], max_techniques=50)
    techniques = {rec.technique for rec in r.recommendations}
    assert "process_hollowing" not in techniques
    assert "amsi_patch_clr" not in techniques  # also breaks under crowdstrike+defender


def test_amsi_blocking_prefers_patchless():
    """When AMSI is blocking, amsi_hwbp should rank highly."""
    r = recommend(blocks_amsi=True, max_techniques=5)
    technique_names = [rec.technique for rec in r.recommendations]
    assert "amsi_hwbp" in technique_names


def test_family_filter():
    r = recommend(families=["hardening"], max_techniques=20)
    for rec in r.recommendations:
        assert rec.family == "hardening"


def test_deterministic_for_fixed_constraints():
    a = recommend(target_edrs=["defender"], max_techniques=5)
    b = recommend(target_edrs=["defender"], max_techniques=5)
    assert [r.technique for r in a.recommendations] == [r.technique for r in b.recommendations]


def test_max_techniques_caps_output():
    r = recommend(max_techniques=3)
    assert r.total == 3


# ── API tests ─────────────────────────────────────────────────────────────────

def test_api_recommend_defaults(client):
    r = client.post("/recommend", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] > 0
    assert body["recommendations"][0]["technique"]


def test_api_recommend_crowdstrike(client):
    r = client.post("/recommend", json={
        "target_edrs": ["crowdstrike"],
        "has_callstack_inspection": True,
        "has_userland_hooks": True,
    })
    assert r.status_code == 200
    body = r.json()
    names = [rec["technique"] for rec in body["recommendations"]]
    # CrowdStrike's strong points are callstack + hooks — indirect_syscalls
    # bypasses both and works_against crowdstrike, so it should appear.
    assert "indirect_syscalls" in names


def test_api_recommend_invalid_edr(client):
    r = client.post("/recommend", json={"target_edrs": ["fictional-edr"]})
    assert r.status_code == 422


def test_api_recommend_no_admin_filters_results(client):
    r = client.post("/recommend", json={"has_admin": False})
    # Should still return some — the catalog has no admin-required entries yet,
    # but the response must be well-formed.
    assert r.status_code == 200
    assert r.json()["total"] > 0
