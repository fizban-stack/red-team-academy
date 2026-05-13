"""/ioc_export Sigma rule generation tests."""
import importlib
import json

import pytest
from fastapi.testclient import TestClient


def _reset_app(monkeypatch, *, audit_path: str | None):
    """Common helper — set env, reload settings + auth + audit + every router + main."""
    if audit_path is None:
        monkeypatch.delenv("AUDIT_LOG", raising=False)
    else:
        monkeypatch.setenv("AUDIT_LOG", audit_path)
    monkeypatch.delenv("API_TOKEN", raising=False)
    import core.settings as s
    importlib.reload(s)
    import core.auth as a
    importlib.reload(a)
    import core.audit as au
    importlib.reload(au)
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


@pytest.fixture
def client_with_audit(monkeypatch, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    return _reset_app(monkeypatch, audit_path=str(audit_path)), audit_path


def test_ioc_export_requires_audit_log(monkeypatch):
    client = _reset_app(monkeypatch, audit_path=None)
    r = client.get("/ioc_export")
    assert r.status_code == 404


def test_ioc_export_generates_sigma_rules(client_with_audit):
    client, _ = client_with_audit
    # Generate some events first.
    client.get("/evasion", params={"technique": "amsi_hwbp"})
    client.get("/anti_forensics", params={"technique": "clear_event_logs"})
    client.get("/sandbox_evasion", params={"technique": "sandbox_check_uptime"})

    r = client.get("/ioc_export")
    assert r.status_code == 200
    body = r.text
    assert "title: Detection" in body
    assert "amsi_hwbp" in body or "amsi-hwbp" in body
    assert "clear_event_logs" in body or "clear-event-logs" in body
    assert "logsource:" in body
    assert "detection:" in body
    # Sigma rule levels must be from the valid set.
    valid_levels = ["low", "medium", "high", "critical"]
    found_level = False
    for line in body.split("\n"):
        if line.startswith("level:"):
            value = line.split(":", 1)[1].strip()
            assert value in valid_levels
            found_level = True
    assert found_level


def test_ioc_export_filters_by_engagement_id(client_with_audit):
    client, _ = client_with_audit
    client.get("/evasion", params={"technique": "amsi_hwbp"},
               headers={"X-Engagement-ID": "ENG-A"})
    client.get("/evasion", params={"technique": "etw_hwbp"},
               headers={"X-Engagement-ID": "ENG-B"})

    a = client.get("/ioc_export", params={"engagement_id": "ENG-A"}).text
    b = client.get("/ioc_export", params={"engagement_id": "ENG-B"}).text
    assert "amsi_hwbp" in a or "amsi-hwbp" in a
    assert "amsi_hwbp" not in b and "amsi-hwbp" not in b
    assert "etw_hwbp" in b or "etw-hwbp" in b


def test_ioc_export_header_advertises_rule_count(client_with_audit):
    client, _ = client_with_audit
    client.get("/evasion", params={"technique": "amsi_hwbp"})
    client.get("/evasion", params={"technique": "etw_hwbp"})
    r = client.get("/ioc_export")
    assert r.headers.get("x-rule-count") == "2"


def test_ioc_export_empty_log_returns_placeholder(client_with_audit):
    client, _ = client_with_audit
    r = client.get("/ioc_export")
    # Empty audit log → placeholder string, not an error.
    assert r.status_code == 200
    assert "No matching audit records" in r.text
