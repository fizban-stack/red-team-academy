"""Audit log behavior."""
import importlib
import json

import pytest
from fastapi.testclient import TestClient


def _client_with_audit(monkeypatch, tmp_path):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG", str(log_path))
    monkeypatch.delenv("API_TOKEN", raising=False)
    import core.settings as s
    importlib.reload(s)
    import core.audit as a
    importlib.reload(a)
    for name in (
        "routers._helpers", "routers.shell", "routers.c2",
        "routers.windows_postex", "routers.linux_postex", "routers.cloud",
        "routers.webshell", "routers.initial_access", "routers.chain",
        "routers.reporting", "main",
    ):
        if name in importlib.sys.modules:
            importlib.reload(importlib.sys.modules[name])
    import main as m
    return TestClient(m.app), log_path


def test_audit_log_writes_entry(tmp_path, monkeypatch):
    client, log_path = _client_with_audit(monkeypatch, tmp_path)
    r = client.get(
        "/generate",
        params={"lhost": "10.0.0.1", "lport": 4444, "language": "bash"},
        headers={"X-Engagement-ID": "ENG-2026-001"},
    )
    assert r.status_code == 200
    assert log_path.exists()
    lines = log_path.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["module"] == "shell"
    assert record["technique"] == "bash"
    assert record["engagement_id"] == "ENG-2026-001"
    assert record["payload_sha256"]


def test_audit_redacts_secrets(tmp_path, monkeypatch):
    client, log_path = _client_with_audit(monkeypatch, tmp_path)
    client.post("/lateral", json={
        "technique": "psexec", "target": "WIN1",
        "username": "alice", "password": "Sup3rS3cret!",
        "lhost": "10.0.0.5", "lport": 8080,
    })
    record = json.loads(log_path.read_text().splitlines()[0])
    assert record["params"]["password"] == "***redacted***"


def test_engagement_id_validation_rejects_special_chars(tmp_path, monkeypatch):
    client, _ = _client_with_audit(monkeypatch, tmp_path)
    r = client.get(
        "/generate",
        params={"lhost": "10.0.0.1", "lport": 4444, "language": "bash"},
        headers={"X-Engagement-ID": "../etc/passwd"},
    )
    assert r.status_code == 422


def test_report_endpoint_renders_markdown(tmp_path, monkeypatch):
    client, _ = _client_with_audit(monkeypatch, tmp_path)
    client.get(
        "/generate",
        params={"lhost": "10.0.0.1", "lport": 4444, "language": "bash"},
        headers={"X-Engagement-ID": "ENG-001"},
    )
    r = client.get("/report", params={"engagement_id": "ENG-001"})
    assert r.status_code == 200
    assert "# Engagement report" in r.text
    assert "ENG-001" in r.text


def test_report_disabled_when_audit_log_unset(monkeypatch):
    monkeypatch.delenv("AUDIT_LOG", raising=False)
    monkeypatch.delenv("API_TOKEN", raising=False)
    import core.settings as s
    importlib.reload(s)
    import core.audit as a
    importlib.reload(a)
    for name in (
        "routers.reporting", "main",
    ):
        if name in importlib.sys.modules:
            importlib.reload(importlib.sys.modules[name])
    import main as m
    client = TestClient(m.app)
    r = client.get("/report")
    assert r.status_code == 404
