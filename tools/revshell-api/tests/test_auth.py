"""Bearer-token auth enforcement."""
import importlib

import pytest
from fastapi.testclient import TestClient


def _client_with_token(monkeypatch, token: str | None):
    """Reload core.settings + main with the supplied API_TOKEN env value."""
    if token is None:
        monkeypatch.delenv("API_TOKEN", raising=False)
    else:
        monkeypatch.setenv("API_TOKEN", token)
    import core.settings as settings_mod
    importlib.reload(settings_mod)
    import core.auth as auth_mod
    importlib.reload(auth_mod)
    # Reload routers + main so the new dependency is picked up.
    for name in (
        "routers.shell", "routers.c2", "routers.windows_postex",
        "routers.linux_postex", "routers.cloud", "routers.webshell",
        "routers.initial_access", "routers.chain", "routers.reporting",
        "main",
    ):
        if name in importlib.sys.modules:
            importlib.reload(importlib.sys.modules[name])
    import main as main_mod
    return TestClient(main_mod.app)


def test_auth_disabled_when_no_token(monkeypatch):
    client = _client_with_token(monkeypatch, None)
    r = client.get("/languages")
    assert r.status_code == 200


def test_auth_required_when_token_set(monkeypatch):
    client = _client_with_token(monkeypatch, "secret-123")
    r = client.get("/languages")
    assert r.status_code == 401


def test_auth_accepts_correct_token(monkeypatch):
    client = _client_with_token(monkeypatch, "secret-123")
    r = client.get("/languages", headers={"Authorization": "Bearer secret-123"})
    assert r.status_code == 200


def test_auth_rejects_wrong_token(monkeypatch):
    client = _client_with_token(monkeypatch, "secret-123")
    r = client.get("/languages", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_auth_rejects_non_bearer_scheme(monkeypatch):
    client = _client_with_token(monkeypatch, "secret-123")
    r = client.get("/languages", headers={"Authorization": "Basic secret-123"})
    assert r.status_code == 401
