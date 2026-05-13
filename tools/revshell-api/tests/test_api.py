"""End-to-end API tests using FastAPI's TestClient."""
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "ok"
    assert j["version"]


def test_languages():
    r = client.get("/languages")
    assert r.status_code == 200
    assert "bash" in r.json()["languages"]


def test_generate_get_bash():
    r = client.get("/generate", params={
        "lhost": "10.0.0.1", "lport": 4444, "language": "bash",
        "obfuscate": False, "seed": 42,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "10.0.0.1" in body["command"]


def test_generate_get_rejects_command_injection_in_lhost():
    r = client.get("/generate", params={
        "lhost": "10.0.0.1;rm -rf /", "lport": 4444, "language": "bash",
    })
    assert r.status_code == 422


def test_generate_post_validates_unknown_language():
    r = client.post("/generate", json={
        "lhost": "10.0.0.1", "lport": 4444, "language": "not-real",
    })
    assert r.status_code == 422


def test_generate_seed_is_deterministic():
    params = {"lhost": "10.0.0.1", "lport": 4444, "language": "powershell", "seed": 99}
    a = client.get("/generate", params=params).json()
    b = client.get("/generate", params=params).json()
    assert a["command"] == b["command"]


def test_persist_get_returns_mitre_metadata():
    r = client.get("/persist", params={"technique": "run_key"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "T1547.001" in body["techniques"]
    assert body["risk"] in {"HIGH", "MEDIUM", "CRITICAL"}
    assert body["detections"]


def test_lateral_includes_lhost_in_psexec():
    r = client.get("/lateral", params={
        "technique": "psexec", "target": "WIN01", "command": "whoami",
        "username": "alice", "password": "Pass1!",
        "lhost": "10.0.0.5", "lport": 8080,
    })
    assert r.status_code == 200
    body = r.json()
    assert "10.0.0.5" in body["command"]
    assert "ATTACKER" not in body["command"]  # the bug we fixed


def test_evasion_certutil_threads_lhost():
    r = client.get("/evasion", params={
        "technique": "lolbas_certutil",
        "lhost": "192.168.50.5", "lport": 8888,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "192.168.50.5:8888" in body["command"]
    assert "ATTACKER" not in body["command"]


def test_adattack_zerologon_accepts_dc_ip():
    r = client.post("/adattack", json={
        "technique": "zerologon_check",
        "dc_host": "DC01", "dc_ip": "172.16.0.10",
    })
    assert r.status_code == 200
    body = r.json()
    assert "172.16.0.10" in body["command"]
    assert "DC_IP_ADDRESS" not in body["command"]


def test_chain_typed_steps():
    r = client.post("/chain", json={
        "lhost": "10.0.0.5", "lport": 4444,
        "steps": [
            {"module": "generate", "language": "bash"},
            {"module": "persist", "technique": "run_key", "payload": "C:\\x.exe", "name": "Z"},
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_steps"] == 2
    assert body["steps"][0]["module"] == "generate"


def test_chain_rejects_unknown_module():
    r = client.post("/chain", json={
        "lhost": "10.0.0.5", "lport": 4444,
        "steps": [{"module": "nope", "technique": "x"}],
    })
    assert r.status_code == 422


def test_c2profile_includes_sliver_and_mythic():
    r = client.get("/c2profile", params={
        "platform": "teams", "lhost": "10.0.0.5", "lport": 443,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["havoc_profile"]
    assert body["cobalt_strike_profile"]
    assert body["sliver_profile"]
    assert body["mythic_profile"]


def test_initial_access_iso_container():
    import base64 as _b64
    r = client.get("/initial_access", params={
        "technique": "iso_container",
        "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "genisoimage" in body["payload"]
    # lhost is inside the EncodedCommand base64 — decode tokens to verify.
    found = False
    for tok in body["payload"].replace("'", " ").split():
        if len(tok) < 32:
            continue
        try:
            decoded = _b64.b64decode(tok, validate=False).decode("utf-16-le", errors="replace")
        except Exception:
            continue
        if "10.0.0.5" in decoded:
            found = True
            break
    assert found, "lhost not found inside ISO container payload (encoded command)"


def test_initial_access_clickonce():
    r = client.get("/initial_access", params={
        "technique": "clickonce_manifest",
        "lhost": "10.0.0.5", "lport": 8080,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "InvoicePortal.application" in body["payload"]


def test_initial_access_onenote():
    r = client.post("/initial_access", json={
        "technique": "onenote_dropper",
        "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 200, r.text


# ── Extended evasion ──────────────────────────────────────────────────────────

def test_anti_forensics_get_clear_event_logs():
    r = client.get("/anti_forensics", params={"technique": "clear_event_logs"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "wevtutil" in body["command"]
    assert "T1070.001" in body["techniques"]


def test_anti_forensics_post_time_stomp():
    r = client.post("/anti_forensics", json={
        "technique": "time_stomp", "target": "C:\\Windows\\Temp\\demo.exe",
    })
    assert r.status_code == 200
    body = r.json()
    assert "C:\\Windows\\Temp\\demo.exe" in body["command"]


def test_sandbox_evasion_get_uptime():
    r = client.get("/sandbox_evasion", params={
        "technique": "sandbox_check_uptime", "threshold": 900,
    })
    assert r.status_code == 200
    body = r.json()
    assert "900" in body["command"]


def test_sandbox_evasion_post_geofence():
    r = client.post("/sandbox_evasion", json={"technique": "sandbox_geofence"})
    assert r.status_code == 200
    body = r.json()
    assert "ifconfig.io" in body["command"]


def test_evasion_amsi_hwbp():
    r = client.get("/evasion", params={"technique": "amsi_hwbp"})
    assert r.status_code == 200
    body = r.json()
    assert "AmsiScanBuffer" in body["command"]
    assert body["risk"] == "CRITICAL"


def test_evasion_direct_syscalls():
    r = client.get("/evasion", params={
        "technique": "direct_syscalls", "lhost": "10.0.0.5", "lport": 4444,
    })
    assert r.status_code == 200
    body = r.json()
    assert "10.0.0.5" in body["command"]


def test_chain_anti_forensics_step():
    r = client.post("/chain", json={
        "lhost": "10.0.0.5", "lport": 4444,
        "steps": [
            {"module": "anti_forensics", "technique": "clear_event_logs"},
            {"module": "sandbox_evasion", "technique": "sandbox_check_ram", "threshold": 8},
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_steps"] == 2
    assert body["steps"][0]["module"] == "anti_forensics"
    assert body["steps"][1]["module"] == "sandbox_evasion"
