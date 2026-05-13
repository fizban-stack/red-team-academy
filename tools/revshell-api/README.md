
# RevShell API

FastAPI server that generates obfuscated red team payloads — reverse shells,
web shells, persistence, lateral movement, AD attacks, cloud attacks, evasion,
initial access, and C2 profiles — for authorized engagements.

> **Authorized use only.** This API exists to support engagements where you have
> explicit written permission to test the target. Unauthorized use is illegal.

---

## Quick start

```bash
# Local
pip install -r requirements.txt
python main.py
# → http://127.0.0.1:8080 (interactive docs at /docs)

# Docker
docker compose up --build revshell-api
```

Health check:

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"4.1.0","auth_enabled":false,"audit_log_enabled":false,...}
```

---

## Authentication

Bearer-token auth is **opt-in**. Set `API_TOKEN` in the environment to enable:

```bash
API_TOKEN=$(openssl rand -hex 32) python main.py
# Every endpoint now requires: Authorization: Bearer <API_TOKEN>
```

When `API_TOKEN` is unset, auth is disabled — convenient for local development,
but never expose an unauthenticated instance on a shared network.

```bash
# Authenticated request
curl -H "Authorization: Bearer $API_TOKEN" \
  "http://localhost:8080/generate?lhost=10.0.0.1&lport=4444&language=bash"
```

---

## Engagement tracking + audit log

Set `AUDIT_LOG=/path/to/audit.jsonl` to record every generated payload:

```bash
AUDIT_LOG=/var/log/revshell-audit.jsonl \
API_TOKEN=$(openssl rand -hex 32) \
python main.py
```

Tag each request with the engagement identifier so the log groups by client:

```bash
curl -H "X-Engagement-ID: ACME-2026-Q2" \
     -H "Authorization: Bearer $API_TOKEN" \
     "http://localhost:8080/generate?lhost=10.0.0.5&lport=4444&language=powershell"
```

Each log entry is a JSON line: `{ts, engagement_id, route, module, technique,
params (passwords/hashes redacted), payload_sha256, client_ip}`.

### Generate the engagement report

```bash
curl -H "Authorization: Bearer $API_TOKEN" \
     "http://localhost:8080/report?engagement_id=ACME-2026-Q2" \
     > deliverables/ACME-2026-Q2/payloads-summary.md
```

The response is Markdown — drop it directly into the client deliverable.

---

## Reproducible output (`?seed=N`)

Pass `seed=<int>` to make the obfuscation deterministic. Same seed →
identical payload, every time. Essential for documentation, training labs,
debugging, and regression tests.

```bash
curl "http://localhost:8080/generate?lhost=10.0.0.1&lport=4444&language=powershell&seed=42"
# Same command produced on every call.
```

---

## Endpoints

All endpoints accept both `GET` (query params) and `POST` (JSON body). Common
fields: `lhost`, `lport`, `obfuscate`, and where supported, `seed`.

### Shells
| Method | Path | Description |
|---|---|---|
| GET/POST | `/generate` | Build a reverse shell. `?language=bash\|powershell\|python3\|...` |
| POST | `/batch/generate` | Up to 20 shells in one call. |
| GET | `/languages` | List supported shell languages. |

Supported languages: `awk, bash, cradle, csharp, golang, lolbins, lua, nc/netcat,
nim, nodejs, openssl, perl, php, powershell, python3, ruby, rust, socat`.

### C2 + redirector
| Method | Path | Description |
|---|---|---|
| GET | `/c2profile` | Generate Havoc + Cobalt Strike + Sliver + Mythic profiles mimicking a SaaS platform. |
| GET/POST | `/redirector` | Apache .htaccess + nginx rewrite rules for blending C2 traffic. |

Platforms: `teams, slack, okta, o365, github, generic`.

### Windows post-exploitation
| Method | Path | Description |
|---|---|---|
| GET/POST | `/harvest` | Credential harvesting (LSASS, SAM, etc.). |
| GET/POST | `/persist` | Persistence (Run key, scheduled task, WMI, services, COM hijack, ...). |
| GET/POST | `/lateral` | WMI, PsExec, WinRM, DCOM, schtasks, PtH, evil-winrm, xfreerdp. |
| GET/POST | `/adattack` | Kerberoast, ASREProast, DCSync, golden/silver/ACL tickets, GPP, zerologon check. |
| GET/POST | `/privesc` | UAC bypasses, unquoted paths, service perms, potatoes, DLL hijack. |
| GET/POST | `/evasion` | AMSI/ETW patches, CLM bypass, Defender exclusion, LOLBAS (mshta/regsvr32/certutil), PS downgrade. |

### Linux / macOS
| Method | Path | Description |
|---|---|---|
| GET/POST | `/linux/persist` | cron, systemd, init.d, SSH keys, LD_PRELOAD, motd, .bashrc. |
| GET/POST | `/linux/harvest` | /etc/shadow, SSH keys, .bash_history, browser creds, keyring. |
| GET/POST | `/linux/privesc` | SUID, sudo, capabilities, kernel exploits. |

### Cloud
| Method | Path | Description |
|---|---|---|
| GET/POST | `/cloud` | AWS IMDS / enum / persistence; Azure IMDS / enum; GCP metadata / enum; K8s SA / pod escape / RBAC abuse. |

### Web + initial access
| Method | Path | Description |
|---|---|---|
| GET/POST | `/webshell` | PHP / ASPX / JSP / CGI variants with auth-token header. |
| GET/POST | `/initial_access` | VBA macro, HTML smuggling, HTA, LNK, **ISO container**, **OneNote dropper**, **ClickOnce manifest**. |

### Orchestration + reporting
| Method | Path | Description |
|---|---|---|
| POST | `/chain` | Multi-step playbook (typed discriminated steps). |
| GET | `/report` | Markdown engagement report from the audit log. |
| GET | `/health` | Status + which features are enabled. |

---

## Example chain — Initial access → Persistence → Lateral

```bash
curl -X POST http://localhost:8080/chain \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "X-Engagement-ID: ACME-2026-Q2" \
  -H "Content-Type: application/json" \
  -d '{
    "lhost": "10.0.0.5",
    "lport": 4444,
    "steps": [
      {"module": "initial_access", "technique": "iso_container"},
      {"module": "persist", "technique": "wmi_subscription", "name": "WinUpd"},
      {"module": "lateral", "technique": "psremoting", "target": "FILESVR01", "username": "ALICE", "password": "Spring2026!"}
    ]
  }'
```

---

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` for LAN exposure. |
| `PORT` | `8080` | Bind port. |
| `API_TOKEN` | _(unset)_ | When set, enables bearer-token auth. |
| `AUDIT_LOG` | _(unset)_ | Path to JSONL audit log. When set, every payload is logged. |
| `CORS_ORIGINS` | `http://localhost*` | Comma-separated allowed origins. |
| `RATE_LIMIT_DEFAULT` | `120/minute` | Per-IP global limit. |
| `RATE_LIMIT_GENERATE` | `60/minute` | Per-IP limit on `/generate`. |
| `LOG_LEVEL` | `INFO` | Python logging level. |

---

## Architecture

```
revshell-api/
├── main.py              app + middleware + router includes (~90 lines)
├── core/
│   ├── settings.py      env-driven config dataclass
│   ├── validation.py    _LHOST_RE, engagement-id regex
│   ├── auth.py          bearer-token dependency (hmac.compare_digest)
│   ├── audit.py         JSONL writer + markdown report renderer
│   ├── ratelimit.py     slowapi integration (degrades if missing)
│   └── schemas.py       all pydantic request/response models
├── routers/
│   ├── shell.py         /generate, /languages, /batch/generate
│   ├── c2.py            /c2profile, /redirector
│   ├── windows_postex.py    /harvest, /persist, /lateral, /adattack, /privesc, /evasion
│   ├── linux_postex.py      /linux/persist, /linux/harvest, /linux/privesc
│   ├── cloud.py             /cloud
│   ├── webshell.py          /webshell
│   ├── initial_access.py    /initial_access
│   ├── chain.py             /chain (typed discriminated steps)
│   └── reporting.py         /report
├── generators/          payload-builder modules — one per technique family
└── tests/               99 pytest tests covering API, auth, audit, all generators
```

---

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest                 # 99 tests, ~4 seconds
python -m pytest -k auth         # subset
python -m pytest --tb=short -v   # verbose
```

---

## Versioning

This is **v4.1.0**. See `../CHANGELOG.md` for the full change list relative to v4.0.0.
