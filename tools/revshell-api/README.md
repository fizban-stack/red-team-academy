
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
| GET/POST | `/evasion` | **49 techniques** — patchless AMSI/ETW, direct/indirect syscalls, NTDLL unhook, ROP+Ekko sleep, PPID spoof, hollowing/stomping/thread-hijack, COM ROT, environment keying, in-memory PE loader, DLL sideload, APC + Early-Bird APC, Heaven's Gate, Process Ghosting/Doppelganging/Herpaderping, **PEB unlinking**, **phantom DLL hollow**, **threadless injection**, **stack spoofing**, **manual map + header erasure**, **function-level encryption**. |
| POST | `/stack` | **EDR-aware evasion orchestrator** — single `edr` or multi `edrs: [...]`. Returns a deduped chain with `counters: [...]` per step. |
| POST | `/recommend` | **Constraint-driven recommender** — `{has_admin, target_os, blocks_amsi, has_userland_hooks, has_memory_scanner, has_callstack_inspection, target_edrs, families, max_techniques}` returns ranked technique list. |
| GET | `/ioc_export` | **Sigma rule export** for purple teams. Reads the audit log, emits one Sigma rule per `(module, technique)` seen. Optional `?engagement_id=`. |
| GET/POST | `/anti_forensics` | Post-engagement artifact cleanup — event log wipe, USN journal, Prefetch, Recent files, Recycle Bin, Jump Lists, ShellBags, Amcache, PS history, file time-stomping, ADS payload hiding, self-deletion stub. |
| GET/POST | `/sandbox_evasion` | Environment gates — VM detection (CPUID / WMI / artifacts), uptime + RAM + screen-resolution + recent-files + domain-joined sandbox checks, geofencing, time-delay, anti-debug (IsDebuggerPresent + CheckRemoteDebuggerPresent + PEB NtGlobalFlag). |

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

## Example chain — Full evasion stack (sandbox gate → bypasses → payload → cleanup)

```bash
curl -X POST http://localhost:8080/chain \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "lhost": "10.0.0.5",
    "lport": 4444,
    "steps": [
      {"module": "sandbox_evasion", "technique": "sandbox_check_uptime", "threshold": 1800},
      {"module": "sandbox_evasion", "technique": "sandbox_check_domain_joined"},
      {"module": "sandbox_evasion", "technique": "vm_detect_wmi"},
      {"module": "evasion", "technique": "amsi_hwbp"},
      {"module": "evasion", "technique": "etw_hwbp"},
      {"module": "evasion", "technique": "ntdll_unhook"},
      {"module": "evasion", "technique": "ppid_spoof"},
      {"module": "generate", "language": "powershell"},
      {"module": "anti_forensics", "technique": "clear_powershell_history"},
      {"module": "anti_forensics", "technique": "clear_event_logs"}
    ]
  }'
```

This produces a sequenced playbook: gate execution to a real corporate endpoint,
disable AMSI + ETW patchlessly, wipe EDR userland hooks, spoof the parent PID,
run the reverse shell, and clean up traces on exit.

## EDR-aware evasion stack — `/stack`

Instead of hand-composing a chain, ask the API for a sequence tuned to the
specific EDR you're up against:

```bash
curl -X POST http://localhost:8080/stack \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "edr": "crowdstrike",
    "lhost": "10.0.0.5",
    "lport": 4444,
    "language": "powershell"
  }'
```

Response (truncated):

```json
{
  "edr": "crowdstrike",
  "total_steps": 9,
  "listener": "rlwrap nc -lvnp 4444    # connect-back from 10.0.0.5",
  "summary": "crowdstrike evasion stack with 9 steps. Payload: powershell ...",
  "chain": [
    { "step": 1, "module": "sandbox_evasion", "technique": "sandbox_check_user_interaction",
      "rationale": "Falcon Sandbox doesn't simulate mouse movement; gate on it", "command": "..." },
    { "step": 2, "module": "sandbox_evasion", "technique": "sandbox_check_uptime",
      "rationale": "Falcon's pre-execution scan in cloud takes ~3 min; gate on 20+ min uptime", "command": "..." },
    { "step": 4, "module": "evasion", "technique": "indirect_syscalls",
      "rationale": "Falcon's userland hooks AND callstack inspection — indirect syscalls land inside ntdll.dll", "command": "..." },
    { "step": 6, "module": "evasion", "technique": "rop_sleep",
      "rationale": "Falcon snapshots memory during sleep — ROP sleep mask defeats the scanner", "command": "..." },
    { "step": 8, "module": "shell", "technique": "powershell",
      "rationale": "Reverse shell payload", "command": "powershell -NoP -NonI ..." }
  ]
}
```

### Supported EDR profiles

| Profile | Tuned for |
|---|---|
| `defender` | Microsoft Defender for Endpoint — patchless AMSI/ETW, WLDP downgrade, NTDLL unhook, PPID spoof |
| `crowdstrike` | Falcon — indirect syscalls (clean callstacks), Early-Bird APC, ROP sleep, ETW patchless |
| `sentinelone` | Singularity Active EDR — patchless AMSI, NTDLL unhook, ROP sleep (anti memory scanner), module stomping |
| `carbonblack` | VMware Carbon Black — DLL sideloading via reputation-trusted binaries, classic AMSI/ETW bypass |
| `generic` | Vendor-agnostic best effort — patchless AMSI+ETW, NTDLL unhook, PPID spoof |

Flags:

| Flag | Default | Effect |
|---|---|---|
| `include_anti_forensics` | `true` | Append cleanup steps after the payload |
| `include_sandbox_evasion` | `true` | Prepend sandbox/VM gates before the payload |
| `seed` | unset | Deterministic shell payload (for tests/docs) |

Order is load-bearing: sandbox gates first, evasion bypasses next, payload, then
cleanup. The stack is fully deterministic for a given `(edr, options)` tuple.

## Multi-EDR stack

Most Fortune 500 environments run more than one EDR. Pass an array:

```bash
curl -X POST http://localhost:8080/stack \
  -H "Content-Type: application/json" \
  -d '{
    "edrs": ["defender", "crowdstrike", "sentinelone"],
    "lhost": "10.0.0.5", "lport": 4444
  }'
```

The builder takes the union of all three profiles, dedupes techniques, and
labels each step with `counters: [...]` showing which vendors that step
bypasses. Order remains load-bearing.

## Technique recommender — `/recommend`

Describe your situation, get a ranked list of techniques that fit:

```bash
curl -X POST http://localhost:8080/recommend \
  -H "Content-Type: application/json" \
  -d '{
    "target_edrs": ["crowdstrike"],
    "has_callstack_inspection": true,
    "has_userland_hooks": true,
    "max_techniques": 5
  }'
```

Returns the top-N techniques scored by how well they satisfy the constraints —
e.g. for CrowdStrike with callstack inspection, `indirect_syscalls`,
`stack_spoof`, and `early_bird_apc` rank highly.

Scoring is deterministic, so this endpoint is safe to call during planning.

## Modern C2 channels — `/c2_channel`

Generate implant configuration and listener setup for alternative C2 transports:

```bash
# List available channels
curl http://localhost:8080/c2_channel

# DNS-over-HTTPS C2 profile
curl -X POST http://localhost:8080/c2_channel \
  -H "Content-Type: application/json" \
  -d '{"channel":"doh_c2","lhost":"10.0.0.5","lport":53,"options":{"doh_provider":"cloudflare","c2_domain":"beacon.example.com"}}'

# WebSocket C2 profile
curl -X POST http://localhost:8080/c2_channel \
  -H "Content-Type: application/json" \
  -d '{"channel":"websocket_c2","lhost":"10.0.0.5","lport":443}'

# Quick GET variant
curl "http://localhost:8080/c2_channel/named_pipe_c2?lhost=10.0.0.5&lport=445"
```

Supported channels: `doh_c2`, `domain_fronting`, `named_pipe_c2`, `icmp_tunnel`,
`websocket_c2`, `cloud_blend_discord`, `cloud_blend_s3`, `cloud_blend_github`.

Each response includes `implant_config`, `listener_setup`, `notes`, MITRE `techniques`,
`risk`, and blue-team `detections`.

---

## EDR stack comparison — `/stack/diff`

Compare two EDR evasion stacks side-by-side to understand overlap and gaps:

```bash
curl -X POST http://localhost:8080/stack/diff \
  -H "Content-Type: application/json" \
  -d '{"edr_a":"defender","edr_b":"crowdstrike","lhost":"10.0.0.5","lport":4444}'
```

Returns three lists:
- `shared` — techniques present in both stacks (your common evasion baseline)
- `only_a` — techniques unique to `edr_a`
- `only_b` — techniques unique to `edr_b`

Each entry includes the technique name, module category (`sandbox_evasion`,
`evasion`, `shell`, `anti_forensics`), and the rationale from each stack.

Deterministic — same `(edr_a, edr_b)` pair always returns the same result.

---

## Sigma rule export — `/ioc_export`

At engagement teardown, hand the blue team the exact detections that would have
caught your tradecraft:

```bash
curl "http://localhost:8080/ioc_export?engagement_id=ACME-2026-Q2" \
  -H "Authorization: Bearer $API_TOKEN" \
  -o acme-2026-q2.sigma.yml
```

Reads the audit log (set `AUDIT_LOG=` to enable), groups by `(module, technique)`,
and emits one Sigma rule per entry. Each rule includes MITRE ATT&CK tags and
the detection patterns from the technique's metadata. Defender for Endpoint /
Sentinel / Splunk Sigma converters consume the output directly.

Requires `AUDIT_LOG` configured at server start. Returns 404 otherwise.

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
│   ├── shell.py              /generate, /languages, /batch/generate
│   ├── c2.py                 /c2profile, /redirector
│   ├── c2_channels.py        /c2_channel (8 modern C2 transports)
│   ├── windows_postex.py     /harvest, /persist, /lateral, /adattack, /privesc, /evasion
│   ├── linux_postex.py       /linux/persist, /linux/harvest, /linux/privesc
│   ├── cloud.py              /cloud
│   ├── webshell.py           /webshell
│   ├── initial_access.py     /initial_access
│   ├── evasion_extended.py   /anti_forensics, /sandbox_evasion
│   ├── stack.py              /stack (EDR-aware evasion stack)
│   ├── diff.py               /stack/diff (stack comparator)
│   ├── recommend.py          /recommend (constraint-driven selector)
│   ├── ioc.py                /ioc_export (Sigma rule export)
│   ├── chain.py              /chain (typed discriminated steps)
│   └── reporting.py          /report
├── generators/          payload-builder modules — one per technique family
└── tests/               418 pytest tests covering API, auth, audit, all generators
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

This is **v4.5.0**. See `CHANGELOG.md` for the full change list.
