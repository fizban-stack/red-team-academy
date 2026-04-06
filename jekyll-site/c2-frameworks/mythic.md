---
layout: training-page
title: "Mythic C2 Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - mythic
  - c2
  - apollo
  - poseidon
  - mythic-cli
  - docker
  - bof
  - pkinit
page_key: "c2-mythic"
render_with_liquid: false
---

# Mythic C2 Framework

Mythic is a free, open-source, multi-operator C2 platform built on Docker microservices. It decouples **agents** (implant logic) from **C2 profiles** (transport protocols), enabling a diverse ecosystem of implants across Windows, Linux, and macOS over 10+ protocol channels. Actively maintained by Cody Thomas (SpecterOps). Used in real red team engagements where Cobalt Strike licensing is not available, multi-language implant diversity is needed, or team operations require role-based access control.

## Architecture

### Core Components

| Component | Role |
| --- | --- |
| **GoLang server** | Core backend — GraphQL APIs, WebSockets, auth, task routing |
| **PostgreSQL** | Persistent storage: operations, tasks, callbacks, artifacts, credentials |
| **RabbitMQ** | Async message broker between server and agent/C2 containers |
| **Nginx** | Reverse proxy unifying all services behind a single port (default 7443) |
| **React frontend** | Web UI served through Nginx — operator interface for tasking, callbacks, artifacts |

### Agent/C2 Profile Separation

The key architectural decision: payload type (what runs on target) and C2 profile (how it communicates) are separate Docker containers that register independently via RabbitMQ. A single payload build can stack multiple C2 channels (e.g., HTTP primary + SMB P2P fallback). New agents or profiles can be added without touching the core server.

```
Agent (target) <-- HTTP/DNS/SMB --> C2 Profile Container
                                            |  RabbitMQ
                                   GoLang Server -- PostgreSQL
                                            |
                                   React Web UI (Nginx:7443)
```

## Installation

```
# 1. Clone repository
git clone https://github.com/its-a-feature/Mythic --depth 1
cd Mythic

# 2. Install Docker (Ubuntu/Debian — skip if Docker 20.10.22+ already present)
sudo ./install_docker_ubuntu.sh

# 3. Build mythic-cli binary (canonical management tool)
sudo make

# 4. Start Mythic (generates .env on first run)
sudo ./mythic-cli start

# 5. Get auto-generated admin password
cat Mythic/.env | grep MYTHIC_ADMIN_PASSWORD

# 6. Install an agent and C2 profile (minimum required before payload generation)
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http

# 7. Access web UI
# https://127.0.0.1:7443  (username: mythic_admin, password: from .env)
```

**System requirements:** Linux (Ubuntu/Debian preferred), Docker 20.10.22+, Docker Compose plugin, minimum 2 CPU / 4 GB RAM.

**Note:** `install_docker_ubuntu.sh` only sets up Docker. It does NOT start Mythic. `mythic-cli` is the canonical management tool — avoid direct docker-compose invocations.

## Agent Ecosystem

### Apollo (Windows — primary Windows agent)

| Property | Value |
| --- | --- |
| Language | C# / .NET Framework 4.0 |
| Targets | Windows only |
| Mythic compat | 3.2 (August 2024) |

80+ commands. The Cobalt Strike Beacon analogue in Mythic. Key capabilities: `execute_coff` (BOF execution), `execute_assembly`, `execute_pe`, process injection (CRT, QueueUserAPC), credential ops (mimikatz, dcsync, pass-the-hash, token steal/make), PPID spoofing, ETW patching, blockdlls, sleep obfuscation, SOCKSv5 proxy, P2P via SMB/TCP named pipes.

```
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
```

### Poseidon (Linux/macOS)

| Property | Value |
| --- | --- |
| Language | Go |
| Targets | Linux x64, macOS x64 |
| Mythic compat | 3.0.0+ |

Standard file ops, shell execution, launchd persistence (macOS), AES encryption, custom C2 profile support. Low-footprint native binary. Preferred over Apfell for modern macOS engagements.

```
sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon
```

### Medusa (Cross-platform Python)

Python 2.7/3.8. Windows, Linux, macOS. No external dependencies. Dynamic function load/unload, in-memory Python module execution, AES256 HMAC, SOCKSv5, `eval()`-based code execution. Use when arbitrary Python execution at agent level is needed, or for cross-platform targets where Python is present. HTTP profile only.

```
sudo ./mythic-cli install github https://github.com/MythicAgents/Medusa
```

### Thanatos (Windows/Linux Rust)

Rust. Windows/Linux. Latest: v0.1.14 (September 2025). SSH client with exec, SFTP, agent hijacking, remote agent spawn. Streaming port scanner, TCP redirector setup, background jobs. Use when Rust detection profile is desired or SSH-based lateral movement is central.

```
sudo ./mythic-cli install github https://github.com/MythicAgents/thanatos
```

### Apfell (macOS JavaScript for Automation)

JXA / macOS only. osascript execution, dylib format. Less actively maintained — prefer Poseidon for modern macOS ops. Use when script-based access avoids native binary detection.

```
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```

## C2 Profiles

| Profile | Protocol | Use Case |
| --- | --- | --- |
| `http` | HTTP GET/POST | Standard async comms, redirector-friendly |
| `httpx` | HTTP (malleable) | Configurable headers, URIs, transforms |
| `websocket` | WebSocket | Push-based, persistent connections |
| `smb` | Named Pipes | P2P lateral movement, no internet egress |
| `tcp` | TCP sockets | P2P network pivoting |
| `dns` | DNS TXT queries | Covert channel through restrictive firewalls |
| `discord` | Discord API | Legitimate cloud service blend-in |
| `github` | GitHub issues/files | Cloud platform C2 |

### Install Common Profiles

```
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/httpx
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dns
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/smb
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket
```

### HTTP Profile Key Parameters

| Parameter | Example | Notes |
| --- | --- | --- |
| `callback_host` | `https://cdn.corp.com` | Full URL to C2 listener / redirector |
| `callback_port` | `443` | Port on callback_host |
| `callback_interval` | `60` | Base polling interval in seconds |
| `callback_jitter` | `23` | % randomization applied to interval (0–99) |
| `kill_date` | `2025-12-31` | Agent exits if system date >= this |
| `use_ssl` | `true` | Auto-generates self-signed cert (use real cert in prod) |

## Payload Generation (Web UI Workflow)

1. Click biohazard icon (top bar) → **Actions** → **Generate New Payload**
2. Select target OS (Windows / Linux / macOS)
3. Select agent type (Apollo, Poseidon, Medusa, Thanatos, etc.)
4. Configure agent parameters: output format (exe/dll/shellcode/binary), PPID spoofing, ETW bypass, proxy settings
5. Select commands to include (reduces footprint — omit unused commands)
6. Select C2 profile and configure: callback host, port, interval, jitter, kill date, User-Agent, custom URIs
7. Click **Build** — agent container compiles/packages asynchronously
8. Download from **Created Payloads** page when build completes

## Operator Workflow

### Initial Setup

```
# Must create an Operation before any data is visible
# Web UI: hamburger menu → Operations → Modify Operations → Create New

# Role levels:
# Lead    — full operational control
# Operator — can task, create payloads, lock callbacks
# Spectator — read-only, cannot task

# Block lists restrict specific commands per operator per payload type
# Slack webhook configurable per-operation for callback alerts
```

### Callback Management

Each agent check-in creates a callback entry showing: payload lineage (who created it, when, which C2 profile), current status (active/stalled/dead), and operator assignments. Task via the Callbacks page — select callback → type command in input field → output streams via WebSocket in real time.

MITRE ATT&CK technique IDs are auto-tagged on tasks. Artifacts (process creation, file writes, network connections, API calls) are auto-recorded per callback for deconfliction and reporting.

## BOF (Beacon Object File) Support

Apollo supports BOF execution natively via `execute_coff`. Runs Cobalt Strike-compatible BOFs in-process.

```
# Apollo execute_coff syntax (in Mythic web UI command input)
execute_coff <bof_file> [function_name] [timeout]

# Example — run whoami BOF
execute_coff whoami.o go 30
```

**Forge** (released February 2025, by Cody Thomas) standardizes BOF and .NET assembly execution across Mythic agents. Single operator interface that dispatches to agent-specific commands (`execute_coff` for Apollo, equivalent for Athena). Integrates with Sliver Armory BOF collection. Supports command augmentation — build a BOF command once, auto-inject into all compatible new callbacks.

## mythic-cli Command Reference

```
# Lifecycle
sudo ./mythic-cli start                     # Start all containers
sudo ./mythic-cli stop                      # Stop all containers
sudo ./mythic-cli restart                   # Restart all containers
sudo ./mythic-cli status                    # Container health, ports

# Logs
sudo ./mythic-cli logs <container_name>

# Agent / C2 profile management
sudo ./mythic-cli install github <url>             # Install from GitHub main branch
sudo ./mythic-cli install github <url> -b <branch> # Specific branch
sudo ./mythic-cli install folder /path/to/local     # Local clone
sudo ./mythic-cli install github <url> -f           # Force overwrite existing
sudo ./mythic-cli payload list                      # List installed payload types
sudo ./mythic-cli c2 list                           # List installed C2 profiles
sudo ./mythic-cli payload start <agent>             # Start specific agent container
sudo ./mythic-cli c2 stop <profile>                 # Stop specific C2 profile container

# Configuration
sudo ./mythic-cli config get                        # Show all .env variables
sudo ./mythic-cli config set <var> <val>            # Set variable
sudo ./mythic-cli update                            # Check for updates
```

### Key .env Variables

```
# Mythic/.env
MYTHIC_ADMIN_USER=mythic_admin
MYTHIC_ADMIN_PASSWORD=<auto-generated>
NGINX_PORT=7443
ALLOWED_IP_BLOCKS="10.0.0.0/8,192.168.0.0/16"   # Restrict UI access
RABBITMQ_BIND_LOCALHOST_ONLY="false"              # Required for remote agent containers
MYTHIC_SERVER_BIND_LOCALHOST_ONLY="false"         # Required for remote deployments
```

## OPSEC Considerations

### Redirectors

Mythic's Nginx listens on a single port. Place an Apache/Nginx redirector in front to protect the teamserver from direct exposure. Use **mythic2modrewrite** to generate Apache .htaccess rules from a Mythic HTTP payload config:

```
# Export payload config from Mythic UI (Created Payloads → config.json)
python3 mythic2modrewrite.py -i config.json \
  -c https://TEAMSERVER:7443 \
  -r https://DECOY_SITE
# Routes matching C2 URIs to Mythic backend
# All other traffic → decoy/legitimate site
```

### Callback Timing

- Set `callback_interval` to 300s+ for long-haul ops
- Set `callback_jitter` to 20–30% to avoid timing signatures
- Apollo has built-in sleep obfuscation — beacon memory is encrypted between callbacks
- Mythic 3.3 Events system: automate sleep increase at end of business hours

### SSL Certificate OPSEC

- Auto-generated self-signed certs are a strong detection signal — use Let's Encrypt or custom CA-signed certs
- Ensure callback domain is categorized, aged, and has legitimate web content on port 80
- Domain fronting is increasingly unreliable in 2025–2026 via TLS SNI inspection — prefer Cloudflare Workers or AWS CloudFront as protocol translators

## Mythic vs Cobalt Strike vs Sliver

| Dimension | Mythic | Cobalt Strike | Sliver |
| --- | --- | --- | --- |
| Cost | Free / open-source | ~$5k+/yr | Free / open-source |
| UI | Rich web UI, multi-user, RBAC | Java GUI, teamserver | CLI only |
| Agent diversity | Multi-language ecosystem (Go, C#, Python, Rust, JXA) | Single Beacon (C/C++) | Single implant (Go) |
| C2 channels | 10+ pluggable profiles | Malleable HTTP/DNS | mTLS, HTTP(S), DNS, WireGuard |
| BOF support | Yes (Apollo + Forge) | Native (original) | Via COFF loader extension |
| Detection maturity | Lower — fewer signatures | Highest | Growing |
| Learning curve | High (Docker, CLI) | Medium | Low |

**Choose Mythic when:** multi-operator team ops with role-based access, agent diversity across platforms, budget-constrained operations (no CS license), custom C2 channel research (GitHub/Discord/MQTT profiles), or training environments.
