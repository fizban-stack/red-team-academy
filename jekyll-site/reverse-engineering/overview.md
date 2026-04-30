---
layout: training-page
title: "Reverse Engineering Windows Malware — Overview & Workflow — Red Team Academy"
module: "Reverse Engineering"
tags:
  - reverse-engineering
  - malware-analysis
  - x64dbg
  - ghidra
  - ida-pro
  - workflow
  - triage
page_key: "re-overview"
render_with_liquid: false
---

# Reverse Engineering Windows Malware

Reverse engineering (RE) of Windows malware is the process of reconstructing what a binary does without access to its source code. For red teamers it serves two purposes: understanding how adversary tooling works so you can replicate or improve it, and understanding detection surfaces so you know what traces your own tools leave.

This section covers the full RE stack — from Windows kernel architecture and the PE file format up through hands-on workflows in x64dbg and Ghidra. Each page builds on the last.

---

## Section Map

| Page | Focus |
|------|-------|
| [RE Workflow & Tool Selection](/reverse-engineering/overview/) | This page — methodology, triage pipeline, tool overview |
| [Windows Internals for RE](/reverse-engineering/windows-internals/) | Rings, syscall table, kernel objects, API layer chain |
| [PE Format Deep Dive](/reverse-engineering/pe-format/) | DOS/PE headers, sections, imports/exports, TLS callbacks |
| [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/) | Injectors, RATs, ransomware, rootkits — API fingerprints |
| [Dynamic RE with x64dbg](/reverse-engineering/x64dbg-workflow/) | Breakpoints, tracing, anti-debug bypass in x64dbg |
| [Static RE with Ghidra](/reverse-engineering/ghidra-static-re/) | Decompiler workflow, API pattern recognition, scripting |

Related pages in other modules: [Windows Process Internals](/exploitation/windows-process-internals/) · [Malware Analysis](/exploitation/malware-analysis/) · [EDR Internals](/evasion/edr-internals/) · [Windows Kernel Exploitation](/exploit-dev/kernel-exploitation-windows/)

---

## The Triage Pipeline

RE work follows a consistent funnel: fast automated checks first, manual work only on targets that survive each gate.

```
SAMPLE RECEIVED
      │
      ▼
┌─────────────────────────────────────────────┐
│  TIER 1 — Automated Triage (< 2 min)        │
│  file, strings, sha256, VirusTotal, PE-bear  │
│  Goal: confirm it's malware; get family hint  │
└─────────────────────────┬───────────────────┘
                          │ suspicious? continue
                          ▼
┌─────────────────────────────────────────────┐
│  TIER 2 — Static Analysis (10–30 min)       │
│  imports, exports, sections, pefile, Ghidra  │
│  Goal: understand capability without running │
└─────────────────────────┬───────────────────┘
                          │ need runtime behavior?
                          ▼
┌─────────────────────────────────────────────┐
│  TIER 3 — Dynamic Analysis (30–120 min)     │
│  x64dbg + API monitor + Wireshark + regmon  │
│  Goal: observe actual runtime behavior       │
└─────────────────────────┬───────────────────┘
                          │ need deep logic?
                          ▼
┌─────────────────────────────────────────────┐
│  TIER 4 — Deep RE (hours/days)              │
│  Ghidra/IDA decompiler, algorithm recovery  │
│  Goal: reconstruct algorithms, decrypt C2   │
└─────────────────────────────────────────────┘
```

Stop at the earliest tier that answers your question. Most samples don't need Tier 4.

---

## Tool Selection

### Static Analysis

| Tool | Purpose | Notes |
|------|---------|-------|
| **PE-bear** | GUI PE header inspector | Best free PE editor; shows all header fields, imports, sections |
| **pefile** (Python) | Scriptable PE parsing | `pip install pefile`; good for batch analysis |
| **CyberChef** | In-browser data transforms | Base64, XOR, entropy, byte search — no install needed |
| **Detect-It-Easy (DIE)** | Packer/compiler detection | Identifies packers (UPX, VMProtect, Themida) and compiler fingerprints |
| **FLOSS** (FireEye) | Stack string extraction | Recovers strings hidden in stack-allocated buffers that `strings` misses |
| **Ghidra** | NSA decompiler/disassembler | Free, scriptable, excellent decompiler; preferred for deep static RE |
| **IDA Pro** | Industry-standard disassembler | More mature than Ghidra; expensive; Freeware version limits binary size |
| **Binary Ninja** | Commercial disassembler | Good middle ground; MLIL is clean for analysis |

### Dynamic Analysis

| Tool | Purpose | Notes |
|------|---------|-------|
| **x64dbg** | User-mode debugger | Best free Windows debugger; replace OllyDbg; rich plugin ecosystem |
| **API Monitor** | API call logging | Logs every Win32/NTAPI call without a debugger; low noise |
| **Process Monitor** | FS/Reg/network events | Sysinternals; filter by process; essential for behavioral triage |
| **Process Hacker** | Process/memory inspection | Real-time view of handles, threads, memory maps, injected DLLs |
| **Wireshark** | Network capture | Capture C2 traffic; filter by process with `npcap` |
| **Fakenet-NG** | Fake internet service | Intercepts all outbound traffic; simulates DNS, HTTP, SMTP |
| **Frida** | Dynamic instrumentation | Hook any function at runtime from Python — no source needed |

### Environment

```
Always analyze in a VM with snapshots. Never on a host with real data.

Recommended baseline:
  - Windows 10 22H2 (most malware targets this)
  - VM snapshots before each run
  - No shared folders unless necessary
  - Host-only or isolated network for most samples
  - Fakenet-NG for samples that need internet to activate
  - Flare-VM or REMnux for a pre-built analysis environment
```

Install Flare-VM (automated setup for Windows RE):

```powershell
# In a clean Windows 10 VM (run as Administrator):
Set-ExecutionPolicy Unrestricted -Force
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1'))
# Takes 2-3 hours. Installs x64dbg, Ghidra, pefile, FLOSS, DIE, and 100+ other tools.
```

---

## Triage Checklist

Run this on every new sample before spending time in a debugger:

```bash
# 1. File type — ignore extension, trust magic bytes
file sample.bin
xxd sample.bin | head -4   # look for MZ (4D 5A) = PE, PK = ZIP/docx, etc.

# 2. Hashes — look up before spending time on already-known samples
sha256sum sample.bin
md5sum sample.bin
# Submit to: https://www.virustotal.com/ or https://bazaar.abuse.ch/

# 3. Strings — find hardcoded artifacts
strings -n 6 sample.bin | grep -E "http|\.exe|\.dll|cmd|powershell|HKEY|Software"
floss sample.bin          # recovers stack strings too

# 4. Entropy — packed/encrypted sections have entropy > 7.0
# High entropy in .text = packed; in .data = encrypted config
python3 -c "
import pefile, math, sys
pe = pefile.PE(sys.argv[1])
for s in pe.sections:
    data = s.get_data()
    counts = [data.count(bytes([i])) for i in range(256)]
    n = len(data)
    h = -sum(c/n * math.log2(c/n) for c in counts if c)
    print(f'{s.Name.decode().rstrip(chr(0))}: entropy={h:.2f}')
" sample.bin

# 5. Imports — what capabilities does it declare?
python3 -c "
import pefile, sys
pe = pefile.PE(sys.argv[1])
for e in pe.DIRECTORY_ENTRY_IMPORT:
    print(e.dll.decode())
    for i in e.imports:
        if i.name: print('  ', i.name.decode())
" sample.bin | grep -E "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|OpenProcess|CryptEncrypt|RegSetValue|InternetOpen|WSAStartup|CreateService"
```

---

## Reading Imports as a Capability Map

Imports are the fastest signal for what a sample can do. Match import clusters to capability:

| Import Cluster | Implied Capability |
|---------------|-------------------|
| `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` | Classic process injection |
| `VirtualAllocEx` + `NtMapViewOfSection` | Section-based injection / process hollowing |
| `CryptEncrypt` / `BCryptEncrypt` | Data encryption (ransomware, config hiding) |
| `InternetOpenUrl` / `HttpSendRequest` | HTTP C2 communication |
| `WSAStartup` + `connect` / `send` / `recv` | Raw socket C2 |
| `RegSetValueEx` + `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence |
| `CreateService` / `OpenSCManager` | Service-based persistence |
| `GetAsyncKeyState` / `SetWindowsHookEx` | Keylogging |
| `NtQuerySystemInformation` / `EnumProcesses` | Process discovery |
| `FindFirstFile` / `FindNextFile` + file writes | File enumeration (ransomware/exfil) |
| `LoadLibrary` + no static imports | Dynamic resolution (evasion) |
| Only `GetProcAddress` + `LoadLibrary` | Manual import resolution — expect shellcode or packer |

If a sample imports almost nothing (just `GetProcAddress`/`LoadLibrary`), it resolves everything at runtime. That means it's either packed or using manual import walking — dynamic analysis is required.

---

## The Windows API Call Chain

Understanding the full path from a Win32 call to the kernel is essential for RE. Every `CreateFile`, `VirtualAlloc`, and `ReadProcessMemory` follows this chain:

```
Win32 API (kernel32.dll / user32.dll)
    │  Thin wrappers; parameter validation; error translation
    ▼
NTAPI (ntdll.dll)
    │  Nt* / Zw* functions; actual syscall stubs
    ▼
SYSCALL instruction (INT 2E on x86 / SYSCALL on x64)
    │  Jumps from Ring 3 → Ring 0; saves registers
    ▼
KiSystemCall64 (ntoskrnl.exe)
    │  Validates syscall number; dispatches via SSDT
    ▼
Nt* kernel implementation (ntoskrnl.exe)
    │  Actual kernel work; object manager, I/O manager, etc.
    ▼
Hardware / HAL
```

See [Windows Internals for RE](/reverse-engineering/windows-internals/) for the SSDT, syscall numbers, and how malware bypasses EDR hooks at each layer.

---

## Quick Reference: Common RE Commands

```bash
# Check if sample uses .NET (decompile with dnSpy instead of Ghidra)
file sample.exe    # look for "Mono/.Net assembly"
strings sample.exe | grep -i "mscoree\|clr\|\.net"

# Detect UPX packing (trivially unpack)
strings sample.exe | grep "UPX"
upx -d sample.exe -o unpacked.exe

# Look for known C2 patterns in strings
strings sample.exe | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
strings sample.exe | grep -E "^[A-Za-z0-9+/]{40,}={0,2}$"   # base64 blobs

# Quick PE info dump
python3 -c "
import pefile, sys
pe = pefile.PE(sys.argv[1])
print('Machine:  ', hex(pe.FILE_HEADER.Machine))
print('Timestamp:', pe.FILE_HEADER.TimeDateStamp)
print('Sections: ', pe.FILE_HEADER.NumberOfSections)
print('EP:       ', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('ImageBase:', hex(pe.OPTIONAL_HEADER.ImageBase))
" sample.exe
```
