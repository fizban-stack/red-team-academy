---
layout: training-page
title: "Dynamic Reverse Engineering with x64dbg — Red Team Academy"
module: "Reverse Engineering"
tags:
  - x64dbg
  - dynamic-analysis
  - debugging
  - breakpoints
  - anti-debug-bypass
  - api-tracing
  - scyllahide
  - malware-debug
page_key: "re-x64dbg-workflow"
render_with_liquid: false
---

# Dynamic RE with x64dbg

x64dbg is the standard user-mode debugger for Windows malware RE. It replaced OllyDbg and offers a rich plugin ecosystem, native x64 support, script automation, and deep integration with the PE format. This page covers the complete workflow: setup, essential plugins, breakpoint methodology, anti-debug bypass, and API call tracing.

Related pages: [RE Workflow & Tool Selection](/reverse-engineering/overview/) · [Windows Internals for RE](/reverse-engineering/windows-internals/) · [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/) · [WinDbg Reference](/evasion/windbg-reference/)

---

## Installation and Setup

```bash
# Download from: https://x64dbg.com/
# Extract — no install needed. Run x64dbg.exe (64-bit) or x32dbg.exe (32-bit)
# Use the correct bitness for the target sample:
#   32-bit malware on 64-bit OS → use x32dbg.exe (runs inside WOW64 layer)
#   64-bit malware → use x64dbg.exe
```

### Essential Plugins

Install these before analyzing any malware:

| Plugin | Purpose | Install |
|--------|---------|---------|
| **ScyllaHide** | Comprehensive anti-anti-debug | Copy to `x64dbg\x64\plugins\` |
| **xAnalyzer** | Auto-comment API calls in disassembly | Copy to plugins dir |
| **ret-sync** | Sync x64dbg with Ghidra/IDA | See ret-sync GitHub |
| **x64dbgpy** | Python scripting support | From x64dbg plugin manager |
| **Lighthouse** | Code coverage visualization | Useful after Frida tracing |
| **TitanHide** | Kernel-level debugger hiding | Optional; complements ScyllaHide |

**Plugin directory:** `x64dbg\x64\plugins\` (for 64-bit) or `x64dbg\x32\plugins\`

### ScyllaHide Configuration

ScyllaHide is mandatory for malware that uses anti-debug checks:

```
Plugins → ScyllaHide → Options
Enable ALL of:
  ☑ IsDebuggerPresent
  ☑ CheckRemoteDebuggerPresent
  ☑ NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle)
  ☑ NtSetInformationThread (HideFromDebugger)
  ☑ NtQueryObject (ObjectAllTypesInformation — debugger object detection)
  ☑ PEB BeingDebugged → patch to 0
  ☑ PEB NtGlobalFlag → patch to 0
  ☑ Heap flags → patch (removes debugger heap magic)
  ☑ NtYieldExecution (timing check bypass)
  ☑ GetTickCount64 (timing spoof)
  ☑ OutputDebugString (some malware probes this)

Also enable TLS callback handling:
Options → Events → ☑ TLS Callbacks
```

---

## First Run Workflow

When you open a new sample, follow this sequence before pressing Run:

```
1. Open sample: File → Open (or drag-and-drop onto x64dbg)

2. x64dbg auto-breaks at the loader entry point (before main):
   You're at ntdll!LdrInitializeThunk — not at your code yet.

3. Configure initial breakpoints BEFORE resuming:

   a) Break at entry point:
      Options → Events → ☑ "Break on TLS Callbacks"
      Options → Events → ☑ "Break on Entry Point"

   b) Set system breakpoints:
      Breakpoints → Add DLL breakpoint → "kernel32.dll" (break when loaded)

4. Enable ScyllaHide profile for the sample.

5. Press Run (F9) — lands at entry point (or TLS callback if present).

6. Note the initial state:
   - Module list (View → Modules): what DLLs are already loaded?
   - Memory map (View → Memory): what regions exist?
   - Strings (right-click disassembly → Search for → All Modules → String References)
```

---

## Breakpoint Types and Methodology

### Software Breakpoints (F2)

Replaces instruction at address with `INT3` (0xCC). Detected by malware scanning `.text` for 0xCC bytes.

```
Right-click address → Breakpoint → Toggle (F2)
Or: type 'bp 0x1234ABCD' in the command bar
```

### Hardware Breakpoints (F2 menu or DR registers)

Uses debug registers (DR0–DR3). Cannot be detected by scanning memory — malware must inspect debug registers via `GetThreadContext` to find them.

```
Right-click address → Breakpoint → Set Hardware → Execute
Command: bph <address>

Limit: maximum 4 hardware breakpoints active at once.
Use these on anti-debug detection code and key crypto functions.
```

### Memory Breakpoints

Fires when a memory region is read, written, or executed. Useful for tracking where shellcode is written and when it runs:

```
View → Memory Map → right-click region → Breakpoint → Write (or Access, or Execute)
Command: membp <address> <size> <type>

Example: break when anything writes to shellcode buffer:
membp 0x00500000 0x1000 w
```

### Conditional Breakpoints

Fires only when a condition is true. Reduces noise when a hot API is called thousands of times:

```
Right-click breakpoint → Edit → Condition:
  [ESP+4] == 0xDEADBEEF     # arg1 equals value
  $pid == 1234              # process ID matches
  eax != 0                  # return value is not NULL

Useful example — break on VirtualAlloc only when size > 0x10000:
  [esp+0xC] > 0x10000       # x86: size is 3rd param at esp+0xC

Logging breakpoint (no halt, just log):
  Right-click BP → Edit → Log → check "Don't break, only log"
  Log text: "VirtualAlloc called with size={[esp+0xC]:#x}"
```

---

## API Breakpoint Methodology

The most efficient dynamic RE approach: break on specific API calls to understand what the malware does without reading every instruction.

### Setting API Breakpoints

```
Symbols tab → search for API name → right-click → Breakpoint → Set

Or via command:
bp kernel32.VirtualAllocEx
bp kernelbase.WriteProcessMemory
bp ntdll.NtCreateThreadEx
bp ws2_32.connect
bp wininet.InternetConnectA

# Break on ALL exports of a DLL (very noisy — use carefully):
bpd ws2_32
```

### Injection Analysis Breakpoint Set

For suspected injector, set this cluster:

```
bp kernel32.OpenProcess
bp kernel32.VirtualAllocEx
bp kernel32.WriteProcessMemory
bp kernel32.CreateRemoteThread
bp ntdll.NtCreateThreadEx
bp ntdll.NtQueueApcThread
bp ntdll.NtMapViewOfSection
bp ntdll.NtCreateSection
```

When `OpenProcess` breaks: note `rcx` (DWORD AccessMask) and `r8` (DWORD dwProcessId) on x64.
When `WriteProcessMemory` breaks: check what data is in the buffer (`rdx` = hProcess, `r8` = lpBaseAddress, `r9` = lpBuffer). Dump `r9` to see the shellcode.

### Crypto Key Extraction

When `BCryptEncrypt` or `CryptEncrypt` breaks, the key material is already set up in the key handle. Read the key before encryption completes:

```
bp bcrypt.BCryptEncrypt

When hit:
  rcx = hKey handle
  View → Handles → find BCrypt key handle
  
  Alternatively: follow hAlgorithm back to BCryptGenerateSymmetricKey
  and capture the pbSecret (key bytes) parameter:
  bp bcrypt.BCryptGenerateSymmetricKey
  When hit: r9 = pbSecret pointer, stack[5] = cbSecret
  Dump: dump r9 <cbSecret_value>
```

### C2 Traffic Interception

```
# Internet WinINet
bp wininet.HttpSendRequestA
bp wininet.HttpSendRequestW
When hit: inspect Stack → find lpszHeaders and lpOptional (POST body)

# Raw socket
bp ws2_32.connect
When hit: rdx = sockaddr struct → read IP + port
  →mov eax, [rdx+4]  # IP in network byte order
  →mov ax, [rdx+2]   # Port in network byte order

bp ws2_32.send
When hit: r8 = buf pointer, r9 = len → dump r8 r9
```

---

## Navigating the Disassembly

### Key Shortcuts

| Shortcut | Action |
|----------|--------|
| F7 | Step Into (follows calls) |
| F8 | Step Over (executes call, stops after) |
| F9 | Run (until next breakpoint) |
| Ctrl+F9 | Run until return (step out of current function) |
| Ctrl+G | Go to address (enter VA, RVA, or symbol) |
| Space | Toggle breakpoint at cursor |
| Enter | Follow call or jump at cursor |
| Esc | Return to previous location |
| ; | Add comment to current line |
| : | Add label to current address |
| Ctrl+R | Find references to selected address |

### Navigating to Specific Code

```
# Go directly to an API call:
Ctrl+G → type "VirtualAlloc" → Enter

# Find all cross-references to a function:
Right-click function start → Find references to → Selected address

# Search for string in current module:
Right-click disassembly → Search for → Current Region → String
Then: right-click result → Follow in Disassembler
```

### Dumping Memory

```
# Dump a memory region to file (e.g., unpacked shellcode):
Memory Map → right-click region → Dump to File

# Or in the Dump panel:
Right-click → Follow in Dump → Address (enter VA)
Select range → right-click → Binary → Save to File

# From command:
savedata "C:\output.bin", <address>, <size>
# Example: savedata "C:\shellcode.bin", 0x00500000, 0x1000
```

---

## Anti-Debug Bypass Techniques

### Bypassing IsDebuggerPresent Manually

```
ScyllaHide handles this automatically. Manual approach if needed:
Ctrl+G → "IsDebuggerPresent"
Find the ReturnValue (PEB check) → set hardware write BP on PEB+2
After PEB.BeingDebugged is written → change EAX to 0 in Registers panel
```

### NtQueryInformationProcess Patch

Some malware calls `NtQueryInformationProcess` with class `ProcessDebugPort` (7) or `ProcessDebugFlags` (31):

```
bp ntdll.NtQueryInformationProcess
When hit:
  rdx = ProcessInformationClass
  if rdx == 7:   # ProcessDebugPort → return 0 (no debugger)
    After NtQueryInformationProcess returns:
    Set rcx = pointer to output buffer → change value at that pointer to 0
  if rdx == 0x1F: # ProcessDebugFlags → return 1 (not being debugged)
    Change output value to 1
```

ScyllaHide automates this. Only do it manually if ScyllaHide fails.

### Timing Check Bypass

```
bp ntdll.NtDelayExecution
  → After return, set RIP to instruction after the timing comparison
  → Or: manually set the tick count / FILETIME return values

bp kernel32.GetTickCount64
  → Set breakpoint on return → change RAX to a consistent large value
  → Use conditional log breakpoint: log RAX and replace with 0xFFFFFFFF
```

### TLS Callback Anti-Debug

```
Options → Events → ☑ TLS Callbacks (auto-breaks at each callback entry)
Step through the callback — if it calls IsDebuggerPresent or accesses PEB,
ScyllaHide will have already patched the values.
After the callback completes, execution continues to OEP.
```

---

## API Call Logging and Tracing

### Log API Calls Without Stopping

Use logging breakpoints to record all API calls in a trace file:

```
# For each breakpoint you want to log:
Right-click BP → Edit → Log condition:
  Log: "VirtualAlloc(size={[esp+0xC]:#x})"
  ☑ Don't break, only log

# View log: View → Log
# Save log: right-click → Save All Log Entries
```

### Automatic API Logging with API Monitor

Complementary to x64dbg — run API Monitor alongside to capture the full call trace without breakpoints:

```
1. In API Monitor: File → Monitor New Process → browse to malware.exe
2. API Monitor → select API sets to monitor:
   File I/O, Registry, Process, Threading, Memory, Network, Crypto
3. Run the sample
4. API Monitor captures every call with parameters and return values
5. Export to CSV for offline analysis
```

### Tracing with x64dbg Script

```python
# x64dbgpy script — trace execution and log API hits
# Save as trace.py and run via Plugins → x64dbgpy → Run Script

import x64dbgpy.pluginsdk as sdk

# Set logging BPs on injection APIs
apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "NtQueueApcThread"]

for api in apis:
    addr = sdk.GetProcAddress("kernel32", api) or sdk.GetProcAddress("ntdll", api)
    if addr:
        sdk.SetBPX(addr, sdk.UE_BREAKPOINT, f"log_api_{api}")
        print(f"[+] BP set on {api} at {addr:#x}")
```

### x64dbg Trace Recording

```
Trace → Record Trace (into: tracelog.db)
Run the sample — every executed instruction is recorded.
Trace → Open Trace (browse to .db file)
→ Step through the full execution history offline
→ Search trace for API call: Ctrl+F → function name

Useful for: examining exactly what code ran inside an anti-analysis check.
```

---

## Unpacking Workflow

Most packed malware self-decrypts to an OEP (Original Entry Point). The standard approach:

```
1. Open packed sample in x64dbg
2. ScyllaHide → enable all options
3. Run to OEP automatically:
   Debug → Break at OEP (requires OEP detection plugin)
   Or: set memory execution BP on the main .text VA range
       → packer will write unpacked code there → breaks when it tries to run

4. When OEP is hit (execution is at legitimate main function):
   a. Plugins → Scylla → Dump → click "Dump"
      → saves unpacked PE to disk
   b. Plugins → Scylla → "Fix Dump"
      → fixes the IAT of the dumped PE so it runs standalone
   c. Open the fixed dump in Ghidra for static analysis

5. Verify: unpacked PE should have:
   - Normal entropy in .text (< 6.5)
   - Valid IAT with meaningful imports
   - Multiple recognizable functions in Ghidra
```

---

## Workflow Summary Cheat Sheet

```
OPEN SAMPLE
  1. Open in x64dbg (correct bitness)
  2. Enable ScyllaHide + TLS callback breaks + entry point break
  3. Check memory map and module list

INITIAL TRIAGE (before running)
  4. Strings: Right-click → Search for → All Modules → String
  5. Imports: Symbols tab → click DLL names → note suspicious imports

SET BREAKPOINTS
  6. Injection cluster: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
  7. Network: InternetConnect, ws2_32.connect, ws2_32.send
  8. Persistence: RegSetValueEx, CreateService
  9. Crypto: BCryptEncrypt, CryptEncrypt
  10. Logging BPs where you want trace without stopping

RUN AND OBSERVE
  11. F9 to run → land at entry point (or TLS callback)
  12. Walk through anti-analysis checks → ScyllaHide patches automatically
  13. At injection break → note target PID, remote address, shellcode bytes
  14. At crypto break → extract key material before encryption

DUMP AND ANALYZE
  15. If packed → extract at OEP with Scylla
  16. Open dumped binary in Ghidra for static follow-up
```
