---
layout: training-page
title: "WinDbg Reference — Red Team Academy"
module: "Evasion"
tags:
  - windbg
  - debugging
  - kernel-debugging
  - reverse-engineering
  - crash-analysis
page_key: "evasion-windbg-reference"
render_with_liquid: false
---

# WinDbg Reference

WinDbg is the primary debugger for Windows kernel and user-mode investigation. This page is a practical command reference for crash analysis, kernel debugging, driver research, and exploit development. Covers both user-mode and kernel-mode workflows.

---

## Setup

### Symbol Configuration

```
# One-time environment variable (all tools honor this):
_NT_SYMBOL_PATH=SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols

# Session-level:
.symfix          ; configure MS public symbol server with default cache
.reload          ; (re)load symbols for all loaded modules
.reload /f       ; force reload even if already loaded
lm               ; verify — look for "pdb symbols" vs "deferred"

# If BPs don't bind — it's almost always symbols:
.reload /f modulename.dll
```

### Launching & Attaching

```
# Launch process under debugger:
windbg.exe notepad.exe
windbg.exe -g target.exe arg1 arg2   ; -g = don't break at entry

# Attach to running process (by PID):
windbg.exe -p <PID>
# Or GUI: File → Attach to Process → select PID

# Open crash dump:
windbg.exe -z C:\crash.dmp
# Or GUI: File → Open Dump File

# Kernel debugging (attach to VM — see kernel-exploitation.md for setup):
windbg.exe -k net:port=51111,key=1.2.3.4
```

---

## User-Mode Commands

### Process & Thread Survey

```
~              ; list all threads (shows TEB, state, index)
~0s            ; switch to thread 0
~1k            ; show thread 1's stack without switching
~*k            ; show stacks for ALL threads (triage deadlocks)
~*e <cmd>      ; execute <cmd> in every thread context

|              ; list processes (multi-process debugging)
|0s            ; switch to process 0
```

### Symbol & Module Inspection

```
lm             ; list loaded modules (addresses, symbol state)
lm kv nt       ; verbose listing for 'nt' (ntoskrnl / ntdll)
x notepad!*    ; list all symbols in notepad
x user32!*MessageBox*   ; wildcard symbol search
ln <address>   ; list nearest symbols to address (resolve unknown addr)
```

### Registers & Memory

```
r              ; show all registers
r rax          ; show single register
r rip=<addr>   ; modify register (dangerous — use in controlled lab)

# Memory display:
db <addr>      ; display bytes
dw <addr>      ; display words (2-byte)
dd <addr>      ; display dwords (4-byte)
dq <addr>      ; display qwords (8-byte)
da <addr>      ; display ASCII string
du <addr>      ; display Unicode string
dp <addr>      ; display pointer-sized values

# Display N units: db <addr> L<count>
db 0x7ff6ab001234 L20    ; 0x20 bytes

# Dereference pointer: poi(addr) = *(addr)
dq poi(@rsp)   ; dereference RSP and show qwords there

# Write to memory:
eb <addr> <byte> [<byte>...]   ; write bytes
eq <addr> <qword>              ; write qword (64-bit value)

# Search memory:
s -b <start> L<len> <bytes>    ; search for byte pattern
s -a <start> L<len> "string"   ; search for ASCII string
```

### Call Stacks

```
k      ; call stack with addresses
kb     ; call stack with first 3 args per frame
kv     ; verbose stack (frame data)
kp     ; stack with full parameter values (needs private symbols)
kn     ; numbered frames

.frame <N>     ; switch to frame N (for dv/dt in that frame)
```

### Breakpoints

```
# Software breakpoints:
bp <symbol>          ; by symbol: bp kernel32!CreateFileW
bp <address>         ; by address: bp 0x7ff6ab001234
bu <symbol>          ; deferred/unresolved (re-arms on DLL load/reload)
bm *!*malloc*        ; wildcard — needs private symbols

# Hardware (data) breakpoints:
ba r4 <addr>         ; break on 4-byte read
ba w4 <addr>         ; break on 4-byte write
ba e1 <addr>         ; break on execute (1-byte)
ba w1 poi(@rsp+28)   ; write to address at [rsp+28]
ba r4 @$peb+0x0      ; break on read of PEB start

# Managing breakpoints:
bl                   ; list all breakpoints
bd <N>               ; disable breakpoint N
be <N>               ; enable breakpoint N
bc <N>               ; clear breakpoint N
bc *                 ; clear all

# Conditional BP (break only when condition is true):
bp kernel32!HeapAlloc "j @rcx==4 ''; 'gc'"
# Break on HeapAlloc only when heap handle == 4; else gc (go conditional)
```

### Run Control

```
g [addr]       ; go (run); optionally run until address
t              ; step into (trace, F11)
p              ; step over (F10)
pc             ; step until next CALL
gu             ; step out (go up, return to caller)
gh / gn        ; go handled / go not handled (after exception)
```

### Exception Handling

```
# First-chance vs second-chance:
# First: debugger notified, program can still handle it
# Second: unhandled → your crash triage point

sxe av         ; break on first-chance access violation
sxe eh         ; break on first-chance C++ exception
sxn av         ; notify (print) but don't break on AV
sxd av         ; disable (ignore) AV exception
sx             ; list current exception settings

# After a crash:
!analyze -v    ; automated root cause analysis (crash dump + live)
```

### Type & Structure Inspection

```
dt <type> [<address>]        ; dump type layout / value at address
dt _PEB @$peb                ; PEB via pseudo-register
dt -r _PEB @$peb             ; recurse into sub-structures
dt -r2 _EPROCESS <addr>      ; limit recursion depth to 2

dv                           ; locals in current frame (needs private symbols)
dt this                      ; dump 'this' pointer type

# Discover types:
dt nt!_*process*             ; wildcard search for type names

# Modern dx viewer (WinDbg Preview):
dx @$peb                     ; browse PEB with hyperlinks
dx @$curthread.Stack.Frames  ; current thread call frames
.prefer_dml 1                ; enable hyperlinked output
```

### Heap Analysis

```
!heap                        ; list all heaps in process
!heap -s                     ; heap stats
!heap -i <heap> <addr>       ; decode block at address (size, state, checksum)
!heap -p -a <addr>           ; page heap: show alloc/free call stacks

# Enable page heap (crash at write site):
gflags.exe /i target.exe +hpa
```

---

## Kernel-Mode Commands

### Kernel Setup (After Attach)

```
.symfix; .reload             ; always run first
!analyze -v                  ; crash dump analysis (after BSOD)
kv                           ; kernel call stack

# Verify symbols:
lm kv nt                     ; check ntoskrnl symbol state
```

### Process & Thread (Kernel)

```
!process 0 0                 ; list all processes (PID, handle count, EPROCESS addr)
!process 0 1                 ; with additional detail
!process <addr> 7            ; full detail for specific EPROCESS (threads, handles, VAD)
dt nt!_EPROCESS <addr>       ; inspect EPROCESS fields directly

!thread                      ; current thread (ETHREAD)
dt nt!_ETHREAD <addr>        ; inspect ETHREAD fields

# Find process by name:
!process 0 0 notepad.exe

# Hidden process detection (DKOM forensics):
!psscan                      ; scan memory for EPROCESS structs (finds DKOM-unlinked ones)
```

### Driver & Module Inspection (Kernel)

```
lm kv                        ; list all kernel modules with bases
!drivers                     ; list loaded drivers with device objects
!drvobj <drivername> 2       ; detail for a driver object (device objects, dispatch table)
!devobj <addr>               ; inspect a device object
!object \Driver              ; enumerate driver object directory
!object \Device              ; enumerate all device objects

# Compare module list vs memory map (DKOM detection):
lm                           ; modules in PsLoadedModuleList
!address -summary            ; all mapped regions
```

### Memory (Kernel)

```
!vm 1                        ; system-wide memory stats (pool, paged, nonpaged)
!vm 2                        ; more detail

# Pool analysis:
!poolused 2                  ; nonpaged pool usage by tag (find leaks)
!poolfind <tag>              ; find pool allocations by tag
!pool <addr>                 ; inspect pool chunk at address

# Physical memory:
!pte <virtual_addr>          ; walk page table entries for an address
```

### IRP & I/O Inspection

```
!irp <addr>                  ; inspect an IRP structure
!irpfind                     ; scan for pending IRPs in kernel pool
!devstack <devobj>           ; show device stack (layered drivers)
```

### EPROCESS Token & Security

```
# Token offset varies by build — verify with:
dt nt!_EPROCESS              ; find Token field offset
dt nt!_TOKEN <token_addr>    ; inspect token fields

# EPROCESS offsets (Windows 10/11 x64 approximate — always verify):
# Win10 1903-20H2:  Token @ +0x360
# Win10 21H1+:      Token @ +0x4b8
# Win11 22H2:       Token @ +0x4b8
```

### Kernel Debugging Live Commands

```
# Read/write kernel memory (requires kernel debugger attached):
db <kernel_addr>             ; read bytes from kernel address
dq <kernel_addr>             ; read qwords
eb <kernel_addr> <byte>      ; write byte (will BSOD if PatchGuard catches it)

# Breakpoints in kernel:
bp nt!NtCreateFile           ; break when NtCreateFile is called
bp nt!MiAllocatePoolPages    ; break on pool allocations
bu nt!NtCreateFile           ; deferred (survives symbol reload)

# Module load events:
sxe ld:mydriver              ; break when mydriver.sys loads
```

---

## Crash Dump Analysis

```
# Standard crash dump triage workflow:
.symfix; .reload             ; configure symbols
!analyze -v                  ; automated analysis → suggests next steps
kv                           ; verbose call stack
!process 0 0                 ; find owning process
dt nt!_EPROCESS <addr>       ; inspect process

# Common BSOD codes:
# 0x50  PAGE_FAULT_IN_NONPAGED_AREA   — null deref or freed page access
# 0x3B  SYSTEM_SERVICE_EXCEPTION      — exception in kernel service
# 0x7E  SYSTEM_THREAD_EXCEPTION_NOT_HANDLED — unhandled kernel exception
# 0x109 CRITICAL_STRUCTURE_CORRUPTION — PatchGuard violation
# 0xD1  DRIVER_IRQL_NOT_LESS_OR_EQUAL — driver accessed paged memory at DISPATCH+

# After analyzing, dump mini output:
.dump /ma C:\crash_full.dmp  ; create full memory dump from live kernel
```

---

## Automation: JavaScript Data Model

```javascript
// triage.js — find frames containing strcpy/memcpy across all threads
function suspiciousFrames() {
    var hits = [];
    var threads = host.currentProcess.Threads;
    for (var t of threads) {
        var frames = t.Stack.Frames;
        for (var f of frames) {
            var sym = f.Function ? f.Function.Name : "";
            if (sym && (sym.indexOf("memcpy") >= 0 || sym.indexOf("strcpy") >= 0)) {
                hits.push({ ThreadId: t.Id, Frame: sym });
            }
        }
    }
    return hits;
}
```

```
# Load and use in WinDbg:
.scriptload C:\path\triage.js
dx @$scriptContents.suspiciousFrames()
```

---

## Time Travel Debugging (TTD)

WinDbg Preview supports recording execution and stepping backwards:

```
# Record a process (requires WinDbg Preview + admin):
windbg.exe -start -out C:\recordings\ target.exe

# Open TTD recording:
windbg.exe -z C:\recordings\target.run

# TTD-specific commands:
!tt 0%              ; go to beginning of trace
!tt 100%            ; go to end of trace
!steps              ; list all recorded steps
g-                  ; step backwards
t-                  ; trace backwards
p-                  ; step over backwards

# Find previous occurrence of an event:
bp kernel32!CreateFileW; g-   ; find previous CreateFileW call
```

---

## Quick Reference Card

| Task | Command |
|------|---------|
| Symbol setup | `.symfix; .reload` |
| Crash triage | `!analyze -v` |
| Call stack | `k` / `kv` / `kb` |
| List threads | `~` |
| List modules | `lm` |
| Set BP on symbol | `bp kernel32!CreateFileW` |
| Data BP on write | `ba w4 <addr>` |
| Dump structure | `dt nt!_EPROCESS <addr>` |
| List processes (kernel) | `!process 0 0` |
| Hidden process scan | `!psscan` |
| Pool usage | `!poolused 2` |
| Memory stats | `!vm 1` |
| Heap block info | `!heap -i <heap> <addr>` |
| Step into / over | `t` / `p` |
| Step out | `gu` |
| Go to address | `g <addr>` |
| Search memory | `s -b <start> L<len> <bytes>` |
| Nearest symbol | `ln <addr>` |

---

## Resources

- WinDbg documentation — `docs.microsoft.com/windows-hardware/drivers/debugger/`
- WinDbg Preview (Microsoft Store) — includes TTD and modern UI
- SOS .NET debugging extension — `docs.microsoft.com/dotnet/core/diagnostics/sos-debugging-extension`
- LiveKd (Sysinternals) — local kernel debugging without reboot — `sysinternals.com/downloads/livekd`
- Inside Windows Debugging (Kesavan) — comprehensive WinDbg reference
- Windows Kernel Programming (Yosifovich) — driver debugging with WinDbg
