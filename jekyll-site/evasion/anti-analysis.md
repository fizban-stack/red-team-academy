---
layout: training-page
title: "Anti-Analysis Techniques — Red Team Academy"
module: "Evasion"
tags:
  - anti-debug
  - anti-sandbox
  - anti-vm
  - edr-bypass
  - timing
  - windows-internals
page_key: "evasion-anti-analysis"
render_with_liquid: false
---

# Anti-Analysis Techniques

Anti-analysis techniques detect or disrupt reverse engineering, debuggers, sandboxes, and VM-based analysis environments. Effective malware combines multiple detection layers: API-based checks, PEB/TEB inspection, timing attacks, hardware register inspection, and exception-based traps.

## Anti-Debugging

### PEB.NtGlobalFlag Detection

Debuggers set heap flags in the Process Environment Block. Flag `0x70` = `FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`.

```cpp
bool CheckNtGlobalFlag() {
#ifdef _M_X64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return (pPeb->NtGlobalFlag & 0x70) != 0;
}
```

### Trap Flag (Single Step via EFLAGS)

Setting the TF bit causes a single-step exception. Debuggers handle this differently than the OS.

```cpp
bool TrapFlagCheck() {
    __try {
        __asm {
            pushfd
            or dword ptr [esp], 0x100  // Set Trap Flag
            popfd
            nop
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}
```

### Prefix Hopping (Undocumented Trick)

Confuses debuggers that don't handle mixed prefix/opcode sequences.

```cpp
__declspec(naked) void PrefixHop() {
    __asm {
        __emit 0xF3    // REP prefix
        __emit 0x64    // FS:
        __emit 0xF1    // ICEBP (undocumented 1-byte breakpoint)
        ret
    }
}
```

### INT 2D (Anti-OllyDbg / Immunity)

OllyDbg and Immunity Debugger handle `INT 0x2D` differently than the OS — the OS generates an exception, debuggers may swallow it.

```cpp
bool Int2DCheck() {
    __try {
        __asm {
            pushad
            mov al, 0
            int 0x2D
            popad
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}
```

### Hardware Breakpoint Detection (DR0–DR7)

Debug registers DR0–DR3 hold hardware breakpoint addresses. DR7 controls which are active.

```cpp
bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return true;
    }
    return false;
}
```

### RDTSC Timing Check

Debuggers slow execution significantly. RDTSC measures CPU cycles — if elapsed cycles are too low for the elapsed wall-clock time, a debugger is likely present.

```cpp
bool TimingCheckRDTSC() {
    unsigned __int64 t1 = __rdtsc();
    Sleep(10);
    unsigned __int64 t2 = __rdtsc();
    return (t2 - t1 < 1000000);  // Too fast => debugger interference
}
```

### Thread Hiding via NtSetInformationThread

`ThreadInformationClass 0x11` (ThreadHideFromDebugger) causes the thread to be invisible to attached debuggers.

```cpp
void HideThread() {
    typedef NTSTATUS(WINAPI* pNtSetInformationThread)(
        HANDLE, THREADINFOCLASS, PVOID, ULONG);

    auto NtSIT = (pNtSetInformationThread)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");

    if (NtSIT)
        NtSIT(GetCurrentThread(), (THREADINFOCLASS)0x11, NULL, 0);
}

// Apply to payload thread to prevent breakpoints hitting it
void HidePayloadThread() {
    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Payload, 0, 0, 0);
    auto NtSIT = (pNtSetInformationThread)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (NtSIT)
        NtSIT(hThread, (THREADINFOCLASS)0x11, 0, 0);
}
```

### Self-Debugging Check

A process cannot have two debuggers. Attempting `DebugActiveProcess` on itself fails if another debugger is already attached.

```cpp
bool SelfDebugCheck() {
    if (DebugActiveProcess(GetCurrentProcessId())) {
        DebugActiveProcessStop(GetCurrentProcessId());
        return false;  // No other debugger
    }
    return true;  // Another debugger blocked the call
}
```

### TLS Callbacks (Pre-Entry Point Execution)

TLS callbacks execute before `main()` / `WinMain()` / `DllMain()`. Most debuggers miss these if breakpoints are set at the entry point.

```cpp
void NTAPI TLSCallback(PVOID, DWORD dwReason, PVOID) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Anti-debug checks run here before main()
        if (CheckNtGlobalFlag() || CheckHardwareBreakpoints()) {
            ExitProcess(0);
        }
    }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:__tls_callback")

extern "C" {
    PIMAGE_TLS_CALLBACK __tls_callback = TLSCallback;
}
```

### NtQueryInformationProcess — DebugPort

Detects a debugger at the kernel level via the debug port (non-zero when a debugger is attached).

```cpp
bool NtDebugPortCheck() {
    typedef NTSTATUS(WINAPI* pNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    DWORD debugPort = 0;
    auto NtQIP = (pNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                         "NtQueryInformationProcess");

    NTSTATUS status = NtQIP(GetCurrentProcess(),
        (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), NULL);

    return (status == 0 && debugPort != 0);
}
```

### Heap Flags Check

Debuggers enable additional heap validation flags that are detectable at runtime.

```cpp
bool HeapFlagsCheck() {
    HANDLE heap = GetProcessHeap();
    ULONG flags = *(PULONG)((PUCHAR)heap + 0x0C);
    ULONG forceFlags = *(PULONG)((PUCHAR)heap + 0x10);
    return (flags & HEAP_TAIL_CHECKING_ENABLED) || (forceFlags != 0);
}
```

### ntdll Inline Hook Detection

Detect debugger or EDR hooks by comparing in-memory ntdll bytes against a disk copy.

```cpp
bool NtdllInlineHookCheck() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC func = GetProcAddress(hNtdll, "NtClose");
    BYTE* b = (BYTE*)func;
    return (b[0] == 0xCC || b[0] == 0xE9 || b[0] == 0xE8 || b[0] == 0xEB);
}

bool CompareNtdllMemoryWithDisk() {
    HMODULE hMem = GetModuleHandleA("ntdll.dll");
    TCHAR path[MAX_PATH];
    GetModuleFileNameA(hMem, path, MAX_PATH);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    HANDLE hMap = CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0, 0);
    BYTE* diskData = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    BYTE* memData = (BYTE*)hMem;

    bool hooked = false;
    for (int i = 0; i < 1024; i++) {
        if (memData[i] != diskData[i]) { hooked = true; break; }
    }

    UnmapViewOfFile(diskData);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return hooked;
}
```

---

## Anti-Sandbox Techniques

Sandboxes (Cuckoo, Any.Run, Joe Sandbox, Hybrid Analysis) run malware in controlled environments for a limited time. Detecting sandbox artifacts causes the malware to abort execution or appear benign.

### Known Process Detection

Sandbox environments run characteristic processes that can be enumerated.

```cpp
bool IsSandboxProcessPresent() {
    const char* suspicious[] = {
        "vmsrvc.exe", "vmwaretray.exe", "vmtoolsd.exe", "df5serv.exe",
        "vboxservice.exe", "vboxtray.exe", "xenservice.exe", "joeboxcontrol.exe"
    };

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &pe32)) {
        do {
            for (auto& name : suspicious) {
                if (_stricmp(pe32.szExeFile, name) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}
```

### Sleep Skipping Detection

Many sandboxes hook `Sleep()` and reduce or eliminate the delay. Measure actual elapsed time to detect this.

```cpp
bool SleepTimingCheck() {
    DWORD start = GetTickCount();
    Sleep(5000);
    DWORD elapsed = GetTickCount() - start;
    return (elapsed < 4000);  // sandbox likely skipped sleep
}
```

### RDTSC Timing Check

Emulated or virtualized environments may not increment TSC correctly.

```cpp
bool RdtscTimingCheck() {
    unsigned int t1, t2;
    __asm {
        rdtsc
        mov t1, eax
        rdtsc
        mov t2, eax
    }
    return (t2 - t1 < 100);  // very small delta = emulation or sandbox
}
```

### Mouse Movement Detection

Sandboxes typically don't simulate human input. Wait for genuine cursor movement before executing payload.

```cpp
bool MouseMovedRecently() {
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    Sleep(3000);
    GetCursorPos(&pt2);
    return (pt1.x != pt2.x || pt1.y != pt2.y);
}
```

### Username / Computer Name Checks

Sandboxes use generic names that reveal their purpose.

```cpp
bool CheckUserComputerName() {
    char user[256], comp[256];
    DWORD size = 256;

    GetUserNameA(user, &size);
    size = 256;
    GetComputerNameA(comp, &size);

    const char* bad[] = { "sandbox", "malware", "test", "lab", "analyst" };

    for (auto& keyword : bad) {
        if (strstr(user, keyword) || strstr(comp, keyword))
            return true;
    }
    return false;
}
```

### Screen Resolution Check

VMs and sandboxes often run at lower resolution to save resources.

```cpp
bool LowResCheck() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    return (width < 1024 || height < 768);
}
```

### Low Memory Check

Sandbox VMs are often allocated minimal RAM.

```cpp
bool LowMemoryCheck() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    return (statex.ullTotalPhys < (2LL * 1024 * 1024 * 1024));  // < 2 GB
}
```

### Registry Artifact Detection

Sandboxie and other tools leave registry keys.

```cpp
bool SandboxieRegistryCheck() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Sandboxie",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}
```

---

## Anti-VM Detection

Malware detects virtual machines to avoid analysis environments. Real-world families using these techniques include Lokibot, Agent Tesla, Redline Stealer, and Qbot.

### CPUID Hypervisor Bit

The `CPUID` instruction exposes a hypervisor present bit in ECX bit 31 when running under a hypervisor.

```cpp
#include <intrin.h>

bool IsRunningInVM_CPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] >> 31) & 1;
}
```

### MAC Address Prefix Detection

VM platforms use well-known NIC MAC address prefixes.

```cpp
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

bool HasVMMacAddress() {
    PIP_ADAPTER_INFO adapterInfo;
    DWORD bufLen = sizeof(IP_ADAPTER_INFO);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);

    if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
    }

    if (GetAdaptersInfo(adapterInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            char macStr[18];
            sprintf_s(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                adapter->Address[0], adapter->Address[1], adapter->Address[2],
                adapter->Address[3], adapter->Address[4], adapter->Address[5]);

            // VMware: 00:05:69, 00:0C:29, 00:50:56 | VirtualBox: 08:00:27
            if (strncmp(macStr, "00:05:69", 8) == 0 ||
                strncmp(macStr, "00:0C:29", 8) == 0 ||
                strncmp(macStr, "08:00:27", 8) == 0 ||
                strncmp(macStr, "00:50:56", 8) == 0) {
                free(adapterInfo);
                return true;
            }
            adapter = adapter->Next;
        }
    }

    free(adapterInfo);
    return false;
}
```

### VM Driver / Registry Checks

VM guest tools install services and drivers detectable via the registry.

```cpp
bool CheckVMwareTools() {
    HKEY hKey;
    // Check for vmtools, vmmouse, vmhgfs, VBoxService, VBoxGuest, qemu-ga
    const char* vmKeys[] = {
        "SYSTEM\\CurrentControlSet\\Services\\vmtools",
        "SYSTEM\\CurrentControlSet\\Services\\vmmouse",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    };
    for (auto& key : vmKeys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}
```

### BIOS / SMBIOS String Enumeration

VM platforms embed identifiable strings in firmware tables.

```cpp
bool CheckBIOSforVM() {
    char buf[4096];
    if (GetSystemFirmwareTable('RSMB', 0, buf, sizeof(buf))) {
        if (strstr(buf, "VMware") || strstr(buf, "VirtualBox") ||
            strstr(buf, "QEMU")   || strstr(buf, "Xen") ||
            strstr(buf, "Hyper-V")) {
            return true;
        }
    }
    return false;
}
```

### Device Path Detection

VirtualBox installs a mini redirector device accessible via a named device path.

```cpp
bool CheckVBoxDevice() {
    HANDLE hDevice = CreateFileA("\\\\.\\VBoxMiniRdrDN",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}
```

---

## Timing-Based Evasion

Sandboxes often run malware for only a few seconds, or accelerate `Sleep()` to bypass time-based delays. Combining multiple timing mechanisms defeats most sandbox evasion countermeasures.

### Multi-Timer Combination

```cpp
#include <windows.h>
#include <iostream>

bool TimingEvasion() {
    // Method 1: GetTickCount + Sleep
    DWORD start = GetTickCount();
    Sleep(5000);
    if (GetTickCount() - start < 4000) return true;  // sandbox skipped sleep

    // Method 2: QueryPerformanceCounter (high-resolution)
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    Sleep(3000);
    QueryPerformanceCounter(&t2);
    double elapsed = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart;
    if (elapsed < 2.0) return true;

    // Method 3: CPU-bound loop (sandbox accelerates Sleep but not loops)
    DWORD loopStart = GetTickCount();
    for (volatile int i = 0; i < 100000000; ++i) {}
    if (GetTickCount() - loopStart < 500) return true;

    return false;
}
```

### CreateTimerQueueTimer (Stealthier Than Sleep)

Less monitored by AV/EDR than `Sleep()` because it uses a different code path.

```cpp
void CALLBACK TimerCallback(PVOID lpParam, BOOLEAN) {
    // Continue execution after timer fires
}

void StealthDelay(DWORD ms) {
    HANDLE hTimer = NULL;
    CreateTimerQueueTimer(&hTimer, NULL, TimerCallback, NULL, ms, 0, 0);
    Sleep(ms + 1000);  // Wait for timer to fire
}
```

### Stage-Based Execution Pattern

Real-world malware (TrickBot, Emotet, LockBit 3.0) uses staged execution: initial stub runs timing checks, and only decrypts/executes the payload if all checks pass.

```
Stage 1 (stub):
  → Anti-debug checks
  → Anti-VM checks
  → Sleep + timing verification
  → Anti-sandbox process scan
  → If all pass: decrypt and jump to Stage 2

Stage 2 (payload):
  → Actual malicious functionality
```

---

## Technique Summary

| Technique | Bypasses | Bypassed By |
|-----------|----------|-------------|
| IsDebuggerPresent / PEB check | Basic debuggers | ScyllaHide, TitanHide |
| Trap Flag / INT 2D | OllyDbg, Immunity | Advanced debuggers |
| TLS callback | Entry-point breakpoints | Static scanners |
| VEH/SEH traps | Most debuggers | Advanced RE tools |
| DRx register check | Hardware breakpoints | Manual register clear |
| Self-debugging | All second debuggers | Process injection |
| Sleep timing | Sandbox time skipping | Physical timer acceleration |
| RDTSC | Emulated TSC | Hardware passthrough |
| Mouse detection | Automated sandboxes | Simulated input |
| CPUID hypervisor bit | VM environments | Hypervisor masking |
| MAC prefix | VirtualBox/VMware | Custom MAC assignment |

---

## Resources

- Al-Khaser (hundreds of anti-debug/anti-VM/anti-sandbox tests) — `github.com/LordNoteworthy/al-khaser`
- Flare-VM (malware analysis environment) — `github.com/mandiant/flare-vm`
- Malgamy Anti-Debugging Series (5-part deep dive) — `malgamy.github.io/revese%20enginnering/`
- MITRE ATT&CK T1497 — Virtualization/Sandbox Evasion
- MITRE ATT&CK T1622 — Debugger Evasion
