---
layout: training-page
title: "Windows Internals for Reverse Engineering — Red Team Academy"
module: "Reverse Engineering"
tags:
  - windows-internals
  - syscall-table
  - ssdt
  - kernel-objects
  - object-manager
  - ntapi
  - api-layers
  - eprocess
  - handles
  - virtual-memory
page_key: "re-windows-internals"
render_with_liquid: false
---

# Windows Internals for Reverse Engineering

To reverse engineer Windows malware effectively you need to understand the operating system structures that malware manipulates. This page covers the kernel architecture, the system call table, the kernel object model, and the full Win32-to-kernel API call chain. Understanding these lets you recognize what a disassembled binary is doing even when API names are stripped.

Related pages: [Windows Process Internals](/exploitation/windows-process-internals/) (PEB/TEB, loader database) · [EDR Internals](/evasion/edr-internals/) (callbacks, hooks) · [Windows Kernel Exploitation](/exploit-dev/kernel-exploitation-windows/) (exploiting kernel bugs)

---

## Privilege Rings

Windows uses two of the four x86/x64 privilege rings:

```
  Ring 3 — User Mode
  ─────────────────────────────────────────────────────
  User processes: calc.exe, chrome.exe, malware.exe
  Can only access own virtual address space.
  Cannot directly touch hardware or kernel memory.
  Communicates with kernel via system calls only.

  ─────── SYSCALL / SYSENTER boundary ────────────────

  Ring 0 — Kernel Mode
  ─────────────────────────────────────────────────────
  ntoskrnl.exe (Executive + kernel core)
  hal.dll      (hardware abstraction)
  Device drivers (*.sys) — same privilege as kernel
  Can access all physical memory, all process memory.
  Runs with full CPU privilege.
```

Malware operating in Ring 3 must use system calls to ask the kernel to do privileged work. Rootkits in Ring 0 have no such restriction — they can manipulate any kernel structure directly.

---

## The System Call Mechanism

### How a Syscall Works (x64)

```asm
; User mode — ntdll.dll stub for NtAllocateVirtualMemory
NtAllocateVirtualMemory:
    mov r10, rcx           ; save first arg (calling convention quirk)
    mov eax, 0x18          ; syscall NUMBER for NtAllocateVirtualMemory
    syscall                ; trap to kernel; CPU switches to Ring 0
    ret
```

The `SYSCALL` instruction:
1. Saves `RIP` (return address) and `RFLAGS` into `IA32_LSTAR` + CPU state
2. Jumps to `KiSystemCall64` in `ntoskrnl.exe`
3. Uses the number in `EAX` to look up the handler in the **SSDT**

### The System Service Descriptor Table (SSDT)

The SSDT (`KeServiceDescriptorTable`) is an array in `ntoskrnl.exe` that maps syscall numbers to function pointers:

```c
// Simplified SSDT layout (internal kernel structure)
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR  Base;         // pointer to the function pointer array
    PULONG      Count;        // per-service call counter (optional)
    ULONG       Limit;        // number of entries
    PUCHAR      Number;       // argument count table
} KSERVICE_TABLE_DESCRIPTOR;

// SSDT entry for syscall N:
//   KiServiceTable[N] encodes a relative offset to the Nt* function
//   Actual address = (KiServiceTable + N * 4) dereference → add KiServiceTable base
```

**Reading the SSDT with WinDbg (kernel debugging):**

```
kd> dps nt!KiServiceTable L20
# Shows first 32 SSDT entries as symbol + offset pairs
# Example:
# fffff803`11234000  fffff803`10abc120 nt!NtAccess CheckAndAuditAlarm+0
# fffff803`11234008  fffff803`10abd340 nt!NtAlpcAcceptConnectPort+0

kd> ? poi(nt!KiServiceTable + (0x18 * 4)) >> 4 + nt!KiServiceTable
# Resolve syscall 0x18 → NtAllocateVirtualMemory
```

**Syscall numbers change between Windows versions.** Syscall 0x18 is `NtAllocateVirtualMemory` on Windows 10 21H2 x64 but may differ on other builds. Malware that uses direct syscalls (bypassing ntdll) must resolve the correct number at runtime.

### Finding Syscall Numbers Programmatically

```python
# Extract all syscall numbers from ntdll.dll
import pefile

ntdll = pefile.PE("C:\\Windows\\System32\\ntdll.dll")
syscalls = {}

for exp in ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name and exp.name.startswith(b"Nt"):
        func_rva = exp.address
        # Syscall stub: mov r10,rcx / mov eax, N / syscall
        # The syscall number is at offset 4 in the stub (after mov r10,rcx)
        data = ntdll.get_data(func_rva, 8)
        if data[0] == 0x4C and data[1] == 0x8B and data[2] == 0xD1:  # mov r10, rcx
            if data[3] == 0xB8:  # mov eax, imm32
                num = int.from_bytes(data[4:8], 'little')
                syscalls[exp.name.decode()] = num

for name, num in sorted(syscalls.items(), key=lambda x: x[1]):
    print(f"0x{num:04X}  {name}")
```

---

## The Windows API Layer Chain

Every malware call flows through multiple layers. Each layer is a hook point — for both EDRs and your RE:

```
Application Code (malware.exe)
    │
    │  calls e.g. CreateFile("C:\secret.txt", ...)
    ▼
kernel32.dll — Win32 API layer
    │  CreateFileW → validates params → calls NtCreateFile
    │  [EDR user-mode hook point: inline hooks on Win32 functions]
    ▼
ntdll.dll — NTAPI layer
    │  NtCreateFile stub → sets EAX = syscall number → SYSCALL
    │  [EDR user-mode hook point: inline hooks on Nt* stubs in ntdll]
    ▼
KiSystemCall64 (ntoskrnl.exe) — kernel entry
    │  Validates syscall number, sets up kernel stack
    │  Dispatches via SSDT to → NtCreateFile (kernel impl)
    │  [EDR kernel callback: IRP filters, ObRegisterCallbacks]
    ▼
I/O Manager → File System Driver → Disk
```

**How malware bypasses EDR hooks at each layer:**

| Layer | EDR Hook Technique | Malware Bypass |
|-------|-------------------|----------------|
| Win32 (kernel32.dll) | Inline hook (JMP to EDR code) | Skip Win32, call NTAPI directly |
| NTAPI (ntdll.dll) | Inline hook on Nt* stubs | Unhook ntdll from disk copy; indirect syscalls |
| Kernel (SSDT) | PatchGuard prevents SSDT patching | BYOVD driver to run code at Ring 0 |
| Kernel callbacks | ObRegisterCallbacks, PsSetLoad­Image­NotifyRoutine | DKOM — remove from callback list |

See [DLL Unhooking](/evasion/dll-unhooking/) and [HookChain & Halo's Gate](/evasion/hookchain/) for implementation details.

---

## Kernel Object Model

### Object Manager

Every kernel resource (file, process, thread, token, event, mutex, section) is a **kernel object** managed by the Object Manager (`ObpRootDirectoryObject`). All objects follow the same header layout before the type-specific body.

```
┌─────────────────────────────────────────────────────┐
│  OBJECT_HEADER  (before every kernel object)        │
│  ─────────────────────────────────────────────────  │
│  PointerCount    — total references                 │
│  HandleCount     — open handles from user mode      │
│  Lock            — spinlock                         │
│  TypeIndex       — index into ObTypeIndexTable[]    │
│  InfoMask        — optional sub-headers present     │
│  ─────────────────────────────────────────────────  │
│  Optional headers (if InfoMask bits set):           │
│    OBJECT_HEADER_CREATOR_INFO                       │
│    OBJECT_HEADER_NAME_INFO  ← object name/namespace │
│    OBJECT_HEADER_HANDLE_INFO                        │
│    OBJECT_HEADER_QUOTA_INFO                         │
│    OBJECT_HEADER_PROCESS_INFO                       │
└─────────────────────────────────────────────────────┘
│  Object Body (type-specific)                        │
│  EPROCESS / ETHREAD / FILE_OBJECT / TOKEN / etc.   │
└─────────────────────────────────────────────────────┘
```

**Locating OBJECT_HEADER from a kernel pointer (WinDbg):**

```
kd> !process 0 0 malware.exe
# Returns: PROCESS ffffb80012345080 ...
kd> dt nt!_OBJECT_HEADER ffffb80012345080-0x30
# 0x30 is the size of OBJECT_HEADER on x64 (subtract to get header from body)
```

### Handles

A **handle** is a user-mode token that indexes into the process's **handle table** (`EPROCESS.ObjectTable`). The kernel translates handle → kernel object pointer internally.

```
User mode:
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
  // hProcess is an integer like 0x1A4 — meaningless outside this process

Kernel perspective:
  EPROCESS.ObjectTable → HANDLE_TABLE
    entry at index (hProcess / 4) → HANDLE_TABLE_ENTRY
      ObjectPointer → EPROCESS of target (kernel VA)
      GrantedAccess → PROCESS_ALL_ACCESS bitmask
```

**Key insight for RE:** When malware calls `OpenProcess` you see a handle value, but the interesting data is `GrantedAccess`. If `PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` are granted, injection follows immediately.

### EPROCESS and the Process List

`ntoskrnl.exe` keeps all processes in a doubly-linked list via `EPROCESS.ActiveProcessLinks`. Rootkits performing **DKOM** (Direct Kernel Object Manipulation) unlink a process from this list to hide it from `EnumProcesses`.

```
kd> !process 0 0          # list all processes via EPROCESS list
kd> dt nt!_EPROCESS       # show EPROCESS layout

Key EPROCESS fields for RE:
  +0x000 Pcb              : _KPROCESS (scheduler data)
  +0x2e0 UniqueProcessId  : PVOID (PID)
  +0x2e8 ActiveProcessLinks: _LIST_ENTRY (forward/back to next EPROCESS)
  +0x358 Token            : _EX_FAST_REF (process security token — target for token stealing)
  +0x3f8 InheritedFromUniqueProcessId: PVOID (parent PID)
  +0x450 ImageFileName    : [15] UCHAR (short process name)
  +0x7d8 WoW64Process     : PVOID (non-null = 32-bit on 64-bit)
```

---

## Virtual Memory Layout (x64 Windows)

The x64 address space is 128 TB per side (user + kernel), but most of it is unmapped. Knowing the layout tells you where to look when you see an address in a disassembler:

```
0x0000000000000000  ┐
        ...          │ User space (Ring 3 readable)
0x00007FFFFFFFFFFF  ┘

── Kernel boundary ───────────────────────────────────────────

0xFFFF800000000000  ┐
        ...          │ PTE self-map (page table entries)
0xFFFFF6FFFFFFFFFF  ┘

0xFFFFF70000000000  ┐ Hyperspace (temporary process mappings)

0xFFFFF78000000000    SharedUserData (KUSER_SHARED_DATA)
                      Read from user mode! Contains:
                        system time, tick count, processor features

0xFFFFF80000000000  ┐
        ...          │ ntoskrnl.exe loaded here (varies with KASLR)
0xFFFFFFFFFFFFFFFF  ┘ Device drivers, kernel heap, paged/non-paged pool
```

**KUSER_SHARED_DATA** at `0x7FFE0000` (user-mode readable copy):

```c
// Malware reads system time without a syscall:
KUSER_SHARED_DATA* kusd = (KUSER_SHARED_DATA*)0x7FFE0000;
ULONGLONG tick = kusd->TickCountQuad;    // milliseconds since boot
ULONGLONG sysTime = kusd->SystemTime;   // FILETIME format
```

This is a common anti-sandbox trick: if tick count is very low (VM just booted for the scan), skip malicious behavior.

### Key User-Space Regions

```
[0x00400000 - 0x7FFEFFFF]  Normal process image and heap range
[0x7FFE0000 - 0x7FFEFFFF]  KUSER_SHARED_DATA (kernel → user shared page)
[0x7FF00000 - 0x7FFFFFFF]  64-bit thread stack (grows down from top)

ntdll.dll typically loads at:    0x7FFA00000000 (ASLR varies)
kernel32.dll typically at:       0x7FFAXXXXXXXX
Stack guard pages:               PAGE_GUARD attribute; access → exception
```

---

## Key Kernel Structures Quick Reference

Use these in WinDbg to navigate kernel memory during malware analysis:

```
kd> dt nt!_EPROCESS              # full process control block
kd> dt nt!_ETHREAD               # thread control block (links to EPROCESS)
kd> dt nt!_TOKEN                 # security token (privileges, groups)
kd> dt nt!_FILE_OBJECT           # open file kernel object
kd> dt nt!_LDR_DATA_TABLE_ENTRY  # loaded module entry (module list)
kd> dt nt!_OBJECT_HEADER         # object header (before any kernel object)
kd> dt nt!_HANDLE_TABLE          # process handle table

kd> !object \                    # dump object namespace root
kd> !object \KnownDlls           # see kernel-mode DLL section objects
kd> !handle 0 f <pid>            # dump all handles for a process

# Walk EPROCESS list:
kd> !list -x "dt nt!_EPROCESS @$extret" poi(nt!PsActiveProcessHead)
```

---

## Syscall Number Tables (Windows 10 x64)

The most important Nt* functions to recognize in disassembly:

| Syscall # | Nt* Function | Win32 Equivalent | Malware Use |
|-----------|-------------|-----------------|------------|
| 0x18 | NtAllocateVirtualMemory | VirtualAlloc | Shellcode staging |
| 0x1F | NtWriteVirtualMemory | WriteProcessMemory | Injection |
| 0x3D | NtReadVirtualMemory | ReadProcessMemory | Memory scraping |
| 0x4D | NtOpenProcess | OpenProcess | Handle to target |
| 0xC2 | NtCreateThreadEx | CreateRemoteThread | Remote thread |
| 0x25 | NtMapViewOfSection | MapViewOfFile | Section injection |
| 0x23 | NtCreateSection | CreateFileMapping | Shared memory |
| 0x55 | NtQueueApcThread | QueueUserAPC | APC injection |
| 0x12 | NtSetContextThread | SetThreadContext | Thread hijack |
| 0x02 | NtQuerySystemInformation | — | Process enumeration |
| 0xF | NtDelayExecution | Sleep | Timing evasion |

> Numbers vary by OS build. Use the [j00ru syscall table](https://j00ru.vexillium.org/syscalls/nt/64/) for exact mappings per Windows version.
