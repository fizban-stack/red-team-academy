---
layout: training-page
title: "PE Format Deep Dive — Reverse Engineering — Red Team Academy"
module: "Reverse Engineering"
tags:
  - pe-format
  - portable-executable
  - pe-header
  - imports
  - exports
  - tls-callbacks
  - sections
  - iat
  - eat
  - pefile
  - pe-bear
page_key: "re-pe-format"
render_with_liquid: false
---

# PE Format Deep Dive

The Portable Executable (PE) format is the container for every Windows EXE, DLL, SYS, and OCX file. Understanding it in detail is mandatory for malware RE: the headers tell you what code can do before it runs, sections reveal packing and encryption, TLS callbacks execute before `main`, and the IAT is the primary target for runtime hooking by both malware and EDRs.

Related pages: [RE Workflow & Tool Selection](/reverse-engineering/overview/) · [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/) · [Windows Process Internals](/exploitation/windows-process-internals/)

---

## File Layout Overview

```
Offset 0x00
┌─────────────────────────────────────────────────────┐
│  DOS Header (_IMAGE_DOS_HEADER)        64 bytes     │
│  e_magic = 0x5A4D ("MZ")                            │
│  e_lfanew = offset to PE header                     │
├─────────────────────────────────────────────────────┤
│  DOS Stub (MS-DOS "This program cannot...")         │
├─────────────────────────────────────────────────────┤
│  PE Signature  ("PE\0\0" = 0x00004550)              │
├─────────────────────────────────────────────────────┤
│  File Header (_IMAGE_FILE_HEADER)      20 bytes     │
├─────────────────────────────────────────────────────┤
│  Optional Header (_IMAGE_OPTIONAL_HEADER)           │
│  (96 bytes for 32-bit / 112 bytes for 64-bit)       │
├─────────────────────────────────────────────────────┤
│  Data Directories (16 entries × 8 bytes)            │
├─────────────────────────────────────────────────────┤
│  Section Headers (_IMAGE_SECTION_HEADER × N)        │
│  (40 bytes each)                                    │
├─────────────────────────────────────────────────────┤
│  Section Data (.text, .data, .rsrc, .reloc, ...)    │
└─────────────────────────────────────────────────────┘
```

---

## DOS Header

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;    // 0x5A4D ("MZ") — must be present
    WORD  e_cblp;
    // ... 27 other fields not normally relevant for RE ...
    LONG  e_lfanew;   // file offset to the PE header — the only field that matters
} IMAGE_DOS_HEADER;
```

**e_lfanew** is typically `0x40` or `0x80`. If it points to garbage, the file is not a valid PE (or is a hand-crafted evasion).

The DOS stub between the header and PE signature is freely writable and occasionally used to store encrypted payloads or watermarks.

---

## File Header

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;              // 0x8664 = AMD64, 0x014C = i386, 0xAA64 = ARM64
    WORD  NumberOfSections;     // section count — watch for > 96 (malformed)
    DWORD TimeDateStamp;        // compile timestamp (easily falsified)
    DWORD PointerToSymbolTable; // 0 for PE files (only in COFF)
    DWORD NumberOfSymbols;      // 0 for PE files
    WORD  SizeOfOptionalHeader; // 0xF0 (x64) or 0xE0 (x86)
    WORD  Characteristics;      // IMAGE_FILE_EXECUTABLE_IMAGE etc.
} IMAGE_FILE_HEADER;
```

**TimeDateStamp forensics:**

```python
import pefile, datetime
pe = pefile.PE("sample.exe")
ts = pe.FILE_HEADER.TimeDateStamp
print(datetime.datetime.utcfromtimestamp(ts))
# Compare to known compiler epoch dates:
# 1970-01-01 = zeroed (stripped/spoofed)
# 1992-06-20 = Delphi 1 (old Delphi default)
# Future date = definitely falsified
```

---

## Optional Header (the most useful header)

Despite the name, this is mandatory:

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic;                    // 0x020B = PE32+ (64-bit), 0x010B = PE32
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;      // RVA of first instruction — critical for RE
    DWORD BaseOfCode;
    ULONGLONG ImageBase;            // preferred load address (0x140000000 typical for 64-bit EXEs)
    DWORD SectionAlignment;         // sections aligned to this (4096 typical)
    DWORD FileAlignment;            // raw data aligned to this (512 typical)
    // ... version fields ...
    DWORD SizeOfImage;              // total virtual size when loaded
    DWORD SizeOfHeaders;            // combined header size (raw)
    DWORD CheckSum;                 // PE checksum (0 for most apps; required for drivers)
    WORD  Subsystem;                // 2 = GUI, 3 = Console, 1 = native (drivers)
    WORD  DllCharacteristics;       // security flags (see below)
    // ... stack/heap sizes ...
    DWORD NumberOfRvaAndSizes;      // how many data directories follow (always 16)
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;
```

### DllCharacteristics Flags — Security Feature Detection

```python
import pefile
pe = pefile.PE("sample.exe")
dc = pe.OPTIONAL_HEADER.DllCharacteristics

flags = {
    0x0020: "HIGH_ENTROPY_VA",     # 64-bit ASLR
    0x0040: "DYNAMIC_BASE",        # ASLR enabled
    0x0080: "FORCE_INTEGRITY",     # code signing enforcement
    0x0100: "NX_COMPAT",           # DEP/NX enabled
    0x0400: "NO_SEH",              # no SafeSEH
    0x0800: "NO_BIND",             # no binding
    0x1000: "APPCONTAINER",        # AppContainer isolation
    0x2000: "WDM_DRIVER",          # WDM kernel driver
    0x4000: "GUARD_CF",            # Control Flow Guard
    0x8000: "TERMINAL_SERVER_AWARE"
}
for mask, name in flags.items():
    if dc & mask:
        print(f"  [+] {name}")
    else:
        print(f"  [-] {name}")
```

Malware often lacks `DYNAMIC_BASE`, `NX_COMPAT`, and `GUARD_CF` — these are missing when compiled with older or custom toolchains designed for compatibility over security.

### AddressOfEntryPoint

The entry point RVA is where execution begins. For packed samples, the entry point section often has high entropy and non-standard section characteristics (execute + write). For DLLs, this is `DllMain`.

```
Normal EXE:   EP is in .text (low entropy, low RVA)
Packed EXE:   EP is in a stub section (high entropy, execute+write chars)
.NET EXE:     EP points to tiny stub that calls _CorExeMain
DLL:          EP is optional; 0x0 means no DllMain
```

---

## Data Directories

The 16 data directories describe where specific structures are within the image:

| Index | Name | Purpose |
|-------|------|---------|
| 0 | Export Table | Exports (functions this file provides to others) |
| 1 | Import Table | Imports (functions this file needs from others) |
| 2 | Resource | Icons, version info, embedded payloads |
| 3 | Exception | .pdata — exception handlers (x64) |
| 4 | Security | Authenticode signature |
| 5 | Base Relocation | Fixup table for non-ASLR-preferred loads |
| 6 | Debug | Debug information pointer |
| 9 | TLS | Thread Local Storage — callbacks run before entry point |
| 12 | Import Address Table | IAT — patched by loader at runtime |
| 14 | CLR | .NET header — present for managed code |

---

## Section Headers

Each section header is 40 bytes:

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];              // ASCII name (NOT null-terminated if 8 chars)
    DWORD VirtualSize;          // actual size when loaded
    DWORD VirtualAddress;       // RVA in memory
    DWORD SizeOfRawData;        // size on disk (rounded to FileAlignment)
    DWORD PointerToRawData;     // file offset to raw data
    // ... relocation / line number fields (rarely used) ...
    DWORD Characteristics;      // flags: executable, readable, writable
} IMAGE_SECTION_HEADER;
```

### Section Characteristics

```python
import pefile
pe = pefile.PE("sample.exe")
for s in pe.sections:
    c = s.Characteristics
    exec_  = bool(c & 0x20000000)
    read_  = bool(c & 0x40000000)
    write_ = bool(c & 0x80000000)
    print(f"{s.Name.decode().rstrip(chr(0)):<12} "
          f"{'X' if exec_ else '-'}{'R' if read_ else '-'}{'W' if write_ else '-'}  "
          f"VSize={s.Misc_VirtualSize:#x}  RSize={s.SizeOfRawData:#x}")
```

### Section Red Flags

| Pattern | What It Means |
|---------|--------------|
| `.text` is writable (W+X) | Self-modifying code or packer stub |
| Anonymous section (blank name) | Added by packer/protector |
| Section name not in standard list | Custom sections often used by packers |
| VirtualSize >> SizeOfRawData | Uninitialized data expands in memory (often unpacking target) |
| SizeOfRawData == 0 | No raw data; virtual-only (rare in legit code) |
| Entropy > 7.0 in `.text` or `.data` | Packed/encrypted payload |
| Single section with full R+W+X | Shellcode launcher or simple packer |

### Standard Section Names

| Name | Content |
|------|---------|
| `.text` | Executable code |
| `.data` | Initialized global/static variables |
| `.rdata` | Read-only data (strings, constants, imports/exports) |
| `.bss` | Uninitialized data (zeroed at load) |
| `.rsrc` | Resources (icons, dialogs, embedded files) |
| `.reloc` | Base relocation table |
| `.pdata` | Exception handler data (x64) |
| `.tls` | Thread Local Storage data |
| `.idata` | Import directory (sometimes split from `.rdata`) |
| UPX0, UPX1 | UPX-packed sections |

---

## Import Address Table (IAT) — Critical for RE

The IAT is what makes dynamic RE at the API level possible. The loader patches it at startup; EDRs hook it; malware can stomp it to call syscalls directly.

### IAT Load-Time Patching

```
At file on disk (before load):
  IAT slot for "VirtualAlloc" → points to thunk code or hint/name RVA

At runtime (after loader fixes up):
  IAT slot for "VirtualAlloc" → actual VA of kernel32!VirtualAlloc

When EDR hooks:
  IAT slot for "VirtualAlloc" → EDR trampoline function → original VirtualAlloc
```

### Reading the Full Import Table

```python
import pefile
pe = pefile.PE("sample.exe")

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = dll_entry.dll.decode()
        print(f"\n[{dll}]")
        for imp in dll_entry.imports:
            if imp.name:
                print(f"  {imp.name.decode():<50}  hint={imp.hint}  iat_rva={hex(imp.address)}")
            else:
                print(f"  Ordinal #{imp.ordinal}")
```

### Delayed Imports

`DIRECTORY_ENTRY_DELAY_IMPORT`: DLLs loaded only on first use. Common in malware to defer loading suspicious DLLs past initial static analysis:

```python
if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
    for d in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        print(f"[Delayed] {d.dll.decode()}")
```

### Manual Import Resolution (No Static Imports)

Heavily evasive malware resolves APIs at runtime without static imports:

```c
// Classic pattern in shellcode / packers:
HMODULE ntdll = GetModuleHandleA("ntdll.dll");
// Or: walk PEB.Ldr.InMemoryOrderModuleList to find ntdll (no API calls)

// Walk EAT of ntdll to find NtAllocateVirtualMemory:
PIMAGE_EXPORT_DIRECTORY eat = /* parse from ntdll headers */;
// Hash function names in EAT until hash matches → get function address
```

When you see this pattern in Ghidra, the binary uses custom API resolution. Identify the hash function, precompute the table, and annotate each resolved address as a comment.

---

## Export Address Table (EAT)

The EAT is how a DLL advertises its functions to other modules. In malware, the EAT is relevant for:
- Analyzing malware DLLs that export specific functions (for sideloading)
- Reflective DLL injection (the loader finds itself via EAT)

```python
import pefile
pe = pefile.PE("malware.dll")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode() if exp.name else f"ord#{exp.ordinal}"
        print(f"  {name:<40}  RVA={hex(exp.address)}")
```

**Suspicious export names:**
- Generic names: `Start`, `Run`, `Go`, `Exec` — common DLL side-loading exports
- Mimicking legit DLLs: `DllGetClassObject`, `DllRegisterServer` — COM hijacking
- Single export with ordinal only — shellcode stage loader

---

## TLS Callbacks — Execute Before Entry Point

Thread Local Storage (TLS) callbacks run **before** `AddressOfEntryPoint`. This is used by both protectors (to set up decryption) and malware (to evade debuggers before `main` is reached).

```c
// TLS callback signature:
VOID CALLBACK TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    // Reason = DLL_PROCESS_ATTACH (1) when process starts
    // Code here runs BEFORE WinMain / DllMain
    if (IsDebuggerPresent()) ExitProcess(0);
}

// TLS directory in the PE:
typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;   // NULL-terminated array of callback pointers
    DWORD     SizeOfZeroFill;
    DWORD     Characteristics;
} IMAGE_TLS_DIRECTORY64;
```

**Detecting TLS callbacks:**

```python
import pefile
pe = pefile.PE("sample.exe")
if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print(f"TLS callbacks at: {hex(tls.AddressOfCallBacks)}")
    # In x64dbg: put a breakpoint on this address BEFORE running
```

**In x64dbg:** Options → Preferences → Events → check "TLS Callbacks" to break on each callback automatically.

---

## Resource Section (.rsrc)

Resources store version info, icons, dialogs, and embedded payloads. Common malware uses:

| Resource Type | Malware Use |
|--------------|------------|
| `RT_RCDATA` (type 10) | Embedded payload (encrypted DLL, shellcode) |
| `RT_BITMAP` | Steganographic payload hiding |
| Version info | Forged legitimate software version strings |
| `RT_MANIFEST` | UAC bypass via `requestedExecutionLevel` |

```python
import pefile
pe = pefile.PE("sample.exe")
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for res_id in res_type.directory.entries:
            for res_lang in res_id.directory.entries:
                data = pe.get_data(res_lang.data.struct.OffsetToData,
                                   res_lang.data.struct.Size)
                print(f"Type={res_type.id} ID={res_id.id} "
                      f"Lang={res_lang.id} Size={len(data)} "
                      f"Entropy={calculate_entropy(data):.2f}")
                # High entropy resource → likely encrypted payload
                # Dump it: open('resource.bin','wb').write(data)
```

---

## PE Analysis Quick Reference

```bash
# PE-bear (GUI): open sample, check Sections tab for entropy + characteristics
# Detect-It-Easy: file type, packer, compiler
die sample.exe

# pefile one-liners
python3 -m pefile sample.exe           # basic PE info dump

# Entropy per section
python3 << 'EOF'
import pefile, math
pe = pefile.PE("sample.exe")
for s in pe.sections:
    d = s.get_data(); n = len(d)
    h = -sum(c/n*math.log2(c/n) for c in [d.count(bytes([i])) for i in range(256)] if c)
    print(f"{s.Name.decode().rstrip(chr(0)):<12} entropy={h:.2f}  {'SUSPICIOUS' if h>7 else 'ok'}")
EOF

# FLOSS — find all strings including stack/encoded strings
floss --no-static-strings sample.exe

# Check Authenticode signature
sigcheck -a sample.exe    # Sysinternals
Get-AuthenticodeSignature sample.exe | Select Status, SignerCertificate
```
