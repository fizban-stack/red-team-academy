---
layout: training-page
title: "BOF Development Overview — Red Team Academy"
module: "Tool Development"
tags:
  - bof
  - beacon-object-file
  - coff
  - cobalt-strike
  - post-exploitation
  - opsec
  - in-memory
page_key: "tool-dev-bof-overview"
render_with_liquid: false
---

# BOF Development Overview

Beacon Object Files (BOFs) are COFF (Common Object File Format) compiled objects that Cobalt Strike's Beacon loads and executes in-process, directly within the Beacon process address space. Unlike traditional post-exploitation that spawns new processes or drops executables to disk, BOFs execute without creating child processes, without writing files to disk, and without triggering the process creation events that EDR solutions monitor. This makes BOFs the primary post-exploitation primitive for operators who need to minimize EDR telemetry.

---

## What BOFs Are

A BOF is a compiled `.o` (object file) — not a `.exe` or `.dll`. It is the output of a C compiler before the linking stage. When Beacon receives a BOF, it:

1. Loads the COFF sections into memory (`.text`, `.data`, `.rdata`)
2. Processes relocations (resolves addresses)
3. Resolves imported symbols (Beacon API, Windows API)
4. Transfers execution to the BOF's `go()` entry function
5. BOF executes, uses Beacon API for output
6. Beacon reclaims memory after BOF returns

**Key properties:**
- Runs in the **Beacon process** — no new process created
- **No C runtime**: no `malloc`, `printf`, `strlen` from MSVCRT
- **No exception handling**: SEH not set up, crashes = Beacon crash
- Must use **Beacon API** (not standard stdio) for output
- Short-lived: executes and returns, no persistent threads

---

## COFFLoader Internals

Understanding the loader helps write more reliable BOFs:

```c
// Simplified COFFLoader logic (what Beacon does internally):

typedef struct {
    PCHAR Name;
    PVOID Address;
} SYMBOL;

void load_and_execute_bof(PBYTE coff_data, size_t coff_size, PBYTE args, int args_size) {
    // 1. Parse COFF header
    PIMAGE_FILE_HEADER hdr = (PIMAGE_FILE_HEADER)coff_data;
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(coff_data + sizeof(IMAGE_FILE_HEADER));
    
    // 2. Allocate memory for each section
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        PVOID section_mem = VirtualAlloc(NULL, sections[i].SizeOfRawData, 
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(section_mem, coff_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
    }
    
    // 3. Process relocations (fix up addresses)
    process_relocations(coff_data, sections, hdr->NumberOfSections);
    
    // 4. Resolve symbols (Beacon API + Windows API)
    resolve_symbols(coff_data, hdr);
    
    // 5. Find entry point: symbol named "go"
    PVOID entry = find_symbol("go");
    
    // 6. Execute
    typedef void (*GoFunc)(PBYTE, int);
    GoFunc go = (GoFunc)entry;
    go(args, args_size);
    
    // 7. Free section memory
    cleanup_sections();
}
```

### Symbol Resolution

BOFs reference Windows API functions and Beacon API functions by name. The loader resolves these:

```c
// In BOF source: calling Windows API via BOF-compatible pattern
// Instead of: HANDLE h = OpenProcess(...)
// You must use: HANDLE (WINAPI * pOpenProcess)(DWORD, BOOL, DWORD) = ...

// beacon.h provides macros that resolve at runtime:
WINAPI_FUNC(OpenProcess);
// Expands to: dynamic resolution via GetProcAddress equivalent

// Or the common pattern using DECLSPEC_IMPORT:
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
// Resolved by COFFLoader to: GetModuleHandle("kernel32") → GetProcAddress("OpenProcess")
```

---

## BOF vs Traditional Post-Exploitation

EDR telemetry comparison for common post-exploitation tasks:

| Action | Traditional (cmd.exe) | BOF Equivalent | Telemetry Difference |
|--------|---------------------|---------------|---------------------|
| Network scan | spawn nmap.exe | port-scan BOF | No process create event |
| List shares | net.exe view | NetShareEnum BOF | No net.exe creation, no command line |
| Dump credentials | spawn mimikatz.exe | nanodump BOF | No child process, no disk write |
| Privilege check | whoami.exe /priv | token-enumerate BOF | No whoami.exe spawn |
| DNS lookup | nslookup.exe | DnsQuery_A BOF | No nslookup.exe process |
| Registry read | reg.exe query | RegQueryValue BOF | No reg.exe, no command line |

**What EDRs still detect:**
- BOF memory allocation (VirtualAlloc RWX) — use RW→RX instead
- Suspicious API call patterns from Beacon process (e.g., Beacon → OpenProcess(LSASS))
- Hook-based API monitoring (userland hooks in kernel32, ntdll)
- ETW (Event Tracing for Windows) events from API calls

---

## BOF Limitations

Understanding limitations prevents common mistakes:

| Limitation | Consequence |
|-----------|-------------|
| No C runtime | Cannot use printf, malloc, free, strlen, memcpy from MSVCRT |
| No exception handling | Crash = Beacon crash = game over |
| No global constructors | Static C++ objects not initialized |
| Size limits | Cobalt Strike: max BOF size ~1MB |
| No blocking calls | Long operations block entire Beacon thread |
| Output via Beacon API only | Cannot write to stdout/stderr |
| Single-threaded | No background threads that outlive BOF |
| No stack-allocated C++ objects with destructors | Resource leaks |

**Working around malloc absence:**

```c
// Available: HeapAlloc (Windows API) — explicitly use kernel32
// BOF-compatible memory allocation:
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

void go(char *args, int args_len) {
    HANDLE heap = KERNEL32$GetProcessHeap();
    
    // Allocate
    char *buf = (char *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR, "Allocation failed\n");
        return;
    }
    
    // Use buf...
    
    // Always free — we are responsible for cleanup
    KERNEL32$HeapFree(heap, 0, buf);
}
```

---

## Development Environment

### Windows (Visual Studio)

```powershell
# Install Visual Studio Build Tools
# Component: MSVC v143 compiler + Windows 11 SDK

# beacon.h from TrustedSec BOF template:
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git
# beacon.h is in src/common/

# Compile a BOF:
cl.exe /c /GS- /Fo bof_name.o bof_name.c -I C:\path\to\beacon.h\dir

# For x64:
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.xx.xxxxx\bin\HostX64\x64\cl.exe" /c /GS- bof_name.c -I . -Fo bof_name.x64.o
```

### Linux (mingw-w64 Cross-Compile)

```bash
# Install mingw-w64
apt install mingw-w64

# Compile for x64 Windows
x86_64-w64-mingw32-gcc -c bof_name.c \
  -I /path/to/beacon_header/ \
  -o bof_name.x64.o \
  -masm=intel

# Compile for x86 Windows
i686-w64-mingw32-gcc -c bof_name.c \
  -I /path/to/beacon_header/ \
  -o bof_name.x86.o

# Verify it's a COFF object
file bof_name.x64.o
# Should output: "PE32+ (object)"  or  "COFF object"

objdump -d bof_name.x64.o  # Disassemble to verify code
nm bof_name.x64.o           # List symbols (verify "go" is present)
```

### Makefile Template

```makefile
# BOF build makefile

CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc
CFLAGS = -c -masm=intel -I ./include/

SRCS = src/my_bof.c
OBJS_x64 = $(SRCS:.c=.x64.o)
OBJS_x86 = $(SRCS:.c=.x86.o)

all: $(OBJS_x64) $(OBJS_x86)

%.x64.o: %.c
	$(CC_x64) $(CFLAGS) $< -o $@

%.x86.o: %.c
	$(CC_x86) $(CFLAGS) $< -o $@

clean:
	rm -f src/*.o
```

---

## Beacon API Reference

The Beacon API is defined in `beacon.h` and provides the only way to send output and parse arguments in a BOF:

### Output Functions

```c
#include "beacon.h"

// Send text output to Beacon operator
BeaconPrintf(CALLBACK_OUTPUT, "Found %d processes\n", count);
BeaconPrintf(CALLBACK_ERROR, "Failed: error code %d\n", GetLastError());

// Send raw byte output (for file downloads, binary data)
BeaconOutput(CALLBACK_OUTPUT, buffer, buffer_len);

// Callback type constants:
// CALLBACK_OUTPUT      = 0  → shown as output in UI
// CALLBACK_ERROR       = 0x0d → shown in red as error
// CALLBACK_OUTPUT_OEM  = 0x1e → OEM encoded output
```

### Argument Parsing

BOFs receive arguments as a packed binary blob. Use `datap` for parsing:

```c
#include "beacon.h"

void go(char *args, int args_len) {
    datap parser;
    
    // Initialize parser with received args
    BeaconDataParse(&parser, args, args_len);
    
    // Extract arguments (must match Aggressor script packing order)
    char   *hostname   = BeaconDataExtract(&parser, NULL); // NULL-terminated string
    int     port       = BeaconDataInt(&parser);            // 4-byte int
    short   flag       = BeaconDataShort(&parser);          // 2-byte short
    
    BeaconPrintf(CALLBACK_OUTPUT, "Target: %s:%d (flag=%d)\n", hostname, port, flag);
    
    // Use the arguments...
}
```

### Format Specifiers

```c
// BeaconPrintf supports a subset of printf format specifiers:
// %d  → int
// %u  → unsigned int
// %s  → string (char *)
// %p  → pointer (hex)
// %x  → hex
// %c  → char
// Does NOT support: %f, %g, %e (floating point), %lld (64-bit on 32-bit)
// Use %p for 64-bit values on x64
```

---

## Loading BOFs in Cobalt Strike

### Aggressor Script Integration

```javascript
// bof_loader.cna — Aggressor script to load and execute BOF

# Register menu item in Cobalt Strike
popup beacon_bottom {
    item "Run My BOF" {
        # Prompt for input
        $hostname = prompt_text("Enter hostname:", "target.domain.com");
        $port = prompt_text("Enter port:", "445");
        
        # Pack arguments in the expected format
        # bof_pack packs args as: c=char, s=short, i=int, z=string, Z=wstring
        $args = bof_pack("zi", $hostname, int($port));
        
        # Execute the BOF on selected beacons
        beacon_inline_execute($1, script_resource("my_bof.x64.o"), "go", $args);
    }
}
```

### Manual Execution (Cobalt Strike Console)

```
# In Cobalt Strike Beacon console:
inline-execute /path/to/bof.x64.o
# With arguments (requires Aggressor or BOF-Kit):
inline-execute /path/to/bof.x64.o arg1 arg2
```

---

## Sliver BOF Loading

Sliver C2 supports BOF execution via the `execute-bof` command:

```bash
# In Sliver console (implant session active):
execute-bof /path/to/bof.x64.o arg1

# Note: Sliver's BOF support requires BOFLoader extension
# Load extension first:
extensions load /path/to/sliver-bof-extension/
```

---

## Resources

**BOF Collections:**
- [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) — ipconfig, netstat, routeprint, nslookup, and more
- [OutFlank C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) — advanced post-exploitation BOFs
- [BOF.NET](https://github.com/CCob/BOF.NET) — .NET runtime inside a BOF
- [Raphael0x90 BOF](https://github.com/R4ph431/0x90_BOF) — various post-exploitation
- [nanodump](https://github.com/helpsystems/nanodump) — LSASS dump BOF

**Development Resources:**
- TrustedSec beacon.h (definitive header): [CS-Situational-Awareness-BOF/src/common/beacon.h](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/beacon.h)
- Raphael Mudge's original BOF documentation: Cobalt Strike blog
- COFFLoader (standalone loader for testing): [trustedsec/COFFLoader](https://github.com/trustedsec/COFFLoader)
