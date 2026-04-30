---
layout: training-page
title: "Static Reverse Engineering with Ghidra — Red Team Academy"
module: "Reverse Engineering"
tags:
  - ghidra
  - static-analysis
  - decompiler
  - disassembly
  - function-identification
  - api-pattern-recognition
  - ghidra-scripting
  - malware-re
page_key: "re-ghidra-static"
render_with_liquid: false
---

# Static RE with Ghidra

Ghidra is the NSA's open-source reverse engineering suite. Its decompiler converts disassembly into readable C-like pseudocode, dramatically reducing the time to understand complex algorithms. This page covers the full static RE workflow: importing binaries, initial analysis, the decompiler, identifying Windows API patterns in pseudocode, and scripting for automation.

Related pages: [RE Workflow & Tool Selection](/reverse-engineering/overview/) · [PE Format Deep Dive](/reverse-engineering/pe-format/) · [Dynamic RE with x64dbg](/reverse-engineering/x64dbg-workflow/) · [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/)

---

## Installation and Project Setup

```bash
# Download: https://ghidra-sre.org/
# Requires Java 17+: sudo apt install openjdk-17-jre

# Linux/Mac:
./ghidraRun

# Windows:
ghidraRun.bat

# Headless mode (for batch analysis):
./analyzeHeadless /path/to/project ProjectName -import /path/to/sample.exe \
  -postScript ExportFunctions.java -scriptPath /path/to/scripts/
```

### Creating a Project

```
1. File → New Project → Non-Shared → choose directory → name project
2. File → Import File → select sample.exe
3. Import dialog: verify format (Portable Executable) and language (x86:LE:64:default)
4. Click OK — Ghidra detects language automatically
5. Double-click the imported file in the project window → opens CodeBrowser
6. Auto-analyze dialog appears → click "Yes, Analyze"
```

### Auto-Analysis Configuration

Select these analyzers for malware (disable slow/noisy ones):

```
Enable (checked):
  ☑ Aggressive Instruction Finder     — finds more code in packed sections
  ☑ Apply Data Archives               — applies known Windows struct types
  ☑ Call Convention ID                — identifies calling conventions
  ☑ Create Address Tables             — locates jump tables
  ☑ Decompiler Parameter ID           — improves decompiler accuracy
  ☑ Demangler                         — demanges C++ function names
  ☑ Disassemble Entry Points          — starts from EP + exports + TLS
  ☑ Embedded Media                    — finds embedded PEs in resources
  ☑ Function Start Search             — pattern-based function detection
  ☑ Non-Returning Functions           — marks ExitProcess etc. as no-return
  ☑ PE x86 Propagate External Symbols — maps import names onto IAT addresses
  ☑ Shared Return Calls               — handles tail-call optimization
  ☑ Stack                             — analyzes stack frame layout

Disable for speed:
  ☐ ASCII Strings (use Search → Memory for specific patterns instead)
  ☐ Decompiler Switch Analysis (enable only if you see switch statements)
```

---

## The CodeBrowser Interface

```
┌─────────────────────────────────────────────────────────────────┐
│  Program Trees (left)    │  Listing (center — disassembly)      │
│  Symbol Tree             │  Decompiler (right — C pseudocode)   │
│  Data Type Manager       │  Console (bottom — script output)    │
└─────────────────────────────────────────────────────────────────┘
```

### Essential Views

| View | Open With | Purpose |
|------|-----------|---------|
| Listing | Default | Disassembly view — click any instruction |
| Decompiler | Window → Decompiler | C pseudocode for current function |
| Symbol Tree | Default left panel | Functions, exports, imports, labels |
| Program Trees | Default left panel | Sections / memory segments |
| Data Type Manager | Default left panel | Apply structures to memory |
| References | Right-click → References | Who calls this function? Who does it call? |
| Function Graph | Window → Function Graph | CFG for current function |
| Byte Viewer | Window → Bytes | Raw hex alongside disassembly |

### Navigation Shortcuts

| Shortcut | Action |
|----------|--------|
| G | Go to address or label |
| Ctrl+F | Search for string / bytes |
| Ctrl+Shift+F | Search in all open programs |
| F3 / Shift+F3 | Find next / previous |
| Ctrl+Z | Undo (very important — undo bad analysis) |
| ; | Add plate comment to function |
| / | Add end-of-line comment |
| L | Rename label at cursor |
| T | Set type at cursor |
| P | Disassemble at cursor |
| F | Create function at cursor |
| Alt+← / Alt+→ | Navigate back / forward (like browser) |

---

## Initial Analysis Workflow

After auto-analysis completes, follow this sequence for malware:

### 1. Check Entry Point

```
Symbol Tree → Exports → entry (or _start)
  → Double-click to jump to disassembly
  → Open Decompiler panel alongside

Key questions:
  - Is there startup boilerplate (CRT init calls: __security_init_cookie, etc.)?
  - Does it call IsDebuggerPresent immediately? → anti-debug sample
  - Does the first few hundred bytes consist mostly of encrypted data + a small decoder?
    → packed sample — look for the loop that decrypts/unpacks
```

### 2. TLS Callbacks

```
Symbol Tree → Labels → search "TlsCallback"
  → If found, review this function FIRST (runs before entry point)
```

### 3. Import Review

```
Symbol Tree → Imports → expand DLL entries
  → Look for high-value DLLs: ws2_32.dll, wininet.dll, bcrypt.dll
  → Click an import → "Show References" → all call sites in code

Right-click any imported function → "Find References to External Symbol"
  → Lists every call site in the binary
```

### 4. String Search

```
Search → Memory → Search All → String → enter search term
Examples:
  "http"   → C2 URLs
  "HKEY"   → registry paths
  "cmd"    → command execution
  ".exe"   → spawned processes
  "=="     → Base64 character set hint
  "AES"    → encryption algorithm name
  "conn"   → connection strings or config keys

Ctrl+click a string reference → jump to where it's used in code
```

---

## Working with the Decompiler

The decompiler output is pseudocode — it approximates intent but is not exact C. Treat it as a high-confidence guide, not ground truth.

### Improving Decompiler Output

**Step 1: Rename variables and functions.** This is the highest-ROI action in static RE.

```
In Decompiler panel:
  Right-click variable name → Rename Variable (L)
  Right-click function name → Rename Function (L)
  Right-click parameter    → Rename Parameter

Example: transform this:
  iVar1 = (**(code **)(param_1 + 0x28))(param_1, (PVOID)0x0, &local_20, ...)

Into:
  result = FreeLibrary(hModule, NULL, &hNewModule, ...)

Do this iteratively — rename what you understand, trace what you don't.
```

**Step 2: Apply Windows structure types.**

```
Right-click memory address in Listing or Decompiler
→ Data → Choose Data Type
→ Type: _STARTUPINFOA, _PROCESS_INFORMATION, _SECURITY_ATTRIBUTES, etc.
(from Windows types in Data Type Manager)

Once applied, the decompiler shows field names instead of hex offsets:
  BEFORE: *(DWORD *)(lpBuffer + 0x2c) = 0x44
  AFTER:  startupInfo.cb = 0x44
```

**Step 3: Fix function signatures.**

```
Right-click function name in Decompiler → Edit Function Signature
→ Adjust return type and parameter types/names
→ Apply — decompiler immediately re-renders with correct types

For Windows APIs resolved at runtime:
  1. Find the function pointer call: (**(code **)(offset + 0x??))(args...)
  2. Determine which API it is from context (arguments, calling pattern)
  3. Create a named label for the function pointer address
  4. Apply correct signature via Edit Function Signature
```

---

## Recognizing Windows API Patterns in Decompiled Code

### Process Injection Pattern

```c
// Decompiler output (before renaming):
uVar1 = OpenProcess(0x1fffff, 0, param_1);
pvVar2 = VirtualAllocEx(uVar1, (PVOID)0x0, 0x1000, 0x3000, 0x40);
WriteProcessMemory(uVar1, pvVar2, &DAT_00403020, 0x1000, (SIZE_T *)0x0);
CreateRemoteThread(uVar1, (LPSECURITY_ATTRIBUTES)0x0, 0, pvVar2,
                   (PVOID)0x0, 0, (LPDWORD)0x0);

// Read: OpenProcess(PROCESS_ALL_ACCESS=0x1fffff, ...) → allocate R/W/X page
//       → write 0x1000 bytes from embedded data at 0x00403020
//       → create remote thread at that page
// Action: dump DAT_00403020 (the shellcode)
```

### Manual API Resolution Pattern

```c
// Decompiler — hash-based API resolution:
uVar1 = GetModuleHandleA("ntdll.dll");
pcVar2 = find_export_by_hash(uVar1, 0xb8e88a3c);

// Analysis steps:
// 1. Identify find_export_by_hash — it walks the EAT
// 2. Find the hash function (usually inside find_export_by_hash)
// 3. Replicate in Python and precompute table for all ntdll exports
// 4. Look up 0xb8e88a3c → NtAllocateVirtualMemory (or whatever it maps to)
// 5. Rename pcVar2 → pNtAllocateVirtualMemory
// 6. All subsequent calls through pcVar2 become readable
```

```python
# Precompute hash table for ntdll exports:
import pefile, ctypes

def ror32(val, count):
    return ((val >> count) | (val << (32 - count))) & 0xFFFFFFFF

def hash_name(name):
    # Common DJB2-style ROR hash used by many shellcodes:
    h = 0
    for c in name.encode() + b'\x00':
        h = ror32(h, 13)
        h = (h + c) & 0xFFFFFFFF
    return h

pe = pefile.PE("C:\\Windows\\System32\\ntdll.dll")
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        h = hash_name(exp.name.decode())
        print(f"0x{h:08x}  {exp.name.decode()}")
```

### C2 Communication Pattern

```c
// Decompiler output (after initial rename pass):
hInternet = InternetOpenW(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 0, NULL, NULL, 0);
hConnect  = InternetConnectW(hInternet, lpC2Host, 443, NULL, NULL, 3, 0, 0);
hRequest  = HttpOpenRequestW(hConnect, L"POST", lpBeaconPath, NULL, NULL, NULL,
                              INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_UI, 0);
// Identify: lpC2Host and lpBeaconPath are your IOCs — extract them
// lpBeaconPath often contains an ID beacon suffix: /updates/check?id=<machineID>
```

### Encryption Key Setup Pattern

```c
// CNG pattern:
BCryptOpenAlgorithmProvider(&hAlgorithm, L"AES", NULL, 0);
BCryptSetProperty(hAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 30, 0);
BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0,
                            &DAT_00404100,   // ← key bytes (hardcoded or derived)
                            0x20,            // 32 bytes = AES-256
                            0);
BCryptEncrypt(hKey, plaintext, plaintextLen, NULL, &DAT_00404120, 0x10,  // ← IV
              ciphertext, ciphertextLen, &bytesWritten, BCRYPT_BLOCK_PADDING);

// Action:
// 1. Dump DAT_00404100 (key) and DAT_00404120 (IV)
// 2. Type: Right-click DAT_00404100 → Data → byte[32]
// 3. These are your decryption artifacts — decrypt captured C2 traffic
```

---

## Ghidra Scripting

Ghidra's script engine supports Java and Python (Jython). Scripts automate repetitive analysis tasks.

### Running Scripts

```
Window → Script Manager → browse built-in scripts
File → New Script → Java or Python → opens editor
Run: Script Manager → right-click → Run Script
Or: press the Run button in the script editor
```

### Finding All API Call Sites (Python)

```python
# FindAPICalls.py — list every call to a specific API
# Run via: Script Manager → FindAPICalls.py

from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
symbolTable = currentProgram.getSymbolTable()

target_api = "VirtualAllocEx"   # change this

for sym in symbolTable.getExternalSymbols():
    if sym.getName() == target_api:
        for ref in refMgr.getReferencesTo(sym.getAddress()):
            caller = listing.getFunctionContaining(ref.getFromAddress())
            callerName = caller.getName() if caller else "unknown"
            print(f"Call to {target_api} at {ref.getFromAddress()} in {callerName}")
```

### Auto-Rename Hash-Resolved Functions (Python)

```python
# HashRename.py — rename function pointers based on precomputed hash table
# Requires: hash_table dict mapping hash → API name

from ghidra.program.model.listing import *

# Pre-computed hash → name table (generate with Python script above)
hash_table = {
    0xb8e88a3c: "NtAllocateVirtualMemory",
    0x4f1c5f63: "NtWriteVirtualMemory",
    # ... add all hashes ...
}

# Find all MOV instructions loading known hash values
instructions = currentProgram.getListing().getInstructions(True)
for instr in instructions:
    if instr.getMnemonicString() == "MOV":
        try:
            operand = instr.getScalar(1)
            if operand and operand.getValue() in hash_table:
                api_name = hash_table[operand.getValue()]
                # Add plate comment showing the resolved name
                setPlateComment(instr.getAddress(),
                               f"HASH RESOLVES TO: {api_name}")
                print(f"[+] {instr.getAddress()}: {api_name}")
        except:
            pass
```

### Dump All Strings to File (Python)

```python
# ExtractStrings.py — export all defined strings with addresses
import os

output = open("/tmp/ghidra_strings.txt", "w")
data = currentProgram.getListing().getDefinedData(True)
for d in data:
    if "string" in d.getDataType().getName().lower():
        try:
            output.write(f"{d.getAddress()}\t{d.getValue()}\n")
        except:
            pass
output.close()
print("Strings written to /tmp/ghidra_strings.txt")
```

### Batch Headless Analysis

```bash
# Analyze entire directory of samples without GUI:
./analyzeHeadless /project/path MalwareProject \
  -import /samples/*.exe \
  -postScript ExtractIOCs.java \
  -scriptPath /scripts/ \
  -log /logs/analysis.log \
  -deleteProject    # don't keep project after analysis

# ExtractIOCs.java would extract strings, imports, and hashes to CSV
# Useful for: YARA rule development from multiple samples of same family
```

---

## Workflow Summary

```
IMPORT AND ANALYZE
  1. New project → import binary → auto-analyze with recommended settings
  2. Check TLS callbacks, entry point, and imports first

ORIENTATION (first 15 minutes)
  3. Search strings: "http", "HKEY", ".exe", crypto algorithm names
  4. Note suspicious imports and find all their call sites
  5. Map out high-level structure: how many meaningful functions?

DEEP ANALYSIS
  6. Start at entry point in Decompiler
  7. Rename every variable and function as you understand it (iterative)
  8. Apply Windows struct types to heap allocations and pointer arguments
  9. Fix function signatures when parameters are misidentified
  10. For hash-resolved APIs: precompute hash table → rename all pointers

PATTERN MATCHING
  11. Identify behavioral category (injector / RAT / ransomware / rootkit)
  12. Cross-reference: see [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/)
  13. Extract IOCs: C2 hosts, file paths, registry keys, crypto constants

HANDOFF TO DYNAMIC
  14. For encrypted blobs: take key material noted in static analysis to x64dbg
  15. For packed samples: use x64dbg to unpack → re-import dumped PE in Ghidra
  16. ret-sync plugin: step in x64dbg, view decompiler in Ghidra simultaneously
```
