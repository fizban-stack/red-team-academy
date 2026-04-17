---
layout: training-page
title: "Binary Analysis with Ghidra & Binary Ninja — Red Team Academy"
module: "Vulnerability Research"
tags:
  - ghidra
  - binary-ninja
  - ida-pro
  - reverse-engineering
  - decompiler
  - bindiff
  - static-analysis
page_key: "vuln-research-binary-analysis"
render_with_liquid: false
---

# Binary Analysis with Ghidra & Binary Ninja

Static binary analysis transforms compiled machine code into understandable representations — disassembly, decompiled pseudocode, data flow graphs, and call graphs. This is the foundation of vulnerability research when source code is unavailable. The three dominant tools — Ghidra (free/NSA), Binary Ninja (commercial, scriptable), and IDA Pro (industry standard, expensive) — each have distinct strengths. This page covers practical workflows for vulnerability research.

---

## Ghidra Basics

Ghidra is a free, open-source reverse engineering framework developed by the NSA and released in 2019. It supports hundreds of processor architectures and includes a powerful decompiler.

### Project Setup

```
1. Launch Ghidra → New Project → Non-Shared Project → Name it
2. File → Import File → select target binary
3. Auto-analysis dialog: Accept defaults, click Analyze
   - Important analyzers: Decompiler Parameter ID, Windows x86 PE RTTI Analyzer,
     Aggressive Instruction Finder, Reference Analyzer
4. Wait for analysis (1-30 min depending on binary size)
```

### Navigating the Interface

| Window | Shortcut | Purpose |
|--------|---------|---------|
| Code Browser | G | Primary disassembly view |
| Decompiler | Ctrl+E | High-level C pseudocode |
| Symbol Tree | — | Functions, namespaces, labels |
| Data Type Manager | — | Struct/enum definitions |
| Function Graph | Ctrl+Shift+E | Control flow graph |
| References | Ctrl+Shift+F | Cross-references to/from |

**Key navigation shortcuts:**
```
G         → Go to address/symbol
L         → Label/rename symbol
T         → Retype variable/function signature  
Ctrl+F    → Search text in current view
Shift+F12 → Search for string
Ctrl+Shift+F → Find references to address
Spacebar  → Toggle disassembly/graph view
Escape    → Navigate back
```

### Function Analysis

```
# Finding interesting functions:
1. Symbol Tree → Functions → sort by name
   - Look for: alloc, parse, process, handle, request, decode
2. String search: Search → For Strings
   - Find error messages → trace callers to find validation code
3. Cross-references: right-click address → References → Find References
4. Imports: Symbol Tree → Imports
   - Dangerous functions: strcpy, sprintf, memcpy, system, popen, gets
```

Working with the decompiler:

```c
// Raw Ghidra decompiler output — function renames needed
undefined8 FUN_00401234(char *param_1, int param_2)
{
    char local_48 [64];
    
    if (param_2 < 0x41) {
        strncpy(local_48, param_1, param_2);  // Ghidra shows the stack buffer
    }
    return 0;
}

// After renaming variables and function:
undefined8 parse_username(char *username, int length)
{
    char username_buf [64];
    
    if (length < 0x41) {  // Only checks < 65, not == 64
        strncpy(username_buf, username, length);  // Off-by-one if length=64!
    }
    return 0;
}
```

### Ghidra Scripting

Ghidra supports both Java and Python (via Jython) scripting for automated analysis.

**Script: Find all calls to dangerous functions**

```python
# Ghidra Python script — run via Script Manager (Window → Script Manager)
# Find all callers of strcpy, memcpy, sprintf, etc.

from ghidra.program.model.symbol import RefType

DANGEROUS_FUNCS = ["strcpy", "strcat", "sprintf", "gets", "memcpy"]

for func_name in DANGEROUS_FUNCS:
    symbol = getSymbol(func_name, None)
    if symbol is None:
        # Try with _imp_ prefix (Windows import)
        symbol = getSymbol("_imp_" + func_name, None)
    
    if symbol:
        refs = getReferencesTo(symbol.getAddress())
        for ref in refs:
            if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                caller_func = getFunctionContaining(ref.getFromAddress())
                print(f"[DANGEROUS] {func_name} called from {caller_func.getName()} "
                      f"at {ref.getFromAddress()}")
```

**Script: Find all functions with large stack allocations (potential overflows)**

```python
# Find functions with stack frames > 256 bytes
from ghidra.program.model.listing import Function

func_mgr = currentProgram.getFunctionManager()
for func in func_mgr.getFunctions(True):
    frame = func.getStackFrame()
    if frame.getFrameSize() > 256:
        print(f"Large stack frame: {func.getName()} at {func.getEntryPoint()} "
              f"(size: {frame.getFrameSize()} bytes)")
```

### Ghidra BinExport + BinDiff

BinExport exports Ghidra analysis to a format compatible with Zynamics BinDiff, enabling binary comparison for patch analysis:

```
1. Install BinExport plugin:
   File → Install Extensions → search BinExport
2. Export both versions:
   File → Export Program → BinExport v2 (*.BinExport)
   # Do this for both patched and unpatched binary
3. Open BinDiff:
   BinDiff Differ → Diff... → select both .BinExport files
4. Analyze diff results:
   - Changed functions: likely contain the security fix
   - New functions: added validation/sanitization
   - Deleted functions: removed dangerous code paths
```

---

## Binary Ninja

Binary Ninja (BN) is a commercial reverse engineering platform with a Python-first plugin API and multi-level intermediate language (BNIL).

### Installation and Setup

```bash
# Download from binary.ninja
# License: Personal (~$400), Commercial (~$3000), Academic (free with edu email)

# Python API (standalone, without GUI)
pip install binaryninja
# Requires valid Binary Ninja license on the machine
```

### Binary Ninja Intermediate Language (BNIL)

BN lifts assembly through multiple IL stages, each progressively higher-level:

```
Assembly → LLIL (Low Level IL) → MLIL (Medium Level IL) → HLIL (High Level IL)
```

```python
import binaryninja as bn

# Open a binary
bv = bn.open_view("/path/to/target")
bv.update_analysis_and_wait()

# Iterate functions
for func in bv.functions:
    print(f"Function: {func.name} at {hex(func.start)}")
    
    # HLIL (closest to source code)
    for block in func.hlil:
        for instr in block:
            print(f"  {instr}")
```

### BN Analysis Scripts: Finding Attack Surface

```python
import binaryninja as bn

# Script: Find all dangerous function calls with their callers
DANGEROUS = {
    "strcpy": "dst, src — no length limit",
    "strncpy": "dst, src, n — n may be wrong",
    "sprintf": "buffer, format, ... — format string + overflow",
    "gets": "buffer — no length limit at all",
    "memcpy": "dst, src, n — if n is user-controlled"
}

bv = bn.open_view("target.exe")
bv.update_analysis_and_wait()

for symbol_name, note in DANGEROUS.items():
    syms = bv.get_symbols_by_name(symbol_name)
    # Also check import names
    syms += bv.get_symbols_by_name(f"_imp_{symbol_name}")
    
    for sym in syms:
        callers = bv.get_code_refs(sym.address)
        for ref in callers:
            func = bv.get_functions_containing(ref.address)
            if func:
                print(f"[{symbol_name}] → {func[0].name} @ {hex(ref.address)}")
                print(f"  Note: {note}")
```

### BN BNIL for Deep Analysis

```python
# Find memory operations with user-controlled length parameter
import binaryninja as bn
from binaryninja import MediumLevelILInstruction

bv = bn.open_view("target.bin")
bv.update_analysis_and_wait()

for func in bv.functions:
    for block in func.mlil:
        for instr in block:
            # Look for MLIL_CALL with memcpy as target
            if instr.operation == bn.MediumLevelILOperation.MLIL_CALL:
                called = str(instr.dest)
                if "memcpy" in called or "memmove" in called:
                    # Third argument is size
                    if len(instr.params) >= 3:
                        size_param = instr.params[2]
                        # Check if size comes from user input (taint analysis)
                        print(f"memcpy at {hex(instr.address)} in {func.name}")
                        print(f"  Size arg: {size_param}")
```

---

## IDA Pro

IDA Pro remains the industry standard despite its high cost, primarily for its mature FLIRT signature database and Hex-Rays decompiler.

### FLIRT Signatures

FLIRT (Fast Library Identification and Recognition Technology) identifies statically-linked library code:

```
# In IDA: File → Load File → FLIRT Signature File
# Download signatures from:
# - IDA Pro default: sig/pc/ directory
# - Community: github.com/push0ebp/sig-database
# - Generate custom: IDA FLAIR tools (pelf, pelf64, plb, sigmake)

# Generate FLIRT signature from library:
pelf libssl.a ssl.pat           # Create pattern file
sigmake ssl.pat ssl.sig         # Compile signature
# Copy ssl.sig to IDA sig/ directory
```

### IDA Pro YARA Rules from Analysis

```python
# IDA Python: generate YARA rule from function
import idc, idaapi, idautils, yara

def func_to_yara(func_addr):
    """Extract byte pattern from function for YARA rule"""
    func = idaapi.get_func(func_addr)
    name = idc.get_func_name(func_addr)
    
    bytes_list = []
    wildcards = []
    
    ea = func.start_ea
    while ea < func.end_ea:
        # Get instruction bytes
        size = idc.get_item_size(ea)
        for i in range(size):
            b = idc.get_wide_byte(ea + i)
            bytes_list.append(f"{b:02X}")
        
        ea = idc.next_head(ea, func.end_ea)
    
    pattern = " ".join(bytes_list[:64])  # First 64 bytes
    return f'rule {name} {{ strings: $a = {{ {pattern} }} condition: $a }}'
```

### Lumina Server

Lumina shares function names across IDA instances via a server — useful for teams:

```
IDA → Options → General → Lumina
Enable "Use Lumina server"
Server: lumina.hex-rays.com (Hex-Rays) or self-hosted
# Functions you rename get pushed to Lumina
# Functions others renamed get pulled automatically
```

### Hex-Rays Decompiler Techniques

```c
// IDA decompiler output — reading pseudocode effectively

// 1. Identify array accesses with unsanitized index
v4 = some_array[user_input];     // Is user_input bounds-checked?

// 2. Find heap operations
v2 = malloc(user_len);            // Is user_len validated before malloc?
memcpy(v2, user_buf, user_len);   // Same length used? 

// 3. Virtual function dispatch (vtable calls)
(*(void (__cdecl **)(DWORD *, _DWORD))*a1)(a1, v3);  // Can *a1 be controlled?

// 4. Integer arithmetic before size calculations
v5 = (unsigned int)(user_size - 1);  // Underflow if user_size=0?
malloc(v5 * 8);                       // Integer overflow if large?
```

---

## Bindiff (Zynamics): Patch Diffing

BinDiff compares two binaries to identify changed functions — essential for CVE research.

### Workflow

```
1. Load both binaries in IDA (or Ghidra with BinExport)
2. Export both as .BinExport files
3. Open BinDiff → Diff... → select exports
4. Review results:

Result columns:
- Similarity: 0.0 (totally different) to 1.0 (identical)
- Confidence: how certain the match is
- Changed/Matched/Unmatched counts
```

### Reading BinDiff for CVE Analysis

```
Strategy for patch diffing:
1. Sort changed functions by Similarity (ascending) — lowest similarity = most changed
2. For each changed function:
   a. Open side-by-side decompiler view
   b. Look for added bounds checks: if (len > MAX_SIZE) return ERROR
   c. Look for added NULL checks: if (!ptr) goto error
   d. Look for type changes: int → unsigned int (sign confusion fix)
   e. Look for removed dangerous calls: sprintf → snprintf
3. Understand the fix → understand the bug
4. Reconstruct the vulnerable code path
5. Build PoC for the vulnerable (unpatched) version
```

---

## Dynamic Analysis Integration

Static analysis reveals what code exists; dynamic analysis reveals what code runs with specific inputs.

### x64dbg Integration with Static Analysis

```
Workflow:
1. Identify interesting function in Ghidra/IDA
2. Get function address (e.g., 0x00401234)
3. Set breakpoint in x64dbg: bp 0x00401234
4. Run target with crafted input
5. Examine registers and stack at breakpoint
6. Step through (F8/F7) to observe data flow

# x64dbg useful commands:
bp 0x00401234          # Set software breakpoint
bph 0x00601234, w, 4  # Hardware breakpoint (write watch, 4 bytes)
!exploitable           # Run exploitability plugin on crash
dump esp, 64           # Hex dump stack
```

### WinDbg Scripts with Static Analysis

```windbg
; WinDbg script: log all calls to a function with arguments
bp module!function_name ".printf \"Called function_name: arg0=%p arg1=%p\\n\", rcx, rdx; g"

; Break on access violation and dump context
sxe av
.logopen c:\windbg_crash.log
g
; On AV:
!analyze -v
.ecxr         ; Show exception context
dds rsp L20   ; Stack dump
```

### Frida for Dynamic Instrumentation

```javascript
// frida_hook.js — hook a function and log arguments
Interceptor.attach(Module.findExportByName("target.dll", "parse_input"), {
    onEnter: function(args) {
        console.log("[parse_input] Called");
        console.log("  arg0 (buffer):", args[0]);
        console.log("  arg1 (length):", args[1].toInt32());
        
        // Dump buffer contents
        if (args[1].toInt32() > 0 && args[1].toInt32() < 4096) {
            console.log("  Buffer:", hexdump(args[0], {length: args[1].toInt32()}));
        }
    },
    onLeave: function(retval) {
        console.log("  Return:", retval.toInt32());
    }
});
```

```bash
# Run Frida hook
frida -l frida_hook.js target_binary
# Or attach to running process
frida -l frida_hook.js -p 1234
```

### Combining Static + Dynamic Analysis

```
Phase 1 (Static — Ghidra):
- Map all attack surface functions
- Identify functions with dangerous operations
- Trace data flow from network/file input to dangerous ops
- Generate hypothesis: "if I send X, Y function gets called with tainted length"

Phase 2 (Dynamic — Frida/WinDbg):
- Validate hypothesis with real inputs
- Observe actual runtime values
- Confirm that tainted data reaches dangerous operations
- Identify exact offset/length values for exploitation

Phase 3 (Exploit Development):
- Build PoC based on static + dynamic findings
- Iterate on exploit with debugger
- Achieve reliable crash → reliable primitive
```

---

## Scripted Binary Analysis Workflows

### Mass Analysis: Finding a Bug Class Across Many Binaries

```python
#!/usr/bin/env python3
# Batch Ghidra analysis — analyze multiple binaries headlessly
import subprocess, sys

GHIDRA_HEADLESS = "/opt/ghidra/support/analyzeHeadless"
SCRIPT = "FindDangerousFuncs.py"

def analyze_binary(binary_path, output_dir):
    cmd = [
        GHIDRA_HEADLESS,
        output_dir, "batch_project",
        "-import", binary_path,
        "-postScript", SCRIPT,
        "-scriptPath", "/opt/analysis_scripts/",
        "-deleteProject",   # Clean up after analysis
        "-log", f"{output_dir}/ghidra.log"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return result.returncode, result.stdout

# Analyze all DLLs in a directory
import glob, os
for dll in glob.glob("/samples/*.dll"):
    print(f"Analyzing {dll}...")
    code, output = analyze_binary(dll, "/tmp/ghidra_projects")
    if "DANGEROUS_CALL" in output:
        print(f"  [!] Potential finding in {dll}")
        print(output)
```

### Binary Ninja Headless Analysis

```python
#!/usr/bin/env python3
# BN headless — no GUI needed
import binaryninja as bn
import sys, json

def analyze_binary(path):
    bv = bn.open_view(path)
    bv.update_analysis_and_wait()
    
    findings = []
    for func in bv.functions:
        for ref in bv.get_code_refs_by_name("strcpy"):
            callers = bv.get_functions_containing(ref.address)
            for caller in callers:
                findings.append({
                    "function": caller.name,
                    "address": hex(ref.address),
                    "binary": path
                })
    
    bv.file.close()
    return findings

if __name__ == "__main__":
    results = analyze_binary(sys.argv[1])
    print(json.dumps(results, indent=2))
```
