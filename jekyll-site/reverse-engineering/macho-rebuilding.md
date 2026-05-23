---
layout: training-page
title: "Mach-O Reverse Engineering — Red Team Academy"
module: "Reverse Engineering"
tags:
  - macho
  - macos
  - codesigning
  - entitlements
  - dyld
  - hopper
  - ida-pro
page_key: "re-macho-rebuilding"
render_with_liquid: false
---

# Mach-O Reverse Engineering

The macOS attack surface has grown alongside enterprise MacBook fleets — engineering teams in particular run them at scale — and Mach-O reversing has gone from a niche skill to required reading. Mach-O is not PE with different magic bytes. The format diverges in load commands, the codesignature blob is part of the binary (not an Authenticode wrapper bolted to the end), entitlements gate kernel-mediated capabilities, dyld linkage works through `@rpath` instead of named DLL search order, and the hardened runtime closes off the classic `DYLD_INSERT_LIBRARIES` trick on signed binaries. This page covers the structure, the toolchain, codesigning analysis, and the patterns you'll see in macOS malware and red team tooling.

Related pages: [RE Workflow & Tool Selection](/reverse-engineering/overview/) · [PE Format Deep Dive](/reverse-engineering/pe-format/) · [Static RE with Ghidra](/reverse-engineering/ghidra-static-re/) · [Malware Behavioral Patterns](/reverse-engineering/malware-patterns/)

---

## Mach-O Format

### Magic Numbers

```
0xFEEDFACE  MH_MAGIC      32-bit, host endian
0xFEEDFACF  MH_MAGIC_64   64-bit, host endian
0xCEFAEDFE  MH_CIGAM      32-bit, byte-swapped
0xCFFAEDFE  MH_CIGAM_64   64-bit, byte-swapped
0xCAFEBABE  FAT_MAGIC     Universal/fat binary, big-endian header
0xBEBAFECA  FAT_CIGAM     Universal/fat binary, little-endian header
```

A universal binary is a thin wrapper containing N architecture slices (`x86_64`, `arm64`, `arm64e`). Each slice is a complete Mach-O. The Apple Silicon transition pushed every shipping app to fat — `arm64` + `x86_64` is now the default. `arm64e` adds pointer authentication and ships on Apple's own binaries.

### Header Structure

```c
struct mach_header_64 {
    uint32_t magic;        // MH_MAGIC_64
    cpu_type_t cputype;    // CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM64 = 0x0100000C
    cpu_subtype_t cpusubtype;
    uint32_t filetype;     // MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8, MH_DSYM=10, MH_KEXT_BUNDLE=11
    uint32_t ncmds;        // number of load commands
    uint32_t sizeofcmds;   // total size of load command region
    uint32_t flags;        // MH_PIE, MH_NO_HEAP_EXECUTION, MH_ALLOW_STACK_EXECUTION
    uint32_t reserved;
};
```

`flags` is your first quick-look on hardening. `MH_PIE` (0x200000) = ASLR. `MH_ALLOW_STACK_EXECUTION` (0x20000) on a non-debug binary is a red flag. `MH_NO_HEAP_EXECUTION` (0x1000000) is the macOS equivalent of DEP.

### Load Commands

Load commands are the heart of Mach-O. They describe everything the loader needs: where segments map, which dylibs to link, where the symbol table lives, what entitlements the binary requests. Each command is `(uint32_t cmd, uint32_t cmdsize)` followed by command-specific data.

| Command | Purpose |
|---------|---------|
| `LC_SEGMENT_64` | Maps a segment (`__TEXT`, `__DATA`, `__LINKEDIT`) into memory |
| `LC_SYMTAB` | Symbol table location + size |
| `LC_DYSYMTAB` | Dynamic symbol table — local/extdef/undef ranges |
| `LC_LOAD_DYLIB` | Link against a dylib (one per dylib) |
| `LC_LOAD_WEAK_DYLIB` | Weak link — OK if missing at runtime |
| `LC_REEXPORT_DYLIB` | Re-export another dylib's symbols (umbrella frameworks) |
| `LC_ID_DYLIB` | This dylib's install name (only present in dylibs) |
| `LC_RPATH` | Add a runtime search path for `@rpath` resolution |
| `LC_CODE_SIGNATURE` | Offset/size of embedded codesignature blob in `__LINKEDIT` |
| `LC_ENCRYPTION_INFO_64` | iOS/FairPlay encryption range (you'll see this on App Store iOS binaries) |
| `LC_VERSION_MIN_MACOSX` | Minimum macOS version target |
| `LC_BUILD_VERSION` | Modern replacement for the version-min commands |
| `LC_UUID` | 128-bit unique build ID — pivots to dSYM symbolication |
| `LC_MAIN` | Entry point file offset (replaces `LC_UNIXTHREAD` on modern binaries) |
| `LC_DYLD_INFO_ONLY` | Rebase/bind/lazy-bind/export trie offsets |
| `LC_DYLD_CHAINED_FIXUPS` | New chained-fixup format (macOS 12+, replaces `LC_DYLD_INFO_ONLY`) |
| `LC_DYLD_EXPORTS_TRIE` | Export trie used with chained fixups |
| `LC_FUNCTION_STARTS` | Compressed table of function entry offsets |
| `LC_SOURCE_VERSION` | Source-control version stamp |

Segments contain sections. `__TEXT.__text` is your code. `__TEXT.__cstring` and `__TEXT.__objc_methname` are where strings live. `__DATA.__objc_classlist` and `__DATA.__objc_classname` are how you discover Objective-C classes. `__LINKEDIT` is the catchall for symbol table, string table, codesignature blob, and the dyld info trees.

---

## Toolchain

```bash
# Static
otool                # Apple's swiss army knife — header, load cmds, sections, disasm
nm                   # symbol table
file                 # confirm Mach-O + architectures
codesign             # signature + entitlement inspection (also signs)
jtool2               # Jonathan Levin's superset of otool/codesign — better signature parsing
                     #   http://newosxbook.com/tools/jtool.html
machoview            # GUI structural browser (older, but excellent for learning layout)

# Disassemblers
Hopper Disassembler  # the de-facto macOS RE tool — Objective-C and Swift demangle out of the box
Binary Ninja         # solid Mach-O support, scriptable in Python
IDA Pro              # excellent Mach-O, ObjC class resolution, FLIRT signatures for libSystem
Ghidra               # works but historically the weakest at Mach-O — improving in 11.x
radare2 / cutter     # free, scriptable; r2 has first-class Mach-O support

# Dynamic
lldb                 # Apple's debugger — built on LLVM
dtrace               # syscall and function tracing (mostly killed by SIP — see below)
frida                # the workhorse for runtime instrumentation on macOS
fs_usage             # syscall-level file/network tracing (root, csrutil-permitting)

# Environment knobs
DYLD_INSERT_LIBRARIES        # inject a dylib (blocked on hardened/restricted binaries)
DYLD_PRINT_LIBRARIES         # log every dylib load — fast triage for what gets pulled in
DYLD_PRINT_BINDINGS          # log every symbol bind
DYLD_PRINT_RPATHS            # see @rpath resolution attempts
DYLD_FALLBACK_LIBRARY_PATH   # fallback dylib search path
```

---

## First-Look Workflow

```bash
# 1. Architecture and slices
file suspect.app/Contents/MacOS/suspect
# suspect: Mach-O universal binary with 2 architectures: [x86_64, arm64]

# Pick a slice for further analysis (avoid analyzing fat binaries directly):
lipo suspect -thin arm64 -output suspect.arm64
lipo -info suspect.arm64

# 2. Header + load commands
otool -h suspect.arm64           # mach_header
otool -l suspect.arm64           # every load command — long output, pipe to less
otool -L suspect.arm64           # just LC_LOAD_DYLIB entries (what it links against)
otool -tV suspect.arm64          # disassembly with symbol resolution

# 3. Signature and entitlements
codesign -dvvvv suspect.arm64
codesign --display --entitlements - suspect.arm64       # entitlements as plist
codesign --display --entitlements :- suspect.arm64      # XML, no leading 8-byte magic

# 4. jtool2 — better detail than codesign for signature internals
jtool2 --sig suspect.arm64
jtool2 --ent suspect.arm64
jtool2 -l suspect.arm64          # load commands with friendlier formatting

# 5. Strings, but smarter
strings -a -n 8 suspect.arm64 | grep -Ei 'http|\.com|\.onion|bash|osascript|sudo'
otool -s __TEXT __cstring suspect.arm64 | less    # C strings only — less noise than strings(1)
```

---

## Codesigning and Entitlements

The codesignature is **inside** the binary — appended to `__LINKEDIT` and pointed to by `LC_CODE_SIGNATURE`. It's a `SuperBlob` of `BlobIndex` entries:

| Slot | Content |
|------|---------|
| `CodeDirectory` | Page hashes + identifier + team ID + flags + cdhash |
| `Requirements` | Designated requirement (DR) — who is allowed to be this binary |
| `Entitlements` (plist) | Human-readable plist of granted capabilities |
| `Entitlements` (DER) | DER-encoded copy — what the kernel actually enforces (Big Sur+) |
| `CMS Signature` | PKCS#7 over the CodeDirectory hash; chains to Apple roots |

### Trust Chain

```
Apple Root CA
  → Apple Worldwide Developer Relations CA
    → Developer ID Application: Acme Corp (TEAMID1234)
      → signs your binary's CodeDirectory hash
```

`codesign -dvvvv` tells you the team ID, the cdhash, and the chain. Ad-hoc signed binaries (`codesign -s -`) have no chain — only a self-hash. Gatekeeper rejects ad-hoc binaries downloaded with the quarantine xattr.

### Entitlements That Matter for RE

```
com.apple.security.cs.allow-jit                    JIT pages — Electron, browsers
com.apple.security.cs.allow-unsigned-executable-memory   loosens W^X — interpreter runtimes
com.apple.security.cs.disable-library-validation   allows loading unsigned dylibs
com.apple.security.cs.disable-executable-page-protection  serious red flag
com.apple.security.cs.allow-dyld-environment-variables    re-enables DYLD_INSERT_LIBRARIES
com.apple.security.get-task-allow                  debuggable — must be FALSE in shipped apps
com.apple.security.device.audio-input              microphone access (TCC-gated)
com.apple.security.device.camera                   camera access
com.apple.security.personal-information.location   location
com.apple.security.files.user-selected.read-write  sandbox file picker scope
com.apple.security.app-sandbox                     App Sandbox enabled
com.apple.security.network.client / server         outbound / inbound network
com.apple.developer.endpoint-security.client       ES framework — only Apple grants this
```

A malware sample with `com.apple.security.cs.allow-dyld-environment-variables` and a Developer ID is staging for environment-variable based injection of legitimate hardened apps. A red team tool needing ES framework access is essentially blocked — that entitlement is provisioned per-bundle-ID by Apple and won't survive review for offensive purposes.

### Hardened Runtime and Notarization

The hardened runtime is a flag in the CodeDirectory (`CS_RUNTIME`). It enforces library validation, blocks unsigned dylib loads, disables `DYLD_INSERT_LIBRARIES` unless the entitlement above is granted, and rejects executable pages without explicit JIT entitlement. Notarization is Apple's malware-scan stamp — without it, Gatekeeper warns on first launch. `spctl -a -vvv -t exec /path/to/app` tells you the Gatekeeper verdict; `stapler validate` checks the notarization ticket.

---

## Dyld Linkage

dyld is the macOS dynamic linker. It resolves `LC_LOAD_DYLIB` entries by walking placeholder-prefixed install names:

| Placeholder | Resolved To |
|------|------------|
| `@executable_path` | Directory of the main executable |
| `@loader_path` | Directory of the binary currently being loaded (dylib's own dir if it's a dylib) |
| `@rpath` | Each `LC_RPATH` entry in the loading binary, tried in order |

Frameworks bundle dylibs at known paths inside an `.app`:

```
MyApp.app/
  Contents/
    MacOS/MyApp                              # references @rpath/Sparkle.framework/...
    Frameworks/Sparkle.framework/Versions/A/Sparkle
    Frameworks/Sparkle.framework/Sparkle     # symlink
```

`otool -l MyApp | grep -A2 LC_RPATH` shows the rpath list. A common attack pattern is dropping a malicious dylib into an `@rpath` directory ahead of the legitimate one — "dylib hijacking" (Patrick Wardle's research). The countermeasure is library validation (hardened runtime), which requires every loaded dylib to be signed by the same team ID as the main binary or by Apple.

### Two-Level Namespace

Mach-O records *both* the symbol name and the dylib it came from in the import table. When dyld resolves `_malloc`, it looks specifically in `libSystem.B.dylib`, not in the global symbol space. This eliminates an entire class of symbol-collision attacks that plague ELF. Flat namespace can be re-enabled per-binary (`MH_FORCE_FLAT`) — uncommon and suspicious if seen on shipping code.

### Lazy vs Immediate Binding

`LC_DYLD_INFO_ONLY` (or `LC_DYLD_CHAINED_FIXUPS` on 12+) describes four streams:

- **rebase** — pointers to fix up after ASLR slides the image
- **bind** — non-lazy imports, resolved at load
- **lazy bind** — imports resolved on first call via a stub
- **export trie** — what this image exports, encoded as a prefix tree

For RE: lazy stubs land in `__TEXT.__stubs`; the resolver jumps through `__DATA.__la_symbol_ptr`. After first call, that pointer caches the real function address. This is the macOS equivalent of the Windows IAT and is where you hook with Frida.

---

## Mach-O Patching

```bash
# insert_dylib — research tool for adding LC_LOAD_DYLIB entries
# https://github.com/Tyilo/insert_dylib
insert_dylib --inplace /path/to/payload.dylib target.bin

# After any modification, the existing signature is invalidated. Re-sign ad-hoc:
codesign --remove-signature target.bin
codesign -s - --force --deep target.bin

# LIEF — Python lib for reading/writing Mach-O (and PE, ELF)
python3 -c "
import lief
m = lief.parse('target.bin')
for cmd in m.commands:
    print(cmd.command, getattr(cmd, 'name', ''))
m.add_library('@executable_path/payload.dylib')
m.write('target.patched')
"
```

The notarization-after-edit problem: any modification breaks the stapled notarization ticket. Re-notarization requires submitting to Apple with a valid Developer ID — not viable for offensive research builds. You either work with ad-hoc signing on a SIP-disabled VM, or you accept Gatekeeper warnings on first launch.

---

## Common Mach-O Malware Patterns

**LaunchDaemon / LaunchAgent persistence.** A plist in `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, or `/Library/LaunchDaemons/` registers a binary to run at login or boot. `launchctl list` enumerates loaded jobs; `KnockKnock` (Objective-See) is the public auditor for this.

**Two-stage downloader.** A small first-stage Mach-O — often unsigned or ad-hoc, dropped from a DMG — pulls a larger encrypted payload over HTTPS, decrypts in memory, writes to a hidden location, and adds a LaunchAgent. The first stage is the boring part; the second stage is the actual RAT.

**AppleScript / JXA loader.** `osascript -l JavaScript -e '...'` runs JavaScript for Automation outside the usual binary detection scope. Used by Empire's macOS launcher and by several real-world families. The JXA runs in `osascript`'s context (Apple-signed), inheriting `osascript`'s trust.

**"Fake Apple Helper" naming.** Bundle IDs like `com.apple.HelperService`, paths under `/Library/Apple/...`, plist labels mimicking Apple's. None of these confer trust — they exist to fool a human glancing at `ps` or Activity Monitor.

**Office macro chain.** Word macro → `osascript` payload → Mach-O drop. The macro never touches a binary directly; Office's sandboxing is bypassed via the `LaunchServices` URL handler dance documented by Patrick Wardle.

---

## Mac Red Team Tooling Patterns

Mythic's **Apfell** (JXA) and **Poseidon** (Go) agents are the modern macOS post-ex platforms. Apfell uses pure JXA, avoiding compiled Mach-O entirely until module load. Poseidon is a Go binary — easier to build, but every Go binary is unsigned by default and trips Gatekeeper instantly without manual signing.

Empire's macOS modules predate Mythic and are mostly Python/AppleScript. They're showing their age on modern macOS where the system Python is gone (12+) and AppleScript triggers TCC prompts on more operations every year.

The codesigning headache is the real constraint on offensive macOS tooling: anything you build needs a Developer ID for smooth operation, but those IDs get revoked the moment Apple flags the bundle ID as malicious. Burner Apple developer accounts have become standard tradecraft and a standard target for Apple's anti-abuse team.

---

## Dynamic Analysis on macOS

```bash
# lldb basics
lldb /path/to/binary
(lldb) settings set target.env-vars DYLD_INSERT_LIBRARIES=/tmp/hook.dylib
(lldb) breakpoint set --name SecKeychainFindGenericPassword
(lldb) breakpoint set --regex "^-\[KeychainAccess "      # ObjC selector regex
(lldb) process launch -- arg1 arg2
(lldb) image list                                        # loaded modules + slide
(lldb) memory read --size 4 --format x --count 16 0x...
(lldb) expression -- (void)NSLog(@"hit!")

# Frida — runtime instrumentation
frida-trace -i 'open*' -i 'connect' /path/to/binary
frida -p $(pgrep target) -l hook.js

# dtrace — mostly disabled by SIP on stock systems
sudo dtrace -n 'syscall:::entry /execname == "target"/ { @[probefunc] = count(); }'
```

SIP (System Integrity Protection) blocks debugging of Apple-signed binaries, dtrace on protected processes, and writes to system directories. You disable it from Recovery Mode with `csrutil disable` on your analysis VM — never on a production endpoint. Even with SIP disabled, the hardened runtime on a target binary still blocks debugging unless `com.apple.security.get-task-allow` is set, which forces you to re-sign the binary with that entitlement before lldb will attach.

---

## Detection Side

Apple deprecated kernel extensions in favor of **Endpoint Security framework** (`es_client_t`) running in userspace. ES delivers events for process exec, file open, mount, signal, login — the whole spectrum of behaviors that matter for EDR. Every commercial macOS EDR (CrowdStrike, SentinelOne, Jamf Protect) consumes ES events. The framework requires the `com.apple.developer.endpoint-security.client` entitlement, provisioned only by Apple, which is why there are very few open-source ES clients (`eslogger`, Patrick Wardle's `appmonitor`).

Key signals for malicious Mach-O behavior:

- Process exec of `osascript` from a non-interactive parent
- Mach-O write to `~/Library/LaunchAgents/` followed by `launchctl load`
- `codesign` flags showing ad-hoc or absent signature on a binary executed from a download location
- `LC_LOAD_DYLIB` entries pointing into world-writable paths
- Dyld load of a dylib from `@rpath` resolving to a non-bundle path
- Process with `get-task-allow` entitlement running outside Xcode

**Unified Logging** (`log stream`, `log show --predicate '...'`) is where dyld, kernel, and security subsystems narrate themselves. `log stream --predicate 'subsystem == "com.apple.securityd"'` shows codesigning verdicts in real time. Apple's removal of plain-text `/var/log/system.log` for unified logging was the single biggest forensics shift on macOS in the last decade.

---

## Resources

- Apple — *Mach-O File Format Reference* (now archived; mirror via `osxbook.com/book/bonus/chapter1/macho/`)
- Jonathan Levin — *MacOS and iOS Internals* (Volume I-III) — the canonical text; jtool2 ships from his site
- Patrick Wardle — *The Art of Mac Malware* (Volumes 1 & 2, No Starch Press) + Objective-See research blog
- Csaba Fitzl (theevilbit) — macOS persistence and TCC research, taught the SANS/Offensive Security mac courses
- Hopper Disassembler User Guide — `hopperapp.com/docs/`
- Mythic Project — `github.com/its-a-feature/Mythic` (Apfell, Poseidon agents)
- LIEF — `lief.re` — Mach-O programmatic editing
- `newosxbook.com/tools/jtool.html` — jtool2 documentation
- Objective-See free tools: KnockKnock, BlockBlock, LuLu, ProcessMonitor, FileMonitor
