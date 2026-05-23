---
layout: training-page
title: "ELF Reverse Engineering — Red Team Academy"
module: "Reverse Engineering"
tags:
  - elf
  - linux
  - got
  - plt
  - dynamic-linking
  - radare2
  - ghidra
page_key: "re-elf-rebuilding"
render_with_liquid: false
---

# ELF Reverse Engineering

Linux endpoints, Linux servers, Linux malware, Linux red team implants — ELF is the binary format. Simpler than PE and Mach-O, with mature tooling and decades of stable documentation. The format is consistent across the Unix ecosystem and the kernel itself ships sample loaders you can read.

Linux malware does not behave like Windows malware. There is no LoadLibrary/GetProcAddress dance, no IAT hooking from EDR vendors, no TLS callback shenanigans by default. Instead you get init scripts, systemd unit files, LD_PRELOAD rootkits, in-memory ELF loaders via `memfd_create`, and increasingly, eBPF-based stealth. The format is simpler; the operating environment is the part that compensates.

Related pages: [RE Workflow & Tool Selection](/reverse-engineering/overview/) · [PE Format Deep Dive](/reverse-engineering/pe-format/) · [Static RE with Ghidra](/reverse-engineering/ghidra-static-re/)

---

## ELF Format

```
┌─────────────────────────────────────────────────────┐
│  ELF Header (Ehdr)              52 or 64 bytes      │
│  e_ident[EI_MAG] = 0x7F 'E' 'L' 'F'                 │
│  e_type, e_machine, e_entry, e_phoff, e_shoff       │
├─────────────────────────────────────────────────────┤
│  Program Headers (Phdr)   — what the LOADER reads   │
│  LOAD, DYNAMIC, INTERP, GNU_STACK, GNU_RELRO, NOTE  │
├─────────────────────────────────────────────────────┤
│  Section Data                                       │
│  .text .rodata .data .bss                           │
│  .plt  .plt.got  .got  .got.plt                     │
│  .dynamic .dynsym .dynstr .interp                   │
│  .init_array .fini_array .ctors .dtors              │
├─────────────────────────────────────────────────────┤
│  Section Headers (Shdr)   — what the LINKER reads   │
└─────────────────────────────────────────────────────┘
```

**Program headers vs section headers** is the single most important ELF distinction. The kernel and the dynamic loader only need program headers — they describe what to map into memory and where the interpreter lives. Section headers are for `ld`, `objdump`, and you. A stripped ELF can have its section header table zeroed out and still run perfectly; many packed samples do exactly this to break naive analysis.

**Key sections:**

| Section | Content |
|---------|---------|
| `.text` | Executable code |
| `.rodata` | Read-only constants and strings |
| `.data` | Initialised globals |
| `.bss` | Uninitialised globals (zero-filled at load) |
| `.plt` | Procedure Linkage Table — jump stubs for imports |
| `.plt.got` / `.plt.sec` | Per-import lazy resolution stubs |
| `.got` | Global Offset Table — resolved addresses |
| `.got.plt` | GOT slots specifically for PLT entries |
| `.dynamic` | Tagged array consumed by the dynamic linker |
| `.dynsym` / `.dynstr` | Dynamic symbol table and its string table |
| `.interp` | Path to the dynamic linker (usually `/lib64/ld-linux-x86-64.so.2`) |
| `.init_array` / `.fini_array` | Constructor / destructor function pointers |
| `.note.gnu.build-id` | Build ID for symbol-server lookup |
| `.eh_frame` / `.eh_frame_hdr` | Unwind info — also useful for function discovery |

**Static vs dynamic linking** changes everything. Statically-linked binaries inline `libc` (often `musl` or `glibc`) and have no `.interp`, no `PT_DYNAMIC`, no PLT/GOT — symbols are stripped down to a single blob of code. Common in Go binaries, Rust `--target x86_64-unknown-linux-musl` builds, and most red team implants. Dynamically-linked binaries are easier to triage but expose every dependency through `ldd`.

**Relocations** are how the loader patches addresses. The two you care about: `R_X86_64_GLOB_DAT` (regular GOT entries, resolved at load if RELRO) and `R_X86_64_JUMP_SLOT` (PLT/GOT entries, resolved lazily by default). Relocations live in `.rela.dyn` and `.rela.plt`. `readelf -r` dumps them.

**Architecture matters** — most red team work is x86-64, but ARM64 is dominant on cloud and IoT. `e_machine` tells you: `EM_X86_64 = 62`, `EM_AARCH64 = 183`, `EM_386 = 3`, `EM_ARM = 40`, `EM_RISCV = 243`. ELF supports both little- and big-endian (`EI_DATA`), and the `EI_OSABI` byte distinguishes Linux from FreeBSD, Solaris, and bare-metal.

---

## Toolchain

```bash
# Format inspection
file sample              # quick triage
readelf -h sample        # ELF header
readelf -l sample        # program headers (LOAD segments etc.)
readelf -S sample        # section headers
readelf -d sample        # dynamic section (DT_NEEDED, RPATH, etc.)
readelf -s sample        # all symbols (dyn + static)
readelf -r sample        # relocations
readelf -n sample        # notes (build-id, ABI tag)

# Disassembly
objdump -d sample        # full disassembly
objdump -D sample        # disassemble ALL sections, not just text
objdump -M intel -d ...  # Intel syntax (default is AT&T)
nm sample | grep ' T '   # global text symbols (defined functions)

# Dependencies and runtime
ldd sample               # shared library dependencies (do NOT run on untrusted samples)
LD_TRACE_LOADED_OBJECTS=1 ./sample   # equivalent to ldd, without invoking ld.so on the target
strings -a -n 6 sample   # extract printable strings, min length 6
strings -e l sample      # 16-bit little-endian (rare on Linux but useful)

# Dynamic analysis
strace -f -e trace=network,file ./sample   # syscall trace
ltrace -f ./sample                          # library call trace (fragile on stripped/static)
gdb sample               # extend with GEF / pwndbg / PEDA
r2 -A sample             # radare2 with auto-analysis
rizin -A sample          # rizin (radare2 fork)

# Heavyweight
ghidra                   # NSA suite — full decompiler
binaryninja              # commercial; excellent ELF support
ida64 sample             # IDA Pro

# Modification
patchelf --print-rpath sample
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 sample
patchelf --replace-needed libold.so libnew.so sample

# Python ELF library
python3 -c "import lief; b = lief.parse('sample'); print(b.entrypoint, hex(b.entrypoint))"
```

`ldd` actually executes parts of the dynamic loader against the binary. **Never run `ldd` on a malware sample on your host.** Use `readelf -d` plus `objdump -p` instead, or run inside a disposable container.

---

## First-Look Workflow

Five commands, in order, before you open anything heavyweight:

```bash
file sample
# Expected: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
#           dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
#           BuildID[sha1]=... , for GNU/Linux 3.2.0, stripped

readelf -h sample        # type (EXEC/DYN), entry point, machine
readelf -l sample        # LOAD segments and their flags; spot RWX
readelf -d sample        # NEEDED libs, RPATH, RUNPATH, FLAGS (BIND_NOW = full RELRO)
readelf -S sample        # section names — if missing or zeroed, sample is stripped/manipulated
nm sample 2>/dev/null | grep ' T ' | head -40   # exported text symbols
ldd sample 2>/dev/null   # only in a sandbox; otherwise skip
strings -a -n 8 sample | less   # the cheapest IOC extraction available
```

What to flag immediately:

- `e_type = ET_DYN` with no `INTERP` segment → PIE executable or shared object loaded by something custom
- `RWX` LOAD segment → unpacker stub or shellcode loader
- Section headers absent or `e_shoff = 0` → deliberately stripped, treat as hostile
- `RPATH` or `RUNPATH` pointing at writable locations (`/tmp`, `/dev/shm`, user home) → library hijack staging
- `NEEDED` includes nonstandard `.so` names (`libcryptominer.so.1`) → name them, search the disk

---

## GOT/PLT Internals

When a dynamically-linked binary calls `puts`, the call site does not go directly to libc. It goes to the PLT, which trampolines through the GOT.

```
Call site in .text:
    call   puts@plt                  ; ← jumps to the .plt stub

.plt stub (one per imported function):
puts@plt:
    jmp    qword ptr [rip + puts@got.plt]   ; ← indirect through GOT
    push   0x0                              ; ← reloc index (used on first call)
    jmp    .plt[0]                          ; ← resolver trampoline

.got.plt slot for puts:
    Before resolution: address of the "push reloc" instruction in puts@plt
    After resolution:  actual address of libc's puts
```

**Lazy binding** is the default. The first call to each import goes through `_dl_runtime_resolve` (in `ld.so`), which writes the resolved libc address back into the GOT slot. Subsequent calls become a single indirect jump — fast.

**Why this matters for RE:**

- During dynamic analysis, GOT slots are uninitialised until the first call. A GOT dump early in execution looks different from one taken later.
- GOT overwrite is a classic CTF exploitation primitive: corrupt the `.got.plt` slot for a function that gets called after your bug, get arbitrary RIP control.
- Hooking the GOT is the easiest interposition mechanism on Linux. `LD_PRELOAD` works by inserting your symbol earlier in the lookup order so the GOT resolves to your function.

**RELRO** is the hardening flag for this whole machinery:

```bash
# Check RELRO state:
readelf -l sample | grep GNU_RELRO       # present?
readelf -d sample | grep BIND_NOW        # full RELRO?

# Three states:
#   No RELRO       — GOT is fully writable; trivial overwrite
#   Partial RELRO  — GOT.PLT writable (lazy binding still works); rest of GOT read-only after init
#   Full RELRO     — entire GOT read-only after init; all imports resolved at load time
```

Full RELRO costs startup time (all symbols resolved up front) and is enabled with `-Wl,-z,relro,-z,now`. Most distro binaries ship partial RELRO. Implants frequently strip RELRO entirely for runtime patching flexibility.

**ASLR** randomises segment base addresses. PIE (`-pie`, the modern default) makes the executable itself relocatable, so `.text`, `.plt`, and `.got` all sit at unpredictable addresses. Inside the loaded image the offsets between `.plt`, `.got.plt`, and `.text` are fixed — only the base moves.

---

## Dynamic Linking

The interpreter (`ld-linux-x86-64.so.2`, `ld-musl-x86_64.so.1`, etc.) is what actually starts your process. The kernel maps the ELF, sees `PT_INTERP`, maps the interpreter, and hands control to it. The interpreter then maps `DT_NEEDED` libraries, performs relocations, runs `.init_array`, and finally jumps to `e_entry`.

**Search order for dependencies** (simplified):

1. `DT_RPATH` (deprecated, but still honoured if `DT_RUNPATH` is absent) — bypasses `LD_LIBRARY_PATH`
2. `LD_LIBRARY_PATH` environment variable
3. `DT_RUNPATH` — modern replacement for RPATH; honoured after `LD_LIBRARY_PATH`
4. `/etc/ld.so.cache` (built by `ldconfig`)
5. `/lib`, `/usr/lib` (and `/lib64`, `/usr/lib64`)

**Hijack vectors live in steps 1, 2, and 3.** Writable `RUNPATH`, attacker-controlled `LD_LIBRARY_PATH`, or a `setuid` binary with sloppy `RUNPATH` all lead to library injection.

**LD_PRELOAD** is the most-used Linux red team primitive. Set the variable, point it at your `.so`, and your symbols are looked up before libc:

```bash
# Defensive bypass — neuter logging:
LD_PRELOAD=./nolog.so legit_program

# Persistence — global preload via /etc/ld.so.preload (loaded for every dynamically-linked process):
echo "/usr/local/lib/rootkit.so" >> /etc/ld.so.preload
```

`/etc/ld.so.preload` is one of the highest-signal IOCs on a Linux host. Any non-empty content there is anomalous; auditd should be configured to alert on writes.

**Constructors** — `.init_array` is a NULL-terminated array of function pointers called before `main`. C/C++ `__attribute__((constructor))` functions land here. Malware uses them for the same reason Windows malware uses TLS callbacks: code runs before any breakpoint set on `main`.

```bash
# Dump .init_array contents:
objdump -s -j .init_array sample
readelf -x .init_array sample
```

Set breakpoints on every `.init_array` entry before letting the binary run.

---

## Common Packer/Obfuscation Classes

| Class | Signal | Notes |
|-------|--------|-------|
| **UPX** | `UPX!` magic, sections named `UPX0`/`UPX1`, single executable RWX segment | `upx -d sample` unpacks; trivially defeated |
| **Custom UPX-like** | UPX-style two-segment layout but no magic | Manual unpack: run under gdb, break after the unpacker loop, dump |
| **Static link + strip** | `e_type = ET_EXEC`, no `INTERP`, no symbols, huge `.text` | Common with Go and musl-Rust; not malicious by itself but defeats `ltrace` |
| **gcc/clang `-O3`** | Heavy inlining, vectorisation, dead-code elimination | Not malicious, but makes decompilation noisy |
| **LLVM-obfuscator (ollvm)** | Control flow flattening, instruction substitution, opaque predicates | Detection: switch-on-state pattern in CFG, suspicious bitwise math |
| **Tigress** | Source-level obfuscator: virtualisation, jitter, opaque preds, branch funcs | Defeated by symbolic execution + manual reasoning; expensive |
| **Packed-init + munmap** | `.init_array` decrypts `.text`, then `munmap`s the unpacker | Dump after init, before main |
| **Polyglot ELF** | Same file is also a valid PE, ZIP, JPEG, etc. via header overlap | `binwalk` and `file` give conflicting answers |

The cheapest single signal is entropy. `binwalk -E sample` or a per-section Shannon entropy script flags packed payloads in seconds.

---

## Dynamic Analysis

```bash
# gdb workflow with GEF or pwndbg installed:
gdb ./sample
(gdb) starti                        # stop at the very first instruction (before .init_array)
(gdb) catch syscall execve          # break on specific syscalls
(gdb) rbreak ^malloc$               # regex breakpoint
(gdb) info proc mappings            # see all loaded segments
(gdb) vmmap                         # GEF/pwndbg version, prettier
(gdb) checksec                      # RELRO/NX/PIE/Canary/Fortify summary
(gdb) got                           # GEF: dump GOT slots
(gdb) telescope $rsp 30             # walk the stack

# Syscall tracing (no debugger overhead):
strace -f -e trace=process,network,file,signal -o trace.log ./sample
strace -f -p $(pidof sample)        # attach to running process

# Library call tracing (fails on static binaries):
ltrace -f -e '*' ./sample

# Frida on Linux:
frida-trace -i 'open*' -i 'connect' ./sample
frida -l hook.js ./sample

# bpftrace — kernel-level visibility without modifying the binary:
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s %s\n", comm, str(args->filename)); }'

# Containerised analysis — always do dynamic analysis in something disposable:
docker run --rm -it --network none -v $PWD:/work ubuntu:22.04 bash
# Or a microVM: firecracker / cloud-hypervisor
```

`strace` is shockingly underused in malware RE. A 30-second `strace` of a sample often reveals C2 hostname, dropper path, and persistence mechanism before you open the disassembler.

---

## Linux Malware Patterns

**Cryptominers (XMRig variants).** Statically-linked, often UPX-packed, hardcoded mining pool URLs in `.rodata`. Persistence via cron, systemd, or `/etc/rc.local`. The miner itself is open source; the malware is the dropper plus persistence wrapper. Look for high-entropy `.text` (if packed), strings matching `stratum+tcp://`, and CPU-affinity syscalls.

**IoT / Mirai-class.** Embeds `busybox`-style functionality, scans for telnet/SSH on port 23/2323/22, brute-forces credentials from a hardcoded list, fork-bomb propagation. Almost always cross-compiled with statically-linked `uClibc` or `musl`. Architectures: ARM, MIPS, MIPSEL, PowerPC, SuperH — check `e_machine`. Cross-arch QEMU (`qemu-mips-static`) plus a chroot or `binfmt_misc` registration is the standard environment.

**Backdoors.** Bind shell (`socket → bind → listen → accept → dup2 → execve("/bin/sh")`) or reverse shell (`socket → connect → dup2 → execve`). Pattern recognition: a `socket(AF_INET, SOCK_STREAM, 0)` followed shortly by `dup2(fd, 0)`, `dup2(fd, 1)`, `dup2(fd, 2)`, `execve` is a complete shell handler in ~20 lines. Common variations: ICMP-tunnelled, DNS-tunnelled, named-pipe-mediated.

**LD_PRELOAD rootkits.** A shared object preloaded via `/etc/ld.so.preload` that hooks `readdir`, `opendir`, `stat`, `open` to hide files; `kill`, `read /proc/<pid>/stat` to hide processes; `accept`, `recv` to hide network connections. Detection: enumerate `/proc/*/maps` directly via raw syscalls (bypassing libc), compare against `ps` output, diff. Examples: `Jynx`, `Azazel`, `Vlany`, `bedevil/bdvl`.

**Systemd / init persistence.** A `.service` unit file in `/etc/systemd/system/` (system) or `~/.config/systemd/user/` (user). User-level systemd does not require root. Triggers: `OnBootSec`, `OnUnitActiveSec`, or `WantedBy=multi-user.target`. Detection: enumerate units, hash unit files, alert on new ones with suspicious `ExecStart`. Older systems use `/etc/init.d/`, `/etc/rc.local`, `/etc/cron.d/`, `~/.bashrc`, `/etc/profile.d/`.

**Kernel module persistence (LKM rootkits).** An `.ko` module loaded via `insmod` that hooks the syscall table or VFS layer. Modern signed-module enforcement (`CONFIG_MODULE_SIG_FORCE`) defeats this on hardened systems, but most enterprise Linux ships with it disabled. Detection: hidden modules via `/sys/module/` listing vs `lsmod` mismatch; kernel symbol table integrity (`/proc/kallsyms`). Examples: `Diamorphine`, `Reptile`, `Suterusu`.

**eBPF-based stealth.** The 2023–2025 frontier. eBPF programs attached to syscall tracepoints or uprobes can hide processes, files, and network activity without modifying any on-disk artifact. The program lives in kernel memory and persists until reboot (unless pinned to bpffs). Detection: `bpftool prog show`, `bpftool map show`, `cat /sys/kernel/debug/tracing/uprobe_events`. Examples: `BPFDoor`, `Symbiote`, `Boopkit`.

**`memfd_create` + in-memory ELF loaders.** Allocate an anonymous file in memory, write the ELF there, `execveat()` it. The binary never touches disk. Detection signals: `memfd_create` followed by `execveat(AT_EMPTY_PATH)`, processes whose `/proc/<pid>/exe` symlink resolves to `/memfd:something (deleted)`.

---

## Linux Red Team Implant Patterns

**Pupy.** Python-based, cross-platform, in-memory module loader. Linux loader uses `memfd_create` + in-memory CPython.

**Mythic poseidon.** Go-based cross-platform agent for Mythic C2. Linux ELF, static `musl` link, no external dependencies. Beacon profile is configurable per build.

**Sliver Linux beacon.** Bishop Fox's open-source C2. Go-compiled, statically linked, supports HTTP(S), DNS, mTLS, WireGuard transports.

**Custom Go implants.** Go ELFs have a distinctive footprint: huge `.text` from the runtime, embedded type metadata in `.rodata`/`.gopclntab`, no PLT for Go-native calls (only for cgo). Identify with `go_parser` (Ghidra plugin) or `redress` to recover function names and types from `gopclntab`.

**Rust implants.** Statically-linked with `musl` for portability. Rust binaries are even more opaque than Go — no embedded type table, heavy monomorphisation, hard-to-recognise `Result<T, E>` unwinding paths. Look for `panic_bounds_check`, `core::panicking`, `rust_begin_unwind` symbols if not stripped.

**Static-musl tradeoff.** Statically-linked-with-musl implants run anywhere, leave no `DT_NEEDED` trail, and defeat `ltrace`. The cost: they are large (4–10 MB), trivially fingerprinted by file size + `musl` strings, and cannot use `LD_PRELOAD`-based evasion themselves.

---

## ELF Patching and Modification

```bash
# patchelf — surgical edits to the dynamic section
patchelf --print-interpreter sample
patchelf --set-interpreter /custom/ld-linux.so sample
patchelf --print-rpath sample
patchelf --set-rpath '$ORIGIN/lib' sample           # use literal $ORIGIN at runtime
patchelf --replace-needed libssl.so.1.1 libssl.so.3 sample
patchelf --add-needed libpreload.so sample          # baked-in LD_PRELOAD equivalent
patchelf --remove-needed libdebug.so sample
patchelf --shrink-rpath sample                       # remove unused RPATH entries

# LIEF (Python) — full ELF manipulation
python3 <<'PYEOF'
import lief
b = lief.parse("sample")
# Add a section:
sec = lief.ELF.Section(".payload")
sec.content = list(open("shellcode.bin","rb").read())
sec.size = len(sec.content)
b.add(sec)
# Hijack .init_array — prepend a constructor:
# (requires injecting code into a new section and updating DT_INIT_ARRAY)
b.write("modified")
PYEOF
```

**Cave injection.** Find an existing section with slack space (often `.eh_frame` or padding between segments), overwrite slack with your code, redirect entry point or a chosen `.init_array` slot to that address. Crude but effective on stripped binaries.

**`.init_array` patching for early execution.** Prepend a pointer to your shellcode to the array. The loader will call your code before `main`. This is the Linux analogue of the Windows TLS-callback trick.

---

## Detection Side

| Signal | Source | Why it matters |
|--------|--------|----------------|
| Write to `/etc/ld.so.preload` | auditd `-w /etc/ld.so.preload -p wa` | Global preload rootkit staging |
| New systemd unit file | auditd watch on `/etc/systemd/system/` and `~/.config/systemd/` | Persistence |
| `memfd_create` followed by `execveat` | eBPF tracepoint on `sys_enter_execveat` | In-memory ELF execution |
| `ptrace(PTRACE_ATTACH)` from non-debugger | auditd or eBPF | Process injection / credential theft |
| Process with `/proc/<pid>/exe` resolving to `(deleted)` | Periodic `/proc` walk | Process hollowing or memfd execution |
| Hidden kernel module (in `/sys/module/` but not `lsmod`) | Direct kernel walk | LKM rootkit |
| eBPF program attached to syscall tracepoints | `bpftool prog show` baseline diff | eBPF rootkit |
| `LD_PRELOAD` set in long-running process env | `tr '\0' '\n' < /proc/<pid>/environ` | Per-process preload injection |

**Tooling.** Falco and Tetragon both consume eBPF events and emit alerts on configured rules — they cover most of the table above out of the box. Sysdig (commercial Falco) adds richer enterprise integrations. Sandfly Security ships agentless Linux IR scanners that detect LKM, LD_PRELOAD, and process-hiding rootkits via `/proc` integrity checks.

**YARA on ELF.** YARA's `elf` module exposes program headers, sections, symbols, and entry-point bytes. Rules built on the entry-point opcode pattern and `.text` byte signatures generalise well across cryptominer and IoT botnet families. Loki, Thor, and YARA-CI all run ELF rule corpora against suspect hosts.

---

## Resources

- ELF specification — System V ABI, `refspecs.linuxfoundation.org/elf/elf.pdf`
- "Learning Linux Binary Analysis" — Ryan O'Neill (`@elfmaster`), Packt 2016
- Intezer Linux threat research — `intezer.com/blog/`
- Sandfly Security Linux IR research — `sandflysecurity.com/blog/`
- LIEF library — `lief.re/doc/latest/`
- patchelf — `github.com/NixOS/patchelf`
- radare2 / rizin — `rada.re/` and `rizin.re/`
- Ghidra — `ghidra-sre.org`
- pwndbg / GEF — `github.com/pwndbg/pwndbg` and `github.com/hugsy/gef`
- Falco / Tetragon — `falco.org` and `github.com/cilium/tetragon`
- Diamorphine LKM rootkit (defensive reading) — `github.com/m0nad/Diamorphine`
- bedevil / bdvl LD_PRELOAD rootkit (defensive reading) — `github.com/Error996/bdvl`
- redress (Go binary inspector) — `github.com/goretk/redress`
