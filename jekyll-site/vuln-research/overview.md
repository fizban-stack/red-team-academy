---
layout: training-page
title: "Vulnerability Research Overview — Red Team Academy"
module: "Vulnerability Research"
tags:
  - vuln-research
  - exploit-dev
  - fuzzing
  - reverse-engineering
  - bug-bounty
  - cve
  - responsible-disclosure
page_key: "vuln-research-overview"
render_with_liquid: false
---

# Vulnerability Research Overview

Vulnerability research is the discipline of discovering, analyzing, and documenting security weaknesses in software and hardware before (or after) adversaries do. Unlike penetration testing, which applies known techniques against known targets, vuln research creates net-new offensive primitives — turning a crash into a CVE, a logic flaw into an exploit chain, or a subtle type confusion into a browser RCE. This page maps the research lifecycle from target selection through responsible disclosure.

---

## Research Methodology

### 1. Target Selection

Target selection is a business decision as much as a technical one. Factors to weigh:

| Factor | High Value | Low Value |
|--------|-----------|-----------|
| Attack surface | Network-facing, complex parsers | CLI utilities, offline tools |
| Patch cadence | Monthly or irregular | Weekly with fast CI |
| Historical bugs | Many CVEs, complex codebase | Clean track record |
| Researcher competition | Low (niche targets) | High (browsers, kernels) |
| Bounty / prestige | High (critical infra, browsers) | No program, low caps |
| Source availability | Open source (faster) | Binary-only (harder but less competition) |

**Practical starting points:**
- **ZDI / Pwn2Own targets** — companies pre-select high-value targets with guaranteed payouts
- **CVE density search** — search NVD for products with many historical memory corruption bugs
- **Exposed network services** — services exposed on the internet with large install bases (VPN gateways, mail servers, hypervisors)
- **Recently acquired codebases** — M&A often means auditing gaps, old code in new products

### 2. Interface Enumeration (Attack Surface Mapping)

Before any fuzzing or auditing begins, map every interface the target exposes:

```bash
# Network-facing attack surface
nmap -sV -p- --open target
# File format parsers
strings target_binary | grep -E "\.(xml|json|docx|pdf|zip)"
# IPC / named pipes (Windows)
pipelist.exe
# IOCTL interface (Windows driver)
IoCTLCommand.exe DriverName
# Sockets / IPC (Linux)
ss -tlnp
ls /proc/$(pgrep target)/fd | xargs -I{} readlink /proc/$(pgrep target)/fd/{}
```

Attack surface categories:
- **Network protocols**: HTTP/S, custom TCP, UDP, WebSocket, proprietary binary protocols
- **File format parsers**: document readers, image decoders, archive handlers, firmware images
- **Kernel interfaces**: IOCTL dispatch tables, syscall handlers, kernel modules
- **IPC mechanisms**: COM/DCOM, D-Bus, named pipes, shared memory, Unix sockets
- **Browser attack surface**: JS engine, CSS parser, DOM, WebGL, WebAssembly, media codecs

### 3. Harness Writing

A harness is the wrapper code that feeds input to the target function and provides feedback (coverage, crash detection) to the fuzzer. Quality harnesses are critical — they define what the fuzzer can reach.

```c
// LibFuzzer harness skeleton
#include <stdint.h>
#include <stddef.h>

// Target function declaration
extern int parse_image(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Call the target with fuzzer-provided bytes
    parse_image(Data, Size);
    return 0; // 0 = continue fuzzing, -1 = discard input
}
```

Harness design principles:
- **Minimize non-fuzzing code** — avoid fork(), exec(), network calls in hot path
- **Persistent mode** — re-use process across iterations for 10-100x speedup
- **Shared memory** — reduce IPC overhead between fuzzer and target
- **Initialize once** — global state setup (log suppression, resource init) outside the fuzzer loop
- **Avoid leaks** — persistent mode amplifies memory leaks into OOMs

### 4. Feedback Engine

Coverage-guided fuzzers use instrumentation to track which code paths each input exercises. New coverage = interesting input → saved to corpus. No new coverage → input discarded.

**Instrumentation types:**
- **Compile-time (fastest)**: `clang -fsanitize=fuzzer` or `afl-clang-fast` inserts counters at every basic block edge
- **Binary rewriting (no source)**: AFL++ QEMU mode, Frida instrumentation, DynamoRIO
- **Hardware tracing**: Intel PT (Processor Trace) — cycle-accurate, minimal overhead, used by kAFL and WTF

### 5. Crash Triage

Raw fuzzer output contains duplicate crashes, benign null derefs, and genuine memory corruption. Triage pipeline:

```
Raw crashes → deduplication (stack hash) → minimization (afl-tmin) 
→ root cause analysis → exploitability assessment → PoC development
```

Triage tools:
- **GDB + exploitable**: `gdb target < crash; python /path/to/exploitable.py`
- **WinDbg + !exploitable**: `!load msec; !exploitable`
- **AddressSanitizer report**: crash output includes allocation site, access site, stack trace
- **ASAN symbolizer**: `llvm-symbolizer` converts addresses to source locations

---

## Bug Classes and Where to Find Them

### Memory Corruption

Memory corruption bugs arise from incorrect memory management — the most exploitable class.

| Bug Class | Root Cause | Typical Location | MITRE |
|-----------|-----------|-----------------|-------|
| Stack overflow | Unbounded write to stack buffer | Parsing, string operations | T1499 |
| Heap overflow | Write past heap allocation end | Parser logic, deserialization | T1055 |
| Use-after-free | Dereference after free() | Event handlers, callbacks, async code | T1055 |
| Double-free | free() called twice | Error handling paths | T1055 |
| Integer overflow | Arithmetic wraps, causing undersized alloc | Size calculations, counters | T1499 |
| Type confusion | Object treated as wrong type | OOP, polymorphism, casting | T1055 |
| Out-of-bounds read | Read past array end | Parser loops, index calculations | — |
| Format string | Unsanitized format argument | Logging, error messages | T1055 |

**Where to look:**
- Memory allocation wrappers (custom malloc, pool allocators)
- Parser length/offset calculations
- Object lifecycle management (reference counting, deferred free)
- Type casting in polymorphic code (C++ virtual dispatch)

### Logic Bugs

Logic bugs don't corrupt memory but violate security invariants:
- Authentication bypass: wrong condition in permission check
- TOCTOU (Time-of-check/time-of-use): race between access check and access
- Integer signedness: signed/unsigned comparison causing wrong bounds check
- Path traversal: missing normalization before file open
- Injection: user input interpreted as command/query structure

Logic bugs are harder to find with fuzzing alone — they require code auditing and understanding of intended semantics.

### Use-After-Free (UAF) Deep Dive

UAF is the dominant bug class in modern browsers and complex applications:

```c
// Vulnerable pattern
struct Node {
    int value;
    struct Node *next;
    void (*callback)(struct Node *); // function pointer
};

void process(struct Node *n) {
    if (n->value == SPECIAL)
        free(n); // n freed here
    n->callback(n); // callback invoked on freed n — UAF!
}
```

UAF exploitation requires:
1. Triggering the free (often via a specific code path)
2. Filling the freed allocation with attacker-controlled data (heap grooming)
3. Triggering the use — now the freed memory contains attacker data
4. Achieving code execution (e.g., overwritten function pointer called)

---

## Setting Up a Research Environment

### Dedicated VM Setup

Research happens in isolated VMs to contain target crashes and avoid polluting the host:

```bash
# KVM/QEMU for Linux targets
virt-install --name vuln-lab --ram 8192 --vcpus 4 \
  --disk size=100 --os-type linux \
  --cdrom ubuntu-22.04-server.iso

# Snapshots for clean-state restoration
virsh snapshot-create-as vuln-lab clean-state
virsh snapshot-revert vuln-lab clean-state
```

**VM hardening for kernel research:**
- Enable serial console for kernel panic output
- Set `panic=1` in kernel cmdline for auto-reboot on crash
- Use `KASAN` (Kernel AddressSanitizer) in the debug kernel

### Windows Kernel Debugging (WinDbg / KD)

Two-machine debugging setup:
```
Target VM <--[COM/KDNET]--> Host WinDbg
```

```powershell
# Target: enable kernel debugging over network (KDNET)
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000
# Target: disable Secure Boot in VM settings first

# Host: WinDbg Preview → Attach to kernel → Net
# Key: set to match target
```

Useful WinDbg commands for crash analysis:
```windbg
!analyze -v          ; automated crash analysis
kb                   ; stack backtrace
dt nt!_EPROCESS      ; display type structure
!pool address        ; pool tag analysis for heap
!exploitable         ; exploitability assessment (MSEC extension)
uf nt!NtCreateFile   ; disassemble function
lm m nt              ; list module info
```

### Crash Analysis Tools

| Tool | Platform | Use Case |
|------|----------|----------|
| WinDbg + !exploitable | Windows | Kernel and user-mode crash triage |
| GDB + exploitable.py | Linux | User-mode exploitability |
| rr (Mozilla) | Linux | Record-and-replay for flaky crashes |
| ASAN/UBSAN | Linux/macOS | Memory error detection with symbolization |
| Dr. Memory | Windows/Linux | Valgrind alternative for Windows |
| Valgrind Memcheck | Linux | Heap error detection |

---

## Research Workflow

The research cycle from target to CVE:

```
1. READ
   ├── Source code audit (if available)
   └── Binary analysis with Ghidra/BN

2. IDENTIFY ATTACK SURFACE
   ├── Network interface enumeration
   ├── File format / input enumeration
   └── API / IPC surface mapping

3. WRITE HARNESS
   ├── Target the most complex parsing code
   ├── Add sanitizer instrumentation
   └── Build initial seed corpus

4. FUZZ
   ├── Coverage-guided fuzzing (AFL++/LibFuzzer)
   ├── Monitor coverage growth
   └── Scale to multiple cores

5. ANALYZE CRASHES
   ├── Deduplicate by stack hash
   ├── Minimize crash inputs
   └── Root cause analysis

6. PROVE EXPLOITABILITY
   ├── Determine bug class
   ├── Develop primitive (read/write/execute)
   └── Build reliable PoC

7. DISCLOSE
   ├── Vendor notification
   ├── CVE request
   └── Public disclosure (90 days post-patch)
```

---

## Responsible Disclosure

### CVE Process

The Common Vulnerabilities and Exposures (CVE) system assigns unique identifiers to publicly disclosed vulnerabilities.

**Requesting a CVE:**
1. **MITRE CNA**: submit to cve.mitre.org/cgi-bin/cvename.cgi for most products
2. **Vendor CNA**: large vendors (Microsoft, Google, Apple, Red Hat) are their own CNAs — submit directly
3. **Bug Bounty Platform**: HackerOne and Bugcrowd often handle CVE requests as part of the program

CVE ID format: `CVE-YEAR-NNNNN` (e.g., CVE-2024-12345)

### Vendor Notification Timelines

Standard timeline (Google Project Zero model):
```
Day 0:   Vendor notification (private)
Day 7:   Reminder if no acknowledgment
Day 30:  Status check — is a patch in progress?
Day 90:  Public disclosure regardless of patch status
Day 90+: If vendor requests extension (active exploitation risk), max 14-day grace
```

**CERT/CC coordinated disclosure:**
- Slower (120-day default) but handles multi-vendor scenarios
- Appropriate when the bug affects many downstream consumers (e.g., open-source library)

### Bug Bounty Programs

| Program | Platform | Scope | Max Payout |
|---------|---------|-------|-----------|
| Google VRP | Bughunters | Chrome, Android, GCP | $250,000+ |
| Microsoft MSRC | MSRC portal | Windows, Azure, M365 | $250,000+ |
| Apple Security | security@apple.com | iOS, macOS, Safari | $1,000,000 (iMessage zero-click) |
| HackerOne programs | hackerone.com | Many vendors | Varies |
| ZDI | Zero Day Initiative | Any product | $2,500–$150,000 |
| Crowdfense | Private | iOS, Android, browsers | $5M (iOS full chain) |

---

## Public Resources

**Research blogs and advisories:**
- **Project Zero** (googleprojectzero.blogspot.com) — deep technical writeups on real 0-days
- **ZDI Blog** (zerodayinitiative.com/blog) — vulnerability analysis and patch diffing
- **Microsoft Security Response Center** (msrc.microsoft.com) — MSRC blog, advisories
- **SEC Consult Vulnerability Lab** — enterprise product research
- **Claroty/Dragos/Nozomi** — ICS/OT vulnerability research

**Databases:**
- **NVD** (nvd.nist.gov) — canonical CVE database with CVSS scores
- **ExploitDB** (exploit-db.com) — public exploit code, searchable by CVE
- **Packet Storm** (packetstormsecurity.com) — advisories, exploits, tools
- **VulDB** (vuldb.com) — alternative CVE database with timeline data

**Training and CTFs:**
- **pwn.college** — browser, kernel, and binary exploitation curriculum
- **ROP Emporium** — ROP chain development practice
- **LiveOverflow** — YouTube channel with research walkthroughs
- **Hack The Box Pro Labs** — realistic enterprise environments
