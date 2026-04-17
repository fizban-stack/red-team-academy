---
layout: training-page
title: "Fuzzing Methodology — Red Team Academy"
module: "Vulnerability Research"
tags:
  - fuzzing
  - afl
  - libfuzzer
  - coverage-guided
  - harness-writing
  - crash-triage
  - sanitizers
page_key: "vuln-research-fuzzing-methodology"
render_with_liquid: false
---

# Fuzzing Methodology

Fuzzing is the process of feeding malformed, unexpected, or randomly generated inputs to a program and monitoring for crashes, hangs, or assertion failures. Modern coverage-guided fuzzing is the single most productive vulnerability discovery technique — it scales, it runs unattended, and it has found thousands of CVEs in production software. This page covers the full methodology from target selection through crash deduplication.

---

## Fuzzing Fundamentals

### Mutation vs Generation

**Mutation-based fuzzing** starts from a seed corpus of valid inputs and applies transformations:
- Bit flips, byte substitutions, block insertion/deletion
- Splice inputs from different corpus entries
- Dictionary-guided substitution of interesting values (0, -1, 0xFFFF, etc.)

**Generation-based fuzzing** (grammar-based / model-based) synthesizes inputs according to a specification:
- Peach fuzzer: XML-defined data models
- Boofuzz: Python network protocol fuzzing framework
- Grammar mutators (Nautilus, FormatFuzzer): derive grammar from examples

**When to use each:**
| Approach | Best For | Drawback |
|---------|---------|---------|
| Mutation | File formats, binary protocols (with seeds) | Needs valid seeds |
| Generation | Protocols with strict validation | Grammar dev is expensive |
| Coverage-guided | Any target you can instrument | Requires instrumentation |
| Blackbox random | Quick triage, unknown targets | Low depth |

### Coverage-Guided vs Blackbox

Coverage-guided fuzzers (AFL++, LibFuzzer, Honggfuzz) instrument the target to track which code paths each input exercises. When an input exercises a new code path, it's added to the corpus as a "interesting" seed for further mutation. This feedback loop systematically explores the program's state space.

```
Seed input → mutate → execute → measure coverage → new path? → save to corpus
                  ↑                    ↓ no new path
                  ←─────────────────── discard
```

Coverage types used in practice:
- **Edge coverage**: counts transitions between basic blocks (AFL++ default)
- **Path coverage**: tracks unique instruction sequences (expensive, rarely practical)
- **Value coverage**: CmpLog (AFL++) instruments comparisons to detect "magic bytes"
- **Call coverage**: which functions were called (coarser, faster)

---

## Target Selection

Not all targets are worth fuzzing. Evaluate:

**High-value fuzzing targets:**
- Complex file format parsers (image decoders, PDF, Office documents, video codecs)
- Network protocol implementations (TLS stacks, HTTP/2 parsers, QUIC)
- Language runtimes and JIT engines (JS engines, Python C extensions)
- Kernel drivers and OS components (file system drivers, network drivers)
- Cryptographic libraries (key parsing, ASN.1 decoders)
- Archive handlers (zlib, liblzma, zstd, 7-zip)

**Assessment criteria:**
```
Attack surface size × Complexity × Install base × Lack of prior fuzzing
```

**Red flags (don't waste time):**
- Already extensively fuzzed with OSS-Fuzz (check oss-fuzz.com/coverage)
- Simple input validation (fuzzer will find the same denial-of-service repeatedly)
- Pure network targets without a harness (need persistent mode or frida)

---

## Interface Identification

Map every input path before building harnesses. Miss an interface, miss the bugs.

### Network Services

```bash
# Service discovery
nmap -sV -p- --script=banner target_ip

# Application protocol identification
tcpdump -i eth0 -w capture.pcap host target_ip
# Analyze with Wireshark dissectors

# TLS inspection (if applicable)
mitmproxy --listen-port 8080 --ssl-insecure
```

### File Formats

```bash
# Identify formats a binary handles
strings target_binary | grep -E "(\.xml|\.json|\.bin|\.dat|magic_bytes)"
# Trace file opens during normal operation
strace -e trace=openat ./target normal_input.bin 2>&1 | grep -v ENOENT
# ltrace for library calls (fopen, fread, etc.)
ltrace -e fopen+fread ./target input.bin
```

### IOCTL Interfaces (Windows Kernel Drivers)

```c
// Enumerate IOCTLs via IDA/Ghidra: find IofCallDriver, find IOCTL dispatch
// IOCTL code structure: DeviceType | Access | Function | Method
// Example: 0x222003 = FILE_DEVICE_UNKNOWN | FILE_ANY_ACCESS | 0x800 | METHOD_BUFFERED

// Test with DeviceIoControl:
HANDLE hDevice = CreateFile(L"\\\\.\\DriverName", GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
DeviceIoControl(hDevice, ioctl_code, inbuf, insize, outbuf, outsize, &ret, NULL);
```

### IPC / COM Objects

```bash
# Windows: enumerate COM objects exposed by target
oleview.exe  # or
python comchrono.py  # enumerate COM class factory

# Linux: D-Bus interface dump
dbus-send --system --dest=org.target.Service \
  --type=method_call --print-reply / \
  org.freedesktop.DBus.Introspectable.Introspect
```

---

## Harness Writing

A fuzzing harness is the most important artifact in a fuzzing campaign. Poor harnesses = low coverage = missed bugs.

### Harness Architecture

```
Fuzzer → harness (test driver) → target function → crash / continue
           |
           ├── Init: global setup done once (suppress logs, init globals)
           ├── Test: LLVMFuzzerTestOneInput() called per iteration
           ├── Cleanup: release per-iteration resources
           └── Signal: crash signal propagates up to fuzzer
```

### Persistent Mode (Critical for Speed)

LibFuzzer is inherently persistent — the harness function is called in a tight loop.

AFL++ persistent mode:
```c
// Tell AFL++ this is persistent mode
#include "AFL/afl-fuzz.h"

int main(int argc, char *argv[]) {
    // One-time init
    target_init();
    
    // AFL++ persistent mode loop
    while (__AFL_LOOP(1000)) {  // Restart after 1000 iterations (memory safety)
        // Read input
        uint8_t buf[MAX_SIZE];
        ssize_t n = read(0, buf, sizeof(buf));
        if (n <= 0) continue;
        
        // Call target
        target_parse(buf, n);
    }
    return 0;
}
```

### Shared Memory (AFL_FUZZ_ARTIFACTS)

For targets that can't be modified for persistent mode:
```bash
# AFL++ shared memory fuzzing — target reads from /dev/shm/afl_shm_id
AFL_TMPDIR=/dev/shm AFL_FAST_CAL=1 afl-fuzz -i seeds/ -o out/ ./target @@
```

### Harness Anti-Patterns

| Anti-Pattern | Problem | Fix |
|-------------|---------|-----|
| `fork()` in harness | Defeats persistent mode, very slow | Call target function directly |
| `sleep()` in target path | Fuzzer hangs detection triggers | Intercept or remove |
| File I/O every iteration | Disk bottleneck, slow | Use `/tmp` ramdisk or memfd |
| Logging enabled | Disk I/O, stderr noise | `fclose(stderr)` or patch logging |
| Memory leaks | OOM after N iterations | Free all per-iteration allocations |

---

## Seed Corpus Creation

The corpus is the starting point for mutation. Quality matters more than quantity.

**Corpus collection strategy:**
```bash
# Collect real-world samples from:
# 1. Open datasets (Common Crawl, PDFs from Internet Archive)
# 2. Target application's test suite (unit tests often have valid inputs)
# 3. Wireshark captures of normal traffic
# 4. File format specifications' example files
# 5. Previous fuzzing runs (coverage-filtered)

# Minimize corpus for efficiency
afl-cmin -i raw_corpus/ -o min_corpus/ -- ./target @@
# Further minimize individual seeds
afl-tmin -i seed.bin -o seed_min.bin -- ./target @@
```

**Boundary values for numeric fields:**
```python
interesting_values = [
    0, 1, -1, 127, 128, 255, 256,
    32767, 32768, 65535, 65536,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
]
```

---

## Sanitizers

Sanitizers are compile-time instrumentation that detect bugs at runtime that would otherwise be silent.

### AddressSanitizer (ASan)

Detects: heap-buffer-overflow, stack-buffer-overflow, use-after-free, use-after-return, double-free

```bash
clang -fsanitize=address -fno-omit-frame-pointer -g target.c -o target_asan
# OR with AFL++
AFL_USE_ASAN=1 afl-clang-fast target.c -o target_asan
```

ASan output example:
```
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050
READ of size 4 at 0x602000000050 thread T0
    #0 0x... in parse_header /src/target.c:42:5
    #1 0x... in process_input /src/target.c:91:3
0x602000000050 is located 0 bytes to the right of 8-byte region
allocated by thread T0 here:
    #0 0x... in malloc /llvm/sanitizer_common.cc
    #1 0x... in init_buffer /src/target.c:30:20
```

### Undefined Behavior Sanitizer (UBSan)

Detects: integer overflow, null pointer dereference, misaligned access, invalid enum values

```bash
clang -fsanitize=undefined -g target.c -o target_ubsan
# Combined with ASan:
clang -fsanitize=address,undefined -g target.c -o target_asan_ubsan
```

### MemorySanitizer (MSan)

Detects: use of uninitialized memory (uninit reads). Requires all linked libraries to be MSan-instrumented.

```bash
clang -fsanitize=memory -fno-omit-frame-pointer -g target.c -o target_msan
```

### When to Enable Which Sanitizer

| Phase | Sanitizer | Reason |
|-------|---------|--------|
| Harness development | ASan + UBSan | Catch harness bugs early |
| Initial fuzzing | ASan | Best bug detection / speed tradeoff |
| Coverage exploration | None | Maximum fuzzing speed |
| Crash validation | ASan + UBSan | Full diagnostic output |
| Regression testing | ASan + MSan | Maximum coverage of bug classes |

---

## Crash Deduplication

Raw fuzzer output contains hundreds or thousands of crash files — most are duplicates of the same bug triggered by different inputs.

### Stack Hash Deduplication

```bash
# AFL++ built-in: crashes in out/crashes/
# Each crash filename contains the mutation stage and parent seed

# External deduplication with exploitable
for f in out/crashes/id*; do
    gdb -q -batch -ex "run < $f" -ex "bt" -ex "quit" ./target 2>&1 | \
    python3 exploitable.py >> crash_report.txt
done

# Group by stack hash
python3 - << 'EOF'
import hashlib, re, sys
crashes = {}
for line in open('crash_report.txt'):
    if 'Hash:' in line:
        h = line.split()[-1]
        crashes[h] = crashes.get(h, 0) + 1
for h, count in sorted(crashes.items(), key=lambda x: -x[1]):
    print(f"{count:4d} {h}")
EOF
```

### Coverage-Bucketed Deduplication

AFL++ addresses this with coverage buckets — each unique branch coverage map = unique crash entry. But coverage-unique crashes may still share root cause.

**Manual triage tiers:**
1. **Tier 1**: SEGFAULT on controlled address → likely exploitable (PC/RIP control, arbitrary write)
2. **Tier 2**: Heap corruption → evaluate with ASAN output
3. **Tier 3**: Stack overflow → likely exploitable if EIP/RIP reachable
4. **Tier 4**: NULL dereference → usually DoS only
5. **Tier 5**: Assertion failure / abort → logic bug, may not be exploitable

### AFL Crash Minimization

```bash
# Minimize crash input to smallest reproducer
afl-tmin -i out/crashes/id:000001 -o crash_min.bin -- ./target @@

# Test minimized crash still triggers
./target_asan < crash_min.bin
# Should see ASAN output
```

---

## Scaling Fuzzing

### Multiple CPU Cores

AFL++ master/secondary pattern:
```bash
# Master instance (generates test cases)
afl-fuzz -i seeds/ -o sync_dir/ -M master -- ./target @@

# Secondary instances (parallel exploration — one per CPU core)
afl-fuzz -i seeds/ -o sync_dir/ -S slave01 -- ./target @@
afl-fuzz -i seeds/ -o sync_dir/ -S slave02 -- ./target @@
afl-fuzz -i seeds/ -o sync_dir/ -S slave03 -- ./target @@

# Monitor all instances
afl-whatsup sync_dir/
```

### VM Snapshot Fuzzing (WTF / kAFL)

For kernel fuzzing where crashes require full VM restart:

**WTF (What the Fuzz)** — Windows kernel fuzzer using Hyper-V snapshots:
```
1. Take VM snapshot at interesting kernel entry point
2. Feed mutated input via shared memory
3. Execute until crash or return
4. Restore snapshot → repeat (no OS boot overhead)
```

**kAFL** — Linux kernel fuzzer using KVM + Intel PT:
```bash
# kAFL setup
git clone https://github.com/IntelLabs/kAFL
# Requires Intel PT hardware support
# Provides coverage feedback without kernel instrumentation
```

### Cloud Scaling

```bash
# Google ClusterFuzz / OSS-Fuzz model
# Run LibFuzzer targets in Cloud Run / GKE
# Corpus synced to GCS bucket
# Crash deduplication via ClusterFuzz backend

# Simple AWS parallel fuzzing
# Spin up N EC2 instances with same AMI
# Each runs independent AFL++ secondary
# Sync corpus via S3 every hour
aws s3 sync s3://fuzz-corpus/target/ seeds/ --quiet
afl-fuzz -i seeds/ -o local_out/ -S worker_$(hostname) -- ./target @@
```

---

## Measuring Progress

### Coverage Growth Curves

A healthy fuzzing campaign shows rapid early coverage growth that levels off:

```
Coverage %
    |
100 |              ──────────────────
 80 |         ────/
 60 |      ───/
 40 |    ──/
 20 |  ─/
    |──
    +────────────────────────────────> Time
       1h  6h  24h  72h  1wk  1mo
```

**Plateau analysis:**
- Early plateau (< 24h): likely missing code paths — add seeds, check harness coverage
- Long flat plateau: consider structure-aware mutators or manual injection of valid intermediate states
- Coverage < 30%: harness probably not reaching deep parsing logic

### Useful AFL++ Metrics

```bash
# Real-time stats
cat sync_dir/master/fuzzer_stats | grep -E "(paths_total|unique_crashes|execs_per_sec|map_density)"

# paths_total: unique code paths found
# unique_crashes: deduplicated crash count
# execs_per_sec: throughput (target 1000+ for native, 100+ for QEMU)
# map_density: percentage of coverage bitmap used (>70% = map overflow risk)
```

**Target throughput ranges:**
| Target Type | Expected Execs/sec |
|------------|-------------------|
| File parser (native) | 5,000–50,000 |
| Network service (persistent mode) | 1,000–10,000 |
| Browser JS engine | 500–5,000 |
| Kernel driver (QEMU mode) | 100–1,000 |
| Hardware emulator | 10–100 |
