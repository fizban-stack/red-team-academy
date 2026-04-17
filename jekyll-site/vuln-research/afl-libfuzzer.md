---
layout: training-page
title: "AFL++, LibFuzzer & Honggfuzz — Red Team Academy"
module: "Vulnerability Research"
tags:
  - afl-plus-plus
  - libfuzzer
  - honggfuzz
  - fuzzing
  - coverage-guided
  - binary-fuzzing
  - structure-aware
page_key: "vuln-research-afl-libfuzzer"
render_with_liquid: false
---

# AFL++, LibFuzzer & Honggfuzz

The three dominant coverage-guided fuzzing frameworks each excel in different scenarios. AFL++ is the most versatile general-purpose fuzzer with extensive mutation strategies. LibFuzzer integrates tightly into the LLVM sanitizer ecosystem and is ideal for in-process library fuzzing. Honggfuzz offers hardware-feedback modes and native network fuzzing. This page covers setup, configuration, and selection criteria for each.

---

## AFL++ Setup and Instrumentation

AFL++ (the community fork of American Fuzzy Lop) is the most widely-used coverage-guided fuzzer for binary targets.

### Installation

```bash
# Build from source (recommended for latest features)
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib   # Build all components
sudo make install

# Verify install
afl-fuzz --version
afl-cc --version
```

### Instrumentation Modes

AFL++ supports multiple instrumentation backends. Choose based on target availability:

| Mode | Invocation | Source Required | Speed | Use Case |
|------|-----------|----------------|-------|---------|
| llvm-mode | `afl-clang-fast` | Yes | Fastest | Default for open-source targets |
| gcc-mode | `afl-gcc-fast` | Yes | Fast | When Clang unavailable |
| QEMU mode | `-Q` flag | No | ~5x slower | Closed-source binaries |
| Frida mode | `-O` flag | No | ~3x slower | iOS/Android, hooking needed |
| Unicorn mode | Manual | No | Slowest | Firmware, partial emulation |

```bash
# llvm-mode compilation (preferred)
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure
make -j$(nproc)

# With AddressSanitizer
AFL_USE_ASAN=1 CC=afl-clang-fast ./configure
make

# QEMU mode for binary-only targets (no source)
afl-fuzz -Q -i seeds/ -o out/ -- ./closed_source_binary @@
```

### Key AFL++ Flags

```bash
# Full example command
afl-fuzz \
  -M master \           # Master instance (deterministic)
  -i seeds/ \           # Input seed corpus
  -o sync_dir/ \        # Output directory (shared for secondary instances)
  -x dict/format.dict \ # Optional dictionary for format-specific mutations
  -p explore \          # Power schedule: explore (vs exploit)
  -c cmplog \           # CmpLog binary for comparison logging
  -t 5000 \             # Timeout per execution (ms)
  -m none \             # Memory limit (none = unlimited, needed for ASAN)
  -- ./target @@        # @@ replaced with temp file path

# Secondary instances
afl-fuzz -S slave01 -i seeds/ -o sync_dir/ -- ./target @@
afl-fuzz -S slave02 -i seeds/ -o sync_dir/ -- ./target @@
```

**Power schedules explained:**
- `explore`: Favors exploring new paths (default, good start)
- `exploit`: Favors inputs that already found bugs (crash-focused)
- `fast`, `coe`, `lin`, `quad`: Different coverage weighting algorithms
- `mmopt`: Machine learning-based scheduling (experimental)

### AFL++ CmpLog

CmpLog instruments comparison operations to learn "magic bytes" — values the target validates:

```bash
# Build two binaries: normal instrumented + cmplog instrumented
afl-clang-fast -o target target.c
afl-clang-fast -DCMPLOG=1 -o target_cmplog target.c  # or use afl-clang-fast with -c

# Run with CmpLog
afl-fuzz -i seeds/ -o out/ -c ./target_cmplog -- ./target @@
# AFL++ learns that bytes at offset 4 must equal 0x4D4D (magic number)
# and generates inputs with correct magic bytes automatically
```

### Persistent Mode in AFL++

```c
// afl-persistent.c — persistent mode example
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AFLplusplus/config.h"  // or just use __AFL_LOOP

extern int parse_target(unsigned char *data, size_t len);

int main(int argc, char *argv[]) {
    unsigned char buf[4096];
    ssize_t n;
    
    // One-time initialization
    setenv("AFL_DISABLE_LOGGING", "1", 1);
    
    // AFL++ persistent mode loop — calls process ~1000x before restart
    while (__AFL_LOOP(1000)) {
        n = read(0, buf, sizeof(buf));
        if (n <= 0) continue;
        parse_target(buf, n);
    }
    return 0;
}
```

```bash
# Compile with AFL++ instrumentation
afl-clang-fast -o target_persistent afl-persistent.c target_lib.a
# Run — AFL++ detects __AFL_LOOP and enables persistent mode automatically
afl-fuzz -i seeds/ -o out/ -- ./target_persistent
```

---

## LibFuzzer

LibFuzzer is a coverage-guided fuzzer built into LLVM, running as an in-process library. It is the fuzzer of choice for library fuzzing where you want maximum speed and tight sanitizer integration.

### Target Function Signature

Every LibFuzzer target implements exactly one function:

```c
// libfuzzer_target.c
#include <stdint.h>
#include <stddef.h>

// The fuzzing entry point — called millions of times per second
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Never: exit(), abort(), global state modification without reset
    // Always: pure function or reset state at end
    
    if (Size < 4) return 0;  // Reject trivially small inputs
    
    my_library_parse(Data, Size);  // Call the target
    return 0;  // Non-zero = crash (intentional), 0 = continue
}
```

### Compilation

```bash
# Compile with LibFuzzer + AddressSanitizer
clang \
  -fsanitize=fuzzer,address \     # LibFuzzer + ASan
  -fno-omit-frame-pointer \       # Better stack traces
  -g \                            # Debug symbols
  libfuzzer_target.c target_lib.c \
  -o target_fuzzer

# Run
./target_fuzzer corpus/ -max_len=10000 -timeout=10 -jobs=8 -workers=8

# Reproduce a specific crash
./target_fuzzer crash-abc123
```

### LibFuzzer Flags

```bash
./target_fuzzer [flags] [corpus_dirs]

# Important flags:
-max_len=N          # Maximum input length (default: 4096)
-timeout=N          # Per-input timeout seconds (default: 1200)
-jobs=N             # Parallel jobs (forks N workers)
-workers=N          # Total worker count
-dict=file          # Dictionary of interesting tokens
-seed=N             # RNG seed for reproducibility
-runs=N             # Total iterations (-1 = infinite)
-print_final_stats=1 # Print coverage stats at end
-artifact_prefix=   # Prefix for saved crashes
-minimize_crash=1   # Minimize crash after finding it
```

### LibFuzzer vs AFL++

| Criterion | LibFuzzer | AFL++ |
|-----------|----------|-------|
| Process model | In-process (single process) | Out-of-process (fork/exec) |
| Speed | Fastest (no fork overhead) | Fast with persistent mode |
| Crash isolation | Poor (crash kills fuzzer) | Excellent |
| Sanitizer integration | Native (LLVM ecosystem) | Good (AFL_USE_ASAN) |
| Binary-only targets | Not supported | Yes (QEMU/Frida) |
| Corpus management | Built-in (corpus dir) | Built-in (sync_dir) |
| Dictionary support | Yes (-dict) | Yes (-x) |
| Parallel scaling | Built-in (-jobs) | Manual secondary instances |
| Community | Large (Google OSS-Fuzz) | Largest (community fork) |

**When to choose LibFuzzer:**
- Library fuzzing with available source
- OSS-Fuzz integration (uses LibFuzzer by default)
- Need maximum speed on single-threaded target
- Tight sanitizer integration required

**When to choose AFL++:**
- Binary-only targets (QEMU/Frida mode)
- Complex mutation strategies needed (CmpLog, custom mutators)
- Multi-process fault isolation required
- Network protocol fuzzing (with `-N` network mode)

---

## Honggfuzz

Honggfuzz (from Google) offers hardware-feedback coverage using Intel BTS/PT and supports native network fuzzing — unique capabilities among major fuzzers.

### Installation

```bash
git clone https://github.com/google/honggfuzz
cd honggfuzz
make
sudo make install
```

### Compilation Modes

```bash
# Software coverage (like AFL++)
hfuzz-clang target.c -o target_hf

# Hardware coverage (Intel PT — requires root and kernel support)
hfuzz-clang -DHFUZZ_USE_INTELPT target.c -o target_hf_pt

# Check Intel PT support
dmesg | grep -i "intel_pt"
cat /proc/cpuinfo | grep pt
```

### Running Honggfuzz

```bash
# Basic file fuzzing
honggfuzz \
  --input seeds/ \            # Seed directory
  --output corpus/ \          # Output directory
  --threads 8 \               # Parallel threads
  --timeout 10 \              # Per-input timeout
  --rlimit_mem 1024 \         # Memory limit (MB)
  -- ./target ___FILE___      # ___FILE___ = input file placeholder

# Network fuzzing (unique to Honggfuzz)
honggfuzz \
  --input seeds/ \
  --net_server \              # Target is a network server
  --net_addr 127.0.0.1 \
  --net_port 8080 \
  --net_proto TCP \
  -- ./network_server_binary
```

### Hardware Coverage Feedback

Intel PT provides cycle-accurate branch tracing with minimal overhead (~5% vs 30-100% for software instrumentation):

```bash
# Verify PT capability
perf stat -e intel_pt// -- ls /tmp  # Should not error

# Run honggfuzz with PT feedback
honggfuzz --linux_perf_pt --input seeds/ -- ./target ___FILE___
```

**Advantages of hardware feedback:**
- No instrumentation pass required (works on stripped binaries)
- Minimal overhead (useful for timing-sensitive targets)
- Captures coverage in shared libraries automatically
- Can fuzz kernel drivers (ring 0) with PT tracing

---

## Binary-Only Fuzzing

When source code is unavailable, instrumentation must happen at runtime.

### AFL++ QEMU Mode

```bash
# Install QEMU mode (builds during AFL++ install if qemu-system available)
cd AFLplusplus
make -C qemu_mode

# Fuzz closed-source x86_64 binary
afl-fuzz -Q -i seeds/ -o out/ -- ./closed_binary @@

# With QEMU persistent mode (target must support AFL_LOOP)
AFL_QEMU_PERSISTENT_ADDR=0x401234 \   # Function entry point
AFL_QEMU_PERSISTENT_RET=0x401300 \    # Function return point
afl-fuzz -Q -i seeds/ -o out/ -- ./closed_binary
```

### AFL++ Frida Mode

Frida mode enables fuzzing of iOS/Android apps and targets requiring dynamic instrumentation:

```bash
# Build Frida mode
cd AFLplusplus
make -C frida_mode

# Fuzz with Frida
afl-fuzz -O -i seeds/ -o out/ -- ./target @@

# Android app fuzzing
afl-fuzz -O -i seeds/ -o out/ \
  -- frida -l harness.js -f com.target.app
```

---

## Structure-Aware Fuzzing

Plain byte mutation struggles with targets that require structurally valid inputs. Structure-aware fuzzing generates inputs that respect the format grammar.

### libprotobuf-mutator

For targets that accept protocol buffer messages:

```cpp
// proto_fuzzer.cc
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "target.pb.h"

DEFINE_PROTO_FUZZER(const MyProtoMessage& input) {
    std::string serialized;
    input.SerializeToString(&serialized);
    parse_target((uint8_t*)serialized.data(), serialized.size());
}
```

```bash
# Compile
clang -fsanitize=fuzzer,address \
  proto_fuzzer.cc \
  -lprotobuf-mutator-libfuzzer -lprotobuf \
  -o proto_fuzzer
./proto_fuzzer corpus/
```

### Custom AFL++ Mutators

For custom binary formats, implement a custom mutator:

```c
// custom_mutator.c — AFL++ custom mutator API
#include "AFL/afl-fuzz.h"

// Called to mutate a single input
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {
    // Parse the buffer as your custom format
    struct MyFormat *fmt = parse_format(buf, buf_size);
    
    // Apply format-aware mutation
    mutate_field_1(fmt);  // e.g., change a specific field value
    
    // Serialize back
    *out_buf = serialize_format(fmt, max_size);
    return get_serialized_size(fmt);
}
```

```bash
AFL_CUSTOM_MUTATOR_LIBRARY=./custom_mutator.so \
AFL_CUSTOM_MUTATOR_ONLY=1 \
afl-fuzz -i seeds/ -o out/ -- ./target @@
```

### Nautilus Grammar Fuzzer

Nautilus uses a formal grammar to generate syntactically valid inputs:

```python
# nautilus_grammar.py — define a grammar for your format
grammar = {
    "<start>": ["<statement>+"],
    "<statement>": ["<assignment>", "<if_stmt>", "<loop>"],
    "<assignment>": ["<var> = <expr>;"],
    "<expr>": ["<number>", "<var>", "<expr> + <expr>", "<expr> * <expr>"],
    "<number>": ["0", "1", "42", "0xFFFF", "-1"],
    "<var>": ["x", "y", "z", "counter"]
}
```

---

## Integrating with Sanitizers

### AFL++ + ASan

```bash
# Build with ASan
AFL_USE_ASAN=1 afl-clang-fast -o target_asan target.c

# Run — ASan output goes to stderr, crash files to out/crashes/
AFL_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.5 \
afl-fuzz -i seeds/ -o out/ -m none -- ./target_asan @@
# -m none: ASan needs large virtual address space
```

### LibFuzzer + MSan

MSan catches reads of uninitialized memory — harder to trigger than ASan bugs:

```bash
# Build with MSan (requires MSan-instrumented system libraries)
clang -fsanitize=fuzzer,memory \
  -fno-omit-frame-pointer \
  target.c -o target_msan_fuzzer

# MSan requires all linked code to be MSan-instrumented
# Use Chromium's MSan instrumented libraries or build everything with MSan
```

---

## Practical End-to-End Example: Fuzzing a File Parser

### Target: libjpeg-turbo (JPEG decoder)

```bash
# 1. Get source
git clone https://github.com/libjpeg-turbo/libjpeg-turbo
cd libjpeg-turbo

# 2. Build with AFL++ instrumentation
mkdir build-afl && cd build-afl
cmake .. -DCMAKE_C_COMPILER=afl-clang-fast \
         -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
         -DWITH_JAVA=OFF
make -j$(nproc)

# 3. Write harness
cat > harness.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "jpeglib.h"

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    
    while (__AFL_LOOP(1000)) {
        FILE *f = fopen(argv[1], "rb");
        if (!f) continue;
        
        struct jpeg_decompress_struct cinfo;
        struct jpeg_error_mgr jerr;
        
        cinfo.err = jpeg_std_error(&jerr);
        jpeg_create_decompress(&cinfo);
        jpeg_stdio_src(&cinfo, f);
        jpeg_read_header(&cinfo, TRUE);
        jpeg_start_decompress(&cinfo);
        
        // Read all scanlines
        while (cinfo.output_scanline < cinfo.output_height) {
            unsigned char *row = malloc(cinfo.output_width * cinfo.output_components);
            jpeg_read_scanlines(&cinfo, &row, 1);
            free(row);
        }
        
        jpeg_finish_decompress(&cinfo);
        jpeg_destroy_decompress(&cinfo);
        fclose(f);
    }
    return 0;
}
EOF

afl-clang-fast harness.c -o harness -I. build-afl/libjpeg.a

# 4. Collect seed corpus
mkdir seeds
# Find valid JPEG files
find /usr/share -name "*.jpg" -size -100k -exec cp {} seeds/ \; 2>/dev/null
# Minimize corpus
afl-cmin -i seeds/ -o seeds_min/ -- ./harness @@

# 5. Fuzz
afl-fuzz -M master -i seeds_min/ -o out/ \
  -x dictionaries/jpeg.dict \
  -p explore \
  -- ./harness @@

# Parallel secondaries (one per remaining core)
for i in $(seq 1 7); do
    afl-fuzz -S slave$i -i seeds_min/ -o out/ -- ./harness @@ &
done

# 6. Monitor
watch -n 5 "afl-whatsup out/"

# 7. Triage crashes
for crash in out/master/crashes/id*; do
    echo "=== $crash ==="
    timeout 5 ./harness_asan "$crash" 2>&1 | head -20
    echo ""
done
```
