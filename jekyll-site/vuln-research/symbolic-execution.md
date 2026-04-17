---
layout: training-page
title: "Symbolic Execution with angr & KLEE — Red Team Academy"
module: "Vulnerability Research"
tags:
  - symbolic-execution
  - angr
  - klee
  - constraint-solving
  - binary-analysis
  - driller
  - s2e
page_key: "vuln-research-symbolic-execution"
render_with_liquid: false
---

# Symbolic Execution with angr & KLEE

Symbolic execution treats program inputs as symbolic variables — mathematical unknowns — rather than concrete values, then propagates those symbols through computations to determine what input values are required to reach any given program state. This enables automated theorem-proving for security properties: "what input causes this vulnerable function to be called?" or "what bytes satisfy all the checks on the way to this crash site?" This page covers practical symbolic execution with angr and KLEE, and their application in vulnerability research.

---

## Symbolic Execution Primer

### Concrete vs Symbolic Execution

In concrete execution, every variable has a definite value at every point in time:
```
x = read()  → x = 42  (whatever the user typed)
if (x > 10):  → True  (because 42 > 10)
    vulnerable_func()  → called
```

In symbolic execution, inputs become symbols that carry constraints:
```
x = read()  → x = α  (symbolic — any value)
if (x > 10):  → path split:
    True path:  constraint: α > 10  → can reach vulnerable_func if solver satisfies α > 10
    False path: constraint: α ≤ 10  → alternative execution path
```

The constraint solver (Z3 SAT/SMT solver) determines whether a path is reachable and, if so, what concrete input values make it so.

### Path Explosion

The fundamental limitation of symbolic execution: the number of paths grows exponentially with the number of branches. A program with 100 `if` statements has up to 2^100 distinct paths. In practice, symbolic executors use:

- **Heuristics**: prioritize paths near the target (e.g., near a suspected vulnerability)
- **Pruning**: detect infeasible paths early via constraint checking
- **Execution merging**: merge similar paths (phi nodes)
- **Loop limiting**: bound loop iterations at a fixed depth
- **Concrete/symbolic hybrid**: run concretely when symbolic becomes too expensive (concolic execution)

---

## angr: Binary Symbolic Execution

angr is a Python framework for binary analysis combining static analysis, symbolic execution, and constraint solving. It operates on compiled binaries without source code.

### Installation

```bash
pip install angr
# Or in a virtualenv (recommended — angr has many dependencies)
python3 -m venv angr-env
source angr-env/bin/activate
pip install angr
```

### Core Concepts

```python
import angr

# Load a binary
proj = angr.Project("./target_binary", auto_load_libs=False)
# auto_load_libs=False: don't symbolically execute system libraries (too slow)

# Entry state — execution starts at program entry point
state = proj.factory.entry_state()

# Full init state — with simulated argc/argv
state = proj.factory.full_init_state(args=["./target", "INPUT"])

# Blank state at specific address — useful for function-level analysis
state = proj.factory.blank_state(addr=0x401234)

# SimulationManager — manages execution states (paths)
simgr = proj.factory.simulation_manager(state)
```

### Explorer: Find/Avoid Pattern

The most common angr usage: find what input reaches a target address while avoiding others.

```python
import angr
import claripy  # angr's constraint solver interface

proj = angr.Project("./crackme", auto_load_libs=False)

# Create symbolic stdin input (16 bytes)
flag = claripy.BVS("flag", 8 * 16)  # BVS = BitVector Symbolic

# Start state with symbolic input on stdin
state = proj.factory.full_init_state(
    args=["./crackme"],
    stdin=angr.SimFileStream(name="stdin", content=flag, has_end=False)
)

simgr = proj.factory.simulation_manager(state)

# Explore: find the "success" address, avoid the "failure" address
# Find these addresses with Ghidra/objdump first
SUCCESS_ADDR = 0x401337  # Address of "Correct!" print
FAILURE_ADDR = 0x401200  # Address of "Wrong!" print

simgr.explore(find=SUCCESS_ADDR, avoid=FAILURE_ADDR)

if simgr.found:
    solution_state = simgr.found[0]
    # Extract the concrete value that satisfies all constraints
    print(solution_state.solver.eval(flag, cast_to=bytes))
else:
    print("No solution found")
```

### angr for CTF: Solving Crackme Binaries

```python
import angr, claripy, sys

def solve_crackme(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # Symbolic argv[1] — 20 chars
    password = claripy.BVS("password", 8 * 20)
    
    # Constrain to printable ASCII
    state = proj.factory.entry_state(args=[binary_path, password])
    for byte in password.chop(8):
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)
    
    simgr = proj.factory.simulation_manager(state)
    
    # Explore — find any path that doesn't exit with code 1
    simgr.run(until=lambda sm: len(sm.deadended) > 0 or len(sm.found) > 0)
    
    # Check deadended states for successful exit
    for state in simgr.deadended:
        if state.history.bbl_addrs.count() > 100:  # Took enough steps
            try:
                result = state.solver.eval(password, cast_to=bytes)
                print(f"Password: {result}")
                return result
            except Exception:
                continue

solve_crackme(sys.argv[1])
```

### angr for Vulnerability Research

Detect buffer overflows symbolically — find inputs that cause out-of-bounds writes:

```python
import angr, claripy

proj = angr.Project("./parser_binary", auto_load_libs=False)

# Large symbolic input
user_input = claripy.BVS("input", 8 * 512)
state = proj.factory.full_init_state(
    stdin=angr.SimFileStream(name="stdin", content=user_input)
)

simgr = proj.factory.simulation_manager(state)

# Run until error or exit
simgr.run()

# Check for segfaults (unconstrained PC = RIP/EIP control!)
if simgr.unconstrained:
    print(f"[!] Found {len(simgr.unconstrained)} unconstrained states — possible RIP control")
    for state in simgr.unconstrained:
        if state.solver.symbolic(state.regs.rip):
            print("[!] RIP is symbolic — arbitrary code execution possible")
            # Get concrete input that reaches this state
            concrete_input = state.solver.eval(user_input, cast_to=bytes)
            print(f"Triggering input: {concrete_input.hex()}")
```

### angr Address Space & Memory

```python
# Reading/writing memory in a state
state.memory.store(0x601000, claripy.BVV(0xdeadbeef, 32))
value = state.memory.load(0x601000, 4)  # Load 4 bytes

# Register access
state.regs.rip  # Instruction pointer
state.regs.rsp  # Stack pointer
state.regs.rax  # Return value

# Hooking functions (replace with stub for speed)
@proj.hook(0x401234, length=5)  # Hook at address, skip 5 bytes
def my_hook(state):
    state.regs.rax = 0  # Make function return 0
```

---

## KLEE: Source-Level Symbolic Execution

KLEE operates on LLVM bitcode — it requires source code but provides more precise analysis than binary-level tools.

### Installation

```bash
# Docker (easiest)
docker pull klee/klee:latest
docker run --rm -ti --ulimit='stack=-1:-1' klee/klee bash

# From source (complex — many dependencies)
# See klee.github.io/getting-started
```

### Writing KLEE Programs

```c
// klee_example.c
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_parse(char *input, size_t len) {
    char buf[64];
    if (len > 10) {
        memcpy(buf, input, len);  // Overflow if len > 64
    }
}

int main() {
    char input[128];
    size_t len;
    
    // Make input and length symbolic
    klee_make_symbolic(input, sizeof(input), "input");
    klee_make_symbolic(&len, sizeof(len), "len");
    
    // Add reasonable constraints
    klee_assume(len <= sizeof(input));
    klee_assume(len > 0);
    
    // Run the vulnerable function
    vulnerable_parse(input, len);
    
    return 0;
}
```

### Running KLEE

```bash
# Compile to LLVM bitcode
clang -I/path/to/klee/include \
  -emit-llvm -c -g \
  -O0 \    # No optimization (preserves program structure)
  klee_example.c \
  -o klee_example.bc

# Run KLEE
klee --libc=uclibc \
     --posix-runtime \
     --output-dir=klee-out \
     klee_example.bc

# Results in klee-out/:
# test*.ktest: test case files
# test*.err: error-triggering test cases
ls klee-out/*.err   # Any .err files = bugs found!

# Replay a test case
klee-replay ./klee_example klee-out/test000001.ktest
```

### Analyzing KLEE Output

```bash
# Print statistics
klee-stats klee-out/

# Examine a specific test case
ktest-tool klee-out/test000001.ktest
# Shows: symbolic name, size, concrete value that triggers the path

# Count paths explored
ls klee-out/test*.ktest | wc -l
```

---

## Driller: AFL++ + angr Hybrid

Driller combines AFL++'s mutation-based fuzzing with angr's symbolic execution to solve "hard" branches that block fuzzer progress.

### How Driller Works

```
AFL++ fuzzes normally → coverage plateau detected → 
Driller's symbolic tracer picks AFL++ corpus entries → 
angr symbolically executes from interesting branch points → 
Finds concrete inputs that satisfy comparison magic bytes → 
Returns new corpus entries to AFL++ → AFL++ resumes fuzzing
```

### Driller Setup

```bash
# Driller requires angr and AFL++ with specific configuration
pip install driller

# AFL++ must be configured to call driller for new seeds
# Typically via AFL++ custom mutator or drilled.py wrapper
python -m driller.driller_main \
  -b ./target_binary \
  -s seeds/ \
  -i input_to_drill \
  -o drilled_output/
```

### When to Use Driller

Driller excels when:
- The target checks a complex constant (CRC32, MD5 prefix, magic bytes deep in format)
- AFL++ coverage has plateaued after 24+ hours
- The target accepts a complex binary format with strict validation

---

## Limitations of Symbolic Execution

Understanding limitations prevents wasting time on unsuitable targets:

| Limitation | Cause | Mitigation |
|-----------|-------|----------|
| Path explosion | Exponential branch growth | Heuristics, time limits, coverage-guided merging |
| Environment modeling | System calls, external I/O | Intercept and stub (angr.SimOS) |
| Floating point | FP ≠ integer arithmetic in SMT solvers | Approximate, avoid FP-heavy targets |
| Loops | Unbound loops = infinite paths | Loop bounds (k-induction) |
| Crypto functions | Hash functions are hard for SMT | Concrete hooks |
| Self-modifying code | Breaks static analysis | Concolic execution only |

---

## Practical Use Cases

### Finding Magic Bytes for Corpus Generation

Symbolic execution can solve format checks that AFL++ struggles with:

```python
# Find all valid "magic byte" combinations for a file format header
import angr, claripy

proj = angr.Project("./image_parser")
header = claripy.BVS("header", 8 * 16)
state = proj.factory.entry_state(
    stdin=angr.SimFileStream(content=header)
)

# Find paths that pass header validation
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x40156a)  # Address after header_validate() returns true

if simgr.found:
    valid_header = simgr.found[0].solver.eval(header, cast_to=bytes)
    print(f"Valid header bytes: {valid_header.hex()}")
    # Use as AFL++ seed
    open("seeds/valid_header.bin", "wb").write(valid_header)
```

### Bypassing License Checks

```python
# Crackme: binary checks a license key against a stored hash
proj = angr.Project("./licensed_app")

# Symbolic license key (32 chars)
license_key = claripy.BVS("key", 8 * 32)

state = proj.factory.full_init_state(args=["./licensed_app"])

# Set argv[1] to symbolic
state.memory.store(
    state.regs.rsp + 0x10,
    license_key
)

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=0x401500,   # "License valid!" message
    avoid=0x401400   # "Invalid license!" message
)

if simgr.found:
    key = simgr.found[0].solver.eval(license_key, cast_to=bytes)
    print(f"License key: {key.decode('utf-8', errors='replace')}")
```

### S2E: System-Level Symbolic Execution

S2E (Selective Symbolic Execution) extends KLEE to full operating system analysis:

```
S2E = KLEE + QEMU + custom hypervisor
```

Use cases:
- Driver vulnerability research (whole-system symbolic execution)
- Finding privilege escalation paths in kernel code
- Analyzing firmware (run firmware image in QEMU + S2E)

```bash
# S2E setup (complex — uses custom QEMU)
git clone https://github.com/S2E/s2e
cd s2e
./scripts/s2e_env create myenv
./s2e_env build

# Create analysis image
./s2e_env image_build ubuntu-22.04-x86_64
```

S2E is research-grade infrastructure — appropriate for dedicated vulnerability research environments rather than casual use.
