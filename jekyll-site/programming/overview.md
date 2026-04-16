---
layout: training-page
title: "Offensive Programming — Red Team Academy"
module: "Programming"
tags:
  - programming
  - offensive-programming
  - red-team
  - overview
page_key: "prog-overview"
render_with_liquid: false
---

# Offensive Programming

## Overview

Writing your own tools is a force multiplier for red team operators. Commercial and open-source frameworks are excellent — but custom code bypasses signature-based detection, fits niche engagement requirements, and teaches you how attacks actually work under the hood. This section covers five languages that span the modern red team tooling ecosystem: Python, Go, PowerShell, Rust, and Ruby.

Each language section contains two components:

- **Cheatsheet** — A quick-reference card for red team idioms in that language: socket patterns, crypto, OS interaction, build commands, and one-liners you'll reach for repeatedly.
- **Offensive Tools** — Complete, runnable programs that demonstrate realistic red team use cases. Not snippets — full programs you can study, adapt, and run.

---

## Language Comparison

| Language | Strengths | Primary Use Cases | AV Evasion |
|----------|-----------|-------------------|------------|
| **Python** | Rapid development, massive library ecosystem | Tooling, automation, exploitation scripts, OSINT | Medium — interpreted, common in AV training data |
| **Go** | Static binaries, goroutine concurrency, cross-compile | C2 implants, scanners, network tools | Medium-High — binaries look different from C/C++ |
| **PowerShell** | Native Windows integration, .NET access, LOLBin | Post-exploitation, AD attacks, AMSI bypass | Low — heavily monitored by EDR; use obfuscation |
| **Rust** | Memory safety, tiny footprint, no GC, cross-compile | Implants, shellcode loaders, evasion-focused tools | High — unfamiliar binary patterns, no telltale runtimes |
| **Ruby** | Metasploit integration, expressive syntax | Msf module development, web exploitation, recon | Medium — less common target, Msf integration unique |

---

## Language Selection Guide

```
Need rapid prototype or automation?    → Python
Building a long-running implant?       → Rust or Go
Targeting Windows post-exploitation?   → PowerShell
Writing a Metasploit module?           → Ruby
Need small, static binary?             → Rust (smallest) or Go (easiest)
Need Windows API calls?                → C# > PowerShell > Rust > Go
Need web exploitation helpers?         → Python > Ruby
```

---

## Section Map

| Language | Cheatsheet | Programs |
|----------|------------|---------|
| Python | [Python Cheatsheet](/programming/python-cheatsheet/) | [Python Offensive Tools](/programming/python-offensive-tools/) |
| Go | [Go Cheatsheet](/programming/go-cheatsheet/) | [Go Offensive Tools](/programming/go-offensive-tools/) |
| PowerShell | [PowerShell Cheatsheet](/programming/powershell-cheatsheet/) | [PowerShell Offensive Tools](/programming/powershell-offensive-tools/) |
| Rust | [Rust Cheatsheet](/programming/rust-cheatsheet/) | [Rust Offensive Tools](/programming/rust-offensive-tools/) |
| Ruby | [Ruby Cheatsheet](/programming/ruby-cheatsheet/) | [Ruby Offensive Tools](/programming/ruby-offensive-tools/) |
| Ruby (Metasploit) | — | [Ruby Metasploit Modules](/programming/ruby-metasploit-modules/) |
| Ruby (Network) | — | [Ruby Network Tools](/programming/ruby-network-tools/) |

---

## Learning Path

If you're new to offensive programming, work through the languages in this order:

1. **Python first** — The most forgiving syntax, largest ecosystem for security tooling. Most CTF writeups and public PoCs are Python.
2. **PowerShell** — Essential for Windows engagements. Understanding PowerShell deeply unlocks Active Directory attacks and LOLBin abuse.
3. **Go** — When you need a binary that runs everywhere without dependencies. Go's goroutine model is perfect for concurrent network tools.
4. **Ruby** — Once you want to write Metasploit modules. Ruby's expressive syntax makes Msf's framework approachable once you understand the mixin system.
5. **Rust** — The final form for implant development. Higher learning curve but produces the most evasion-friendly output.

---

## Common Red Team Programming Patterns

These patterns appear across all five languages. Learn them once, apply everywhere.

### The Listener / Implant Split

Every C2 channel has two programs:
- **Implant** (victim-side): connects home, receives commands, returns output
- **Listener** (attacker-side): accepts connections, issues commands, logs results

### Encrypt Everything

Traffic between implant and listener should always be encrypted:
- Use AES-256-GCM (authenticated) or AES-256-CBC (with HMAC) for symmetric encryption
- Derive session keys from a pre-shared key using PBKDF2 or HKDF
- Prepend a random 16-byte IV to every ciphertext

### Jitter Your Beacons

A beacon that calls home every exactly 60 seconds is a detection signature. Add jitter:

```python
import random, time
base_interval = 60
jitter = 0.3  # ±30%
sleep_time = base_interval * (1 + random.uniform(-jitter, jitter))
time.sleep(sleep_time)
```

### Concurrency for Scanning

Network scanning is I/O bound — use concurrency:

```python
# Python: ThreadPoolExecutor
# Go: goroutines + semaphore channel
# Rust: tokio::net with Semaphore
# Ruby: Thread + Queue
```

The pattern is the same: a pool of workers reading from a shared queue, writing results to a synchronized collection.

### Parse Port Ranges

A recurring utility — parsing `"1-1024,3389,8080,8443"` into a list of integers:

```python
def parse_ports(spec: str) -> list[int]:
    ports = set()
    for part in spec.split(','):
        if '-' in part:
            lo, hi = part.split('-', 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)
```

### Error Handling Philosophy

In offensive tools, failed connections are not errors — they're results:
- Log `CLOSED` or `FILTERED`, not exceptions
- Only crash on configuration errors (bad arguments, missing files)
- Network failures should retry with backoff, not terminate

---

## Building for Evasion

### Strip Debug Information

```bash
# Go
go build -ldflags "-s -w" -o tool

# Rust
cargo build --release  # [profile.release] strip = true in Cargo.toml

# Python → PyInstaller
pyinstaller --onefile --strip tool.py
```

### Cross-Compile from Linux

```bash
# Go → Windows
GOOS=windows GOARCH=amd64 go build -o tool.exe

# Rust → Windows (requires mingw-w64)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

### Minimize Imports

Every import is a potential signature. Only import what you use. Prefer stdlib over third-party where the functionality is equivalent.

---

## Resources

- [OffSec PEN-200 Tool Dev Module](https://www.offsec.com/courses/pen-200/) — Course covering custom tool development
- [VX Underground](https://www.vx-underground.org/) — Malware samples and research for educational analysis
- [Awesome Red Team](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming) — Curated list of red team resources
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference for all languages
- [LOLBAS Project](https://lolbas-project.github.io/) — Living-off-the-land binaries (Windows)
- [GTFOBins](https://gtfobins.github.io/) — Linux binary exploitation reference
