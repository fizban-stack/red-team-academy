---
layout: training-page
title: "Brute Force & Rate Limit Bypass — Red Team Academy"
module: "Web Hacking"
tags:
  - brute-force
  - rate-limit-bypass
  - ffuf
  - burp-suite
  - ip-rotation
  - ja3-fingerprint
page_key: "web-brute-force"
render_with_liquid: false
---

# Brute Force & Rate Limit Bypass

Brute forcing in web contexts means systematically attempting combinations of credentials, tokens, or parameter values against login forms, APIs, or other input endpoints. Rate limiting, account lockout, CAPTCHA, and TLS fingerprinting are common defenses — each of which has bypass techniques.

## Tools

- **ffuf** — Fast web fuzzer written in Go — `github.com/ffuf/ffuf`
- **Burp Suite Intruder** — Multi-mode attack tool for web parameter fuzzing — `portswigger.net/burp`
- **OmniProx** — IP rotation from GCP, Azure, Alibaba, and Cloudflare — `github.com/ZephrFish/OmniProx`
- **curl-impersonate** — curl build that impersonates Chrome and Firefox TLS fingerprints — `github.com/lwthiker/curl-impersonate`
- **gpb** — Bruteforce Google user phone numbers with IPv6 rotation — `github.com/ddd/gpb`

## Burp Suite Intruder Attack Modes

Burp Suite Intruder provides four distinct attack modes for different brute force scenarios:

### Sniper

Targets a single position with one payload set. All other parameters remain static. Best for single-field fuzzing:

```
Username: password
Username1:Password1
Username1:Password2
Username1:Password3
```

### Battering Ram

Sends the same payload to all marked positions simultaneously. Useful when the same value must appear in multiple fields:

```
Username1:Username1
Username2:Username2
Username3:Username3
```

### Pitchfork

Uses different payload lists in parallel — combines the Nth entry from each list into one request. Ideal for credential stuffing with known username:password pairs:

```
Username1:Password1
Username2:Password2
Username3:Password3
```

### Cluster Bomb

Iterates through all combinations of multiple payload sets. Most thorough but generates the most requests — use for full credential brute force when account lockout is not a concern:

```
Username1:Password1
Username1:Password2
Username1:Password3
Username2:Password1
Username2:Password2
Username2:Password3
```

## FFUF Credential Brute Force

Combining username and password wordlists with IP rotation headers in a single ffuf command:

```
ffuf -w usernames.txt:USER -w passwords.txt:PASS \
     -u https://target.tld/login \
     -X POST -d "username=USER&password=PASS" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "X-Forwarded-For: FUZZ" -w ipv4-list.txt:FUZZ \
     -mc all
```

## Rate Limit Bypass Techniques

### HTTP Pipelining

HTTP/1.1 pipelining lets a client send multiple requests on a single persistent TCP connection without waiting for each response. This can saturate rate-limit counters that track per-connection request counts rather than per-IP counts, and is useful for race condition attacks against login endpoints.

### TLS Fingerprint Bypass (JA3)

JA3 fingerprints TLS clients by hashing fields from the TLS Client Hello — SSL version, cipher suites, extensions, elliptic curves, and elliptic curve formats. Web application firewalls and bot-detection systems use JA3 to identify automated tools even when HTTP headers are spoofed.

Known fingerprints to avoid:

- Burp Suite JA3: `53d67b2a806147a7d1d5df74b54dd049`, `62f6a6727fda5a1104d5b147cd82e520`
- Tor Client JA3: `e7d705a3286e19ea42f587b344ee6865`

Bypass methods:

- Use browser-driven automation (Puppeteer / Playwright) — inherits the browser's real TLS stack
- Spoof TLS handshakes with `curl-impersonate` to match Chrome or Firefox fingerprints
- Use JA3 randomization plugins for scripting libraries

```
# curl-impersonate — make requests that look like Chrome 120
curl_chrome120 https://target.com/login -d "username=admin&password=test"
```

### IPv4 Proxy Rotation

Rotate through multiple proxy servers so each request appears to originate from a different IP address, bypassing per-IP rate limits:

```
proxychains ffuf -w wordlist.txt -u https://target.tld/FUZZ
```

proxychains configuration for rotation:

```
# /etc/proxychains.conf
random_chain
chain_len = 1

[ProxyList]
socks5  127.0.0.1 1080
socks5  192.168.1.50 1080
http    proxy1.example.com 8080
http    proxy2.example.com 8080
```

### IPv6 Address Rotation

Cloud providers such as Vultr offer /64 IPv6 ranges — 18,446,744,073,709,551,616 addresses per allocation. Each request can originate from a unique IPv6 address, making per-IP rate limiting ineffective. Tools like `gpb` leverage this for large-scale attacks while remaining within a single cloud account.

## Resources

- ffuf — `github.com/ffuf/ffuf`
- OmniProx — Multi-Cloud IP Rotation — `github.com/ZephrFish/OmniProx`
- curl-impersonate — `github.com/lwthiker/curl-impersonate`
- Burp Intruder attack types — PortSwigger documentation
- Bruteforcing the phone number of any Google user — brutecat.com
