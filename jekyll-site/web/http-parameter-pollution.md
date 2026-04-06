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

## Resources

- How to Detect HTTP Parameter Pollution Attacks — Acunetix — `acunetix.com/blog/whitepaper-http-parameter-pollution/`
- HTTP Parameter Pollution — Itamar Verta, Imperva — `imperva.com/learn/application-security/http-parameter-pollution/`
- HTTP Parameter Pollution in 11 minutes — PwnFunction — `youtube.com/watch?v=QVZBl8yxVX0`
