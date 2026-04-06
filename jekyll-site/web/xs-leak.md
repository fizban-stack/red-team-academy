---
layout: training-page
title: "XS-Leak (Cross-Site Leaks) — Red Team Academy"
module: "Web Hacking"
tags:
  - xs-leak
  - side-channel
  - timing-attack
  - frame-counting
  - cache-probing
page_key: "web-xs-leak"
render_with_liquid: false
---

# XS-Leak (Cross-Site Leaks)

Cross-Site Leaks (XS-Leaks) are side-channel vulnerabilities that allow an attacker to infer
  sensitive information about a victim's state on another origin — without reading the actual
  response body. Unlike CORS or XSS, XS-Leaks exploit observable browser behaviors: timing
  differences, iframe counts, error events, cache hits, and navigation side effects.

The attacker's page can observe indirect signals from requests to the target origin to answer
  boolean questions: "Is the user logged in?", "Does the user have admin privileges?",
  "Does a search for 'password' return results?" — and iteratively leak sensitive data.

## Tools

- xsinator.com — XS-Leak browser test suite — `github.com/RUB-NDS/xsinator.com`
- AutoLeak — find XS-Leaks by diffing DOM graphs in two states — `github.com/RUB-NDS/AutoLeak`

## Attack Primitives

Each primitive leaks a different type of information:

```
Timing      → Resource size or processing complexity
Frame count → Whether content loaded (different pages have different iframes)
Errors      → Access control decisions (403 vs 200 differences)
Cache       → Whether the user previously visited a page
Navigation  → Authentication state (redirect destination differs per auth state)
Rendering   → Text length or content differences
```

## XS-Search

XS-Search abuses query-based search systems. By making a search request and observing a side
  effect (timing, frame count, error), the attacker learns whether the query returned results.
  This boolean oracle is then used to brute-force sensitive data character by character.

Example pipeline: attacker opens 50 tabs, measures the timing of an iframe CSP violation
  triggered only when search results exist, and uses timing differences to determine each
  character of a flag or sensitive string.

## Timing Attacks

Measure how long a cross-origin request takes to complete. A query that returns many results
  takes longer than one returning none. An authenticated endpoint takes a different time than a
  rejected one.

```
// Measure response time for a cross-origin resource
const start = performance.now();
fetch('https://target.com/api/search?q=admin', { mode: 'no-cors' })
  .then(() => {
    const elapsed = performance.now() - start;
    console.log('Response time:', elapsed, 'ms');
    // Compare against baseline to infer search hit/miss
  });
```

## Frame Counting

If a page renders a different number of iframes based on the user's state (e.g., search results
  page shows one iframe per result), an attacker can count them to infer data.

```
// Open the target page and count its iframes
var win = window.open('https://target.com/search?q=secret');

setTimeout(function() {
  // win.length returns the number of frames in the window
  console.log(win.length + " iframes detected");
  // 0 frames = no results; N frames = N results found
}, 2000);
```

## Cache Probing

Determine whether the victim has previously visited a specific page by checking if its resources
  are cached. A cached resource loads faster than an uncached one. If the resource only gets cached
  when a user is authenticated, its presence in cache reveals authentication state.

```
// Probe cache by measuring load time of a resource
function probeCacheForResource(url) {
  const img = new Image();
  const start = performance.now();
  img.onload = img.onerror = function() {
    const time = performance.now() - start;
    if (time < 5) {
      console.log(url + " — likely CACHED (user visited this page)");
    } else {
      console.log(url + " — likely NOT CACHED");
    }
  };
  img.src = url + '?cachebuster=' + Math.random();
}
```

## Known Oracle Techniques

### Error-Based Oracles

- **Event Handler Leak (Script)** — detect errors with onload/onerror on <script> tag; 200 vs 403 behavior differs
- **Event Handler Leak (Stylesheet)** — same with stylesheet; cross-origin load success/failure reveals access control
- **MediaError Leak** — detect HTTP status codes via MediaError.message on audio/video elements
- **SRI Error Leak** — leak content length via Subresource Integrity mismatch error

### Header Detection Oracles

- **COOP Leak** — detect Cross-Origin-Opener-Policy header presence using popup behavior
- **CORP Leak** — detect Cross-Origin-Resource-Policy header via fetch behavior
- **CORB Leak** — detect X-Content-Type-Options in combination with specific content types
- **CSP Directive Leak** — detect CSP directives using iframe CSP attribute
- **CSP Violation Leak** — leak cross-origin redirect target via CSP violation event
- **ContentDocument X-Frame Leak** — detect X-Frame-Options via ContentDocument

### Redirect Detection Oracles

- **Fetch Redirect Leak** — detect HTTP redirects using the Fetch API opaque redirect response
- **Duration Redirect Leak** — detect cross-origin redirects by checking response duration
- **CSP Redirect Detection** — detect cross-origin redirects via CSP violation events
- **Max Redirect Leak** — detect server redirects by hitting the browser's max redirect limit
- **Redirect Start Leak** — detect HTTP redirects via redirectStart time in Performance API

### Performance API Oracles

- **Performance API Error Leak** — detect request errors via performance timeline entries
- **Performance API Empty Page Leak** — detect empty (204) responses
- **Performance API Download Detection** — detect Content-Disposition responses
- **Performance API CORP Leak** — detect Cross-Origin-Resource-Policy header

### Media Oracles

- **Media Dimensions Leak** — leak image or video dimensions cross-origin
- **Media Duration Leak** — leak audio or video duration cross-origin

### Miscellaneous Oracles

- **History Length Leak** — detect JavaScript redirects via window.history.length
- **Id Attribute Leak** — leak id attribute of focusable HTML elements via onblur event
- **Download Detection** — detect Content-Disposition: attachment responses
- **ETag Header Length Leak** — detect response body size via ETag header string length (newer technique)
- **URL Max Length Leak** — detect server redirects by sending URLs near the max length limit
- **WebSocket Leak (Chrome/Firefox)** — detect active WebSockets by exhausting socket limits
- **CSS Property Leak** — leak CSS rules via getComputedStyle cross-origin

## Practical XS-Search Example

```
// Boolean oracle: does /inbox?search=X return results?
// Uses frame count as signal
function searchOracle(query, callback) {
  var win = window.open('https://target.com/inbox?search=' + encodeURIComponent(query));
  setTimeout(function() {
    var frames = win.length;
    win.close();
    // 1+ frames means results found; 0 frames means no results
    callback(frames > 0);
  }, 1500);
}

// Brute-force a secret string character by character
var charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
var known = 'flag{';

function bruteNextChar(idx) {
  if (idx >= charset.length) return;
  var candidate = known + charset[idx];
  searchOracle(candidate, function(hit) {
    if (hit) {
      known = candidate;
      console.log('Found so far:', known);
      bruteNextChar(0); // restart from first char for next position
    } else {
      bruteNextChar(idx + 1);
    }
  });
}
bruteNextChar(0);
```

## Resources

- PayloadsAllTheThings XS-Leak — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XS-Leak`
- xsleaks.dev — comprehensive XS-Leaks wiki — `xsleaks.dev`
- xsinator.com test suite — `xsinator.com`
- Root Me XS Leaks challenge — `root-me.org/en/Challenges/Web-Client/XS-Leaks`
- XS-Leak: Leaking IDs using focus — Gareth Heyes — portswigger.net/research
- Cross-Site ETag Length Leak — Takeshi Kaneko, December 2025
