---
layout: training-page
title: "Hidden Parameters — Red Team Academy"
module: "Web Hacking"
tags:
  - hidden-parameters
  - parameter-discovery
  - fuzzing
  - recon
page_key: "web-hidden-parameters"
render_with_liquid: false
---

# Hidden Parameters

Web applications often have hidden, undocumented, or legacy parameters not exposed in the user interface. These parameters may have been used during development, debugging, or older versions of the application, and can still be processed by the backend. Discovering these parameters can reveal unauthorized functionality, debug modes, access control bypasses, or additional injection surfaces.

## Tools

- **param-miner** — Burp Suite extension to identify hidden, unlinked parameters — `github.com/PortSwigger/param-miner`
- **Arjun** — HTTP parameter discovery suite — `github.com/s0md3v/Arjun`
- **x8** — Hidden parameters discovery suite — `github.com/Sh1Yo/x8`
- **waybackurls** — Fetch all URLs the Wayback Machine knows about for a domain — `github.com/tomnomnom/waybackurls`
- **ParamSpider** — Mine URLs from web archives for bug hunting and fuzzing — `github.com/devanshbatham/ParamSpider`

## Brute Force Parameter Discovery

Send large wordlists of common parameter names to an endpoint and observe backend behavior changes. Look for differences in response size, status codes, error messages, or content — any unexpected behavior suggests the parameter is being processed.

```
# x8 — GET parameter discovery
x8 -u "https://example.com/" -w /path/to/wordlist.txt

# x8 — POST parameter discovery
x8 -u "https://example.com/" -X POST -w /path/to/wordlist.txt

# Arjun — GET parameter discovery
arjun -u https://example.com/endpoint

# Arjun — POST parameter discovery
arjun -u https://example.com/endpoint -m POST

# ffuf — parameter fuzzing
ffuf -u "https://example.com/?FUZZ=test" -w /path/to/params.txt -mc 200,302,400
```

### Recommended Wordlists

- `github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt`
- `github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt`
- `github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt`
- `github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt`
- `github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt`

## Old / Historical Parameters

Applications evolve and parameters that were used in older versions may still be processed by the backend even if removed from the frontend. Mine archived URLs to find these:

### Wayback Machine

Search for archived versions of the target's pages and extract all parameters:

```
# Fetch all archived URLs for a domain
waybackurls example.com | grep "?" | sort -u

# Extract unique parameter names from archived URLs
waybackurls example.com | grep "?" | sed 's/=.*/=/g' | sort -u

# Pipe directly to ffuf for parameter fuzzing
waybackurls example.com | grep "?" | sort -u | ffuf -w - -u FUZZ -mc 200,301,302
```

### JavaScript File Analysis

JavaScript files often contain API calls, fetch requests, and form submissions with parameters not visible in the HTML. Extract parameters from JS files:

```
# Download all JS files and grep for parameters
cat js_urls.txt | xargs -I{} curl -s {} | grep -oP '(?<=[?&])[a-zA-Z_][a-zA-Z0-9_]*(?==)' | sort -u

# Use ParamSpider to extract from archives
python3 paramspider.py -d example.com --subs
```

## What to Look For

When a parameter is discovered and processed by the server, test it for all relevant vulnerabilities:

- **debug**, **test**, **dev** — may enable debug modes or verbose error output
- **admin**, **role**, **isAdmin** — potential access control bypass
- **callback**, **redirect**, **return_url** — open redirect or SSRF
- **format**, **output**, **type** — content type manipulation
- **id**, **user_id**, **account** — IDOR (Insecure Direct Object Reference)
- **file**, **path**, **filename** — path traversal or LFI
- **q**, **search**, **query** — injection surfaces (SQLi, NoSQLi, XSS)

## Param Miner (Burp) — Configuration Reference

Param Miner is a Burp Suite extension that discovers hidden HTTP parameters by probing the application with a large wordlist and measuring responses for behavioral differences. Right-click any request → Guess params → Guess everything. The following explains the non-obvious configuration options.

```
# Install Param Miner:
# Burp Suite → Extensions → BApp Store → search "Param Miner" → Install

# Basic usage:
# Right-click any request in Proxy / Repeater → Extensions → Param Miner → Guess everything
# Results appear in: Extensions → Param Miner → Output tab

# Key configuration options explained:

# Add 'fcbz' cachebuster
#   Adds fcbz=1 to every request to avoid hitting cached responses.
#   Enable when testing apps with caching (Varnish, Nginx cache, CDN).
#   Required for cache poisoning parameter discovery.

# learn observed words
#   Extracts words from HTTP responses and adds them to the wordlist dynamically.
#   Useful for discovering app-specific parameter names that aren't in standard wordlists.

# use basic wordlist
#   Uses Param Miner's built-in headers and params wordlists (~20k entries).
#   Good starting point for most scans.

# use bonus wordlist
#   Adds functions and words wordlists on top of basic.
#   Also includes headers/params if basic wordlist isn't checked.

# fuzz detect
#   Appends <a`'"${{\` to parameter values.
#   Detects parameters that reflect input differently when it contains special chars.
#   Essential for finding hidden XSS, SSTI, or injection points.

# enable auto-mine
#   Automatically runs Param Miner on every in-scope proxy request.
#   High traffic volume — only use on targeted hosts, not full browsing sessions.

# try -_ bypass
#   For every HTTP header with a dash, also tries the underscore version (X-Custom → X_Custom).
#   Useful because some reverse proxies strip dashes but pass underscores.

# try method flip
#   Tests non-GET requests as GET (moves POST body params to URL query string).
#   Finds params that only work when the method is changed.

# skip boring words
#   Skips known common/safe headers (Content-Type, Accept, etc.).
#   Reduces noise in results.

# max bucketsize
#   Maximum number of params tested per request (default 256 for JSON, less for URL).
#   Increase to speed up scanning; decrease if app rate-limits or breaks.

# max param length
#   Maximum length for params found in responses (longer ones are truncated).
#   Also affects size of dummy parameters in calibration requests.

# scan identified params
#   Runs Burp Scanner on any newly discovered parameters automatically.
#   Useful for automated vuln discovery on found params (requires Burp Pro).

# skip uncacheable
#   Skip cookie/header params when the response contains no-cache.
#   Use when specifically hunting for cache poisoning — avoids uncacheable responses.

# Workflow for cache poisoning parameter discovery:
# 1. Enable: Add 'fcbz' cachebuster + learn observed words + fuzz detect
# 2. Right-click target request → Guess headers
# 3. Look for: headers that change response (X-Forwarded-Host, X-Forwarded-Port, etc.)
# 4. Test discovered headers manually for cache poisoning behavior
```

## Resources

- param-miner — `github.com/PortSwigger/param-miner`
- Arjun — `github.com/s0md3v/Arjun`
- x8 — `github.com/Sh1Yo/x8`
- ParamSpider — `github.com/devanshbatham/ParamSpider`
- Hacker tools: Arjun — The parameter discovery tool — Intigriti Blog
- Parameter Discovery: A quick guide to start — YesWeHack Blog
