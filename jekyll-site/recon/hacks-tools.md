---
layout: training-page
title: "tomnomnom Hacks — Recon Tool Suite — Red Team Academy"
module: "Reconnaissance"
tags:
  - recon
  - bug-bounty
  - waybackurls
  - unfurl
  - qsreplace
  - kxss
  - assetfinder
  - go-tools
page_key: "recon-hacks-tools"
render_with_liquid: false
---

# tomnomnom Hacks — Recon Tool Suite

A collection of focused Go tools by tomnomnom, widely used in bug bounty recon pipelines. Each tool does one thing well and reads from stdin / writes to stdout, making them ideal for Unix pipelines. Install any tool with `go install github.com/tomnomnom/hacks/TOOL@latest` or build from the repo.

## Installation

```
# Install all core tools at once:
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/assetfinder@latest

# Tools from the hacks monorepo (build manually):
git clone https://github.com/tomnomnom/hacks
cd hacks
go build ./kxss/ && mv kxss ~/go/bin/
go build ./inscope/ && mv inscope ~/go/bin/
go build ./fff/ && mv fff ~/go/bin/
go build ./cors-blimey/ && mv cors-blimey ~/go/bin/
go build ./unfurl/ && mv unfurl ~/go/bin/
go build ./qsreplace/ && mv qsreplace ~/go/bin/
```

## waybackurls — Fetch Historical URLs

Pulls all URLs archived for a domain from the Wayback Machine CDX API. Invaluable for finding forgotten endpoints, old parameter names, and dead admin paths.

```
# Single domain:
waybackurls example.com

# Multiple domains from a file:
cat domains.txt | waybackurls

# Filter to only URLs with query parameters:
waybackurls example.com | grep '?'

# Find old API endpoints:
waybackurls example.com | grep -E '/api/|/v[0-9]/'

# Save to file for later processing:
waybackurls example.com | tee wayback-urls.txt
```

## unfurl — Parse and Extract URL Components

Parses URLs on stdin and extracts specific parts. Modes: `keys`, `values`, `domains`, `paths`, `format`.

```
# Extract all unique parameter keys from a URL list:
cat wayback-urls.txt | unfurl keys | sort -u

# Extract all unique parameter values:
cat wayback-urls.txt | unfurl values | sort -u

# Extract unique domains/subdomains:
cat wayback-urls.txt | unfurl domains | sort -u

# Extract paths only:
cat wayback-urls.txt | unfurl paths | sort -u

# Custom format (use %s for scheme, %d for domain, %p for path, %q for query):
cat wayback-urls.txt | unfurl format '%d%p'

# Find parameters that might accept URLs (for SSRF/open redirect testing):
cat wayback-urls.txt | unfurl keys | grep -Ei 'url|link|src|dest|redirect|path|uri'
```

## qsreplace — Replace Query String Values

Reads URLs from stdin and replaces all query string values with a specified string. De-duplicates by unique host+path+param-name combination so you test each parameter once.

```
# Replace all query values with XSS probe:
cat wayback-urls.txt | qsreplace '<script>alert(1)</script>'

# Replace with SSRF probe:
cat wayback-urls.txt | qsreplace 'http://BURP_COLLAB.burpcollaborator.net/'

# Append instead of replace (for blind injection):
cat wayback-urls.txt | qsreplace -a "'--"

# Full recon → fuzz pipeline:
waybackurls example.com \
  | grep '=' \
  | qsreplace 'FUZZ' \
  | ffuf -u FUZZ -w - -mc 200,301,302,403 -o results.json
```

## kxss — Find Reflected XSS Parameters

Tests URLs for reflected parameters — sends requests and checks if the value appears in the response, indicating potential XSS. Filters parameters that reflect XSS-relevant characters (`< > " ' ;`).

```
# Basic usage — pipe URLs with parameters:
cat wayback-urls.txt | kxss

# Full pipeline — find reflected params in live pages:
waybackurls example.com \
  | grep '=' \
  | kxss

# Output shows parameter name and which special chars are reflected:
# https://example.com/search?q=test [< > " ' &]

# Feed reflected params to a more powerful XSS scanner:
cat wayback-urls.txt | kxss | grep -oP 'https?://[^ ]+' | dalfox pipe
```

## assetfinder — Subdomain Discovery

Finds subdomains via passive sources: crt.sh, HackerTarget, ThreatCrowd, CertSpotter, Facebook CT, VirusTotal, and more. No bruteforcing — fast and low-noise.

```
# Find all subdomains:
assetfinder example.com

# Only return subdomains (not root domain):
assetfinder --subs-only example.com

# Save and probe for live hosts:
assetfinder --subs-only example.com | httprobe | tee live-hosts.txt

# Combine with other tools:
assetfinder --subs-only example.com \
  | sort -u \
  | tee subdomains.txt \
  | httprobe -c 50 \
  | tee live.txt
```

## inscope — Filter by Scope

Filters URLs and domains to only include those matching regexes in a `.scope` file. Prevents accidentally testing out-of-scope assets.

```
# Create scope file (.scope in current directory):
cat > .scope <<'EOF'
.*\.example\.com$
^example\.com$
EOF

# Filter stdin to scope:
cat all-urls.txt | inscope

# Filter subdomains:
assetfinder example.com | inscope

# Use in recon pipeline — feed FUZZ-marked URLs straight into ffuf:
waybackurls example.com | inscope | qsreplace 'FUZZ' | \
  ffuf -w /opt/wordlists/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt \
       -u FUZZ -mc 200 -fs 0 -t 50 -o ffuf-results.json
```

## fff — Fetch URLs Fast

"Fairly frickin' fast" HTTP requester. Reads URLs from stdin, makes requests, and saves responses or reports status codes. Good for bulk probing.

```
# Basic — just show status codes:
cat urls.txt | fff

# Save all responses to a directory:
cat urls.txt | fff -o responses/

# Save only 200 responses:
cat urls.txt | fff -s 200 -o responses/

# Add custom header:
cat urls.txt | fff -H 'Authorization: Bearer TOKEN'

# POST requests:
cat urls.txt | fff -m POST -b 'data=test'

# With delay (rate limit):
cat urls.txt | fff -d 100  # 100ms between requests
```

## cors-blimey — CORS Misconfiguration Testing

Tests URLs for CORS misconfiguration by sending requests with various Origin headers and checking if they are reflected in Access-Control-Allow-Origin.

```
# Test a single URL:
echo "https://example.com/api/user" | cors-blimey

# Test many URLs:
cat live-apis.txt | cors-blimey

# What it tests:
# - Origin: https://evil.com → checks for wildcard or reflection
# - Origin: null → checks for null origin acceptance
# - Origin: https://example.com.evil.com → suffix match check
```

## Complete Bug Bounty Recon Pipeline

```
#!/bin/bash
# Full recon pipeline for a single target domain

TARGET=$1
echo "[*] Target: $TARGET"

# Step 1: Subdomain enumeration
echo "[*] Finding subdomains..."
assetfinder --subs-only $TARGET | tee subdomains.txt
subfinder -d $TARGET | tee -a subdomains.txt
sort -u subdomains.txt -o subdomains.txt

# Step 2: Probe for live hosts
echo "[*] Probing for live hosts..."
cat subdomains.txt | httprobe | tee live.txt

# Step 3: Pull historical URLs from all live hosts
echo "[*] Fetching Wayback URLs..."
cat live.txt \
  | sed 's|https\?://||' \
  | sort -u \
  | waybackurls \
  | tee wayback.txt

# Step 4: Filter and deduplicate parameterized URLs
echo "[*] Extracting parameter URLs..."
cat wayback.txt \
  | inscope \
  | grep '=' \
  | qsreplace 'FUZZ' \
  | sort -u \
  | tee fuzz-targets.txt

# Step 5: Check for reflected parameters (potential XSS)
echo "[*] Checking for reflected params..."
cat fuzz-targets.txt | qsreplace 'xsstest123' | kxss | tee xss-candidates.txt

# Step 6: Check CORS on API endpoints
echo "[*] Testing CORS..."
cat live.txt | grep -E '/api/|/v[0-9]/' | cors-blimey | tee cors-results.txt

echo "[*] Done. Results in wayback.txt, fuzz-targets.txt, xss-candidates.txt, cors-results.txt"
```

## URL Pattern Mining

```
# Find interesting URL patterns in Wayback data:

# Old admin panels:
cat wayback.txt | grep -iE '/admin|/manager|/console|/dashboard|/panel'

# Config/debug endpoints:
cat wayback.txt | grep -iE '/config|/debug|/test|/dev|/backup|/\.git'

# File extensions of interest:
cat wayback.txt | grep -E '\.(php|asp|aspx|jsp|json|xml|yaml|yml|env|bak|sql|log)'

# Extract unique parameter names across all URLs:
cat wayback.txt | unfurl keys | sort | uniq -c | sort -rn | head -50

# Find URLs with multiple parameters (more attack surface):
cat wayback.txt | grep -E '(&[^=]+=|=[^&]+){3,}'

# Find API versioning:
cat wayback.txt | grep -oP '/v[0-9]+/' | sort -u
```

## Resources

- tomnomnom hacks monorepo — `github.com/tomnomnom/hacks`
- waybackurls — `github.com/tomnomnom/waybackurls`
- assetfinder — `github.com/tomnomnom/assetfinder`
- unfurl — `github.com/tomnomnom/unfurl`
- httprobe — `github.com/tomnomnom/httprobe`
- anew (append new lines only) — `github.com/tomnomnom/anew`
- Wayback CDX API docs — `github.com/internetarchive/wayback/tree/master/wayback-cdx-server`
