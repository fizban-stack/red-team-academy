---
layout: training-page
title: "CSP Reconnaissance — Red Team Academy"
module: "Reconnaissance"
tags:
  - csp
  - recon
  - subdomain
  - content-security-policy
  - domain-discovery
page_key: "recon-csp-recon"
render_with_liquid: false
---

# CSP Reconnaissance

Content Security Policy headers are a goldmine for attackers. The `Content-Security-Policy` header lists every domain a site trusts — CDNs, analytics, ad networks, third-party APIs, internal services, and sister domains. By reading CSP headers, you can discover the full scope of an organization's infrastructure without ever brute-forcing a subdomain.

## Why CSP Reveals Infrastructure

Developers configure CSP to whitelist domains their app loads resources from. This list often includes:

- Internal subdomains (e.g., `api.internal.company.com`, `cdn-staging.company.com`)
- Third-party services that reveal technology stack (analytics, payment processors, monitoring)
- Development/staging domains not listed in DNS certificate transparency logs
- Acquired company domains (indicating M&A activity and legacy infrastructure)
- Hardcoded S3 buckets, CloudFront distributions, and CDN origins

```
# Example CSP header that reveals infrastructure:
# content-security-policy: default-src 'self';
#   script-src 'self' cdn.company.com staging-api.company.com
#              analytics.internal.company.com https://cdnjs.cloudflare.com;
#   connect-src 'self' api.company.com ws://realtime.company.com;
#   img-src 'self' s3-us-east-1.amazonaws.com/company-uploads
#            media.company.com;
#
# Discovered: cdn.company.com, staging-api.company.com,
#             analytics.internal.company.com, api.company.com,
#             realtime.company.com, media.company.com,
#             S3 bucket name
```

## csprecon

csprecon is a Go-based tool that fetches CSP headers and extracts all domains referenced within them. It supports single targets, lists, and CIDR ranges, and can filter results to specific parent domains.

### Install

```
# Go install (recommended):
go install github.com/edoardottt/csprecon/cmd/csprecon@latest

# Homebrew (macOS):
brew install csprecon

# Snap (Linux):
sudo snap install csprecon
```

### Basic Usage

```
# Single target — discover all domains in CSP:
csprecon -u https://www.github.com

# Pipe from echo:
echo https://www.github.com | csprecon

# Read from a targets file (full URLs with protocol required):
csprecon -l targets.txt

# Pipe from a list:
cat targets.txt | csprecon
```

### Flags Reference

```
INPUT:
  -u, -url string    Single input domain
  -l, -list string   File containing input domains (one per line)
  -cidr              Treat input as CIDR range

CONFIGURATIONS:
  -d, -domain string[]   Filter results to these parent domains (comma-separated)
  -c, -concurrency int   Concurrent requests (default: 50)
  -t, -timeout int       Connection timeout in seconds (default: 10)
  -rl, -rate-limit int   Rate limit (requests per second)
  -px, -proxy string     Proxy server URL (e.g. http://127.0.0.1:8080)

OUTPUT:
  -o, -output string   Write results to file
  -v, -verbose         Verbose output (show errors, debug)
  -s, -silent          Silent mode — only print results
  -j, -json            JSON output format
```

### Focused Recon Workflows

```
# Filter results to target organization only:
cat targets.txt | csprecon -d company.com

# Multiple parent domain filters:
cat targets.txt | csprecon -d company.com,companycdn.net,company.io

# Scan a CIDR range for CSP headers:
csprecon -u 192.168.1.0/24 -cidr

# Rate-limited scan (avoid detection):
cat targets.txt | csprecon -rl 10

# Through Burp proxy for manual review:
cat targets.txt | csprecon -px http://127.0.0.1:8080

# JSON output for downstream processing:
cat targets.txt | csprecon -j | jq '.domains[]'

# Silent mode — pipe directly to other tools:
echo https://target.com | csprecon -s | sort -u > csp_domains.txt
```

### Pipeline: CSP to Subdomain Validation

```
# Step 1: Discover domains from CSP
cat urls.txt | csprecon -s -d target.com | sort -u > csp_domains.txt

# Step 2: Resolve discovered domains (find live ones)
cat csp_domains.txt | httpx -silent -status-code -title | tee live_csp_targets.txt

# Step 3: Port scan live targets
cat csp_domains.txt | dnsx -silent | awk '{print $1}' | naabu -silent

# Step 4: Feed to nuclei for vulnerability scanning
cat csp_domains.txt | httpx -silent | nuclei -silent -t ~/nuclei-templates/

# Step 5: Check for subdomain takeover potential
cat csp_domains.txt | subzy run --targets /dev/stdin
```

### Combining with Other Recon Tools

```
# Combine CSP recon with subdomain enumeration:

# 1. Run subfinder for DNS-based subdomains
subfinder -d target.com -silent | sort -u > dns_subs.txt

# 2. Run csprecon against discovered subdomains
cat dns_subs.txt | sed 's/^/https:\/\//' | csprecon -s -d target.com | sort -u > csp_subs.txt

# 3. Merge and deduplicate all discovered domains
cat dns_subs.txt csp_subs.txt | sort -u > all_subs.txt

echo "[CSP-unique domains not found by subfinder]:"
comm -13 <(sort dns_subs.txt) <(sort csp_subs.txt)
```

## Manual CSP Analysis

```
# Manually fetch and parse CSP header:
curl -s -I https://target.com | grep -i "content-security-policy"

# Extract all unique domains from CSP manually:
curl -s -I https://target.com \
  | grep -i "content-security-policy" \
  | grep -oE "[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}" \
  | sort -u

# Check CSP from page response body (not just headers):
curl -s https://target.com \
  | grep -oE 'content-security-policy[^"]*' \
  | head -5

# Fetch CSP for a list of pages (different sections may differ):
for url in https://target.com https://target.com/login https://target.com/admin; do
  echo "=== $url ==="
  curl -sI "$url" | grep -i csp
done
```

## What to Do with Discovered Domains

Each domain extracted from a CSP header represents a trust relationship. From an attacker's perspective:

- **Staging/dev domains** — often have weaker security controls, may expose debug endpoints
- **S3 buckets / cloud storage** — check for public read/write access, bucket takeover
- **Third-party scripts** — XSS via compromised CDN or supply chain attack vector
- **Internal domains** — potential for SSRF exploitation by targeting these trusted hosts
- **Subdomain takeover** — CSP domains pointing to dangling DNS records
- **Affiliate/acquired domains** — separate attack surface with potentially weaker security posture

```
# Check for subdomain takeover on CSP-discovered domains:
# (domains pointing to unclaimed cloud services)
cat csp_domains.txt | subzy run --targets /dev/stdin --concurrency 50

# Check for open S3 buckets:
cat csp_domains.txt | grep -i "s3\|amazonaws\|cloudfront" | while read bucket; do
  aws s3 ls s3://$(echo $bucket | grep -oE "[a-z0-9-]+-[a-z0-9-]+" | head -1) 2>/dev/null \
    && echo "PUBLIC: $bucket"
done

# Check if staging/dev domains are reachable:
cat csp_domains.txt | grep -iE "staging|dev|test|uat|qa" | httpx -silent -status-code
```

## Resources

- csprecon — `github.com/edoardottt/csprecon`
- CSP specification — `developer.mozilla.org/en-US/docs/Web/HTTP/CSP`
- httpx (HTTP probing) — `github.com/projectdiscovery/httpx`
- subfinder (DNS subdomain enum) — `github.com/projectdiscovery/subfinder`
- subzy (subdomain takeover) — `github.com/LukaSikic/subzy`
- nuclei (vulnerability scanning) — `github.com/projectdiscovery/nuclei`
