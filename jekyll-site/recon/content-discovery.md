---
layout: training-page
title: "Content Discovery — Red Team Academy"
module: "Reconnaissance"
tags:
  - content-discovery
  - fuzzing
  - gobuster
  - feroxbuster
  - nuclei
  - gowitness
page_key: "recon-content-discovery"
render_with_liquid: false
---

# Content Discovery

## The Problem with Black-Box Recon

Passive recon tells you what's exposed. Content discovery tells you what's *hidden* — unlisted endpoints, forgotten admin panels, backup files, API routes, and misconfigured directories that never made it into the sitemap. The application's visible surface is rarely its most interesting.

Content discovery is methodical enumeration: directories, files, virtual hosts, API endpoints, parameters. The goal is coverage — you want to know about every accessible path before you decide which ones to attack.

## Gobuster — Targeted Directory and DNS Brute Force

Gobuster is fast, single-threaded-per-goroutine Go tooling optimized for directional brute force. It excels at directory/file enumeration and DNS subdomain brute force where you want predictable, controllable throughput.

### Installation

```bash
go install github.com/OJ/gobuster/v3@latest
# or
apt install gobuster
```

### Directory Enumeration

```bash
# Basic directory brute force
gobuster dir -u https://target.com -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Add extensions — critical for finding backup/config files
gobuster dir \
  -u https://target.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt \
  -x php,txt,bak,conf,config,yaml,yml,json,xml,asp,aspx \
  -t 50 \
  -o gobuster-dir.txt

# Follow redirects, show status codes
gobuster dir \
  -u https://target.com \
  -w /opt/SecLists/Discovery/Web-Content/common.txt \
  -r \
  --status-codes-blacklist 404,403 \
  -v
```

### DNS Subdomain Brute Force

```bash
# Subdomain enumeration
gobuster dns \
  -d target.com \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50

# Show IP addresses in results
gobuster dns -d target.com -w wordlist.txt --show-ips
```

### Virtual Host Enumeration

```bash
# Find virtual hosts (apps behind the same IP)
gobuster vhost \
  -u https://target.com \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
  --append-domain \
  -t 50
```

### S3 Bucket Enumeration

```bash
gobuster s3 -w bucket-names.txt
```

## Feroxbuster — Recursive Content Discovery

Feroxbuster is a Rust-based recursive directory brute forcer. The key differentiator: it automatically recurses into discovered directories, finding `admin/users/`, `admin/config/`, etc. without manual chaining.

### Installation

```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s $HOME/.local/bin

# or cargo
cargo install feroxbuster
```

### Basic Recursive Scan

```bash
# Recursive with common extensions
feroxbuster \
  -u https://target.com \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt \
  -x php,html,txt,bak,conf \
  --depth 3 \
  -t 50 \
  -o ferox-output.txt

# Scan with custom headers (auth tokens, session cookies)
feroxbuster \
  -u https://target.com \
  -w wordlist.txt \
  -H "Authorization: Bearer eyJ..." \
  -H "Cookie: session=abc123" \
  --depth 4

# Filter out noise by response size
feroxbuster \
  -u https://target.com \
  -w wordlist.txt \
  --filter-size 1234 \
  --filter-similar-to https://target.com/404page
```

### API Endpoint Discovery

```bash
# API-specific wordlists
feroxbuster \
  -u https://api.target.com \
  -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -x json \
  --depth 3 \
  -H "Content-Type: application/json"

# Scan multiple targets
feroxbuster \
  --stdin \
  -w wordlist.txt \
  --depth 2 << EOF
https://target1.com
https://target2.com
https://api.target.com
EOF
```

### Resume and Configuration

```bash
# Save state and resume interrupted scans
feroxbuster -u https://target.com -w wordlist.txt --scan-limit 5

# Use config file for complex setups
cat > ferox.toml << EOF
wordlist = "/opt/SecLists/Discovery/Web-Content/raft-large-words.txt"
threads = 50
depth = 3
extensions = ["php", "txt", "bak", "conf"]
filter_status = [404, 403]
output = "ferox-results.txt"
EOF

feroxbuster -u https://target.com --config ferox.toml
```

## Nuclei — Template-Based Vulnerability Scanning

Nuclei is a fast, template-driven scanner built for red teams. Over 9,000 community templates cover CVEs, misconfigurations, exposed panels, and default credentials. The value isn't just finding known vulns — it's running structured checks at scale across many targets.

### Installation

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates
```

### Targeted Scanning

```bash
# Run all templates against a target
nuclei -u https://target.com

# Specific template categories
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/
nuclei -u https://target.com -t cves/

# Severity filtering
nuclei -u https://target.com -severity critical,high

# Technology-specific templates
nuclei -u https://target.com -tags apache,nginx,wordpress,drupal
```

### Bulk Scanning from Recon Output

```bash
# Pipe subfinder output directly to nuclei
subfinder -d target.com -silent | httpx -silent | nuclei -t exposures/ -silent

# Scan list of URLs
nuclei -l urls.txt -t cves/ -severity critical,high -o nuclei-findings.txt

# Scan with rate limiting (stealth)
nuclei -l urls.txt -t exposures/ -rate-limit 10 -bulk-size 5
```

### Custom Templates

```bash
# Write a custom template for target-specific checks
cat > custom-admin-panel.yaml << 'EOF'
id: custom-admin-panel
info:
  name: Hidden Admin Panel Discovery
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/wp-admin"
      - "{{BaseURL}}/phpmyadmin"
      - "{{BaseURL}}/_cpanel"
    matchers:
      - type: status
        status:
          - 200
          - 302
EOF

nuclei -u https://target.com -t custom-admin-panel.yaml
```

### Finding Exposed Configuration

```bash
# Look for secrets and configs
nuclei -u https://target.com -t exposures/configs/
nuclei -u https://target.com -t exposures/tokens/
nuclei -u https://target.com -t exposures/files/

# Default credentials
nuclei -u https://target.com -t default-logins/
```

## Gowitness — Visual Enumeration and Screenshot Capture

Gowitness screenshots web services at scale. When you have a list of 500 discovered hosts or subdomains, manually visiting each one is impractical. Gowitness generates visual thumbnails and an HTML report, letting you identify interesting targets (login pages, admin panels, app servers) by sight in minutes.

### Installation

```bash
go install github.com/sensepost/gowitness@latest
```

### Screenshot from URL List

```bash
# Screenshot a list of URLs
gowitness file -f urls.txt

# Screenshot with custom resolution
gowitness file -f urls.txt --resolution 1920x1080

# Disable TLS verification (for internal hosts)
gowitness file -f urls.txt --disable-db --no-tls-check

# Concurrent screenshots
gowitness file -f urls.txt --threads 20
```

### Screenshot from CIDR / Port Scan

```bash
# Screenshot from nmap output
gowitness nmap --nmap-file nmap-output.xml

# Screenshot a full subnet
gowitness scan --cidr 10.10.10.0/24 --open-timeout 5
```

### Generate Report

```bash
# Generate HTML report (default location: gowitness.db)
gowitness report generate

# Start interactive web server for browsing results
gowitness report serve --host 127.0.0.1 --port 7171
# Open http://127.0.0.1:7171 in browser
```

### Combine with Subdomain Recon

```bash
# Full pipeline: enumerate subdomains → probe HTTP → screenshot
subfinder -d target.com -silent | \
  httpx -silent -ports 80,443,8080,8443 | \
  gowitness file -f - --threads 10

# Review report to prioritize manual review
gowitness report serve
```

## Recommended Wordlists

All tools above depend on quality wordlists. The [SecLists](https://github.com/danielmiessler/SecLists) repo is the standard:

```bash
git clone https://github.com/danielmiessler/SecLists /opt/SecLists
```

Key wordlists by use case:

| Use Case | Wordlist |
|---|---|
| General directories | `Discovery/Web-Content/raft-large-words.txt` |
| Common files | `Discovery/Web-Content/common.txt` |
| API endpoints | `Discovery/Web-Content/api/api-endpoints.txt` |
| Backup/config files | `Discovery/Web-Content/quickhits.txt` |
| DNS subdomains | `Discovery/DNS/subdomains-top1million-5000.txt` |
| Parameters | `Discovery/Web-Content/burp-parameter-names.txt` |

## Workflow Integration

```
subfinder / amass       →  subdomain list
    ↓
httpx                   →  filter live HTTP services
    ↓
gowitness               →  visual triage (find interesting targets)
    ↓
feroxbuster / gobuster  →  deep content discovery on prioritized hosts
    ↓
nuclei                  →  automated vuln/misconfig checks
    ↓
manual review           →  investigate interesting findings
```

## Detection Signals

Content discovery generates significant log noise:

- Rapid sequential 404s in web server logs — classic brute force signature
- High request rate from single IP
- User-Agent strings: `gobuster/3.x`, `feroxbuster`, `nuclei/x.x.x`
- Probing for non-existent files with specific extensions (`.bak`, `.conf`, `.env`)

**OPSEC mitigations:**

```bash
# Randomize user agent
feroxbuster -u https://target.com -w wordlist.txt -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Rate limit to blend with legitimate traffic
gobuster dir -u https://target.com -w wordlist.txt -t 5 --delay 500ms

# Proxy through Burp for logging and replay
feroxbuster -u https://target.com -w wordlist.txt --proxy http://127.0.0.1:8080

# Nuclei rate limiting
nuclei -u https://target.com -rate-limit 5
```
