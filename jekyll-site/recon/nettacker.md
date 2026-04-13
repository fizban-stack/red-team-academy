---
layout: training-page
title: "OWASP Nettacker — Automated Pentesting Framework — Red Team Academy"
module: "Reconnaissance"
tags:
  - nettacker
  - owasp
  - port-scanning
  - subdomain-enumeration
  - vulnerability-scanning
  - brute-force
  - recon
  - automated
page_key: "recon-nettacker"
render_with_liquid: false
---

# OWASP Nettacker — Automated Pentesting Framework

OWASP Nettacker is a modular, Python-based automated penetration testing and information-gathering framework. It combines port scanning, service detection, subdomain enumeration, directory discovery, vulnerability scanning, and credential brute-forcing into a single tool. Modules run in parallel across single IPs, CIDR ranges, and domain lists. Results are stored in SQLite and exportable as HTML, JSON, CSV, or plain text. It also exposes a REST API and web UI for managing scan campaigns.

## Install

```
# Docker (quickest — no Python dependency management):
docker pull owasp/nettacker

# Docker run wrapper (creates alias for convenience):
alias nettacker="docker run --rm owasp/nettacker"
nettacker --help

# Python (pip):
pip3 install nettacker

# From source:
git clone https://github.com/OWASP/Nettacker
cd Nettacker
pip3 install -r requirements.txt
python3 nettacker.py --help
```

## Core Concepts

```
# Target formats:
# -i 192.168.1.1           single IP
# -i 192.168.1.0/24        CIDR block
# -i corp.com              domain (with -d also scans subdomains)
# -i 192.168.1.1,corp.com  comma-separated mixed targets
# -l targets.txt           file with one target per line

# Module syntax:
# -m port_scan             single module
# -m port_scan,http_status_scan,subdomain_scan   comma-separated modules
# -m all                   run ALL modules (slow — use with -x to exclude)
# -x port_scan             exclude a module from -m all

# Threading:
# -t 10                    10 parallel threads (default: 100 — lower for stealth)
# -g 80,443,8080           scan only specific ports (port_scan module)

# Output:
# -o /tmp/scan.html        export to HTML report
# -o /tmp/scan.json        export to JSON
# Default: results stored in ~/.nettacker/data/nettacker.db (SQLite)
```

## Port Scanning

```
# Scan a single host for all common ports:
nettacker -i 192.168.1.1 -m port_scan

# Scan a subnet for hosts with port 22 open:
nettacker -i 192.168.1.0/24 -m port_scan -g 22

# Scan for web services (80, 443, 8080, 8443):
nettacker -i 10.10.0.0/24 -m port_scan -g 80,443,8080,8443

# Docker equivalent:
docker run owasp/nettacker -i 192.168.0.0/24 -m port_scan -g 22

# Port scan + HTTP status check in one pass:
nettacker -i 10.10.0.0/24 -m port_scan,http_status_scan -g 80,443,8080
```

## Subdomain Enumeration

```
# Discover subdomains of a domain:
nettacker -i corp.com -m subdomain_scan

# Scan all discovered subdomains too (-d flag):
nettacker -i corp.com -d -m subdomain_scan,http_status_scan

# -d (--subdomains) tells Nettacker to expand discovered subdomains into the
# target list and run all selected modules against them

# Combined: subdomain enum + port scan + HTTP status on everything found:
nettacker -i corp.com -d -s -m subdomain_scan,port_scan,http_status_scan

# -s (--scan-subdomains) runs the scan modules on all discovered subdomains
# and returns HTTP status codes — useful for quickly mapping live web surface
```

## Vulnerability Scanning

```
# List all available vulnerability modules:
nettacker --list-modules | grep vuln

# Common vuln modules:
# - dir_scan              directory brute-force (common paths)
# - admin_scan            admin panel discovery
# - http_cors_vuln        misconfigured CORS headers
# - drupal_version_scan   Drupal version fingerprinting
# - wordpress_version_scan  WordPress version + plugin enum
# - joomla_version_scan   Joomla fingerprinting
# - ssl_certificate_scan  TLS cert info (expiry, SANs, CN)
# - ftp_anon_login        anonymous FTP access check
# - smb_vuln_scan         SMB vulnerability detection

# Run a set of web vuln checks against a target:
nettacker -i corp.com -m dir_scan,admin_scan,http_cors_vuln,ssl_certificate_scan

# Check for admin panels across a subnet:
nettacker -i 10.10.0.0/24 -m admin_scan -g 80,443,8080

# Full web recon pipeline:
nettacker -i corp.com -d -s \
  -m subdomain_scan,port_scan,http_status_scan,admin_scan,dir_scan
```

## Credential Brute-Force

```
# List available brute-force modules:
nettacker --list-modules | grep brute

# SSH brute-force against a host:
nettacker -i 192.168.1.10 -m ssh_brute \
  -u admin,root,ubuntu \
  -p password,admin123,root

# FTP brute-force:
nettacker -i 192.168.1.10 -m ftp_brute \
  -u admin,anonymous \
  -p "" ,password,ftp

# HTTP basic auth brute-force:
nettacker -i 192.168.1.10 -m http_brute \
  -u admin,administrator \
  -p password,admin,123456

# Use wordlist files:
nettacker -i 192.168.1.10 -m ssh_brute \
  -u /usr/share/wordlists/usernames.txt \
  -p /usr/share/wordlists/passwords.txt \
  -t 5    # lower threads for brute-force to avoid lockout
```

## Evasion & Stealth Options

```
# Slow down scans to avoid IDS detection:
nettacker -i corp.com -m port_scan --timeout 3 --delay 1 -t 10

# Use a proxy (SOCKS5 or HTTP):
nettacker -i corp.com -m http_status_scan \
  --proxy socks5://127.0.0.1:1080

# Randomize user-agent (built-in for HTTP modules):
# Nettacker rotates user-agents automatically for HTTP-based modules

# Reduce thread count for quieter scans:
nettacker -i 10.10.0.0/24 -m port_scan -t 5

# Timeout per connection (seconds):
nettacker -i 192.168.1.0/24 -m port_scan --timeout 2
```

## Output & Reporting

```
# Save results to HTML report:
nettacker -i corp.com -m port_scan,subdomain_scan -o /tmp/report.html

# JSON output (for piping into other tools):
nettacker -i corp.com -m port_scan -o /tmp/results.json

# CSV output (import into spreadsheets):
nettacker -i corp.com -m port_scan -o /tmp/results.csv

# Results also stored in SQLite DB at:
# ~/.nettacker/data/nettacker.db
# Query with: sqlite3 ~/.nettacker/data/nettacker.db "SELECT * FROM logs;"

# Web UI (docker-compose):
docker-compose up
# → Access https://localhost:5000 with the API key shown in the logs
# → Run scans, browse results, export reports through the UI
```

## REST API

```
# Start the API server:
nettacker --start-api --api-port 5000 --api-host 127.0.0.1

# Authenticate and capture the JWT into a shell variable:
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"nettacker","password":"nettacker"}' | jq -r .token)
echo "$TOKEN"

# Submit a scan via API:
curl -X POST http://127.0.0.1:5000/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": "corp.com",
    "modules": "port_scan,subdomain_scan",
    "threads": 20
  }'

# Check scan status:
curl "http://127.0.0.1:5000/api/v1/logs?token=$TOKEN"

# Useful for integrating Nettacker into CI/CD pipelines or custom scripts
```

## Full Recon Pipeline Example

```
# Comprehensive external recon against a single domain:
# Phase 1: Subdomain enumeration + live host detection
nettacker -i corp.com -d -s \
  -m subdomain_scan,http_status_scan,port_scan \
  -g 80,443,8080,8443,22,21,25,3389 \
  -t 50 \
  -o /tmp/phase1.html

# Phase 2: Run vuln checks against discovered web hosts
# (extract IPs from phase 1 results first)
nettacker -l /tmp/live_hosts.txt \
  -m dir_scan,admin_scan,http_cors_vuln,ssl_certificate_scan \
  -t 20 \
  -o /tmp/phase2.html

# Phase 3: Default credential check on non-web services
nettacker -l /tmp/live_hosts.txt \
  -m ssh_brute,ftp_anon_login \
  -t 5 \
  -o /tmp/phase3.html
```

## Resources

- OWASP Nettacker — `github.com/OWASP/Nettacker`
- Documentation — `nettacker.readthedocs.io`
- Docker Hub — `hub.docker.com/r/owasp/nettacker`
- Related: [Web Reconnaissance](/recon/web-recon/)
- Related: [Password Cracking Guide](/exploitation/password-cracking-guide/)
- Related: [TREVORspray — Password Spraying](/recon/trevorspray/)
