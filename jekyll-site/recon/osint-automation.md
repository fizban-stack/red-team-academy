---
layout: training-page
title: "OSINT Automation — Red Team Academy"
module: "Reconnaissance"
tags:
  - osint
  - automation
  - spiderfoot
  - reconftw
  - metabigor
  - dismap
  - aort
page_key: "recon-osint-automation"
render_with_liquid: false
---

# OSINT Automation

## Beyond Manual OSINT

Manual OSINT — searching LinkedIn, checking Shodan, enumerating subdomains one tool at a time — works for targeted investigation. It doesn't scale when you need comprehensive coverage of a target organization before an engagement starts. OSINT automation frameworks aggregate dozens of sources in parallel, correlate the results, and surface what would take hours to find manually.

These tools are for the **intelligence gathering phase**: building a complete picture of the attack surface before a single packet hits the target.

## SpiderFoot — Comprehensive OSINT Platform

SpiderFoot runs 200+ modules against a target, pulling data from passive DNS, certificate transparency, breach databases, social media, dark web monitors, Shodan, Censys, HaveIBeenPwned, and more. It correlates findings into a relationship graph showing how discovered assets connect.

### Installation

```bash
git clone https://github.com/smicallef/spiderfoot
cd spiderfoot
pip3 install -r requirements.txt
python3 sf.py -l 127.0.0.1:5001
```

### Command-Line Usage

```bash
# Scan a domain — DNS, WHOIS, certificates, subdomains, emails
python3 sfcli.py -s target.com -t INTERNET_NAME -m sfp_dnsresolve,sfp_ssl,sfp_whois

# Full passive scan (all modules, no active probing)
python3 sfcli.py -s target.com -t INTERNET_NAME --modules all-passive

# Scan for emails associated with a company
python3 sfcli.py -s "Target Corp" -t COMPANY_NAME -m sfp_hunter,sfp_emailformat

# Export results to CSV
python3 sfcli.py -s target.com -t INTERNET_NAME -o csv -f results.csv
```

### Web UI Workflows

The web UI at `http://127.0.0.1:5001` provides:

1. **New Scan** → enter target (domain, IP, company name, email)
2. Select scan profile: *All* (comprehensive), *Passive* (no target contact), *Investigate*
3. Configure API keys (Shodan, HaveIBeenPwned, Hunter.io, etc.) under Settings
4. Browse the graph view to see asset relationships

Key scan types:

| Target Type | Use Case |
|---|---|
| `INTERNET_NAME` | Domain — subdomains, DNS, certs |
| `IP_ADDRESS` | IP — ports, ASN, geolocation |
| `EMAILADDR` | Email — breach data, social profiles |
| `COMPANY_NAME` | Org — employees, social, press |
| `PHONE_NUMBER` | Phone — carrier, social accounts |

### API Keys That Matter

SpiderFoot is more powerful with API keys configured:

- **Shodan** — internet-wide port/service scanning
- **HaveIBeenPwned** — credential breach data
- **Hunter.io** — email enumeration
- **Censys** — certificate and host intelligence
- **VirusTotal** — malware/domain reputation
- **SecurityTrails** — DNS history

## reconFTW — Full Recon Pipeline Automation

reconFTW chains 80+ recon tools into a single automated pipeline. You give it a domain; it runs subdomain enumeration, port scanning, content discovery, vulnerability scanning, screenshot capture, and nuclei templates — then consolidates results.

### Installation

```bash
git clone https://github.com/six2dez/reconftw
cd reconftw
./install.sh   # installs all dependencies
```

### Running Scans

```bash
# Full recon (everything)
./reconftw.sh -d target.com -a

# Passive only (no active probing, no port scanning)
./reconftw.sh -d target.com -p

# Subdomain enumeration only
./reconftw.sh -d target.com -s

# Web recon only (assumes subdomains known)
./reconftw.sh -d target.com -w

# Custom output directory
./reconftw.sh -d target.com -a -o /tmp/target-recon/
```

### What reconFTW Does

The full pipeline (-a flag) runs sequentially:

1. **Subdomain discovery**: subfinder, amass, assetfinder, findomain, crt.sh
2. **DNS resolution**: massdns, dnsx
3. **Port scanning**: nmap, masscan, naabu
4. **HTTP probing**: httpx
5. **Screenshot**: gowitness
6. **JS analysis**: LinkFinder, SecretFinder (finds API keys, endpoints in JS)
7. **Content discovery**: ffuf, feroxbuster
8. **Vulnerability scanning**: nuclei, dalfox (XSS), SQLMap
9. **Directory listing checks**
10. **Reporting**: consolidates all results into structured output

### Configuration

```bash
# reconftw.cfg controls which tools run and API keys
cat reconftw.cfg | grep -A2 "SHODAN\|CENSYS\|GITHUB"

# Key settings
DEEP=false              # Full deep scan (slow but thorough)
AXIOM=false             # Distributed scanning via Axiom
NOTIFICATION=false      # Slack/Telegram notifications on completion
```

## Metabigor — Shodan/Fofa Without API Keys

Metabigor queries internet-wide scanning databases (Shodan, FOFA, Censys, Zoomeye) without requiring API keys, using web scraping. Less reliable than direct API access but useful when you don't have Shodan Pro.

### Installation

```bash
go install github.com/j3ssie/metabigor@latest
```

### Usage

```bash
# Find ASN for an organization
echo "target corp" | metabigor net --org -o target-asn.txt

# Find IPs for an ASN
echo "AS12345" | metabigor net --asn -o target-ips.txt

# Shodan search without API key
echo "hostname:target.com" | metabigor shodan --json

# Find related domains/IPs
echo "target.com" | metabigor related

# CIDR to IPs
echo "192.168.1.0/24" | metabigor net --cidr -o ips.txt
```

### Practical ASN Recon

```bash
# Full org recon pipeline
# 1. Find ASN
echo "Target Corporation" | metabigor net --org > asn.txt

# 2. Find all IP ranges for those ASNs
cat asn.txt | metabigor net --asn > ip-ranges.txt

# 3. Active IPs from those ranges (combine with masscan)
masscan -iL ip-ranges.txt -p 80,443,8080,8443 --rate 10000

# 4. Probe for HTTP services
cat ip-ranges.txt | metabigor scan --port 80,443 -o live-hosts.txt
```

## Dismap — Asset Discovery and Fingerprinting

Dismap is an asset discovery and fingerprinting tool focused on identifying technology stacks and services. It's particularly useful for mapping what's running on discovered IPs without deep port scanning.

### Installation

```bash
# Download binary from releases
wget https://github.com/zhzyker/dismap/releases/latest/download/dismap-linux-amd64
chmod +x dismap-linux-amd64
mv dismap-linux-amd64 /usr/local/bin/dismap
```

### Usage

```bash
# Fingerprint a single target
dismap -i https://target.com

# Scan an IP range
dismap -i 192.168.1.0/24

# Scan from file
dismap -f ips.txt -o results.json

# Include port scanning
dismap -i 192.168.1.0/24 --port 80,443,8080,8443,8888,9090

# JSON output for pipeline integration
dismap -f ips.txt -o results.json --json
```

Dismap identifies:

- Web frameworks (Django, Rails, Express, WordPress)
- Application servers (Tomcat, WebLogic, JBoss)
- Network devices (routers, printers, cameras)
- Security products (WAFs, load balancers)
- Development tools (Jupyter, Grafana, Jenkins)

## AORT — All-in-One Recon Tool

AORT (All-in-One Recon Tool) focuses on subdomain enumeration and passive discovery through DNS aggregation, certificate transparency, and threat intelligence feeds.

### Installation

```bash
git clone https://github.com/D3Ext/AORT
cd AORT
pip3 install -r requirements.txt
```

### Usage

```bash
# Full recon for a domain
python3 aort.py -d target.com

# Subdomain enumeration only
python3 aort.py -d target.com --subdomains

# WHOIS + DNS + ASN
python3 aort.py -d target.com --whois --dns --asn

# Email harvesting
python3 aort.py -d target.com --emails

# Output to file
python3 aort.py -d target.com -o aort-results.txt

# Show all records (MX, TXT, NS, A, AAAA)
python3 aort.py -d target.com --dns --all-records
```

## Building a Recon Pipeline

The real power is chaining these tools:

```bash
#!/usr/bin/env bash
TARGET=$1
OUT="/tmp/recon-${TARGET}"
mkdir -p $OUT

echo "[*] Starting OSINT pipeline for $TARGET"

# 1. ASN and IP range discovery
echo "[*] ASN discovery..."
echo "$TARGET" | metabigor net --org > $OUT/asn.txt
cat $OUT/asn.txt | metabigor net --asn > $OUT/ip-ranges.txt

# 2. Subdomain enumeration
echo "[*] Subdomain enumeration..."
subfinder -d $TARGET -silent > $OUT/subdomains-passive.txt
python3 aort.py -d $TARGET --subdomains 2>/dev/null >> $OUT/subdomains-passive.txt
sort -u $OUT/subdomains-passive.txt > $OUT/subdomains.txt

# 3. DNS resolution
echo "[*] Resolving subdomains..."
cat $OUT/subdomains.txt | dnsx -silent > $OUT/resolved.txt

# 4. HTTP probing
echo "[*] Probing HTTP services..."
cat $OUT/resolved.txt | httpx -silent -o $OUT/live-hosts.txt

# 5. SpiderFoot scan (run async)
echo "[*] Starting SpiderFoot scan..."
python3 ~/spiderfoot/sfcli.py -s $TARGET -t INTERNET_NAME -o csv -f $OUT/spiderfoot.csv &

# 6. Screenshot
echo "[*] Screenshotting..."
gowitness file -f $OUT/live-hosts.txt --threads 10 --db $OUT/gowitness.db

echo "[+] Pipeline complete. Results in $OUT/"
```

## Detection and OPSEC

OSINT automation is largely passive — you're querying third-party databases, not the target. The target typically cannot detect:

- crt.sh certificate lookups
- Shodan/Censys queries
- WHOIS lookups
- Social media scraping

What can leave traces:

- DNS queries to the target's nameservers (even "passive" tools sometimes resolve)
- Direct HTTP requests (screenshot tools, httpx probing)
- Nuclei scanning

For truly passive recon, configure tools to use only third-party data sources and avoid any direct contact with target infrastructure until you're ready to go active.
