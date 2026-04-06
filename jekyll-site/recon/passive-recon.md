---
layout: training-page
title: "Passive Recon (OSINT) — Red Team Academy"
module: "Reconnaissance"
tags:
  - osint
  - passive
  - google-dorks
  - shodan
page_key: "recon-passive"
render_with_liquid: false
---

# Passive Recon (OSINT)

## The Passive Recon Mindset

Passive reconnaissance gathers intelligence about a target without sending a single packet to their systems. You're reading what's already publicly visible — search engine indexes, DNS records, certificate logs, archived pages, and data aggregators. Done correctly, a target's SOC has no idea you exist while you build a complete picture of their infrastructure, employees, and technology stack.

Passive recon precedes all active activity. Information gathered here shapes every subsequent decision: which IPs to scan, which employees to phish, which services to probe. Time invested here saves wasted effort later.

![Passive recon intelligence sources: search engines (Google dorks), WHOIS/DNS, certificate transparency logs, Shodan/Censys, LinkedIn/OSINT, and Wayback/GitHub — all feeding into target intelligence with zero packets sent](/images/recon/passive-recon-sources.svg)  
*// passive recon sources — intelligence gathering with zero target contact*

## Google Dorking

Google indexes far more than websites. Exposed files, login portals, configuration dumps, and internal documents are all discoverable via search operators.

### Essential Google Operators

```
# site: — restrict to specific domain
site:targetcompany.com

# filetype: — find exposed documents
site:targetcompany.com filetype:pdf
site:targetcompany.com filetype:xlsx
site:targetcompany.com filetype:docx

# intitle: — page title contains string
intitle:"index of" site:targetcompany.com
intitle:"login" site:targetcompany.com

# inurl: — URL contains string
inurl:admin site:targetcompany.com
inurl:login site:targetcompany.com
inurl:portal site:targetcompany.com

# intext: — page body contains string
intext:"confidential" site:targetcompany.com

# Combine operators for precision:
site:targetcompany.com filetype:pdf intext:"internal use only"
site:targetcompany.com inurl:wp-admin     # WordPress admin pages
site:targetcompany.com inurl:.git         # Exposed Git repos
```

### High-Value Dork Patterns

```
# Exposed configuration files:
site:targetcompany.com ext:env OR ext:cfg OR ext:conf OR ext:ini
site:targetcompany.com filetype:xml intext:"password"

# Login portals:
site:targetcompany.com intext:"Username" intext:"Password" intitle:"Login"
site:targetcompany.com inurl:"/vpn/index.html"

# Error pages revealing technology:
site:targetcompany.com "powered by" OR "running" intext:"PHP" OR "Apache"

# Cached credentials:
site:targetcompany.com filetype:log intext:"password" OR intext:"passwd"

# Juicy endpoints:
inurl:/api/v1/ site:targetcompany.com
inurl:swagger site:targetcompany.com   # API documentation exposed
inurl:jira site:targetcompany.com      # Jira instance

# Google Hacking Database — 10,000+ tested dork patterns:
# https://www.exploit-db.com/google-hacking-database
```

## Shodan

Shodan continuously scans the entire internet and indexes everything it finds. It knows about open ports, running services, TLS certificates, banners, and misconfigurations — without you ever touching the target.

### Shodan Search Operators

```
# Basic search — finds all devices for a company:
org:"Target Company Inc"
org:"Target Company" country:"US"

# hostname/domain — find subdomains indexed by Shodan:
hostname:targetcompany.com
hostname:.targetcompany.com           # All subdomains

# Search for specific ports/services:
hostname:targetcompany.com port:22    # SSH exposed
hostname:targetcompany.com port:3389  # RDP exposed
hostname:targetcompany.com port:8080  # Alt HTTP

# Find specific technologies:
org:"Target Company" http.title:"Dashboard"
org:"Target Company" http.component:"WordPress"
org:"Target Company" product:"Apache httpd"

# Find default credentials / exposed panels:
org:"Target Company" http.title:"Router Login"
org:"Target Company" http.title:"Webcam"
org:"Target Company" http.title:"phpMyAdmin"

# SSL certificate search — pivot from cert to all their IPs:
ssl.cert.subject.cn:targetcompany.com
ssl:"Target Company"                 # Cert issued to company name

# Network range search:
net:203.0.113.0/24                   # All indexed IPs in range
net:203.0.113.0/24 port:22

# Vuln filter (Shodan paid tier):
org:"Target Company" vuln:CVE-2021-44228  # Log4Shell exposure

# Shodan CLI:
sudo apt install python3-shodan
shodan init YOUR_API_KEY
shodan search 'org:"Target Company"' --fields ip_str,port,hostnames
shodan host 203.0.113.1              # Full report on a single IP
```

### Censys — Complementary to Shodan

```
# Censys focuses on certificates and full IP space
# https://search.censys.io

# Search by company (Censys web UI):
# Hosts → "autonomous_system.name: Target Company"
# Certificates → "parsed.subject.organization: Target Company"

# Censys CLI:
pip3 install censys
censys config  # Enter API credentials

# Search certificates for company domain:
censys certificates --query "parsed.subject.cn: targetcompany.com" \
  --fields "parsed.subject.cn,parsed.names,ip"

# Search hosts:
censys ipv4 --query "autonomous_system.name: \"Target Company\"" \
  --fields "ip,protocols,metadata.os"
```

## WHOIS & DNS History

```
# WHOIS — registrar, registration dates, registrant info:
whois targetcompany.com | grep -i "registrar\|creation\|updated\|expiry\|name server\|admin\|tech"

# Useful fields to extract:
# - Registrar: Namecheap? GoDaddy? Cloudflare Registrar?
# - Name Servers: authoritative DNS (tells you if Cloudflare is in use)
# - Admin email: personal email? → OSINT pivot
# - Creation date: domain age (legitimacy signal)

# Historical DNS records — find old IPs before CDN:
# https://viewdns.info/iphistory/?domain=targetcompany.com
# https://securitytrails.com/domain/targetcompany.com/history/a
# Old IPs often bypass Cloudflare/CDN and expose origin server directly

# Current DNS records:
dig targetcompany.com ANY            # All record types
dig +short A targetcompany.com       # IPv4 addresses
dig +short AAAA targetcompany.com    # IPv6 addresses
dig +short MX targetcompany.com      # Mail servers
dig +short NS targetcompany.com      # Nameservers
dig +short TXT targetcompany.com     # SPF, DMARC, verification tokens

# Reverse DNS:
dig -x 203.0.113.1 +short            # PTR record for IP

# DMARC policy:
dig +short TXT _dmarc.targetcompany.com
```

## Certificate Transparency

Every TLS certificate must be logged to a public Certificate Transparency log. This reveals every subdomain that ever got a certificate — including development environments, internal systems, and forgotten assets.

```
# crt.sh — web interface:
# https://crt.sh/?q=%.targetcompany.com

# crt.sh — command line (returns all certificates):
curl -s "https://crt.sh/?q=%.targetcompany.com&output=json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for entry in data:
    for name in entry['name_value'].split('\n'):
        names.add(name.strip())
for n in sorted(names):
    print(n)
" | grep -v '*' | sort -u

# What to hunt for in results:
# dev.targetcompany.com     → development environment (often fewer controls)
# staging.targetcompany.com → staging server (same code, less hardened)
# vpn.targetcompany.com     → VPN portal (credential attack target)
# owa.targetcompany.com     → Outlook Web Access (password spray target)
# jira.targetcompany.com    → project tracking (data exfiltration potential)
# gitlab.targetcompany.com  → source code (credentials in code)
# api.targetcompany.com     → API endpoint
# cdn.targetcompany.com     → CDN (may reveal cloud provider)

# Certificate Transparency live logs:
# https://transparencyreport.google.com/https/certificates
# https://censys.io/certificates
```

## theHarvester

theHarvester aggregates OSINT from multiple public sources — search engines, DNS datasets, LinkedIn, and more. It's the standard first-pass email and subdomain collector.

```
# Install (included in Kali by default):
sudo apt install theharvester

# Basic scan — all sources:
theHarvester -d targetcompany.com -b all -f output.html

# Targeted source scans:
theHarvester -d targetcompany.com -b google       # Google search results
theHarvester -d targetcompany.com -b bing         # Bing results
theHarvester -d targetcompany.com -b linkedin     # LinkedIn (limited)
theHarvester -d targetcompany.com -b anubis       # Subdomain database
theHarvester -d targetcompany.com -b crtsh        # Certificate transparency
theHarvester -d targetcompany.com -b rapiddns     # RapidDNS database

# With DNS resolution and virtual host check:
theHarvester -d targetcompany.com -b google,bing,anubis -n

# Shodan integration (requires API key):
theHarvester -d targetcompany.com -b shodan -s SHODAN_API_KEY

# Output formats:
# -f output   → saves output.html and output.xml
# Default stdout shows: emails, hosts, IPs, virtual hosts
```

## Recon-ng Framework

Recon-ng is a full-featured OSINT framework modeled after Metasploit. Modules chain together — a domain becomes subdomains, which become IPs, which become hosts, which become credentials from breach data.

```
# Install and launch:
sudo apt install recon-ng
recon-ng

# Inside recon-ng console:
[recon-ng] > marketplace search domain      # Find domain-related modules
[recon-ng] > marketplace install recon/domains-hosts/hackertarget
[recon-ng] > modules load recon/domains-hosts/hackertarget
[recon-ng] > options set SOURCE targetcompany.com
[recon-ng] > run

# Key module categories:
# recon/domains-hosts/*      → domains to hostnames/subdomains
# recon/hosts-hosts/*        → host to IP resolution
# recon/domains-contacts/*   → domains to email contacts
# recon/contacts-credentials/*  → contacts to breach credentials

# Build a workspace for organized collection:
[recon-ng] > workspaces create targetcompany
[recon-ng] > db insert domains
# Enter domain: targetcompany.com

# Reporting:
[recon-ng] > marketplace install reporting/html
[recon-ng] > modules load reporting/html
[recon-ng] > run    # Generates full HTML report
```

## Social Media & Personnel Recon

```
# LinkedIn — manual recon targets:
# 1. Navigate to company LinkedIn page
# 2. Filter employees by department: IT, Finance, HR, Executive
# 3. Record names, titles, tenure (new hires = low security awareness)
# 4. Note job postings → reveals technology stack
#    "Experience with CrowdStrike Falcon" = they run CrowdStrike
#    "Manage Azure AD" = Azure-based identity infrastructure
#    "Palo Alto PCNSA" = Palo Alto firewalls in use

# LinkedIn advanced search (Google dork approach):
site:linkedin.com/in "Target Company" "IT Manager"
site:linkedin.com/in "Target Company" "Security Engineer"
site:linkedin.com/in "Target Company" "Active Directory"

# Twitter/X — find employee accounts:
site:twitter.com "targetcompany.com"

# GitHub — developer emails and source code:
# https://github.com/search?q=%40targetcompany.com&type=code
# git log --pretty=format:"%ae %an" | grep targetcompany.com
```

## Maltego (Passive Mode)

Maltego visualizes OSINT relationships as a graph. Starting from a domain, transforms pivot to IPs, ASNs, emails, social accounts, and physical locations — all through public data.

- Download: `https://www.maltego.com` — Community Edition is free
- Create a Domain entity → right-click → Run All Transforms → watch the graph build
- Key passive transforms: **DNS to IP**, **Domain to Email**, **Domain to Subdomains**, **IP to ASN**
- Import theHarvester results (XML output) directly into Maltego for visualization
- CE limitation: 12 results per transform — sufficient for targeted pivot, use theHarvester for bulk

## Wayback Machine & Web Archives

```
# Wayback Machine — find old versions of pages and hidden paths:
# https://web.archive.org/web/*/targetcompany.com/*

# waybackurls — extract all URLs ever crawled for a domain:
go install github.com/tomnomnom/waybackurls@latest
waybackurls targetcompany.com | sort -u > wayback_urls.txt

# What to look for in archived URLs:
# /admin/ paths that no longer exist but once did
# Old API endpoints: /api/v1/, /api/v2/
# Exposed parameters: ?user=, ?id=, ?debug=true
# Config file paths that were once accessible
# Historical login portals (may still exist, just de-linked)

# gau (GetAllURLs) — combines Wayback + Common Crawl + URLScan:
go install github.com/lc/gau/v2/cmd/gau@latest
gau targetcompany.com | sort -u > all_urls.txt
```

## Passive Recon OPSEC

- Use a VPN for all web searches and Shodan queries — your IP is logged
- Use a separate browser profile with no personal account logins
- Do NOT visit target's website during passive recon — server logs capture your IP and User-Agent
- theHarvester and Recon-ng still make DNS queries to external resolvers — use a VPN
- Shodan/Censys queries may alert advanced teams watching for their own company name in query logs

## Key Resources

- `https://www.exploit-db.com/google-hacking-database` — Google Hacking Database (GHDB)
- `https://shodan.io` — Internet-wide device scanner
- `https://search.censys.io` — Certificate and host intelligence
- `https://crt.sh` — Certificate transparency search
- `https://web.archive.org` — Wayback Machine
- `https://github.com/laramies/theHarvester` — theHarvester OSINT tool
- `https://github.com/lanmaster53/recon-ng` — Recon-ng framework
- `https://osintframework.com` — OSINT tool index by category
