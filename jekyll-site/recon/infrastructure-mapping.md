---
layout: training-page
title: "Infrastructure Mapping — Red Team Academy"
module: "Reconnaissance"
tags:
  - asn
  - cloud
  - network-mapping
page_key: "recon-infrastructure-mapping"
render_with_liquid: false
---

# Infrastructure Mapping

## Goal: Build the Attack Surface Map

Before scanning, you need to know *what* to scan. Infrastructure mapping answers: what IP ranges does the target own? What cloud providers do they use? What internet-facing systems exist that are not on a publicly listed domain? A thorough map prevents you from wasting time on third-party infrastructure and ensures you find assets the target's own security team has forgotten about.

![Infrastructure mapping attack surface discovery: ASN lookup, cloud asset enumeration, Shodan org search, reverse DNS on IP ranges, certificate SANs, and GitHub org search — all feeding into target.com attack surface](/images/recon/infrastructure-map.svg)  
*// infrastructure mapping — discovering all assets owned by the target*

## ASN & IP Range Discovery

Autonomous System Numbers (ASNs) group IP ranges under a single organization. Finding a target's ASN reveals every IP block they own globally — far more than just what's behind their main domain.

### Finding the ASN

```
# Method 1 — whois lookup from a known IP
whois 93.184.216.34 | grep -i "asn\|orgname\|netname\|cidr"

# Method 2 — BGP lookup tools (web):
# https://bgp.he.net — search company name → lists ASN + all prefixes
# https://www.ultratools.com/tools/asnInfo
# https://bgpview.io/search#search=Target Company

# Method 3 — ASN lookup via command line
# install: sudo apt install whois
whois -h whois.radb.net -- '-i origin AS15169' | grep route  # Google's routes

# Method 4 — amass (includes ASN enumeration)
amass intel -org "Target Company"              # Find ASN by org name
amass intel -asn 15169 -ip                    # Enumerate IPs from ASN number
```

### Enumerating All IP Ranges from an ASN

```
# Once you have the ASN number (e.g., AS12345):

# BGPView API:
curl -s "https://api.bgpview.io/asn/12345/prefixes" | \
  python3 -m json.tool | grep "prefix"

# RIPE NCC (for European orgs):
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12345" | \
  python3 -c "import sys,json; [print(p['prefix']) for p in json.load(sys.stdin)['data']['prefixes']]"

# Build a target IP list for Nmap:
curl -s "https://api.bgpview.io/asn/12345/prefixes" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(p['prefix']) for p in d['data']['ipv4_prefixes']]" \
  > target_ranges.txt

# Then scan those ranges:
nmap -sn -iL target_ranges.txt -oG alive_hosts.txt  # Host discovery only
masscan -iL target_ranges.txt -p0-65535 --rate=10000 -oL masscan.txt
```

## DNS Reconnaissance

```
# Basic DNS enumeration:
host targetcompany.com                    # A, MX, NS records
dig targetcompany.com ANY                 # All record types
dig +short mx targetcompany.com           # Mail servers → identify email provider
dig +short txt targetcompany.com          # SPF, DMARC, DKIM, verification tokens
dig +short ns targetcompany.com           # Authoritative nameservers

# SPF record analysis — reveals infrastructure:
dig +short txt targetcompany.com | grep spf
# "v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.0/24 ~all"
# → They use G Suite AND SendGrid AND have a direct mail server at 203.0.113.0/24

# MX record → find email provider:
# MX: aspmx.l.google.com     → Google Workspace
# MX: mail.protection.outlook.com → Microsoft 365
# MX: mxX.mailgun.org         → Mailgun
# MX: inbound-smtp.us-east-1.amazonaws.com → AWS SES

# Reverse DNS sweep of IP ranges:
for ip in $(seq 1 254); do
  host 10.0.0.$ip 2>/dev/null | grep "domain name"
done
```

## Cloud Provider Footprinting

Modern organizations split their infrastructure across AWS, Azure, and GCP. Each cloud provider publishes their IP ranges publicly — use this to identify cloud-hosted assets.

### AWS Footprinting

```
# AWS publishes all their IP ranges:
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for p in data['prefixes']:
    if p['region'] == 'us-east-1':
        print(p['ip_prefix'], p['service'])
" | grep -v AMAZON | head -20

# Check if a target IP is in AWS:
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  python3 -c "
import sys, json, ipaddress
data = json.load(sys.stdin)
target = ipaddress.ip_address('54.192.1.1')
for p in data['prefixes']:
    if target in ipaddress.ip_network(p['ip_prefix']):
        print(p)
"

# Find S3 buckets — guessing and enumeration:
# Format: https://BUCKETNAME.s3.amazonaws.com or https://s3.amazonaws.com/BUCKETNAME
# Common names: company-backup, company-logs, company-assets, company-dev

# Automated S3 bucket finder:
python3 bucket_finder.py targetcompany
# or
aws s3 ls s3://targetcompany-backup --no-sign-request   # Public bucket check
```

### Azure Footprinting

```
# Microsoft publishes Azure IP ranges:
# Download from: https://www.microsoft.com/en-us/download/details.aspx?id=56519
# (Weekly updated JSON file)

# Azure AD tenant discovery from domain:
curl -s "https://login.microsoftonline.com/targetcompany.com/.well-known/openid-configuration" | \
  python3 -m json.tool | grep "tenant_region_scope\|issuer"

# Find tenant ID:
curl -s "https://login.microsoftonline.com/targetcompany.com/v2.0/.well-known/openid-configuration" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['issuer'])"

# Check if target uses Office 365 (MX lookup then):
# MX points to *.mail.protection.outlook.com = they're on M365
# This means: Exchange Online, SharePoint Online, Teams, Azure AD
# Attack surface: OWA, Azure AD password spray (use slow spray — M365 has smart lockout)
```

### GCP Footprinting

```
# GCP IP ranges:
curl -s https://www.gstatic.com/ipranges/cloud.json | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for p in data.get('prefixes', []):
    if 'ipv4Prefix' in p and p.get('scope') == 'us-east1':
        print(p['ipv4Prefix'], p['service'])
"

# Google Cloud Storage bucket enumeration:
# Format: https://storage.googleapis.com/BUCKETNAME
curl -s "https://storage.googleapis.com/targetcompany-public"
curl -s "https://storage.googleapis.com/targetcompany-backup"
```

## Certificate Transparency for Asset Discovery

Every TLS certificate is logged publicly. This reveals subdomains and internal hostnames that never appeared in DNS — even ones on private networks that briefly got a cert.

```
# crt.sh web query:
# https://crt.sh/?q=%.targetcompany.com

# crt.sh via command line:
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
" | grep -v '*'

# What to look for in cert results:
# dev.targetcompany.com         → development environment (often less secured)
# staging.targetcompany.com     → staging — same code, less monitoring
# vpn.targetcompany.com         → VPN portal → try known credentials
# owa.targetcompany.com         → Outlook Web Access → password spray target
# admin.targetcompany.com       → admin panel
# jira.targetcompany.com        → Jira → often has public project exposure
# gitlab.targetcompany.com      → internal Git → source code
```

## Reverse IP & Hosting History

```
# Find all domains hosted on an IP (virtual hosting):
# https://viewdns.info/reverseip/?host=203.0.113.50
# https://hackertarget.com/reverse-ip-lookup/

# Command line:
curl -s "https://api.hackertarget.com/reverseiplookup/?q=203.0.113.50"

# Historical DNS — find old IPs for a domain (before CDN):
# https://viewdns.info/iphistory/?domain=targetcompany.com
# Old IPs may bypass Cloudflare/CDN and expose the real origin server

# Autonomous whois — find the registrar and registration dates:
whois targetcompany.com | grep -i "registrar\|creation\|updated\|expiry\|name server"
```

## Visual Mapping with Maltego & SpiderFoot

### SpiderFoot (Automated OSINT)

```
# SpiderFoot — automated OSINT that builds entity graphs
# Install:
sudo apt install spiderfoot
# or:
pip3 install spiderfoot

# Run web UI:
spiderfoot -l 127.0.0.1:5001

# CLI scan (no UI needed):
python3 sf.py -s targetcompany.com -t INTERNET_NAME \
  -m sfp_dnsresolve,sfp_ssl,sfp_shodan,sfp_whois,sfp_email \
  -o output.json

# SpiderFoot automatically chains:
# domain → subdomains → IPs → ASN → more IPs → emails → linked domains
```

### Maltego CE (Free Tier)

- Download from [https://www.maltego.com](https://www.maltego.com) — Community Edition is free
- Start with a Domain entity → Run all transforms → builds a visual graph
- Key transforms: DNS to IP, IP to ASN, Domain to Email, Person to Social
- Export graph as PDF for report appendix
- Limitation: CE has transform limits per session — use for targeted pivots, not bulk enumeration

## Putting It All Together — Recon Pipeline

```
># Full passive recon pipeline for a target domain:

TARGET="targetcompany.com"

# 1. Find ASN and IP ranges
amass intel -org "Target Company" -o asn.txt
curl -s "https://api.bgpview.io/search?query_term=${TARGET}" | \
  python3 -m json.tool > bgp.json

# 2. Certificate transparency → subdomains
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
  python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
  sort -u | grep -v '*' > crt_subs.txt

# 3. Email addresses
theHarvester -d ${TARGET} -b google,bing,linkedin -f harvest.html

# 4. Infrastructure map
dig +short mx ${TARGET}
dig +short txt ${TARGET}
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
  python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" \
  >> all_hosts.txt

# 5. Compile scope list for active scanning
cat crt_subs.txt >> all_hosts.txt
sort -u all_hosts.txt > final_scope.txt
echo "[*] Identified $(wc -l < final_scope.txt) assets for active recon"
```

## Key Resources

- [ASN and prefix lookup](https://bgp.he.net)
- [BGP route visualization](https://bgpview.io)
- [Certificate transparency search](https://crt.sh)
- [Reverse IP and network tools](https://api.hackertarget.com)
- [AWS IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)
- [SpiderFoot OSINT automation](https://github.com/smicallef/spiderfoot)
- [OSINT tool index](https://osintframework.com)
