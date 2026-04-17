---
layout: training-page
title: "Subdomain Enumeration — Red Team Academy"
module: "Reconnaissance"
tags:
  - subdomains
  - dns
  - amass
page_key: "recon-subdomain-enum"
render_with_liquid: false
---

# Subdomain Enumeration

## Why Subdomains Matter

The attack surface isn't just `www.targetcompany.com`. Large organizations run hundreds of subdomains — development environments, internal portals, legacy applications, admin panels, and staging servers. Many of these are forgotten, under-monitored, or running outdated software. A forgotten `dev.targetcompany.com` running PHP 5.x is more valuable than a hardened `www`.

The approach is layered: passive discovery first (no DNS queries to target), then brute-forcing to find what passive methods missed, then virtual host probing to find hosts that don't resolve publicly.

![Subdomain enumeration layered approach: passive discovery via crt.sh and subfinder, brute force with dnsx, virtual host probing, DNS zone transfer, and permutation mutations — then probing live hosts](/images/recon/subdomain-enum-flow.svg)  
*// subdomain enumeration — layered passive, brute force, and probe approach*

## Passive Subdomain Discovery

### Certificate Transparency (crt.sh)

```
# Every TLS cert is publicly logged — this reveals subdomains
# even if they're not in public DNS:
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
" | grep -v '*' | sort -u > crt_subs.txt
```

### subfinder

subfinder is the fastest passive subdomain tool. It queries 30+ passive sources simultaneously without touching the target's infrastructure.

```
# Install:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# or:
sudo apt install subfinder

# Basic usage — passive only:
subfinder -d targetcompany.com

# Silent mode (subdomains only, no banner):
subfinder -d targetcompany.com -silent

# All sources (requires API keys configured):
subfinder -d targetcompany.com -all -silent

# Save output:
subfinder -d targetcompany.com -silent -o subfinder_subs.txt

# Scan multiple domains:
subfinder -dL domains.txt -silent -o all_subs.txt

# Configure API keys (significantly improves results):
# Edit ~/.config/subfinder/provider-config.yaml
# Add keys for: virustotal, shodan, censys, securitytrails, github, etc.

# Passive sources subfinder queries include:
# CertSpotter, crt.sh, DNSDumpster, HackerTarget, PassiveTotal,
# Robtex, SecurityTrails, Shodan, ThreatCrowd, URLScan, VirusTotal
```

### assetfinder

```
# Install:
go install github.com/tomnomnom/assetfinder@latest

# Find subdomains and associated domains:
assetfinder targetcompany.com

# Subdomains only (filter to exact domain):
assetfinder --subs-only targetcompany.com

# Combine with subfinder for wider coverage:
{ subfinder -d targetcompany.com -silent; assetfinder --subs-only targetcompany.com; } | \
  sort -u > passive_subs.txt
```

### Amass (Passive Mode)

```
# Install:
sudo apt install amass

# Passive-only intel gathering:
amass enum -passive -d targetcompany.com

# Passive with all sources:
amass enum -passive -d targetcompany.com -src     # Show source of each result

# ASN-based discovery (find all subdomains by IP range):
amass intel -org "Target Company"                  # Find ASN from org name
amass intel -asn 12345 -ip                         # Find all IPs in ASN
amass enum -passive -d targetcompany.com -asn 12345

# Save to file:
amass enum -passive -d targetcompany.com -o amass_passive.txt

# Amass config for API keys:
# ~/.config/amass/config.ini
# [virustotal]  — API key
# [shodan]      — API key
# [censys]      — API ID and secret
```

## Active DNS Brute Forcing

Active brute-forcing sends DNS queries trying wordlists of common subdomain names. It finds hosts that passive discovery misses — particularly internal-facing subdomains not indexed by any external service.

### dnsx

dnsx resolves a list of potential subdomains against real DNS — fast, parallel, accurate.

```
# Install:
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Resolve a list of subdomains (check which actually exist):
cat passive_subs.txt | dnsx -silent

# Generate subdomain list and resolve in one pipeline:
cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | \
  sed 's/^/targetcompany.com./' | \
  dnsx -silent -resp

# Resolve with A records:
echo "targetcompany.com" | dnsx -a -resp -silent

# Check for wildcard DNS:
dnsx -d targetcompany.com -wt 30      # Wildcard check

# Bulk resolve from subfinder output:
subfinder -d targetcompany.com -silent | dnsx -silent -o resolved_subs.txt

# Get A records for all resolved subdomains:
cat resolved_subs.txt | dnsx -a -resp -silent
```

### gobuster (DNS Mode)

```
# Install:
sudo apt install gobuster

# DNS subdomain brute force:
gobuster dns -d targetcompany.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 \
  --timeout 5s

# Flags:
# -d     Target domain
# -w     Wordlist
# -t     Threads (default 10, increase for speed)
# --timeout  DNS timeout per query
# -r     Custom DNS resolver (use target's NS for accuracy)
# -o     Output file

# Use a specific resolver (target's authoritative NS):
gobuster dns -d targetcompany.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r 8.8.8.8 -t 50

# Show IPs too:
gobuster dns -d targetcompany.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --show-ips -t 50
```

### Amass (Active Mode)

```
># Active mode — brute forces + passive:
amass enum -active -d targetcompany.com \
  -brute \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With zone transfer attempt:
amass enum -active -d targetcompany.com -brute -axfr

# Full scan (passive + active + brute):
amass enum -d targetcompany.com \
  -brute \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -active \
  -o amass_full.txt \
  -src
```

## Virtual Host Enumeration

Virtual hosts allow multiple sites to run on a single IP. A subdomain might not resolve in public DNS but be accessible if you send a request to the IP with the right `Host:` header. This is common for internal applications, staging environments, and admin panels that aren't intended to be publicly discovered.

### gobuster (vhost mode)

```
# Vhost brute force — sends requests with custom Host headers:
gobuster vhost \
  -u http://192.168.56.10 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain \
  -t 50

# --append-domain: appends target domain to each word
# e.g., wordlist entry "dev" → Host: dev.targetcompany.com

# With HTTPS:
gobuster vhost \
  -u https://10.0.0.1 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain \
  -k \
  -t 50

# Filter by response status/size to reduce false positives:
gobuster vhost \
  -u http://10.0.0.1 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain \
  --exclude-length 612   # Exclude default 404 response size
```

### ffuf (vhost mode)

```
# ffuf — flexible fuzzer, excellent for vhost discovery:
sudo apt install ffuf

# Basic vhost fuzzing:
ffuf -u http://192.168.56.10 \
  -H "Host: FUZZ.targetcompany.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 \
  -mc 200,301,302,403

# Filter out the "default" response size to reduce noise:
# First: check what the default response size is for unknown hosts
curl -s -o /dev/null -w "%{size_download}" -H "Host: notexist.targetcompany.com" http://192.168.56.10
# Then filter out that size:
ffuf -u http://192.168.56.10 \
  -H "Host: FUZZ.targetcompany.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 612 \
  -t 50
```

## DNS Wordlists

```
># SecLists DNS wordlists (ranked by quality):
ls /usr/share/seclists/Discovery/DNS/

# subdomains-top1million-5000.txt    — Fast, covers common subdomains
# subdomains-top1million-20000.txt   — Wider coverage
# subdomains-top1million-110000.txt  — Comprehensive but slow
# combined_subdomains.txt            — Large community-sourced list
# dns-Jhaddix.txt                    — Jason Haddix's curated list

# Build a custom wordlist from collected subdomains:
# 1. Collect all discovered subdomains
# 2. Extract the subdomain part only
cat all_subs.txt | sed 's/\.targetcompany\.com//' | sort -u > custom_words.txt
# 3. Use as wordlist for other targets in same sector
```

## Full Subdomain Recon Pipeline

```
>#!/bin/bash
DOMAIN="targetcompany.com"
OUT="subdomain_enum"
mkdir -p "$OUT"

echo "[*] Phase 1: Passive discovery"
subfinder -d "$DOMAIN" -silent -o "$OUT/subfinder.txt"
assetfinder --subs-only "$DOMAIN" >> "$OUT/subfinder.txt"
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | \
  python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
  grep -v '*' | sort -u >> "$OUT/subfinder.txt"

echo "[*] Phase 2: DNS brute force"
gobuster dns -d "$DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -o "$OUT/gobuster_dns.txt" 2>/dev/null
grep "Found:" "$OUT/gobuster_dns.txt" | awk '{print $2}' >> "$OUT/subfinder.txt"

echo "[*] Phase 3: Resolve all to IPs"
sort -u "$OUT/subfinder.txt" | dnsx -silent -a -resp -o "$OUT/resolved.txt"

echo "[*] Phase 4: Extract live IPs for scanning"
grep -oP '\d+\.\d+\.\d+\.\d+' "$OUT/resolved.txt" | sort -u > "$OUT/live_ips.txt"

echo "[*] Found $(wc -l < $OUT/resolved.txt) live subdomains"
echo "[*] Found $(wc -l < $OUT/live_ips.txt) unique IPs"
echo "[*] Results in $OUT/"
```

## Key Resources

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [dnsx DNS resolver](https://github.com/projectdiscovery/dnsx)
- [Amass (now projectdiscovery/amass)](https://github.com/OWASP/Amass)
- [gobuster](https://github.com/OJ/gobuster)
- [ffuf fuzzer](https://github.com/ffuf/ffuf)
- [SecLists DNS wordlists](https://github.com/danielmiessler/SecLists)
