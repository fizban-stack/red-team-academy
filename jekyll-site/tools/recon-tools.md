---
layout: training-page
title: "Reconnaissance Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - recon
  - scanning
  - osint
  - enumeration
page_key: "tools-recon"
render_with_liquid: false
---

# Reconnaissance Tools

Recon tools are used for external attack surface discovery, port scanning, subdomain enumeration,
    and vulnerability identification. These are typically the first tools deployed in an engagement.

 NMAP 

## // Nmap

Network Mapper — the gold standard for port scanning, OS fingerprinting, and service detection. NSE (Nmap Scripting Engine) provides hundreds of built-in vulnerability checks.

### Install

```
sudo apt install nmap          # Kali / Debian
brew install nmap              # macOS
# Windows: https://nmap.org/download.html
```

### Key Capabilities

| Feature | Flag | Description |
| --- | --- | --- |
| SYN scan | -sS | Stealth half-open scan (root required) |
| Version detect | -sV | Service/version banner grabbing |
| OS detection | -O | OS fingerprinting via TCP/IP stack |
| Script engine | -sC / --script | Run default or custom NSE scripts |
| UDP scan | -sU | Scan UDP ports (slow, but critical) |
| Timing | -T0 to -T5 | Paranoid to insane timing templates |

### Common Usage

```
# Phase 1: Fast host discovery
nmap -sn 192.168.1.0/24 -oG sweep.txt

# Phase 2: Full port scan on live hosts
nmap -p- --min-rate 5000 -T4 192.168.1.10 -oN full-ports.txt

# Phase 3: Targeted version + script scan on open ports
nmap -sV -sC -p 22,80,443,445 192.168.1.10 -oN detailed.txt

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users -p 445 192.168.1.10

# Vuln scanning
nmap --script vuln 192.168.1.10

# Firewall evasion: fragment packets
nmap -f -sS 10.10.10.10

# Decoy scan (hide source IP among decoys)
nmap -D RND:10 -sS 10.10.10.10
```

### Detections

- IDS/IPS: SYN flood patterns, half-open connections, port sweep signatures (Snort SID 1228, 469)
- Firewall logs: sequential port access, high connection rate from single source
- EDR: Unusual outbound connection bursts; Windows Event 5156 (filtering platform connection)
- Network TAP / NetFlow: abnormal packet volume, TTL anomalies from -O flag
- Honeypots: Nmap touches common ports on fake services

**OPSEC:** Use -T1 or -T2 timing, randomize port order (--randomize-hosts),
    avoid -sC/-sV simultaneously on sensitive targets (generates heavy traffic),
    route through SOCKS5 proxy where possible.

---

 MASSCAN 

## // Masscan

Asynchronous TCP port scanner capable of scanning the entire IPv4 internet in under 6 minutes. Uses its own TCP/IP stack for maximum speed. Best used for initial discovery before targeted Nmap scans.

### Install

```
sudo apt install masscan
# or build from source
git clone https://github.com/robertdavidgraham/masscan
cd masscan && make && sudo make install
```

### Common Usage

```
# Scan top 100 ports across large subnet (10k pps)
sudo masscan -p80,443,22,445,3389,8080,8443 10.0.0.0/8 --rate 10000 -oG masscan.txt

# Full port scan on single target
sudo masscan -p1-65535 192.168.1.10 --rate 100000

# Banner grabbing
sudo masscan -p80,443 10.0.0.0/8 --banners --rate 5000

# Use discovered IPs as Nmap input
masscan -p- 10.10.10.0/24 --rate 50000 -oG - | grep "Host:" | awk '{print $2}' > live-hosts.txt
nmap -sV -iL live-hosts.txt
```

### Detections

- Very high packet rate is unmissable — masscan generates millions of SYN packets
- Firewall: RST flood from target (masscan ignores state)
- SIEM: High-volume connection attempts from single source IP
- Rate limiting / null-routing from ISP or upstream firewall

**OPSEC:** Keep rate under 1000 pps in sensitive environments. Never run masscan from your C2 infrastructure — use a disposable VPS. Use --source-ip to spoof (requires raw socket access).

---

 RUSTSCAN 

## // RustScan

Fast port scanner written in Rust. Scans all 65,535 ports in ~3 seconds, then automatically pipes results to Nmap for service detection. Best of both worlds approach.

### Install

```
# Via cargo
cargo install rustscan

# Docker (recommended)
docker pull rustscan/rustscan:latest
alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:latest'
```

### Common Usage

```
# Scan all ports, pass open ports to Nmap
rustscan -a 192.168.1.10 -- -sV -sC

# Batch multiple hosts
rustscan -a 192.168.1.0/24 --range 1-65535 -- -A

# Custom timeout (lower = faster but misses filtered ports)
rustscan -a 10.10.10.10 --timeout 2000 --tries 2

# Quiet mode for piping
rustscan -a 10.10.10.10 -g  # outputs: 10.10.10.10 -> [22, 80, 443]
```

### Detections

- Similar to Nmap — full port scan generates ~65k SYN packets per host
- The subsequent Nmap pass triggers additional IDS signatures
- Network baseline anomaly detection will flag unusual connection volumes

---

 AMASS 

## // Amass

OWASP Amass performs in-depth DNS enumeration and external attack surface mapping. Uses passive sources (Certificate Transparency, APIs, DNS brute-force) and active techniques. The gold standard for subdomain enumeration in pentests.

### Install

```
go install -v github.com/owasp-amass/amass/v4/...@master
# or
sudo apt install amass
```

### Common Usage

```
# Passive subdomain enumeration (no DNS queries to target)
amass enum -passive -d example.com -o subdomains.txt

# Active enumeration (brute force + permutations)
amass enum -active -d example.com -brute -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Full scan with API keys configured in config.ini
amass enum -d example.com -config ~/.config/amass/config.ini -o full-enum.txt

# Map the network infrastructure
amass intel -d example.com -whois

# Find related organizations/ASNs
amass intel -org "Example Corp"

# Output as JSON for processing
amass enum -d example.com -json output.json
```

### API Integrations

Amass supports 50+ data sources. Key ones to configure in ~/.config/amass/config.ini:

- Shodan, VirusTotal, SecurityTrails, Censys, PassiveTotal
- GitHub, GitLab (token scraping), Hunter.io, WhoisXML
- NetblockTool, BGPView (ASN/IP range discovery)

### Detections

- Active mode: DNS brute-force generates NXDOMAIN floods visible in DNS logs
- Passive mode: No direct detection — queries third-party APIs
- Certificate Transparency monitoring services (like Facebook CT Monitor) may alert on new cert issuance

---

 SUBFINDER 

## // Subfinder

Fast passive subdomain enumeration tool by ProjectDiscovery. Queries 40+ passive sources. Designed for speed and pipeline integration with other ProjectDiscovery tools.

### Install

```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Common Usage

```
# Basic enumeration
subfinder -d example.com -o subdomains.txt

# All sources (requires API keys in ~/.config/subfinder/provider-config.yaml)
subfinder -d example.com -all -o subdomains.txt

# Pipeline with httpx to find live web services
subfinder -d example.com | httpx -silent -o live-web.txt

# Multiple domains
subfinder -dL domains.txt -o all-subs.txt

# Verbose with source attribution
subfinder -d example.com -v 2>&1 | grep "\[" | head -50
```

### Detections

- Passive only — no direct network contact with target
- Queries external APIs (VirusTotal, Shodan, etc.) — may be logged by those services
- No detection on target-side infrastructure

---

 BBOT 

## // BBOT (Bighuge BLS OSINT Tool)

Modern OSINT automation framework by Black Lantern Security. Combines subdomain enum, web crawling, port scanning, cloud asset discovery, and vulnerability scanning in a single modular pipeline. The most comprehensive open-source recon tool in 2025.

### Install

```
pip install bbot
# or
pipx install bbot
```

### Common Usage

```
# Basic subdomain scan
bbot -t example.com -p subdomain-enum

# Full external attack surface scan
bbot -t example.com -p kitchen-sink

# Specific modules
bbot -t example.com -m subfinder,amass,httpx,nuclei

# Output to multiple formats
bbot -t example.com -p subdomain-enum -o output/ --output-modules json,csv,neo4j

# Cloud asset discovery (S3, Azure, GCP)
bbot -t example.com -p cloud-enum

# Email discovery
bbot -t example.com -m emailformat,hunter -c modules.hunter.api_key=YOUR_KEY
```

### Key Modules

| Module | Function |
| --- | --- |
| subfinder | Passive subdomain enumeration |
| httpx | HTTP probe, tech detection |
| nuclei | Template-based vuln scanning |
| gowitness | Screenshot web services |
| bucket_finder | S3/Azure/GCP bucket enum |
| github_codesearch | Leaked credentials on GitHub |

### Detections

- Active modules (httpx, nuclei) generate HTTP requests to target — visible in web logs
- User-Agent: "bbot/x.x.x" by default — trivially blocked/detected; override with -c http.user_agent=...
- Nuclei scanning leaves distinct request patterns in WAF/IDS logs

---

 NUCLEI 

## // Nuclei

Template-based vulnerability scanner by ProjectDiscovery. Community-maintained library of 9,000+ templates covering CVEs, misconfigs, exposed panels, default credentials, and more.

### Install

```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Common Usage

```
# Scan with all templates
nuclei -u https://example.com -o results.txt

# Scan specific severity
nuclei -u https://example.com -s critical,high -o critical.txt

# Scan specific categories
nuclei -u https://example.com -t cves/ -t exposures/ -t misconfigurations/

# Bulk scan from list
nuclei -l urls.txt -s critical,high -o results.json -j

# Technology-specific scan
nuclei -u https://example.com -t technologies/

# CVE scanning only
nuclei -u https://example.com -tags cve -o cves.txt

# Default credentials check
nuclei -u https://example.com -t default-logins/

# Custom template
nuclei -u https://example.com -t /path/to/custom-template.yaml

# Subdomain pipeline
subfinder -d example.com | httpx -silent | nuclei -t cves/ -o output.txt
```

### Detections

- WAF: Nuclei templates often contain distinctive payloads ({{FUZZING_KEY}}, etc.)
- User-Agent: "Nuclei - Open-Source Project (github.com/projectdiscovery/nuclei)" by default
- Rate limiting: Nuclei can be aggressive — WAFs will trigger rate-based blocks
- SIEM: High volume of 4xx/5xx responses from single IP

**OPSEC:** Use -H "User-Agent: Mozilla/5.0..." to mask the scanner, add -rl 10 rate limiting, use -proxy for routing through Burp or SOCKS5.

---

 THEHARVESTER 

## // theHarvester

OSINT tool for gathering emails, subdomains, hosts, employee names, open ports, and banners from public sources. Pre-installed on Kali. Essential for initial OSINT phase.

### Common Usage

```
# LinkedIn employee enumeration
theHarvester -d example.com -b linkedin -l 500

# Email harvesting from all sources
theHarvester -d example.com -b all -l 200

# Specific sources
theHarvester -d example.com -b google,bing,duckduckgo,crtsh,dnsdumpster

# Output to XML/JSON
theHarvester -d example.com -b all -f output

# Shodan integration
theHarvester -d example.com -b shodan -s 0 -l 100
```

### Detections

- Passive sources only — no direct target contact
- LinkedIn: Unusual profile view volumes may trigger LinkedIn's bot detection
- Google: CAPTCHA after repeated queries without API key

---

 SHODAN CLI 

## // Shodan CLI

Command-line interface for Shodan, the search engine for internet-connected devices. Find exposed services, default credentials, CVE-vulnerable systems without ever touching the target.

### Install & Setup

```
pip install shodan
shodan init YOUR_API_KEY
```

### Common Usage

```
# Search for exposed RDP on an org's IP range
shodan search --fields ip_str,port,org "org:\"Example Corp\" port:3389"

# Find all hosts for an IP range
shodan host 192.0.2.0/24

# Check specific IP
shodan host 192.0.2.1

# CVE-based search
shodan search "vuln:CVE-2021-44228"  # Log4Shell

# Technology search
shodan search "product:Apache httpd version:2.4.49"

# Download results
shodan download results "org:\"Example Corp\"" --limit 1000
shodan parse --fields ip_str,port results.json.gz

# SSL cert search (find domains by cert)
shodan search "ssl.cert.subject.cn:*.example.com"

# Alert: get notified when new hosts appear for org
shodan alert create "Example Corp Monitor" 192.0.2.0/24
```

### Key Shodan Dorks

```
org:"Target Corp" port:22 country:US          # SSH exposed
hostname:example.com has_screenshot:true       # web panels
product:Kubernetes port:6443                   # exposed K8s API
"default password" product:nginx               # default creds
net:192.0.2.0/24 port:8080,8443,9200          # internal services exposed
ssl:"example.com" 200                          # live HTTPS assets
```

### Detections

- Shodan queries target IPs directly for indexing — defenders can see Shodan's scanner IPs in logs
- Your queries are logged by Shodan (API key tied to account)
- No real-time target interaction — Shodan data may be hours to weeks old
