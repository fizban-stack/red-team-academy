---
layout: training-page
title: "Active Recon (Scanning) — Red Team Academy"
module: "Reconnaissance"
tags:
  - nmap
  - masscan
  - scanning
page_key: "recon-active"
render_with_liquid: false
---

# Active Recon (Scanning)

## Active vs Passive Recon

Active reconnaissance sends packets to target systems. They can log your activity. Always confirm scope and authorization before scanning — an unauthorized scan is unauthorized access in most jurisdictions. In an authorized engagement, active recon reveals the actual attack surface: open ports, running services, OS versions, and accessible pathways.

The workflow: **fast port discovery first** → **targeted service enumeration second**. Never run a slow -sV scan against every port from the start — it wastes time and makes noise.

![Active recon workflow: fast port discovery with masscan, targeted service enumeration with nmap -sV, OS detection, then vulnerability scanning — outputting exploitation targets](/images/recon/active-recon-workflow.svg)  
*// active recon workflow — fast discovery to targeted service enumeration*

## Nmap Scan Types

### Port Discovery Scan Types

```
# -sS  SYN scan ("half-open") — DEFAULT for root
# Sends SYN, receives SYN-ACK (open) or RST (closed)
# Never completes TCP handshake → less logging on target
# Requires root/sudo
sudo nmap -sS 10.0.0.1

# -sT  TCP Connect scan — fallback without root
# Completes full TCP handshake → more logging
# Use when running as non-root or through proxies/socks
nmap -sT 10.0.0.1

# -sU  UDP scan — critical, often skipped
# Much slower than TCP; unreliable without root
# Key UDP services: DNS (53), SNMP (161), NTP (123), TFTP (69), NetBIOS (137)
sudo nmap -sU -p 53,67,68,69,111,123,137,138,161,500,1900 10.0.0.1

# -sN  TCP Null scan — no flags set → firewall evasion
# -sF  FIN scan — FIN flag only
# -sX  Xmas scan — FIN, PSH, URG flags
# These evade some stateless packet filters, but unreliable on Windows
sudo nmap -sN 10.0.0.1
sudo nmap -sF 10.0.0.1

# -sA  ACK scan — maps firewall rules, NOT open ports
# Open and closed ports both return RST
# Filtered ports return nothing → firewall rule identified
sudo nmap -sA 10.0.0.1
```

### Host Discovery

```
# -sn  Ping scan (host discovery, no port scan)
# Default: ICMP echo + TCP SYN 443 + TCP ACK 80 + ICMP timestamp
sudo nmap -sn 192.168.56.0/24

# -Pn  Skip host discovery — assume all hosts are up
# Essential when ICMP is blocked (common in corporate environments)
sudo nmap -Pn 10.0.0.1

# -PE  ICMP echo only (ping)
# -PP  ICMP timestamp
# -PS  TCP SYN to port(s): -PS22,80,443
# -PA  TCP ACK to port(s): -PA80
sudo nmap -PE 10.0.0.0/24
sudo nmap -PS22,80,443 10.0.0.0/24
```

### Service & Version Detection

```
# -sV  Version detection — probes open ports for service/version
# Intensity 0-9 (default 7): higher = more accurate but slower
sudo nmap -sV 10.0.0.1
sudo nmap -sV --version-intensity 9 10.0.0.1  # Maximum accuracy

# -O   OS detection — requires root, needs open + closed port
sudo nmap -O 10.0.0.1

# -A   Aggressive: -sV -O + NSE default scripts + traceroute
# Most informative single flag combo for targeted hosts
sudo nmap -A 10.0.0.1

# -sC  Default NSE scripts only (safer than -A in narrow scope)
sudo nmap -sC 10.0.0.1

# Combining flags — standard red team scan pattern:
sudo nmap -sS -sV -sC -O -p- 10.0.0.1  # Full port range with detection
```

### Port Specification

```
# -p   Port specification:
nmap -p 22            # Single port
nmap -p 22,80,443     # Multiple ports
nmap -p 1-1000        # Range
nmap -p-              # ALL 65535 ports (slow — use masscan first)
nmap -p 0-            # Include port 0

# --top-ports  Most commonly used N ports (by frequency in Nmap data):
nmap --top-ports 100 10.0.0.1     # Top 100
nmap --top-ports 1000 10.0.0.0/24 # Top 1000 on a /24

# -F   Fast scan — top 100 ports
nmap -F 10.0.0.0/24
```

### Timing Templates

```
# -T0  Paranoid  — 5 min between probes  (IDS evasion)
# -T1  Sneaky    — 15 sec between probes (IDS evasion, very slow)
# -T2  Polite    — 0.4 sec between probes (low bandwidth)
# -T3  Normal    — DEFAULT
# -T4  Aggressive — faster, assumes fast network (good for local lab)
# -T5  Insane    — very fast, may miss open ports on slow networks

# Production network (authorized engagement): use T2 or T3 to avoid
# triggering rate-based IDS alerts
sudo nmap -T2 -sS 10.0.0.0/24

# Local lab: T4 is fine
sudo nmap -T4 -sS -p- 192.168.56.10
```

### Output Formats

```
# -oN  Normal text output
# -oX  XML output (parseable, used by tools like Metasploit)
# -oG  Grepable output (easy for bash processing)
# -oA  ALL formats — saves .nmap, .xml, .gnmap simultaneously

# ALWAYS use -oA on engagements — save evidence:
sudo nmap -sS -sV -sC -p- -oA scan_target 10.0.0.1
# Creates: scan_target.nmap, scan_target.xml, scan_target.gnmap

# Process grepable output:
grep "open" scan_target.gnmap | awk '{print $2, $5}'

# Import XML into Metasploit:
msf > db_import scan_target.xml
```

## NSE (Nmap Scripting Engine)

NSE scripts extend Nmap from port scanner to vulnerability assessor. Scripts are organized by category and live in `/usr/share/nmap/scripts/`.

### Script Categories

```
# Categories:
# auth    — authentication bypass, default credentials
# broadcast — LAN discovery via broadcast
# brute   — brute force credential attacks
# default — run with -sC; safe, informative scripts
# discovery — enumerate services
# dos     — denial of service (never use in production)
# exploit — actual exploitation (careful)
# external — queries external resources
# fuzzer  — fuzzing inputs
# intrusive — may crash services (don't use on prod without care)
# malware — detect backdoors
# safe    — safe to run, won't harm target
# version — service version detection helpers
# vuln    — check for vulnerabilities

# Run all scripts in a category:
sudo nmap --script auth 10.0.0.1
sudo nmap --script vuln 10.0.0.1     # Vulnerability checks (noisy)

# Run specific script:
sudo nmap --script smb-vuln-ms17-010 10.0.0.1

# Run multiple scripts:
sudo nmap --script "smb-vuln-*" 10.0.0.1     # All SMB vuln scripts
sudo nmap --script "http-*" 10.0.0.1 -p 80    # All HTTP scripts

# Pass script arguments:
sudo nmap --script http-brute --script-args userdb=users.txt,passdb=pass.txt 10.0.0.1
```

### High-Value NSE Scripts by Service

```
# SMB:
sudo nmap --script smb-vuln-ms17-010 -p 445 10.0.0.1      # EternalBlue
sudo nmap --script smb-vuln-ms08-067 -p 445 10.0.0.1      # MS08-067
sudo nmap --script smb-security-mode -p 445 10.0.0.1      # SMB signing?
sudo nmap --script smb2-security-mode -p 445 10.0.0.1     # SMBv2 signing
sudo nmap --script smb-enum-shares -p 445 10.0.0.1        # List shares
sudo nmap --script smb-enum-users -p 445 10.0.0.1         # Enumerate users

# HTTP/HTTPS:
sudo nmap --script http-title -p 80,443,8080 10.0.0.0/24  # Page titles
sudo nmap --script http-methods -p 80,443 10.0.0.1        # Allowed methods
sudo nmap --script http-auth-finder -p 80,443 10.0.0.1    # Auth type
sudo nmap --script http-robots.txt -p 80 10.0.0.1         # robots.txt
sudo nmap --script http-shellshock -p 80 10.0.0.1         # Shellshock

# SSL/TLS:
sudo nmap --script ssl-enum-ciphers -p 443 10.0.0.1       # Cipher suites
sudo nmap --script ssl-heartbleed -p 443 10.0.0.1         # Heartbleed
sudo nmap --script ssl-cert -p 443 10.0.0.0/24            # Cert details

# DNS:
sudo nmap --script dns-zone-transfer -p 53 ns1.targetcompany.com
sudo nmap --script dns-brute targetcompany.com

# FTP:
sudo nmap --script ftp-anon -p 21 10.0.0.0/24            # Anonymous FTP
sudo nmap --script ftp-bounce -p 21 10.0.0.1             # FTP bounce

# MySQL/MSSQL:
sudo nmap --script mysql-info -p 3306 10.0.0.1
sudo nmap --script ms-sql-info -p 1433 10.0.0.1
sudo nmap --script ms-sql-empty-password -p 1433 10.0.0.1

# RDP:
sudo nmap --script rdp-enum-encryption -p 3389 10.0.0.0/24
```

## Masscan — High-Speed Scanning

Masscan sends packets at line rate. It can scan the entire IPv4 internet in under 6 minutes from a 10Gbps connection. For engagements, use it to pre-identify open ports across large ranges, then hand off to Nmap for detailed fingerprinting.

```
# Install:
sudo apt install masscan

# Basic scan — all ports on a range:
sudo masscan -p0-65535 192.168.56.0/24 --rate=1000 -oL masscan_output.txt

# Key flags:
# --rate    Packets per second (start slow: 1000, increase to 10000 for LAN)
# -p        Port list: single, range, comma-separated
# --banners Grab banners where possible
# -oL       Output in list format (easy to parse)
# -oX       Output XML (importable)
# --excludefile  Exclude hosts (keep a no-scan list for OOB systems)

# Typical red team workflow:
sudo masscan -p1-65535 10.0.0.0/24 --rate=5000 -oG masscan.gnmap

# Extract open ports for Nmap handoff:
awk '/open/{print $4, $3}' masscan.gnmap | \
  sed 's|/tcp||; s|/udp||' | \
  sort -k1 -u > hosts_ports.txt

# Then Nmap for detailed fingerprint:
sudo nmap -sV -sC -iL hosts_ports.txt -oA nmap_detailed
```

## Rustscan — Fast Port Pre-Scanner

Rustscan finds all open ports in seconds using async Rust, then automatically feeds results into Nmap for service detection. Best of both tools.

```
# Install via cargo:
cargo install rustscan
# Or via Docker:
docker pull rustscan/rustscan:latest

# Basic usage — scans all ports, passes to Nmap:
rustscan -a 10.0.0.1 -- -sV -sC

# Scan a range:
rustscan -a 192.168.56.0/24 -- -sV -sC -oA output

# Key flags:
# -a    Address or CIDR range
# -p    Specific ports (default: all)
# -b    Batch size (connections per second, default 500)
# -t    Timeout in ms (default 1500)
# --    Everything after -- is passed to Nmap

# Fast full-port scan:
rustscan -a 10.0.0.1 -b 5000 -t 2000 -- -A -oA rustscan_output
```

## httpx — Web Service Probing

After port/subdomain discovery, `httpx` probes a list of hosts/URLs to find which are actually serving HTTP/HTTPS, grabs status codes, titles, and technology headers, and filters to live web targets for further attack. It's the bridge between subdomain lists and web exploitation.

```
# Install:
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# or: sudo apt install httpx

# Probe a list of hosts (from subdomain enum output):
cat resolved_subs.txt | httpx -silent

# Get status codes, titles, and tech:
cat resolved_subs.txt | httpx -silent -status-code -title -tech-detect

# Get full response info:
cat resolved_subs.txt | httpx \
  -status-code -title -tech-detect -web-server \
  -content-length -follow-redirects \
  -o live_web_targets.txt

# Filter to only 200 OK responses:
cat resolved_subs.txt | httpx -mc 200 -silent

# Probe with both HTTP and HTTPS (default: tries both):
cat hosts.txt | httpx -no-color -o httpx_results.txt

# Screenshot discovered pages (for quick visual triage):
cat resolved_subs.txt | httpx -screenshot -o screenshots/

# Pipeline: subdomain → resolve → probe web:
subfinder -d targetcompany.com -silent | \
  dnsx -silent | \
  httpx -silent -status-code -title -o web_targets.txt
```

## Standard Red Team Scan Workflow

```
>#!/bin/bash
TARGET="192.168.56.0/24"
OUTDIR="scan_output"
mkdir -p "$OUTDIR"

# Phase 1: Fast host discovery
echo "[*] Phase 1: Host discovery"
sudo nmap -sn "$TARGET" -oG "$OUTDIR/hosts.gnmap"
grep "Up" "$OUTDIR/hosts.gnmap" | awk '{print $2}' > "$OUTDIR/alive_hosts.txt"
echo "[*] Found $(wc -l < $OUTDIR/alive_hosts.txt) alive hosts"

# Phase 2: Fast port discovery on all alive hosts
echo "[*] Phase 2: Fast port scan (masscan)"
sudo masscan -iL "$OUTDIR/alive_hosts.txt" -p0-65535 \
  --rate=5000 -oL "$OUTDIR/masscan_all.txt"

# Phase 3: Extract unique port/host combos
grep "open" "$OUTDIR/masscan_all.txt" | \
  awk '{print $4":"$3}' | sed 's|/tcp||;s|/udp||' | \
  sort -u > "$OUTDIR/open_ports.txt"

# Phase 4: Detailed Nmap service + script scan
echo "[*] Phase 4: Nmap detailed scan"
sudo nmap -sV -sC -O \
  --script "default,vuln" \
  -iL "$OUTDIR/alive_hosts.txt" \
  -oA "$OUTDIR/nmap_full"

echo "[*] Done. Results in $OUTDIR/"
```

## Key Resources

- `https://nmap.org/book/man.html` — Official Nmap manual
- `https://nmap.org/nsedoc/` — NSE script documentation
- `https://github.com/robertdavidgraham/masscan` — Masscan GitHub
- `https://github.com/RustScan/RustScan` — Rustscan GitHub
- `/usr/share/nmap/scripts/` — Local NSE scripts on Kali
