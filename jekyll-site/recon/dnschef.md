---
layout: training-page
title: "DNSChef — DNS Proxy & Faker — Red Team Academy"
module: "Reconnaissance"
tags:
  - dnschef
  - dns
  - mitm
  - dns-proxy
  - malware-analysis
  - network-interception
  - recon
page_key: "recon-dnschef"
render_with_liquid: false
---

# DNSChef — DNS Proxy & Faker

DNSChef is a configurable DNS proxy that intercepts DNS queries and returns fake (or real) responses based on rules you define. It is used in man-in-the-middle setups to redirect traffic at the DNS layer: point a target machine's DNS at DNSChef, and any domain you specify gets resolved to an IP you control. Common uses include redirecting malware C2 traffic for analysis, forcing traffic through a proxy, testing DNS pinning, and simulating network environments in labs.

## Install

```
# Clone and install:
git clone https://github.com/iphelix/dnschef
cd dnschef
pip install dnspython

# Run directly:
python dnschef.py --help

# Or install system-wide:
pip install dnschef
```

## How It Works

```
# DNSChef listens on UDP/TCP port 53 and acts as a DNS server.
# For each query it receives, it checks your rules:
#
#   1. If the domain matches a --fakedomains entry  → return the fake IP/response
#   2. If the domain matches a --truedomains entry  → forward to real DNS upstream
#   3. Otherwise                                    → apply the default (fakeip or forward)
#
# Use cases:
# - Redirect malware C2 domains to your analysis machine (fakeip = your sinkhole)
# - Redirect all traffic to a proxy/MitM box (fakeip = proxy IP, truedomains = none)
# - Pass-through for everything except specific targets (truedomains = everything, fakedomains = targets)
# - Simulate split-horizon DNS in a lab

# Set the target machine's DNS server to your DNSChef IP:
# Windows:  Control Panel → Network → Adapter → IPv4 → DNS = [your IP]
# Linux:    /etc/resolv.conf → nameserver [your IP]
# Or via DHCP: set DNS option in your DHCP server to your IP
```

## Basic Usage — Redirect All Traffic

```
# Respond to ALL DNS queries with a single fake IP:
# Useful for MitM labs — everything resolves to your proxy/intercept box
sudo python dnschef.py --fakeip 10.0.0.1

# Listen on a specific interface and port:
sudo python dnschef.py --fakeip 10.0.0.1 --interface 192.168.1.100 --port 53

# TCP mode (useful when UDP is filtered or for large responses):
sudo python dnschef.py --fakeip 10.0.0.1 --tcp

# Verbose — shows every query received and response sent:
sudo python dnschef.py --fakeip 10.0.0.1 -q
```

## Faking Specific Domains

```
# Fake only specific domains — everything else gets forwarded to real DNS:
# --fakedomains   comma-separated list of domains to fake
# --fakeip        what IP to return for those domains
sudo python dnschef.py --fakeip 10.10.14.5 --fakedomains "evil.com,malware-c2.net"

# Wildcard matching — redirects all subdomains:
# *.corp.com → 10.0.0.1  (catches mail.corp.com, vpn.corp.com, etc.)
sudo python dnschef.py --fakeip 10.0.0.1 --fakedomains "corp.com"

# Fake only a subdomain, pass through everything else:
sudo python dnschef.py --fakeip 192.168.1.100 --fakedomains "internal.corp.com" \
  --nameservers 8.8.8.8

# Use a different fake IP for AAAA (IPv6) queries:
sudo python dnschef.py --fakeip 10.0.0.1 --fakeipv6 "::1" \
  --fakedomains "targetdomain.com"
```

## Passthrough for Specific Domains (Reverse Filtering)

```
# --truedomains   comma-separated list of domains to forward to real DNS
# Use when you want to fake EVERYTHING except a whitelist of legit domains

# Fake all traffic (--fakeip for default) but let Google/Microsoft resolve normally:
sudo python dnschef.py --fakeip 10.0.0.1 \
  --truedomains "google.com,microsoft.com,windowsupdate.com,windows.com"

# Practical malware analysis setup:
# - fakeip = your sinkhole/analysis listener (Wireshark + netcat)
# - truedomains = OS update domains so the sandbox doesn't break
sudo python dnschef.py --fakeip 192.168.1.50 \
  --truedomains "windowsupdate.com,microsoft.com,akamaitechnologies.com" \
  --nameservers 8.8.8.8 -q
```

## Custom Response Types

```
# Fake MX record (redirect email traffic to your server):
sudo python dnschef.py --fakemx "mail.attacker.com" --fakedomains "corp.com"

# Fake NS record:
sudo python dnschef.py --fakens "ns1.attacker.com" --fakedomains "corp.com"

# Fake CNAME:
sudo python dnschef.py --fakecname "attacker.com" --fakedomains "corp.com"

# Fake TXT record (useful for testing SPF/DMARC checks):
sudo python dnschef.py --faketxt "v=spf1 all" --fakedomains "corp.com"

# Fake PTR record (reverse DNS):
sudo python dnschef.py --fakeptr "malware-host.attacker.com" \
  --fakedomains "50.14.10.192.in-addr.arpa"
```

## Config File Mode

For complex setups with many rules, use an INI config file instead of long command-line flags.

```
# Create dnschef.ini:
cat > dnschef.ini <<'EOF'
[A]
# Return fake A record for these domains:
*.corp.com=10.0.0.1
malware-c2.net=192.168.1.50
evil-domain.com=192.168.1.50

[MX]
# Redirect mail for corp.com to your server:
corp.com=mail.attacker.com

[CNAME]
cdn.corp.com=attacker.com
EOF

# Run with config file:
sudo python dnschef.py --file dnschef.ini --nameservers 8.8.8.8 -q

# The config file supports all record types as section headers:
# [A], [AAAA], [MX], [CNAME], [NS], [TXT], [PTR], [SOA]
# Wildcard prefix (*.) matches any subdomain
```

## Malware Analysis Lab Setup

```
# Typical lab architecture:
# [Malware VM] → DNS → [DNSChef on analysis host] → [sinkhole listener]
#                    → real DNS for OS traffic

# Step 1: Start a listener to capture C2 connections:
nc -lvnp 443     # or use Wireshark to capture on the interface

# Step 2: Start DNSChef with verbose mode on analysis host (e.g., 192.168.1.50):
sudo python dnschef.py \
  --fakeip 192.168.1.50 \
  --truedomains "windowsupdate.com,microsoft.com,digicert.com" \
  --nameservers 8.8.8.8 \
  --interface 192.168.1.50 \
  -q

# Step 3: Configure malware VM DNS:
# Windows: Set DNS = 192.168.1.50 (your analysis host)
# All malware C2 domains now resolve to 192.168.1.50

# Step 4: Run malware sample — watch DNSChef logs for C2 domain queries:
# [*] Cooking A: c2.malware-domain.com → 192.168.1.50
# [*] Cooking A: cdn.malware-domain.net → 192.168.1.50

# The malware connects to your listener — you capture traffic and certs
```

## Red Team Usage — DNS Interception in a Pentest

```
# Scenario: you control a network segment and want to redirect HTTP traffic
# through your proxy to intercept credentials

# Prerequisites: ARP poison or DHCP-based DNS injection to point
# target machines at your DNSChef instance

# Redirect all web traffic to your MitM proxy (e.g., Bettercap or mitmproxy):
sudo python dnschef.py --fakeip YOUR_IP --nameservers 8.8.8.8 -q

# Start mitmproxy to intercept the HTTP/HTTPS connections:
mitmproxy --mode transparent --listen-port 8080

# Set iptables to redirect port 80/443 to mitmproxy:
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080

# DNS log (-q) shows every query from intercepted hosts — useful for asset discovery:
# [*] Cooking A: internal-app.corp.com → YOUR_IP
# [*] Forwarding: windowsupdate.com → 8.8.8.8
```

## Resources

- DNSChef — `github.com/iphelix/dnschef`
- Related: [DNS Rebinding Attacks](/web/dns-rebinding/)
- Related: [Web Reconnaissance](/recon/web-recon/)
- Related: [Port Forwarding & Tunneling](/pivoting/port-forwarding/)
