---
layout: training-page
title: "Network Scanning & Mapping — Red Team Academy"
module: "Network Attacks"
tags:
  - nmap
  - masscan
  - network-scanning
  - host-discovery
  - service-enumeration
page_key: "network-scanning"
render_with_liquid: false
---

# Network Scanning & Mapping

Effective network scanning builds an accurate picture of the target environment: live hosts, open ports, running services, OS versions, and network topology. Speed and stealth are in tension — tune scans for the operational context.

## Host Discovery

```bash
# Ping sweep — fast, but firewalls block ICMP
nmap -sn 192.168.1.0/24

# ARP scan — reliable on local segment, not blocked by host firewalls
nmap -sn -PR 192.168.1.0/24
arp-scan -l                        # local subnet via ARP
arp-scan --interface=eth0 192.168.1.0/24

# netdiscover — passive + active ARP discovery
netdiscover -r 192.168.1.0/24     # active
netdiscover -p                    # passive mode — listen for ARP traffic

# masscan — port scan at line rate (also reveals live hosts)
masscan -p80,443,445,22 192.168.1.0/24 --rate 10000

# nbtscan — discover Windows hosts via NetBIOS
nbtscan 192.168.1.0/24

# fping — ICMP sweep
fping -a -g 192.168.1.0/24 2>/dev/null

# Multiple techniques to avoid missing hosts
nmap -sn -PE -PP -PS21,22,23,25,80,443,445,3389 -PA80,443 192.168.1.0/24
```

## Fast Port Scanning with Masscan

```bash
# masscan — fastest scanner available; sends packets at multi-million/sec
# Useful for scanning /8 or /16 ranges quickly

# Common ports — internal network
masscan -p21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443 \
  192.168.0.0/16 --rate 50000

# All ports on a subnet
masscan -p0-65535 192.168.1.0/24 --rate 100000

# Save output for nmap follow-up
masscan -p0-65535 192.168.1.0/24 --rate 50000 -oG masscan.txt

# Extract live IPs for nmap follow-up
grep "open" masscan.txt | awk '{print $4}' | sort -u > live_hosts.txt
```

## Nmap — Service and Version Detection

```bash
# Standard service scan on known live hosts
nmap -sV -sC -p- -iL live_hosts.txt -oA full_scan

# Top 1000 ports — faster initial sweep
nmap -sV -sC -iL live_hosts.txt -oA initial

# OS detection
nmap -O -sV 192.168.1.10

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A 192.168.1.10

# UDP scan (slow — target key UDP services)
nmap -sU -p 53,67,68,69,111,123,135,137,138,161,500,514,1900 192.168.1.0/24

# Nmap output formats
nmap ... -oN output.txt   # normal
nmap ... -oG output.grep  # greppable
nmap ... -oX output.xml   # XML (for parsers)
nmap ... -oA output       # all three formats
```

## Targeted Protocol Enumeration

```bash
# SMB (445) — enumerate shares, OS, signing status
nmap --script smb-enum-shares,smb-os-discovery,smb2-security-mode -p 445 192.168.1.0/24
crackmapexec smb 192.168.1.0/24

# SMB signing check (for NTLM relay targets)
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# LDAP (389/636) — enumerate domain info
nmap --script ldap-rootdse -p 389 192.168.1.0/24
ldapsearch -x -H ldap://192.168.1.10 -b "" -s base

# RDP (3389) — check NLA enforcement
nmap --script rdp-enum-encryption -p 3389 192.168.1.0/24

# HTTP/HTTPS — service fingerprinting
nmap --script http-title,http-server-header -p 80,443,8080,8443 192.168.1.0/24
whatweb http://192.168.1.10

# SNMP (161) — community string bruteforce + MIB walk
nmap --script snmp-brute 192.168.1.0/24
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt \
  -i live_hosts.txt
snmpwalk -c public -v2c 192.168.1.10

# DNS (53) — zone transfer, reverse lookups
nmap --script dns-zone-transfer -p 53 192.168.1.10
dig axfr @192.168.1.10 corp.local
```

## Stealth Scanning Techniques

```bash
# SYN scan (default for root — never completes TCP handshake)
nmap -sS 192.168.1.10

# Slow scan to evade IDS rate-based detection
nmap -sS -T1 192.168.1.0/24        # Paranoid (very slow)
nmap -sS -T2 192.168.1.0/24        # Sneaky

# Decoy scan — make scan appear from multiple sources
nmap -D RND:10 192.168.1.10        # 10 random decoys
nmap -D 192.168.1.5,192.168.1.6,ME 192.168.1.10

# Fragmented packets — may evade stateless packet inspection
nmap -f 192.168.1.10

# Source port manipulation — appear to come from port 80 or 443
nmap --source-port 443 192.168.1.10

# Randomize host order
nmap --randomize-hosts 192.168.1.0/24

# Spoof source MAC (only works on local segment)
nmap --spoof-mac 0 192.168.1.10    # random MAC
nmap --spoof-mac AA:BB:CC:DD:EE:FF 192.168.1.10
```

## Network Topology Mapping

```bash
# Traceroute to identify routing paths and network boundaries
nmap -sn --traceroute 192.168.1.0/24
traceroute 10.10.10.1

# Identify routers and default gateways
ip route show
arp -n
netstat -rn

# Nmap with path discovery
nmap --traceroute -sn 10.0.0.0/8 -iL subnets.txt

# Identify firewall/NAT boundaries
# TTL decrements: look for hops where TTL-1 hits 0
# RST vs ICMP unreachable on filtered ports reveals security devices
```

## Post-Compromise Internal Recon

```bash
# From a compromised Windows host (no tools)
net view /domain
net view \\DC01
ipconfig /all
arp -a
route print
netstat -ano

# PowerShell network enumeration
Get-NetIPConfiguration
Get-NetNeighbor
Get-NetRoute
Test-NetConnection -ComputerName DC01 -Port 445

# From Linux pivot
# With nmap tunneled through SOCKS proxy (via Chisel)
proxychains nmap -sT -Pn 10.10.10.0/24 -p 445,80,443

# With CrackMapExec via SOCKS
proxychains crackmapexec smb 10.10.10.0/24
```

## Resources

- Nmap book — `nmap.org/book/`
- Masscan — `github.com/robertdavidgraham/masscan`
- CrackMapExec — `github.com/byt3bl33d3r/CrackMapExec`
- MITRE T1046 — Network Service Discovery — `attack.mitre.org/techniques/T1046/`
- MITRE T1018 — Remote System Discovery — `attack.mitre.org/techniques/T1018/`
