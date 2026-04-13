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

## Masscan for Initial Host Discovery

```bash
# Masscan — fastest SYN scanner; ideal for large internal ranges
# Sends packets at configurable rate; does NOT do service detection
# Use masscan to find live hosts/ports, then nmap for detail

# Install
apt install masscan
# Or from source: github.com/robertdavidgraham/masscan

# Common internal network sweeps
# Start conservative (--rate 1000) to avoid flooding switches
masscan -p80,443,445,22,3389 192.168.1.0/24 --rate 1000

# Wider sweep — top 20 ports across /16
masscan -p21,22,23,25,53,80,110,135,139,143,389,443,445,636,3389,8080,8443 \
  10.0.0.0/16 --rate 5000

# All ports on a /24 (slower but thorough)
masscan -p0-65535 192.168.1.0/24 --rate 10000

# Save output formats
masscan -p445,80,443,3389 192.168.1.0/24 --rate 2000 \
  -oG masscan-grepable.txt    # greppable format
masscan -p445,80,443,3389 192.168.1.0/24 --rate 2000 \
  -oX masscan-xml.txt         # XML format
masscan -p445,80,443,3389 192.168.1.0/24 --rate 2000 \
  -oJ masscan-json.txt        # JSON format

# Extract live IPs from masscan output
grep "open" masscan-grepable.txt | awk '{print $4}' | sort -u > live_hosts.txt

# Resume interrupted scan
masscan --resume paused.conf

# Exclude specific IPs/ranges (avoid critical infrastructure)
masscan -p445 192.168.1.0/24 --rate 1000 \
  --excludefile /tmp/exclude.txt
# exclude.txt: one IP/range per line (192.168.1.1, 192.168.1.10/32)

# Two-phase workflow: masscan first, nmap second
masscan -p0-65535 192.168.1.0/24 --rate 50000 -oG masscan.txt
grep "open" masscan.txt | awk '{print $4}' | sort -u > targets.txt
nmap -sV -sC -p- -iL targets.txt -oA nmap_detailed --open
```

## Nmap Service/Version Detection and Timing Templates

```bash
# Timing templates: -T0 (paranoid) through -T5 (insane)
# -T3 = default (normal); -T4 = aggressive (fast, more noise)

# Standard recon workflow
nmap -T4 -sV -sC --open 192.168.1.0/24 -oA initial_scan

# Version detection only (no scripts — faster)
nmap -sV -T4 192.168.1.0/24 -p 22,80,443,445,3389 --open

# Comprehensive single-host scan
nmap -A -T4 -p- 192.168.1.10 -oA comprehensive_host

# Timing tuning for specific environments
nmap -T1 --max-retries 2 --min-rate 10 192.168.1.0/24  # stealth (very slow)
nmap -T4 --min-rate 1000 192.168.1.0/24                 # fast internal scan
nmap -T5 192.168.1.0/24                                  # insane (risky — drops packets)

# Parallel scanning — multiple hosts at once
nmap -T4 --min-parallelism 10 --max-parallelism 100 -iL targets.txt

# Host groups for organized output
nmap -T4 -sV -p- 192.168.1.10 -oA host_192.168.1.10
nmap -T4 -sV -p- 192.168.1.20 -oA host_192.168.1.20
```

## Nmap NSE Scripts for Common Network Targets

```bash
# SMB — shares, OS, signing, vulnerabilities
nmap --script smb-enum-shares,smb-os-discovery -p 445 192.168.1.0/24
nmap --script smb2-security-mode -p 445 192.168.1.0/24  # signing status
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.0/24   # EternalBlue
nmap --script smb-vuln-ms08-067 -p 445 192.168.1.0/24   # Conficker/MS08-067
nmap --script smb-enum-users -p 445 192.168.1.10         # user enumeration

# LDAP — DC/AD info
nmap --script ldap-rootdse -p 389 192.168.1.0/24
# Reveals: domain name, LDAP server version, supported controls
nmap --script ldap-search -p 389 192.168.1.10 \
  --script-args ldap.base="DC=contoso,DC=local"

# HTTP — title and server headers (quick web inventory)
nmap --script http-title,http-server-header -p 80,443,8080,8443 192.168.1.0/24

# HTTP auth methods
nmap --script http-auth-finder -p 80,443,8080 192.168.1.0/24

# RDP encryption and NLA status
nmap --script rdp-enum-encryption -p 3389 192.168.1.0/24

# SNMP enumeration
nmap --script snmp-info,snmp-sysdescr -p 161 -sU 192.168.1.0/24
nmap --script snmp-brute -p 161 -sU 192.168.1.0/24  # community string brute

# MS-SQL
nmap --script ms-sql-info,ms-sql-empty-password -p 1433 192.168.1.0/24

# VNC (no auth check)
nmap --script vnc-info,realvnc-auth-bypass -p 5900 192.168.1.0/24

# Multiple scripts combined — comprehensive target scan
nmap -p 21,22,23,25,80,110,135,139,143,389,443,445,636,1433,3306,3389,5900 \
  --script "not intrusive and not brute" \
  -sV 192.168.1.10
```

## Network Topology Mapping

```bash
# Build a map of routing boundaries and infrastructure devices

# Traceroute to multiple hosts — identify hop counts and routing paths
nmap -sn --traceroute 192.168.1.0/24
traceroute -T -p 80 10.10.10.1   # TCP traceroute (bypasses ICMP blocks)
traceroute -U -p 53 10.10.10.1   # UDP traceroute

# Identify network boundaries (where TTL exceeds hop)
for host in $(cat live_hosts.txt); do
    hops=$(traceroute -n -m 15 $host 2>/dev/null | tail -1 | awk '{print $1}')
    echo "$host: $hops hops"
done

# SNMP enumeration for network topology
# Routers and switches expose routing tables via SNMP
snmpwalk -c public -v2c 192.168.1.1 1.3.6.1.2.1.4.21   # ipRouteTable
snmpwalk -c public -v2c 192.168.1.1 1.3.6.1.2.1.17.4   # bridge table (MACs per port)
snmpwalk -c public -v2c 192.168.1.1 1.3.6.1.2.1.2.2.1  # interface table

# CDP/LLDP enumeration — discover switch topology
# CDP reveals: switch hostname, port, VLAN, capabilities
tcpdump -i eth0 'ether proto 0x2000' -v 2>/dev/null &  # CDP
tcpdump -i eth0 'ether proto 0x88cc' -v 2>/dev/null &  # LLDP
sleep 60; kill %1 %2

# ARP to build a host-to-MAC-to-port map
arp-scan --interface=eth0 192.168.1.0/24 > arp_scan.txt
# Look for OUI prefixes: 00:50:56 = VMware, 00:0c:29 = VMware Workstation,
# 00:1a:4b = Intel, c8:d3:ff = Dell

# Subnet discovery via route enumeration (once on a host)
# Windows: route print, ipconfig /all, arp -a
# Linux: ip route show, arp -n, cat /proc/net/arp
ip route show       # reveals all known subnets
netstat -rn         # routing table
arp -n              # ARP cache (known hosts)
```

## IPv6 Host Discovery

```bash
# IPv6 hosts don't respond to the same broadcast mechanisms as IPv4
# Different discovery techniques required

# alive6 (thc-ipv6 toolkit) — all-nodes multicast ping
# apt install thc-ipv6
alive6 eth0
# Sends ICMPv6 echo request to ff02::1 (all nodes on link)
# All IPv6-enabled hosts on the segment should respond

# ping6 all-nodes multicast
ping6 -I eth0 ff02::1
# Returns: all hosts with IPv6 link-local addresses (fe80::/10)

# Discover via Neighbor Discovery Protocol (NDP)
# Linux kernel learns neighbors automatically when you ping6 ff02::1
ip -6 neigh show
# Lists: IPv6 address, interface, MAC, state

# scan6 (thc-ipv6) — more thorough IPv6 host scan
scan6 -i eth0 -l -e -v
# -l = local network scan
# -e = generate from Ethernet MACs (EUI-64)

# nmap IPv6 sweep (requires known prefix)
# First discover prefix from alive6, then scan it
nmap -6 -sn fe80::1/64 --interface eth0       # link-local
nmap -6 -sn 2001:db8:1::/64 --interface eth0   # global prefix

# sipcalc — generate all possible EUI-64 addresses from MACs
# If you've captured MACs via ARP, derive their IPv6 link-local:
# Formula: Take MAC, insert ff:fe in middle, flip 7th bit
# 00:11:22:33:44:55 → fe80::0211:22ff:fe33:4455

# Detecting IPv6 in a network (passive)
tcpdump -i eth0 'ip6' -c 50 | head -20
# Look for: fe80:: addresses (link-local), ff02:: (multicast)
# NDP (Neighbor Discovery): ICMPv6 type 135 (NS) and 136 (NA)

# IPv6 DNS queries (via nmap)
nmap -6 --script ipv6-ra-flood,ipv6-multicast-mld-list -sn eth0
```

## Scanning through Proxychains

```bash
# When pivoting through a SOCKS proxy (Chisel, SSH, Meterpreter)
# proxychains routes TCP scans through the proxy

# Configure proxychains
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF

# IMPORTANT: proxychains only works with TCP (not ICMP or UDP)
# Use -sT (TCP connect scan) not -sS (SYN scan)
# Use -Pn (skip ping — ICMP won't work)

# Basic TCP scan through proxy
proxychains nmap -sT -Pn -T3 -p 22,80,443,445,3389 10.10.10.0/24

# Enumerate SMB through proxy
proxychains crackmapexec smb 10.10.10.0/24

# LDAP enumeration through proxy
proxychains ldapsearch -x -H ldap://10.10.10.10 -b "" -s base

# Web enumeration through proxy
proxychains curl -sk https://10.10.10.10/
proxychains whatweb http://10.10.10.10

# Firefox through proxy (for web GUIs)
proxychains firefox &

# Note on speed: proxychains scans are MUCH slower than direct
# Use smaller port ranges and target specific hosts
# Masscan does NOT work through proxychains (raw socket, no TCP)

# Alternative: Metasploit route (for Meterpreter pivots)
# msf> route add 10.10.10.0/24 SESSION_ID
# msf> use auxiliary/scanner/portscan/tcp
# set RHOSTS 10.10.10.0/24; set PORTS 445,80,443; run
```

## OPSEC: Scanning Noise and How to Reduce It

```bash
# Default nmap/masscan activity is extremely visible to defenders
# IDS, XDR, and SIEM all flag rapid port scanning patterns

# Noise profile of common scan types:
# nmap -sS (default): SYN to every port → RST flood on closed ports → obvious
# masscan: millions of SYNs/sec → link saturation + IDS alert
# nmap -A: OS detection sends unusual probes (TCP null, FIN, Xmas) → fingerprinted

# Reducing noise:

# 1. Rate limiting
nmap --min-rate 50 --max-rate 200 192.168.1.10      # very slow
masscan -p445,80 192.168.1.0/24 --rate 100          # masscan at sane rate

# 2. Targeted scanning (only what you need)
# Bad: nmap -p- (all 65535 ports)
# Good: nmap -p 22,80,443,445,3389 (just the targets you care about)

# 3. Avoid aggressive scan modes
# nmap -T5 = insane (immediately detected)
# nmap -T3 or -T2 = much quieter

# 4. Avoid Nmap scripting engine on discovery phase
# Scripts like smb-vuln-ms17-010 send exploit probes → IDS signature matches
# Run vuln scripts only against confirmed high-value targets

# 5. Use passive discovery before active scanning
# Check ARP cache, listen to broadcasts, read DHCP logs → no scan traffic

# 6. Blend with normal traffic
# Scan on port 80, 443 (common) rather than obscure ports
# Scan at business hours (more traffic, harder to distinguish from normal)
# Spread scan over hours, not seconds

# 7. Source IP rotation (if you have access to multiple IPs)
nmap -D RND:10 192.168.1.10      # 10 decoys + real IP
# Defenders see 11 source IPs; harder to determine real attacker

# 8. Segment your scan targets
# Scan non-critical hosts first; save DCs and security appliances for last
# Most detections trigger on volume, not single hosts

# 9. Use passive tools as a complement
# Responder -A, netdiscover -p, arp -n
# Reveals hosts without sending a single probe packet
```

## Resources

- Nmap book — `nmap.org/book/`
- Masscan — `github.com/robertdavidgraham/masscan`
- CrackMapExec — `github.com/byt3bl33d3r/CrackMapExec`
- thc-ipv6 (alive6, scan6) — `github.com/vanhauser-thc/thc-ipv6`
- proxychains-ng — `github.com/rofl0r/proxychains-ng`
- MITRE T1046 — Network Service Discovery — `attack.mitre.org/techniques/T1046/`
- MITRE T1018 — Remote System Discovery — `attack.mitre.org/techniques/T1018/`
