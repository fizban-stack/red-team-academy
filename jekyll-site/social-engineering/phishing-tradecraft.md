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
---
<h1>Phishing Tradecraft</h1>
<p>Phishing tradecraft covers the infrastructure, lure design, and delivery techniques that make phishing campaigns effective and hard to block. This page focuses on the craft and evasion; for tooling see GoPhish and Evilginx pages.</p>

<h2>Infrastructure Setup</h2>
<h3>Domain Selection</h3>
<pre><code># Typosquatting techniques
contoso.com       → cont0so.com, contos0.com, cntoso.com
microsoft.com     → microsofft.com, micosoft.com

# Lookalike domains
contoso.com       → contoso-support.com, contoso-helpdesk.com
                    login-contoso.com, contoso.com.attacker.com

# IDN homograph (Unicode lookalikes)
# а (Cyrillic) looks identical to a (Latin)
paypal.com        → pаypal.com  (Cyrillic а)

# Domain aging — buy 30+ days before use to avoid newness flags
# Use aged domains or purchase expired domains with history</code></pre>

<h3>Email Authentication (Required)</h3>
<pre><code># SPF — authorize your sending IP
_spf.attacker.com TXT "v=spf1 ip4:1.2.3.4 -all"

# DKIM — sign outgoing mail
# Generate keypair, publish public key in DNS
opendkim-genkey -t -s mail -d attacker.com
# DNS: mail._domainkey.attacker.com TXT "v=DKIM1; k=rsa; p=&lt;pubkey&gt;"

# DMARC — required to pass corporate spam filters
_dmarc.attacker.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@attacker.com"

# Check your configuration
swaks --to target@corp.com --from support@attacker.com \
  --server mail.attacker.com --auth LOGIN \
  --header "Subject: Test" --body "Test"

# Score your email before sending
# mail-tester.com, mxtoolbox.com/emailhealth</code></pre>

<h3>Mail Server Options</h3>
<pre><code>GoPhish         — purpose-built phishing server (tracking built in)
Postfix + DKIM  — manual setup, full control
Mailgun/SendGrid — commercial relay (risky — TOS violations, logging)
Amazon SES      — reliable deliverability, requires domain verification</code></pre>

<h2>Lure Design</h2>
<h3>High-Converting Lure Themes</h3>
<pre><code>Password expiry         — "Your password expires in 24 hours"
MFA enrollment          — "Action required: enroll in MFA by Friday"
Shared document         — "John Smith shared a document with you" (O365/Google)
Voicemail notification  — "You have a new voicemail" (with audio file attachment)
Package delivery        — "Your package could not be delivered" (FedEx/UPS/Amazon)
Payroll / benefits      — "Your W-2 is ready" / "Benefits enrollment closes today"
Security alert          — "Suspicious sign-in detected from [target's city]"
IT ticket update        — "Your ticket #INC-48821 has been updated"</code></pre>

<h3>HTML Lure Cloning</h3>
<pre><code># Clone legitimate pages with HTTrack or wget
wget --mirror --convert-links --page-requisites \
  -P ./clone https://login.microsoftonline.com/

# Or use GoPhish's built-in site importer
# GoPhish > Landing Pages > Import Site

# Modify the form action to point to your credential capture endpoint
# Remove/replace tracking pixels from the original</code></pre>

<h3>Attachment Lures</h3>
<pre><code>Macro-enabled Office docs (.docm, .xlsm)
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
   — See: evasion/html-smuggling</code></pre>

<h2>Bypassing Email Security</h2>
<pre><code># Common email security layers to bypass:
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
#    Only serve payload to targets with matching user-agent / IP range</code></pre>

<h2>Tracking &amp; Metrics</h2>
<pre><code># GoPhish auto-tracks:
# - Email opened (1x1 pixel beacon)
# - Link clicked (redirect through GoPhish server)
# - Credentials submitted (form capture)

# Custom tracking pixel
&lt;img src="https://track.attacker.com/open/{% raw %}{{.RId}}{% endraw %}" width="1" height="1" /&gt;

# Per-target unique links
https://attacker.com/verify?token=&lt;unique-per-target-token&gt;

# Key metrics to report
Click rate          = clicks / sent
Submission rate     = submissions / clicks  
Time-to-first-click = timestamp of first click - send time</code></pre>

<h2>Operational Security</h2>
<pre><code># Separate infrastructure per campaign
# Never reuse phishing domains across engagements
# Use redirectors — phishing domain → redirector → credential capture server
# Strip identifying headers from outbound mail
# Use HTTPS on landing pages (Let's Encrypt)
# Rotate infrastructure if campaign is burned

# Check if your domain is blocked before sending
curl -s "https://transparencyreport.google.com/safe-browsing/search?url=attacker.com"
mxtoolbox.com/blacklists — check MX/IP blacklists</code></pre>

<h2>Resources</h2>
<ul>
  <li>GoPhish — <code>github.com/gophish/gophish</code></li>
  <li>Evilginx — AiTM credential capture — <code>github.com/kgretzky/evilginx2</code></li>
  <li>mail-tester.com — spam score checker</li>
  <li>Phishing Frenzy — campaign management — <code>github.com/pentestgeek/phishing-frenzy</code></li>
  <li>MITRE T1566 — Phishing — <code>attack.mitre.org/techniques/T1566/</code></li>
</ul>
