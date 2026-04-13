---
layout: training-page
title: "Spear Phishing — Red Team Academy"
module: "Social Engineering"
tags:
  - spear-phishing
  - social-engineering
  - targeted-attack
  - initial-access
page_key: "se-spear-phishing"
render_with_liquid: false
---

# Spear Phishing

Spear phishing is highly targeted phishing personalized to a specific individual using intelligence gathered during reconnaissance. Where mass phishing relies on volume, spear phishing relies on relevance — a believable email from a known sender about something the target actually cares about.

## Target Selection

```
# High-value targets (most likely to have access worth stealing):
IT administrators        — VPN, AD, cloud console credentials
Finance / accounting     — wire transfer authority, banking access
HR                       — employee PII, payroll system access
Executives               — email access, approval authority (BEC)
Help desk                — can reset passwords, grant access
DevOps / engineering     — code repos, CI/CD, cloud infrastructure

# Soft targets (less security-aware, more likely to click):
New employees            — unfamiliar with processes, eager to comply
Remote workers           — less oversight, used to receiving IT emails
Contractors              — less trained, less integrated with security culture
```

## Target Profiling Workflow

```
# 1. Find the target on LinkedIn
#    - Current role, tenure, recent activity, connections
#    - What tools/platforms they mention ("Excited to start using Salesforce")
#    - Who they report to, who reports to them

# 2. Check social media (Twitter/X, Facebook)
#    - Personal interests for rapport-building lures
#    - Travel / OOO patterns ("Flying to NYC for the conference")
#    - Complaints about work tools (reveals stack)

# 3. Search for email address
theHarvester -d target-corp.com -b all
# Or use hunter.io, clearbit, email format permutation

# 4. Check data breach databases
# haveibeenpwned.com — check if target email is in breaches
# DeHashed, Snusbase — breach search with password history

# 5. Review GitHub / public repos
# Look for commits with target's email, personal repos, leaked credentials

# 6. Check company website, press releases, blog posts
#    - Recent projects, partnerships, technology decisions
```

## Lure Personalization Techniques

### Context-Aware Lures

```
# Use recent events the target would recognize
"Hi [Name], following up on the Salesforce migration we discussed at
 [Company] All-Hands last week — the IT team needs your confirmation
 before we can migrate your account."

# Reference their manager by name
"[Manager name] asked me to reach out to you directly about the
 pending access review for your team."

# Reference their current project (from LinkedIn/GitHub)
"Regarding the Azure migration project your team is working on —
 there's a required security configuration step before go-live."

# Use their timezone / location context
"Hi [Name], I noticed you logged in from [city] earlier today — our
 system flagged this as unusual. Please verify your identity."
```

### Sender Spoofing & Impersonation

```
# Spoof a known internal contact (requires bypassing DMARC or using lookalike)
From: "John Smith (IT)" <jsmith@c0ntoso.com>

# Compromise a real account and use it (internal spearphishing - T1534)
# Most effective — emails come from legitimate domain with no spoofing

# Use a display name match to a known contact
From: "Sarah Johnson" <noreply@helpdesk-portal.com>
# Target sees "Sarah Johnson" in mail client, may not check address

# Reply-chain injection — reply to a real existing email thread
# Requires knowing the thread context (from OSINT or prior access)
```

## Multi-Stage Spear Phishing

```
# Stage 1: Rapport building email (no malicious content)
"Hi [Name], I'm [Persona] reaching out about [legitimate topic].
 Would you have 15 minutes to connect this week?"

# Stage 2: Follow-up with payload after reply
"Great speaking with you — as mentioned, here's the document
 we discussed. Let me know if you have any issues accessing it."

# This works because:
# - Target is expecting an email from you
# - They've already engaged once (lowered guard)
# - SEGs may whitelist the sender after the first benign exchange
```

## Delivery via Third-Party Platforms

```
# LinkedIn InMail
# — High trust, professional context, bypasses email security entirely
# — "Saw your profile — I work with [mutual connection] and wanted to share..."

# Microsoft Teams / Slack (external messaging)
# — If tenant allows external messages
# — Impersonate a vendor or partner
# — See T1566.003 — Spear Phishing via Service

# SMS (Smishing)
# — Harder to verify sender, direct to mobile
# — See smishing page for details

# Phone call (Vishing)
# — After email to warm the target
# — "I sent you an email earlier — did you get a chance to look at it?"
```

## Spear Phishing Checklist

```
[ ] Target profiled — role, tools, manager, recent activity
[ ] Lure personalized with at least 2 specific details
[ ] Sender identity chosen and configured
[ ] Email passes SPF, DKIM, DMARC
[ ] Landing page or attachment ready and tested
[ ] Tracking pixel or unique link configured
[ ] Objection handling prepared
[ ] Timing selected — Tuesday-Thursday 9-11am best open rates
```

---

## Target Research Workflow

### LinkedIn Recon

```
# Full name search — find all employees at a company
site:linkedin.com/in "Contoso" "IT Manager"

# Google dork for specific tech stack roles
site:linkedin.com/in "Contoso" "CrowdStrike OR ServiceNow OR Intune"

# LinkedIn Sales Navigator (paid — provides full org chart, contact details)
# Free alternative: LinkSpy, PhantomBuster for public profile scraping

# Key fields to capture per target:
Name, current title, department, manager (from "reports to" or profile)
Tools mentioned in experience or about section
Recent activity (posts, likes, reactions — reveals projects and interests)
Connections who also work at the target company (for social proof in lures)
```

### Email Format Discovery

```bash
# Method 1: hunter.io domain search
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY" \
  | python3 -m json.tool

# Method 2: theHarvester multi-source
theHarvester -d target.com -b linkedin,google,bing,baidu -l 500

# Method 3: Email permutation
# Once you know one email address, permute others
# Tools: emailhippo, email-format.com, or manual permutation

# Common formats to test:
# first.last@corp.com
# flast@corp.com
# first@corp.com
# firstname.lastname@corp.com

# Verify without sending (SMTP VRFY or RCPT TO probe):
smtp-user-enum -M RCPT -u john.smith -d target.com -t mail.target.com
```

### Org Chart Mapping

```
# Sources for org structure:
LinkedIn      — direct reports, managers, team sizes
SEC filings   — named executives and board members (public companies)
Company website — leadership page, team pages
Press releases — "John Smith, VP of IT, commented..."
Glassdoor     — reviews often mention manager names and team structure
ZoomInfo      — commercial; org chart and direct email/phone data
Apollo.io     — similar to ZoomInfo, has a free tier

# Build a hierarchy diagram:
# C-suite → VP level → Director level → Manager level → Individual contributor
# Note: targeting the layer below decision-makers often more effective
# (they execute requests without the authority skepticism of executives)
```

---

## Email Infrastructure Setup

### Domain Selection and Registration

```bash
# Typosquatting — one character different
contoso.com → cont0so.com, cntoso.com, contos0.com

# Lookalike domains — plausibly related
contoso.com → contoso-it.com, contoso-helpdesk.com, it-contoso.com

# Homoglyph domains (Unicode lookalikes — IDN)
# Requires IDN-compatible registrar (Namecheap supports this)
# а = Cyrillic 'a', looks identical to Latin 'a' in most fonts
# paypal.com → pаypal.com (Cyrillic а in position 1)

# Domain aging — buy domain 30+ days before use
# New domains score higher in spam filters and Safe Browsing
# Best: purchase expired domain with existing reputation
# Tools: expireddomains.net, domcop.com

# Registrar recommendations:
# Namecheap — anonymous purchase with crypto, cheap, no fuss
# Porkbun    — competitive pricing, WHOIS privacy included free
# Njalla     — privacy-focused, accepts crypto, no KYC for basic registration
```

### SPF / DKIM / DMARC Setup

```bash
# Step 1: SPF record — authorize your mail server IP
# DNS TXT record for your phishing domain:
# _spf.attacker.com  TXT  "v=spf1 ip4:1.2.3.4 ~all"
# Use -all (hard fail) only if all legitimate sources are covered
# Use ~all (soft fail) for testing

# Step 2: DKIM — sign outbound mail
# Install opendkim on your mail server
sudo apt install opendkim opendkim-tools

# Generate keypair
opendkim-genkey -t -s mail -d attacker.com
# Creates: mail.private (private key) and mail.txt (DNS record)

# Add DNS record (TXT):
# mail._domainkey.attacker.com  TXT  "v=DKIM1; k=rsa; p=<pubkey_from_mail.txt>"

# Step 3: DMARC record
# _dmarc.attacker.com  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@attacker.com"
# p=none: monitoring only (collect reports, don't block)
# p=quarantine: failed messages go to spam
# p=reject: failed messages rejected — use sparingly

# Verify your setup before sending:
# 1. Send to mail-tester.com unique address
# 2. Check score (aim for 9+/10)
# 3. Verify: mxtoolbox.com/SuperTool — test SPF, DKIM, DMARC
```

---

## Payload Selection Matrix

The 2026 landscape has significantly changed attachment-based payload delivery. Default policies from Microsoft and Google have made many historical techniques less reliable.

### Current Payload Landscape

```
Office Macros (.docm, .xlsm):
  Status: BLOCKED by default on all Office 365 tenants (since 2022 policy rollout)
  Blocked: Mark of the Web (MOTW) triggers block for internet-sourced files
  Still works: Internal delivery from compromised account, network share delivery
  Bypass: Password-protected ZIP (breaks MOTW propagation in some configs)
           Macro-enabled templates via .dotm (less blocked than .docm)

LNK files:
  Status: Widely used 2021–2023; now commonly flagged by EDR
  Delivery: ZIP attachment, ISO file
  Effectiveness: Depends on EDR configuration; still viable on unmanaged endpoints

ISO / IMG disk images:
  Status: MOTW bypass closed in Windows 11 22H2 (Oct 2022) — ISO now propagates MOTW
  Effectiveness: Significantly reduced; legacy Windows still vulnerable

HTML Smuggling:
  Status: MOST EFFECTIVE in 2026 for attachment-based delivery
  How it works: JavaScript constructs the payload in the browser from base64 chunks
                The email gateway scans an HTML file (not a PE/Office file)
                Browser assembles and downloads the real payload
  Delivery: .html or .htm attachment, or link to hosted HTML page
  Detection: EDR will flag the downloaded payload on execution; HTML itself is clean

OneNote (.one) attachments:
  Status: Heavily blocked by Defender and email gateways since 2023
  Previously used to embed HTA/exe files inside OneNote pages

Signed executables / LOLBins:
  Status: High effectiveness for payload execution once delivered
  Use MSBuild.exe, regsvr32.exe, certutil.exe, mshta.exe to execute payloads
  Delivery: Dropped via HTML smuggling or hosted on attacker infrastructure
```

### Payload Decision Matrix

```
Scenario                          | Recommended Approach
----------------------------------|------------------------------------------
Unmanaged endpoint, no EDR        | Office macro or LNK via ISO
Managed endpoint, Defender only   | HTML smuggling → LOLBin dropper
Full EDR (CrowdStrike, SentinelOne)| HTML smuggling → signed loader → shellcode
Credential capture only (no exec) | Evilginx AiTM or GoPhish credential page
Linux / macOS target              | Shell script in ZIP, AppleScript, .dmg dropper
High-security target (SOC monitored)| Staged delivery — benign first, payload later
```

---

## GoPhish Campaign Setup

```bash
# Download and run GoPhish
wget https://github.com/gophish/gophish/releases/latest/download/gophish-linux-amd64.zip
unzip gophish-linux-amd64.zip
chmod +x gophish
./gophish
# Admin UI: https://localhost:3333
# Default: admin / gophish — CHANGE THE PASSWORD IMMEDIATELY

# Step 1: Create a Sending Profile
# Settings: SMTP host/port, username/password, from address
# Example SMTP: your Postfix server or Amazon SES

# Step 2: Create Email Template
# - Import from URL (GoPhish clones real email layouts)
# - Variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.Position}}
# - Add tracking: GoPhish auto-embeds tracking pixel — do not remove
# - Add phishing URL: {{.URL}} — GoPhish auto-substitutes per-target link

# Step 3: Create Landing Page
# - Import site: Enter the URL of the real login page to clone
# - GoPhish downloads HTML/CSS/JS and hosts locally
# - Enable "Capture Submitted Data" and "Capture Passwords"
# - Set Redirect URL (where to send user after submission)

# Step 4: Create Target Group
# CSV format: First Name,Last Name,Email,Position
# Example:
# John,Smith,j.smith@target.com,IT Manager
# Jane,Doe,j.doe@target.com,Finance Director

# Step 5: Launch Campaign
# Set: Name, Email Template, Landing Page, URL (your GoPhish listener IP/domain)
# Sending Profile, Launch Date, Groups
# Review and launch

# Monitor results:
# Dashboard shows: Sent, Opened, Clicked, Submitted Data, Email Reported
```

---

## Bypassing Email Security Gateways

### SEG Evasion Techniques

```
# 1. Password-protected attachments
# SEGs cannot detonate password-protected archives
# Include the password in the email body — humans can use it, most sandboxes cannot
# Example: "The document is password-protected: Contoso2026"

# 2. HTML Smuggling
# Payload is assembled in the browser; email body/attachment is pure HTML
# SEG scans HTML — no malicious content found
# Browser assembles payload via JavaScript Blob API and triggers download

# 3. Redirect chains via trusted services
# Link → legitimate service (Google, Bing, LinkedIn redirect) → attacker site
# SEG follows the redirect — sees google.com — allows
# Target follows the redirect — reaches attacker landing page
# Example:
# https://www.google.com/url?q=https://attacker.com/verify

# 4. Use trusted cloud hosting for payload delivery
# Host the payload on: GitHub Releases, Azure Blob, AWS S3, Dropbox
# SEG typically allowlists these domains
# Payload is at: https://github.com/real-looking-org/releases/tool.zip

# 5. Delayed payload activation
# Landing page returns 404 or benign content at SEG scan time
# Activate after 30–60 minutes (after SEG has scanned and cached result)
# Use IP filtering — only serve payload to corporate IP ranges

# 6. Browser fingerprinting on landing page
# Check user-agent, screen resolution, timezone before serving payload
# If user-agent matches a headless browser (HeadlessChrome), serve 404
# Only serve credential page to matching browser profiles
```

### Sandbox Detection on Landing Pages

```javascript
// Detect sandbox/automated scanners before serving phishing content
// Include in landing page JavaScript:

(function() {
  // Check for real mouse movement (bots don't move the mouse)
  var moved = false;
  document.addEventListener('mousemove', function() { moved = true; });

  // Check for real screen dimensions
  var realScreen = (screen.width > 800 && screen.height > 600);

  // Check timezone is consistent with target geography
  var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  var targetTZ = ["America/New_York", "America/Chicago", "America/Los_Angeles"];

  // After 2 seconds, decide whether to show the phishing page
  setTimeout(function() {
    if (moved && realScreen) {
      // Show real phishing content
      document.getElementById('login-form').style.display = 'block';
    } else {
      // Redirect to a benign page
      window.location.href = 'https://www.google.com';
    }
  }, 2000);
})();
```

---

## Tracking Opens and Clicks Without Triggering Sandboxes

```
# Problem: SEGs and sandboxes follow your tracking links and pollute metrics
# A "click" from a sandbox IP looks like a real click but is not

# Technique 1: Per-target unique tokens
# Generate UUID per target
import uuid
targets = [{"email": "john@corp.com", "token": str(uuid.uuid4())}]
# Link: https://attacker.com/verify?t=<uuid>
# Correlate token to target in backend

# Technique 2: Tracking pixel with IP filtering
# Log every request to the pixel
# Filter out known scanner/VPN/cloud IP ranges
# Use MaxMind GeoIP or ipinfo.io to filter non-target IPs

# Technique 3: JavaScript-based beacons (not loaded by SEG link scanners)
# SEGs typically don't execute JavaScript when scanning
# Embed beacon in page JS rather than as a direct image tag

# Technique 4: Time-delayed response
# Page shows spinner for 3 seconds before redirecting
# SEG follows the initial URL but may not wait for the redirect
# Record the "real" hit based on whether the target reached the second page

# Technique 5: CAPTCHA gate
# Require a simple click/CAPTCHA before serving credential form
# Bots/scanners will not complete the CAPTCHA
# Adds ~0% friction for real humans
```

---

## Resources

- MITRE T1566.001 — Spear Phishing Attachment — `attack.mitre.org/techniques/T1566/001/`
- MITRE T1566.002 — Spear Phishing Link — `attack.mitre.org/techniques/T1566/002/`
- MITRE T1566.003 — Spear Phishing via Service — `attack.mitre.org/techniques/T1566/003/`
- theHarvester — email harvesting — `github.com/laramies/theHarvester`
- hunter.io — email format discovery — `hunter.io`
- GoPhish — open source phishing framework — `github.com/gophish/gophish`
- Evilginx — AiTM phishing — `github.com/kgretzky/evilginx2`
- HTML Smuggling explained — `outflank.nl/blog/2018/08/14/html-smuggling-explained/`
- expireddomains.net — aged domain search
