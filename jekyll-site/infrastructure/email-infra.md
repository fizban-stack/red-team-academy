---
layout: training-page
title: "Phishing Email Infrastructure — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - phishing
  - email
  - smtp
  - gophish
page_key: "infrastructure-email-infra"
render_with_liquid: false
---

# Phishing Email Infrastructure

Email phishing remains the dominant initial access vector in red team operations. A well-configured email infrastructure with proper SPF, DKIM, and DMARC records, combined with a warmed domain, achieves inbox placement at enterprise targets — bypassing spam filters and making technical detection difficult.

## Domain Warming

A freshly registered domain used for phishing will be flagged by spam filters before the first email is sent. Domain warming establishes a sending history that raises the reputation score.

### Warming Timeline

```
Week 1 — Establishment:
  - Host legitimate website on domain
  - Submit for categorization (Fortiguard, Talos)
  - Send 5-10 internal test emails per day between your own mailboxes
  - Verify: email to Gmail, Outlook, Yahoo — check spam folder placement

Week 2 — Light Volume:
  - Increase to 20-50 emails per day
  - Mix of text-only and HTML emails
  - Send to real email addresses (honeypot mailboxes you control)
  - Target: 100% inbox placement across Gmail/Outlook/Yahoo

Week 3 — Pre-Campaign:
  - Send 50-100 emails per day
  - Introduce attachments (non-malicious — PDF, docx)
  - Test domain-specific spam score at mail-tester.com (target: 10/10)
  - Verify DKIM signatures are valid via MXToolbox

Campaign:
  - Execute phishing campaign
  - Monitor: bounce rate, complaint rate (keep below 0.1%)
```

### Warming Email Content

```
Warming emails should look legitimate:

Example warming email:
From: noreply@yourphishingdomain.com
To: test@yourhoneypotmailbox.com
Subject: Q4 Newsletter

Body: Plain text or simple HTML newsletter content.
      No attachments. No links to suspicious domains.
      Professional tone. Corporate-relevant topic.

Goal: Spam filters see: real domain, real MTA, real DKIM, real content.
      Reputation builds organically.
```

## SPF Record Configuration

Sender Policy Framework (SPF) tells receiving mail servers which IP addresses are authorized to send email for your domain.

```dns
# Add to DNS for phishingdomain.com:

# Basic SPF — authorize your mail server only
phishingdomain.com.  IN  TXT  "v=spf1 ip4:[YOUR_MTA_IP] ~all"

# If using SMTP relay (SendGrid, Mailgun):
phishingdomain.com.  IN  TXT  "v=spf1 ip4:[YOUR_MTA_IP] include:sendgrid.net ~all"

# SPF qualifiers:
# +all  — allow any sender (never use — bypasses SPF entirely)
# ~all  — softfail — suspicious but deliver (recommended for phishing — less likely to bounce)
# -all  — hardfail — reject unauthorized senders
# ?all  — neutral — no policy

# For phishing domains: use ~all (softfail) initially
# Allows delivery while building reputation; upgrade to -all if needed for legitimacy
```

```bash
# Verify SPF record published correctly
dig +short TXT phishingdomain.com | grep spf
# Expected: "v=spf1 ip4:x.x.x.x ~all"

# Test SPF validation
# MXToolbox: https://mxtoolbox.com/spf.aspx
# Or: send email and check received headers for SPF result
# Look for: Received-SPF: pass (... designated sender)
```

## DKIM Configuration

DomainKeys Identified Mail (DKIM) adds a cryptographic signature to outgoing emails, allowing receiving servers to verify the email was sent by an authorized server and was not modified in transit.

### Key Generation

```bash
# Generate 2048-bit RSA key pair for DKIM
mkdir -p /etc/dkim/keys/phishingdomain.com
cd /etc/dkim/keys/phishingdomain.com

# Generate key pair
openssl genrsa -out phishingdomain.com.private 2048
openssl rsa -in phishingdomain.com.private -pubout -out phishingdomain.com.public

# Format public key for DNS TXT record (remove headers, concatenate)
PUBLIC_KEY=$(cat phishingdomain.com.public | grep -v 'PUBLIC KEY' | tr -d '\n')
echo "v=DKIM1; k=rsa; p=$PUBLIC_KEY"
```

### DNS TXT Record for DKIM

```dns
# Selector format: [selector]._domainkey.[domain]
# Common selector names: default, mail, email, s1, dkim2024

mail._domainkey.phishingdomain.com.  IN  TXT  "v=DKIM1; k=rsa; p=[PUBLIC_KEY_HERE]"

# Example with actual base64 key (truncated):
mail._domainkey.phishingdomain.com.  IN  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkq...AQAB"

# Note: TXT records have 255 character limit per string
# Split large keys using quoted strings:
mail._domainkey.phishingdomain.com.  IN  TXT  (
    "v=DKIM1; k=rsa; p="
    "MIIBIjANBgkqhkiG9w0BAQEFAAOC"
    "AQ8AMIIBCgKCAQEA..."
    "AQAB" )
```

### Postfix DKIM Integration (OpenDKIM)

```bash
# Install OpenDKIM
apt install opendkim opendkim-tools

# /etc/opendkim.conf
Mode                  sv
Syslog                yes
Socket                local:/run/opendkim/opendkim.sock
UMask                 007
UserID                opendkim
KeyTable              /etc/opendkim/KeyTable
SigningTable          refile:/etc/opendkim/SigningTable
ExternalIgnoreList    refile:/etc/opendkim/TrustedHosts
InternalHosts         refile:/etc/opendkim/TrustedHosts

# /etc/opendkim/KeyTable
mail._domainkey.phishingdomain.com  phishingdomain.com:mail:/etc/dkim/keys/phishingdomain.com/phishingdomain.com.private

# /etc/opendkim/SigningTable
*@phishingdomain.com  mail._domainkey.phishingdomain.com

# /etc/opendkim/TrustedHosts
127.0.0.1
localhost
[YOUR_MTA_IP]

# /etc/postfix/main.cf — add OpenDKIM milter
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:/run/opendkim/opendkim.sock
non_smtpd_milters = local:/run/opendkim/opendkim.sock

# Restart services
systemctl restart opendkim postfix

# Test DKIM signing
echo "Test DKIM" | mail -s "DKIM Test" test@gmail.com
# Check received email headers for DKIM-Signature header
```

## DMARC Configuration

DMARC builds on SPF and DKIM to instruct receiving servers on how to handle emails that fail authentication.

```dns
# Start with p=none (monitor mode — does not affect delivery)
_dmarc.phishingdomain.com.  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@phishingdomain.com; ruf=mailto:dmarc@phishingdomain.com; fo=1"

# Policy options:
# p=none        — take no action, just report
# p=quarantine  — send to spam if fail
# p=reject      — reject email if fail

# For phishing campaigns: start with p=none
# This satisfies DMARC presence checks (some receivers require DMARC)
# without potentially blocking your own campaign

# After warming: consider p=quarantine for more legitimate appearance
# (signals mature email configuration to spam filters)

# Fields:
# rua: aggregate report email (summary of DMARC pass/fail)
# ruf: forensic report email (individual failure reports)
# fo=1: generate forensic reports for any auth failure
```

## MTA Setup: Postfix for Phishing

```bash
# Install Postfix
apt update && apt install -y postfix

# /etc/postfix/main.cf — phishing MTA configuration
# Key settings:

# Hostname must match PTR record on your IP
myhostname = mail.phishingdomain.com
mydomain = phishingdomain.com

# Listen on all interfaces
inet_interfaces = all

# Relay through smarthost if needed (or direct delivery)
# For direct delivery:
relayhost =

# TLS configuration (required for modern deliverability)
smtpd_tls_cert_file = /etc/letsencrypt/live/phishingdomain.com/fullchain.pem
smtpd_tls_key_file  = /etc/letsencrypt/live/phishingdomain.com/privkey.pem
smtpd_use_tls = yes
smtp_tls_security_level = may
smtp_tls_loglevel = 1

# Remove identifying headers
smtp_header_checks = regexp:/etc/postfix/header_checks

# /etc/postfix/header_checks — remove X-Mailer and X-Originating-IP
/^X-Mailer:/               IGNORE
/^X-Originating-IP:/       IGNORE
/^X-PHP-Originating-Script:/  IGNORE
/^X-Source:/               IGNORE
```

```bash
# Apply header_checks
postmap /etc/postfix/header_checks
systemctl restart postfix

# Test email delivery
echo "Test phishing infra" | mail -s "Infrastructure Test" recipient@testdomain.com

# Monitor mail queue
mailq
postqueue -f   # Flush queue

# Check logs
tail -f /var/log/mail.log | grep -E "status|reject|defer"
```

## GoPhish Deployment

GoPhish is the primary phishing campaign management framework for red teams.

```bash
# Download GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish

# config.json — GoPhish configuration
{
    "admin_server": {
        "listen_url": "127.0.0.1:3333",   # Bind to localhost only
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:443",      # Listen on 443 for phish pages
        "use_tls": true,
        "cert_path": "/etc/letsencrypt/live/phishingdomain.com/fullchain.pem",
        "key_path": "/etc/letsencrypt/live/phishingdomain.com/privkey.pem"
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": "",
    "logging": {
        "filename": "",
        "level": ""
    }
}

# Run GoPhish
./gophish
# Admin UI: https://127.0.0.1:3333 (SSH tunnel to reach from operator machine)
# Default credentials: admin / [generated password shown in stdout on first run]
```

### GoPhish Campaign Setup

```
1. Create Sending Profile:
   Name: Corporate Mail Server
   From: IT Support <itsupport@phishingdomain.com>
   Host: localhost:25   (or relay through port 587 with auth)
   
2. Create Landing Page:
   Name: Office365 Login
   HTML: Clone from target's actual O365 login page
   Capture Submitted Data: YES
   Capture Passwords: YES
   Redirect to: https://login.microsoftonline.com/ (actual O365 after capture)

3. Create Email Template:
   Name: Password Reset Alert
   Subject: [URGENT] Your Microsoft 365 password is expiring today
   HTML Body: (craft plausible template — see below)

4. Create User Group (Target List):
   Import CSV: firstname,lastname,email,position
   john,doe,jdoe@targetcorp.com,Finance Manager

5. Create Campaign:
   Name: [CLIENT] Phish 1 - Password Reset
   Template: Password Reset Alert
   Page: Office365 Login
   URL: https://login.phishingdomain.com/
   Schedule: [START DATE/TIME]
   Send By: [END DATE/TIME]
   Groups: Target employees

6. Launch Campaign
   GoPhish generates unique tracking token per target
   Tracks: email opened, link clicked, credential submitted, attachment opened
```

### Tracking Pixel

```html
<!-- GoPhish automatically inserts tracking pixel -->
<!-- Manually: 1x1 transparent pixel to your GoPhish server -->
<img src="https://phishingdomain.com/track?id={{.RId}}" 
     width="1" height="1" style="display:none" />

<!-- GoPhish uses {{.RId}} = unique recipient ID for tracking -->
<!-- Link template in GoPhish: -->
<a href="{{.URL}}">Click here to reset your password</a>
```

## Email Header Hygiene

```bash
# Headers that expose MTA identity — remove all of them

# Postfix /etc/postfix/header_checks (regexp format):
/^X-Mailer:/                    IGNORE
/^X-Originating-IP:/            IGNORE
/^X-PHP-Originating-Script:/    IGNORE
/^X-Source:/                    IGNORE
/^X-Source-Args:/               IGNORE
/^X-Source-Dir:/                IGNORE
/^X-AntiAbuse:/                 IGNORE
/^X-Spam-Status:/               IGNORE
/^X-Spam-Score:/                IGNORE
/^X-Spam-Bar:/                  IGNORE
/^X-Ham-Report:/                IGNORE

# Reveal: check your outgoing email headers
# Gmail: three-dot menu → Show Original
# Look for: X-Mailer, X-Originating-IP, Received headers

# Received headers reveal relay path — cannot be fully suppressed
# But internal Received headers (from your own server) can be minimized:
# /etc/postfix/main.cf:
# header_size_limit = 4096  (limits header exposure)
```

## Graymail Domains

```
Graymail concept:
  "Graymail" = bulk email that receivers have opted into (newsletters, marketing)
  These senders have established reputation — their emails land in inbox
  not spam, even with marketing content

For red team: acquire a domain previously used for legitimate graymail
  (email marketing, SaaS notifications) — slight reputation advantage

Search:
  - expireddomains.net filter: domains with MX records in Wayback Machine
  - Look for: former e-commerce, SaaS, newsletter domains
  - Verify: no blacklist hits, Talos category = Marketing or Business
```

## SMTP Relay Services

```
SendGrid, Mailgun, and similar services as relay:
  Pros:
    - Established sending reputation
    - Deliverability team manages IP reputation
    - Automatic bounce handling
  
  Cons:
    - Requires email verification/account approval
    - ToS prohibits phishing (account may be terminated)
    - Support team may report suspicious campaigns
    - Legitimate-looking campaigns may still be reviewed

  Strategy:
    - Use relay service for warming phase only (legitimate emails)
    - Switch to direct MTA for actual phishing campaign
    - OR: use relay for very targeted campaigns with convincing pretexts

  SendGrid relay configuration in Postfix:
    /etc/postfix/main.cf:
    relayhost = [smtp.sendgrid.net]:587
    smtp_sasl_auth_enable = yes
    smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
    smtp_sasl_security_options = noanonymous
    smtp_tls_security_level = encrypt
    
    /etc/postfix/sasl_passwd:
    [smtp.sendgrid.net]:587  apikey:[SENDGRID_API_KEY]
    
    postmap /etc/postfix/sasl_passwd
    systemctl restart postfix
```

## Inbox Placement Testing

```bash
# mail-tester.com — most comprehensive free test
# 1. Navigate to mail-tester.com
# 2. Get unique test email address
# 3. Send test email from your MTA to that address
# 4. View score (target: 10/10)
# Checks: SPF, DKIM, DMARC, blacklists, content, HTML quality

# GlockApps — paid, but tests against actual ISP inboxes (Gmail, Outlook, Yahoo)
# Shows: Inbox / Spam / Missing placement per provider

# MXToolbox comprehensive email health
curl "https://api.mxtoolbox.com/api/v1/Health/[yourdomain.com]" | python3 -m json.tool

# Manual inbox testing:
# Create test accounts at: Gmail, Outlook/Hotmail, Yahoo, ProtonMail
# Send from your MTA to each
# Check: inbox placement, spam warnings, "via [relay]" notations

# Header analysis — check what spam filters see:
# Send to Gmail, open email, View Original
# Analyze Authentication-Results header:
#   spf=pass, dkim=pass, dmarc=pass → likely inbox
#   spf=fail or dkim=fail → likely spam

# PTR record check (critical for inbox placement):
host [YOUR_MTA_IP]
# Expected: [YOUR_MTA_IP] domain name pointer mail.phishingdomain.com.
# Configure PTR at VPS provider: "Reverse DNS" setting in control panel
```

## Pre-Campaign Checklist

```
Infrastructure validation before launching phishing:

Domain and DNS:
  [ ] Domain registered and active
  [ ] A record points to MTA IP
  [ ] MX record points to mail server hostname
  [ ] SPF record published and validated (MXToolbox)
  [ ] DKIM record published and signing verified
  [ ] DMARC record published (p=none minimum)
  [ ] PTR (reverse DNS) set at VPS provider to match myhostname

Mail Server:
  [ ] Postfix running and accepting connections on port 25 and 587
  [ ] TLS configured with valid certificate (Let's Encrypt)
  [ ] OpenDKIM running and signing outgoing mail
  [ ] Header cleanup active (X-Mailer removed)
  [ ] Test email received in inbox (Gmail, Outlook)
  [ ] mail-tester.com score: 8/10 minimum (10/10 preferred)

GoPhish:
  [ ] GoPhish running with correct config
  [ ] Sending profile tested (sends correctly)
  [ ] Landing page cloned and captures credentials
  [ ] Email template rendered correctly in Outlook and Gmail
  [ ] Tracking link clickable and records in GoPhish
  [ ] Redirect after credential capture points to legitimate site
  [ ] Campaign settings verified (schedule, targets, template)

OPSEC:
  [ ] Domain and MTA not linked to C2 domains (separate infrastructure)
  [ ] Phishing infrastructure documented for teardown
  [ ] Scope confirmation: phishing targets are in authorized list only
```
