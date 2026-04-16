---
layout: training-page
title: "GoPhish Phishing Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - phishing
  - social-engineering
  - initial-access
  - gophish
  - campaign-management
page_key: "c2-gophish"
render_with_liquid: false
---

# GoPhish Phishing Framework

GoPhish is an open-source phishing simulation framework written in Go. It provides a full campaign management pipeline: create sending profiles, build email templates, clone landing pages, import target lists, launch campaigns, and track results in real time. It is widely used by red teams for authorized phishing engagements and security awareness assessments.

## Architecture Overview

GoPhish runs two servers simultaneously:

- **Admin server** — HTTPS web UI (default `127.0.0.1:3333`) for managing campaigns, templates, and results
- **Phishing server** — HTTP/HTTPS server (default `0.0.0.0:80`) that hosts landing pages and tracks clicks/submissions

Every target gets a unique tracking token embedded in their phishing URL. GoPhish records when email is delivered, opened, link clicked, and credentials submitted — all in real time.

## Installation

### Binary (Recommended)

```
# Download the latest release for your platform from GitHub
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
cd gophish
chmod +x gophish
./gophish
```

### Build from Source

```
# Requires Go 1.10+ and a C compiler
git clone https://github.com/gophish/gophish
cd gophish
go build .
./gophish
```

### Docker

```
docker pull gophish/gophish
docker run -p 3333:3333 -p 80:80 gophish/gophish
```

## Initial Setup

```
# Launch and watch stdout for generated admin credentials
./gophish

# Output example:
# Please login with the username admin and the password 7c652a4a8f3f85d4
# time="2024-01-01T12:00:00Z" level=info msg="Starting admin server at https://127.0.0.1:3333"
# time="2024-01-01T12:00:00Z" level=info msg="Starting phishing server at http://0.0.0.0:80"
```

Access the admin UI at `https://127.0.0.1:3333`. Accept the self-signed certificate. The generated password is one-time — change it after first login. Versions prior to v0.10.1 used default credentials `admin`/`gophish`.

## Configuration (config.json)

```
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/phish.example.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/phish.example.com/privkey.pem"
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
```

For production engagements: bind the phishing server to port 443 with a valid TLS certificate. The admin server should remain bound to `127.0.0.1` and accessed via SSH tunnel — never expose it publicly.

## Run as a Service (Linux)

```
# /etc/systemd/system/gophish.service
[Unit]
Description=GoPhish Phishing Framework
After=network.target

[Service]
Type=simple
User=gophish
WorkingDirectory=/opt/gophish
ExecStart=/opt/gophish/gophish
Restart=on-failure

[Install]
WantedBy=multi-user.target

# Enable and start
systemctl daemon-reload
systemctl enable gophish
systemctl start gophish
```

## Campaign Workflow

A complete GoPhish campaign requires five components built in order:

1. Sending Profile (SMTP relay)
2. Email Template
3. Landing Page (credential capture)
4. Users & Groups (target list)
5. Campaign (ties everything together)

### 1. Sending Profile

Defines the SMTP relay GoPhish uses to deliver email.

- **From**: Display name and spoofed sender (e.g., `IT Security <security@corp-helpdesk.com>`)
- **Host**: SMTP server in `host:port` format — always include the port (e.g., `mail.relay.com:587`)
- **Username/Password**: SMTP auth credentials if required
- **Headers**: Add custom headers like `X-Mailer`, `Reply-To`, or `List-Unsubscribe` to improve deliverability or impersonate internal systems

Use the "Send Test Email" button to verify the relay works before launching.

### 2. Email Templates

Templates support Go's text/template syntax with the following built-in variables:

```
{{.FirstName}}    - Target's first name
{{.LastName}}     - Target's last name
{{.Email}}        - Target's email address
{{.Position}}     - Target's job title
{{.From}}         - Spoofed sender address
{{.TrackingURL}}  - Invisible 1x1 tracking pixel URL (email open tracking)
{{.URL}}          - Unique phishing link for this target
```

Example template (password reset lure):

```
Subject: Action Required: Password Expiration Notice for {{.Email}}

Dear {{.FirstName}},

Your corporate password for {{.Email}} will expire in 24 hours.
To avoid account lockout, please reset your password immediately:

    <a href="{{.URL}}">Reset My Password</a>

If you did not request this notice, contact the IT Help Desk.

Regards,
IT Security Team
```

Use "Import Email" to paste in a real corporate email as a starting point for more convincing lures. Enable "Add Tracking Image" to record email opens via a hidden pixel.

### 3. Landing Pages

GoPhish can clone any login page via "Import Site" — paste the target URL and it pulls the HTML. After import:

- Enable **Capture Submitted Data** to record all form fields
- Enable **Capture Passwords** to store cleartext credentials
- Set a **Redirect URL** — send victims to the real login page after submission to avoid suspicion

Review the cloned HTML in the editor and fix any broken asset paths or absolute URLs pointing to the real site.

### 4. Users & Groups

Create groups via manual entry or CSV bulk import. Required CSV format:

```
First Name,Last Name,Position,Email
Alice,Smith,CFO,asmith@target.com
Bob,Jones,IT Administrator,bjones@target.com
Carol,White,HR Manager,cwhite@target.com
```

Navigate to **Users & Groups > New Group**, name the group, and use "Bulk Import Users" to upload the CSV.

### 5. Launching a Campaign

Navigate to **Campaigns > New Campaign** and fill in:

- **Name**: Internal campaign identifier
- **Email Template**: Select the template you built
- **Landing Page**: Select the cloned login page
- **URL**: Your phishing server's external IP or domain (e.g., `https://phish.example.com`)
- **Launch Date**: Schedule or launch immediately
- **Sending Profile**: Select SMTP relay
- **Groups**: Select target groups

Click "Launch Campaign" — GoPhish redirects to the results dashboard and begins delivering emails.

## Results Dashboard

The campaign timeline tracks these events per target:

- **Email Sent**: Delivery confirmed by SMTP server
- **Email Opened**: Tracking pixel loaded (requires HTML email)
- **Clicked Link**: Target visited the phishing URL
- **Submitted Data**: Form credentials captured
- **Email Reported**: Target used the report button (if deployed)

Export results as CSV for inclusion in final reports. Individual captured credentials are viewable per-target.

## API Automation

GoPhish has a full REST API for scripting campaigns. Generate an API key in account settings.

```
# Get all campaigns
curl -k -H "Authorization: Bearer <api_key>" https://localhost:3333/api/campaigns/

# Create a campaign (JSON body)
curl -k -X POST -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Q1 Phishing Test","template":{"name":"Password Reset"},"page":{"name":"Login Portal"},"smtp":{"name":"Corp Relay"},"url":"https://phish.example.com","launch_date":"2026-04-20T09:00:00Z","groups":[{"name":"Targets"}]}' \
  https://localhost:3333/api/campaigns/

# Get campaign results
curl -k -H "Authorization: Bearer <api_key>" \
  https://localhost:3333/api/campaigns/1/results
```

## Operational Security Considerations

- Never expose the admin port (3333) to the internet — use SSH port forwarding: `ssh -L 3333:127.0.0.1:3333 user@phishserver`
- Use a dedicated domain registered weeks before the engagement to improve email reputation
- Set up SPF, DKIM, and DMARC records on your phishing domain to bypass spam filters
- Use a commercial SMTP relay (SendGrid, Mailgun, AWS SES) rather than direct sending — reduces likelihood of IP blocks
- Evilginx can serve as the phishing URL backend instead of GoPhish's built-in landing pages — see the Evilginx page for integration details
- Remove GoPhish default headers that identify it: the `X-Gophish-Contact` and `X-Gophish-Signature` headers are detectable by Blue Teams — patch them out of the source before building

## Stripping GoPhish Fingerprints (Source Patch)

```
# Clone and patch before building
git clone https://github.com/gophish/gophish
cd gophish

# Remove X-Gophish headers from models/email_request_test.go and util/util.go
grep -rn "X-Gophish" .
# Edit the identified files to remove or rename these headers

# Rename the default rid parameter
# In models/campaign.go: change "rid" to something generic like "id" or "ref"
grep -rn '"rid"' .

go build .
./gophish
```

## Resources

- GoPhish — `github.com/gophish/gophish`
- Documentation — `docs.getgophish.com`
- GoPhish fingerprint removal — `github.com/puzzlepeaches/sneaky_gophish`
