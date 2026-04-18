---
layout: training-page
title: "NHA Branching Attack Path — Red Team Academy"
module: "Active Directory"
tags:
  - nha
  - attack-path
  - graph
  - lab
  - walkthrough
page_key: "ad-nha-attack-path"
render_with_liquid: false
---

# NHA Branching Attack Path

Every host in the Ninja Hacker Academy lab has more than one way in. This page is a decision graph — each node is a foothold or privilege state, and each edge is a technique with a link to its documentation. Pick any route to Domain Admin on both `academy.ninja.lan` and `ninja.hack`.

**Starting position:** Unauthenticated, network access to `192.168.58.0/24`. First reachable host is `SRV01` at `192.168.58.21`. Defender is live on every machine — pair every Windows-host action with a look at the [Evasion](/evasion/windows-defender/) guidance.

For the complete narrative walkthrough with commands, see the main [NHA page](/active-directory/nha/).

---

## High-Level Branch Tree

```
                          [ NETWORK FOOTHOLD — 192.168.58.0/24 ]
                                        │
                       ┌────────────────┼────────────────┐
                       │                │                │
               [A] SRV01 web RCE  [B] No-auth SMB   [C] Relay / coerce
                   (primary)      enum + ASREP-roast (secondary)
                       │                │                │
                       └────────┬───────┴────────┬───────┘
                                ▼                ▼
                       [ Academy domain creds  or  web SYSTEM ]
                                │
           ┌────────────────────┼────────────────────────────┐
           │                    │                            │
  [D] Kerberoast frank/   [E] CredSSP capture of       [F] SQL$ RBCD abuse
      sql_svc → crack         frank from bot.ps1           → impersonate DA
           │                    │                            │
           └──────────┬─────────┴──────────┬─────────────────┘
                      ▼                    ▼
             [ frank cleartext/hash ]   [ lateral movement ]
                      │
         ┌────────────┼────────────────────────┐
         │            │                        │
  [G] MSSQL on  [H] Constrained delegation  [I] Frank's TGT
      SRV02 →       (S4U2Self/Proxy) →          → direct service
      xp_cmdshell   impersonate DA on share     access
         │            │                        │
         └────────────┼────────────────────────┘
                      ▼
                 [ SRV03 share ]
                      │
              ┌───────┴────────┐
              │                │
   [J] Read gmsaNFS$     [K] Find bot.ps1 —
       password blob         poison for persistence
              │                │
              ▼                ▼
      [L] ForceChangePassword on backup user
              │
              ▼
   [M] backup's WriteOwner on Sensei + AdminSDHolder
              │
              ▼
       [ DOMAIN ADMIN — academy.ninja.lan ]
              │
              ▼
    [N] Trust-key pivot into ninja.hack
              │
     ┌────────┴──────────────┐
     │                       │
 [O] Direct Hokage       [P] olivia.davis → WriteDacl → rachel →
     membership (if you      Sanin GenericAll → Jonin GenericAll →
     can reach it)           SignatureValidation ESC4 → ESC1
     │                       │
     └───────────┬───────────┘
                 ▼
       [ DOMAIN ADMIN — ninja.hack ]
```

---

## Branch Catalog

Every branch in the tree above maps to a documented technique. Pick a node, follow the link for commands.

### [A] SRV01 — Web RCE on IIS

**Summary:** Enumerate the IIS app at `http://192.168.58.21`, find a web vuln (upload, SSTI, command injection, deserialization, or auth bypass), land RCE, then upgrade to SYSTEM. Primary entry.

**Links:** [Web Hacking Methodology](/web/web-hacking-methodology/) · [File Upload](/web/file-upload/) · [Command Injection](/web/command-injection/) · [SQL Injection](/web/sql-injection/) · [SSTI](/web/ssti/) · [Insecure Deserialization](/web/insecure-deserialization/) · [IIS Shortname Scanner](/web/iis-shortscan/) · [Evasive Loaders](/evasion/shellcode-loaders/) · [Windows Defender](/evasion/windows-defender/)

### [B] No-auth SMB enumeration + AS-REP roast

**Summary:** Before web exploitation, enumerate SMB / LDAP anonymously. NHA may expose user account names via null sessions or Kerberos pre-auth disabled accounts — useful for AS-REP roasting without any creds.

**Links:** [AD Enumeration](/active-directory/ad-enumeration/) · [AS-REProasting](/active-directory/asreproasting/)

### [C] Coercion + NTLM Relay

**Summary:** Force a machine account (DC02, SRV03) to authenticate to you with PetitPotam, PrinterBug, or DFSCoerce, then relay to LDAPS on the DC for RBCD abuse, or to ADCS web enrollment on `dc-vil` (ESC8).

**Links:** [Coercion Attacks](/active-directory/coercion-attacks/) · [NTLM Relay](/active-directory/ntlm-relay/) · [ADCS Attacks](/active-directory/adcs-attacks/)

### [D] Kerberoast frank and sql_svc

**Summary:** Two SPN-bearing users — `frank` (HTTP/WEB) and `sql_svc` (MSSQLSvc/sql) — are Kerberoastable. Request TGS tickets, crack offline. NHA passwords are NOT in rockyou — use rules, patterns, and targeted wordlists.

**Links:** [Kerberoasting & AS-REP](/active-directory/kerberoasting/)

### [E] CredSSP capture from bot.ps1

**Summary:** SRV03 runs a scheduled task every 60s that CredSSP-connects to SRV01 as `academy\frank`. Once you own SRV01, frank's cleartext password is in LSASS within one minute. Alternative: poison bot.ps1 itself for persistence.

**Links:** [CredSSP Attacks](/active-directory/credssp-attacks/) · [LSASS Dumping](/post-exploitation/lsass-dumping/) · [Windows Defender Evasion](/evasion/windows-defender/)

### [F] SQL$ Resource-Based Constrained Delegation

**Summary:** The `SQL$` computer account has `GenericAll` on the `Computers` OU. Create your own computer account, write RBCD to a target machine, S4U2Self/Proxy for Domain Admin impersonation — full lateral without needing frank's password.

**Links:** [Kerberos Delegation — RBCD](/active-directory/kerberos-delegation/) · [ACL / ACE Abuse](/active-directory/acl-abuse/)

### [G] MSSQL → xp_cmdshell (frank → SRV02)

**Summary:** `frank` is MSSQL sysadmin on SRV02. Connect with frank's creds or TGT, enable `xp_cmdshell`, get OS-level code exec on `sql`. Also gives another host to pivot from.

**Links:** [Database Attacks](/exploitation/database-attacks/) · [Lateral Movement](/post-exploitation/lateral-movement/)

### [H] Constrained Delegation (frank → share)

**Summary:** `frank` has constrained delegation with protocol transition to `eventlog/share.academy.ninja.lan`. S4U2Self + S4U2Proxy lets frank impersonate Domain Administrator to the share service — DA-on-share without ever touching a DA account.

**Links:** [Kerberos Delegation — Constrained](/active-directory/kerberos-delegation/)

### [I] Silver Ticket on sql_svc / frank

**Summary:** After cracking sql_svc or frank's hash, forge silver tickets for the MSSQL or HTTP service without ever contacting the KDC. Useful for stealth — skips TGT requests and 4769 events.

**Links:** [Kerberoasting & AS-REP](/active-directory/kerberoasting/) · [DCSync & Golden Ticket](/active-directory/dcsync/)

### [J] Read gMSA (gmsaNFS$) Password

**Summary:** From `share` (or any authorized principal), read `msDS-ManagedPassword` on `gmsaNFS$` — directly decodes to NT/AES keys. Multiple tools on both Windows (DSInternals) and Linux (bloodyAD, GMSAPasswordReader).

**Links:** [gMSA Abuse](/active-directory/gmsa-abuse/) · [BloodHound](/active-directory/bloodhound/)

### [K] Poison bot.ps1 on share

**Summary:** If your path through SRV03 grants write access to the bot script, replace it with a payload that runs every 60 seconds as whatever identity the scheduler uses. Persistence + repeated credential theft.

**Links:** [CredSSP Attacks](/active-directory/credssp-attacks/) · [AD Persistence](/active-directory/ad-persistence/)

### [L] ForceChangePassword on backup

**Summary:** `gmsaNFS$` has `ForceChangePassword` on `backup`. Either reset backup's password via RPC, or (stealthier) inject Shadow Credentials (`msDS-KeyCredentialLink`) and PKINIT-authenticate as backup without changing their password.

**Links:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [Shadow Credentials](/active-directory/shadow-credentials/) · [gMSA Abuse](/active-directory/gmsa-abuse/)

### [M] backup → Sensei via WriteOwner — DA on ACADEMY

**Summary:** `backup` has `WriteOwner` on the `Sensei` group and on `AdminSDHolder`. Take ownership → grant yourself `GenericAll` → add your account to Sensei (which is local admin on web + sql and contains the DA `alice`). Path to full Domain Admin.

**Links:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [AD Persistence](/active-directory/ad-persistence/)

### [N] Cross-Domain Trust Pivot

**Summary:** `academy.ninja.lan` ↔ `ninja.hack` share a bidirectional trust. Dump the inter-realm trust keys with DCSync, forge an inter-realm TGT as any user, or request cross-realm TGS directly. Access NINJA as if you were authenticated there.

**Links:** [Domain Trusts](/active-directory/domain-trusts/) · [DCSync & Golden Ticket](/active-directory/dcsync/)

### [O] Hokage Direct Path

**Summary:** If you can land into the `Hokage` group (via cross-domain ACL pivot or membership of `alice.johnson`), `Hokage` has `GenericAll` on `Domain Admins` — one LDAP write away from DA on NINJA.

**Links:** [ACL / ACE Abuse](/active-directory/acl-abuse/)

### [P] ACL Chain → ADCS ESC4 → ESC1

**Summary:** Three-hop ACL chain: `olivia.davis` WriteDacl → `rachel.philips` (in Sanin) → Sanin GenericAll on Jonin → Jonin GenericAll on `SignatureValidation` cert template. Rewrite template to be ESC1-vulnerable, request cert as DA, PKINIT → NT hash.

**Links:** [ACL / ACE Abuse](/active-directory/acl-abuse/) · [ADCS Attacks](/active-directory/adcs-attacks/) · [Shadow Credentials](/active-directory/shadow-credentials/)

---

## Per-Device Compromise Menu

Because every host has multiple paths, here is each target with every documented route in:

### SRV01 (web — 192.168.58.21)
1. Web app RCE via file upload, cmd injection, SSTI, deserialization — [Web Methodology](/web/web-hacking-methodology/)
2. IIS-specific — shortname scanning, web.config abuse, appcmd — [IIS Shortname](/web/iis-shortscan/)
3. Coerce + relay from elsewhere once you have any foothold — [Coercion](/active-directory/coercion-attacks/) · [NTLM Relay](/active-directory/ntlm-relay/)

### SRV02 (sql — 192.168.58.22)
1. frank's creds → MSSQL sysadmin → xp_cmdshell — [Database Attacks](/exploitation/database-attacks/)
2. Kerberoast `sql_svc` then PtT / silver ticket — [Kerberoasting](/active-directory/kerberoasting/)
3. SQL$ RBCD pivot — abuse from the SQL machine account — [Kerberos Delegation](/active-directory/kerberos-delegation/)
4. Relay SQL's machine account to a target accepting NTLM — [NTLM Relay](/active-directory/ntlm-relay/)

### SRV03 (share — 192.168.58.23)
1. S4U2Self/Proxy from `frank` to `eventlog/share` — [Kerberos Delegation](/active-directory/kerberos-delegation/)
2. RBCD via `SQL$` GenericAll on Computers OU — [Kerberos Delegation — RBCD](/active-directory/kerberos-delegation/)
3. Direct access if you land creds for any Teacher or Sensei member — [ACL Abuse](/active-directory/acl-abuse/)
4. Coerce + relay share's machine account — [Coercion](/active-directory/coercion-attacks/)

### DC02 (dc-ac — 192.168.58.20, ACADEMY)
1. `backup` → Sensei WriteOwner → DA ACL path — [ACL Abuse](/active-directory/acl-abuse/)
2. SQL$ RBCD on DC02 (write `msDS-AllowedToActOnBehalfOfOtherIdentity`) — [Kerberos Delegation](/active-directory/kerberos-delegation/)
3. DCSync once any DA-equivalent is obtained — [DCSync](/active-directory/dcsync/)
4. Coerce DC02 machine account and relay to LDAPS — [NTLM Relay](/active-directory/ntlm-relay/)

### DC01 (dc-vil — 192.168.58.10, NINJA)
1. ACL chain (olivia → rachel → Sanin → Jonin → SignatureValidation → ESC1) — [ADCS Attacks](/active-directory/adcs-attacks/) · [ACL Abuse](/active-directory/acl-abuse/)
2. Hokage group → GenericAll on DA — [ACL Abuse](/active-directory/acl-abuse/)
3. Cross-realm Golden Ticket via trust key (post ACADEMY DA) — [DCSync / Golden Ticket](/active-directory/dcsync/) · [Domain Trusts](/active-directory/domain-trusts/)
4. ADCS ESC8 via coerced relay to the CA web enrollment — [Coercion](/active-directory/coercion-attacks/) · [ADCS](/active-directory/adcs-attacks/) · [NTLM Relay](/active-directory/ntlm-relay/)

---

## Evasion Notes by Branch

NHA runs Defender on every Windows host. Per-branch evasion tips:

| Branch | Evasion concern | Tactic |
|--------|-----------------|--------|
| [A] Web RCE | Payload drops Defender-known signatures | Use [Shellcode Loaders](/evasion/shellcode-loaders/) · [HTML Smuggling](/evasion/html-smuggling/) |
| [D] Kerberoast | Rubeus AMSI-flagged on host | Use [GetUserSPNs.py from Linux](/active-directory/kerberoasting/) |
| [E] CredSSP capture | Mimikatz.exe always caught | [Reflective Mimikatz loader](/evasion/shellcode-loaders/) · [AMSI Bypass](/evasion/amsi-bypass/) first |
| [F] RBCD abuse | Impacket on-host via Python gets flagged | Run rbcd.py from Linux attacker box |
| [G] MSSQL xp_cmdshell | Powershell one-liner reverse shells flagged | [PowerShell Without PowerShell.exe](/evasion/powershell-without-ps/) · use nishang-style encoding |
| [H] S4U2 with Rubeus | .NET assembly flagged by Defender | Use [getST.py (Impacket, Linux)](/active-directory/kerberos-delegation/) |
| [J] gMSA read | LDAP reads of ManagedPassword audited | [bloodyAD from Linux](/active-directory/gmsa-abuse/) — SOCKS-tunnel through compromised host |
| [M] bloodyAD ACL writes | Kerberos 4662 events on DC | Batch writes; use [AD LOTL](/active-directory/ad-lotl/) idioms where possible |
| [P] Certipy on-host | Unusual cert enrollment traffic | Run certipy from Linux only; use AES keys, not RC4 |

See the full catalog in [Windows Defender Evasion](/evasion/windows-defender/), [LOLBAS Reference](/evasion/lolbas-reference/), and [LOTL Advanced](/evasion/lotl-advanced/).

---

## Opinionated Fastest-Path Route

If you want the shortest viable path (not the stealthiest), this is the route most experienced NHA players take:

1. **[A]** Web RCE on SRV01 → SYSTEM with a Sliver/Havoc implant
2. **[E]** Wait ≤60 seconds for bot.ps1 → extract frank's cleartext from LSASS
3. **[H]** S4U2 from frank → Administrator on `share` (skips SRV02 entirely)
4. **[J]** Read gmsaNFS$ from share → derive NT hash
5. **[L]** ForceChangePassword on backup
6. **[M]** backup's WriteOwner → Sensei membership → DA ACADEMY
7. **[N]** Trust-key pivot to NINJA
8. **[P]** ACL chain → SignatureValidation ESC1 → DA NINJA

Alternate stealth-focused route: substitute **[P] Shadow Credentials** for the password reset step, and use **[O] Hokage direct path** if you already have access.

---

## Related Pages

- [Ninja Hacker Academy (NHA)](/active-directory/nha/)
- [Game of Active Directory (GOAD)](/active-directory/goad/)
- [BloodHound](/active-directory/bloodhound/)
- [Evasion: Windows Defender](/evasion/windows-defender/)
- [Lateral Movement](/post-exploitation/lateral-movement/)
