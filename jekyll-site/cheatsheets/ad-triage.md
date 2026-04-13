---
layout: training-page
title: "AD Triage Cheatsheet — Red Team Academy"
module: "Ops Cheatsheets"
tags:
  - cheatsheet
  - active-directory
  - triage
page_key: "cheatsheets-ad-triage"
render_with_liquid: false
updated: "2026-04-13"
---

# AD Triage Cheatsheet

Repeatable **order of operations** on a Windows domain foothold. Adapt tools to what the engagement allows (EDR, logging, OPSEC).

## Phase 1 — Session context

```
whoami /all
hostname
ipconfig /all
route print
net user %USERNAME%
net localgroup administrators
```

## Phase 2 — Domain identity

```
echo %USERDOMAIN%
echo %LOGONSERVER%
nltest /dclist:<DOMAIN>
nltest /domain_trusts
```

## Phase 3 — Bloodline-style questions (answer with your stack)

- **Who am I in AD?** — groups, privileges, delegation exposure.
- **Where is the DC?** — DNS, `nltest`, SRV lookups.
- **What trusts exist?** — inbound/outbound, forest vs external.
- **What can Kerberoast / AS-REP?** — SPNs, preauth settings (authorized enumeration only).

## Phase 4 — Network reachability

```
netstat -ano
arp -a
Test-NetConnection <HOST> -Port 445
Test-NetConnection <HOST> -Port 5985
```

## Phase 5 — Credential and session artifacts (authorized)

- Browser stores, DPAPI-backed secrets, unattend/credential manager — see [post-exploitation](/post-exploitation/) modules.
- **Do not** mix production creds into personal notes; use engagement vaults.

## Quick PowerShell patterns (examples)

```powershell
Get-ADDomain
Get-ADForest
Get-ADDomainController -Filter *
```

Use **SharpHound / BloodHound** collection only when the rules of engagement permit graph ingestion.

## Detection notes

- Mass LDAP, Kerberos ticket requests, and remote admin tool execution are commonly logged.
- Align beaconing and scan rates with target SOC maturity.

## Resources

- [AD enumeration](/active-directory/ad-enumeration/)
- [BloodHound](/active-directory/bloodhound/)
- [Kerberoasting](/active-directory/kerberoasting/)
