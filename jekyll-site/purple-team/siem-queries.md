---
layout: training-page
title: "SIEM Queries for Attack Detection — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - siem
  - kql
  - splunk-spl
  - detection
  - mitre-attack
  - elastic
page_key: "purple-team-siem-queries"
render_with_liquid: false
---

<h1>SIEM Queries for Attack Detection</h1>

<p>Writing effective SIEM queries is the core skill of detection engineering. This page provides KQL (Kibana Query Language) queries and Splunk SPL equivalents for attack techniques organized by MITRE ATT&CK tactic. Each query targets a specific technique or behavior pattern and includes the relevant event IDs, field names, and conditions. Use these as starting points — tune them for your environment to reduce false positives.</p>

<h2>KQL Fundamentals</h2>

<pre><code># KQL (Kibana Query Language) — used in Elastic/Kibana
#
# Basic syntax:
# field:value                   exact match
# field:"exact phrase"          phrase match
# field:value*                  wildcard suffix
# field:*value*                 wildcard contains
# field:(val1 OR val2)          OR condition
# field:value AND field2:value2 AND condition
# NOT field:value               negation
# field:[1 TO 100]              range (numeric)
# field:>100                    greater than
# field:<100                    less than
#
# ECS (Elastic Common Schema) field names used in Winlogbeat/Elastic Agent:
# event.code            — Windows Event ID
# winlog.channel        — Event log channel (Security, System, etc.)
# process.name          — process filename
# process.command_line  — full command line string
# process.parent.name   — parent process name
# user.name             — account name
# host.name             — hostname
# winlog.event_data.*   — raw event data fields
# source.ip             — source IP address
# destination.ip        — destination IP
# destination.port      — destination port
# dns.question.name     — DNS query name
#
# For Sysmon events via Winlogbeat, Sysmon fields appear under:
# winlog.event_data.Image           — process image path
# winlog.event_data.CommandLine     — command line
# winlog.event_data.TargetImage     — target process (Sysmon 10)
# winlog.event_data.GrantedAccess   — access mask (Sysmon 10)
# winlog.event_data.TargetObject    — registry key/value (Sysmon 12/13)</code></pre>

<h2>Initial Access</h2>

<h3>Phishing — Malicious Office Document Execution (T1566.001)</h3>

<pre><code># KQL — Suspicious process spawned by Office applications
# Looks for cmd.exe, powershell.exe, wscript.exe spawned from Office
# Event ID 4688 (process creation with command line) or Sysmon ID 1

event.code:"4688" AND
winlog.event_data.ParentProcessName:(*\\WINWORD.EXE OR *\\EXCEL.EXE OR *\\POWERPNT.EXE OR *\\OUTLOOK.EXE) AND
winlog.event_data.NewProcessName:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\cscript.exe OR *\\mshta.exe OR *\\rundll32.exe)

# KQL — Sysmon variant (Event ID 1 — more detail)
event.code:"1" AND
winlog.event_data.ParentImage:(*\\WINWORD.EXE OR *\\EXCEL.EXE OR *\\POWERPNT.EXE) AND
winlog.event_data.Image:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\mshta.exe)

# Splunk SPL equivalent
index=windows (EventCode=4688 OR EventCode=1)
  (ParentProcessName="*\\WINWORD.EXE" OR ParentProcessName="*\\EXCEL.EXE" OR ParentProcessName="*\\POWERPNT.EXE")
  (NewProcessName="*\\powershell.exe" OR NewProcessName="*\\cmd.exe" OR NewProcessName="*\\wscript.exe" OR NewProcessName="*\\mshta.exe")
| table _time, ComputerName, ParentProcessName, NewProcessName, CommandLine</code></pre>

<h2>Execution</h2>

<h3>Suspicious PowerShell — Encoded Commands (T1059.001)</h3>

<pre><code># KQL — PowerShell encoded command execution
# Attackers use -EncodedCommand (-enc, -ec) to hide payload

event.code:"4104" AND
winlog.event_data.ScriptBlockText:(*-EncodedCommand* OR *-enc * OR * -ec *)

# KQL — PowerShell download cradles (common C2 stage 1)
event.code:"4104" AND
winlog.event_data.ScriptBlockText:(
  *IEX* OR
  *Invoke-Expression* OR
  *DownloadString* OR
  *DownloadFile* OR
  *Net.WebClient* OR
  *WebRequest* OR
  *bitsadmin* OR
  *certutil*
) AND
winlog.event_data.ScriptBlockText:(*http* OR *https*)

# Splunk SPL — PowerShell encoded command
index=windows EventCode=4104
  (ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*-enc *" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*IEX*")
  (ScriptBlockText="*http*" OR ScriptBlockText="*DownloadString*")
| eval decoded=if(match(ScriptBlockText,"-EncodedCommand"),"ENCODED","PLAIN")
| table _time, ComputerName, UserID, ScriptBlockText, decoded</code></pre>

<h3>WMI Execution (T1047)</h3>

<pre><code># KQL — WMI process creation (wmiprvse.exe spawning child processes)
event.code:"1" AND
winlog.event_data.ParentImage:*\\wmiprvse.exe AND
NOT winlog.event_data.Image:(*\\WmiPrvSE.exe OR *\\msiexec.exe)

# KQL — WMIC command-line execution (event 4688)
event.code:"4688" AND
winlog.event_data.NewProcessName:*\\wmic.exe AND
winlog.event_data.CommandLine:(*process call create* OR *os get* OR */node:*)

# Splunk SPL — WMI lateral movement (wmiprvse parent + unusual child)
index=windows EventCode=1
  ParentImage="*\\wmiprvse.exe"
  NOT (Image="*\\WmiPrvSE.exe" OR Image="*\\msiexec.exe" OR Image="*\\svchost.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage</code></pre>

<h3>Rundll32 Abuse (T1218.011)</h3>

<pre><code># KQL — Rundll32 loading suspicious DLLs or calling unusual functions
event.code:"1" AND
winlog.event_data.Image:*\\rundll32.exe AND
(
  winlog.event_data.CommandLine:(*javascript:* OR *vbscript:* OR *http* OR *\\\\* OR *.dll,* ) OR
  NOT winlog.event_data.CommandLine:*\\Windows\\System32*
)

# Splunk SPL equivalent
index=windows EventCode=1 Image="*\\rundll32.exe"
  (CommandLine="*javascript:*" OR CommandLine="*vbscript:*" OR CommandLine="*http*" OR CommandLine="*\\\\*")
| table _time, ComputerName, User, CommandLine, ParentCommandLine</code></pre>

<h2>Persistence</h2>

<h3>Scheduled Task Creation (T1053.005) — Event ID 4698/4702</h3>

<pre><code># KQL — New scheduled task created (4698) or modified (4702)
event.code:("4698" OR "4702") AND
NOT user.name:(*$ OR SYSTEM OR LOCAL SERVICE OR NETWORK SERVICE)

# KQL — Scheduled task with suspicious command
event.code:"4698" AND
winlog.event_data.TaskContent:(*powershell* OR *cmd.exe* OR *wscript* OR *mshta* OR *regsvr32* OR *rundll32*)

# Splunk SPL — Scheduled task creation by non-system accounts
index=windows (EventCode=4698 OR EventCode=4702)
  NOT (SubjectUserName="*$" OR SubjectUserName="SYSTEM")
| rex field=TaskContent "<Exec><Command>(?P<task_command>[^<]+)</Command>"
| table _time, ComputerName, SubjectUserName, TaskName, task_command</code></pre>

<h3>Registry Run Key Persistence (T1547.001) — Sysmon Event ID 13</h3>

<pre><code># KQL — Registry value set in Run/RunOnce keys (Sysmon 13)
event.code:"13" AND
winlog.event_data.TargetObject:(
  *\\CurrentVersion\\Run* OR
  *\\CurrentVersion\\RunOnce* OR
  *\\CurrentVersion\\RunServices* OR
  *\\CurrentVersion\\RunServicesOnce* OR
  *Policies\\Explorer\\Run* OR
  *\\CurrentVersion\\Explorer\\Shell Folders*
) AND
NOT winlog.event_data.Image:(*\\MsiExec.exe OR *\\msiexec.exe OR *\\TrustedInstaller.exe)

# Splunk SPL equivalent
index=windows EventCode=13
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*")
  NOT (Image="*\\MsiExec.exe" OR Image="*\\msiexec.exe" OR Image="*\\TrustedInstaller.exe")
| table _time, ComputerName, Image, TargetObject, Details</code></pre>

<h3>New Service Installation (T1543.003) — Event ID 7045</h3>

<pre><code># KQL — New Windows service installed (7045)
event.code:"7045" AND
NOT winlog.event_data.ServiceName:(
  *WindowsUpdate* OR *WinDefend* OR *Spooler* OR *wuauserv*
) AND
winlog.event_data.ImagePath:(*ADMIN$* OR *\\temp\\* OR *\\AppData\\* OR *powershell* OR *cmd.exe*)

# Splunk SPL
index=windows EventCode=7045
  NOT (ServiceName="WindowsUpdate" OR ServiceName="WinDefend")
  (ImagePath="*ADMIN$*" OR ImagePath="*\\temp\\*" OR ImagePath="*powershell*")
| table _time, ComputerName, ServiceName, ImagePath, ServiceType, StartType</code></pre>

<h2>Privilege Escalation</h2>

<h3>Token Impersonation (T1134) — Logon Type 4/9</h3>

<pre><code># KQL — Explicit credential logon (Type 9 = NewCredentials, used in Pass-the-Hash/Ticket)
event.code:"4624" AND
winlog.event_data.LogonType:"9" AND
NOT user.name:(*$ OR ANONYMOUS LOGON)

# KQL — Logon type 4 (batch) from unusual process
event.code:"4624" AND
winlog.event_data.LogonType:"4" AND
NOT winlog.event_data.ProcessName:(*\\services.exe OR *\\lsass.exe OR *\\svchost.exe)

# Splunk SPL — Type 9 logon (impersonation indicator)
index=windows EventCode=4624 LogonType=9
  NOT (TargetUserName="*$" OR TargetUserName="ANONYMOUS LOGON")
| table _time, ComputerName, TargetUserName, IpAddress, ProcessName, LogonType</code></pre>

<h2>Defense Evasion</h2>

<h3>Event Log Clearing (T1070.001) — Event ID 1102/104</h3>

<pre><code># KQL — Security or System log cleared (1102 = Security, 104 = System/Application)
event.code:("1102" OR "104")

# KQL — Wevtutil used to clear logs (via process creation)
event.code:("4688" OR "1") AND
winlog.event_data.CommandLine:(*wevtutil* AND (*cl* OR *clear-log*))

# Splunk SPL
index=windows (EventCode=1102 OR EventCode=104)
| table _time, ComputerName, SubjectUserName, Channel
| append
  [search index=windows (EventCode=4688 OR EventCode=1)
    CommandLine="*wevtutil*" (CommandLine="* cl *" OR CommandLine="*clear-log*")
  | table _time, ComputerName, User, CommandLine]</code></pre>

<h3>Process Injection — CreateRemoteThread (T1055) — Sysmon Event ID 8</h3>

<pre><code># KQL — CreateRemoteThread targeting sensitive processes (Sysmon 8)
event.code:"8" AND
winlog.event_data.TargetImage:(
  *\\lsass.exe OR
  *\\svchost.exe OR
  *\\explorer.exe OR
  *\\winlogon.exe OR
  *\\services.exe
) AND
NOT winlog.event_data.SourceImage:(*\\csrss.exe OR *\\System)

# KQL — Sysmon 10 process access (memory reads — includes injection prep)
event.code:"10" AND
winlog.event_data.GrantedAccess:("0x1fffff" OR "0x1010" OR "0x1438" OR "0x143a")

# Splunk SPL — CreateRemoteThread into system processes
index=windows EventCode=8
  (TargetImage="*\\lsass.exe" OR TargetImage="*\\svchost.exe" OR TargetImage="*\\explorer.exe")
  NOT (SourceImage="*\\csrss.exe")
| table _time, ComputerName, SourceImage, TargetImage, StartAddress, StartModule</code></pre>

<h2>Credential Access</h2>

<h3>LSASS Memory Access (T1003.001) — Sysmon Event ID 10</h3>

<pre><code># KQL — LSASS process access by non-standard callers (Sysmon 10)
event.code:"10" AND
winlog.event_data.TargetImage:*\\lsass.exe AND
NOT winlog.event_data.SourceImage:(
  *\\wmiprvse.exe OR
  *\\taskmgr.exe OR
  *\\procexp64.exe OR
  *\\procexp.exe OR
  *\\svchost.exe OR
  *\\csrss.exe OR
  *\\werfault.exe OR
  *\\AV_PRODUCT_PATH*
) AND
winlog.event_data.GrantedAccess:(
  "0x1010" OR "0x1410" OR "0x147a" OR "0x1418" OR
  "0x1fffff" OR "0x1438" OR "0x143a" OR "0x1000"
)

# Splunk SPL equivalent
index=windows EventCode=10 TargetImage="*\\lsass.exe"
  NOT (SourceImage="*\\wmiprvse.exe" OR SourceImage="*\\svchost.exe" OR SourceImage="*\\csrss.exe")
  (GrantedAccess="0x1010" OR GrantedAccess="0x1fffff" OR GrantedAccess="0x1438")
| table _time, ComputerName, SourceImage, GrantedAccess, CallTrace</code></pre>

<h3>SAM Registry Access (T1003.002)</h3>

<pre><code># KQL — SAM hive access (4656 = handle request to registry key)
event.code:"4656" AND
winlog.event_data.ObjectName:*\\SAM AND
NOT winlog.event_data.ProcessName:(*\\lsass.exe OR *\\svchost.exe)

# Splunk SPL
index=windows EventCode=4656
  ObjectName="*\\SAM"
  NOT (ProcessName="*\\lsass.exe" OR ProcessName="*\\svchost.exe")
| table _time, ComputerName, SubjectUserName, ProcessName, ObjectName, AccessMask</code></pre>

<h2>Lateral Movement</h2>

<h3>PsExec Lateral Movement (T1021.002)</h3>

<pre><code># KQL — PsExec service creation (7045) with typical naming
event.code:"7045" AND
(
  winlog.event_data.ServiceName:(PSEXESVC OR *psexec*) OR
  winlog.event_data.ImagePath:(*\\PSEXESVC.exe OR *ADMIN$\\PSEXESVC*)
)

# KQL — Named pipe creation associated with PsExec (Sysmon 17)
event.code:"17" AND
winlog.event_data.PipeName:(\PSEXESVC* OR \\PSEXESVC*)

# Splunk SPL — PsExec service + named pipe correlation
index=windows (EventCode=7045 OR EventCode=17)
  (ServiceName="PSEXESVC" OR ServiceName="*psexec*" OR PipeName="*PSEXESVC*")
| table _time, ComputerName, ServiceName, ImagePath, PipeName</code></pre>

<h3>Pass-the-Hash (T1550.002)</h3>

<pre><code># KQL — Pass-the-Hash indicator: NtLmSsp auth, type 3 logon, non-machine account
event.code:"4624" AND
winlog.event_data.LogonType:"3" AND
winlog.event_data.AuthenticationPackageName:"NTLM" AND
winlog.event_data.LmPackageName:"NTLM V2" AND
NOT user.name:(*$ OR ANONYMOUS LOGON) AND
NOT source.ip:("127.0.0.1" OR "::1")

# Splunk SPL equivalent
index=windows EventCode=4624 LogonType=3
  AuthenticationPackageName="NTLM"
  LmPackageName="NTLM V2"
  NOT (TargetUserName="*$" OR TargetUserName="ANONYMOUS LOGON")
  NOT (IpAddress="127.0.0.1" OR IpAddress="-")
| table _time, ComputerName, TargetUserName, IpAddress, WorkstationName, LmPackageName</code></pre>

<h2>Command and Control</h2>

<h3>Beacon Timing Patterns (T1071.001)</h3>

<pre><code># KQL — Identify hosts making regular outbound connections (beaconing behavior)
# This requires aggregation — best done in Kibana Lens or as a saved search
# Look for: consistent destination IP, consistent byte count, regular intervals

event.dataset:"network_traffic.flow" AND
destination.port:(80 OR 443 OR 8080 OR 8443) AND
NOT destination.ip:("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16") AND
network.bytes:[100 TO 5000]

# Splunk SPL — Beacon detection via connection regularity
index=network sourcetype=zeek_conn
  NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12" OR dest_ip="192.168.0.0/16")
  dest_port IN (80, 443, 8080, 8443)
| bin span=1h _time
| stats count, avg(duration), stdev(duration) as jitter by src_ip, dest_ip, dest_port
| where count > 5 AND jitter < 5
| sort -count
| table _time, src_ip, dest_ip, dest_port, count, avg(duration), jitter</code></pre>

<h3>DNS Query Anomalies (T1071.004)</h3>

<pre><code># KQL — Long DNS subdomain queries (DNS tunneling / DGA indicator)
event.code:"22" AND
dns.question.name:* AND
NOT dns.question.name:(*.microsoft.com OR *.windows.com OR *.office.com OR *.google.com)

# Splunk SPL — DNS queries with abnormally long names (tunneling indicator)
index=dns sourcetype=zeek_dns
  NOT (query="*.microsoft.com" OR query="*.google.com" OR query="*.amazonaws.com")
| eval query_len=len(query)
| where query_len > 50
| stats count, avg(query_len) as avg_len by src_ip, query
| sort -count
| table src_ip, query, query_len, count</code></pre>

<h2>Exfiltration</h2>

<h3>Large Outbound Data Transfers (T1048)</h3>

<pre><code># KQL — Large outbound network flows to external destinations
event.dataset:"network_traffic.flow" AND
network.direction:"outbound" AND
destination.bytes:>10000000 AND
NOT destination.ip:("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16")

# Splunk SPL — Top talkers outbound (potential exfil)
index=network sourcetype=zeek_conn
  NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12")
| stats sum(resp_bytes) as total_bytes, count by src_ip, dest_ip, dest_port
| where total_bytes > 10000000
| eval total_mb=round(total_bytes/1048576, 2)
| sort -total_bytes
| table src_ip, dest_ip, dest_port, total_mb, count</code></pre>

<h2>Query Tuning Tips</h2>

<pre><code># Common tuning strategies to reduce false positives:
#
# 1. Filter known-good software by path
#    Add: NOT process.name:*\\SoftwareName\\executable.exe
#
# 2. Restrict to non-system accounts
#    Add: NOT user.name:(*$ OR SYSTEM OR "LOCAL SERVICE" OR "NETWORK SERVICE")
#
# 3. Add time window constraints in dashboards
#    Kibana: date range picker (top right)
#    Splunk: earliest=-1h latest=now
#
# 4. Use threshold-based triggers for noisy detections
#    KQL: requires Elastic alerting rules with count threshold
#    SPL: | stats count by src | where count > 10
#
# 5. Normalize hostnames in Splunk
#    | eval host=lower(ComputerName)
#
# 6. Test queries against known-bad and known-good
#    Run against your Atomic Red Team execution time window
#    Confirm true positive fires, confirm no false positives in quiet period</code></pre>

<h2>Resources</h2>

<ul>
  <li>KQL Reference — <code>elastic.co/guide/en/kibana/current/kuery-query.html</code></li>
  <li>Elastic ECS Field Reference — <code>elastic.co/guide/en/ecs/current/ecs-field-reference.html</code></li>
  <li>Splunk SPL Reference — <code>docs.splunk.com/Documentation/Splunk/latest/SearchReference</code></li>
  <li>MITRE ATT&amp;CK Windows Event ID Mapping — <code>attack.mitre.org/datasources/DS0017/</code></li>
  <li>Elastic Detection Rules (community) — <code>github.com/elastic/detection-rules</code></li>
  <li>Splunk Security Essentials App — <code>splunkbase.splunk.com/app/3435</code></li>
</ul>
