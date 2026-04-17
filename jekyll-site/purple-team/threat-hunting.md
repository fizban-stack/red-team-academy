---
layout: training-page
title: "Threat Hunting Methodology — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - threat-hunting
  - hypothesis-driven
  - peak-methodology
  - lolbins
  - beaconing
  - edr
page_key: "purple-team-threat-hunting"
render_with_liquid: false
---

<h1>Threat Hunting Methodology</h1>

<p>Threat hunting is the proactive, hypothesis-driven search for attackers who have already evaded your detection controls. Unlike reactive detection (waiting for an alert), threat hunting assumes breach: an attacker may be present in your environment right now, operating below the alert threshold of your existing detection rules. Hunters use knowledge of adversary tradecraft, data science intuition, and deep familiarity with normal behavior baselines to find anomalies that rules haven't been written to catch yet.</p>

<p>Effective hunting produces two outputs: confirmed findings (escalated to incident response) and unconfirmed findings converted into detection rules (raising the detection floor for next time).</p>

<h2>PEAK Hunting Methodology</h2>

<pre><code># PEAK: Prepare, Execute, Act with Knowledge
# A structured methodology for repeatable, measurable threat hunting
# Developed by Splunk Threat Research Team
#
# PHASE 1: PREPARE
# ----------------
# Goal: Define a testable hypothesis before touching any data
#
# 1a. Hypothesis formulation
#     A hypothesis is a specific, testable statement:
#     FORMAT: "I believe [adversary technique] is occurring on [target systems]
#              because [threat intel / intuition / anomaly observed]"
#
#     GOOD hypothesis:
#     "I believe an attacker is using living-off-the-land binaries (LOLBins)
#      for lateral movement on Windows servers because our threat intel indicates
#      our sector is being targeted by FIN7 who heavily uses this technique."
#
#     BAD hypothesis:
#     "I'm going to look at PowerShell logs for something suspicious."
#     (Too vague — no specific technique, no success criteria, no scope)
#
# 1b. Data source verification
#     Before hunting, confirm the required data is available:
#     - Is Sysmon deployed on the target systems?
#     - Is the relevant event channel being collected?
#     - What's the retention period? Is the window you need still available?
#     - Do you have the right field mapping for your SIEM?
#
# 1c. Define success criteria
#     What would a confirmed finding look like?
#     What would a clean bill of health look like?
#     How many results before you escalate vs tune and continue?
#
# PHASE 2: EXECUTE
# ----------------
# Goal: Systematically test the hypothesis using queries and analysis
#
# 2a. Write the initial query (broad, then narrow)
#     Start broad to understand the data landscape
#     Progressively narrow using filters and conditions
#     Document each query iteration and result counts
#
# 2b. Baseline analysis
#     What is normal for this environment?
#     Count occurrences by host, user, time of day
#     Identify statistical outliers
#
# 2c. Pivot on anomalies
#     Interesting finding? Pivot: same user? Same host? Same time?
#     Use SIEM correlations, EDR process tree, DNS logs to enrich
#
# PHASE 3: ACT WITH KNOWLEDGE
# ----------------------------
# Goal: Convert hunt outcomes into durable security improvements
#
# 3a. Confirmed malicious finding → Escalate to IR
#     Document: technique, host, user, timestamps, evidence
#     Hand off to incident response with full context
#
# 3b. Unconfirmed / interesting finding → Detection rule
#     Convert hunt query to Sigma rule
#     Test against known-bad ART executions
#     Deploy to SIEM as live detection rule
#
# 3c. Clean result → Document and close
#     Record: hypothesis, data source, query, finding (negative)
#     Negative results have value — they confirm coverage
#     Useful for: ATT&CK coverage map updates, compliance evidence</code></pre>

<h2>Data Sources for Threat Hunting</h2>

<pre><code># Primary data sources ranked by hunting value:
#
# EDR TELEMETRY (Highest value)
#   - Process creation with full command line, hashes, parent/child tree
#   - File operations (read, write, delete, rename)
#   - Registry modifications
#   - Network connections from process context
#   - Memory operations (injection, hollowing indicators)
#   - Sources: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint
#              Elastic Endpoint, Sysmon + Winlogbeat (open-source equivalent)
#
# WINDOWS EVENT LOGS
#   - Authentication events: 4624, 4625, 4648, 4768, 4769, 4771
#   - Process creation: 4688 (requires audit policy enabling)
#   - Scheduled tasks: 4698, 4702
#   - Service operations: 7045, 7034
#   - Object access: 4656, 4663 (requires SACL configuration)
#   - Sysmon: the enhanced version of the above
#
# NETWORK FLOW DATA (NetFlow / Zeek / IPFIX)
#   - Connection volume, duration, bytes per session
#   - Port/protocol inventory per host
#   - Peer-to-peer connections between internal hosts
#   - Long-duration sessions (potential beaconing / tunneling)
#   - DNS query volume and response patterns
#
# DNS LOGS
#   - Query name length (DNS tunneling: long names)
#   - Query frequency (beaconing: regular intervals)
#   - NXDOMAIN ratio (DGA: high failure rate)
#   - First-seen domains (new infrastructure)
#   - PTR vs A record mismatches
#
# PROXY / WEB GATEWAY LOGS
#   - User-agent strings (malware often uses hardcoded or unusual UAs)
#   - URL patterns (C2 often uses specific paths or patterns)
#   - Bytes transferred per session (exfil: large unusual uploads)
#   - Destination reputation (new/uncategorized domains)
#
# VELOCIRAPTOR / LIVE FORENSICS
#   - Process memory: running processes and their loaded modules
#   - Autoruns: registry run keys, scheduled tasks, services, startup
#   - Prefetch: historical execution evidence (up to 128 entries)
#   - ShimCache / AmCache: program execution artifacts
#   - MFT: file system timeline</code></pre>

<h2>Hunt Playbook 1: Living-off-the-Land Binaries (LOLBins)</h2>

<pre><code># HUNT: Unusual LOLBin Execution
# Hypothesis: An attacker is using Windows built-in binaries (LOLBins) to
#             execute commands or download payloads without introducing new
#             executables, evading application allowlisting controls.
# ATT&CK: T1218 (Signed Binary Proxy Execution), T1059.001, T1105
# Data Source: Sysmon Event 1 (process_creation), Windows 4688
#
# KQL Query — LOLBins with unusual command lines
event.code:"1" AND
winlog.event_data.Image:(
  *\\certutil.exe OR
  *\\mshta.exe OR
  *\\regsvr32.exe OR
  *\\wscript.exe OR
  *\\cscript.exe OR
  *\\bitsadmin.exe OR
  *\\esentutl.exe OR
  *\\expand.exe OR
  *\\extrac32.exe OR
  *\\wmic.exe
) AND
winlog.event_data.CommandLine:(*http* OR *ftp* OR *\\\\* OR *Invoke* OR *download*)

# Splunk SPL equivalent
index=windows EventCode=1
  (Image="*\\certutil.exe" OR Image="*\\mshta.exe" OR Image="*\\regsvr32.exe"
   OR Image="*\\wscript.exe" OR Image="*\\bitsadmin.exe")
  (CommandLine="*http*" OR CommandLine="*ftp*" OR CommandLine="*\\\\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage, Hashes

# EXPECTED FINDINGS: certutil -urlcache, regsvr32 /s /u /i:http...
# FALSE POSITIVES: SCCM deployments, software updates using certutil
# HANDLING FPs: Filter by ParentImage (SCCM paths) and known software update paths
# PIVOT: On any result → check same host for network connections at same time</code></pre>

<h2>Hunt Playbook 2: Beaconing Detection</h2>

<pre><code># HUNT: Network Beaconing (C2 Callback Pattern)
# Hypothesis: A compromised host is running a C2 implant that periodically
#             calls back to an attacker-controlled server on a regular interval.
# ATT&CK: T1071.001, T1071.004, T1132
# Data Source: Network flow data (Zeek conn.log, NetFlow, proxy logs)
#
# KQL Query — connections with periodic intervals to same destination
# (This requires aggregation — Kibana Lens or TSVB visualization works well)
event.dataset:"network_traffic.flow" AND
NOT destination.ip:("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16" OR "127.0.0.0/8") AND
destination.port:(80 OR 443 OR 8080 OR 8443 OR 4443) AND
network.bytes:[100 TO 10000]

# Splunk SPL — Beaconing via standard deviation analysis
# Low jitter = regular interval = potential beacon
index=network sourcetype=zeek_conn
  NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12" OR dest_ip="192.168.0.0/16")
  dest_port IN (80, 443, 8080, 8443)
| eval interval=relative_time(now(), "@s")
| bin span=1m _time
| stats count, avg(orig_bytes) as avg_bytes, stdev(duration) as jitter
  by src_ip, dest_ip, dest_port
| where count > 20 AND jitter < 2.0 AND avg_bytes < 5000
| sort -count
| table src_ip, dest_ip, dest_port, count, avg_bytes, jitter

# EXPECTED FINDINGS: Hosts with jitter < 2 seconds and regular 30s/60s intervals
# FALSE POSITIVES: NTP, telemetry agents, monitoring software
# HANDLING FPs: Whitelist known telemetry endpoints, NTP servers, corporate proxy IPs
# PIVOT: Suspicious IP → Threat intel lookup → WHOIS/registration date
#         Old domain with recent registration = high suspicion</code></pre>

<h2>Hunt Playbook 3: Credential Access</h2>

<pre><code># HUNT: Credential Access via LSASS, SAM, and NTDS
# Hypothesis: An attacker with local admin access is attempting to harvest
#             credentials from memory or registry to enable lateral movement.
# ATT&CK: T1003.001, T1003.002, T1003.003
# Data Source: Sysmon Event 10 (process_access), Windows Security 4656
#
# KQL — LSASS process access by unusual callers
event.code:"10" AND
winlog.event_data.TargetImage:*\\lsass.exe AND
NOT winlog.event_data.SourceImage:(
  *\\MsMpEng.exe OR *\\svchost.exe OR *\\csrss.exe OR *\\werfault.exe OR
  *\\taskmgr.exe OR *\\procexp64.exe OR *\\procexp.exe
)

# KQL — SAM hive read (credential extraction from offline registry)
event.code:("4656" OR "4663") AND
winlog.event_data.ObjectName:("\\REGISTRY\\MACHINE\\SAM" OR "*\\SAM\\SAM*")

# Splunk SPL — LSASS access with enrichment
index=windows EventCode=10 TargetImage="*\\lsass.exe"
  NOT (SourceImage="*\\MsMpEng.exe" OR SourceImage="*\\svchost.exe")
| eval risk_score=case(
    match(GrantedAccess,"0x1fffff"), 100,
    match(GrantedAccess,"0x1410"), 75,
    match(GrantedAccess,"0x1010"), 50,
    1==1, 25)
| sort -risk_score
| table _time, ComputerName, User, SourceImage, GrantedAccess, CallTrace, risk_score

# Velociraptor hunt — find processes with lsass.exe handles (live)
# VQL query to run as a hunt in Velociraptor:
# SELECT Pid, Name, Exe, Username,
#   handle(pid=Pid, types='Process') as Handles
# FROM pslist()
# WHERE Name = 'lsass.exe' AND
#   handle.Name =~ 'lsass'

# EXPECTED FINDINGS: processes with unusual GrantedAccess masks to lsass.exe
# FALSE POSITIVES: AV/EDR (filtered above), debugging sessions
# HANDLING FPs: Build per-environment filter list for known-good security tools</code></pre>

<h2>Hunt Playbook 4: Persistence via Autoruns</h2>

<pre><code># HUNT: Unauthorized Persistence Mechanisms
# Hypothesis: An attacker has established persistence via run keys, scheduled
#             tasks, or services that survive reboots and are not in our
#             software inventory baseline.
# ATT&CK: T1053.005, T1543.003, T1547.001, T1574.001
# Data Source: Sysmon 12/13 (registry), 4698 (scheduled tasks), 7045 (services)
#
# KQL — Registry run key modifications (Sysmon 13)
event.code:"13" AND
winlog.event_data.TargetObject:(
  *\\CurrentVersion\\Run\\* OR
  *\\CurrentVersion\\RunOnce\\* OR
  *\\CurrentVersion\\RunServices* OR
  *Policies\\Explorer\\Run*
) AND
NOT winlog.event_data.Image:(*\\msiexec.exe OR *\\TrustedInstaller.exe OR *\\MsMpEng.exe)

# Splunk SPL — Baseline comparison for scheduled tasks
# Run this to build a baseline at known-clean time, compare weekly
index=windows EventCode=4698
| eval task_week=strftime(_time,"%Y-W%V")
| stats count by task_week, TaskName, TaskContent
| sort task_week
| streamstats count as appearance by TaskName
| where appearance = 1
| table task_week, TaskName, TaskContent

# Velociraptor autoruns hunt — comprehensive persistence inventory
# Deploy as a scheduled hunt to all endpoints
# Artifact: Windows.System.Autoruns
# Compares against approved software baseline hash list

# EXPECTED FINDINGS: new scheduled tasks, run key entries added outside of patch windows
# FALSE POSITIVES: software installations, update mechanisms, RMM tools
# HANDLING FPs: Maintain approved autorun baseline; new software installs require sign-off
# PIVOT: Unknown task → check TaskContent command → analyze binary hash in VT/threat intel</code></pre>

<h2>Hunt Playbook 5: Lateral Movement Patterns</h2>

<pre><code># HUNT: Unusual Authentication and Lateral Movement
# Hypothesis: An attacker with harvested credentials is moving laterally
#             between Windows hosts using SMB/WMI/WinRM/RDP.
# ATT&CK: T1021.001, T1021.002, T1021.003, T1021.006
# Data Source: Windows Security 4624/4625, Sysmon 3
#
# KQL — Interactive or network logons to multiple hosts from single source
event.code:"4624" AND
winlog.event_data.LogonType:("3" OR "10") AND
NOT winlog.event_data.TargetUserName:(*$ OR ANONYMOUS LOGON) AND
NOT source.ip:("127.0.0.1" OR "-")

# Splunk SPL — Find accounts authenticating to unusually many hosts (lateral movement)
index=windows EventCode=4624 (LogonType=3 OR LogonType=10)
  NOT (TargetUserName="*$" OR TargetUserName="ANONYMOUS LOGON")
  NOT (IpAddress="127.0.0.1" OR IpAddress="-")
| stats dc(ComputerName) as host_count, values(ComputerName) as hosts,
        values(IpAddress) as source_ips
  by TargetUserName, LogonType
| where host_count > 3
| sort -host_count
| table TargetUserName, host_count, hosts, source_ips, LogonType

# KQL — WMI lateral movement (wmiprvse parent spawning child processes)
event.code:"1" AND
winlog.event_data.ParentImage:*\\wmiprvse.exe AND
NOT winlog.event_data.Image:(*\\msiexec.exe OR *\\WmiPrvSE.exe OR *\\svchost.exe)

# KQL — WinRM lateral (wsmprovhost spawning processes on target)
event.code:"1" AND
winlog.event_data.ParentImage:*\\wsmprovhost.exe

# EXPECTED FINDINGS: accounts logging into 5+ unique hosts within 1 hour
# FALSE POSITIVES: IT administrators, monitoring accounts, service accounts
# HANDLING FPs: Maintain list of privileged admin accounts with expected behavior</code></pre>

<h2>Hunt Playbook 6: Data Staging and Exfiltration</h2>

<pre><code># HUNT: Data Staging Before Exfiltration
# Hypothesis: An attacker with access to sensitive data is staging it for
#             exfiltration — compressing files, copying to temp directories,
#             or using cloud sync tools to move data out.
# ATT&CK: T1074.001, T1560.001, T1041, T1048
# Data Source: Sysmon 11 (file create), network flow
#
# KQL — Archive creation in temp directories (staging behavior)
event.code:"11" AND
winlog.event_data.TargetFilename:(
  *\\Temp\\*.zip OR *\\Temp\\*.rar OR *\\Temp\\*.7z OR
  *\\AppData\\Local\\Temp\\*.zip OR
  *\\AppData\\Roaming\\*.zip OR
  *\\Users\\Public\\*.zip OR *\\Users\\Public\\*.rar
) AND
NOT winlog.event_data.Image:(*\\7zFM.exe OR *\\WinRar.exe OR *\\explorer.exe)

# KQL — Compression utilities run on sensitive directories
event.code:"1" AND
winlog.event_data.Image:(*\\7z.exe OR *\\rar.exe OR *\\7za.exe OR *\\compress.exe) AND
winlog.event_data.CommandLine:(*\\Users\\* OR *\\Documents\\* OR *\\Desktop\\* OR *\\Finance\\*)

# Splunk SPL — Large file creation events followed by outbound transfer
index=windows EventCode=11
  (TargetFilename="*\\Temp\\*.zip" OR TargetFilename="*\\Temp\\*.rar")
  NOT (Image="*\\7zFM.exe" OR Image="*\\explorer.exe")
| table _time, ComputerName, User, Image, TargetFilename
| join ComputerName
  [search index=network sourcetype=zeek_conn resp_bytes>1000000
    NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12")
  | table _time, src_ip, dest_ip, dest_port, resp_bytes, conn_state
  | rename src_ip as ComputerName]
| table _time, ComputerName, User, TargetFilename, dest_ip, resp_bytes

# Splunk SPL — DNS exfiltration (high query rate with long names)
index=dns sourcetype=zeek_dns
| eval name_len=len(query)
| where name_len > 40
| bin span=5m _time
| stats count, dc(query) as unique_subdomains, avg(name_len) as avg_len by src_ip, _time
| where count > 100 AND unique_subdomains > 50
| sort -count

# EXPECTED FINDINGS: archive creation in unusual paths, large compressed files in temp
# FALSE POSITIVES: backup agents, legitimate compression tasks, software deployment
# HANDLING FPs: Baseline normal backup agent paths; filter by known backup tool image paths</code></pre>

<h2>Converting Hunt Findings to Detection Rules</h2>

<pre><code># Workflow: Hunt finding → Sigma rule → Production detection
#
# Step 1: Identify the essential signal from your hunt query
#   Your hunt query may be broad (high sensitivity, high FPs)
#   The detection rule should be narrow (low FPs, high precision)
#   Extract: which fields, which values, which conditions define the attack?
#
# Step 2: Write the Sigma rule from your hunt query
#   Use the hunt as the detection logic baseline
#   Add filter blocks for every false positive source you identified
#   Set appropriate logsource category for your event source
#
# Step 3: Test against Atomic Red Team ground truth
#   Execute the technique: Invoke-AtomicTest T1074.001 -TestNumbers 1
#   Confirm rule fires (true positive)
#   Run during a clean period, confirm no spurious fires (false positive check)
#
# Step 4: Assign severity level and metadata
#   level: critical/high/medium/low
#   ATT&CK tags: attack.tXXXX
#   References: technique URL, hunt write-up, any relevant blog posts
#
# Step 5: Deploy to SIEM detection pipeline
#   sigma convert -t elasticsearch -p ecs_windows rules/new_rule.yml
#   Import into Kibana Detection Rules
#   Set alert action: create case, notify SOC team
#
# Step 6: Update ATT&CK coverage map
#   Open Navigator layer
#   Find the technique, update score from 0 → 2
#   Add comment: "Sigma: [rule filename] — Hunt: [hunt name] — [date deployed]"
#   Commit updated layer to git

# Hunt finding documentation template:
#
# Hunt: [Hunt name]
# Date: [YYYY-MM-DD]
# Hunter: [Name]
# Hypothesis: [Original hypothesis statement]
# Data Source: [Event IDs, log sources queried]
# Query: [Final query used]
# Findings: [What was found — confirmed malicious / FP / negative]
# Evidence: [Host, user, time, command, artifact details]
# Disposition: [Escalated to IR / Converted to detection rule / Closed negative]
# Rule Created: [Sigma rule filename if applicable]
# ATT&CK Updated: [Technique ID, new score]</code></pre>

<h2>Hunting Calendar and Cadence</h2>

<pre><code># Recommended threat hunting cadence:
#
# WEEKLY (2-4 hours)
#   - Review new threat intelligence for active campaigns
#   - Run 1-2 targeted hunts based on recent TTPs in the news
#   - Spot-check new systems added since last week
#   - Review any detection rule gaps flagged from this week's purple team work
#
# MONTHLY (1-2 days)
#   - Full run of all 6 core playbooks against 30-day data window
#   - Review and close action items from previous month hunts
#   - Update ATT&CK Navigator layer with any new detections
#   - Hunt for threat actors specifically targeting your industry (use MITRE groups)
#
# QUARTERLY (2-3 days)
#   - Full environment sweep with fresh hypothesis set
#   - Review hypothesis backlog — generate 10-15 new hypotheses from threat intel
#   - Analyze hunt effectiveness: how many findings, conversion rate to rules
#   - Brief CISO on hunting program metrics
#
# EVENT-DRIVEN (immediately)
#   - Major vulnerability disclosed (Log4Shell, ProxyShell, Exchange zero-days)
#   - Threat intel indicates specific TTPs targeting your sector
#   - After a real incident: hunt for same TTP across rest of environment
#   - After a red team engagement: hunt for the specific techniques used</code></pre>

<h2>Resources</h2>

<ul>
  <li>PEAK Hunting Methodology — <code>splunk.com/en_us/blog/security/peak-a-threat-hunting-model.html</code></li>
  <li>ThreatHunting.net Playbooks — <code>threathunting.net</code></li>
  <li>MITRE TTP-Based Hunting — <code>attack.mitre.org/techniques/enterprise</code></li>
  <li>Sigma Rules for Hunt Conversion — <code>github.com/SigmaHQ/sigma</code></li>
  <li>Velociraptor Artifacts — <code>docs.velociraptor.app/artifact_references</code></li>
  <li>Elastic Hunting Guides — <code>elastic.co/security-labs/hunting-topics</code></li>
  <li>Zeek Network Analysis — <code>zeek.org</code></li>
  <li>LOLBins Reference — <code>lolbas-project.github.io</code></li>
  <li>Mordor Dataset (hunt practice data) — <code>mordordatasets.com</code></li>
</ul>
