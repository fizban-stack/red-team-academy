---
layout: training-page
title: "Purple Teaming & Detection Engineering — Red Team Academy"
module: "Fundamentals"
tags:
  - purple-team
  - detection
  - sigma
  - yara
  - atomic-red-team
  - blue-team
page_key: "fundamentals-purple-teaming"
---

<h1>Purple Teaming &amp; Detection Engineering</h1>

<p>Purple teaming bridges offensive and defensive security by combining red team attack execution with blue team detection validation. A red team operator who understands detection engineering can craft operations that evade specific detection rules, validate that their techniques trigger (or don't trigger) alerts, and help the organization build better defenses. This page covers detection rule languages, testing frameworks, and the methodology for validating defensive coverage.</p>

<h2>Purple Team Methodology</h2>

<pre><code># Purple team engagement flow:
#
# 1. PLAN   — Select MITRE ATT&amp;CK techniques to test
# 2. DETECT — Review existing detection rules for those techniques
# 3. ATTACK — Execute the technique in a controlled environment
# 4. ASSESS — Did the detection fire? Was the alert accurate?
# 5. TUNE   — Improve detection rules OR improve evasion
# 6. REPEAT — Iterate with variations of the technique
#
# Difference from red team:
# - Red team: Goal is to succeed without detection
# - Purple team: Goal is to validate and improve detection
# - Both require the same technical skills</code></pre>

<h2>Sigma Rules</h2>

<p>Sigma is the universal detection rule format. Write once, convert to any SIEM (Splunk, Elastic, Sentinel, QRadar, etc.).</p>

<h3>Sigma Rule Structure</h3>

<pre><code># Sigma rules are YAML-based detection logic
# They describe WHAT to detect, not WHERE (SIEM-agnostic)

title: Suspicious LSASS Access
id: a2f29a63-5c48-4b3e-a7c8-bf89b3d3b123
status: stable
description: Detects suspicious access to LSASS process memory
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'    # PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION
      - '0x1038'    # PROCESS_VM_READ + PROCESS_VM_WRITE + PROCESS_QUERY_LIMITED_INFORMATION
      - '0x1FFFFF'  # PROCESS_ALL_ACCESS
  filter_legitimate:
    SourceImage|endswith:
      - '\wmiprvse.exe'
      - '\taskmgr.exe'
      - '\procexp64.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate administration tools
  - Security scanners
level: high</code></pre>

<h3>Writing Sigma Rules</h3>

<pre><code># Key detection patterns in Sigma:

# Process creation — detect suspicious command execution
title: Certutil Download
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - '-decode'
      - '/decode'
  condition: selection

# File creation — detect malicious file drops
title: Suspicious File in System32
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|startswith: 'C:\Windows\System32\'
    TargetFilename|endswith:
      - '.dll'
      - '.exe'
  filter:
    Image|endswith:
      - '\msiexec.exe'
      - '\TrustedInstaller.exe'
  condition: selection and not filter

# Registry — detect persistence
title: Run Key Persistence
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\CurrentVersion\Run'
      - '\CurrentVersion\RunOnce'
  condition: selection

# Network — detect C2 callbacks
title: Suspicious DNS Query
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName|endswith:
      - '.duckdns.org'
      - '.ngrok.io'
      - '.serveo.net'
  condition: selection</code></pre>

<h3>Sigma Rule Conversion</h3>

<pre><code># sigma-cli — convert Sigma to SIEM queries
pip install sigma-cli

# Convert to Splunk
sigma convert -t splunk -p sysmon rules/suspicious_lsass_access.yml

# Convert to Elastic/EQL
sigma convert -t elasticsearch -p ecs_windows rules/suspicious_lsass_access.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender rules/suspicious_lsass_access.yml

# Convert to QRadar AQL
sigma convert -t qradar rules/suspicious_lsass_access.yml

# Batch convert all rules
sigma convert -t splunk -p sysmon rules/ --output splunk_rules/

# SigmaHQ — the main Sigma rule repository
# github.com/SigmaHQ/sigma
# Contains 3000+ community-maintained detection rules</code></pre>

<h2>YARA Rules</h2>

<p>YARA is the pattern matching language for malware identification. Used for file scanning, memory scanning, and threat hunting.</p>

<pre><code># YARA rule structure
rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon in memory or on disk"
        author = "Red Team Academy"
        reference = "https://attack.mitre.org/software/S0154/"
        date = "2025-01-15"

    strings:
        // Beacon configuration patterns
        $config1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $config2 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? }

        // Named pipe patterns
        $pipe1 = "\\\\.\\pipe\\MSSE-" ascii
        $pipe2 = "\\\\.\\pipe\\msagent_" ascii
        $pipe3 = "\\\\.\\pipe\\postex_" ascii

        // Sleep mask patterns
        $sleep1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 }

        // Reflective loader
        $loader = { 4D 5A 41 52 55 48 89 E5 }

    condition:
        2 of ($config*) or
        any of ($pipe*) or
        ($sleep1 and $loader)
}

rule Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz by string patterns"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "lsadump::dcsync" ascii wide
        $s3 = "privilege::debug" ascii wide
        $s4 = "token::elevate" ascii wide
        $s5 = "gentilkiwi" ascii wide
        $s6 = "mimikatz" ascii wide nocase

    condition:
        3 of them
}</code></pre>

<h3>Using YARA for Threat Hunting</h3>

<pre><code># Scan a file
yara rules/cobalt_strike.yar suspect_binary.exe

# Scan a directory recursively
yara -r rules/ /path/to/scan/

# Scan a running process's memory
yara -p 1234 rules/beacon.yar

# Scan with multiple rule files
yara rules/apt_*.yar -r /tmp/artifacts/

# YARA with Python (for automation)
import yara
rules = yara.compile(filepath='rules/cobalt_strike.yar')
matches = rules.match('/path/to/suspect')
for match in matches:
    print(f"Rule: {match.rule}, Tags: {match.tags}")
    for s in match.strings:
        print(f"  Offset: {s[0]}, Identifier: {s[1]}, Data: {s[2]}")</code></pre>

<h2>Atomic Red Team</h2>

<p>Atomic Red Team provides small, focused test cases mapped to MITRE ATT&amp;CK. Each "atomic test" executes a single technique in isolation.</p>

<pre><code># Install Atomic Red Team (PowerShell)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# List available tests for a technique
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Execute a test
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Execute all tests for a technique
Invoke-AtomicTest T1003.001

# Execute with cleanup (undo changes after test)
Invoke-AtomicTest T1003.001 -Cleanup

# Get prerequisites (install dependencies)
Invoke-AtomicTest T1003.001 -GetPrereqs

# Common techniques to test:
# T1003     — OS Credential Dumping
# T1059     — Command and Scripting Interpreter
# T1053     — Scheduled Task/Job
# T1547     — Boot or Logon Autostart Execution
# T1021     — Remote Services
# T1055     — Process Injection
# T1027     — Obfuscated Files or Information
# T1071     — Application Layer Protocol</code></pre>

<h3>Linux Atomic Tests</h3>

<pre><code># Atomic tests work on Linux too
# Install
git clone https://github.com/redcanaryco/atomic-red-team.git

# Run with bash executor
# T1053.003 — Cron persistence
echo "* * * * * /tmp/art-test" | crontab -

# T1070.003 — Clear command history
export HISTFILESIZE=0
history -c

# T1136.001 — Create local account
sudo useradd -M -N -r -s /bin/bash art-test

# Cleanup
crontab -r
sudo userdel art-test</code></pre>

<h2>MITRE ATT&amp;CK Coverage Mapping</h2>

<pre><code># Map your detection coverage against ATT&amp;CK
# Tools for coverage assessment:

# ATT&amp;CK Navigator — visual layer editor
# mitre-attack.github.io/attack-navigator/
# Create layers showing:
# - Green: techniques with working detections
# - Yellow: techniques with partial detection
# - Red: techniques with no detection (gaps)
# - Blue: techniques tested in purple team exercises

# DeTT&amp;CT — Detection and TTP Coverage Tool
# github.com/rabobank-cdc/DeTTECT
# Maps data sources → ATT&amp;CK techniques → detection rules

# Export coverage as JSON for Navigator
{
  "name": "Detection Coverage",
  "versions": {"attack": "14", "navigator": "4.9"},
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1003.001", "score": 100, "color": "#00ff00",
     "comment": "Sigma rule: Suspicious LSASS Access"},
    {"techniqueID": "T1055.001", "score": 50, "color": "#ffff00",
     "comment": "Partial detection: only catches CreateRemoteThread"},
    {"techniqueID": "T1134.001", "score": 0, "color": "#ff0000",
     "comment": "No detection rule exists"}
  ]
}</code></pre>

<h2>Detection Engineering Workflow</h2>

<pre><code># Structured approach to building detections:
#
# 1. Select technique from ATT&amp;CK
# 2. Research: What artifacts does this technique produce?
#    - Event logs (Security, Sysmon, PowerShell)
#    - File system changes
#    - Registry modifications
#    - Network connections
#    - Process relationships
#
# 3. Data source check: Do we collect the required telemetry?
#    - Is Sysmon deployed? What config?
#    - Is PowerShell script block logging enabled?
#    - Is command line logging enabled? (ProcessCreationIncludeCmdLine)
#    - Are DNS queries logged?
#
# 4. Write detection rule (Sigma → convert to SIEM)
#
# 5. Test with Atomic Red Team or manual execution
#
# 6. Tune: Reduce false positives, increase true positives
#
# 7. Validate: Run red team variations to test robustness

# Essential Windows event IDs for detection:
# 4624  — Successful logon
# 4625  — Failed logon
# 4648  — Logon using explicit credentials
# 4672  — Special privileges assigned
# 4688  — Process creation (enable command line logging)
# 4698  — Scheduled task created
# 4720  — User account created
# 4732  — Member added to security-enabled local group
# 7045  — Service installed
# 1102  — Security log cleared

# Essential Sysmon event IDs:
# 1   — Process creation (with hashes, parent, command line)
# 3   — Network connection
# 7   — Image loaded (DLL)
# 8   — CreateRemoteThread
# 10  — Process access (LSASS monitoring)
# 11  — File creation
# 12  — Registry key/value create/delete
# 13  — Registry value set
# 17  — Pipe created
# 22  — DNS query
# 25  — Process tampering</code></pre>

<h2>Building a Detection Lab</h2>

<pre><code># Essential components for a purple team lab:

# 1. SIEM — Elastic Security (free), Splunk (free tier), Wazuh
# Elastic Security:
docker-compose up -d elasticsearch kibana
# Import Sigma rules via sigmac

# 2. Sysmon — Windows telemetry
# SwiftOnSecurity config (good baseline):
sysmon -accepteula -i sysmonconfig-export.xml

# Olaf Hartong's modular config (better granularity):
# github.com/olafhartong/sysmon-modular

# 3. Windows Event Forwarding (WEF)
# Centralize Windows event logs

# 4. Velociraptor — endpoint visibility and hunting
# github.com/Velocidex/velociraptor
# Provides live forensic capability during purple team exercises

# 5. Attack tools — see other pages for specific tools
# Atomic Red Team, Caldera, Infection Monkey</code></pre>

<h2>CALDERA — Automated Adversary Emulation</h2>

<pre><code># MITRE CALDERA — automated adversary emulation platform
# github.com/mitre/caldera

# Install
git clone --recursive https://github.com/mitre/caldera.git
cd caldera
pip install -r requirements.txt
python server.py --insecure

# CALDERA runs adversary profiles (chains of ATT&amp;CK techniques)
# Pre-built profiles:
# - Discovery — enumerate the environment
# - Collection — gather sensitive data
# - Credential Access — extract credentials
# - Lateral Movement — spread to other systems

# Deploy agents (called "sandcat")
# Download from CALDERA server and run on targets
# Agent reports back and executes abilities on command

# Create custom adversary profiles
# Chain techniques together for realistic attack simulation
# Automated purple team — attack executes, SIEM should alert</code></pre>

<h2>Resources</h2>

<ul>
  <li>SigmaHQ Rules Repository — <code>github.com/SigmaHQ/sigma</code></li>
  <li>Atomic Red Team — <code>github.com/redcanaryco/atomic-red-team</code></li>
  <li>MITRE ATT&amp;CK Navigator — <code>mitre-attack.github.io/attack-navigator</code></li>
  <li>MITRE CALDERA — <code>github.com/mitre/caldera</code></li>
  <li>Velociraptor — <code>github.com/Velocidex/velociraptor</code></li>
  <li>DeTT&amp;CT — <code>github.com/rabobank-cdc/DeTTECT</code></li>
  <li>YARA documentation — <code>yara.readthedocs.io</code></li>
  <li>Elastic Detection Rules — <code>github.com/elastic/detection-rules</code></li>
  <li>Sysmon Modular Config — <code>github.com/olafhartong/sysmon-modular</code></li>
</ul>
