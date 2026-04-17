---
layout: training-page
title: "Sigma Rules for Detection Engineering — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - sigma
  - detection-engineering
  - siem
  - yaml
  - sigma-cli
page_key: "purple-team-sigma-rules"
render_with_liquid: false
---

<h1>Sigma Rules for Detection Engineering</h1>

<p>Sigma is the universal detection rule format. Write a rule once and convert it to any SIEM: Elastic/KQL, Splunk SPL, Microsoft Sentinel KQL, QRadar AQL, Carbon Black, and dozens more. Sigma rules are YAML files that describe <em>what</em> to detect — the logsource (where to look) and the detection logic (what to match). The conversion pipeline handles the translation to SIEM-specific query syntax.</p>

<p>This page covers the Sigma rule format in depth, walks through writing rules for real attack techniques, and shows you how to convert and test them using sigma-cli.</p>

<h2>Sigma Rule Structure</h2>

<pre><code># Full Sigma rule schema — every field explained:

title: Short descriptive name (required)
#   Max ~100 chars, should identify the technique/behavior clearly

id: a2f29a63-5c48-4b3e-a7c8-bf89b3d3b123
#   UUID v4, unique identifier — generate with: python3 -c "import uuid; print(uuid.uuid4())"

status: stable
#   stable    — tested, low false positive rate, production-ready
#   test      — testing phase, needs validation in your environment
#   experimental — not fully tested, high false positive rate expected
#   deprecated — rule replaced or no longer relevant
#   unsupported — logsource not commonly available

description: |
  Detects specific behavior XYZ associated with technique T1234.
  Explain what artifact or behavior this rule detects and why
  it's significant. Include context about the attack technique.

references:
  - https://attack.mitre.org/techniques/T1234/
  - https://blog.example.com/technique-writeup
  - https://github.com/SigmaHQ/sigma/issues/1234

author: Your Name
date: 2025/01/15
modified: 2025/06/01

tags:
  - attack.tactic_name          # e.g., attack.execution
  - attack.tXXXX               # ATT&CK technique ID e.g., attack.t1059.001
  - attack.gXXXX               # ATT&CK group ID (optional)
  - attack.sXXXX               # ATT&CK software ID (optional)

logsource:
  category: process_creation   # OR use product + service directly
  product: windows
  # Logsource categories (most common):
  # process_creation    — process start events (Sysmon 1 / EventID 4688)
  # process_access      — handle/memory access (Sysmon 10)
  # network_connection  — outbound network (Sysmon 3)
  # file_event          — file create/modify (Sysmon 11)
  # registry_set        — registry value set (Sysmon 13)
  # registry_add        — registry key create (Sysmon 12)
  # dns_query           — DNS lookups (Sysmon 22)
  # pipe_created        — named pipe creation (Sysmon 17)
  # image_load          — DLL/image loaded (Sysmon 7)

detection:
  selection:
    # Field: value matching patterns
    # Use modifiers with | separator:
    #   |contains   — substring match
    #   |startswith — prefix match
    #   |endswith   — suffix match
    #   |re         — regex match
    #   |contains|all — all values must match (AND within list)
    #   |contains|any — any value matches (OR within list)
    FieldName|endswith: '\process.exe'
    CommandLine|contains:
      - 'suspicious_string1'
      - 'suspicious_string2'

  filter_main:
    # Exceptions — known-good processes/conditions to exclude
    Image|endswith:
      - '\legitimate.exe'
      - '\known_good.exe'

  condition: selection and not filter_main
  # Condition operators:
  # selection                    — just the selection
  # selection and filter         — selection AND filter (use for inclusions)
  # selection and not filter     — selection AND NOT filter (use for exclusions)
  # 1 of selection*              — any selection_* blocks match
  # all of them                  — all detection blocks match
  # selection | count() > 5      — threshold (frequency-based)
  # selection | near filter      — temporal correlation (sigma >= 0.19)

falsepositives:
  - Legitimate administration tools
  - Security product scanning
  - Software updates or deployment tools

level: high
# low, medium, high, critical
# Based on: confidence in detection, blast radius, severity of technique</code></pre>

<h2>Complete Sigma Rules — Eight Production Examples</h2>

<h3>1. AMSI Bypass via Reflection (T1562.001)</h3>

<pre><code>title: AMSI Bypass via Reflection in PowerShell Script Block
id: 8f1e4c2a-3b7d-4f9e-a8c5-1d2e3f4a5b6c
status: test
description: |
  Detects attempts to disable the Antimalware Scan Interface (AMSI) using
  .NET reflection to patch the AmsiScanBuffer function. A common technique
  used by attackers before executing malicious PowerShell payloads.
references:
  - https://attack.mitre.org/techniques/T1562/001/
  - https://amsi.fail/
  - https://rastamouse.me/memory-patching-amsi-bypass/
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  product: windows
  category: ps_script_block
detection:
  keywords:
    - 'amsiInitFailed'
    - 'AmsiScanBuffer'
    - 'AmsiUtils'
  amsi_reflection:
    ScriptBlockText|contains|all:
      - 'System.Management.Automation'
      - 'GetField'
  amsi_patch:
    ScriptBlockText|contains:
      - '[Ref].Assembly.GetType'
      - 'NonPublic,Static'
      - 'amsiContext'
  condition: keywords or amsi_reflection or amsi_patch
falsepositives:
  - Security research in controlled environments
  - Authorized red team exercises
level: high</code></pre>

<h3>2. Suspicious LSASS Access (T1003.001)</h3>

<pre><code">title: Suspicious LSASS Process Memory Access
id: a2f29a63-5c48-4b3e-a7c8-bf89b3d3b456
status: stable
description: |
  Detects suspicious access to the LSASS (Local Security Authority Subsystem Service)
  process memory. LSASS holds credentials in memory and is a primary target for
  credential theft tools like Mimikatz, ProcDump targeting LSASS, and Nanodump.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Procdump/
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
      - '0x1010'      # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
      - '0x1410'      # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
      - '0x147a'      # common Mimikatz access mask
      - '0x1418'      # Invoke-Mimikatz
      - '0x1fffff'    # PROCESS_ALL_ACCESS
      - '0x1438'
      - '0x143a'
  filter_legitimate:
    SourceImage|endswith:
      - '\wmiprvse.exe'
      - '\taskmgr.exe'
      - '\procexp64.exe'
      - '\procexp.exe'
      - '\csrss.exe'
      - '\werfault.exe'
      - '\werfaultsecure.exe'
      - '\MsMpEng.exe'    # Windows Defender
      - '\SavService.exe' # Sophos
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate administrative tools (Process Explorer, Task Manager)
  - Endpoint security products performing process inspection
  - Debugging tools in a dev environment
level: high</code></pre>

<h3>3. DCSync Attack Detection (T1003.006)</h3>

<pre><code>title: DCSync Attack — Directory Replication Privilege Request
id: 56128d72-c4d9-4e9b-b5f9-2c3a4d5e6f70
status: stable
description: |
  Detects DCSync attacks which abuse the MS-DRSR (Directory Replication Service
  Remote Protocol) to extract password hashes from a domain controller.
  The attack triggers Windows Security Event 4662 with specific GUIDs for
  the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights.
  Mimikatz dcsync and Impacket secretsdump use this technique.
references:
  - https://attack.mitre.org/techniques/T1003/006/
  - https://adsecurity.org/?p=1729
  - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.credential_access
  - attack.t1003.006
  - attack.s0002  # Mimikatz
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType|contains: 'domainDNS'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
      - '89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
  filter_dc_accounts:
    SubjectUserName|endswith: '$'  # Machine accounts (DCs replicating normally)
  filter_ad_sync:
    SubjectUserName|contains:
      - 'MSOL_'      # Azure AD Connect
      - 'AADConnect'
  condition: selection and not 1 of filter_*
falsepositives:
  - Domain controller normal replication (filtered by machine accounts)
  - Azure AD Connect synchronization service account
  - Legitimate directory synchronization tools
level: critical</code></pre>

<h3>4. Kerberoasting (T1558.003)</h3>

<pre><code>title: Kerberoasting — RC4 Encrypted Service Ticket Request
id: 3b4c5d6e-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: stable
description: |
  Detects Kerberoasting attacks where an attacker requests TGS (Service) tickets
  for service accounts using RC4 encryption (etype 23). Legitimate modern
  Kerberos uses AES-256 (etype 18). RC4 requests for service accounts with
  SPNs are a strong indicator of Kerberoasting activity.
  Tools: Rubeus, Impacket GetUserSPNs, PowerView.
references:
  - https://attack.mitre.org/techniques/T1558/003/
  - https://adsecurity.org/?p=2021
  - https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'    # RC4-HMAC (etype 23)
    TicketOptions: '0x40810000'     # Standard Kerberoasting ticket options
  filter_computer_accounts:
    ServiceName|endswith: '$'       # Filter machine account tickets
  filter_krbtgt:
    ServiceName: 'krbtgt'           # Filter krbtgt requests
  condition: selection and not 1 of filter_*
falsepositives:
  - Legacy applications that only support RC4 Kerberos encryption
  - Older Windows systems that downgrade Kerberos encryption
  - Specific legacy service accounts
level: high</code></pre>

<h3>5. Scheduled Task Creation by Non-Admin (T1053.005)</h3>

<pre><code">title: Suspicious Scheduled Task Created by Non-Administrative User
id: 4c5d6e7f-8a9b-0c1d-2e3f-4a5b6c7d8e9f
status: test
description: |
  Detects scheduled task creation by standard user accounts that are not
  typical administrative or system accounts. Attackers use scheduled tasks
  for persistence, privilege escalation, and lateral movement.
  Event 4698 fires when a new scheduled task is registered.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.005
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter_system_accounts:
    SubjectUserName|endswith: '$'
  filter_builtin:
    SubjectUserName:
      - 'SYSTEM'
      - 'LOCAL SERVICE'
      - 'NETWORK SERVICE'
      - 'Administrator'
  filter_known_software:
    TaskName|contains:
      - 'GoogleUpdate'
      - 'MicrosoftEdge'
      - 'OneDrive'
      - 'WindowsUpdate'
  condition: selection and not 1 of filter_*
falsepositives:
  - Legitimate software installation by standard users
  - Software deployment tools running as non-admin
  - Automation scripts with approved task creation
level: medium</code></pre>

<h3>6. PsExec Lateral Movement (T1021.002)</h3>

<pre><code">title: PsExec Lateral Movement — Service Creation and Named Pipe
id: 5d6e7f8a-9b0c-1d2e-3f4a-5b6c7d8e9f0a
status: stable
description: |
  Detects PsExec usage for lateral movement. PsExec creates a service
  (PSEXESVC) on the target host and communicates via a named pipe.
  Both the service creation event (7045) and named pipe creation (Sysmon 17)
  are captured. Correlate with Event 4624 type 3 logon from source host.
references:
  - https://attack.mitre.org/techniques/T1021/002/
  - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  product: windows
  service: system
detection:
  selection_service:
    EventID: 7045
    ServiceName|contains:
      - 'PSEXESVC'
      - 'psexec'
  selection_imagepath:
    EventID: 7045
    ImagePath|contains:
      - 'ADMIN$'
      - 'PSEXESVC.exe'
  condition: 1 of selection_*
falsepositives:
  - Authorized use of PsExec by system administrators
  - IT automation tools using PsExec for legitimate deployments
level: high

---
# Companion rule — named pipe variant (Sysmon logsource)
title: PsExec Named Pipe Creation
id: 6e7f8a9b-0c1d-2e3f-4a5b-6c7d8e9f0a1b
status: stable
logsource:
  product: windows
  category: pipe_created
detection:
  selection:
    PipeName|startswith:
      - '\PSEXESVC'
      - '\psexecsvc'
  condition: selection
falsepositives:
  - Authorized PsExec use
level: high</code></pre>

<h3>7. DNS Covert Channel (T1071.004)</h3>

<pre><code">title: DNS Covert Channel — Abnormally Long DNS Query Names
id: 7f8a9b0c-1d2e-3f4a-5b6c-7d8e9f0a1b2c
status: test
description: |
  Detects potential DNS tunneling or covert channel activity by identifying
  DNS queries with unusually long subdomain names. DNS tunneling tools
  (Iodine, DNScat2, Cobalt Strike DNS C2) encode data in subdomain labels,
  resulting in query names significantly longer than typical domain names.
  Threshold of 50 characters is a starting point — tune for your environment.
references:
  - https://attack.mitre.org/techniques/T1071/004/
  - https://github.com/yarrick/iodine
  - https://github.com/iagox86/dnscat2
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
logsource:
  product: windows
  category: dns_query
detection:
  selection:
    QueryName|re: '^[a-zA-Z0-9\-]{50,}\.'
  filter_known_long:
    QueryName|endswith:
      - '.cloudfront.net'
      - '.azurewebsites.net'
      - '.googleusercontent.com'
      - '.windows.net'
      - '.amazonaws.com'
  condition: selection and not filter_known_long
falsepositives:
  - CDN domains with long hostnames (filtered above)
  - Certificate transparency subdomains
  - Some legitimate SaaS vendor domains
level: medium</code></pre>

<h3>8. Pass-the-Hash via NTLM (T1550.002)</h3>

<pre><code">title: Pass-the-Hash — NTLM Type 3 Logon from Non-Domain Controller
id: 8a9b0c1d-2e3f-4a5b-6c7d-8e9f0a1b2c3d
status: stable
description: |
  Detects Pass-the-Hash attacks by identifying NTLM network logon events
  (Event 4624, Logon Type 3) with NtLmSsp authentication package from
  non-machine, non-anonymous accounts. Pass-the-Hash uses captured NTLM
  hashes without knowing the plaintext password to authenticate laterally.
  Tools: Impacket, CrackMapExec, Mimikatz sekurlsa::pth.
references:
  - https://attack.mitre.org/techniques/T1550/002/
  - https://www.sans.org/reading-room/whitepapers/testing/detecting-pass-hash-36067
author: Red Team Academy
date: 2025/01/15
tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.t1550.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    LmPackageName:
      - 'NTLM V1'
      - 'NTLM V2'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  filter_anonymous:
    TargetUserName: 'ANONYMOUS LOGON'
  filter_local:
    IpAddress:
      - '127.0.0.1'
      - '::1'
      - '-'
  condition: selection and not 1 of filter_*
falsepositives:
  - Legitimate NTLM authentication in environments without Kerberos
  - Legacy applications that only support NTLM
  - Workgroup (non-domain) environments
level: high</code></pre>

<h2>Converting Sigma Rules to SIEM Backends</h2>

<pre><code># sigma-cli — official Sigma conversion tool
# https://github.com/SigmaHQ/sigma-cli

# Install
pip install sigma-cli

# List available backends and pipelines
sigma list backends
sigma list pipelines

# Convert a single rule to Elastic KQL (ECS format)
sigma convert -t elasticsearch -p ecs_windows rules/lsass_access.yml

# Convert to Splunk SPL
sigma convert -t splunk -p sysmon rules/lsass_access.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender rules/kerberoasting.yml

# Convert to Elastic EQL (Event Query Language)
sigma convert -t elasticsearch_eql -p ecs_windows rules/dcsync.yml

# Convert to QRadar AQL
sigma convert -t qradar rules/psexec.yml

# Convert to Carbon Black
sigma convert -t carbonblack rules/amsi_bypass.yml

# Batch convert entire directory to Elastic KQL
sigma convert -t elasticsearch -p ecs_windows -r rules/ -o output_queries.txt

# Convert with output format (sigma 0.19+)
sigma convert -t splunk -p sysmon --output-format savedsearches rules/ > savedsearches.conf

# pySigma — Python library for programmatic conversion
pip install pysigma
pip install pysigma-backend-elasticsearch
pip install pysigma-pipeline-sysmon

# Python conversion example
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline

pipeline = sysmon_pipeline()
backend = LuceneBackend(pipeline)
rules = SigmaCollection.load_ruleset(["rules/"])
queries = backend.convert(rules)
for query in queries:
    print(query)</code></pre>

<h2>Testing Sigma Rules with sigma-cli</h2>

<pre><code># Validate rule syntax
sigma check rules/lsass_access.yml

# Validate all rules in a directory
sigma check -r rules/

# Test rule against sample events (requires sigma-test backend)
# Create a test file: lsass_access_test.yml
# ---
# title: Test cases for LSASS access rule
# tests:
#   - name: True positive - Mimikatz LSASS access
#     event:
#       TargetImage: C:\Windows\system32\lsass.exe
#       GrantedAccess: '0x1fffff'
#       SourceImage: C:\Users\attacker\mimikatz.exe
#     result: match
#   - name: False positive - Windows Defender
#     event:
#       TargetImage: C:\Windows\system32\lsass.exe
#       GrantedAccess: '0x1010'
#       SourceImage: C:\Program Files\Windows Defender\MsMpEng.exe
#     result: no_match

# Community Sigma rules repository
# https://github.com/SigmaHQ/sigma
# Contains 3000+ curated detection rules across Windows, Linux, macOS, Cloud
# Clone and use as your baseline detection library:
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
ls sigma/rules/windows/</code></pre>

<h2>Logsource Category Reference</h2>

<pre><code># Sigma logsource categories and the Sysmon/Windows event IDs they map to:
#
# category: process_creation
#   → Sysmon Event ID 1 (preferred — includes hashes, parent, cmdline)
#   → Windows Security 4688 (requires command line audit policy enabled)
#
# category: process_access (process_access)
#   → Sysmon Event ID 10
#
# category: network_connection
#   → Sysmon Event ID 3
#
# category: file_event
#   → Sysmon Event ID 11 (file created)
#   → Sysmon Event ID 23 (file deleted)
#
# category: registry_set
#   → Sysmon Event ID 13 (registry value set)
#
# category: registry_add
#   → Sysmon Event ID 12 (registry key created/deleted)
#
# category: dns_query
#   → Sysmon Event ID 22
#
# category: pipe_created
#   → Sysmon Event ID 17 (named pipe created)
#   → Sysmon Event ID 18 (named pipe connected)
#
# category: image_load
#   → Sysmon Event ID 7 (image/DLL loaded)
#
# category: ps_script_block (PowerShell)
#   → Windows PowerShell/Operational Event ID 4104
#
# product: windows, service: security
#   → Windows Security Event Log (4624, 4625, 4698, 4662, etc.)
#
# product: windows, service: system
#   → Windows System Event Log (7045, 7034, etc.)</code></pre>

<h2>Resources</h2>

<ul>
  <li>SigmaHQ Rules Repository — <code>github.com/SigmaHQ/sigma</code></li>
  <li>sigma-cli Documentation — <code>github.com/SigmaHQ/sigma-cli</code></li>
  <li>pySigma Documentation — <code>github.com/SigmaHQ/pySigma</code></li>
  <li>Sigma Specification — <code>github.com/SigmaHQ/sigma/wiki/Specification</code></li>
  <li>Uncoder.IO — online Sigma converter — <code>uncoder.io</code></li>
  <li>SOC Prime Threat Detection Marketplace — <code>socprime.com</code></li>
</ul>
