---
layout: training-page
title: "PurpleSharp — Active Directory Adversary Simulation — Red Team Academy"
module: "Red Team Tools"
tags:
  - purplesharp
  - active-directory
  - purple-team
  - kerberoasting
  - detection-engineering
  - adversary-simulation
page_key: "tools-purplesharp"
render_with_liquid: false
---

# PurpleSharp — Active Directory Adversary Simulation

PurpleSharp (Mauricio Velazco, `mvelazc0`) is a C# adversary-simulation tool built specifically for generating high-fidelity attack telemetry in Active Directory environments. Its purpose is precise: give blue teams repeatable, ATT&CK-mapped attack traffic so they can build and tune detections against the AD techniques that actually matter.

Unlike Atomic Red Team (broad cross-platform single commands) or CALDERA (full autonomous chains), PurpleSharp targets the **AD attack layer specifically** — Kerberoasting, DCSync, Pass-the-Hash, lateral movement across domain hosts — with multiple implementation variants per technique and realistic user impersonation.

**Status (2025):** Active but stable-cadence. Last commit Dec 2024. Repo is NOT archived. 846 stars, BSD 3-Clause. The tool reached feature stability because the AD attack surface it targets hasn't changed materially. 47 ATT&CK techniques supported. Built against .NET 4.5 — runs on any domain-joined Windows from Server 2008 R2 forward.

## Supported Techniques by Tactic

### Discovery
- T1087 — Account Discovery (local + domain)
- T1018 — Remote System Discovery
- T1135 — Network Share Discovery
- T1069 — Permission Groups Discovery
- T1016 — System Network Configuration Discovery
- T1049 — System Network Connections Discovery
- T1033 — System Owner/User Discovery
- T1057 — Process Discovery
- T1083 — File and Directory Discovery

### Credential Access (the high-signal AD techniques)
- T1003.001 — LSASS Memory
- T1003.006 — DCSync
- T1558.003 — Kerberoasting
- T1558.004 — AS-REP Roasting
- T1110.003 — Password Spraying

### Lateral Movement
- T1021.002 — Remote Services: SMB / Windows Admin Shares
- T1021.006 — Remote Services: Windows Remote Management (WinRM)
- T1021.001 — Remote Services: Remote Desktop Protocol
- T1570 — Lateral Tool Transfer

### Execution
- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1053.005 — Scheduled Task
- T1569.002 — Service Execution
- T1047 — Windows Management Instrumentation

### Persistence
- T1136.001 — Create Account: Local Account
- T1136.002 — Create Account: Domain Account
- T1543.003 — Create or Modify System Process: Windows Service
- T1547.001 — Registry Run Keys / Startup Folder

### Defense Evasion
- T1055.002 — Process Injection: Portable Executable
- T1055.003 — Process Injection: Thread Execution Hijacking
- T1055.004 — Process Injection: Asynchronous Procedure Call
- T1070.001 — Indicator Removal: Clear Windows Event Logs
- T1218 — Signed Binary Proxy Execution

### Privilege Escalation
- T1134 — Access Token Manipulation

## Command-Line Usage

<pre><code># Single technique — local execution:
PurpleSharp.exe /t T1059.001

# Kerberoasting with domain credentials:
PurpleSharp.exe /t T1558.003 /d corp.local /u svc_test /p P@ssw0rd! /dc DC01.corp.local

# DCSync with domain admin credentials:
PurpleSharp.exe /t T1003.006 /d corp.local /u Administrator /p Admin@Pass1! /dc DC01.corp.local

# Multiple techniques (comma-separated, quote if using spaces):
PurpleSharp.exe /t "T1558.003, T1003.006"

# Lateral movement to a remote host (SMB execution):
PurpleSharp.exe /t T1021.002 /rhost WS-02.corp.local /ruser Administrator /p Admin@Pass1!

# Execute from JSON playbook (recommended for production):
PurpleSharp.exe /pb credential_access.json

# Execute playbook with sleep between techniques:
PurpleSharp.exe /pb full_chain.json /pbsleep 30
</code></pre>

### Flag Reference

| Flag | Purpose |
|------|---------|
| `/t <T-ID[,T-ID,...]>` | Technique(s) to execute |
| `/d <domain>` | Domain FQDN (e.g., `corp.local`) |
| `/u <user>` | Username for impersonation/authentication |
| `/p <password>` | Password |
| `/dc <controller>` | Domain controller hostname or IP |
| `/rhost <host>` | Remote target host for lateral movement |
| `/ruser <user>` | Authentication user for remote execution |
| `/pb <playbook.json>` | Execute from JSON playbook |
| `/pbsleep <seconds>` | Sleep between techniques in playbook mode |
| `/scout <wef\|...>` | Pre-attack recon (wef = read WEF subscriptions) |
| `/scoutpath <path>` | Custom path for scout helper binary |
| `/simpath <path>` | Custom path for sim helper binary |

**Note:** The docs explicitly state command-line parameters do not expose all features. Use playbooks for any production work.

## Playbook JSON (Production Interface)

The playbook is where PurpleSharp's full capability lives — multiple variants per technique, configurable timing, explicit target lists.

<pre><code>{
  "playbooks": [
    {
      "enabled": true,
      "technique_id": "T1558.003",
      "variation": 1,
      "playbook_sleep": 0,
      "task_sleep": 2,
      "user_target_total": 0,
      "user_targets": []
    },
    {
      "enabled": true,
      "technique_id": "T1558.003",
      "variation": 2,
      "playbook_sleep": 15,
      "task_sleep": 5,
      "user_target_total": 5,
      "user_targets": []
    },
    {
      "enabled": true,
      "technique_id": "T1003.006",
      "variation": 1,
      "playbook_sleep": 30,
      "task_sleep": 0,
      "user_target_total": 0,
      "user_targets": []
    }
  ]
}
</code></pre>

**Variation** selects among multiple implementation variants for the same technique — different code paths that produce different telemetry signatures. T1558.003 has variants for: all SPN users, random subset, specific targets, with/without task delay to spread traffic. This is key for detection engineering — if only variation 1 fires your detection, variation 2 might evade it.

**user_targets** overrides automatic target selection — specify exact accounts in `accountName#SPN` format for Kerberoasting:

<pre><code>"user_targets": [
  "svc_sql#MSSQLSvc/sqlserver.corp.local:1433",
  "svc_http#HTTP/intranet.corp.local"
]
</code></pre>

## Kerberoasting Exercise — Full Workflow

<pre><code># 1. Create the playbook — kerberoast_full.json:
{
  "playbooks": [
    {
      "enabled": true, "technique_id": "T1558.003",
      "variation": 1, "task_sleep": 2,
      "playbook_sleep": 30,
      "comment": "All SPNs, standard timing"
    },
    {
      "enabled": true, "technique_id": "T1558.003",
      "variation": 2, "task_sleep": 10,
      "playbook_sleep": 30,
      "user_target_total": 3,
      "comment": "Random subset, spread over time"
    }
  ]
}

# 2. Stage PurpleSharp on a domain-joined host with appropriate creds.
#    Coordinate with blue team — they should be watching Splunk/Sentinel.

# 3. Run:
PurpleSharp.exe /pb kerberoast_full.json /d corp.local /u svc_test /p P@ssw0rd! /dc DC01

# 4. Blue team checks for expected signals:
#    Sysmon: EID 4769 — Kerberos Service Ticket (look for RC4 encryption, 0x17)
#    Splunk: index=wineventlog EventCode=4769 TicketEncryptionType=0x17 ServiceName!=krbtgt
#    Sentinel: SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17"

# 5. Record outcome in VECTR:
#    Technique: T1558.003
#    Variation 1: Detection → Alert Generated (Splunk fired within 45s)
#    Variation 2: Detection → Not Detected (spread traffic evaded the threshold rule)

# 6. Clean up — domain accounts requested during Kerberoasting don't persist
#    Check for any temp scheduled tasks if T1053.005 was used
</code></pre>

## Domain-Wide (Networked) Execution

With `/rhost` and remote authentication, PurpleSharp pushes execution to remote hosts via SMB, WinRM, scheduled tasks, or service installation:

<pre><code># Lateral movement via SMB to push and execute payload:
PurpleSharp.exe /t T1021.002 /rhost WS-02.corp.local /ruser Administrator /p P@ss!

# WinRM execution (generates richer telemetry — PowerShell remoting logs):
PurpleSharp.exe /t T1021.006 /rhost WS-02.corp.local /ruser Administrator /p P@ss!

# Chain: discovery on DC → creds → lateral to workstation
{
  "playbooks": [
    { "enabled": true, "technique_id": "T1087", "variation": 1, "playbook_sleep": 10 },
    { "enabled": true, "technique_id": "T1558.003", "variation": 1, "playbook_sleep": 20 },
    { "enabled": true, "technique_id": "T1021.002", "variation": 1, "playbook_sleep": 15 }
  ]
}
</code></pre>

This generates realistic multi-host telemetry — events on the source machine, on the DC (Kerberos), and on the target workstation — without any C2 implant.

## PurpleAD Playbook Library

**mvelazc0/PurpleAD** (companion repo) is a structured library of ready-to-use JSON playbooks organized by tactic:

<pre><code>PurpleAD/
├── Simulation Playbooks/
│   ├── Credential Access/
│   │   ├── T1558.003.json   # Kerberoasting (4 variations)
│   │   ├── T1558.004.json   # AS-REP Roasting
│   │   ├── T1003.006.json   # DCSync
│   │   └── T1003.001.json   # LSASS Memory
│   ├── Discovery/
│   │   ├── T1087.001.json   # Local account enumeration
│   │   └── T1087.002.json   # Domain account enumeration
│   ├── Lateral Movement/
│   │   ├── T1021.002.json   # SMB lateral movement
│   │   └── T1021.006.json   # WinRM lateral movement
│   └── Execution/
│       └── T1053.005.json   # Scheduled task execution
└── Emulation Playbooks/
    └── Conti/
        └── conti_emulation.json   # Full Conti ransomware chain
</code></pre>

The Conti emulation playbook chains: domain enumeration → Kerberoasting → DCSync → lateral movement → service-based persistence. Run it end-to-end to validate your AD detection stack against a realistic ransomware campaign.

## Integration with Atomic Red Team and VECTR

PurpleSharp and Atomic Red Team are complementary:
- **Atomic RT** for endpoint-local single-technique tests and non-AD techniques
- **PurpleSharp** for the AD lateral-movement / credential-access / discovery layer with realistic domain impersonation

Standard workflow for a full purple-team session:

<pre><code># Phase 1: Endpoint-local atomic tests (on a single host)
Invoke-AtomicTest T1059.001 -TestNumbers 1 \
  -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath "C:\Logs\art.json"

# Phase 2: AD-layer simulation (domain-wide)
PurpleSharp.exe /pb credential_access.json /d corp.local /u svc_test /p P@ss! /dc DC01
# PurpleSharp output: JSON with timestamps, technique IDs, success/failure per action

# Phase 3: Import both into VECTR
# Art.json: VECTR → Library → Import ATTiRe → select file
# PurpleSharp JSON: convert to ATTiRe format or record outcomes manually
</code></pre>

## Output Format

PurpleSharp writes JSON results with:
- Technique ID and name
- Variation number
- Timestamp (start/stop)
- Target host/user
- Success/failure boolean
- Action details (e.g., "Kerberoasted 7 accounts successfully")

Use these timestamps to correlate against SIEM alerts and Velociraptor hunt results.

## OPSEC Notes

- Kerberoasting and DCSync are loud — coordinate with blue team first or you will trigger on-call alerts
- PurpleSharp requires domain credentials appropriate to the technique; don't run with DA credentials unless testing DCSync or privilege escalation specifically
- Cleanup is minimal — most PurpleSharp techniques don't persist artifacts. Check scheduled tasks and service installs after any Execution tactic tests.
- Run from a domain-joined host, not directly from the attacker box — the telemetry should look like insider activity, not external intrusion

## Resources

- PurpleSharp GitHub — `github.com/mvelazc0/PurpleSharp`
- PurpleSharp documentation — `purplesharp.com`
- PurpleAD playbook library — `github.com/mvelazc0/PurpleAD`
- ATT&CK Navigator layer (in repo) — `github.com/mvelazc0/PurpleSharp/blob/master/PurpleSharp/misc/navigator_layer.json`
- VECTR (track outcomes) — `tools/vectr/`
- Atomic Red Team (complementary endpoint layer) — `tools/atomic-red-team/`
- Self-hosted tools overview — `tools/self-hosted-tools/`
