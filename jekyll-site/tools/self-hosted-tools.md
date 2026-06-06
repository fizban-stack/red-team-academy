---
layout: training-page
title: "Self-Hosted Adversary Emulation Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - self-hosted
  - adversary-emulation
  - purple-team
  - caldera
  - atomic-red-team
  - vectr
  - openaev
  - purplesharp
  - ludus
  - velociraptor
  - detection-validation
  - lab-setup
page_key: "tools-self-hosted-tools"
render_with_liquid: false
---

# Self-Hosted Adversary Emulation Tools

A mature purple-team program doesn't run on one tool — it runs on a stack. Seven purpose-built tools cover the full pipeline from range substrate to exercise management. Each solves a discrete problem; together they close the loop from *"run the attack"* to *"confirm the detection fired"* to *"prove coverage is improving quarter over quarter."*

This page covers the complete stack, how the tools relate to each other, and how to compose them into a working purple-team program.

## The Self-Hosted Stack at a Glance

| Tool | Role | What It Solves |
|------|------|----------------|
| **Ludus** | Range substrate | Proxmox-based lab automation — reproducible AD environments with auto-revert |
| **MITRE CALDERA** | Adversary emulation | Multi-step ATT&CK-mapped operations; autonomous or manual execution |
| **Atomic Red Team** | Atomic tests | Single-technique detection validation; per-technique SIEM tuning |
| **PurpleSharp** | AD simulation | High-fidelity AD-layer attack telemetry (Kerberoasting, DCSync, lateral movement) |
| **Velociraptor** | Endpoint visibility | Confirms that expected telemetry landed on the endpoint; post-attack triage |
| **VECTR** | Exercise management | System of record — tracks outcomes, drives resilience trending reports |
| **OpenAEV** | BAS orchestration | Scheduled exercises, human-in-the-loop injects, OpenCTI-driven scenarios |

**Note on Prelude Operator:** Prelude Operator (Prelude Security) is defunct — all repos were deleted and the company pivoted to commercial SaaS in 2024. It is not covered here and should not be used for new deployments.

## Tool Comparison

### Execution Layer

| | MITRE CALDERA | Atomic Red Team | PurpleSharp |
|---|---|---|---|
| **Primary unit** | Adversary profile + abilities | Atomic test (single command) | Playbook (ordered AD techniques) |
| **Agent required** | Yes — Sandcat/Manx beaconing implant | No — tests run inline | No — runs as standalone binary |
| **Execution model** | Autonomous (planner-driven) or manual | Manual or Invoke-AtomicTest script | JSON playbook, sequential |
| **Scope** | Multi-stage kill chains | One technique at a time | AD credential access / lateral movement layer |
| **ATT&CK mapping** | First-class (every ability) | First-class (every atomic) | First-class (47 techniques) |
| **Reporting** | Debrief plugin: PDF, ATT&CK heat map, ATTiRe | CSV / ATTiRe export | JSON with timestamps, success/failure per technique |
| **Domain required** | No — works standalone | No | Yes — built for domain-joined environments |
| **Best for** | Full emulation campaigns, threat-actor simulations | Per-technique SIEM rule validation | AD-specific: Kerberoasting, DCSync, Pass-the-Hash variants |

### Infrastructure and Visibility Layer

| | Ludus | Velociraptor | VECTR | OpenAEV |
|---|---|---|---|---|
| **Role** | Range substrate | Endpoint visibility | Tracking / system of record | BAS orchestration |
| **Primary action** | Build reproducible Proxmox AD labs | Dispatch VQL hunts to endpoints post-attack | Record and trend detection outcomes | Schedule and orchestrate exercises |
| **Human layer** | None | None | Red + blue team collaboration | First-class (email/SMS injects, player teams) |
| **Auto-validation** | Via testing-mode revert loop | VQL artifact confirms telemetry landed | Via collector integrations (CrowdStrike, Sentinel, Splunk) | Via collector integrations |
| **Threat-intel integration** | No | No | SRA Threat Simulation Index (importable YAML) | OpenCTI — generates scenarios from actor profiles |
| **Scheduling** | Manual | Manual | Assessment groups (periodic re-run) | Cron-style recurrence built-in |
| **Best for** | Clean-snapshot repeatable test environments | Confirming Sysmon/event log telemetry on the endpoint | Long-running programs; quarterly board reporting | Org-wide exercises with tabletop + technical layers |

## The Complete Pipeline

<pre><code>┌─────────────────────────────────────────────────────────────────────────┐
│  LUDUS — Range Substrate                                                  │
│  Proxmox + automated Ansible provisioning                                 │
│  DC01, WS01, WS02 — domain joined, Sysmon deployed                       │
│  testing start → test → testing stop (auto-revert all VMs)               │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ attack targets
         ┌─────────────────────────┼──────────────────────────┐
         │                         │                          │
         ▼                         ▼                          ▼
┌────────────────┐      ┌─────────────────────┐    ┌──────────────────────┐
│ CALDERA        │      │ Atomic Red Team      │    │ PurpleSharp          │
│ Multi-stage    │      │ Single-technique     │    │ AD layer simulation  │
│ emulation      │      │ detection tests      │    │ Kerberoasting/DCSync │
└───────┬────────┘      └──────────┬──────────┘    └──────────┬───────────┘
        │                          │                           │
        └──────────────────────────┼───────────────────────────┘
                                   │ attack telemetry lands
                                   ▼
                    ┌──────────────────────────────┐
                    │ VELOCIRAPTOR                  │
                    │ VQL hunts confirm telemetry   │
                    │ on the endpoint — no SSH/RDP  │
                    └──────────────┬───────────────┘
                                   │ outcomes (detected / not detected)
                                   ▼
                    ┌──────────────────────────────┐
                    │ VECTR                         │
                    │ System of record              │
                    │ ATTiRe import + manual entry  │
                    │ Resilience trending reports   │
                    └──────────────┬───────────────┘
                                   │ long-running program data
                                   ▼
                    ┌──────────────────────────────┐
                    │ OPENAEV                       │
                    │ Scheduled recurring exercises │
                    │ Human + technical injects     │
                    │ Collector auto-validation     │
                    └──────────────────────────────┘
</code></pre>

## When to Use Which Tool

**Use Ludus when:**
- You need a full AD lab that rebuilds cleanly between test runs
- You're running a detection engineering program and snapshots-and-revert need to be automated
- You're deploying GOAD, Sliver, Mythic, or Elastic into a lab — Ludus roles handle it

**Use Atomic Red Team when:**
- You need to validate that a specific detection rule fires on a specific technique
- A SIEM engineer says "show me T1059.001 executing on a Windows host"
- You're building out detection coverage and want to test one technique at a time
- You want minimal setup — no server, no implant, just a PowerShell module

**Use CALDERA when:**
- You're running a full adversary emulation exercise simulating a known threat actor (APT29, FIN6)
- You need multi-stage operations: initial execution → persistence → credential access → lateral movement → exfil
- You want autonomous execution while you focus on other work
- You need structured reporting for a stakeholder briefing (ATT&CK heat maps, campaign timelines)

**Use PurpleSharp when:**
- You specifically need high-fidelity AD attack telemetry: Kerberoasting, DCSync, Pass-the-Hash, AS-REP Roasting
- You need multiple implementation variants of the same technique to test detection coverage breadth
- You want realistic domain-user impersonation (not just command execution)
- Atomic RT doesn't cover the nuances of the AD technique you're testing

**Use Velociraptor when:**
- You want to confirm that a technique produced expected telemetry on the endpoint, without SSH or RDP
- You want to search for IOCs across all endpoints in the range simultaneously (hunt)
- You need VQL forensic analysis post-attack

**Use VECTR when:**
- You're running a structured purple-team program and need outcomes tracked over time
- You need to show a CISO how detection coverage changed from Q2 to Q3
- You're running a vendor bake-off and need side-by-side EDR performance data on identical test sets

**Use OpenAEV when:**
- You need recurring scheduled exercises (monthly/quarterly) that run without manual setup
- Your exercises include tabletop elements — email/SMS injects to SOC analysts or CISO
- You're connected to OpenCTI and want threat-intel-driven scenarios generated automatically
- You need multi-dimension scoring: Prevention + Detection + Vulnerability + Human Response

## Purple-Team Program Structure

A mature purple-team program combines all tools in sequence:

<pre><code>Phase 1 — Technique Coverage (Atomic Red Team + PurpleSharp + Velociraptor)
  Environment: Ludus range with Sysmon + EDR + SIEM deployed
  For each technique on your detection backlog:
    → Run Invoke-AtomicTest or PurpleSharp playbook
    → Velociraptor hunt confirms whether telemetry landed on the endpoint
    → SIEM alert status recorded in VECTR per defense tool
    → Outcome: pass (detected), fail (not detected), or blocked (prevented)
  Repeat per technique until coverage map is complete.
  Output: ATT&CK coverage heat map, technique-by-technique gap list

Phase 2 — Kill Chain Emulation (CALDERA + Velociraptor + VECTR)
  For each threat actor relevant to your environment:
    → Deploy Sandcat → build adversary profile → run CALDERA operation
    → Velociraptor confirms which technique artifacts are visible on disk/memory
    → Debrief plugin generates PDF + ATT&CK Navigator export
    → Results imported to VECTR via ATTiRe → resilience trending updated
  Output: kill-chain coverage report, VECTR assessment with trending data

Phase 3 — Scheduled Program (OpenAEV)
  Automate Phase 1 and Phase 2 as recurring OpenAEV simulations:
    → Monthly Atomic/CALDERA/PurpleSharp injects via OpenAEV executor
    → Collector integrations (CrowdStrike/Sentinel/Splunk) auto-validate detections
    → Human injects sent to SOC team and CISO at milestone points
    → Quarterly VECTR resilience report shows trend over time
  Output: continuous purple-team program with automatic scheduling + reporting
</code></pre>

## Lab Architecture with Ludus

### Full Stack Lab (Recommended)

<pre><code>LUDUS HOST (Proxmox bare metal or VM)
│
├── {{ range_id }}-DC01   (Windows Server, primary domain controller)
│   ├── Sysmon + Windows Event Forwarding
│   ├── Velociraptor client
│   └── Domain: lab.internal
│
├── {{ range_id }}-WS01   (Windows 11, domain-joined workstation)
│   ├── Sysmon + Velociraptor client
│   └── CALDERA Sandcat + PurpleSharp staged here
│
├── {{ range_id }}-kali   (Kali, attacker machine)
│   └── Invoke-AtomicRedTeam via pwsh-core, CALDERA server
│
├── {{ range_id }}-velociraptor  (Ubuntu, Velociraptor server)
│   └── GUI: https://velociraptor-host:8889
│
└── {{ range_id }}-splunk  (or Elastic) (Ubuntu, SIEM)
    └── Receives Windows event logs from all hosts

CALDERA server port: 8888 (kali box or dedicated VM)
VECTR: Docker Compose on a management VM, port 8081
OpenAEV: Docker Compose, port 80 (optional, for recurring programs)
</code></pre>

### Minimum Viable Lab

<pre><code>┌─────────────────────────────────────────────────────────┐
│  Attacker Machine (Linux)                                 │
│  - CALDERA server (port 8888)                             │
│  - Atomic Red Team runner (PowerShell Core)               │
│  - VECTR (Docker Compose)                                 │
└──────────────────────┬──────────────────────────────────┘
                       │ agent callback / WinRM
┌──────────────────────▼──────────────────────────────────┐
│  Target Machine (Windows, domain-joined preferred)        │
│  - Sysmon + Windows Event Forwarding                      │
│  - Sandcat agent (for CALDERA)                            │
│  - Velociraptor client                                    │
│  - PowerShell 5.1+ (for Invoke-AtomicRedTeam)             │
└──────────────────────┬──────────────────────────────────┘
                       │ log forwarding
┌──────────────────────▼──────────────────────────────────┐
│  SIEM / EDR                                              │
│  - Receives Windows event logs                           │
│  - Validates that detections fire                        │
└─────────────────────────────────────────────────────────┘
</code></pre>

### Recommended Sysmon Config

Run Sysmon on all target machines with a comprehensive configuration. The SwiftOnSecurity or Olaf Hartong modular configs are the standard starting point:

<pre><code>sysmon64.exe -accepteula -i sysmonconfig.xml

# Key event IDs for adversary emulation coverage:
# EID 1  — Process creation (catches most execution techniques)
# EID 3  — Network connection (C2, lateral movement)
# EID 7  — Image load (DLL injection, reflective loading)
# EID 8  — CreateRemoteThread (process injection)
# EID 10 — ProcessAccess (LSASS dumping, credential access)
# EID 11 — FileCreate (payload drops)
# EID 12/13 — Registry create/set (persistence)
# EID 22 — DNS query (C2 over DNS, discovery)
# EID 25 — ProcessTampering (hollowing, herpaderping)
</code></pre>

### Isolation Requirements

- **Use Ludus testing mode.** `ludus testing start` snapshots all VMs and blocks internet egress. `ludus testing stop` reverts everything automatically. This is the correct revert primitive — not manual VM snapshots.
- **Never expose CALDERA to the internet.** Run on a dedicated VPN segment or management network. Change the default `admin/admin` credentials immediately.
- **Domain-joined targets** produce richer telemetry (Kerberos events, AD replication logs) than standalone workstations. PurpleSharp requires a domain.
- **Velociraptor server** handles all endpoint queries via its existing comms channel — no need to open additional ports for telemetry collection.

## Core Integration: CALDERA + Atomic Red Team

<pre><code># 1. Enable the atomic plugin in CALDERA conf/local.yml:
plugins:
  - atomic
  - sandcat
  - debrief
  - compass

# 2. Start CALDERA. On first load, it clones and imports the atomics catalog.

# 3. Deploy Sandcat to target hosts (see caldera.md — Deploying Agents).

# 4. Build an adversary profile using atomic ability IDs:
#    In the UI: Campaigns → Adversaries → New
#    Add atomic abilities by ATT&CK technique or search by name

# 5. Run the operation:
#    Operations → New Operation
#    Adversary: your atomic-based profile
#    Planner: atomic (sequential, predictable for detection testing)
#    Start

# 6. When done: Plugins → Debrief → select operation → Export PDF
</code></pre>

## Core Integration: Attack Execution → Velociraptor → VECTR

<pre><code># 1. Run attack (CALDERA operation, Invoke-AtomicTest, PurpleSharp playbook)
#    Record execution timestamp.

# 2. Validate in Velociraptor:
#    Hunt Manager → New Hunt → select relevant artifact
#    e.g., Windows.Detection.LsassMemoryAccess for T1003.001
#    Results arrive on next client check-in (seconds to minutes)

# 3. Confirm in Velociraptor Notebook:
LET attack_time_minus5 = timestamp(string="2025-06-15T13:57:17Z")
LET attack_time_plus5  = timestamp(string="2025-06-15T14:07:17Z")
SELECT * FROM hunt_results(hunt_id='H.123456')
WHERE Timestamp &gt; attack_time_minus5 AND Timestamp &lt; attack_time_plus5

# 4. Record outcome in VECTR:
#    Test Case → record per defense tool:
#    Detection: Alert Generated | Not Detected | Logged Only | Blocked
#    Add latency (seconds from execution to alert)

# 5. Import execution log (Invoke-AtomicRedTeam with ATTiRe logger):
Invoke-AtomicTest T1003.001 -TestNumbers 1 \
  -LoggingModule "Attire-ExecutionLogger" \
  -ExecutionLogPath "C:\Logs\session.json"
# VECTR UI → Library → Import Data → ATTiRe → select session.json
</code></pre>

## Security Considerations

**CALDERA is not hardened for production.** The web UI and API were not designed to resist external attack. Mitigations:

- Run on an isolated management VLAN, block port 8888 at the perimeter
- Change all default credentials immediately (`admin/admin` is public knowledge)
- Rotate API keys between engagements

**Atomic Red Team and PurpleSharp run real attack commands.** Neither is a simulation:

- Tests execute on the machine running the session — or on the remote PSSession / domain-joined target
- Elevation-required tests can modify system state beyond cleanup's reach
- Run against dedicated lab machines only; never against production endpoints without explicit written authorization
- Ludus testing mode's auto-revert is the correct protection primitive

**Velociraptor `api_client.yaml` files contain full administrative credentials.** Lock them down:

- GOLD SALEM / Warlock ransomware operators (Dec 2025, Sophos CTU) abused legitimate Velociraptor binaries as backdoor delivery — treat Velociraptor binaries on disk as a high-signal IOC in non-DFIR environments
- Never expose the Velociraptor API port (8001) externally

**VECTR stores operator commands, outputs, and screenshots.** Treat as sensitive:

- API keys are account-level (not scoped) — rotate after each engagement
- Keep VECTR off the internet; community deployment is Docker Compose on-prem only

**Detection signal from these tools is high-fidelity but recognizable:**

- Sandcat's HTTP beacon pattern is well-documented and easy to detect — intentional for purple-team work
- Neither CALDERA, Atomic RT, PurpleSharp, nor Velociraptor are suitable for real red-team engagements where detection evasion matters

## Resources

- CALDERA platform guide — `tools/caldera/`
- Atomic Red Team guide — `tools/atomic-red-team/`
- VECTR guide — `tools/vectr/`
- OpenAEV guide — `tools/openaev/`
- PurpleSharp guide — `tools/purplesharp/`
- Ludus guide — `tools/ludus/`
- Velociraptor guide — `tools/velociraptor/`
- MITRE CALDERA — `github.com/mitre/caldera`
- Atomic Red Team — `github.com/redcanaryco/atomic-red-team`
- VECTR — `github.com/SecurityRiskAdvisors/VECTR`
- OpenAEV — `github.com/OpenBAS-Platform/openbas`
- PurpleSharp — `github.com/mvelazc0/PurpleSharp`
- Ludus — `gitlab.com/badsectorlabs/ludus`
- Velociraptor — `github.com/Velocidex/velociraptor`
- ATT&CK Navigator — `mitre-attack.github.io/attack-navigator/`
- Sysmon config (SwiftOnSecurity) — `github.com/SwiftOnSecurity/sysmon-config`
- Sysmon config (Olaf Hartong modular) — `github.com/olafhartong/sysmon-modular`
- ATTiRe format spec — `github.com/attackiq/attire`
- SRA Threat Simulation Indexes — `github.com/SecurityRiskAdvisors/indexes`
- CTID Adversary Emulation Plans — `github.com/center-for-threat-informed-defense/adversary_emulation_library`
- GOAD (Game of Active Directory) — `github.com/Orange-Cyberdefense/GOAD`
