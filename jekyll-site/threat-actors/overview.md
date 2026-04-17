---
layout: training-page
title: "Threat Actor Emulation Methodology — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - threat-emulation
  - mitre-attack
  - purple-team
  - ctid
  - methodology
page_key: "threat-actors-overview"
render_with_liquid: false
---

# Threat Actor Emulation Methodology

Threat actor emulation replicates the specific techniques, tools, and behaviors of a known adversary group rather than performing generic red team activity. The goal is to test whether an organization's security investments would detect and respond to a particular threat that is relevant to their industry, region, or infrastructure.

## Threat Emulation vs Generic Red Teaming

| Aspect | Generic Red Team | Threat Emulation |
|---|---|---|
| Objective | Find exploitable vulnerabilities | Test detection of specific threat actor's TTPs |
| Techniques used | Operator's choice / most effective | Restricted to actor's known TTPs |
| Tools used | Best available | Actor's known tools (or functional equivalents) |
| Reporting audience | Technical security team | Board, CISO, threat intelligence team |
| Detection testing | General control effectiveness | Specific detection investment validation |
| Success metric | Achieved objective (domain admin, data) | Replicated actor's kill chain; measured detection fidelity |

**Example:** A defense contractor hires a red team after learning APT28 (Russian GRU) targets companies in their sector. Instead of generic offensive testing, they commission an APT28 emulation exercise to validate whether their EDR, network monitoring, and SOC can detect GRU-specific tooling and TTPs.

## Sources for Threat Intelligence

### MITRE ATT&CK Groups
`attack.mitre.org/groups/` — The primary open-source repository. Each group page lists:
- Attribution details
- Software used
- Technique IDs with references
- Associated campaigns

### CISA Advisories
`cisa.gov/news-events/cybersecurity-advisories` — Government-issued advisories, often contain:
- Specific IOCs
- YARA rules
- Network signatures
- Technique breakdowns with examples

### Commercial Threat Intelligence
- **CrowdStrike Adversary Intelligence** — detailed actor profiles with TTP breakdowns
- **Mandiant (Google) Threat Intelligence** — deep technical reports on APT groups
- **Recorded Future** — dark web monitoring + geopolitical context
- **SentinelOne StellarParticle, Palo Alto Unit 42** — public research blogs

### CTI-Specific Resources
- **Vx-Underground** — malware sample archive, many nation-state tools
- **MalwareBazaar** — hash database for known malware families
- **VirusTotal Intelligence** — sandbox reports for known implants
- **Threat Fox** — IOC sharing platform

## Emulation Plan Format

A professional threat emulation plan includes these sections:

### 1. Actor Profile
```yaml
actor: APT28 (Fancy Bear)
attribution: GRU Unit 26165 / Unit 74455, Russian Federation
confidence: High (US DoJ indictments, NCSC attribution)
active_since: 2004
targeting:
  - NATO governments
  - Defense contractors
  - Political organizations
  - Energy sector
motivation: Espionage, influence operations
```

### 2. Campaign Targeting (Client-Specific)
Map actor's known targeting to the client's profile:
- Does the actor target this industry vertical?
- Has the actor previously targeted this geographic region?
- Does the actor use techniques that the client's current controls are designed to detect?
- Is there active threat intelligence indicating this actor is currently conducting campaigns?

### 3. TTP Chain (Kill Chain Mapping)
Document the emulated kill chain as sequential phases, each tied to ATT&CK IDs:

```
Phase 1: Initial Access
  T1566.001 — Spearphishing Attachment: .docx with embedded macro
  Tool: maldoc_builder.py → VBA macro drops loader

Phase 2: Execution
  T1059.001 — PowerShell: AMSI bypass + download cradle
  T1059.005 — VBA macro execution

Phase 3: Persistence
  T1053.005 — Scheduled Task: schtasks.exe creates daily task
  T1547.001 — Registry Run Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

[...]
```

### 4. Tools Used
For each phase, document:
- Actor's known tool (e.g., CHOPSTICK, X-Agent)
- Emulation equivalent (e.g., Cobalt Strike beacon mimicking CHOPSTICK behavior)
- Functional differences and caveats
- YARA/Sigma detection rules for the actual tool

### 5. Detection Opportunities
For each technique, document what telemetry should capture it:

```
T1566.001 — Spearphishing Attachment
  Email gateway: Attachment flagged by sandbox? Malicious macro detected?
  Endpoint: Word spawning PowerShell (parent process anomaly)
  SIEM: Alert on office application spawning cmd.exe or powershell.exe
  Detection: Sigma rule process_creation_office_spawning_wscript_or_cscript
```

## CTID Adversary Emulation Library

The Center for Threat-Informed Defense (CTID) publishes ready-made emulation plans:
**github.com/center-for-threat-informed-defense/adversary_emulation_library**

Currently published plans:
- APT29 (Cozy Bear) — full emulation plan with payloads
- FIN6 — retail/hospitality financial crime
- Carbanak — banking malware emulation
- menuPass (APT10) — managed service provider targeting
- Wizard Spider (Ryuk/Conti) — ransomware emulation
- OilRig (APT34) — Middle East espionage

Each CTID plan includes:
- Emulation plan PDF with phased TTP breakdown
- Associated tools/scripts for executing the techniques
- Detection guidance per technique
- ATT&CK Navigator layer files showing covered techniques

## Scoping: Full Emulation vs Atomic Testing

| Scope Level | Description | Duration | Best For |
|---|---|---|---|
| **Full emulation** | End-to-end kill chain from initial access to objective | Days to weeks | Annual assessments, breach simulation |
| **Phased emulation** | Selected phases only (e.g., post-compromise only) | 1-3 days | Testing specific control investments |
| **Atomic testing** | Individual technique execution in isolation | Hours | Validating specific detections (detection engineering) |
| **Adversary simulation** | Full emulation with purple team (blue team watches) | 1-2 weeks | Detection development, analyst training |

**Atomic Red Team** (github.com/redcanaryco/atomic-red-team) provides atomic tests indexed by ATT&CK technique ID. Each test is a script that performs exactly one technique and can be run independently.

## Deconfliction with Threat Intelligence

Before scoping an emulation exercise:

1. **Check active campaigns** — confirm the emulated actor is not actively targeting the client at the time of the exercise. Running an APT28 emulation while APT28 is actively in the environment creates confusion.

2. **Industry relevance** — verify the actor historically targets the client's sector. Testing a healthcare organization against Volt Typhoon (critical infrastructure focus) may not be the highest-value exercise.

3. **Detection investment alignment** — identify which controls the client has recently deployed that are designed to stop this actor. The exercise validates those investments.

4. **Rules of engagement** — define whether live credentials should be used, which systems are in scope, and what constitutes "impact" without causing actual damage.

## Exercise Phases: Operation Flow

```
Week 1: Intelligence & Planning
  ├── Actor research: ATT&CK page, threat intel reports, malware analysis
  ├── Client scoping: network diagram, identity systems, email gateway, EDR
  ├── Tool preparation: configure emulation tooling, test in lab
  └── Emulation plan sign-off with client

Week 2-3: Execution (Unannounced)
  ├── Phase 1: Initial Access — execute actor's preferred method
  ├── Phase 2-4: Execution, Persistence, Privilege Escalation
  ├── Phase 5-7: Defense Evasion, Lateral Movement, Collection
  └── Phase 8: Exfiltration simulation (no real data leaves)

Week 4: Purple Team / Detection Development
  ├── Replay each technique with blue team watching
  ├── Develop/tune detection rules for missed techniques
  ├── Validate detection coverage in SIEM/EDR
  └── Document coverage gaps

Week 5: Reporting
  ├── Executive summary (board-level: actor relevance, detection gaps)
  ├── Technical findings (per-technique detection status)
  ├── ATT&CK Navigator heat map (detected vs missed)
  └── Recommendations (prioritized by actor-relevance and gap severity)
```

## ATT&CK Navigator for Visualization

The ATT&CK Navigator displays coverage across the ATT&CK matrix. Use it to:
- Show which actor techniques were emulated
- Mark which techniques were detected (green) vs missed (red)
- Present to stakeholders as a visual gap analysis

```bash
# Generate navigator layer from emulation results (Python)
import json

layer = {
    "name": "APT28 Emulation Results",
    "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": "T1566.001", "score": 100, "comment": "Detected by email sandbox"},
        {"techniqueID": "T1059.001", "score": 0,   "comment": "MISSED — AMSI bypass evaded"},
        {"techniqueID": "T1053.005", "score": 100, "comment": "Detected by Sysmon Event 1"},
        # ... all emulated techniques
    ],
    "gradient": {"colors": ["#ff6666", "#aaeeaa"], "minValue": 0, "maxValue": 100}
}
with open("apt28_emulation_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
# Upload to: https://mitre-attack.github.io/attack-navigator/
```

## Emulation Report: Detection Fidelity Score

Summarize exercise results as a **detection fidelity score** for each MITRE tactic category:

| Tactic | Techniques Tested | Detected | Missed | Fidelity |
|---|---|---|---|---|
| Initial Access | 3 | 2 | 1 | 67% |
| Execution | 4 | 2 | 2 | 50% |
| Persistence | 2 | 2 | 0 | 100% |
| Privilege Escalation | 3 | 1 | 2 | 33% |
| Defense Evasion | 5 | 1 | 4 | 20% |
| Credential Access | 3 | 2 | 1 | 67% |
| Lateral Movement | 2 | 1 | 1 | 50% |
| Collection & Exfil | 2 | 1 | 1 | 50% |
| **Overall** | **24** | **12** | **12** | **50%** |

This format enables the board to understand security investment effectiveness against a specific, named threat actor relevant to their business.

## References

- MITRE ATT&CK Groups: attack.mitre.org/groups/
- CTID Adversary Emulation Library: github.com/center-for-threat-informed-defense/adversary_emulation_library
- Atomic Red Team: github.com/redcanaryco/atomic-red-team
- ATT&CK Navigator: github.com/mitre-attack/attack-navigator
- CISA advisories: cisa.gov/news-events/cybersecurity-advisories
- Purple Team Exercise Framework (PTEF): github.com/scythe-io/purple-team-exercise-framework
- Threat Actor Profiles — MITRE ATT&CK CTI: github.com/mitre/cti
