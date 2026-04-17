---
layout: training-page
title: "MITRE ATT&CK Framework — Red Team Academy"
module: "Fundamentals"
tags:
  - mitre
  - att&ck
  - threat-intel
page_key: "fundamentals-mitre-attack"
render_with_liquid: false
---

# MITRE ATT&CK Framework

## What is ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques & Common Knowledge) is a globally accessible, curated knowledge base of real-world adversary behavior. It documents **how attackers operate** — not hypothetically, but based on observed incidents and threat intelligence. Every red team operation should map to ATT&CK so your work is comparable, repeatable, and communicates directly to defenders.

ATT&CK v18 (Enterprise) contains **216 techniques** and **475 sub-techniques** across 14 tactic categories.

![MITRE ATT&CK 14 enterprise tactics in sequence: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact](/images/fundamentals/mitre-tactics-chain.svg)  
*// mitre att&ck enterprise — all 14 tactics in attack lifecycle order*

## The 14 Enterprise Tactics

Tactics represent the *why* — the adversary's strategic objective at each stage. Techniques are the *how*. Read these in order — they describe a complete attack lifecycle.

| ID | Tactic | Goal |
| --- | --- | --- |
| TA0043 | Reconnaissance | Gather info to plan future operations |
| TA0042 | Resource Development | Establish infrastructure to support operations |
| TA0001 | Initial Access | Get into the target network |
| TA0002 | Execution | Run malicious code on target systems |
| TA0003 | Persistence | Maintain foothold across reboots/credential changes |
| TA0004 | Privilege Escalation | Gain higher-level permissions (SYSTEM, root, DA) |
| TA0005 | Defense Evasion | Avoid detection (largest tactic: 42 techniques) |
| TA0006 | Credential Access | Steal credentials and authentication material |
| TA0007 | Discovery | Learn the target environment (users, hosts, network) |
| TA0008 | Lateral Movement | Move through the network to reach objectives |
| TA0009 | Collection | Gather data of interest to mission objectives |
| TA0011 | Command & Control | Communicate with and control compromised systems |
| TA0010 | Exfiltration | Steal data out of the environment |
| TA0040 | Impact | Destroy, manipulate, or disrupt systems/data |

## Techniques vs Sub-Techniques

ATT&CK uses a hierarchical ID system with three levels:

- **Tactic (TA####)** — The *why*. Strategic adversary goal (e.g., TA0001 Initial Access)
- **Technique (T####)** — The *how*. A specific method to achieve a tactic (e.g., T1566 Phishing)
- **Sub-technique (T####.###)** — A specific variant of a technique (e.g., T1566.001 Spearphishing Attachment)

Example breakdown of `T1003 — OS Credential Dumping`:

```
T1003       OS Credential Dumping (parent)
T1003.001   LSASS Memory              ← Mimikatz, procdump lsass
T1003.002   Security Account Manager  ← reg save HKLM\SAM
T1003.003   NTDS                      ← ntdsutil, secretsdump
T1003.004   LSA Secrets               ← reg query HKLM\SECURITY
T1003.005   Cached Domain Credentials ← NL$KM registry key
T1003.006   DCSync                    ← Mimikatz lsadump::dcsync
T1003.007   Proc Filesystem           ← Linux /proc/<pid>/mem
T1003.008   /etc/passwd and /etc/shadow
```

Always cite sub-techniques when reporting. `T1003` is too vague — `T1003.006 DCSync` tells defenders exactly what happened and what to detect.

## ATT&CK Navigator

The ATT&CK Navigator is a web-based visualization tool for annotating the ATT&CK matrix. Access it at [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) or self-host via GitHub.

### Red Team Use Cases

- **Attack Planning:** Build a layer showing every technique your engagement will use before you start. Share it with your team as an operational plan.
- **Heatmap Generation:** Color-code techniques by frequency, tool availability, or detection difficulty. Export as SVG for reports.
- **Gap Analysis:** Overlay your planned techniques against the blue team's known detection coverage. Uncolored cells = blind spots to exploit.
- **Adversary Emulation:** Import a published layer for APT29, FIN7, etc. to emulate specific threat actors against your target.
- **Purple Team Reporting:** After an engagement, show which techniques fired alerts (green), which were missed (red), and which weren't tested (grey).

Layers are stored as JSON files — easily scripted, version-controlled, and shared:

```
# Download the Navigator and run locally
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install && npm run start
```

## Example Attack Chain — Mapped to ATT&CK

Real attack chains are non-linear. Adversaries loop back, re-enumerate, and adapt. This example maps a realistic nation-state intrusion to ATT&CK IDs:

| Phase | Technique ID | Name | Action |
| --- | --- | --- | --- |
| Recon | T1592 | Gather Victim Org Info | LinkedIn, OSINT on employees |
| Resource Dev | T1583 | Acquire Infrastructure | Register lookalike domain |
| Initial Access | T1566.002 | Spearphishing Link | Targeted email to executive |
| Execution | T1204.001 | User Execution: Malicious Link | Victim clicks, payload drops |
| Persistence | T1547.001 | Registry Run Keys | Backdoor added to HKCU\Run |
| Cred Access | T1003.001 | LSASS Memory | Mimikatz sekurlsa::logonpasswords |
| Discovery | T1087 | Account Discovery | Enumerate AD users/groups |
| Lateral Move | T1021.001 | RDP | RDP to DC with stolen creds |
| C2 | T1071.001 | Web Protocols | HTTPS beacon blends with traffic |
| Exfiltration | T1041 | Exfil Over C2 Channel | Data sent through existing HTTPS C2 |

## Enterprise vs ICS vs Mobile

- **Enterprise** — IT networks: Windows, Linux, macOS, cloud (AWS/Azure/GCP). 14 tactics, 216 techniques. *This is your primary matrix.*
- **ICS** — Operational technology: PLCs, SCADA, DCS. 12 tactics, 81 techniques. Unique tactics: *Inhibit Response Function*, *Impair Process Control*. Use for critical infrastructure engagements.
- **Mobile** — Android and iOS. 13 tactics, 100 techniques. Focus: credential theft, app exploitation, on-path interception.

## Using ATT&CK for Adversary Emulation

MITRE publishes free **Adversary Emulation Plans (AEPs)** that translate real APT behavior into executable red team scripts. Available for APT3, APT29, FIN7, and others.

1. Choose a threat actor relevant to your target's industry
2. Download their AEP from `attack.mitre.org/resources/adversary-emulation-plans/`
3. Build an ATT&CK Navigator layer from their documented techniques
4. Execute techniques in realistic order against the target environment
5. Document which techniques fired blue team alerts vs. went undetected
6. Deliver a layer showing coverage gaps as part of your report

## Adversary Emulation Tools

These tools automate ATT&CK-mapped adversary emulation, ranging from guided manual testing to fully autonomous simulation. Use them to systematically validate detection coverage against specific APT profiles.

```
# MITRE Caldera — automated adversary emulation via ATT&CK:
# https://github.com/mitre/caldera
# Web-based C2 server deploys agents to targets, executes ability chains
# Groups abilities into Adversary profiles (APT3, APT29 built-in)
# Autonomous operation mode + manual control
python3 server.py --insecure  # start Caldera server (default :8888)

# Atomic Red Team — lightweight ATT&CK test library:
# https://github.com/redcanaryco/atomic-red-team
# Each technique has atomic tests with prereqs, cleanup, and commands
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1003.001         # run LSASS dump test
Invoke-AtomicTest T1003.001 -Cleanup # cleanup
Invoke-AtomicTest ALL               # run all available tests

# Infection Monkey — breach and attack simulation:
# https://www.akamai.com/infectionmonkey
# Self-propagating agent tests lateral movement and network segmentation
# Generates visual report of attack paths across network

# Stratus Red Team — cloud attack simulation:
# https://stratus-red-team.cloud/
# Tests AWS, Azure, GCP attack scenarios mapped to ATT&CK
stratus list                        # list available attack techniques
stratus detonate aws.credential-access.ec2-get-password-data
stratus revert aws.credential-access.ec2-get-password-data
```

## Key Resources

- [Main ATT&CK knowledge base](https://attack.mitre.org)
- [Navigator (online)](https://mitre-attack.github.io/attack-navigator/)
- [Self-hosted Navigator](https://github.com/mitre-attack/attack-navigator)
- [AEPs](https://attack.mitre.org/resources/adversary-emulation-plans/)
- [CTID adversary emulation library](https://github.com/center-for-threat-informed-defense)
