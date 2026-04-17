---
layout: training-page
title: "Scenarios — Red Team Academy"
module: "Scenarios"
tags:
  - scenarios
  - adversary-simulation
  - threat-emulation
  - red-team
page_key: "scenarios-overview"
render_with_liquid: false
---

# Adversary Simulation Scenarios

## What Are Scenarios?

Adversary simulation scenarios are end-to-end, narrative-driven training exercises that emulate a specific threat actor's complete attack chain against a realistic target environment. They are distinct from individual technique modules — instead of learning a single tool or attack primitive in isolation, scenarios place those primitives inside a coherent operational story: who is attacking, why, against what organization, with what constraints, and what happens when defenders push back.

The goal of a scenario is not just "can you execute these techniques?" It is: "can you execute these techniques in the correct order, with appropriate tradecraft, while adapting to detection events and maintaining operational security — in the way that a real nation-state or criminal organization would?"

| Training Type | What You Learn | Scenario Equivalent |
| --- | --- | --- |
| Technique module | How to run Mimikatz | When in an APT29 campaign does credential dumping occur, and against which systems, using which operational security posture? |
| Lab exercise | Exploit a vulnerable service | How does initial access fit into a 6-week adversary simulation campaign with a specific objective? |
| CTF challenge | Solve the puzzle | Navigate an environment where defenders are actively hunting and controls will trigger |

## Who Are Scenarios For?

- **Red teamers** building adversary emulation programs — use scenarios as blueprints for client engagements
- **Purple teamers** — run scenarios in planned exercises with the blue team to validate detection coverage
- **Security engineers** building detection rules — walk the defender debrief sections to understand what telemetry exists and what logs to correlate
- **Threat intelligence analysts** — use the threat actor profiles to understand how documented groups operate in practice

## How to Use These Scenarios

Each scenario is structured identically. Work through them in order:

1. **Read the threat actor profile** — understand who you are emulating. Know their motivations, their tooling, their operational pace, their known TTPs from public intelligence. You cannot emulate an adversary you don't understand.
2. **Read the target profile** — understand the defensive stack before you start. A simulation against an organization running CrowdStrike Falcon requires different tradecraft than one running Windows Defender. Know the environment.
3. **Execute the phases sequentially** — each phase has exact commands, decision points, and contingencies. Read the "If detected" branches. Scenarios are not linear success stories — defenders will sometimes catch things.
4. **Use the MITRE ATT&CK mappings** — every technique is tagged. After the exercise, assess your detection coverage against the complete technique list.
5. **Run the defender debrief** — after completing the attacker walkthrough, read this section from the perspective of a SOC analyst. Identify which phases generated logs, which alerts should have fired, and which gaps remain.

## Available Scenarios

### APT29 Financial Sector Attack

**Threat Actor:** APT29 (Cozy Bear / NOBELIUM) — Russian SVR foreign intelligence service  
**Target:** GlobalBank Financial Services — 1,500-person US financial firm  
**Objective:** Long-term access and exfiltration of merger and acquisition intelligence  
**Duration (simulated):** 8 weeks from initial phish to objective completion  
**Complexity:** Advanced — nation-state tradecraft, cloud-integrated C2, AD domain persistence  
**Key Techniques:** HTML smuggling, OAuth app abuse, domain-fronted HTTPS C2, DCOM lateral movement, Golden Ticket, OneDrive staged exfiltration  

This scenario emulates APT29's documented NOBELIUM campaign techniques including the use of HTML smuggling payloads, malicious OAuth applications for persistent cloud access, and staged data exfiltration through the victim's own cloud storage infrastructure. Defenders running CrowdStrike Falcon, Palo Alto NGFW, and a mature M365 security stack must catch an adversary that deliberately avoids touching disk and operates at a slow, deliberate pace designed to blend with normal user behavior.

[**→ APT29 Financial Scenario**](./apt29-financial)

---

### Software Supply Chain Attack

**Threat Actor:** Nation-state-affiliated, based on Midnight Blizzard / UNC2452 operational patterns  
**Target:** DevCorp Software — a fictional SaaS development company with 500+ enterprise customers  
**Objective:** Backdoor DevCorp's software distribution pipeline to gain access to customer environments  
**Duration (simulated):** 12 weeks from developer compromise to customer environment access  
**Complexity:** Advanced — multi-organization compromise chain, CI/CD pipeline manipulation, build system backdoor  
**Key Techniques:** Spearphishing developer via LinkedIn, GitHub Actions workflow poisoning, build artifact manipulation, auto-update mechanism abuse, multi-tenant lateral movement  

Inspired by the SolarWinds Orion compromise (Sunburst), this scenario walks through how a sophisticated actor compromises a software vendor's development and build infrastructure to implant a backdoor in a signed, legitimate software update. The simulation covers the full chain: from developer workstation compromise through CI/CD pipeline manipulation, build server access, artifact signing subversion, and finally the downstream impact on a sample customer environment receiving the malicious update.

[**→ Supply Chain Attack Scenario**](./supply-chain-attack)

---

### Malicious Insider — Data Theft

**Threat Actor:** Malicious insider — disgruntled senior sysadmin planning departure  
**Target:** MedTech Innovations — a fictional healthcare technology company  
**Objective:** Steal intellectual property, customer data, and credentials before leaving  
**Duration (simulated):** 6 weeks of insider activity before planned resignation date  
**Complexity:** Intermediate-Advanced — unique challenge of evading detection while having legitimate elevated access  
**Key Techniques:** Legitimate access abuse, data staging in personal cloud storage, DLP evasion, anti-forensics, behavioral anomaly avoidance  

Unlike external threat simulations, the insider threat scenario presents a fundamentally different challenge: the attacker already has legitimate, authorized access to most of what they want. The challenge is not gaining access — it is operating below the threshold of behavioral detection tools (UEBA, DLP, CASB) that are tuned for both insider threats and external actors. This scenario covers reconnaissance of high-value data, staging strategies that blend with normal administrative behavior, exfiltration techniques designed to evade monitoring, and anti-forensic steps taken before departure.

[**→ Insider Threat Scenario**](./insider-threat)

---

## Scenario Structure

Every scenario in this module follows the same structure:

### 1 — Threat Actor Profile

Background on the threat actor being emulated: their real-world attribution (if public), known motivations, organizational affiliation, documented TTPs from public threat intelligence, tooling preferences, and operational pace. For fictional actors (insider scenarios), a realistic profile describing their access level, technical skills, motivations, and timeline.

### 2 — Target Profile

The fictional organization being attacked: industry, headcount, technology stack (endpoints, network, cloud, identity), security tooling, security team maturity level, and key assets that represent the objective. This section is deliberately detailed — understanding the defender's stack is prerequisite to meaningful adversary emulation.

### 3 — Phase-by-Phase Walkthrough

The core of each scenario. Each phase includes:

- **Objective** — what must be accomplished before moving to the next phase
- **Exact commands and tools** — not pseudocode, real command syntax that an operator would type
- **Decision points** — what to do if a technique fails or triggers an alert
- **Operational security notes** — what not to do, what signatures to avoid, how APT tradecraft differs from a noisy pentest
- **MITRE ATT&CK mappings** — technique IDs for every action taken

### 4 — Defender Debrief

Written from the SOC analyst's perspective. For each phase, this section answers:

- What telemetry exists for this technique in this environment?
- Which specific log sources would capture it?
- What alert threshold or correlation rule would fire?
- When in the attack chain would a well-tuned SOC have caught this?
- What does the false positive landscape look like for this detection?

The defender debrief is designed for purple team exercises where the scenario is run collaboratively with the blue team, and for engineering teams building detection content.

## MITRE ATT&CK Coverage Reference

Scenarios are mapped to the MITRE ATT&CK Enterprise framework. The table below shows the primary tactic coverage across all three scenarios.

| Tactic | APT29 Financial | Supply Chain | Insider Threat |
| --- | --- | --- | --- |
| Reconnaissance (TA0043) | Yes | Yes | Yes |
| Resource Development (TA0042) | Yes | Yes | No |
| Initial Access (TA0001) | Yes | Yes | No (already inside) |
| Execution (TA0002) | Yes | Yes | Yes |
| Persistence (TA0003) | Yes | Yes | Yes |
| Privilege Escalation (TA0004) | Yes | Yes | Yes |
| Defense Evasion (TA0005) | Yes | Yes | Yes |
| Credential Access (TA0006) | Yes | Yes | Yes |
| Discovery (TA0007) | Yes | Yes | Yes |
| Lateral Movement (TA0008) | Yes | Yes | Limited |
| Collection (TA0009) | Yes | Yes | Yes |
| Command and Control (TA0011) | Yes | Yes | No |
| Exfiltration (TA0010) | Yes | Yes | Yes |
| Impact (TA0040) | No | Potential | No |

## Prerequisites

These scenarios are advanced exercises. Before attempting them, you should have completed:

- **Fundamentals** — Red Team Methodology, Engagement Planning
- **Active Directory** — AD Enumeration, Kerberos Attacks, Lateral Movement
- **Initial Access** — Phishing, Payload Development, C2 Frameworks

Familiarity with at least one C2 framework (Cobalt Strike, Sliver, Brute Ratel C4, or Havoc) is assumed throughout. Familiarity with cloud attack techniques (Azure AD, M365, AWS IAM) is recommended for the APT29 and supply chain scenarios.

## Lab Environment Notes

These scenarios reference a fictional target environment with specific IP ranges, hostnames, and infrastructure. When adapting for your own lab:

- Replace `globalbank.corp` / `devcorp.internal` / `medtech.local` with your lab domain
- IP ranges used are illustrative — adjust to your environment
- Cloud references (M365, Azure AD) require a test tenant — do NOT run these techniques against production Microsoft tenants without explicit written authorization
- All commands have been written for a Linux-based operator workstation attacking a Windows target environment

**Legal Reminder:** Adversary simulation techniques described here are for authorized testing only. Running these techniques against any organization without explicit written authorization is a criminal offense in most jurisdictions (US: CFAA 18 U.S.C. § 1030; UK: Computer Misuse Act 1990; EU: Directive 2013/40/EU).

## Running Scenarios as Purple Team Exercises

Scenarios become most valuable when run as structured purple team exercises — where the red team operator executes each phase while the blue team monitors in real time, and both teams debrief together after each phase.

### Purple Team Exercise Format

**Before the exercise:**
1. Confirm exercise scope in writing — which systems, which techniques, what is out-of-bounds
2. Brief the SOC at the phase level but NOT the technique level — they should know "Phase 4 happens today at 2pm" but not "we're doing DCOM lateral movement"
3. Establish a deconfliction channel — immediate contact if real suspicious activity is detected
4. Ensure all telemetry is flowing correctly (test log ingestion before starting)

**During each phase:**
1. Red team executes the phase
2. Blue team monitors independently — attempts to detect and alert
3. Red team signals phase completion to exercise coordinator
4. Both teams record: what they did (red) and what they saw (blue)

**After each phase (debrief):**
1. Red team reveals exact techniques and timestamps
2. Blue team reveals what alerts fired, what was investigated, what was missed
3. Together: identify the detection gap and write a new detection rule or tune an existing one
4. Document the new rule, test it against the replay, validate it fires correctly

### Measuring Scenario Coverage

After completing a scenario, assess your detection coverage using the MITRE ATT&CK heat map:

```
# Export scenario ATT&CK technique IDs to Navigator layer:
# Use MITRE ATT&CK Navigator at https://mitre-attack.github.io/attack-navigator/
# Color coding:
#   Red:    Technique executed, not detected
#   Yellow: Technique executed, partially detected (fired but too late or too noisy)
#   Green:  Technique executed, detected and alerted within acceptable window
#   Gray:   Not tested in this scenario

# After all three scenarios, your heat map shows:
# - Which tactics have coverage gaps (typically red clusters)
# - Which detections are reliable vs. noisy
# - Where investment in detection engineering will have the most impact
```

## Scenario Difficulty Rating

| Scenario | Attacker Difficulty | Defender Difficulty | Key Challenge |
| --- | --- | --- | --- |
| APT29 Financial | Hard | Hard | Nation-state pace and stealth; OAuth persistence is systematic blind spot |
| Supply Chain | Very Hard | Very Hard | Multi-organization chain; defenders aren't watching their software vendor |
| Insider Threat | Medium | Hard | No exploitation; detecting legitimate access abuse requires behavioral analytics |

## Key References

- `https://attack.mitre.org` — MITRE ATT&CK Enterprise Matrix
- `https://github.com/center-for-threat-informed-defense/adversary_emulation_library` — CTID Adversary Emulation Plans
- `https://www.microsoft.com/en-us/security/blog/tag/threat-intelligence/` — Microsoft MSTIC threat intelligence
- `https://www.crowdstrike.com/adversaries/` — CrowdStrike adversary profiles (Fancy Bear, Cozy Bear, etc.)
- `https://attack.mitre.org/groups/G0016/` — APT29 MITRE ATT&CK group page
- `https://mitre-attack.github.io/attack-navigator/` — MITRE ATT&CK Navigator (heat mapping)
- `https://www.scythe.io/library/purple-team-exercise-framework` — PTEF Purple Team Exercise Framework
- *Operator Handbook* by Joshua Picolet — operational tradecraft reference
- *The Art of Cyberwar* — strategic context for nation-state operations
