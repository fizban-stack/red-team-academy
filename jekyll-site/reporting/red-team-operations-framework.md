---
layout: training-page
title: "Red Team Operations Framework — Red Team Academy"
module: "Reporting"
tags:
  - operations
  - framework
  - methodology
  - planning
  - roe
  - threat-modeling
  - mitre-attack
  - opsec
  - reporting
page_key: "reporting-rt-ops-framework"
render_with_liquid: false
---

# Red Team Operations Framework

A structured framework for maturing red team operations from ad-hoc exercises to fully operationalized red teaming. Covers scope definition, planning, threat modeling, tool selection, rules of engagement, execution phases, analysis and reporting, and continuous improvement. The framework keeps red team activities driven by specific business needs rather than generic penetration testing checklists.

## Scope Definition

Before any activity begins, establish what is in scope, why it matters, and what success looks like.

```
# Attack Surface Management — identify all exposed assets:
# - External attack surface: DNS, IP ranges, web apps, APIs, SaaS, cloud
# - Internal attack surface: AD, internal services, OT/IoT, trusted 3rd parties
# - Shadow IT: cloud storage, dev environments, forgotten subdomains

# Inventory inputs:
# - CMDB export
# - Cloud asset inventory (AWS: aws iam list-users, az ad user list)
# - Certificate transparency logs: crt.sh, certspotter
# - Shodan/Censys scans of ASN ranges

# Data classification — prioritize by impact:
# Tier 1 (Critical): production DBs, PII, payment data, crown jewels
# Tier 2 (High):     internal tools, credentials stores, source code repos
# Tier 3 (Medium):   employee data, internal docs, partner portals

# Business critical asset identification (examples):
# - Transaction processing system
# - Customer database
# - Core banking infrastructure
# - Identity provider (AD, AAD, Okta)
# - CI/CD pipeline with prod deploy access
```

## Planning Phase

```
# Step 1 — Review previous assessments:
# - Prior pentest/red team reports: recurring issues = systemic weakness
# - Incident reports: real attacker TTPs used against the org
# - Bug bounty submissions: externally found vulns = starting point

# Step 2 — Risk profile analysis:
# - Most valuable assets (from scope definition above)
# - Likely threat actors: financially motivated, nation-state, insider
# - Probable attack vectors: phishing, supply chain, exposed RDP/VPN
# - Business impact per scenario: data breach, ransomware, service disruption

# Step 3 — Stakeholder input:
# - IT/security leadership: known weak points, recent incidents
# - Business unit leaders: critical processes, seasonal peak periods
# - Legal/compliance: frameworks (TIBER-EU, CBEST, NIST), data handling

# Step 4 — Define SMART objectives:
# Weak: "test the web application"
# Strong: "achieve code execution on the internal payment processing API
#          within 14 days using only phishing as initial access vector"

# Step 5 — Align with business objectives:
# - New SaaS rollout → test that tenant's security posture
# - M&A integration → test the newly acquired network segment
# - Regulatory audit upcoming → test controls CBEST requires

# Step 6 — Set benchmarks:
# - Time to initial foothold from campaign start
# - Time from initial access to reaching crown jewel
# - Percentage of Red Team actions detected by Blue Team
# - Number of unique techniques that bypassed detections
```

## Threat Modeling (MITRE ATT&CK)

```
# Build a threat model before selecting TTPs:

# 1. Select relevant threat groups:
#    navigator.attack.mitre.org → select groups matching your client's industry
#    Example: financial sector → FIN7, Carbanak, ALPHV ransomware affiliates

# 2. Extract their TTPs from ATT&CK:
#    T1566.001 Spearphishing Attachment
#    T1059.001 PowerShell
#    T1055    Process Injection
#    T1021.001 RDP Lateral Movement
#    T1486    Encrypt for Impact (ransomware)

# 3. Map to engagement objectives:
#    Phase 1 — Initial Access:   T1566.002 (spearphish link), T1190 (exposed service)
#    Phase 2 — Execution:        T1059.001 (PS), T1204.002 (user exec macro)
#    Phase 3 — Persistence:      T1053.005 (schtask), T1547.001 (run key)
#    Phase 4 — Lateral Movement: T1021.002 (SMB/Windows Admin), T1550.002 (PTH)
#    Phase 5 — Impact:           T1005 (collect local data), T1041 (exfil over C2)

# 4. Use ATT&CK Navigator to build your engagement layer:
#    github.com/mitre-attack/attack-navigator
#    Export as JSON → share with client in debrief

# APT Emulation plans (pre-built):
#    center-for-threat-informed-defense/adversary_emulation_library
#    Example: APT29, APT3, FIN6, menuPass
```

## Tool Selection

```
# TTP-based selection: match tools to the threat model TTPs

# T1566 — Phishing:
#   GoPhish (campaign mgmt), Evilginx2 (session theft), o365-attack-toolkit

# T1059.001 — PowerShell execution:
#   Empire (PS agent), PowerSploit, Covenant

# T1055 — Process Injection:
#   Cobalt Strike BOFs, Sliver, Havoc

# T1021 — Remote Services:
#   CrackMapExec, impacket, SharpRDP

# T1003 — OS Credential Dumping:
#   Mimikatz (via BOF), nanodump, Dumpert (direct syscalls)

# T1562 — Impair Defenses:
#   EDRSandBlast, EDRSilencer, Phant0m

# Custom tool criteria:
#   - Off-the-shelf tool well-known to SIEM? → customise or build
#   - Unique environment (OT, mainframe, custom app)? → custom tooling
#   - Evasion requirements exceed packaged tool? → stage with wrappers

# Verification checklist per tool:
#   [ ] OPSEC tested: does it beacon, create artefacts, write to disk?
#   [ ] Stealthy: user-agent, JA3, PE metadata scrubbed?
#   [ ] Reversible: can all changes be rolled back cleanly?
#   [ ] Legal: licensed, no copyleft issues for client deliverables?
```

## Rules of Engagement (ROE)

```
# ROE is a signed document. Do not start until it is countersigned.

# Required ROE components:

# 1. Explicit restrictions (what is OFF-LIMITS):
#    - No DoS / destructive payloads (ransomware simulators only)
#    - No access to PII beyond proof-of-concept screenshots
#    - No exfiltration of real data (use canary tokens as proof)
#    - No social engineering of executives without pre-approval
#    - OT/ICS networks: read-only; zero writes without dedicated approval

# 2. Authorized target space:
#    - IP ranges: 10.10.0.0/16, 192.168.1.0/24
#    - Domains: *.corp.example.com (not partner.example.com)
#    - Cloud tenants: AWS account 123456789012
#    - Out-of-scope: 10.10.99.0/24 (production payments), hr.example.com

# 3. Permitted activities:
#    - Reconnaissance (passive and active within scope)
#    - Phishing (pre-approved email templates, max 500 targets/week)
#    - Exploitation (no destructive payloads)
#    - Post-exploitation (no data exfil of real PII)
#    - Lateral movement within authorized IP ranges

# 4. Deconfliction process:
#    - Hotline number for Blue Team to call if they find an incident
#    - Red Team checks in every 24h with engagement lead
#    - Emergency stop: email engagement lead + CISO within 30 minutes

# 5. Cease operations triggers:
#    - Discovery of real unauthorized attacker in the environment
#    - Unintended system instability caused by Red Team
#    - Client request at any time (no questions asked)
#    - Business crisis (incident, outage) declared by client

# 6. Sensitive data handling:
#    - Credentials found: document, don't store, hash and report
#    - PII in scope: screenshot only, delete from Red Team systems within 24h
#    - Crown jewel access: screenshot + hash of file, immediate notification
```

## Execution Phase

### Design Plan

```
# Build multi-path attack scenarios — do not plan a single linear chain

# Example 3-path design for phishing engagement:
# Plan A: phishing → macro → Cobalt Strike → lateral → DC
# Plan B: phishing → credential harvest → VPN → internal pivot
# Plan C: exposed internet service (VPN, OWA) → password spray → initial access

# Scenario design checklist:
# [ ] Aligns with the threat model (realistic TTPs for this sector)
# [ ] Multiple contingency paths (if A is detected, pivot to B)
# [ ] Each phase has clear objectives and success criteria
# [ ] Testing specific controls (MFA, EDR, network segmentation, IR speed)
# [ ] Crown jewel access is the end-state goal

# Cyber Kill Chain vs. flexible approach:
# Kill Chain is a checklist — useful for structuring the report
# In execution: adversaries don't follow a linear chain
# Be prepared to:
#   - Skip phases (e.g., direct access to crown jewel via misconfiguration)
#   - Loop back (re-establish access after detection)
#   - Pivot tactics when defenses adapt
```

### Preparation

```
# Infrastructure setup:
# - Domain: registered 30+ days old, categorized as business/tech
# - C2 server: VPS with malleable profile, redirectors in front
# - Phishing: GoPhish on dedicated VPS, valid DKIM/SPF/DMARC
# - Staging: pwndrop or S3 for payload hosting

# Payload configuration:
# - Build implant targeting the specific OS/AV in scope
# - Test against client's AV/EDR stack (ThreatCheck)
# - Verify C2 channels are not blocked at the perimeter (firewall egress)

# Traceability — log everything:
mkdir -p /opt/engagements/client-2024/logs
# Log all commands, tool outputs, screenshots with timestamps
# Use tmux logging: tmux new -s rt; set -g history-limit 50000
# CS teamserver logs every beacon interaction automatically

# Pre-engagement legal check:
# [ ] Signed ROE in hand
# [ ] Personal indemnification confirmed
# [ ] NDA/MSA signed
# [ ] Emergency contact confirmed (not just email — phone number)
```

### Active Engagement

```
# Execution principles:

# 1. Minimal footprint:
#    - Memory-resident payloads where possible (avoid disk writes)
#    - Clean up artefacts as you go (del /f, rm -rf staging files)
#    - Use built-in Windows tools (LOLBins) to blend with normal traffic

# 2. Operational tempo:
#    - Match attacker's expected tempo (APT = slow, ransomware = fast)
#    - Avoid generating hundreds of requests per second (IDS noise)
#    - Use jitter in C2 beacons (sleep 60 jitter 30 in CS)

# 3. Communication with Blue Team (purple mode):
#    - Agree on deconfliction channel before engagement starts
#    - Check in at agreed intervals (prevents Blue Team escalating real incident)
#    - If Blue Team detects you: document what triggered detection (valuable data)

# 4. Dynamic adaptation:
#    - Initial phishing blocked? Switch to credential spray against OWA
#    - EDR catching injections? Switch to LOLBin-based execution
#    - Lateral movement detected? Go quiet for 48h, then resume

# 5. Track everything in operator log:
#    - Timestamp, host, action, outcome, artefact left behind
#    - This becomes the basis for the detailed findings section of the report
```

## Analysis and Reporting

```
# Data collection during the engagement:
# - CS teamserver logs (all beacon interactions)
# - Manual operator logs (timestamped notes per action)
# - Tool output files (nmap, BloodHound, Seatbelt exports)
# - Screenshots with timestamps for every significant finding
# - Blue Team response log (what they detected, when, what action taken)

# Evaluation metrics to calculate:
# - Time to initial compromise (from campaign start)
# - Time from initial access to crown jewel
# - Detection rate: (# of Red Team actions detected) / (total actions) * 100
# - Mean time to detect (MTTD) per tactic category
# - Coverage gaps: which ATT&CK techniques generated no Blue Team response?

# Report structure:
# 1. Executive Summary (1 page):
#    - What was tested, what objectives were achieved
#    - Critical findings (business risk language, not technical)
#    - Top 3 prioritized recommendations

# 2. Methodology:
#    - Threat model (which threat actor emulated)
#    - ATT&CK techniques used (include Navigator layer screenshot)
#    - Tool list with justifications

# 3. Attack Narrative:
#    - Chronological story from initial access to crown jewel
#    - Include timestamps, screenshots, evidence
#    - Explain what each step would mean in a real attack

# 4. Technical Findings:
#    - Finding per vulnerability/misconfiguration
#    - CVSS or risk rating, affected assets, evidence, remediation

# 5. Detection Analysis:
#    - What did Blue Team detect vs. miss?
#    - MTTD for each category
#    - Detection gap map (ATT&CK heatmap)

# 6. Recommendations:
#    - Quick wins (patch, config change)
#    - Medium-term (detection rule development, IR playbook updates)
#    - Strategic (architecture change, security program investment)
```

## Improvement Phase

```
# Debrief session structure:
# Attendees: Red Team, Blue Team, SOC, CISO, IT leadership
# Agenda:
#   1. Red Team: walkthrough of attack path (no blame, focus on learning)
#   2. Blue Team: what was detected, what escalation happened
#   3. Joint: where did defenses fail? Why?
#   4. Prioritize remediation by risk and effort

# Action plan template:
# | Finding                   | Owner     | Priority | Deadline |
# |---------------------------|-----------|----------|----------|
# | Missing EDR on OT segment | IT Ops    | Critical | 30 days  |
# | No MFA on VPN             | IT Ops    | Critical | 14 days  |
# | Weak PS logging           | SecOps    | High     | 60 days  |
# | No LSASS protection       | IT Ops    | High     | 30 days  |
# | IR playbook outdated      | SecOps    | Medium   | 90 days  |

# Follow-up exercise planning:
# - Schedule re-test on specific findings after remediation (30-60-90 days)
# - Design next engagement to test defenses improved this cycle
# - Use detection gaps as the starting TTPs for the next engagement

# Continuous improvement tracking:
# - Track detection rate improvement engagement-over-engagement
# - Track MTTD reduction over time
# - Report improvement metrics to CISO quarterly
```

## OpSec Checklist

```
# Pre-engagement:
# [ ] C2 domains registered 30+ days, properly categorized
# [ ] Redirectors in front of all C2 infrastructure
# [ ] Malleable C2 profile tested — no default Cobalt Strike signatures
# [ ] All tools tested against target AV/EDR stack
# [ ] VPN/anonymisation for all operator traffic
# [ ] Separate infrastructure per client — never reuse

# During engagement:
# [ ] Beacon jitter enabled (randomise callback intervals)
# [ ] Memory-resident payloads (avoid disk writes)
# [ ] Clean up staging artefacts after use
# [ ] Use LOLBins where possible (blend with normal admin traffic)
# [ ] No operator personal accounts on Red Team systems
# [ ] Log every action with timestamp (for report + cover)

# Post-engagement:
# [ ] All infrastructure torn down within 72h of engagement end
# [ ] Credentials / screenshots wiped from Red Team systems
# [ ] DNS / certificate records removed
# [ ] Client data deleted per data handling agreement
# [ ] Operator logs archived securely (encrypted, access-controlled)
```

## Regulatory Frameworks

```
# TIBER-EU (European Central Bank — financial sector):
# - Threat intelligence phase led by approved CTI provider
# - Red Team test phase against specific crown jewels
# - Requires central bank notification and approval
# - Output: TIBER test report shared with regulator

# CBEST (Bank of England — UK financial sector):
# - CREST-accredited providers only
# - Intelligence-led — threat actor profiles provided by NCSC/CERT-UK
# - Strict scoping and ROE requirements
# - FCA/PRA coordinated

# TLPT / DORA (EU Digital Operational Resilience Act):
# - TIBER-EU-equivalent for all EU financial entities by Jan 2025
# - Threat-led penetration testing every 3 years for significant entities

# NIST SP 800-115 (Technical Guide to IS Testing):
# - Describes planning, execution, and reporting methodology
# - Not prescriptive — used as baseline for non-regulated sectors

# Scope of authorization — verify before every action:
# Document in ROE: "authorization covers IP range X / domain Y"
# Computer Fraud and Abuse Act (US) / CMA (UK) apply to unauthorized access
# When in doubt: stop, call engagement lead, document the question
```

## Resources

- Red-Team-Operations-Framework — `github.com/V33RU/Red-Team-Operations-Framework`
- MITRE ATT&CK Framework — `attack.mitre.org`
- ATT&CK Navigator — `github.com/mitre-attack/attack-navigator`
- TIBER-EU Framework — `ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf`
- Adversary Emulation Library — `github.com/center-for-threat-informed-defense/adversary_emulation_library`
- Red Team Infrastructure Wiki — `github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki`
- Ghostwriter (report management) — `github.com/GhostManager/Ghostwriter`
- Related: [Executive Report Writing](/reporting/executive-report/)
- Related: [Red Teaming Toolkit](/tools/red-teaming-toolkit/)
