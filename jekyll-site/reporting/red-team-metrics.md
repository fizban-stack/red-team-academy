---
layout: training-page
title: "Red Team Metrics & ROI — Measuring Program Effectiveness"
module: "Reporting"
tags:
  - metrics
  - roi
  - red-team-program
  - tiber-eu
  - vectr
  - mttd
  - detection-rate
  - purple-team
page_key: "reporting-red-team-metrics"
render_with_liquid: false
---

# Red Team Metrics & ROI

How to measure, track, and communicate red team program effectiveness. This page covers program-level measurement — not individual engagement reporting (covered in the technical and executive report pages). The goal: prove security improvement over time and earn continued investment.

---

## Why Metrics Matter

The most common red team failure mode isn't technical — it's organizational. Red team programs get defunded because they can only say "we got in" without demonstrating trend improvement or risk reduction. Metrics solve this.

**Without metrics:**
- Each engagement is standalone with no comparison baseline
- Defenders have no feedback loop on which controls improved
- Executive sponsors can't quantify the program's value
- Budget justification relies on narrative, not data

**With metrics:**
- MTTD trending shows detection capability improving quarter-over-quarter
- ATT&CK coverage maps show which techniques the SOC can/can't detect
- TIBER-EU compliance produces formal attestation for regulators
- Executives see risk reduction in language they understand

---

## Core Operational KPIs

### Mean Time to Detect (MTTD)

Time from the red team's first malicious action to the SOC generating an alert.

```
# Formula:
MTTD = sum(detection_timestamp[i] - action_timestamp[i]) / n_detected_techniques

# Example calculation:
# Technique 1: Action at 09:00, Detected at 09:47 → 47 minutes
# Technique 2: Action at 10:15, Detected at 14:30 → 255 minutes
# Technique 3: Action at 11:00, Not detected → excluded from MTTD
# MTTD = (47 + 255) / 2 = 151 minutes

# Track per-quarter:
# Q1 2025: MTTD = 6.2 hours
# Q2 2025: MTTD = 4.1 hours  (-34% improvement)
# Q3 2025: MTTD = 2.8 hours  (-32% improvement)
```

### Detection Rate

Percentage of executed red team techniques that generated at least one alert.

```
# Formula:
Detection Rate = techniques_detected / techniques_executed * 100

# Example:
# 42 techniques executed, 17 detected = 40.5% detection rate

# ATT&CK breakdown (most useful form):
Initial Access:         3/5 detected (60%)
Execution:              2/8 detected (25%)   ← gap identified
Persistence:            1/6 detected (17%)   ← gap identified
Privilege Escalation:   4/7 detected (57%)
Defense Evasion:        1/9 detected (11%)   ← biggest gap
Credential Access:      3/5 detected (60%)
Lateral Movement:       2/4 detected (50%)
Collection/Exfiltration:1/3 detected (33%)
```

### ATT&CK Technique Coverage

```
# Track per technique ID over time:
# Use VECTR to log each technique execution and detection outcome

# VECTR output format (per campaign):
# Technique ID | Name                        | Outcome
# T1566.002    | Spear Phishing via Link     | No Detection
# T1059.001    | PowerShell                  | Detected (Event 4104)
# T1003.001    | LSASS Memory Dumping        | Detected (EDR alert)
# T1021.002    | SMB Lateral Movement        | No Detection

# ATT&CK Navigator: export heatmap as JSON for presentation
# Green = detected, Red = not detected, Grey = not tested
```

### Other Key Metrics

```
# Persistence Duration — time from initial access to eviction:
Persistence_Duration = eviction_timestamp - initial_access_timestamp

# If red team ran for 5 days before detection:
# "An adversary could maintain access for ~5 days undetected"

# Objective Achievement Rate — % of engagements where red team reached objective:
# Q3 2025: 7/10 engagements — red team reached target data within scope
# This should DECREASE over time as defenses improve

# Containment Rate — % of detections resulting in successful containment:
# Detected 17 techniques, SOC contained 12 = 70.6% containment rate
# Remaining 5 detected but not contained → SOC playbook gaps
```

---

## ATT&CK Coverage Tracking with VECTR

VECTR (SecurityRiskAdvisors) is the standard open-source platform for tracking red/purple team exercise results against ATT&CK.

```
# VECTR setup (Docker):
git clone https://github.com/SecurityRiskAdvisors/VECTR
cd VECTR
docker compose up -d
# Access at http://localhost:8081

# VECTR workflow:
# 1. Create a Campaign (maps to one red team engagement)
# 2. Add Test Cases (each ATT&CK technique tested)
# 3. For each test case: record outcome (detected/not detected, containment)
# 4. Generate coverage reports and ATT&CK Navigator export

# ATT&CK Navigator layer export from VECTR:
# Shows heat map across the ATT&CK matrix
# Compare between Q1 and Q4: which cells changed from red to green?

# Quarterly delta report:
# Techniques newly detected: T1059.001, T1003.001, T1021.002 (+3)
# Techniques regressed (detection lost): T1055.001 (-1)
# Net improvement: +2 techniques detected this quarter
```

---

## Regulatory Frameworks

### TIBER-EU (European Central Bank)

The official threat-intelligence-based red team framework for European financial institutions.

```
# Three mandatory phases:
# 1. Threat Intelligence Phase (8-12 weeks)
#    - External CTI provider maps threats to the institution
#    - Produces Targeted Threat Intelligence (TTI) report
#    - TTI defines the adversary scenarios for testing

# 2. Red Team Test Phase (12-16 weeks)
#    - Red team executes scenarios from TTI report
#    - Findings documented in Red Team Test Report

# 3. Closure Phase (4-8 weeks)
#    - Blue team retrospective (what was detected/missed)
#    - Remediation plan
#    - Formal closure report to regulator

# Required metrics in TIBER-EU closure report:
# - Total attack scenarios tested
# - Scenarios resulting in objective achieved (critical findings)
# - Detection rate per phase
# - Mean time to detect per scenario
# - Control effectiveness ratings
```

### DORA (EU Digital Operational Resilience Act, 2025)

```
# Article 26: TLPT (Threat-Led Penetration Testing) — mandatory for significant financial entities
# Scope: production systems, no safe harbor testing environment
# Frequency: every 3 years minimum
# Required TLPT output:
# - Risk register updates
# - Control gap analysis
# - Specific remediation commitments with deadlines
# - Regulator attestation

# DORA-aligned red team metrics to track:
# ICT risk indicator: detection coverage per critical function
# MTTD for critical business processes
# Recovery Time Objective (RTO) after simulated breach
```

---

## Executive Reporting Framework

### Translating Findings to Business Impact

```
# Technical finding:
"Red team maintained persistent access to domain controller for 14 days 
without triggering any SOC alerts."

# Executive translation:
"If a real attacker targeted us with equivalent techniques, we would not 
know our systems were compromised for approximately two weeks — giving 
the attacker unlimited time to access payroll systems, customer data, 
and wire transfer capabilities."

# Metrics table for board presentation:
Metric                  | Q1 2025 | Q2 2025 | Q3 2025 | Trend
Mean Time to Detect     | 8.2 hrs | 6.1 hrs | 4.3 hrs | ↑ Improving
Detection Rate          | 28%     | 35%     | 44%     | ↑ Improving
Objective Achievement   | 90%     | 80%     | 60%     | ↓ Hardening
Persistence Duration    | 21 days | 14 days | 8 days  | ↓ Improving
```

---

## Maturity Model

```
Level 1 — Ad-Hoc
  - Testing conducted sporadically
  - No measurement or trending
  - Findings not tracked to remediation

Level 2 — Documented
  - Individual engagement reports produced
  - Findings tracked in a spreadsheet or ticketing system
  - No cross-engagement comparison

Level 3 — Measured
  - ATT&CK coverage tracked per engagement (VECTR)
  - MTTD and detection rate calculated quarterly
  - Trend reporting presented to security leadership

Level 4 — Integrated
  - Red team findings feed directly into SOC detection engineering
  - Automated adversary simulation supplements manual testing (SCYTHE, AttackIQ)
  - Purple team exercises run alongside red team engagements

Level 5 — Optimized
  - Continuous validation via BAS (Breach and Attack Simulation)
  - Real-time detection coverage metrics on security dashboard
  - Red team KPIs tied to security program investment decisions
  - Regulatory compliance (TIBER-EU/DORA) embedded in cadence
```

---

## Resources

- VECTR — `github.com/SecurityRiskAdvisors/VECTR`
- TIBER-EU framework — `ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf`
- DORA regulatory technical standards — `eba.europa.eu/regulation-and-policy/operational-resilience`
- SCYTHE automated adversary emulation — `scythe.io`
- AttackIQ BAS platform — `attackiq.com`
- Picus Red Report 2025 — `picussecurity.com/red-report`
- MITRE ATT&CK Evaluations — `attackevals.mitre-engenuity.org`
- ATT&CK Navigator — `github.com/mitre-attack/attack-navigator`
