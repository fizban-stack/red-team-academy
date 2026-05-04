---
layout: training-page
title: "Threat Intelligence for Red Teams — TI-Driven Exercise Design"
module: "Threat Actors"
tags:
  - threat-intelligence
  - red-team-planning
  - mitre-attack
  - threat-actor-emulation
  - tiber-eu
  - apt
  - ttps
  - exercise-design
page_key: "threat-actors-ti-for-red-teams"
render_with_liquid: false
---

# Threat Intelligence for Red Teams — TI-Driven Exercise Design

Red team exercises are most valuable when they emulate *your actual adversaries*, not generic attack playbooks. This page covers how to consume threat intelligence from Mandiant, Dragos, CISA, and MITRE ATT&CK to design exercises that test whether your defenses can withstand the threats actually targeting your sector.

---

## Why TI-Driven Exercises

```
Generic red team:
- Tests "what can we break?" 
- Uses attacker's tool preferences
- Measures general security posture

TI-driven red team:
- Tests "can our defenses stop APT-X, which is known to target us?"
- Uses the actual TTPs the adversary uses
- Measures gap between real threat capability and current defenses

The difference: a financial services firm defending against FIN7 vs.
generic web app testing. FIN7's specific tooling (Carbanak, Griffon JS),
delivery methods (BEC → internal phish), and objectives (SWIFT/ATM fraud)
require targeted exercise design.
```

---

## Step 1: Identify Your Relevant Threat Actors

### By Sector

```
# CISA Known Exploited Vulnerabilities (KEV) by sector:
# Free, regularly updated, sector-tagged
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
# Filter for your sector's technologies
vulns = [v for v in data['vulnerabilities'] if 'Exchange' in v.get('product','')]
for v in vulns[:10]:
    print(v['cveID'], v['vendorProject'], v['product'], v['dateAdded'])
"

# MITRE ATT&CK sector-specific threat groups:
# Financial: FIN7, FIN8, FIN11, Lazarus Group, APT38
# Healthcare: APT41, Volt Typhoon (PRC), various ransomware operators
# Energy/ICS: Sandworm (Russia/ELECTRUM), Volt Typhoon, TRITON actor
# Defense: APT10, APT41, Cozy Bear (APT29)
# Technology: APT10, APT41, UNC2452 (SolarWinds actor)

# Dragos threat groups (ICS/OT focused):
# ELECTRUM → attacks on power grids (linked to Sandworm)
# HEXANE → oil & gas targeting
# KAMACITE → pre-positioning in energy sector
# Free: dragos.com/threat-groups/ for group cards
```

### Mining Threat Reports

```
# Key sources by vendor:
# Mandiant (Google): mandiant.com/resources/insights/reports
# CrowdStrike: crowdstrike.com/global-threat-report/
# CISA Advisories: cisa.gov/news-events/cybersecurity-advisories
# NCSC: ncsc.gov.uk/collection/threat-reports
# Recorded Future: recordedfuture.com/research/

# What to extract from a threat report:
# 1. Initial access vector used by this actor
# 2. Persistence mechanism (registry, scheduled task, service?)
# 3. Lateral movement technique (WMI, PSExec, RDP, DCOM?)
# 4. Credential access (LSASS, DCSync, AS-REP, Kerberoast?)
# 5. C2 protocol and infrastructure (Cobalt Strike HTTP, DNS tunneling?)
# 6. Target industries and observed objectives

# Report parsing with LLM assistance:
# Paste report excerpt + prompt:
# "Extract all ATT&CK technique IDs mentioned or implied in this threat report.
#  For each, note: technique ID, name, specific tooling used, and indicator of compromise."
```

---

## Step 2: Map Adversary TTPs to ATT&CK

```
# ATT&CK Navigator — create threat actor layer:
# navigator.attack.mitre.org → Load actor TTP layer

# Manual mapping example — FIN7 (from MITRE):
FIN7 TTPs (selected):
  T1566.001 - Spear phishing attachment (DOCX with macro)
  T1059.005 - Visual Basic (malicious VBScript delivery)
  T1547.001 - Registry Run Keys (CARBANAK persistence)
  T1055.001 - Process injection (Griffon JS in-memory)
  T1041     - Exfiltration over C2 channel
  T1071.001 - Web protocols for C2 (HTTPS to CDNs)

# Export as JSON for your Navigator layer:
python3 << 'EOF'
import json

# Template for ATT&CK Navigator layer:
layer = {
    "name": "FIN7 Emulation Layer",
    "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": "T1566.001", "score": 1, "comment": "Primary delivery: DOCX macro"},
        {"techniqueID": "T1059.005", "score": 1, "comment": "VBScript loader"},
        {"techniqueID": "T1547.001", "score": 1, "comment": "CARBANAK Registry persistence"},
        {"techniqueID": "T1055.001", "score": 1, "comment": "Griffon JS injection"},
        {"techniqueID": "T1071.001", "score": 1, "comment": "HTTPS C2 via CDN"},
    ],
    "gradient": {"colors": ["#ffffff","#ff6666"], "minValue": 0, "maxValue": 1}
}
print(json.dumps(layer, indent=2))
EOF
```

---

## Step 3: Design the Exercise Against Target TTPs

```
# Exercise design template:

# Objective: "Can our SOC detect and contain an FIN7-style intrusion 
#              before financial system access?"

# Phase 1: Initial Access (map to T1566.001)
# Emulation: Spear phishing campaign with DOCX attachment
# - Target: finance or AP staff (FIN7's typical target)
# - Payload: macro that downloads CARBANAK-like stage 2
# - Red team tooling: use actual FIN7 delivery format (DOCX with VBA macro)
# - Detection criteria: email filtering, user reporting, endpoint alert

# Phase 2: Execution & Persistence (T1059.005, T1547.001)
# Emulation: Run VBScript loader, Registry Run Key for persistence
# - Use actual CARBANAK registry key name format
# - Detection criteria: registry write alerts, script execution events

# Phase 3: Lateral Movement (T1021.002 - SMB, T1078 - valid accounts)
# Emulation: SMB lateral movement to financial workstations
# - Detection criteria: lateral movement detection in SIEM

# Phase 4: Target Action (T1041 - C2 exfil)
# Objective: reach SWIFT terminal or wire transfer system
# - Detection criteria: DLP alert on financial data movement

# VECTR exercise setup:
# Create campaign: "FIN7 Emulation Q3-2025"
# Add test cases for each TTP with success criteria
```

---

## Step 4: Source Threat-Authentic Tooling

```
# MITRE CALDERA — automated adversary emulation:
git clone https://github.com/mitre/caldera && cd caldera
pip install -r requirements.txt
python server.py --insecure

# CALDERA has pre-built APT profiles:
# APT3 (UPS), APT29 (Cozy Bear), FIN6, menuPass
# Access via: http://localhost:8888 → Campaigns → Apply profile

# Atomic Red Team — threat-specific test library:
git clone https://github.com/redcanaryco/atomic-red-team
# Run specific technique matching actor TTP:
Invoke-AtomicTest T1566.001 -GetPrereqs
Invoke-AtomicTest T1566.001 -TestNumbers 1

# Threat actor-specific tooling sources:
# APT29 tooling: github.com/OTRF/Microsoft-Sentinel-Attack-Simulation/tree/main/APT29
# FIN7: Mandiant FIN7 emulation: github.com/mandiant/APT-Hunter
# Sandworm (CRASHOVERRIDE/Industroyer): research-only, see ESET reports

# For custom emulation — replicate TTPs not tools:
# You don't need Carbanak malware — replicate what it DOES:
# Registry persistence + HTTPS C2 + process injection
# Custom tooling that matches the behavior profile is more defensively useful
```

---

## Step 5: Build the Exercise Scenario Narrative

```
# Scenario narrative template:

# "OPERATION [CODENAME]"
# Threat Actor: [APT/FIN group]
# Sector Targeting: [your sector]
# Observed Campaign: [date of actual campaign from report]
# 
# Intelligence Assessment:
# [Group] has been observed targeting [sector] organizations in [region]
# using [initial access technique]. The group seeks [objective: IP theft, 
# financial gain, pre-positioning for disruption].
# 
# Exercise Objective:
# Test whether [org] can detect and respond to a [group]-style intrusion
# within [X hours] before the adversary reaches [critical system].
#
# Test Scenarios (in order):
# Scenario 1: Spear phishing targeting [role] staff
# Scenario 2: Post-compromise lateral movement from workstation to server segment
# Scenario 3: Credential access from domain controller
# Scenario 4: Data staging and exfiltration
# 
# Success Criteria (Red Team):
# - Achieve domain admin within 5 days
# - Reach [critical asset] without detection
#
# Success Criteria (Blue Team):
# - Detect initial access within 4 hours
# - Contain lateral movement within 24 hours
# - Evict red team before reaching [critical asset]

# TIBER-EU format (regulated entities):
# This scenario narrative maps to the TIBER-EU Targeted Threat Intelligence (TTI) 
# report format required by the framework
```

---

## Reading Dragos Reports for ICS Exercises

```
# Dragos Year in Review report (annual, free download):
# Contains: most targeted ICS sectors, active threat groups, TTPs

# For ICS-targeting exercises, extract:
# - Initial access to corporate IT (where all ICS campaigns start)
# - IT-to-OT pivot technique (historian servers, jump hosts, VPN)
# - OT enumeration tools (Nmap against PLC subnets, passive monitoring)
# - Disruption techniques (if applicable to exercise)

# ICS ATT&CK (ICS-specific matrix):
# attack.mitre.org/matrices/ics/
# Separate matrix from enterprise — covers ICS-specific techniques:
# T0817 - Drive-by Compromise (initial access to IT)
# T0886 - Remote Services (pivot to OT via RDP/VPN)
# T0842 - Network Sniffing (OT protocol capture)
# T0831 - Manipulation of Control (objective)

# Dragos Neighborhood Keeper (free OT threat intel sharing):
# dragos.com/neighborhood-keeper/
# Share IOCs with other ICS operators, receive sector-specific intelligence
```

---

## Translating Reports to Detection Gaps

```
# After exercise completion, map results to TI report findings:

# Template: "Intelligence says actor uses X — do we detect X?"
# Technique          | Actor Uses? | We Detected? | Gap?
# ─────────────────────────────────────────────────────────
# DOCX macro delivery| Yes (FIN7)  | 55% emails   | Partial gap
# VBScript execution | Yes         | No           | GAP
# Registry persistence| Yes        | Yes          | Covered
# SMB lateral move   | Yes         | 50% of cases | Partial gap
# HTTPS C2 via CDN   | Yes         | No           | GAP

# This gap analysis directly drives:
# 1. Detection engineering priorities (write new SIEM/EDR rules)
# 2. Tool improvement (new endpoint sensor deployment)
# 3. Process improvement (SOC playbook for VBScript execution)

# Quarterly progress: run same TTP set 3 months later
# Did gap close? → measure with same exercise framework
```

---

## Resources

- MITRE ATT&CK — `attack.mitre.org`
- MITRE ATT&CK Navigator — `github.com/mitre-attack/attack-navigator`
- CALDERA adversary emulation — `github.com/mitre/caldera`
- Atomic Red Team — `github.com/redcanaryco/atomic-red-team`
- Mandiant threat intelligence — `mandiant.com/resources`
- Dragos ICS threat groups — `dragos.com/threat-groups/`
- CISA cybersecurity advisories — `cisa.gov/news-events/cybersecurity-advisories`
- TIBER-EU framework — `ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf`
- CISA KEV catalog — `cisa.gov/known-exploited-vulnerabilities-catalog`
- Recorded Future Annual Report — `recordedfuture.com/research`
