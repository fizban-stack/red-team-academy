---
layout: training-page
title: "Engagement Planning — Red Team Academy"
module: "Fundamentals"
tags:
  - planning
  - roe
  - legal
page_key: "fundamentals-engagement-planning"
render_with_liquid: false
---

# Engagement Planning

## Why Engagement Planning Matters

An unplanned red team engagement is a liability — legally, professionally, and operationally. Engagement planning defines the boundaries of your operation before a single packet is sent. It protects you, the client, and the integrity of the findings. A well-structured engagement plan transforms a penetration test into a controlled, repeatable adversary simulation.

![Engagement planning flow: kickoff call, draft RoE, sign and approve, prep infrastructure, execute — with key documents shown below](/images/fundamentals/engagement-planning-flow.svg)  
*// engagement planning flow — from kickoff to authorized execution*

## Rules of Engagement (RoE)

The Rules of Engagement document is the legal contract between the red team and the client. It must be signed before any testing begins. Key components:

- **Authorization statement** — Explicit written permission: who authorizes the test, their title, and signature
- **Scope definition** — IP ranges, domains, applications, physical locations, and personnel that are in/out of scope
- **Testing window** — Dates, times, and any blackout periods (payroll runs, board meetings, prod deployments)
- **Deconfliction contacts** — Point of contact at client who can call off the engagement immediately (with phone number, not just email)
- **Escalation path** — What happens if a real attacker is discovered during the engagement
- **Data handling** — How captured credentials and sensitive data are stored and destroyed post-engagement
- **Prohibited actions** — DoS/DDoS, destructive payloads, social engineering real employees (if not in scope)
- **Emergency stop procedure** — Verbal/written stop command the client can use at any time

## Scope Definition

Scope is the most negotiated part of any engagement. Push for the widest scope justified by the threat model — attackers don't respect artificial boundaries. Common scope elements:

### Network Scope

```
# Example scope notation in RoE
IN SCOPE:
  10.0.0.0/8          # Internal corporate network
  192.168.100.0/24    # DMZ segment
  *.acmecorp.com      # All subdomains
  203.0.113.0/24      # External IP block

OUT OF SCOPE:
  10.50.0.0/16        # HR/Payroll systems
  203.0.113.200       # Production load balancer
  *.acmecorp-uat.com  # UAT environment
```

### Application Scope

- List specific URLs, APIs, and mobile apps by name and version
- Clarify whether authenticated testing is required and who provides test accounts
- Specify whether automated scanners (Burp, Nessus) are permitted

### Social Engineering Scope

- Is phishing permitted? Against all employees or a specific target list?
- Physical access testing (tailgating, badge cloning)?
- Vishing (voice phishing) against help desk or specific roles?
- What pretexts are approved? (IT support, vendor, executive assistant)

## Engagement Types

| Type | Starting Point | Goal | Best For |
| --- | --- | --- | --- |
| External | Internet, no credentials | Gain initial access | Perimeter testing |
| Internal | On-net, low-priv user | Domain Admin / objectives | Internal threat simulation |
| Assumed Breach | Shell on workstation | Detect lateral movement / DA | Testing detection capability |
| Full Simulation | Internet, no knowledge | Full APT simulation | Mature security programs |
| Physical | On-site, no access | Gain physical access, plant implant | Physical security testing |

## Pre-Engagement Checklist

Before the first scan, confirm all of these:

- ☐ Written authorization signed by appropriate authority (CISO/CTO/Owner)
- ☐ RoE document reviewed and agreed by both parties
- ☐ Scope list is final and locked — no verbal scope expansions
- ☐ Emergency deconfliction contact confirmed (cell number, not email)
- ☐ Testing window confirmed — calendar blocked
- ☐ Test accounts created (if internal/assumed breach)
- ☐ VPN or jump host access provisioned (if required)
- ☐ C2 infrastructure deployed and tested in advance
- ☐ Operator systems are clean — no PII or prior engagement data present
- ☐ Secure communication channel established (Signal, encrypted email)
- ☐ Report template prepared — document findings in real time
- ☐ Get-out-of-jail letter in hand (printed, if physical engagement)

## Legal Considerations

Red team testing without written authorization is a crime in most jurisdictions. Key laws to understand:

- **US — CFAA (Computer Fraud and Abuse Act)** — Unauthorized access to protected computers. Explicit written authorization is your defense.
- **UK — Computer Misuse Act 1990** — Unauthorized access/modification. Same principle — written authorization is mandatory.
- **EU — NIS2 Directive** — Governs security testing of critical infrastructure. Additional notification requirements.
- **Cloud environments** — AWS, Azure, GCP have their own penetration testing policies. You must notify them before testing cloud resources.

```
# AWS Penetration Testing Policy
# Some services require prior approval — check:
# https://aws.amazon.com/security/penetration-testing/

# Azure: No prior approval needed for own resources, but notify
# https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement

# GCP: Notify security@google.com for large-scale testing
```

## Kick-off Meeting Agenda

Run a structured kick-off call before testing begins. Cover:

1. Introductions — red team lead, client POC, escalation contacts
2. Objectives review — what does the client want to learn?
3. Scope walkthrough — confirm IP ranges, applications, personnel
4. Timeline — testing window, check-in cadence, reporting deadline
5. Communication protocol — status updates, critical finding notification (<24h for critical)
6. Deconfliction — how to pause/stop the engagement immediately
7. Questions — client asks anything they need clarified before you start

## Adversary Emulation Planning

For full red team simulations, define which threat actor you're emulating before the engagement starts. This shapes your tool selection, TTPs, and timing — the client gets more relevant findings when you model their actual threat landscape.

```
# Steps to build an adversary emulation plan:

# 1. Identify relevant threat actors for the client's sector
#    Tools: MITRE ATT&CK Groups (attack.mitre.org/groups/)
#    Example: Financial sector → FIN7, FIN8, Lazarus Group
#    Example: Healthcare → APT41, FIN12 (ransomware)
#    Example: Government → APT29, APT28, Volt Typhoon

# 2. Map actor TTPs to ATT&CK techniques
#    Use ATT&CK Navigator to create an actor layer:
#    - Filter by group → export Navigator layer
#    - Highlight techniques you will simulate vs skip (out of scope)
#    - Green = will simulate, Yellow = will demonstrate, Gray = out of scope

# 3. Prioritize techniques by detectability + business impact
#    High priority (simulate in full):
#    - Initial access vectors the actor uses (phishing, supply chain, VPN exploit)
#    - Persistence mechanisms (scheduled tasks, WMI, registry keys)
#    - Credential access (LSASS dump, Kerberoasting, DCSync)
#    Lower priority (demonstrate or skip):
#    - Destructive payloads (never in production)
#    - Data encryption (ransomware pre-deployment stages only)

# 4. Document the plan in your RoE appendix:
#    - Threat actor modeled: [Group name, sector relevance]
#    - ATT&CK techniques in scope: T1566.001, T1078, T1003.001, ...
#    - Techniques out of scope and why: T1485 (Data Destruction) — destructive
#    - Tools mapping to actor: [Cobalt Strike = TA0001, Mimikatz = TA0006]

# Example adversary emulation brief (1-pager):
# Threat Actor: FIN7 (financially motivated, retail/hospitality targeting)
# Initial Access: Spear-phishing with macro-enabled Office documents (T1566.001)
# Persistence: WMI event subscriptions (T1546.003), scheduled tasks (T1053.005)
# C2: HTTPS beaconing to attacker-controlled domain (T1071.001)
# Credential Access: LSASS dump via procdump (T1003.001), Kerberoasting (T1558.003)
# Lateral Movement: Pass-the-hash (T1550.002), RDP (T1021.001)
# Objective: Access to POS systems / payment card data environment
```

## Reporting Deliverables

- **Executive Summary** — 1-2 pages, business risk language, no technical jargon, risk rating
- **Technical Findings** — Per finding: title, CVSS score, description, evidence, impact, reproduction steps, remediation
- **Attack Narrative** — Chronological story of how the red team moved from initial access to objectives
- **ATT&CK Navigator Layer** — Visual showing which techniques were used, detected, and missed
- **Remediation Roadmap** — Prioritized list of fixes with effort estimates
