---
layout: training-page
title: "Rules of Engagement Template"
module: "Reporting"
page_key: "reporting-templates-roe"
render_with_liquid: false
updated: "2026-04-17"
---

# Rules of Engagement (RoE)

> **Purpose**: The Rules of Engagement document defines the explicit boundaries, protocols, and authorities for a red team engagement. Both parties must sign and acknowledge the RoE before any testing begins. The RoE supplements — it does not replace — the Statement of Work (SOW).

---

## RULES OF ENGAGEMENT

**Document Reference**: ROE-[YEAR]-[CLIENT_CODE]-[SEQUENCE]
**Associated SOW**: SOW-[YEAR]-[CLIENT_CODE]-[SEQUENCE]
**Effective Date**: [DATE]
**Engagement Window**: [START DATE] to [END DATE]

---

## 1. Engagement Overview

**Client Organization**: [CLIENT LEGAL NAME]
**Engagement Name**: [PROJECT NAME]
**Engagement Type**: [Full Red Team / Assumed Breach / Social Engineering Only]
**Operator Firm**: [FIRM NAME]
**Engagement Lead**: [NAME]

This document governs the conduct of the above-referenced red team engagement. All members of the red team and all Client stakeholders named herein are bound by these rules. Violations of the RoE may result in immediate engagement suspension and may constitute breach of contract.

---

## 2. Authorization Chain

The following individuals have authorized this engagement and have the authority to modify or terminate it.

**Primary Authorizing Executive** (highest authority — can terminate engagement):
```
Name:         [C-SUITE EXECUTIVE NAME — CEO / CIO / CISO]
Title:        [TITLE]
Organization: [CLIENT NAME]
Phone:        [MOBILE]
Email:        [EMAIL]
```

**Technical Authorization Contact** (day-to-day authority):
```
Name:         [NAME]
Title:        [TITLE — e.g., CISO / Director of Security]
Phone:        [MOBILE]
Email:        [EMAIL]
```

**IT Operations Contact** (infrastructure coordination):
```
Name:         [NAME]
Title:        [TITLE]
Phone:        [MOBILE]
Email:        [EMAIL]
```

**Engagement Lead — [FIRM NAME]**:
```
Name:         [NAME]
Phone:        [MOBILE]
Email:        [EMAIL]
```

---

## 3. In-Scope Systems

### 3.1 Network IP Ranges

```
Network / CIDR            | Description                 | Testing Authorization
--------------------------|-----------------------------|-----------------------
[10.0.0.0/8]              | Corporate internal network  | Full
[172.16.0.0/12]           | Server segment              | Full — no intentional DoS
[192.168.100.0/24]        | OT/ICS network (read-only)  | Passive enumeration only
[EXTERNAL_IP/32]          | Web server public IP        | Full external testing
[EXTERNAL_IP_RANGE/CIDR]  | IP range for external scan  | Full
```

### 3.2 Domain Names

```
Domain                         | Type       | Authorization
-------------------------------|------------|-----------------------------
[*.targetcorp.com]             | External   | Full — all subdomains
[corp.internal]                | Internal   | Full AD enumeration + attack
[targetcorp.onmicrosoft.com]   | M365       | Authorized — no data deletion
[legacy.corp.internal]         | Internal   | Read-only — legacy systems
```

### 3.3 Cloud Environments

```
Platform | Account / Tenant                        | Authorization
---------|----------------------------------------|---------------------------
AWS      | Account ID: [XXXXXXXXXXXX]              | Full — except [SERVICE]
Azure    | Tenant ID: [XXXX-XXXX-XXXX-XXXX]        | Full
M365     | [targetcorp.onmicrosoft.com]            | Read + exfil sim only
GCP      | Project: [PROJECT_NAME]                 | Not in scope this engagement
```

### 3.4 Physical Locations (if applicable)

```
Location                              | Address              | Authorization Level
--------------------------------------|----------------------|--------------------
[SITE NAME — Headquarters]            | [ADDRESS]            | Full — all areas
[SITE NAME — Branch Office]           | [ADDRESS]            | Lobby + common areas only
[SITE NAME — Data Center]             | [ADDRESS]            | Not in scope — excluded
```

---

## 4. Out-of-Scope Systems

**The following are explicitly excluded. Any accidental access to out-of-scope systems must be reported immediately (see Section 7).**

```
System / IP / Domain              | Reason for Exclusion
----------------------------------|-----------------------------------------------
[IP/RANGE]                        | Third-party hosted — no authorization obtained
[SYSTEM NAME — payment processor] | PCI-DSS — must not be disrupted
[SYSTEM NAME]                     | Safety-critical — physical risk
[DOMAIN]                          | Subsidiary company — separate legal entity
[NAMED EMPLOYEE]                  | Explicitly excluded from social engineering
[CLOUD SERVICE]                   | Critical infrastructure — no disruption
```

---

## 5. Prohibited Actions

The following actions are **strictly prohibited** regardless of technical feasibility. Performing any prohibited action will result in immediate engagement suspension.

### 5.1 Data Handling Restrictions

- [ ] Do NOT exfiltrate actual production data from Client systems to operator infrastructure
- [ ] Do NOT retain copies of Client employee PII, PHI, PCI card data, or passwords
- [ ] Do NOT access, read, or copy data from out-of-scope systems even if technically reachable
- [ ] Do NOT store captured credentials beyond the engagement window
- [ ] Do NOT transmit Client data over unencrypted channels

### 5.2 System Stability Restrictions

- [ ] Do NOT intentionally cause denial of service to production systems
- [ ] Do NOT run bandwidth-intensive scans during business hours without prior approval
- [ ] Do NOT crash, reboot, or significantly degrade production servers
- [ ] Do NOT modify production data (read-only access except where specifically authorized)
- [ ] Do NOT modify Active Directory objects not specifically created during this engagement
- [ ] Do NOT modify firewall rules, ACLs, or routing tables permanently

### 5.3 Social Engineering Restrictions

- [ ] Do NOT impersonate emergency services (police, fire, medical)
- [ ] Do NOT use threats, coercion, or psychological manipulation beyond approved scope
- [ ] Do NOT target employees who have explicitly opted out: [LIST IF APPLICABLE]
- [ ] Do NOT conduct in-person social engineering without at least two operators present
- [ ] Do NOT attempt to access areas that would require physical confrontation

### 5.4 Legal Restrictions

- [ ] Do NOT use techniques that would constitute criminal unauthorized access under applicable law
  (Note: engagement authorization covers these activities — retain a copy of this signed RoE)
- [ ] Do NOT intercept communications of non-consenting third parties
- [ ] Do NOT conduct testing from jurisdictions where the activity would be illegal

---

## 6. Required Notifications

The operator team must notify the Client in the following circumstances. Notification must be made within the timeframe specified.

### 6.1 Immediate Notification (< 15 minutes)

Contact the Technical Authorization Contact and IT Operations Contact immediately if:

- [ ] Any production system becomes unavailable or unresponsive during testing
- [ ] A previously undiscovered critical vulnerability is found that could affect safety of life
- [ ] Evidence of active real-world attacker activity is discovered
- [ ] Testing activity triggers a security incident response activation

### 6.2 Same-Day Notification (< 4 hours)

- [ ] Initial access is obtained (notify: Technical Authorization Contact)
- [ ] Domain/cloud administrator compromise is achieved
- [ ] Objective 1 (highest priority) is achieved
- [ ] Accidental access to out-of-scope systems occurs
- [ ] Evidence of a pre-existing compromise is identified

### 6.3 End-of-Day Notification

- [ ] Daily activity summary — what was tested, what was found (summary level only)
- [ ] New critical findings identified during the day

### 6.4 Notification Method

Primary notification method: [Phone call to Technical Authorization Contact]
Secondary (if primary unreachable): [Email to IT Operations Contact + Authorizing Executive]
Emergency (non-business hours): [SMS to both primary contacts]

---

## 7. Emergency Stop Procedure

If any of the following conditions occur, the red team must immediately cease all testing activities and notify the Primary Authorizing Executive.

**Emergency Stop Triggers**:

- [ ] Any instruction from Primary Authorizing Executive or Technical Authorization Contact to stop
- [ ] Unintended production system outage caused by testing
- [ ] Discovery of safety-critical vulnerability in a non-test system
- [ ] Discovery of active attacker compromise of Client environment
- [ ] Operator personal safety concern during physical testing
- [ ] Legal or law enforcement contact related to the engagement

**Emergency Stop Procedure**:

```
1. IMMEDIATELY halt all active attack tools, sessions, and scans
2. Record exact time of stop and reason
3. Call Primary Authorizing Executive: [PHONE] — within 5 minutes
4. Call Technical Authorization Contact: [PHONE] — within 5 minutes
5. Do NOT remove persistence or clean up until instructed — preserve state for IR
6. Document all active sessions and implants for handoff to Client IR team
7. Do not resume testing until written authorization is received from
   Primary Authorizing Executive
```

---

## 8. Communication Protocols

### 8.1 Secure Communications

All engagement-related communications between [FIRM NAME] and Client must use:

- **Primary**: [ENCRYPTION METHOD — e.g., Signal app, ProtonMail, PGP-encrypted email]
- **Secondary**: Standard corporate email (for non-sensitive scheduling only)
- **Emergency**: Phone or SMS (for immediate stop/go decisions)

PGP key for [FIRM NAME] engagement lead: [KEY FINGERPRINT OR LINK]

### 8.2 Code Words

```
Phrase                    | Meaning
--------------------------|--------------------------------------------
"[CODE WORD — e.g., AMBER]"  | Pause testing — potential concern to discuss
"[CODE WORD — e.g., RED]"    | Emergency stop — immediate halt
"[CODE WORD — e.g., GREEN]"  | All clear — resume testing
"[CODE WORD — e.g., BLUE]"   | Engagement complete — begin cleanup
```

### 8.3 Check-in Schedule

- Daily check-in: [TIME] [TIMEZONE] via [METHOD]
- Weekly status report: every [DAY] by [TIME] [TIMEZONE]
- Missed check-in protocol: if operator misses check-in by [30/60] minutes,
  Client will attempt contact at [PHONE]; if no response after [N] attempts,
  Client may pause engagement activities

---

## 9. Evidence Handling

### 9.1 Evidence Collection Standards

- All evidence must be timestamped with UTC time
- Screenshots must show hostname / IP, username, and timestamp
- Command output must be captured in full (not cropped)
- Evidence must be stored encrypted on [FIRM NAME] infrastructure

### 9.2 Data Minimization

- Real customer data, PII, PHI, or PCI data must not be retained
- If access to such data is demonstrated, capture only a screenshot showing access
  (e.g., partial record, not full export)
- Captured credentials will be salted/masked in the final report
- All engagement data will be securely destroyed [30/60/90] days after final report delivery

### 9.3 Evidence Retention

Evidence collected during the engagement will be retained for [12] months after delivery of the final report to support any remediation questions. After this period, all data will be securely destroyed and destruction confirmed in writing.

---

## 10. Operator Identification

All red team operators must carry the following during physical testing phases:

- [ ] A copy of this signed RoE document
- [ ] Photo identification
- [ ] [FIRM NAME] business card or letterhead
- [ ] Contact information for Primary Authorizing Executive

If stopped by law enforcement or Client security during physical testing:
1. Do not resist — comply with all instructions
2. Identify yourself and state: "I am conducting an authorized security assessment for [CLIENT NAME]"
3. Provide contact information for Primary Authorizing Executive: [NAME] at [PHONE]
4. Do not make statements about findings or methods beyond confirming authorization

---

## 11. Acknowledgment and Signatures

All parties acknowledge they have read, understood, and agree to abide by these Rules of Engagement. Violations may result in engagement termination and potential legal action.

**[CLIENT ORGANIZATION NAME] — Primary Authorizing Executive**:
```
Signature:  ________________________________
Name:       [PRINTED NAME]
Title:      [TITLE]
Date:       [DATE]
```

**[CLIENT ORGANIZATION NAME] — Technical Authorization Contact**:
```
Signature:  ________________________________
Name:       [PRINTED NAME]
Title:      [TITLE]
Date:       [DATE]
```

**[FIRM NAME] — Engagement Lead**:
```
Signature:  ________________________________
Name:       [PRINTED NAME]
Title:      [TITLE]
Date:       [DATE]
```

**Document Version**: 1.0 — Final
**Next Review**: This document will be reviewed and re-signed if scope changes during the engagement.
