---
layout: training-page
title: "Red Team Report Template"
module: "Reporting"
page_key: "reporting-templates-report"
render_with_liquid: false
updated: "2026-04-17"
---

# Red Team Engagement Report

## Document Control

```
Classification:  [CONFIDENTIAL — [CLIENT NAME] EYES ONLY]
Document Title:  Red Team Engagement Report
Client:          [CLIENT ORGANIZATION NAME]
Engagement:      [ENGAGEMENT CODE / PROJECT NAME]
Report Version:  1.0
Prepared By:     [LEAD CONSULTANT NAME], [FIRM NAME]
Review Date:     [DATE]
Delivery Date:   [DATE]

Distribution:
  [NAME, TITLE, CLIENT ORG]
  [NAME, TITLE, CLIENT ORG]

This report contains sensitive security findings. Distribution must be
restricted to authorized recipients only. Do not reproduce or forward
without written authorization from [FIRM NAME].
```

---

## 1. Executive Summary

### 1.1 Engagement Overview

[CLIENT NAME] engaged [FIRM NAME] to conduct a full-scope red team assessment of [BRIEF DESCRIPTION OF ENVIRONMENT — e.g., "the corporate headquarters network, cloud infrastructure, and remote access systems"]. The engagement was conducted from [START DATE] to [END DATE] and simulated a real-world, motivated adversary attempting to gain unauthorized access, escalate privileges, and achieve the client-defined objectives.

### 1.2 Key Findings at a Glance

| Severity | Count |
|----------|-------|
| Critical | [N]   |
| High     | [N]   |
| Medium   | [N]   |
| Low      | [N]   |
| Informational | [N] |
| **Total** | **[N]** |

### 1.3 Objectives Achieved

```
Objective 1: [OBJECTIVE DESCRIPTION — e.g., "Gain domain administrator access"]
Status:       ACHIEVED / PARTIALLY ACHIEVED / NOT ACHIEVED
Summary:      [2-3 sentence description of how it was achieved or why not]

Objective 2: [OBJECTIVE DESCRIPTION — e.g., "Access financial records in scope"]
Status:       ACHIEVED / PARTIALLY ACHIEVED / NOT ACHIEVED
Summary:      [2-3 sentence description]

Objective 3: [OBJECTIVE DESCRIPTION — e.g., "Demonstrate persistence post-password reset"]
Status:       ACHIEVED / PARTIALLY ACHIEVED / NOT ACHIEVED
Summary:      [2-3 sentence description]
```

### 1.4 Executive Risk Statement

[2-3 paragraphs written for a non-technical executive audience. Cover: overall risk posture, most significant findings and their business impact, the key investment areas that would reduce risk most. Avoid technical jargon. Emphasize business impact over technical details.]

Example: "During the [N]-week assessment, the red team successfully achieved all three defined objectives, including unauthorized access to [SENSITIVE SYSTEM] within [N] days of engagement start. The most significant risk identified was [FINDING NAME], which allowed the team to [IMPACT SUMMARY]. This type of attack is actively used by [THREAT ACTOR TYPE] and does not require advanced technical capability to execute."

### 1.5 Top Remediation Priorities

1. **[FINDING TITLE]** — [One-sentence business impact]. Estimated remediation effort: [LOW/MEDIUM/HIGH].
2. **[FINDING TITLE]** — [One-sentence business impact]. Estimated remediation effort: [LOW/MEDIUM/HIGH].
3. **[FINDING TITLE]** — [One-sentence business impact]. Estimated remediation effort: [LOW/MEDIUM/HIGH].

---

## 2. Engagement Overview

### 2.1 Scope

**In-Scope Systems and Networks:**
```
IP Ranges:
  [10.0.0.0/8] — Corporate internal network
  [172.16.0.0/12] — Server segment
  [EXTERNAL_IP/CIDR] — DMZ / internet-facing systems

Domains:
  [corp.internal] — Active Directory domain
  [*.targetcorp.com] — Public web applications
  [targetcorp.onmicrosoft.com] — Microsoft 365 tenant

Physical Locations:
  [LOCATION NAME] — [Address] — [Scope: building access, no server room]
  [LOCATION NAME] — [Address] — [Scope: full facility, including data center]

Cloud Environments:
  AWS Account: [ACCOUNT ID] — [SCOPE DESCRIPTION]
  Azure Tenant: [TENANT ID] — [SCOPE DESCRIPTION]
```

**Out-of-Scope Systems:**
```
  [SYSTEM/IP] — [Reason: production payment system, no disruption allowed]
  [SYSTEM/IP] — [Reason: third-party managed, no authorization from vendor]
  [DOMAIN]    — [Reason: subsidiary excluded by client request]
```

### 2.2 Engagement Type and Methodology

- **Assessment Type**: [Full Red Team / Assumed Breach / Purple Team / Adversary Simulation]
- **Knowledge Level**: [Black Box / Grey Box / White Box]
- **Starting Position**: [External internet / Internal network via VPN / Assumed compromise of workstation]
- **Threat Model**: [APT29 / Financially Motivated Actor / Insider Threat / Custom]

### 2.3 Engagement Timeline

```
[DATE] — Kickoff call, scope finalization, RoE signed
[DATE] — External reconnaissance phase begins
[DATE] — Initial access obtained (via [VECTOR])
[DATE] — Internal reconnaissance phase begins
[DATE] — Privilege escalation achieved ([ACCOUNT])
[DATE] — Domain compromise ([EVENT])
[DATE] — Objective 1 achieved: [DESCRIPTION]
[DATE] — Objective 2 achieved: [DESCRIPTION]
[DATE] — Assessment end, cleanup, debrief call
[DATE] — Draft report delivered
[DATE] — Final report delivered
```

---

## 3. Attack Narrative

### 3.1 Phase 1 — Reconnaissance

[Describe reconnaissance activities: OSINT, subdomain enumeration, employee profiling, LinkedIn, job postings, leaked credentials, exposed cloud assets, email address harvesting. What was learned and how it informed the attack.]

Key findings from reconnaissance:
- [FINDING]: [DESCRIPTION AND ATTACK VALUE]
- [FINDING]: [DESCRIPTION AND ATTACK VALUE]

### 3.2 Phase 2 — Initial Access

[Describe how initial access was obtained. Phishing campaign, exploited external service, valid credentials, physical access. Include enough detail that a technical reader understands the exact method but limit sensitive operational details.]

**Initial access vector**: [DESCRIPTION — e.g., "Spearphishing email with malicious HTML attachment targeting [DEPARTMENT] employees"]

**Initial access date/time**: [DATE TIME UTC]

**Initial foothold**: [DESCRIPTION — e.g., "Shell on WORKSTATION-042 (Windows 10, 10.10.10.55) as [USER]"]

**Evidence Reference**: See Appendix C, Evidence Item RT-001 through RT-005.

### 3.3 Phase 3 — Internal Reconnaissance

[Describe network enumeration, Active Directory reconnaissance, service discovery, credential harvesting from memory and disk. What was mapped and how it informed next steps.]

Network topology discovered: [DESCRIPTION]
Key assets identified: [LIST]
Credentials obtained: [SUMMARIZE WITHOUT INCLUDING ACTUAL PASSWORDS]

### 3.4 Phase 4 — Privilege Escalation

[Describe the privilege escalation chain: from initial low-privilege foothold to elevated access. Each step should reference a specific finding in Section 4.]

Escalation chain:
```
[USER] on [WORKSTATION] → Finding RT-F002 (Kerberoasting) → [SVC_ACCOUNT] 
→ Finding RT-F003 (Local Admin via svc_account) → Local Admin on [SERVER]
→ Finding RT-F004 (Token Impersonation) → SYSTEM on [SERVER]
→ Finding RT-F001 (DCSync) → Domain Admin
```

**Domain compromise date/time**: [DATE TIME UTC]

### 3.5 Phase 5 — Lateral Movement

[Describe how access was expanded from the initial foothold: Pass-the-Hash, Kerberoasting, credential reuse, RDP, WMI, PSRemoting. Which systems were accessed and why (path to objective).]

### 3.6 Phase 6 — Objective Achievement

**Objective 1 — [DESCRIPTION]:**
[Describe exactly what was done, what was accessed, and what evidence was captured to demonstrate access. Reference evidence items.]

**Objective 2 — [DESCRIPTION]:**
[Describe exactly what was done.]

### 3.7 Phase 7 — Persistence

[Describe any persistence mechanisms installed during the assessment: scheduled tasks, service installations, registry run keys, Active Directory backdoors, cloud service principal backdoors. All persistence must be cleaned up — reference cleanup confirmation in Appendix D.]

### 3.8 Cleanup Confirmation

All persistence mechanisms and modified artifacts have been removed as of [DATE]. See Appendix D for complete cleanup log.

---

## 4. Findings

### Findings Summary Table

| ID | Title | Severity | CVSS | Affected System |
|----|-------|----------|------|-----------------|
| RT-F001 | [FINDING TITLE] | Critical | [SCORE] | [SYSTEM] |
| RT-F002 | [FINDING TITLE] | High | [SCORE] | [SYSTEM] |
| RT-F003 | [FINDING TITLE] | Medium | [SCORE] | [SYSTEM] |
| RT-F004 | [FINDING TITLE] | Low | [SCORE] | [SYSTEM] |

---

### RT-F001 — [FINDING TITLE]

**Severity**: CRITICAL
**CVSS v3.1 Score**: [SCORE]
**CVSS Vector**: `CVSS:3.1/AV:[X]/AC:[X]/PR:[X]/UI:[X]/S:[X]/C:[X]/I:[X]/A:[X]`
**Affected System(s)**: [HOSTNAME / IP / SERVICE]
**Discovery Date**: [DATE]

**Description**

[One to three paragraphs explaining what the vulnerability is, where it was found, and why it is a problem. Write for a technical audience (developer, sysadmin) but avoid excessive jargon. First paragraph: what it is. Second paragraph: where it is and how it manifests. Third paragraph (if needed): broader context or related weakness.]

**Steps to Reproduce**

```
1. [Action taken — e.g., "From a low-privilege domain account, ran Rubeus on WORKSTATION-042:"]
   Rubeus.exe kerberoast /outfile:tickets.txt

2. [Next step — e.g., "Cracked the recovered TGS ticket offline:"]
   hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt -r best64.rule

3. [Result — e.g., "Password cracked in 3 minutes 42 seconds:"]
   $krb5tgs$23$*svc_backup$CORP.LOCAL$svc_backup/backup01.corp.local*$...
   → svc_backup:Summer2024!

4. [Impact demonstration:]
   crackmapexec smb 10.10.10.0/24 -u svc_backup -p 'Summer2024!'
   → Local admin access confirmed on 14 workstations and 3 servers
```

**Evidence**

- `RT-E001`: Screenshot — Rubeus output showing TGS ticket retrieval
  `[20260315_143022_kerberoast_ticket-request.png]`
- `RT-E002`: Screenshot — hashcat crack completion with recovered password
  `[20260315_145511_hashcat_svc-backup-cracked.png]`
- `RT-E003`: Screenshot — CrackMapExec confirming local admin on 14 systems
  `[20260315_150033_cme_svc-backup-auth.png]`

**Business Impact**

[2-3 sentences on real-world impact. Who or what is at risk. What an attacker could do with this access. Connect to business consequences: data breach, regulatory violation, financial loss, operational disruption.]

**Remediation**

Priority: **IMMEDIATE** — remediate within [7/30/90] days.

1. **[Specific action]**: [Exact steps to take. Not vague guidance — specific instructions.]
   - Example: "Reset svc_backup account password to a minimum 25-character random string generated by a password manager."
2. **[Specific action]**: [Steps.]
   - Example: "Implement Group Managed Service Accounts (gMSA) for all service accounts. gMSA passwords are 120 characters, auto-rotated by Active Directory, and cannot be extracted from memory."
3. **[Specific action]**: [Steps.]
   - Example: "Audit all accounts with ServicePrincipalNames: `Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName`. Remove SPNs from accounts that do not require them."
4. **Detection**: "Monitor for Windows Event ID 4769 (Kerberos Service Ticket Operations) with Encryption Type = 0x17 (RC4). This indicates Kerberoasting activity."

**References**

- [MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft Security Advisory on gMSA implementation]

---

## 5. Risk Register

```
ID      | Finding Title                        | Likelihood | Impact | Risk Score | Owner
--------|--------------------------------------|------------|--------|------------|----------
RT-F001 | [TITLE]                              | HIGH       | HIGH   | CRITICAL   | [TEAM]
RT-F002 | [TITLE]                              | MEDIUM     | HIGH   | HIGH       | [TEAM]
RT-F003 | [TITLE]                              | LOW        | MEDIUM | MEDIUM     | [TEAM]
RT-F004 | [TITLE]                              | LOW        | LOW    | LOW        | [TEAM]
```

Risk Score Matrix:

```
           Impact
           LOW     MEDIUM   HIGH
L  HIGH  | MEDIUM | HIGH   | CRITICAL
I MEDIUM | LOW    | MEDIUM | HIGH
K   LOW  | LOW    | LOW    | MEDIUM
E
L
I
H
O
O
D
```

---

## 6. Remediation Roadmap

### Immediate Actions (0–7 days)

Critical findings require immediate action regardless of change management cycles.

- [ ] [FINDING RT-F001]: [Specific immediate action — e.g., "Reset all identified Kerberoastable service account passwords"]
- [ ] [FINDING RT-F00X]: [Action]
- [ ] Revoke all access tokens and sessions for compromised accounts: [LIST]
- [ ] Review and terminate any suspicious active sessions in Azure AD / Okta

### Short-Term (8–30 days)

High severity findings with moderate remediation effort.

- [ ] [FINDING]: [Action] — Owner: [TEAM] — Target date: [DATE]
- [ ] [FINDING]: [Action] — Owner: [TEAM] — Target date: [DATE]
- [ ] Implement detection rules for observed attack techniques (see Section 4 individual findings)
- [ ] Conduct tabletop exercise for incident response to domain compromise scenario

### Medium-Term (31–90 days)

Medium severity findings and systemic improvements.

- [ ] [FINDING]: [Action]
- [ ] Review all Active Directory service accounts for SPN usage and password age
- [ ] Deploy privileged access workstations (PAWs) for all domain admin activities
- [ ] Implement network segmentation recommendations from Section [X]

### Long-Term (90+ days)

Strategic risk reduction programs.

- [ ] Deploy CyberArk / BeyondTrust PAM solution for privileged account lifecycle management
- [ ] Implement least-privilege group policy across workstation fleet
- [ ] Conduct purple team exercise to validate detection coverage against observed attack chain
- [ ] Annual red team engagement to measure remediation effectiveness

---

## 7. Appendices

### Appendix A — Methodology

The assessment followed the [PTES / MITRE ATT&CK / Custom] framework and covered the following phases:

1. **Reconnaissance** — Passive and active information gathering about the target environment
2. **Weaponization** — Development of attack tooling and payloads for target environment
3. **Initial Access** — Exploitation of identified vectors to gain a foothold
4. **Post-Exploitation** — Privilege escalation, lateral movement, persistence
5. **Objective Achievement** — Demonstrating access to defined target assets
6. **Reporting** — Documentation of findings and remediation recommendations
7. **Cleanup** — Removal of all artifacts, persistence, and modifications

MITRE ATT&CK techniques used: [List technique IDs — e.g., T1566.001, T1078, T1558.003]

### Appendix B — Tools Used

```
Tool              | Version | Purpose
------------------|---------|----------------------------------
Nmap              | 7.94    | Network scanning and service discovery
BloodHound        | 4.3     | Active Directory attack path analysis
Rubeus            | 2.3.2   | Kerberos ticket operations
Mimikatz          | 2.2.0   | Credential extraction
CrackMapExec      | 5.4.0   | Lateral movement and enumeration
Impacket          | 0.11.0  | Network protocol implementations
Cobalt Strike     | 4.9     | C2 framework
[TOOL]            | [VER]   | [PURPOSE]
```

### Appendix C — Evidence Log

```
Item ID | Date/Time (UTC)       | Type       | Description                        | File
--------|----------------------|------------|------------------------------------|------------------
RT-E001 | 2026-03-15 14:30:22  | Screenshot | Rubeus kerberoast ticket request    | rt-e001.png
RT-E002 | 2026-03-15 14:55:11  | Screenshot | hashcat cracked svc_backup hash     | rt-e002.png
RT-E003 | 2026-03-15 15:00:33  | Screenshot | CME local admin across network      | rt-e003.png
RT-E004 | 2026-03-16 09:12:04  | Log file   | Full BloodHound attack path export  | rt-e004.json
RT-E005 | 2026-03-16 11:44:17  | Screenshot | Objective 1 — data accessed         | rt-e005.png
[...]   | [...]                | [...]      | [...]                               | [...]
```

### Appendix D — Cleanup Log

All artifacts created during the assessment have been removed. The following table documents each item that was created and its removal confirmation.

```
Item                           | Created On  | Removed On  | Confirmed By
-------------------------------|-------------|-------------|---------------
Scheduled task on WORKSTATION-042 | 2026-03-16 | 2026-03-22 | [CONSULTANT]
Service binary on SERVER-DC01    | 2026-03-17 | 2026-03-22 | [CONSULTANT]
Registry run key on WORKSTATION-012 | 2026-03-18 | 2026-03-22 | [CONSULTANT]
AD service principal RT-BACKDOOR | 2026-03-19 | 2026-03-22 | [CONSULTANT]
Cobalt Strike beacon on 10.10.10.25 | 2026-03-20 | 2026-03-22 | [CONSULTANT]
```

**Cleanup Certification**: All artifacts have been removed as of [DATE]. Client IT security team confirmed removal via [METHOD — e.g., "EDR event log review"] on [DATE].

### Appendix E — Retest Guidance

The following findings are recommended for retest after remediation:

```
Finding    | Retest Method                                          | Expected Result
-----------|--------------------------------------------------------|------------------
RT-F001    | Repeat Kerberoast on same accounts after password reset | No weak hashes
RT-F002    | Attempt same privilege escalation path                 | Escalation blocked
RT-F003    | Re-run BloodHound, verify attack path removed           | Path broken
```

Retest should be scheduled approximately [30/60/90] days after remediation of each critical/high finding. [FIRM NAME] recommends requesting a formal retest engagement rather than client-side validation for critical findings.
