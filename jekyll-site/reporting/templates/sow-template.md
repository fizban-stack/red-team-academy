---
layout: training-page
title: "Statement of Work Template"
module: "Reporting"
page_key: "reporting-templates-sow"
render_with_liquid: false
updated: "2026-04-17"
---

# Statement of Work — Red Team Engagement

> **Disclaimer**: This template is provided for educational purposes. Have all legal agreements reviewed by qualified legal counsel before use in a real engagement. Laws governing cybersecurity testing vary by jurisdiction.

---

## STATEMENT OF WORK

**Agreement Reference**: SOW-[YEAR]-[CLIENT_CODE]-[SEQUENCE]
**Effective Date**: [DATE]
**Expiration Date**: [DATE]

---

## 1. Parties

**Service Provider**:
```
[FIRM NAME]
[ADDRESS LINE 1]
[CITY, STATE, ZIP]
[COUNTRY]
Authorized Representative: [NAME, TITLE]
Contact Email: [EMAIL]
Contact Phone: [PHONE]
```

**Client**:
```
[CLIENT ORGANIZATION LEGAL NAME]
[ADDRESS LINE 1]
[CITY, STATE, ZIP]
[COUNTRY]
Authorized Representative: [NAME, TITLE]
Contact Email: [EMAIL]
Contact Phone: [PHONE]
```

This Statement of Work is entered into pursuant to the Master Services Agreement (MSA) between [FIRM NAME] and [CLIENT NAME] dated [MSA DATE], or in the absence of an MSA, shall constitute the entire agreement between the parties for the services described herein.

---

## 2. Engagement Description

[FIRM NAME] will conduct a [ENGAGEMENT TYPE — e.g., "full-scope red team assessment / adversary simulation / assumed breach exercise"] for [CLIENT NAME] (hereinafter "Client"). The engagement will simulate a motivated, skilled adversary targeting [BRIEF DESCRIPTION — e.g., "the Client's corporate network infrastructure, cloud environments, and employees"] to identify security gaps before a real attacker can exploit them.

**Engagement Name**: [PROJECT NAME / CODE NAME]
**Engagement Type**: [Full Red Team / Assumed Breach / Purple Team / Social Engineering Only]
**Assessment Model**: [Black Box / Grey Box / White Box]

---

## 3. Scope

### 3.1 In-Scope Assets

The following systems, networks, and environments are authorized targets for this engagement:

**Network Infrastructure**:
```
IP Range / CIDR    | Description                    | Notes
-------------------|--------------------------------|---------------------------
[IP/CIDR]          | [Corporate LAN]                | [Full access authorized]
[IP/CIDR]          | [DMZ / Internet-facing]        | [External testing only]
[IP/CIDR]          | [Cloud VPC/VNet]               | [AWS Account: XXXXXXXXXXXX]
```

**Web Applications**:
```
URL / Domain                  | Application Name     | Auth Level
------------------------------|----------------------|-------------------
[https://app.targetcorp.com]  | [Customer Portal]    | [Unauthenticated + Authenticated]
[https://admin.targetcorp.com] | [Admin Interface]   | [Authenticated only]
```

**Microsoft 365 / Cloud Tenants**:
```
[targetcorp.onmicrosoft.com] — Microsoft 365 tenant
[AWS Account ID: XXXXXXXXXXXX] — Production AWS account
[Azure Tenant ID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX]
```

**Physical Locations** (if applicable):
```
[SITE NAME] — [Full Address] — [Scope Description]
```

**Personnel** (for social engineering scope, if applicable):
```
All employees of [CLIENT NAME] are in scope for phishing simulation.
Executive staff are in scope for voice phishing (vishing) simulation.
[SPECIFIC DEPARTMENTS] are in scope for physical social engineering.
```

### 3.2 Out-of-Scope Assets

The following are explicitly excluded from this engagement. Testing against out-of-scope systems is prohibited and may result in immediate engagement termination.

```
System / Range              | Reason
----------------------------|-----------------------------------------------
[IP/SYSTEM]                 | Production payment processing — PCI compliance
[IP/SYSTEM]                 | Third-party hosted — no authorization from vendor
[DOMAIN]                    | Subsidiary not covered by this authorization
[SYSTEM NAME]               | Safety-critical system — no disruption permitted
[EMPLOYEE NAME(S)]          | Executive leadership explicitly excluded
```

### 3.3 Destructive Testing Restrictions

The following actions are prohibited unless explicitly authorized in writing as an addendum to this SOW:

- [ ] Ransomware simulation or file encryption
- [ ] Deletion or permanent modification of production data
- [ ] Denial of service attacks against production systems
- [ ] Exfiltration of real customer PII, PCI, or HIPAA data off Client premises
- [ ] Physical damage to hardware or infrastructure
- [ ] Testing of safety-critical systems (power, water, building systems)
- [ ] Social engineering attacks against named individuals explicitly excluded

---

## 4. Objectives

The red team engagement will attempt to achieve the following client-defined objectives. Objectives are listed in priority order.

```
Priority | Objective                                           | Success Criteria
---------|-----------------------------------------------------|------------------
1        | [e.g., Gain domain administrator access]            | [AD Domain Admin group membership]
2        | [e.g., Access financial records on [SYSTEM]]        | [Screenshot of sensitive file contents]
3        | [e.g., Demonstrate persistence across password reset]| [Shell retained 24h after pwd reset]
4        | [e.g., Gain access to Azure cloud environment]       | [ARM token or cloud console access]
```

---

## 5. Methodology

The engagement will be conducted in accordance with industry-standard red team methodology, including but not limited to:

1. **Reconnaissance**: Passive and active intelligence gathering using publicly available information and authorized network scanning within scope.
2. **Initial Access**: Exploitation of identified vulnerabilities, misconfigurations, or human factors to obtain a foothold within the target environment.
3. **Post-Exploitation**: Privilege escalation, lateral movement, credential access, persistence, and advancement toward objectives.
4. **Objective Achievement**: Demonstration of access to defined target assets, capturing evidence of access without retaining actual sensitive data.
5. **Cleanup**: Removal of all tools, implants, persistence mechanisms, and modifications made during the engagement.
6. **Reporting**: Delivery of findings, recommendations, and remediation roadmap.

MITRE ATT&CK framework TTPs will be mapped to all attack techniques used. The threat actor profile to be simulated is: [DESCRIPTION — e.g., "a financially motivated threat actor consistent with FIN7 TTPs / an APT consistent with state-sponsored actor targeting critical infrastructure"].

---

## 6. Deliverables

| Deliverable | Description | Format | Delivery Date |
|-------------|-------------|--------|---------------|
| Rules of Engagement document | Finalized RoE prior to engagement start | PDF | [DATE] |
| Weekly status updates | Brief written update on progress | Email | [WEEKLY DATE] |
| Debrief presentation | Live walkthrough of findings | PowerPoint + Video call | [DATE] |
| Draft final report | Full written report for client review | PDF | [DATE] |
| Final report | Revised report incorporating client feedback | PDF | [DATE + 5 business days] |
| Remediation guidance session | 2-hour call to walk through remediation | Video call | [DATE] |
| Retest summary (if purchased) | Verification of critical finding remediation | PDF | [DATE] |

---

## 7. Timeline

```
Phase                          | Start Date  | End Date    | Duration
-------------------------------|-------------|-------------|----------
Kickoff & RoE Finalization     | [DATE]      | [DATE]      | [N] days
External Reconnaissance        | [DATE]      | [DATE]      | [N] days
Active Testing                 | [DATE]      | [DATE]      | [N] weeks
Cleanup & Evidence Collection  | [DATE]      | [DATE]      | [N] days
Report Writing                 | [DATE]      | [DATE]      | [N] days
Draft Report Delivery          | [DATE]      | [DATE]      | —
Client Review Period           | [DATE]      | [DATE]      | [N] days
Final Report Delivery          | [DATE]      | [DATE]      | —
Remediation Session            | [DATE]      | [DATE]      | 2 hours
```

**Engagement Window**: Active testing will be conducted between [START DATE] and [END DATE]. Testing hours are [HOURS — e.g., "24/7 unrestricted" or "Monday–Friday 0800–1800 [TIMEZONE]"].

---

## 8. Fees and Payment

**Total Engagement Fee**: $[AMOUNT]

```
Breakdown:
  Red team operators ([N] consultants × [N] weeks)  $ [AMOUNT]
  Travel and expenses (estimated)                   $ [AMOUNT]
  Report writing and deliverables                   $ [AMOUNT]
  Retest (if applicable)                            $ [AMOUNT]
  ────────────────────────────────────────────────────────────
  Total                                             $ [AMOUNT]
```

**Payment Schedule**:
- 50% due upon execution of this SOW: $[AMOUNT] — due [DATE]
- 50% due upon delivery of draft report: $[AMOUNT] — due [DATE]

**Expenses**: Travel, accommodation, and per diem expenses for on-site activities will be billed at cost with prior written approval for individual expenses exceeding $[AMOUNT]. Estimated travel budget: $[AMOUNT].

**Out-of-Scope Work**: Any work outside the defined scope requires a written Change Order executed by both parties before commencing. Change Orders will include revised fees and timeline impacts.

---

## 9. Confidentiality

Both parties agree to maintain the confidentiality of all information shared during the engagement. [FIRM NAME] will not disclose Client information, systems, vulnerabilities, or findings to any third party without written authorization from Client.

Deliverables containing findings are classified [CONFIDENTIAL — CLIENT EYES ONLY] and must be protected accordingly by Client. Physical copies must be stored securely. Electronic copies must be protected with appropriate access controls.

[FIRM NAME] may retain anonymized, non-client-identifiable statistics and general techniques for internal training purposes only.

All personnel assigned to this engagement will execute individual Non-Disclosure Agreements prior to engagement start, copies of which will be provided to Client upon request.

---

## 10. Liability Limitations

**Limitation of Liability**: [FIRM NAME]'s total liability for any claim arising out of or related to this engagement, whether in contract, tort, or otherwise, shall not exceed the total fees paid by Client under this SOW.

**Indemnification**: Client shall indemnify and hold [FIRM NAME] harmless from any claims, damages, or losses arising from (a) Client's failure to properly authorize this engagement with all relevant system owners, (b) Client's failure to notify [FIRM NAME] of out-of-scope systems prior to engagement start, or (c) any disruption caused by Client's failure to follow agreed emergency stop procedures.

**Service Availability**: [FIRM NAME] will use reasonable care to avoid disruption of Client systems. Client acknowledges that penetration testing inherently carries a risk of unintended system behavior and accepts this risk by executing this SOW. [FIRM NAME] will immediately notify Client and cease testing if any unintended disruption occurs.

**Force Majeure**: Neither party shall be liable for delays caused by circumstances beyond their reasonable control.

---

## 11. Emergency Contacts

In the event of an unintended system disruption, potential security incident triggered by testing activity, or any situation requiring immediate escalation, the following contacts will be used:

**Client Emergency Contacts**:
```
Name:    [PRIMARY CONTACT NAME]
Title:   [TITLE — e.g., CISO / IT Director]
Phone:   [MOBILE — available 24/7 during engagement]
Email:   [EMAIL]

Name:    [SECONDARY CONTACT NAME]
Title:   [TITLE]
Phone:   [MOBILE]
Email:   [EMAIL]
```

**[FIRM NAME] Engagement Contacts**:
```
Engagement Lead: [NAME]
Phone:   [MOBILE — 24/7 during engagement]
Email:   [EMAIL]

Operations Lead: [NAME]
Phone:   [MOBILE]
```

**Stop-Work Trigger**: Either party may invoke an immediate engagement pause by contacting the above contacts. [FIRM NAME] will cease all testing activity within [15/30] minutes of receiving a stop-work notification.

---

## 12. Authorization and Signatures

By executing this Statement of Work, the undersigned confirm they have authority to authorize this security assessment on behalf of their respective organizations and agree to all terms herein.

**[CLIENT ORGANIZATION NAME]**:

```
Signature:  ________________________________
Name:       [PRINTED NAME]
Title:      [TITLE]
Date:       [DATE]
```

**[FIRM NAME]**:

```
Signature:  ________________________________
Name:       [PRINTED NAME]
Title:      [TITLE]
Date:       [DATE]
```
