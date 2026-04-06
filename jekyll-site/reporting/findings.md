---
layout: training-page
title: "Documenting Findings — Red Team Academy"
module: "Reporting"
tags:
  - findings
  - cvss
  - evidence
  - documentation
page_key: "reporting-findings"
render_with_liquid: false
---

# Documenting Findings

## Overview

A red team engagement is only as valuable as its documentation. The findings you produce are the client's primary deliverable — they drive remediation, inform leadership decisions, and justify the engagement cost. Sloppy documentation wastes the technical work you did. This page covers finding structure, CVSS scoring, evidence capture, and the notetaking workflow that makes reporting faster after the engagement ends.

![Finding structure with six required components: title with CVSS severity, executive summary, technical detail, evidence (screenshots/requests), impact assessment, and remediation with priority and retest requirement](/images/reporting/finding-structure.svg)  
*// finding structure — six required components for a complete finding*

## Finding Structure

Every finding needs six components. Missing any of them forces the client to follow up, delays remediation, and undermines credibility.

```
># Standard finding components:

1. TITLE
   Short, specific, action-oriented.
   Bad:  "SQL Injection"
   Good: "SQL Injection in Login Form Allows Authentication Bypass"

2. SEVERITY
   Critical / High / Medium / Low / Informational
   Derived from CVSS score or business impact judgment.

3. CVSS SCORE + VECTOR STRING
   Use CVSS v3.1. Include the full vector string.
   Example: 9.8 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

4. DESCRIPTION
   What the vulnerability is, where it exists, and why it matters.
   One paragraph. Non-technical language. No jargon without definition.

5. EVIDENCE
   Proof of exploitation: screenshots, command output, timestamps.
   Must be reproducible from the evidence — reviewer should be able to
   follow your steps and get the same result.

6. REMEDIATION
   Specific, actionable fix. Not "apply patches" — "apply patch KB5028168
   for CVE-2023-28229, which addresses this specific vulnerability."
   Include a remediation priority: immediate / short-term / long-term.
```

## CVSS v3.1 Scoring

CVSS (Common Vulnerability Scoring System) v3.1 provides a standardized 0–10 score based on attack vector, complexity, required privileges, user interaction, scope, and CIA impact. Learn the base metric groups — you'll score findings mentally before calculating formally.

```
># CVSS v3.1 Base Metrics:

# Attack Vector (AV):
#   N = Network    (exploitable remotely, highest severity modifier)
#   A = Adjacent   (requires access to local network segment)
#   L = Local      (requires local system access)
#   P = Physical   (requires physical contact)

# Attack Complexity (AC):
#   L = Low    (no special conditions, repeatable)
#   H = High   (requires specific, non-default conditions)

# Privileges Required (PR):
#   N = None       (unauthenticated)
#   L = Low        (regular user account)
#   H = High       (admin / elevated privileges required)

# User Interaction (UI):
#   N = None       (exploitable without victim action)
#   R = Required   (victim must take an action — click link, open file)

# Scope (S):
#   U = Unchanged  (impact limited to vulnerable component)
#   C = Changed    (impact extends to other components)

# Confidentiality / Integrity / Availability (C/I/A):
#   H = High    (complete loss of CIA for affected component)
#   L = Low     (partial loss)
#   N = None    (no impact)

# Common vector string examples:
# Unauthenticated RCE over network:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 CRITICAL

# SQLi requiring auth, network-accessible:
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N → 8.1 HIGH

# Stored XSS requiring user interaction:
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N → 5.4 MEDIUM

# Local privesc requiring local access:
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H → 7.8 HIGH

# Information disclosure, no CIA impact:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 MEDIUM

# Use the NVD calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
```

## CVSS 4.0 — What Changed

CVSS 4.0 was released in November 2023 and introduces a restructured metric set. Industry adoption is gradual — most clients and vulnerability management platforms still default to CVSS 3.1 as of 2025, but awareness of 4.0 is expected. When reporting, match what your client's platform supports; include both vectors when possible.

```
# CVSS 4.0 key changes from v3.1:

# New metric groups:
# Base (required) + Threat (replaces Temporal) + Environmental + Supplemental

# Attack Complexity split into two metrics:
# AC = Attack Complexity (L/H — same as before)
# AT = Attack Requirements (N/P — new: does attack need specific pre-conditions?)

# Scope replaced by separate Vulnerable/Subsequent system impact:
# VC/VI/VA = impact on the vulnerable component
# SC/SI/SA = impact on subsequent components (was "Changed Scope")

# CVSS 4.0 vector format:
# CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N → 9.3 CRITICAL

# Common v3.1 → 4.0 mapping:
# Unauthenticated RCE, no scope change:
#   v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
#   v4.0: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N → 9.3

# Scoring tools:
# CVSS 4.0 calculator: https://www.first.org/cvss/calculator/4.0
# CVSS 3.1 calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

# Practical guidance:
# - Default to CVSS 3.1 unless client specifically requires 4.0
# - Include both vectors in reports for forward compatibility
# - CVSS 4.0 Threat score (E metric: A/P/U) replaces Temporal Exploitability
```

## Severity Classification

CVSS provides a score — severity classification adds business context. Apply these thresholds as starting points, then adjust based on the specific environment and impact.

```
># Severity bands (CVSS v3.1 base score):
# Critical   9.0 – 10.0   Immediate remediation required. Likely exploitable by automated tools.
# High       7.0 – 8.9    Exploitable with moderate skill. Significant business risk.
# Medium     4.0 – 6.9    Requires some context or privileges. Real risk, scheduled remediation.
# Low        0.1 – 3.9    Limited impact or difficult exploitation path.
# Info       0.0          No direct vulnerability — noteworthy configuration or practice.

# When to override CVSS with higher severity:
# - Finding leads directly to domain compromise (always Critical, regardless of CVSS)
# - Finding exposes PII/PCI/HIPAA-regulated data
# - Finding affects production safety systems
# - Finding is trivially exploitable despite low CVSS (AC:H might be AC:L in this env)

# When to override with lower severity:
# - Compensating controls significantly reduce real-world exploitability
# - Affected component is isolated / decommissioned
# - Risk accepted by client in writing
```

## Evidence Capture — What to Record and When

Capture evidence at the moment of exploitation — you cannot always reproduce it cleanly later. Timestamps matter for chain-of-custody and timeline reconstruction.

```
># What to capture for every finding:

Screenshot requirements:
- Full terminal window (not cropped) — shows full command + output
- URL bar visible for web findings — confirms the target host
- Timestamp visible (terminal PS1 with date, or system clock in corner)
- Username/hostname visible — confirms you ran this on the right target

Command output:
- Save raw terminal output: script -a /tmp/engagement_$(date +%Y%m%d).log
  # 'script' records everything to a file; stop with exit
- Redirect tool output: tool 2>&1 | tee /tmp/tool_output.txt
- For Windows: Invoke-Command ... | Out-File C:\log.txt -Append

Timestamps — record these for every critical step:
- Initial access time
- Privilege escalation time
- Domain compromise time
- Each lateral movement hop
- Data access time (what data, on which system)

# Naming convention for screenshots:
# YYYYMMDD_HHMMSS_finding-title_step-description.png
# Example: 20260327_143022_sqli-auth-bypass_admin-login.png
```

## Notetaking During Engagements

Good notes during the engagement cut reporting time in half. The goal is to capture enough detail that someone who wasn't on the engagement can reproduce every step from your notes alone.

```
># Recommended notetaking structure per finding:

## Finding: [Title]
Date/Time: 2026-03-27 14:30:22 UTC
Target: 192.168.1.50 (web01.corp.internal)
Port/Service: 443/HTTPS — Login page at /admin/login

### Steps to Reproduce:
1. Navigate to https://web01.corp.internal/admin/login
2. Enter username: admin' -- -
3. Enter password: anything
4. Click Login

### Evidence:
- Screenshot: 20260327_143022_sqli-auth-bypass_login.png
- Command output in: /tmp/sqlmap_output.txt

### Impact:
Unauthenticated access to admin panel. Tested: viewed user list (/admin/users).
Did NOT: modify data, create accounts, or access customer records.

### Recommended Fix:
Parameterized queries for all login form inputs.
Reference: OWASP SQL Injection Prevention Cheat Sheet.

# Tools for structured notes:
# - Obsidian (Markdown, local files, good for red team notes)
# - CherryTree (hierarchical, local)
# - Ghostwriter (open-source report management tool)
# - Plextrac (commercial engagement management platform)
```

## Example Finding — Complete

A fully written finding ready for inclusion in a report.

```
># ─────────────────────────────────────────────────────────────
# FINDING: Kerberoastable Service Accounts Allow Offline
#          Password Cracking Leading to Domain Escalation
# ─────────────────────────────────────────────────────────────

Severity:   HIGH
CVSS Score: 7.5
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

Description:
  Three domain service accounts are configured with SPNs
  (ServicePrincipalNames) and use weak passwords. Any
  authenticated domain user can request Kerberos TGS tickets
  for these accounts, export the encrypted ticket material,
  and perform offline password cracking without generating
  alerts on the domain controller. During testing, the
  svc_backup account password was cracked in under 4 minutes
  using a standard wordlist. This account has local
  administrator rights on 12 workstations and read access
  to the backup share containing configuration files with
  additional embedded credentials.

Affected Accounts:
  - svc_backup   (cracked: Summer2024!)
  - svc_scanner  (crack in progress, not included in scope)
  - svc_deploy

Evidence:
  1. Kerberoast tickets requested via Rubeus:
     Rubeus.exe kerberoast /outfile:hashes.txt
     [Screenshot: 20260327_143022_kerberoast_ticket-request.png]

  2. hashcat crack of svc_backup hash:
     hashcat -m 13100 hashes.txt rockyou.txt
     [Output: 20260327_145511_hashcat_svc-backup-cracked.txt]

  3. Authentication with cracked credentials confirmed:
     crackmapexec smb 10.10.10.0/24 -u svc_backup -p 'Summer2024!'
     [Screenshot: 20260327_150033_cme_svc-backup-auth.png]

Remediation:
  1. Immediate: Reset svc_backup password to 25+ character random string.
  2. Short-term: Implement managed service accounts (gMSA) for all
     service accounts — passwords auto-rotated by AD, 120 chars.
  3. Short-term: Audit all accounts with SPNs; remove SPNs from
     accounts that don't require them.
  4. Long-term: Monitor for TGS requests using Windows Event ID 4769
     (Kerberos Service Ticket Operations) with RC4 encryption type.
```
