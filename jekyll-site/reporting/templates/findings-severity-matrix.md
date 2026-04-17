---
layout: training-page
title: "Findings Severity Matrix"
module: "Reporting"
page_key: "reporting-templates-severity"
render_with_liquid: false
updated: "2026-04-17"
---

# Findings Severity Matrix and Scoring Guide

## Overview

Consistent severity scoring makes reports credible, comparable across engagements, and useful for client prioritization. This guide covers CVSS v3.1 scoring mechanics, severity tier definitions, business impact modifiers, a reference table of common finding types with pre-assigned CVSS base ranges, and a remediation priority matrix.

Use CVSS v3.1 as the primary scoring baseline. Apply business impact modifiers based on the sensitivity of the affected system. Document the full CVSS vector string in every finding.

---

## CVSS v3.1 Base Metrics — Complete Reference

```
# CVSS v3.1 Base Score = f(AV, AC, PR, UI, S, C, I, A)
# Score range: 0.0 – 10.0
# Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

# EXPLOITABILITY METRICS

# AV — Attack Vector
# Measures how remote an attacker needs to be to exploit the vulnerability.
#
#   N = Network      (0.85) — Exploitable remotely over the internet / network
#                             No physical proximity or local access required
#                             Example: vulnerable web app, open port exploit
#
#   A = Adjacent     (0.62) — Requires access to the same local network segment
#                             Example: ARP spoofing, local broadcast attack
#                             Not directly reachable from the internet
#
#   L = Local        (0.55) — Requires local system access (RDP, SSH, console)
#                             Typically needs OS login or physical access to terminal
#                             Example: local privilege escalation, SUID binary
#
#   P = Physical     (0.20) — Requires physical contact with the device
#                             Example: USB drop attack, hardware tampering, cold boot

# AC — Attack Complexity
# How much of the attack is outside the attacker's control?
#
#   L = Low          (0.77) — No special conditions; attack is repeatable
#                             Attacker can perform it reliably at will
#                             Example: SQL injection in login form
#
#   H = High         (0.44) — Requires race condition, specific config, or
#                             prior preparation; not reliably repeatable
#                             Example: race condition exploit, MitM timing attack

# PR — Privileges Required
# What level of access does the attacker need BEFORE exploiting?
#
#   N = None         (0.85) — No account needed; unauthenticated
#   L = Low          (0.62) — Standard user account (non-privileged)
#   H = High         (0.27) — Admin or elevated privileges required

# UI — User Interaction
# Does exploitation require a victim to take an action?
#
#   N = None         (0.85) — No action required from a third party
#   R = Required     (0.62) — Victim must click link, open file, visit page

# S — Scope
# Does the vulnerability allow impact beyond the vulnerable component?
#
#   U = Unchanged    — Impact limited to the vulnerable component
#   C = Changed      — Impact extends to other components or systems
#                      Example: XSS compromising another user's session

# C/I/A — Confidentiality / Integrity / Availability Impact
#   N = None    (0.00) — No impact
#   L = Low     (0.22) — Partial or limited impact
#   H = High    (0.56) — Complete loss of CIA for the affected component

# Common vector examples:
# Unauthenticated RCE over network:
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL

# Authenticated SQLi, network-accessible:
# CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 HIGH

# Stored XSS requiring user interaction:
# CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 MEDIUM

# Local privesc requiring local access:
# CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 HIGH
```

---

## Severity Tier Definitions

```
# CRITICAL  (CVSS 9.0 – 10.0)
#
# Characteristics:
# - Exploitable remotely, no authentication, no user interaction
# - Or: directly leads to complete system/domain compromise
# - Automated exploitation tools exist (Metasploit module, public PoC)
#
# Business Impact:
# - Immediate risk of unauthorized data access or system takeover
# - Likely reportable under breach notification laws if exploited
# - Can result in complete operational disruption
#
# Response Requirement:
# EMERGENCY — Remediate immediately. Do not wait for change windows.
# Escalate to CISO and executive leadership.
#
# Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL

# HIGH  (CVSS 7.0 – 8.9)
#
# Characteristics:
# - Exploitable by an attacker with moderate skill
# - May require authentication or specific conditions, but conditions are common
# - Often a significant stepping stone to full compromise
#
# Business Impact:
# - Significant risk of unauthorized access to sensitive data or systems
# - Likely to be exploited in the wild if not patched
#
# Response Requirement:
# URGENT — Remediate within 14-30 days. Next emergency change window.
#
# Example: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 HIGH

# MEDIUM  (CVSS 4.0 – 6.9)
#
# Characteristics:
# - Requires specific conditions, user interaction, or existing access
# - Limited impact in isolation but may combine with other findings
#
# Business Impact:
# - May expose sensitive information with significant effort
# - Could contribute to a larger attack chain
#
# Response Requirement:
# SCHEDULED — Remediate within 30-90 days in standard change management cycle.
#
# Example: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 MEDIUM

# LOW  (CVSS 0.1 – 3.9)
#
# Characteristics:
# - Difficult to exploit or very limited impact
# - May require physical access, high complexity, or very specific conditions
#
# Business Impact:
# - Minimal direct risk; may provide marginal intelligence to an attacker
#
# Response Requirement:
# PLANNED — Address in next scheduled maintenance cycle (90+ days).
#
# Example: CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 1.8 LOW

# INFORMATIONAL  (No CVSS — 0.0)
#
# Characteristics:
# - Not a vulnerability in the traditional sense
# - Noteworthy configuration, practice, or observation
# - Security hygiene recommendations, policy observations
#
# Examples:
# - Verbose error messages revealing software versions
# - HTTP security headers not set (without exploitable consequences)
# - Weak TLS cipher suites without exploitable path
# - Outdated software with no known CVEs
#
# Response Requirement:
# DISCRETIONARY — Address when convenient or as part of broader hardening.
```

---

## Business Impact Modifiers

Apply these modifiers AFTER computing the base CVSS score. These adjust the reported severity tier upward to reflect real-world risk in the client's specific environment.

```
# Modifier 1: Payment System / PCI-DSS Scope
# Any finding in a system handling payment card data gets +1 severity tier
# Rationale: PCI-DSS violations carry direct financial penalties
# Example: Medium (5.5) finding on payment server -> report as HIGH

# Modifier 2: Authentication / Identity Infrastructure
# Findings in login systems, identity providers (AD, Okta, Azure AD, SSO) get +1 tier
# Rationale: compromise of auth systems amplifies to all connected applications
# Example: High (7.5) finding on AD DC -> report as CRITICAL

# Modifier 3: Administrative Interfaces
# Findings in management panels, admin APIs, backup systems get +1 tier
# Rationale: admin access converts to full system control
# Example: Medium (5.8) IDOR on admin panel -> report as HIGH

# Modifier 4: Regulatory Data (HIPAA, GDPR, etc.)
# Findings affecting systems holding regulated personal data get +1 tier
# Example: Low (3.2) information disclosure on HIPAA-covered system -> MEDIUM

# Modifier 5: Combined / Chained Findings
# If individual findings combine to produce a higher-impact attack path:
# - Document the chain
# - Score the chain as a single finding at the chain's combined impact level
# Example: SSRF (Medium 5.3) + IMDS access (Medium 4.8) = Chained Path: HIGH

# Modifier 6: Active Exploitation in Wild
# If a public exploit or active exploitation is confirmed for a specific CVE:
# Increase by +1 tier regardless of CVSS
# Example: CVSS 6.8 Medium with known Metasploit module -> report as HIGH

# Modifier Table:
# Context                          | Modifier
# ---------------------------------|----------
# Payment / PCI-DSS system         | +1 tier
# Authentication / identity system | +1 tier
# Admin / management interface     | +1 tier
# HIPAA / GDPR data system         | +1 tier
# Active exploitation in wild      | +1 tier
# Isolated / non-production system | -1 tier (with justification)
# Multiple compensating controls   | -1 tier (document controls explicitly)
```

---

## Common Finding Types — CVSS Base Ranges

The following table provides pre-assigned CVSS base score ranges for 30 common red team findings. These are starting points — adjust individual metrics based on observed exploitation conditions.

| # | Finding Type | CVSS Range | Typical Severity | Notes |
|---|-------------|------------|-----------------|-------|
| 1 | Unauthenticated RCE (network) | 9.0–10.0 | Critical | Baseline critical |
| 2 | Authenticated RCE (web app) | 7.5–9.0 | High–Critical | Scope affects score |
| 3 | SQL Injection (auth bypass) | 8.0–9.8 | Critical | Adjust PR if auth needed |
| 4 | SQL Injection (data extraction) | 7.0–8.5 | High | |
| 5 | Stored XSS | 5.4–7.5 | Medium–High | S:C if steals admin session |
| 6 | Reflected XSS | 4.8–6.1 | Medium | Lower without S:C |
| 7 | SSRF (internal access) | 7.5–9.3 | High–Critical | IMDS access = Critical |
| 8 | XXE (file read) | 7.5–9.1 | High–Critical | |
| 9 | Path Traversal | 5.3–8.6 | Medium–High | Depends on files readable |
| 10 | Insecure Deserialization (RCE) | 9.0–10.0 | Critical | RCE context |
| 11 | IDOR (access own data) | 4.3–6.5 | Medium | |
| 12 | IDOR (access all user data) | 7.5–8.1 | High | |
| 13 | Broken Authentication | 7.0–9.0 | High–Critical | Depends on bypass method |
| 14 | JWT None Algorithm | 7.5–9.3 | High–Critical | Full auth bypass |
| 15 | Kerberoasting | 7.0–8.0 | High | Adjust for crack likelihood |
| 16 | AS-REP Roasting | 7.0–8.0 | High | No auth required |
| 17 | Pass-the-Hash | 7.8–9.3 | High–Critical | Scope depends on target |
| 18 | DCSync (Domain Admin) | 9.0–10.0 | Critical | Full domain compromise |
| 19 | LSASS Credential Dump | 7.0–8.5 | High | Local, but high impact |
| 20 | Local Privilege Escalation | 7.0–8.8 | High | |
| 21 | DLL Hijacking (writable path) | 7.3–8.8 | High | |
| 22 | Hardcoded Credentials (app) | 7.0–8.5 | High | AV depends on access |
| 23 | Default Credentials (service) | 8.0–9.8 | High–Critical | Depends on service |
| 24 | Open S3 Bucket / Cloud Storage | 5.3–9.8 | Medium–Critical | Score per data sensitivity |
| 25 | Cloud IMDS Token Theft | 8.0–9.3 | High–Critical | Escalates via MSI |
| 26 | Subdomain Takeover | 5.3–8.2 | Medium–High | UI:N if fully automatic |
| 27 | Phishing — Credential Harvest | 6.5–8.0 | High | High with 2FA bypass |
| 28 | Exposed Admin Interface (no auth) | 8.0–9.8 | High–Critical | Per what admin can do |
| 29 | Missing Patch / Known CVE | Varies | Per CVE | Use NVD CVSS as baseline |
| 30 | IDOR — Admin Function Access | 8.0–9.0 | High–Critical | Admin escalation |

---

## Remediation Priority Matrix

After CVSS scoring and business impact modifiers, assign a remediation priority that accounts for both risk level and implementation effort.

```
# Effort levels:
# LOW    — Configuration change, one-line fix, applying a patch
#           Hours to 1-2 days
#           Examples: rotate credential, disable feature, add header, apply patch
#
# MEDIUM — Code change, policy update, process change
#           Typically 1-2 week development cycle
#           Examples: refactor auth module, implement parameterized queries,
#                     deploy new GPO, migrate service to gMSA
#
# HIGH   — Architectural change, multi-team coordination
#           Typically weeks to months
#           Examples: redesign authentication architecture, segment network,
#                     implement PAM solution, re-architect legacy application

# Priority Matrix:
# Severity \ Effort |  LOW  |  MEDIUM  |  HIGH
# ------------------|-------|----------|-------
# CRITICAL          |  P0   |    P1    |   P1
# HIGH              |  P1   |    P1    |   P2
# MEDIUM            |  P2   |    P2    |   P3
# LOW               |  P3   |    P3    |   P4
# INFO              |  P4   |    P4    |   P4

# Priority definitions:
# P0 — EMERGENCY: Fix immediately. Break change freeze if necessary.
#                 Escalate to CISO, brief executive team.
#
# P1 — URGENT: Fix within 14-30 days. Next emergency change window.
#              Dedicated remediation owner assigned with deadline.
#
# P2 — SCHEDULED: Fix within 30-90 days. Standard change management.
#                 Include in sprint planning.
#
# P3 — PLANNED: Fix in next scheduled maintenance cycle (90-180 days).
#               Include in roadmap / backlog.
#
# P4 — DISCRETIONARY: Fix when convenient. No fixed deadline.
#                     Document acceptance of residual risk if not fixed.
```

---

## Scoring Worked Examples

```
# Example 1: Unauthenticated SQL Injection in Login Form
# - AV:N (internet-accessible web app)
# - AC:L (reliable, no special conditions)
# - PR:N (unauthenticated)
# - UI:N (no victim interaction needed)
# - S:U (impact to database only)
# - C:H (full database read access)
# - I:H (can modify or delete records)
# - A:N (no direct availability impact)
#
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 CRITICAL
# Business modifier: affects authentication system -> already Critical
# Effort: LOW (parameterized queries, quick code fix)
# Priority: P0 — EMERGENCY

# Example 2: Stored XSS in User Profile (Admin Views Profiles)
# - AV:N, AC:L, PR:L, UI:R, S:C, C:L, I:L, A:N
# CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 MEDIUM
# Business modifier: admin panel -> HIGH after modifier
# Effort: MEDIUM (output encoding in template layer)
# Priority: P1 — URGENT

# Example 3: Local Privilege Escalation via DLL Hijacking
# - AV:L, AC:L, PR:L, UI:N, S:U, C:H, I:H, A:H
# CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 HIGH
# No business modifier needed for standard workstation
# Effort: LOW (fix directory permissions, remove writable path)
# Priority: P1 — URGENT

# Example 4: Open AWS S3 Bucket Exposing Application Logs
# - AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:N, A:N
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 HIGH
# If logs contain auth tokens -> bump to CRITICAL
# Effort: LOW (enable bucket ACL, remove public access)
# Priority: P0/P1 depending on data sensitivity
```
