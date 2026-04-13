---
layout: training-page
title: "Exfil & Evidence Cheatsheet — Red Team Academy"
module: "Ops Cheatsheets"
tags:
  - cheatsheet
  - evidence
  - reporting
  - opsec
page_key: "cheatsheets-exfil-evidence"
render_with_liquid: false
updated: "2026-04-13"
---

# Exfil & Evidence Cheatsheet

Scope-safe habits for **what to move**, **how to log it**, and **what belongs in a report**. Not legal advice — follow your **RoE** and **local law**.

## Before you move data

- **RoE**: Is exfiltration explicitly allowed? Which asset classes?
- **Minimize**: Take the **smallest** artifact that proves impact (single row, config snippet, non-production sample).
- **Encrypt in transit** when required (engagement VPN, approved channels).

## Evidence bundle (typical)

| Artifact | Why |
|----------|-----|
| Dated command log | Reproducibility |
| Request/response (redacted) | For web/API issues |
| Screenshots with **visible clock** or terminal timestamp | Chain of events |
| File hashes (SHA-256) | Integrity |
| Scope statement excerpt | Shows authorization |

## What to avoid

- Copying **production PII** into personal notes or unapproved cloud.
- Storing **live credentials** in plaintext outside the engagement vault.
- **Unbounded** recursive dumps “just in case.”

## Reporting alignment

- Map findings to **MITRE ATT&CK** where it helps the blue team.
- Separate **technical impact** from **business impact** per your template.

## Resources

- [Documenting findings](/reporting/findings/)
- [Technical report](/reporting/technical-report/)
- [Data exfiltration](/post-exploitation/data-exfil/) — technique context (authorized use only)
