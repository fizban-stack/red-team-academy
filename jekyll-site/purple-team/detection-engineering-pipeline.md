---
layout: training-page
title: "Detection Engineering Pipeline — Red Team Academy"
module: "Purple Team"
tags:
  - detection-engineering
  - sigma
  - siem
  - false-positives
  - rule-lifecycle
page_key: "purple-detection-engineering-pipeline"
render_with_liquid: false
---

# Detection Engineering Pipeline

Detection engineering is a software discipline. Rules are code, alerts are output, and the SOC is the production environment. The teams that catch sophisticated attackers do not write "smart" Sigma — they run a pipeline that ingests threat intel, ships rules through validation, deploys in stages, tunes from telemetry, and retires what no longer matches reality.

For operators, the pipeline is a map. The rules that catch you live at specific stages of maturity. Stage-1 rules (status: experimental) miss almost everything and produce noise. Stage-5 rules (status: stable, owned, tuned) are the ones with names and dashboards behind them. If you understand where a detection sits in its lifecycle, you understand whether deviating from a known TTP buys you a week of free movement or trips an alert in 90 seconds.

This page documents the six-stage lifecycle most mature shops actually run, the metrics that govern rule quality, the anti-patterns that quietly kill detection programs, and where red team output plugs into the input side of the pipeline.

## Lifecycle Overview

Six stages, sequential, with explicit gates:

```
[1] Threat Research  ->  [2] Rule Authoring  ->  [3] Validation
                                                       |
                                                       v
[6] Retirement  <-  [5] Tuning  <-  [4] Staged Deploy
```

| # | Stage | Owner | Exit Gate |
|---|-------|-------|-----------|
| 1 | Threat Research | CTI / Red Team / IR | Documented requirement w/ ATT&CK mapping |
| 2 | Rule Authoring | Detection Engineer | Sigma + backend translations + test cases |
| 3 | Validation | Detection Engineer + Purple | TP fires, FP rate <5%, time-to-fire <5min |
| 4 | Staged Deploy | DE + SOC Lead | Audit-mode volume measured for 2-4 weeks |
| 5 | Tuning | DE + SOC Analysts | FP rate <1%, owner assigned, runbook linked |
| 6 | Retirement | DE Lead | No matches in 6mo OR TTP obsolete OR superseded |

## Stage 1 — Threat Research

The input. A detection requirement does not start with "let's write a rule for T1003.001" — it starts with a specific behavior that someone has demonstrated is achievable in your environment.

Inputs that matter:

- **CTI feeds** — Mandiant, CrowdStrike, Recorded Future, ETPro. Filter ruthlessly. Most CTI is marketing.
- **Public IR reports** — DFIR Report, Mandiant M-Trends, Microsoft DART blogs. These describe real intrusions with timestamps, commands, and artifacts.
- **Red team findings** — internal team or contracted. Highest signal-to-noise because the attacks ran in your network against your controls.
- **Vendor advisories** — CVE-tied detections, often with proof-of-concept code already public.
- **Internal hunt findings** — when a hunter finds something via ad-hoc query that nobody alerted on, that hunt query is a detection requirement.

Output of Stage 1 is a single document per requirement:

```
Requirement: DR-2026-0142
Behavior: NTLM relay to LDAP via PetitPotam coercion
ATT&CK: T1557.001 + T1187
Source: Red team report 2026-03, page 14
Telemetry: Sysmon 3, 4624 Logon, Domain Controller security log
Hypothesis: Outbound SMB from non-server -> any DC, followed by
            4624 LogonType 3 from same source IP within 60s
Priority: high (used in last engagement, no current coverage)
```

This document is the contract. Stages 2-5 execute against it.

## Stage 2 — Rule Authoring

Sigma is the source-of-truth format. Write the rule in Sigma YAML, then translate to your SIEM backends via `sigma-cli`. Do not author native SPL/KQL by hand as the primary artifact — you lose portability and the rule becomes invisible to your peers.

Three rule archetypes, each with different authoring discipline:

**Signature rules** — match a specific string, hash, or known-bad value. Cheap to write, brittle to evasion. A rule for `mimikatz.exe` filename matches 0% of real intrusions.

**Behavior rules** — match a sequence or property that the technique requires regardless of tooling. Example: any process accessing LSASS handle with `0x1010` access mask from a non-allowlisted source. This is where the value lives.

**Anomaly rules** — match statistical deviation from a baseline. Example: a host making >5x its 30-day average DNS queries to a single domain. Powerful but requires platform support (Splunk MLTK, Elastic ML, Sentinel UEBA) and a stable baseline.

For each requirement, author:

1. The Sigma YAML (canonical)
2. Test cases (TP events, FP events)
3. Translations: `sigma convert -t splunk -p sysmon` and `sigma convert -t elasticsearch -p ecs_windows`
4. Documentation: ATT&CK mapping, prerequisite telemetry, expected volume, runbook link

## Stage 3 — Validation

A rule that has never fired against real telemetry is not a rule, it is a hypothesis. Validation is the gate between "I wrote something" and "it works."

The Atomic Red Team execution loop:

```
# Find tests for the technique
Invoke-AtomicTest T1003.001 -ShowDetails

# Pre-check: is telemetry collecting?
Invoke-AtomicTest T1003.001 -CheckPrereqs

# Run the test in your validation environment
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Confirm rule fired
# Splunk: index=alerts rule_name="LSASS_Memory_Access" earliest=-15m
# Elastic: search alerts index for rule.id within 15m window
```

Validation metrics that matter:

| Metric | Target | What it means |
|--------|--------|---------------|
| TP rate | 100% across known tests | Rule fires on every Atomic Red Team variant of the technique |
| FP rate | <5% in first 7 days | Acceptable for a new rule; tightens in Stage 5 |
| Time-to-fire | <5 min from event to alert | Beyond 5 min the attacker is past the action you'd take |
| Coverage | All known tool variants | Mimikatz, ProcDump, Nanodump, comsvcs.dll, direct syscalls |

Use Caldera for chained adversary emulation when you need to validate that a sequence of rules fires in the right order — an initial access rule, an LSASS rule, and a lateral movement rule all firing and correlating inside the same incident.

## Stage 4 — Staged Deploy

Never push a new rule directly to alert/block. The audit-mode pipeline:

```
Week 1-2:  Deploy in shadow/audit mode. Rule runs, results go to a
           detection-engineering index. No alert. No SOC ticket.
           Measure: events/day, hosts/day, top firing sources.

Week 3:    Review with SOC lead. Is the volume sustainable?
           Are the matches the right kind of matches?
           If yes -> promote to alert. If no -> back to Stage 2.

Week 4+:   Live alerting. SOC sees the rule for the first time.
           Time-to-triage measured from this point.
```

Documentation requirements before promotion:

- Owner: a named human, not a team alias
- Runbook: linked, with TP/FP triage steps and explicit "this is what to do next"
- ATT&CK mapping: technique + sub-technique IDs
- Expected volume: events/day at p95
- Suppression policy: what known-good exceptions exist, where they live

## Stage 5 — Tuning

This is where most detection programs die. A rule that fires 200 times a day gets ignored. A rule that requires the SOC to remember "ignore matches from host SRV-BUILD-42" gets ignored. Tuning is the gardening that keeps the signal alive.

The FP triage workflow:

```
FP reported -> Is it actually an FP? (50% of "FPs" are real, just misunderstood)
            -> Yes -> Is the pattern reproducible?
                   -> Yes -> Can the rule logic distinguish TP from FP?
                          -> Yes -> Rewrite the rule.
                          -> No  -> Add a narrow suppression (allowlist).
                   -> No  -> Mark as one-off, do not tune yet.
            -> No  -> Educate the analyst, link the runbook.
```

Anti-patterns to refuse:

- **Broad exceptions** — `NOT process.name:*service*` excludes 40% of Windows. Never use a wildcard exception that you cannot articulate the scope of.
- **Per-host exceptions** — `NOT host.name:(SRV-01 OR SRV-02 OR SRV-03 OR ...)`. If the list grows past 5, the rule logic is wrong.
- **Suppression in place of fix** — if the rule fires on a legitimate behavior that occurs 20x/day, the rule is mis-scoped. Rewrite, do not suppress.
- **Tuning by analyst** — analysts close tickets, they do not modify rules. All tuning goes through the detection engineer who owns the rule.

Suppression vs rewrite decision rule: if you can name the legitimate pattern in one sentence and it is genuinely narrow, suppress. If you cannot, the rule is wrong.

## Stage 6 — Retirement

Rules accumulate. Tooling changes, environment changes, the attacker stops using the technique, the underlying log source gets replaced. A retirement review every quarter prevents the rule library from becoming a graveyard.

Retire when:

- No matches (TP or FP) for 6+ months
- Underlying TTP is obsolete (rules for SMBv1-only behaviors after SMBv1 is disabled)
- Vendor product change broke the telemetry the rule depends on
- A newer rule supersedes it with better fidelity
- The owner left the org and nobody adopted the rule

Document retirement, do not just delete. Keep the YAML in an `archived/` directory with a tombstone comment explaining why. Future detection engineers will look for the rule when the technique resurfaces.

## Rule Quality Metrics

Track these per-rule, monthly:

| Metric | Definition | Healthy Range |
|--------|------------|---------------|
| Precision | TP / (TP + FP) | >0.95 for stable rules |
| Recall | TP / (TP + missed attacks) | Measured via purple team |
| Volume/day | Total alerts per day | <10 for high-severity rules |
| Time-to-fire | Event timestamp -> alert timestamp | <5 min |
| Time-to-triage | Alert -> analyst acknowledgement | <30 min for critical |
| Time-to-action | Triage -> containment | <2 hours for critical |
| Ownership | Named human owner | 100% of rules; null owner = retire |

Volume/day is the most common warning sign. A high-severity rule firing >50 times/day is broken — either the rule logic is wrong or it should be a medium-severity informational.

## Anti-Patterns

The five patterns that kill detection programs in slow motion:

**Detection-coverage theater.** "We have 1,400 rules covering 312 ATT&CK techniques." Coverage by count is meaningless. The question is: how many of those rules would fire if a real intrusion happened today? In most environments the honest answer is 50-100.

**Rules nobody trusts.** When SOC analysts routinely close a rule's alerts as "false positive — known issue," the rule is dead but still firing. Either fix it or retire it. A noisy rule degrades the signal of every other rule next to it.

**Broad exceptions that swallow the technique.** A rule that detects LSASS access but excludes "any process under Program Files" excludes Mimikatz dropped to `C:\Program Files\WindowsUpdate\m.exe`. Exceptions must be narrower than the technique they exempt.

**Per-host exceptions as architecture.** Maintaining a list of 80 hosts that are "allowed" to do the detected behavior is not tuning, it is admitting the rule is mis-scoped. Either rebuild the rule around what makes those hosts different, or accept that those hosts are out of scope.

**Rules nobody owns.** When the author leaves and nobody picks up the rule, every FP triage becomes archaeology. Quarterly ownership review. Null-owner rules go to a managed list with a 90-day retirement clock.

## Sigma Examples with FP Notes

Three rules at the level of fidelity Stage 5 expects. The full Sigma library is in `purple-team/sigma-rules`; these are abbreviated and annotated for pipeline context.

**LSASS Handle Access — high-fidelity behavioral rule.**

```yaml
title: Suspicious LSASS Process Memory Access
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x1fffff'
  filter_legitimate:
    SourceImage|endswith:
      - '\wmiprvse.exe'
      - '\taskmgr.exe'
      - '\procexp64.exe'
      - '\MsMpEng.exe'
  condition: selection and not filter_legitimate
level: high
```

FP-tuning consideration: the `filter_legitimate` list is curated per environment. Do not add entries by Image path alone — combine with `SourceImage|endswith` AND signer name where the platform exposes it. EDR vendors update their internal process names; the list needs a quarterly review.

**Suspicious WINWORD Child Process — initial-access classic.**

```yaml
title: Office Application Spawning Script Interpreter
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
  condition: selection
level: high
```

FP-tuning consideration: macro-enabled spreadsheets in finance teams legitimately spawn `cmd.exe` for ETL workflows. Do not suppress at the parent level. Add a `CommandLine|contains` filter on the known ETL invocation strings, scoped by `User.Department` or host group. This pushes the FP-handling burden into a narrow allowlist that finance owns.

**Encoded PowerShell — execution signal.**

```yaml
title: PowerShell Encoded Command Execution
logsource:
  product: windows
  category: ps_script_block
detection:
  encoded_args:
    ScriptBlockText|contains:
      - '-EncodedCommand'
      - '-enc '
      - ' -ec '
  download_cradle:
    ScriptBlockText|contains:
      - 'DownloadString'
      - 'Net.WebClient'
      - 'Invoke-WebRequest'
  condition: encoded_args or download_cradle
level: medium
```

FP-tuning consideration: legitimate scheduled tasks and Configuration Manager packages use `-EncodedCommand` for argument escaping, not for evasion. Promote to high only when correlated with another signal in the same session (LSASS access, lateral logon, suspicious child process). On its own, this is a hunting query, not a page-the-on-call alert.

## Tools

- **Sigma + sigma-cli** — canonical detection language and converter
- **Uncoder.io** — web-based Sigma converter for quick translations
- **Atomic Red Team** — per-technique test scripts for validation
- **Caldera** — chained adversary emulation for sequence validation
- **DeepBlueCLI** — Windows event log triage and detection prototyping
- **Sentinel content hub** — Microsoft's curated KQL detection packs
- **Splunk Security Essentials** — Splunk's detection catalog with use cases
- **Elastic Security Detection Engine** — Elastic's prebuilt and custom rule platform
- **Detection-as-code repos** — `palantir/alerting-detection-strategy-framework`, `elastic/detection-rules`, `splunk/security_content`

## Integration with Red Team

The cleanest input to detection engineering is a red team report. The integration model that works:

1. **Red team engagement closes** with a TTP inventory: technique, ATT&CK ID, tooling, observed indicators, telemetry available.
2. **Purple team review** within 2 weeks: walk the TTPs, score current coverage (alerted / hunted / missed), file detection requirements for misses.
3. **Replay scripts** as deliverables: every TTP gets an Atomic Red Team test or a custom Caldera ability so it can be re-run during validation.
4. **Coverage report** to leadership: before-engagement coverage % vs after-engagement coverage % per ATT&CK tactic.
5. **Quarterly review**: re-run the replay scripts against current rules. Did the rules that were added still fire? Did anything regress? Did vendor changes break telemetry?

This loop is what makes red teaming actually pay back. A red team that finds gaps but produces no replayable artifacts has done half the job.

## Resources

- SigmaHQ — `github.com/SigmaHQ/sigma`
- MITRE ATT&CK Detection Engineering — `attack.mitre.org/resources/engage-with-attack/`
- Palantir Alerting & Detection Strategy Framework — `github.com/palantir/alerting-detection-strategy-framework`
- Elastic Detection Rules — `github.com/elastic/detection-rules`
- Splunk Security Content — `github.com/splunk/security_content`
- Atomic Red Team — `github.com/redcanaryco/atomic-red-team`
- Caldera — `github.com/mitre/caldera`
- SANS SEC555: SIEM with Tactical Analytics
- SANS SEC588: Cloud Penetration Testing (cloud detection coverage)
- The DFIR Report — `thedfirreport.com` (real intrusions, real TTPs)
