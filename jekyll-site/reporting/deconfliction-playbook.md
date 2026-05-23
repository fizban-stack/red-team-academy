---
layout: training-page
title: "Deconfliction Playbook — Red Team Academy"
module: "Reporting"
tags:
  - deconfliction
  - communications
  - ir
  - soc
  - legal
  - operational-comms
page_key: "reporting-deconfliction-playbook"
render_with_liquid: false
---

# Deconfliction Playbook

A red team that cannot deconflict in real time is a red team about to cause an incident. Deconfliction is the discipline of keeping the right people inside the customer informed without leaking the engagement to the people whose response you are trying to test. Done well, it preserves test fidelity and prevents real-IR-on-fake-attacker waste. Done badly, it ends with the SOC paging the FBI on a sanctioned engagement, the CEO finding out about the test from a news alert, or the legal team demanding the operator turn over disk images at 2am. Treat comms with the same rigor as your C2 stack — they fail the same way and they fail more often.

## The Three Audiences

Every person inside the customer org sits in one of three rings. Mapping people to rings before the engagement starts is non-negotiable — the worst comms failures happen when an operator assumes someone is in a ring they are not.

```
# Ring 1 — White Cell (knows everything)
#   Engagement lead / sponsor (the person who signed the SOW)
#   Trusted agent (their day-to-day delegate)
#   Scoping team (defined targets, ROE, crown jewels)
#   Procurement / legal counterparty (signed the MSA)
#   Up to ~5 people. Larger than this and the engagement leaks.

# Ring 2 — Trusted Control Group (knows test is happening, not specifics)
#   CISO (always, unless they are explicitly the target)
#   General Counsel / privileged attorney
#   Specific IT-ops leads if destructive actions are possible
#   CEO / CFO only if board-level exposure (TIBER, CBEST style)
#   They know the dates, not the TTPs. They get summary, not feed.

# Ring 3 — Operational Defenders (knows nothing, or partial)
#   SOC analysts, IR team, threat hunters
#   Network engineering, helpdesk, identity ops
#   This is the audience under test. Their unawareness is the product.
#   Some engagements brief them after the fact, some never.

# Anti-pattern: "telling just one more person on the IT team"
#   Every leak doubles. Confirmed compromise of the test happens
#   when a Ring 3 member is told to "just look the other way."
#   Refuse this. It ruins the engagement and exposes the customer to
#   insider-threat liability the next time that employee leaves.
```

A useful rule: if a person in Ring 1 or Ring 2 cannot be reached on a phone call within 30 minutes, they are functionally not in the ring. Reachability is the membership test, not job title.

## Daily Cadence

The single highest-ROI comms artefact in any engagement is the daily operator status to white cell. Skip it once and the engagement starts feeling opaque to the sponsor. Skip it twice and they assume you are not working.

```
# Recommended cadence:
#   - Daily status: end of operator day, 3-paragraph max written summary
#   - Weekly sync: 30-minute call, white cell + lead operator
#   - Ad-hoc: any time an action requires advance notice (defined below)

# What goes in the daily status:
#   Paragraph 1 — What happened today (actions taken, results)
#   Paragraph 2 — Where we are vs. plan (on track, blocked, pivoting)
#   Paragraph 3 — What is happening tomorrow (planned actions, asks)

# Quiet days matter as much as findings days.
# A "quiet day" report ("ran passive recon, no new access, continuing
# enumeration tomorrow") is critical — it tells the sponsor you are
# alive, working, and not sitting on something they should know about.

# The Friday-afternoon problem:
#   Do NOT drop new findings or new infrastructure into a Friday EOD
#   when the white cell is signing off for the weekend. Either:
#     - Deliver critical findings by Thursday EOD, OR
#     - Hold non-critical updates until Monday morning, AND
#   confirm weekend on-call coverage in writing before day 1.

# Time-zone rule:
#   The cadence runs on the customer's business clock, not yours.
#   If your team is in Europe and the customer is in PST, your
#   "EOD" is their lunchtime. Decide which clock the daily lives on
#   at kickoff and put it in the ROE annex.
```

## Real-Time Deconfliction Triggers

Real-time deconfliction is what you do when the daily cadence is too slow. Three trigger patterns matter, and they go in both directions.

```
# Trigger 1 — White cell calls you: "Is this you?"
#   Cause: SOC has detected something, escalated to CISO,
#   CISO is now on the phone trying to figure out if it is the test
#   or a real attacker before activating IR.
#
#   Response protocol:
#     1. Answer the phone. Always. Even if you are mid-action.
#     2. Have your operator log open before you confirm anything.
#     3. Quote back: timestamp, source IP, target host, action.
#     4. If it matches your log: "Yes, that is us, beacon ID X."
#     5. If it does not match: "Not us — recommend you treat as real."
#     6. Never answer "probably us" — it is yes or no, with evidence.
#
#   The white cell must be able to call you 24/7. A voicemail box
#   is not a deconfliction channel.

# Trigger 2 — You call them: advance notice
#   Required before:
#     - Any action against a system flagged "notify before touch" in ROE
#     - Any action that could plausibly cause downtime (mass auth, brute force)
#     - Any phishing send to executives or finance staff
#     - Any data access against a system holding regulated data (PHI, PCI)
#     - Any C2 channel change (new domain, new redirector)
#     - Any persistence mechanism that survives a reboot
#
#   Format: short email + phone follow-up. Email alone is not notice.
#   Wait for explicit acknowledgement before firing the action.

# Trigger 3 — Customer calls you: "We are about to do X"
#   They are about to take an action that would burn your access or
#   destroy your evidence. Examples:
#     - Forced password reset of an account you have
#     - Patching a server you have shelled
#     - Rebooting a host to apply a kernel update
#     - Decommissioning a system you are using as a pivot
#
#   Your job: tell them whether to proceed, pause, or coordinate.
#   This is NOT a request to block their normal operations. It is
#   information so they can decide. They decide, not you.
```

## Comms Channels

The customer's M365 tenant is the worst place to run the engagement comms. It is exactly the surface you are testing. Use it for nothing operational.

```
# Primary deconfliction channel:
#   Signal — group chat with white cell, disappearing messages OFF
#   (you need the record), screen lock enforced, no linked desktops
#   on shared workstations.
#
#   Why Signal: out-of-band from the customer's identity stack,
#   strong crypto, supports voice calls, available on operator phones.

# Secondary / formal channel:
#   Encrypted email (PGP or S/MIME) to a small, named list.
#   Use for: signed ROE addenda, formal scope changes, retention
#   notices, anything that must survive a Signal account loss.

# Forbidden channels (never use for engagement comms):
#   - Customer M365 / Google Workspace tenant
#   - Customer Slack / Teams
#   - Customer-issued laptops or phones
#   - Any tool that routes through customer SSO

# Channel hygiene:
#   - Rotate Signal group at the start of every engagement
#   - One group per engagement, never reuse across customers
#   - Operator phones are engagement-dedicated (no personal accounts)
#   - Phone lock screen blanks message previews
#   - Backups disabled on the operator phone (no iCloud / Google Drive)

# Recording and transcripts:
#   Voice calls: recorded with both-party consent stated at the top.
#   Store recordings encrypted, on engagement infra only, deleted at
#   engagement close + retention window (typically 30-90 days for
#   audit, longer if regulated).

# Channel-compromise plan:
#   Pre-arrange a fallback channel BEFORE the engagement starts:
#     - Phone number tree (printed, not stored in Signal)
#     - Out-of-band secondary email (personal-but-engagement-dedicated)
#     - Physical meeting location for in-person reset if channels burn
#
#   Test the fallback on day 1, not on the day you need it.
```

## Calling Off a Live Op

The hardest comms decision in a red team engagement is calling off an op in flight. Operators do not want to pause; sponsors do not want to admit something went wrong; everyone wants to keep going. The decision tree has to exist before the moment arrives.

```
# Triggers that should force a pause / abort discussion:
#   - Customer declares a real, unrelated security incident
#   - A major business event hits (M&A announcement, earnings)
#   - Customer executive event (CEO resignation, layoffs)
#   - Comms breakdown with white cell (> 8h no response, urgent need)
#   - Operator action caused unplanned downtime or data loss
#   - Real attacker discovered in the environment
#   - Legal counsel raises a privilege / disclosure concern

# Decision tree:
#
#   Pause vs. abort vs. continue covertly?
#
#   PAUSE if:
#     - Trigger is temporary (24-72h business event)
#     - Engagement state is preservable (access still warm)
#     - Both sides agree on resume conditions
#
#   ABORT if:
#     - Real attacker present (you exfil the env, period)
#     - Customer requests it (always, no debate)
#     - Operator action caused real damage
#     - Legal / regulatory issue surfaced
#
#   CONTINUE COVERTLY if:
#     - The disturbance is in Ring 3 and the white cell explicitly
#       wants you to keep going to test the response
#     - You can confirm in writing from Ring 1 that continuing is sanctioned
#     - You have NOT been instructed to pause

# Communicating the call-off:
#   1. Stop all operator actions immediately. Hands off keyboard.
#   2. Lead operator confirms with white cell on phone (not chat).
#   3. Send written confirmation: "All operator actions stopped at HH:MM UTC."
#   4. Document state: what access you have, where the implants are,
#      what the C2 looks like, what is persistent vs. ephemeral.
#   5. Decide jointly: keep access warm, or burn it down.

# Resuming a paused engagement:
#   - Verify the pause condition is fully resolved (in writing)
#   - Re-confirm ROE still applies (no scope drift)
#   - State-check every implant before resuming actions
#   - Re-establish daily cadence — do NOT pick up where you left off
```

## When Blue is Hunting You

The most interesting moment in a red team engagement is the moment the SOC pivots from baseline to hunting your activity specifically. Recognise it, slow down, and let the data accumulate.

```
# Detection signals — blue has noticed:
#   - Sudden network ACLs targeting your C2 IPs or domains
#   - Forced re-authentication of accounts you are using
#   - New EDR rules deployed mid-engagement (look for cloud-side push events)
#   - Honeypot / canary traffic touching your hosts
#   - Threat-hunt queries hitting indicators you generated
#   - SIEM correlation rules suddenly firing on your beacon timing

# Operator response when you notice you are being hunted:
#   1. Slow down. Beacon jitter up, sleep longer, fewer actions per hour.
#   2. Stop NEW infrastructure spin-up. Hold the existing footprint.
#   3. Surface to white cell: "Blue activity detected, slowing tempo."
#   4. Do NOT pivot to fresh infrastructure to evade — that is the test.
#   5. Document what triggered detection (this is gold for the report).

# The "let them catch you" play:
#   Sometimes the best engagement decision is to be detected on purpose.
#   You have the access. The remaining value is testing the IR loop.
#   Coordinate with white cell — burn a known TTP and time the response.
#
#   Outputs to capture:
#     - Time from action to alert in SIEM
#     - Time from alert to analyst eyes
#     - Time from analyst eyes to escalation
#     - Time from escalation to containment action
#     - What containment actually happened (host iso? account disable? net ACL?)

# The "quietly remediated" detection:
#   You lose access. There was no comms event. No alert you saw fired.
#   Possibilities:
#     - You were detected and remediated without your knowledge
#     - Routine ops killed your access (password rotation, patch, reboot)
#     - Your infrastructure failed (C2 server, redirector)
#
#   Investigate in this order: your infra -> your account -> host telemetry.
#   Do not assume detection. Do not assume routine. Confirm with white cell.
```

## Coordinating with Real IR

If a real incident lands during your engagement, the engagement is the second priority. The customer's actual security is the first.

```
# Procedure when a real incident appears:
#   1. Lead operator pauses all actions immediately.
#   2. Phone the white cell — voice, not chat. "Real incident suspected."
#   3. Surface ALL your activity to the white cell in a single dump:
#        - Every host you have touched
#        - Every account you are using
#        - Every persistence mechanism in place
#        - Every C2 channel and IP/domain
#        - Every implant location and timestamp
#   4. Make the dump structured — IR will diff it against their hunt.
#   5. Do not delete anything. IR may need your artefacts for triage.

# Why this matters:
#   Customer IR is going to be sifting through alerts trying to figure
#   out which are real and which are you. If you do not give them a
#   clean baseline, they will spend days chasing your TTPs instead of
#   the real adversary. That is a direct cost to the customer.

# Boundary — you do NOT assist with the real incident:
#   - You are an authorized adversary, not their IR team
#   - Helping pollutes your independence and complicates legal
#   - If they need IR help, they engage a separate IR firm
#   - Your job is to give them the clean baseline and then stand down

# When the engagement resumes (if it resumes):
#   - Wait for written all-clear from white cell + CISO
#   - Confirm IR is comfortable with you re-entering the env
#   - Re-baseline your access (some of it may have been remediated
#     as part of the real-incident response, intentionally or not)
```

## Working with Legal

Legal involvement protects everyone — the customer, the consultancy, and the individual operator. Bring legal in early or pay for it later.

```
# When privilege matters:
#   Engage customer's General Counsel (or outside privileged counsel)
#   BEFORE the engagement starts if any of these apply:
#     - The engagement may surface real wrongdoing (insider activity,
#       fraud, prior breach)
#     - Findings may be subpoenaed in ongoing litigation
#     - Customer is regulated (financial services, healthcare, defense)
#     - Cross-border data flows are involved
#
#   The framing: "Engagement performed at direction of counsel for
#   purposes of legal advice." This is the attorney-client framing.
#   It is not automatic. It has to be set up at the start, on paper.

# Evidence handling for engagements that may surface real wrongdoing:
#   - All artefacts stored encrypted on engagement infrastructure only
#   - Chain-of-custody log maintained from collection forward
#   - No artefacts on operator personal devices, ever
#   - Retention per legal hold, not per default consultancy policy

# Customer disclosure obligations — know them before you find them:
#   - GLBA / SEC for US financial services (4-day disclosure rules)
#   - HIPAA for healthcare (60-day breach notification)
#   - GDPR for EU PII (72-hour to authority)
#   - State breach laws (varies; California, New York, Massachusetts strict)
#
#   Your job is NOT to interpret these. Your job is to surface the
#   facts to customer legal in time for them to interpret and act.

# If you find a real prior breach during an authorized test:
#   1. Stop touching the artefact immediately. Do not enumerate further.
#   2. Phone white cell + customer legal counsel within the hour.
#   3. Preserve evidence in place — do not delete, do not move.
#   4. Document what you saw, when, and how you found it.
#   5. Hand off to customer IR / forensic firm.
#   6. Pause your engagement until written direction to resume.
#
#   Do not include the real breach in your engagement report unless
#   customer legal directs you to. They may want it in a separate doc.
```

## Working with Executive Sponsors

The CISO / CIO / sponsor is your direct contact, and managing their expectations is half the job. Executives respond to surprise badly.

```
# Mid-engagement updates to sponsor:
#   - Weekly written summary (1 page max, no jargon)
#   - Critical findings: immediate phone call, then written summary
#   - "We are quiet but on track" updates matter — silence reads as failure
#
#   Format:
#     - What we did this week (one paragraph, business language)
#     - What we found this week (high-level, no TTP details)
#     - Where we are vs. plan (on track / behind / pivoted)
#     - What we need from you this week (decisions, access, intros)

# Board-level briefings:
#   Avoid mid-engagement briefings to the board. The board panics,
#   the panic flows back down to operations, and the engagement
#   becomes about reassurance instead of testing.
#
#   Reserve board briefings for end-of-engagement, in joint format
#   with the CISO presenting alongside the lead operator.

# The "executive panic" cycle:
#   Trigger: a finding gets exposed to the executive too early or
#   without context. Executive demands immediate remediation.
#   Operators get pulled to support remediation instead of testing.
#   The engagement collapses into a fire drill.
#
#   Prevention:
#     - Brief the CISO on the finding first, in private
#     - Agree on the executive framing together
#     - Let the CISO carry the message up, not the operator
#     - Operators do not brief executives without the CISO present

# When the executive sponsor changes mid-engagement:
#   - Pause and re-establish ROE with the new sponsor in writing
#   - Re-confirm authorization (the old sponsor's signature may not bind the new one)
#   - Walk the new sponsor through what has happened so far
#   - Do not assume continuity. Confirm everything.
```

## Comms Failure Modes

Every comms failure pattern below has happened to working red team operators. Plan for them before they happen to you.

```
# Failure 1 — White cell goes silent
#   Cause: vacation, illness, personnel change, sponsor escalation elsewhere
#   Detection: > 8h no response to a non-urgent ping, > 1h to urgent
#   Mitigation:
#     - Pre-arranged backup contact in Ring 1 (named, on day-1 contact card)
#     - Fallback escalation to CISO directly if backup also silent
#     - Default action if no contact reachable: PAUSE, do not continue

# Failure 2 — Customer wants a 4h standing meeting daily
#   Cause: sponsor anxiety, lack of trust, prior bad engagement
#   Mitigation:
#     - Offer rich daily written + 30-min weekly sync as alternative
#     - Frame the cost: "Every hour in the meeting is an hour not testing"
#     - If they insist: comply, charge for it, note in lessons learned

# Failure 3 — Pre-arranged escalation list is stale on day 5
#   Cause: org changes, the named contact left the company
#   Detection: contact attempt rings unanswered or bounces
#   Mitigation:
#     - Validate every contact on day 1 with a "comms check" message
#     - Re-validate weekly during long engagements
#     - Keep a "contact obituary" in the engagement log

# Failure 4 — Engagement gets longer than planned, contacts rotate
#   Cause: scope expansion, vacation, project handoffs
#   Mitigation:
#     - Treat every contact change as a mini-kickoff
#     - Walk the new contact through scope, ROE, current state
#     - Do not assume the new contact inherits the prior trust posture

# Failure 5 — Channel itself gets compromised
#   Cause: operator phone lost, Signal account hijacked, email leaked
#   Detection: messages you did not send, login alerts from unknown IPs
#   Mitigation:
#     - Treat the channel as burned. Stop using it.
#     - Move to fallback channel established pre-engagement.
#     - Notify all parties via the fallback. Pause operations.
#     - Reset only after forensic confirmation of what leaked.
```

## Sample Comms Templates

These are starting points, not scripts. Adapt them to your engagement and customer. The shape is more important than the exact wording — short, dated, evidenced.

```
# Template 1 — Daily status (3 paragraphs max)

Subject: [Engagement Name] Daily Status — YYYY-MM-DD

Today we executed Phase 2 of the kill chain. Initial foothold from
the phishing campaign converted into Cobalt Strike beacon on
WKSTN-1042 at 14:22 UTC. Beacon stable, sleep 300s/30% jitter.
No detection events observed.

We are on track against the plan. Original target was domain
foothold by EOD Wednesday; we are now positioned to attempt
privilege escalation tomorrow morning. No blockers.

Tomorrow: privilege escalation via Kerberoasting against three
identified SPN accounts. If successful, lateral movement toward
the file server cluster. No actions planned that require
advance notice. Sign-off cadence resumes at 09:00 UTC.
```

```
# Template 2 — Urgent deconfliction request

Subject: URGENT — Deconfliction Request — [Engagement Name]

Phone call to follow within 5 minutes. Acknowledge receipt.

Action: Mass authentication attempt against OWA from infrastructure
192.0.2.45 starting at 16:00 UTC today.
Targets: 50 accounts, password-spray (one password, many users).
Risk: May trigger account lockouts. May generate SOC alerts.
Required by ROE: notify white cell, hold for explicit go-ahead.

Please confirm GO / NO-GO by 15:45 UTC.

Operator on standby: [Name], +1-555-0100, Signal verified.
```

```
# Template 3 — Mid-engagement abort

Subject: Engagement Pause — [Engagement Name] — Effective Immediately

All operator actions halted at HH:MM UTC.

Reason: [Real incident declared / Customer request / Operator action
caused unplanned downtime].

State preserved:
  - 3 active beacons (WKSTN-1042, FILE-SRV-01, DC-02)
  - 2 sets of valid credentials (1 service account, 1 user)
  - No persistence mechanisms deployed beyond beacon
  - C2 infrastructure remains active, no new connections

Next step: phone call within 30 minutes to determine
pause / abort / continue.

Lead operator: [Name], +1-555-0100
```

```
# Template 4 — Engagement-complete handoff

Subject: Engagement Closed — [Engagement Name] — Final State

All operator actions concluded at HH:MM UTC YYYY-MM-DD.

Cleanup status:
  [x] All implants removed (list attached)
  [x] All persistence mechanisms reverted (list attached)
  [x] All C2 infrastructure torn down
  [x] All credentials stored in encrypted archive (key with sponsor)
  [x] All test phishing accounts disabled / deleted

Artefacts retained per ROE:
  - Operator logs (encrypted, retention 90 days)
  - Screenshots and evidence files (encrypted, retention 90 days)
  - Final report draft (delivered separately by [date])

Verbal readout scheduled: [date/time]
Draft report delivery: [date]
Final report delivery: [date]

Thank you for the engagement. Please confirm receipt and acknowledge
that no further actions are expected from the operator team.
```

## Post-Engagement Comms

The engagement is not over when the last beacon dies. The comms cadence shifts but does not stop.

```
# Initial verbal readout — within 24h of operator close:
#   Audience: Ring 1 (white cell)
#   Format: 30-60 minute call
#   Content:
#     - High-level summary of what was achieved
#     - Top 3 findings by business impact
#     - Confirmation of cleanup status
#     - Preview of the draft report timeline
#   Why: lock in the narrative while it is fresh, before
#   internal politics start reshaping what the engagement "meant."

# Draft report cadence:
#   - Draft delivered within 5-10 business days of operator close
#   - Customer review window: 5 business days minimum
#   - Customer feedback consolidated, single revision pass
#   - Final report within 15-20 business days of operator close
#
#   Do not allow open-ended review cycles. Specify the window
#   in the SOW. Drift here is where engagements die in committee.

# Final report:
#   Two versions standard:
#     - Executive (5-10 pages, business language)
#     - Technical (full detail, evidence, remediation per finding)
#   Optional third:
#     - Regulator package if the engagement was TIBER / CBEST / DORA

# Lessons-learned session:
#   Run jointly with Ring 1 + Ring 3 (the SOC sees themselves now).
#   Format: 90 minutes, structured.
#     - Operator walkthrough of the attack path (no blame, no theatrics)
#     - Blue team walkthrough of what they saw, when, what they did
#     - Joint discussion: where defenses worked, where they did not
#     - Prioritized action plan with named owners and dates
#
#   This session is where the real value crystallizes. Skipping it
#   reduces a six-figure engagement to a PDF that nobody reads.

# Long-tail comms:
#   30-day check-in: how is remediation progressing?
#   60-day re-test offer: validate fixes on top findings
#   Quarterly metrics review: detection rate trend, MTTD trend
#   Schedule the next engagement based on what THIS engagement missed.
```

## Resources

- Red Team Operations Framework (deconfliction sections) — `github.com/V33RU/Red-Team-Operations-Framework`
- NIST SP 800-53 IR Family Controls — `csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search`
- NIST SP 800-115 Technical Guide to IS Testing — `csrc.nist.gov/pubs/sp/800/115/final`
- CREST Penetration Testing Guide — `crest-approved.org/buying-building-cyber-services/penetration-testing/`
- MITRE Engenuity Adversary Emulation Library — `github.com/center-for-threat-informed-defense/adversary_emulation_library`
- TIBER-EU Framework (intelligence-led red team) — `ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf`
- CBEST Intelligence-Led Testing — `bankofengland.co.uk/financial-stability/financial-sector-continuity`
- DORA Regulation (EU) 2022/2554 — `eur-lex.europa.eu/eli/reg/2022/2554/oj`
- Signal Messenger (recommended OOB channel) — `signal.org`
- Ghostwriter (engagement management) — `github.com/GhostManager/Ghostwriter`
- Related: [Red Team Operations Framework](/reporting/red-team-operations-framework/)
- Related: [Documenting Findings](/reporting/findings/)
