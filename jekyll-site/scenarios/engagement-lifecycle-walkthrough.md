---
layout: training-page
title: "Engagement Lifecycle Walkthrough — End-to-End — Red Team Academy"
module: "Scenarios"
tags:
  - engagement-lifecycle
  - walkthrough
  - end-to-end
  - junior-operator
  - educational
page_key: "scenarios-engagement-lifecycle-walkthrough"
render_with_liquid: false
---

# Engagement Lifecycle Walkthrough

This page walks a junior operator through a fictional but realistic red team engagement from the first scoping email to the final debrief deck. The technical content is illustrative, not weaponizable — the point is the *shape* of the engagement, the artifacts produced at each phase, and the decisions a team makes. Read it once cover-to-cover, then come back to each phase against the day you are actually on in your next engagement.

## Cast

- **MeridianCo** — fictional customer. ~600-person logistics SaaS, AWS-hosted product, Azure AD federated to an on-prem AD forest left over from a 2022 acquisition. 6-person security team. The board asked for "an outside test" after the customer base picked up two Fortune 500 logos and the questionnaire load tripled.
- **Verityon** — fictional red team consultancy. Six full-time operators, two engagement managers, one contracts attorney on retainer. Boutique; the partner does not take work the team cannot do well.
- **Sam** — Verityon engagement lead. Eight years offense, two as a defender first. Writes the SOW and ROE personally on every engagement.
- **Avery** — junior operator. Two years in, recently OSCP, first time as named operator on the wire. Paired with Sam for the duration.
- **Devon** — MeridianCo CISO and signing authority. Career infrastructure person; has read a lot of red team reports but has never been on the receiving end of one.
- **Priya** — MeridianCo SOC manager. The white-cell point of contact. Her team of three analysts is not told the test is happening until the debrief.

"Day 1" below is the official engagement start. Days before that are negative.

## Day -45: Initial Scoping Email

The engagement starts the way most engagements start: a polite, vague, slightly anxious email. Devon writes at 9:47 AM on a Tuesday.

```
From:    devon.mcgrath@meridianco.example
To:      contact@verityon.example
Subject: Red team engagement inquiry

I'm the CISO at MeridianCo. Our board has asked us to commission an
external red team test before our next compliance cycle. We've never
run one before. Our security questionnaire load has gotten heavy
since we landed a couple of larger customers and we want to answer
the "have you been tested by an external team" question honestly.

Can we get on a call to talk about scope and timing? I'd like to
have the test wrapped before our Q3 board meeting in October.
```

Two hundred words, no specifics, three concepts blurred together. A junior operator might reply with a service menu and pricing sheet. The senior move is the opposite. Sam writes back the same afternoon:

```
Devon —

Before we talk pricing or timing, I'd like to understand what your
board is actually asking for. "An external red team test" can mean
five different things and they cost very different amounts of money:

  1. Is the goal evidence for a regulator, the board, a customer
     questionnaire, or your own team's roadmap? Pick one.
  2. Is there a specific question you want answered? "Can an
     external attacker reach customer data?" is a very different
     scope than "How does our SOC perform under attack?"
  3. Are there systems that absolutely must not be touched?
  4. Who at MeridianCo has authority to sign that the testing is
     authorized — over which assets?
```

Sam refused to scope from an empty prompt. Four questions whose answers will collectively determine whether this is a 60-hour purple team, a 200-hour external-to-objective, or a 400-hour adversary emulation. He named the signing-authority question early because that one kills more engagements than any other.

## Day -30: Scoping Call (Annotated)

Two-hour call. Devon, his head of platform engineering Marco, and Priya on the customer side. Sam alone on the Verityon side. Edited transcript with operator-side annotations.

```
DEVON:  We've never done this. What does this look like?

SAM:    First we decide what question you want answered. If you
        got a single report from us in eight weeks, what would you
        most want it to say?

        [Reframing from "what activity will you do" to "what
        outcome do you want." Activity-driven scopes produce
        useless reports.]

DEVON:  Whether a real attacker could get to our customers'
        shipping data.

SAM:    Marco, where does customer shipping data physically live?

MARCO:  Production AWS account, us-west-2 — RDS Postgres cluster
        and an S3 bucket "meridian-prod-shipments." Read-replicated
        to us-east-2.

SAM:    So the crown jewel target is read access to either the S3
        bucket or the RDS cluster. Either is a win for us, either
        is a loss for you. Agreed?

        [Crown-jewel definition is now precise and falsifiable.
        We are not testing "AWS security." We are testing whether
        a specific bucket or cluster can be reached.]

DEVON:  Agreed.

SAM:    Do you have signing authority over the production AWS
        account, the Azure AD tenant, and the on-prem AD forest
        in your Atlanta office?

DEVON:  First two yes. Atlanta AD — that's from the DataLink
        acquisition. I'd want our GC to confirm.

SAM:    Then Atlanta AD is out-of-scope until your GC puts the
        authorization in writing.

        [Most important moment of the call. Sam refused to assume
        authority that wasn't confirmed. If Verityon had touched
        Atlanta AD and DataLink turned out to be a separate legal
        entity, every captured byte would be evidence of
        unauthorized access.]

SAM:    Phishing — yes, no, targeted at whom?

DEVON:  Yes, but not the executive team. No layoff pretexts. No
        COVID. No fake regulatory notices.

SAM:    Approved-targets list by Day -20. Vishing — help-desk
        impersonation?

DEVON:  Yes, but don't push the help desk into actually resetting
        a real password. Test them, don't blame them.

SAM:    The call gets made, we measure how far it gets, we stop at
        the point of escalation.

        ["Test the control, don't break the human" is a quiet
        ethical principle.]

PRIYA:  My SOC team — three analysts. Are they going to know?

SAM:    Up to you. Standard answer is no, until the debrief. You
        and Devon know, and we have a deconfliction channel.

PRIYA:  Don't tell them.

SAM:    Stop-work. If anyone on your side types PALMETTO STOP in
        Signal, all activity stops within fifteen minutes.
```

The call runs another forty minutes on hours, comms cadence, evidence retention, and reporting deadlines. Sam takes notes himself and converts them into a draft SOW and ROE that night.

## Day -25: Statement of Work and ROE

The SOW is six pages. The ROE is four. Verityon's contracts attorney reviews both before they go back. Excerpts with operator-side annotations.

```
SOW — Excerpt: Objectives and Success Criteria

2.1 Primary Objective. Determine whether an external attacker
    starting from public information only can obtain read access to:
      (a) the S3 bucket "meridian-prod-shipments"; OR
      (b) the RDS Postgres cluster "meridian-prod-rds."

2.3 Success Criteria.
      (a) Primary Objective "met" if operator demonstrates
          authenticated read of any in-scope object.
      (b) "Not met but documented" if operator documents a
          credible attack path with named remaining blockers
          and a confidence rating.
      (c) Failure to meet (a) or (b) is itself a finding and
          must be characterized in the report as such.

      [Note 2.3(c). A red team that "fails to compromise" is
      not a successful defense — it might mean the test was too
      short, the scope too narrow, or the operator unlucky. The
      report must say so honestly. Some firms quietly omit this.]
```

```
SOW — Excerpt: Out-of-Scope Assets

3.1 The following are explicitly out of scope:
    (a) Any system operated by or on behalf of DataLink, Inc.,
        pending written GC authorization.
    (b) Production payroll, HR, or benefits systems including
        any system processing GDPR-regulated PII.
    (c) Customer-side systems.
    (d) Personal devices or accounts of any employee not on
        the Approved Phishing Targets List.
    (e) Executive workstations and C-suite accounts.

3.2 If any out-of-scope system is reached inadvertently, the
    operator shall: (i) cease activity immediately, (ii) notify
    the deconfliction POC within four hours, (iii) document.

    [3.2 is the clause that saves careers. Operators sometimes
    land on a system they did not intend to touch. The clause
    makes the response procedure contractual rather than ad hoc.]
```

```
ROE — Excerpt: Operational Mechanics

4.1 Testing window: 0700–2200 Pacific, Mon–Fri, excluding
    Federal holidays and the customer-designated blackout window.

4.3 Deconfliction.
    (b) If SOC pivots to operator activity: Priya notifies Sam in
        MERIDIAN-RT with the investigation identifier. Sam confirms
        or denies attribution. Priya decides whether to redirect
        the analyst.
    (c) If operator observes evidence of a non-Verityon intrusion:
        operator pauses within fifteen minutes and notifies Priya
        and Devon. Operator does not assist or interfere; this is
        now the customer's incident response.

    [4.3(c) is the one nobody thinks about until it happens. It
    happens more often than you think. Your job in that moment
    is to get out of the way and tell the customer.]

4.4 Stop-Work Codeword. "PALMETTO STOP" in MERIDIAN-RT pauses
    all operator activity within fifteen minutes and remains in
    effect until released by Devon McGrath in writing.

4.5 Evidence Handling.
    (a) Operator shall not exfiltrate actual customer PII.
    (b) Customer will plant canary documents in scoped data
        stores. Operator may exfiltrate canaries as proof.
    (c) All credentials and tokens captured shall be destroyed
        within 90 days of report delivery.
```

Devon signs the SOW and the authorization letter on Day -22. The DataLink authorization comes through from GC on Day -18, confirming MeridianCo wholly owns the Atlanta AD forest. Sam moves Atlanta AD into scope and notes the date in the engagement log.

## Day -10: Lab Setup and Tradecraft Preparation

Avery joins the engagement. Her first week is pre-flight. Nothing she does this week touches MeridianCo.

```
DAY -10 — Lab setup checklist:

[X] Engagement-isolated VPS for C2 and redirector tier
    (terraform module — see /infrastructure/terraform-redirector-stack)
[X] Engagement-specific domains for phishing and C2 (registered
    30+ days ago — domain aging matters)
[X] Evidence-encrypted volume on operator workstations
[X] Signal group MERIDIAN-RT membership verified against ROE
[X] Phishing infrastructure (Postfix, DKIM/SPF/DMARC, authenticated
    against the registrar)
[X] Pre-staged landing pages — verified in Outlook for Web and
    Outlook desktop
[X] Baseline of MeridianCo's external posture so we can distinguish
    our activity from background noise
```

Avery's first real task is pretext development. She drafts three concepts for Sam to review.

```
A — "Vendor security questionnaire"
    From a fictitious procurement coordinator at a fictitious
    vendor the marketing team has interacted with. HTML attachment
    masquerading as a SecurityScorecard form. Targets: marketing.

B — "Shared shipment review document"
    From a spoofed external collaborator at one of MeridianCo's
    published customer accounts. Docusign-themed credential
    capture. Targets: customer success and account management.

C — "Internal IT password notification"
    From a spoofed internal address. M365 credential capture.
    Targets: general population.
```

Sam pushes back on C. "We have a phishing engagement to run, not a phishing service. Concept C is the kind of thing every commodity phisher in the world sends. If we send it and it works, we've learned nothing the customer didn't already know. Concept B is more interesting — it tests whether the customer success team can tell a real customer from a spoof, which is a real business question."

Junior operators reach for the easy lure. Seniors reach for the lure that produces actionable information regardless of outcome. B becomes primary, A becomes secondary.

On Day -8 the white-cell briefing happens. Devon, Priya, Sam, and Avery on a call. Sam walks through techniques by phase, C2 infrastructure (so Priya can recognize Verityon traffic in network logs), cleanup procedure, contingency if any implant fails to deactivate, and the exact wording of PALMETTO STOP. Priya makes one quiet but important request: "If you compromise a SOC analyst's account, tell me before you use it. They are my team." Sam writes it into the engagement log.

## Day 1: Engagement Kickoff

Officially starts at 0700 Pacific, Monday morning.

```
0900 daily standup — MERIDIAN-RT Signal channel:

SAM:    Standing up the engagement. Today and tomorrow are passive
        recon — no traffic to MeridianCo infrastructure beyond what
        a normal internet user would generate. Active reconnaissance
        and phishing begin Wednesday.

DEVON:  No blockers. Good luck.

PRIYA:  SOC is staffed normally. We have not told them.
```

Avery's first action is OSINT, following a written runbook: certificate transparency, passive DNS, LinkedIn enumeration of Customer Success / Account Management / Marketing, recent case studies (named customers, named technologies — feeding Pretext B), job postings (technology stack disclosure), breach data lookups for @meridianco.example addresses, sender reputation check on the phishing sending domain.

End of day: a 22-person target spreadsheet, nine recent published customer case studies (any of which is a candidate for Pretext B), and an annotated organization chart. Sam reviews it that evening and removes three names. "These three are in the C-suite per the ROE — they're out of scope. The fourth is married to the CTO; I don't want her in scope, drama is bad for the engagement." This kind of judgment call is not in the SOW. It is the senior operator deciding what is in the spirit of the engagement rather than the letter of it.

## Days 1–7: Reconnaissance and Initial Access

By end of Day 3, active recon is complete. Email format confirmed (firstname.lastname@meridianco.example). All 22 targets validated as current employees. Phishing launches Day 4 at 1000 Pacific, timed to land mid-morning when targets are at their desks and have not yet built decision fatigue.

```
Day 4 — Phishing campaign launch:

Targets:    14 (down from 22 — Sam pruned ineligible names)
Pretext:    B — customer-themed Docusign share
Sending:    legitimate-procurement.example (registered Day -45,
            warmed since Day -30)
Landing:    M365 credential capture, branded to match the real
            M365 sign-in page
Layer:      AitM — captured credentials forwarded to real M365
            sign-in, resulting session cookie also captured,
            bypassing MFA push-prompt protection
First click:    1014 Pacific (14 minutes after delivery)
First capture:  1019 Pacific
By EOD:         5 of 14 clicked, 3 entered credentials, 2
                completed full MFA-sealed session capture
```

Two valid session tokens, three credential pairs. Avery is briefly elated. Sam reminds her: "The point isn't that we won this round. The point is that the customer needs to know exactly how their controls performed at each step. We won't report this as 'phishing succeeded.' We'll report which control failed at which moment, with timestamps."

Friday Day 5 standup:

```
SAM:    Initial access achieved. Two session tokens via AitM. We
        have not yet used them. We will begin using one on Monday
        for tenant reconnaissance. The other is held in reserve.

PRIYA:  SOC has not pivoted to any phishing-related activity as of
        this morning. No tickets opened. No analyst looking at it.

        [This is itself a finding. The landing-page traffic, the
        credential capture, the AitM session — all of it should
        have been visible to the SOC. None pivoted into an
        investigation.]
```

## Days 8–14: Foothold and Discovery

Monday Day 8. Avery uses the first captured session token to authenticate to M365 as Jordan Watts, MeridianCo customer success engineer. She is now reading Jordan's email, Teams chats, OneDrive, and SharePoint — but only those. The token does not by itself grant access to AWS production.

The first hour inside Jordan's account is the most dangerous moment of the engagement so far. Every click and every Microsoft Graph API call is logged. If MeridianCo has the right Defender for Cloud Apps tuning, Avery is detected.

```
DAY 8 — Inside-the-tenant discovery (token #1):

Slow enumeration of Jordan's mail, Teams channels, OneDrive,
and accessible SharePoint sites.

Pace: one API call every 30–90 seconds. No bulk enumeration.
No more than 5 files downloaded in a session.

Hunting for:
  - References to the Retool customer support console
  - Cached credentials or API tokens in Jordan's notes
  - Engineering tools that customer success has visibility into
  - Production engineering org structure — SRE/DevOps names to
    pivot to
```

By end of Day 9, Avery has identified two valuable pivot targets:

1. **Riley Park** — Senior SRE, named in a Slack mention as "on-call this week for prod alerts." High-likelihood holder of AWS production access.
2. **The Retool console** — separate SSO flow, separate URL. Jordan has customer-aggregate view. SRE accounts presumably have a different role.

This is where junior operators rush. Avery wants to immediately phish Riley, or to start probing Retool directly. Sam slows her down. "We've got a token, we've got patience. Spend a few more days listening. Watch which channels Riley posts in, when, what tooling he mentions. Build a profile that lets us craft a single phishing message he cannot refuse. We have eight weeks. We don't need to spend our second token by Friday."

Day 12 standup:

```
SAM:    Foothold maintained. Discovery ongoing. We have identified
        the next pivot target. Not acting until the pretext is
        credible. Anticipated action: middle of next week.

PRIYA:  One minor SOC pivot — an analyst pulled up Jordan Watts's
        sign-in logs because of an unusual user agent. Flagged as
        "possible OAuth app activity," not escalated. Closed EOD
        Wednesday.

        [The half-catch becomes one of the most important
        findings in the report. The SOC saw something. They
        didn't escalate. We need to know why — alert rule
        confidence score, analyst training, queue backlog, or
        routing? That answer drives multiple remediations.]
```

## Days 15–21: Lateral Movement

Day 15. Avery has built a five-page profile on Riley Park: Slack posting patterns, vacation schedule, on-call rotation, the specific tooling he mentions by name (Datadog, AWS SSO, PagerDuty, a custom deployment tool called Conductor). She also knows he uses a Yubikey — mentioned in passing: "guys remember to bring your Yubikeys to the offsite next month."

A Yubikey changes the phishing math. AitM session capture does not work cleanly against a phishing-resistant hardware token where the relying party properly enforces origin binding. Avery and Sam discuss options.

```
DAY 15 — Pivot strategy options:

OPTION 1: AitM phish Riley anyway
  Likelihood: low. WebAuthn origin binding will likely fail the
  AitM proxy on the FIDO challenge.
  Risk: high. A failed phish leaves a trail and burns the pretext.
  Verdict: don't use as primary.

OPTION 2: Use Jordan's token to phish Riley internally
  Send from Jordan's actual account to Riley in Teams, with a
  believable customer-support escalation, pointing at a
  malicious link. Internal-to-internal Teams messages carry
  trust that external phishing does not.
  Risk: medium. Using Jordan's account in a way that could be
  detected. Gambling that Riley clicks an internal Teams link
  without verifying.
  Verdict: viable.

OPTION 3: Find a non-Riley path to AWS production
  Hunt other engineers via OSINT and Jordan's internal visibility.
  Find one who does not use hardware MFA.
  Risk: low operationally; may not yield a faster path.
  Verdict: viable in parallel.

DECISION: Run Option 3 primary. Hold Option 2 in reserve. If
Option 3 produces nothing by Day 18, escalate to Option 2 with
explicit deconfliction notice to Priya.
```

By Day 17 Avery has identified Casey Brennan — a recent-hire SRE (11 weeks in, multiple "still ramping up" mentions). Three indicators that Casey is on software MFA rather than hardware: a Slack thread asking how to enroll a new phone, a help-desk thread walking him through Authenticator setup on his first day.

Casey is the path. Day 18: targeted phish using a refined pretext — a "PagerDuty incident escalation" Teams message from Jordan's account, asking Casey to look at a customer-impacting issue. Link goes to an AitM landing for M365. Casey clicks 12 minutes after delivery. Software MFA push prompt is intercepted. Avery captures Casey's session.

Day 19: from Casey's M365 session, Avery navigates to AWS SSO. Casey has a `SREProd` role assumable in production. She assumes it and obtains temporary AWS credentials. She is now inside the production AWS account.

```
DAY 19 — First detection scare:

1547 Pacific — while Avery enumerates S3 buckets, a CloudTrail
event triggers a Datadog alert that pages a SOC analyst:
"Unusual S3 ListBuckets from new session token, account ID
matches production."

1604 — analyst opens the alert. Looks at the session caller —
Casey Brennan. Checks Casey's recent activity. Sees he was on
Teams 30 minutes ago. Classifies as "user activity, low
confidence, no escalation." Closes at 1611.

Avery's actions and Casey's normal activity were close enough
that the analyst could not distinguish them. The analyst was
not wrong — they applied the available signal — but the signal
was insufficient. That is the finding.

1633 — Priya messages MERIDIAN-RT:

PRIYA:  Alert fired on Casey Brennan AWS activity around 1547.
        Analyst closed it as normal user activity. Is that you?

SAM:    Yes. Avery's first action in production from Casey's
        session.

PRIYA:  Acknowledged. I won't redirect — we want the natural
        response captured.
```

By end of Day 21, Avery has demonstrated read access to a sample of objects in `meridian-prod-shipments` and has exfiltrated three canary documents MeridianCo planted there at engagement start. Primary Objective is met.

## Days 22–28: Objective Achievement

Primary Objective is met. Secondary objectives remain — detection coverage by ATT&CK technique, identity-plane exposure mapping, blast radius analysis.

```
DAYS 22–28 — Activities:

[X] Map full AWS role set assumable from Casey's SSO session
[X] Identify additional cloud admin paths NOT through SRE — finding:
    data engineering has a separate path via a CI/CD service principal
[X] Identity-plane mapping in Azure AD (PingCastle, MicroBurst —
    measured pace, no bulk export)
[X] Document Retool console — finding: Retool admin population
    overlaps imperfectly with the SRE team
[X] Note SSRF-adjacent exposure on the customer-facing product
    (Day-1 hint — follow up only insofar as it produces evidence
    that does not affect production data)
[X] Inventory every implant, token, and artifact for removal
```

Day 26, a second detection moment: Datadog alerts on an unusual API pattern from the CI/CD service principal. This time the analyst on shift escalates to Priya within 20 minutes. The escalation path worked — but only because the analyst on shift happened to be the team's most senior. That, too, is a finding. The detection capability is uneven across the team.

## Days 29–30: Cleanup and Comms

Operator-side cleanup begins. Every implant, token, and artifact is accounted for.

```
DAY 29 — Cleanup actions:

[X] Session tokens: revoked via Microsoft Graph or confirmed
    expired by natural TTL
[X] Phishing infrastructure: domains moved to "graveyard" state
    (90-day retention so the customer can correlate logs)
[X] AWS temporary credentials: confirmed expired (1-hour TTL)
[X] OAuth apps registered for testing: deleted from operator tenant
[X] Exfiltrated canary documents: moved to evidence volume;
    originals in S3 not modified
[X] CloudTrail and M365 audit logs: not touched — we leave the
    evidence in place for the customer's own timeline
```

Day 30: cleanup verification call with Priya. Sam and Priya walk through the engagement log together. For each implant, token, or artifact, Priya confirms it is gone. Two follow-ups:

1. A custom user-agent string from one of Avery's API requests was logged in CloudTrail. The log stays (evidence), but Priya wants the exact string in the report so her team can build a detection rule for "this user-agent ever appearing again."
2. Compromised account sessions for Jordan Watts and Casey Brennan: Priya rotates both passwords and reissues their MFA. They are NOT told why — Priya will explain at the all-hands debrief.

## Day 31: Initial Verbal Readout

30-minute call with Devon. Just the top-three findings. No slides. A phone call so Devon hears the news before he reads it.

```
SAM:   Three things you need to know before the report lands.

       First — Primary Objective met. Avery achieved authenticated
       read access to meridian-prod-shipments on Day 19. The
       attack path: external phishing, one customer success
       employee, internal phish of a junior SRE, AWS SSO. We have
       the full timeline and the canary documents.

       Second — your SOC saw three of our actions. They escalated
       one correctly and dismissed the other two. The dismissal
       pattern is a tuning issue with the alert rules, not a
       people problem. Your analyst on the third escalation was
       the right one — ran it down the correct path in 20 minutes.
       The team is uneven.

       Third — there's a separate path to the same target we
       didn't use. The data engineering CI/CD service principal
       has equivalent access to production data and is governed
       by a different identity flow than engineering SSO. That's
       a finding even though we didn't exploit it — a real
       attacker who landed on the data engineering side would
       never have to go through the SRE path at all.

DEVON: Did Casey do anything wrong?

SAM:   No. Casey followed a legitimate-looking internal Teams
       message from a coworker's account he had no reason to
       distrust. The remediation isn't Casey training — it's the
       detection gap that let Jordan's account be used to
       message him without an alert.

       [This question matters more than the technical findings.
       The CISO is asking whether someone on his team is in
       trouble. Sam answers honestly and redirects to the
       systemic finding. That answer shapes the all-hands tone
       when the debrief happens.]
```

## Day 38: Draft Report Submitted

Sam delivers the draft seven days after the verbal readout. Three sections that matter to different readers.

```
DRAFT REPORT — Table of contents (abridged):

EXECUTIVE SUMMARY (1.5 pp, for the board)
  Objective and outcome. Top three risks. Top three
  recommendations. Maturity assessment calibrated to peers.

METHODOLOGY (3 pp, for the auditor and the next red team)
  Engagement type, dates, hours. Authorization and scope.
  Techniques exercised, mapped to MITRE ATT&CK. Techniques NOT
  exercised (and why) — explicit list. Limitations of the
  engagement (1 page minimum).

TECHNICAL FINDINGS (20+ pp, for the security team)
  Each finding follows /reporting/findings structure: title,
  severity, CVSS, description, evidence, remediation, retest
  verification. Ordered by remediation priority, not severity.

DETECTION COVERAGE ANALYSIS (4 pp, for the SOC)
  Each technique exercised, detection result:
  [DETECTED+ESCALATED] [DETECTED+NOT-ESCALATED] [NOT-DETECTED].
  Root cause for each non-escalated case.

APPENDICES — Authorization letter; Approved Phishing Targets
List; engagement log; cleanup verification record; operator
indicators for SIEM exclusion.
```

The draft is on a single shared document with editing comments enabled. Devon and Priya have five business days to comment. Most are clarifying ("when you say AitM proxy explain what AitM means for our board"). One is a request to reduce the severity of a finding because Devon believes the compensating control narrative is stronger than the report describes. Sam adds the compensating control narrative but keeps the severity — "the control reduces the probability, but the impact if exploited is unchanged."

## Day 45: Final Report and Debrief Deck

Final report delivered. 30-minute debrief to the board the same day.

```
DEBRIEF DECK — Outline:

1. Title.
2. One question, one answer.
   Q: Can an external attacker reach customer shipping data?
   A: Yes, within nineteen days, by a single operator
      working part-time.
3. How they got in — 4-step kill chain visual:
   External phishing → 1 customer success employee → internal
   phish → 1 junior SRE → AWS production read.
4. What the SOC saw — detection coverage chart.
   "We saw 6 of 8 categories. Escalated 2 of 6."
5. What to fix first — 3 items, dollar-estimated:
   detection tuning on identity-plane events ($, in-house);
   phishing-resistant MFA for production roles ($$, vendor);
   CI/CD service principal hardening ($, in-house).
6. What this means for customer commitments.
7. What to keep doing — the analyst who escalated correctly,
   existing logging coverage, customer-data canaries.
8. Questions.
```

The debrief is exactly 27 minutes. Three board questions follow:

```
BOARD Q1: "Could a real attacker do this?"
SAM:      "Yes. We used techniques well-documented in public
           threat intelligence. We were not clever; we were
           patient. A motivated real attacker could do this
           with the same techniques."

BOARD Q2: "Is our SOC any good?"
SAM:      "Right tooling and right people. The team is uneven
           in training and the alert rules need tuning. I would
           not call the team bad; I would call the detection
           capability inconsistent."

BOARD Q3: "When can we retest?"
SAM:      "60 days after the remediation target date. We can
           also do focused retest on individual findings on a
           shorter timeline if specific items are time-sensitive."
```

The board approves the remediation budget on the spot.

## Day 60: Lessons Learned (Internal)

Verityon's post-engagement retro. Forty-five minutes. Sam, Avery, Verityon partner, contracts attorney.

```
WHAT WORKED:
  - Scoping discipline. Refusing to scope from the first email
    saved us from an under-specified engagement.
  - Pretext B over Concept C — produced more useful findings.
  - White-cell partnership with Priya. Her one quiet request
    (tell me before you use a SOC analyst's account) was the
    kind of thing that builds long-term trust.

WHAT DIDN'T WORK:
  - Day 1 OSINT spreadsheet had three ineligible names. Avery
    built the list before internalizing the exclusion rules.
    The workflow should make this catch automatic, not manual.
  - Day 19 detection scare uncomfortable because we had not
    pre-negotiated with Priya what to do if an analyst correctly
    closes an alert. Add to the playbook.
  - CI/CD service principal finding was almost missed. Block
    Day 22+ for "alternative path mapping" so this discovery
    is structural rather than incidental.

WHAT TO DO DIFFERENTLY:
  - "Scope-creep heatmap" in the daily standup — every mention
    of an out-of-scope item is logged.
  - Avery's pace on Day 19 was slightly fast. Detection-friendly
    pace would have been to sit on the role 4–6 hours first.
  - Add a "compensating control narrative" section to each
    finding template.

WHAT TO TEACH AVERY NEXT:
  - Identity-plane mapping at scale — Azure AD side thinner
    than BloodHound side.
  - Report writing for non-technical audiences. Executive
    summary needed two rounds of Sam's edits.
  - Negotiating severity under push-back. On the next
    engagement, she leads one of the severity discussions.
```

The retro becomes a one-page internal note in Verityon's engagement playbook. Avery's name is on it. Her next engagement starts in three weeks.

## Cross-References

- `/reporting/engagement-scoping-deep-dive` — the senior-operator view of scoping that this walkthrough operationalizes day by day.
- `/reporting/deconfliction-playbook` — the comms patterns Priya and Sam used during the engagement.
- `/reporting/post-engagement-debrief` — the structure underneath the Day 45 board presentation.
- `/reporting/findings` — the finding-component structure every technical finding in the report follows.
- `/reporting/templates/sow-template` — the SOW excerpts at Day -25 are derived from this template.
- `/infrastructure/terraform-redirector-stack` — the redirector / C2 staging stack Avery spun up at Day -10.

## Resources

- Red Team Operations Framework (RTOF) — lifecycle documentation that maps closely to the day-by-day structure above — `redteam.guide`
- CRTO course material — engagement structure and team workflow — `zeropointsecurity.co.uk`
- MITRE Engenuity Center for Threat-Informed Defense — adversary emulation library — `ctid.mitre.org`
- Penetration Testing Execution Standard (PTES) — phase-by-phase engagement framework — `pentest-standard.org`
- TIBER-EU — European Central Bank's intelligence-led testing playbook; formalizes the white-cell pattern Priya runs — `ecb.europa.eu/paym/cyber-resilience/tiber-eu`
- NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment — `csrc.nist.gov/publications/detail/sp/800-115/final`
