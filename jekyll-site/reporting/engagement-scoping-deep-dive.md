---
layout: training-page
title: "Engagement Scoping Deep Dive — Red Team Academy"
module: "Reporting"
tags:
  - scoping
  - sow
  - roe
  - authorization
  - engagement-planning
  - legal
page_key: "reporting-engagement-scoping-deep-dive"
render_with_liquid: false
---

# Engagement Scoping Deep Dive

Scoping is the most consequential phase of the engagement. It sets the ceiling on the value the customer can extract from the report AND the floor on the operator's personal legal risk. Too loose and you produce a useless report while wandering into systems nobody authorized you to touch. Too tight and you can't demonstrate the impact that justifies the budget. Most operators treat scoping as a procurement formality run by the sales lead — the senior people treat it as the most important hour of the engagement. This page is the operator's view: the questions to ask, the clauses that have actually saved careers, and the political dynamics that scoping calls hide behind polite language.

## What Scoping Decides

Every scoping call has to leave with answers to five questions. If any one of them is still ambiguous when you hang up, you do not have a scope — you have an expensive misunderstanding waiting to detonate mid-engagement.

```
># The five questions:

1. OBJECTIVES — What outcome does the customer want? (Not: what activity.)
2. TARGET SCOPE — Exactly which assets, IPs, domains, accounts, tenants?
3. IN-BOUNDS TECHNIQUES — What may we do? What may we NOT do?
4. RULES OF ENGAGEMENT — Hours, comms, escalation, abort, evidence handling.
5. LEGAL AUTHORIZATION — Who signs, under what authority, for which assets?

# If you cannot get a clean answer to all five, the engagement is not
# ready to start. Delay the kickoff. Do not improvise scope on the wire.
```

## Objectives

The single most common mistake in scoping is conflating activities with outcomes. "Run a red team" is an activity. "Determine whether a financially-motivated external attacker can reach the payment processing environment within 30 days" is an outcome. Outcomes drive technique selection; activities drive nothing.

```
># Activity vs outcome — re-frame the customer's ask:

CUSTOMER SAYS                       WHAT IT PROBABLY MEANS
─────────────────────────────────────────────────────────────────
"We want a red team"                "We have a regulatory checkbox"
"Test our SOC"                      "Justify the SOC budget or fire them"
"Pentest the new app"               "Sign-off needed for go-live"
"Assume breach exercise"            "Detection coverage is unknown, prove it"
"Adversary emulation"               "Board asked about ransomware risk"

# Always reframe back: "So the outcome you want is X. Is that right?"
# Get a yes on the outcome BEFORE you scope the activity.
```

Stakeholder mismatch will kill the engagement. The CISO wants evidence to justify next year's budget. The board wants a one-page risk rating. IT operations wants nothing to break. The SOC manager wants to look good. These objectives are not aligned. On the kickoff call, name the stakeholders out loud and ask whose objective the engagement is actually serving. If the answer is "all of them" — push back. You cannot serve four masters in 80 hours.

```
># Pushing back on the wrong objective — sample language:

"The scope you've described would let us produce a vulnerability list,
 but it won't tell you whether a real attacker can reach your crown jewels.
 If that's the question the board is actually asking, we should reshape
 the objective. If the answer you need is the vulnerability list, that's
 a different engagement — and probably half the budget."
```

## Target Scope

Asset scoping is where the operator's legal risk lives. Get this wrong and you will touch a system the customer does not have authority to authorize. The scoping document must list assets with the same precision a network engineer would use — CIDR ranges, FQDN globs, cloud account numbers, AAD tenant GUIDs, repository URLs, app IDs. Verbal scope ("everything in the corporate network") is not scope.

```
># Asset inventory — minimum precision required:

NETWORKS:    CIDR with /mask, both IPv4 and IPv6
DOMAINS:     FQDN with explicit subdomain wildcarding (*.acmecorp.com)
CLOUD:       AWS account ID, Azure tenant + subscription GUID, GCP project
SAAS:        Tenant URL + admin authority confirmed (Okta, M365, Salesforce)
IDENTITIES:  Which directories — on-prem AD, AAD, both, federated to which IdP
REPOS:       Github org slug, Gitlab instance URL, Bitbucket workspace
PEOPLE:      In-scope role list — NOT names of individuals
PHYSICAL:    Site addresses, suite numbers, which entrances, which floors
```

Cloud tenant scoping is its own minefield. The customer may own production AWS account A, but the auth flow trusts a federation IdP in a sibling account B that was carved off after an acquisition. If you compromise the IdP in B you have technically pwned a system that was not in scope and which the signing party has no authority over. Ask the question explicitly: "Does the signing party have legal authority over every cloud account the production identity plane depends on?"

Subsidiary scoping has the same problem. A parent company can sign authorization for systems it operates, but a wholly-owned subsidiary in a different jurisdiction may be a separate legal entity that requires its own signature. The same applies to acquisitions inside the integration period — assets the parent thinks it owns may still be operated under the acquired entity's contracts.

The "everything internet-facing in the parent org's name" pitfall: passive recon will surface assets across forgotten subsidiaries, dev contractors' personal AWS accounts, marketing-team-owned WordPress hosts on a third party, and shadow IT in regional offices. None of those are necessarily authorized just because they show up in a Shodan query for the parent's keywords. Build the inventory together with the customer and explicitly mark anything you find later that wasn't on the list as out-of-scope until written confirmation.

## In-Bounds Techniques

Techniques scoping is where the customer's discomfort surfaces. Most customers want findings but do not want to be reminded what finding them entails. Walk every technique class explicitly.

```
># Technique-class checklist — get YES or NO on each:

# Phishing
- In scope? Y/N
- Targets: full employee list, role-targeted, or pre-approved list?
- Pretexts: any banned topics (CEO impersonation, COVID, layoffs)?
- Click-through goal: credential capture, payload exec, or both?
- Will captured creds be USED against the production environment?

# Vishing / SE-by-phone
- In scope? Y/N
- Jurisdictional issue: two-party consent recording laws (CA, FL, IL, MA,
  MD, MT, NH, PA, WA + others). If you record, you may be committing a
  crime in the target's state. Get written waiver or do not record.
- Help-desk impersonation OK? Most customers say yes, then panic when
  the help-desk lead complains. Get the help-desk lead on the call first.

# Physical
- Separate engagement class. Different authorization, different insurance,
  different abort criteria. Do not bolt physical onto a network scope.

# DoS / Service-degrading activity
- DEFAULT NO. State it in writing. Some "tests" are accidental DoS
  (auth bruteforce that locks all users, scanner that crashes a fragile
  service). Define the tolerance — e.g. "no action that knocks more than
  one production system offline for more than 5 minutes."

# Destructive impact
- DEFAULT NO. No data destruction, no encryption, no defacement, no
  config wipe, no firmware flash. Include this even when "obvious" —
  the operator who wipes a domain controller by accident wants this
  clause in writing.

# Dwell-time and persistence
- How long may implants persist? Some customers want 30-day simulated
  dwell. Most want everything off the network the day the report is
  delivered. Define cleanup procedure and verification.

# Infrastructure region
- Where does C2 live? Some customers' insurance excludes attacks
  originating from specific geographies. Some have data-residency
  contracts that prohibit credentials transiting certain jurisdictions.

# Detection-bypass intensity
- "Stealth" is a spectrum. Define it: opportunistic OPSEC, full evasion,
  or assumed-compromise (noisy on purpose). Bills hours very differently.
```

## Rules of Engagement

ROE governs the operational mechanics — when you act, how you talk to the customer, what happens when something breaks. The legal document is the SOW + auth letter. The ROE is the operator's playbook.

```
># ROE — must address all of these:

# Hours
- Active testing windows (e.g. 0800-2000 customer-local)
- Blackout windows (board meetings, payroll runs, holiday freeze)
- 24x7 ops? Only with dedicated customer on-call

# Communication cadence
- Daily check-in (time, channel, with whom)
- Critical-finding notification (target: 4 hours, max: 24)
- Out-of-band channel (Signal, not email — email may be the compromise)

# Escalation tree
- Primary POC: name, cell, backup cell
- Secondary POC: when primary unreachable
- Executive escalation: CISO direct line
- Confirm verbally during kickoff that those numbers connect to a
  human, not a voicemail tree

# Deconfliction protocol
- If the SOC sees you, what's the unmask procedure?
- If you see another attacker (real, not a teammate), what do you do?
- Stop-work codeword — single phrase that pauses all activity

# Evidence handling
- Where do captured credentials live? Encrypted volume only.
- Customer data exfil: NEVER exfil real PII/PHI/PCI. Use canary
  files the customer plants, or screenshot-only proof.
- Retention: how long do you keep evidence after the report ships?
  Default 90 days encrypted, then secure-delete.

# MFA-fatigue cap
- Push-bombing is in scope but limit to N prompts per target per hour
  to avoid actual account lockout / user distress at scale.

# Pause and abort triggers
- Customer-side trigger: any POC says "pause" or "stop" — instant.
- Operator-side trigger: if we see evidence of a real intrusion in
  progress, we pause and notify within 15 minutes.
- Third-party trigger: if a cloud provider or upstream ISP contacts
  the customer about our traffic, we pause until cleared.
```

## Legal Authorization Letter

The authorization letter is the document you carry. If a real-world consequence happens — a sysadmin calls the FBI, a network owner files an abuse complaint, you get detained at a physical engagement — this letter is what makes the difference between an inconvenience and a felony charge.

```
># Authorization letter — must contain:

1. Identity of the authorizing party (full legal name of entity, not DBA)
2. Identity of the testing party (your firm + named lead operator)
3. Specific assets authorized (the scope document, attached by reference
   AND embedded so it travels with the letter)
4. Date range of authorization (start and end, with timezone)
5. Signatory's name, title, and statement of authority over the assets
6. Signatory's wet signature OR cryptographically verifiable e-signature
7. Counter-signature from the testing party's authorized signatory
8. Contact phone numbers for both parties' POCs
9. Statement that the letter may be presented to law enforcement
10. Carry instructions for physical engagements ("present this letter
    to any individual challenging the bearer")
```

Who signs matters. The signatory must have actual authority over the assets. A CISO can authorize testing of corporate infrastructure but cannot authorize testing of a subsidiary they do not control. A cloud architect can authorize testing of the AWS account they're the root owner of, but cannot authorize testing of a federated IdP held by a different team. If the signatory's authority is ambiguous, get a second signature. Two signatures is cheap insurance.

CFAA (18 USC §1030) is the US federal anchor — unauthorized access to a "protected computer" is a federal crime. Written authorization from someone with authority is the affirmative defense. Most US states also have their own computer-crime statutes (Penal Code §502 in California, NY Penal Law §156 in New York, etc.) that can be charged independently of federal CFAA. If the engagement touches assets in multiple states, the authorization letter should reference the assets, not assume federal jurisdiction.

Multi-jurisdiction engagements need parallel authorization. UK assets need cover under the Computer Misuse Act 1990. EU assets touching critical infrastructure may trigger NIS2 notification obligations. Singapore (Computer Misuse Act 1993), Australia (Criminal Code Act 1995, Part 10.7), and Canada (Criminal Code §342.1) each have their own framework. Do not assume a US-form authorization covers operations originating from or terminating in another country.

Cloud-provider AUP is an overlay on top of the legal authorization, not a substitute for it. AWS dropped pre-approval for most testing in 2019 but maintains a list of prohibited activities (no DoS, no port-flood, restrictions on certain managed services). Azure and GCP have similar policies. Read the current policy text from the provider on the day you start — the policies change.

```
# Cloud penetration-testing policies (verify on day-of):
# AWS:    https://aws.amazon.com/security/penetration-testing/
# Azure:  https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement
# GCP:    https://support.google.com/cloud/answer/6262505
# Oracle: https://www.oracle.com/corporate/security-practices/assurance/vulnerability/pentest.html
```

## Out-of-Scope Drift

Mid-engagement scope creep is the second most common operator-side failure (the first is bad evidence capture). The customer's IT lead drops into the daily standup and says "while you're in there, can you also look at this other thing?" Saying yes feels collaborative. Saying yes is a contract violation.

```
># Scope-change procedure — write this into the SOW:

1. Any change to scope, technique, or ROE requires a written change order.
2. Change orders are signed by the same authority that signed the SOW.
3. No change is in effect until both parties have countersigned.
4. The operator may pause work pending change-order resolution at no
   penalty to the engagement timeline.
5. Verbal expansions of scope are non-binding and will not be executed.

# Operator script for in-call scope creep:
"That's a good idea and I want to help — but I can't touch that system
 today because it's outside my authorization. Let's get a quick change
 order written up. Who would need to sign that on your side?"
```

When to refuse a change order: the change would touch a system whose signing authority is not represented in the request. The change would require a technique class that was explicitly out-of-scope (someone wanted no phishing during initial scoping; mid-engagement they want phishing because "the network angle isn't producing"). The change is being requested by a stakeholder who is not the contractually-named POC.

## Time and Money

Hours estimation is where the proposal lives or dies. Most firms estimate against a checklist of activities. Senior operators estimate against the objective.

```
># Realistic hours by objective class (single competent operator):

External recon + perimeter scan, no exploitation        24-40 hours
External + initial-access attempt, single objective     60-120 hours
Internal assumed-breach to domain compromise            80-160 hours
Full external-to-objective, no assumed breach           160-320 hours
Adversary emulation, named threat actor, full TTP set   200-400 hours
Purple-team detection exercise, week-long               40-80 hours
Continuous (monthly retainer, 40h/mo)                   ongoing

# Multipliers:
# +25% for multi-tenant cloud
# +30% for hardened/EDR-heavy environment
# +40% for first engagement with this customer (learning curve)
# +50% if customer requires evidence-chain for legal/compliance use
# +100% if physical is included
```

The gap between scoped-effort and realistic-effort is where engagements get lost. If the customer's budget is 80 hours and the objective realistically takes 200, you have two honest options: reshape the objective to fit 80 hours, or walk away. The dishonest option — accept the budget, do 80 hours of work, and deliver a report that claims the objective was met — is what produces the false-confidence outcomes that get customers breached six months after a clean pentest.

## Stakeholder Politics

The scoping call has people in the room whose interests are not aligned with a good engagement. Naming the dynamics out loud, even just to yourself, is half the work.

"We want to test our SOC" — but the SOC manager is the scoping contact. The SOC manager's career depends on the SOC looking good. They will steer the scope toward techniques the SOC is already known to detect. The honest move is to ask whether someone outside the SOC's chain of command (CISO, internal audit, board risk committee) is sponsoring the engagement. If not, the engagement will produce a flattering report that proves nothing.

"Don't actually pwn us, just write the report" — the customer wants the deliverable for an auditor without the operational disruption of a real test. This is paid red team theater. It produces fraudulent compliance evidence. Refuse it. If you cannot refuse it (it's a multi-year client and the partner is pressuring you), at minimum get the limitation in writing in the report's methodology section so the next auditor can see what was actually performed.

"The CEO wants to see his own password get cracked" — vanity scope. Will produce a finding the executive personally cares about and ignore the systemic issues. Steer toward an objective the company actually needs answered.

## Engagement Types and Scope Effect

The engagement type sets the starting state, and the starting state changes everything downstream — hours, technique scope, evidence capture, what counts as success.

```
># Type vs scope implications:

WHITE-BOX
- Operator gets full network diagrams, source code, credentials.
- Scope can be narrow and deep (specific component).
- Goal: exhaustively prove or disprove vulnerability hypotheses.
- Risk profile: low — operator has the map.

ASSUMED-BREACH
- Operator starts with shell on a workstation OR user-level domain creds.
- Scope: internal, lateral movement and detection.
- Goal: time-to-DA, detection coverage, blast radius from one foothold.
- Most cost-effective format — 80% of the value of full simulation
  at 40% of the effort.

BLACK-BOX
- Operator starts with public information only.
- Scope: external-to-objective, full kill chain.
- Goal: simulate an unauthenticated attacker.
- Highest cost, most realistic, longest timeline.

PURPLE TEAM
- Red team and blue team co-located, techniques announced.
- Scope: detection coverage of specific TTPs (MITRE ATT&CK mapped).
- Goal: measurable detection improvement during the engagement itself.
- Not a substitute for adversarial testing — it is a tuning exercise.

CONTINUOUS / RETAINER
- Ongoing low-volume testing, monthly or quarterly objectives.
- Scope renegotiated per cycle within a master agreement.
- Goal: detect change over time, catch new exposure as infra evolves.

ADVERSARY EMULATION
- Black-box constrained to a named threat actor's TTPs.
- Scope: techniques are the scope (FIN7, APT29, etc.).
- Goal: model a specific threat the customer faces.
- Requires good threat-intel input — pick wrong actor = wrong findings.

TABLETOP HYBRID
- Discussion-based simulation with selective live execution.
- Scope: scenarios and decision points, with optional technical proof.
- Goal: test the response process, not the controls.
- Cheap, high-signal for executive teams.
```

## Scoping Worksheet

Use this as a reproducible template. Fill it in before the kickoff call and bring it to the meeting. Empty fields are conversations you have not yet had.

```
># Scoping worksheet — fill before kickoff:

1.  Customer legal entity name:           __________________________
2.  Signing authority (name, title):      __________________________
3.  Engagement type (from table above):   assumed-breach
4.  Primary objective (one sentence):     "Determine whether an external
                                           attacker can access the payment
                                           processing environment within
                                           the testing window."
5.  Success criteria (measurable):        Reach PCI DSS card data env OR
                                           document a path with 70%+
                                           confidence and named blockers.
6.  Asset scope (attach inventory):       See Appendix A — 4 /24 ranges,
                                           2 AWS accounts, *.acmecorp.com
7.  Out of scope (be explicit):           HR/payroll subnet 10.50.0.0/16,
                                           UAT environment, executive
                                           workstations, customer DB writes
8.  Techniques in scope (check):          [X] Phishing  [X] Vishing
                                           [X] Cloud   [ ] Physical
                                           [ ] DoS     [ ] Destructive
9.  Testing window:                       2026-06-01 to 2026-06-28,
                                           0700-2200 Pacific, no weekends
10. Blackout windows:                     Jun 15 (board meeting),
                                           Jun 20-21 (release freeze)
11. Comms cadence:                        Daily 0900 Signal check-in,
                                           critical findings within 4h
12. Deconfliction POC (primary):          Jane Doe, +1-555-XXX-XXXX
13. Deconfliction POC (backup):           John Roe, +1-555-XXX-XXXX
14. Reporting deadline:                   2026-07-12
15. Retest included? (yes/no, when):      Yes — 60 days post-remediation
```

## When to Walk Away

Some engagements should not be accepted. Recognizing them early protects the customer, the operator, and the firm.

Walk away when the engagement cannot legally happen — the signing party does not have authority over the assets, or the testing would violate a binding contract the customer has with a third party (a SaaS provider's ToS, a regulator's restriction, an upstream contract that prohibits security testing of the deliverable).

Walk away when the scope makes the customer worse off — the customer demands a scope so narrow it will produce a false-confidence report ("test only this one app, nothing else") when their actual exposure is elsewhere. Delivering a clean report on a narrow scope to a customer with broad exposure is professional malpractice.

Walk away on mismatched maturity — a customer with no asset inventory, no patch management, no logging, and no incident response capability does not need a red team. They need a vulnerability assessment and a maturity engagement. Selling them a red team is taking their money.

Walk away when insurance conditions compromise honesty — some customers' cyber-insurance policies require the operator to sign a clause limiting the report's contents or capping findings severity. If the contract requires you to misrepresent what you found, do not sign it.

## Resources

- NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment — `csrc.nist.gov/publications/detail/sp/800-115/final`
- MITRE ATT&CK and Center for Threat-Informed Defense — `attack.mitre.org` and `ctid.mitre.org`
- Red Team Operations Framework (RTOF) — `redteam.guide`
- CREST CCSAS / CCT — Certified Simulated Attack Specialist / Certified Tester — `crest-approved.org`
- CBEST (Bank of England intelligence-led testing) — `bankofengland.co.uk/financial-stability/financial-sector-continuity`
- TIBER-EU (European Central Bank framework) — `ecb.europa.eu/paym/cyber-resilience/tiber-eu`
- Penetration Testing Execution Standard (PTES) — `pentest-standard.org`
- OWASP Web Security Testing Guide — `owasp.org/www-project-web-security-testing-guide/`
- CFAA (18 USC §1030) — `law.cornell.edu/uscode/text/18/1030`
- AWS Penetration Testing Policy — `aws.amazon.com/security/penetration-testing/`
- Azure Penetration Testing Rules of Engagement — `microsoft.com/en-us/msrc/pentest-rules-of-engagement`
- GCP Customer Penetration Testing — `support.google.com/cloud/answer/6262505`
