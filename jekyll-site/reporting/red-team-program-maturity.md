---
layout: training-page
title: "Red Team Program Maturity — Red Team Academy"
module: "Reporting"
tags:
  - program-management
  - maturity-model
  - staffing
  - metrics
  - board-reporting
  - continuous-red-team
page_key: "reporting-red-team-program-maturity"
render_with_liquid: false
---

# Red Team Program Maturity

An engagement is a project. A program is a function. Most security organizations stall at the gap between those two ideas — they have run "a red team test" but they have not built "a red team capability." The first is a calendar item with a SOW. The second is a permanent organizational muscle with staffing, cadence, deliverables, governance, and a budget line item that survives the next CFO.

This page is a model for that gap and what fills it. It is written from the seat of someone who has stood up internal red teams at two large enterprises, sold retainer work into a third, and watched a fourth dismantle a perfectly competent program because nobody wrote down what it was for. The lessons are repetitive across all four: the technical work is the easy part. The hard part is making the function legible to people who do not buy implants for a living.

If you are running a red team and you cannot answer "why do we still have a red team" in one sentence that an audit committee understands, you are at risk of being cut in the next budget cycle. This page is the antidote.

## Five Maturity Tiers

The model is intentionally short. Five is enough to argue about; ten is enough to wallpaper with.

### Tier 0 — None

No red team capability. The organization has compliance pen tests once a year because PCI or a regulator requires it. Findings go into a binder. Nobody reads the binder. If someone says "red team" internally, they mean "the consultants who wear black t-shirts."

- **Staffing:** zero offensive staff. Vulnerability management owns scanner output.
- **Cadence:** annual scoped pen test, driven by audit calendar.
- **Deliverables:** a PDF report archived somewhere on SharePoint.
- **What blocks T1:** lack of executive sponsorship. The CISO has not yet had a public incident that made the board care.

### Tier 1 — Annual External Engagement

The organization buys one full-scope red team engagement per year from an external firm. Usually because a regulator (TIBER-EU, CBEST, DORA, NYDFS) requires it, or because a peer institution had a public breach and the board got nervous.

- **Staffing:** one internal program manager who runs procurement and coordinates with the firm. No internal operators.
- **Cadence:** one engagement per year, 8–12 weeks, scoped 4–6 weeks ahead.
- **Deliverables:** one technical report, one executive summary, one debrief meeting.
- **What blocks T2:** the realization that one engagement per year measures nothing. Findings cannot be trended. The organization spends $300k–$600k per year and cannot say whether it is getting better.

### Tier 2 — Internal Team or Sustained Retainer

Either (a) the organization hires its first internal operator(s) and a lead, or (b) it converts the annual engagement into a multi-engagement retainer with the same external firm so that the firm builds institutional knowledge.

- **Staffing:** 2–4 internal operators plus a program lead, OR a named retainer team at an external firm with continuity guarantees.
- **Cadence:** 3–6 engagements per year. Quarterly scoped objectives. First atomic red team tests appear between engagements.
- **Deliverables:** per-engagement reports, plus a quarterly trend deck for the CISO.
- **What blocks T3:** the team operates in isolation from detection engineering. Findings get tickets but tickets do not produce detections. The red team is still measured by "did you get in" instead of "did the blue team learn."

### Tier 3 — Continuous Testing Program with Purple-Team Integration

The red team is a permanent function. It has a charter. It has a multi-year roadmap. Every engagement produces detection-engineering deliverables, not just findings. Purple-team rotations are scheduled. Atomic Red Team or CALDERA runs continuously in the background. The team produces threat-model updates back into the application security org and the architecture review board.

- **Staffing:** 4–8 internal operators, an infrastructure engineer, a tradecraft researcher, a program lead, and a customer-facing comms person. Often a junior pipeline (associates/interns) feeding the senior bench.
- **Cadence:** continuous. Engagement boundaries become bookkeeping fictions. The team is always running something.
- **Deliverables:** engagement reports, detection rules delivered to the SOC, threat-model PRs to AppSec, board-level quarterly narrative, ISAC contributions.
- **What blocks T4:** the team can describe what it does but cannot predict what an attacker will do next. It is reactive, not anticipatory.

### Tier 4 — Optimized, Business-Aligned, Predictive

The red team is treated as a forward-deployed risk function. It runs ahead of new product launches, M&A integrations, and infrastructure migrations. It has embedded threat intelligence — its own, not borrowed from a vendor. It produces predictive analyses: "given current attacker tradecraft and our control posture, here are the three scenarios most likely to result in a material incident this year." Funding is approved on a multi-year basis. The CISO uses red team output in board reporting as a forward-looking risk indicator, not a backward-looking audit artifact.

- **Staffing:** 10+ FTEs across operators, infrastructure, research, intel integration, comms, and program management. Sometimes split into specialty squads (cloud, identity, OT, application).
- **Cadence:** continuous + predictive. The team allocates ~30% of its capacity to forward-looking research that has no engagement attached.
- **Deliverables:** everything in T3, plus predictive risk briefings, public research talks, ISAC leadership, vendor pressure (telling EDR vendors what they are missing).
- **What blocks T5:** there is no T5. Stop building maturity models past four.

## Staffing Model

### Roles

A real red team is not "a bunch of operators." It is a small product organization with specialized roles:

- **Operators.** The people who run engagements. The temptation is to hire only operators and call it a team. This is wrong — operators alone cannot sustain a program.
- **Infrastructure engineer.** Builds and maintains C2 infrastructure, redirectors, phishing rigs, domain inventories, and the lab. Without this role, operators waste 30–40% of their time on plumbing.
- **Tradecraft researcher.** Develops novel TTPs, BOFs, evasion techniques, and tooling. Does not run customer-facing engagements. Feeds the operator bench.
- **Program lead.** Runs the function. Owns the charter, budget, calendar, and stakeholder relationships. Should have been an operator. Should not still be running engagements.
- **Customer-facing comms.** Writes executive summaries, runs debriefs, builds the quarterly board deck. In small teams this is the program lead. In larger teams it is a dedicated role — often the highest-paid person on the team because the function depends on it.

### Career Ladder

A realistic ladder for offensive ICs:

- **Associate operator (0–2 years).** Runs assigned tasks within engagements. Pair-programmed on tradecraft. Owns no engagements.
- **Senior operator (2–5 years).** Owns engagement phases. Can lead a small engagement end-to-end. Mentors associates.
- **Principal operator (5–10 years).** Owns multi-phase engagements, designs scenarios, contributes tradecraft. Public-facing (talks, research).
- **Staff operator (10+ years).** Sets technical direction for the function. Often the right person to promote into program lead. Often does not want to.

Compensation should be flat across the ladder relative to detection engineering and platform engineering at the same firm. If offensive ICs make 30% more than blue team ICs, you have a retention problem on the blue side and a hiring problem on yours when defense pay catches up.

### Retention Realities

Average tenure for an internal red team operator is 18–30 months. People leave for three reasons, in this order:

1. **Engagement load.** Six full-scope engagements per year per operator is unsustainable. Four is the ceiling. Three is sane.
2. **Repetition.** After two years on the same enterprise, every engagement looks the same. Rotating engagement types (cloud, identity, OT, application) buys another year.
3. **Comp gaps with consulting.** The big four and the boutiques pay 20–40% more for senior operators. Internal teams cannot match cash but can match equity, calendar predictability, and a real lab.

Plan for it. Build a pipeline. Assume any operator will leave within three years. Build the function so that no engagement, no tool, no domain registration depends on a single person.

### Hiring

Interview structure that works:

- **Phone screen (45 min).** Tradecraft conversation. "Walk me through your last engagement from initial access to objective." Listen for whether they understand why each step worked, not just what tool they used.
- **Lab assessment (4–6 hours, async, take-home).** A purpose-built environment with a defined objective. Submit a report. The report is the deliverable, not the shell. Operators who get the shell but write a bad report fail.
- **Panel (3 hours).** Three 45-minute sessions: tradecraft deep-dive, scenario design, comms. The comms session is non-negotiable. If a candidate cannot explain a finding to a non-technical stakeholder in five minutes, they will not work out.
- **Reference checks.** Call three people the candidate has worked with on engagements. Ask: "would you put them in front of a customer alone?"

Do not use whiteboard coding interviews. Do not use CTF challenges as the primary signal. The job is not CTF.

### DEI in Offensive Security

Offensive security teams trend whiter, more male, and more US/UK-centric than the rest of the security org. This is a hiring pipeline problem, not a talent problem. The fix is not lowering the bar; the fix is widening the funnel:

- Sponsor scholarships at OSCP/CRTO/SANS for candidates from underrepresented backgrounds.
- Run internal apprenticeship tracks from the SOC and detection-engineering teams into the red team. The pipeline is shorter than people assume, and blue-to-red transitions produce some of the best operators because they understand what defenders see.
- Hire for tradecraft potential, not certs. Certs are a proxy that systematically excludes candidates without employer sponsorship.
- Do not run "diversity engagements." Do not point at the one woman on the team in marketing photos. Operators notice. Candidates notice.

This is a non-performative section because performative DEI in security teams is worse than none.

## Engagement Cadence

The cadence question is "how often do you test, and what does each test do?" The honest answer changes with maturity tier.

- **Annual full-scope (T1).** One engagement per year, broad scope, threat-actor emulation. Useful for compliance. Insufficient for improvement.
- **Quarterly objective-scoped (T2).** Four engagements per year, each targeting a specific control or business process. Detection coverage improves measurably.
- **Continuous (T3+).** Engagement boundaries blur. The team is always running something — full-scope or objective-scoped or atomic. Reporting cadence shifts to monthly trend reports rather than per-engagement reports.

Threat-informed scoping means each engagement starts from a CTI brief, not a checklist. "FIN12 has shifted to targeting our sector via X" produces a scoping conversation; "we want to test the network" does not.

Purple-team rotation: every third or fourth engagement should be run as a purple team, with the blue team in the room watching the operator's screen. This is the highest-leverage activity the red team does. It produces detection rules at 10x the rate of normal engagements.

Atomic red team tests fill the space between full engagements. Atomic Red Team (Red Canary) and CALDERA (MITRE) both produce repeatable, single-technique tests that can run weekly without operator time. The output feeds detection engineering directly.

Mandatory cooldown periods are real. After a full-scope engagement, operators need 2–3 weeks of tradecraft development, lab work, or training. Engagements back-to-back produce burnout and decline in quality. Schedule the cooldown explicitly or it will not happen.

## Deliverables Library

The set of artifacts a mature red team produces, beyond the engagement report:

- **Engagement reports — technical and executive.** Covered in detail in the [Executive Report](/reporting/executive-report/) and [Operations Framework](/reporting/red-team-operations-framework/) pages. The technical report is for engineers. The executive summary is for the board. They are not the same document with different fonts.
- **Findings tracker.** A multi-engagement aggregation. Recurring findings across engagements indicate systemic weakness, not isolated bugs. The tracker is the input to the quarterly trend report. Ghostwriter (`GhostManager/Ghostwriter`) is the open-source standard.
- **Detection-engineering deliverables to the blue team.** Sigma rules, SIEM queries, Splunk searches, KQL for Sentinel, custom YARA. Delivered as PRs to the SOC's detection repo, not as bullet points in a Word doc.
- **Threat-model updates to AppSec.** When the red team finds an architectural weakness in an application, the deliverable is not a finding ticket — it is a threat-model update committed to the application's threat-model repo.
- **Board / CISO quarterly summaries.** One slide deck per quarter. The narrative is "what would have happened against us, and what changed." See the Board-Level Reporting section below.
- **Industry reports (anonymized) for ISAC contributions.** FS-ISAC, H-ISAC, MS-ISAC. Sharing anonymized TTPs and detection gaps builds reciprocal intel with peer institutions. T3+ teams do this routinely.

## Metrics That Matter

Covered in detail in [Red Team Metrics & ROI](/reporting/red-team-metrics/). The short list of program-level metrics:

- **MTTD per engagement, trended over time.** Detection capability should improve. If it is flat or worsening, the SOC is not learning from your work.
- **MTTR per engagement.** Time from detection to containment. Often longer than people assume.
- **% objectives achieved (capped at 100%).** Overachievement signals weak scoping. If the team achieves every objective every engagement, the scoping is too easy. Adjust upward.
- **Dwell time achieved.** How long the team maintained access undetected. Should decrease over time.
- **Defender capability uplift score.** A purple-team metric: how many new detections were produced per engagement. Counts only detections that go into production, not draft rules.
- **Recurring findings, and why they recur.** If the same finding appears in three consecutive engagements, the remediation process is broken — not the finding.
- **Engagement-to-engagement detection improvement delta.** Per ATT&CK technique. Tracked in VECTR.

### Anti-Metrics

These are metrics that look meaningful and are not:

- **Number of engagements run.** A T1 team that runs one excellent engagement is more valuable than a T3 team that runs twelve shallow ones.
- **CVEs filed.** Filing CVEs is research output, not red team output. Conflating them inflates the team's apparent productivity.
- **Number of findings.** A 200-finding report is usually worse than a 12-finding report — it means the team did not prioritize.
- **Operator-hours billed.** Internal teams sometimes get pulled into chargeback accounting. Refuse. It produces the wrong incentives.

## Governance

A red team without a charter is one CISO change away from being dissolved. The charter is the document that says what the function exists to do, who it reports to, what authority it has, and what it cannot do.

Charter components:

- **Mission statement.** One sentence. "Continuously validate the organization's ability to detect and respond to advanced threats."
- **Scope and authority.** What systems the team can test. What approvals are required for which actions.
- **Reporting line.** Typically to the CISO, sometimes dual-reporting to internal audit for independence.
- **Conflict-of-interest provisions.** The team does not test its own infrastructure. The team does not perform compliance audits. The team does not own remediation.
- **Refresh cadence.** Annual. Reviewed by the CISO, signed by the CEO or audit committee chair.

Independence requirements at regulated institutions:

- **Financial services.** TIBER-EU, CBEST, and DORA all require some degree of independence from the security operations function. The red team should not report into the same line as the SOC. In practice this means a dotted line to internal audit or directly to the CISO with the SOC reporting to a deputy.
- **Public sector.** Federal civilian and DoD red teams often sit in an independent assessment organization separate from IT operations.
- **Healthcare and critical infrastructure.** Independence is regulator-driven. Verify against current HHS, FERC, NRC, and TSA guidance.

Documentation and evidence retention:

- Operator logs retained for the engagement duration plus 12 months minimum.
- All credentials accessed during engagements documented, hashed, and destroyed within 24 hours of engagement end.
- Audit responses: a mature team can produce, on demand, a list of every system touched, every credential accessed, and every change made during any historical engagement.

## Funding and Headcount

The build-vs-buy decision is the most consequential financial choice in red team program design.

### Cost Benchmarks

These are rough numbers for a US-based enterprise in 2025–2026:

- **Per-FTE fully loaded.** $220k–$380k depending on seniority. Senior operators in major metros (NYC, SF, London) clear $300k base.
- **Infrastructure annual.** $80k–$200k for a T3 team. Includes C2 licenses (Cobalt Strike, Brute Ratel), domain inventory, redirector VPSes, lab hardware, and SaaS tooling.
- **Tooling budget.** $40k–$100k annually for commercial tools (Cobalt Strike licenses, Burp Suite Enterprise, BloodHound Enterprise, etc.).
- **Training and conferences.** $15k–$25k per operator annually. Non-negotiable. This is retention spend disguised as training spend.

A 6-person T3 internal team runs $1.8M–$2.8M annually fully loaded.

### Outsource vs. Insource

Insource when:

- The organization runs 6+ engagements per year (the breakeven point against retainer pricing).
- The work requires deep domain knowledge that takes more than one engagement to build (proprietary applications, OT, mainframe).
- Confidentiality requirements make external sharing of TTPs costly.
- The organization wants the team to influence the detection-engineering function continuously, not just at engagement boundaries.

Outsource when:

- The organization runs 1–3 engagements per year. The math does not work for an internal team.
- The team needs a specific specialty (industrial control, mainframe, satellite) that the internal team cannot justify hiring for full-time.
- Independence requirements from a regulator are easier to satisfy with an external firm.
- The organization is below T2 maturity and is not ready to manage an internal offensive function.

### Hybrid Models

The most successful T3+ programs are hybrids: a small internal team (4–6 FTEs) plus a retainer with an external firm for surge capacity and specialty work. The internal team owns continuity, infrastructure, and detection-engineering integration. The external firm provides extra operator capacity during peak periods and specialty expertise the internal team does not have.

The internal team should never compete with the retainer firm on engagement volume. They are complementary, not redundant.

## Tooling and Infrastructure as a Program

A mature red team treats infrastructure as a product, not as scratch space.

- **Owned vs. rented infrastructure.** C2 infrastructure should be owned and reusable across engagements with careful hygiene (no domain reuse across customers). Some teams build a domain inventory of 30–50 categorized domains that rotate.
- **C2 framework choices at the program level.** Standardize on a primary (Cobalt Strike, Brute Ratel, or Sliver) and a secondary for diversity. Operators should be fluent in both. Avoid framework sprawl — teams that run six different C2s spend more time on plumbing than on tradecraft.
- **Persistent lab.** A dedicated environment for tradecraft development. Mirrors production EDR/SIEM stacks. Operators test every payload here before it touches a customer environment.
- **Tradecraft library.** A private knowledge base — typically a Git repo or Obsidian vault — that captures TTPs, BOFs, evasion techniques, and engagement learnings. The library is the team's intellectual property and the reason senior operators stay.
- **Tooling budget cadence.** Annual review. New tools evaluated against the existing stack before purchase. No vendor relationships that create lock-in for engagement-critical functions.

## Threat-Informed Continuous Improvement

Threat-informed means each engagement starts from real intelligence about adversaries that target your sector — not from a list of TTPs the team finds interesting.

- **CTI integration.** Identify 3–5 intel sources that produce signal: Mandiant, Recorded Future, CrowdStrike, your sector ISAC, and CISA advisories. Map current adversary tradecraft to ATT&CK and use that map to scope engagements.
- **Actor tracking.** Pick 4–8 threat actors most relevant to your sector. Maintain a one-page profile per actor: known TTPs, recent activity, sector targeting. Refresh quarterly.
- **Atomic Red Team / CALDERA.** Run continuously in the lab and in pre-prod environments. Each new attacker technique discovered in CTI becomes an atomic test within 30 days.
- **Purple-team rotation.** Every third or fourth engagement. The blue team sits in the room. The output is detection rules, not findings.
- **Annual program review.** Once per year, audit the program's CTI coverage. Are you tracking the right actors? Are you testing the right techniques? Are your detection gaps shrinking?

## Board-Level Reporting

The quarterly board update is the single most important deliverable for program survival.

### Format

One deck. 8–12 slides. Read in 7 minutes. Discussed in 15.

- **Slide 1 — Headline metric.** "Detection coverage of FIN12-aligned TTPs improved from 34% to 52% this quarter."
- **Slides 2–3 — What was tested.** Plain English. No ATT&CK technique IDs.
- **Slides 4–5 — What we learned.** Two or three findings written as business risks, not technical issues.
- **Slides 6–7 — What changed because of us.** Specific detections shipped, controls hardened, processes updated.
- **Slide 8 — What is next.** The threat trajectory for the next quarter.
- **Appendix — Detail for the audit committee.** Compliance attestation, TIBER-EU/DORA closure references, MTTD trend, detection coverage heatmap.

### The "What Would Have Happened Against Us" Narrative

The most effective single rhetorical device for executive reporting:

> "If a real attacker with capabilities equivalent to what we tested had targeted us this quarter, they would have reached our customer database in 3.2 days, and we would not have detected them for 11 days. That is a meaningful improvement from last quarter, where they would have reached the same data in 14 hours and we would not have detected them at all."

This is risk language. It connects the team's work to outcomes the board understands.

### Avoiding Fear-Driven Funding Cycles

Do not run a red team program by scaring the board into giving you more money. It works for one or two cycles. Then a new CFO arrives, or a new CEO, and the story stops working. Fund the program on trend improvement, not on shock value.

If every board meeting features a new "we found a critical flaw" story, the board will eventually ask why the security organization keeps having critical flaws. The story has to be "we found this, we fixed it, here is the curve of risk going down."

### Risk-Reducing, Not Risk-Amplifying

Establish early that the red team is part of risk reduction, not part of the threat. Frame engagements in terms of reducing time-to-detect, increasing detection coverage, and improving incident response readiness. The team is part of the defense, not adjacent to it.

## Anti-Patterns

Common failure modes, from the field:

- **The "compliance check" red team.** The engagement is scoped to pass a regulator, not to find anything. Findings are negotiated down before the report is signed. Everyone gets a clean attestation. Nothing improves. This is the most common failure mode and the hardest to fix because the people paying for it want exactly this outcome.
- **The "we just want a clean report" customer.** Often internal. A business unit knows it has problems and wants a report that does not surface them. Resist by establishing in the charter that report contents are not negotiable.
- **Over-rotation toward novel TTPs at the expense of basics.** Operators want to develop new tradecraft. The team's job is to find what would actually be used against the organization. APT29 still uses spear phishing and credential reuse. Test the boring stuff first.
- **Operator burnout from compounding engagement load.** Six engagements per year per operator is unsustainable. Cap at four. Build cooldown into the calendar.
- **The "PR firm" red team.** Operators leak attempted-but-unauthorized targets to industry press, or brag about specific customer engagements at conferences. This is a career-ending offense and a program-ending offense. Enforce in the charter, in employment agreements, and in conference talk approval processes.
- **The "single-point-of-failure" senior operator.** One person owns all the tradecraft. When they leave, the team loses a year. Build the tradecraft library aggressively. Pair-program engagements. Rotate engagement ownership.
- **The "we own remediation" trap.** The red team finds a problem and then gets pulled into fixing it. This destroys the team's independence. Red team finds; another function fixes. Hold the line.

## Industry Comparisons

Different sectors run mature red team programs in characteristically different ways.

### Large Financial Services

Typical staffing at a tier-1 US/EU bank: 15–40 FTEs across operations, infrastructure, research, and intel. Regulator-driven cadence (TIBER-EU, CBEST, DORA, NYDFS, OCC). Heavy emphasis on independence from the SOC — typically dual-reporting to CISO and chief audit executive. Sector-level information sharing through FS-ISAC is active and reciprocal. Several large banks operate joint red team exercises across institutions to test sector-wide controls.

### Federal Civilian (US)

CISA's red team services (CRT) provide engagements for federal civilian agencies that lack internal capability. Larger agencies (DHS, Treasury, State) maintain internal teams of varying maturity. The DoD operates a different model with combatant-command-aligned red teams under USCYBERCOM.

Cadence is driven by FISMA, the Executive Order 14028 requirements, and agency-specific compliance regimes. Reporting flows to the agency CISO and to OMB/CISA aggregation. Findings are tracked across agencies for systemic risk identification.

### Tech-Sector Internal Teams

Companies like Google, Microsoft, Meta, and Amazon run multi-team red team functions with specialization (cloud, identity, supply chain, AI). Cadence is continuous. Public disclosure norms vary — Google's Project Zero discloses upstream, Microsoft's MSRC red team discloses internally and through CVE channels for vendor issues.

These teams operate at T4 maturity and produce significant public research. Talks at Black Hat, DEF CON, and Bsides are common and used as recruiting funnels.

### Defense Contractors

Cleared environments under CMMC (Cybersecurity Maturity Model Certification) have specific requirements for offensive testing of CUI-handling systems. Engagements are run under classified ROE in some cases. Findings reporting flows to the DoD program office and to DCSA. Independence from the host contractor's IT operations is contractually required.

## Resources

- CREST Red Team Guide — `crest-approved.org`
- TIBER-EU framework — `ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf`
- CBEST framework — `bankofengland.co.uk/financial-stability/financial-sector-continuity`
- DORA regulatory technical standards — `eba.europa.eu/regulation-and-policy/operational-resilience`
- MITRE Engenuity Adversary Emulation Library — `github.com/center-for-threat-informed-defense/adversary_emulation_library`
- Atomic Red Team — `github.com/redcanaryco/atomic-red-team`
- CALDERA — `github.com/mitre/caldera`
- SANS CAS-006 Red Team Operations — `sans.org/cyber-security-courses/`
- Ghostwriter (engagement management) — `github.com/GhostManager/Ghostwriter`
- VECTR (purple team tracking) — `github.com/SecurityRiskAdvisors/VECTR`
- Red Team Operator Career Path (CRTO) — `zeropointsecurity.co.uk`
- CISA Red Team Services — `cisa.gov/resources-tools/services/cisa-red-team-services`
- FS-ISAC — `fsisac.com`
- Related: [Red Team Operations Framework](/reporting/red-team-operations-framework/)
- Related: [Red Team Metrics & ROI](/reporting/red-team-metrics/)
- Related: [Executive Report Writing](/reporting/executive-report/)
