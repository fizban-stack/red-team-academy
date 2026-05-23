---
layout: training-page
title: "Metrics That Matter — MTTD, MTTR, % Objectives, Dwell — Red Team Academy"
module: "Reporting"
tags:
  - metrics
  - mttd
  - mttr
  - dwell-time
  - reporting
  - board
  - program-management
page_key: "reporting-metrics-that-matter"
render_with_liquid: false
---

# Metrics That Matter

Red team programs that report well get funded. Red team programs that report poorly get cut.

That sentence is the entire reason this page exists. I have watched two perfectly competent internal red teams get dissolved inside eighteen months because nobody on the team could put the right four numbers on a quarterly slide. I have also watched a mediocre team double its headcount because its program lead understood that the board does not buy "we got domain admin" — the board buys "time-to-detect went from eight hours to ninety minutes."

This is the operator-program-lead view of measurement. Not the consultant view. Not the vendor pitch. What the metrics actually mean when you run the function, what they look like on a real slide, and what they cost you when you measure the wrong thing.

Sister pages cover broader KPIs ([Red Team Metrics & ROI](/reporting/red-team-metrics/)) and the program scaffolding around them ([Red Team Program Maturity](/reporting/red-team-program-maturity/)). This page is narrower and more opinionated: four core numbers, a short list of secondaries, an even shorter list of metrics to refuse to report, and the framing that makes them legible to people who do not live in ATT&CK Navigator.

If you take one thing from this page: report trend, not snapshots. A single MTTD number is a data point. Four quarters of MTTD trending downward is a program.

---

## The Four Core Metrics

These are the four numbers that go on the headline slide every quarter. Every other metric on this page is in service of these four. If you cannot produce all four with defensible methodology, your program is not yet at Tier 3 maturity, and the rest of your dashboard does not matter.

### Mean Time To Detect (MTTD)

**Definition.** The average elapsed time between a red team malicious action and the first SOC alert that fires on it, measured per engagement and trended across engagements. Only detected techniques count toward the average — undetected techniques are tracked separately under detection rate. Mixing them produces a meaningless blended number.

**Measurement methodology.** Operators stamp every meaningful action with a UTC timestamp in the engagement log — initial payload execution, first credential dump, first lateral movement, first beacon callback after persistence. The blue team produces the corresponding alert timestamps from the SIEM. Reconciliation happens during the debrief, not during the engagement. Disputed timestamps go to the operator log first, SIEM log second — operator clocks have less drift on a controlled box than enterprise SIEM ingestion does on a bad day.

Two practices that pay for themselves within a quarter. Use NTP-synced operator hosts so the engagement log clocks are within a second of the SIEM clocks; this kills ninety percent of timestamp arguments before they start. Log every action through a single canonical sink — Ghostwriter, a shared engagement notebook, or a structured JSONL file in the team's tradecraft repo — rather than letting operators record actions in personal notes that have to be reconciled later. The reconciliation cost on per-operator notes is brutal. The reconciliation cost on a single sink with timestamps is approximately zero.

**Board-presentable format.** A single number per quarter, with the prior three quarters as context, paired with a trend arrow. "Q1: 8.2 hours. Q2: 6.1 hours. Q3: 4.3 hours. Q4: 2.8 hours. Trending down sixty-six percent year-over-year." That is the entire slide. Do not show the formula. Do not show per-technique breakdown on the board deck. The audit committee appendix can have the detail.

**Common gotchas.** Three that bite every program.

First, MTTD without a denominator population is meaningless — "our MTTD is forty-seven minutes" means nothing if you only detected four of forty-two techniques. Always pair MTTD with detection rate.

Second, MTTD is not symmetric across the kill chain. A four-hour MTTD on initial access is catastrophic; a four-hour MTTD on collection-exfiltration is excellent. Report a tiered MTTD when the audience can handle it.

Third, the clock should start at first malicious action, not at engagement kickoff. Teams that game this start the clock at "first noisy action" to make the number look better. The number that matters to the board is the one that maps to a real attacker — and a real attacker is loud the moment they execute code, not the moment they want to be loud.

**Worked example.** Engagement runs ten business days. Operators execute forty-two distinct ATT&CK techniques across initial access, execution, persistence, privilege escalation, defense evasion, credential access, lateral movement, collection, and exfiltration. Seventeen techniques produce at least one SIEM alert. The other twenty-five do not. The MTTD is the average elapsed time across those seventeen detected techniques, measured from operator-stamped action time to first alert time. If that average comes out to four hours and eleven minutes, the report reads "MTTD 4.2 hours across seventeen of forty-two techniques, detection rate forty percent." Three numbers, one sentence. The fourth-quarter trend slide then plots that 4.2 against the trailing three quarters and the picture is complete.

**What the slide actually says.** "Mean Time To Detect — Q4 2025: 4.2 hours. Trailing four quarters: 8.2, 6.1, 4.3, 4.2. Year-over-year improvement: forty-nine percent. Benchmark (financial-sector internal-detection median, M-Trends 2025): eight days. We are detecting an order of magnitude faster than the sector median." That is the whole slide. The audit committee reads it in eight seconds and asks one follow-up. The follow-up is in the appendix.

### Mean Time To Respond / Remediate (MTTR)

**Definition.** Two different numbers under the same acronym, and you must pick one and stay with it. MTTR-respond is the time from first alert to first containment action — host isolated, account disabled, network ACL pushed. MTTR-remediate is the time from finding delivery to the finding being closed in the ticketing system with verified fix. They are not the same. They do not trend together. Confusing them in a single deck is how program leads lose credibility in front of executives who actually understand incident response.

**Measurement methodology.** MTTR-respond comes from the SOC's IR ticketing system, cross-referenced with the engagement log. MTTR-remediate comes from the finding tracker (Ghostwriter or equivalent), measured from finding-delivered date to ticket-closed-verified date. Verified means the red team retested. A closed ticket without retest is a closed ticket against a fix that may or may not exist.

**Board-presentable format.** Both, on the same slide, labeled clearly. "Time to contain (detected incidents): twenty-three minutes median. Time to remediate (red team findings): thirty-seven days median." Two numbers, two definitions, two trend arrows. Do not let executives think they are the same number measured differently.

**Common gotchas.** MTTR-respond is almost always faster than the program assumes, because the SOC ticketing system already tracks it well. MTTR-remediate is almost always worse than the program assumes, because findings ship to the engineering org and disappear into backlogs. The honest MTTR-remediate number is often forty-five to ninety days for high-severity findings — and that number being public, on the slide, is the lever that gets engineering attention. Hiding the number protects the engineering org from accountability. Do not hide the number.

The most common political failure I have watched: an engineering VP asks the program lead to "smooth out" the MTTR-remediate number by excluding tickets that were blocked on third-party vendor fixes, blocked on architectural decisions, or blocked on budget. Refuse every one of those exclusions. A ticket blocked on a vendor fix is still an open finding from the attacker's perspective. The vendor does not care about your remediation deadline. Neither does the attacker. The board cares whether the finding is closed, and the only honest closed-state is "fix shipped, red team retested, vulnerability confirmed remediated." Anything else is theater.

**What the slide actually says.** "Time to contain — Q4 2025: twenty-three minutes median, n equals fourteen incidents. Time to remediate — Q4 2025: thirty-seven days median for high-severity findings, n equals nine. Trailing four-quarter trend on time-to-remediate: 62, 51, 44, 37 days. Trending down forty percent year-over-year, driven by the detection-engineering integration program that shipped in Q2." Two numbers, two trend lines, one causal attribution. The program lead earns credibility by attributing the trend to a specific intervention rather than to luck.

### Percent Objectives Achieved

**Definition.** Of the in-scope objectives written into the engagement SOW, the percentage the red team reached without operating out of scope. Cap at one hundred percent. Overachievement — "we achieved one hundred forty percent of objectives" — is a scoping failure, not a victory. It means the scoping conversation was too easy and the next engagement needs harder objectives.

**Measurement methodology.** Objectives are written into the SOW before kickoff and signed off by the customer or business sponsor. They are specific, measurable, and binary: "obtain read access to the customer-PII data lake," not "demonstrate impact." During the engagement, objectives are marked achieved, partially achieved, or not achieved. Partial achievement is recorded honestly — "reached the data lake but could not exfiltrate due to DLP" is partial, not full.

**Board-presentable format.** Two numbers side by side: percent achieved this quarter, percent achieved averaged over the trailing four quarters. The trend is what matters. A mature program watches this number decrease over time as defenses harden. If you achieve every objective every engagement, your scoping is too soft and your board is being lied to about how hard the organization is to break into.

**Common gotchas.** The number is meaningless without scope discipline. A red team that scopes itself five trivial objectives and achieves all five reports one hundred percent and learns nothing. A red team that scopes three objectives at the threat-actor-realistic level and achieves one reports thirty-three percent and learned three times more. The board does not understand this distinction unless the program lead surfaces it explicitly. Every quarterly report should include one sentence on objective difficulty: "Objectives this quarter were calibrated to FIN12-equivalent tradecraft. Last quarter, objectives were calibrated to commodity-ransomware tradecraft."

A second gotcha specific to internal teams: business sponsors will quietly push for softer objectives over time because soft objectives produce reports that flatter the sponsor's organization. Resist by anchoring objective calibration to the CTI brief, not to the sponsor conversation. The threat-actor profile drives the objective set. The sponsor approves scope and ROE; the sponsor does not get to negotiate down what realistic tradecraft looks like. If you let sponsors calibrate objectives, the metric becomes a measure of sponsor comfort, not of organizational resilience.

**What the slide actually says.** "Percent objectives achieved — Q4 2025: forty-three percent (three of seven objectives fully achieved, one partial, three not achieved). Trailing four-quarter average: fifty-two percent. Year-over-year trend: declining as objective difficulty calibrates upward against FIN12-tier tradecraft. The declining number is the desired direction; it indicates the defensive posture is hardening against the tradecraft we are simulating." That last sentence is the most important one on the slide. Boards read declining numbers as bad news unless the program lead explicitly reframes the direction.

### Dwell Time Achieved

**Definition.** The maximum continuous duration the red team maintained undetected access during the engagement, from initial successful action to first credible blue-team detection. If the team was detected on day one and re-established on day three undetected for two more days, dwell is two days, not five. Continuous matters. The threat model is "would an attacker have stayed in undetected" — and an attacker who gets bounced and re-establishes is a different threat than an attacker who was never detected.

**Measurement methodology.** From the engagement log: the timestamp of the first action that produced lasting access, and the timestamp of the first SOC detection that would have prevented that access from continuing. If no detection occurred, dwell equals the engagement duration. Report that explicitly: "Dwell time: full engagement duration, twelve days. No credible detection produced."

**Board-presentable format.** A single number per engagement, trended across the year. "Dwell time, last four engagements: twelve days, eight days, five days, three days. Trending down seventy-five percent." This is the single most viscerally compelling number for a board. It maps directly to industry benchmarks (Mandiant M-Trends global dwell-time medians) and answers the question every board member is actually asking: "how long could someone be inside us right now without us knowing?"

**Common gotchas.** Three again, because dwell is the metric most vulnerable to misreporting.

First, scoping games. A team that runs a three-day engagement reports a three-day maximum dwell and looks better than a team that runs a twenty-one-day engagement and reports twelve. The honest move is to report dwell as a percentage of engagement duration alongside the raw number. "Twelve days of undetected dwell across a twenty-one-day engagement, fifty-seven percent of engagement duration." That is the apples-to-apples version.

Second, dwell is not detection. A blue team that detects on day eleven and does not contain until day fourteen has a three-day MTTR-respond and an eleven-day dwell. Both numbers are correct, both numbers matter, and they are not the same.

Third, dwell time achieved against a red team is a lower bound on attacker dwell, not an upper bound. A real attacker has unlimited time, unlimited patience, and no engagement end date. Twelve days of red team dwell does not mean a real attacker would be detected on day thirteen — it means the red team did not stay long enough to find out. Report dwell with that caveat in the appendix, every quarter, without exception.

**What the slide actually says.** "Maximum undetected dwell — last four engagements: twelve days, eight days, five days, three days. Trending down seventy-five percent year-over-year. Sector benchmark (M-Trends 2025 financial-sector internal-detection median): eight days. We are now detecting faster than the sector median. Caveat: dwell is a lower bound; a real attacker would persist beyond engagement end." Five sentences. Trend, benchmark, caveat. The caveat sentence is what separates a credible program from a program that gets caught overclaiming when an auditor finally asks the right question.

---

## Secondary Metrics

These do not go on the headline slide but they belong on the appendix slide and on the SOC's quarterly review. They are how the security organization actually improves.

- **Detection coverage improvement (per engagement delta).** Per ATT&CK technique, what percentage of previously-undetected techniques became detected between this engagement and the prior one? A T3 program ships net-positive numbers every quarter. A program that ships zero or negative deltas is not learning, and you should investigate whether findings are actually reaching the detection engineering team or dying in a ticket queue.
- **Recurring findings, with root-cause attribution.** A finding that appears in three consecutive engagements is not a finding. It is a process failure. Track recurrence with a one-line root cause: "remediation deferred for budget reasons," "fix shipped but bypass discovered," "owner left the company." Recurring findings reported without root cause look like the red team is finding the same thing over and over because they are not creative. Recurring findings reported with root cause look like the security organization has a remediation pipeline problem. Same finding, different conclusion. Always report the root cause.
- **Engagement-to-engagement detection improvement.** A scorecard, not a number. Per ATT&CK technique tested in both engagements, did the SOC's detection capability improve, stay flat, or regress? Regressions are the most important data point on this page. A regression — detection that worked last quarter and does not work this quarter — almost always indicates a SIEM-rule change, a tooling migration, or a SOC-team turnover event that nobody flagged. Surface them aggressively.
- **Defender capability uplift score (purple-team specific).** For purple-team engagements only: count of new production detections produced as a direct result of the engagement. Production means committed to the SIEM detection repo, tested, and in active rotation. Draft rules do not count. A purple-team engagement that produces fewer than three production detections is a failed purple-team engagement and the program lead should ask why.
- **Time-to-first-detection (separate from MTTD overall).** The single number for the very first detected technique in the engagement. This is the answer to "how long before the SOC noticed anything was happening at all," which is a different question from "what is the average detection time across all techniques." Time-to-first-detection trending down means the SOC's tripwires are improving. It can move independently of MTTD, and watching both is more informative than watching either alone.

---

## Anti-Metrics — Do Not Report These

A list of metrics that look meaningful, get adopted by programs that have never been audited by a real CFO, and produce the wrong incentives every time.

- **Number of engagements run.** On its own, this is volume not value. A team that runs twelve shallow engagements is worse than a team that runs four deep ones. The instant you put engagement count on a slide, you have created an incentive to run shallow engagements. Refuse.
- **Number of CVEs filed.** CVE filing is research output. Mixing it with red team output inflates apparent productivity and dilutes the program's identity as an internal-risk-reduction function. If the team does novel research, report it separately under a research-output line. Do not let it contaminate the red team scorecard.
- **Hours spent on engagement.** Volume not value. Tracking operator hours is a chargeback-accounting trap that turns the team into a billable-utilization shop and destroys the strategic latitude that makes red teams useful. Refuse chargeback accounting in the charter if you can. If you cannot, report hours only to finance, never to the security leadership team.
- **Number of findings.** A 200-finding report is almost always worse than a 12-finding report. It means the team did not prioritize, which means the customer cannot prioritize either. The metric that matters is severity-weighted finding count, and even that is better presented as risk-reduction trend than as a raw number.
- **Pass / fail per engagement.** Some programs adopt a binary "red team passed / blue team passed" framing per engagement. This gamifies the entire function in the worst possible way. The red team's job is not to "win." The red team's job is to produce signal that improves the security organization. Pass/fail framing turns engagements into adversarial sport and breaks the relationship with the blue team within two cycles.
- **Detection coverage of the full ATT&CK matrix as a single percentage.** A program that reports "we have detection coverage of forty-three percent of ATT&CK" is reporting noise. The full matrix is not equally relevant to every organization, and uniform coverage is not the goal. Report coverage against the techniques in your CTI brief, against the techniques tested in the last four engagements, or against the techniques associated with the actors most likely to target your sector. A single full-matrix number invites the executive question "why isn't it one hundred percent" — and the answer requires twenty minutes of nuance that does not survive a board meeting.
- **Operator-level rankings.** Some programs build internal scoreboards ranking operators by techniques executed, objectives achieved, or dwell time produced. This destroys the team within a year. Operators stop sharing tradecraft, stop helping each other on hard engagements, and start optimizing for the scoreboard instead of for the customer outcome. Track operator performance through engagement review and 1:1 conversation. Never through public ranking.

---

## Board-Level Framing

The board does not care about the red team. The board cares about risk. The red team report is interesting to the board only insofar as it answers "how exposed are we, and is that getting better or worse."

The single most effective rhetorical device is the "what would have happened against us" narrative. Concrete, plain English, mapped to a real adversary, with a year-over-year delta. Example: "If a real attacker with capabilities equivalent to FIN12 had targeted us this quarter, they would have reached the customer-PII data lake in approximately three days, and we would not have detected them for eleven days. Last quarter, those numbers were fourteen hours and never. We are reducing dwell time meaningfully and we are now detecting attackers we previously would have missed entirely." That is the slide. Two sentences. Two adversary-anchored numbers. One delta.

Avoid fear-driven funding cycles. The temptation is to lead every board update with the scariest finding of the quarter. It works once. It works a second time. By the third quarter, the audit committee starts asking why the security organization keeps finding critical flaws, and the program loses credibility. Fund the program on trend improvement, not on shock value. Save the scary finding for the appendix, where it belongs as context for the trend.

Establish the program as risk-reducing, not risk-amplifying. The red team is part of the defense. It is not a separate threat. Frame every engagement in terms of detection coverage improved, MTTD reduced, dwell shortened, findings remediated. The team is a control, not an attacker — even when the team's day-job is being an attacker.

One framing trick that I have watched work in three different board rooms: present every metric as a delta against a peer-institution benchmark when possible. "Our dwell time is three days. The financial-sector median is sixteen days. We are detecting an order of magnitude faster than our peers." Board members respond to peer comparison in ways they do not respond to absolute numbers, because peer comparison is how they evaluate every other function in the organization. If you have access to ISAC-shared data or industry survey data, use it. If you do not, use the public benchmarks from M-Trends and DBIR and call out the methodology delta in the appendix.

---

## Per-Engagement vs Trend

Single-engagement numbers are noisy. A team that detects forty-seven percent of techniques in one engagement and twenty-two percent in the next has not regressed by twenty-five points — it has run two engagements against different scopes, against different operators, against different blue-team shift rotations. The variance between two adjacent engagements is structurally larger than the year-over-year trend that the program is actually measuring. Reporting single-engagement numbers as if they were trend signal is one of the most common credibility-destroying mistakes a junior program lead makes.

The only numbers that survive scrutiny at the board level are trend lines. Four quarters of MTTD trending downward is a program. One quarter of low MTTD is a data point. Always report at least the trailing four quarters on every headline metric, and always anchor the current number against the trailing average, not against a single prior period.

The exception is benchmark comparison. A single-engagement number can be meaningfully compared to an industry benchmark (Mandiant M-Trends global median dwell time, for example) and that comparison is useful even without a trend. "Our dwell time this engagement was three days, against a global financial-sector median of sixteen days per Mandiant M-Trends 2025." That sentence on its own gives the board a reference point.

The right combination on a slide is current number, four-quarter trend, and benchmark comparison. Three data points. Six seconds to read. That is the engineering target for board metrics.

A practical pattern that I have seen work across multiple programs: every headline slide has the current quarter's number in large type, the trailing four quarters as a small sparkline immediately to the right, and the benchmark as a horizontal reference line on the sparkline. The viewer sees the number, the direction, and the calibration in a single visual fixation. There is no second slide on the same metric. There is no detail beyond the appendix. If a board member wants more, the program lead has the appendix ready. If no one asks, the program has saved fifteen minutes of meeting time and the next item gets discussed.

**Worked example of trend versus snapshot.** Engagement A in Q2 produces MTTD of 3.1 hours against thirty-eight techniques tested, detection rate of forty-five percent, dwell of five days. Engagement B in Q3 produces MTTD of 5.8 hours against twenty-two techniques tested, detection rate of twenty-seven percent, dwell of nine days. Read as snapshot, the program has regressed dramatically — MTTD nearly doubled, detection rate dropped eighteen points, dwell increased eighty percent. Read as trend with context, the engagements tested different parts of the kill chain against different operators, and the trailing four-quarter MTTD trend is still 8.2, 6.1, 4.3, 4.5 — a slight quarter-over-quarter uptick within a strongly improving annual trend. The program lead who reports the snapshot regression panics the board. The program lead who reports the trend explains the calibration and protects the credibility. Same data, two completely different stories. Always tell the trend story; carry the snapshot in the appendix in case anyone asks.

---

## Industry Benchmarks

Public reporting provides reference points. Use them carefully — methodology differs across reports, and a Mandiant median is not directly comparable to a Verizon median is not directly comparable to a CrowdStrike median.

Approximate ranges from the major public sources at the time of writing:

- **Global median dwell time (Mandiant M-Trends).** Trended from over four hundred days in the mid-2010s to under twenty days in recent reporting for externally-detected intrusions, and roughly half that for internally-detected ones. This is the benchmark every program lead should know.
- **Breakout time (CrowdStrike Global Threat Report).** The time from initial compromise to first lateral movement. Reported in minutes for top-tier actors. Useful as a calibration point for what your red team should be able to achieve on a sophisticated engagement.
- **Breach detection sources (Verizon DBIR).** The percentage of breaches detected internally versus by external parties. A program that improves the internal-detection percentage is doing the work.
- **Detection coverage of ATT&CK techniques (MITRE Engenuity ATT&CK Evaluations).** Per-vendor detection rates across emulated adversary scenarios. Useful for calibrating vendor pitches and for benchmarking your own SOC against the EDR vendors' best-case results.
- **Recovery time (IBM Cost of a Data Breach Report).** The average time from breach detection to containment, broken out by industry and geography. The number is consistently in the high double digits of days for under-prepared organizations. Use it as a forcing function for the MTTR-respond conversation with the SOC leadership.
- **Sector-specific actor profiles (ISAC reports).** FS-ISAC, H-ISAC, MS-ISAC, and the various critical-infrastructure ISACs publish sector-tuned threat-actor intelligence that is materially more relevant than the global reports for any organization inside that sector. The trade-off is paywalled access and methodology variance across ISACs. Worth the friction.

Two caveats on benchmark comparison. First, the published medians are skewed by the sample — companies that hire Mandiant or CrowdStrike for incident response are not a representative slice of the global enterprise. Adjust mentally. Second, every report has methodology footnotes that matter. Read them once a year. Use them in the appendix slide when an executive challenges your numbers — being able to say "Mandiant defines dwell as X, we define dwell as Y, here is the reconciliation" earns more credibility than any individual number.

A third caveat that matters less often but matters a lot when it does: industry benchmarks lag the threat landscape. Mandiant's 2025 report describes the threat landscape that Mandiant's customers experienced in 2024. The actors, techniques, and tradecraft that will define the next twelve months are not in the benchmark yet. Programs that calibrate purely against last year's published benchmarks systematically underweight emerging actors and overweight legacy ones. Read the benchmarks; do not let them set the entire scope conversation.

---

## Operational Hygiene

The metrics are only as good as the operational discipline behind them. Three things to get right:

- **Dashboard cadence.** Quarterly board, monthly security leadership, weekly internal team. The board deck is built from the leadership deck which is built from the internal scorecard. Single source of truth. If the numbers diverge between layers, the numbers are wrong somewhere and the program lead has a fire to put out before the next board meeting.
- **Reporting integration with the SIEM/SOAR.** Engagement logs and SIEM logs should reconcile automatically wherever possible. Manual reconciliation is acceptable for the first year of a program and unacceptable thereafter. Detection-engineering deliverables (Sigma rules, KQL queries, Splunk searches) ship as PRs into the SOC's detection repo, not as appendices in a Word doc. The PR is the deliverable.
- **Detection rule lifecycle tied to engagement findings.** Every finding that has a detection-engineering component (most of them) gets a tracking ticket against the detection repo. The ticket has an owner on the SOC side, a target ship date, and a retest requirement before close. The retest is run by the red team in the following engagement. A detection rule that ships and is not retested does not count toward detection coverage improvement.
- **Quarterly metric audit.** Once per quarter, the program lead spends a half-day re-walking every published number against its source data. Wrong numbers found in the audit are corrected publicly in the next reporting cycle. Wrong numbers found in the wild — by an executive, an auditor, or a regulator — are program-credibility events. The audit is cheaper than the credibility event by two orders of magnitude. Schedule it on the calendar; protect it from being skipped.
- **Tooling that survives the operator who built it.** Engagement-tracking tools, finding databases, and metric dashboards should be set up so that any operator on the team can rebuild the current quarter's numbers from raw data inside a day. Custom spreadsheets owned by one operator are a single-point-of-failure waiting for that operator to leave. Ghostwriter for engagement and finding management, VECTR for ATT&CK coverage, a structured metrics dashboard built on the SIEM data lake — pick the boring, well-supported, multi-operator-friendly tooling and stick with it.

The discipline around these three is the difference between a metrics program that survives a CISO change and one that does not. A new CISO who arrives and finds a clean monthly scorecard, automatically reconciled with the SIEM, with detection PRs landing in the repo and being retested — that new CISO does not cut the red team. A new CISO who arrives and finds quarterly slide decks with hand-counted numbers and no auditable trail — that new CISO has a budget line to cut by Friday.

---

## Calibration and the Trust Budget

Every metrics program has a trust budget with executive sponsors. The trust budget is built over years and spent in minutes. The single fastest way to burn it: publish a number that an auditor or a competent skeptic can pick apart in the meeting.

Three calibration practices that protect the trust budget.

**Methodology document per metric.** Every headline metric has a one-page methodology document, written in plain English, signed by the program lead, available in the appendix of every quarterly deck. The document defines the metric, the data sources, the inclusion and exclusion rules, the time-bucketing convention, and the known limitations. Any executive who challenges a number can be handed the methodology page and the conversation moves from "I do not believe this number" to "I do not believe this methodology" — which is a real conversation and a survivable one.

**Sample size disclosure with every reported number.** Every metric reported to the board has a confidence interval or a sample-size disclosure. "MTTD 4.2 hours, n equals seventeen detected techniques" is more defensible than "MTTD 4.2 hours." When n is small, the confidence interval is wide, and saying so out loud is what separates an honest program from a program that is one bad question away from being audited.

**Whiteboard-defensibility rule.** Refuse to report metrics you cannot defend on a whiteboard. If you cannot reconstruct the number from the underlying data in five minutes in front of an auditor, the number is not ready to leave the team. The temptation to publish a directionally-correct number ahead of the methodology is constant and is always wrong. A delayed metric with defensible methodology costs the program less than a fast metric that gets challenged and falls apart.

The trust budget is also why every program should publish corrections in public. If a number was wrong in the previous quarter's deck, the corrected number appears in the current quarter's deck with a one-line acknowledgement. "Q2 MTTD was reported as 3.8 hours; correct value is 4.1 hours; reconciliation error in SIEM ingestion timestamps." This is the single most credibility-positive action a program lead can take. Boards trust programs that publish corrections. Boards stop trusting programs that quietly restate numbers without acknowledgement.

---

## The "Did We Get Better" Question

Once a year, usually at the annual board cycle or the annual budget review, someone with authority will ask the only question that matters: "Are we more secure than we were last year, and how do you know?"

The credible answer has four parts. First, the trend on every core metric — MTTD, MTTR, percent objectives achieved, dwell time. Second, the delta in detection coverage across the ATT&CK matrix. Third, the count of recurring findings that were resolved this year and removed from the recurrence list. Fourth, the count of high-severity findings that did not exist a year ago, contextualized against the threat landscape — new findings against new technology is normal, new findings against existing technology is a regression in coverage.

The non-credible answer is "we got into more systems than last year." That is volume. It is not improvement. If anything, it is worse — a red team that gets into more systems against the same defenders is reporting that defenders are not learning from the engagements.

The credible answer requires the entire metrics program to be in place — the four core numbers trended quarterly, the secondary metrics tracked, the anti-metrics refused, the trend separated from the snapshot, the engagement results reconciled with the SIEM, the detection PRs shipped and retested, the recurring findings attributed to root cause. The answer is the output of the system. The system is the work. Get the system right and the annual question becomes easy. Skip the system and the annual question becomes the answer to "why are we cutting the red team this year."

The honest version of the annual answer is sometimes "no." Some years the threat landscape outruns the program. Some years a major reorganization rotates SOC personnel and detection capability regresses while the team rebuilds. Some years the board approves an acquisition that brings in an entire shadow IT estate and the attack surface doubles overnight. When the honest answer is "no, we did not get better this year, and here is why," that answer is more credible than a fabricated yes. Boards remember the program lead who said "no" once and was right, longer than they remember the program lead who said "yes" every year regardless of evidence. Credibility compounds. The metrics program is the substrate on which credibility compounds. Build it correctly and protect it ruthlessly.

The annual answer also requires a forward statement. "Here is what we will measure better next year. Here is the gap we identified this year that we did not have visibility into. Here is the metric we are adding to the dashboard because we discovered we were not tracking something that matters." The forward statement is what differentiates a metrics program that learns from one that calcifies. A program that reports the same four metrics with no methodology evolution for three years in a row has stopped learning. The board may not notice for two years; the auditor will notice the first time they look closely.

---

## Metric Maturity by Program Tier

Different program maturity tiers should report different metrics. A T1 program reporting like a T4 program is overreaching; a T3 program reporting like a T1 program is underdelivering. Pick the right metric set for the tier.

**Tier 1 — Annual external engagement.** Report what the engagement produced. One MTTD number per engagement. One detection rate per engagement. A list of findings with severity. No trend yet because there is no trend yet — one engagement per year does not produce a trend. The honest framing is "we tested once, here is what we learned, here is what we are doing about it before next year."

**Tier 2 — Internal team or sustained retainer.** Three to six engagements per year is enough to start trending. Report MTTD as a quarterly average, detection rate as a quarterly average, percent objectives achieved per quarter. Dwell may still be too variable for a stable trend; report it per engagement with explicit caveats. The board package starts to look like a real program package at this tier.

**Tier 3 — Continuous testing with purple-team integration.** Full four-metric headline package. Trailing four-quarter trend on every metric. Benchmark comparison where the data supports it. Detection-engineering deliverables tracked through the SOC's repo. Recurring findings tracked with root-cause attribution. This is the tier where the metrics program starts producing forward signal about where the security organization needs to invest.

**Tier 4 — Optimized, business-aligned, predictive.** Everything in T3, plus predictive metrics. Forward-looking MTTD projection based on the threat-actor profile the team is tracking. Risk-adjusted detection coverage that weights techniques by likely-attacker probability. Sector-comparative dwell time that anchors the program against ISAC peers. At T4 the metrics program is contributing to enterprise risk reporting, not just to the security organization's internal dashboards.

The progression is not optional. A T1 program that tries to publish T4 metrics will be caught the first time an auditor or a competent CFO asks for the underlying data. A T4 program that publishes T1 metrics is failing to use its capability. Match the metric set to the tier, and let the metric set evolve as the program matures.

---

## Putting It All Together

The minimum credible quarterly board package, in one paragraph, for a program lead to use as a checklist: four headline metrics on one slide each (MTTD, MTTR-respond and MTTR-remediate, percent objectives achieved, dwell time), with current number, trailing four-quarter trend, peer benchmark, and one-sentence interpretive context. A "what would have happened against us" narrative slide that translates the headline metrics into a real-attacker scenario calibrated to a current threat actor. A secondary-metrics appendix slide for the audit committee. A methodology appendix that defines every published number. A corrections-from-prior-quarter section if any corrections apply. Eight to twelve slides total. Reads in seven minutes. Discussed in fifteen. Survives a CISO change, an auditor visit, and a regulator inquiry.

The maximum credible package is the same package, with a few additions: a sector-comparison slide if ISAC data is available, a forward-looking risk briefing on the threat-actor profile shifts the team is tracking, and a research-output slide if the team produces public research. Never more than fifteen slides for the board. The detail lives in the SOC's monthly review and the team's weekly scorecard, not in the board deck. Discipline up the chain protects discipline down the chain.

The metrics that matter are the metrics that survive scrutiny. Four numbers, trended, benchmarked, attributed to interventions, defended with methodology, corrected publicly when wrong, refused when they would mislead. Everything else on this page is in service of those four numbers being defensible the next time someone with authority asks "are we more secure than we were last year, and how do you know?"

---

## Resources

- Mandiant M-Trends Annual Report — `mandiant.com/m-trends`
- Verizon Data Breach Investigations Report (DBIR) — `verizon.com/business/resources/reports/dbir/`
- CrowdStrike Global Threat Report — `crowdstrike.com/global-threat-report/`
- MITRE Engenuity ATT&CK Evaluations — `attackevals.mitre-engenuity.org`
- MITRE ATT&CK Navigator — `github.com/mitre-attack/attack-navigator`
- VECTR (purple team and ATT&CK coverage tracking) — `github.com/SecurityRiskAdvisors/VECTR`
- Ghostwriter (engagement management and finding tracking) — `github.com/GhostManager/Ghostwriter`
- CISA Cybersecurity Performance Goals (program-level metrics framework) — `cisa.gov/cross-sector-cybersecurity-performance-goals`
- Related: [Red Team Metrics & ROI](/reporting/red-team-metrics/)
- Related: [Red Team Program Maturity](/reporting/red-team-program-maturity/)
- Related: [Executive Report Writing](/reporting/executive-report/)
- Related: [Red Team Operations Framework](/reporting/red-team-operations-framework/)
