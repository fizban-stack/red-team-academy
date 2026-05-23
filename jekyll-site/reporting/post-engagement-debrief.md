---
layout: training-page
title: "Post-Engagement Debrief Framework — Red Team Academy"
module: "Reporting"
tags:
  - debrief
  - lessons-learned
  - purple-team
  - retrospective
  - blue-mirror
page_key: "reporting-post-engagement-debrief"
render_with_liquid: false
---

# Post-Engagement Debrief Framework

The most valuable hour of an engagement is the debrief. The most-skipped hour of an engagement is the debrief.

We finish six weeks of operations. We write a 90-page report. We deliver the PDF, invoice the client, and move on. Then we wonder why the same control gaps show up at the same customer next year. The technical report tells the customer what happened. The executive report tells them how bad it is. The debrief is what tells them what to do about it — and it is the only artifact in the entire engagement that gives the red team the data needed to actually get better.

This page is the reusable framework I run for every engagement: who attends, the agenda for each session, the artifacts we produce, the questions that change the outcome, and the anti-patterns that turn a useful debrief into a sales meeting.

## Why the Debrief Matters

A written report is a one-way channel. The reader gets your conclusions but cannot ask follow-up questions, cannot watch you demonstrate the technique, and cannot push back when something doesn't match what they saw on their end. The debrief closes that loop.

Four reasons it exists, in order of how often I cite them:

- **Knowledge transfer to defenders.** SOC analysts, detection engineers, and IR leads learn more in ninety minutes of operator Q&A than they do reading the full report. They get to ask "what did you see when our EDR fired" and you get to show them.
- **Real-time tradecraft Q&A.** High-bandwidth conversation lets defenders probe edges the report can't cover — "would your beacon have survived if we'd had AppLocker in audit-only mode?" — and you get to answer honestly.
- **Surfacing political constraints.** Half the reason a control isn't deployed is political, not technical. In the room, the CISO will tell you the EDR rollout is blocked by the desktop team's change freeze. That context never makes it to the report, and it changes your recommendations.
- **Lessons-learned for the red team.** Every engagement is data for our own program. What detection capabilities surprised us? What tradecraft needs a library entry? What customer dynamics caught us off-guard? Captured at the debrief, used on the next engagement.

If you only remember one thing from this page: the debrief is where compounding improvement happens. Skip it and you're running the same engagement, with the same gaps, year after year, just with different logos on the cover sheet.

## Two Audiences, Two Meetings

One debrief cannot serve both technical operators and executives. Trying to do it as a single meeting produces a deck that's too shallow for the SOC and too technical for the board. Run two separate sessions, in this order:

- **Operator-to-operator debrief** — SOC leadership, IR leads, detection engineering, AppSec, the network team. Red team operators present. 90 minutes minimum, two hours preferred.
- **Executive debrief** — CISO, CIO, sometimes CEO or board sub-committee. Red team lead and engagement manager present. 30 minutes, strict.

Run the operator session first. The executive session uses material refined during operator Q&A, and the CISO benefits from hearing their own team's reactions before walking into the boardroom. If the executive session has to happen on the same day, schedule a one-hour buffer between them so you can update your slides based on what came out of the operator room.

## Operator-to-Operator Debrief

### Attendees — Who Must Be There

- SOC lead or senior analyst who worked the engagement window — not the manager who was on PTO
- IR / detection engineering lead — the person who would write the new Sigma rule
- Identity / Active Directory team representative — for any AD-heavy engagement
- Network team representative — for any pivoting, egress, or DNS work
- AppSec lead — for any web or API findings
- The actual operators from the red team — not just the engagement lead reading from notes

### Who Must Not Be There

- Anyone whose job is to defend their team's reputation. If the SOC manager spent the engagement window pointing fingers at the EDR vendor, they will do the same here. Push for the working-level lead instead.
- Sales. From either side. The room collapses to performance theater the moment a quota carrier walks in.
- Auditors looking for evidence of negligence. The debrief is a learning environment. If audit needs material, they get the report, not the room.
- Legal, unless something material happened during the engagement that requires their presence. Their job in the room is to make people careful about what they say, which is the opposite of what we want.

### Agenda — 120 Minute Block

I block two hours, target ninety minutes, and stop at the hundred-twenty-minute mark whether we're done or not. Energy collapses past that.

- 0:00 — 0:10 — Rules of the room. Blameless retrospective framing. Chatham House for any specifics.
- 0:10 — 0:35 — Timeline walkthrough. Day-by-day. What we did, when, from where.
- 0:35 — 1:05 — Technique-by-technique. For each major step (initial access, foothold, escalation, lateral, exfil) walk through the technique, show the telemetry it produced, and ask the SOC what they saw.
- 1:05 — 1:20 — Live tool demonstration. Recreate one beacon callback, one Kerberoast, one whatever-they're-most-confused-about in real time.
- 1:20 — 1:35 — The "what made you nervous" question.
- 1:35 — 1:50 — Detection engineering deliverables walkthrough.
- 1:50 — 2:00 — Open Q&A and next-steps capture.

### Live Tool Demonstration

Offer to recreate something on the spot. A beacon callback. A Kerberoast TGS request. An LDAP enumeration query. Whatever the defenders were most uncertain about in the report.

Use a lab VM, not the customer environment, but show the actual tooling — Sliver, Rubeus, Impacket, whatever you used in the engagement. Walking defenders through your screen as you type the command, while they pull up their SIEM dashboard on a second monitor, is worth ten pages of report prose. Most operators skip this because it's intimidating. Do it anyway. The handful of customers I've worked with where the SOC ended up writing meaningful new detections every quarter — every single one of them — had operators who ran the live demo.

### The Most Valuable Question

At some point during the walkthrough, look at the SOC lead and ask: *"What made you nervous?"*

The answer is the most actionable piece of intelligence in the entire engagement. Not what they caught — what made them lean forward. What query result made them stop and double-check. What sequence of events almost crossed their threshold but didn't quite. That's the gap. That's where the next investment goes. Write down the literal quote.

If they say "nothing made us nervous, we caught everything," they didn't catch everything. Ask "what alert volume did you see during weeks two and three?" and watch them realize you ran an entire phase of the engagement that never generated a ticket.

### Detection Engineering Deliverables

Do not leave the room without committing to deliver, within five business days:

- A per-technique signal map — what telemetry the engagement produced, by ATT&CK technique ID
- Sample SIEM queries (Splunk SPL, KQL, Elastic ES|QL — match the customer's stack)
- Recommended Sigma rules — generic, then a translation note for their platform
- Atomic Red Team test IDs that exercise each technique, so they can run regression
- A short README explaining how to run those tests safely on a non-production segment

These are the deliverables that close the loop. The report is the diagnosis. These are the prescriptions.

## Executive Debrief

### 30 Minute Structure

Executives do not have an hour. Plan for 30 minutes, deliver in 25, leave 5 for questions.

- 0:00 — 0:03 — Engagement framing. Scope, dates, rules of engagement, what success looked like.
- 0:03 — 0:08 — Overall posture statement. One sentence: red, amber, green. Then the supporting narrative.
- 0:08 — 0:15 — Breach narrative. The story of the engagement, told as a story, no acronyms.
- 0:15 — 0:22 — Top three recommendations with rough cost and effort.
- 0:22 — 0:25 — Threat model update — what changed about how you think about adversaries.
- 0:25 — 0:30 — Q&A.

### Business-Impact Framing

Same rule as the executive report: every technical finding maps to a business risk. In the debrief you say it out loud. Not "we got Kerberoast-able service accounts." You say: "a standard intern account could have ransomware on every endpoint in six hours, undetected." Then you stop talking and let it land.

Three rules for executive framing in the room:

- **Lead with what an attacker could do, not what we did.** "An attacker could have shut down payroll processing for a week" lands harder than "we obtained Domain Admin via Kerberoasting."
- **Use comparable incidents.** "This is the same entry point used in the Colonial Pipeline incident" is a sentence the CISO will repeat at the board meeting next week. Give them the comparison.
- **Never use an acronym you haven't defined.** The C-suite will not stop you to ask what TGS means. They will nod and lose interest. Define MFA, EDR, AD — every time, every meeting.

### The Threat-Model Update

Most CISOs maintain a threat model in their head, formal or not. The debrief is where you update theirs based on what you proved. Two sentences:

"Before this engagement, your threat model reasoned about adversaries as needing a foothold. We've shown that with the current configuration of remote access, foothold is essentially free. Your threat model should assume that any motivated attacker reaches the internal network within a week."

That sentence — written down, in the slides — is what the CISO uses to justify next year's budget. Give it to them clean.

### Top Three Recommendations with Cost and Effort

Executives are deciding what to fund. Give them numbers, even rough ones.

- "MFA on remote access — 4 to 6 weeks, $80K including licensing and rollout."
- "EDR coverage to 100% — 8 to 12 weeks, $250K annualized."
- "Tier-zero asset audit — internal effort, 3 FTE for 6 weeks."

Wrong by a factor of two is fine. Missing entirely is malpractice. If you don't know the numbers, write down "rough order of magnitude" next to each one and put a placeholder. The CISO will fill in the real numbers with their team, but they need to start with something concrete.

### Q&A Management — The Political Dynamics

When the CISO asks a question in front of the CIO, they are sometimes asking *you* and sometimes asking *the CIO* through you. Read the room.

If the question is "should we have had MFA already?" — answer the technical question and stop. Do not editorialize. Do not assign blame. The CISO will use your report internally; your job is to give them clean, defensible language, not to do their politics for them.

If someone in the room is visibly defensive, slow down. Acknowledge what their team did right. Then ask the question that lets them tell you what they need to do better. "Given what we showed, what would help your team detect this next time?" is a different question than "why didn't you detect this?"

## Artifacts Produced by the Debrief

By the end of both sessions, the customer should walk away with:

- The technical report (already delivered before the debrief)
- A timeline document with timestamps for every significant event
- A detection-mapping table (technique → telemetry → query → was it caught?)
- A prioritized recommendation list with rough cost and effort
- Atomic Red Team or CALDERA replay scripts for ongoing validation
- An updated threat-model document deliverable to the AppSec / architecture team
- Reference SIEM queries in their platform's language
- Recommended Sigma rules for ongoing detection
- An anonymized engagement timeline they can share internally for awareness training

If any of those is missing, the debrief was incomplete and you owe a follow-up. Schedule the follow-up before you leave the room.

## The Detection-Mapping Table

This is the single most useful artifact you produce. One row per significant technique. The customer uses this to drive detection engineering for the next quarter.

```
># Detection-mapping table — row schema

Column                | Example
──────────────────────┼─────────────────────────────────────────────────
ATT&CK Technique      | T1558.003 — Kerberoasting
Engagement Timestamp  | 2026-03-21 14:22 UTC
Telemetry Emitted     | Windows EID 4769, ticket encryption type 0x17 (RC4)
                      | EDR process telemetry: Rubeus.exe execution
                      | Network: Kerberos AS-REQ to DC from workstation
Detection Rule Fired  | None — no rule for RC4 TGS request volume
                      | EDR rule "suspicious process name" suppressed
                      | by exception added 2025-08
SOC Response Time     | N/A — never alerted
Closing the Loop      | Add Sigma rule: 4769 with EncryptionType=0x17
                      | from a single source within 60 seconds → high
                      | Tune EDR exception to allow legitimate paths only
                      | Add Atomic Red Team T1558.003 to weekly run
```

Fill out a row for every significant technique. Critical and High findings always get a row. Medium findings get a row if there was useful telemetry. Low and Info findings get a row only if there's a defender takeaway.

Two columns I sometimes add for mature customers:

- **Confidence level.** How confident are you that the recommended rule will catch this technique without drowning the SOC in false positives? High / Medium / Low.
- **Effort to implement.** Rough estimate: hours, days, weeks. Lets the detection-engineering lead plan a sprint.

## What to Bring as the Operator

Walking into the debrief with nothing but the report is amateur. Bring:

- **Timeline reconstruction.** Hour-by-hour for the active engagement days, generated from your operator notes plus C2 logs.
- **Beacon logs and C2 transcripts.** Sanitized of any customer secret you grabbed, but otherwise raw. Defenders learn from raw output.
- **Screenshots at each milestone.** The same set used in the report, organized in the order you'll walk through them.
- **Specific blue-team artifacts you saw.** If you watched their EDR fire a process-injection alert and you saw an analyst close it as a false positive, bring that. Be specific. "At 14:42 your SOC closed alert ID 88421 as FP. The alert was correct."
- **A short list of high-confidence recommendations.** Not the long tail. The five things you'd do if you ran security here.
- **The replay scripts.** If you wrote Atomic Red Team tests or CALDERA abilities to exercise the techniques, bring them on a thumb drive and hand them over.
- **One thing you got wrong.** If during the engagement you misread a signal, or burned a technique that should have worked, or wasted a day on something that turned out to be a dead end — say so in the room. It humanizes you and it lowers the room's defensiveness. Operators who never admit a mistake get treated as adversaries instead of collaborators.

## Anti-Patterns

I have run this meeting more than a hundred times. These are the failure modes.

### The Debrief That Becomes a Sales Pitch

The engagement lead opens with "and based on what we found, we'd recommend a quarterly retainer for…" — the room shuts down. The customer needed honest feedback and got a quota play instead. Run sales conversations *after* the debrief, in a separate meeting, with separate people in the room. If the account team can't wait one week, that's the account team's problem, not yours.

### The Operator Who Lectures Instead of Collaborates

The technical operator who treats the debrief as a TED talk loses the room within ten minutes. The defenders know their environment better than you do. Your job is to share what you saw, then *listen* to what they saw on their side. The best debriefs are 60% you talking in the first half and 60% them talking in the second.

If you find yourself two minutes into a monologue and nobody has interrupted you, stop and ask a question. "Does that match what you saw?" Always works.

### The Customer Who Weaponizes Findings Against Internal Teams

You will sometimes notice that the CISO is using your report as ammunition against the network team or the desktop team. This is not your problem to solve, but it is your problem to refuse to amplify. When asked "isn't it true that the network team should have caught this?" answer the technical question, not the political one. "The detection logic for that technique requires telemetry from both EDR and DNS, which sit in different teams. Building it requires coordination."

### "Blame the SOC" Framing

If the customer's instinct is to fire the SOC because you walked through their environment undetected, you push back. The SOC is a function of staffing, tooling, training, and process. If the SOC missed everything, the system failed — not the analysts. State this explicitly in the room. James Reason's Swiss Cheese model is the language: every layer had holes; the holes lined up. Not the analyst's fault.

Push the conversation toward structural questions: "Was the SOC staffed to a level that allows them to investigate every alert? Did they have the telemetry needed to see this technique? Was the alert routing logic ever tested against an actual attack chain?" Those are answerable questions. "Why did Bob miss it?" is not.

### Skipping the Operator-to-Operator Session for Time

The single most common failure mode. The customer wants to cut the engagement short, the executive debrief is on the calendar, and the operator session gets dropped "for scheduling reasons." Push back hard. The operator session is where the value lives. If you have to choose between the two, deliver the operator session and email the executive summary. The executive can read a PDF. The defenders cannot read a tradecraft demo.

### The "Everything Is Critical" Recommendation List

If your prioritized list has eleven items all marked "immediate," you have not prioritized. Three immediate items. Two short-term. Two medium-term. That's it. The CISO will fund the first three. Items four through eleven get ignored.

### Reading the Report Aloud

Possibly worse than the sales-pitch debrief. If the customer wanted the report read to them, they would have hired a voice actor. The debrief is where you add things that aren't in the report — context, demos, the political reading of the room, the unwritten lessons. If your debrief is identical to the report, cancel the meeting.

## Lessons-Learned Capture — Internal Post-Mortem

Within five business days of the executive debrief, the red team runs its own retrospective. Separate meeting, no customer present. This is the meeting nobody bills for and everyone benefits from.

- **What was hard.** Tradecraft that didn't work first try. Tooling that broke. Detection that surprised us. The customer's BloodHound noise rule that almost burned the operator on day two — write it down.
- **What detection capabilities the customer had that surprised us.** A network DLP that flagged our exfil channel. A custom Sigma rule that caught the specific tool we used. Write these down. They go into the library.
- **New tradecraft that needs a library entry.** If we burned a novel technique or wrote a new tool variation, document it before everyone forgets. Two weeks from now, nobody will remember the exact PowerShell trick that worked.
- **Customer-management lessons.** Difficult stakeholder dynamics, scope creep, communication patterns. The next team going in deserves to know.
- **Process improvements.** What part of our own playbook failed? Did we forget to capture a piece of evidence? Did we miss a scope item? Update the playbook.

Capture all of this in a single internal markdown document, store it in the engagement's archive, and tag it for retrieval against similar engagements. Tag by customer industry (finance, healthcare, energy), customer maturity level, and the techniques that worked or failed. Six months later, when a new engagement starts in the same industry, the lead operator searches the archive and lands on every relevant lesson.

## Closing Out the Engagement

The debrief is not the end of the engagement. There are four discrete close-out steps that often get dropped:

- **Sign-off on the report.** Get written confirmation from the engagement sponsor that the report has been received, reviewed, and accepted. This protects both sides.
- **Evidence preservation handoff.** Either you destroy all evidence within the agreed retention window, or you transfer it to the customer under a chain-of-custody document. NDA terms govern. Do not let evidence linger in operator home directories.
- **Cleanup verification.** Every implant removed, every account disabled, every file deleted, every C2 redirector torn down. Get written customer sign-off that cleanup is complete. If you left a beacon on a workstation by accident, you want it found by you, today, not by their IR team in six months.
- **Reference-customer ask.** If the engagement went well, ask now. Memory of the value you delivered fades within 30 days. The polite ask while the report is still on their desk converts at much higher rates than a cold ask three months later.

A fifth step worth adding for any long-term customer relationship: **schedule the six-month check-in**. Thirty minutes, no fee, just "how did the remediation roadmap go?" That call alone is worth more renewal revenue than any sales pitch we've ever run.

## Closing Thought

The report documents what we did. The debrief is where the customer actually gets better. Every red team I've worked with that took the debrief seriously had compounding improvement across customers, year over year. Every one that treated it as a formality watched the same control gaps reappear at the same customers, engagement after engagement.

The hour costs nothing extra. Run it. Run it well. Bring the demo. Ask the nervous question. Hand over the detection rules. Then run your own internal post-mortem and update the playbook before the next engagement starts.

## Resources

- MITRE ATT&CK Defender (MAD) — engagement debrief and purple-team material — `mad-certified.mitre-engenuity.org`
- MITRE Engenuity Center for Threat-Informed Defense — adversary emulation library — `github.com/center-for-threat-informed-defense/adversary_emulation_library`
- CRTO (Certified Red Team Operator) — post-engagement and reporting guidance — `training.zeropointsecurity.co.uk/courses/red-team-ops`
- Atomic Red Team — technique replay scripts — `github.com/redcanaryco/atomic-red-team`
- MITRE CALDERA — adversary emulation platform with replay support — `github.com/mitre/caldera`
- SANS SEC565 — Red Team Operations and Adversary Emulation — debrief module — `sans.org/cyber-security-courses/red-team-operations-adversary-emulation`
- James Reason — "Human Error" — Swiss Cheese model, foundation for blameless framing
- Google SRE — "Postmortem Culture: Learning from Failure" — `sre.google/sre-book/postmortem-culture`
- Sigma — generic detection rule format — `github.com/SigmaHQ/sigma`
- TIBER-EU — European framework for threat intelligence-based red teaming, includes debrief guidance — `ecb.europa.eu/paym/cyber-resilience/tiber-eu`
- CREST STAR — Simulated Targeted Attack and Response framework, includes structured debrief requirements — `crest-approved.org`
