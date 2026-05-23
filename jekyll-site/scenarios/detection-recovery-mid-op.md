---
layout: training-page
title: "Detection Recovery Mid-Op — Red Team Academy"
module: "Scenarios"
tags:
  - detection-recovery
  - opsec
  - infra-burn
  - channel-rotation
  - mid-engagement
  - decision-tree
page_key: "scenarios-detection-recovery-mid-op"
render_with_liquid: false
---

# Detection Recovery Mid-Op

Every operator with enough engagements behind them has been on the wrong end of "we just saw your beacon." Most of the published red team curriculum is about not getting caught. This page is about what to do when you have been caught — the live decision tree, the signals to read, and the moves that preserve engagement value vs. the moves that turn the engagement into an embarrassing post-mortem.

This is not a phased scenario. It is the playbook you reach for at 02:47 local time when the team server console shows a stale beacon, the white cell Signal channel goes quiet, and somebody on the team types "is anyone seeing what I'm seeing." The next forty minutes determine whether you walk out of the engagement with a finding worth defending in the readout or whether you end up writing the apology email.

The dominant rule across every branch below: **the engagement objective decides, not your ego.** Operators burn engagements by treating detection as a personal failure to recover from rather than a state of the system to respond to. Read the signal. Pick the branch. Execute the branch. Move on.

---

## Reading the Signal

Detection is not binary. Between "completely undetected" and "incident commander has your beacon's IP on a whiteboard" there are at least four distinguishable states, and the operator's job is to identify which one you are in before reacting. Reacting to a Tier 3 like it's a Tier 1 gets the engagement called. Reacting to a Tier 1 like it's a Tier 3 burns your infrastructure for no reason and tells the customer you panicked.

### Tier 1 — Analyst Curiosity

A SOC analyst has noticed something. Their cursor is on your activity in the SIEM. They have not escalated. They might not even know what they are looking at yet — they may be triaging a queue and your event landed near the top by coincidence.

**How you read this:**

- Beacon traffic still flowing normally, no callback gaps
- No new firewall rules applied to your egress paths
- No password resets on accounts you have credentials for
- No process kills on your implants
- Tasked commands return on the expected cadence
- Pulling AD logs (if you have DC access) shows no new queries against your beacon-host account
- The SIEM you can see (if you have access) shows your event in a queue but no notes attached, no assignee, no severity bump
- No outbound DNS queries from SOC subnets that resolve to your C2 domain (someone manually checking your domain against threat intel feeds is a Tier 2 signal)
- No new entries in the customer's allowlist or blocklist tooling
- Sysmon EventID 1 telemetry from your beacon hosts is still flowing normally — if it suddenly stops, the host was just isolated and you are not at Tier 1 anymore

Tier 1 is the most common state and the one operators most often misread. Most analyst-level curiosity dies in the queue. Do not burn infrastructure on a maybe. The corollary: most engagements that get burned at Tier 4 started with an operator reacting to a Tier 1 like it was a Tier 3 and creating the very escalation they were trying to avoid.

### Tier 2 — Named Pivot

The analyst has escalated. Someone — a senior analyst, a shift lead, a Tier 2 analyst — is now looking at your activity specifically, with intent. They are pivoting through the data: from the alert, to the host, to the user, to the network connections, to the parent process. The investigation has a name attached to it, in their ticketing system, with an assignee and a priority.

**How you read this:**

- Sudden burst of authentication events from a SOC subnet against the host running your beacon (DC logs are the giveaway)
- New process telemetry queries hitting your beacon host (visible in CrowdStrike RTR sessions if you have access)
- Egress firewall logs (if you can pull them) show packet captures starting against your C2 IP
- Account you are using starts seeing forced re-authentication prompts
- The SOC's ticketing system (if you have visibility) shows a new ticket opened, tagged with your alert's signature
- A second beacon on the same network sees its callbacks delayed or dropped — they are looking at network paths, not just hosts
- WHOIS lookups against your C2 domain start appearing in passive DNS feeds you monitor
- VirusTotal sees a fresh submission of your implant binary — someone uploaded it from inside the customer's environment

Tier 2 is the decision point. Up to here, you can probably ride it out by going quiet. Past here, every minute you remain on burned infrastructure costs you more than the rotation would. The asymmetry of detection means that once a named analyst is on your trail, the velocity of their investigation accelerates — they have organizational permission to pull threads, request additional telemetry, and engage IR. Tier 2 to Tier 3 transitions often happen in less than an hour. Plan for it.

### Tier 3 — IR Engaged

Incident Response has been called in. This may be an internal IR team, an external retainer (Mandiant, CrowdStrike Services, Unit 42), or both. You are the named subject of an active investigation. The customer's IR runbook is now executing against you.

**How you read this:**

- Sudden network segmentation activity — VLAN changes, ACL deployments
- New EDR sensor policies pushed to hosts you have implants on
- Memory acquisition processes (winpmem, FTK, Velociraptor agents) executing on hosts you are on
- Credentials you harvested start failing — bulk password resets across the directory
- Service principal you compromised gets disabled
- An incident channel exists in the customer's chat platform with names you recognize from the IR retainer
- Egress to your C2 domain is now sinkholed or actively blocked at the edge

Once you are at Tier 3, you are not running an engagement anymore. You are running a recovery operation. The objective changes from "achieve the original goal" to "preserve engagement value, exit cleanly, generate a high-quality finding."

### Tier 4 — Containment

The customer is executing containment. Hosts are being isolated, accounts disabled, network paths cut. Tickets are open with executives copied. Counsel may be involved. Law enforcement may have been notified if the engagement authorization was unclear at the customer's executive level (this happens — the SOC may not know it is a red team engagement, especially in a double-blind scope).

**How you read this:**

- All your beacons dead, no recovery
- All your harvested credentials invalid
- All your domains sinkholed
- You cannot reach the customer's externally facing assets — they're now blocking your operator IPs
- White cell silent or actively telling you to stand down

At Tier 4 there are no operational choices left. Only communication choices.

---

## Three-Minute Decision Tree

The longer you spend deciding, the worse your options get. Three minutes is the budget. The flow:

```
Is the engagement objective achievable in the next 24 hours
with current access?
├── YES, and Tier is 1 ......................... CONTINUE (slow)
├── YES, and Tier is 2 ......................... SLOW + PRE-STAGE ROTATION
├── YES, and Tier is 3 ......................... ROTATE NOW, finish on new infra
├── NO, and Tier is 1 ........................... CONTINUE normally
├── NO, and Tier is 2 ......................... SLOW + RECONNAISSANCE
├── NO, and Tier is 3 ......................... BURN AND ROTATE
└── ANY, and Tier is 4 ......................... ABORT + COMMS

Has the customer's IR cycle become the engagement finding?
├── YES ......................................... LET IT RUN, document the chain
└── NO .......................................... see above
```

The dominant input is **engagement objective**, not technique. A team with a "achieve domain admin and persist for 14 days" objective makes very different choices at Tier 2 than a team with an "achieve initial access on a specific high-value mailbox" objective. The first team has time. The second team's clock is the next phishing window.

Three branches matter most in practice: **Continue**, **Rotate**, and **Burn**. Most of the rest are variants of these three. Treat them as the canonical states.

---

## Continue (Tier 1, Low Confidence Detection)

This is the "they are not sure it is you" branch. The math is simple: if you reduce the action rate enough, the analyst's queue will move on to the next alert and your event ages out.

**What to do:**

- Pause beacon tasking immediately. Let beacons callback on their normal cadence with no work to do. A beacon that does nothing for a day looks like a beacon that has nothing wrong with it.
- Hold all credential operations. No new authentications from harvested accounts. No new DCSyncs, no new lateral movement.
- Hold all file system writes on compromised hosts. No new staging. No new tools dropped. No new scheduled tasks.
- Increase the cover ratio. If you are routing traffic through a high-reputation CDN, slow it to match the genuine background traffic rate. If you have multiple beacons, route only through the ones with the lowest noise profile.
- Pre-position for clean exit. Confirm your pre-staged rotation infrastructure is reachable and warm. Confirm your secondary personas are operational. Confirm your secondary pretext domains have warm MX records. You are not rotating now, but you might be in six hours.

**What you absolutely do not do:**

- Send a fresh phishing wave to a different target inside the same org. The SOC is already looking at one anomaly. A second one in the same window is how analyst curiosity becomes a named pivot.
- Spin up new infrastructure. New infrastructure means new DNS, new TLS handshakes, new outbound connections — all new alert candidates.
- Have a side conversation in the team channel about "did anyone see the alert get cleared." If the engagement is being recorded and the white cell pulls the recording, this is the kind of side chatter that becomes a finding.

**Exit condition:** 24 hours of clean beacons and no escalation signals. Resume tasking at half cadence for another 24 hours before returning to normal operation.

---

## Slow / Quiet (Tier 1–2)

The middle branch. The analyst's curiosity may already have escalated. You are not sure. Your job is to be uninteresting until you have better information.

**What to do:**

- Cease beacon callbacks for 48–72 hours. Set your beacons to a sleep cycle that exceeds the SOC's working memory. A beacon that sleeps for three days and wakes up clean is harder to investigate than one that beacons every four hours through a suspected anomaly.
- Burn nothing yet. Do not rotate infrastructure. Do not abandon personas. Once you burn, you cannot un-burn.
- Use the dead time to gather intelligence. If you have access to internal documentation, pull the SOC's known runbook. If you have read access to ticketing, look for tickets tagged with anything that matches your event signature.
- Pre-stage the rotation. Spin up the standby infrastructure to a warm but unused state. Verify the new C2 profile, new domains, new certificates, new MX records, new persona email accounts. Do not connect anything to it yet.
- Hold a comms briefing with the team. The operators need to know that beacons going dark for 48 hours is intentional, not lost. Document the decision in the engagement log.

**What you absolutely do not do:**

- Send a final "checking in" task to the beacons before they go quiet. Whatever the beacon was last doing is what the SOC will see in the recent-events view when they finally pivot. Make the last action boring.
- Use the dead time to compromise additional hosts on the same network. The point of going quiet is for the customer's perception of the incident to age. New activity resets that clock.
- Argue with white cell about whether the detection was real. White cell will tell you what they can tell you. Asking for more usually generates a paper trail you do not want.

**Exit condition:** at 48–72 hours, send one low-value probe (a `whoami` from a beacon that was sleeping). If it returns clean and no escalation has occurred, return to a slow operational cadence. If it does not return, you are at Tier 3 and the rotation decision is made for you.

---

## Rotate (Tier 2–3)

The blue team is looking. You probably have hours, not days. The play here is to abandon the noisy infrastructure on your own terms while the blue team is still spinning up their remediation, then continue the engagement from the new infrastructure they do not know about.

**The pre-condition for rotation is that the rotation infrastructure already exists.** If you are spinning up new C2 servers at 03:00 in the middle of an active detection, you have already lost. Pre-staged rotation infrastructure is the difference between a recovered engagement and a burned one.

**What "pre-staged" means:**

- A second C2 server, fully configured, with a different Malleable C2 profile that does not share JA3/JA4 fingerprints with the primary
- A different fronting domain on a different CDN (if primary is Azure Front Door, secondary is Cloudflare or Fastly)
- A different set of redirector IPs in a different ASN
- Different TLS certificates issued by a different CA
- A different operator persona for any human-facing actions (different email addresses, different phone numbers, different LinkedIn profiles if applicable)
- A different initial-access vector pre-built and ready to use (if primary was OAuth consent, secondary is HTML smuggling, or vice versa)

**Execution:**

- Push the rotation command to all active beacons. This is a one-time stager that points the beacon at the new C2 profile and new domain, then exits cleanly. The old beacon dies. The new beacon callbacks to new infra.
- Confirm callback on the new infrastructure for every beacon you intend to keep. Beacons that fail to migrate are abandoned — do not try to recover them on the old infra.
- Sever connections to the old infrastructure. Shut down the old team server. Sinkhole the old domains yourself (rather than letting the customer's IR sinkhole them — it looks better in their logs if the malicious domain "went dark" on its own).
- Update the engagement log with the rotation event. White cell needs to know, even if the customer's SOC does not.
- Communicate the rotation to all active operators. Every operator on the team needs the new C2 profile, the new domain list, the new authentication flow for tasking. A confused operator using old credentials against new infra is its own kind of detection.
- Time-box the rotation. From the decision to rotate to the last beacon migrated should be under 30 minutes. Slower than that and you are operating across two infrastructures simultaneously — twice the noise, half the operational coherence.

**The "let them remediate the old infra" play:**

The optimal outcome of a rotation is that the customer's IR team remediates the old infrastructure thoroughly. They block the old domains. They quarantine the hosts with the old beacons. They reset the credentials that came from the old harvested set. They congratulate themselves on a successful incident response. Meanwhile, you are operating from infrastructure they do not know exists, against credentials they did not reset, on hosts they did not investigate.

This is not malice. This is the engagement finding. **The customer's IR cycle is the test.** A well-run IR that misses the second infrastructure is a finding about detection coverage. A well-run IR that finds the second infrastructure is a finding about defense-in-depth. Both are valuable. The bad outcome is the IR cycle finding nothing because you did not rotate and they just ate your primary.

---

## Burn (Tier 2–3, High Confidence)

There is a category of detection that is high-confidence enough that you cannot rotate cleanly — you have to burn the infrastructure to prevent attribution leakage that affects future engagements, future customers, or other teams operating from the same provider footprint.

**What gets burned:**

- **Infrastructure:** Domains, IPs, certificates. Take them down. Do not leave them registered for re-use — once a domain shows up in a customer's IR report, it is in threat intel feeds within a week and unusable for any future engagement.
- **Implants:** Let them be remediated. Do not attempt persistence recovery. Anything that was on the burned infrastructure dies with it.
- **Pretexts:** If a phishing pretext was identified — a specific lure, a specific cover story, a specific document template — burn it. Do not reuse it on a different customer. Threat intel sharing across IR firms means a pretext that gets attributed in one engagement may be flagged in the next.
- **Personas:** If an operator identity (an email account, a LinkedIn profile, a phone number used for vishing) was identified, burn it. The persona is dead. Build a new one.

**What gets kept:**

- Tradecraft. Techniques. The decision tree, the workflows, the operator runbook. These are not infrastructure — they are intellectual property. Burning a domain does not burn the technique that used it.
- The lessons. The engagement log. The detection signal that triggered the burn. These go into the post-engagement debrief and inform the next engagement's pre-staging.

**The cost calculation:**

The hard question is always whether to burn. The framework: compare the replacement cost of the infrastructure to the engagement value you would lose by burning prematurely.

- Pre-staged rotation domains cost roughly $100–500 each in registration plus warm-up time. Replacement is real but bounded.
- Personas cost more to replace — a warm LinkedIn profile with two years of credible activity is not something you spin up overnight.
- Pretexts cost the most. A novel, target-appropriate lure that has not been seen by threat intel feeds is the scarcest resource.

If the engagement value of continuing is less than the replacement cost of burned assets, do not burn. Rotate or abort instead. If the engagement value is greater, burn cleanly and quickly. The worst possible outcome is partial burn — domains down but personas still tied to them, certificates revoked but operator IPs still active. Partial burn leaks attribution surface without preserving anything.

---

## Abort (Tier 3–4)

The engagement is over. Not the contract — the engagement, the live operation. The work that remains is communication, evidence preservation, and reporting.

**The "we're done" call:**

- The lead operator makes the call. Not the most senior. The lead. There is one decision-maker for abort, and it is the named lead on the engagement. This is in the engagement plan from day one.
- The call is made in the engagement comms channel with timestamp. "Aborting at 04:13 UTC. Tier 4 contained. Rotation infrastructure standing down. White cell briefed."
- All beacons receive the final command and die. No persistence is left running unless the engagement scope explicitly required it.

**Communicating with the white cell:**

- White cell is your liaison to the customer's executive sponsor. Most customers run engagements double-blind to the SOC but single-blind to the executive sponsor. White cell knows the engagement is real. They can tell the customer's IR lead, when appropriate, that the activity they are responding to is authorized.
- The white cell briefing on abort is a structured deliverable: timeline, detection events as we saw them, exit state of infrastructure and personas, evidence preservation status, any actions taken that the customer's IR will see in the next 24 hours (e.g., domains going dark on their own, beacons receiving termination commands).
- Do not surprise the white cell. They cannot help you if they are learning about your abort from the customer's SOC.

**Evidence preservation (your side):**

- Capture state. The team server's beacon list, the credential vault, the command history, the network captures, the screenshots. This is the raw material for the engagement report.
- Capture timing. Every meaningful event with a timestamp. The detection event, the escalation signal, the abort decision, the comms with white cell.
- Hash the artifacts. The chain of custody for the engagement report needs to be defensible.

**Customer-facing comms:**

- The customer-facing comms are the white cell's job during the engagement. After the engagement closes, the report is the operator team's job. The two should agree on what gets disclosed before the readout meeting.
- Do not, under any circumstance, contact the customer's SOC directly during the engagement. Even with the best intentions, even to clarify a confused IR, the only acceptable channel is the white cell.
- If the IR cycle has produced incorrect attribution (e.g., the customer believes they are dealing with a named external threat actor because of a tradecraft choice you made), white cell decides whether and when to correct that attribution. Sometimes the correction happens during the readout. Sometimes it happens immediately to prevent the customer from notifying external parties (law enforcement, partners, vendors) based on a false premise. The decision is white cell's, not yours.

**Post-abort engagement value:**

An aborted engagement is not a failed engagement. The deliverable shifts: instead of a report on achieved objectives, the deliverable is a complete reconstruction of the attack chain up to the abort point, paired with a complete reconstruction of the customer's detection and response chain. Both reconstructions need to be timestamped, evidence-backed, and presented without spin. Customers value honest post-abort reports more highly than mediocre "we succeeded" reports — because the honest reports give them something to fix.

---

## Cover Stories

When the SOC is looking at your activity, sometimes the best move is to give them something else to look at. A well-constructed cover story is plausible, internally consistent, and just noisy enough that the SOC's attention spends itself investigating it instead of you.

- **The "noisy second team" cover.** A second, deliberately noisy red team — a decoy — runs parallel activity that the blue team finds quickly. The blue team congratulates themselves on the detection, writes up the lessons learned, and moves on. The real campaign continues quietly underneath. This works best when the customer has authorized two simultaneous engagements (rare) or when the second team is the operator team's own sacrificial branch (more common).
- **The "test traffic" cover.** Your activity looks like internal IT testing. New scanning from an internal IP coincides with a known patch window. New service installations match a vendor support pattern. The SOC analyst sees the alert, asks IT, gets "oh yeah, that's the new monitoring tool," closes the ticket. This requires reconnaissance of the customer's internal change management cadence.
- **The "vendor maintenance" cover.** Your beacon traffic looks like a third-party vendor's normal communication. The traffic patterns match an installed vendor agent's documented behavior. The destination resembles the vendor's documented endpoints. This is the highest-effort cover and the most durable — it survives even close inspection if the impersonation is good.

**When cover stories backfire:**

A cover story that the blue team disproves is worse than no cover at all. If you claim "test traffic" and the SOC pings the IT manager and IT denies it, you have just confirmed to the SOC that the traffic is malicious and additionally trying to deceive them. The signal you give off when caught lying is louder than the original detection.

Rule of thumb: a cover story must be one the customer cannot disprove in less than four hours. If they can disprove it faster than your operational pace, the cover is worse than silence.

---

## Real Patterns from Engagement Debriefs

Across enough engagements, the same shapes recur. These are the four most common:

- **Pattern A — noisy on initial access, quiet during dwell.** Blue team caught the initial access — a phishing email that triggered Defender, a macro that AMSI flagged, a download cradle that script block logging captured. The SOC saw it, the analyst escalated, IR started a ticket. Then the operator team went dark for 72 hours and did nothing. IR could not find follow-up activity. The ticket was closed as "blocked at gateway, no further action." The engagement continued from a different initial access vector. The lesson: a noisy initial access can be survivable if the dwell is silent enough.
- **Pattern B — quiet initial access, loud post-ex.** Blue team missed the foothold entirely. Six weeks of dwell, no detection. Then the lateral movement to a domain controller via DCSync triggered CrowdStrike's explicit DCSync detection. Critical alert, escalated within four hours. IR found the lateral movement chain — but never traced it back upstream to the initial access. The remediation cleaned the lateral movement and the domain controller, but the persistence on the initial foothold survived. The engagement ran for another four weeks before scope closed. The lesson: a loud post-ex event focuses defender attention on the loud event, often at the expense of upstream investigation.
- **Pattern C — SOC escalation that fizzled.** Analyst saw the activity, pivoted to it, attempted to escalate to IR. IR was tied up on a different incident. The analyst's escalation aged out of the queue. The ticket was closed at the end of the analyst's shift with notes for the next shift. The next shift did not pick it up. The detection happened, the response did not. The lesson: detection without response is not a failure on the operator's side. Read the absence of escalation as a signal in its own right.
- **Pattern D — full containment in four hours.** SOC analyst recognized the activity within fifteen minutes. Escalated to IR within thirty. IR engaged the affected hosts within sixty. Network segmentation deployed within two hours. Credentials reset within three. Engagement ended at the four-hour mark with the operator team locked out of every access path. The lesson: this is what a mature, well-resourced, well-practiced IR looks like. It exists. When you find it, your job is to make the engagement finding be about the response quality, not about your continued operation.

---

## What Not to Do

The high-cost mistakes after detection, in rough order of how often operators make them:

- **Escalate aggression after detection.** Operators feeling caught sometimes try to "win" by running louder, faster, with more techniques. This converts a Tier 2 into a Tier 4 within an hour. The blue team's confidence increases with every additional indicator. Do not feed them.
- **Reuse burned infrastructure.** A domain that appeared in one customer's IR report becomes a domain in threat intel feeds in days. Do not bring it back, even on a different engagement, even six months later. Burned is burned.
- **Argue with the customer's SOC during the engagement.** Direct communication with the SOC is white-cell-only. Operators who try to "help" by explaining the activity to a SOC analyst destroy the engagement's value as a test. The point of the engagement is to evaluate the customer's response. The response cannot be evaluated if you contaminate the evaluation.
- **Try to "fight" the IR team.** You lose. They have full visibility into their network, you have a foothold. They can isolate hosts at will, you cannot prevent it. They control authentication, you have stolen credentials that they can invalidate in a single command. The fight is asymmetric in their favor. The correct response to IR engagement is to disengage on your own terms before they disengage you on theirs.
- **Continue silently when you should abort.** "Silent persistence" through a Tier 4 containment is not stealth — it is denial. If the customer is doing full containment, your remaining infrastructure is a liability, not an asset. Abort and document.
- **Hide the detection from the engagement log.** The post-engagement report is honest about every detection event. Customers know whether their SOC saw you. If your report says "achieved goals undetected" and their SIEM shows two analyst pivots, you have damaged the trust that gets you the next engagement.

---

## Mid-Op Comms with White Cell

The white cell is the operator team's interface to the customer's executive sponsor. The relationship is critical and easy to mismanage.

**When to surface a detection event:**

- Tier 1 (analyst curiosity): No comms needed unless it escalates. Log it.
- Tier 2 (named pivot): Notify white cell within 30 minutes. They may need to brief the customer's executive sponsor that the SOC's signal is real.
- Tier 3 (IR engaged): Notify white cell immediately. White cell may need to decide whether to surface the engagement's authorization status to the IR lead.
- Tier 4 (containment): Notify white cell as the first action, before any technical response.

**Format for the notification:**

```
DETECTION EVENT — [timestamp UTC]
Tier:           [1|2|3|4]
Source:         [what triggered the assessment — SIEM alert, beacon behavior, account state]
Confidence:     [low|medium|high]
Affected:       [which assets / hosts / personas]
Current action: [continue|slow|rotate|burn|abort]
Risk:           [what the customer's response is likely to do in next 4 hours]
Asks:           [anything from white cell — e.g., "please confirm SOC awareness"]
```

**The "I think they have us" call:**

You will sometimes need to call something in before you are sure. The format: explicit uncertainty. "Possible Tier 2. Pivot signals present but not definitive. Holding all activity for 60 minutes pending confirmation. Will update at [timestamp]." White cell appreciates uncertainty calls because they preserve their own decision-making time. Operators who only call confirmed events leave white cell flat-footed when an event escalates.

**The "they definitely have us" call:**

Short. Factual. No emotional content. "Tier 3 confirmed. IR engaged at [timestamp]. Beacons going dark in 5 minutes. Rotation infrastructure activating. Engagement continues at reduced scope. Will brief at next checkpoint."

---

## Post-Detection Engagement Value

A detection event is not necessarily an engagement failure. Often it is the engagement's most valuable finding.

**Sometimes getting caught is the win condition.**

Engagements scoped as "evaluate the customer's detection and response capability" want detection events. The whole point is to see whether the SOC catches you, how fast, what they do next. An engagement that goes 14 days with zero detections is often a less valuable finding than one that gets caught on day 3 because the day-3 catch lets the customer test their IR.

**The "let them complete the IR cycle" play:**

Once you have been detected at Tier 3, the highest-value engagement continuation is often to let the customer's IR cycle complete fully. Document every step of their response. Time their notification chains, their containment decisions, their communication patterns. The engagement finding becomes a complete picture of their response capability, not just their detection capability.

**Documenting the detection chain for the report:**

- What event triggered the detection (be specific — which SIEM rule, which EDR signature, which analyst's pivot)
- How long from the malicious action to the detection event (detection time)
- How long from the detection event to escalation (escalation time)
- How long from escalation to containment action (response time)
- What containment actions were effective and what were missed

These four metrics are usable. They show up in the customer's executive readout. They make the engagement valuable independent of whether the original objective was achieved.

**Detection time as a primary engagement metric:**

In modern engagements, detection time often replaces "did we achieve the objective" as the primary metric. A 14-day dwell with no detection is a finding. A 4-hour detection is also a finding. Both are useful. Operator teams that anchor on objective-achievement above all else miss the value of detection-timing as the deliverable.

---

## Pre-Engagement Preparation

Every recovery move above is only possible if it was prepared for before the engagement started. The work that happens at 03:00 in the middle of a detection is not improvisation — it is execution of a pre-built plan.

- **Pre-staged rotation infrastructure.** A second C2 server, configured, certificates issued, domains warm. Different CDN, different ASN, different profile. Tested to verify callbacks work. Sitting idle until activated.
- **Pre-staged secondary personas.** Email accounts created, LinkedIn profiles warmed up over weeks or months, phone numbers operational with voicemail recordings. Identities the customer has never seen.
- **Pre-staged secondary pretexts.** A different lure template, a different cover story, a different target persona. Different document templates, different sender domains, different traffic patterns.
- **Pre-defined abort criteria.** Written down. Reviewed with white cell. Agreed before day one. "If detection reaches Tier 4, we abort within 60 minutes. If credentials are bulk-reset, we abort within 30 minutes. If IR is named in scope, we hold for 24 hours before resuming."
- **White-cell escalation tree printed and at-hand.** Names, phone numbers, time zones, backup contacts. When the team server is dead and your communications are degraded, you do not want to be looking up phone numbers.
- **Operator-side IR playbook.** Your own internal IR plan for when you are the one being responded to. Who does the rotation. Who talks to white cell. Who locks the team server. Who hashes the evidence. Rehearsed at least once before the engagement starts.
- **Decision authority documented.** Who is allowed to call abort. Who is allowed to call burn. Who is allowed to commit new infrastructure to the engagement. Most engagement disasters trace to ambiguous authority during a high-stress moment — three operators arguing about whether to burn at 03:00 while the IR cycle accelerates around them.

The work of preparing for detection recovery is roughly equal to the work of preparing for initial access. Treat it that way. An engagement plan that has three pages on initial access and one paragraph on detection recovery is not a complete plan. The mature operator team measures itself not by how rarely they get detected — every team gets detected eventually — but by how cleanly they recover when it happens.

---

## Resources

- MITRE ATT&CK Evaluations transcripts — `attackevals.mitre-engenuity.org` (red team transcripts from APT3, APT29, Carbanak, Sandworm, Wizard Spider, Turla evaluations — read how the red team handled detection events during the evaluation runs)
- MITRE Engenuity Adversary Emulation Library — `github.com/center-for-threat-informed-defense/adversary_emulation_library` (full emulation plans including detection-response handling)
- RTOF — Red Team Operations Framework — `redteam.guide` (operational handling guidance including post-detection branches)
- Joe Vest & James Tubberville, "Red Team Development and Operations" — the canonical text on engagement lifecycle including detection recovery
- CRTO — Certified Red Team Operator — course material on infrastructure rotation and operational survivability
- MITRE ATT&CK Detection Mappings — `attack.mitre.org` (each technique's Detection subsection — useful both for understanding what defenders are looking for and for reading the signal of being caught)
- Daniel Duggan's "Offensive Tradecraft Fundamentals" — Sektor7 Institute course covering operational discipline in active engagements
- Mandiant M-Trends annual reports — `mandiant.com/m-trends` (detection time and response time statistics across industries, useful for calibrating expectations)
