---
layout: training-page
title: "Purple Team Tabletop Exercises — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - tabletop
  - exercise
  - incident-response
  - threat-modeling
  - scenario-planning
page_key: "purple-team-tabletop-exercises"
render_with_liquid: false
---

<h1>Purple Team Tabletop Exercises</h1>

<p>A tabletop exercise (TTX) is a facilitated, discussion-based exercise where participants walk through a hypothetical attack scenario without executing actual techniques. Unlike a live purple team simulation, a tabletop exercises is lower cost, broader in scope, and excellent for testing process maturity, communication flows, and decision-making rather than technical detection capability. Tabletop exercises are often the right starting point before committing to a full purple team simulation — they reveal gaps in procedure and communication that live testing cannot surface.</p>

<h2>Tabletop vs Full Simulation</h2>

<pre><code># TABLETOP EXERCISE
# -----------------
# Format:      Discussion-based, conference room or video call
# Duration:    2-4 hours typically
# Cost:        Low — requires facilitator time only
# Output:      Action items list, lessons learned, process gaps
# Tests:       Procedures, communication, decision-making, awareness
# Does NOT test: Technical detection capability, alert fidelity, SIEM queries
# When to use: Early in program maturity, quarterly touchpoint, new team members,
#              before a live simulation, for executive-level engagement
#
# LIVE PURPLE TEAM SIMULATION
# ----------------------------
# Format:      Red team executes techniques, blue team responds in real time
# Duration:    1-5 days typically
# Cost:        High — requires red team operator time, lab environment
# Output:      Coverage map updates, new Sigma rules, tuned detection rules
# Tests:       Technical detection, alert fidelity, SIEM queries, MTTD/MTTR
# Does NOT test: Decision-making, executive escalation procedures
# When to use: Mature blue team (logging deployed, SIEM operational, analysts staffed)
#
# HYBRID: Tabletop + mini technical validation
# --------------------------------------------
# Walk through scenario discussion → execute 2-3 techniques manually
# Best of both worlds: test process AND test detections in same session</code></pre>

<h2>Roles in a Tabletop Exercise</h2>

<pre><code># Core roles and responsibilities:
#
# FACILITATOR
#   Role:         Controls the exercise flow, introduces injects, keeps time
#   Background:   Offensive security knowledge (to make injects realistic)
#   Preparation:  Develops the scenario script, prepares injects, reads AAR templates
#   During TTX:   Reads injects, asks probing questions, ensures all roles participate
#   Key skill:    Know when to move on vs let discussion continue productively
#
# RED TEAM LEAD
#   Role:         Describes what the attacker is doing and why (adversary perspective)
#   Background:   Penetration tester or red team operator
#   During TTX:   Explains attack technique realism, what the attacker's next move is,
#                 what artifacts would/wouldn't be left, common evasion options
#   Key question: "Would a real attacker actually do this? What would they do next?"
#
# BLUE TEAM LEAD
#   Role:         Describes the detection/response perspective, drives IR process
#   Background:   SOC analyst, detection engineer, or incident responder
#   During TTX:   Identifies what data sources would have captured the activity,
#                 walks through alert triage, escalation, containment decision-making
#   Key question: "What would we actually see in our SIEM right now?"
#
# STAKEHOLDERS (optional for executive-focused exercises)
#   CISO:         Escalation decision authority, risk acceptance, public comms
#   Legal:        Data breach notification requirements, attorney-client privilege
#   PR/Comms:     Customer/media communication decisions
#   IT Operations: Change control, emergency patching, system isolation authority</code></pre>

<h2>Exercise Flow</h2>

<pre><code># Standard tabletop exercise flow:
#
# PRE-EXERCISE PREPARATION (1-2 weeks before)
# -------------------------------------------
# 1. Select threat actor or scenario theme
#    - Match to organization's industry threat landscape
#    - Use current threat intel: what's being used against peers right now?
#    - Example: "FIN7-style ransomware precursor campaign targeting finance sector"
#
# 2. Define objectives and success criteria
#    - What do we want to learn from this exercise?
#    - Examples: "Test our ransomware escalation runbook"
#                "Identify gaps in our cloud IR process"
#                "Ensure all stakeholders understand their roles in a data breach"
#
# 3. Write scenario script (see templates below)
#    - 8-12 injects paced over the exercise duration
#    - Each inject: what happened, when, technical details
#    - Include discussion questions for each inject
#
# 4. Pre-read distribution (24-48 hours before)
#    - Send participants: scenario background, their role, ground rules
#    - Do NOT reveal full script — preserve reaction authenticity
#
# EXERCISE EXECUTION
# -------------------
# Opening (15 min):
#   - Facilitator sets ground rules: "This is a learning exercise, no blame"
#   - Introduce scenario background and ground rules
#   - Confirm roles and introduce all participants
#
# Inject → Response → Discussion loop:
#   - Facilitator reads inject (2-3 sentences describing what just happened)
#   - Each role responds from their perspective (5-10 min per inject)
#   - Facilitator asks probing questions (see templates below)
#   - Note: capture action items and gaps in real time
#
# Debrief (30 min):
#   - Hot wash: immediate reactions — what went well, what didn't
#   - Review captured action items
#   - Assign owners and due dates to action items
#
# POST-EXERCISE
# -------------
# 1. Write After-Action Report (AAR) within 5 business days
# 2. Track action items to completion
# 3. Update runbooks and procedures
# 4. Schedule follow-up exercise in 3-6 months</code></pre>

<h2>Scenario 1: Ransomware Initial Access via Phishing</h2>

<pre><code"># SCENARIO: "Operation Scattered Spider" — Ransomware Precursor Campaign
# Threat Actor: FIN8 / ransomware affiliate
# Objective: Ransomware deployment after lateral movement
# Duration: 3-4 hours
# Participants: Red Team Lead, SOC Lead, IR Lead, CISO, IT Ops Lead
#
# BACKGROUND (read to participants at opening):
# "Your organization has received threat intelligence indicating that a
# ransomware affiliate group has been observed targeting companies in your
# industry vertical using spear phishing campaigns delivering macro-enabled
# Office documents. The malware used is consistent with SystemBC loader
# followed by Cobalt Strike for C2. We are now going to walk through a
# simulated scenario and test our readiness."
#
# INJECT 1 — Day 1, 09:15 AM
# ----------------------------
# "An employee in the Accounts Payable team receives an email appearing to come
# from an existing vendor, 'GlobalSupplyCo'. The email contains an invoice
# attachment: 'Invoice_December_FINAL.xlsx'. The employee opens the attachment
# and receives a notification that the document is 'protected' and asks to
# enable macros to view the content. They click Enable Content."
#
# DISCUSSION QUESTIONS:
# → Blue Team: "Do we have email gateway logging? Did this email get scanned?"
# → Blue Team: "Is macro execution in Office monitored? What would event 4104 show?"
# → Red Team: "What does the macro likely do at this stage? (mshta.exe, cmd.exe)"
# → SOC Lead: "Would our existing phishing detection rule catch this email?"
# → Action items to capture: Do we alert on Office spawning mshta/cmd? Email DLP configured?
#
# INJECT 2 — Day 1, 09:45 AM
# ----------------------------
# "The SystemBC loader successfully runs, establishing persistence via a scheduled
# task named 'MicrosoftEdgeUpdateTaskMachineCore'. The C2 beacon calls out to
# 185.220.101.33 on TCP port 443 every 60 seconds."
#
# DISCUSSION QUESTIONS:
# → Blue Team: "Scheduled task 4698 — would our rule have caught 'MicrosoftEdge' in name?"
# → Blue Team: "Outbound to that IP — is threat intel integrated with our firewall/proxy?"
# → Red Team: "Why port 443? Why mask as Edge update? What's the operator doing now?"
# → SOC: "Do we have IP reputation/threat intel feed connected to our proxy logs?"
# → Action item: Review scheduled task detection filter for common masquerading names
#
# INJECT 3 — Day 1, 14:30 PM (5 hours later)
# ----------------------------
# "The attacker operator uses Cobalt Strike to run BloodHound via SharpHound.
# The collection runs for 15 minutes and generates ~50,000 LDAP queries against
# the domain controller from the compromised workstation WS-AP-012."
#
# DISCUSSION QUESTIONS:
# → Blue Team: "LDAP reconnaissance — Event 1644 (expensive LDAP queries). Is that enabled?"
# → Blue Team: "SharpHound makes specific named pipes. Do we alert on them? (Sysmon 17)"
# → IR Lead: "5 hours after initial infection — what's our expected MTTD for this scenario?"
# → Red Team: "BloodHound reveals: Domain Admin is logged into FS-SHARE-01. What's next?"
# → Action item: Enable LDAP diagnostic logging on DCs, review BloodHound detection
#
# INJECT 4 — Day 2, 02:00 AM
# ----------------------------
# "At 2 AM the attacker uses Pass-the-Hash to move laterally to FS-SHARE-01 where
# the Domain Admin session was found. From FS-SHARE-01 they dump credentials using
# a reflective DLL injection of Mimikatz — LSASS memory access via Sysmon Event 10.
# They now have Domain Admin credentials in plaintext."
#
# DISCUSSION QUESTIONS:
# → SOC: "2 AM — would anyone have been looking at alerts? What's our after-hours process?"
# → Blue Team: "Pass-the-Hash Event 4624 Type 3 NTLM — does our rule fire? Does it page?"
# → Blue Team: "LSASS Sysmon 10 with GrantedAccess 0x1fffff — is this a P1 alert?"
# → IR Lead: "We now have a DA compromise confirmed. What are our first three actions?"
# → CISO: "At what point do we convene the incident management team and notify counsel?"
# → Action item: After-hours P1 escalation path needs review; PtH alert severity uplift
#
# INJECT 5 — Day 2, 03:30 AM
# ----------------------------
# "The attacker deploys a ransomware binary via GPO to all workstations and servers.
# File encryption begins simultaneously across 312 Windows hosts. Helpdesk calls
# start flooding in at 06:00 AM as employees arrive. Ransom note visible on screens."
#
# DISCUSSION QUESTIONS:
# → IT Ops: "Emergency action: do we kill network access at the core switch? Who approves?"
# → IR Lead: "Scope — how quickly can we determine the blast radius? EDR query across fleet?"
# → CISO: "Ransomware deployed. Do we have offline backups? What's our RTO?"
# → Legal: "At what point does this trigger data breach notification requirements?"
# → Action item: Mass encryption detection rule (volume shadow copy deletion — 4688 + vssadmin)</code></pre>

<h2>Scenario 2: Privileged Insider Threat</h2>

<pre><code># SCENARIO: Privileged Insider Accessing Financial Data
# Threat Actor: Malicious insider (IT administrator)
# Objective: Data exfiltration before resignation
# Duration: 2-3 hours
#
# BACKGROUND:
# "A senior IT administrator, Alex Chen, submitted a resignation letter yesterday.
# HR has been informed. Alex has Domain Admin credentials, admin access to the
# finance file server (FS-FIN-01), and knows the backup procedures. We have
# received a tip from a colleague that Alex may be planning to take proprietary
# financial data to a competitor."
#
# INJECT 1 — Day of resignation submission
# -----------------------------------------
# "Alex authenticates to FS-FIN-01 outside of normal working hours (11 PM) from
# their personal laptop via VPN. This triggers Event 4624 with an unusual source
# workstation name 'ALEX-PERSONAL-PC' (not a corporate asset)."
#
# DISCUSSION QUESTIONS:
# → Blue Team: "Do we alert on authentication from non-corporate asset names? How?"
# → Blue Team: "11 PM access from personal device — baseline behavior analysis?"
# → HR/Legal: "What is our process when a resignation involves privileged accounts?"
# → IR Lead: "At what point do we notify Alex's manager? CISO? Legal?"
# → Action item: UEBA/behavior analytics baseline review for privileged accounts
#
# INJECT 2
# ----------
# "Alex runs a PowerShell script to recursively copy the Q3 and Q4 financial
# model directories (~8 GB) to C:\Users\Alex\AppData\Local\Temp\backup2024\.
# Sysmon Event 11 shows thousands of file creation events in a 10-minute window."
#
# DISCUSSION QUESTIONS:
# → Blue Team: "Mass file staging — do we alert on high-volume file reads/copies?"
# → Blue Team: "Would DLP detect financial model files (XLSX, PPTX) being staged?"
# → Red Team: "What are common evasion techniques? (compress to ISO, rename to .bak)"
# → IR Lead: "Evidence preservation — can we capture this activity forensically?"
# → Action item: File staging detection rule (mass file creation in temp dirs)
#
# INJECT 3
# ----------
# "Alex uploads the archive to a personal Google Drive account via the corporate
# web proxy. 8 GB transfer to drive.google.com over 45 minutes."
#
# DISCUSSION QUESTIONS:
# → Blue Team: "Google Drive is not blocked. Do we have CASB visibility into uploads?"
# → Blue Team: "8 GB outbound — do we alert on large file uploads to cloud storage?"
# → Legal: "Can we preserve evidence without alerting Alex? Chain of custody?"
# → HR: "What immediate access termination actions can we take legally?"
# → Action item: CASB/proxy upload volume alert; personal cloud storage policy review</code></pre>

<h2>Scenario 3: Supply Chain Compromise via Build Pipeline</h2>

<pre><code># SCENARIO: Supply Chain Attack via Compromised CI/CD Pipeline
# Threat Actor: State-sponsored APT (SolarWinds-style)
# Objective: Long-term access via trojanized software
# Duration: 3-4 hours
#
# BACKGROUND:
# "Your organization uses a popular third-party logging library (LogBridge v2.3)
# maintained by a small open-source team. Threat intelligence indicates that a
# state-sponsored group has compromised a developer's credentials on the
# LogBridge GitHub repository and introduced a backdoored version (v2.3.1)."
#
# INJECT 1 — Compromise discovery notification
# ---------------------------------------------
# "GitHub security notifies your vendor management team that LogBridge v2.3.1
# contains malicious code. Your build system automatically pulled v2.3.1 three
# weeks ago. The malicious code establishes persistence and phones home to a C2
# domain: logbridge-telemetry[.]io"
#
# DISCUSSION QUESTIONS:
# → IR Lead: "Three weeks of dwell time. What do we know about what the malware does?"
# → Blue Team: "DNS queries to logbridge-telemetry.io — is this in our DNS logs?"
# → Blue Team: "Which of our systems run the affected application?"
# → Dev/IT: "Do we have a software bill of materials (SBOM) for our applications?"
# → Action item: SBOM process; DNS monitoring for new/unusual domain communications
#
# INJECT 2 — Scope determination
# --------------------------------
# "Your DevOps team identifies that the affected application runs on 23 production
# servers. Log analysis shows DNS queries to the C2 domain from 18 of those servers
# starting 21 days ago. The malware is configured to harvest environment variables
# (which include API keys and database credentials) and exfiltrate them."
#
# DISCUSSION QUESTIONS:
# → IR Lead: "18 systems exfiltrating creds for 21 days. What credentials were exposed?"
# → Blue Team: "Environment variable exfil — what does that look like in process telemetry?"
# → Security: "Credential rotation plan — what's the priority order? Which creds matter most?"
# → Red Team: "What would the attacker do with harvested API keys? (cloud pivot, customer data)"
# → Action item: Credential rotation runbook review; secrets scanning in CI/CD
#
# INJECT 3 — Containment decision
# ---------------------------------
# "Threat intel confirms the C2 infrastructure is linked to APT29. The actor is
# known to establish secondary persistence before clean-up operations are detected.
# You must decide: silent remediation (patch and watch) or active containment
# (take systems offline, rotate all credentials, notify customers)."
#
# DISCUSSION QUESTIONS:
# → CISO: "Silent vs active remediation — risk tradeoffs, legal obligations, timeline?"
# → Legal: "Customer notification requirements if their data may have been accessed?"
# → IR Lead: "How do we ensure we find all persistence mechanisms before declaring clean?"
# → Red Team: "APT29 typically uses X, Y, Z secondary persistence. Where do we look?"
# → Action item: APT29 TTP hunting checklist; customer breach notification threshold criteria</code></pre>

<h2>After-Action Report Template</h2>

<pre><code># AFTER-ACTION REPORT TEMPLATE
# ==============================
# Exercise: [Scenario Name]
# Date: [Date]
# Duration: [Hours]
# Participants: [Name, Role]
#
# EXECUTIVE SUMMARY (1-2 paragraphs)
# Description of the exercise, key findings, overall assessment
#
# EXERCISE OBJECTIVES vs OUTCOMES
# Objective 1: [stated objective] → [met/partially met/not met] — [evidence]
# Objective 2: ...
#
# STRENGTHS (What went well)
# - [Observation] — [Evidence/Example from exercise]
# - Example: "SOC escalation to IR team within 15 minutes of inject 2 confirm"
#
# AREAS FOR IMPROVEMENT (Gaps identified)
# - [Observation] — [Root cause] — [Recommended action]
# - Example: "No after-hours escalation path for P1 events — assign on-call rotation"
#
# ACTION ITEMS (Each MUST have owner and due date)
# Priority | Action | Owner | Due Date | Status
# HIGH     | Implement LSASS access alert as P1 | SOC Manager | 2025-02-01 | Open
# HIGH     | Review after-hours escalation path | IR Lead | 2025-01-15 | Open
# MEDIUM   | Enable LDAP diagnostic logging on DCs | IT Ops | 2025-02-15 | Open
# MEDIUM   | Develop file staging detection rule | Detection Eng | 2025-02-01 | Open
# LOW      | Update ransomware response runbook | IR Lead | 2025-03-01 | Open
#
# METRICS
# - Mean Time to Detect (MTTD): [How many minutes from inject to first detection?]
# - Mean Time to Respond (MTTR): [From detection to first containment action?]
# - Detection Rate by Tactic: [How many injects produced discussion of detections?]
# - Escalation accuracy: [Were the right people notified at the right inject?]
#
# NEXT EXERCISE
# - Recommended date: [3-6 months]
# - Suggested scenario: [Based on gaps identified]
# - Suggested scope changes: [What wasn't covered this time?]</code></pre>

<h2>Exercise Metrics</h2>

<pre><code># Key metrics to track across tabletop exercises:
#
# MEAN TIME TO DETECT (MTTD)
#   Definition: Time from attack action to first detection discussion
#   Measurement: Inject timestamp → time participant first says "we would see this in..."
#   Target: < 15 minutes for high-severity techniques
#   Trend: Should decrease as detection rules improve
#
# MEAN TIME TO RESPOND (MTTR)
#   Definition: Time from first detection to first containment action
#   Measurement: Detection discussion → "we would isolate/block/reset at..."
#   Target: < 1 hour for confirmed compromises
#   Trend: Should decrease as runbooks mature
#
# DETECTION RATE BY TECHNIQUE
#   Definition: % of injects where the team identified a detection mechanism
#   Measurement: [Injects with detection discussion] / [Total injects] * 100
#   Target: > 80% for high-severity techniques
#   Trend: Tracks detection engineering progress over multiple exercises
#
# ESCALATION ACCURACY
#   Definition: Were the right stakeholders notified at the right time?
#   Measurement: Qualitative — did escalation happen per the runbook?
#   Target: 100% adherence to escalation playbook
#
# ACTION ITEM CLOSURE RATE
#   Definition: % of action items from previous exercise that were closed before next
#   Measurement: [Closed items] / [Total items from last TTX] * 100
#   Target: > 70% before next exercise
#   Trend: Reflects organizational follow-through culture</code></pre>

<h2>Resources</h2>

<ul>
  <li>CISA Tabletop Exercise Packages — <code>cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages</code></li>
  <li>FEMA Exercise Design Guide — <code>training.fema.gov/hiedu/aemrc/booksdownload/</code></li>
  <li>MITRE ATT&amp;CK for Scenario Design — <code>attack.mitre.org/groups</code></li>
  <li>VECTR — Purple Team Tracking Platform — <code>github.com/SecurityRiskAdvisors/VECTR</code></li>
  <li>NIST SP 800-84 — Guide to Test, Training, and Exercise Programs — <code>nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-84.pdf</code></li>
</ul>
