---
layout: training-page
title: "Purple Team Overview — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - detection
  - mitre-attack
  - tiber-eu
  - cbest
  - adversary-emulation
page_key: "purple-team-overview"
render_with_liquid: false
---

<h1>Purple Team: Overview</h1>

<p>Purple teaming is a collaborative security validation methodology where offensive operators (red team) and defensive analysts (blue team) work together toward a shared goal: improving the organization's ability to detect, respond to, and contain real-world threats. Unlike a traditional red team engagement where stealth and non-attribution are paramount, a purple team exercise is an open, structured conversation about detection coverage.</p>

<p>This module builds on the attack techniques covered elsewhere in Red Team Academy and teaches you how to use those skills to drive measurable security improvements. Every technique you learn on the offensive side has a detection story — purple teaming is where you learn to write that story from both sides of the table.</p>

<h2>Red Team vs Blue Team vs Purple Team</h2>

<pre><code># The three team model — understanding roles:
#
# RED TEAM
# --------
# Mission:  Simulate a real-world adversary
# Goal:     Achieve objectives without detection
# Output:   Findings report, narrative, IOCs
# Mindset:  Adversarial — assume defenders are watching
# Metric:   Objectives achieved, dwell time, evasion rate
#
# BLUE TEAM
# ---------
# Mission:  Detect, respond to, and contain threats
# Goal:     Minimize time-to-detect and time-to-respond
# Output:   Detection rules, incident reports, runbooks
# Mindset:  Defensive — hunt for anomalies, build coverage
# Metric:   MTTD (mean time to detect), MTTR (mean time to respond)
#
# PURPLE TEAM
# -----------
# Mission:  Validate and improve the detection capability
# Goal:     Close gaps between what attackers do and what defenders see
# Output:   Updated detection rules, coverage maps, tuned alerts
# Mindset:  Collaborative — attacker explains what they did, defender explains what they saw
# Metric:   Technique coverage %, detection rate improvement, false positive rate
#
# Key distinction:
# - Red team: "We got in and you didn't know" → proves risk
# - Purple team: "We ran T1059.001 and here is what fired" → builds coverage</code></pre>

<h2>When Purple Teaming is Appropriate</h2>

<p>Purple teaming is not a substitute for a red team engagement — it is a complement to it. Purple teaming requires a <strong>mature blue team</strong> as a prerequisite. Running a purple team exercise against an organization that has no SIEM, no Sysmon deployment, and no alert pipeline produces little value. The preconditions for productive purple teaming are:</p>

<pre><code># Prerequisites for effective purple teaming:
#
# 1. Log collection is deployed
#    - Windows Event Forwarding or agent-based collection (Elastic Agent, Splunk UF)
#    - Sysmon installed with a reasonable config (SwiftOnSecurity or sysmon-modular)
#    - Command-line audit policy enabled (4688 with command line)
#    - PowerShell Script Block Logging enabled (Event ID 4104)
#    - Network connection logging (Sysmon 3 or NetFlow)
#
# 2. A SIEM is operational
#    - Logs are searchable (Elastic/Kibana, Splunk, Sentinel, etc.)
#    - Alert pipeline exists (rules produce alerts, alerts route to analysts)
#    - Analysts know how to write and test detection queries
#
# 3. Blue team is staffed and engaged
#    - Analysts available to participate in real time
#    - Team has authority to tune detection rules
#    - Management supports measurable outcomes (coverage %, metrics)
#
# 4. Scope and rules of engagement are defined
#    - Which systems are in scope for technique execution
#    - What time windows are acceptable (business hours, maintenance windows)
#    - Who approves each technique before execution
#
# If these conditions are NOT met:
# - Start with detection engineering workshops instead
# - Deploy logging infrastructure first (see detection-lab-setup.md)
# - Run tabletop exercises to build process maturity before live execution</code></pre>

<h2>The Purple Team Loop</h2>

<p>The core workflow of purple teaming is a structured feedback loop. Each iteration improves detection coverage for a specific ATT&CK technique. The loop repeats until coverage is satisfactory or gaps are accepted as residual risk.</p>

<pre><code># The Purple Team Loop — one technique per iteration:
#
# ┌─────────────────────────────────────────────────────────┐
# │                                                         │
# │   ATTACK → LOG → DETECT → TUNE → VERIFY → (repeat)    │
# │                                                         │
# └─────────────────────────────────────────────────────────┘
#
# Step 1: ATTACK
#   - Red team operator selects an ATT&CK technique
#   - Executes the technique on an in-scope system
#   - Documents: exact command, time of execution, target host
#   - Tools: Atomic Red Team, manual execution, Caldera
#   - Example: Invoke-AtomicTest T1003.001 -TestNumbers 1
#
# Step 2: LOG
#   - Blue team analyst reviews raw telemetry for that time window
#   - Identifies what artifacts were produced:
#     * Which Windows Event IDs fired?
#     * Which Sysmon events captured it?
#     * What process tree was created?
#   - Determines if required data sources are even present
#   - If no relevant events: data source gap identified
#
# Step 3: DETECT
#   - Analyst writes or reviews a detection query/rule
#   - Tests whether the existing rule would have caught it
#   - If no rule exists: write one now (Sigma → convert to SIEM)
#   - Run the query against the execution time window
#   - Did it produce a true positive alert?
#
# Step 4: TUNE
#   - If detection fired with false positives: tighten the logic
#   - If detection missed: broaden coverage or add new data source
#   - Add detection filters to suppress known-good processes
#   - Adjust alert confidence level (high/medium/low)
#
# Step 5: VERIFY
#   - Red team executes the technique again (variation)
#   - Blue team confirms detection fires on the new execution
#   - Test evasion variants: same technique, different tooling
#   - Document: detection rate, false positive rate, coverage confidence
#
# Repeat for next technique in the priority list</code></pre>

<h2>Major Purple Team Frameworks</h2>

<h3>TIBER-EU</h3>

<p>TIBER-EU (Threat Intelligence-Based Ethical Red Teaming for EU) is a European framework developed by the European Central Bank (ECB) for testing the cyber resilience of financial sector organizations. It is widely adopted by central banks and financial regulators across the EU.</p>

<pre><code># TIBER-EU Framework Overview:
#
# Phase 1: PREPARATION
#   - Engagement scoping with senior leadership and regulators
#   - Threat landscape assessment (what adversaries target this org?)
#   - Define crown jewels and critical functions
#   - Procurement of approved red team provider and threat intel provider
#
# Phase 2: TESTING
#   - Threat Intel phase: Targeted Threat Intelligence Report (TTIR)
#     * Identifies specific threat actors likely to target the organization
#     * Maps their TTPs to the current environment
#   - Red Team phase: Adversary emulation based on TTIR
#     * Red team replicates specific threat actor TTPs
#     * Tests against defined target systems
#     * Covers initial access, persistence, lateral movement, objective completion
#
# Phase 3: CLOSURE
#   - Purple team exercise: replay techniques with blue team present
#   - Gap analysis: what was missed vs detected
#   - Remediation planning with prioritized recommendations
#   - Final report to regulators (for regulated entities)
#
# Key characteristics:
# - Intelligence-led: attacks are based on real threat actor behavior
# - Regulator-endorsed: results can satisfy regulatory requirements
# - Three-party model: organization, red team provider, threat intel provider
# - Closed loop: purple team closure is mandatory, not optional
#
# Website: https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html</code></pre>

<h3>CBEST</h3>

<p>CBEST is the UK equivalent of TIBER-EU, developed by the Bank of England and the Financial Conduct Authority (FCA). It applies to firms regulated by these bodies including banks, insurance companies, and financial market infrastructure.</p>

<pre><code># CBEST Framework Overview:
#
# Similar to TIBER-EU with UK-specific adaptations:
# - Threat Intelligence: CREST-certified threat intel providers
# - Red Team: CREST-certified penetration testing firms
# - Scope: FCA/PRA regulated firms
#
# CBEST test phases:
# 1. Scoping and approvals (regulator notification required)
# 2. Threat Intelligence report (30-60 day intelligence gathering)
# 3. Red team testing (60-90 days of adversary emulation)
# 4. Remediation and re-testing
# 5. Report submission to Bank of England / FCA
#
# Key document: "CBEST Intelligence-Led Testing: Framework" (Bank of England)
# URL: https://www.bankofengland.co.uk/financial-stability/operational-resilience/cbest</code></pre>

<h3>CREST STAR</h3>

<p>CREST STAR (Simulated Target Attack and Response) is a framework from CREST (Council of Registered Ethical Security Testers) designed for organizations that want to run intelligence-led adversary emulation tests without the full regulatory overhead of TIBER-EU or CBEST.</p>

<pre><code># CREST STAR Framework Overview:
#
# STAR is designed for:
# - Organizations outside regulated financial sector
# - Organizations preparing for TIBER/CBEST engagement
# - Periodic security validation between formal assessments
#
# STAR phases:
# 1. STAR-FS (Foundations): establish scope, crown jewels, threat profile
# 2. STAR-TI (Threat Intelligence): targeted intel report for the organization
# 3. STAR-PT (Penetration Test): adversary emulation by CREST-certified team
# 4. STAR-PR (Purple Team Review): closure exercise, gap analysis
#
# STAR-Light variant:
# - Streamlined version for smaller organizations
# - Shorter timeline (30-60 days vs 90-180 days)
# - Less regulatory documentation overhead
# - Same technical rigor, reduced compliance burden
#
# URL: https://www.crest-approved.org/membership/star/</code></pre>

<h2>Recommended Tooling Stack</h2>

<pre><code># Purple team tooling stack — what you need for an effective exercise:
#
# ATTACK EXECUTION
#   Atomic Red Team    — technique-level test cases, ATT&CK mapped
#   MITRE Caldera      — automated adversary emulation, agent-based
#   Cobalt Strike      — C2 framework, realistic adversary simulation
#   Manual execution   — scripted PowerShell/bash for custom scenarios
#
# LOG COLLECTION & SIEM
#   Elastic Stack      — Elasticsearch + Kibana + Fleet (recommended for labs)
#   Splunk             — industry standard, powerful SPL queries
#   Microsoft Sentinel — Azure-native, good for M365/Azure environments
#   Wazuh              — open-source, lighter weight than Elastic
#
# ENDPOINT TELEMETRY
#   Sysmon             — Windows kernel-level event generation (free, Microsoft)
#   Elastic Agent      — cross-platform, integrates with Elastic Stack
#   CrowdStrike/SentinelOne — commercial EDR with rich telemetry
#   Velociraptor       — live response + artifact collection
#
# DETECTION ENGINEERING
#   Sigma              — universal detection rule language (convert to any SIEM)
#   sigma-cli          — Sigma rule conversion tool
#   pySigma            — Python library for Sigma conversion
#   Elastic Detection Rules — community detection rules for Elastic
#
# COVERAGE MAPPING
#   ATT&CK Navigator   — visual technique coverage mapping
#   DeTT&CT            — data source and detection coverage tool
#   VECTR              — purple team tracking and reporting platform
#
# DOCUMENTATION & TRACKING
#   VECTR              — track exercise results, generate reports
#   PlexTrac           — engagement management platform
#   Confluence/Notion  — custom exercise tracking</code></pre>

<h2>Module Overview — What Each Page Covers</h2>

<pre><code># This Purple Team module contains seven pages:
#
# 1. Overview (this page)
#    - Red vs Blue vs Purple distinctions
#    - The purple team loop
#    - Major frameworks (TIBER-EU, CBEST, CREST STAR)
#    - Tooling stack overview
#
# 2. Detection Lab Setup (detection-lab-setup.md)
#    - Building a self-hosted detection lab from scratch
#    - Elastic Stack deployment via Docker Compose
#    - Sysmon, Winlogbeat, Velociraptor configuration
#    - Connecting attack lab to detection lab
#
# 3. SIEM Queries (siem-queries.md)
#    - KQL and SPL query writing for ATT&CK techniques
#    - Queries organized by tactic
#    - Real event IDs, field names, and conditions
#
# 4. Sigma Rules (sigma-rules.md)
#    - Writing and converting Sigma rules
#    - 8 complete production-quality Sigma rules
#    - sigma-cli conversion and testing
#
# 5. ATT&CK Coverage Mapping (attack-coverage-mapping.md)
#    - ATT&CK Navigator usage
#    - Scoring methodology and gap analysis
#    - DeTT&CT for data source mapping
#
# 6. Tabletop Exercises (tabletop-exercises.md)
#    - Running facilitated purple team tabletop exercises
#    - 3 complete scenario scripts
#    - After-action report templates
#
# 7. Threat Hunting (threat-hunting.md)
#    - Hypothesis-driven hunting methodology
#    - 6 complete hunt playbooks with queries
#    - Converting hunt findings to detection rules
#
# Connection to attack-side modules:
# - Lateral Movement techniques → see siem-queries.md lateral movement section
# - Credential Access tools (Mimikatz, etc.) → see sigma-rules.md LSASS/DCSync rules
# - C2 frameworks → see siem-queries.md C2 beacon detection
# - Persistence techniques → see threat-hunting.md persistence hunt playbook</code></pre>

<h2>Resources</h2>

<ul>
  <li>MITRE ATT&amp;CK Framework — <code>attack.mitre.org</code></li>
  <li>TIBER-EU Framework — <code>ecb.europa.eu/paym/cyber-resilience/tiber-eu</code></li>
  <li>CBEST Framework — <code>bankofengland.co.uk/financial-stability/operational-resilience/cbest</code></li>
  <li>CREST STAR — <code>crest-approved.org/membership/star</code></li>
  <li>VECTR Purple Team Platform — <code>vectr.io</code></li>
  <li>Atomic Red Team — <code>github.com/redcanaryco/atomic-red-team</code></li>
  <li>MITRE Caldera — <code>github.com/mitre/caldera</code></li>
  <li>ATT&amp;CK Navigator — <code>mitre-attack.github.io/attack-navigator</code></li>
</ul>
