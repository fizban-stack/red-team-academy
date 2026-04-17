---
layout: training-page
title: "ATT&CK Coverage Mapping — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - mitre-attack
  - attack-navigator
  - detection-coverage
  - dettect
  - gap-analysis
page_key: "purple-team-attack-coverage-mapping"
render_with_liquid: false
---

<h1>ATT&amp;CK Coverage Mapping</h1>

<p>Coverage mapping is the process of determining which MITRE ATT&amp;CK techniques your current detection capability can identify, and which it cannot. A coverage map transforms the abstract idea of "we have good detections" into a measurable, visual representation showing exactly where your detection capability is strong, where it's partial, and where there are complete gaps.</p>

<p>Coverage mapping drives purple team exercise prioritization: you work on the techniques with the worst detection coverage first. Over time, iterating through the purple team loop closes gaps and shifts your coverage map from red to green.</p>

<h2>ATT&amp;CK Navigator Basics</h2>

<p>ATT&amp;CK Navigator is the official MITRE tool for creating and editing coverage layers. It renders the ATT&amp;CK matrix as an interactive heatmap where each cell represents a technique and can be colored, scored, and annotated.</p>

<pre><code># Accessing ATT&CK Navigator:
# Online: https://mitre-attack.github.io/attack-navigator/
# Self-hosted (recommended for sensitive data):
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install
npm run start
# Access at http://localhost:4200

# Navigator key operations:
#
# CREATING A NEW LAYER
# 1. Click "Create New Layer"
# 2. Select domain: Enterprise ATT&CK (most common), Mobile, or ICS
# 3. Select ATT&CK version (use latest stable — currently v14)
# 4. Layer opens — all techniques visible, none selected/colored
#
# SELECTING TECHNIQUES
# - Click individual technique cells to select
# - Shift+click to select multiple
# - Use "Select Techniques" button to filter by tactic, platform, data source
#
# COLORING BY DETECTION STATUS
# 1. Select techniques → click "Background Color" → choose color
#    Color convention (widely used):
#    #0000ff blue    — tested technique (purple team exercise completed)
#    #00ff00 green   — automated detection rule in place
#    #ffff00 yellow  — partial detection or noisy rule
#    #ff0000 red     — no detection coverage
#    #ffffff white   — not in scope / not tested
#
# SCORING
# - Score field (0-100) tracks detection confidence
# - Use score for heat gradient coloring
# - Scores drive gap analysis queries
#
# COMMENTS / ANNOTATIONS
# - Add technique-level comments with rule names, last tested date
# - Visible on hover in the matrix view
#
# EXPORT
# Layer → Download Layer as JSON (saves complete layer for version control)</code></pre>

<h2>Scoring Methodology</h2>

<p>A consistent scoring scale allows you to quantify detection coverage and track improvement over time. The four-point scale below maps technical detection states to actionable priorities.</p>

<pre><code># Detection Coverage Scoring Scale:
#
# Score 0 — NO DETECTION
#   Meaning:  No detection rule exists, no telemetry collected, or technique
#             was confirmed to produce zero alerts in testing
#   Color:    Red (#ff0000) or gray (#cccccc for unknown)
#   Action:   Highest priority — implement detection rule or data source
#   Example:  Process hollowing (T1055.012) — no Sysmon rule, not tested
#
# Score 1 — PARTIAL / NOISY DETECTION
#   Meaning:  A detection rule exists but has high false positive rate,
#             only catches specific variants, or coverage is incomplete
#   Color:    Yellow (#ffff00)
#   Action:   Medium priority — tune rule, add data source, expand coverage
#   Example:  PowerShell execution (T1059.001) rule fires on all PS, not tuned
#
# Score 2 — ALERTING DETECTION
#   Meaning:  Detection rule fires reliably, is tuned to low false positives,
#             and routes to analyst queue
#   Color:    Green (#00ff00)
#   Action:   Maintain — retest after environment changes, watch for evasions
#   Example:  DCSync (T1003.006) — Event 4662 with GUID filter, confirmed TP
#
# Score 3 — AUTOMATED RESPONSE
#   Meaning:  Detection fires AND automated response triggers (quarantine,
#             block, SOAR playbook runs without analyst intervention)
#   Color:    Dark Green (#005500) or Blue
#   Action:   Validate response actions are correct, prevent abuse
#   Example:  LSASS access — EDR auto-kills process, creates incident ticket
#
# Using scores in Navigator:
# - Set "Score Color Gradient" to use low=red, high=green
# - Filter by score < 1 to find all gaps
# - Export filtered view for remediation prioritization</code></pre>

<h2>Gap Analysis — Finding Your Worst Detection Gaps</h2>

<pre><code># Gap analysis methodology:
#
# Step 1: Populate your Navigator layer
#   - For every technique in your detection rule set, mark score 1 or 2
#   - Leave undetected techniques at score 0
#   - Techniques without telemetry data source: score 0 with comment "no data"
#
# Step 2: Map threat actor TTPs to your layer
#   - In Navigator: "Select Techniques Used By" → choose threat actor group
#   - Example: APT29, Lazarus Group, FIN7
#   - This creates a "threat actor layer"
#   - Overlay it with your coverage layer
#
# Step 3: Identify gaps at your highest-risk tactics
#   - Filter layer by tactic, sort by score ascending
#   - Focus order: Credential Access → Lateral Movement → Persistence
#     (these are high-value, high-frequency targets)
#   - For each gap: assess likelihood and impact
#
# Step 4: Prioritize gaps by:
#   - Threat actor frequency (how often do relevant APTs use this?)
#   - Technique impact (credential theft > low-impact discovery)
#   - Detection difficulty (easy wins first)
#   - Data source availability (do you even have the logs?)
#
# Step 5: Create detection backlog
#   - Ordered list of techniques to add detections for
#   - Each backlog item includes: technique ID, required data source,
#     draft Sigma rule, estimated effort
#
# Practical filtering in Navigator:
# 1. Click "Scoring" → set filter "Techniques: Show Only Techniques with Score"
# 2. Set to "Less than 1" → matrix shows only uncovered techniques
# 3. Enable platform filter for your environment (Windows, Linux, Cloud)
# 4. Export filtered matrix as SVG for gap analysis report</code></pre>

<h2>Using Coverage Mapping to Prioritize Purple Team Exercises</h2>

<pre><code># Coverage-driven purple team planning:
#
# QUARTERLY REVIEW PROCESS
#
# 1. Export current coverage layer from Navigator
#    Compare with previous quarter layer (git diff shows changes)
#
# 2. Identify top 10 uncovered techniques for the quarter:
#    - Techniques scored 0 in highest-priority tactics
#    - Techniques recently exploited in the wild (threat intel input)
#    - Techniques used by threat actors targeting your industry
#
# 3. Map each technique to an Atomic Red Team test:
#    Invoke-AtomicTest T1003.001 -ShowDetailsBrief
#    If no ART test exists, write a manual execution script
#
# 4. Schedule purple team exercise sessions:
#    - 2-3 techniques per session (1-2 hour sessions work well)
#    - Red team: execute and document
#    - Blue team: query SIEM, write rule, confirm detection
#
# 5. After exercise: update Navigator layer with new scores
#    - Committed to git with date: git commit -m "Q1 2025 purple team coverage update"
#
# 6. Generate coverage delta report:
#    Before: 45% coverage of Enterprise ATT&CK
#    After: 52% coverage — 15 new detections added

# Technique prioritization matrix:
#
# HIGH PRIORITY (Start here):
# T1003.001  Credential Access — LSASS Memory
# T1003.006  Credential Access — DCSync
# T1558.003  Credential Access — Kerberoasting
# T1021.002  Lateral Movement — SMB/Windows Admin Shares
# T1021.003  Lateral Movement — DCOM
# T1053.005  Persistence — Scheduled Task
# T1059.001  Execution — PowerShell
# T1078      Defense Evasion/Persistence — Valid Accounts
#
# MEDIUM PRIORITY:
# T1055      Defense Evasion — Process Injection
# T1071.001  C2 — Web Protocols
# T1041      Exfiltration Over C2 Channel
# T1027      Defense Evasion — Obfuscated Files</code></pre>

<h2>DeTT&CT Tool</h2>

<p>DeTT&CT (Detection Coverage and Threat Actor) is a Python tool that maps your data sources and detection rules to ATT&CK techniques and generates Navigator layers programmatically. It provides a more structured, file-based approach to coverage management compared to manual Navigator editing.</p>

<pre><code># DeTT&CT installation
# https://github.com/rabobank-cdc/DeTTECT
pip install dettect

# DeTT&CT uses three YAML file types:
#
# 1. data-sources.yaml — what telemetry do you collect?
# 2. techniques.yaml   — what techniques can you detect with that data?
# 3. groups.yaml       — threat actor group profiles
#
# Example data-sources.yaml (partial):
name: Lab Detection Stack
platform: Windows
data_sources:
  - data_source_name: Process creation
    date_registered: 2024-01-01
    date_connected: 2024-01-01
    products:
      - Sysmon
      - Windows Security (4688)
    available_for_data_analytics: true
    data_quality:
      device_completeness: 4     # 1-5 scale: 5=all endpoints covered
      data_field_completeness: 4 # 1-5: are all important fields collected?
      timeliness: 5              # 1-5: how quickly is data available?
      consistency: 4             # 1-5: is data format consistent?
      retention: 4               # 1-5: how long is data kept?

  - data_source_name: Windows event logs
    products:
      - Windows Security
      - Windows System
    available_for_data_analytics: true
    data_quality:
      device_completeness: 5
      data_field_completeness: 4
      timeliness: 5
      consistency: 5
      retention: 3

# Generate Navigator layer from data sources
dettect ds -fd data-sources.yaml -l
# Output: navigator layer showing which techniques have data source coverage

# Example techniques.yaml entry
name: Lab Detection Rules
platform: Windows
techniques:
  - technique_id: T1003.001
    technique_name: LSASS Memory
    detection:
      applicable_to:
        - all
      date_implemented: 2024-06-01
      location:
        - Kibana Detection Rules
      rule_confidence: good       # minimal/fair/good/excellent
      score_logbook:
        - date: 2024-06-01
          score: 75
          comment: Sigma rule deployed, tested with Mimikatz ART T1003.001 #1
        - date: 2024-09-15
          score: 85
          comment: Added additional GrantedAccess masks, reduced FPs

# Generate detection score layer
dettect tc -fd techniques.yaml -l
# Output: navigator layer with color-coded detection scores</code></pre>

<h2>Tracking Coverage Over Time with Git</h2>

<pre><code># Structure for tracking coverage in a git repository:
#
# detection-coverage/
# ├── layers/
# │   ├── enterprise-coverage-2025-Q1.json   (Navigator JSON export)
# │   ├── enterprise-coverage-2025-Q2.json
# │   └── enterprise-coverage-current.json  (symlink to latest)
# ├── dettect/
# │   ├── data-sources.yaml
# │   ├── techniques.yaml
# │   └── groups/
# │       ├── apt29.yaml
# │       └── fin7.yaml
# ├── sigma-rules/
# │   ├── credential-access/
# │   ├── lateral-movement/
# │   └── persistence/
# └── README.md  (coverage statistics, last updated date)
#
# Git workflow:
# After each purple team exercise:
git add layers/enterprise-coverage-current.json sigma-rules/
git commit -m "feat: add DCSync and Kerberoasting detections — Q2 2025 PT session 3"
git push origin main

# Generate coverage statistics from Navigator JSON
python3 << 'EOF'
import json

with open('layers/enterprise-coverage-current.json') as f:
    layer = json.load(f)

scored = [t for t in layer['techniques'] if t.get('score', 0) > 0]
total = len(layer['techniques'])
print(f"Scored techniques: {len(scored)}/{total} ({len(scored)/total*100:.1f}%)")

by_score = {}
for t in layer['techniques']:
    s = t.get('score', 0)
    by_score[s] = by_score.get(s, 0) + 1

for score, count in sorted(by_score.items()):
    labels = {0: "No detection", 1: "Partial", 2: "Alert", 3: "Auto-response"}
    label = labels.get(score, str(score))
    print(f"  Score {score} ({label}): {count} techniques")
EOF</code></pre>

<h2>Sample ATT&amp;CK Navigator Layer JSON</h2>

<pre><code">{
  "name": "Enterprise Detection Coverage — Lab",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Purple team detection coverage map — Red Team Academy Lab",
  "filters": {
    "platforms": ["Windows", "Linux"]
  },
  "sorting": 0,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": false,
    "showName": true,
    "showAggregateScores": true,
    "countUnscored": false,
    "expandedSubtechniques": "annotated"
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T1003.001",
      "tactic": "credential-access",
      "score": 2,
      "color": "#00ff00",
      "comment": "Sigma: lsass_access.yml — Sysmon 10 — Tested 2025-06-01 with ART T1003.001 #1",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1003.006",
      "tactic": "credential-access",
      "score": 2,
      "color": "#00ff00",
      "comment": "Sigma: dcsync.yml — Event 4662 — Tested with secretsdump.py",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1558.003",
      "tactic": "credential-access",
      "score": 2,
      "color": "#00ff00",
      "comment": "Sigma: kerberoasting.yml — Event 4769 RC4 — Tested with Rubeus",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1055.001",
      "tactic": "defense-evasion",
      "score": 1,
      "color": "#ffff00",
      "comment": "Partial: Sysmon 8 rule catches CreateRemoteThread but misses APC injection",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1021.002",
      "tactic": "lateral-movement",
      "score": 2,
      "color": "#00ff00",
      "comment": "PsExec detection via 7045 + Sysmon 17 pipe — Tested with CrackMapExec",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1134.001",
      "tactic": "privilege-escalation",
      "score": 0,
      "color": "#ff0000",
      "comment": "GAP: No detection rule for token impersonation variants",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    }
  ],
  "gradient": {
    "colors": ["#ff0000", "#ffff00", "#00ff00"],
    "minValue": 0,
    "maxValue": 3
  },
  "legendItems": [
    {"label": "No detection", "color": "#ff0000"},
    {"label": "Partial / noisy", "color": "#ffff00"},
    {"label": "Alert in place", "color": "#00ff00"}
  ],
  "metadata": [],
  "links": [],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#dddddd",
  "selectTechniquesAcrossTactics": true,
  "selectSubtechniquesWithParent": false,
  "selectVisibleTechniques": false
}</code></pre>

<h2>Resources</h2>

<ul>
  <li>ATT&amp;CK Navigator — <code>mitre-attack.github.io/attack-navigator</code></li>
  <li>ATT&amp;CK Navigator GitHub — <code>github.com/mitre-attack/attack-navigator</code></li>
  <li>DeTT&CT — <code>github.com/rabobank-cdc/DeTTECT</code></li>
  <li>DeTT&CT Documentation — <code>github.com/rabobank-cdc/DeTTECT/wiki</code></li>
  <li>MITRE ATT&amp;CK Enterprise Matrix — <code>attack.mitre.org/matrices/enterprise</code></li>
  <li>ATT&amp;CK Groups (threat actor TTPs) — <code>attack.mitre.org/groups</code></li>
  <li>VECTR Purple Team Tracking — <code>github.com/SecurityRiskAdvisors/VECTR</code></li>
</ul>
