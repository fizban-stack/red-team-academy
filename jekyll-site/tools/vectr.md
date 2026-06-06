---
layout: training-page
title: "VECTR — Purple Team Exercise Management — Red Team Academy"
module: "Red Team Tools"
tags:
  - vectr
  - purple-team
  - exercise-management
  - attire
  - detection-validation
  - reporting
page_key: "tools-vectr"
render_with_liquid: false
---

# VECTR — Purple Team Exercise Management

VECTR (Security Risk Advisors) is the open-source system of record for purple team programs. It does not run attacks — it records what red executed, what blue detected, and tracks whether your detection coverage is actually improving over time. Every technique becomes a Test Case with structured outcomes, every campaign rolls up into Threat Resilience Metrics, and quarterly comparisons replace one-off PDF reports that rot in SharePoint.

**Current release:** ce-9.13.x (actively maintained, roughly monthly releases since 2019). Community Edition is free and open-source. Enterprise Edition (launched Aug 2024) adds multi-org tenancy, SSO, cross-org peer benchmarking, and Portable Runtime agents for automated TTP execution.

## Data Model

VECTR's hierarchy trips up almost everyone first time. Top to bottom:

| Layer | What It Is |
|-------|------------|
| **Organization** | Top-level tenant boundary. Community Edition has one; Enterprise supports multiple with separated RBAC. |
| **Database / Environment** | An isolated test environment (e.g., `corp-prod`, `corp-dev`, `pentest-lab`). Attack tools, defense tools, sources, and targets are scoped per-environment. |
| **Assessment Group** | A bounded testing event: "Q3 2025 APT29 Emulation," "Monthly Detection Validation," etc. The unit you trend and report on. |
| **Campaign** | Logical grouping inside an Assessment — organized by kill-chain phase, threat-group TTP cluster, or detection layer (endpoint / network / cloud). |
| **Test Case** | The atomic unit. Has commands/instructions, ATT&CK technique mapping, expected outcomes, and recorded outcomes per Defense Tool. |
| **Defense Tool** | The EDR/SIEM/IDS being measured (CrowdStrike, Splunk, SentinelOne). Each Test Case records a per-tool outcome — this is what enables side-by-side vendor comparisons. |
| **Threat Actor / Source / Target** | Metadata for actor-based reporting ("how do we look against APT29 specifically"). |

**Critical:** there is no "loose" Test Case — everything lives inside an Assessment. Create the Assessment before adding test cases.

## Creating a Campaign: End-to-End

<pre><code># VECTR is a web UI + GraphQL API — no CLI. Workflow via browser at https://&lt;host&gt;:8081

# 1. Create or select an Environment (Database)
#    Settings → Databases → New Database
#    Name: "corp-prod-2025"

# 2. Create an Assessment Group
#    Assessments → New Assessment Group
#    Name: "Q3 2025 APT29 Emulation"
#    Start/end dates — these drive the trending math

# 3. Add Defense Tools (the systems being tested)
#    Settings → Defense Tools → Add
#    Add: CrowdStrike Falcon, Splunk ES, Microsoft Sentinel

# 4. Create Campaigns inside the Assessment
#    Campaigns → New Campaign
#    Name: "Initial Access + Execution"
#    Kill Chain Phase: Execution, Initial Access

# 5. Add Test Cases to Campaign
#    Method A: Manual — New Test Case → fill technique, commands, expected outcome
#    Method B: From Library → copy from organizational library or SRA Threat Index
#    Method C: Import → ATTiRe JSON (from CALDERA/Atomic Red Team execution)

# 6. Execute outside VECTR (CALDERA, Invoke-AtomicRedTeam, PurpleSharp, etc.)
#    Keep timestamps — you'll need them for ATTiRe import

# 7. Record Outcomes in VECTR per Test Case per Defense Tool:
#    Detection Outcome: Not Detected | Logged Only | Alert Generated | Blocked
#    Prevention Outcome: Not Prevented | Blocked
#    + detection latency (seconds from execution to alert)
#    + analyst response time
#    + notes and screenshots

# 8. Run Resilience Report after Assessment closes
#    Reports → Resilience Trending → select Assessment
</code></pre>

## ATTiRe Integration (Atomic Red Team + CALDERA)

**ATTiRe** (Attack Tool Timing and Reporting) is the open JSON spec that normalizes execution logs from any attack tool into a shape VECTR can ingest. This is the primary automation path — execute in your tool, import results into VECTR automatically.

### Atomic Red Team → ATTiRe → VECTR

<pre><code># Run Invoke-AtomicRedTeam with the ATTiRe logger:
Invoke-AtomicTest T1003.001 -TestNumbers 1 \
  -LoggingModule "Attire-ExecutionLogger" \
  -ExecutionLogPath "C:\Logs\session-$(Get-Date -f yyyyMMdd).json"

# session-20250615.json is ATTiRe-format — import directly into VECTR:
# VECTR UI → Library → Import Data → ATTiRe → select file → map to Campaign
</code></pre>

### CALDERA → ATTiRe → VECTR

<pre><code># In CALDERA: after operation completes
# Plugins → Debrief → select operation → Export → JSON (Event Logs)
# That export can be converted via community CALDERA-to-ATTiRe converters
# or use the Debrief API endpoint directly

# ATTiRe minimum required fields in JSON:
#{
#  "attire-version": "1.1",
#  "start-timestamp": "2025-06-15T14:02:17Z",
#  "stop-timestamp":  "2025-06-15T14:02:19Z",
#  "execution-data": [{
#    "command": "C:\\ProcDump\\procdump.exe -ma lsass.exe %TEMP%\\dump.dmp",
#    "target": {"host": "WIN-TARGET-01", "ip": "192.168.1.50"},
#    "time-start": "2025-06-15T14:02:17Z",
#    "time-stop":  "2025-06-15T14:02:19Z",
#    "technique": {
#      "mitre-technique-id": "T1003.001",
#      "mitre-technique-name": "LSASS Memory"
#    }
#  }]
#}
</code></pre>

### Mythic → VECTR (Live Linking)

The community **MythicAgents/vectr** agent creates a callback-style service link so Mythic operator tasks flow into VECTR as Test Case outcomes in real time — no export/import step.

## Reporting

**Executive Dashboard:** Detection/prevention percentages, MTTR, MTTD by Campaign.

**ATT&CK Heat Maps:** Techniques colored by detection/prevention outcome — the single most common artifact in board decks. Exportable as ATT&CK Navigator-compatible JSON.

**Resilience Trending:** Same campaign re-run across multiple Assessments over time. Shows whether your detection coverage is actually improving quarter-over-quarter. This is VECTR's primary differentiator over one-off reports.

**Defense Tool Comparison:** Side-by-side EDR/SIEM performance on identical test sets — use this during vendor bake-offs.

**Global Report Filtering by Defense Tool** (added ce-9.12.1): Slice any report to a single tool — essential for isolating CrowdStrike vs. SentinelOne performance on the same technique set.

**CSV Export**: Per-Defense-Tool outcome columns for offline analysis in Excel/Tableau.

## Community Templates (SRA Threat Simulation Index)

Security Risk Advisors publishes annual Threat Simulation Indexes as VECTR-importable YAML. **2026 Index v1.0.0** covers 17 actor/malware sets:

APT29, Lumma, Akira, ShinyHunters, Storm-2603, MuddyWater, Cephalus, Qilin, Play, Famous Chollima, Vidar, XWorm, RansomHub, SocGholish, Gootloader, UNC1549, Scattered Spider.

Import: VECTR UI → **Library → Import Data** → select the merged YAML. Each technique folder includes a REQUIREMENTS.md and operator notebook.

**Import caution:** Don't import the full MITRE Enterprise ATT&CK CTI JSON — it generates thousands of half-empty test cases. Cherry-pick by threat actor.

## GraphQL API

VECTR's API is GraphQL, not REST. Single endpoint, API-key auth:

<pre><code># Endpoint: https://&lt;vectr_host&gt;:8081/sra-purpletools-rest/graphql
# Auth header: Authorization: VEC1 &lt;KEY_ID&gt;:&lt;KEY_SECRET&gt;
# Keys generated under: User Settings → API Keys
# Service accounts used for API must NOT have 2FA enabled (current limitation)

# Query test cases in a database:
curl -H "Authorization: VEC1 KEY_ID:KEY_SECRET" \
     -H "Content-Type: application/json" \
     -d '{"query":"{testcases(db: \"corp-prod-2025\") {nodes{id name attackTechniqueId outcomes{detectionOutcome preventionOutcome}}}}"}' \
     -X POST https://vectr.corp.internal:8081/sra-purpletools-rest/graphql

# List campaigns in an assessment:
curl -H "Authorization: VEC1 KEY_ID:KEY_SECRET" \
     -H "Content-Type: application/json" \
     -d '{"query":"{campaigns(assessmentGroupId: \"ASSESS_UUID\") {nodes{id name description}}}"}' \
     -X POST https://vectr.corp.internal:8081/sra-purpletools-rest/graphql

# Pagination uses cursor-based first/after:
# pageInfo.endCursor + pageInfo.hasNextPage
</code></pre>

**vectr-tools** (SecurityRiskAdvisors/vectr-tools) includes a Python CSV-to-VECTR importer (~90 seconds for 1,000 test cases) using a `.env` config:

<pre><code># .env for vectr-tools:
API_KEY=KEY_ID:KEY_SECRET
VECTR_GQL_URL=https://vectr.corp.internal:8081/sra-purpletools-rest/graphql
CSV_PATH=/opt/purple-team/techniques.csv
TARGET_DB=corp-prod-2025
ORG_NAME=corp

python3 import_csv.py
</code></pre>

## Multi-Team Workflow

VECTR is designed for structured red/blue collaboration:

- **Red team** creates Test Cases with commands, expected outcomes, and notes. Executes outside VECTR, imports ATTiRe results, or manually records what ran.
- **Blue team** records detection/prevention outcomes per Defense Tool, adds latency and response time metrics.
- **Exercise control** reviews coverage gaps in the heat map and feeds new techniques to the next campaign.

Access control is per-Environment (Community Edition). Enterprise adds org-level RBAC, SSO, and cross-org peer benchmarking.

## In the Self-Hosted Stack

VECTR sits at the top of the tracking layer:

<pre><code>VECTR                   ← system of record, trending, executive reporting
↑ (ATTiRe import)
Atomic Red Team / CALDERA / PurpleSharp   ← execution layer
↑ (range substrate)
Ludus                   ← where the target machines live
</code></pre>

## OPSEC Notes

- VECTR stores operator commands, outputs, and screenshots — treat as sensitive. Lock down access.
- API keys are not scoped (account-level) — rotate after each engagement.
- On-prem by default; community deployment runs as Docker Compose. Keep off the internet.

## Resources

- VECTR GitHub — `github.com/SecurityRiskAdvisors/VECTR`
- VECTR documentation — `docs.vectr.io`
- SRA Threat Simulation Indexes — `github.com/SecurityRiskAdvisors/indexes`
- vectr-tools (Python API tools) — `github.com/SecurityRiskAdvisors/vectr-tools`
- ATTiRe format spec — `github.com/attackiq/attire`
- MythicAgents/vectr integration — `github.com/MythicAgents/vectr`
- VECTR Enterprise info — `sra.io/vectr-community/`
- Self-hosted tools overview — `tools/self-hosted-tools/`
