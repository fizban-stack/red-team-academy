---
layout: training-page
title: "OpenAEV — Breach and Attack Simulation — Red Team Academy"
module: "Red Team Tools"
tags:
  - openaev
  - openbas
  - breach-attack-simulation
  - purple-team
  - scenario-based
  - filigran
  - opencti
page_key: "tools-openaev"
render_with_liquid: false
---

# OpenAEV — Adversarial Exposure Validation

**OpenAEV** (formerly OpenBAS — Breach and Attack Simulation) is the open-source adversarial exposure validation platform from Filigran, the same team behind OpenCTI. Filigran rebranded OpenBAS to OpenAEV in November 2025, reflecting a shift from "BAS" to *Adversarial Exposure Validation* — a scope that goes beyond controls testing to include exposure prioritization driven by live threat intelligence.

**Current release:** v2.260604.0 (June 2026). Apache 2.0 license. Actively developed; monthly releases, ~1.7k GitHub stars. Community Edition is free/open-source; Enterprise Edition adds AI-assisted scenario authoring, advanced automation, and managed integrations. Docs: `docs.openaev.io` (old `docs.openbas.io` redirects).

## What OpenAEV Is Not

OpenAEV is not a replacement for CALDERA or Atomic Red Team — it's the **orchestration and tracking layer above them**. It can use CALDERA agents and Atomic Red Team tests as executors inside its inject framework, but its unique value is:

1. **Scheduling** — run the same scenario monthly, automatically
2. **Human exercises** — email, SMS, and in-platform injects to players (SOC analysts, sysadmins, CISO)
3. **Multi-dimension scoring** — Prevention + Detection + Vulnerability + Human Response, all in one exercise
4. **Threat-intel-driven scenarios** — pull real actor profiles from OpenCTI, generate scenarios automatically

## Core Data Model

| Concept | What It Is |
|---------|------------|
| **Scenario** | The reusable template — an ordered sequence of injects. Built once, run many times. |
| **Simulation / Exercise** | A live instance of a scenario, one-time or recurring. The execution and scoring artifact. |
| **Inject** | The atomic action. Technical (endpoint command, payload) or non-technical (email, SMS, decision prompt). |
| **Payload** | Reusable procedure: Command, Executable, File Drop, DNS Resolution, Network Traffic — mapped to ATT&CK. |
| **Team** | Group of Players (humans or roles: "SOC L1," "sysadmin") who receive non-technical injects and produce human-response telemetry. |
| **Asset** | A system under test (workstation, server, container). |
| **Asset Group** | Collection of assets selected dynamically (tag-based) or statically for inject targeting. |
| **Agent** | Execution surrogate on an Asset. OpenAEV ships its own cross-platform agent; CALDERA agents also work. |
| **Channel** | Distribution surface for human injects: email, SMS, in-platform messaging. |
| **Expectation** | What should happen as a result of an inject: Prevention, Detection, Vulnerability, Human Response. Validated manually or automatically via collector. |
| **Collector** | Integration that auto-validates expectations: CrowdStrike, MDE, Sentinel, SentinelOne, Splunk. |

## OpenAEV vs. CALDERA vs. Atomic Red Team

| Dimension | CALDERA | Atomic Red Team | OpenAEV |
|-----------|---------|-----------------|---------|
| Primary unit | Adversary profile + abilities | Atomic test (single command) | Scenario of mixed injects |
| Execution model | Agent-driven autonomous chains | Manual or Invoke-AtomicTest | Multi-executor: own agent, CALDERA, Atomic, manual |
| Human element | None | None | First-class (players, teams, email/SMS) |
| Scoring | Operational success only | None natively | 4-dimension: Prevention/Detection/Vulnerability/Human |
| Auto-validation | No | No | Yes — via collector integrations |
| Scheduling | Manual | Manual | Cron-style recurrence built-in |
| Threat-intel-driven | No | No | Yes — OpenCTI integration |
| Best for | Endpoint emulation chains | Per-technique detection tests | Whole-org exercises with human participants |

## Agent Deployment

<pre><code># Deploy OpenAEV agent on Windows:
Invoke-WebRequest -Uri "https://openaev.corp.internal/api/agent/packages/windows" \
  -OutFile "openaev-agent.exe"
Start-Process "openaev-agent.exe" -ArgumentList "--uri https://openaev.corp.internal --token TOKEN"

# Deploy on Linux:
curl -s "https://openaev.corp.internal/api/agent/packages/linux" -o openaev-agent
chmod +x openaev-agent
./openaev-agent --uri https://openaev.corp.internal --token TOKEN &

# Or use CALDERA agents as executors (enable CALDERA injector in OpenAEV settings)
# CALDERA is configured as an executor; OpenAEV sends ability IDs to CALDERA's API
</code></pre>

## Scenario Building Workflow

<pre><code># All via the web UI at https://&lt;openaev_host&gt;:80 (or your configured port)

# Step 1: Import assets
# Assets → Import → CSV or auto-discovery via collector
# Or add manually: Assets → New Asset → hostname, IP, platform, tags

# Step 2: Import or create teams
# Teams → New Team → "SOC Team", "IT Ops", "CISO"
# Add players to each team with real or role-based identities

# Step 3: Create payloads (reusable procedures)
# Payloads → New Payload → type: Command
#   Name: "Kerberoast via PowerShell"
#   ATT&CK technique: T1558.003
#   Platform: Windows
#   Content: "Invoke-AtomicTest T1558.003 -GetPrereqs; Invoke-AtomicTest T1558.003"
#   Executor: OpenAEV Agent (or CALDERA)

# Step 4: Create the scenario
# Scenarios → New Scenario
#   Name: "APT29 Initial Access Exercise"
#   Description, MITRE actor mapping, kill-chain phases
#   Tags for categorization

# Step 5: Add injects in order with timing offsets
# Scenario → Injects → Add Inject
#   T+0:    technical inject — "Execution via PowerShell" on Asset Group "workstations"
#           Payload: T1059.001 payload
#           Expectation: Detection (expect SIEM alert within 5 min)
#   T+15m:  human inject — email to "SOC Team" channel
#           Subject: "Unusual PowerShell detected on WS-01 — please investigate"
#           Expectation: Human Response (runbook completion within 30 min)
#   T+45m:  technical inject — "LSASS dump" on WS-01
#           Payload: T1003.001 payload
#           Expectation: Prevention (expect CrowdStrike to block)
#   T+90m:  human inject — SMS to "CISO" channel
#           "Potential credential theft in progress — escalation decision required"

# Step 6: Schedule as a simulation
# Simulations → New Simulation → select scenario
# Run mode: One-time | Recurring (cron)
# Recurring example: every first Monday of the month at 14:00 UTC

# Step 7: Launch
# Simulations → Start → confirmation
# Inject timeline executes automatically; results aggregate in real time
</code></pre>

## Collector Integrations (Auto-Validation)

Collectors are the highest-value setup. They automatically validate expectations without manual observer input — when an inject executes, the collector polls the security tool and records whether the expected alert fired.

<pre><code># Connect a collector: Collectors → New Collector → select type
# CrowdStrike Falcon:
#   Client ID + Client Secret (API key with "Detections: read" scope)
#   Automatically polls /detections/queries/detections/v1 after each technical inject
#   Validates "Detection" expectations

# Microsoft Defender for Endpoint:
#   App registration in Entra ID with WindowsDefenderATP.Read.All
#   Polls MDE alerts API for matching device/technique within the inject's time window

# Splunk:
#   API token + search endpoint
#   OpenAEV sends a search query for the ATT&CK technique ID after each inject
#   Returns alert count → validates Detection expectation

# Microsoft Sentinel:
#   Azure AD app + Log Analytics workspace ID
#   Queries SecurityAlert table filtered by technique and time window
</code></pre>

## OpenCTI Integration

With OpenCTI connected, OpenAEV can generate scenarios directly from threat intelligence:

<pre><code># Settings → Integrations → OpenCTI → enter API URL + token

# Then: Scenarios → New from Threat Actor
# Select actor (e.g., APT29) → OpenAEV pulls:
# - Known TTPs from STIX2 attack patterns
# - Pre-associated payloads where available
# - Generates inject timeline with technique timing based on campaign data

# Push back: after a simulation, exposure data flows to OpenCTI
# as a sighting relationship — "APT29 technique T1566.001 tested, not detected"
</code></pre>

## REST API

<pre><code># Base: https://&lt;openaev_host&gt;/api/
# Auth: Bearer token from user settings

# List scenarios:
curl -H "Authorization: Bearer TOKEN" \
     https://openaev.corp.internal/api/scenarios

# Get scenario detail:
curl -H "Authorization: Bearer TOKEN" \
     https://openaev.corp.internal/api/scenarios/SCENARIO_UUID

# List exercises:
curl -H "Authorization: Bearer TOKEN" \
     https://openaev.corp.internal/api/exercises

# Launch a simulation:
curl -X POST \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"exercise_scenario": "SCENARIO_UUID", "exercise_start_date": "2025-07-01T14:00:00Z"}' \
     https://openaev.corp.internal/api/exercises

# List injects for an exercise:
curl -H "Authorization: Bearer TOKEN" \
     https://openaev.corp.internal/api/exercises/EXERCISE_UUID/injects

# Get expectations/scoring for an exercise:
curl -H "Authorization: Bearer TOKEN" \
     https://openaev.corp.internal/api/exercises/EXERCISE_UUID/expectations
</code></pre>

Custom injectors are microservices in Python or Node — explicitly architected to be small (50-line implementations are typical). An injector registers via the API and receives inject payloads over a webhook, executes them on its target system, and posts results back.

## Reporting and Scoring

Four-dimension scoring rolls up per inject and per scenario:

- **Prevention** — was the action blocked?
- **Detection** — did a control fire an alert?
- **Vulnerability** — did the action reveal an exploitable weakness?
- **Human Response** — did the team follow the runbook within SLA?

Aggregate views: kill-chain coverage heatmaps, per-team performance reports, per-Defense-Tool outcome tables. The ATT&CK heatmap exports are similar to VECTR's but tied to live collector data instead of manually recorded outcomes.

## In the Self-Hosted Stack

<pre><code>OpenAEV
├── orchestrates: CALDERA + Atomic RT + PurpleSharp (technical injects)
├── orchestrates: email/SMS channels (human injects)
├── validates via: CrowdStrike, MDE, Sentinel collectors
├── imports intel from: OpenCTI
└── feeds gaps to: VECTR (via ATTiRe) or directly via API
</code></pre>

OpenAEV is most valuable when you need: recurring scheduled exercises, human-in-the-loop tabletop elements combined with technical attacks, or threat-intel-driven scenario generation from OpenCTI.

## Resources

- OpenAEV GitHub — `github.com/OpenBAS-Platform/openbas`
- OpenAEV documentation — `docs.openaev.io`
- Filigran platform overview — `filigran.io/platforms/openaev/`
- OpenCTI (threat intel integration) — `github.com/OpenCTI-Platform/opencti`
- Filigran community Slack — `community.filigran.io`
- ATTiRe format spec — `github.com/attackiq/attire`
- Self-hosted tools overview — `tools/self-hosted-tools/`
- VECTR (tracking layer) — `tools/vectr/`
