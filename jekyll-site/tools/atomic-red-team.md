---
layout: training-page
title: "Atomic Red Team — Red Team Academy"
module: "Red Team Tools"
tags:
  - atomic-red-team
  - invoke-atomictest
  - mitre-attack
  - purple-team
  - detection-validation
page_key: "tools-atomic-red-team"
render_with_liquid: false
---

# Atomic Red Team — Small, Targeted, Mapped-to-ATT&CK Tests

Atomic Red Team (Red Canary, `redcanaryco/atomic-red-team`) is a catalog of ~1,770+ small, portable tests mapped 1-to-1 to MITRE ATT&CK techniques. Each "atomic" is a single verifiable action — not a chained attack — designed to answer *"if this technique runs in my environment, does my detection see it?"* It's the canonical tool for purple-team / detection-engineering validation.

Unlike a full C2 or attack framework, an atomic is small enough that a blue team can trigger and review it in isolation, and large enough to actually produce the telemetry the detection is supposed to catch.

## Format — An Atomic Test

Every atomic is a YAML file under `atomics/T<TechniqueID>/T<TechniqueID>.yaml`. Structure:

```
attack_technique: T1003.001
display_name: "LSASS Memory"
atomic_tests:
  - name: Dump LSASS.exe Memory using ProcDump
    auto_generated_guid: ac9fbe8a-5b86-4b6f-90df-a43e8a9d01d5
    description: |
      The following Atomic Test utilizes ProcDump to dump the LSASS process memory...
    supported_platforms:
      - windows
    input_arguments:
      output_file:
        description: Path where LSASS dump will be written
        type: path
        default: '%temp%\lsass_dump.dmp'
    dependency_executor_name: powershell
    dependencies:
      - description: Procdump must exist on disk
        prereq_command: |
          if (Test-Path "C:\ProcDump\procdump.exe") { exit 0 } else { exit 1 }
        get_prereq_command: |
          Invoke-WebRequest "https://download.sysinternals.com/files/Procdump.zip" -OutFile "$env:TEMP\procdump.zip"
          Expand-Archive "$env:TEMP\procdump.zip" "C:\ProcDump" -Force
    executor:
      command: |
        C:\ProcDump\procdump.exe -accepteula -ma lsass.exe #{output_file}
      cleanup_command: |
        Remove-Item #{output_file} -ErrorAction Ignore
      name: command_prompt
      elevation_required: true
```

Every test has: prerequisite check, prerequisite install, executor (the actual command), cleanup. Running the test is idempotent.

## Invoke-AtomicRedTeam — The Runner

`Invoke-AtomicRedTeam` is the PowerShell module that executes atomics on Windows/Linux/macOS. Installing it is the one required step — everything else is test invocation.

```
# Install the runner and the atomics bundle:
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
# Default install path:
#   C:\AtomicRedTeam\atomics\           (the test catalog)
#   C:\AtomicRedTeam\invoke-atomicredteam\  (the runner)

# Import the module (added to $profile by default):
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

## Core Commands

```
# List tests for a technique:
Invoke-AtomicTest T1003.001 -ShowDetailsBrief       # one-line list
Invoke-AtomicTest T1003.001 -ShowDetails             # full detail

# Check prerequisites without running:
Invoke-AtomicTest T1003.001 -CheckPrereqs

# Auto-install dependencies:
Invoke-AtomicTest T1003.001 -GetPrereqs

# Run a single test (1st test in the technique file):
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Run multiple specific tests:
Invoke-AtomicTest T1003.001 -TestNumbers 1,3,5

# Run by name:
Invoke-AtomicTest T1003.001 -TestNames "Dump LSASS.exe Memory using ProcDump"

# Run every test in a technique:
Invoke-AtomicTest T1003.001

# Clean up after a test:
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup

# Pass custom input arguments:
Invoke-AtomicTest T1003.001 -TestNumbers 1 -InputArgs @{ output_file = 'C:\Temp\lsass.dmp' }

# Time-bounded test (stop if over N sec):
Invoke-AtomicTest T1003.001 -TimeoutSeconds 60

# Full bucket test — every test across a bundle of techniques:
Invoke-AtomicTest All
```

## Purple-Team Workflow

```
# 1. Identify the detections you want to validate — pull the ATT&CK coverage map.
# 2. For each technique on the map, pick the atomics that exercise it:
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
Invoke-AtomicTest T1548.002 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# 3. Run from a managed endpoint — your SIEM should see:
#    - Sysmon EID 10 on LSASS handle open (T1003.001)
#    - EID 4688 with elevated token (T1548.002)
#    - EID 4104 script-block logs (T1059.001)

Invoke-AtomicTest T1003.001 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1

# 4. Confirm the SIEM fires the expected alert.
# 5. Cleanup:
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup

# 6. Repeat across your coverage map. Keep results in a spreadsheet or Navigator layer
#    (atomic-red-team ships ATT&CK Navigator layers under `atomics/Indexes/Navigator/`).
```

## Atomic vs Caldera vs CS / Havoc

| Tool | Scope | Best for |
|------|-------|----------|
| **Atomic Red Team** | One-shot tests, no chaining | Detection validation, specific technique coverage |
| **Caldera (MITRE)** | Chained automated adversaries, fact-driven | Adversary emulation, multi-step operations |
| **Cobalt Strike / Havoc** | Real C2 + agents | Real red-team ops with evasion and human operator |

For a mature program, you want all three: Atomic for per-technique coverage tests, Caldera for adversary-emulation day exercises, and a real C2 for genuine red-team engagements.

## Integration Points

- **CALDERA `atomic` plugin** — imports every Atomic Red Team test as a Caldera ability, letting you run them from Caldera operations
- **Velociraptor / MDE** — "Detection Rules Management" workflows that run atomics on every new rule
- **PurpleSharp, vectr.io** — other purple-team frameworks consume Atomic YAML directly
- **GitHub Codespaces** — the repo ships a devcontainer, so a cloud IDE can run Linux atomics with one click for quick experiments

## OPSEC / Safety

- **Atomics run dangerous commands by design.** ProcDump against LSASS, registry edits, service installs — treat as authorized pentest activity, with explicit test-system scoping.
- Clean-up commands are best-effort. After a purple session, check registry keys, scheduled tasks, and firewall rules for leftovers; the `-Cleanup` flag catches most but not all.
- Some atomics disable AV or EDR as a prereq — know which ones before running, and only on systems where that's acceptable.
- Keep the atomics repo current — Red Canary ships new tests regularly as new techniques are documented, and your coverage only stays fresh if you pull.

## Resources

- Atomic Red Team — `github.com/redcanaryco/atomic-red-team`
- Invoke-AtomicRedTeam — `github.com/redcanaryco/invoke-atomicredteam`
- atomicredteam.io — project philosophy and updates
- Atomic Test indexes (CSV, Markdown, Navigator) — `atomics/Indexes/`
- Slack community — linked from the project README
- See also: `tools/caldera.md`, `fundamentals/mitre-attack.md`, `fundamentals/purple-teaming.md`
