---
layout: training-page
title: "Atomic Red Team — Detection Validation Tests — Red Team Academy"
module: "Red Team Tools"
tags:
  - atomic-red-team
  - invoke-atomicredteam
  - mitre-attack
  - purple-team
  - detection-validation
  - powershell
page_key: "tools-atomic-red-team"
render_with_liquid: false
---

# Atomic Red Team — Small, Targeted, Mapped-to-ATT&CK Tests

Atomic Red Team (Red Canary, `redcanaryco/atomic-red-team`) is a catalog of 1,800+ small, portable tests mapped 1-to-1 to MITRE ATT&CK techniques. Each "atomic" is a single verifiable action designed to answer: *if this technique executes in my environment, does my detection see it?* It is the standard tool for purple-team detection validation.

Unlike a full C2 or attack framework, an atomic is scoped to one technique, runs in under a minute, and leaves behind exactly the telemetry the detection is supposed to catch. A SIEM engineer can request a specific atomic, watch it run, confirm the alert fires, and clean up — a complete detection validation in one session.

## Invoke-AtomicRedTeam — The Module

`Invoke-AtomicRedTeam` is the PowerShell module that executes atomics on Windows, Linux, and macOS (via PowerShell Core 7+). It is the primary execution interface for the catalog.

### Setup

<pre><code># Install from PowerShell Gallery (recommended):
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force

# Import in current session:
Import-Module invoke-atomicredteam

# Download the atomics catalog alongside the module:
Install-AtomicRedTeam -getAtomics

# Default paths after install:
#   C:\AtomicRedTeam\atomics\                      (Windows — test catalog)
#   C:\AtomicRedTeam\invoke-atomicredteam\         (Windows — runner)
#   ~/AtomicRedTeam/atomics/                       (Linux/macOS)
</code></pre>

For air-gapped environments, clone the repo and module manually, then import by path:

<pre><code>Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
</code></pre>

## Core Commands

<pre><code># Inspect a technique — list all tests:
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Inspect with full YAML detail:
Invoke-AtomicTest T1059.001 -ShowDetails

# Check whether prerequisites are satisfied:
Invoke-AtomicTest T1059.001 -CheckPrereqs

# Auto-install prerequisites:
Invoke-AtomicTest T1059.001 -GetPrereqs

# Run the first test in a technique:
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Run specific test numbers:
Invoke-AtomicTest T1059.001 -TestNumbers 1,3,5

# Run by test name:
Invoke-AtomicTest T1059.001 -TestNames "PowerShell Downgrade Attack"

# Run by GUID (most stable — GUIDs never change):
Invoke-AtomicTest T1059.001 -TestGuids 9c8f29db-4f67-4b45-9f71-aa0a43b4e9c7

# Run all tests for a technique:
Invoke-AtomicTest T1059.001

# Run all tests across all techniques in the catalog:
Invoke-AtomicTest All -Confirm:$false

# Clean up after a specific test:
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# Clean up all tests:
Invoke-AtomicTest All -Cleanup -Confirm:$false
</code></pre>

## Parameter Reference

| Parameter | Type | Purpose |
|-----------|------|---------|
| `-TestNumbers` | int[] | Run specific test number(s) within a technique |
| `-TestNames` | string[] | Run test(s) by display name |
| `-TestGuids` | string[] | Run test(s) by auto_generated_guid — most stable reference |
| `-CheckPrereqs` | switch | Print prereq check results without running |
| `-GetPrereqs` | switch | Auto-install dependencies |
| `-Cleanup` | switch | Execute cleanup commands |
| `-InputArgs` | hashtable | Override input arguments: `@{ output_file = 'C:\Temp\lsass.dmp' }` |
| `-PromptForInputArgs` | switch | Interactive prompt for each input argument |
| `-TimeoutSeconds` | int | Kill execution after N seconds (default 120) |
| `-Session` | PSSession | Run on remote host via WinRM session |
| `-PathToAtomicsFolder` | string | Override default atomics location |
| `-LoggingModule` | string | Execution logger: `Default-ExecutionLogger`, `Attire-ExecutionLogger` |
| `-ExecutionLogPath` | string | Path for CSV log output |
| `-anyOS` | switch | Run test regardless of declared platform (cross-platform testing) |
| `-Confirm:$false` | switch | Suppress confirmation prompts (unattended runs) |

## Prerequisite Workflow

Most atomics declare dependencies — tools, registry keys, file paths — that must exist before the test runs. The prereq workflow:

<pre><code># 1. Check what's needed:
Invoke-AtomicTest T1003.001 -CheckPrereqs
# Output shows PASS/FAIL per dependency

# 2. Auto-install anything missing:
Invoke-AtomicTest T1003.001 -GetPrereqs

# 3. Verify prereqs are now satisfied:
Invoke-AtomicTest T1003.001 -CheckPrereqs

# 4. Run the test:
Invoke-AtomicTest T1003.001 -TestNumbers 1

# 5. Clean up:
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
</code></pre>

Prereqs use `dependency_executor_name` (default PowerShell) and run `prereq_command` to check. If it exits non-zero, the dependency is considered missing and `get_prereq_command` runs to install it.

## Custom Input Arguments

Every atomic defines `input_arguments` with defaults. Override at runtime:

<pre><code># See what inputs a test accepts:
Invoke-AtomicTest T1003.001 -ShowDetails
# Look for: input_arguments section

# Override specific args:
Invoke-AtomicTest T1003.001 -TestNumbers 1 -InputArgs @{
    output_file = "C:\Windows\Temp\my_dump.dmp"
    procdump_exe = "C:\Tools\procdump.exe"
}

# Interactive prompt (asks for each input one at a time):
Invoke-AtomicTest T1003.001 -PromptForInputArgs
</code></pre>

## Remote Execution

Run atomics against a remote host via PowerShell Remoting:

<pre><code># Create a session:
$cred = Get-Credential
$sess = New-PSSession -ComputerName "win-target-01" -Credential $cred

# Install prereqs remotely:
Invoke-AtomicTest T1003.001 -Session $sess -GetPrereqs

# Run test remotely:
Invoke-AtomicTest T1003.001 -Session $sess -TestNumbers 1

# Cleanup remotely:
Invoke-AtomicTest T1003.001 -Session $sess -TestNumbers 1 -Cleanup

# Close the session:
Remove-PSSession $sess
</code></pre>

The Invoke-AtomicRedTeam module must be imported on the remote host, or the session must be established from a machine where the module is available and it gets serialized across.

## Logging and Reporting

### CSV Logger (Default)

<pre><code>Invoke-AtomicTest T1003 \
  -LoggingModule "Default-ExecutionLogger" \
  -ExecutionLogPath "C:\Logs\atomic-results.csv"
</code></pre>

CSV columns: Execution Time (UTC), Execution Time (Local), Technique, TestNumber, TestName, TestGUID, ExecutorName, ExecutorCommand, IsSuccess, Hostname, Username, Output.

### ATTiRe Logger (VECTR / AttackIQ Ingestion)

<pre><code>Invoke-AtomicTest T1003 \
  -LoggingModule "Attire-ExecutionLogger" \
  -ExecutionLogPath "C:\Logs\atomic-results.json"
</code></pre>

The ATTiRe format is the standard for automated test-result ingestion into platforms like VECTR. The output JSON can be uploaded directly to a VECTR assessment for tracking coverage across multiple sessions.

### Custom Logger

Drop a `.psm1` into the `ExecutionLoggers/` directory exposing three functions:
`Start-ExecutionLog`, `Write-ExecutionLog`, `Stop-ExecutionLog`. Reference by the file's base name as the `-LoggingModule` value.

## Purple-Team Workflow

<pre><code># 1. Pull the ATT&CK technique list you want to validate — from your detection backlog,
#    a Navigator layer, or a threat intelligence report.

# 2. Browse available atomics for each technique:
Invoke-AtomicTest T1078.002 -ShowDetailsBrief   # Valid accounts — domain
Invoke-AtomicTest T1059.001 -ShowDetailsBrief   # PowerShell execution
Invoke-AtomicTest T1003.001 -ShowDetailsBrief   # LSASS credential dumping

# 3. Install prereqs for your selected tests:
Invoke-AtomicTest T1003.001 -GetPrereqs

# 4. Run on the test endpoint while watching your SIEM:
Invoke-AtomicTest T1003.001 -TestNumbers 1 \
  -LoggingModule "Default-ExecutionLogger" \
  -ExecutionLogPath "C:\Logs\purple-session-$(Get-Date -f yyyyMMdd).csv"

# 5. Confirm the expected alert fired in your SIEM / EDR.
#    For T1003.001: expect Sysmon EID 10 (ProcessAccess on lsass.exe)

# 6. Cleanup:
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup

# 7. Record pass/fail in your tracking spreadsheet or VECTR.
</code></pre>

## Atomics Directory Structure

<pre><code>atomic-red-team/
├── atomics/
│   ├── T1003/
│   │   ├── T1003.yaml          # test definitions
│   │   ├── T1003.md            # auto-generated markdown (do not edit)
│   │   └── src/                # supporting scripts (PS1, BAT, sh, etc.)
│   ├── T1059.001/
│   │   ├── T1059.001.yaml
│   │   └── src/
│   └── Indexes/
│       ├── Indexes-CSV/        # flat CSV index by platform
│       ├── Indexes-Markdown/   # markdown technique matrix
│       └── *-index.yaml        # YAML indexes for tooling
├── atomic_red_team/            # Python utilities and spec validation
└── bin/                        # repo tooling
</code></pre>

ATT&CK Navigator layers shipped with the repo are at `atomics/Indexes/Attack-Navigator-Layers/`. Import these into Navigator to see full catalog coverage by platform.

## Atomic Test YAML Schema

Every atomic is a YAML file. The full schema:

<pre><code>attack_technique: T1003.001
display_name: 'OS Credential Dumping: LSASS Memory'
atomic_tests:
  - name: Dump LSASS.exe Memory using ProcDump
    auto_generated_guid: 36fbbd75-f1a4-4ce3-9c0c-08fa9f5f7e3c
    description: |
      Dumps LSASS process memory using Sysinternals ProcDump.
      Produces a .dmp file that can be parsed with Mimikatz offline.
    supported_platforms:
      - windows
    input_arguments:
      output_file:
        description: Path where the LSASS dump will be written
        type: Path
        default: '%temp%\lsass_dump.dmp'
      procdump_exe:
        description: Path to ProcDump binary
        type: Path
        default: PathToAtomicsFolder\T1003.001\bin\procdump.exe
    dependency_executor_name: powershell
    dependencies:
      - description: ProcDump must exist on disk at the specified path
        prereq_command: |
          if (Test-Path "#{procdump_exe}") { exit 0 } else { exit 1 }
        get_prereq_command: |
          Invoke-WebRequest "https://download.sysinternals.com/files/Procdump.zip" `
            -OutFile "$env:TEMP\Procdump.zip"
          Expand-Archive "$env:TEMP\Procdump.zip" `
            -DestinationPath (Split-Path "#{procdump_exe}") -Force
    executor:
      name: command_prompt
      elevation_required: true
      command: |
        "#{procdump_exe}" -accepteula -ma lsass.exe "#{output_file}"
      cleanup_command: |
        del "#{output_file}" &gt;nul 2&gt;&amp;1
</code></pre>

**Executor names:** `command_prompt`, `powershell`, `sh`, `bash`, `manual` (human-executed steps).

**Input argument types:** `String`, `Path`, `Url`, `Integer`, `Float`.

**Substitution:** `#{argname}` is replaced with the argument value in `command`, `prereq_command`, `get_prereq_command`, and `cleanup_command`.

`PathToAtomicsFolder` is a special built-in that resolves to the atomics root at runtime.

## Creating Custom Atomic Tests

Add a new test to an existing technique's YAML file, or create a new YAML for a technique not yet covered:

<pre><code># Option 1: Add a new test to an existing file
# Edit atomics/T1003/T1003.yaml — append a new item under atomic_tests:

  - name: Dump credentials using custom tool
    auto_generated_guid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # generate a real UUID
    description: |
      Run a custom credential dumper built in-house.
    supported_platforms:
      - windows
    input_arguments:
      tool_path:
        description: Path to the credential dumper binary
        type: Path
        default: C:\Tools\custom-dumper.exe
      output_path:
        description: Output file for captured credentials
        type: Path
        default: C:\Windows\Temp\creds.txt
    executor:
      name: command_prompt
      elevation_required: true
      command: |
        "#{tool_path}" -output "#{output_path}"
      cleanup_command: |
        del "#{output_path}" 2&gt;nul
</code></pre>

<pre><code># Option 2: Use the PowerShell generators to scaffold a new test
Import-Module invoke-atomicredteam

$inputArgs = @{
  tool_path = New-AtomicTestInputArgument `
    -description "Path to tool" -type Path -default "C:\Tools\dumper.exe"
}

$test = New-AtomicTest `
  -name "Dump credentials with custom tool" `
  -description "Uses internal tool to extract credentials" `
  -supported_platforms "windows" `
  -executor_command '"#{tool_path}" -output C:\Temp\out.txt' `
  -executor_name command_prompt `
  -input_arguments $inputArgs

$technique = New-AtomicTechnique `
  -attack_technique T1003 `
  -display_name "OS Credential Dumping" `
  -atomic_tests @($test)

$technique | ConvertTo-Yaml | Out-File `
  C:\AtomicRedTeam\atomics\T1003\T1003.yaml -Append
</code></pre>

Generate a valid UUID for `auto_generated_guid`:

<pre><code>[guid]::NewGuid().ToString()
</code></pre>

Validate your YAML against the schema:

<pre><code>cd atomic-red-team/
pip install -r requirements.txt
python atomic_red_team/validate.py atomics/T1003/T1003.yaml
</code></pre>

## CALDERA Integration (Atomic Plugin)

The `atomic` plugin in CALDERA imports every Atomic Red Team test as a CALDERA ability, letting you run them from Caldera operations with full agent orchestration.

Enable in `conf/local.yml`:

<pre><code>plugins:
  - atomic
</code></pre>

On first load, the plugin clones `redcanaryco/atomic-red-team` into `plugins/atomic/data/atomic-red-team/` and converts each test. After restart, browse **Campaigns → Abilities** and filter by source `Atomic Red Team` to see all imported tests.

### Use Custom Atomics with CALDERA

To use a modified or custom atomic repo:

<pre><code># Docker: mount your local atomics repo:
docker run -d -p 8888:8888 \
  -v /path/to/your/atomic-red-team:/usr/src/app/plugins/atomic/data/atomic-red-team \
  mitre/caldera
</code></pre>

### Building Operations from Atomics

Once imported, atomic tests are first-class abilities in CALDERA. Build an adversary profile using atomic ability IDs, run it with the `atomic` planner, and let CALDERA orchestrate execution across multiple agents. Combined with Debrief, this gives you ATT&CK-mapped reports for each purple-team session.

## atomic-operator (Python — Archived)

`swimlane/atomic-operator` is the Python alternative for running atomics in non-PowerShell environments. The repository is archived but remains functional:

<pre><code>pip install atomic-operator

# Download the atomics catalog:
atomic-operator get_atomics
atomic-operator get_atomics --destination "/opt/atomics"

# Run a technique:
atomic-operator run --techniques T1003 --atomics-path /opt/atomics

# Interactive test picker:
atomic-operator run --techniques T1003 --select_tests

# With prereqs and cleanup:
atomic-operator run --techniques T1003 \
  --check_prereqs \
  --get_prereqs \
  --cleanup

# Custom input arguments:
atomic-operator run --techniques T1003 \
  --input_arguments '{"output_file": {"value": "/tmp/dump.bin"}}'

# Remote SSH execution:
atomic-operator run \
  --hosts 10.0.0.50 \
  --username root \
  --ssh_key_path ~/.ssh/id_rsa \
  --techniques T1003

# Config-file driven batch run:
atomic-operator run --config_file /etc/atomic/runbook.yml
</code></pre>

Config file format for unattended batch runs:

<pre><code># runbook.yml
atomic_tests:
  - guid: f7e6ec05-c19e-4a80-a7e7-241027992fdb
    input_arguments:
      output_file: { value: /tmp/loot.txt }
  - guid: 32f90516-4bc9-43bd-b18d-2cbe0b7ca9b2
</code></pre>

**Prefer Invoke-AtomicRedTeam** — it is actively maintained. atomic-operator is useful for Linux-only environments without PowerShell Core or for Python-native automation pipelines.

## OPSEC / Safety

- Atomics run genuinely dangerous commands — ProcDump against LSASS, registry edits, service installs, firewall modifications. Treat as authorized pentest activity with explicit test-system scoping.
- Cleanup commands are best-effort. After a session, manually check: scheduled tasks, new registry keys, firewall rules, temp files.
- Some atomics disable AV or EDR as a prerequisite — know which ones before running, and only on systems where that is explicitly authorized.
- Atomics run with your current process elevation. Elevation-required tests (`elevation_required: true`) need an admin shell — check `ShowDetails` before running.
- Keep the atomics catalog current — Red Canary ships new tests regularly and your coverage only stays current if you pull.

## Resources

- Atomic Red Team repo — `github.com/redcanaryco/atomic-red-team`
- Invoke-AtomicRedTeam repo — `github.com/redcanaryco/invoke-atomicredteam`
- Invoke-AtomicRedTeam wiki — `github.com/redcanaryco/invoke-atomicredteam/wiki`
- atomicredteam.io — project philosophy and updates
- Atomic Test indexes (CSV, Markdown, Navigator) — `atomics/Indexes/`
- ATTiRe format spec — `github.com/attackiq/attire`
- VECTR (test-result tracking) — `github.com/SecurityRiskAdvisors/VECTR`
- atomic-operator (Python, archived) — `github.com/swimlane/atomic-operator`
- CALDERA atomic plugin — `github.com/mitre/atomic`
- MITRE ATT&CK — `attack.mitre.org`
- CALDERA platform — `tools/caldera/`
- Self-hosted tools overview — `tools/self-hosted-tools/`
