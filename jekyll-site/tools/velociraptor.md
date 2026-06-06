---
layout: training-page
title: "Velociraptor — Endpoint Visibility and Purple Team Validation — Red Team Academy"
module: "Red Team Tools"
tags:
  - velociraptor
  - dfir
  - endpoint-visibility
  - vql
  - purple-team
  - threat-hunting
  - rapid7
page_key: "tools-velociraptor"
render_with_liquid: false
---

# Velociraptor — Endpoint Visibility and Purple Team Validation

Velociraptor is an open-source endpoint visibility, DFIR, and threat hunting platform that answers the key purple-team question: *did the technique actually produce the telemetry the detection is supposed to catch?* After running an atomic test or CALDERA operation, Velociraptor confirms — via actual artifact collection from the endpoint — whether the expected evidence is present. No SSH into the box, no RDP, no log grep. A VQL query dispatched as a hunt and results aggregate in seconds.

**Status (2025):** Actively maintained under Rapid7 stewardship (acquired Velocidex). Current stable: v0.75 (Aug 30, 2025). Rapid7 acquisition improved engineering capacity — releases are more frequent. Works offline-capable (clients cache tasks, deliver results on next check-in).

**Security note:** Sophos Counter Threat Unit (Dec 2025) reported that GOLD SALEM / Warlock ransomware operators are abusing legitimate Velociraptor binaries as a backdoor delivery mechanism. Lock down your `api_client.yaml` files and treat Velociraptor binaries on disk as a high-signal IOC in non-DFIR contexts.

## Post-Install Server Setup

<pre><code># 1. Generate server and client configs (interactive wizard):
./velociraptor config generate -i
# Prompts: deployment type (Self-signed / Let's Encrypt / Custom cert),
# server hostnames, GUI port (default 8889), Frontend port (8000), API port (8001)
# Output: server.config.yaml + client.config.yaml

# 2. Add admin user:
./velociraptor --config server.config.yaml user add james --role administrator

# 3. Run the server:
# Linux (foreground for testing):
./velociraptor --config server.config.yaml frontend

# Linux (systemd service):
./velociraptor --config server.config.yaml service install
systemctl start velociraptor

# Windows:
velociraptor.exe service install --config server.config.yaml

# 4. Access GUI:
#    https://&lt;server-ip&gt;:8889

# 5. Extract the client config later if needed:
./velociraptor --config server.config.yaml config client &gt; client.config.yaml
</code></pre>

## Deploying Clients

<pre><code># Windows — MSI repack (preferred for GPO/SCCM/Intune mass-deploy):
# Bake client.config.yaml into the MSI — ships one binary, no per-host config step
./velociraptor config repack \
    --msi velociraptor-windows-amd64.msi \
    client.config.yaml \
    velociraptor-repacked.msi

msiexec /i velociraptor-repacked.msi /quiet

# Windows — EXE service install (manual/testing):
velociraptor.exe service install --config client.config.yaml -v

# Linux — Debian package:
./velociraptor debian client --config client.config.yaml

# Linux — RPM:
./velociraptor rpm client --config client.config.yaml

# macOS:
sudo ./velociraptor service install --config client.config.yaml -v
</code></pre>

After install, clients appear in **Clients** view at the GUI. Each gets a `C.<hex>` identifier.

## Core Concepts

| Concept | What It Is |
|---------|------------|
| **Client** | An endpoint agent, identified as `C.<hex>`. Checks in on a configurable schedule, caches tasks for offline delivery. |
| **Artifact** | YAML file containing VQL queries — the unit of collection. Client artifacts run on endpoints; Server artifacts run on the server. |
| **Hunt** | A collection job dispatched to all clients matching a label, OS, or condition. Results aggregate centrally. |
| **VQL** | Velociraptor Query Language — SQL-flavored query language. Everything in Velociraptor is ultimately VQL. |
| **Notebook** | Post-processing workspace combining Markdown and VQL. Supports typed parameters (v0.74+) for reusable analysis workflows. |
| **Label** | Tags applied to clients for targeting — `Windows`, `workstations`, `dc`, custom. Hunts and flows can filter by label. |

## Key Artifacts for Purple Team Validation

| Artifact | What It Confirms |
|----------|-----------------|
| `Windows.System.Pslist` | Process listing — confirm beacon process is alive, check parent/child chain |
| `Windows.System.Services` | Persistent services — catch T1543.003 (Windows Service) |
| `Windows.EventLogs.Evtx` | Generic EVTX parser — query any channel and EventID set |
| `Windows.EventLogs.EvtxHunter` | Regex hunt across all EVTX files — fastest way to find a string IOC |
| `Windows.Sysinternals.Autoruns` | Wraps autorunsc.exe — comprehensive persistence sweep |
| `Windows.Network.NetstatEnriched` | Active TCP/UDP connections with process attribution — C2 beacon detection |
| `Windows.Memory.Acquisition` | WinPmem full memory capture |
| `Windows.Detection.LsassMemoryAccess` | Watches Sysmon EID 10 for LSASS handle requests (T1003.001) |
| `Windows.Persistence.PermanentWMIEvents` | WMI event subscription persistence (T1546.003) |
| `Windows.Forensics.RecentApps` | Recently executed applications — quick execution confirmation |
| `Windows.System.Programs` | Installed software inventory |

## Running a Hunt

### GUI Workflow

<pre><code># 1. Hunt Manager → New Hunt
# 2. Select artifact: e.g., Windows.Detection.LsassMemoryAccess
# 3. Set parameters (most have sensible defaults)
# 4. Set target: All clients | OS filter | Label filter
# 5. Schedule → hunt queues and dispatches on client check-in
# 6. Results aggregate in Hunt view — export as JSON or CSV
#    or post-process in a Notebook (click "Create Notebook from Hunt")
</code></pre>

### CLI Collection (Single Host / Offline Triage)

<pre><code># Collect artifacts directly (no server needed — embedded mode):
./velociraptor --config client.config.yaml artifacts collect \
    Windows.EventLogs.Evtx \
    --args ChannelRegex=Security \
    --args IDRegex="4624|4625|4688" \
    --output triage.zip

# Multiple artifacts in one collection:
./velociraptor --config client.config.yaml artifacts collect \
    Windows.Sysinternals.Autoruns \
    Windows.System.Pslist \
    Windows.Network.NetstatEnriched \
    --output triage.zip
</code></pre>

## VQL — Practical Examples

VQL is the heart of Velociraptor. Every artifact, every hunt, every notebook query is VQL.

### Basic Process Hunt

<pre><code>-- Find common red team tools by process name:
SELECT Name, Pid, Ppid, CommandLine, CreateTime
FROM pslist()
WHERE Name =~ '(?i)(mimikatz|rubeus|certify|sharphound|bloodhound|cobalt|havoc|sliver)\\.exe'
</code></pre>

### Parent/Child Chain Enrichment

<pre><code>-- Detect Office/Outlook spawning scripting engines (common maldoc pattern):
LET children = SELECT * FROM process_tracker_pslist()

SELECT Name,
       Pid,
       CommandLine,
       process_tracker_get(id=Ppid).Data.Name AS ParentName,
       process_tracker_get(id=Ppid).Data.CommandLine AS ParentCmd,
       process_tracker_tree(id=Pid) AS Tree
FROM children
WHERE Name =~ '(?i)(powershell|wscript|mshta|rundll32|cscript)\\.exe'
  AND ParentName =~ '(?i)(winword|excel|outlook|onenote)\\.exe'
</code></pre>

### C2 Beacon Detection (External Connections)

<pre><code>-- Active established connections to non-RFC1918 IPs, with process info:
LET suspicious_conns =
  SELECT Pid, Laddr.IP AS LocalIP, Raddr.IP AS RemoteIP, Raddr.Port AS RPort
  FROM netstat()
  WHERE Status = 'ESTAB'
    AND NOT Raddr.IP =~ '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.)'

SELECT * FROM foreach(row=suspicious_conns,
  query={
    SELECT Pid, RemoteIP, RPort, Name, CommandLine, CreateTime
    FROM pslist()
    WHERE Pid = suspicious_conns.Pid
  })
</code></pre>

### Named Pipe Enumeration (Cobalt Strike / Mythic Detection)

<pre><code>-- Find named pipes matching known C2 framework patterns:
SELECT Name, OwnerPid,
       process_tracker_get(id=OwnerPid).Data.Name AS OwnerProcess,
       process_tracker_get(id=OwnerPid).Data.CommandLine AS OwnerCmdLine
FROM glob(globs='\\\\.\\pipe\\*', accessor='file')
WHERE Name =~ '(?i)(MSSE-|postex_|mojo\\.|wkssvc_|\\\\[0-9a-f]{8}-[0-9a-f]{4})'
</code></pre>

### EVTX Logon Hunting (Across All Event Logs)

<pre><code>-- Parse Security.evtx for remote interactive and network logons:
LET evtx = SELECT FullPath FROM glob(
  globs='C:/Windows/System32/winevt/Logs/Security.evtx')

SELECT System.TimeCreated.SystemTime AS Time,
       System.EventID.Value AS EID,
       EventData.TargetUserName AS User,
       EventData.IpAddress AS SourceIP,
       EventData.LogonType AS LogonType
FROM foreach(row=evtx,
             query={
               SELECT * FROM parse_evtx(filename=FullPath)
               WHERE System.EventID.Value IN (4624, 4625, 4648)
                 AND EventData.LogonType IN ('3', '10')
             })
ORDER BY Time DESC
</code></pre>

### Hunt Dispatch from Server (VQL)

<pre><code>-- Programmatically create a hunt and collect results via server VQL:
LET h = hunt(
  description='LSASS access hunt post-Atomic-run',
  artifacts=['Windows.Detection.LsassMemoryAccess'])

SELECT * FROM h
</code></pre>

## Purple Team Integration Loop

The standard validation workflow for a CALDERA or Atomic Red Team session:

<pre><code># 1. Run your attack:
#    CALDERA operation, Invoke-AtomicTest, PurpleSharp playbook, etc.
#    Record the execution timestamp.

# 2. Dispatch a validation hunt in Velociraptor:
#    Hunt Manager → New Hunt
#    Artifact: Windows.Detection.LsassMemoryAccess (or relevant artifact)
#    Target: the asset(s) under test

# 3. Velociraptor collects from the client(s) on next check-in (seconds to minutes).

# 4. In a Notebook, JOIN hunt results with the attack timestamp:
LET attack_time = "2025-06-15T14:02:17Z"
LET attack_time_minus5 = timestamp(string="2025-06-15T13:57:17Z")
LET attack_time_plus5  = timestamp(string="2025-06-15T14:07:17Z")

SELECT * FROM hunt_results(hunt_id='H.123456')
WHERE Timestamp &gt; attack_time_minus5 AND Timestamp &lt; attack_time_plus5

# 5. Result: evidence (or absence of evidence) that the technique's telemetry landed.
# 6. Record outcome in VECTR.
</code></pre>

**Key advantage:** this workflow runs identically against 1 endpoint or 10,000 — you never SSH or RDP into the target. Velociraptor's existing comms channel handles it.

### Wrapping Atomic Red Team as a Velociraptor Artifact

For a tighter loop, create a custom artifact that runs an atomic test AND collects the expected telemetry in one hunt:

<pre><code>name: Custom.PurpleTeam.AtomicWithTelemetry
description: Run an Atomic Red Team test and collect telemetry
parameters:
  - name: TechniqueID
    type: string
    default: T1003.001
  - name: TestNumbers
    type: string
    default: "1"
sources:
  - name: Execution
    query: |
      LET result = SELECT * FROM execve(argv=["pwsh", "-c",
        format(format="Invoke-AtomicTest %v -TestNumbers %v",
               args=[TechniqueID, TestNumbers])])
      SELECT * FROM result

  - name: LsassTelemetry
    query: |
      -- Collect LSASS telemetry immediately after execution
      SELECT * FROM Artifact.Windows.Detection.LsassMemoryAccess()
</code></pre>

## gRPC API (Automation)

The gRPC API is the correct interface for automation. The internal REST API is not stable — don't use it.

<pre><code># Generate API client credentials:
./velociraptor --config server.config.yaml \
    config api_client \
    --name automation_user \
    --role administrator \
    api_client.yaml

# The YAML contains cert chain + API endpoint (default 127.0.0.1:8001)
# For remote access: set API.bind_address: 0.0.0.0 in server.config.yaml

# Python (pyvelociraptor):
pip install pyvelociraptor
pyvelociraptor --config api_client.yaml "SELECT * FROM info()"
</code></pre>

<pre><code>import grpc, yaml
from pyvelociraptor import api_pb2, api_pb2_grpc

cfg = yaml.safe_load(open('api_client.yaml'))
creds = grpc.ssl_channel_credentials(
    root_certificates=cfg['ca_certificate'].encode(),
    private_key=cfg['client_private_key'].encode(),
    certificate_chain=cfg['client_cert'].encode())

with grpc.secure_channel(cfg['api_connection_string'], creds) as ch:
    stub = api_pb2_grpc.APIStub(ch)
    req = api_pb2.VQLCollectorArgs(
        max_wait=60,
        Query=[api_pb2.VQLRequest(
            Name="pslist_hunt",
            VQL="SELECT Name, Pid, CommandLine FROM pslist() "
                "WHERE Name =~ '(?i)mimikatz'"
        )])
    for response in stub.Query(req):
        print(response.Response)
</code></pre>

## In the Self-Hosted Stack

<pre><code>Ludus              ← range substrate; Velociraptor agent pre-deployed on all Windows VMs
↓
CALDERA / Atomic / PurpleSharp   ← attack execution
↓
Velociraptor        ← confirmation: "did the telemetry land?"
↓
VECTR               ← outcome recording: "Detection: Alert Generated"
</code></pre>

Velociraptor is the confirmation layer. It answers the question CALDERA and Atomic can't: did the defensive tooling see what just happened?

## Resources

- Velociraptor documentation — `docs.velociraptor.app`
- Velociraptor GitHub — `github.com/Velocidex/velociraptor`
- VQL reference — `docs.velociraptor.app/docs/vql/`
- Artifact reference library — `docs.velociraptor.app/artifact_references/`
- pyvelociraptor (Python gRPC client) — `github.com/Velocidex/pyvelociraptor`
- Rapid7 product page — `rapid7.com/products/velociraptor/`
- SOCFortress: Atomic Red Team + Velociraptor — referenced in community blog
- Self-hosted tools overview — `tools/self-hosted-tools/`
- VECTR (outcome tracking) — `tools/vectr/`
- Ludus (range substrate) — `tools/ludus/`
