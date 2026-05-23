---
layout: training-page
title: "CrowdStrike Falcon Evasion Tradecraft — Red Team Academy"
module: "Evasion"
tags:
  - crowdstrike
  - falcon
  - edr-evasion
  - csagent
  - threat-graph
  - kernel-callbacks
  - byovd
page_key: "evasion-crowdstrike-tradecraft"
render_with_liquid: false
---

# CrowdStrike Falcon Evasion Tradecraft

Falcon is the floor in 2026 endpoint defense. If you have not assumed it on the box, you have not planned the engagement. This page covers Falcon's sensor architecture, what it sees well, what it sees poorly, fingerprinting techniques, and the surviving evasion patterns for AMSI / ETW / process-injection / credential-access against Falcon Prevent + Insight + OverWatch deployments. The defensive landscape against Falcon is not stagnant — what worked in 2022 (classic AMSI patch, SysWhispers2 syscalls) is mostly burned in 2026. What follows is what is still standing.

This is vendor-specific tradecraft and assumes you already understand the EDR architecture concepts on `/evasion/edr-internals/` and the kernel-mode tooling on `/evasion/byovd/`. If you have not read those yet, start there.

## Falcon Architecture — What You're Actually Up Against

Falcon is a thin-on-host, fat-in-cloud architecture. The endpoint sensor is intentionally minimal — most of the actual detection happens in CrowdStrike's Threat Graph after telemetry reaches the cloud. This is the single most important fact about Falcon: **killing the sensor process is not the same as evading detection**. The cloud already saw what led up to that, and a sensor heartbeat gap is itself an IOA.

```
# Sensor components
CSAgent.sys         — kernel-mode driver. Registers callbacks, runs minifilter,
                      hosts the ETW-TI consumer, and provides anti-tamper.
CSBoot.sys          — early-launch anti-malware (ELAM) driver. Loads before
                      most kernel components, lets Falcon observe early boot.
CSFalconService.exe — user-mode service that uploads telemetry to the cloud,
                      handles policy fetch, and orchestrates response actions.
CSFalconContainer.exe — sandbox for content-update execution.
CSAgent.exe         — auxiliary user-mode component (newer builds).

# Cloud components (what actually decides whether you get caught)
Threat Graph        — cross-tenant graph database of every process, file,
                      network connection, and authentication event Falcon
                      sees. The IOAs run here, not on the endpoint.
IOA (Indicator of Attack) — behavioral pattern detection. Catches tradecraft
                            and TTPs. This is what flags you on novel payloads.
IOC (Indicator of Compromise) — hash / file / domain / IP signatures. Trivial
                                to evade with a recompile or domain rotation.
OverWatch           — Falcon Enterprise SKU only. 24/7 human threat hunters
                      reviewing flagged Threat Graph data. They write IOA
                      hunting queries based on observed tradecraft. Assume
                      OverWatch is reviewing within minutes of any high-IOA
                      event on tier-1 customers (FSI, defense, fortune 100).
```

The practical implication: a sensor-side bypass that fires zero local detections can still earn you an OverWatch ticket forty minutes later because the cloud correlation engine saw a pattern of suspicious-but-allowed events. Plan accordingly.

## Fingerprinting Falcon Presence

Before you touch anything, confirm what you are dealing with. Falcon shows up in predictable places.

```
># Services (sensor process):
Get-Service CSFalconService, CSFalconContainer -ErrorAction SilentlyContinue
sc query CSFalconService

# Kernel drivers (presence and version):
driverquery /v /fo csv | findstr /i "CSAgent CSBoot"
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "CSAgent|CSBoot" } | Select-Object Name, PathName, State, Started

# Processes (look for sensor + cloud uploader):
Get-Process | Where-Object { $_.Name -match "CSFalcon|CSAgent" } | Select-Object Id, Name, Path

# Registry:
reg query HKLM\SYSTEM\CurrentControlSet\Services\CSAgent
reg query HKLM\SYSTEM\CurrentControlSet\Services\CSFalconService

# File system locations:
dir "C:\Windows\System32\drivers\CSAgent.sys"
dir "C:\Windows\System32\drivers\CSBoot.sys"
dir "C:\Program Files\CrowdStrike\"
dir "C:\ProgramData\CrowdStrike\"  # channel files live here

# Sensor version (matters — known bypasses are version-specific):
(Get-Item "C:\Program Files\CrowdStrike\CSFalconService.exe").VersionInfo.FileVersion
# Or from the registry:
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CSAgent" /v "Sensor Version"

# Channel file inventory (content updates — sensor version is one thing, channel
# version is another, and detections live in channel files):
dir "C:\Windows\System32\drivers\CrowdStrike\C-*.sys"
```

For a one-shot fingerprint with no PowerShell logging artifacts, use **SharpEDRChecker** (github.com/PwnDexter/SharpEDRChecker) — a C# binary that enumerates running processes, loaded drivers, installed services, and known EDR file paths in a single execution. Pair it with **EDR-Mapper** (github.com/AnonymousProxyy/EDR-Mapper) for a faster passive lookup.

The sensor version matters because the Falcon attack surface changes with every channel file rollout. A bypass that landed in v7.18 may be detected reliably in v7.22. Always check the version before selecting your technique.

## What Falcon Catches Well (Don't Bother)

These are decided. Trying them on a Falcon-protected endpoint is a self-own.

```
# Mimikatz binary on disk or in memory — instant termination
# - Both the unmodified binary AND reflective-loaded variants trip a memory
#   IOA because Falcon scans for the sekurlsa string table and lsass handle
#   patterns. Even renamed/recompiled, the call graph fingerprint matches.

# LSASS handle with PROCESS_VM_READ from non-trusted process — Cred Access IOA
# - Falcon's ObRegisterCallbacks strips access rights from new handles
# - Direct syscalls bypass the user-mode hook but ETW-TI still reports the
#   syscall to the kernel ETW consumer

# Suspicious parent/child process chains:
#   winword.exe → cmd.exe                       (Office macro IOA)
#   winword.exe → powershell.exe                (Office macro IOA)
#   outlook.exe → cmd.exe                       (phishing payload IOA)
#   svchost.exe → cmd.exe                       (LOL chain anomaly)
#   wmiprvse.exe → powershell.exe → curl.exe    (lateral mvmt IOA)
#   any → bitsadmin.exe /transfer               (T1197 IOA)

# Default Cobalt Strike beacon — even with malleable C2:
# - Default named pipe pattern \\.\pipe\MSSE-* — instant kill
# - Default sleep/jitter footprint with unmodified profile — Threat Graph hit
# - sleep_mask=false + default stack — memory scan fingerprint

# Living-off-the-land binary chains that hit Threat Graph signatures:
#   certutil -urlcache -f http://... — flagged
#   bitsadmin /transfer ... http://... — flagged
#   regsvr32 /s /n /u /i:http://...scrobj.dll  (Squiblydoo) — burned
#   mshta http://...                            — burned

# Direct LSASS dump via comsvcs.dll MiniDump on Falcon-protected hosts:
# - The technique works against Defender, fails against Falcon since 2023.
# - rundll32.exe → comsvcs.dll → MiniDump is now a hard IOA.
```

Save your novel techniques for the things that still work. Burning a session on `mimikatz.exe` or a default Cobalt Strike profile is amateur hour.

## What Falcon Catches Less Well

These are the surfaces still worth investing in. None are free passes — they require care — but they survive on a properly tuned Falcon deployment in 2026.

- **Custom indirect syscalls.** Hell's Gate, Halo's Gate, and Tartarus' Gate generate per-build dynamic syscall stubs. Falcon's user-mode hooks on ntdll are bypassed cleanly. Detection then depends on ETW-TI in the kernel, which is the next layer down (see ETW-TI Bypass below).
- **BYOVD where the driver is signed and not blocklisted.** The Microsoft blocklist is updated quarterly. There are ~730 vulnerable drivers in LOLDrivers that are not yet on it — see `/evasion/byovd/` for the broader picture. Pre-installed OEM drivers (LnvMSRIO.sys on Lenovo, gdrv.sys on GIGABYTE) avoid even the service-creation event.
- **In-memory PowerShell with AMSI bypassed at process startup.** Specifically, hardware-breakpoint AMSI bypass that runs before the first `AmsiScanBuffer` call.
- **C# .NET reflection with a freshly unhooked ntdll** — load a clean copy from disk or `\KnownDlls\` before any sensitive API is touched. Falcon's user-mode hooks are gone before they fire.
- **Sleep obfuscation against memory scanning windows.** Falcon periodically scans process memory for shellcode signatures and beacon configs. Encrypting your implant heap during sleep (Ekko, Foliage, Cronos, DeepSleep) breaks this.
- **Encrypted-stage payloads** with payload-specific keys derived from the host environment. Even if Falcon snags the loader, the stage is unrecoverable without the host context.

## AMSI Bypass Survival Against Falcon

Falcon does not own AMSI — Defender does — but Falcon consumes AMSI events and correlates them. AMSI is also still the gate for in-memory PowerShell and .NET execution.

```
># DEAD TECHNIQUES against Falcon (will trigger an IOA):
# - Classic [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')...
#   amsiInitFailed = $true. The string pattern is hard-flagged.
# - WriteProcessMemory + AmsiScanBuffer first-byte 0xC3 (ret) patch via P/Invoke.
#   Falcon IOA on the API sequence: VirtualProtect on amsi.dll → write to
#   AmsiScanBuffer prologue → restore protection. Instant kill in 2024+.
# - AMSI provider unregistration via deleting HKLM\SOFTWARE\Microsoft\AMSI\Providers.
#   Sensor IOA hit. Triggers in seconds.

# SURVIVING APPROACHES (2024-2026):

# 1) Hardware breakpoint AMSI bypass (Rasta Mouse research)
#    - Sets a hardware breakpoint on AmsiScanBuffer's first instruction
#    - Vectored exception handler intercepts, modifies the return value, resumes
#    - No memory write to amsi.dll → no VirtualProtect → no IOA on patching
#    - Implementation: github.com/rasta-mouse/AmsiScanBufferBypass-HWBP

# 2) Set hardware breakpoint AT PROCESS STARTUP, before any AMSI calls fire
#    - Spawn powershell.exe -NoProfile suspended, set HWBP via SetThreadContext,
#      then ResumeThread. The first AmsiScanBuffer call triggers the handler
#      and the call never sees real script content.

# 3) Full amsi.dll unloading via reflection (skip AMSI entirely, not patch it)
#    [System.AppDomain]::CurrentDomain.GetAssemblies() | ?{$_.Location -match 'amsi'}
#    # Then enumerate loaded modules, find amsi.dll base, FreeLibrary it.
#    # Subsequent script blocks don't go through AMSI at all.

# 4) Use a .NET execution path that doesn't invoke AMSI:
#    - Assembly.Load(byte[]) on .NET 4.8 still hits AMSI
#    - Assembly.LoadFile() from a signed/whitelisted location bypasses it
#    - Custom runspace from a C# binary starts in FullLanguage with no AMSI hooks
#      attached until the host process re-registers them
```

If you have to run PowerShell on a Falcon host, do it inside a custom runspace created from a C# loader you wrote. Do not use `powershell.exe`. The host process matters as much as the script content.

## ETW-TI Bypass

Falcon's kernel-mode driver consumes the Microsoft-Windows-Threat-Intelligence ETW provider. ETW-TI sees the things user-mode hooks miss — direct syscalls fire ETW-TI events because the syscall handler in the kernel emits them. This is why "I have direct syscalls" is no longer the answer to "I have evaded Falcon."

```
# What ETW-TI sees (kernel-side, after the syscall lands):
# - NtAllocateVirtualMemory in foreign process
# - NtProtectVirtualMemory (RWX transitions)
# - NtMapViewOfSection cross-process
# - NtWriteVirtualMemory cross-process
# - NtQueueApcThread cross-process
# - NtCreateThreadEx with remote process handle
# Direct syscalls do NOT bypass ETW-TI. They only bypass user-mode hooks.

# DEAD: Patching EtwEventWrite in ntdll
# - Worked 2018-2022
# - Modern Falcon IOA: writes to ntdll!EtwEventWrite prologue
#   Sensor fires within seconds. Don't.

# SURVIVING:

# 1) ETW provider deregistration via NtTraceControl
#    - Enumerate ETW provider registrations in the process EPROCESS
#    - Use NtTraceControl with EtwSendDataBlock to silence the provider
#    - Requires getting at the provider GUID table — accessible from user mode
#      via undocumented ntdll exports (EtwEnumerateProcessRegistrations etc.)

# 2) Patch the provider's EnableInfo BEFORE Falcon enables it (early boot only)
#    - Useful for persistence implants that load via boot driver / WPP

# 3) "Patch the kernel ETW-TI handle to NULL" via BYOVD
#    - EtwThreatIntProvRegHandle in ntoskrnl.exe — write 0 to it
#    - Implementations: EDRSandblast --etwti, CheekyBlinder
#    - Requires kernel R/W primitive from a vuln driver (see /evasion/byovd/)
#    - This is the highest-impact bypass — it kills the entire ETW-TI feed
#      that Falcon's kernel driver consumes. Multiple sensors lose telemetry.

# 4) Run the noisy operation from a process whose ETW-TI events Falcon does
#    not aggressively flag (signed/trusted host process). Combine with a
#    spoofed call stack so the source frame points at a legitimate module.
```

The pragmatic order: try to do the operation without anything noisy enough to need ETW-TI to be off. If you have to, go straight to the BYOVD ETW-TI patch. Half-measures in between (EtwEventWrite patch, AMSI patch alone) buy you a 30-second window and a ticket on the OverWatch hunter's screen.

## Process Injection Patterns and Their Falcon Fate

The injection technique you choose determines whether the operation survives. This is the current state against Falcon v7.20+ in early 2026:

| Technique | Falcon Detection | Survival Approach |
|---|---|---|
| `CreateRemoteThread` + `LoadLibrary` | HARD CATCH — user-mode hook on `CreateRemoteThread`, ETW-TI confirms, IOA fires inside the second | Don't. Burn budget here = burn engagement |
| Classic process hollowing (`NtUnmapViewOfSection` + `WriteProcessMemory` + `SetThreadContext`) | HARD CATCH — call sequence is a signature | Move to module stomping or transacted hollowing |
| Module stomping into a legit DLL's `.text` section | PARTIAL — depends on the DLL chosen and whether thread start address is in the stomp region | Pick a DLL not normally executed; redirect via existing thread hijack rather than starting a new thread |
| APC injection via `NtQueueApcThread` (user APC) | SOFT — caught when the alertable thread runs LoadLibraryA shellcode | Inline-resolve the API table, no LoadLibrary, payload runs from RX memory in legit module range |
| Thread hijacking with custom indirect syscalls | PARTIAL — user-mode is clean, ETW-TI fires on `NtSetContextThread` cross-process | Combine with ETW-TI patch (BYOVD) or pick a target thread in the same process (no cross-process syscall) |
| Reflective DLL injection via section view | PARTIAL — `NtCreateSection` + `NtMapViewOfSection` cross-process is loud | Section + map happens in a sacrificial worker process, then the section is shared and mapped into the real target — splits the IOA chain |
| Indirect syscalls + remote DLL via section mapped from `\KnownDlls\` | VIABLE — the section already exists in the OS and is signed; no new section creation event | Currently the cleanest 2025-2026 approach |
| Early Bird (APC pre-init) into a `CREATE_SUSPENDED` child | SOFT — process creation with `CREATE_SUSPENDED` from non-shell parent is itself an IOA signal | Use only when the parent is a trusted host (msbuild, regsvr32 in a whitelist-allowed config) |
| Process Doppelgänging (NTFS transactions) | SOFT — transaction APIs are themselves rare and now flagged | Transacted Hollowing variant still works on un-patched Falcon-Lite deployments only |
| Function stomping (`PAGE_EXECUTE_READWRITE` only briefly) | PARTIAL — memory scanner catches the RWX window | Allocate RW, write, then `VirtualProtect` → RX before any execution. Never have RWX visible to a scan |

The pattern: the user-mode hook layer is bypassed by direct/indirect syscalls. The kernel-side ETW-TI is bypassed by patching ETW-TI in the kernel via BYOVD. The cloud Threat Graph correlation is bypassed by behavioral discipline — slow, legitimate-looking call chains, no characteristic API sequences clustered in time.

## BYOVD against Falcon's Kernel Driver

The endgame for Falcon evasion at high effort tiers is removing Falcon's own kernel callbacks via BYOVD. See `/evasion/byovd/` for the full taxonomy — this section is Falcon-specific.

```
# Goal: Strip CSAgent.sys callback entries from:
#   PspCreateProcessNotifyRoutine   (process create)
#   PspCreateThreadNotifyRoutine    (thread create)
#   PspLoadImageNotifyRoutine       (image load)
#   ObProcessCallbacks              (handle to process)
#   ObThreadCallbacks               (handle to thread)
#   Falcon's minifilter altitude    (filesystem)

# Driver selection (2026 reality):
# - LnvMSRIO.sys (CVE-2025-8061) — Lenovo, pre-installed on managed laptops,
#   no DACL on device object, exploitable from unprivileged user. Best-in-class
#   if you're on a Lenovo fleet. See /evasion/byovd/ for IOCTL details.
# - gdrv.sys (GIGABYTE) — pre-installed where GIGABYTE App Center is deployed.
# - dbutil_2_3.sys (Dell CVE-2021-21551) — still works on un-patched fleets;
#   on the MS blocklist, so service-create event will trigger on HVCI hosts.
# - RTCore64.sys (MSI Afterburner) — on the blocklist as of 2023; loud.

# Callback removal flow (with kernel R/W primitive from a vuln driver):
# 1. Resolve ntoskrnl.exe base address (NtQuerySystemInformation
#    SystemModuleInformation, class 11)
# 2. Resolve PspCreateProcessNotifyRoutine offset from ntos symbols
#    (use the embedded PDB GUID from ntoskrnl headers + the MS symbol server,
#    or use signature scanning for the prologue of PsSetCreateProcessNotifyRoutineEx)
# 3. Read the array of EX_CALLBACK_ROUTINE_BLOCK pointers
# 4. For each entry, resolve the callback function address → which module owns it?
# 5. If the owning module is CSAgent.sys (or another EDR sensor driver),
#    write 0 to that array entry
# 6. Repeat for thread, image, and Ob callback arrays

# Practical tooling: EDRSandblast does all of this automatically with a config:
EDRSandblast.exe --kernelmode --offsets-from-file offsets.csv
# Provide the offsets CSV for the current Windows build; EDRSandblast walks
# each callback array, identifies sensor entries, and NULLs them.
# Add: --etwti to also patch the ETW-TI kernel provider handle.
```

**Critical OPSEC: the sensor heartbeat gap.** When you strip Falcon's callbacks, the sensor process keeps running and keeps sending heartbeats. But the telemetry it sends goes flat — no new process events, no DLL loads, no handle opens. The cloud detects the gap. OverWatch sees "host X stopped reporting normal endpoint activity at HH:MM" within a few minutes.

This means you have a window — call it the **4-minute window** — between callback removal and the first OverWatch query landing on your host. Whatever you needed to do (LSASS dump, lateral move, beacon stage) gets done in those minutes, then you either restore the callbacks (less common, complex) or accept that the box is burned post-operation.

```
# The 4-minute window playbook:
# 0:00  Drop and load vuln driver (or open handle to pre-installed driver)
# 0:15  Patch ETW-TI handle to 0
# 0:30  Strip CSAgent kernel callbacks
# 0:45  Operation begins: LSASS dump, secrets harvest, lateral pivot
# 3:30  Operation complete, stage tools to next host or beacon out
# 4:00  Cleanup pass: re-register minimal callbacks to avoid forensic flag
# 4:00+ OverWatch query begins arriving — operation is already complete
```

If your operation cannot fit in four minutes, decompose it. Move pivot lateral, harvest creds on the next host, repeat. Do not extend the window on a single host.

## C2 OPSEC for Falcon-Heavy Environments

Falcon's Threat Graph correlates network beacons with process behavior. A "clean" implant on disk that beacons every 60 seconds to a fresh domain still gets flagged because the *cloud sees the pattern*, not the local sensor.

```
# Beacon URI shape and Threat Graph signature:
# - Default Cobalt Strike URIs (/__utm.gif, /pixel.gif, /api/v1/...) — burned
# - Random-string URIs (e.g., /xT9k2/jHs4n) — high entropy, flagged
# - Realistic application-mimicking URIs that match the cover traffic — survive

# HTTPS profile mimicking real applications:
# - OneDrive sync — POST/GET pattern with specific headers, predictable cadence,
#   typical payload sizes 2-50KB
# - Teams telemetry — frequent small POSTs to *.skype.com / *.office.com style
#   destinations with valid TLS fingerprints
# - Slack — wss:// long-lived connection (good for low-and-slow beaconing)

# Sleep interval (defeat behavior windows):
# - Falcon's behavior windows are typically 30-90 seconds for IOA correlation
# - Sleep 5-10 minutes with 50% jitter → events scatter across windows
# - Sleep > 30 minutes for high-value persistence → essentially undetectable
#   in behavioral correlation, only static IOC remains as risk

# Cobalt Strike default profiles are an instant signature hit on Threat Graph:
# - Avoid default URIs, default named pipes, default HTTP headers
# - Even with malleable C2, the JA3 hash of an unmodified Beacon TLS handshake
#   is fingerprinted by every major EDR vendor

# Mythic with a custom C2 profile is recommended over Cobalt Strike on
# Falcon-heavy targets in 2024+. Reasons:
# - The default Mythic agents (Apollo, Athena, Apfell) are less broadly
#   fingerprinted than Beacon
# - Profile customization is part of the framework, not bolted on
# - The Hugo (HTTP/2) and TetanusJSON-RPC profiles look like modern API
#   traffic, not the suspicious patterns CS profiles default to
# - Sliver is another viable option with similar properties

# Domain fronting is largely dead (Cloudflare, Google, Amazon all blocked it
# 2018-2020). Use:
# - Trusted SaaS C2 (Mythic with Slack/Discord/OneDrive transport)
# - High-reputation domain categorization purchased pre-engagement
# - SNI shuffling on CDNs that still allow it (decreasing list)
```

A clean implant on a Falcon endpoint dies from its callback pattern, not its loader. Spend the engineering budget on the profile, not the shellcode.

## Sensor Downgrade / Disable

There are three paths to stopping Falcon from working. Listed in order of decreasing OPSEC:

```
># Path 1: BYOVD callback removal (best OPSEC)
#   - Sensor process keeps running
#   - Heartbeat continues, no service-stop event
#   - Visibility goes flat — cloud notices the gap, but only after ~4 min
#   - See above (BYOVD against Falcon Kernel Driver)

># Path 2: Sensor disable via maintenance token / admin command (cloud aware)
#   - Requires either:
#     a) DA-tier compromise with the org's CrowdStrike console access, OR
#     b) The local maintenance token (rotates, per-host, fetched from cloud)
#   - Command: CsUninstallTool.exe /quiet MAINTENANCE_TOKEN=<token>
#   - The cloud sees the uninstall command and logs it — high-severity alert
#   - Useful only for pre-positioned access where you can stage console comp
#     and uninstall right before exfil

># Path 3: Tampering via channel file abuse (research direction)
#   - The May 2024 RTC0011 sensor crash incident demonstrated a single
#     channel file (C-00000291-*.sys) with a malformed configuration could
#     panic CSAgent.sys and bluescreen ~8.5 million Windows endpoints.
#   - The crash was an unintended config error from CrowdStrike themselves,
#     not an attacker. But it proved the channel-file processing path is a
#     parsing-bug attack surface.
#   - As a red team, do not weaponize a CSAgent crash in a real engagement —
#     causing a bluescreen on customer endpoints crosses into destructive
#     territory and is almost certainly outside your scope. Note the surface
#     exists; do not use it.
#   - Legitimate research direction only.
```

If you are reading this and considering crashing Falcon via channel file manipulation on a live engagement: don't. Your client's incident-response retainer is not measured in patience for an "oops the EDR fell over" event.

## Detection Signals Operators Should Expect to Fire

Even if you do everything right, you will trip some IOAs. Knowing which ones to expect helps you decide whether to push or fall back.

```
# Common Falcon IOA Detection Codes you should plan around:
# CredentialAccess via LSASS — any handle to lsass.exe with VM_READ or
#   DUP_HANDLE. Fires universally; bypass requires BYOVD or PssCaptureSnapshot.
# SuspiciousChild — Office spawning shell, Outlook spawning anything, browser
#   spawning powershell. Initial-access on Falcon leans on signed LNK/HTA/MSI.
# UnusualParentChain — wmiprvse → cmd/powershell, services.exe → unusual path,
#   lsass → anything. sc-create + remote service-start gets flagged.
# MemoryScrape — memory scans flag shellcode patterns; sleep obfuscation fixes.
# AnomalousProcess — unusual directory, unsigned + new + parented oddly.
# NetworkContain — outbound to known-bad C2; use fresh high-rep infra aged 4-8w.

# Threat Graph correlation events (cloud-side, you don't see them locally):
#   - Cross-host beacon pattern (same JA3 hash across multiple hosts in a
#     tenant within a time window)
#   - Auth-then-RPC pattern (Kerberos TGT request followed by RPC call to
#     SCM / WinRM / WMI on a different host within 60s)
#   - Discovery cluster (multiple "net user", "net group", "whoami /priv"
#     events from the same process in a short window)

# OverWatch human-analyst flags:
#   - Tooling fingerprints: even refactored, certain implants have
#     characteristic call graphs that experienced analysts recognize
#   - Time-of-day anomalies: legitimate admin activity at 03:00 local on a
#     non-IT user's box draws a manual look
#   - Cross-tenant pattern matching: if your TTP looks like a known APT
#     pattern OverWatch has seen elsewhere, your dwell time shrinks
```

## Tools and Research

The tooling that survives against Falcon in 2026 is the tooling that's actively maintained and not yet widely fingerprinted. Public, off-the-shelf tooling has a half-life — what's on GitHub today is in CrowdStrike's IOA library next quarter.

```
# Recon and fingerprinting:
SharpEDRChecker — github.com/PwnDexter/SharpEDRChecker
EDR-Mapper      — github.com/AnonymousProxyy/EDR-Mapper

# Kernel-mode bypass:
EDRSandblast    — github.com/wavestone-cdt/EDRSandblast (callback + ETW-TI)
CheekyBlinder   — github.com/br-sn/CheekyBlinder (callback array walking)
KDU             — github.com/hfiref0x/KDU (40+ vuln driver providers)
Backstab        — github.com/Yaxser/Backstab (PROCEXP152.sys kills)

# Loader / injection tradecraft:
Donut           — github.com/TheWover/donut (PE-to-shellcode converter)
Freeze          — github.com/optiv/Freeze (Cobalt Strike loader, sleep-mask)
KrakenMask      — sleep obfuscation framework
SilentMoonwalk  — call-stack spoofing (github.com/klezVirus/SilentMoonwalk)

# AMSI / ETW bypass:
AmsiScanBufferBypass-HWBP — github.com/rasta-mouse/AmsiScanBufferBypass-HWBP
BypassAMSI                — collection of approaches at github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

# Cobalt Strike Falcon-evasion profiles: most useful ones are private. Public
# profiles on GitHub are fingerprinted within weeks of publication. The
# professional move is to build your own or buy a maintained profile through
# Outflank OST or RastaMouse's profile service.

# Outflank OST documentation on Falcon — Outflank publish detailed blog posts
# on EDR evasion including Falcon-specific notes. Their toolset is private but
# the public research is among the best in the field:
#   https://www.outflank.nl/blog/
#   outflank.nl on AMSI, ETW, syscalls, and sleep obfuscation specifically

# Christopher Vella's research — public Falcon-bypass research, including
# kernel callback enumeration and ETW-TI manipulation.

# MDSec on Falcon — MDSec publish periodic deep dives on commercial EDRs
# including Falcon. Search their site for "CrowdStrike" or "Falcon" and read
# the most recent posts.

# Falcon Insight querying language (CrowdStrike Query Language, CQL) — public
# CrowdStrike KB. Understanding how defenders query their own data tells you
# what to avoid leaving in it:
#   https://www.crowdstrike.com/en-us/falcon-platform-documentation/
```

## Resources

- CrowdStrike Falcon documentation (public KB) — `crowdstrike.com/en-us/falcon-platform-documentation/`
- Outflank blog on EDR evasion (AMSI, ETW-TI, sleep obfuscation, syscalls) — `outflank.nl/blog/`
- MDSec on commercial EDR evasion (search "CrowdStrike", "Falcon") — `mdsec.co.uk/knowledge-centre/research/`
- Rasta Mouse — hardware breakpoint AMSI bypass — `github.com/rasta-mouse/AmsiScanBufferBypass-HWBP`
- EDRSandblast (kernel callback + ETW-TI removal) — `github.com/wavestone-cdt/EDRSandblast`
- CheekyBlinder (callback array enumeration) — `github.com/br-sn/CheekyBlinder`
- Backstab (PROCEXP152.sys EDR-process kill) — `github.com/Yaxser/Backstab`
- SharpEDRChecker (EDR fingerprinting) — `github.com/PwnDexter/SharpEDRChecker`
- KDU (Kernel Driver Utility, 40+ vuln driver providers) — `github.com/hfiref0x/KDU`
- SilentMoonwalk (call-stack spoofing) — `github.com/klezVirus/SilentMoonwalk`
- Donut (PE → shellcode) — `github.com/TheWover/donut`
- Freeze (Cobalt Strike loader with sleep mask) — `github.com/optiv/Freeze`
- AMSI bypass collection — `github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell`
- LOLDrivers (vulnerable driver catalog) — `loldrivers.io`
- Falcon RTC0011 incident postmortem (channel file crash, July 2024) — `crowdstrike.com/falcon-content-update-remediation-and-guidance-hub/`
- "Blinding EDR on Windows" — Optiv research, kernel callback approach
- Christopher Vella — Falcon-specific kernel research, public blog posts
- Sektor7 — RED TEAM Operator: Windows Evasion course (commercial training, current syllabus covers Falcon-relevant techniques)
