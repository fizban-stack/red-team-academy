---
layout: training-page
title: "Microsoft Defender for Endpoint (MDE) Tradecraft — Red Team Academy"
module: "Evasion"
tags:
  - mde
  - defender-for-endpoint
  - edr-evasion
  - amsi
  - etw
  - asr
  - sensor-tamper
  - kernel-callbacks
page_key: "evasion-mde-tradecraft"
render_with_liquid: false
---

# Microsoft Defender for Endpoint (MDE) Tradecraft

Microsoft Defender for Endpoint is the de facto floor for Windows EDR in 2025-2026. It ships in every E5 licensing bundle, it is on by default in Windows 11 Enterprise, and Microsoft has aggressively pushed it to the same parity as CrowdStrike Falcon and SentinelOne. The Defender brand is split: consumer "Microsoft Defender Antivirus" (covered separately at `/evasion/windows-defender`) and the enterprise EDR + XDR product, "Microsoft Defender for Endpoint" (MDE). This page is about the enterprise one. Approaches that work against consumer Defender are noisy under MDE because the cloud-side analytics layer is entirely different.

The operator who plans for "I'll just patch AMSI" has not engaged with MDE. By 2025 nearly every easy AMSI patch is itself an ASR rule trigger or a behavioral IOA. This page covers MDE's actual architecture, the surviving evasion patterns, and the way ASR + sensor-tamper protection compound to make traditional tradecraft increasingly noisy.

## What MDE Actually Is

MDE is four products in a trench coat. The names matter because each has its own bypass surface.

1. **Microsoft Defender Antivirus (MDAV)** — the AV engine. Real-time signature scans, AMSI, behavioral detection rules in `MpEngine.dll`. Same engine on consumer Windows, different cloud telemetry destination.
2. **MDE Sensor (MsSense)** — the EDR sensor that ships ETW + kernel telemetry to Microsoft's cloud. `MsSense.exe`, `SenseCM.exe`, `SenseIR.exe`, `SenseSampleUploader.exe`, `MsMpEng.exe` (the AV scanner co-process).
3. **Attack Surface Reduction (ASR) rules** — a set of process-behavior rules with GUIDs that block specific patterns regardless of detection (Office spawning child processes, lsass credential dumping, executable content in Outlook, etc.). ASR is a *blocking* control that fires *before* the cloud sees the event.
4. **Defender XDR (formerly Microsoft 365 Defender)** — the cloud-side correlation. Pulls MDE + Defender for Office (email), Defender for Identity (AD signals), Defender for Cloud Apps (SaaS), Entra ID Protection. The XDR layer is what makes MDE materially harder than a stand-alone EDR.

Operators must defeat or evade all four. Patching AMSI defeats nothing useful if the loader spawned by Word is already blocked by ASR rule `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` (Office spawn child).

## Fingerprinting MDE on the Box

```
# Service / process indicators (run any of these as a low-priv user)
Get-Service | Where-Object {$_.Name -match "Sense|Wd|MsMp"}
# Look for: Sense (the EDR sensor), WdNisSvc, WinDefend

Get-Process | Where-Object {$_.ProcessName -match "MsSense|SenseCM|SenseIR|MsMpEng"}

# Registry — sensor configuration
reg query "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection" /s
# Key indicator: OnboardingState = 1 (sensor is onboarded to a tenant)

# WMI — get tenant ID and sensor state
Get-MpComputerStatus | Select-Object AMRunningMode, AMServiceEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# Find ASR rules currently configured
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Tamper protection state (the key MDE setting)
Get-MpComputerStatus | Select-Object IsTamperProtected
```

Tamper protection is the single most important state to read. If `IsTamperProtected = True`, no admin (including SYSTEM, including TrustedInstaller) can disable Defender services or modify scan exclusions via supported APIs. Disabling tamper protection requires either the cloud-side admin path (Defender XDR portal) or a kernel-level write.

## What MDE Catches Well

The cloud-side behavior engine has trained on real attacker activity for several years. The list of things that fire reliably is long. Operators planning an engagement should assume catch on:

- **LSASS handle open** from any non-system process — Cred Access IOA fires within seconds, often before the dump completes.
- **Mimikatz** in any form — binary, in-memory string presence, behavioral signature on `sekurlsa::logonpasswords`.
- **PsExec** without legitimate context — service create with executable image launched from non-standard path.
- **`certutil.exe -urlcache`** or **`bitsadmin /transfer`** as living-off-the-land download — Threat & Vulnerability Management flags this independent of cloud verdict.
- **Office spawning script hosts** (`winword.exe → wscript.exe`) — ASR rule blocks, period.
- **Encoded PowerShell** above a complexity threshold — AMSI + cloud heuristic.
- **Process hollowing** into `notepad.exe` / `explorer.exe` from non-standard parent — behavior detection.
- **Macro launching child process** — ASR rule blocks.
- **WMI persistence via `__EventConsumer`** — Threat Graph telemetry hit.
- **Suspicious DLL load by Office** — ASR rule blocks.

The pattern: anything that has appeared in a real incident response engagement is in the dataset. MDE's defensive advantage over Falcon is the breadth of Microsoft's signal — every Exchange Online tenant, every M365 tenant, every Defender for Identity install feeds the model.

## What MDE Catches Less Well

The gaps are narrower than they used to be but they still exist:

- **In-process code execution that never crosses a process boundary** — a reflective load into the same process that originated the loader, with AMSI patched at process startup before any malicious string is scanned.
- **Memory-resident shellcode loaded via custom syscalls** in a *signed* host process when no API call sequence triggers a behavioral IOA. The host process matters here — a known LOLBin like `werfault.exe` running with unusual memory layout often slips.
- **Activity inside a process tree MDE considers benign** — a long-running developer tool process (VS Code with extensions, GitHub Desktop) that loads a malicious extension or DLL has a different risk profile than a fresh process tree from a downloaded file.
- **Slow operations** — Defender's cloud behavioral models look at sequences in time windows. Spreading a credential-access operation across an hour with cover activity in between drops below threshold.
- **Data exchange to legitimate cloud endpoints from a high-trust process** — Beacon HTTP traffic to `*.azureedge.net` or `graph.microsoft.com` from `MsEdgeWebView2.exe` is hard to distinguish from normal telemetry.
- **Kernel callbacks removed via BYOVD** — sensor stops receiving events. XDR sees a heartbeat anomaly but the on-box stream is silent.

## AMSI Bypass Survival

AMSI is the in-process content-scan interface. Defender hooks `AmsiScanBuffer` and friends. By 2025, the easy bypasses are noisy:

| Technique | MDE outcome (2024-2026) |
|---|---|
| `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` reflection | Caught — signature on the pattern itself. |
| AMSI provider DLL unregister | Caught — registry write IOA. |
| `AmsiScanBuffer` first-byte patch via VirtualProtect + WriteProcessMemory | Caught most variants — the patch *pattern* is detected. |
| AMSI DLL unmap from process | Caught — module-unload telemetry. |
| Hardware breakpoint (HWBP) AMSI bypass | Generally **survives** — the bypass occurs in DR registers without writing memory; AMSI scans return zero results. |
| Provider-process-startup patch (patch before AMSI registers in the process) | Generally **survives** for new processes; harder for processes already running. |

Hardware-breakpoint AMSI bypass via `SetThreadContext` against the loader thread is the 2024-2026 baseline. Combine with **ETW-TI bypass** (also via HWBP) and the in-process surface is materially reduced. The cross-process surface (sensor → cloud telemetry from other processes) is unaffected.

## ETW Telemetry — The Quiet Killer

Defender consumes ETW from many providers, but ETW-Threat-Intelligence (ETW-TI) is the one that produces the most behavior-IOA-relevant data. Hooking patterns:

- `EtwEventWrite` in `ntdll.dll` patched to return success without writing — historically worked; modern Defender has a behavior IOA on the patch pattern.
- `NtTraceControl` to deregister provider — sensor IOA hit.
- HWBP on `EtwEventWrite` for selective bypass — generally survives because no memory is modified.
- Patch *before* ETW provider registration in the process — possible only for new processes; the most stealthy.

The realistic 2026 approach is HWBP-based for both AMSI and ETW, applied at process startup via a small loader.

## ASR Rules — The Bypass That Isn't

Attack Surface Reduction rules block patterns regardless of cloud verdict. They are evaluated in the sensor and act as a hard wall. Common rules and what they block:

| ASR Rule GUID | What it blocks |
|---|---|
| `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | Office apps creating child processes |
| `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2` | Office apps creating executable content |
| `26190899-1602-49E8-8B27-EB1D0A1CE869` | Office communication apps (Outlook) creating child processes |
| `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` | Executable content in email and webmail |
| `D3E037E1-3EB8-44C8-A917-57927947596D` | JavaScript or VBScript launching downloaded content |
| `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B` | Win32 API calls from Office macros |
| `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` | Obfuscated scripts |
| `01443614-cd74-433a-b99e-2ecdc07bfc25` | Executable files unless prevalence, age, or trusted list criteria |
| `c1db55ab-c21a-4637-bb3f-a12568109d35` | Advanced ransomware protection |
| `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` | Persistence through WMI event subscription |
| `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Office launching child processes (duplicate of older GUID) |
| `e6db77e5-3df2-4cf1-b95a-636979351e5b` | LSASS credential stealing |

The lsass rule (`e6db77e5-3df2-4cf1-b95a-636979351e5b`) is particularly aggressive. With it enabled, any `OpenProcess` against `lsass.exe` from a non-protected process is blocked. The fact that Defender does this *before* a cloud-side verdict means custom syscall lsass dumping fails too.

ASR rules can be in "audit" mode rather than "block" mode. The first check on a target is which rules are blocking vs. auditing.

```
# Block mode = 1, audit = 2, off = 0, warn = 6
$rules = Get-MpPreference
for ($i = 0; $i -lt $rules.AttackSurfaceReductionRules_Ids.Length; $i++) {
    [PSCustomObject]@{
        GUID = $rules.AttackSurfaceReductionRules_Ids[$i]
        Action = $rules.AttackSurfaceReductionRules_Actions[$i]
    }
}
```

If lsass rule is in audit (2), an operator can still dump lsass; the alert fires but no block.

## Sensor Tamper Protection

Tamper protection prevents disabling Defender services, scan exclusion modification, real-time protection disable, and ASR rule changes via local admin. It is enabled by default in Windows 11 23H2+ and in any tenant with security defaults.

Approaches:

- **Cloud-side disable** — requires owning a Defender XDR Security Administrator role. Rare initial-access target, but the highest-value path: cloud-disable tamper protection on a target machine, then operate normally.
- **Kernel write via BYOVD** — directly modify the `WdFilter.sys` config or remove kernel callbacks. The most reliable on-box approach in 2024-2026. Vulnerable drivers covered at `/evasion/byovd`.
- **MpCmdRun unsupported flags** — older versions of `MpCmdRun.exe` accept signed-binary-proxy patterns to invoke arbitrary loaders. Mostly patched by 2024 but worth checking sensor version.

## Cross-Process Tradecraft Survival

Practical patterns that survive a 2026 MDE deployment when combined:

1. **HWBP AMSI + ETW bypass** at process startup via small loader.
2. **Custom syscall stubs** for sensitive APIs (process injection, memory allocation in remote process, token operations). Indirect syscalls via Halo's/Tartarus' Gate.
3. **Process injection target = signed, long-lived host process** — explorer.exe, OneDrive.exe, MsEdgeWebView2.exe. Reduce the parent/child IOA surface.
4. **Sleep obfuscation** — encrypt the beacon payload during sleep so memory scanning windows return clean content.
5. **C2 traffic mimicking Office 365 telemetry** — beacon URLs that match `*.office.com/api/`, JSON payload shaped like Graph telemetry. Defender XDR is *less* prone to flag this because it shares telemetry shape with legitimate M365.
6. **Avoid LOLBins on the standard threat-intel list** — `certutil`, `bitsadmin`, `mshta`. Use less-trodden ones (`finger.exe`, `forfiles.exe`, `regsvcs.exe`) with awareness that the list keeps growing.

## Sensor Downgrade and Off-Box Disable

The cleanest disable is from the Defender XDR console. The pre-condition is a tenant admin compromise (covered at `/active-directory/entra-connect-compromise` and `/active-directory/azure-ad`). With a Security Administrator role:

- Remove machine from sensor onboarding (machine reports as "unmanaged")
- Disable specific ASR rules tenant-wide
- Add scan exclusions for specific paths or processes
- Tag machine as "isolated" or "low priority"

The Defender XDR portal action shows in the audit log, but rate-limit and timing are the cover.

## C2 Profile Considerations

Cobalt Strike default profiles and Mythic default profiles are heavily fingerprinted in Defender XDR. The 2024-2026 baseline:

- **Custom Malleable C2 profile** that mimics a real M365 service (Graph API, Teams telemetry, OneDrive sync).
- **HTTPS only**, with JA3/JA4 fingerprint mimicking a recent Edge browser.
- **POST body** shaped like Graph API JSON.
- **User-Agent** matching the Edge build present on target machines.
- **Sleep interval** between 30s and 5min with jitter ≥35%.

## Detection Signals to Expect

| Action | Likely outcome |
|---|---|
| Run `nltest /domain_trusts` | Cloud telemetry; no block |
| `whoami /priv` | Cloud telemetry; no block |
| Open handle to `lsass.exe` | ASR block if rule enabled; loud IOA if not |
| Create remote thread in another process | Behavior IOA |
| Register WMI permanent event consumer | Behavior IOA; ASR block if rule enabled |
| Write to `Run` key in HKCU | Behavior IOA |
| Schedule task with PowerShell -enc | Behavior IOA |
| Download via certutil | Behavior IOA |
| AMSI scan of obvious malicious string | Static detection + AV block |
| Run signed LOLBin (rundll32) with unusual arguments | Behavior IOA |

## Tools and Research

- **SharpEDRChecker** (PwnDexter) — sensor enumeration including MDE.
- **`Defender-Check.ps1`** — community PS script for tamper protection / ASR rule reading.
- **`Inceptor`** / **`ScareCrow`** — payload loaders with EDR-evasion plumbing built in (need updating per release).
- **`PPLBlade`** — PPL-bypass and lsass-dump bypass (regularly patched).
- **`SyscallMon`** — research-grade tool for studying syscall coverage.
- **`AMSITrigger`** — pre-test PowerShell payloads against the AMSI signature surface before live use.
- **`Process Hacker`** with custom plugins — useful for sensor enumeration in lab.

## Resources

- Microsoft Learn, "Defender for Endpoint" full product documentation
- Microsoft Threat Intelligence blog, MDE detection case studies (Storm-XXXX series)
- Outflank, "EDR detection mechanisms and bypasses" (multi-part)
- MDSec, "Bypassing Microsoft Defender for Endpoint" research
- Christopher Vella, "Defender for Endpoint internals" blog series
- F-Secure Labs / WithSecure Labs, sensor research papers
- Antonio Cocomazzi (cocomelonc), per-technique MDE outcome blog series
