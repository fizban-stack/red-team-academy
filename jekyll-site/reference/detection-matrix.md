---
layout: training-page
title: "Detection Adversarial Matrix — Red Team Academy"
module: "Reference"
tags:
  - detection
  - edr
  - crowdstrike
  - sentinelone
  - defender
  - carbon-black
  - evasion
  - reference
page_key: "reference-detection-matrix"
render_with_liquid: false
---

# Detection Adversarial Matrix

This matrix documents how major EDR/XDR platforms detect common red team techniques. It is intended as a quick-reference guide for operators planning engagements, selecting evasion approaches, and understanding what telemetry defenders can see.

---

## Methodology and Caveats

**Assessment sources:**
- Vendor public documentation and technical whitepapers
- Security research papers and conference presentations (Black Hat, DEF CON, BlueHat, x33fcon)
- Published red team practitioner reports and blog posts
- Community testing from vendors like SpecterOps, MDSec, TrustedSec, FortyNorth Security

**Critical caveats:**

1. **Detection varies by configuration.** A "Detected by Default" rating assumes a fully configured deployment with recommended settings. A poorly tuned CrowdStrike deployment may miss things a well-tuned one catches.

2. **Evasion is a cat-and-mouse game.** A bypass documented in 2023 may be patched by the time you read this. Always test in your own lab against your target's specific EDR version.

3. **Cloud intelligence matters.** CrowdStrike Threat Graph and SentinelOne's cloud AI see telemetry from millions of endpoints. A technique that was novel one month may be detectable the next after being observed in the wild.

4. **Detection status key:**
   - **YES** — Detected by default with standard configuration
   - **CUSTOM** — Detected only with custom detections or tuning
   - **BYPASS** — Known public bypass exists (may be patched)
   - **PARTIAL** — Some implementations caught, others not
   - **NO** — Not reliably detected by default

---

## CrowdStrike Falcon (Prevent + Threat Graph)

CrowdStrike Falcon uses a combination of machine learning (on-sensor and cloud), behavioral indicators of attack (IoAs), and Threat Graph (cloud-based correlation across all telemetry). Its primary strength is behavioral detection — it often does not care what a file is named or what hash it has, but rather what it *does*.

**Architecture relevant to evasion:** Falcon's sensor hooks at the kernel driver level. Many userland unhooking techniques that work against other EDR products do not work against CrowdStrike because it hooks at a lower level.

| Technique | Detected by Default | Custom Logic Needed | Known Bypass | Notes |
|---|---|---|---|---|
| **Mimikatz (direct execution)** | YES | — | YES | Binary hash signatured; behavioral pattern also detected. Obfuscated builds and renamed binaries still triggered by lsass handle pattern |
| **LSASS dump via handle (Task Manager)** | YES | — | PARTIAL | Task Manager as lsass dumper detected; custom lsass handle + minidump pattern also caught |
| **LSASS dump via ProcDump** | YES | — | YES | ProcDump with lsass is flagged; using signed dumpers with /ma and /accepteula bypasses some detections |
| **Pass-the-Hash (PtH)** | YES | — | PARTIAL | PtH detected via network logon patterns + LSASS access; remote execution via PtH harder to detect |
| **Pass-the-Ticket (PtT)** | PARTIAL | YES | PARTIAL | TGT injection not well detected by default; suspicious Kerberos ticket usage can trigger with tuning |
| **BOF-based LSASS dump (nanodump)** | PARTIAL | YES | YES | Direct syscall BOFs avoid Falcon userland hooks; nanodump via direct handle duplicating bypasses many patterns |
| **Reflective DLL Injection** | YES | — | PARTIAL | Reflective loader patterns detected; custom reflective loaders with stomping reduce detection |
| **Process Hollowing** | YES | — | PARTIAL | PE unmapping + writing patterns detected; some implementations evade by avoiding standard hollowing APIs |
| **Module Stomping** | PARTIAL | YES | YES | Writing to existing legitimate module memory space less detected than standard injection |
| **Early Bird APC Injection** | PARTIAL | YES | YES | Queue APC to process before entry point executes; less behavioral coverage than standard injection |
| **VBA Macro (Office)** | YES | — | PARTIAL | Default macros detected; template injection via remote template partially evades |
| **PowerShell download cradle** | YES | — | YES | IEX (IWR ...) and similar patterns detected; encoding and splitting strings across variables can bypass |
| **Scheduled Task persistence** | YES | — | PARTIAL | schtasks.exe usage detected; COM-based task creation via Task Scheduler API less visible |
| **Service creation (sc.exe)** | YES | — | PARTIAL | sc create + start detected; API-based service creation less flagged |
| **Registry Run key** | YES | — | PARTIAL | Obvious run key writes detected; encrypted payload paths or indirect writes (via Group Policy simulation) evade |
| **DLL Side-Loading** | PARTIAL | YES | YES | Known vulnerable application + DLL combination detected; novel combinations not |
| **BloodHound enumeration (SharpHound)** | YES | — | YES | SharpHound binary signatured; custom builds, BOF-based LDAP collection evade |
| **Kerberoasting (Rubeus)** | YES | — | PARTIAL | Rubeus binary detected; Invoke-Kerberoast (PowerShell) partially evades; ticket volume anomalies caught in Threat Graph |
| **DCSync (Mimikatz)** | YES | — | PARTIAL | DRSUAPI calls from non-DC detected; via Impacket from Linux with valid DA creds partially evades |
| **Golden Ticket** | PARTIAL | YES | PARTIAL | Golden ticket usage patterns detected (PAC validation failures); forged tickets with valid data harder |
| **AMSI bypass (patching)** | YES | — | YES | Memory write to amsi.dll AMSI patterns detected; BOF-based bypass at kernel level less detected |
| **ETW bypass (patching)** | PARTIAL | YES | YES | ETW patch in EtwEventWrite detected by some Falcon builds; kernel-level ETW bypass evades |
| **Process injection (classic)** | YES | — | PARTIAL | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread is well detected; indirect variants less so |
| **Shellcode via indirect syscalls** | PARTIAL | YES | YES | Falcon hooks at kernel level, but timing of syscall execution and call stack still analyzed |

**Key CrowdStrike evasion insight:** CrowdStrike's kernel driver is hard to unhook from userland. The most reliable evasion approach is to avoid triggering behavioral patterns entirely — use BOFs that execute in-process, use sleep obfuscation to hide beacon in memory, and use legitimate system processes as the behavioral context for your actions.

---

## SentinelOne (Static AI + Behavioral AI)

SentinelOne uses a dual AI engine: a static machine learning model that scans files before execution, and a behavioral AI engine that watches process trees and API calls at runtime. SentinelOne's approach differs from CrowdStrike in that it relies more heavily on AI-based classification and less on hand-written signatures.

**Architecture relevant to evasion:** SentinelOne uses a user-space agent and installs kernel-level components for behavioral data collection. Its static AI can be tested before deployment by running files through its local classifier. Behavioral AI is harder to evade because it models the entire process tree, not individual API calls.

| Technique | Detected by Default | Custom Logic Needed | Known Bypass | Notes |
|---|---|---|---|---|
| **Mimikatz (direct execution)** | YES | — | YES | Static AI catches known binary; heavily modified builds evade static; behavioral patterns (LSASS handle) caught by behavioral AI |
| **LSASS dump via handle** | YES | — | PARTIAL | Handle duplication + minidump pattern detected; nanodump-style dump via forked process reduces detection |
| **LSASS dump via ProcDump** | YES | — | YES | Microsoft-signed ProcDump against lsass detected; custom signed dumper with obfuscated flags can bypass |
| **Pass-the-Hash** | YES | — | PARTIAL | PtH network patterns detected; same as CrowdStrike |
| **Pass-the-Ticket** | PARTIAL | YES | PARTIAL | Similar to CS; anomalous ticket usage requires tuning |
| **BOF-based LSASS dump** | PARTIAL | YES | YES | BOF executes in beacon process; direct syscalls partially evade userland hooks |
| **Reflective DLL Injection** | YES | — | YES | Behavioral pattern detected; module stomping less detected than standard reflective load |
| **Process Hollowing** | YES | — | PARTIAL | Process unmapping behavior detected; some novel implementations evade |
| **Module Stomping** | PARTIAL | YES | YES | Less covered than hollowing; beacon with module stomping can evade |
| **Early Bird APC** | YES | — | PARTIAL | SentinelOne's behavioral graph covers process startup injection |
| **VBA Macro (Office)** | YES | — | PARTIAL | VBA + shellcode detected; template injection + remote template partially bypasses |
| **PowerShell download cradle** | YES | — | YES | AMSI integration catches most PS cradles; encoding + AMSI bypass required |
| **Scheduled Task persistence** | YES | — | PARTIAL | schtasks.exe behavioral pattern detected; API-based less detected |
| **Service creation** | YES | — | PARTIAL | Behavioral service creation pattern caught; obfuscated service names not specifically flagged |
| **Registry Run key** | YES | — | PARTIAL | Direct RegSetValue to Run keys detected; indirect writes less so |
| **DLL Side-Loading** | PARTIAL | YES | YES | Known vulnerable apps detected; novel side-loading not |
| **BloodHound enumeration** | YES | — | YES | Binary signatured; LDAP query volume heuristic catches enumeration behavior |
| **Kerberoasting** | PARTIAL | YES | PARTIAL | Rubeus binary caught; ticket request volume from non-service context detected with tuning |
| **DCSync** | YES | — | PARTIAL | DRSUAPI behavior detected; Impacket from Linux partially evades |
| **Golden Ticket** | PARTIAL | YES | PARTIAL | Post-ticket anomalies detected; ticket forgery itself hard to detect |
| **AMSI bypass (patching)** | YES | — | YES | Memory modification of amsi.dll detected by behavioral AI; in-process BOF bypass less covered |
| **ETW bypass** | PARTIAL | YES | YES | ETW patching detected in some configurations |
| **Process injection (classic)** | YES | — | PARTIAL | Classic injection chain detected; indirect injection with legitimate API call patterns less so |
| **Shellcode via indirect syscalls** | PARTIAL | YES | YES | Syscall-based injection bypasses userland hooks; behavioral pattern (process tree anomaly) still visible |

**Key SentinelOne evasion insight:** SentinelOne's static AI is good at catching modified binaries but imperfect — heavily obfuscated builds with low-entropy encryption can evade. The behavioral AI is harder to evade because it models entire attack chains, not individual events. BOF-based tradecraft is the most reliable approach since it minimizes the behavioral footprint.

---

## Microsoft Defender for Endpoint (MDE / Defender ATP)

MDE benefits from deep Windows OS integration that other products cannot replicate. It is built directly into the kernel, has access to ETW telemetry at the OS level, and is integrated with Microsoft's global threat intelligence. Its Advanced Hunting capability via KQL and its integration with Azure Sentinel make it powerful for defenders.

**Architecture relevant to evasion:** MDE uses the same AMSI integration as Windows Defender AV. Its ASR (Attack Surface Reduction) rules block specific behaviors (Office spawning processes, etc.). The Tamper Protection feature prevents the Defender service from being stopped or modified.

| Technique | Detected by Default | Custom Logic Needed | ASR Rule Coverage | Notes |
|---|---|---|---|---|
| **Mimikatz (direct execution)** | YES | — | Partial | Binary signatured; behavioral lsass access detected; LSASS PPL not bypassed by standard Mimikatz |
| **LSASS dump via handle** | YES | — | YES (ASR: Block LSASS credential stealing) | ASR Rule ID: 9e6c4e1f blocks credential stealing tools from LSASS |
| **LSASS dump via ProcDump** | YES | — | PARTIAL | ProcDump + lsass caught by ASR; signed dumpers partially evade |
| **Pass-the-Hash** | YES | — | NO | PtH itself not ASR-covered; lateral movement patterns detected by Advanced Hunting |
| **Pass-the-Ticket** | PARTIAL | YES | NO | Anomalous Kerberos ticket usage detected with Advanced Hunting rules |
| **BOF-based LSASS dump** | PARTIAL | YES | PARTIAL | Direct syscall BOF bypasses AMSI; ASR LSASS rule still applies at kernel level |
| **Reflective DLL Injection** | YES | — | NO | Behavioral detection; not ASR covered |
| **Process Hollowing** | YES | — | NO | Behavioral detection; MDE has good coverage of standard hollowing |
| **Module Stomping** | PARTIAL | YES | NO | Less behavioral coverage than standard injection |
| **Early Bird APC** | PARTIAL | YES | NO | Some builds detect; not consistent |
| **VBA Macro (Office)** | YES | — | YES (ASR: Block Office macro obfuscated code) | Multiple ASR rules: block Office from spawning processes, block obfuscated macros |
| **PowerShell download cradle** | YES | — | PARTIAL | AMSI catches most; constrained language mode blocks some cradles |
| **Scheduled Task persistence** | YES | — | NO | Behavioral detection of task creation + script execution |
| **Service creation** | YES | — | NO | Service installation with unsigned binary detected |
| **Registry Run key** | YES | — | NO | Behavioral and signature detection |
| **DLL Side-Loading** | PARTIAL | YES | NO | Known patterns detected; novel combinations not |
| **BloodHound enumeration** | YES | — | NO | SharpHound binary signatured; LDAP query volume flagged in Advanced Hunting |
| **Kerberoasting** | PARTIAL | YES | NO | Rubeus binary; ticket request anomalies need Advanced Hunting rules |
| **DCSync** | YES | — | NO | DRSUAPI from non-DC detected; Advanced Hunting alert available |
| **Golden Ticket** | PARTIAL | YES | NO | Requires Advanced Hunting; Kerberos PAC validation anomalies |
| **AMSI bypass (patching)** | YES | — | YES | Tamper protection + AMSI integrity monitoring |
| **ETW bypass** | PARTIAL | YES | NO | Detected in some builds; Advanced Hunting for ETW patching |
| **Process injection (classic)** | YES | — | NO | Well-detected behavioral pattern |
| **Shellcode via indirect syscalls** | PARTIAL | YES | NO | Bypasses userland hooks; kernel telemetry still catches process anomalies |

**ASR Rules Reference for Operators:**

| ASR Rule ID | Rule Name | Impact on Red Team |
|---|---|---|
| `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` | Block credential stealing from LSASS | Major — blocks most lsass dumping |
| `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Block Office apps from creating child processes | Major — blocks macro payloads |
| `3b576869-a4ec-4529-8536-b80a7769e899` | Block Office apps from creating executable content | Major — blocks macro droppers |
| `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` | Block Win32 API calls from Office macros | Major — blocks shellcode-in-macro |
| `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Block execution of potentially obfuscated scripts | High — catches obfuscated PS/VBS |
| `e6db77e5-3df2-4cf1-b95a-636979351e5b` | Block persistence through WMI event subscription | High — blocks WMI persistence |

---

## VMware Carbon Black (Carbon Black Cloud)

Carbon Black takes a reputation and behavioral approach. Every process is assigned a reputation score based on its certificate, hash, and behavioral history. Unknown or low-reputation processes receive higher scrutiny. Defenders can set policies ranging from "log everything" to "block low-reputation processes."

**Architecture relevant to evasion:** Carbon Black's reputation system is exploitable — if you can execute from a high-reputation binary (signed by Microsoft or a major vendor), your action inherits that reputation. This is why LOLBins (Living Off the Land Binaries) are particularly effective against Carbon Black.

| Technique | Detected by Default | Custom Logic Needed | Known Bypass | Notes |
|---|---|---|---|---|
| **Mimikatz (direct execution)** | YES | — | YES | Low reputation + known hash; signed, custom build with high-rep certificate evades |
| **LSASS dump via handle** | YES | — | YES | Handle behavior flagged; using signed trusted tools partially evades |
| **LSASS dump via ProcDump** | PARTIAL | YES | YES | Microsoft-signed ProcDump against lsass; reputation is high (MS signed) but behavior flagged |
| **Pass-the-Hash** | PARTIAL | YES | PARTIAL | Network logon anomalies; requires custom watchlists |
| **Pass-the-Ticket** | PARTIAL | YES | PARTIAL | Requires custom detection logic |
| **BOF-based LSASS dump** | PARTIAL | YES | YES | BOF executes in beacon process (high rep if beacon is signed); behavior still analyzed |
| **Reflective DLL Injection** | YES | — | PARTIAL | Memory injection behavioral pattern detected |
| **Process Hollowing** | PARTIAL | YES | YES | Less behavioral coverage than CrowdStrike; novel hollowing often evades |
| **Module Stomping** | NO | YES | YES | Carbon Black has limited coverage of module stomping |
| **Early Bird APC** | PARTIAL | YES | YES | APC injection into trusted process often evades |
| **VBA Macro (Office)** | YES | — | PARTIAL | Office macro spawning child processes detected; template injection less covered |
| **PowerShell download cradle** | YES | — | YES | PowerShell from Office detected; signed PS with obfuscation evades |
| **Scheduled Task persistence** | PARTIAL | YES | YES | Task creation detected for low-rep processes; high-rep parent evades |
| **Service creation** | PARTIAL | YES | YES | Service from low-rep binary caught; high-rep binary as service evades |
| **Registry Run key** | PARTIAL | YES | YES | Run key writes detected for low-rep processes |
| **DLL Side-Loading** | PARTIAL | YES | YES | Known side-loading pairs detected; novel pairs not |
| **BloodHound enumeration** | PARTIAL | YES | YES | SharpHound reputation is low; LDAP queries from low-rep process flagged |
| **Kerberoasting** | PARTIAL | YES | YES | Low-rep process making Kerberos requests flagged; from high-rep process less flagged |
| **DCSync** | PARTIAL | YES | YES | DRSUAPI behavior; requires custom alerting in Carbon Black |
| **Golden Ticket** | NO | YES | YES | Carbon Black has limited native Kerberos ticket analysis |
| **AMSI bypass (patching)** | PARTIAL | YES | YES | Memory writes by low-rep process detected; high-rep loader less flagged |
| **ETW bypass** | NO | YES | YES | Carbon Black has limited ETW bypass detection |
| **Process injection (classic)** | YES | — | YES | Standard injection from low-rep process detected; from high-rep process (e.g., signed binary) less detected |
| **Shellcode via indirect syscalls** | PARTIAL | YES | YES | Syscall-based techniques partially evade; parent process reputation matters |

**Carbon Black key insight:** Reputation is the primary control. If you can execute from within a trusted, signed process, you inherit that process's reputation. This makes LOLBins (mshta.exe, regsvr32.exe, wscript.exe, rundll32.exe) effective but also common — defenders with Carbon Black should watchlist LOLBin behaviors.

---

## Bypass Matrix Summary

Side-by-side view of which EDR products provide the most reliable detection for common techniques. **Lower = harder to detect without bypass**.

| Technique | CrowdStrike | SentinelOne | MDE | Carbon Black |
|---|---|---|---|---|
| Mimikatz direct | HIGH | HIGH | HIGH | HIGH |
| LSASS dump (standard) | HIGH | HIGH | HIGH | MEDIUM |
| LSASS dump (nanodump BOF) | MEDIUM | MEDIUM | MEDIUM | LOW |
| Pass-the-Hash | HIGH | HIGH | HIGH | MEDIUM |
| Pass-the-Ticket | MEDIUM | MEDIUM | MEDIUM | LOW |
| Reflective DLL injection | HIGH | HIGH | HIGH | MEDIUM |
| Process Hollowing | HIGH | HIGH | HIGH | MEDIUM |
| Module Stomping | MEDIUM | MEDIUM | MEDIUM | LOW |
| Early Bird APC | MEDIUM | HIGH | MEDIUM | MEDIUM |
| VBA Macro | HIGH | HIGH | HIGH | HIGH |
| PowerShell cradle (unobfuscated) | HIGH | HIGH | HIGH | HIGH |
| Scheduled Task (API-based) | MEDIUM | MEDIUM | MEDIUM | LOW |
| DLL Side-Loading (novel) | LOW | LOW | LOW | LOW |
| SharpHound / BloodHound | HIGH | HIGH | HIGH | MEDIUM |
| Kerberoasting (Rubeus) | HIGH | HIGH | MEDIUM | MEDIUM |
| DCSync (Mimikatz) | HIGH | HIGH | HIGH | MEDIUM |
| DCSync (Impacket from Linux) | MEDIUM | MEDIUM | MEDIUM | LOW |
| Golden Ticket | MEDIUM | MEDIUM | LOW | LOW |
| AMSI bypass (patching) | HIGH | HIGH | HIGH | MEDIUM |
| ETW bypass | MEDIUM | MEDIUM | MEDIUM | LOW |
| Process injection (standard) | HIGH | HIGH | HIGH | MEDIUM |
| Indirect syscalls | MEDIUM | MEDIUM | MEDIUM | LOW |
| Sleep obfuscation | LOW | LOW | LOW | LOW |
| BOF-based tradecraft | MEDIUM | MEDIUM | MEDIUM | LOW |

**Rating:** HIGH = reliably detected, MEDIUM = detected with tuning or specific implementations, LOW = generally not detected by default

---

## Key Takeaways for Operators

### Most Reliable Evasion Techniques Across All Products

1. **BOF-based post-exploitation** — executing in the beacon process (especially Cobalt Strike BOFs) avoids spawning new processes and minimizes behavioral footprint across all four products.

2. **Module stomping + sleep obfuscation** — writing beacon into a legitimate DLL's memory space and encrypting it during sleep makes static and memory scanning significantly less effective.

3. **Indirect/direct syscalls** — bypassing userland hooks is most effective against products that rely heavily on userland hooking (SentinelOne, Carbon Black). CrowdStrike's kernel-level monitoring reduces this effectiveness, but syscall-based techniques still bypass some patterns.

4. **Novel DLL side-loading** — all four products have limited coverage of newly discovered side-loading pairs. Research known-vulnerable applications with signed executables and test against your target EDR.

5. **LOLBins (high reputation)** — Carbon Black specifically, and others to a lesser degree, are vulnerable to LOLBin abuse when the parent process has high reputation. The key is finding LOLBin chains that are not watchlisted.

6. **Impacket-based attacks from Linux** — DCSync and PtH attacks from a Linux host using Impacket are less detected than the same attacks from a Windows host using GUI tools.

### Techniques That Almost Always Get Caught

1. **Mimikatz.exe (any standard build)** — all four products detect it via binary hash, behavioral patterns, or both. Do not use the standard Mimikatz binary in any engagement with modern EDR.

2. **SharpHound.exe (standard build)** — similarly signatured across all products. Use custom-compiled builds, BOF-based collection, or ADExplorer as an alternative.

3. **Standard VBA macros spawning processes** — all four products catch the Office → child process behavioral chain. Use template injection, DCOM-based execution, or shellcode-only macros.

4. **Unobfuscated PowerShell download cradles** — caught by AMSI integration across all Windows-based products. Always pair with a working AMSI bypass.

5. **PsExec (Cobalt Strike built-in)** — the standard PsExec lateral movement in Cobalt Strike is highly signatured. Use WMI, DCOM, or SMB beacon pivoting instead.

### The Value of BOFs vs Traditional Post-Exploitation Tools

Traditional post-exploitation follows the pattern: drop binary → execute binary → binary makes noisy OS calls → EDR detects. BOFs change this entirely:

- **No new process** — BOF executes within the existing beacon process (e.g., `explorer.exe` or `svchost.exe` if injected)
- **No disk writes** — BOF is sent from the team server, executes in memory, results are returned
- **Inherits beacon's reputation** — if your beacon is in a high-reputation process, your BOF inherits that reputation
- **Hard to attribute** — no separate process tree entry, no prefetch entry, no shimcache/amcache entry

Key BOF collections for offensive operators:
- [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) — recon BOFs
- [OutflankNL C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) — LSASS, Kerberos BOFs
- [Crypt0-m3lon BOF collection](https://github.com/Crypt0-m3lon/CobaltStrike4.x-BOFs) — various offensive BOFs
- [nanodump](https://github.com/helpsystems/nanodump) — stealthy LSASS dump via BOF

---

## Updating This Matrix

Detection capabilities change frequently. When you test a technique against an EDR and find results that differ from this matrix, consider:
- Checking the EDR product version (detections vary significantly between versions)
- Whether the policy is on Detect mode vs Prevent mode (Detect = alert only, Prevent = block)
- Whether the target has custom detections or integrations (SIEM rules, threat hunting rules)

This matrix reflects community knowledge as of 2025. Always validate against your specific target environment in a controlled lab before the engagement.
