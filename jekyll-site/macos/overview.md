---
layout: training-page
title: "macOS Red Team — Module Overview — Red Team Academy"
module: "macOS"
tags:
  - macos
  - overview
  - apple-silicon
  - tcc
  - gatekeeper
  - sip
  - mdm
  - threat-model
page_key: "macos-overview"
render_with_liquid: false
---

# macOS Red Team — Module Overview

For the better part of the last decade, macOS was the "engineering laptops" footnote of a red team engagement scope. That footnote has become a body paragraph. Modern enterprises — particularly in tech, finance trading desks, media, biotech, and the executive class of every other industry — run substantial Mac fleets. The crown jewels travel on these machines, the developer credentials live in these machines' keychains, and the IT teams managing them often inherit Windows-trained instincts that do not transfer cleanly. This module is the operator's map of the macOS attack surface in 2025-2026, anchored in public research and aimed at training operators who already have Windows fluency.

The module is also, deliberately, defender-aware. Apple's security architecture is opinionated, layered, and surfaces a great deal of telemetry that goes uncollected in many enterprises. Every page here pairs the offensive mechanism with what defender telemetry exists for it. That's not because attackers and defenders use the same training material; it's because operators who don't understand the telemetry their actions produce are operators about to get caught by signals they didn't know existed.

## Why Mac Now

Three shifts pulled macOS into the foreground of enterprise threat modeling.

1. **Population growth.** Engineering, design, and executive populations skew heavily Mac. In several tech-sector firms, the Mac fleet now outnumbers the Windows fleet. The Mac is no longer the "design team's laptops" — it's the primary endpoint.
2. **Apple Silicon's security architecture.** The M1 and successor chips brought hardware-rooted security features (Secure Enclave, Activation Lock, Pointer Authentication on supported binaries, kernel coalescing) that meaningfully change the bypass landscape. Older techniques don't transfer.
3. **MDM-managed fleets at scale.** Jamf, Kandji, Mosyle, and Microsoft Intune for Mac are now common. The MDM is a centralized capability that, when compromised, yields code execution against every enrolled device. The Mac MDM threat model deserves the same gravity as SCCM/MECM on the Windows side.

## The Apple Security Stack

The controls below are layered. Operators need to understand each layer's purpose and what it can and cannot prevent.

| Layer | What it does | Failure mode (mechanism, not chain) |
|---|---|---|
| **Code signing** | Every binary that runs goes through trust evaluation | Ad-hoc signing, expired identities, post-quarantine modification |
| **Notarization** | Apple cloud-side scan + ticket on submitted binaries | Notarized binaries can be revoked centrally; tickets can be stapled |
| **Gatekeeper** | First-launch policy: signed, notarized, quarantined? | First-launch only by default; quarantine attribute can be absent on certain delivery methods |
| **XProtect** | YARA-driven signature scanner, Apple-maintained | Signature-based; lag from disclosure to rule |
| **MRT** | Periodic removal of known malware | Lags XProtect; reactive |
| **TCC** | Per-app permissions for files, camera, mic, screen | User consent + Full Disk Access path |
| **SIP** | System Integrity Protection — kernel-level filesystem and process policy | Disabled in recoveryOS by explicit user action |
| **Hardened Runtime** | Memory protection + library-load restrictions | Per-binary opt-in; legacy binaries don't have it |
| **App Sandbox** | Mandatory access control inside an app's process | Not all apps sandboxed |
| **Endpoint Security framework** | Defender API surface | Requires kernel-extension-or-system-extension entitlement |

Understanding the stack is the prerequisite for understanding why a given technique works on macOS 11 and not 14, why notarized binaries are harder to use than they were in 2019, and why the operator's persistence options shrank in macOS 13.

## What This Module Covers

This is the module map. Click each page for the deep dive.

| Page | Coverage |
|---|---|
| [`gatekeeper-xprotect`](/macos/gatekeeper-xprotect) | Gatekeeper, XProtect, MRT, notarization — mechanism and detection signals |
| [`tcc-bypass`](/macos/tcc-bypass) | Transparency Consent Control — mechanism, defender telemetry, historical bypass classes |
| [`sip-bypass`](/macos/sip-bypass) | System Integrity Protection — boundary, defender telemetry, recovery-mode posture |
| [`mdm-jamf-kandji-abuse`](/macos/mdm-jamf-kandji-abuse) | MDM as a lateral-movement vector; Jamf/Kandji/Mosyle/Intune for Mac |
| [`persistence-catalog`](/macos/persistence-catalog) | The fifteen-ish persistence vectors, current as of macOS 14+ |

Adjacent pages elsewhere in the site that bear on Mac engagements:

- `/post-exploitation/macos-red-team` — broader post-ex content
- `/exploitation/macos-initial-access` — initial-access vectors
- `/living-off-the-land/macos-lotl` — LOLBin equivalents for macOS
- `/post-exploitation/anti-forensics` — covers macOS-relevant anti-forensics
- `/mobile/ios-setup`, `/mobile/frida` — iOS-side content (shares some primitives)

## Apple Silicon vs Intel — What Matters

The transition from Intel Macs to Apple Silicon (M1, M2, M3, M4 and successors) is largely complete in enterprise fleets being deployed today (2025-2026). Operators must internalize the differences:

- **Pointer Authentication (PAC)** — control-flow integrity feature on Apple Silicon. Materially changes return-oriented programming feasibility on hardened binaries.
- **Recovery mode requires physical or remote-recoveryOS access.** You cannot drop into Recovery from a fully-running session over SSH the way some older techniques implied.
- **Boot Security policy is per-OS-install.** Reduced Security mode (required for legacy kexts and some debugging) is set per-installation and surfaces to MDM.
- **Activation Lock and Find My** are tied to Apple ID and the Secure Enclave; remote wipe is fast and reliable.
- **Local Network Privacy** changed how applications announce themselves on the LAN.
- **macOS 14 (Sonoma) and 15 (Sequoia)** continued tightening — login items UI, weekly TCC notification, executable-resource-allow on screen recording.

Operators arriving on a target Mac in 2025-2026 should assume Apple Silicon, hardened runtime, MDM enrollment, and TCC-restricted access until proven otherwise.

## Telemetry Sources Operators Should Expect

If the target has any meaningful Mac security maturity, these telemetry streams are likely in play. Operators should assume their actions appear in at least one of them.

- **Unified Logging System** — `log show` / `log stream` — verbose system-wide log. Subsystems like `com.apple.syspolicy`, `com.apple.amfi`, `com.apple.tcc`, `com.apple.security.codesigning` are particularly relevant.
- **Endpoint Security framework** — what commercial Mac EDR tools (Jamf Protect, CrowdStrike Falcon for Mac, SentinelOne, Sophos for Mac, BlockBlock, Objective-See suite) sit on top of.
- **Notarization revocation** — Apple can revoke a notarization ticket; the OS checks online on first launch (if network available).
- **MDM device inventory** — Jamf/Kandji/Mosyle/Intune all report installed apps, configuration, and policy compliance.
- **FileVault state** and disk-level encryption posture.
- **iCloud and Find My** account state.
- **macOS-native crash reports** in `~/Library/Logs/DiagnosticReports/` — frequently survive cleanup attempts.

## What Defenders Do Well on Mac

Mac shops with mature security generally do these things, and operators should expect them at high-tier targets:

1. MDM-pushed Jamf Protect / CrowdStrike Falcon for Mac with kernel-level Endpoint Security extension.
2. Unified Log streaming to a SIEM (Splunk Connect for log, or a custom forwarder).
3. Configuration profiles that enforce FileVault, restrict TCC modification, disable Recovery without password, disable SSH, and disable USB autorun.
4. Application allow-listing (often Jamf's "restricted software" or Kandji's blueprint policies).
5. EDR coverage of LaunchAgent / LaunchDaemon creation.
6. Apple Business Manager (ABM) integration for zero-touch enrollment, removing the "personal Apple ID on corporate device" path.

## What Defenders Frequently Miss on Mac

The asymmetry the operator can plan around:

1. **Unified Log retention is typically short and non-streamed.** Many shops keep Mac logs local-only or stream selectively.
2. **TCC.db modifications often go uncorrelated.** Even with logging, the SOC may not have a detection rule on TCC database alteration.
3. **MDM admin auditing is weak.** Who pushed which policy, when, with what justification — these are often not enforced as workflow.
4. **Mac-specific YARA / Sigma rule coverage lags Windows by years.**
5. **MFA on MDM admin consoles is inconsistent.** FIDO2 enforcement on Jamf Pro admin login is the exception, not the norm.
6. **Recovery mode posture varies.** Reduced Security mode is set in some fleets to support legacy software, with no compensating control.

## Engagement Notes — Scoping Considerations Specific to Mac

- **MDM admin** is high-blast-radius. Engagement scope should explicitly address whether MDM admin compromise is in or out of scope.
- **Personal-device implications.** Some Mac fleets allow personal Apple ID on corporate device. Operator activity may surface in the user's personal iCloud account in unexpected ways. Engagement plans must address this.
- **Recovery-mode actions** require physical access (or screen-sharing into a system that's been put into Recovery). Scope this explicitly.
- **Apple Business Manager / Apple School Manager** is a separate admin surface from MDM. If in scope, surface it as such.

## Recommended Reading Order for Operators New to Mac

If you are Windows-fluent and stepping into a Mac engagement for the first time:

1. This overview (you are here).
2. `gatekeeper-xprotect` — how the first-launch security boundary works.
3. `persistence-catalog` — how Mac persistence differs from Windows.
4. `tcc-bypass` — the privacy-control boundary that does NOT exist on Windows.
5. `sip-bypass` — the SIP boundary, why it matters, why it usually doesn't move.
6. `mdm-jamf-kandji-abuse` — the management-plane threat model.

After these five, branch into the post-exploitation and initial-access pages elsewhere on the site.

## Defender Quick Reference

If you are reading this from the blue side, the minimum-viable Mac security uplift is:

- MDM with mandatory FIDO2 on admin consoles
- Jamf Protect or equivalent EDR with Endpoint Security framework
- Unified Log streaming to SIEM with retention measured in months
- Detection rules on: new LaunchAgent/LaunchDaemon, TCC.db direct write, MDM admin login from new IP, SIP state change, configuration profile install from outside MDM
- Application allow-listing via MDM policy
- ABM-only enrollment (no personal Apple ID on corporate device)
- Periodic audit of installed configuration profiles fleet-wide

## Resources

- Apple Platform Security Guide (apple.com/security/) — annual updates, the foundational document
- Apple Endpoint Security framework documentation (developer.apple.com)
- Patrick Wardle / Objective-See — long-running coverage of macOS malware and security architecture
- *The Art of Mac Malware* (Wardle, 2022 / Vol 2 forthcoming) — book-length treatment
- Jaron Bradley, *OS X Incident Response: Scripting and Analysis*
- Jonathan Levin's *MacOS and iOS Internals* series — foundational
- Cedric Owens — public research on Mac TTPs
- Sentinel One macOS research blog
- Objective-See's annual Mac Malware Report
- Mandiant / Microsoft Threat Intelligence reports referencing macOS-targeting actors
