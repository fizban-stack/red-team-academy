---
layout: training-page
title: "SIP — System Integrity Protection — Red Team Academy"
module: "macOS"
tags:
  - macos
  - sip
  - system-integrity-protection
  - recovery-mode
  - csrutil
  - apple-silicon
page_key: "macos-sip-bypass"
render_with_liquid: false
---

# SIP — System Integrity Protection

System Integrity Protection (SIP, sometimes called "rootless") is the kernel-enforced boundary that prevents even root from modifying system files, system processes, and a specific set of system-level configurations. Apple introduced SIP in El Capitan (10.11, 2015) and has tightened it with every subsequent release. SIP is the reason that "I have root on this Mac" does *not* mean "I can do whatever I want on this Mac." Understanding SIP is prerequisite to understanding why the macOS attack surface has the shape it does.

This page covers what SIP actually protects, the boundary mechanics, how SIP state is set and read, the historical bypass-class taxonomy (anchored in public CVEs), and the defender telemetry for SIP changes. The intent is mechanism understanding; weaponization details for any specific historical bypass remain in vendor advisories and original research.

## What SIP Protects

SIP is enforced by the kernel and configured by AppleMobileFileIntegrity (AMFI). It restricts the following even from root:

- **Filesystem write** to `/System`, `/usr` (excluding `/usr/local`), `/bin`, `/sbin`, parts of `/var`, and `/Library/Apple/*`
- **Process injection** into Apple-signed processes (DTrace, debugger attachment, task port acquisition)
- **Kernel extension loading** — only signed and Apple-approved kexts can load (and on modern macOS, kexts are nearly extinct anyway)
- **NVRAM variable modification** for security-relevant variables (boot-args restrictions)
- **Modification of /System/Library** even by package installers — packages that need to land there go through System Software Update or Apple-only signed installers
- **Modification of certain system caches** (kernel cache, dyld shared cache)

On Apple Silicon, SIP composes with **Signed System Volume (SSV)** — the system volume is a cryptographically-sealed snapshot, not just file-protected. Modifying it requires rebuilding the seal, which requires recoveryOS-side action.

## What SIP Does NOT Protect

The boundary is precise. SIP does *not* protect:

- `/Users/*` (the home directories)
- `/Applications` (most apps)
- `/Library` (excluding the Apple-prefixed subdirectories)
- `/etc`, `/var/log`, `/tmp`, `/usr/local`, `/opt`
- LaunchAgent / LaunchDaemon directories outside `/System` (i.e., `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents`)
- Per-app TCC database for user-context apps (`~/Library/Application Support/com.apple.TCC/TCC.db`)
- Configuration profile installation (PPPCs can grant TCC entitlements without touching SIP-protected paths)

The above are where operators land most of their persistence and where defenders most need their telemetry — SIP narrows the surface but does not eliminate it.

## SIP State Mechanics

SIP state is stored in an NVRAM variable read at boot. The state is queried in user space with `csrutil`:

```
# Query SIP state
csrutil status
# Sample outputs:
#   System Integrity Protection status: enabled.
#   System Integrity Protection status: disabled.
#   System Integrity Protection status: enabled (Custom Configuration).

# Querying more detail
csrutil status --verbose
# Lists the granular flags: filesystem-protections, debugging-restrictions, 
# kext-loading, task-for-pid, dtrace-restrictions, NVRAM-protections, BaseSystem
```

The granular flags allow partial disable — for example, kext loading can be re-enabled (`Reduced Security`) without disabling filesystem protections.

SIP state can only be changed from **recoveryOS** with `csrutil enable|disable`. On Apple Silicon, recoveryOS requires either a physical power-up-and-hold-power-button or an MDM-driven `mdmclient` action with appropriate entitlement. Even with root on a running system, SIP cannot be changed.

## Apple Silicon and SIP — The Important Change

On Apple Silicon, SIP is composed with the **boot security policy**:

- **Full Security** — only Apple-signed software boots; kexts cannot load; recovery requires Apple ID; **SIP can be changed from recoveryOS only after entering the local admin password**.
- **Reduced Security** — kexts allowed (with consent dialogs), third-party OS images allowed; SIP can be modified in recoveryOS.
- **Permissive Security** — research/lab posture; reduced trust evaluation; SIP can be modified freely in recoveryOS.

Most enterprise MDM-managed Macs are on Full Security with MDM-controlled boot-security-policy. Changing security policy requires a recoveryOS visit and admin authentication. The implication: enterprise operators encountering "I'll just disable SIP" expectations from Intel-era Mac engagements need to recalibrate. On a managed Apple Silicon Mac with Full Security, SIP-changing actions are gated by physical access plus admin authentication plus an MDM-monitored event.

## Historical Bypass Classes — Anchored in Research

Apple has patched a series of SIP bypasses since 2015; the public catalogue is useful for mechanism understanding.

### CVE-2015-7062 (Shrootless and earlier ancestors)
The "rootpipe" class — pre-SIP and early-SIP bugs in `Authorization` and `XPC` services that exposed privileged operations.

### CVE-2021-30892 — Shrootless (Microsoft Research)
Microsoft's Shrootless research showed a SIP bypass via `system_installd`'s package-installation post-install scripts. The post-install scripts ran with SIP-bypassed entitlements, and the script content was attacker-controllable. Patched in macOS 11.6 / 12.0.

### CVE-2022-32894 (Pointer authentication boundary)
Apple Silicon-specific kernel write that bypassed SIP indirectly. Patched in macOS 12.5.

### CVE-2023-32369 — Migraine (Microsoft Research)
A SIP bypass via Time Machine's privileged restore process. Patched in macOS 13.4.

### CVE-2023-42932
Disclosed bypass in a system component. Patched promptly.

The pattern is consistent: each class is patched within a release cycle, and the value to operators is the mechanism understanding (system services running with `com.apple.rootless.install.heritable` entitlement, controllable inputs to such services, post-install scripts as a vector). The class lives; the specific bypass is patched.

## The MDM-Side Path

A compromised MDM admin can push a configuration profile that affects boot security policy. The mechanism:

- MDM profile with `com.apple.security.firmware` payload type
- Pushes boot-security-policy change to enrolled devices
- On Apple Silicon, the change does *not* disable SIP directly — but it can set the device to Reduced or Permissive Security, which makes recovery-mode SIP changes possible
- The MDM payload itself is logged; auditing MDM admin actions catches this

This is why MDM admin is a high-blast-radius target. The Mac's SIP boundary is not bypassed by a network-side action — but the *posture* under which SIP can be relaxed is.

## Defender Telemetry

SIP state changes produce telemetry. A SOC with Mac visibility should see:

- **NVRAM variable changes** — via Endpoint Security framework (some EDRs) or via boot-time inventory
- **Boot-args modifications** — via diagnostic logs at boot
- **csrutil invocations** — via Unified Log (`com.apple.csrutil` subsystem)
- **`mdmclient` security-policy commands** — via Unified Log on the endpoint and MDM admin audit log on the server side
- **Boot Security Policy changes** — surfaced via Jamf Protect / CrowdStrike Falcon for Mac inventory reporting

The detection rule shape: **"any Mac whose boot security policy or SIP state changed without a corresponding approved MDM action"** is a strong rule with a low FP rate.

## Operator Considerations

For scoped engagements on hardened Mac targets:

- **Don't plan on disabling SIP.** On Apple Silicon Full Security, this is impractical without physical-plus-admin-password access and a recoveryOS visit, which is a visible event.
- **Stay within the SIP-unprotected paths.** The persistence catalog at `/macos/persistence-catalog` is structured around what is reachable from a SIP-respecting position.
- **Watch for environments with Reduced/Permissive Security.** Lab Macs, developer Macs, and some legacy fleets may be in Reduced Security. Those are operationally different.
- **MDM admin compromise is the realistic SIP-relaxation path** — and it is high-visibility on the customer side.

## Tools for Inspection (Research / Defensive)

- **`csrutil status [--verbose]`** — user-space query
- **`nvram -p`** — view NVRAM variables
- **`bputil`** — Apple Silicon boot-security-policy command (recoveryOS-only on hardened devices)
- **`profiles list`** — view configuration profiles (including MDM-pushed ones that affect security policy)
- **`system_profiler SPiBridgeDataType`** — view T2 / Secure Enclave details (Intel + Apple Silicon)
- **Patrick Wardle's Objective-See tools** — surface SIP-relevant runtime events

## Cross-References

- `/macos/tcc-bypass` — TCC database is SIP-protected at the system level
- `/macos/gatekeeper-xprotect` — Gatekeeper enforcement runs in SIP-protected processes
- `/macos/persistence-catalog` — persistence vectors within SIP-allowed paths
- `/macos/mdm-jamf-kandji-abuse` — MDM-driven boot-security-policy changes
- `/post-exploitation/macos-red-team` — broader Mac post-ex

## Resources

- Apple Platform Security Guide — SIP section (apple.com/security/)
- Microsoft Security Research — Shrootless writeup (Oct 2021), Migraine writeup (May 2023)
- Patrick Wardle / Objective-See — multiple SIP-relevant blog posts
- Csaba Fitzl (theevilbit) — SIP research blog series
- Jonathan Levin's *MacOS and iOS Internals* series — SIP and AMFI internals
- Apple's CVE advisories per release
- WWDC sessions on system integrity (multiple years)
