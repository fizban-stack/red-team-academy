---
layout: training-page
title: "Gatekeeper, XProtect, MRT, Notarization — Red Team Academy"
module: "macOS"
tags:
  - macos
  - gatekeeper
  - xprotect
  - mrt
  - notarization
  - codesigning
  - quarantine
page_key: "macos-gatekeeper-xprotect"
render_with_liquid: false
---

# Gatekeeper, XProtect, MRT, Notarization

macOS layers four Apple-maintained controls between an arriving binary and the user double-clicking it. Operators who don't understand the layers run noisy engagements; defenders who don't understand them miss the signals each control emits. This page is the mechanism, the defender telemetry, and the historical bypass-class taxonomy. Detailed weaponization is out of scope here — the intent is to give operators the architectural understanding that lets them predict which payloads will land cleanly and which will trip an alert before the user even clicks.

## The Four Layers

| Layer | What it does | When it fires |
|---|---|---|
| **Gatekeeper** | Runtime policy: is this signed? notarized? quarantined? | First launch of a quarantined binary |
| **XProtect** | Apple's built-in YARA-driven signature scanner | On execution + periodic background scans |
| **MRT** | Malware Removal Tool — periodic removal of known malware | Periodically + on signature update |
| **Notarization** | Apple cloud-side scan + ticket on submitted binaries | At submission (developer side) + first launch (user side) |

The layers are sequenced. Gatekeeper evaluates *first*; if Gatekeeper denies, the binary doesn't run. XProtect scans on execution and during background sweeps. MRT cleans up post-hoc. Notarization is a developer-side step that produces an artifact (the ticket) that Gatekeeper consults.

## Gatekeeper — How It Decides

Gatekeeper is implemented in `syspolicyd` and consulted by LaunchServices when a new binary is asked to run. The decision tree:

1. Is the binary quarantined (has `com.apple.quarantine` extended attribute)?
2. If quarantined: is it signed with a recognized identity?
3. If signed: is it notarized (does it have a stapled ticket, or can the system reach Apple's notary service)?
4. If notarized: has the notarization been revoked?
5. If all pass: present the first-launch confirmation dialog to the user.
6. If any fail: present the error dialog.

The user-space query tool is `spctl`:

```
# Assess a binary the way Gatekeeper would
spctl --assess --verbose /path/to/Binary.app
# Output: source=Notarized Developer ID

# Assess with origin (where it came from)
spctl --assess --verbose --type execute /path/to/Binary.app

# View Gatekeeper policy
spctl --status
# Output: assessments enabled / disabled

# View the policy database
sqlite3 /var/db/SystemPolicy "SELECT * FROM authority"
```

The decision is logged extensively in the Unified Log under the `com.apple.syspolicy` subsystem.

## The Quarantine Attribute

The `com.apple.quarantine` extended attribute is the trigger for Gatekeeper evaluation. It is added by applications that fetch content from the network and conform to LaunchServices' quarantine API. Most browsers add it; AirDrop sometimes does; `curl` and `wget` do not.

```
# View quarantine attribute on a file
xattr -p com.apple.quarantine /path/to/file
# Sample: 0083;65a1b234;Safari;ABC12345-6789-...

# Strip it (the historical "no Gatekeeper prompt" trick)
xattr -d com.apple.quarantine /path/to/file
xattr -cr /path/to/Bundle.app    # recursive clear

# Add it for testing
xattr -w com.apple.quarantine "0001;65a1b234;Test;ABC" /path/to/file
```

The attribute is the primary input to Gatekeeper. A binary that arrives via a delivery method that doesn't apply quarantine sidesteps Gatekeeper entirely. This is the operational reality behind a class of historical bypasses — not "I broke Gatekeeper" but "I delivered the binary in a way that never invoked Gatekeeper."

## Notarization Architecture

Notarization is Apple's cloud-side malware check for developer-signed binaries. The submission flow:

1. Developer submits binary (or container .dmg, .pkg, .zip) to Apple's notary service.
2. Apple runs automated malware-scanning checks (typically a few minutes).
3. Apple returns a notarization ticket — a cryptographic statement bound to the binary's signature and hash.
4. Developer optionally "staples" the ticket onto the binary (so first-launch works without network access).
5. On user-side first launch, Gatekeeper either uses the stapled ticket or fetches it online.

The notable property of notarization: **Apple can revoke a ticket centrally**. Once revoked, every Mac that's been online since revocation will refuse the binary. This is a one-way door for engagement payloads — a single bad signature decision can burn the payload across the fleet.

The notarization API does not deeply analyse binaries; it primarily checks for known-malicious code patterns and certain entitlement misuse. Many post-disclosure analyses showed notarized binaries had snuck through notarization repeatedly (Shlayer / OSAMiner cases). Notarization is a useful filter; it is not a thorough malware sandbox.

## XProtect

XProtect lives at `/Library/Apple/System/Library/CoreServices/XProtect.bundle`. Its primary artifact is `XProtect.yara` — a YARA rule file Apple updates centrally and pushes to enrolled Macs out-of-band.

```
# View XProtect version
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version

# Read the YARA rules (root may need SIP-bypass on some macOS versions; on modern macOS the file is SIP-protected)
sudo cat /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara
```

XProtect signatures are visible to anyone who can read the file — which means the threat-research community treats new XProtect rules as a signal of what malware families Apple is currently catching. The rule names map to families: `XProtect_Pirrit`, `XProtect_Genieo`, `XProtect_Shlayer`, etc.

XProtect updates run in the background via the XProtect Remediator (XPR) and through MRT. The cadence is weekly to bi-weekly for routine updates and faster for active campaigns.

## MRT (Malware Removal Tool)

`/Library/Apple/System/Library/CoreServices/MRT.app` is the on-disk removal tool. MRT runs on system events (boot, login, software update) and removes known-malicious files keyed by Apple's signature database. MRT is reactive — it removes what XProtect or other detection has identified.

## Historical Bypass Classes — Anchored in Research

Patched bypasses, useful for mechanism understanding:

### Quarantine attribute not applied
Several delivery methods historically didn't apply quarantine: `curl`/`wget`, mounted disk images in specific configurations, some AirDrop paths, files synced via early-version cloud storage clients. Each was a Gatekeeper sidestep, not a Gatekeeper bypass.

### CVE-2021-30657 (Shlayer / ACE bypass — Cedric Owens research)
A flaw in how Gatekeeper evaluated unsigned scripts in `.app` bundles allowed Shlayer-class malware to bypass Gatekeeper entirely. Patched in macOS 11.3.

### CVE-2022-22616 (notarization sidestep)
Disclosed bypass that allowed notarized-binary-substitution patterns. Patched promptly.

### CVE-2023-23204 / CVE-2023-32434
Various Gatekeeper / notarization adjacent issues patched through 2023.

### Bundle structure tricks
Several historical bypasses involved manipulating `.app` bundle metadata to confuse the evaluator. Apple has hardened bundle parsing across releases.

## Defender Telemetry

What the SOC should be collecting (and frequently isn't):

| Signal | Where it lives |
|---|---|
| Gatekeeper decisions | Unified Log, `com.apple.syspolicy` subsystem |
| XProtect detections | Unified Log + XPR reports |
| MRT removal events | Unified Log + Endpoint Security framework |
| Notarization fetch failures | Unified Log + diagnostic reports |
| `xattr` modifications stripping quarantine | EDR via Endpoint Security framework |
| `spctl --add` (admin policy modification) | Unified Log |

A defender streaming `subsystem = com.apple.syspolicy` to a SIEM gets visibility into every Gatekeeper decision on the fleet. The volume is low enough to retain for months.

## Operator-Side Realities

- **Notarized payloads are revocable.** Use them with awareness that a bad-day signature decision burns every host that's online.
- **Document-borne delivery (Office macros, packaged scripts) routes through a different stack** — different evaluation, different signals.
- **Stage-zero must be benign.** A delivery that gets through Gatekeeper is usually one that hands off to a payload that doesn't itself need to pass Gatekeeper.
- **Quarantine is the trigger, not the rule.** Knowing which delivery vectors apply quarantine and which don't is the operational primitive.

## Cross-References

- `/macos/tcc-bypass` — TCC controls run downstream of Gatekeeper
- `/macos/sip-bypass` — SIP protects the Gatekeeper / XProtect / MRT files themselves
- `/macos/persistence-catalog` — persistence interacts with Gatekeeper on each application launch
- `/macos/mdm-jamf-kandji-abuse` — MDM-pushed application allow-listing complements Gatekeeper

## Resources

- Apple Platform Security Guide — Gatekeeper, XProtect, and Notarization sections
- Patrick Wardle / Objective-See — extensive coverage including *The Art of Mac Malware*
- Cedric Owens — Shlayer bypass research
- Microsoft Security Research — multiple TCC/SIP/Gatekeeper adjacency posts
- Csaba Fitzl (theevilbit) — Mac security research blog
- Sentinel One macOS research
- Phil Stokes / SentinelLabs — extensive Mac malware analysis
- The XProtect / MRT version history tracked publicly on GitHub by community researchers
- Apple's CVE advisories per release
