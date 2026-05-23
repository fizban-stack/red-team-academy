---
layout: training-page
title: "TCC — Transparency Consent Control — Red Team Academy"
module: "macOS"
tags:
  - macos
  - tcc
  - privacy
  - fda
  - full-disk-access
  - consent
  - endpoint-security
page_key: "macos-tcc-bypass"
render_with_liquid: false
---

# TCC — Transparency, Consent, and Control

Transparency, Consent, and Control (TCC) is Apple's per-app permissions framework. It is the privacy boundary that does not exist on Windows, the boundary most Windows-fluent operators consistently underestimate when stepping into Mac engagements, and the boundary defenders most frequently fail to instrument. This page is the mechanism, the historical bypass classes anchored in public CVEs and research, the defender telemetry, and the engagement-time considerations for operators planning Mac actions.

## What TCC Controls

TCC gates an application's access to a curated set of sensitive resources. The list grew with each macOS release; by macOS 15 (Sequoia) the gated set includes:

- Full Disk Access (FDA) — the master switch for many other categories
- User documents (Documents, Downloads, Desktop)
- Contacts
- Calendar
- Reminders
- Photos
- Camera
- Microphone
- Screen Recording (covers screenshot and screen-share)
- Accessibility (the keystroke-injection / UI-automation surface)
- Input Monitoring (keylogger-relevant)
- Automation (sending Apple Events to another app — the AppleScript / JXA primitive)
- Bluetooth, Location, HomeKit
- Files in iCloud Drive
- Files on network volumes
- Removable volumes

The list determines TCC's behavior. An app cannot perform a screenshot capture, send an Apple Event to another app, monitor keystrokes, or read most user data without an entry in the relevant TCC database.

## TCC.db — Where Permissions Live

Two databases hold TCC state:

- **System TCC.db** — `/Library/Application Support/com.apple.TCC/TCC.db` (root-owned, SIP-protected on modern macOS)
- **User TCC.db** — `~/Library/Application Support/com.apple.TCC/TCC.db` (per-user, accessible by the user themselves with the right permission flags but not externally)

Both are SQLite. The schema centers on the `access` table:

```sql
-- Schema (simplified)
CREATE TABLE access (
    service     TEXT NOT NULL,        -- e.g. "kTCCServiceSystemPolicyAllFiles"
    client      TEXT NOT NULL,        -- bundle ID or path
    client_type INTEGER NOT NULL,     -- 0 = bundle ID, 1 = path
    auth_value  INTEGER NOT NULL,     -- 0 denied, 2 allowed, 3 limited
    auth_reason INTEGER NOT NULL,
    auth_version INTEGER NOT NULL,
    csreq       BLOB,                 -- code signing requirement
    policy_id   INTEGER,
    indirect_object_identifier_type INTEGER,
    indirect_object_identifier TEXT,
    indirect_object_code_identity BLOB,
    flags       INTEGER,
    last_modified INTEGER,
    PRIMARY KEY (service, client, client_type, indirect_object_identifier)
);
```

The `csreq` column is the cryptographic binding: each TCC grant is tied to the specific code-signing identity of the granted app. This is what prevents a malicious replacement of `iTerm.app` from inheriting iTerm's Full Disk Access grant.

## Why TCC Matters for Operators

An operator who has user-level code execution on a Mac with no TCC grants for their hosting process is materially limited:

- Cannot read `~/Documents`, `~/Downloads`, `~/Desktop` directly
- Cannot read mail data, calendar, contacts
- Cannot record the screen
- Cannot send Apple Events to other apps (no Automation-driven LOTL)
- Cannot read browser histories or saved passwords from Chrome/Firefox/Safari profiles
- Cannot capture keystrokes outside their own app
- Cannot read certain login keychain entries depending on app context

Getting useful work done on a hardened Mac frequently routes through obtaining a TCC grant — most commonly Full Disk Access — for the hosting process. That requirement shapes much of the macOS post-exploitation page (`/post-exploitation/macos-red-team`).

## Full Disk Access — The Master Grant

Full Disk Access is the most consequential TCC grant. It implicitly grants access to most other categories (Documents, Mail data, browser data, Messages history, Safari history, location services data, and the TCC.db itself in some configurations).

FDA is granted manually via System Settings → Privacy & Security → Full Disk Access, requires entering the admin password, and is bound to a specific application. The grant entry lives in the system TCC.db, which is SIP-protected. An attacker cannot quietly add their own application to FDA — the grant must go through the legitimate UI path or via MDM.

The dominant path for an operator who wants FDA is therefore one of:

1. **Inherit FDA from a legitimately-granted app.** Many enterprise IT-management apps (Jamf Connect, IT-deployed backup agents, certain VPN clients, Microsoft AutoUpdate components) ship with FDA in deployed fleets. Compromising or injecting into one of those processes inherits the grant.
2. **Use the MDM path.** A compromised MDM admin can push a Privacy Preferences Policy Control (PPPC) profile that grants TCC permissions silently. Covered at `/macos/mdm-jamf-kandji-abuse`.
3. **Social engineering the user** to grant the FDA dialog to attacker-supplied software. High-friction, well-defended by enterprise IT, but historically successful at smaller orgs.

## Defender Telemetry for TCC

This is where operators most often misjudge — TCC produces telemetry, and good defenders can see it.

### Endpoint Security framework events

- `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` (macOS 13+) — fires on TCC.db modification
- `ES_EVENT_TYPE_AUTH_OPEN` — for files protected by TCC
- `ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION` — system-level authorization requests
- These are consumed by Jamf Protect, CrowdStrike Falcon for Mac, SentinelOne, and the Objective-See open-source tools.

### Unified Log subsystem

The `com.apple.TCC` subsystem produces verbose log entries on every TCC decision. Key fields:

- Service requested
- Bundle ID / executable path
- Decision (allowed / denied / prompt-shown)
- Decision source (db match, prompt, MDM profile)

A defender streaming the Unified Log filtering on `subsystem = com.apple.TCC` sees every grant attempt, including the failed ones. The volume is moderate but well within SIEM-budgets for any Mac fleet larger than a few hundred.

### Database modification

The `last_modified` column in the TCC.db updates on every change. A daily snapshot of TCC.db and a diff is a cheap detection that catches a class of historical bypasses.

## Historical Bypass Classes — Anchored in Public Research

This section catalogs bypass classes that have appeared in vendor advisories and public CVE filings. Apple has patched each as it surfaced; the value here is understanding the mechanism so defenders and operators alike can recognize the pattern.

### Direct TCC.db write (pre-modern)

On older macOS (10.13 and earlier), the system TCC.db was writable by root without SIP intervention. A root process could grant itself any TCC permission. Apple's response was to bring TCC.db under SIP protection, which is the current state.

### Symbolic link redirection (CVE-2020-9934)

Discussed in Adam Chester's 2020 research and Apple's subsequent advisory. The user TCC.db was reachable through a controllable path; symlink manipulation allowed a malicious app to redirect TCC.db reads to an attacker-controlled file. Patched in macOS 11.

### CVE-2021-30713 — XCSSET malware abuse of TCC

XCSSET malware used a chain involving privileged helper apps to bypass TCC. Disclosed in the Apple security advisory for macOS 11.4.

### CVE-2021-30798 — "Powerdir" (Microsoft research)

Researchers at Microsoft's 365 Defender Research Team demonstrated that the TCC database could be redirected by manipulating the `HOME` environment variable in specific paths. Patched in macOS 12.1.

### CVE-2022-32826 — "Achilles" (Wardle / Objective-See research)

Bypass involving the way TCC handled certain inherited permissions. Patched in macOS 12.4.

### CVE-2023-32369 — "Migraine" (Microsoft research)

A SIP bypass that, combined with TCC, allowed bypass of TCC controls. Discussed at length in the Microsoft Security Response Center advisory.

The pattern: each disclosure produces a vendor patch within a release cycle. Operators who depend on these patterns are operators relying on un-patched fleets — which exist, but degrade over time.

## What Defenders Get Wrong

Three recurring blue-side gaps:

1. **No streaming of `com.apple.TCC` Unified Log.** The data is there; the rule is missing.
2. **TCC.db modifications not correlated with policy push.** A grant that arrived via MDM is logged differently than one that arrived via the UI; many SOCs do not distinguish.
3. **PPPC profiles not inventoried.** A maliciously-pushed PPPC profile grants TCC permissions silently. Inventorying installed PPPCs daily and diffing against an approved list catches this class.

## Engagement-Time Considerations

For scoped engagements on hardened Mac targets:

- **Assume TCC limits your unaided process.** Plan the chain accordingly.
- **The screen-recording category requires re-consent every 24 hours on macOS 15+.** The 24-hour weekly notification pattern surfaces granted-app activity to the user.
- **Accessibility is now an explicit, separately-granted category** and shows the user a strong banner when newly-added apps request it.
- **The notarization-then-revocation path is a one-way door.** Once a notarization ticket is revoked, every Mac that's gone online since revocation will refuse the binary. Engagement payloads that rely on notarization need rotation plans.

## Tools for Inspection (Defensive and Research)

- **Patrick Wardle's tooling** — KnockKnock (persistence audit), BlockBlock (creation-time blocks), DoNotDisturb (lid-close detection), and the broader Objective-See suite. Open source.
- **`tccutil reset <service>`** — administrative reset of TCC grants for a category.
- **`sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db`** — direct read of user TCC.db for inspection purposes.
- **`profiles list`** — view installed configuration profiles, including PPPCs.

## Cross-References

- `/macos/sip-bypass` — System Integrity Protection that protects the system TCC.db
- `/macos/gatekeeper-xprotect` — the first-launch evaluation that precedes TCC concerns
- `/macos/mdm-jamf-kandji-abuse` — the PPPC-via-MDM path
- `/post-exploitation/macos-red-team` — broader Mac post-exploitation
- `/exploitation/macos-initial-access` — initial access vectors that produce the unaided-by-TCC process state

## Resources

- Apple Platform Security Guide — TCC section (apple.com/security/)
- Adam Chester / SpecterOps blog — "TCC and the macOS Privacy Subsystem"
- Patrick Wardle / Objective-See — multiple blog posts and *The Art of Mac Malware* book
- Csaba Fitzl (theevilbit) — extensive TCC research blog
- Microsoft Security Response Center — Powerdir / Achilles / Migraine writeups
- Wojciech Reguła (wojciechregula.blog) — macOS / iOS security research
- Sentinel One macOS research blog
- Apple's CVE advisories per release
