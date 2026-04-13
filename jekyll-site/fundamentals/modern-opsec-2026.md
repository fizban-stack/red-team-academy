---
layout: training-page
title: "Modern OPSEC (2026) — Red Team Academy"
module: "Fundamentals"
tags:
  - opsec
  - tradecraft
  - threat-modeling
  - 2026
  - ja4
  - aitm
  - residential-proxies
  - lots
  - persona
page_key: "fundamentals-modern-opsec-2026"
render_with_liquid: false
---

# Modern OPSEC for Red Team Operators (2026)

The fundamentals of OPSEC do not change year to year — identify critical information, analyze threats, apply countermeasures. What changes every year is **what the defenders actually detect** and **what techniques still survive**. This page is the 2026-current layer on top of `/fundamentals/opsec/` and `/c2-frameworks/c2-opsec/`. Everything here is actionable, measured against the current defensive landscape (Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic, Microsoft Sentinel, Chronicle), and cross-referenced with real 2024–2025 threat-actor tradecraft that still works in 2026.

Use this as both:

- A **red team operator checklist** — what you must do on every engagement
- A **threat model** — what defenders should expect from adversaries who care about not getting caught

## What Changed Since 2023

If your tradecraft references still talk about JA3, direct syscalls, and raw Evilginx2 — it is out of date. The 2024–2026 shifts to internalize:

| Area | 2022–2023 state | 2026 state |
|------|-----------------|------------|
| TLS fingerprinting | JA3 / JA3S | **JA4+ family** (JA4, JA4S, JA4H, JA4T, JA4L, JA4X) — richer, harder to spoof |
| HTTP client spoofing | Custom headers | **curl-impersonate, curl_cffi, utls, go-reality** — byte-exact browser emulation |
| EDR user-mode bypass | Direct syscalls | Direct syscalls are **detected**. Indirect syscalls + **hardware breakpoints** + **call-stack spoofing** |
| LSASS dumping | MiniDumpWriteDump, procdump | Both are instant detects. Use **Nanodump**, **remote DCSync**, **silver ticket forging** |
| Kernel callbacks | Ignore them | **Enumerate and neutralize** via BYOVD (EDRSandBlast, EvilEDR, Terminator) |
| C2 infrastructure | VPS + redirector | **Cloud-native C2** — Cloudflare Workers, Lambda, Azure Functions, Vercel, Deno Deploy |
| Covert channels | HTTPS beaconing | **LOTS** — Telegram, Discord, Graph API, Dropbox, Slack, Notion |
| MFA bypass | Evilginx2 | **Evilginx 3.x, Tycoon 2FA, Mamba 2FA, EvilProxy, Caffeine** — Phishing-as-a-Service kits |
| IPv4 phishing exit | VPN | **Residential proxy networks** — BrightData, Oxylabs, NetNut, IPRoyal |
| FIDO2 / Passkeys | Rare | Widespread. **Cannot be phished.** Force downgrade to OTP/push, or steal session tokens after login |
| Defender landscape | On-prem SIEM | **MDR + XDR + managed hunt** — CrowdStrike OverWatch, Defender XDR, Mandiant |
| Threat actor ref model | APT29, FIN7 | **Scattered Spider, Volt Typhoon, Midnight Blizzard (token theft), Lazarus supply chain** |

Every section below unpacks one of these shifts into actionable tradecraft.

## Threat Model First

Before you pick tools, pick a **threat model tier** for the engagement. Tradecraft cost scales with tier.

### Tier 0 — Internal lab / CTF
- No real defenders. Defaults are fine.
- Used to: learn mechanics, build muscle memory.

### Tier 1 — Commodity AV, no EDR, reactive SOC
- Signature AV only. Log review is manual and after-the-fact.
- Survive by: not matching any public signature. Custom payload, basic crypter, no default tool output, don't write obvious filenames.

### Tier 2 — Modern EDR (CrowdStrike/Defender/SentinelOne), 24/7 SOC, SIEM
- Behavioural detection, memory scanning, canned threat-hunt queries.
- Survive by: in-memory operations only, malleable C2 with JA4 spoofing, indirect syscalls, no LSASS touch, no `whoami /all`, no default tool arguments.

### Tier 3 — MDR with active hunt team (OverWatch/Managed Defense), kernel-level telemetry, EDR + XDR + NDR
- Hunters write custom queries looking for your behavior, not your bytes.
- Survive by: sub-weekly dwell times, no repetitive beacon patterns, mimic user workflows, use LOTS C2, avoid anything that produces a single abnormal event.

### Tier 4 — Nation-state target
- Kernel callbacks enumerated and defended, ETW-TI, WDAC enforced, Smart App Control, network egress deeply inspected, insider-threat analytics, deception grid (canaries/honeytokens/decoys everywhere).
- Survive by: operate like a nation-state. LOTL only, supply chain or physical initial access, zero-tool operations where possible, pre-deployed infrastructure with months-long aging, strict compartmentalization between operators.

Pick your tier honestly. If you are tier 2 and you deploy a default Cobalt Strike beacon, you will be caught in the first beacon callback. If you are tier 4 and you try to act tier 2 by bringing an EXE, you will be caught before the process starts.

## TLS Fingerprinting in 2026 — JA4+ Family

JA3 / JA3S are dead signals. In 2024 FoxIO released the **JA4+ family**, and by 2026 every serious EDR/NDR vendor has adopted them:

- **JA4** — Client TLS ClientHello fingerprint (cipher list, extensions, supported groups, ALPN)
- **JA4S** — Server TLS response fingerprint
- **JA4H** — HTTP request fingerprint (method, version, headers, cookies)
- **JA4T** — TCP fingerprint (window size, options)
- **JA4L** — Latency fingerprint (RTT distribution)
- **JA4X** — X.509 certificate fingerprint

**Why this matters:** JA4H alone can distinguish Chrome 119 from Chrome 120, from Edge, from curl, from Go's `net/http`. JA4L catches beacon timing regularity you thought you had jittered away. Together they are effectively a TLS biometric.

**Red team countermeasures (2026):**

Do **not** write your own HTTP client. Use one of these libraries that reproduces a real browser byte-for-byte:

```
# curl-impersonate — drop-in curl that imitates Chrome/Firefox/Safari/Edge TLS fingerprint
curl_chrome116 https://target/

# curl_cffi — Python binding for curl-impersonate
import curl_cffi.requests as r
r.get("https://target/", impersonate="chrome120")

# utls (Go) — hand-craft ClientHello to match a specific browser
import "github.com/refraction-networking/utls"
spec, _ := utls.UTLSIdToSpec(utls.HelloChrome_120)

# go-reality — post-quantum TLS masquerade with XTLS-Reality, defeats SNI inspection entirely
```

Rotate the impersonation target per beacon if you can. Match the User-Agent header to the JA4 fingerprint — JA4H correlates the two, so a Chrome 120 JA4 with a "Mozilla/4.0 MSIE 7" UA is a free detect.

**Detection-side (for threat modelers):** log JA4 from the egress proxy or TLS terminating reverse proxy. Cluster unknown JA4s. A JA4 that does not match any known browser or OS telemetry is an implant.

## Modern EDR Evasion Stack (2026)

The 2022 "use direct syscalls" advice is now a **detect** — every mature EDR product hooks or inspects syscall invocation site, call stack, and return address. 2026 stack:

1. **Indirect syscalls** — jump through a legitimate ntdll.dll syscall stub so the return address lives in `ntdll.dll`, not your module. Tools: **Syswhispers3**, **HellsHall**, **TartarusGate**, **Halo's Gate**.
2. **Hardware breakpoint hooks (SetThreadContext)** — replace user-mode hooks with DR0-DR3 hardware breakpoints instead of patching function prologues. See `/evasion/hookchain/`.
3. **Call stack spoofing** — before calling a sensitive API, rewrite the return address chain so the stack walk looks like it originated in a legitimate module. Tools: **CallStackMasker**, **SilentMoonwalk**, **VulcanRaven**.
4. **Module stomping / module overloading** — load a benign signed DLL into your process and copy your shellcode over its `.text` section, so memory scans see a valid signed module.
5. **Sleep obfuscation** — encrypt the implant in memory during sleep. Ekko, Zilean, Deathsleep, Foliage. See `/evasion/sleep-obfuscation/`.
6. **Heap encryption** — same idea for the heap during sleep.
7. **ETW-TI awareness** — on Windows 11 22H2+ the ETW Threat Intelligence provider (`PsEtwLogThreatIntelligence`) runs in PPL and cannot be patched from user mode. Any `NtProtectVirtualMemory → RX` transition produces a telemetry event consumed by EDR. Mitigate by **never** transitioning RW→RX in your own process after startup. Use module stomping or separate processes.
8. **Kernel callback enumeration and neutralization** — a BYOVD driver enumerates and removes the EDR's `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `CmRegisterCallbackEx`, and `ObRegisterCallbacks` entries. Tools: **EDRSandBlast**, **EvilEDR**, **Terminator**, **AuKill**. Only use on engagements that authorize BYOVD. Microsoft's Vulnerable Driver Blocklist (enabled by default on Win11 22H2+) rejects many public vulnerable drivers — use one not yet on the list.
9. **WDAC / Smart App Control bypass** — under WDAC enforce mode, unsigned binaries do not run. Bypasses rely on signed interpreters (MSBuild, InstallUtil, Regsvr32 with scriptlet), or on signing your payload with a code-signing cert you've stolen / purchased through a shell company.

Treat the above as **stacked**. Missing one layer can unmask the others.

## Modern Credential Tradecraft

- **Never touch LSASS.** In 2026, any process opening a handle to `lsass.exe` with `PROCESS_VM_READ` fires an immediate detection on every mainstream EDR. Use one of:
  - **Nanodump** — duplicates a handle from a process that already has one, or reads LSASS via silent process exit.
  - **DCSync** — `secretsdump.py -just-dc-user domain/krbtgt` from a Domain Admin session. No LSASS touch on the target; the DC generates a replication event (4662 + 4624 on DC) which is still detectable but less noisy than LSASS.
  - **DSRM credential abuse** — offline NTDS.dit copy via VSS snapshot.
  - **Silver ticket / Golden ticket forging** — after you've exfiltrated hashes, forge tickets offline. No on-target credential theft at all.
- **Token theft over credential theft.** In cloud-heavy environments, stealing refresh tokens from browser cookies and data-protection API (DPAPI) stores gives you persistent access without ever needing a password or MFA. Tools: **ROADtools**, **TokenTactics**, **AADInternals**, **GraphRunner**.
- **Passkey / FIDO2 reality.** Passkeys are **not phishable**. If the target uses FIDO2, you cannot steal a passkey via AiTM. Workarounds:
  - **Downgrade attack** — trick the victim into selecting "Use another method" → OTP / push.
  - **Session token theft** post-authentication (the passkey authenticates the session; the session cookie is fair game).
  - **Authenticator enrollment hijack** — register your own passkey during a compromised admin session.
  - **Device code phishing** — see `/exploitation/device-code-phishing/`. FIDO2 is bypassed because the victim consents on their own device.

## Modern AiTM Phishing (2026)

Evilginx2 is still taught everywhere, but 2026 tooling has moved on:

- **Evilginx 3.x** — active fork maintained by Kuba Gretzky, still the reference implementation
- **Tycoon 2FA** — PhaaS kit, Cloudflare-fronted, rotates URIs and obfuscates JS per visitor
- **Mamba 2FA** — Telegram-delivered credentials, dynamic asset fetching
- **EvilProxy** — commercial PhaaS, rotates infrastructure automatically
- **Caffeine** — formerly dominant, still seen
- **Greatness** — Microsoft 365 targeting

The tradecraft lesson is not which kit to use. It is that **infrastructure is disposable**. Every one of these kits rotates domains, cert subjects, and landing-page JS per victim. A red team operator should be doing the same.

**Actionable 2026 AiTM setup (Evilginx 3.x example):**

```
# Use a categorized, aged domain behind Cloudflare
# Register via anonymous registrar (Njalla, 1984, Orangewebsite)

# Phishlet setup — use community phishlets, but customize:
# - Change all asset filenames (/js/main.js → /assets/v1/core.js)
# - Randomize captured-session cookie name
# - Change lure path per victim

evilginx config domain login.corp-portal[.]xyz
evilginx config ipv4 external $(curl -s ifconfig.me)
evilginx phishlets hostname o365 login.corp-portal.xyz
evilginx phishlets enable o365
evilginx lures create o365
evilginx lures edit 0 path /auth/$(openssl rand -hex 8)/
evilginx lures get-url 0

# Front it with Cloudflare Workers for IP abstraction:
# Worker proxies to origin, strips bot/scanner UAs, rewrites Cf-Connecting-IP
```

Combine with:

- **SMS lure** from a spoofed or Twilio number
- **Voice lure** from an AI voice clone calling the helpdesk
- **MS Teams chat lure** from a compromised adjacent tenant (Midnight Blizzard style)

## Living Off Trusted Sites (LOTS) C2

In 2026, the cheapest way to defeat egress inspection is to **not use your own infrastructure at all**. Route beaconing through SaaS platforms already allowlisted in the target environment.

| Platform | Mechanism | Detection difficulty |
|----------|-----------|----------------------|
| **Telegram Bot API** | HTTPS to `api.telegram.org`, commands via bot messages | H