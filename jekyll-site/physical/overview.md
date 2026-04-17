---
layout: training-page
title: "Physical Red Team Methodology — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - red-team
  - methodology
  - social-engineering
page_key: "physical-overview"
render_with_liquid: false
---

# Physical Red Team Methodology

Physical red teaming tests an organization's ability to detect, prevent, and respond to real-world intrusion attempts against physical premises. Where network red teams probe digital perimeters, physical operators probe doors, badges, fences, and people.

## What Physical Red Teaming Is

A physical red team engagement attempts to gain unauthorized physical access to facilities, secure areas, or sensitive assets using the same techniques adversaries employ:

- **Lock bypass**: picking, shimming, loiding, and tool-based attacks on mechanical locks
- **Electronic access control attacks**: RFID/NFC badge cloning, reader spoofing, REX sensor manipulation
- **Social engineering**: tailgating, impersonation, pretext calls to security or facilities staff
- **Covert entry**: door gap tools, crash bar bypass, elevator manipulation, loading dock exploitation
- **Physical surveillance**: facility reconnaissance, guard patrol mapping, camera blind-spot identification

Physical intrusions are frequently the fastest path to critical assets — a red teamer who walks into a data center with a cloned badge bypasses every network control in the stack.

## Rules of Engagement

Rules of engagement (ROE) for physical operations are more complex than network engagements due to the real-world legal and safety risks.

### Get-Out-of-Jail (GOJ) Letter

Every operator must carry an authorization letter before any physical operation begins. The GOJ letter:

- Is printed on company letterhead of the authorizing entity
- Contains the engagement dates (not open-ended)
- Names the specific facilities in scope (addresses)
- Names the security firm and operator names/descriptions
- Includes an emergency contact number reachable 24/7 during the engagement
- Is signed by a C-level or VP-level sponsor

```
TEMPLATE — GET-OUT-OF-JAIL LETTER

[Company Letterhead]
Date: [DATE]

To Whom It May Concern:

This letter authorizes [SECURITY FIRM NAME] to conduct a physical security
assessment of [COMPANY NAME] facilities located at:

  - [FACILITY ADDRESS 1]
  - [FACILITY ADDRESS 2]

Assessment window: [START DATE] through [END DATE], 24 hours per day.

Authorized testers:
  - [OPERATOR 1 NAME] — [PHYSICAL DESCRIPTION]
  - [OPERATOR 2 NAME] — [PHYSICAL DESCRIPTION]

If any of the above individuals are detained, please contact:
  [ENGAGEMENT SPONSOR NAME], [TITLE]
  Phone: [24/7 EMERGENCY NUMBER]
  Email: [SPONSOR EMAIL]

This assessment is fully authorized and being conducted with the knowledge
and consent of [COMPANY NAME] executive leadership.

Signed: _______________________
[SPONSOR NAME, TITLE]
```

### Scope Definition

Scope must specify:

| Scope Item | Example |
|-----------|---------|
| In-scope facilities | 123 Main St (HQ), 456 Oak Ave (Data Center) |
| In-scope areas | All common areas, server rooms, executive floor |
| Out-of-scope areas | Executive residences, off-site employee homes |
| In-scope techniques | Lock picking, badge cloning, tailgating, impersonation |
| Out-of-scope techniques | Physical violence, damage to property, alarm triggering |
| Time windows | Business hours only / 24x7 / nights only |
| Notification | Black-box (security unaware) or gray-box (select staff aware) |

### Safe Words

Safe words provide an immediate abort mechanism when an operator is challenged or detained.

```
Primary safe word:   "AUDIT COMPLETE"
Secondary safe word: "RED TEAM ABORT"

Procedure:
1. Operator states safe word clearly to challenging party
2. Operator immediately produces GOJ letter
3. Operator contacts engagement sponsor at emergency number
4. All activity ceases in that area pending resolution
```

## Engagement Phases

### Phase 1: Target OSINT

Before stepping foot near the facility, conduct comprehensive open-source intelligence:

- Google Maps / Street View: building entrances, parking patterns, camera locations
- LinkedIn: employee count, titles, security vendor names from job postings
- Building permits (county records): may reveal floor plans
- Shodan: internet-exposed cameras, access control panels, BAS systems
- Job postings: security guard company name reveals access control vendor
- Social media: employee badge photos, facility photos, naming conventions

### Phase 2: Facility Reconnaissance

Physical drive-by and on-site observation before the active operation:

- Employee smoking areas (identify badge holders, door prop habits)
- Loading dock schedules (delivery windows, security gaps)
- Guard patrol routes and timing (timing laps gives entry windows)
- Visitor parking vs. employee parking (different badge/process)
- Camera coverage angles and blind spots
- Door hardware identification (lock brand, reader type, door gap size)

### Phase 3: Social Engineering Pretext Development

Build the persona and cover story before execution:

- IT support / vendor (works for HID badge reader service calls)
- Building maintenance / HVAC technician
- Fire safety inspector
- Coffee/catering delivery
- New employee (works with tailgating)

Pretext must include: backstory, plausible reason to be in target area, appropriate props (clipboard, ID badge, tool bag), and a rehearsed response to challenge questions.

### Phase 4: Covert Entry

Execute access attempts using selected techniques:

- **Physical**: lock picking, shimming, loiding, under-door tool
- **Electronic**: cloned badge presented to reader
- **Social**: tailgate behind legitimate employee, hold door social engineering
- **Combined**: badging in with clone + tailgate the inner door

### Phase 5: Objective Achievement

Once inside, achieve defined objectives:

- Photograph physical evidence of access (server room, workstation, sensitive documents)
- Capture flag items left by client (USB, printed document)
- Install physical payload (LAN Turtle, hardware keylogger, rogue AP)
- Access secure areas (data center, wiring closet, executive floor)

### Phase 6: Exfiltration

Extract any collected evidence or placed devices as defined by scope. Document:

- Exact path taken from entry to objective
- Time elapsed
- Controls encountered and bypassed
- Artifacts left (if any covert implants placed per scope)

### Phase 7: Egress

Exit the facility without triggering response. Clean exit requires:

- No alarm states triggered
- No confrontation with security
- All tools retrieved
- Photographic evidence secured on encrypted device

## Key Deliverables

### Physical Entry Report Format

```
1. Executive Summary (1 page)
   - Engagement overview and critical findings
   - Overall risk rating

2. Scope and Rules of Engagement
   - Facilities tested, dates, techniques authorized

3. Methodology
   - Tools used, techniques employed

4. Findings
   - Per finding: Title, Location, Severity, Evidence, Recommendation

5. Narrative Timeline
   - Chronological account with timestamps

6. Evidence Appendix
   - Photographs, video stills, badge clone data

7. Recommendations
   - Prioritized remediation list
```

### Evidence Considerations

- Photograph door hardware, readers, and locks from outside scope boundary before any manipulation
- Capture timestamped entry photos at each access point
- Never photograph individuals (or blur faces in post-processing before report)
- Store all evidence encrypted at rest (VeraCrypt container on operator device)
- Video evidence: edit out faces, ensure no sensitive data visible in frame
- GPS metadata: strip from all photos before including in report

## Legal Considerations

Physical red teaming carries real legal risk. Key points:

| Risk | Mitigation |
|------|-----------|
| Trespass | GOJ letter, stay within scoped areas |
| Theft | Never remove company property |
| Computer fraud | Only access systems explicitly in scope |
| Wiretap/recording laws | Know one-party vs two-party consent in jurisdiction |
| Impersonation of law enforcement | Never impersonate police, fire marshals with authority |
| Weapons charges | Know local laws on lock picks as "burglary tools" |

**Lock picks are illegal to carry in some jurisdictions without proof of professional use.** Always verify local law before traveling with lock picks. Several US states (Virginia, Ohio, Nevada) have specific statutes.

## Tools Overview

| Category | Tool | Use Case |
|----------|------|----------|
| Lock picking | Peterson picks, Sparrows picks | Pin tumbler SPP and raking |
| Lock picking | Covert Companion | High-quality slim-line picks |
| RFID | Proxmark3 RDV4 | 125kHz/13.56MHz read/write/emulate |
| RFID | Flipper Zero | Quick field reads, emulation |
| Entry tools | Under-door tool (UDT) | Lever handle bypass |
| Entry tools | Loid (credit card shim) | Spring latch bypass |
| Payloads | O.MG Cable | HID + WiFi C2 payload delivery |
| Payloads | LAN Turtle | Inline network implant |
| Payloads | WiFi Pineapple | Rogue AP, credential capture |
| Surveillance | FLIR thermal | Camera detection, guard location |
| Documentation | Action camera | Body-worn evidence capture |
| Comms | Encrypted radio or Signal | Operator team communication |

## Metrics for Physical Engagements

Track these metrics for reporting:

- Time from facility arrival to first access attempt
- Number of access attempts before success
- Number of floors / areas accessed
- Number of security challenges encountered
- Number of employees who held doors without challenging
- Time from initial access to objective achievement
- Time on target without detection

## Recommended Training Resources

- [TOOOL](https://toool.us/) — The Open Organisation Of Lockpickers
- Bosnian Bill and LockPickingLawyer (YouTube) — technique demonstration
- DEF CON Physical Security Village — annual hands-on workshops
- Gryman / Deviant Ollam — conference talks on physical penetration testing
- "The Art of Intrusion" — Kevin Mitnick (background reading)
- "No Tech Hacking" — Johnny Long (social engineering and physical)
