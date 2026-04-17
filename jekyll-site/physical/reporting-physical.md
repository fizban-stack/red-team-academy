---
layout: training-page
title: "Physical Engagement Reporting — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - reporting
  - documentation
  - deliverables
page_key: "physical-reporting-physical"
render_with_liquid: false
---

# Physical Engagement Reporting

Physical red team reports must translate operational findings into clear, defensible documentation that drives remediation. Unlike network reports, physical findings are supported by photographic and video evidence, and the narrative is inherently chronological and story-driven.

## Report Structure

```
PHYSICAL PENETRATION TEST REPORT
[Client Name] — [Facility Address(es)]
[Assessment Dates]
Prepared by: [Firm Name]
Version: 1.0 — CONFIDENTIAL

CONTENTS
  1. Executive Summary
  2. Scope and Rules of Engagement
  3. Methodology
  4. Attack Narrative — Chronological Timeline
  5. Findings (Indexed)
  6. Risk Ratings and Prioritization Matrix
  7. Recommendations
  8. Lessons Learned
  9. Appendices (Evidence, Tools Used)
```

### Section 1: Executive Summary (1-2 Pages)

The executive summary is read by C-suite who will not read the full report. It must convey what was hired, what was achieved, the business impact in plain language, an overall risk posture, and the top 3 priority remediation actions.

```
Executive Summary Template:

[FIRM] conducted a physical security assessment of [CLIENT]'s [FACILITY]
from [DATE] to [DATE]. The engagement tested [CLIENT]'s ability to detect,
prevent, and respond to unauthorized physical access.

Results: Testers successfully gained unauthorized access to [N] areas 
including [SPECIFIC HIGH-VALUE AREAS]. At no point was access challenged 
or detected by security personnel during active intrusion attempts.

Significant findings:
  * Access credentials (HID Prox badges) were cloned without physical
    contact from employees in the lobby area
  * Server room door bypassed using a $12 tool in under 4 minutes
  * A functioning network implant was installed in Wiring Closet 3B
    and remained undetected for the [X]-day assessment period

Overall Risk Rating: CRITICAL
```

### Section 2: Scope and Rules of Engagement

Document verbatim: in-scope facilities, in-scope areas, out-of-scope areas, authorized techniques, assessment window, notification status, emergency contact, and tester identities.

### Section 3: Methodology

```
List all techniques used, organized by category:

OSINT and Reconnaissance:
  - Passive: Google Maps, LinkedIn employee profiling, job posting analysis,
    public records (building permits), Shodan (exposed cameras)
  - Active: Physical drive-by observation, employee behavior observation,
    guard patrol timing

Credential Attacks:
  - RFID reading: Proxmark3 RDV4, long-range antenna (modified HID reader)
  - Card cloning: T5577 writable cards

Covert Entry:
  - Lock picking: [List lock types picked, tools used]
  - Door bypass: Under-door tool (lever handle bypass)
  - Tailgating: Opportunistic (N occurrences)
  
Payload Deployment:
  - Network implant: LAN Turtle (AutoSSH, Ethernet)
```

## Evidence Standards

### Photography: Requirements and Chain of Custody

Required photographs at each access point follow this sequence:

1. **PRE-ENTRY**: Photograph from outside before any manipulation — shows original state of lock/reader/door, captures camera positions and coverage, time-stamped by camera

2. **MID-ENTRY**: Document the bypass technique in progress if possible — shows tool in use or door in open state

3. **POST-ENTRY**: Photograph access achieved — shows interior of room/area, captures evidence of objective achievement (flag, sensitive document, server rack, workstation), blurred faces or no personnel

4. **OBJECTIVE EVIDENCE**: Photograph the specific finding — screenshot of sensitive data visible (blurred if classified), photograph of unlocked server rack, unattended workstation with session active

```bash
# Photo metadata management
# Strip GPS before including in report
exiftool -gps:all= -overwrite_original evidence/*.jpg

# Verify GPS removed
exiftool -gpslatitude evidence/*.jpg

# Batch face blurring with ImageMagick
for f in evidence/*.jpg; do
  convert "$f" -region 150x150+[X]+[Y] -blur 0x10 "blurred_$f"
done

# File naming convention:
# YYYYMMDD_HHMM_[location]_[description].jpg
# Example: 20260315_0847_NorthEntrance_PreEntry.jpg
```

### Sensitive Content Handling

```bash
# Video face blurring
ffmpeg -i body_cam_footage.mp4 \
  -vf "boxblur=10:1" \
  output_blurred.mp4

# Secure report package encryption
7z a -p -mhe=on report_package.7z report/ evidence/
# Transmit password via separate out-of-band channel (phone call, Signal)

# VeraCrypt container for physical delivery
veracrypt --text --create report_container.vc \
  --size 500M --password [PASSWORD] --encryption AES
```

Never email report or evidence unencrypted. Never upload evidence to cloud storage without encryption. Transmit password via separate channel (phone call, Signal).

## Findings Format

### Finding Template

```
FINDING [ID]: [SHORT TITLE]
Severity: CRITICAL / HIGH / MEDIUM / LOW
Location: [SPECIFIC LOCATION: Building, Floor, Room]
Evidence: [REFERENCE TO EVIDENCE FILES]

Description:
  [1-3 sentences explaining what was found and why it is a vulnerability]

Steps to Reproduce:
  1. [Specific steps taken by tester]

Business Impact:
  [What an actual attacker could achieve through this vulnerability]
  
Recommendation:
  [Specific, actionable remediation steps]
```

### Physical Finding Severity Definitions

| Severity | Definition | Examples |
|----------|-----------|---------|
| CRITICAL | Unauthorized access to highest-sensitivity areas | Data center access, SOC physical access, primary vault |
| HIGH | Unauthorized access to sensitive areas with significant data risk | Server room, wiring closet, HR office, network implant installed |
| MEDIUM | Unauthorized access to general business areas | General office floor, badge cloning capability demonstrated |
| LOW | Reconnaissance or informational findings | Camera positions documented, guard patrol timing mapped |

## Entry Narrative

The narrative is the most-read section after the executive summary. Write in chronological, story format.

```
NARRATIVE TEMPLATE:

Day 1 — [DATE], [DAY OF WEEK]

0830: Operators arrived at [FACILITY ADDRESS]. Physical reconnaissance 
conducted from vehicles parked on [STREET NAME]. Guard patrol interval 
observed at approximately 45 minutes.

0912: Operator A entered main lobby carrying laptop bag. Long-range RFID 
antenna concealed in bag captured 3 HID Prox credentials during 22-minute 
sit at lobby coffee station.
[Evidence: Photo_0912_LobbyEntry.jpg]

1045: Credentials from earlier capture cloned to T5577 card using Proxmark3. 
Card 2 (FC: 123, CN: 4567) tested at employee parking garage reader — 
green LED, access granted.
[Evidence: Photo_1045_GarageAccess.jpg]

1347: Operator B approached North Employee Entrance during peak lunch 
return traffic. Tailgated behind 3 employees without challenge.
[Evidence: BodyCam_1347_NorthEntry.mp4, still at 00:02:14]

1412: Proceeded to 3rd floor server room. Door hardware: Schlage B60N 
deadbolt + HID Prox reader. Reader bypassed using cloned credential 
(FC:123/CN:4567). Deadbolt was not engaged — spring latch only.
[Evidence: Photo_1412_ServerRoom.jpg]

1415: Server room interior accessed. LAN Turtle deployed in switch 
port SW3-GigE1/0/12.
[Evidence: Photo_1415_LanTurtleDeploy.jpg]

1423: Exited server room. Door left in original state. LAN Turtle 
network connection verified via reverse SSH tunnel at 1418.

1445: Exited facility via South stairwell emergency exit. 
No challenges received during 3.5 hours on target.
```

## Risk Ratings and Prioritization Matrix

```
FINDINGS MATRIX:

ID   | Title                        | Severity | Likelihood | Priority
-----|------------------------------|----------|------------|--------
F-01 | 125kHz badge cloneable       | HIGH     | Certain    | P1
F-02 | Server room door no deadbolt | CRITICAL | Certain    | P1
F-03 | Tailgating uncontrolled      | HIGH     | Certain    | P1
F-04 | Network implant installed    | CRITICAL | Certain    | P1
F-05 | Guard patrol gaps >40 min    | MEDIUM   | Certain    | P2
F-06 | Loading dock no card reader  | HIGH     | High       | P1
F-07 | Cameras lack lobby coverage  | MEDIUM   | Certain    | P2
F-08 | Visitor log not reviewed     | LOW      | High       | P3
```

## Recommendations Format

Every finding must have a specific, actionable recommendation with a timeline and rough cost estimate.

```
RECOMMENDATION EXAMPLES:

F-01 (125kHz badge cloneable):
  Short-term: Implement anti-scan badge sleeves or holders for all employee 
  badges. Brief employees on RFID skimming risk.
  
  Long-term: Replace HID Prox (125kHz) readers and cards with HID iClass SE 
  or MIFARE DESFire EV2 (13.56MHz with AES-128 encryption). Prioritize 
  high-risk entry points (main entrance, data center, server rooms).
  
  Timeline: Replace within 12 months. Interim: sleeve protection immediately.
  Estimated cost: $15-25 per reader, $5-8 per card at volume.

F-02 (Server room door no deadbolt):
  Immediate: Enforce deadbolt engagement procedure when server room 
  is unoccupied. Post notice on door.
  
  Hardware: Replace spring latch hardware with deadlatch + deadbolt 
  combination (Schlage B62N or equivalent). Deadlatch prevents shimming; 
  deadbolt requires key for access.
  
  Process: Add server room access log (electronic preferred via ACS audit log).
  Verify last-out procedure engages deadbolt.
  Timeline: Hardware replacement within 30 days.

F-03 (Tailgating):
  Training: Mandatory security awareness training covering tailgating.
  Include video of the actual engagement (with approval) as training material.
  
  Technical: Install optical turnstiles or mantrap at main employee entrance.
  Optical turnstiles detect multiple persons per badge swipe.
  
  Process: Empower employees to challenge tailgaters. Implement "see something 
  say something" culture backed by management.
  Timeline: Training immediate; turnstiles 3-6 month project.
```

## Executive Presentation

```
Presentation structure for C-suite (30-45 minutes):

Slide 1: Title and scope (1 min)
Slide 2: "What we were hired to do" (2 min)
Slide 3: "What we achieved" — use visuals, not text (5 min)
  - Entry photo sequence: lobby → door → server room
  - Implant photo
  - Timeline graphic
Slide 4: Business risk — what could a real attacker have done? (5 min)
  - Data exfiltration from server room hardware
  - Ransomware deployment via network implant
  - Executive impersonation via stolen credentials
Slide 5: Findings matrix (color-coded) (3 min)
Slide 6: Top 5 recommendations with rough cost estimates (10 min)
Slide 7: Remediation roadmap — 30/60/90 day plan (5 min)
Slide 8: Q&A

Audience management principles:
  - Lead with business risk and cost, not technical detail
  - Frame as partnership: "We found this so an adversary won't"
  - Never humiliate named individuals in the presentation
  - Prebrief CISO separately before broader audience sees report
  - Have technical detail available for questions but not on slides
```

## Lessons Learned Section

```
LESSONS LEARNED TEMPLATE:

What went well:
  - RFID credential capture in lobby was highly effective. Long-range 
    antenna captured 23 credentials in under 2 hours without suspicion.
  - Tailgating on Day 2 consistent with recon hypothesis — no employees 
    challenged at the North entrance.

What was harder than expected:
  - Loading dock more controlled than expected — delivery drivers required 
    PO numbers. Loading dock bypassed via tailgate instead.

Security controls that worked effectively:
  - Server room in Building B had proper deadbolt engaged — unable to 
    quickly bypass. Chose alternate path.
  - Visitor logbook at front desk was active — avoided main reception.
    (Note: logbook alone is insufficient without follow-up verification)

Detection opportunities missed by client:
  - ACS audit log showed unusual badge reads (cloned credential at 
    multiple doors) — not reviewed in real time. Real-time ACS anomaly 
    alerting would have detected our activity within 15 minutes.
  - CCTV footage available covering server room door — not reviewed 
    until end of assessment. Behavioral analytics would flag approach.

What we would do differently:
  - Establish secondary exfiltration channel earlier in engagement
  - Attempt loading dock approach during weekend when guard staffing reduced
```

## Post-Engagement Checklist

```
Before finalizing and delivering report:

Evidence:
  [ ] All photos reviewed for sensitive content (faces, screens, proprietary info)
  [ ] GPS stripped from all photo EXIF data
  [ ] Video edited (faces blurred, sensitive audio muted)
  [ ] Evidence inventory complete (all deployed devices accounted for)
  [ ] Evidence stored in encrypted container

Report:
  [ ] All findings have reproducible steps, evidence references, and recommendations
  [ ] Severity ratings reviewed against definitions (consistent application)
  [ ] Executive summary written for non-technical reader (tested on non-technical reviewer)
  [ ] Timeline narrative reviewed for accuracy against field notes
  [ ] Client names and facility addresses correct throughout

Delivery:
  [ ] Report encrypted before transmission
  [ ] Password transmitted via separate channel
  [ ] Delivery receipt confirmed from client
  [ ] Debrief call scheduled before full report dissemination
  [ ] Physical evidence (implants, cloned cards) returned or destroyed per scope

Post-delivery:
  [ ] Engagement notes and field recordings purged from operator devices
  [ ] Working files deleted from assessment infrastructure
  [ ] Client data removed from operator systems within 30 days
  [ ] Lessons learned captured in firm internal knowledge base
```
