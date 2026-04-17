---
layout: training-page
title: "Physical OPSEC & Surveillance Detection — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - opsec
  - surveillance-detection
  - counter-surveillance
page_key: "physical-physical-opsec"
render_with_liquid: false
---

# Physical OPSEC & Surveillance Detection

Physical OPSEC governs how operators protect themselves, their tools, and their mission during facility reconnaissance and active intrusion attempts. A technically skilled operator who is burned by poor OPSEC delivers nothing but a compromised engagement.

## Baseline Establishment

Before any active operation, operators must understand what "normal" looks like at the target.

### Behavior Patterns to Document

```
During recon phase (days before active operation), observe and record:

Timing patterns:
  - When do employees arrive? (±30 min window around peak)
  - When does foot traffic drop off in lobby? (secondary entry timing)
  - Guard shift changes (look for two guards interacting, radio handoffs)
  - Delivery windows (loading dock activity times)
  - Lunch rush (predictable high-traffic window for tailgating)

Physical patterns:
  - What do employees wear? (casual vs. business dress, badge lanyard style)
  - Do employees badge in individually or tailgate?
  - Are there frequent visitors? How are they processed?
  - What do vendors/contractors look like? (hi-vis vests, tool bags)
  - What vehicles are in the parking lot? (employee vs. visitor parking)

Security patterns:
  - Guard patrol route and interval
  - Roving vs. stationary security
  - Camera coverage: fixed PTZ, wide-angle dome locations
  - Do guards actively challenge everyone or wave people through?
  - Is there a visitor logbook? Photo ID check? Escort requirement?
```

### Baseline Documentation Method

```
Field notes format (encrypted note app or voice memo):
  [TIME] [LOCATION] [OBSERVATION]
  
  08:12 North entrance: 3 employees entered without badge — held door
  08:45 Loading dock: HVAC contractor van, no badge required, walked to elevator
  09:00 Guard shift: 2 guards at desk, handoff took ~5 min, neither patrolled during
  12:10 Lobby: food delivery (green vest, no badge), escorted to elevator by receptionist
```

Minimum baseline observation: **2-3 separate days** at target. Pattern identification requires repetition.

## Surveillance Detection Routes (SDR)

An SDR is a deliberate route taken to identify whether you are being followed or observed before or during an operation.

### SDR Principles

```
Core principle: A surveillant must follow you. Your route must force them
to expose themselves or abandon coverage.

Route design requirements:
  - Include natural checkpoints (corners, building reflections, shop windows)
  - Vary pace (force follower to adjust)
  - Include direction reversals (turn 180° — anyone following must react)
  - Include choke points (single entry/exit — if they went in, they follow you out)
  - Minimum: 20-30 minutes of deliberate route

Detection indicators:
  - Same individual seen twice at different points of route
  - Vehicle seen twice (especially if it parked and then is moving again)
  - Individual who "window shops" but never enters stores
  - Sudden phone call when you stop
  - Over-interest in direction you came from
```

### Vehicle-Based SDR

```
Vehicle SDR adds speed and range:

1. Drive normal routes initially
2. Make unexpected U-turns (legal ones) and observe reaction vehicles
3. Pull over for 60 seconds — any stop-and-wait behind you?
4. Enter parking garage with single entrance/exit — if followed in, they must follow out
5. Speed variation: 5 mph below limit, then accelerate to normal — erratic vehicles react

Team SDR (2+ operators):
  - Operator A drives, Operator B follows in separate vehicle
  - Operator B observes vehicles behind Operator A from behind
  - If surveillance detected: team activates abort protocol
```

## Counter-Surveillance

Once surveillance is detected or suspected:

```
Response options:
  1. Abort: Do not proceed. Call engagement manager. Debrief.
  2. Dry cleaning: Continue on planned route and "clean" surveillance
     through natural route variations without revealing awareness
  3. Static: Enter a location (coffee shop, store) and wait
     — surveillant must either expose themselves or abandon

Never confront suspected surveillance.
Never let surveillance know you detected them.
Documentation: if surveillance detected, note descriptions, vehicles,
license plates if visible, and report to engagement manager
```

## Disguise Principles

Physical red teamers operate in a visual environment. Appearance must match the operational context.

### Dress for the Environment

| Environment | Appropriate Appearance |
|-------------|----------------------|
| Corporate HQ (business district) | Business casual, laptop bag, ID badge on lanyard |
| Industrial/warehouse | Hi-vis vest, work boots, hardhat clip on bag |
| Hospital/healthcare | Scrubs, ID badge, clipboard |
| University campus | Casual (jeans/backpack), student-adjacent appearance |
| Data center/ISP | IT vendor polo, laptop bag, Pelican case for "equipment" |
| Construction area near target | Safety vest, hard hat, steel-toed boots |

### The Art of Blending

```
Rules for appearance:
  1. Nothing stands out. No logos of wrong company, no brand mismatches.
  2. Accessories must match context (IT vendor = Dell/HP branded bag, not personal)
  3. Props must be functional-looking (real clipboard, real tool bag with real tools)
  4. ID badge: even a blank badge on a lanyard with company logo increases acceptance
  5. Confidence > costume. Hesitation breaks cover. Move with purpose.
  
Pre-operation preparation:
  - Purchase or borrow appropriate props before engagement
  - Verify clothing won't betray operator (wrong company badge, obvious gear)
  - Test: "Would I question someone who looks like this walking in?"
```

### Movement Patterns

- Walk at normal pace — hurrying draws attention
- Avoid looking at cameras (triggers cognitive recognition in observers)
- Keep eyes at "horizon level" — not looking at ground (nervous) or ceiling (tourist)
- If challenged: stop immediately, engage pleasantly, produce pretext materials
- Avoid checking phone while walking through entry points (distraction = suspicious)

## Photography for Reconnaissance

### Telephoto / Standoff Photography

```
Equipment options:
  - DSLR with 200-400mm telephoto lens (from parked vehicle, 200+ meters away)
  - Spotting scope with smartphone adapter
  - Superzoom compact camera (looks tourist-like)
  - Dash camera (continuous recording while parked)

Operational:
  - Photograph from inside vehicle with windows down (reduces reflections)
  - Use autofocus on specific targets (badge readers, lock hardware, camera positions)
  - Capture multiple angles of entry doors (identify latch vs deadbolt, door gap)
  - Document guard positions, patrol paths, camera angles
```

### Avoiding Detection During Photography

```
  - Do not point camera directly at security personnel
  - Use window/reflection shots when possible
  - Photograph "tourist attractions" that happen to include target in background
  - Vary shooting positions — do not spend >10 minutes at one location
  - GPS: consider disabling or spoofing on camera (phone cameras embed GPS)
  - Clothing: avoid camera straps, large lens caps — go compact
```

### Counter-Surveillance Photography

Document any potential surveillance of your team:

```bash
# Post-process: extract EXIF from captured images to verify no GPS data
exiftool -gpslatitude -gpslongitude recon_photos/*.jpg
# Remove GPS before storing in report
exiftool -gps:all= -overwrite_original recon_photos/*.jpg
```

## Social Behavior During Operations

### Confidence Projection

```
The OODA loop of a security guard challenged by someone unfamiliar:
  Observe → Orient → Decide → Act

Your goal: disrupt their Orient phase. When you project certainty and
deliver a plausible pretext immediately, their brain orients toward
"legitimate" before they decide to question further.

Rules:
  - Answer challenges immediately. Pause = suspicious.
  - First words set the frame. "Hey, I'm from [vendor] here for [thing]."
  - Use insider language specific to the facility (obtained from recon)
  - Carry the right name (receptionist name from LinkedIn, supervisor name
    from org chart — drop casually in conversation)
```

### Handling Challenges from Security

```
Challenge scenario scripts:

GUARD: "Can I help you?"
RESPONSE: "Yeah, I'm with [HVAC company] — I have a service call for the
  AHU-3 unit on floor 4. I've got paperwork here [produce clipboard]."
  [Do not wait for guard to process — begin moving toward elevator with
  appropriate purpose]

GUARD: "Do you have an appointment?"
RESPONSE: "I was called by your facilities manager, [NAME from LinkedIn].
  He may have put it in the service log — I can call him if there's
  any confusion. Let me grab my phone."
  [Produce phone, begin "calling" — guard often waves you through]

GUARD: "I need to see ID."
RESPONSE: [Produce ID without hesitation. May be real ID or pretext ID.]
  "Happy to. [Name] from [Company] — should be in the system."
```

## OPSEC for Tools

### Concealing Tools in Transit

```
Lock picks:
  - Thin wallet pick sets (Bogota rake + tension) → inside notebook/organizer
  - Peterson sets in original leather pouch → inside tool bag
  - Avoid loose picks that rattle in pockets or bags
  - Metal detector note: picks are thin stainless, may not trigger
  
Proxmark3:
  - Concealed inside padded laptop bag pouch
  - Proxmark3 Nano fits in small pocket — standard antenna
  - Antenna concealed under jacket or in bag lining for unattended capture

Flipper Zero:
  - Fits in pants pocket — looks like small game device
  - Screen off during transit
  - Belt pouch available (looks like pager/radio to casual observer)

USB payload devices:
  - O.MG Cable looks identical to legitimate USB cable — carry as "charging cable"
  - Rubber Ducky: looks like standard USB drive — label with generic name "BACKUP"
  - LAN Turtle: slightly larger — keep in tool bag with other networking gear
```

### Tools on Person During Facility Entry

```
Minimize: Carry only what is needed for the specific objective.
Tiered approach:
  Tier 1 (always on person): GOJ letter, ID, one tension bar + hook pick
  Tier 2 (in bag): Flipper Zero, cloned badge card, small camera
  Tier 3 (in vehicle): Full Proxmark3, pick set, bypass tools, payload hardware
```

## Documentation While Covert

### Audio Recording

```
Jurisdictions:
  - One-party consent (most US states): only one party to conversation must consent
  - Two-party (all-party) consent: California, Illinois, Florida, Maryland, others
  
  In two-party states: recording without consent may be illegal even for red team.
  Consult legal counsel and include recording restrictions in ROE.

Hardware:
  - Small digital recorder (Sony ICD-PX370) clipped inside breast pocket
  - Smartphone voice memo with screen locked — less visible than active recording UI
  - Smartwatch audio recording capabilities
```

### Body Camera Concealment

```
Purpose: Document entry, interaction, evidence of access achieved

Options:
  - Button camera: replaces actual shirt/jacket button, micro-SD card
  - Glasses cam: lightweight, looks like normal eyewear
  - Tie/lapel cam: integrated into necktie or lapel pin
  - Hat brim cam: forward-facing, natural head movement = natural footage
  
File management:
  - Record to encrypted SD card
  - Transfer to VeraCrypt container at EOD
  - Immediately delete off camera storage after transfer
```

### Log Taking in Field

```
Digital: Encrypted notes app (Standard Notes, Obsidian with encryption)
  - Time-stamped entries
  - One entry per significant event
  - No company-identifiable information in entry titles

Analog: Small Rite in the Rain notebook (waterproof)
  - Abbreviated personal shorthand
  - Destroy after digital transcription
  - Never include client name on cover
```

## Emergency Protocols

### Challenge Script (If Detained)

```
Priority order if confronted and unable to talk your way out:

1. State safe word clearly: "AUDIT COMPLETE" / "RED TEAM ABORT"
2. Produce GOJ letter immediately and physically hand it to challenger
3. Do not resist — comply fully with any reasonable request
4. Request to contact engagement sponsor immediately:
   "Please call [SPONSOR NAME] at [EMERGENCY NUMBER] right now —
   they can verify everything."
5. Do NOT identify as "hacker" or use security jargon
6. Do NOT describe tools being carried unless directly asked by police
7. Remain calm — elevated situation = more risk, not less
```

### Abort Triggers

```
Pre-defined abort conditions (brief engagement manager if triggered):
  - Physical altercation initiated by target staff
  - Security personnel radio call or obvious alarm response
  - Camera operator actively tracking movement
  - Engagement sponsor contact fails on emergency number
  - Operator receives verbal detention attempt ("Sir, stop right there")
  - Police involvement (regardless of resolution)

After abort: Do not attempt re-entry same day. Debrief before any
subsequent attempt. Evaluate whether engagement continues.
```

## Post-Operation OPSEC

```
Immediate post-op checklist:
  □ All tools retrieved from target area and accounted for
  □ No physical items left at target (USB drops are intentional, note them)
  □ Memory card evidence transferred to encrypted container
  □ Camera storage wiped
  □ GOJ letter re-secured
  □ Notes transcribed to encrypted digital format
  □ Physical notes destroyed (shredder or burn)

Camera awareness — locations to check:
  □ Parking lot entry/exit (captured vehicle/license plate)
  □ Lobby cameras (facial capture at entry)
  □ Elevator cameras (floor selection visible)
  □ Stairwell cameras (often overlooked, frequently present)
  □ External street cameras (municipality, business exterior)
  
Report to engagement manager within 2 hours of operation conclusion.
```
