---
layout: training-page
title: "Covert Entry Techniques — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - covert-entry
  - door-bypass
  - electric-strike
page_key: "physical-covert-entry"
render_with_liquid: false
---

# Covert Entry Techniques

Covert entry encompasses all techniques used to pass through doors, gates, and access points without authorization, without leaving damage, and ideally without triggering any alarm state. Mastery of these techniques allows operators to bypass physical controls that mechanical lock picking alone cannot defeat.

## Door Anatomy: What Determines Attack Surface

Before selecting a technique, identify the door's configuration:

```
Door assessment checklist:
  □ Swing direction: inward or outward?
  □ Latch type: spring latch, deadlatch, deadbolt, or mortise?
  □ Handle type: lever, knob, push/pull, crash bar?
  □ Frame gap: how much clearance between door and frame?
  □ Hinge side: which side are the hinges on?
  □ Bottom gap: clearance between door bottom and floor?
  □ Electronic access: reader side, REX sensor, electric strike?
  □ Door closer: automatic close mechanism present?
  □ Alarms: door contact sensors? Monitoring?

Door hardware terminology:
  Latch bolt:     Spring-loaded bolt (angled face) — retracted by handle
  Deadlatch:      Auxiliary pin next to latch bolt — prevents shimming when engaged
  Deadbolt:       Requires key/thumb-turn to retract — NOT spring-loaded
  Strike plate:   Metal plate in frame accepting latch/bolt
  Electric strike: Strike plate that can release electrically to allow exit
  Door closer:    Pneumatic or spring arm that closes door automatically
  REX sensor:     Request-to-Exit — PIR or microwave sensor on secure side
```

## Latch Manipulation: Shimming and Loiding

### Spring Latch Bypass

Applicable when: door has spring latch (no deadlatch auxiliary), no deadbolt engaged, door has gap at latch side.

```
Tools:
  - Commercial loid card (Sparrows Shove-It, under-door loid strip)
  - Credit card, hotel key card (thicker = less effective)
  - Thin metal shim (purpose-cut from aluminum)

Procedure:
1. Locate latch bolt — opposite hinge side, typically at handle height
2. Check for deadlatch: if present (small rectangular pin next to latch), shimming
   is defeated — deadlatch must be depressed first or use another technique
3. Insert shim/card in door gap at latch height
4. Angle shim to contact angled face of latch bolt
5. Apply pressure toward latch while using shim to push bolt back into door
6. Simultaneously apply light pulling pressure on door
7. When bolt fully retracts, door opens

Defeating deadlatches:
  - Deadlatch is the small rectangular follower pin next to the main latch bolt
  - When door is fully closed, deadlatch contacts strike → disables shimming
  - Attack: Sparrows "Deadlatch Bypass Strip" — thin enough to depress deadlatch
    tab at the strike before inserting main shim
  - Or: loosen door frame enough that deadlatch does not engage (frame gap attack)
```

### Loiding an Outward-Opening Door

```
Outward-opening doors are MORE susceptible because:
  - Door gap is accessible from outside on latch side
  - No need to push card through frame gap

Procedure (outward-opening):
1. Insert shim between door and frame at latch height
2. Angle shim away from door edge and toward latch bolt face
3. The inclined face of the latch bolt deflects shim inward
4. Pull door slightly outward while working shim
5. Bolt retracts → door opens

Tools specifically designed for outward doors:
  - Sparrows Shove-It (rigid, L-shaped end)
  - "Loid strips" — long flexible strips that wrap around door edge
```

## Door Gap Attacks

### Frame Gap Manipulation

```
When door frame has visible gap (often on older doors, settling buildings):

1. Insert thin pry tool (door crack wedge) to slightly widen gap
2. Use gap to access latch bolt, deadlatch follower, or electric strike
3. Frame gap attack + loiding = combination technique

Warning: Excessive prying leaves visible damage — NOT covert
Use only light pressure — assess whether gap is naturally accessible
```

## Under-Door Tool (UDT)

The under-door tool is one of the highest-value physical entry tools for lever-handle doors.

### Standard UDT Operation

```
Target: Outward-opening door with lever handles

Minimum floor gap required: ~1 cm (3/8 inch)
Minimum clearance under door sweep: tool must fit through

UDT components:
  - Flat carrier arm: slides under door horizontally
  - Vertical lifter: raises hook on far side of door
  - Rotation hook: loops around lever handle
  - Trigger line: operates from near side of door

Step-by-step:
1. Assess gap: slide a credit card under door to confirm clearance
2. Slide carrier flat under door at lever handle position
3. Thread trigger line back to your side before advancing carrier
4. Use lifter to raise hook arm on far side to lever height
5. Adjust depth: hook should be directly below or at lever level
6. Pull trigger line → hook rotates → lever is depressed
7. Push/pull door open (maintain trigger line tension)
8. Remove tool after passing through

Complications:
  - Door sweeps: compress rubber sweep with wedge, then insert carrier
  - Inward-opening doors: hook must push UP on lever from below (different angle)
  - High-mounted handles: requires extended carrier length
  - Crash bars: UDT can engage bar if bar height is within reach
```

### Field-Fabricated UDT

```
Materials:
  - Wire coat hanger × 2 (or 12 gauge steel wire)
  - Rubber tubing for grip on hook
  - Duct tape for joint reinforcement

Construction:
1. Straighten one hanger → carrier arm (~60cm / 24 inches)
2. Bend hook end at 90 degrees → rotation hook
3. Wrap hook tip with rubber tubing (prevents slippage on lever)
4. Second hanger → lifter mechanism
5. Fishing line or thin cord for trigger

Not as effective as commercial tool but functional in field emergency
```

## Electric Strike Bypass

### Overview of Electric Strikes

```
Electric strike types:
  - Fail-secure (fail-locked): power loss = door stays locked
  - Fail-safe (fail-open): power loss = door unlocks

Attack relevance:
  - Fail-safe: power disruption at door unlocks it (wall transformer attack)
  - Fail-secure: power disruption locks it — attack on reader or REX side instead

Common models:
  - HES 5000 series: common in commercial doors, fail-secure default
  - Adams Rite: aluminum storefront doors, cam-bolt design
  - Folger Adam: older institutional buildings
```

### Blocking the Latch

```
Technique: Prevent latch bolt from fully engaging strike plate → door appears
closed but can be pulled open without credential

When to use: When you have brief unmonitored access to a door you want
to be able to re-enter later

Method 1 (business card):
1. Fold business card or card stock to ~3mm thickness
2. Insert between latch bolt and strike plate before door fully closes
3. Door closes, latch bolt rests on card — does not engage fully
4. Card hidden in strike plate recess — not visible from outside
5. Return later, pull door — opens without badge

Method 2 (tape):
1. Apply thin tape over latch bolt face before door closes
2. Tape prevents latch from latching into strike
3. Less reliable than card method — tape may compress

Method 3 (commercial covert latch block):
1. Pre-formed plastic or rubber insert designed for this purpose
2. Fits various strike plate depths, color-matched to frame
```

### REX Sensor Spoofing

Request-to-Exit sensors allow secure-side egress without credential. Triggering them from the unsecured side unlocks the door.

```
PIR (Passive Infrared) REX sensors:
  Detection principle: heat differential movement
  Typical location: above door frame or on adjacent wall, aimed inward

Method 1: PIR activation through gap
1. Insert thin rod or wire hanger through door gap (horizontal crack, bottom gap)
2. Move rod slowly near sensor plane (6-12 inches from sensor face)
3. Thermal "movement" triggers PIR → REX fires → electric strike releases
4. Works better with hand vs. metal rod (thermal signature)

Method 2: Balloon inflation
1. Partially inflate small latex balloon
2. Compress and insert through gap at bottom of door
3. Inflate fully with hand pump or mouth (via thin tube)
4. Balloon expands into PIR detection zone → triggers REX
5. REX releases door → deflate and remove balloon + tool

Method 3: Commercial Hooligan Tool (Covert Instruments)
1. Telescoping arm with PIR-friendly tip (warm material)
2. Designed to pass through door gaps and reach PIR sensors
3. Much more reliable than improvised methods

Microwave/doppler REX sensors:
  Detection principle: frequency shift from moving objects
  Less susceptible to thermal tricks — motion-based
  Attack: any movement through gap, including the door latch manipulation itself
  May self-trigger during aggressive latch bypass operations
```

## Crash Bar / Panic Hardware Bypass

### Dogknob Tool

```
Target: Emergency exit bars (crash bars / panic hardware)
Condition: No alarm monitoring on door, or alarm known to be disabled

Tool: Dogknob or crash bar bypass tool
  - Thin metal hook on long flexible wire
  - Designed to pass through door gap and hook over crash bar

Procedure:
1. Insert wire through gap at latch side of door (vertical gap or bottom gap)
2. Wire curves around door edge
3. Hook engages crash bar paddle on far side
4. Pull wire → crash bar depresses → door opens

Note: Many exit-only doors trigger building alarm when opened — assess
before attempting. Check: any wired contacts at door frame? Any
magnetic contact sensors at top of door?
```

## Elevator Bypass

### Firefighter Service Key

```
FEO-K1 (Fire Emergency Operation Key 1):
  - Standard key used by fire departments for elevator control panels
  - Provides: fire service mode, independent service, pit access
  - Standardized across most North American elevator installations
  - Obtainable: locksmiths, eBay, elevator supply companies (varies by jurisdiction)

Key uses:
  - Recall elevator to ground floor (fire service mode)
  - Hold elevator doors open on specific floor (independent service)
  - Access elevator machine room panel
  - Bypass floor call restrictions (some elevators block certain floors)

Physical appearance:
  - Oval or triangular bow, flat key, common keyways
  - Common keyways: FEO-K1 (most common), FEO-K2, FEO-K3
  - Purchase appropriate keyway for target building type

Operation in independent service mode:
1. Insert FEO-K1 in elevator panel at ground floor → turn to phase 1
2. Elevator returns to ground, doors open, remain open
3. Board elevator → switch panel inside to phase 2 (car switch)
4. Now in independent service: doors stay open until closed manually
5. Choose any floor including "restricted" floors
```

## Tailgating vs. Piggybacking

These are social-based entry techniques, but physical in execution.

### True Tailgating (Unauthorized)

```
Definition: Following an authorized person through an access-controlled door
without their knowledge or permission

Timing:
  - Enter at 0.5 - 1.0 second after the authorized person's badge grants access
  - Door magnetic hold + door closer gives 3-5 second window
  - Move at normal walking pace — running triggers attention

Position:
  - Approach from 10-15 feet behind, closing gap as they badge in
  - Time your pace so you arrive at door just as it begins to close
  - Arms full (coffee + bag) = natural reason to not badge yourself

Anti-tailgate systems:
  - Mantraps: two-door airlock, only one door open at a time
  - Optical sensors: count people through door (turnstile variation without physical bar)
  - Security cameras with tailgate detection (AI-assisted analysis)
  - Culture: employees trained to challenge tailgaters
```

### Social Tailgating (Consensual)

```
Definition: Employee holds door open for you, believing you are authorized

Scripts:
  "Hey, thanks — I always forget my badge on Mondays."
  "Could you hold that? My hands are completely full."
  [arrive at door with coffee tray, boxes, props]

Psychological principle:
  - Holding the door is deeply ingrained social norm
  - Refusing = confrontational; most employees default to help
  - Uniform/prop increases probability significantly
  - Timing: arrive at door at same time as legitimate employee heading in
```

## Loading Dock and Service Entrance

```
Loading docks represent the highest-risk entry point for many facilities:
  - Delivery vehicles expect to come and go with minimal screening
  - Guards typically focused on vehicles, not pedestrians
  - Often lacks full electronic access control (key locks, padlocks)
  - Connected to freight elevators with broader floor access

Approach:
  - Time arrival during delivery window (UPS/FedEx 10am-2pm typical)
  - Carry delivery prop (small box, tablet with clipboard)
  - Dock guards accustomed to unfamiliar vendors
  - Do not use main lobby — loading dock guard has no visitor log context

Camera blind spots:
  - Cameras are expensive — docks frequently have coverage gaps
  - Camera positions: note during recon which angles exist
  - Dead zone between dock platform and building entry door is common
```

## Window and Door Sensor Bypass

```
Door contact sensors (magnetic reed switches):
  - Consist of two components: magnet (on door) + switch (on frame)
  - When door opens, magnet moves away → switch opens → alarm triggers

Bypass technique (magnet spoofing):
1. Identify sensor location (typically top corner of door frame, small rectangular housing)
2. Obtain neodymium magnet of sufficient strength (N52 grade, 1 inch diameter)
3. Hold external magnet near sensor switch position on frame side
4. External magnet keeps switch "closed" even when door magnet moves away
5. Open door → sensor reads as closed → no alarm

Limitations:
  - Requires knowledge of exact sensor position
  - Sensor may be surface-mounted (easy to locate) or flush/concealed
  - Monitoring system may detect abnormal patterns (door ajar without motion)
  - Only works on basic magnetic contact sensors — not on vibration, PIR-combined sensors

Equipment: N52 neodymium magnets (Amazon, hardware store)
           Magnetic field detector to locate concealed sensors
```

## Physical Attack on Electronic Access Control Keypads

```
Code observation (shoulder surfing):
  - Position at angle to target keypad before occupant punches code
  - Best position: 45 degrees and slightly elevated
  - Camera concealed in glasses/hat captures keystrokes
  - Thermal camera: pressed keys retain heat signature for 45-90 seconds after entry

Thermal camera approach:
  Equipment: FLIR ONE (smartphone attachment) ~$200-400
  Procedure:
    1. Wait for person to enter PIN and pass through door
    2. Approach keypad within 30 seconds of entry
    3. Point FLIR at keypad — recently pressed keys show as warm (orange/yellow)
    4. Note which keys are warm — may not reveal order, but reduces combinations
    5. If 4 keys pressed: 4! = 24 combinations to try

Code guessing:
  Most common 4-digit PINs: 1234, 0000, 1111, 1212, 7777, 1004, 2000, 4444, 2222, 6969
  Facility-specific patterns: year of construction, zip code, founding year
  Try 3 attempts, then pause (many keypads lockout after 5-10 attempts)
  
Keypad replacement attack (advanced):
  - Purchase identical keypad model
  - Install modified keypad that captures PINs and transmits
  - Extremely high-risk and leaves evidence — rarely appropriate for authorized testing
```
