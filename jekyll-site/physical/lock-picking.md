---
layout: training-page
title: "Lock Picking & Bypass Techniques — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - lock-picking
  - bypass
  - entry
page_key: "physical-lock-picking"
render_with_liquid: false
---

# Lock Picking & Bypass Techniques

Lock picking and bypass represent the core mechanical skill set for physical red team operators. Understanding lock anatomy and failure modes allows operators to select the fastest, most covert entry technique for a given target.

## Lock Anatomy

### Pin Tumbler Locks

The most common lock type globally. Found on most residential and commercial door cylinders.

```
Key Pin Stack (viewed from plug cross-section):

  ┌─────────────────┐  ← Housing (shell)
  │  [Driver Pin 5] │
  │  [Driver Pin 4] │  ← Spring-loaded driver pins
  │  [Driver Pin 3] │     (want to fall into plug)
  │  [Driver Pin 2] │
  │  [Driver Pin 1] │
  ├-----------------┤  ← Shear line (where plug meets housing)
  │  [Key Pin 5]    │
  │  [Key Pin 4]    │  ← Key pins (variable height)
  │  [Key Pin 3]    │     Correct key lifts each key pin
  │  [Key Pin 2]    │     to EXACTLY the shear line
  │  [Key Pin 1]    │
  └─────────────────┘  ← Plug (rotates when all pins set)
```

**Picking principle**: Apply rotational tension to the plug (torque wrench/tension bar). Due to manufacturing tolerances, one pin will bind. Pick that pin to the shear line — it will set (click, slight plug rotation). Move to the next binding pin. Repeat until all pins are set and plug rotates.

### Wafer Locks

Simpler than pin tumbler. Common in filing cabinets, desk drawers, older automotive.

- Single flat wafer per position (no driver/key pin separation)
- Wafer must be lifted to exact height to clear the sidebar or shear line
- Easier to pick than quality pin tumbler locks
- Raking is highly effective

### Disc Detainer Locks

Found on higher-security applications (Abloy, some bike locks, vending machines).

- Rotating discs replace pins
- Each disc has a notch that must align to allow the sidebar to drop
- Requires specialized disc detainer pick (Multipick ELITE or similar)
- Cannot be raked — must use rotary pick tool

### High-Security Cylinders

High-security locks include additional anti-pick features:

| Lock | Features | Difficulty |
|------|----------|------------|
| Medeco | Angled key cuts + rotating pins + sidebar | Very High |
| Abloy Protec | Rotating discs, no springs | Extremely High |
| Mul-T-Lock Interactive | Telescoping pins, sidebar | Very High |
| Schlage Primus | Sidebar with secondary bitting | High |
| ASSA Abloy Cliq | Electronic + mechanical hybrid | Varies |

## Single Pin Picking (SPP)

SPP is the most controlled, quietest picking technique. Preferred for operations requiring no visible damage and minimal noise.

### Tools Required

- **Tension bar (torque wrench)**: Light tension on plug. Choose: top of keyway (TOK) or bottom of keyway (BOK) depending on keyway profile
- **Hook pick**: Short hook (most common), medium hook (deeper front pins), offset hook (restricted keyways)
- **Short hook**: Works on most 4-5 pin cylinders
- **City rake**: For initial mapping of pin stack heights (optional)

### SPP Procedure

```
1. Insert tension bar. Apply LIGHT tension (less than you think you need).
   Too much tension = all pins bind = nothing moves.
   Too little = no binding order = random success.

2. Insert hook pick. Sweep lightly across all pins to feel the stack heights.
   You're building a mental model of pin positions.

3. Find the binding pin: The pin that resists upward movement most strongly.
   On a 5-pin lock, the binding order changes as pins set.

4. Lift the binding pin slowly until you feel/hear a subtle click
   and sense a micro-rotation of the plug. The pin has SET at the shear line.

5. Maintain tension. Move to the next binding pin.

6. Repeat for all pins. On final pin: plug rotates to open position.

Typical time range:
  - Beginner on Master #3 (5-pin):  2-10 minutes
  - Intermediate on Kwikset:        30-90 seconds
  - Experienced on Schlage B60N:    1-3 minutes
  - Experienced on high-security:   10-45 minutes (or not feasible)
```

### Feedback Recognition

| Sensation | Meaning |
|-----------|---------|
| Pin moves freely, springs back | Not the binding pin, skip |
| Pin resists, then clicks slightly | Binding pin — set it |
| Pin sets but plug won't fully rotate | False set (spool/serrated driver pin — increase tension briefly then back off) |
| All pins feel bound | Too much tension — release slightly |

### Spool and Serrated Driver Pins (Security Pins)

High-quality locks use security pins that create a false set to defeat basic picking:

- **Spool pins**: Mushroom-shaped driver pin. Creates a false set when waist catches shear line. Requires tension adjustment (brief increase then release) to clear.
- **Serrated pins**: Multiple false set positions per pin. Requires patience and consistent technique.
- **Mushroom pins**: Similar to spools, found in some Kwikset high-security variants.

## Raking

Raking sacrifices precision for speed by rapidly moving a serrated pick in and out while rotating, relying on probability that all pins will momentarily align.

### Rake Types

| Rake | Best For |
|------|---------|
| Bogota (triple peak) | Most pin tumbler locks, fast and aggressive |
| Snake (city) rake | Locks with irregular pin stacks |
| Batarang | Wide variation in pin heights |
| Half-diamond | Both raking and gentle SPP |
| L-rake (wiper) | Fast but less controlled |

### Raking Technique

```
1. Insert tension bar with light-to-medium tension.
2. Insert rake fully. 
3. Rapidly push/pull rake in a scrubbing motion while simultaneously
   applying rotary motion (in/out + rotate).
4. Vary speed and depth. Faster = more chaotic pin movement.
5. Maintain gentle tension throughout. When pins momentarily align, 
   plug rotates.

Typical open time on unsecured 5-pin:  5-30 seconds
When to use raking vs SPP:
  - Rake first (30 seconds attempt)
  - If no success, switch to SPP
  - High-security or keyway-restricted: go straight to SPP
```

## Bypass Techniques

### Shimming Padlocks

Padlock shims exploit the shackle release mechanism directly — no picking required.

```
Materials:
  - Aluminum shim cut from soda can or purpose-cut metal
  - Fold into U-shape, insert into shackle gap

Procedure:
1. Fold shim into narrow U-profile (like a staple)
2. Slide shim down into shackle gap on the side opposite the keyway
3. Press shim while applying upward pressure to shackle
4. Shim depresses the locking pawl, shackle releases
5. Works on: most import padlocks, low-end Master Lock, combination locks

Does NOT work on: double-locking shackles (locking notch on both sides),
Abloy disc detainer, high-security shrouded padlocks
```

### Loiding (Credit Card / Shim)

Attacks spring latches on doors that do not have a deadbolt or deadlatch engaged.

```
Target: Spring latch bolts on doors with gap between door and frame
Tools:  Plastic shim (loid card), Sparrows Shove-It tool, purpose-made loid

Procedure:
1. Identify the latch bolt side (opposite the hinges, upper bolt on ANSI strikes)
2. Insert loid card in door gap at latch height
3. Angle card toward the latch at ~45 degrees
4. Apply pressure and push/wiggle
5. Card depresses the angled face of the latch bolt → door opens

Defeats:
  - Wooden door frames (bend card around frame)
  - Anti-shimming strips (purpose-made rigid loids)
  
Does NOT defeat:
  - Deadbolt locks
  - Deadlatch (auxiliary latch, found on Schlage and good commercial strikes)
  - Reinforced strike plates
```

### Under-Door Tool (UDT)

The UDT is highly effective against outward-opening doors with lever handles.

```
Tool: Commercial UDT kit (Southord, Covert Instruments) or field-fabricated
      from wire hanger + rubber gripper

Target: Outward-opening doors with lever/paddle handles and REX sensor
        OR simple lever handles without sensor

Procedure:
1. Slide the flat carrier under the door gap (minimum ~1cm gap required)
2. Stand carrier upright using the lifting mechanism
3. Rotate the hook to position over the lever handle
4. Pull the trigger line → hook rotates around handle → depresses lever
5. Door opens

Refinements:
  - Add fabric pad to hook for quieter operation
  - Practice depth estimation (knowing how far to extend without hitting)
  - Some doors have door sweeps that block insertion — carry a gap wedge
```

### Request-to-Exit (REX) Sensor Spoofing

REX sensors (passive infrared or microwave) automatically unlock the door when someone approaches from the secure side. They can sometimes be triggered through gaps.

```
Technique 1: Thin rod through door gap
  - Thin rigid wire bent into L-shape
  - Passed through door gap to reach PIR sensor on secure side
  - PIR sensors typically detect at 6-18 inches

Technique 2: Compressed air / balloon
  - Partially inflate balloon, slide under door
  - Inflate fully to fill detection zone of PIR sensor
  - REX triggers → electric strike releases

Technique 3: Commercial tool (Hooligan Tool)
  - Designed specifically for PIR REX spoofing
  - Telescoping arm with PIR-friendly material on tip
```

### Bypass Handle Tools (Crash Bars / Panic Hardware)

```
Target: Outward-opening emergency exit bars without alarm monitoring

Tool: Dogknob / crash bar tool (thin metal hook on wire)

Procedure:
1. Insert tool through door gap (vertical gap on hinge or latch side)
2. Hook wraps around and contacts the crash bar paddle
3. Pull wire = crash bar depresses = door opens
4. Door may trigger local alarm if monitored — assess before use
```

## High-Security Lock Notes

### Medeco

- Angled key cuts require precise blade angle + height
- Rotating pins (pin must rotate to correct angle AND lift to height)
- Sidebar requires ALL pins to be both lifted AND rotated correctly
- SPP is theoretically possible but extremely difficult in field conditions
- **Practical approach**: Look for physical bypass, REX exploit, or social engineering

### Abloy Protec / Protec2

- Rotating disc mechanism — no spring-loaded pins
- Requires specialized disc detainer pick and significant practice
- Protec2 adds magnetic disc that requires matching key tool
- Field bypass: extremely rare — focus on entry via other attack surface

### Mul-T-Lock Interactive + Classic

- Telescoping pin within a pin — inner pin adds a second shear line
- Classic: 5 outer pins, each with inner pin = effectively 10 pin positions
- Interactive: adds sidebar
- SPP possible with practice but time-consuming
- **Practical approach**: Often appears on exterior doors; target interior door with lower security hardware

## Impressioning

Impressioning creates a working key by transferring lock impressions to a key blank.

```
Tools:
  - Key blank matching lock brand/profile
  - Needle file set
  - Lacquer or smoke (marks the blank before insertion)

Procedure:
1. Coat blank with lacquer spray or smoke from lighter
2. Insert blank into lock
3. Apply upward pressure while turning back and forth (like wrong key)
4. Pins mark the blank where they contact it
5. File down marked locations — a small amount at a time
6. Reinsert and repeat
7. After 5-20 cycles, blank operates the lock

Time: 20-90 minutes for experienced practitioner
Use case: When you have unmonitored access to a lock for duration
          (e.g., a padlock left unattended)
```

## Lock Bumping

Bump keys exploit the physics of pin tumbler operation.

```
How it works:
1. Bump key is cut to maximum depth on all positions
2. Inserted in lock, pulled back one tooth position
3. Sharp strike applied while simultaneously applying rotation tension
4. Impact energy transfers UP through key pins to driver pins
5. For a brief moment (microseconds), all key pins are at shear line
6. If tension is applied at the right instant, plug rotates

Limitations:
  - High-security pins (spools, serrated) resist bumping
  - Requires physical feel and timing — not automatic
  - Leaves small strike marks on lock face (detectable)
  - Security pins make bumping much harder
  - Modern Schlage, Kwikset with SecureKey resist bumping
  
Tools: Bump key set (cut to spec for common keyways: KW1, SC1, Kwikset)
```

## Practice Resources

- **Legal practice locks**: Buy at hardware store — Kwikset (beginner), Schlage B60N (intermediate), Master Lock 140 (padlock basics)
- **TOOOL (The Open Organisation Of Lockpickers)**: [toool.us](https://toool.us/) — chapters in major cities, monthly meetings
- **LockPickingLawyer** (YouTube): 2,000+ video library covering almost every lock made
- **Bosnian Bill** (YouTube): Longer-form explanations, impressioning, high-security locks
- **r/lockpicking** (Reddit): Belt ranking system, practice challenges, community help
- **Locksport International**: Community and competition

> **Legal Note**: In the US, possession of lock picks is legal in most states but may be considered "burglary tools" if intent to commit crime is proven. Ohio, Virginia, and several other states have specific statutes. Always research local law. Carry picks only during authorized engagements with GOJ letter on person.
