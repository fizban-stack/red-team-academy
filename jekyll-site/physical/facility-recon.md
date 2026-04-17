---
layout: training-page
title: "Facility OSINT & Physical Reconnaissance — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - osint
  - recon
  - facility
page_key: "physical-facility-recon"
render_with_liquid: false
---

# Facility OSINT & Physical Reconnaissance

Physical reconnaissance combines open-source intelligence gathering with direct observation to build a complete operational picture of the target facility before any active intrusion attempt. Quality reconnaissance is the difference between a fumbling approach and a confident, efficient entry.

## Passive OSINT: Remote Intelligence

### Google Maps & Street View

```
Google Maps workflow:
1. Search for target address → switch to satellite view
2. Zoom in to identify:
   - Main entrance(s) and secondary entrances
   - Parking structure (employee vs. visitor separation)
   - Loading docks (location, size, access roads)
   - External HVAC units (often near server rooms)
   - Exterior camera positions (visible mounting brackets)
   - Fence lines, gates, security guard booths
   - Roof access hatches, ladder positions
   - Proximity to neighboring buildings (possible observation posts)

Street View:
  - Navigate to facility at street level
  - Examine:
    - Door hardware (lock brand often visible at high zoom)
    - Reader type on access-controlled entrances
    - Camera types and positions
    - Window security film or grilles
    - Guard positions at peak hours
  
  Historical Street View:
    - Click clock icon on Street View to access historical images
    - Useful for seeing construction changes, old guard positions
    - Time of capture shown (often 9am-3pm — useful baseline)

Google Earth Pro:
  - Free desktop application
  - Historical satellite imagery with date selector
  - 3D building view reveals roof access, raised platforms
  - Measure function: door widths, setback from street, perimeter length
```

### Public Records

```
Building permits (US):
  - Filed with county building/planning department
  - Search by address at county assessor or permit portal
  - Reveals: tenant improvements, HVAC work, electrical work
  - Floor plans often attached to permit applications
  - ADA compliance drawings may show interior door locations
  - Search: "[County Name] building permit search" or "certificate of occupancy"

Fire Inspection Reports:
  - Many municipalities post online (FOIA request if not)
  - Reveal: hazmat locations (data centers have CO2 suppression — good target indicator)
  - Fire egress maps: may include interior corridor layouts

Certificate of Occupancy:
  - Public record confirming building use type
  - Confirms square footage and floor count
  - Available from city/county building department

FOIA / Public Records Requests:
  - If target is government agency or public entity: use FOIA
  - Request: "All building permits, fire safety inspection records, 
    and floor plan submissions for [address] from [date range]"
  - Response time: 5-20 business days typically
```

### LinkedIn Intelligence

```
Search for target company employees:
  - Sort by title: "Security Director", "Physical Security Manager", "Facilities Manager"
  - Names of security leadership = social engineering targets
  - Security company name in background images (some guards post photos)
  - "Works at [target company]" + "Security Officer" or "Guard"

Job postings reveal physical security posture:
  Example job posting analysis:
    "[Company] seeks Security Officer to manage HID access control system"
    → Reveals: HID readers (125kHz likely), employer managing their own system

    "Monitor Lenel OnGuard access control platform"
    → Reveals: Lenel system (common enterprise, often iClass SE)

    "Experience with Genetec Security Center required"
    → Reveals: Genetec = high-end CCTV + access integrated platform

    "Manned guard desk 24/7"
    → Reveals: staffed security presence around clock

Employee photos:
  - Profile photos may show badge lanyards (reveals badge type, company logo)
  - Conference/event photos: employees sometimes visible with badge
  - ID badge vendor logo often visible (HID, Allegion, Dormakaba)
```

### Job Posting Analysis

```
Search for target company jobs on LinkedIn, Indeed, Glassdoor, ZipRecruiter

Security-related keywords to analyze:
  - "access control" → which system (HID, Lenel, Honeywell, CCURE)
  - "CCTV monitoring" → camera system brand (Genetec, Milestone, Avigilon)
  - "guard company" → subcontractor name (Allied Universal, Securitas, G4S)
  - "badging system" → credential type (iClass, Prox, DESFire)
  - "alarm system" → vendor (Bosch, Honeywell, DSC)

IT job postings (also useful):
  - "manage physical access control integration with Active Directory"
    → AD-integrated ACS = employee accounts may appear in AD with badge data
  - "support Cisco Meraki camera system"
    → Meraki cameras: cloud-managed, may have internet-facing admin console
  - "administer Milestone VMS"
    → Milestone VMS: check for internet exposure (Shodan: port 7563)
```

### Shodan for Facility Intelligence

```bash
# Search for cameras at target IP range
shodan search 'org:"[Company Name]" has_screenshot:true'

# Building automation systems (Niagara/Tridium)
shodan search 'port:4911 "Niagara"'

# Access control panels (common ports)
shodan search 'port:4050 "CCURE"'   # Software House CCURE
shodan search 'port:8080 "Lenel"'   # Lenel OnGuard

# Bosch/Honeywell intrusion panels
shodan search 'org:"[Company]" "RADIONICS"'
shodan search '"Galaxy Dimension"'   # Honeywell Galaxy

# IP cameras with default credentials
shodan search 'product:"Hikvision" default password'

# Axis cameras (ubiquitous in corporate)
shodan search 'Server: "Apache" "Axis" org:"[Company]"'

# Search for company-specific subnet
shodan search 'net:[IP_RANGE/CIDR] screenshot'
```

### Vendor Identification from Photos

```
LinkedIn and Google Images searches often reveal reader photos:
  - Search: "[Company Name] office" site:linkedin.com
  - Filter for images of entrances, lobbies, security desks

Reader identification from photos:
  HID: Red/white oval logo; common models: RP10/RP40, iCLASS R10, Multiclass
  Lenel: Often paired with LNL-1320 door controllers
  Honeywell: Pro-Watch system, OmniAssure readers
  Allegion (Schlage): Schlage AD-series readers
  Dormakaba: Kaba access readers

From reader model number: cross-reference to frequency and protocol
  HID RP40: 125kHz Prox → T5577 clone works
  HID iCLASS R40: 13.56MHz iClass → loclass attack if legacy
  HID iCLASS SE R40: 13.56MHz iClass SE → much harder
  HID multiCLASS RP40: supports both frequencies → dual-frequency attack
```

## Dumpster Diving

Physical OSINT from disposed materials is highly effective and commonly overlooked.

```
High-value targets:
  - Discarded access badges (temporary, expired, terminated employee)
  - Badge printer ribbons (retain mirror impression of printed cards)
  - Network diagrams printed for meeting (common in recycling bin)
  - Vendor invoices (reveal IT vendors, security system vendors)
  - Employee phone lists (names, extensions, departments)
  - Organizational charts (reporting structure, security contacts)
  - Old access control enrollment forms
  - Lock/key log books (reveals which keys exist, who has copies)
  - Badge reader installation manuals (confirm model, programming guide)

Legal context:
  - In the US: items placed in public trash typically lose 4th Amendment
    protection (California v. Greenwood, 1988)
  - Private property dumpsters: may require authorization in ROE
  - Include "dumpster access" in scope definition for physical engagements

Execution:
  - Conduct during low-traffic hours (pre-dawn or after business hours)
  - Wear gloves (hygiene and no fingerprints)
  - Work quickly — sorting takes time, prioritize paper documents
  - Photograph contents before sorting (preserves context)
  - Re-seal bag and replace to avoid visible disturbance
```

## Physical Drive-By Reconnaissance

### First-Pass Assessment

```
Drive-by reconnaissance (vehicle):
  - Single slow pass on each street adjacent to facility
  - Photograph with dashcam (continuous recording)
  - Note: entrances, signage, guard booth positions, external cameras
  - Time: 10-15 seconds per pass maximum (avoid lingering)
  
Multiple passes:
  - Space over days and times (morning rush, lunch, late afternoon)
  - Vary vehicle used (not same car on repeated visits)
  - Vary approach direction

Pedestrian reconnaissance:
  - Walk near facility on public sidewalk
  - Photograph casually (tourist mode)
  - Assess: door hardware at each entrance, lock brands visible
  - Time guard patrols: guard exits building → note time → guard returns → note time
  - Identify employee smoking areas (badge holders visible, door prop habits)
```

### Loading Dock Assessment

```
Loading docks require specific recon:
  Timing:
    - Peak delivery: 9am-11am, 1pm-3pm for most commercial facilities
    - Overnight: some large facilities have 24h loading with night guard
    - Weekends: many corporate docks go to card-reader only (no guard)

  Access controls at dock:
    - Often: simple padlock or deadbolt (no electronic access)
    - Less commonly: card reader matches main system
    - Guard booth at dock entrance: ID check required or wave-through?

  Camera coverage:
    - Dock usually has 1-2 cameras covering vehicle bays
    - Human-height camera over pedestrian entry often absent
    - Interior of dock: camera above freight elevator (most common)
    - Dead zone: between dock platform edge and building exterior wall
```

### Guard Patrol Timing

```
Observation methodology:
1. Establish observation post with clear sightline to guard position
   (parked vehicle, nearby coffee shop, public bench)
2. Note time guard last seen at post/door
3. Note time guard returns or reappears
4. Repeat for minimum 3 cycles (same day or multiple days)
5. Calculate patrol interval and identify window for unobserved entry

Typical patrol intervals:
  - No patrol: guard stationary at desk (common in large lobbies)
  - 30-minute: scheduled hourly walk-through
  - 60-minute: less common, usually larger perimeters
  - Random: guard uses random patrol schedule (note irregularity)

Guard hand-off timing (shift change):
  - During handoff: attention is divided between incoming/outgoing guard
  - Usually 5-15 minutes of reduced coverage
  - Identify shift change time from observation
```

## Aerial Imagery

```
Google Earth historical imagery:
  - Tool → Historical imagery → adjust timeline slider
  - View seasonal differences (foliage affects camera angles)
  - Identify construction changes, access control installations
  - Spot rooftop HVAC locations (server room heat signature possible)

County Assessor Maps:
  - Search: "[County] GIS parcel viewer" or "[County] assessor map"
  - Building footprint: exact dimensions and layout
  - Lot lines: useful for understanding adjacent property access
  - Identifies secondary structures (outbuildings, parking structures)

FAA UAS (Drone) Considerations:
  - Drones require FAA Part 107 or hobbyist authorization for non-recreational use
  - Flying over private property: state trespass laws vary
  - Include in scope discussion if drone recon is planned
  - Useful for: rooftop access point identification, camera positions
  - Risk: drones are visible — potentially alerts security
```

## Social Engineering Intelligence (Pretexting for Information)

### Front Desk Call

```
Script template — Calling as prospective tenant:
  "Hi, I'm looking at office space in the area for our company and 
  I understand you might have some availability on [floor X]? 
  I was wondering if I could schedule a tour — and is parking validated 
  for visitors?"
  
  Intelligence gained:
    - Who answers (receptionist, security desk, or forwarded to facilities)
    - Building management company name
    - Visitor process (ID check, escort, or self-serve)
    - Parking validation (confirms visitor flow)
    - General office hours and access patterns
```

### Facilities Management Call

```
Script template — Calling as building services vendor:
  "Hi, this is [Name] from [HVAC company] — we're the service 
  provider for the Trane units on your third floor. We have a 
  scheduled service visit next week and I wanted to confirm 
  the loading dock access procedure."

  Intelligence gained:
    - Facilities manager name
    - Loading dock access procedure (badge required? Call ahead?)
    - Vendor access policy
    - Whether third-party vendors are pre-approved or escorted
```

### Security Desk Call

```
Script template — Testing security posture:
  "Hi, this is [Name] from [staffing company]. I have a contract 
  worker starting Monday and I want to make sure the badge process 
  is set up correctly. Who should he check in with for his visitor 
  badge?"
  
  Intelligence gained:
    - Visitor badge process
    - Who administers badges (HR? security? facilities?)
    - Whether pre-enrollment required
    - Whether visitor badges allow unescorted access
```

## Reconnaissance Documentation Template

```
FACILITY RECON REPORT — TEMPLATE

Facility: [ADDRESS]
Operator: [NAME]
Date(s): [DATES]
Method: Passive OSINT, Drive-by, Social Engineering calls

LAYOUT:
  Main entrance: [DESCRIPTION — facing direction, door count, guard presence]
  Secondary entrances: [LIST ALL]
  Loading dock: [DESCRIPTION]
  Parking: [TYPE, visitor vs employee separation]
  Floors: [CONFIRMED COUNT FROM PERMITS/GOOGLE EARTH]

ACCESS CONTROLS:
  Reader type: [HID RP40 / Lenel / Unknown]
  Reader frequency: [125kHz / 13.56MHz / Both]
  Card technology: [HID Prox / iClass / MIFARE / Unknown]
  Guard presence: [Hours, stationary vs. patrol]
  Visitor process: [Escort / Self-serve / Log-only]

CAMERA COVERAGE:
  Entrance cameras: [COUNT, TYPE, COVERAGE ANGLE]
  Parking cameras: [Yes/No, coverage]
  Interior lobby: [Coverage extent]
  Blind spots: [IDENTIFIED GAPS]

EMPLOYEE PATTERNS:
  Peak arrival: [TIME WINDOW]
  Lunch rush: [TIME]
  Common tailgating behavior: [Yes/No — observed frequency]
  Smoking area: [LOCATION, estimated frequency]

VENDOR INTELLIGENCE:
  Guard company: [NAME if identified]
  ACS vendor: [HID/Lenel/Honeywell/Other]
  Camera vendor: [Identified from job posts/photos]

ATTACK SURFACE SUMMARY:
  Highest probability entry: [TECHNIQUE — e.g., "tailgate at north entrance during 08:30-09:00"]
  Secondary option: [TECHNIQUE]
  Recommended tools: [LIST]
```
