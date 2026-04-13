---
layout: training-page
title: "SE Overview & Methodology — Red Team Academy"
module: "Social Engineering"
tags:
  - social-engineering
  - phishing
  - pretexting
  - initial-access
page_key: "se-overview"
render_with_liquid: false
---

# Social Engineering Overview & Methodology

Social engineering exploits human psychology rather than technical vulnerabilities. It is consistently one of the most effective initial access vectors — a convincing email or phone call bypasses every firewall, EDR, and patch cycle.

## Attack Lifecycle

```
1. Intelligence Gathering  — OSINT, org mapping, target profiling
2. Pretext Development     — cover story, persona, lure design
3. Infrastructure Build    — domains, mail servers, landing pages
4. Delivery                — email, phone, SMS, in-person
5. Exploitation            — credential capture, payload execution, access
6. Follow-through          — maintain trust, pivot, escalate
```

## Attack Categories

### Phishing Variants

```
Phishing         — mass email, untargeted
Spear phishing   — targeted, personalized to the individual
Whaling          — C-suite and high-value executives
Vishing          — voice / phone calls
Smishing         — SMS text messages
Internal phishing — from a compromised internal account (T1534)
```

### Pretexting

Creating a fabricated scenario to justify the request. Common pretexts:

- IT helpdesk — "We need to verify your credentials after a system update"
- Executive assistant — "The CEO needs this urgent wire transfer approved"
- Vendor / contractor — calling to schedule on-site access
- HR / payroll — "Update your direct deposit details before Friday"
- Security team — "Your account flagged suspicious login activity"

## Psychological Principles (Cialdini)

```
Authority    — impersonate IT, management, legal, government
Urgency      — "your account will be suspended in 2 hours"
Scarcity     — "only 3 slots remaining for mandatory training"
Social proof — "everyone on your team has already completed this"
Reciprocity  — provide something useful before making the ask
Liking       — build rapport, mirror communication style
Fear         — consequences of inaction (account lockout, audit finding)
```

## SE in the Kill Chain

```
Recon ──► Weaponize ──► Deliver (SE) ──► Exploit ──► Install ──► C2 ──► Actions
                              │
                   Phishing / Vishing / Smishing
                   Pretexting / Impersonation
                   Physical access attempts
```

## MITRE ATT&CK Coverage

```
TA0001 — Initial Access
  T1566     Phishing
  T1566.001 Spear Phishing Attachment
  T1566.002 Spear Phishing Link
  T1566.003 Spear Phishing via Service (Teams, Slack, LinkedIn)
  T1598     Phishing for Information (credential harvesting)
  T1534     Internal Spearphishing (post-compromise)
  T1656     Impersonation
```

## Engagement Planning Checklist

```
[ ] Scope defined — what channels, targets, and actions are permitted
[ ] Objective clear — credentials, payload delivery, physical badge, info exfil
[ ] Rules of engagement — can you spoof internal domains? impersonate employees?
[ ] OSINT phase complete — org chart, email format, tooling identified
[ ] Pretext developed and reviewed
[ ] Infrastructure built and tested
[ ] Deliverability tested — spam score, SPF/DKIM/DMARC configured
[ ] Deconfliction — blue team notified if purple team exercise
[ ] Metrics defined — click rate, submission rate, callback rate, time-to-click
```

## Success Metrics

```
Click rate           — % of targets who clicked the link
Credential rate      — % who submitted credentials
Payload execution    — % who ran the attachment
Callback rate        — % who called the vishing number
Reporting rate       — % who reported the phishing to security (blue metric)
Time-to-first-click  — how quickly the campaign gets a hit
```

---

## Engagement Scoping & Rules of Engagement

Before any social engineering engagement begins, the scope and rules of engagement (RoE) must be agreed upon in writing. Ambiguity leads to client complaints, legal exposure, and unintended damage. Cover every item below in the Statement of Work or a dedicated RoE document.

### What to Agree on Before the Engagement

```
Permitted channels:
  [ ] Email phishing (mass or spear)
  [ ] Vishing (which numbers, which employee groups)
  [ ] Smishing (personal and/or corporate mobile numbers)
  [ ] Physical social engineering (tailgating, badge cloning)
  [ ] In-person impersonation (visitor access, delivery personas)

Permitted actions:
  [ ] Credential capture (landing page forms)
  [ ] MFA interception (AiTM / OTP relay)
  [ ] Payload delivery (attach or link to an implant)
  [ ] Gaining physical access to restricted areas
  [ ] Document or hardware theft simulation

Impersonation scope:
  [ ] Can you impersonate named employees by name?
  [ ] Can you spoof the client's own domain?
  [ ] Can you impersonate the client's IT helpdesk?
  [ ] Are executives (CEO, CFO) explicitly in or out of scope?
  [ ] Are any roles or individuals explicitly excluded? (legal, HR leadership)

Target scope:
  [ ] All employees, or a defined subset?
  [ ] Specific departments (finance, IT, HR)?
  [ ] Specific individuals (named in scope list)?
  [ ] Contract staff / third-party vendors included?

Data handling:
  [ ] How are captured credentials stored and transmitted?
  [ ] Who at the client receives raw results?
  [ ] When are credentials and campaign data destroyed?
  [ ] Are submitted credentials ever tested against real systems?
```

### Common Scope Limitations

Many clients include restrictions that are critical to respect:

```
"Do not target employees currently on FMLA, medical leave, or PIP"
"Do not use the CEO or CFO as the impersonated sender"
"Do not attempt to deliver executable payloads — link-click metrics only"
"Do not attempt physical entry to data center floors"
"Avoid contacting employees between 6pm and 8am local time"
"All captured data must be deleted within 72 hours of report delivery"
```

Keep a signed copy of the RoE document accessible during the engagement. If a target calls your engagement number, you need to be able to confirm the engagement is authorized immediately.

---

## Physical Social Engineering Overview

Physical social engineering tests whether an attacker can gain unauthorized physical access to a facility, floor, or restricted area by manipulating employees rather than defeating technical controls.

### Objectives Typically Tested

```
- Gain access to office floor without a badge
- Reach IT server room or data center
- Plant a USB device or rogue access point on-site
- Clone an employee access badge
- Retrieve sensitive documents left unattended
- Access an unlocked workstation
```

### Tailgating & Piggybacking

Tailgating is entering a secured area by following an authorized person through a controlled door without badging in. It requires no technical capability — only timing and confidence.

```
High-yield scenarios:
  - Morning rush (8:00–9:30am): high badge-in volume, door held as courtesy
  - Lunch hour: groups returning together, doors propped informally
  - Deliveries: delivery staff often waved through without badging
  - Shift handoffs at 24/7 facilities

Confidence boosters:
  - Carry something (boxes, laptop bag, coffee tray) — hands full = door held
  - Wear a high-visibility vest or contractor badge lanyard
  - Look purposeful — act as if you belong there
  - Engage in small talk as you approach the door
```

### Pretexting for Physical Access

Common physical pretexts that gain cooperation from employees:

```
HVAC / facilities technician:
  "I'm with [HVAC vendor] — we have a scheduled maintenance visit for
   the server room today. My contact was [name] but they're not picking up."

IT contractor:
  "I'm from [MSP name] — I have a ticket to replace a faulty switch on
   the 4th floor. My badge access hasn't been set up yet."

Auditor:
  "We're doing a compliance walkthrough for the [ISO 27001 / SOC 2] audit.
   I just need a quick look at the network closet configuration."

Delivery:
  "Package for [real employee name] — needs a signature.
   Can you buzz me in to drop it at their desk?"
```

### Badge Cloning

Low-frequency (125kHz) RFID access cards are cloned by reading the card ID and replaying it on a blank card. See the Physical Social Engineering page for full tooling coverage.

---

## Insider Threat Simulation

Authorized phishing simulations test employees' susceptibility to social engineering and measure the effectiveness of security awareness training. These differ from red team engagements in that the goal is measurement and improvement, not compromise.

### Phishing Simulation Programme Design

```
Frequency:     Quarterly campaigns minimum; monthly for high-risk groups
Scope:         All employees, including executives
Channels:      Email phishing + vishing + smishing for comprehensive coverage
Difficulty:    Vary difficulty level — easy, medium, hard templates
Debrief:       Immediate in-browser training for anyone who clicks
Reporting:     Aggregate stats to CISO, department-level breakdown to managers
```

### Click-Rate Metrics and Benchmarks

Industry benchmarks for comparison (varies by sector and awareness maturity):

```
Initial campaign (no prior training):  25–40% click rate is common
After 1 year of regular training:       5–15%
Mature programme (3+ years):            2–8%
Executive click rate is often HIGHER   than general population

High-risk indicator thresholds:
  Click rate > 25%    — immediate awareness programme needed
  Submission rate > 10% — credential handling training required
  Report rate < 5%    — reporting culture needs development
```

### GoPhish for Simulation Campaigns

```bash
# Launch GoPhish
./gophish

# Access admin UI
# https://localhost:3333 (default: admin / gophish — change immediately)

# Campaign setup workflow:
# 1. Create Email Template (subject, HTML body, {{.FirstName}} substitution)
# 2. Create Landing Page (clone from real login page or simple training page)
# 3. Create Sending Profile (SMTP server, from address)
# 4. Create Group (import targets from CSV: First Name, Last Name, Email, Position)
# 5. Launch Campaign — set send window to avoid nights/weekends
```

### Reporting What to Include

```
Executive summary:
  - Overall click rate and trend vs prior campaigns
  - Credential submission rate
  - Time to first click (how quickly the campaign landed)
  - Reporting rate (how many reported the phishing)

Department breakdown:
  - Worst-performing departments (for targeted follow-on training)
  - Best-performing departments (recognise and share practices)

Individual flags:
  - Repeat clickers (targeted 1:1 coaching)
  - Users who submitted credentials (mandatory security conversation)

Recommendations:
  - Specific training modules to assign
  - Process changes (e.g., verify wire transfers by phone)
  - Technical controls to implement (link rewriting, attachment blocking)
```

---

## Defence and Awareness

### What Defenders Look For

Security operations and phishing-aware employees are trained to recognise these signals:

```
Email indicators:
  - Sender domain does not match the claimed organisation
  - Display name does not match email address
  - Unexpected urgency or pressure to act immediately
  - Grammar or tone inconsistent with known sender
  - Link domain differs from displayed text (hover to check)
  - Attachment with unusual file type (ISO, LNK, DOCM, HTA)
  - Request for credentials, OTP, or payment via email

Vishing indicators:
  - Caller requests password, OTP, or sensitive data
  - Caller discourages verification ("no time to call back")
  - Caller ID matches a known number but behaviour is unusual
  - Unusual request inconsistent with known processes

Physical indicators:
  - Unfamiliar person without escort in restricted areas
  - Person unable to present a valid badge or ID
  - Unusual interest in IT infrastructure areas
  - USB devices or cables left unattended
```

### Security Awareness Training Pitfalls

Common mistakes in awareness programmes that reduce effectiveness:

```
Pitfall: Annual-only training
Fix:     Continuous drip training — monthly micro-learning modules

Pitfall: Generic, non-contextual training (fake Nigerian prince emails)
Fix:     Use lures that match your org's actual risk profile and vendors

Pitfall: Shaming or punishing employees who click
Fix:     Use just-in-time training and a blameless reporting culture

Pitfall: Training only covers email
Fix:     Include vishing and physical SE scenarios

Pitfall: No phishing reporting mechanism
Fix:     Deploy a "Report Phishing" button in email clients (Outlook add-in)

Pitfall: Metrics tracked but never acted on
Fix:     Feed results into targeted training and process changes
```

### Technical Controls That Reduce SE Risk

```
Email controls:
  - External email banners ("This email originated outside the organisation")
  - Link rewriting and detonation (Defender Safe Links, Proofpoint URL Defense)
  - Attachment sandboxing (Defender ATP, Proofpoint TAP)
  - DMARC policy enforcement (p=reject) on own domain prevents spoofing

Endpoint controls:
  - Disable Office macros by default (Group Policy / Intune)
  - Block LNK, ISO, IMG, HTA execution from Downloads
  - Browser isolation for suspicious links

Authentication controls:
  - FIDO2 / hardware keys — phishing-resistant MFA (not defeated by AiTM)
  - Conditional access policies — block logins from unexpected locations
  - Privileged access workstations (PAW) for admin accounts

Physical controls:
  - Tailgate detection systems (e.g., Kouba Systems, Smarter Security)
  - Visitor management system with photo ID verification
  - Clear desk policy enforcement
  - CCTV coverage at all entry points
```

---

## MITRE ATT&CK Social Engineering Techniques Reference

| Technique ID | Name | Description |
|---|---|---|
| T1566 | Phishing | Umbrella technique for email-based phishing attacks |
| T1566.001 | Spear Phishing Attachment | Targeted emails with malicious attachments |
| T1566.002 | Spear Phishing Link | Targeted emails with malicious links |
| T1566.003 | Spear Phishing via Service | Phishing via Teams, Slack, LinkedIn, social media |
| T1598 | Phishing for Information | Credential harvesting without malware delivery |
| T1598.001 | Spear Phishing Service | Harvesting via social media or messaging services |
| T1598.002 | Spear Phishing Attachment | Credential-stealing documents |
| T1598.003 | Spear Phishing Link | Link to credential harvester |
| T1585 | Establish Accounts | Creating fake social media, email, or web accounts for SE |
| T1585.001 | Social Media Accounts | Creating LinkedIn, Twitter personas for SE |
| T1585.002 | Email Accounts | Registering attacker-controlled email addresses |
| T1586 | Compromise Accounts | Hijacking real accounts to use for SE delivery |
| T1586.001 | Social Media Accounts | Compromising real social accounts |
| T1586.002 | Email Accounts | Compromising real email accounts for phishing |
| T1534 | Internal Spearphishing | Phishing from a compromised internal account |
| T1656 | Impersonation | Pretending to be a trusted entity |

---

## Resources

- MITRE ATT&CK Initial Access — `attack.mitre.org/tactics/TA0001/`
- Social Engineer Framework — `www.social-engineer.org/framework/`
- Influence: The Psychology of Persuasion — Robert Cialdini
- The Art of Intrusion / The Art of Deception — Kevin Mitnick
- GoPhish — open source phishing framework — `github.com/gophish/gophish`
- NIST SP 800-177 — Trustworthy Email — `csrc.nist.gov`
- SANS Security Awareness — `sans.org/security-awareness-training`
