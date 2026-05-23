---
layout: training-page
title: "Deepfake Voice & Vishing Operations — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - vishing
  - deepfake
  - voice
  - persona
  - social-engineering
  - elevenlabs
  - scoping
page_key: "ai-deepfake-voice-vishing-ops"
render_with_liquid: false
---

# Deepfake Voice & Vishing Operations

2024 is when synthetic voice stopped being a research curio and became a line item on the operator's tool list. The Hong Kong "$25M deepfake CFO video call" in February of that year was the headline event — a finance worker authorised fifteen transfers totalling around HK$200M after a multi-participant video meeting in which every other "attendee" was generated. Within twelve months, public reporting was tracking voice-clone-to-helpdesk callbacks against US enterprises, Retool/Reddit-pattern intrusions where vishing pivoted off SMS phishing, and the well-known MGM and Caesars incidents where the entry point was a phone call to the service desk.

If you operate in red team or assumed-breach engagements, you are now expected to know how this works on both sides of the call. This page is written for the operator who is going to use synthetic voice under a sanctioned engagement, and for the defender preparing controls before the attacker shows up uninvited. It is not a how-to for fraud. Every technique below is paired with the boundary that keeps it legal and the control that beats it.

Read this alongside `social-engineering/vishing.md` (call mechanics, scripts, infrastructure) and `social-engineering/pretexting.md` (persona construction, scenario library, failure recovery). The page you are reading focuses specifically on the synthetic-voice layer that sits on top of those foundations.

## The 2024–2026 Threat Model

The threat surface for voice-driven attacks expanded faster than any other social engineering vector during this period. The relevant shifts:

```
Cloning latency collapsed
  2022 — 30+ minutes of clean audio, batch synthesis, audible artefacts
  2023 — 5 minutes of audio, near-real-time synthesis on commercial APIs
  2024 — under 60 seconds of source audio, real-time conversion during calls
  2025 — local open-weight models (RVC variants) approach commercial quality
  2026 — voice-to-voice latency under 200ms on consumer GPUs

Source audio is everywhere
  LinkedIn audio name pronunciation clips (a 5–10 second sample is enough
    to seed several commercial clone services to "passable" quality)
  Executive YouTube interviews, conference keynote recordings, earnings calls
  Podcast guest appearances (often 30–60 minutes of clean studio audio)
  Webinar recordings on corporate marketing sites
  Press conference clips and analyst Q&A audio published by IR teams

Real-time voice conversion in calls
  Operator speaks normally into a headset, target hears the cloned voice
  Round-trip latency low enough that the target perceives natural conversation
  Background ambience can be layered in (open-plan office, airport, car)
  Emotional inflection survives the conversion better than it did 18 months ago

AI-driven call-center personas
  Fully autonomous LLM-driven callers handling tier-1 helpdesk dialogue
  Used today by criminal groups at scale for low-quality refund/IRS scams
  Used in sanctioned engagements for parallel pretext probing across many
    targets in a short window — operator listens and pivots only to live
    calls that respond to the lure
  Detection signal: extreme consistency of phrasing across calls

Live transcript adaptation
  Real-time speech-to-text feeds an LLM that suggests the next line to the
    operator while the call is in progress
  Lets a less experienced operator hold a more convincing pretext
  Also lets the operator pivot mid-call when the target volunteers an
    unexpected detail (a tool name, a colleague's name, a recent event)
```

What used to demand a skilled human caller can now be run by an operator with modest skill and a $22/month commercial voice account. That is the shift defenders need to internalise. The cost curve has bent and the floor of attacker capability has risen sharply.

## Engagement Boundaries — Read This Before Anything Else

Synthetic voice is one of the highest-risk techniques an operator can field. It is one of the small number of methods that can cross from "sanctioned test" into "criminal impersonation" with a single careless word. Treat the boundary as non-negotiable.

```
Written authorisation is mandatory — and it must be specific
  Generic vishing authorisation does NOT cover deepfake voice
  Rules of Engagement must say "synthetic voice / voice cloning of
    specific named individuals is authorised" in plain language
  RoE must list each individual whose voice may be cloned
  RoE must list each individual who may be impersonated TO
  Signed by an authorising officer with explicit authority — usually
    CISO, CIO, or General Counsel; never the engagement sponsor alone

Targets who can be impersonated
  Only individuals who have signed an explicit consent form for their
    voice to be cloned in the engagement — even if they are the CEO
  No board members unless the board itself has approved (this is a
    governance trigger that surprises sponsors — flag it early)
  No customers, suppliers, regulators, or any external party — full stop
  No deceased individuals (some jurisdictions criminalise this even
    with family consent)

Targets who can be called
  Only employees of the contracting organisation
  Only employees within the in-scope departments
  No personal mobile numbers unless individually consented and listed
  No customers of the contracting organisation under any circumstance
  If a non-scope party answers (wrong-number, family member of a
    target, child) — terminate immediately and log the contact

Recording-consent jurisdictions
  US federal — single-party consent (operator consenting is sufficient)
  Two-party / all-party consent states — California, Connecticut,
    Florida, Illinois, Maryland, Massachusetts, Montana, Nevada,
    New Hampshire, Pennsylvania, Washington
  EU/UK — GDPR requires a lawful basis; "legitimate interest" is the
    usual basis for sanctioned testing but document the assessment
  Calls that cross jurisdictions take the stricter standard

Customer-side notification protocol
  The client's security operations team is informed in advance — they
    will receive the inevitable reports from targets who detected the call
  Service desk leadership knows an engagement is running but front-line
    staff do not (defeats the test if they do)
  Out-of-hours emergency contact at the client carries the RoE document
    digitally — when a target escalates and SOC opens an incident, the
    deconflict number stops the response before law enforcement is called

Two-person rule
  Never run live synthetic-voice vishing solo
  One operator runs the call, the second monitors and pulls the plug
    if the conversation drifts off-script or off-scope
  The second operator is also the witness if a target later disputes
    what was said
  Both operators are on the engagement contract, both have signed the
    RoE, both have completed any client-mandated training

Killswitch and abort criteria
  Pre-agreed words or phrases that end the call instantly — typically
    used if the operator realises mid-call they are talking to the wrong
    person, a minor, or someone in obvious distress
  Pre-agreed scope-creep triggers — if the conversation moves toward
    a topic outside RoE (medical, legal, financial detail beyond the
    pretext), end the call
  Post-call deconflict — every successful credential capture or wire
    authorisation triggers immediate notification to the client SOC
    so no real harm propagates
```

If any of the above cannot be satisfied in writing, the technique is not in scope. Decline the work or scope it down to traditional vishing without voice cloning. There is no professional benefit to running an engagement that is one ambiguous phrase away from a criminal complaint.

## Technical Primitives (High Level)

Operator-facing detail kept deliberately at a conceptual level. Specific commercial services and open-source projects are named because defenders need to know them too.

```
Cloning services (commercial)
  ElevenLabs    — quality leader, ethical-use policy, voice
                  verification step required before cloning
  Resemble AI   — enterprise-focused, explicit consent workflow,
                  watermarking on output
  PlayHT        — API-first, common in scaled abuse cases
  Azure / GCP   — gated behind enterprise contracts with strict
                  consent verification

Cloning frameworks (open weight, local)
  RVC          — most-deployed open framework, consumer GPU,
                 voice-to-voice real-time conversion
  XTTS / Coqui — text-to-speech with voice cloning; higher quality
                 than RVC for synthesis but not real-time
  StyleTTS2, OpenVoice, Tortoise — research-grade alternatives

Real-time conversion pipelines
  Operator mic -> VAD -> conversion model -> SIP/WebRTC/PSTN bridge
  Latency budget: ~200ms one-way is the perception threshold; above
    ~400ms the rhythm breaks
  Ambience injected at the output stage, not pre-conversion

Telephony layer
  Twilio / SignalWire / Vonage — programmable voice APIs,
    caller-ID spoofing within carrier rules
  Self-hosted Asterisk / FreePBX — full control via wholesale SIP
    trunk; more configurability for sanctioned ops

Audio source acquisition (defender awareness)
  LinkedIn pronunciation clips, YouTube/podcast feeds, earnings
    calls, conference recordings, webinars, internal Zoom/Teams
    recordings if the attacker already has partial access
```

The relevant defender takeaway is that source audio collection is essentially free and detectable only at the social-graph level — you cannot prevent LinkedIn from carrying executive voice clips, but you can choose not to publish thirty-minute keynotes of your CFO in a public webinar.

## Persona Development for Voice-Cloned Operations

A cloned voice is only one ingredient. The pretext, the timing, the script, and the live pivot capability matter at least as much. A perfect clone of a CEO reading an obviously wrong script falls apart in ten seconds.

```
OSINT for tone and phrasing
  LinkedIn posts, podcast transcripts, internal all-hands clips (if
    accessible) — extract characteristic phrases, hedges, jokes
  Corporate blog posts that name the target as author often reflect
    their actual speaking style after light editing
  Investor letters and shareholder communications — formal, but the
    cadence is real
  Twitter/X archive — informal phrasing, common topics
  Build a one-page "voice card" for each impersonated individual that
    lists characteristic vocabulary, names of family/colleagues they
    reference publicly, recent topics they have discussed

Calendar-style timing match
  Calling an executive assistant at a known-busy moment (just before a
    standing weekly meeting) increases compliance — the target is
    juggling and inclined to defer
  Calling finance late on a Friday before a long weekend exploits the
    "just clear this off the desk" reflex
  Avoid calling at moments where the impersonated party is provably
    elsewhere — if the CEO is publicly speaking at a conference at
    10am Pacific, do not impersonate them at 10:15am Pacific
  Public calendars (conference appearances, scheduled press events) are
    the constraints you build the call window around

Script preparation
  Pre-write the first 90 seconds — opener, context, ask
  Pre-write the three most likely objection lines and your response
  Pre-write the close, including the graceful exit
  Keep the live, unscripted portion short — the longer the operator
    is improvising in a cloned voice, the more likely a deviation
    from the impersonated party's known mannerisms surfaces
  Anchor every ask in a verifiable-sounding detail (a real meeting
    name, a real project codename surfaced via OSINT, a real ticket
    system reference)

The pivot moment
  The point at which the scripted content runs out and the operator
    must improvise is where most deepfake calls collapse
  Plan for this — either close the call before the pivot is needed
    ("I'll send the details by email in five minutes — have a good
    afternoon"), or hand off to a second operator using a different
    pretext ("I'm going to put you on with our finance lead who has
    the specifics")
  Never improvise dollar figures, dates, or names — write them down
    on paper in front of you before the call

Synthesised-voice quirks the script should hide
  Numbers and codes — most cloning models stumble on long digit
    sequences; have the operator read these in normal speech, or
    avoid the ask entirely
  Acronyms — read out as the impersonated party would actually say
    them (some say "S-O-C", some say "sock")
  Laughter, hesitations, throat-clearing — current models do these
    badly; the script should not require them
  Code-switching — bilingual impersonation is significantly harder
    than monolingual; treat any multi-language target as out of scope
    unless the model has been explicitly trained on bilingual audio
```

The persona-development discipline in `social-engineering/pretexting.md` applies in full. The voice clone is an amplifier on a well-built pretext, not a substitute for one.

## Defender Controls That Work

The good news for defenders is that the controls which beat synthetic-voice attacks today are the same controls that have always beaten high-stakes vishing. The bad news is that most organisations have not actually deployed them.

```
Out-of-band callback verification
  Any high-impact request (wire transfer, credential reset for a
    privileged account, mass mailbox export, change to vendor payment
    details) requires the receiver to call the requester back through
    a known channel
  "Known channel" means a number stored in the corporate directory
    BEFORE the request — not a number the caller provided
  This is the single most effective control against deepfake voice;
    the attacker cannot intercept a call placed to a number they did
    not nominate

Code phrases / safe words
  Pre-agreed words between named individuals — typically executives
    and their direct reports, finance team and named approvers
  The word is rotated quarterly and stored only in physical form
    or in a dedicated app outside email and chat
  Low-tech, surprisingly effective; an attacker who has cloned the
    voice still cannot guess the word
  Adoption resistance is the main obstacle; pitch this as a five-minute
    quarterly cost for an existential risk control

Helpdesk procedures with non-voice secondary auth
  No password reset, no MFA reset, no account unlock based on voice
    confirmation alone — ever
  Secondary auth via in-band corporate channel (Teams/Slack ping to
    the verified employee account, ticketing system response)
  For high-value accounts, in-person or video-with-badge verification
  Document the procedure, drill it quarterly, measure deviations

"I'll have my team email you" reframe
  Training employees to respond to any phone-based request with
    "thanks, I'll have my team follow up via email" defangs almost all
    real-time voice attacks
  Works because it shifts the attacker out of the live-pressure
    advantage and into a channel where their pretext can be verified
  Easy to train, easy to audit, easy to roll out

Voice biometric systems (commercial)
  Pindrop, Nuance Gatekeeper, ID R&D — deployed primarily in banking
    and call centres
  Detect synthetic-voice artefacts in real time, flag suspect calls
  Limited deployment outside banking and government; expect to see
    these spread to enterprise helpdesk over 2026
  Treat as defence-in-depth, not a primary control — false negatives
    are common against current-generation clones

Procedural friction on irrevocable actions
  Wire transfers above a threshold require dual approval through a
    system that captures employee identity (not a phone call)
  Credential resets for service accounts go through a change-management
    workflow with a 30-minute minimum window
  Mass actions (mailbox exports, group membership changes, MFA bulk
    operations) require ticket-and-approval before execution

Awareness training that includes synthetic voice
  Replace generic "be careful on the phone" training with specific
    scenarios involving voice cloning
  Show employees that synthetic-voice samples can be generated of
    THEIR voice from public sources — this lands harder than abstract
    warnings
  Reward employees who correctly report attempts — positive
    reinforcement consistently outperforms punitive frameworks
```

## Defender Controls That Don't Work

Equally important to know what does not. Several controls that organisations rely on are demonstrably weak against deepfake-driven vishing.

```
Push-to-confirm MFA (without number matching)
  The deepfake voice can talk through it — "I'm going to push a
    verification, please approve when you see it" works against a
    cooperating target whether the voice is real or cloned
  Number-matching push (target reads a number off the prompt and
    enters it on the device requesting access) helps somewhat, but
    the cloned voice can also social-engineer the read-back
  FIDO2 / WebAuthn / passkeys are the only fully phishing-resistant
    option — voice cannot mediate them

Caller-ID checks
  Caller-ID spoofing remains trivial through SIP trunks
  STIR/SHAKEN rollout has reduced but not eliminated this; the
    attestation level is rarely surfaced to end users
  Treat caller-ID as untrusted by default

"I recognised their voice"
  No longer a reliable signal at all
  The 60-second-source-audio threshold has crossed the line where
    human ear is consistently fooled in a phone-quality channel
  Train employees explicitly: "if you recognised the voice but the
    request feels off, the voice does NOT increase your confidence"

Voice-only password resets
  Banking has known this for years; enterprise helpdesk is catching up
  Any process that ends with the caller getting credential material
    based on voice ID alone is now a documented vulnerability

Liveness checks via "say a random phrase"
  Modern voice clones can read arbitrary text in near-real-time
  This control is effective against pre-recorded playback attacks but
    not against live conversion
  Useful as part of a defence stack; useless as a sole control

Generic "be vigilant" training
  Without specific scenarios, employees do not generalise from a
    poster to a real call
  Measure training effectiveness by running internal sanctioned
    phishing/vishing programmes and tracking response rates over time
```

## Real-World Cases (Public Reporting)

```
Hong Kong, Feb 2024 — HK$200M deepfake CFO video call
  Finance worker authorised 15 transfers (~US$25M) after joining a
    video meeting with a synthetic "CFO" and synthetic peers
  Lesson: video is no longer a verification channel any more than
    voice is; out-of-band callback to a known number is the control

"Fake-CEO urgent wire" — ongoing, multi-jurisdiction
  Classic BEC with synthetic voice replacing or supplementing email
  FBI IC3 tracking growth in voice-cloned variants 2024–2025
  Lesson: dual-approval workflows that touch a system, not a call

MGM Resorts / Caesars Entertainment, 2023 — service-desk vishing
  Pre-deepfake mainstream but the template since retro-fitted onto
  Vector was a phone call to IT service desk requesting password/MFA
    reset; disclosed via MGM's 8-K and trade press
  Lesson: helpdesk verification is an enterprise risk surface

Retool, Aug 2023 — vishing-after-SMS
  Attacker SMS-phished employees, then called one impersonating IT
    during the credential reset workflow; disclosed publicly
  Lesson: SMS as an MFA channel is broken

WPP, May 2024 — attempted deepfake-CEO fraud
  WhatsApp + voice + deepfake-video attempt against an executive;
    failed at the verification step
  Lesson: the control did work — out-of-band verification caught it

Recurring 2024–2025 enterprise helpdesk incidents
  Caller claims to be a named employee, uses voice that matches
    public samples, requests credential reset, helpdesk complies
  Documented in Mandiant / CrowdStrike / Unit 42 IR write-ups
```

## Detection

Detection of synthetic voice in a live call is hard. Detection of synthetic-voice-driven attacks at the procedural layer is much easier.

```
Audio forensics (limited)
  ElevenLabs Classifier, Resemble Detect, Pindrop — effective against
    known generators with artefacts; arms race lags each generator by
    months; useful as post-incident evidence, not real-time gate

Behavioural signals (operator-side)
  Script-out pivot — voice cadence shifts when improvisation begins
  Unnatural pauses while the operator reads pre-typed responses
  Inconsistent ambient sound versus claimed location
  Reluctance to switch to a video channel mid-call

Procedural-violation signals (defender-side)
  Caller request that deviates from documented procedure
  Resistance to the out-of-band callback ("I'm in a meeting")
  Time pressure that does not match a legitimate cadence
  Multiple attempts on different employees within a short window

Network and identity correlation
  Anomalous login from a new geography shortly after a service-desk
    interaction — correlate helpdesk and authentication telemetry
  MFA reset followed by sign-in from a new device within minutes
  Privilege change requested via phone, executed via ticket
```

The strongest detection posture is procedural: build the controls so that a successful synthetic-voice attack still requires the attacker to violate a logged, alertable step. Then the call itself does not need to be detected — the consequence does.

## Reporting Findings

If the technique succeeds under engagement, lead the report with the procedural failure, not the synthetic voice — frame remediation as a process change ("the wire-approval workflow accepts a single phone-based authorisation without out-of-band callback") rather than an arms race against clone quality. Demonstrate the source-audio collection to the board with the cloned sample of the impersonated party (with their post-engagement consent for replay); abstract warnings rarely land at executive level, this always does. Recommend layered controls — callback, code phrases, helpdesk procedure, training, voice biometrics for high-volume call centres — and a re-test cadence that measures "calls that triggered the callback procedure" rather than "calls that failed."

## Resources

- ElevenLabs Voice AI Safety policy and usage guidelines — `elevenlabs.io/safety`
- Resemble AI ethical use guidance — `resemble.ai/ethics`
- FBI Public Service Announcement on AI-enabled voice cloning fraud — `ic3.gov`
- CISA advisory series on deepfake-driven fraud — `cisa.gov`
- NCSC (UK) guidance on synthetic media and social engineering — `ncsc.gov.uk`
- Pindrop research reports on synthetic voice in call centres — `pindrop.com/research`
- NIST AI Risk Management Framework — `nist.gov/ai-risk-management-framework`
- MITRE ATLAS — adversarial threat landscape for AI systems — `atlas.mitre.org`
- MITRE T1656 — Impersonation — `attack.mitre.org/techniques/T1656/`
- MITRE T1598 — Phishing for Information — `attack.mitre.org/techniques/T1598/`
- Hong Kong deepfake CFO case — South China Morning Post (Feb 2024) coverage
- MGM Resorts 8-K filing (September 2023) and subsequent IR vendor write-ups
- Retool post-incident blog (August 2023) — `retool.com/blog`
- Social-Engineer.org framework — `social-engineer.org/framework/`
- Companion pages: `social-engineering/vishing.md`, `social-engineering/pretexting.md`
