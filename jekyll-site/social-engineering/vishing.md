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
---
<h1>Vishing</h1>
<p>Vishing (voice phishing) uses phone calls to manipulate targets into revealing credentials, transferring funds, or taking actions that compromise security. It is often more effective than email phishing because people apply less scrutiny to phone calls and feel greater social pressure to comply in real time.</p>

<h2>Why Vishing Works</h2>
<pre><code>Real-time pressure    — target can't pause to think as easily as with email
Authority signals     — tone of voice conveys confidence and authority
Harder to verify      — fewer cues to check than a suspicious email link
Rapport building      — voice creates personal connection faster than text
Urgency is amplified  — spoken urgency is more compelling than written</code></pre>

<h2>Infrastructure</h2>
<h3>Caller ID Spoofing</h3>
<pre><code># Services for spoofed outbound calls
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
)</code></pre>

<h3>Voice Changers / Modifiers</h3>
<pre><code>Clownfish Voice Changer   — real-time pitch/gender shift
MorphVOX Pro              — real-time voice transformation
AV Voice Changer          — multiple voice profiles
ElevenLabs                — AI voice cloning (ethical concerns — confirm scope)

# Use cases:
# - Male-presenting caller using female voice for IT persona
# - Pitch adjustment to sound older/more authoritative
# - Background noise injection (call center ambience)</code></pre>

<h2>Call Scripts</h2>
<h3>IT Helpdesk Password Reset</h3>
<pre><code>"Hi, this is [name] from the IT helpdesk — ticket number INC-48821.
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
that the migration window closes at midnight tonight."</code></pre>

<h3>Verification / Security Alert</h3>
<pre><code>"Hi [Name], this is [name] from the security operations team.
We've detected some unusual activity on your account — looks like
there was a login attempt from [foreign country] about 20 minutes ago.

I need to verify a few things to confirm it wasn't you.
Can you confirm the last four digits of your employee ID?

[After confirmation]
Thanks. Now I'm going to send a verification code to your mobile —
can you read that back to me when you get it?

[This captures the MFA/OTP code in real time]"</code></pre>

<h3>Executive Impersonation (BEC)</h3>
<pre><code>"Hi [Name], this is [CEO name]'s assistant calling.
[CEO] is in a board meeting and asked me to reach out urgently —
there's a wire transfer that needs to be processed today to close
the [acquisition/deal]. I'm going to send you the details by email
in a few minutes. Can you confirm you're available to action this
this afternoon?

[After yes]
Perfect. He specifically asked this be kept confidential until the
announcement next week. I'll have the email to you within five minutes."</code></pre>

<h2>Real-Time MFA Capture</h2>
<pre><code># AiTM phishing (automated) is preferred, but manual vishing can capture OTPs:

# Scenario: Target believes they're verifying their account
# Attacker simultaneously:
# 1. Enters target's credentials into the real login page
# 2. Real site sends MFA code to target's phone
# 3. Attacker (on call) asks target to "read the verification code we just sent"
# 4. Target reads OTP — attacker enters it to complete authentication

# This works against TOTP, SMS OTP, and push-notification MFA
# Does NOT work against FIDO2/WebAuthn hardware keys (phishing-resistant)</code></pre>

<h2>Handling Resistance</h2>
<pre><code>Target: "I'm not comfortable sharing that over the phone."
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
           security team. Have a good day." [Terminate immediately]</code></pre>

<h2>Operational Notes</h2>
<pre><code># Best times to call
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
Log time, target name, result, script used</code></pre>

<h2>Resources</h2>
<ul>
  <li>MITRE T1598 — Phishing for Information — <code>attack.mitre.org/techniques/T1598/</code></li>
  <li>Twilio — programmable voice API — <code>twilio.com</code></li>
  <li>FreePBX — open source PBX — <code>freepbx.org</code></li>
  <li>Social Engineering: The Science of Human Hacking — Christopher Hadnagy</li>
  <li>SEORG Podcast — Social-Engineer.org</li>
</ul>
