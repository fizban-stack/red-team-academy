---
layout: training-page
title: "Smishing — Red Team Academy"
module: "Social Engineering"
tags:
  - smishing
  - social-engineering
  - sms
  - mobile
page_key: "se-smishing"
render_with_liquid: false
---

# Smishing

Smishing (SMS phishing) delivers malicious links or social engineering lures via text message. Mobile users apply less scrutiny to SMS than email, and many corporate security controls do not extend to personal or corporate mobile devices.

## Why Smishing is Effective

```
High open rate    — SMS open rate ~98% vs ~20% for email
Immediate         — most people read texts within 3 minutes
Less security     — no SEG, no URL rewriting, no sandbox on SMS
Short content     — less context to evaluate, easier to deceive
Personal channel  — texts feel more direct and urgent than email
```

## Infrastructure

### SMS Sending Platforms

```
Twilio            — most common, full API, requires account verification
Vonage (Nexmo)    — similar to Twilio
AWS SNS           — bulk SMS, good deliverability
TextNow / Google Voice — consumer-grade, limited but no verification
SIM card + modem  — physical SIM for authentic carrier origination

# Twilio example — send SMS
from twilio.rest import Client
client = Client(account_sid, auth_token)
message = client.messages.create(
    body="Your package could not be delivered. Reschedule: https://short.url/abc",
    from_="+15551234567",
    to="+15559876543"
)
```

### Sender ID Spoofing

```
# In many countries, alphanumeric sender IDs can be set freely:
# "FedEx", "USPS", "Apple", "Chase"

# US: Carrier filtering makes spoofing harder — use 10DLC or toll-free numbers
# UK/EU: Alphanumeric sender IDs are easier to set

# Legitimate-looking numbers
# Purchase a number matching target's area code for local trust
# Use a number starting with a known carrier prefix
```

## Lure Templates

### Package Delivery

```
FedEx: Your package (ID: FX847291) could not be delivered.
Schedule redelivery: https://fedex-redeliver.attacker.com
```

### Bank / Financial

```
Chase: Unusual activity detected on your account ending in 4821.
Verify now to avoid suspension: https://chase-secure.attacker.com
```

### Corporate IT

```
IT Security: Your VPN certificate expires today. Renew immediately
to maintain remote access: https://vpn-renew.corp-attacker.com
```

### MFA / OTP Capture

```
[Company] Security: We detected a sign-in from a new device.
If this wasn't you, secure your account: https://attacker.com/verify

# Landing page captures credentials
# Then in real-time, use captured creds to trigger real MFA
# Call or text again to "confirm the code we just sent you"
```

### Executive Impersonation

```
[CEO Name]: Hey, are you available? I'm in a meeting and need
you to handle something urgent for me. Reply YES.
```

## Link Shortening & Evasion

```
# Use URL shorteners to hide domain
bit.ly, tinyurl.com, t.ly — but many are now flagged

# Self-hosted shortener
yourls.org — self-hosted URL shortener
# Register a short, credible domain: pkg-dlv.com, acct-sec.com

# Use legitimate redirect services
https://www.google.com/url?q=https://attacker.com/
https://t.co/ (Twitter shortener) — high trust

# Landing page should be mobile-optimized
# HTTPS required (HTTP raises browser warning on mobile)
```

## Targeting

```
# Obtain mobile numbers from:
LinkedIn — sometimes listed on profiles
OSINT tools — Spokeo, Whitepages, BeenVerified
Data breaches — many include mobile numbers
Company directories — some publish DID/mobile for employees
Conference registrations — sometimes leaked or accessible
```

## Operational Notes

```
# Timing
Send during business hours — 9am-6pm target timezone
Avoid weekends for corporate lures

# Volume
Carrier filtering triggers on high volume from a single number
Use multiple numbers or stagger sends for larger campaigns

# Landing page
Mobile-optimized — large form fields, minimal scrolling
Fast-loading — mobile users abandon slow pages
Match the brand exactly — logo, colors, font, layout
```

---

## Advanced Evasion

### Carrier Filtering and 10DLC

US mobile carriers (AT&T, Verizon, T-Mobile) use The Campaign Registry (TCR) to filter unregistered bulk SMS. Messages from unregistered numbers with certain patterns are blocked or throttled.

```
10DLC (10-Digit Long Code) — standard US local numbers
  - Must be registered with TCR before sending campaigns
  - Requires: brand registration + campaign registration + use case declaration
  - Cost: ~$4/month for brand + ~$10/month per campaign
  - Legitimate path — carriers will not block registered campaigns
  - Red team note: registration requires a real business identity; use with caution

Toll-free numbers (800, 888, 877 etc.)
  - Separate registration path — toll-free verification (TFV)
  - Better deliverability for bulk sends than unregistered 10DLC
  - Higher perceived authority ("only real companies use toll-free numbers")

Short codes (5–6 digit numbers e.g. 12345)
  - Highest deliverability, highest cost (~$500–1000/month)
  - Requires carrier approval — not practical for red teams
  - Useful context: real banks and delivery services use short codes
    → your smishing page should note "this is different from their real short code"

Bypass techniques for testing (unregistered):
  - P2P messaging — send as person-to-person, low volume (under 200/day per number)
  - Physical SIM + modem — carrier treats as organic P2P traffic
  - Multiple numbers — rotate sending numbers to stay under filtering thresholds
  - Conversational opening — "Hey, is this [name]?" before the payload text
    reduces filter confidence
```

### International Sending

```
UK / EU:
  Alphanumeric sender IDs freely settable via Vonage, Twilio
  "FedEx", "HSBC", "HMRC" as sender ID — no carrier registration required
  HMRC / NHS lures are extremely effective in UK

India / Southeast Asia:
  Transactional SMS (DLT registration required for commercial)
  Promotional SMS has restrictions; P2P largely unrestricted

Australia:
  Australian Communications and Media Authority (ACMA) rules
  Alphanumeric sender IDs allowed; carrier filtering less aggressive than US
```

---

## Multi-Stage Smishing Campaigns

Single-message smishing is detectable and low-trust. Multi-stage campaigns build credibility before delivering the payload.

### Stage 1: Establish Contact (Day 1)

```
Message: "Hi [Name], this is [PersonaName] from [Company] HR.
          Is this still the best number to reach you on?"

Purpose: Confirm the number is active; begin building rapport
Target response: "Yes, who is this?" or "Yes" — either opens stage 2
```

### Stage 2: Build Trust (Day 1–2)

```
Message: "Thanks for confirming. I'm following up about the benefits
          enrolment window — it closes this Friday and your file shows
          as incomplete. I'll send you the link in a moment."

Purpose: Establish urgency and legitimacy before sending the link
Technique: Reference a real HR process; use first name from OSINT
```

### Stage 3: Payload Delivery (Day 2–3)

```
Message: "Here's the benefits portal link — should only take 2 minutes:
          https://corp-benefits-enroll.attacker.com

          If you have any issues logging in just reply here."

Purpose: Credential capture on mobile-optimized landing page
Follow-up: If no click after 24h, send a reminder ("Hi, just checking
           you got my previous message — portal closes tomorrow")
```

### Campaign Flow Diagram

```
[Number confirmed] → [Rapport established] → [Urgency introduced]
      → [Link delivered] → [Credential captured] → [OTP relay if needed]
```

---

## iOS vs Android Delivery Differences

Understanding platform differences affects link format, landing page design, and detection probability.

### iOS

```
Link preview:    iOS shows a preview card for URLs (can reveal domain)
Safari warnings: "This website may be harmful" for known phishing domains
iMessage:        Not SMS — uses Apple's network; blue bubble, E2E encrypted
                 iMessage links open in Safari with Safe Browsing enabled
SMS:             Grey bubble — uses carrier network; less filtering than iMessage
Universal Links: iOS will prompt to open URLs in native apps
                 (bank link may open the bank's app instead of Safari)

Recommendations for iOS targeting:
  - Use fresh domains not yet in Google Safe Browsing
  - Consider using a redirect chain (legitimate site → attacker site)
  - Mobile landing page must pass iOS Safe Browsing check
  - Use https:// — http:// triggers a browser warning since iOS 12
```

### Android

```
Link preview:    Less aggressive preview — URL usually shown as plain text
Google Safe Browsing: Built into Chrome, checks URLs against Google's blocklist
RCS (Rich Communication Services): Android's iMessage equivalent
  - Carrier-controlled; some carriers filter RCS URLs
  - Most smishing still uses traditional SMS on Android

Recommendations for Android targeting:
  - Landing pages should load fast (Android users expect speed)
  - Chrome on Android shows site identity prominently — use credible domain
  - Test landing page in Chrome Android before campaign launch
  - APK delivery possible on Android (iOS does not allow sideloading)
    → deliver .apk for spyware/RAT delivery in high-value engagements
```

---

## OTP Relay Attacks

Real-time MFA interception via smishing combines credential capture with live OTP relay. The attacker captures the victim's credentials and OTP simultaneously while the victim is interacting with the phishing page.

### How OTP Relay Works

```
Step 1: Victim receives smishing link
Step 2: Victim enters credentials on the phishing landing page
Step 3: Attacker receives credentials in real time
Step 4: Attacker immediately enters credentials at the real login page
Step 5: Real site sends OTP to victim's phone
Step 6: Phishing landing page shows "Please enter the verification code we sent you"
Step 7: Victim enters OTP on phishing page
Step 8: Attacker receives OTP and enters it at the real site
Step 9: Attacker gains authenticated session with active cookie
```

### Tools for OTP Relay

```
Evilginx:
  - Reverse proxy — victim's browser talks to real site through attacker's server
  - Captures credentials AND session cookie automatically
  - No manual relay needed — fully automated AiTM
  - See: se-tools.md for Evilginx setup

Manual relay (for custom targets not covered by Evilginx phishlets):
  - Build a custom landing page that mirrors the real login flow
  - Use WebSockets or server-sent events to push victim input to attacker panel
  - Attacker panel shows real-time form submissions and prompts for next step
  - Operator relays OTP manually within the 30-second TOTP window

Modlishka:
  - Similar to Evilginx — configurable reverse proxy
  - Less pre-built phishlets but more flexible for custom targets
```

### OTP Relay Limitations

```
FIDO2 / WebAuthn (hardware keys, passkeys):
  - Cryptographically bound to the real domain
  - Will NOT work on a phishing domain — authentication fails at step 4
  - This is the only MFA that defeats AiTM phishing

Push notification MFA (Duo Push, Microsoft Authenticator):
  - Relay works — victim approves the push notification not knowing it's real
  - "MFA fatigue" attack: send repeated push notifications until victim approves

SMS OTP / TOTP apps (Google Authenticator, Authy):
  - Relay works with the manual or automated relay flow above
  - 30-second window for TOTP — attacker must act fast
```

---

## Metrics and Campaign Management

### Key Metrics to Track

```
Delivery rate    = messages delivered / messages sent
                   (low rate = carrier filtering; rotate numbers)

Open rate        = not directly measurable for SMS
                   (approximate: replies + link clicks / delivered)

Click rate       = link clicks / delivered
                   (track via unique per-target URLs or URL shortener analytics)

Credential rate  = credential submissions / link clicks
                   (low rate = landing page issue or device/browser incompatibility)

OTP relay rate   = OTPs captured / credential submissions
                   (measures real-time interception success)

Reporting rate   = targets who reported the smish to security / total targeted
                   (blue team metric — want this high for trained employees)
```

### Campaign Management

```bash
# Track using a simple campaign spreadsheet or GoPhish group management
# CSV format for target management:
# phone,name,department,sent,clicked,submitted,reported

# Per-target unique URLs (using YOURLS or custom redirector)
# Generate: https://track.attacker.com/s/?id=<unique_id>
# Log clicks with timestamp, IP, user-agent

# YOURLS — self-hosted short links with click tracking
# Install: https://yourls.org/
# Configure in config.php, then access admin at /admin/
```

---

## Resources

- MITRE T1660 — Phishing — Mobile — `attack.mitre.org/techniques/T1660/`
- Twilio SMS API — `twilio.com/docs/sms`
- YOURLS — self-hosted URL shortener — `yourls.org`
- The Campaign Registry (TCR) — 10DLC registration — `campaignregistry.com`
- Evilginx — AiTM phishing framework — `github.com/kgretzky/evilginx2`
- Vonage SMS API — `developer.vonage.com/messaging/sms/overview`
