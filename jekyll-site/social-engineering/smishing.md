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
---
<h1>Smishing</h1>
<p>Smishing (SMS phishing) delivers malicious links or social engineering lures via text message. Mobile users apply less scrutiny to SMS than email, and many corporate security controls do not extend to personal or corporate mobile devices.</p>

<h2>Why Smishing is Effective</h2>
<pre><code>High open rate    — SMS open rate ~98% vs ~20% for email
Immediate         — most people read texts within 3 minutes
Less security     — no SEG, no URL rewriting, no sandbox on SMS
Short content     — less context to evaluate, easier to deceive
Personal channel  — texts feel more direct and urgent than email</code></pre>

<h2>Infrastructure</h2>
<h3>SMS Sending Platforms</h3>
<pre><code>Twilio            — most common, full API, requires account verification
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
)</code></pre>

<h3>Sender ID Spoofing</h3>
<pre><code># In many countries, alphanumeric sender IDs can be set freely:
# "FedEx", "USPS", "Apple", "Chase"

# US: Carrier filtering makes spoofing harder — use 10DLC or toll-free numbers
# UK/EU: Alphanumeric sender IDs are easier to set

# Legitimate-looking numbers
# Purchase a number matching target's area code for local trust
# Use a number starting with a known carrier prefix</code></pre>

<h2>Lure Templates</h2>
<h3>Package Delivery</h3>
<pre><code>FedEx: Your package (ID: FX847291) could not be delivered.
Schedule redelivery: https://fedex-redeliver.attacker.com</code></pre>

<h3>Bank / Financial</h3>
<pre><code>Chase: Unusual activity detected on your account ending in 4821.
Verify now to avoid suspension: https://chase-secure.attacker.com</code></pre>

<h3>Corporate IT</h3>
<pre><code>IT Security: Your VPN certificate expires today. Renew immediately
to maintain remote access: https://vpn-renew.corp-attacker.com</code></pre>

<h3>MFA / OTP Capture</h3>
<pre><code">[Company] Security: We detected a sign-in from a new device.
If this wasn't you, secure your account: https://attacker.com/verify

# Landing page captures credentials
# Then in real-time, use captured creds to trigger real MFA
# Call or text again to "confirm the code we just sent you"</code></pre>

<h3>Executive Impersonation</h3>
<pre><code>[CEO Name]: Hey, are you available? I'm in a meeting and need
you to handle something urgent for me. Reply YES.</code></pre>

<h2>Link Shortening &amp; Evasion</h2>
<pre><code># Use URL shorteners to hide domain
bit.ly, tinyurl.com, t.ly — but many are now flagged

# Self-hosted shortener
yourls.org — self-hosted URL shortener
# Register a short, credible domain: pkg-dlv.com, acct-sec.com

# Use legitimate redirect services
https://www.google.com/url?q=https://attacker.com/
https://t.co/ (Twitter shortener) — high trust

# Landing page should be mobile-optimized
# HTTPS required (HTTP raises browser warning on mobile)</code></pre>

<h2>Targeting</h2>
<pre><code># Obtain mobile numbers from:
LinkedIn — sometimes listed on profiles
OSINT tools — Spokeo, Whitepages, BeenVerified
Data breaches — many include mobile numbers
Company directories — some publish DID/mobile for employees
Conference registrations — sometimes leaked or accessible</code></pre>

<h2>Operational Notes</h2>
<pre><code># Timing
Send during business hours — 9am-6pm target timezone
Avoid weekends for corporate lures

# Volume
Carrier filtering triggers on high volume from a single number
Use multiple numbers or stagger sends for larger campaigns

# Landing page
Mobile-optimized — large form fields, minimal scrolling
Fast-loading — mobile users abandon slow pages
Match the brand exactly — logo, colors, font, layout</code></pre>

<h2>Resources</h2>
<ul>
  <li>MITRE T1660 — Phishing — Mobile — <code>attack.mitre.org/techniques/T1660/</code></li>
  <li>Twilio SMS API — <code>twilio.com/docs/sms</code></li>
  <li>YOURLS — self-hosted URL shortener — <code>yourls.org</code></li>
</ul>
