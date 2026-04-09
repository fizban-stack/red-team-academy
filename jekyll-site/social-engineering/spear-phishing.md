---
layout: training-page
title: "Spear Phishing — Red Team Academy"
module: "Social Engineering"
tags:
  - spear-phishing
  - social-engineering
  - targeted-attack
  - initial-access
page_key: "se-spear-phishing"
---
<h1>Spear Phishing</h1>
<p>Spear phishing is highly targeted phishing personalized to a specific individual using intelligence gathered during reconnaissance. Where mass phishing relies on volume, spear phishing relies on relevance — a believable email from a known sender about something the target actually cares about.</p>

<h2>Target Selection</h2>
<pre><code># High-value targets (most likely to have access worth stealing):
IT administrators        — VPN, AD, cloud console credentials
Finance / accounting     — wire transfer authority, banking access
HR                       — employee PII, payroll system access
Executives               — email access, approval authority (BEC)
Help desk                — can reset passwords, grant access
DevOps / engineering     — code repos, CI/CD, cloud infrastructure

# Soft targets (less security-aware, more likely to click):
New employees            — unfamiliar with processes, eager to comply
Remote workers           — less oversight, used to receiving IT emails
Contractors              — less trained, less integrated with security culture</code></pre>

<h2>Target Profiling Workflow</h2>
<pre><code># 1. Find the target on LinkedIn
#    - Current role, tenure, recent activity, connections
#    - What tools/platforms they mention ("Excited to start using Salesforce")
#    - Who they report to, who reports to them

# 2. Check social media (Twitter/X, Facebook)
#    - Personal interests for rapport-building lures
#    - Travel / OOO patterns ("Flying to NYC for the conference")
#    - Complaints about work tools (reveals stack)

# 3. Search for email address
theHarvester -d target-corp.com -b all
# Or use hunter.io, clearbit, email format permutation

# 4. Check data breach databases
# haveibeenpwned.com — check if target email is in breaches
# DeHashed, Snusbase — breach search with password history

# 5. Review GitHub / public repos
# Look for commits with target's email, personal repos, leaked credentials

# 6. Check company website, press releases, blog posts
#    - Recent projects, partnerships, technology decisions</code></pre>

<h2>Lure Personalization Techniques</h2>
<h3>Context-Aware Lures</h3>
<pre><code># Use recent events the target would recognize
"Hi [Name], following up on the Salesforce migration we discussed at
 [Company] All-Hands last week — the IT team needs your confirmation
 before we can migrate your account."

# Reference their manager by name
"[Manager name] asked me to reach out to you directly about the
 pending access review for your team."

# Reference their current project (from LinkedIn/GitHub)
"Regarding the Azure migration project your team is working on —
 there's a required security configuration step before go-live."

# Use their timezone / location context
"Hi [Name], I noticed you logged in from [city] earlier today — our
 system flagged this as unusual. Please verify your identity."</code></pre>

<h3>Sender Spoofing &amp; Impersonation</h3>
<pre><code># Spoof a known internal contact (requires bypassing DMARC or using lookalike)
From: "John Smith (IT)" &lt;jsmith@c0ntoso.com&gt;

# Compromise a real account and use it (internal spearphishing - T1534)
# Most effective — emails come from legitimate domain with no spoofing

# Use a display name match to a known contact
From: "Sarah Johnson" &lt;noreply@helpdesk-portal.com&gt;
# Target sees "Sarah Johnson" in mail client, may not check address

# Reply-chain injection — reply to a real existing email thread
# Requires knowing the thread context (from OSINT or prior access)</code></pre>

<h2>Multi-Stage Spear Phishing</h2>
<pre><code># Stage 1: Rapport building email (no malicious content)
"Hi [Name], I'm [Persona] reaching out about [legitimate topic].
 Would you have 15 minutes to connect this week?"

# Stage 2: Follow-up with payload after reply
"Great speaking with you — as mentioned, here's the document
 we discussed. Let me know if you have any issues accessing it."

# This works because:
# - Target is expecting an email from you
# - They've already engaged once (lowered guard)
# - SEGs may whitelist the sender after the first benign exchange</code></pre>

<h2>Delivery via Third-Party Platforms</h2>
<pre><code># LinkedIn InMail
# — High trust, professional context, bypasses email security entirely
# — "Saw your profile — I work with [mutual connection] and wanted to share..."

# Microsoft Teams / Slack (external messaging)
# — If tenant allows external messages
# — Impersonate a vendor or partner
# — See T1566.003 — Spear Phishing via Service

# SMS (Smishing)
# — Harder to verify sender, direct to mobile
# — See smishing page for details

# Phone call (Vishing)
# — After email to warm the target
# — "I sent you an email earlier — did you get a chance to look at it?"</code></pre>

<h2>Spear Phishing Checklist</h2>
<pre><code>[ ] Target profiled — role, tools, manager, recent activity
[ ] Lure personalized with at least 2 specific details
[ ] Sender identity chosen and configured
[ ] Email passes SPF, DKIM, DMARC
[ ] Landing page or attachment ready and tested
[ ] Tracking pixel or unique link configured
[ ] Objection handling prepared
[ ] Timing selected — Tuesday-Thursday 9-11am best open rates</code></pre>

<h2>Resources</h2>
<ul>
  <li>MITRE T1566.001 — Spear Phishing Attachment — <code>attack.mitre.org/techniques/T1566/001/</code></li>
  <li>MITRE T1566.002 — Spear Phishing Link — <code>attack.mitre.org/techniques/T1566/002/</code></li>
  <li>MITRE T1566.003 — Spear Phishing via Service — <code>attack.mitre.org/techniques/T1566/003/</code></li>
  <li>theHarvester — email harvesting — <code>github.com/laramies/theHarvester</code></li>
  <li>hunter.io — email format discovery</li>
</ul>
