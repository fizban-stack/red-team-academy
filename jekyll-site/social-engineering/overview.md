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
---
<h1>Social Engineering Overview &amp; Methodology</h1>
<p>Social engineering exploits human psychology rather than technical vulnerabilities. It is consistently one of the most effective initial access vectors — a convincing email or phone call bypasses every firewall, EDR, and patch cycle.</p>

<h2>Attack Lifecycle</h2>
<pre><code>1. Intelligence Gathering  — OSINT, org mapping, target profiling
2. Pretext Development     — cover story, persona, lure design
3. Infrastructure Build    — domains, mail servers, landing pages
4. Delivery                — email, phone, SMS, in-person
5. Exploitation            — credential capture, payload execution, access
6. Follow-through          — maintain trust, pivot, escalate</code></pre>

<h2>Attack Categories</h2>
<h3>Phishing Variants</h3>
<pre><code>Phishing         — mass email, untargeted
Spear phishing   — targeted, personalized to the individual
Whaling          — C-suite and high-value executives
Vishing          — voice / phone calls
Smishing         — SMS text messages
Internal phishing — from a compromised internal account (T1534)</code></pre>

<h3>Pretexting</h3>
<p>Creating a fabricated scenario to justify the request. Common pretexts:</p>
<ul>
  <li>IT helpdesk — "We need to verify your credentials after a system update"</li>
  <li>Executive assistant — "The CEO needs this urgent wire transfer approved"</li>
  <li>Vendor / contractor — calling to schedule on-site access</li>
  <li>HR / payroll — "Update your direct deposit details before Friday"</li>
  <li>Security team — "Your account flagged suspicious login activity"</li>
</ul>

<h2>Psychological Principles (Cialdini)</h2>
<pre><code>Authority    — impersonate IT, management, legal, government
Urgency      — "your account will be suspended in 2 hours"
Scarcity     — "only 3 slots remaining for mandatory training"
Social proof — "everyone on your team has already completed this"
Reciprocity  — provide something useful before making the ask
Liking       — build rapport, mirror communication style
Fear         — consequences of inaction (account lockout, audit finding)</code></pre>

<h2>SE in the Kill Chain</h2>
<pre><code>Recon ──► Weaponize ──► Deliver (SE) ──► Exploit ──► Install ──► C2 ──► Actions
                              │
                   Phishing / Vishing / Smishing
                   Pretexting / Impersonation
                   Physical access attempts</code></pre>

<h2>MITRE ATT&amp;CK Coverage</h2>
<pre><code>TA0001 — Initial Access
  T1566     Phishing
  T1566.001 Spear Phishing Attachment
  T1566.002 Spear Phishing Link
  T1566.003 Spear Phishing via Service (Teams, Slack, LinkedIn)
  T1598     Phishing for Information (credential harvesting)
  T1534     Internal Spearphishing (post-compromise)
  T1656     Impersonation</code></pre>

<h2>Engagement Planning Checklist</h2>
<pre><code>[ ] Scope defined — what channels, targets, and actions are permitted
[ ] Objective clear — credentials, payload delivery, physical badge, info exfil
[ ] Rules of engagement — can you spoof internal domains? impersonate employees?
[ ] OSINT phase complete — org chart, email format, tooling identified
[ ] Pretext developed and reviewed
[ ] Infrastructure built and tested
[ ] Deliverability tested — spam score, SPF/DKIM/DMARC configured
[ ] Deconfliction — blue team notified if purple team exercise
[ ] Metrics defined — click rate, submission rate, callback rate, time-to-click</code></pre>

<h2>Success Metrics</h2>
<pre><code>Click rate           — % of targets who clicked the link
Credential rate      — % who submitted credentials
Payload execution    — % who ran the attachment
Callback rate        — % who called the vishing number
Reporting rate       — % who reported the phishing to security (blue metric)
Time-to-first-click  — how quickly the campaign gets a hit</code></pre>

<h2>Resources</h2>
<ul>
  <li>MITRE ATT&amp;CK Initial Access — <code>attack.mitre.org/tactics/TA0001/</code></li>
  <li>Social Engineer Framework — <code>www.social-engineer.org/framework/</code></li>
  <li>Influence: The Psychology of Persuasion — Robert Cialdini</li>
  <li>The Art of Intrusion / The Art of Deception — Kevin Mitnick</li>
</ul>
