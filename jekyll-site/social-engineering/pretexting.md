---
layout: training-page
title: "Pretexting Scenarios — Red Team Academy"
module: "Social Engineering"
tags:
  - pretexting
  - social-engineering
  - impersonation
  - vishing
page_key: "se-pretexting"
---
<h1>Pretexting Scenarios</h1>
<p>A pretext is the fabricated identity and scenario used to make a social engineering attack believable. The quality of your pretext determines whether the target complies or becomes suspicious. Good pretexts are researched, specific, and require minimal effort from the target.</p>

<h2>Pretext Development Framework</h2>
<pre><code>1. Identify the objective  — what do you need? credentials, access, info?
2. Select the persona      — who would plausibly make this request?
3. Research the context    — org structure, tool names, process names
4. Build the scenario      — why now? why urgent? what happens if ignored?
5. Prepare objection handling — what if they verify? push back? ask questions?
6. Test on a peer          — does it sound believable out loud?</code></pre>

<h2>High-Yield Pretexts</h2>

<h3>IT Helpdesk / Password Reset</h3>
<pre><code>Persona:   Internal IT support or outsourced helpdesk
Lure:      "We're rolling out MFA / system upgrades and need to verify your account"
Ask:       Current credentials, MFA code, or click link to "verify"
Works because: IT helpdesk contacts are expected, authority is implied
Research needed: Helpdesk name, ticketing system name (ServiceNow, Jira, etc.)</code></pre>

<h3>Executive / BEC (Business Email Compromise)</h3>
<pre><code>Persona:   CFO, CEO, or executive assistant
Lure:      Urgent wire transfer, gift card purchase, payroll change
Ask:       Wire funds, provide banking details, update payroll info
Works because: Employees defer to executives; urgency overrides caution
Research needed: Executive names, reporting structure, travel schedule (for "I'm abroad")</code></pre>

<h3>HR / Payroll Notification</h3>
<pre><code>Persona:   HR department or payroll provider (ADP, Workday, Paycom)
Lure:      "Update your direct deposit before the next pay cycle"
Ask:       Banking details or login to HR portal
Works because: Paycheck is high-priority; employees act fast
Research needed: Payroll provider name, HR contact names, pay schedule</code></pre>

<h3>Vendor / Third-Party Supplier</h3>
<pre><code>Persona:   Known vendor, software vendor, or contractor
Lure:      Invoice dispute, contract renewal, or urgent support request
Ask:       Login to vendor portal, run a tool, provide network access
Works because: Vendor relationships are assumed; third parties are trusted
Research needed: Active vendor relationships (check LinkedIn, job postings, press releases)</code></pre>

<h3>Security / Compliance Notification</h3>
<pre><code>Persona:   Internal security team, compliance, or external auditor
Lure:      "Your account showed suspicious activity — verify immediately"
Ask:       Click link to verify, provide current credentials, run scan tool
Works because: Fear of consequences; security messages carry urgency
Research needed: Security team names, SIEM/tool names used internally</code></pre>

<h3>IT Asset / Software Deployment</h3>
<pre><code>Persona:   IT operations or MSP
Lure:      "Required security patch / VPN client update needs to be installed"
Ask:       Run the attached installer, click link to download
Works because: Software updates are routine and expected
Research needed: IT tool names (CrowdStrike, Tanium, SCCM, Intune), MSP name</code></pre>

<h2>Building Believability</h2>
<h3>Research Sources</h3>
<pre><code>LinkedIn     — org chart, employee names, roles, tenure, tools mentioned
Job postings — technology stack, internal tool names, team structure
Press releases — vendor partnerships, mergers, new systems
GitHub       — internal tooling, employee handles, leaked config
Twitter/X    — employee complaints about tools reveal tool names
Glassdoor    — internal processes, interview questions reveal workflows</code></pre>

<h3>Specificity Signals Trust</h3>
<pre><code>Weak:   "We're updating our systems and need your password."
Strong: "Hi Sarah, I'm calling from the ServiceNow team — we're migrating
         your Contoso account from v7 to the new ITSM portal ahead of the
         Q2 deadline. I need to verify your current login before we transfer
         your open tickets."</code></pre>

<h2>Objection Handling</h2>
<pre><code>Objection: "I need to verify who you are."
Response:  "Absolutely — you can call back on [spoofed/legit number] and ask
            for ticket #INC-48821. I'll be here until 5."

Objection: "I need to check with my manager."
Response:  "Of course — just keep in mind the maintenance window closes at
            midnight and we won't be able to migrate your account without
            this step. But your call."

Objection: "We don't give passwords over the phone."
Response:  "Understood, that's exactly right — I'm not asking for your
            password. I just need you to click this verification link so
            the system can confirm your session token."

Objection: "Can you send an email instead?"
Response:  "I just sent it — check your inbox, subject line starts with
            [IT] Account Migration — let me know when you see it."</code></pre>

<h2>Pretext Research Checklist</h2>
<pre><code>[ ] Employee names and roles confirmed (LinkedIn)
[ ] Internal tool names identified (job postings, GitHub)
[ ] Email format confirmed (hunter.io, email permutator)
[ ] Known vendors identified (LinkedIn, press releases)
[ ] Relevant events researched (mergers, product launches, audits)
[ ] Legitimate contact names available for credibility anchors
[ ] Callback number or email ready for verification requests</code></pre>

<h2>Resources</h2>
<ul>
  <li>MITRE T1656 — Impersonation — <code>attack.mitre.org/techniques/T1656/</code></li>
  <li>Hunter.io — email format discovery — <code>hunter.io</code></li>
  <li>The Art of Human Hacking — Christopher Hadnagy</li>
  <li>Social Engineering: The Science of Human Hacking — Christopher Hadnagy</li>
</ul>
