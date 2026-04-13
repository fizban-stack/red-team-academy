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
render_with_liquid: false
---

# Pretexting Scenarios

A pretext is the fabricated identity and scenario used to make a social engineering attack believable. The quality of your pretext determines whether the target complies or becomes suspicious. Good pretexts are researched, specific, and require minimal effort from the target.

## Pretext Development Framework

```
1. Identify the objective  — what do you need? credentials, access, info?
2. Select the persona      — who would plausibly make this request?
3. Research the context    — org structure, tool names, process names
4. Build the scenario      — why now? why urgent? what happens if ignored?
5. Prepare objection handling — what if they verify? push back? ask questions?
6. Test on a peer          — does it sound believable out loud?
```

## High-Yield Pretexts

### IT Helpdesk / Password Reset

```
Persona:   Internal IT support or outsourced helpdesk
Lure:      "We're rolling out MFA / system upgrades and need to verify your account"
Ask:       Current credentials, MFA code, or click link to "verify"
Works because: IT helpdesk contacts are expected, authority is implied
Research needed: Helpdesk name, ticketing system name (ServiceNow, Jira, etc.)
```

### Executive / BEC (Business Email Compromise)

```
Persona:   CFO, CEO, or executive assistant
Lure:      Urgent wire transfer, gift card purchase, payroll change
Ask:       Wire funds, provide banking details, update payroll info
Works because: Employees defer to executives; urgency overrides caution
Research needed: Executive names, reporting structure, travel schedule (for "I'm abroad")
```

### HR / Payroll Notification

```
Persona:   HR department or payroll provider (ADP, Workday, Paycom)
Lure:      "Update your direct deposit before the next pay cycle"
Ask:       Banking details or login to HR portal
Works because: Paycheck is high-priority; employees act fast
Research needed: Payroll provider name, HR contact names, pay schedule
```

### Vendor / Third-Party Supplier

```
Persona:   Known vendor, software vendor, or contractor
Lure:      Invoice dispute, contract renewal, or urgent support request
Ask:       Login to vendor portal, run a tool, provide network access
Works because: Vendor relationships are assumed; third parties are trusted
Research needed: Active vendor relationships (check LinkedIn, job postings, press releases)
```

### Security / Compliance Notification

```
Persona:   Internal security team, compliance, or external auditor
Lure:      "Your account showed suspicious activity — verify immediately"
Ask:       Click link to verify, provide current credentials, run scan tool
Works because: Fear of consequences; security messages carry urgency
Research needed: Security team names, SIEM/tool names used internally
```

### IT Asset / Software Deployment

```
Persona:   IT operations or MSP
Lure:      "Required security patch / VPN client update needs to be installed"
Ask:       Run the attached installer, click link to download
Works because: Software updates are routine and expected
Research needed: IT tool names (CrowdStrike, Tanium, SCCM, Intune), MSP name
```

## Building Believability

### Research Sources

```
LinkedIn     — org chart, employee names, roles, tenure, tools mentioned
Job postings — technology stack, internal tool names, team structure
Press releases — vendor partnerships, mergers, new systems
GitHub       — internal tooling, employee handles, leaked config
Twitter/X    — employee complaints about tools reveal tool names
Glassdoor    — internal processes, interview questions reveal workflows
```

### Specificity Signals Trust

```
Weak:   "We're updating our systems and need your password."
Strong: "Hi Sarah, I'm calling from the ServiceNow team — we're migrating
         your Contoso account from v7 to the new ITSM portal ahead of the
         Q2 deadline. I need to verify your current login before we transfer
         your open tickets."
```

## Objection Handling

```
Objection: "I need to verify who you are."
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
            [IT] Account Migration — let me know when you see it."
```

## Pretext Research Checklist

```
[ ] Employee names and roles confirmed (LinkedIn)
[ ] Internal tool names identified (job postings, GitHub)
[ ] Email format confirmed (hunter.io, email permutator)
[ ] Known vendors identified (LinkedIn, press releases)
[ ] Relevant events researched (mergers, product launches, audits)
[ ] Legitimate contact names available for credibility anchors
[ ] Callback number or email ready for verification requests
```

---

## Building a Believable Persona

A well-constructed persona holds up under scrutiny. Weak personas collapse the moment a target asks a basic verification question.

### Core Persona Elements

```
Full name:      Choose a plausible name for the role/company
Email address:  Register a domain that matches your cover (support@corp-helpdesk.com)
Phone number:   Use Twilio or a VoIP number matching the target's area code
LinkedIn:       A 2–3 year old profile with 100+ connections and real history
                (can be aged or purchased — confirm scope permits this)
Job title:      Match the target's known helpdesk or vendor tier
Voice:          Practice your cover — pace, authority, familiarity with internal terms
```

### Creating a LinkedIn Persona

Aged LinkedIn accounts are significantly more convincing than new ones:

```
If creating a new profile:
  - Use a real-looking headshot (thispersondoesnotexist.com)
  - Add 10+ connections before use (connect with open networkers)
  - Fill in full job history with plausible previous employers
  - Add certifications relevant to your role (CompTIA, ITIL, etc.)
  - Post 1–2 professional articles or re-shares to establish activity
  - Wait at least 30 days before using in the engagement if possible

Profile fields to populate:
  - Headline: "IT Support Specialist | ServiceNow | ITIL Certified"
  - About: 2–3 sentences of generic but credible background
  - Experience: Current role at the cover company + 1–2 prior roles
  - Education: Real university, generic CS or IT degree
  - Skills: 5–10 relevant technical skills with endorsements
```

### Email Account Setup

```bash
# Register a domain that fits your persona
# Example: corp-itsupport.com, helpdesk-contoso.com
# Use Namecheap, Google Domains, or Porkbun (avoid overly cheap registrars)

# Configure SPF, DKIM, DMARC for the domain
# See phishing-tradecraft.md for full DNS configuration walkthrough

# Use ProtonMail or Fastmail for the mailbox (avoid Gmail — domain mismatch is obvious)
# Or self-host on the registered domain with Postfix

# Activate the account and send a few test messages first
# Warm up the email account (send to mail-tester.com, exchange a few emails)
```

### Phone Number Setup

```python
# Twilio — purchase a number matching the target's area code
# Cost: ~$1/month per number
# pip install twilio

from twilio.rest import Client

account_sid = "ACxxxxxxxxxxx"
auth_token  = "your_auth_token"
client = Client(account_sid, auth_token)

# Purchase a number
available = client.available_phone_numbers("US").local.list(area_code="212")
number = client.incoming_phone_numbers.create(phone_number=available[0].phone_number)
print(f"Purchased: {number.phone_number}")
```

---

## Scenario Library

### 1. IT Helpdesk — MFA Rollout

```
Context: Company is rolling out Duo or Microsoft Authenticator
Caller:  "Hi [Name], I'm [FirstName] from the IT helpdesk. I'm reaching out
          to help set up your Authenticator enrolment — we're completing the
          rollout for your department today. I need about two minutes of your time.

          Can you confirm you received the enrolment email from IT@[company]?

          [If yes] Great, I'm going to walk you through the setup now. When you click
          the link, it'll ask for your current password first — that's normal for
          the migration. Let me know what you see.

          [If no] That's okay, I'll re-send it now. Keep an eye on your inbox —
          it'll come from IT-noreply@[company]. Let me know when you see it."

Goal:    Credential capture via fake MFA enrolment page
```

### 2. Vendor — Contract Renewal / Portal Access

```
Context: Target company uses a specific SaaS vendor (e.g., Salesforce, Workday)
Caller:  "Hi [Name], this is [Name] from Salesforce account support.
          I'm calling about your enterprise contract renewal — your primary
          contact [Manager name] asked us to loop you in for the technical
          verification step.

          I'm going to send a portal link to [email address] — when you log in
          you'll see the renewal terms. There's one field that needs your
          current admin credentials to transfer the licence keys.
          Is now a good time to walk through that?"

Goal:    Admin credential capture via fake vendor portal
```

### 3. Recruiter — LinkedIn Message

```
Context: Target is a developer or engineer with public LinkedIn
Message: "Hi [Name],

          I came across your profile while searching for [tech stack] engineers.
          We're working with a company in [city] that's building [relevant product].
          The role is fully remote, comp range £90–110k.

          I have a technical brief I'd like to share — it includes some details
          about the architecture they're working on. Would it be okay to send it over?

          Best,
          [Name] | [Fake Recruitment Agency]"

          [Follow-up with link to document hosted on attacker-controlled page
          or payload delivered via HTML smuggling]

Goal:    Payload delivery via recruiter lure
```

### 4. Auditor — Information Request

```
Context: Financial services or regulated industry target
Email:   "Dear [Name],

          I'm writing on behalf of [external audit firm] in connection with the
          upcoming [ISO 27001 / SOC 2 / PCI-DSS] audit engagement. Your name
          was provided as the technical contact for the IT infrastructure review.

          Please find attached the evidence request list. We'll need the items
          in Section B submitted via our client portal by end of week.
          Login credentials for the portal are [email] / [temp password].

          Please log in and confirm receipt.

          Regards,
          [Auditor name]
          [Fake audit firm email]"

Goal:    Portal login capture + potential payload via "evidence list" attachment
```

### 5. New Employee — Onboarding Confusion

```
Context: Target recently changed roles or the company has been hiring
Caller:  "Hi [Name], I'm [Name] from HR — I'm supporting the onboarding
          process this week. I think there may have been a mix-up with your
          account setup. I'm not seeing your profile in our HRIS system.

          Can you verify a few details so I can get this resolved before payroll
          closes on Friday? I just need your employee ID, your manager's name,
          and the email address you've been using to log in."

Goal:    PII and credential enumeration for follow-on attack
```

### 6. Legal / Compliance — Urgent Document Request

```
Context: Large organisations with in-house legal or compliance
Email:   "Subject: URGENT — Legal Hold Notice — INC-2024-1182

          This message is from the Legal & Compliance team. As part of an
          ongoing investigation, a legal hold has been placed on records
          associated with your account.

          Please do not delete any emails, files, or communications.
          Additionally, you are required to log in to the compliance portal
          within 24 hours to acknowledge receipt of this notice.

          Portal: https://[look-alike domain]/compliance-portal

          Failure to acknowledge within 24 hours may result in escalation to
          your department head."

Goal:    Credential capture via fear and legal authority
```

### 7. Executive Assistant — Urgent Transfer

```
Context: Finance team or accounts payable target
Caller:  "Hi, this is [Name] — I'm the EA to [CEO Name]. [CEO] is currently
          in the [City] board meeting and has asked me to reach out urgently.
          There's a time-sensitive payment that needs to go out today for a
          strategic acquisition — I'm sure you'll hear more about this publicly
          next week.

          [CEO] specifically asked that this stays confidential until the
          announcement. The details will be in an email from me in the next
          few minutes. Can you confirm you'll be available this afternoon to
          process a wire?"

Goal:    BEC wire fraud setup
```

### 8. Facilities / HVAC Contractor

```
Context: Physical access to the building
Script:  "Hi, I'm here with [HVAC company] — we have a scheduled maintenance
          call for the server room cooling units. My supervisor told me the
          contact would be at reception but there's nobody there.

          [Holds clipboard with generic work order]
          Work order is for Server Room B, fourth floor. It's a quarterly PM.
          Should only take about 20 minutes.

          [If challenged about badge]
          We're a contractor so I don't have an access badge — last time the
          facilities manager just let us up. Is there someone you can call?"

Goal:    Physical access to restricted area
```

---

## Pretext Failure Recovery

Even well-researched pretexts sometimes fail. The key is recognising early signs of suspicion and exiting gracefully before the target can alert security.

### Early Warning Signs

```
- Target asks for your employee ID or badge number
- Target puts you on hold without warning (likely calling to verify)
- Target says "let me transfer you to [security/manager/IT]"
- Target asks you to spell your name or repeat details slowly (writing it down)
- Target becomes unusually quiet or monosyllabic
- Target says "I'm not comfortable with this" — escalation likely
```

### Graceful Exit Scripts

```
"No problem at all — I can see this isn't a convenient time. I'll follow up
 by email with the details so you have everything in writing. Have a good day."

"That's completely fine — I understand the caution. I'll have my supervisor
 send the official request through your IT ticketing system instead."

"Of course — I'll flag this in our system as pending. You'll receive an email
 confirmation within the hour. Thanks for your time."
```

### What NOT to Do

```
- Do not become defensive or confrontational when challenged
- Do not repeat the pretext louder or more insistently
- Do not continue after the target says they are going to report the call
- Do not hang up abruptly — it confirms something is wrong
- Do not attempt the same pretext on the same target a second time
```

### Logging Failed Attempts

Failed attempts are valuable data — log them accurately:

```
Date/time:      [timestamp]
Target:         [name/department — no full PII in notes]
Channel:        [email/phone/in-person]
Pretext used:   [brief description]
Failure point:  [where in the script the target became suspicious]
Likely reason:  [awareness training, caller ID mismatch, wrong tool name, etc.]
Recommendation: [adjust pretext, change channel, use different lure]
```

---

## Documentation and Debrief

All pretext interactions must be documented in the engagement log, regardless of outcome. This forms the basis of the final report's narrative.

### Interaction Log Template

```
Engagement:     [Client name — engagement ID]
Date:           [YYYY-MM-DD]
Time:           [HH:MM local]
Operator:       [Tester name / alias]
Channel:        [Email / Phone / SMS / In-person]
Target (role):  [Job title and department — no unnecessary PII]
Pretext:        [Persona and scenario used]
Objective:      [Credential capture / payload / physical access / information]

Interaction summary:
  [Step-by-step narrative of what happened]

Outcome:
  [ ] Success — objective achieved
  [ ] Partial — some information gathered, objective not fully met
  [ ] Failure — target did not comply
  [ ] Reported — target reported the interaction to security

Evidence:
  [Screenshot of credential submission / recording reference / photo]

MITRE techniques observed:
  [T1566.002, T1598, T1656 etc.]
```

### Debrief with the Client

Post-engagement debrief should cover:

```
1. Walk through each successful interaction — what worked and why
2. Walk through notable failures — what gave it away
3. Discuss systemic weaknesses (e.g., "finance team consistently clicked")
4. Call out any employees who reported correctly (positive reinforcement)
5. Recommend training and process changes per department
6. Discuss re-test timeline to measure improvement
```

---

## Resources

- MITRE T1656 — Impersonation — `attack.mitre.org/techniques/T1656/`
- Hunter.io — email format discovery — `hunter.io`
- The Art of Human Hacking — Christopher Hadnagy
- Social Engineering: The Science of Human Hacking — Christopher Hadnagy
- thispersondoesnotexist.com — AI-generated profile photos
- Twilio — programmable voice and SMS — `twilio.com`
- SEORG — Social-Engineer.org framework — `social-engineer.org/framework/`
