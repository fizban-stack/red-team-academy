---
layout: training-page
title: "OSINT for Social Engineering — Red Team Academy"
module: "Social Engineering"
tags:
  - osint
  - social-engineering
  - reconnaissance
  - target-profiling
page_key: "se-osint"
render_with_liquid: false
---

# OSINT for Social Engineering

Effective social engineering starts with intelligence. The goal is to gather enough information about the target and their organization to construct a believable pretext, identify the right lure, and impersonate a known trusted entity. This page covers SE-specific OSINT — see the Reconnaissance module for broader OSINT tooling.

## Intelligence Requirements

```
Organizational:
  - Org chart (who reports to whom)
  - IT vendors and tools in use
  - Email format (first.last@corp.com vs flast@corp.com)
  - Current projects, mergers, system migrations
  - Office locations, remote work policy

Individual (target-specific):
  - Full name, title, direct reports
  - Mobile number
  - Work email address
  - Personal interests (for rapport)
  - Recent activity, travel, conferences attended
  - Communication style (formal vs casual)
```

## LinkedIn

```
# Most valuable SE OSINT source
# Reveals: org chart, titles, tools, vendors, projects, tenure

# Find all employees at a company
site:linkedin.com/in "Company Name" "Title"

# Identify IT staff and admins
site:linkedin.com/in "Company Name" "IT" OR "sysadmin" OR "infrastructure"
site:linkedin.com/in "Company Name" "ServiceNow" OR "CrowdStrike" OR "Active Directory"

# Tools mentioned in job postings reveal the tech stack
# "Experience with Okta, Azure AD, and CrowdStrike preferred" = pretext gold

# LinkedIn Sales Navigator (if available)
# Full org chart, direct contact info, relationship mapping
```

## Email Harvesting

```
# theHarvester — multi-source email enumeration
theHarvester -d target.com -b all -l 500

# hunter.io — email format + known addresses
# API: https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY

# Email format permutation
# Once you know the format, generate addresses for all employees
python3 emailharvester.py -d target.com

# Common formats to test (verify with hunter.io or email validation)
first.last@corp.com
flast@corp.com
firstname@corp.com
f.last@corp.com
```

## GitHub & Code Repositories

```
# Search for organization repositories and employee commits
github.com/orgs/[orgname]

# Find employees via commit emails
# API: https://api.github.com/repos/org/repo/commits

# Search for internal tool names, config files, secrets
gh search code "corp-internal" org:targetorg
gh search code "ServiceNow" org:targetorg

# Look for accidentally committed credentials or internal hostnames
trufflehog github --org=targetorg
gitleaks detect --source=./cloned-repo
```

## Job Postings

```
# Job postings are a goldmine for technology stack intelligence
# Platforms: LinkedIn Jobs, Indeed, Glassdoor, company careers page

# Keywords that reveal infrastructure:
"Experience with [tool]"    — confirms tool is in use
"Administer [platform]"     — confirms platform
"migrate from X to Y"       — active migration = disruption pretext
"MSP", "outsourced IT"      — third-party IT = helpdesk pretext
"rollout", "deployment"     — new systems = IT email pretext

# Example extracted intel:
"Proficiency in ServiceNow, Azure AD, Intune, and CrowdStrike"
→ Use these exact tool names in phishing/vishing for authenticity
```

## Social Media

```
# Twitter/X — search for employee complaints about tools
"[company name] VPN" site:twitter.com
"[company name] outlook" site:twitter.com

# Facebook / Instagram — personal interests, family info
# Useful for rapport building in vishing scenarios

# Conference attendance
# Search for "[conference name] [company name]" — reveals who attended
# Excellent for "I met you at [conference] last month" pretexts
```

## Data Breaches

```
# Check if target email is in known breaches
haveibeenpwned.com/api/v3/breachedaccount/{email}

# Breach databases (for credential stuffing and password analysis)
# DeHashed, Snusbase, IntelX

# Value for SE:
# - Prior passwords reveal password patterns for password spraying
# - Personal info from breaches (DOB, address) enhances pretext credibility
# - Prior account breaches = "We detected your credentials in a data breach" lure
```

## Company Website & Public Documents

```
# Press releases — announce vendor partnerships, new hires, migrations
# "Contoso announces partnership with Okta for identity management"
# → Okta onboarding/migration pretext

# Annual reports — reveal subsidiaries, locations, key personnel
# SEC filings (EDGAR) — for public companies, reveal leadership, operations

# Metadata from public documents
exiftool company_document.pdf
# Reveals: author names, internal tool names (Office version, printer names)
# Hostnames sometimes embedded in documents

# Google dorks for internal documents
site:corp.com filetype:pdf "internal" OR "confidential"
site:corp.com filetype:xlsx
```

## Phone Number Discovery

```
# Corporate directories (sometimes public)
# Conference programs — speakers list with contact info
# Email signatures in forwarded emails
# LinkedIn "Contact Info" section (sometimes populated)

# Reverse phone lookup
truecaller.com
spokeo.com
whitepages.com

# Google: "[full name]" "[company]" phone
# Google: "[full name]" site:linkedin.com phone
```

## Target Profile Template

```
Name:           [First Last]
Title:          [Job title]
Email:          [Email address]
Phone:          [Mobile/direct if found]
Manager:        [Manager name and title]
Reports to:     [Skip level if relevant]
Tools used:     [List from job postings/LinkedIn]
Vendors:        [Known vendor relationships]
Recent activity: [Conferences, promotions, projects]
Personal notes: [Interests, location from social media]
Breach history: [Y/N, which breaches]
Best lure:      [Recommended pretext based on profile]
```

---

## Email Format Discovery

### Hunter.io Deep Dive

```bash
# Hunter.io — most reliable email format discovery tool
# Free tier: 25 searches/month; paid tiers for more

# Domain search (finds all known emails + format)
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY&limit=100" \
  | python3 -m json.tool

# Response includes:
# "pattern": "first.last"   ← the email format for the domain
# "emails": [...]            ← list of discovered email addresses
# "confidence" score per email

# Email finder (for a specific person)
curl "https://api.hunter.io/v2/email-finder?domain=target.com&first_name=John&last_name=Smith&api_key=YOUR_KEY" \
  | python3 -m json.tool

# Email verifier (confirm deliverability before sending)
curl "https://api.hunter.io/v2/email-verifier?email=j.smith@target.com&api_key=YOUR_KEY" \
  | python3 -m json.tool
# Status: "valid", "invalid", "accept_all", "unknown"
```

### Email Permutator

```python
# Generate all permutations of a person's email address
# Install: pip3 install EmailPermutator

# Or write your own:
def permutate_email(first, last, domain):
    patterns = [
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{first}.{last[0]}@{domain}",
        f"{first}_{last}@{domain}",
        f"{first[0]}_{last}@{domain}",
    ]
    return patterns

emails = permutate_email("john", "smith", "contoso.com")
for e in emails:
    print(e)
```

### SMTP Verification Without Sending

```bash
# Verify email exists without sending a message
# smtp-user-enum tool

# Install
sudo apt install smtp-user-enum

# VRFY method (checks if mailbox exists via SMTP VRFY command)
smtp-user-enum -M VRFY -u john.smith -d target.com -t mail.target.com

# RCPT method (more universally supported)
smtp-user-enum -M RCPT -u john.smith -d target.com -t mail.target.com

# Bulk check from file:
smtp-user-enum -M RCPT -U userlist.txt -d target.com -t mail.target.com

# Note: Many mail servers disable VRFY
# RCPT method works on most but may generate log entries
# Some mail servers use "catch-all" — accept all addresses regardless
```

---

## Phone Number OSINT

### Truecaller and Reverse Lookup

```bash
# Truecaller — crowd-sourced caller ID database
# Effective for mobile numbers, especially in certain regions
# Web: truecaller.com/search/[phone-number]
# API available for bulk lookups (requires account)

# Spokeo — aggregated personal data
# spokeo.com — search by name, email, or phone
# Includes: carrier, location, relatives, social accounts
# Cost: ~$1–3 per report on paid tier

# Whitepages — US and Canada focused
# whitepages.com — name, phone, address cross-reference

# BeenVerified — US background check data
# beenverified.com — comprehensive personal data aggregation

# Pipl — professional people search (enterprise pricing)
# pipl.com — very comprehensive, focuses on professional identity
```

### Data Breach Sources for Phone Numbers

```bash
# Many data breaches include mobile phone numbers
# Sources to check:
# - haveibeenpwned.com: check if email is in known breaches
# - IntelligenceX (intelx.io): breach data search
# - DeHashed (dehashed.com): breach data with phone numbers
# - Snusbase (snusbase.com): breach database search

# Example: searching DeHashed API for a phone number
curl -H 'Accept: application/json' \
  -u "email:api_key" \
  "https://api.dehashed.com/search?query=phone:+15551234567"

# What to look for in breaches for SE:
# - Phone number confirmation (validate the number is correct)
# - Personal email address (for personal-channel attacks)
# - Date of birth (enhances pretext credibility)
# - Physical address (regional context for vishing)
# - Username (may reuse across platforms — check social media)
# - Password hash/plaintext (for credential stuffing or pattern analysis)
```

---

## Corporate Org Chart Reconstruction

### LinkedIn Org Chart Mapping

```bash
# Systematically map the org chart using LinkedIn
# Start from known executives (company website leadership page)
# then follow "Reports to" / "Manager" relationships

# Step 1: Find C-suite from company website or LinkedIn company page
# Step 2: Search LinkedIn for "[Company] [Title]" for each level
# Step 3: For each employee, note: name, title, department, manager
# Step 4: Build a hierarchy tree

# Automate with PhantomBuster (phantombuster.com):
# LinkedIn Profile Scraper — scrapes profile data at scale
# LinkedIn Company Employees Export — exports all visible employees
# Requires LinkedIn account; respect rate limits

# Alternative: Clearbit (clearbit.com)
# API for company and person data including org structure
curl "https://company.clearbit.com/v2/companies/domain/target.com" \
  -u sk_live_YOUR_API_KEY:
# Returns: company size, technologies, employee count by department
```

### ZoomInfo and Apollo.io

```
ZoomInfo (zoominfo.com):
  - Most comprehensive B2B contact database
  - Org chart visualization
  - Direct phone numbers and email addresses
  - Job change alerts (useful for timing engagements)
  - Cost: enterprise pricing ($15,000+/year)
  - Free trial available

Apollo.io (apollo.io):
  - Similar to ZoomInfo but significantly cheaper
  - 10,000+ free credits per month on free tier
  - Search by company, title, department, location
  - Export to CSV
  - API access available

LinkedIn Sales Navigator:
  - $100/month per seat
  - Advanced search filters (seniority, function, geography)
  - Full org chart view for target companies
  - Lead recommendations
  - InMail credits for direct contact
```

### SEC Filings for Public Companies

```bash
# EDGAR (SEC EDGAR — edgar.sec.gov)
# Public companies must disclose:
# - Executive names and compensation (DEF 14A proxy statement)
# - Board of directors (10-K annual report)
# - Material changes in leadership (8-K current report)

# Search EDGAR for a company:
curl "https://efts.sec.gov/LATEST/search-index?q=%22Contoso+Inc%22&dateRange=custom&startdt=2025-01-01&enddt=2026-01-01&forms=DEF+14A" \
  | python3 -m json.tool

# DEF 14A (proxy statement): lists all named executive officers with titles
# 10-K (annual report): describes company structure, subsidiaries, key personnel
# 8-K (current report): new hires, executive departures, acquisitions
```

---

## Social Media Profiling for Pretext Development

### Twitter / X Intelligence

```bash
# Search for employee posts about work tools
# site:twitter.com "[company name]" "VPN" OR "Outlook" OR "helpdesk"

# Advanced Twitter search (search.twitter.com):
# From a specific user: from:username keyword
# About a company: to:CompanyHandle complaint OR issue

# Tools:
# twint (archived) — twitter scraping without API
# snscrape — social media scraping (pip install snscrape)
python3 -m snscrape --jsonl twitter-search '"Contoso" "VPN" OR "SSO" since:2025-01-01' \
  > twitter_results.jsonl

# What to look for:
# Tool complaints ("ugh, ServiceNow is down again")
# Company culture signals ("big announcement coming next week")
# OOO/travel posts ("heading to RSA Conference this week")
# Team structure hints ("congrats to my manager on the promotion")
```

### Instagram and Facebook

```bash
# Instagram — useful for personal interest profiling
# Search: instagram.com/[username] (if known from LinkedIn or other sources)
# Google: site:instagram.com "[full name]" "[company]"

# Facebook — profile may be locked but group memberships often visible
# Google: site:facebook.com "[full name]" "[company name]"
# Search for company-specific groups or alumni groups

# What to extract:
# Personal interests (sports, hobbies — for rapport in vishing)
# Family members (children's names sometimes mentioned)
# Location (confirm city for geo-targeted lures)
# Travel patterns (out of office = harder to verify with colleagues)
```

### Conference and Event Attendance

```bash
# Conference speaker databases
# Black Hat: blackhat.com/us-26/speakers.html
# DEF CON: defcon.org/html/links/dc-speakers.html
# RSA: rsaconference.com/speakers

# Search for attendance:
# Google: "[company name]" "[conference name]" 2025
# LinkedIn: search for posts mentioning conference hashtags by company employees
# Twitter: #BlackHat OR #RSA "[company name]"

# Conference attendance = "I met you at [conference] last month" pretext
# Speaker at conference = authoritative persona for follow-up

# Eventbrite and Meetup:
# Search by company or location for networking events
# Some events list attendees publicly
```

---

## Data Breach Mining for SE

### What to Look for Beyond Passwords

```bash
# Standard breach data: email, password hash, username
# But for SE, look for:

# 1. Personal email addresses (alongside corporate)
#    → Target personal email for attacks that bypass corporate filtering
#    → Personal email often has weaker security

# 2. Physical addresses
#    → Regional context: "I'm calling from our [city] office"
#    → Physical mailing for targeted parcel pretexts

# 3. Date of birth
#    → Enhances pretext: "Can you confirm your date of birth for verification?"
#    → Often used by banks/HR as a verification field

# 4. Phone numbers
#    → Mobile numbers for smishing and vishing targeting
#    → May be more current than corporate directory listings

# 5. Password patterns
#    → Even hashed passwords reveal patterns when cracked
#    → "Contoso123!", "Spring2024!" = company name + season + year
#    → Use for password spraying (separate engagement scope item)

# 6. Security question answers
#    → Some old breaches include security Q&A
#    → "Mother's maiden name" / "First pet" = useful pretext details

# 7. Previous employer data (from LinkedIn-type breaches)
#    → Multi-company correlations build more detailed profiles
```

### Using HaveIBeenPwned

```bash
# Check a single email
curl "https://haveibeenpwned.com/api/v3/breachedaccount/j.smith@target.com" \
  -H "hibp-api-key: YOUR_API_KEY" \
  -H "User-Agent: RedTeam-OSINT"

# Response includes breach names:
# ["LinkedIn", "Adobe", "Collection1", ...]

# Use breach names to:
# - Determine what data is available (LinkedIn breach = name, title, email)
# - Build credibility: "We've detected your credentials in the [breach name] breach"
# - Identify breach dates (old breaches = may have stale passwords)

# Check for password exposure (Pwned Passwords API):
# Hash the password candidate and check the first 5 chars
echo -n "Password123!" | sha1sum
# Returns: abc123...
curl "https://api.pwnedpasswords.com/range/ABC12"
# Returns: list of matching hash suffixes and counts
```

### DeHashed API Usage

```bash
# DeHashed — comprehensive breach database with API
# Cost: $5/month for basic API access

# Search by email
curl -H 'Accept: application/json' \
  -u "your@email.com:your_api_key" \
  "https://api.dehashed.com/search?query=email%3Aj.smith%40target.com&size=20"

# Search by name
curl -H 'Accept: application/json' \
  -u "your@email.com:your_api_key" \
  "https://api.dehashed.com/search?query=name%3A%22John+Smith%22&size=20"

# Search by phone
curl -H 'Accept: application/json' \
  -u "your@email.com:your_api_key" \
  "https://api.dehashed.com/search?query=phone%3A%2B15551234567&size=20"

# Output fields include:
# id, email, ip_address, username, password, hashed_password,
# name, vin, address, phone, database_name
```

---

## Building Target Dossiers

### Full Dossier Template

```
═══════════════════════════════════════════════════════
TARGET DOSSIER — CONFIDENTIAL
Engagement: [Client — Engagement ID]
Date:       [YYYY-MM-DD]
Analyst:    [Tester name]
═══════════════════════════════════════════════════════

PERSONAL INFORMATION
──────────────────────────────────────────────────────
Full name:           [First Middle Last]
Preferred name:      [Goes by "Mike" not "Michael"]
Job title:           [Current title]
Department:          [Department and team]
Company:             [Company name]
Office location:     [City, building if known]
Start date:          [Approximate tenure from LinkedIn]
LinkedIn URL:        [Profile URL]

CONTACT INFORMATION
──────────────────────────────────────────────────────
Work email:          [Confirmed email address]
Email confidence:    [Verified / Permuted / Assumed]
Work phone:          [DID if discoverable]
Mobile:              [If found via OSINT]
Personal email:      [If found in breach data]

ORGANIZATIONAL CONTEXT
──────────────────────────────────────────────────────
Reports to:          [Manager name and title]
Direct reports:      [List of subordinates if applicable]
Key peers:           [Colleagues who might be referenced in lures]
Skip-level:          [Manager's manager]
Team size:           [Approximate]

TECHNOLOGY FOOTPRINT
──────────────────────────────────────────────────────
Tools confirmed:     [ServiceNow, CrowdStrike, Okta — source: job posting]
Cloud platforms:     [Azure, AWS, GCP]
Identity provider:   [Azure AD, Okta, Google Workspace]
Endpoint security:   [CrowdStrike, SentinelOne, Defender]
Known vendors:       [List with source]

PERSONAL PROFILE
──────────────────────────────────────────────────────
Interests:           [Sports, hobbies from social media]
Travel/location:     [City, recent travel patterns]
Communication style: [Formal/informal based on LinkedIn posts]
Conference activity: [Events attended or spoken at]

BREACH INTELLIGENCE
──────────────────────────────────────────────────────
HIBP breaches:       [Breach names, dates]
Password patterns:   [If recoverable — note for password spray]
Additional PII found: [DOB, phone, address from breach data]

RECOMMENDED PRETEXT
──────────────────────────────────────────────────────
Primary pretext:     [Best option based on profile]
Lure hook:           [Specific detail to reference]
Delivery channel:    [Email / Vishing / Smishing]
Persona to use:      [IT / HR / Vendor / Executive]
Best time to contact: [Based on time zone and role]
Risk of verification: [High / Medium / Low]

EVIDENCE SOURCES
──────────────────────────────────────────────────────
LinkedIn:            [Y/N — last checked date]
Job postings:        [Y/N — source URL]
GitHub:              [Y/N — profile/commit email]
Social media:        [Platforms found on]
Breach data:         [Y/N — sources]
Public documents:    [Any SEC/press release sources]
═══════════════════════════════════════════════════════
```

---

## Resources

- theHarvester — `github.com/laramies/theHarvester`
- hunter.io — email discovery — `hunter.io`
- haveibeenpwned.com — breach checking
- trufflehog — git secret scanning — `github.com/trufflesecurity/trufflehog`
- Maltego — relationship mapping — see recon/maltego-osint
- DeHashed — breach database — `dehashed.com`
- Apollo.io — B2B contact database — `apollo.io`
- EDGAR — SEC filings — `edgar.sec.gov`
- dnstwist — domain permutation — `github.com/elceef/dnstwist`
- snscrape — social media scraping — `github.com/JustAnotherArchivist/snscrape`
- smtp-user-enum — email validation — `github.com/pentestmonkey/smtp-user-enum`
