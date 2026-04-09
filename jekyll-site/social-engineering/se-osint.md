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
---
<h1>OSINT for Social Engineering</h1>
<p>Effective social engineering starts with intelligence. The goal is to gather enough information about the target and their organization to construct a believable pretext, identify the right lure, and impersonate a known trusted entity. This page covers SE-specific OSINT — see the Reconnaissance module for broader OSINT tooling.</p>

<h2>Intelligence Requirements</h2>
<pre><code>Organizational:
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
  - Communication style (formal vs casual)</code></pre>

<h2>LinkedIn</h2>
<pre><code># Most valuable SE OSINT source
# Reveals: org chart, titles, tools, vendors, projects, tenure

# Find all employees at a company
site:linkedin.com/in "Company Name" "Title"

# Identify IT staff and admins
site:linkedin.com/in "Company Name" "IT" OR "sysadmin" OR "infrastructure"
site:linkedin.com/in "Company Name" "ServiceNow" OR "CrowdStrike" OR "Active Directory"

# Tools mentioned in job postings reveal the tech stack
# "Experience with Okta, Azure AD, and CrowdStrike preferred" = pretext gold

# LinkedIn Sales Navigator (if available)
# Full org chart, direct contact info, relationship mapping</code></pre>

<h2>Email Harvesting</h2>
<pre><code># theHarvester — multi-source email enumeration
theHarvester -d target.com -b all -l 500

# hunter.io — email format + known addresses
# API: https://api.hunter.io/v2/domain-search?domain=target.com&amp;api_key=KEY

# Email format permutation
# Once you know the format, generate addresses for all employees
python3 emailharvester.py -d target.com

# Common formats to test (verify with hunter.io or email validation)
first.last@corp.com
flast@corp.com
firstname@corp.com
f.last@corp.com</code></pre>

<h2>GitHub &amp; Code Repositories</h2>
<pre><code># Search for organization repositories and employee commits
github.com/orgs/[orgname]

# Find employees via commit emails
# API: https://api.github.com/repos/org/repo/commits

# Search for internal tool names, config files, secrets
gh search code "corp-internal" org:targetorg
gh search code "ServiceNow" org:targetorg

# Look for accidentally committed credentials or internal hostnames
trufflehog github --org=targetorg
gitleaks detect --source=./cloned-repo</code></pre>

<h2>Job Postings</h2>
<pre><code># Job postings are a goldmine for technology stack intelligence
# Platforms: LinkedIn Jobs, Indeed, Glassdoor, company careers page

# Keywords that reveal infrastructure:
"Experience with [tool]"    — confirms tool is in use
"Administer [platform]"     — confirms platform
"migrate from X to Y"       — active migration = disruption pretext
"MSP", "outsourced IT"      — third-party IT = helpdesk pretext
"rollout", "deployment"     — new systems = IT email pretext

# Example extracted intel:
"Proficiency in ServiceNow, Azure AD, Intune, and CrowdStrike"
→ Use these exact tool names in phishing/vishing for authenticity</code></pre>

<h2>Social Media</h2>
<pre><code># Twitter/X — search for employee complaints about tools
"[company name] VPN" site:twitter.com
"[company name] outlook" site:twitter.com

# Facebook / Instagram — personal interests, family info
# Useful for rapport building in vishing scenarios

# Conference attendance
# Search for "[conference name] [company name]" — reveals who attended
# Excellent for "I met you at [conference] last month" pretexts</code></pre>

<h2>Data Breaches</h2>
<pre><code># Check if target email is in known breaches
haveibeenpwned.com/api/v3/breachedaccount/{email}

# Breach databases (for credential stuffing and password analysis)
# DeHashed, Snusbase, IntelX

# Value for SE:
# - Prior passwords reveal password patterns for password spraying
# - Personal info from breaches (DOB, address) enhances pretext credibility
# - Prior account breaches = "We detected your credentials in a data breach" lure</code></pre>

<h2>Company Website &amp; Public Documents</h2>
<pre><code"># Press releases — announce vendor partnerships, new hires, migrations
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
site:corp.com filetype:xlsx</code></pre>

<h2>Phone Number Discovery</h2>
<pre><code># Corporate directories (sometimes public)
# Conference programs — speakers list with contact info
# Email signatures in forwarded emails
# LinkedIn "Contact Info" section (sometimes populated)

# Reverse phone lookup
truecaller.com
spokeo.com
whitepages.com

# Google: "[full name]" "[company]" phone
# Google: "[full name]" site:linkedin.com phone</code></pre>

<h2>Target Profile Template</h2>
<pre><code">Name:           [First Last]
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
Best lure:      [Recommended pretext based on profile]</code></pre>

<h2>Resources</h2>
<ul>
  <li>theHarvester — <code>github.com/laramies/theHarvester</code></li>
  <li>hunter.io — email discovery — <code>hunter.io</code></li>
  <li>haveibeenpwned.com — breach checking</li>
  <li>trufflehog — git secret scanning — <code>github.com/trufflesecurity/trufflehog</code></li>
  <li>Maltego — relationship mapping — see recon/maltego-osint</li>
</ul>
