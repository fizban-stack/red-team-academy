---
layout: training-page
title: "Email OSINT — Red Team Academy"
module: "Reconnaissance"
tags:
  - osint
  - email
  - phishing-prep
page_key: "recon-email-osint"
render_with_liquid: false
---

# Email OSINT

## Why Email OSINT Matters

Email addresses are the most valuable pre-engagement asset. They unlock phishing simulations, breach data correlation, LinkedIn recon, and password spraying. A thorough email OSINT phase transforms a generic phishing campaign into a highly targeted, believable attack against specific individuals with relevant pretexts. **All activity here is passive — no target systems are touched.**

![Email OSINT pipeline: discover format via hunter.io, build list from LinkedIn and theHarvester, validate addresses, check breach databases for leaked passwords, then engage with targeted phishing or password spray](/images/recon/email-osint-pipeline.svg)  
*// email osint pipeline — domain to validated phishing target list*

## Discovering the Email Format

Most organizations use one of a handful of email formats. Once you know it, every name becomes a valid target address.

```
# Common corporate email formats:
# firstname.lastname@company.com       (most common)
# flastname@company.com
# firstname@company.com
# f.lastname@company.com
# firstname_lastname@company.com

# Step 1 — Find a confirmed email (LinkedIn, company website, WHOIS)
# Step 2 — Derive the pattern
# Step 3 — Generate addresses for all employees you've identified

# Hunter.io — free tier reveals the format and sample addresses:
# https://hunter.io/domain-search?domain=targetcompany.com

# Verify format from job posting emails, conference speaker bios,
# press releases, GitHub commit metadata
```

## Email Discovery Tools

### theHarvester

```
# Harvest emails from multiple public sources
theHarvester -d targetcompany.com -b all -f output.html
theHarvester -d targetcompany.com -b google,bing,linkedin,twitter
theHarvester -d targetcompany.com -b anubis,rapiddns,crtsh -n  # Include DNS

# Key sources:
# -b google      Google search results
# -b bing        Bing search results
# -b linkedin    LinkedIn (limited without auth)
# -b hunter      Hunter.io API (requires key)
# -b shodan      Shodan (requires API key)
# -b anubis      Anubis subdomain lookup
# Output: emails, subdomains, IPs, hostnames found in search results
```

### Hunter.io

```
# Web interface: https://hunter.io
# Domain Search → enter target domain → see:
#   - Discovered email addresses
#   - Email format pattern
#   - Employee names
#   - Sources where emails were found

# Hunter.io CLI (requires free API key):
curl "https://api.hunter.io/v2/domain-search?domain=targetcompany.com&api_key=YOUR_KEY"

# Email Finder — verify a specific guessed address:
curl "https://api.hunter.io/v2/email-finder?domain=targetcompany.com&first_name=John&last_name=Smith&api_key=YOUR_KEY"

# Email Verifier:
curl "https://api.hunter.io/v2/email-verifier?email=john.smith@targetcompany.com&api_key=YOUR_KEY"
```

### Phonebook.cz / IntelX

```
# Phonebook.cz — searches leaked/public data for email addresses
# https://phonebook.cz
# Enter domain → get list of all emails ever associated with it

# Intelligence X — broader breach and darkweb search
# https://intelx.io
# Searches paste sites, darkweb, data leaks for target domain emails

# These sources frequently surface emails from old breaches that
# still have valid corporate accounts using the same password
```

### GitHub & Code Repository Mining

```
# Developers commit with their corporate email — mine it:
# Search GitHub for the target domain:
# https://github.com/search?q=@targetcompany.com&type=code

# Git commit metadata — email in every commit:
git log --pretty=format:"%ae %an" | grep targetcompany.com | sort -u

# GitDorker — automated GitHub OSINT:
python3 gitdorker.py -tf TOKENSFILE -q targetcompany.com -d dorks/medium_dorks.txt

# Also check: GitLab, Bitbucket, npm packages, PyPI packages
# Package maintainer fields often contain corporate emails
```

## LinkedIn Reconnaissance

LinkedIn is the richest source of employee data for building a target list. Use it to map the org chart, identify high-value targets, and craft believable pretexts.

```
# Manual LinkedIn recon — what to collect:
# 1. Org chart: C-suite, IT, Finance, HR (highest-value phishing targets)
# 2. Job titles → infer technology stack ("Azure DevOps Engineer" = Azure infra)
# 3. Job postings → "Required: CrowdStrike Falcon experience" = they run CrowdStrike
# 4. Employee names → generate email addresses from format
# 5. Recent hires/departures → new employees are prime social engineering targets

# Tools for scraping LinkedIn (use responsibly, within ToS limits):
# - linkedin2username — generates email list from company LinkedIn page
python3 linkedin2username.py -u your_linkedin@email.com -c "Target Company" -n 5

# - CrossLinked — similar, with name permutation
python3 crosslinked.py -f '{first}.{last}@targetcompany.com' "Target Company"

# Google dorking LinkedIn:
site:linkedin.com/in "Target Company" "IT Manager"
site:linkedin.com/in "Target Company" "Active Directory"
```

## Breach Data & Password Intelligence

Leaked credentials from previous breaches are gold. Employees reuse passwords across personal and corporate accounts. Breach data reveals real password patterns for spraying.

### Have I Been Pwned (HIBP)

```
# Check if a domain has appeared in known breaches:
# https://haveibeenpwned.com/DomainSearch (requires domain verification)

# Check individual emails via API:
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/target@targetcompany.com" \
  -H "hibp-api-key: YOUR_KEY"

# What to look for:
# - Which breaches the email appears in (LinkedIn 2012, Adobe 2013, etc.)
# - Password patterns from those breach databases (crack them with Hashcat)
# - If someone@targetcompany.com was in the LinkedIn breach, try
#   their LinkedIn password (or variations) against corporate VPN/OWA
```

### DeHashed

```
# DeHashed — searches breach databases by email, domain, username, IP, name
# https://dehashed.com (subscription required for full data)

# Search for entire domain:
curl -s -H 'Accept: application/json' \
  -u "email@youraccount.com:API_KEY" \
  "https://api.dehashed.com/search?query=domain:targetcompany.com&size=100"

# What you get: email addresses, usernames, plaintext/hashed passwords, IP addresses
# Use recovered passwords to build a target-specific wordlist for spraying
```

### Building a Target Wordlist from Breach Data

```
# 1. Collect all passwords from breach data for the target domain
# 2. Clean and deduplicate:
sort -u breach_passwords.txt > clean_passwords.txt

# 3. Generate variations (Hashcat rules):
hashcat --stdout clean_passwords.txt -r /usr/share/hashcat/rules/best64.rule > variants.txt

# 4. Add target-specific words: company name, products, city, year:
echo "TargetCo2024!" >> variants.txt
echo "Welcome1" >> variants.txt
echo "Password1!" >> variants.txt   # Classic corporate default

# 5. Use for password spray (low-and-slow to avoid lockout):
crackmapexec smb dc.targetcompany.com -u users.txt -p variants.txt \
  --no-bruteforce --continue-on-success
```

## Social Media Recon

```
# Twitter/X — employees often tweet about work projects, tech stack, events:
site:twitter.com "targetcompany.com"
# Search: "at targetcompany" "just started at" "first day at"

# Job postings — technology intelligence:
# Indeed, LinkedIn Jobs, Glassdoor → search target company
# "We use": AWS, Splunk, CrowdStrike, Okta → tells you the security stack
# "Experience with": Cisco ASA, Palo Alto, Fortinet → firewall/VPN vendors

# Conference presentations (SANS, RSA, DEF CON, BSides):
site:youtube.com "Target Company" security OR infrastructure OR DevOps
# Presenters often reveal internal tools, architecture, incident history

# Press releases, blog posts:
# Company announcements → new offices (physical red team targets)
# Acquisitions → newly integrated (and often insecure) infrastructure
# "We recently migrated to Azure" → cloud attack surface
```

## Pretext Development from Email OSINT

The goal of all this OSINT is to build a believable pretext — the story that makes the phishing email credible.

- **IT Help Desk** — "Your MFA device needs re-enrollment" → targets all employees, high click rate
- **Finance Spearphish** — Fake invoice from known vendor (discovered via LinkedIn or company website) → targets AP/Finance team
- **Executive impersonation (BEC)** — Spoof CEO email to CFO → "Wire transfer needed urgently" → requires good CEO name/email from OSINT
- **IT Infrastructure alert** — "Your Okta session expired — click to re-authenticate" → works when you know they use Okta (from job postings)
- **New employee onboarding** — "Welcome to Target Co — please set up your laptop" → new hires from LinkedIn (started 1-4 weeks ago) are unaware of normal procedures

## OPSEC for Email OSINT

- Use a VPN or Tor for Hunter.io and web searches — don't let target see your IP in referrer logs
- Do NOT verify email addresses by sending test emails — delivery receipts alert defenders
- Do NOT connect to employee LinkedIn profiles from a profile linked to your company
- Create a persona account with no real identity for social media research

## Key Resources

- [Email discovery and verification](https://hunter.io)
- [Breach data email search](https://phonebook.cz)
- [Breach notification](https://haveibeenpwned.com)
- [Breach credential search](https://dehashed.com)
- [LinkedIn email generation](https://github.com/initstring/linkedin2username)
- [OSINT tool index by category](https://osintframework.com)
