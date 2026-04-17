---
layout: training-page
title: "Bug Bounty Starter Path (4 Weeks) — Red Team Academy"
module: "Learning Paths"
tags:
  - bug-bounty
  - learning-path
  - web-security
  - recon
  - hackerone
  - bugcrowd
page_key: "learning-paths-bug-bounty"
render_with_liquid: false
---

# Bug Bounty Starter Path — 4 Weeks

Bug bounty hunting is the practice of finding and reporting security vulnerabilities in real-world applications through authorized programs run by companies. Unlike penetration testing engagements, bug bounty is open-ended, competitive, and self-directed. This path teaches you to find real bugs in real targets on platforms like HackerOne, Bugcrowd, and Intigriti.

This is a beginner-to-intermediate path. It assumes you can use Burp Suite and understand HTTP, but does not require prior security research experience.

---

## Platform Overview

### HackerOne
- Largest platform by program count
- Mix of private (invitation-only) and public programs
- Good triage team at major programs
- Reputation system affects invitation to private programs
- Signal/Noise reputation score matters for private invites

### Bugcrowd
- Strong in financial services and enterprise software
- Crowdsourced security model with priority-based rewards
- Managed programs have Bugcrowd staff doing initial triage
- Good for finding programs with less competition

### Intigriti
- Europe-focused
- Smaller but growing — less competition than HackerOne
- Good for European tech companies
- Pays in EUR (favorable for non-US hunters)

### Self-Hosted Programs (not on platforms)
- Google VRP, Apple Security Bounty, Microsoft MSRC
- Higher payouts, harder to get noticed
- No platform triage — deal directly with security teams
- Worth targeting once you have platform reputation

---

## Scope Types Explained

| Scope Type | What's Included | Typical Restrictions |
|---|---|---|
| Web application | Web app + APIs on listed domains | Only listed domains and subdomains |
| Mobile | iOS/Android apps + APIs | Usually excludes server-side infrastructure |
| API | REST/GraphQL/SOAP endpoints | Often separate from web scope |
| Wide scope | All assets (*.company.com) | Acquirees may be excluded |
| Hardware/IoT | Firmware + hardware | Requires physical device |

**Reading scope carefully is the most important skill in bug bounty.** Submitting an out-of-scope finding wastes your time and damages your reputation. Always identify exactly what domains and assets are in scope before testing.

---

## Week 1: Reconnaissance and Subdomain Enumeration

**Goal:** Build a comprehensive map of the target's attack surface before touching any vulnerability testing.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/recon/subdomain-enum](/recon/subdomain-enum) | amass, subfinder, assetfinder, passive vs active enumeration |
| [/recon/web-recon](/recon/web-recon) | httpx, gowitness, crawling, technology fingerprinting |
| [/recon/subdomain-takeover](/recon/subdomain-takeover) | Dangling CNAMEs, unclaimed cloud assets, takeover techniques |
| [/recon/csp-recon](/recon/csp-recon) | Content Security Policy mining for hidden domains and assets |

### Recon Pipeline

Build a repeatable recon pipeline. Run it every time you start working on a new program:

```bash
#!/bin/bash
TARGET="example.com"
mkdir -p recon/$TARGET/{subdomains,screenshots,ports,urls}

# Phase 1: Passive subdomain enumeration
subfinder -d $TARGET -o recon/$TARGET/subdomains/subfinder.txt
amass enum -passive -d $TARGET -o recon/$TARGET/subdomains/amass.txt
assetfinder --subs-only $TARGET > recon/$TARGET/subdomains/assetfinder.txt

# Combine and deduplicate
cat recon/$TARGET/subdomains/*.txt | sort -u > recon/$TARGET/subdomains/all.txt

# Phase 2: Probe live hosts
httpx -l recon/$TARGET/subdomains/all.txt -title -status-code -tech-detect -o recon/$TARGET/subdomains/live.txt

# Phase 3: Screenshots
gowitness file -f recon/$TARGET/subdomains/all.txt -P recon/$TARGET/screenshots/

# Phase 4: Port scanning (only on explicitly in-scope assets)
nmap -iL recon/$TARGET/subdomains/all.txt --open -T4 -p 80,443,8080,8443,8888,3000,4000 -oA recon/$TARGET/ports/nmap

echo "Recon complete for $TARGET"
```

### What to Look For in Recon Output

| Finding | Potential Impact | Next Step |
|---|---|---|
| Subdomain resolves to cloud service (CNAME dangling) | Subdomain takeover | Check with `can-i-take-over-xyz` reference |
| Old/forgotten applications | Higher bug density | Manually enumerate all functionality |
| Staging or dev environments | Lower security, leaked debug info | Look for debug endpoints, verbose errors |
| API subdomains (api., api-v2., etc.) | API vulnerabilities | Test all endpoints systematically |
| Admin panels | Auth bypass, IDOR | Test all authentication mechanisms |
| S3 buckets, GCS buckets | Exposed data | Test read/write/list permissions |

### Subdomain Takeover Quick Check

```bash
# Install subjack
go install github.com/haccer/subjack@latest

# Run against your subdomain list
subjack -w recon/$TARGET/subdomains/all.txt -t 100 -timeout 30 -o takeover_candidates.txt -ssl

# Manual verification for candidates
dig CNAME <subdomain>  # Find the CNAME target
# Check if the CNAME target is claimable (unclaimed GitHub Pages, S3, etc.)
```

### CSP Recon for Hidden Domains

```bash
# Pull CSP headers from all live hosts
for url in $(cat live.txt | awk '{print $1}'); do
  echo "--- $url ---"
  curl -s -I "$url" | grep -i "content-security-policy"
done

# Parse unique domains from CSP
grep -oP "https?://[^;'\"\s]+" all_csps.txt | sort -u
```

---

## Week 2: Web Vulnerability Classes

**Goal:** Learn to identify and exploit the core web vulnerability classes that appear most frequently in bug bounty programs.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/sql-injection](/web/sql-injection) | SQLi identification, manual testing, sqlmap, blind techniques |
| [/web/xss-csp-bypass](/web/xss-csp-bypass) | Reflected, stored, DOM XSS; CSP bypass techniques |
| [/web/ssrf](/web/ssrf) | SSRF identification, cloud metadata access, bypass techniques |
| [/web/jwt-attacks](/web/jwt-attacks) | JWT alg:none, weak secrets, kid injection, JWK confusion |
| [/web/xxe](/web/xxe) | XXE via XML parsers, blind XXE with OOB, file read |

### Bug Bounty Payout Expectations by Vulnerability

| Vulnerability | Typical HackerOne Payout | Difficulty to Find |
|---|---|---|
| Critical SQLi (auth bypass) | $2,000–$20,000 | Medium |
| Stored XSS in admin panel | $500–$5,000 | Medium |
| SSRF with internal access | $1,000–$10,000 | Medium |
| IDOR (sensitive data) | $200–$3,000 | Low-Medium |
| Auth bypass | $500–$15,000 | Hard |
| XXE with file read | $500–$5,000 | Medium |
| Open redirect | $50–$300 | Low |
| Subdomain takeover | $100–$500 | Low |
| Rate limiting missing | $50–$200 | Low |

### SSRF Testing Approach

```
# Common SSRF injection points:
- URL parameters (?url=, ?redirect=, ?image=, ?file=, ?path=)
- Webhook endpoints ("notify me at this URL")
- PDF generators (HTML to PDF)
- Import features ("import from URL")
- Preview features ("preview this link")

# Test payloads (cloud metadata):
http://169.254.169.254/latest/meta-data/         # AWS
http://169.254.169.254/computeMetadata/v1/       # GCP (needs header)
http://169.254.169.254/metadata/instance         # Azure

# Bypass common filters:
http://0x7f000001/               # 127.0.0.1 in hex
http://127.1/                    # Shortened loopback
http://[::1]/                    # IPv6 loopback
http://2130706433/               # 127.0.0.1 as integer
http://attacker.com@127.0.0.1/  # @ trick

# OOB detection (when response is blind):
http://<your_burp_collaborator>/
http://<your_interactsh_url>/
```

### JWT Attacks Quick Reference

```bash
# Test alg:none (manually modify header)
# Original: {"alg":"HS256","typ":"JWT"}
# Modified: {"alg":"none","typ":"JWT"}
# Remove signature, keep trailing dot

# Crack weak HS256 secret
hashcat -m 16500 <jwt_token> /usr/share/wordlists/rockyou.txt

# Test key confusion (RS256 → HS256)
# If server uses RS256, try signing with public key as HMAC secret
python3 jwt_tool.py <token> -X k -pk public.pem

# JWK injection
# Craft a token with "jwk" header parameter pointing to your own key
```

---

## Week 3: API and Advanced Web Attacks

**Goal:** Learn to systematically test APIs and exploit advanced web vulnerabilities that have higher payouts and less competition.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/graphql](/web/graphql) | GraphQL introspection, query abuse, batch attacks, IDOR |
| [/web/http-smuggling](/web/http-smuggling) | CL.TE, TE.CL, TE.TE smuggling; server desync attacks |
| [/web/oauth](/web/oauth) | OAuth flow attacks, state bypass, redirect_uri manipulation |
| [/web/api-testing](/web/api-testing) | REST API methodology, IDOR, mass assignment, BOLA |

### API Testing Methodology

```
1. Collect all API endpoints
   - Burp Suite spider + proxy all traffic
   - Check JS files for hardcoded endpoints: grep -r "api/" --include="*.js"
   - Look for OpenAPI/Swagger docs at /api-docs, /swagger, /openapi.json
   - Check mobile app traffic (proxy Android/iOS)

2. Understand object references
   - Map every ID to what object it represents
   - Test: can user A access user B's resources by changing the ID?
   - Test: can non-admin access admin endpoints?

3. Test HTTP methods
   - Many APIs restrict GET but allow PUT/PATCH/DELETE without auth check
   - Try PATCH on objects you shouldn't own
   - Try DELETE on other users' resources

4. Mass assignment
   - POST /api/users {name: "test"} — try adding: "role": "admin", "is_admin": true
   - Look at the full response object for field names to use in requests

5. Rate limiting
   - Is there rate limiting on auth endpoints?
   - Can you enumerate users via timing differences?
   - Can you bypass via X-Forwarded-For: 127.0.0.1 header?
```

### GraphQL Attack Surface

```bash
# Introspection query (check if enabled)
{__schema{queryType{name}}}

# Full introspection
{"query":"{ __schema { types { name fields { name } } } }"}

# Batching for brute force (bypass rate limiting)
[
  {"query":"mutation{login(email:\"admin@example.com\",password:\"password1\")}"},
  {"query":"mutation{login(email:\"admin@example.com\",password:\"password2\")}"},
  ...
]

# Useful GraphQL tools:
# graphql-cop — security audit tool
# InQL (Burp extension) — introspection and testing
# clairvoyance — introspection without enabled introspection
```

### IDOR — The Highest ROI Bug Class for Beginners

IDOR (Insecure Direct Object Reference) is the most commonly found bug in bug bounty programs. It occurs when an application uses user-controllable input to access objects without authorization checks.

**IDOR hunting approach:**
1. Create two accounts (Account A and Account B)
2. Perform all actions in Account A while Burp is proxying
3. Note all numeric or UUID object references in requests/responses
4. Log in as Account B, replay Account A's requests with Account A's object IDs
5. Can Account B read/modify/delete Account A's data?

Common IDOR locations:
- Order IDs in e-commerce apps
- Invoice/document IDs
- User profile photo URLs
- Message/notification IDs
- API keys or token management
- Report/export download IDs

---

## Week 4: Reporting and Program Selection

**Goal:** Write compelling, impactful bug reports and develop a strategy for selecting programs where you can succeed.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding documentation, evidence quality, remediation writing |

### Program Selection Criteria

| Criterion | What to Look For | Why It Matters |
|---|---|---|
| Scope width | `*.company.com` is better than specific subdomains | More attack surface = more bugs |
| Program age | Newer programs have more unpatched bugs | Competition is lower early |
| Response time | Average time to first response < 3 days | Faster feedback loop |
| Payout history | Consistent payouts, not "hall of fame only" | You get paid |
| Duplicate rate | Lower is better | Your bugs are still findable |
| Managed vs unmanaged | Managed (with platform triage) is more reliable | Less risk of "wont fix" |

**Practical selection strategy for beginners:**
1. Find programs less than 6 months old on HackerOne (sort by newest)
2. Prioritize wide scope programs with API components
3. Look for programs with web + mobile scope (mobile APIs are often less tested)
4. Avoid programs with "no monetary reward" unless building reputation

### Finding Your First Bug: Low-Hanging Fruit

These vulnerabilities require minimal skill and are found frequently in newer or less-tested programs:

**1. Exposed .git directories**
```bash
# Check target for exposed git repo
curl -s https://target.com/.git/HEAD
# If returns "ref: refs/heads/main" — git is exposed
# Use git-dumper to extract the repo
git-dumper https://target.com/.git output_dir/
```

**2. Open Redirects**
```
# Test common redirect parameters:
https://target.com/redirect?url=https://evil.com
https://target.com/out?to=//evil.com
https://target.com/login?next=//evil.com
```

**3. Missing Authentication on API Endpoints**
```bash
# Test endpoints without Authorization header
# Many apps have mobile API endpoints that lack auth checks
curl -H "Content-Type: application/json" https://api.target.com/v1/users
curl -H "Content-Type: application/json" https://api.target.com/v1/admin/users
```

**4. Information Disclosure in Error Messages**
```bash
# Send malformed requests and observe error messages
curl -X POST https://target.com/api/data -H "Content-Type: application/json" -d '{"key": "'
# Stack traces, database errors, framework version info = reportable
```

### Bug Bounty Report Writing

A good bug bounty report converts directly into payout speed and amount. Poor reports get triaged slowly and sometimes wrongly downgraded.

**Required sections:**
```markdown
## Summary
One paragraph: what is the vulnerability, what is affected, what can an attacker do.

## Steps to Reproduce
1. Log in to https://target.com as a standard user
2. Navigate to /account/settings
3. Capture the POST /api/profile request in Burp Suite
4. Modify the "role" parameter from "user" to "admin"
5. Forward the request
6. Observe that the user's role is now "admin" (confirmed by GET /api/me response)

## Proof of Concept
[Screenshot showing the modified request in Burp]
[Screenshot showing the admin role in the response]
[Video recording if the vulnerability requires specific timing]

## Impact
A malicious user can escalate their account to administrator role without any admin approval.
As an administrator, they can access [specific admin functionality], view [sensitive data], 
and modify [other users' settings].

## CVSS Score
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N — Score: 8.1 (High)

## Remediation
- Implement server-side authorization checks on all profile update endpoints
- Whitelist acceptable values for the "role" field (do not allow user input to set roles)
- Review all API endpoints that accept object properties for similar mass assignment issues
```

### CVSS Score Reference

| Score Range | Severity | Typical Bounty Tier |
|---|---|---|
| 9.0–10.0 | Critical | Top tier |
| 7.0–8.9 | High | High tier |
| 4.0–6.9 | Medium | Medium tier |
| 0.1–3.9 | Low | Low tier or informational |

**Common beginner mistakes in reports:**
- Unclear reproduction steps (triager cannot reproduce = no payout)
- Missing screenshots or proof
- Overstating impact (claiming critical for a low-severity bug damages credibility)
- Understating impact (failing to show full impact means lower payout)
- Reporting to wrong program (out-of-scope = automatic closed/duplicate risk)

### Building a Long-Term Bug Bounty Practice

**Reputation building:**
- Engage professionally with triagers even when reports are closed
- Write detailed disclosure blog posts after CVDs (coordinate with program)
- Help other hunters in community Discords (gives you insight into what's being found)

**Tooling investment:**
- Burp Suite Pro is non-negotiable for serious hunting ($449/year)
- Nuclei for automated initial scanning
- Caido as an alternative/supplement to Burp
- Custom wordlists built from your findings

**Tracking your work:**
- Keep a database of all programs you've tested
- Track: dates tested, bugs found, bugs paid, duplicates
- Revisit programs after major releases (new features = new bugs)
- Set up monitoring for scope changes and new programs

---

## Essential Bug Bounty Resources

| Resource | Type | Purpose |
|---|---|---|
| HackerOne Hacktivity | Feed | See publicly disclosed reports — best learning resource |
| Bugcrowd University | Free course | Platform-specific learning |
| PortSwigger Web Academy | Free lab | Best web vuln learning platform |
| PentesterLab | Structured labs | Badge-based skill building |
| nahamsec Bug Bounty resources | GitHub | Curated list of tools and resources |
| OWASP Testing Guide | Reference | Comprehensive testing methodology |
| Jason Haddix Bug Hunter's Methodology | Talk/notes | Updated methodology from a top hunter |
| Bug Bounty Forum | Community | Program reviews, technique sharing |
