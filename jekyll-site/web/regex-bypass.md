---
layout: training-page
title: "ReDoS & Regex Bypass — Red Team Academy"
module: "Web Hacking"
tags:
  - redos
  - regex-bypass
  - denial-of-service
  - php
  - input-validation
page_key: "web-regex-bypass"
render_with_liquid: false
---

# ReDoS & Regex Bypass

Regular Expression Denial of Service (ReDoS) is an attack that exploits catastrophic backtracking in certain regular expression patterns. When a regex engine processes an input designed to trigger exponential backtracking, it can consume all available CPU time — causing the application to hang, time out, or crash. This is particularly impactful in synchronous server-side code where one slow regex blocks all other requests.

## Tools

- **redos-detector** — CLI and library that tests if a regex pattern is safe from ReDoS with certainty — `github.com/tjenkinson/redos-detector`
- **regexploit** — Finds vulnerable regex patterns and generates exploit strings — `github.com/doyensec/regexploit`
- **ReDoS Checker (Devina)** — Online tool to examine regex for DoS vulnerabilities — `devina.io/redos-checker`

## Evil Regex Patterns

A regex is "evil" (vulnerable to ReDoS) when it contains:

1. Grouping with repetition
2. Inside the repeated group: another repetition OR alternation with overlapping matches

Classic vulnerable patterns:

- `(a+)+` — nested repetition
- `([a-zA-Z]+)*` — repeated character class
- `(a|aa)+` — alternation with overlap
- `(a|a?)+` — alternation where one branch matches the other
- `(.*a){x}` for x > 10 — repetition with anchoring

## Triggering ReDoS

For evil patterns, a carefully crafted input causes the regex engine to try an exponential number of paths before declaring no match. The standard trigger is a long string of matching characters followed by a character that ultimately causes the entire match to fail:

```
aaaaaaaaaaaaaaaaaaaa!
# 20 'a' characters followed by '!'
# The engine tries all possible groupings of 'a' before failing on '!'
```

Testing the pattern `(a+)+$`:

```
import re, time

pattern = re.compile(r'(a+)+$')

# Safe input — matches instantly
start = time.time()
pattern.match('aaaa')
print(f"Short: {time.time()-start:.4f}s")

# Attack input — hangs for seconds or minutes
start = time.time()
pattern.match('aaaaaaaaaaaaaaaaaaaa!')
print(f"Attack: {time.time()-start:.4f}s")
```

## PHP Backtrack Limit Bypass

PHP's PCRE implementation has configurable limits on backtracking and recursion. When these limits are exceeded, `preg_match()` returns `false` instead of 0 (no match). This behavior difference can be exploited to bypass input validation that relies on regex matching — if the function returns `false`, a naive check like `if (preg_match(...) == false)` may incorrectly allow the input through.

PHP PCRE configuration defaults:

| Option | Default | Notes |
| --- | --- | --- |
| `pcre.backtrack_limit` | 1,000,000 | 100,000 for PHP < 5.3.7 |
| `pcre.recursion_limit` | 100,000 |  |
| `pcre.jit` | 1 | JIT compilation enabled |

Vulnerable PHP pattern:

```
<?php
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';

$result = preg_match($pattern, $subject);
// $result is FALSE (not 0!) because backtrack limit exceeded

// Dangerous check:
if ($result === false) {
    // This branch executes on ERROR, not just on "no match"
    echo "Error — may allow bypass";
}

// Safe check:
if ($result !== 1) {
    echo "Did not match or error";
}
?>
```

## Regex Bypass for Input Validation

Beyond DoS, regex patterns used for security validation can often be bypassed if they are not anchored correctly or make wrong assumptions about input structure.

### Missing Anchors

A regex without start and end anchors only needs to match anywhere in the string:

```
# Vulnerable — checks if input CONTAINS a valid email
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
# Without anchors: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
# Payload: "evil@hack.com<script>alert(1)</script>" — matches the email portion
```

### Newline Bypass (. vs [\s\S])

In many languages, `.` does not match newlines by default. A filter using `.` to block content can be bypassed by embedding newlines:

```
# PHP — dot does not match \n by default
preg_match('/^admin$/', "admin\nevil")  // 0 — matches "admin" before newline
# But if used without the /m flag, multiline bypasses may work
```

### Unicode and Case Folding

Case-insensitive regex matching may not cover all Unicode case equivalents. Characters that normalize to ASCII equivalents can bypass character-class checks:

```
# Bypassing a blacklist for "script" using Unicode
<SCRİPT>  # Turkish dotless I — may fold to lowercase differently
ſcript     # Latin small letter long S (U+017F) — NFKC normalizes to 's'
```

## ReDoS in Security Context

ReDoS is exploitable in:

- Input validation endpoints (email, URL, phone number validation)
- Web Application Firewalls that use regex rules
- Search functionality that compiles user-supplied regex (if not sandboxed)
- Log parsers and SIEM rules

A single HTTP request with a crafted payload can freeze a Node.js or PHP server that processes regex synchronously, taking it offline for several seconds — equivalent to a DoS attack with minimal bandwidth.

## Resources

- redos-detector — `github.com/tjenkinson/redos-detector`
- regexploit — `github.com/doyensec/regexploit`
- ReDoS Checker — `devina.io/redos-checker`
- Regular Expression Denial of Service — ReDoS — OWASP
- OWASP Validation Regex Repository — wiki.owasp.org
- PHP PCRE Configuration — php.net/manual/en/pcre.configuration.php
