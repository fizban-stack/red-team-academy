---
layout: training-page
title: "Web Triage Cheatsheet — Red Team Academy"
module: "Ops Cheatsheets"
tags:
  - cheatsheet
  - web
  - triage
page_key: "cheatsheets-web-triage"
render_with_liquid: false
updated: "2026-04-13"
---

# Web Triage Cheatsheet

Prioritize when time is short: **map → authenticate → abuse trust boundaries → automate**.

## 1 — Surface map

- **Tech stack**: headers, cookies, `X-Powered-By`, JS bundles, WAF hints.
- **Scope**: hosts in scope, API base paths, mobile vs web parity.
- **Identity**: registration, SSO, OAuth/OIDC, password reset, MFA posture.

## 2 — Auth and session

- Login, logout, refresh, **password reset**, **remember me**, OAuth callbacks.
- Session fixation, cookie flags (`HttpOnly`, `Secure`, `SameSite`), JWT location (header vs cookie).

## 3 — High-yield bug classes (order flexibly)

| Class | Quick signal |
|-------|----------------|
| IDOR | predictable IDs, bulk export, role swap |
| SSRF | URL fetch, PDF generators, webhooks |
| XSS | reflected/stored, DOM sinks, CSP |
| SQLi | errors, timing, stack traces |
| File upload | extension, content-type, path traversal |
| Mass assignment | JSON PATCH, hidden fields |

## 4 — Tooling workflow (typical)

```
# Proxy everything through Burp; scope strictly
# Crawl + passive scan first; then targeted intruder/fuzzing on parameters

# ffuf example (authorized target only)
ffuf -u https://<TARGET>/FUZZ -w /path/to/wordlist -mc 200,301,302,403
```

## 5 — Evidence

- Request/response pairs with **timestamp** and **hash** of body when proving impact.
- Redact tokens and PII per program rules.

## Resources

- [Web pentest checklist](/web/web-pentest-checklist/)
- [Bug bounty methodology](/web/bug-bounty-methodology/)
- OWASP WSTG — [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)
