---
layout: training-page
title: "Mobile Security Overview — Red Team Academy"
module: "Mobile Security"
tags:
  - mobile
  - android
  - ios
  - owasp-mobile
page_key: "mobile-overview"
---
<h1>Mobile Security Overview</h1>
<p>Mobile application security testing covers Android and iOS platforms, assessing apps for insecure data storage, improper authentication, network vulnerabilities, and platform-specific weaknesses. Mobile apps often expose the same backend APIs as web apps but with additional attack surface from the client binary itself.</p>

<h2>OWASP Mobile Top 10 (2024)</h2>
<pre><code>M1  — Improper Credential Usage
      Hardcoded credentials, insecure credential storage, weak auth

M2  — Inadequate Supply Chain Security
      Third-party SDKs, malicious libraries, build process compromise

M3  — Insecure Authentication / Authorization
      Broken auth flows, missing server-side checks, JWT weaknesses

M4  — Insufficient Input / Output Validation
      SQL injection via mobile, XSS in WebViews, intent injection

M5  — Insecure Communication
      Cleartext traffic, improper TLS validation, SSL pinning absent

M6  — Inadequate Privacy Controls
      Excessive permissions, PII in logs, clipboard leakage

M7  — Insufficient Binary Protections
      No obfuscation, no root/jailbreak detection, no integrity check

M8  — Security Misconfiguration
      Debug builds in production, exported components, weak permissions

M9  — Insecure Data Storage
      Plaintext in SharedPreferences, SQLite, logs, backups, Keychain

M10 — Insufficient Cryptography
      Weak algorithms, hardcoded keys, improper IV usage</code></pre>

<h2>Mobile Attack Surface</h2>
<pre><code>Client-side:
  Binary / bytecode       — decompile APK/IPA, extract logic and secrets
  Local storage           — SharedPreferences, SQLite, files, Keychain
  Logs                    — sensitive data written to logcat / syslog
  Clipboard               — passwords copied to clipboard
  Inter-process comms     — exported Activities, BroadcastReceivers, Services
  WebViews                — JavaScript bridge, file:// access, XSS

Network:
  API calls               — same as web app testing but intercepted via proxy
  SSL pinning             — must bypass to intercept HTTPS traffic
  Certificate validation  — missing/improper TLS checks
  Cleartext traffic       — HTTP used for some endpoints

Platform:
  Permissions             — excessive permissions requested
  Root/jailbreak          — device compromise enables full access
  Backup                  — adb backup extracts unencrypted app data
  Deep links / intents    — malicious apps can invoke exposed components</code></pre>

<h2>Testing Environments</h2>
<h3>Android</h3>
<pre><code># Physical device (preferred)
# - Root with Magisk for full access
# - Easier to intercept real network traffic

# Android Emulator (AVD)
# - Android Studio AVD Manager
# - Choose Google APIs image (not Google Play — harder to root)
# - ARM or x86 image (x86 faster but some apps check architecture)

# Genymotion — faster emulator, easy rooting
# genymotion.com</code></pre>

<h3>iOS</h3>
<pre><code># Physical device required for most testing
# - Jailbreak with checkra1n (A7-A11 chips) or palera1n (A9-A16)
# - iPhone 6s through X best for checkra1n compatibility

# Corellium — cloud-based iOS virtualization (commercial)
# corellium.com — excellent for enterprise testing without physical devices</code></pre>

<h2>Methodology Overview</h2>
<pre><code">Phase 1: Reconnaissance
  - Identify app version, permissions, technologies used
  - Download APK/IPA for static analysis

Phase 2: Static Analysis
  - Decompile binary
  - Find hardcoded credentials, API keys, secrets
  - Review manifest / Info.plist for misconfigurations
  - Map exported components, URL schemes, deep links

Phase 3: Dynamic Analysis
  - Set up proxy (Burp Suite)
  - Bypass SSL pinning
  - Intercept and modify API traffic
  - Instrument with Frida / Objection

Phase 4: Data Storage Analysis
  - Check SharedPreferences, SQLite, files for sensitive data
  - Review logcat output
  - Test backup extraction

Phase 5: Authentication / Authorization
  - Replay attacks on API tokens
  - Test for broken object-level authorization (BOLA/IDOR)
  - Check for server-side enforcement of restrictions</code></pre>

<h2>Key Tools Summary</h2>
<pre><code">Static Analysis:
  jadx-gui        — Android: decompile APK to readable Java
  apktool         — Android: decode resources and smali
  MobSF           — both: automated static + dynamic analysis
  class-dump      — iOS: dump Objective-C class headers
  Ghidra / IDA    — binary reverse engineering

Dynamic Analysis:
  Frida           — runtime instrumentation and hooking
  Objection       — Frida-based mobile pentest toolkit
  Burp Suite      — HTTP/HTTPS proxy

Platform Tools:
  adb             — Android Debug Bridge
  idb             — iOS Debug Bridge
  apksigner       — APK signing for repackaging</code></pre>

<h2>Resources</h2>
<ul>
  <li>OWASP Mobile Security Testing Guide — <code>mas.owasp.org</code></li>
  <li>OWASP Mobile Top 10 — <code>owasp.org/www-project-mobile-top-10/</code></li>
  <li>MobSF — Mobile Security Framework — <code>github.com/MobSF/Mobile-Security-Framework-MobSF</code></li>
  <li>Frida — <code>frida.re</code></li>
  <li>Objection — <code>github.com/sensepost/objection</code></li>
</ul>
