---
layout: training-page
title: "iOS App Analysis — Red Team Academy"
module: "Mobile Security"
tags:
  - ios
  - mobile
  - static-analysis
  - reverse-engineering
  - keychain
page_key: "mobile-ios-analysis"
---
<h1>iOS App Analysis</h1>
<p>iOS app analysis covers static analysis of IPA files and binary inspection, dynamic analysis via Frida and Objection, and testing common iOS-specific weaknesses including insecure Keychain storage, data leakage, and URL scheme abuse.</p>

<h2>IPA Structure</h2>
<pre><code">App.ipa (ZIP archive)
└── Payload/
    └── App.app/
        ├── App                   # Mach-O binary (encrypted from App Store)
        ├── Info.plist            # App metadata, permissions, URL schemes
        ├── embedded.mobileprovision  # signing info
        ├── Frameworks/           # bundled frameworks
        └── Assets.car            # compiled assets</code></pre>

<h2>Extract &amp; Decrypt IPA</h2>
<pre><code"># App Store IPAs are encrypted with FairPlay DRM
# Must decrypt from a jailbroken device

# frida-ios-dump (recommended)
# github.com/AloneMonkey/frida-ios-dump
python3 dump.py com.target.app

# palera1n + ssh method:
# Install frida on device, run dump.py with SSH credentials configured

# Or use ipatool (download non-DRM IPAs where available)
# github.com/majd/ipatool
ipatool download -b com.target.app</code></pre>

<h2>Static Analysis — Info.plist</h2>
<pre><code"># Info.plist contains app config, permissions, URL schemes, ATS settings

# Convert binary plist to XML
plutil -convert xml1 Info.plist -o Info_readable.plist
# Or on Linux:
plistutil -i Info.plist -o Info.xml

# Key things to check:
# 1. URL schemes (deep links)
grep -i "CFBundleURLSchemes\|CFBundleURLName" Info.plist

# 2. App Transport Security exceptions (allow HTTP)
# NSAppTransportSecurity / NSAllowsArbitraryLoads = true = no TLS enforcement

# 3. Permissions (NSCameraUsageDescription, NSLocationUsageDescription, etc.)

# 4. Exported keys / secrets accidentally left in plist
grep -iE "key|secret|password|token|api" Info_readable.plist</code></pre>

<h2>Binary Analysis — class-dump</h2>
<pre><code"># class-dump extracts Objective-C class headers from Mach-O binary
# Reveals class names, method signatures, property names

# Install on macOS
brew install class-dump

# Dump headers
class-dump -H App -o ./headers/

# Search for interesting methods
grep -r "password\|token\|auth\|secret\|key" headers/
grep -r "URLScheme\|handleOpen\|application:openURL" headers/

# For Swift binaries — class-dump is less effective
# Use nm or strings instead:
nm App | grep -E "Auth|Login|Password|Token"
strings App | grep -iE "https?://|password|secret|api_key"</code></pre>

<h2>Binary Analysis — strings &amp; nm</h2>
<pre><code"># Extract strings from binary
strings App | grep -iE "http|api|key|secret|password|token"
strings App | grep -E "AKIA[A-Z0-9]{16}"   # AWS keys
strings App | grep -E "sk_live_"            # Stripe keys

# Symbol table (for non-stripped binaries)
nm App | grep -i "auth\|login\|password"

# Check if binary is encrypted (App Store = encrypted at offset)
otool -l App | grep -A4 "LC_ENCRYPTION_INFO"
# cryptid = 1 means encrypted (decrypt via jailbroken device first)</code></pre>

<h2>Dynamic Analysis — Keychain</h2>
<pre><code"># Keychain stores credentials, tokens, certificates
# Dump via Objection (jailbroken device required)
ios keychain dump

# Raw dump (includes binary data)
ios keychain dump --raw

# What to look for:
# - kSecClassGenericPassword — stored passwords
# - kSecClassInternetPassword — web credentials
# - kSecClassCertificate — client certificates
# - kSecClassKey — cryptographic keys

# Check Keychain protection levels (via static analysis in jadx equivalent):
# kSecAttrAccessibleAlways — readable even when device locked (insecure)
# kSecAttrAccessibleWhenUnlocked — correct
# kSecAttrAccessibleAfterFirstUnlock — correct for background access</code></pre>

<h2>Dynamic Analysis — File System</h2>
<pre><code"># App sandbox locations on jailbroken device:
# /var/mobile/Containers/Data/Application/[UUID]/
#   Documents/     — user-facing documents
#   Library/       — caches, preferences, application support
#   tmp/           — temporary files

# Via Objection
file ls
file cd /var/mobile/Containers/Data/Application/[UUID]/
file ls Library/Preferences/
file cat Library/Preferences/com.target.app.plist

# NSUserDefaults (stored as plist)
ios nsuserdefaults get

# SQLite databases
sqlite databases
sqlite execute --query "SELECT * FROM users" --database app.db

# Logcat equivalent (iOS system log)
# On device via SSH:
log stream --predicate 'subsystem == "com.target.app"'
# Look for logged credentials, tokens, sensitive data</code></pre>

<h2>URL Scheme / Deep Link Testing</h2>
<pre><code"># Find URL schemes in Info.plist
grep -A5 "CFBundleURLTypes" Info_readable.plist

# Test URL schemes from another app or Safari
# On device, open Safari and navigate to:
# targetapp://action?param=value

# Via idb or SSH:
open targetapp://reset?email=admin@target.com
open targetapp://oauth/callback?code=attacker_code

# Check how the app handles URL schemes in code
grep -r "application:openURL\|scene:openURLContexts\|handleDeepLink" headers/</code></pre>

<h2>iOS Data Protection Classes</h2>
<pre><code"># iOS files have protection classes — check if sensitive files use weak protection

# Via SSH on jailbroken device:
# List file protection attributes
find /var/mobile/Containers/Data/Application/[UUID]/ -exec ls -le {} \;

# Protection classes:
# NSFileProtectionComplete          — best, file locked when device locked
# NSFileProtectionCompleteUnlessOpen — accessible if file was open when locked
# NSFileProtectionCompleteUntilFirstUserAuthentication — default
# NSFileProtectionNone              — always accessible, worst</code></pre>

<h2>Resources</h2>
<ul>
  <li>frida-ios-dump — <code>github.com/AloneMonkey/frida-ios-dump</code></li>
  <li>class-dump — <code>github.com/nygard/class-dump</code></li>
  <li>idb — iOS App Security Assessment Tool — <code>github.com/dmayer/idb</code></li>
  <li>OWASP MASTG iOS Testing — <code>mas.owasp.org/MASTG/iOS/</code></li>
  <li>Objection iOS — <code>github.com/sensepost/objection</code></li>
</ul>
