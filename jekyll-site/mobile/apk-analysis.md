---
layout: training-page
title: "APK Static Analysis — Red Team Academy"
module: "Mobile Security"
tags:
  - android
  - mobile
  - apk
  - static-analysis
  - reverse-engineering
page_key: "mobile-apk-analysis"
---
<h1>APK Static Analysis</h1>
<p>Static analysis of Android APKs involves decompiling the application to inspect source code, resources, and configuration without running it. The goal is to find hardcoded secrets, identify attack surface (exported components, deep links), and understand the application logic.</p>

<h2>APK Structure</h2>
<pre><code>app.apk (ZIP archive)
├── AndroidManifest.xml     # permissions, components, exported flags
├── classes.dex             # compiled Dalvik bytecode
├── classes2.dex            # additional dex (if multidex)
├── resources.arsc          # compiled resource table
├── res/                    # layouts, strings, drawables
├── assets/                 # raw assets bundled with app
├── lib/                    # native .so libraries (x86, arm64, etc.)
└── META-INF/               # signing certificates, MANIFEST.MF</code></pre>

<h2>Initial Recon</h2>
<pre><code"># Extract APK (it's just a ZIP)
unzip app.apk -d app_extracted/

# Read manifest (binary XML — use apktool or aapt)
aapt dump badging app.apk          # package name, version, permissions
aapt dump permissions app.apk     # declared permissions
aapt dump xmltree app.apk AndroidManifest.xml   # raw manifest

# Quick checks
strings app.apk | grep -i "http\|api\|key\|secret\|password\|token"
strings lib/arm64-v8a/libnative.so | grep -E "[A-Za-z0-9+/]{20,}"</code></pre>

<h2>apktool — Decode Resources &amp; Smali</h2>
<pre><code"># Decode APK (decompile to smali bytecode + decoded resources)
apktool d app.apk -o app_decoded/

# Key files after decoding:
# app_decoded/AndroidManifest.xml    — decoded, readable manifest
# app_decoded/res/values/strings.xml — string resources (may contain secrets)
# app_decoded/smali/                 — Dalvik assembly (readable but verbose)
# app_decoded/assets/                — raw assets

# Search for secrets in resources
grep -r "api_key\|secret\|password\|token\|key" app_decoded/res/

# Check for Firebase config
cat app_decoded/assets/google-services.json 2>/dev/null
grep -r "firebase\|firebaseio" app_decoded/</code></pre>

<h2>jadx — Decompile to Java</h2>
<pre><code"># jadx produces readable Java from Dalvik bytecode
# Download: github.com/skylot/jadx

# GUI (recommended)
jadx-gui app.apk

# CLI
jadx -d output_dir/ app.apk

# Key things to look for:
# 1. Hardcoded credentials and API keys
grep -r "password\|secret\|api_key\|apikey\|access_token" output_dir/

# 2. URL endpoints
grep -rE "https?://[a-zA-Z0-9./_-]+" output_dir/ | grep -v ".gradle"

# 3. Cryptographic keys
grep -rE "[A-Za-z0-9+/]{32,}={0,2}" output_dir/ | grep -v "R\.java"

# 4. Logging (sensitive data in logs)
grep -r "Log\.d\|Log\.v\|Log\.i\|System\.out\.print" output_dir/

# 5. Exported component handlers
grep -r "getIntent\(\)\|getStringExtra\|getParcelableExtra" output_dir/</code></pre>

<h2>AndroidManifest.xml Analysis</h2>
<pre><code">&lt;!-- Key things to check in AndroidManifest.xml --&gt;

&lt;!-- 1. Exported components (attack surface) --&gt;
android:exported="true"    &lt;!-- explicitly exported --&gt;
&lt;!-- Any component with an &lt;intent-filter&gt; is exported by default on API &lt; 31 --&gt;

&lt;!-- 2. Dangerous permissions --&gt;
android.permission.READ_CONTACTS
android.permission.ACCESS_FINE_LOCATION
android.permission.READ_SMS
android.permission.CAMERA
android.permission.RECORD_AUDIO

&lt;!-- 3. Backup enabled (allows adb backup data extraction) --&gt;
android:allowBackup="true"

&lt;!-- 4. Debug flag in production --&gt;
android:debuggable="true"

&lt;!-- 5. Deep link schemes --&gt;
&lt;data android:scheme="myapp" android:host="action" /&gt;

&lt;!-- 6. Network security config --&gt;
android:networkSecurityConfig="@xml/network_security_config"</code></pre>

<h2>MobSF — Automated Analysis</h2>
<pre><code"># Mobile Security Framework — web-based automated static + dynamic analysis
# github.com/MobSF/Mobile-Security-Framework-MobSF

# Docker install (easiest)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Browse to http://localhost:8000
# Upload APK → get automated report covering:
# - Hardcoded secrets and API keys
# - Manifest analysis (exported components, permissions)
# - Code analysis (dangerous functions, crypto usage)
# - Network analysis (URLs, IPs found in code)
# - Certificate analysis</code></pre>

<h2>Secrets Scanning</h2>
<pre><code"># After decoding with apktool + jadx, scan for secrets
# trufflehog on local directory
trufflehog filesystem ./output_dir/

# Custom grep patterns for common secrets
grep -rE "AKIA[A-Z0-9]{16}" .               # AWS access key
grep -rE "sk_live_[a-zA-Z0-9]{24}" .        # Stripe secret key
grep -rE "AIza[0-9A-Za-z\-_]{35}" .         # Google API key
grep -rE "ghp_[a-zA-Z0-9]{36}" .            # GitHub personal access token
grep -rE "[a-z0-9]{32}" .                   # Generic 32-char hex key</code></pre>

<h2>Native Library Analysis</h2>
<pre><code"># Native .so files may contain secrets or crypto implementations
# Extract and analyze with strings + Ghidra/IDA

strings lib/arm64-v8a/libnative.so | grep -iE "key|secret|password|http"

# Load in Ghidra for deeper analysis
# File → Import File → select .so
# Auto-analyze → search for string references</code></pre>

<h2>Resources</h2>
<ul>
  <li>jadx — <code>github.com/skylot/jadx</code></li>
  <li>apktool — <code>apktool.org</code></li>
  <li>MobSF — <code>github.com/MobSF/Mobile-Security-Framework-MobSF</code></li>
  <li>OWASP MASTG Android Static — <code>mas.owasp.org/MASTG/Android/0x05c-Reverse-Engineering-and-Tampering/</code></li>
</ul>
