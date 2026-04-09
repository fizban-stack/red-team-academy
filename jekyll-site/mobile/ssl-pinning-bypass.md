---
layout: training-page
title: "SSL Pinning Bypass — Red Team Academy"
module: "Mobile Security"
tags:
  - ssl-pinning
  - mobile
  - frida
  - objection
  - android
  - ios
page_key: "mobile-ssl-pinning"
---
<h1>SSL Pinning Bypass</h1>
<p>SSL pinning causes an app to verify that the server's certificate matches a specific expected value (hash or public key) rather than accepting any certificate signed by a trusted CA. Bypassing it is a prerequisite for intercepting HTTPS traffic with Burp Suite.</p>

<h2>Detecting SSL Pinning</h2>
<pre><code"># Signs that an app uses SSL pinning:
# 1. Burp proxy causes app to show a network error / crash
# 2. App functions normally without proxy but fails with proxy
# 3. Static analysis shows pinning code (see below)

# Static detection in jadx output:
grep -r "CertificatePinner\|TrustManager\|checkServerTrusted\|getAcceptedIssuers" output/
grep -r "X509TrustManager\|SSLContext\|TrustKit\|TrustKit" output/
grep -r "javax.net.ssl" output/</code></pre>

<h2>Method 1: Objection (Easiest)</h2>
<pre><code"># Requires: rooted Android or jailbroken iOS + Frida server running

# Android
objection -g com.target.app explore
android sslpinning disable

# iOS
objection -g com.target.ios.app explore
ios sslpinning disable

# Objection hooks the most common pinning implementations automatically:
# - OkHttp3 CertificatePinner
# - TrustKit
# - HttpsURLConnection
# - Apache HttpClient</code></pre>

<h2>Method 2: Frida Universal Unpinner</h2>
<pre><code"># httptoolkit/frida-android-unpinning — hooks 20+ SSL pinning implementations

# Download the script
wget https://raw.githubusercontent.com/httptoolkit/frida-android-unpinning/main/frida-script.js

# Run it
frida -U -f com.target.app -l frida-script.js --no-pause

# Covers:
# OkHttp3, Conscrypt, Cronet, Kotlin, Flutter, Xamarin, Cordova, React Native</code></pre>

<h2>Method 3: APK Patching (No Root Required)</h2>
<pre><code"># Repackage the APK with pinning removed — works on non-rooted devices
# Requires: apktool, uber-apk-signer

# 1. Decode APK
apktool d app.apk -o app_decoded/

# 2. Edit network_security_config.xml (or create it)
# app_decoded/res/xml/network_security_config.xml
cat &gt; app_decoded/res/xml/network_security_config.xml &lt;&lt; 'EOF'
&lt;?xml version="1.0" encoding="utf-8"?&gt;
&lt;network-security-config&gt;
    &lt;base-config&gt;
        &lt;trust-anchors&gt;
            &lt;certificates src="system" /&gt;
            &lt;certificates src="user" /&gt;
        &lt;/trust-anchors&gt;
    &lt;/base-config&gt;
&lt;/network-security-config&gt;
EOF

# 3. Update AndroidManifest.xml to reference the config
# Add to &lt;application&gt; tag:
# android:networkSecurityConfig="@xml/network_security_config"

# 4. Rebuild and sign
apktool b app_decoded/ -o app_patched.apk
uber-apk-signer --apks app_patched.apk

# 5. Install patched APK
adb install -r app_patched.apk</code></pre>

<h2>Method 4: apk-mitm (Automated Patching)</h2>
<pre><code"># apk-mitm automates the patching process
# github.com/shroudedcode/apk-mitm
# npm install -g apk-mitm

apk-mitm app.apk

# Automatically:
# - Disables certificate pinning via network_security_config
# - Patches the APK
# - Signs with a debug key
# Outputs: app-patched.apk — install directly</code></pre>

<h2>Method 5: Manual Frida Hook (Custom Implementations)</h2>
<pre><code">// For custom or obfuscated pinning implementations — hook the actual verification

Java.perform(function() {
    // Hook TrustManager checkServerTrusted
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManager = Java.registerClass({
        name: "com.custom.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContextInstance = SSLContext.getInstance("TLS");
    SSLContextInstance.init(null, TrustManagers, null);
    SSLContext.getDefault.implementation = function() {
        return SSLContextInstance;
    };
});</code></pre>

<h2>iOS SSL Pinning Bypass</h2>
<pre><code"># Method 1: Objection
ios sslpinning disable

# Method 2: SSL Kill Switch 2 (Cydia tweak)
# Install via Cydia/Sileo: SSL Kill Switch 2
# Settings → SSL Kill Switch 2 → Enable

# Method 3: Frida script for TrustKit / AFNetworking
# frida-scripts/ios-ssl-pinning-bypass.js

# Method 4: Patch Info.plist to remove pinning config
# ATS exceptions: NSAllowsArbitraryLoads = true in Info.plist</code></pre>

<h2>Flutter Apps</h2>
<pre><code"># Flutter uses Dart's own network stack — standard hooks may not work
# Use: ressl (reSSL Flutter unpinner)
# github.com/lrq3000/ressl

# Or: patch the libflutter.so to disable certificate verification
# frida-android-unpinning covers Flutter in newer versions</code></pre>

<h2>Verification</h2>
<pre><code"># After applying bypass, confirm interception works:
# 1. Start Burp listener
# 2. Configure device proxy
# 3. Launch app with bypass active
# 4. Use app features that make network requests
# 5. Check Burp → Proxy → HTTP History for HTTPS traffic</code></pre>

<h2>Resources</h2>
<ul>
  <li>frida-android-unpinning — <code>github.com/httptoolkit/frida-android-unpinning</code></li>
  <li>apk-mitm — <code>github.com/shroudedcode/apk-mitm</code></li>
  <li>SSL Kill Switch 2 — <code>github.com/nabla-c0d3/ssl-kill-switch2</code></li>
  <li>Objection — <code>github.com/sensepost/objection</code></li>
  <li>OWASP MASTG — Network Communication — <code>mas.owasp.org</code></li>
</ul>
