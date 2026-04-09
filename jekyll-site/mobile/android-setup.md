---
layout: training-page
title: "Android Pentest Setup — Red Team Academy"
module: "Mobile Security"
tags:
  - android
  - mobile
  - adb
  - setup
  - burp
page_key: "mobile-android-setup"
---
<h1>Android Pentest Setup</h1>
<p>Setting up an Android penetration testing environment — device/emulator configuration, ADB, rooting, and Burp Suite proxy interception.</p>

<h2>Device vs Emulator</h2>
<pre><code># Physical device (preferred)
# + Real hardware, real baseband, real app behavior
# + Easier to intercept traffic on real network
# - Requires rooting, which may vary by device/OEM

# Android Emulator (AVD)
# + Free, easy to snapshot/restore, multiple API versions
# + Already rooted (Google APIs images)
# - Some apps detect emulator and refuse to run
# - Slower than physical device

# Genymotion (recommended emulator)
# + Faster than AVD, easy root, good for quick testing
# genymotion.com — community edition is free</code></pre>

<h2>Android Emulator Setup (AVD)</h2>
<pre><code># Install Android Studio → SDK Manager → install API level you need
# AVD Manager → Create Virtual Device

# Choose image: "Google APIs" (NOT "Google Play")
# Google APIs images are rooted by default
# Google Play images have protections that prevent rooting

# Start emulator from command line
emulator -avd Pixel_6_API_33 -writable-system

# Verify root access
adb shell
su
id  # should show uid=0(root)</code></pre>

<h2>ADB — Android Debug Bridge</h2>
<pre><code># Enable on physical device:
# Settings → About Phone → tap Build Number 7 times
# Settings → Developer Options → Enable USB Debugging

# Connect and verify
adb devices
adb shell

# Essential ADB commands
adb install app.apk                          # install APK
adb pull /data/data/com.app/                 # pull app data
adb push file.txt /sdcard/                  # push file
adb logcat                                   # live device log
adb logcat | grep "com.targetapp"            # filter to target app
adb backup -apk -f backup.ab com.targetapp  # backup app data

# Port forwarding (for proxy)
adb reverse tcp:8080 tcp:8080  # forward device port to Burp on host

# Shell commands
adb shell pm list packages              # list installed packages
adb shell pm path com.targetapp         # find APK path
adb shell dumpsys package com.targetapp # detailed package info
adb shell am start -n com.app/.MainActivity  # launch activity</code></pre>

<h2>Rooting Physical Devices</h2>
<pre><code># Magisk — most common root method
# github.com/topjohnwu/Magisk

# General process:
# 1. Unlock bootloader (varies by OEM — may wipe device)
# 2. Flash recovery (TWRP) or use Magisk boot image patching
# 3. Patch boot.img with Magisk app
# 4. Flash patched boot.img via fastboot

fastboot devices
fastboot flash boot magisk_patched.img
fastboot reboot

# Verify root
adb shell
su
id</code></pre>

<h2>Burp Suite Proxy Setup</h2>
<pre><code"># 1. Configure Burp listener on all interfaces
# Burp → Proxy → Options → Add listener on 0.0.0.0:8080

# 2. Configure Android proxy
# Settings → Wi-Fi → Long-press network → Modify Network
# Proxy: Manual | Hostname: [your machine IP] | Port: 8080

# 3. Install Burp CA certificate (required for HTTPS)
# Browse to http://burp in Android browser → download cert
# Settings → Security → Install certificate from storage

# OR via ADB (faster)
# Export Burp cert as DER
openssl x509 -inform DER -in burp.der -out burp.pem
# Get cert hash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
mv burp.pem ${HASH}.0
# Push to system certs (requires root)
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot</code></pre>

<h2>Network Security Config Bypass</h2>
<pre><code># Android 7+ ignores user-installed CAs by default for apps targeting API 24+
# Apps must declare network_security_config.xml to trust user CAs

# Option 1: Patch APK to include user CAs (see apk-analysis page)
# Option 2: Install Burp cert as system CA (above — requires root)
# Option 3: Use Frida/Objection to bypass SSL pinning at runtime

# Check if app has custom network security config
apktool d app.apk
cat app/res/xml/network_security_config.xml</code></pre>

<h2>Useful Packages to Install</h2>
<pre><code"># Frida server — for dynamic instrumentation
# Download from: github.com/frida/frida/releases
# Match version to installed frida-tools on host

adb root
adb push frida-server-16.x.x-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &amp;

# Verify Frida connection
frida-ps -U   # list processes on USB-connected device</code></pre>

<h2>Extract APK from Device</h2>
<pre><code># Find package path
adb shell pm path com.targetapp
# package:/data/app/com.targetapp-1/base.apk

# Pull the APK
adb pull /data/app/com.targetapp-1/base.apk ./target.apk

# Or use apk-mitm / apkeep for automated extraction
apkeep -a com.targetapp ./</code></pre>

<h2>Resources</h2>
<ul>
  <li>ADB documentation — <code>developer.android.com/studio/command-line/adb</code></li>
  <li>Magisk — <code>github.com/topjohnwu/Magisk</code></li>
  <li>Frida — <code>frida.re/docs/installation/</code></li>
  <li>OWASP MASTG Android Setup — <code>mas.owasp.org/MASTG/Android/0x05b-Basic-Security_Testing/</code></li>
</ul>
