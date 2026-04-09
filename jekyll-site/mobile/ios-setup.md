---
layout: training-page
title: "iOS Pentest Setup — Red Team Academy"
module: "Mobile Security"
tags:
  - ios
  - mobile
  - jailbreak
  - frida
  - burp
page_key: "mobile-ios-setup"
---
<h1>iOS Pentest Setup</h1>
<p>Setting up an iOS penetration testing environment — jailbreaking, Frida installation, and Burp Suite proxy configuration. Physical device required for most testing; Corellium provides virtualized iOS for commercial engagements.</p>

<h2>Jailbreaking</h2>
<h3>checkra1n (A7–A11, iOS 12–14.8.1)</h3>
<pre><code># Supports: iPhone 6s through iPhone X, iPad (various)
# Boot-tethered — must re-jailbreak on every reboot

# checkra1n.com — download for Linux or macOS
sudo ./checkra1n

# Put device in DFU mode:
# 1. Connect device, open checkra1n
# 2. Follow on-screen instructions for DFU entry
# 3. checkra1n patches the bootchain and installs loader

# After jailbreak — install Cydia or Sileo for packages</code></pre>

<h3>palera1n (A9–A16, iOS 15–17)</h3>
<pre><code"># Supports newer devices including iPhone 11, 12, 13, 14
# Semi-tethered on A15/A16; tethered on older

# github.com/palera1n/palera1n
# Install via CLI
curl -L https://github.com/palera1n/palera1n/releases/latest/download/palera1n-linux-x86_64 \
  -o palera1n
chmod +x palera1n
sudo ./palera1n --install-rootless  # iOS 15+, rootless jailbreak</code></pre>

<h3>Sileo / Cydia Package Manager</h3>
<pre><code># Sileo — modern package manager (preferred on newer jailbreaks)
# Cydia — legacy, still works on older jailbreaks

# Essential packages to install:
OpenSSH          — remote shell access to device
Frida            — from Frida.re repo: https://build.frida.re
ldid             — codesigning utility
debugserver      — LLDB debugging support
AppSync Unified  — install unsigned IPAs</code></pre>

<h2>SSH Access</h2>
<pre><code># After installing OpenSSH via Sileo/Cydia:

# Connect via USB tunnel (preferred)
# Install: brew install libimobiledevice iproxy
iproxy 2222 22 &amp;
ssh root@localhost -p 2222
# Default password: alpine (CHANGE THIS)

# Change default passwords immediately
passwd root
passwd mobile

# Or connect over Wi-Fi
ssh root@[device-ip]</code></pre>

<h2>Frida on iOS</h2>
<pre><code># Install Frida server via Sileo/Cydia
# Add repo: https://build.frida.re
# Install: Frida package

# On host — install matching frida-tools version
pip install frida-tools==16.x.x

# Verify connection
frida-ps -U        # list processes (USB)
frida-ps -Ua       # list apps
frida-ps -Uai      # list apps with identifiers

# Launch app with Frida
frida -U -f com.target.app --no-pause</code></pre>

<h2>Burp Suite Proxy Setup</h2>
<pre><code># 1. Configure Burp listener on all interfaces
# Burp → Proxy → Options → Add: 0.0.0.0:8080

# 2. Configure iOS proxy
# Settings → Wi-Fi → tap info (i) next to network
# Configure Proxy → Manual
# Server: [your machine IP]  Port: 8080

# 3. Install Burp CA certificate
# On iOS device, browse to http://burp
# Download cacert.der
# Settings → General → VPN &amp; Device Management → install profile
# Settings → General → About → Certificate Trust Settings → enable Burp CA

# 4. Trust the certificate
# Settings → General → About → Certificate Trust Settings
# Toggle on "PortSwigger CA"</code></pre>

<h2>IPA Extraction</h2>
<pre><code"># Method 1: frida-ios-dump (decrypts and dumps IPA from running app)
# github.com/AloneMonkey/frida-ios-dump

git clone https://github.com/AloneMonkey/frida-ios-dump
pip install -r requirements.txt

# Configure dump.py: set HOST, PORT, USER, PASSWORD for SSH
python3 dump.py -l          # list installed apps
python3 dump.py com.target.app    # dump decrypted IPA

# Method 2: ipainstaller / SSH pull
# For apps installed via AppSync:
# /var/containers/Bundle/Application/[UUID]/App.app</code></pre>

<h2>Useful Tools on Device</h2>
<pre><code"># Install via Sileo/Cydia:
sqlite3        — query app databases directly
strings        — extract strings from binaries
class-dump-z   — dump Objective-C/Swift class headers
cycript        — runtime inspection and patching (older apps)
adv-cmds       — ps, top, and other Unix utilities

# File system navigation
ls /var/mobile/Containers/Data/Application/     # app data containers
ls /var/containers/Bundle/Application/          # app bundles</code></pre>

<h2>Resources</h2>
<ul>
  <li>checkra1n — <code>checkra1n.com</code></li>
  <li>palera1n — <code>github.com/palera1n/palera1n</code></li>
  <li>Frida on iOS — <code>frida.re/docs/ios/</code></li>
  <li>frida-ios-dump — <code>github.com/AloneMonkey/frida-ios-dump</code></li>
  <li>OWASP MASTG iOS Setup — <code>mas.owasp.org/MASTG/iOS/0x06b-Basic-Security-Testing/</code></li>
</ul>
