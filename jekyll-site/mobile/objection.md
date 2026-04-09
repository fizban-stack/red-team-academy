---
layout: training-page
title: "Objection Framework — Red Team Academy"
module: "Mobile Security"
tags:
  - objection
  - mobile
  - frida
  - android
  - ios
page_key: "mobile-objection"
---
<h1>Objection Framework</h1>
<p>Objection is a runtime mobile exploration toolkit built on Frida. It provides a command-line interface for common mobile pentesting tasks without needing to write Frida scripts — bypassing SSL pinning, exploring the file system, dumping memory, and inspecting classes at runtime.</p>

<h2>Installation</h2>
<pre><code"># Install (requires Frida to be installed)
pip3 install objection

# Verify
objection version</code></pre>

<h2>Connecting to a Device</h2>
<pre><code"># Frida server must be running on device (see Frida setup page)

# Attach to a running app (by package name)
objection -g com.target.app explore

# Spawn fresh instance
objection -g com.target.app explore --startup-command "android sslpinning disable"

# iOS
objection -g com.target.ios.app explore

# List running apps
frida-ps -Uai</code></pre>

<h2>Android Commands</h2>
<h3>SSL Pinning</h3>
<pre><code"># Inside objection REPL:
android sslpinning disable

# Verbose mode (shows what it hooks)
android sslpinning disable --quiet false</code></pre>

<h3>Root Detection</h3>
<pre><code"># Bypass root detection checks
android root disable</code></pre>

<h3>File System</h3>
<pre><code"># Navigate app file system
file ls
file cd /data/data/com.target.app/
file ls
file cat /data/data/com.target.app/shared_prefs/settings.xml
file download /data/data/com.target.app/databases/app.db ./local_app.db</code></pre>

<h3>SharedPreferences</h3>
<pre><code"># List all SharedPreferences files and their contents
android shared_preferences list

# Get specific file
android shared_preferences get settings</code></pre>

<h3>SQLite Databases</h3>
<pre><code"># List databases
sqlite databases

# Execute query
sqlite execute --query "SELECT * FROM users" --database app.db</code></pre>

<h3>Class and Method Inspection</h3>
<pre><code"># List loaded classes (filter by name)
android hooking list classes
android hooking search classes Auth

# List methods on a class
android hooking list class_methods com.target.app.AuthManager

# Hook all methods on a class (logs calls with args and return values)
android hooking watch class com.target.app.AuthManager

# Hook a specific method
android hooking watch method 'com.target.app.AuthManager.checkPassword' \
    --dump-args --dump-backtrace --dump-return

# Set method return value
android hooking set return_value 'com.target.app.AuthManager.isRooted' false</code></pre>

<h3>Intent Monitoring</h3>
<pre><code"># Monitor all intent activity
android intent start_activity

# Broadcast intents
android intent broadcast</code></pre>

<h3>Memory</h3>
<pre><code"># Dump memory to file
memory dump all /tmp/memdump.bin

# Search memory for strings
memory search --string "password"
memory search --string "eyJ"   # JWT tokens (base64 start)</code></pre>

<h2>iOS Commands</h2>
<h3>SSL Pinning</h3>
<pre><code"># Disable SSL pinning
ios sslpinning disable</code></pre>

<h3>Jailbreak Detection</h3>
<pre><code"># Bypass jailbreak detection
ios jailbreak disable</code></pre>

<h3>File System</h3>
<pre><code"># Navigate app container
file ls
file cd /var/mobile/Containers/Data/Application/[UUID]/
file ls Documents/
file download Documents/app.db ./local.db</code></pre>

<h3>Keychain</h3>
<pre><code"># Dump Keychain entries for the app
ios keychain dump

# Dump with raw output
ios keychain dump --raw</code></pre>

<h3>UserDefaults (iOS equivalent of SharedPreferences)</h3>
<pre><code"># Get all UserDefaults
ios nsuserdefaults get</code></pre>

<h3>Class Inspection</h3>
<pre><code"># List classes
ios hooking list classes
ios hooking search classes Auth

# List methods
ios hooking list class_methods AuthManager

# Hook method
ios hooking watch method "-[AuthManager checkPassword:]" --dump-args --dump-return</code></pre>

<h2>Workflow Example — Full Android Assessment</h2>
<pre><code"># 1. Connect
objection -g com.target.app explore

# 2. Disable security checks
android sslpinning disable
android root disable

# 3. Explore storage
android shared_preferences list
sqlite databases
file ls /data/data/com.target.app/

# 4. Find credentials
memory search --string "password"
android keystore list

# 5. Hook authentication
android hooking search classes Auth
android hooking watch class com.target.app.AuthManager --dump-args --dump-return

# 6. Download interesting files
file download /data/data/com.target.app/databases/app.db ./app.db
# Then: sqlite3 app.db ".tables"</code></pre>

<h2>Resources</h2>
<ul>
  <li>Objection — <code>github.com/sensepost/objection</code></li>
  <li>Objection wiki — <code>github.com/sensepost/objection/wiki</code></li>
  <li>Frida — <code>frida.re</code></li>
</ul>
