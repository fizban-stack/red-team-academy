---
layout: training-page
title: "Frida Dynamic Instrumentation — Red Team Academy"
module: "Mobile Security"
tags:
  - frida
  - mobile
  - dynamic-analysis
  - hooking
  - android
  - ios
page_key: "mobile-frida"
---
<h1>Frida Dynamic Instrumentation</h1>
<p>Frida is a dynamic instrumentation toolkit that lets you inject JavaScript into native apps at runtime. On mobile it is used to hook functions, bypass security checks, dump decrypted data, and modify app behavior without recompiling or repackaging.</p>

<h2>Installation</h2>
<pre><code"># Host (your pentest machine)
pip install frida-tools

# Verify
frida --version

# Android device — push frida-server
# Download from github.com/frida/frida/releases
# Match frida-server version exactly to frida-tools version

adb root
adb push frida-server-16.x.x-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &amp;"

# iOS — install Frida from Sileo/Cydia
# Repo: https://build.frida.re → install Frida package

# Verify connectivity
frida-ps -U        # list processes on USB device
frida-ps -Ua       # list running apps</code></pre>

<h2>Basic Usage</h2>
<pre><code"># Attach to running process
frida -U com.target.app

# Spawn and attach (recommended — catches early init)
frida -U -f com.target.app --no-pause

# Run a script
frida -U -f com.target.app -l script.js --no-pause

# REPL — interactive JavaScript console
frida -U com.target.app
[Frida REPL]  Java.perform(() =&gt; { ... })</code></pre>

<h2>Core Frida APIs</h2>
<h3>Android (Java)</h3>
<pre><code">// Enumerate loaded classes
Java.enumerateLoadedClasses({
    onMatch: function(name) {
        if (name.includes("Target")) console.log(name);
    },
    onComplete: function() {}
});

// Hook a method
Java.perform(function() {
    var TargetClass = Java.use("com.target.app.AuthManager");
    TargetClass.checkPassword.implementation = function(password) {
        console.log("[*] checkPassword called with: " + password);
        var result = this.checkPassword(password);
        console.log("[*] Result: " + result);
        return result;  // return true to bypass
    };
});

// Overload resolution (when method has multiple signatures)
TargetClass.checkPassword.overload("java.lang.String").implementation = function(p) {
    return true;
};

// Print stack trace
Java.perform(function() {
    var Exception = Java.use("java.lang.Exception");
    var e = Exception.$new();
    console.log(e.getStackTrace().join("\n"));
});</code></pre>

<h3>iOS (Objective-C)</h3>
<pre><code">// Hook Objective-C method
var hook = ObjC.classes.AuthManager["- checkPassword:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        // args[0] = self, args[1] = selector, args[2+] = method args
        var password = ObjC.Object(args[2]).toString();
        console.log("[*] checkPassword: " + password);
    },
    onLeave: function(retval) {
        console.log("[*] Return: " + retval);
        retval.replace(1);  // return YES (true)
    }
});

// List all classes
for (var cls in ObjC.classes) {
    if (cls.includes("Auth")) console.log(cls);
}

// List methods on a class
var methods = ObjC.classes.AuthManager.$ownMethods;
console.log(methods.join("\n"));</code></pre>

<h2>Common Security Bypass Scripts</h2>
<h3>Root / Jailbreak Detection Bypass (Android)</h3>
<pre><code">Java.perform(function() {
    // Hook common root check method names
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        console.log("[*] isRooted() bypassed");
        return false;
    };

    // Generic: any method returning boolean that checks for root
    // Identify via jadx, then hook specifically
});</code></pre>

<h3>SSL Pinning Bypass (Android)</h3>
<pre><code">// Universal unpinner — hooks multiple common implementations
// See: mobile/ssl-pinning-bypass for full coverage

Java.perform(function() {
    // OkHttp3 CertificatePinner bypass
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List")
        .implementation = function(hostname, peerCertificates) {
            console.log("[*] SSL pinning bypassed for: " + hostname);
        };
});</code></pre>

<h3>Dump Decrypted Strings</h3>
<pre><code">// Hook crypto decryption to capture plaintext output
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        var result = this.doFinal(input);
        console.log("[*] Decrypted: " + Java.array("byte", result));
        return result;
    };
});</code></pre>

<h2>Frida Scripts — Useful One-liners</h2>
<pre><code"># Dump all HTTP/HTTPS traffic (hook OkHttp)
frida -U -f com.target.app -l okhttp-logger.js --no-pause

# Enumerate all methods called at runtime
frida-trace -U -f com.target.app -j "com.target.*!*"

# Trace native function calls
frida-trace -U -f com.target.app -i "open" -i "read" -i "write"

# Dump SharedPreferences at runtime
frida -U com.target.app -e "
  Java.perform(function() {
    var SharedPreferences = Java.use('android.app.ContextImpl');
    // use frida-scripts repo for ready-made scripts
  })
"</code></pre>

<h2>Resources</h2>
<ul>
  <li>Frida documentation — <code>frida.re/docs/</code></li>
  <li>Frida releases — <code>github.com/frida/frida/releases</code></li>
  <li>frida-scripts collection — <code>github.com/interference-security/frida-scripts</code></li>
  <li>Universal SSL unpinner — <code>github.com/httptoolkit/frida-android-unpinning</code></li>
  <li>Objection — Frida-based pentest toolkit — <code>github.com/sensepost/objection</code></li>
</ul>
