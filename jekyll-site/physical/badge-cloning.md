---
layout: training-page
title: "Badge Cloning & RFID/NFC Physical Access — Red Team Academy"
module: "Physical Red Team"
tags:
  - physical
  - rfid
  - nfc
  - badge-cloning
  - proxmark
page_key: "physical-badge-cloning"
render_with_liquid: false
---

# Badge Cloning & RFID/NFC Physical Access

Access control systems based on RFID and NFC proximity cards are prevalent in corporate environments. Many deployments use card technologies that are trivially cloneable, enabling red teamers to acquire and replay credentials without any visible interaction with a badge reader.

## Access Control Technology Primer

| Technology | Frequency | Common Systems | Security Level |
|-----------|-----------|----------------|----------------|
| EM4100 (EM410x) | 125 kHz | Generic proximity | None — trivially cloneable |
| HID Prox (H10301) | 125 kHz | HID 1386, 1326 | None — trivially cloneable |
| Indala | 125 kHz | HID Indala | None — trivially cloneable |
| MIFARE Classic | 13.56 MHz | Many OEM systems | Weak — broken crypto (CRYPTO1) |
| MIFARE Ultralight | 13.56 MHz | Event passes, cafeteria | None — no crypto |
| iClass (Legacy) | 13.56 MHz | HID iClass | Weak — default key broken |
| iClass SE/Seos | 13.56 MHz | HID iClass SE | Strong — AES-128 |
| MIFARE DESFire EV1 | 13.56 MHz | Modern enterprise | Strong — AES-128/3DES |
| MIFARE DESFire EV2/EV3 | 13.56 MHz | High-security enterprise | Very Strong |
| Apple/Google Pay (EMV) | 13.56 MHz | Payment | Very Strong |

**Field identification**: Look at the badge reader. HID readers with the HID logo typically run 125 kHz HID Prox. Readers with a more modern look and contactless symbol often support 13.56 MHz. The physical card may have a logo: HID (red/white logo), Lenel, Honeywell, Bosch.

## 125 kHz Cloning: HID Prox & EM4100

### Reading with Proxmark3 RDV4

```bash
# Start Proxmark3 client
pm3

# Search for 125kHz card (auto-detects protocol)
[pm3] lf search

# Expected output for HID Prox:
# [=] Checking HID
# [+] HID Prox TAG ID: 2006920d3f (12345) - FC: 36 Card: 12345

# Read HID Prox specifically
[pm3] lf hid read

# Read EM410x
[pm3] lf em 410x read
# Output: EM 410x ID: 1122334455
```

### Cloning HID Prox to T5577 Card

The T5577 is a writable 125kHz card that can emulate HID Prox, EM410x, Indala, and others.

```bash
# After reading a card, clone directly to T5577
[pm3] lf hid clone --r 2006920d3f

# Verify the clone
[pm3] lf hid read
# Should return same ID as original card

# Alternative: specify bit length if needed
[pm3] lf hid clone -w H10301 --fc 36 --cn 12345

# Clone EM410x to T5577
[pm3] lf em 410x clone --id 1122334455
```

### Flipper Zero for 125 kHz

```
1. Hold Flipper near card → Main Menu → RFID → Read
2. Card type and ID displayed on screen
3. Save → name it
4. RFID → Saved → select card → Emulate
5. Hold Flipper near reader to present credential

Flipper supports: EM4100, HID H10301, HID Corporate 1000, Indala, 
                  Paradox, Pyramid, Viking, Keri Systems
```

### Long-Range Reading

The standard Proxmark3 has a read range of ~5 cm. Long-range readers dramatically extend operational reach.

**BishopFox Tastic RFID Thief** (now RFID Thief v2):
- Purpose-built long-range 125 kHz reader
- Concealed in laptop bag, briefcase, or backpack
- Read range: 18-36 inches depending on card and antenna orientation
- Logs card IDs to SD card for later cloning

```
Construction notes (DIY approach):
- Long-range HID reader (HID MaxiProx 5375) + Arduino + SD card logger
- External battery pack, 12V
- Coil antenna concealed in bag false bottom
- Activation: pushbutton or proximity trigger
- Data: CSV of card reads with timestamps

Commercial: RFID Thief v2 (BishopFox GitHub), ProxBrute
```

**Operational use**:
- Position near high-traffic access points (elevator lobby, cafeteria line)
- Crowded areas where close contact is normal (badge conference check-in)
- Target: employees who wear badge on belt or lanyard at hip level

## iClass Attack

### Legacy iClass (Standard Key)

HID Legacy iClass cards used a common default diversification key across all standard deployments. The loclass attack recovers this.

```bash
# On Proxmark3 — read iClass card
[pm3] hf iclass read

# Attempt authentication with known default key sets
[pm3] hf iclass loclass --dump

# If default key found, dump card contents
[pm3] hf iclass dump --ki 0

# Clone to a writable iClass card
[pm3] hf iclass wrbl --blk 7 --d [data] --ki 0

# Check if reader accepts standard application area (SAM)
[pm3] hf iclass info
```

**Note**: Legacy iClass (HID Part Numbers: 201x, 200x series) are vulnerable. iClass SE and Seos (HID Part Numbers: 300x series) use AES-128 and are NOT vulnerable to loclass.

### Field Identification of iClass Generation

```
Identify reader:
- HID iCLASS R10/R40/RP10/RP40 = Legacy (vulnerable)
- HID iCLASS SE R10/R40 = SE/Seos (not vulnerable)
- Look for "SE" designation on reader face plate
```

## MIFARE Classic

### Why MIFARE Classic is Broken

MIFARE Classic uses CRYPTO1 — a proprietary stream cipher developed by NXP with fundamental weaknesses:

- Key length: 48 bits (brute-forceable)
- Nonce generation is weak (predictable in some implementations)
- Nested authentication attack allows key recovery from a single known key
- "Darkside" attack can recover a key with zero known keys (reader+card interaction required)

### MFOC — Key Recovery

```bash
# Install MFOC
sudo apt install mfoc libnfc-dev

# List attached NFC readers
nfc-list

# Dump MIFARE Classic with MFOC (known key attack)
mfoc -O card_dump.mfd

# If default keys don't work, use mfcuk first
mfcuk -C -R 0:A -s 250 -S 250 -o recovered_keys.mfd
# (Takes 30-60+ minutes — iterates darkside attack)

# Then use recovered keys with MFOC
mfoc -k A0A1A2A3A4A5 -k B0B1B2B3B4B5 -O card_dump.mfd
```

### Proxmark3 MIFARE Classic Workflow

```bash
# Detect card
[pm3] hf search

# Automatic key recovery (chk, nested, darkside)
[pm3] hf mf autopwn

# Outputs recovered keys and full sector dump
# Example output:
# [+] Sector 00 | Key A: FFFFFFFFFFFF | Key B: FFFFFFFFFFFF
# [+] Sector 01 | Key A: A0A1A2A3A4A5 | Key B: DEADBEEF1234

# Dump to file
[pm3] hf mf dump

# Clone to magic card (Gen1a, Gen2, Gen4)
[pm3] hf mf cload --f hf-mf-dump.bin

# Write UID to Gen1a/Gen2 card
[pm3] hf mf csetuid --uid 12345678
```

### Magic Cards for MIFARE Classic Cloning

| Card Type | UID Writable | Backdoor Commands | Use Case |
|-----------|-------------|-------------------|----------|
| Gen1a (UID) | Yes, via backdoor | Yes | Classic cloning, bypasses UID lockout |
| Gen2 (CUID) | Yes, via standard write | No | More compatible with modern readers |
| Gen3 | Yes | No | Most reader-compatible option |
| Gen4 (Ultimate) | Yes | Yes | Full card simulation incl. SAK/ATQA |

```bash
# Identify magic card generation
[pm3] hf mf info

# Write to Gen1a magic card
[pm3] hf mf cload -f card_dump.bin

# Write UID only to Gen2
[pm3] hf mf setuid --uid AABBCCDD
```

## MIFARE DESFire EV1/EV2 — Why It Resists Cloning

DESFire EV1+ uses AES-128 mutual authentication with session keys derived from a card-unique diversified master key:

- Each card has a unique diversified application key — cannot be transferred
- Replay attacks impossible — authentication uses challenge-response nonces
- UID randomization (EV2+): re-reads return different UIDs

**When cloning IS possible**:
- When the access control system only reads the UID (not the cryptographic application) — operator misconfiguration
- When legacy application area is enabled alongside DESFire (backward compat)

```bash
# Check if reader uses full DESFire crypto or just UID
[pm3] hf desfire info
# If "Application IDs" shows 000000 only or no apps — UID-only reader
# UID-only readers: can clone UID to Gen4 magic card
[pm3] hf mf setuid --uid [desfire_uid]  # (4-byte UID only)
```

## Flipper Zero for RFID Operations

```
# 125 kHz LF Operations
Main Menu → RFID → Read         (holds until card detected)
                 → Add Manually  (enter ID manually)
                 → Saved         (emulate saved card)
                 → Extra Actions → RAW Actions → Read RAW

# 13.56 MHz HF/NFC Operations  
Main Menu → NFC → Read
                → Saved → Emulate

# Supported 13.56 MHz:
  Emulate: MIFARE Classic (with magic card data), MIFARE Ultralight, 
           NTAG213/215/216, EMV card parsing (read-only)
  
# Field commands (CLI via USB)
./flipperzero-cli nfc read
./flipperzero-cli rfid read
```

**Flipper Zero limitations**: Cannot perform CRYPTO1 key recovery (no processing power). Use Proxmark3 for key recovery, then import dump to Flipper for emulation.

## NFC Relay Attacks

Relay attacks allow real-time proxying of card authentication — the reader thinks the legitimate card is present.

```
Setup:
  Attacker A (near reader) ←→ [network/BLE] ←→ Attacker B (near victim's card)

  Attacker B:
  - Proxmark3 or custom hardware in "card emulator" mode
  - Reads victim card's RF field
  - Forwards challenge to Attacker A

  Attacker A:
  - Proxmark3 in "reader" mode near victim card
  - Or: custom hardware near access control reader
  - Forwards challenge response back

# Proxmark3 relay mode (experimental)
[pm3] hf 14a reader    # on attacker near reader
[pm3] hf 14a sim      # on attacker near card
```

**Practical feasibility**: Relay attacks require two operators and custom hardware. The latency must be under ~100ms for MIFARE Classic. Works better against EM/HID 125kHz (no timing-sensitive crypto). MIFARE DESFire has timing-based anti-relay (proximity check in EV2+).

## Smart Card Physical Attacks

### Shoulder Surfing PINs

When an access control system requires both badge + PIN:

- Position at 45-degree angle to target keypads
- Thermal cameras can reveal recently pressed keys (heat signature lasts ~60 seconds)
- Video replay of keypads without covers
- Social engineering: "I forgot my PIN, can I follow you in?"

### Card Wedge Hardware

```
Hardware keyloggers designed for smart card readers:
- Insert between card and reader (USB inline keylogger variant)
- Records card data transmitted over contact interface
- Not applicable for contactless RFID (no physical contact)
- Applicable for chip+PIN smartcard readers (workstations, door readers)
```

## Defensive Awareness for Operators

Understanding defenses helps assess security posture:

| Defense | Effectiveness | Red Team Note |
|---------|-------------|---------------|
| RFID-blocking wallet/sleeve | Blocks long-range reads | Ineffective once card is out |
| Faraday badge holder | Stops ALL reads when holstered | Employees must remove to badge in |
| Multi-factor (badge+PIN) | Stops clone-only attacks | Shoulder surf PIN |
| DESFire EV2 with crypto | Stops cloning | Check if reader uses crypto or UID-only |
| Anti-passback | Stops "pass your card under door" | Cloned card bypasses if enrollment not tied to crypto |
| Behavioral analytics | Detects badge used at unusual hours | Operate during business hours |

## Full Attack Chain Example

```
Scenario: Corporate campus using HID Prox readers

1. Facility recon (Day 1):
   - Observe badge readers: HID RP40 readers → 125 kHz HID Prox
   - Note: employees wear badges on lanyards at chest level
   - Identify high-traffic area: main lobby coffee shop

2. Credential capture (Day 2):
   - Operator carries laptop bag with RFID Thief concealed
   - Sits at coffee shop table near door for 90 minutes during morning rush
   - Captures 23 HID Prox credential IDs logged to SD card

3. Clone (same day, offsite):
   pm3 → lf hid clone --r [first captured ID]
   Test on T5577 card — verify card reads as expected

4. Entry (Day 3):
   - Approach employee entrance at 8:47 AM (peak entry time)
   - Present cloned T5577 to reader
   - Reader grants access → green LED, door unlocks
   - Enter facility with flow of employees
```
