---
layout: training-page
title: "Wireless Attacks Overview — Red Team Academy"
module: "Wireless"
tags:
  - wireless
  - wifi
  - bluetooth
  - nfc
  - rfid
  - overview
page_key: "wireless-overview"
render_with_liquid: false
---

# Wireless Attacks

## Overview

Wireless attack surfaces are present in almost every physical engagement and many remote assessments. Radio-frequency based systems — Wi-Fi, Bluetooth, NFC, and RFID — are broadly deployed with varying levels of security maturity. Physical proximity provides access that bypasses network perimeter controls entirely, making wireless attacks a high-value initial access vector.

This module covers four radio domains from a red team perspective. Each has distinct hardware requirements, tooling, attack methodology, and detection profile. All techniques described assume authorized engagement scope that explicitly includes wireless testing.

## Attack Surface Summary

### Wi-Fi (802.11)

Wi-Fi is the primary wireless network protocol. Attack goals range from credential capture (WPA passphrase or enterprise credentials) to network access via rogue AP or MITM. Modern deployments use WPA3 or WPA2-Enterprise, but legacy configs remain common.

- **Range:** 50–300m outdoors with standard hardware; km-range with directional antennas
- **Frequency:** 2.4 GHz and 5 GHz (6 GHz with Wi-Fi 6E)
- **Primary targets:** PSK networks (WPA2/3 passphrase), enterprise networks (EAP credentials), legacy WEP/WPS deployments
- **Key tools:** aircrack-ng suite, hcxdumptool/hcxtools, bettercap, hostapd-wpe, eaphammer

### Bluetooth (Classic + BLE)

Bluetooth Classic and Bluetooth Low Energy are distinct protocols sharing the 2.4 GHz band. BLE has exploded in IoT, medical devices, building access, and wearables — all high-value targets. Classic Bluetooth is used in audio, peripherals, and older mobile devices.

- **Range:** 10–100m (Class 1 devices up to 100m)
- **Frequency:** 2.4 GHz FHSS (79 channels for Classic, 40 channels for BLE)
- **Primary targets:** BLE IoT devices, access control, payment terminals, medical devices, peripherals
- **Key tools:** Ubertooth One, btlejack, gattacker, scapy, BlueToolkit, nRF Sniffer

### NFC (Near Field Communication)

NFC operates at 13.56 MHz at very short range (typically <10cm). Used for contactless payments (EMV), access control badges, transit cards, and asset tags. Relay attacks extend the effective range significantly.

- **Range:** 0–10cm standard; 10–100m+ with relay attack hardware
- **Frequency:** 13.56 MHz
- **Primary targets:** Contactless payment cards, building access cards, NFC-enabled mobile payments
- **Key tools:** Proxmark3, Flipper Zero, NFCGate, libnfc, nfc-tools

### RFID (Radio Frequency Identification)

RFID covers a wide range of frequencies. Low-frequency (125 kHz) cards (HID, EM4100) are the dominant access control technology in corporate environments. High-frequency (13.56 MHz) includes MIFARE and iCLASS. Many systems deployed years ago remain vulnerable to cloning and replay attacks.

- **Range:** LF: 10–30cm standard, 1m+ with long-range readers; HF: 1–10cm
- **Frequency:** LF 125 kHz, HF 13.56 MHz, UHF 860–960 MHz (asset tracking)
- **Primary targets:** Building access control, parking systems, time-attendance systems
- **Key tools:** Proxmark3 RDV4, Flipper Zero, ACR122U, RFIDler, HydraNFC

## Required Hardware

```
# ── Wi-Fi ─────────────────────────────────────────────────────
# Alfa AWUS036ACM   — dual-band 2.4/5GHz, MediaTek MT7612U, monitor+inject ✓
# Alfa AWUS036ACHM  — 2.4 GHz, MT7610U chip, best Linux driver support
# Alfa AWUS1900     — 4x4 MIMO, RTL8814AU, long-range
# TP-Link AC600     — budget option (Archer T2U Nano), limited 5GHz support
# Directional antennas: Alfa APA-M25 (25dBi), Yagi (16–22dBi) — long range attacks
# Note: RTL8812AU/RTL8814AU and MT76xx chipsets have best aircrack-ng support

# ── Bluetooth ──────────────────────────────────────────────────
# Ubertooth One     — 2.4GHz transceiver, Bluetooth Classic sniffing
# nRF52840 dongle   — BLE sniffing + injection (Nordic Semiconductor)
# HackRF One        — wideband SDR (1MHz–6GHz), Bluetooth with gr-bluetooth
# BTLEJuice hardware: Raspberry Pi + 2x BLE USB dongles (MITM setup)
# Any BLE USB dongle with BlueZ support (CSR, Broadcom) for scanning/GATT

# ── NFC / RFID ─────────────────────────────────────────────────
# Proxmark3 RDV4    — gold standard, LF+HF, active community, scripting (PM3 script)
# Proxmark3 Easy    — budget clone, good compatibility with official firmware
# Flipper Zero      — portable, LF+HF RFID + NFC + Bluetooth + infrared + SubGHz
# ACR122U           — HF only (13.56 MHz), good for MIFARE research (libnfc)
# RFIDler           — open-source LF RFID researcher tool
# Tastic RFID Thief — long-range LF capture (custom build ~$100, 30cm read range)
# HydraNFC          — open-source HF NFC tool with sniffer support
```

## Legal and Authorization Considerations

Wireless testing has a larger blast radius than most other attack categories. Signals propagate beyond organizational boundaries, deauth attacks affect all nearby devices, and rogue APs may capture credentials from uninvolved users. Scope must explicitly authorize wireless testing.

```
# Pre-engagement wireless checklist:
# ✓ Scope document explicitly includes wireless testing
# ✓ Specific SSID names / BSSID ranges are in scope (avoid adjacent tenants)
# ✓ Physical locations where testing is permitted are defined
# ✓ Time windows are defined (deauth at 2am in a hospital = bad)
# ✓ RFID/NFC scope defines which reader/card types are authorized
# ✓ Bluetooth scope defines which devices/services are in target range
# ✓ Client-targeting approval (capturing credentials from users = sensitive)

# Regulatory considerations:
# - Active RF transmission (jamming, deauth) may require license in some jurisdictions
# - Deauth attacks (802.11 disassociate frames) are technically RF interference
# - Intercepting communications is regulated differently by country
# - FCC Part 97 / EU Radio Equipment Directive apply

# Minimize unintended impact:
# - Use directional antennas to focus signal on target
# - Reduce TX power to minimum effective level
# - Monitor for non-target clients connecting to evil twin — release immediately
# - Stop deauth attacks once target handshake is captured
```

## Detection Profile

```
# Wireless IDS/IPS systems (WIDS) detect:
# - Deauth flood attacks (high-volume 802.11 management frames)
# - Rogue AP with matching SSID (by BSSID and beacon characteristics)
# - PMKID capture attempts (station sending EAPOL messages without associating)
# - Channel hopping patterns (monitoring mode behavior on managed switches)
# - 802.11 probe request floods (scanner behavior)

# WIDS products in common enterprise use:
# Cisco Adaptive WIPS (Aironet), Aruba RFProtect, Extreme Networks AirDefense
# Zebra/AirTight, Mojo Networks, Kismet-based open source WIDS

# Counter-detection measures:
# - MAC address randomization (many modern OS default, also set manually)
# - Directional antenna to reduce detectable signal footprint
# - Targeted attacks (one client, not broadcast) — fewer detectable frames
# - Operate at low TX power
# - Target deauth to specific client MAC, not broadcast (less noisy)
# - For passive attacks (PMKID capture) — no transmitted frames at all
```
