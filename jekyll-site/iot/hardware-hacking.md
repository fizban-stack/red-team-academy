---
layout: training-page
title: "Hardware Hacking — Red Team Academy"
module: "IoT Hacking"
tags:
  - uart
  - jtag
  - spi
  - i2c
  - serial
  - embedded
page_key: "iot-hardware-hacking"
render_with_liquid: false
---

# Hardware Hacking (UART / JTAG / SPI)

IoT devices expose debug interfaces that provide root shells, firmware dumps, and memory access. UART is the most common — typically exposed as test pads on the PCB giving a Linux serial console. JTAG enables full CPU debug. SPI/I2C buses can be sniffed to capture firmware and credentials in transit.

## UART — Serial Console Access

```
# UART = Universal Asynchronous Receiver/Transmitter
# Typical 3-wire interface: TX, RX, GND (sometimes VCC)
# Default baud rates: 115200, 57600, 38400, 9600

# Equipment needed:
# - USB-to-UART adapter (CP2102, CH340, FTDI)
# - Multimeter or logic analyzer
# - Soldering iron (sometimes)

# Find UART pads on PCB:
# 1. Look for groups of 3-4 test pads near CPU/SoC
# 2. Use multimeter continuity mode: one pad = GND (continuity to metal shield)
# 3. Power on device: UART TX should show 3.3V (idle high)
# 4. Use logic analyzer to confirm signals and baud rate

# Connect USB-UART adapter:
# Device TX → Adapter RX
# Device RX → Adapter TX
# Device GND → Adapter GND
# (DO NOT connect VCC unless adapter matches device voltage: 3.3V or 1.8V)

# Connect with minicom:
minicom -D /dev/ttyUSB0 -b 115200 -8 -N

# Connect with screen:
screen /dev/ttyUSB0 115200

# Connect with picocom:
picocom -b 115200 /dev/ttyUSB0 --flow=none

# Auto-detect baud rate with minicom:
# Try 9600, 38400, 57600, 115200, 230400, 460800, 921600

# Bootloader access (U-Boot):
# Power on while holding a key or sending bytes
# Common interrupts: space, 'c', Ctrl+C
# U-Boot commands:
printenv         # show environment variables (contains kernel cmdline)
setenv bootargs "init=/bin/sh"
boot             # boot with shell instead of init
nand read; nand dump   # read NAND flash
tftp $addr firmware.bin; nand write  # write firmware
```

## JTAG — Full Debug Access

```
# JTAG = Joint Test Action Group
# Provides: CPU halt, single-step, memory read/write, register access
# 4-wire: TDI, TDO, TMS, TCK (plus GND, sometimes TRST, SRST)

# Equipment:
# - JTAG adapter: J-Link, OpenOCD-compatible, Bus Blaster, RP2040 (cheap)
# - JTAGulator — auto-identifies JTAG pinout from test pads

# JTAGulator pinout identification:
# Connect JTAGulator to test pads
# Use JTAGulator serial interface:
# BYPASS scan → identifies JTAG pins

# OpenOCD connection:
openocd -f interface/jlink.cfg -f target/bcm2711.cfg
# Or generic:
openocd -f interface/ftdi/ft232r.cfg -f target/armbigendian.cfg

# GDB via OpenOCD:
arm-linux-gnueabi-gdb vmlinux
target remote :3333    # connect to OpenOCD GDB port
monitor halt           # halt CPU
monitor step           # single step
monitor reg            # show registers
x/20x $sp              # examine stack
dump binary memory /tmp/dump.bin 0x80000000 0x80100000  # dump memory region

# Extract filesystem via JTAG:
# Halt CPU, find flash base address from memory map
# Dump flash region to file
```

## SPI Flash Extraction

```
# SPI = Serial Peripheral Interface
# Used for NOR flash chips (firmware storage)
# 4-wire: MOSI, MISO, CLK, CS (Chip Select)

# In-circuit SPI reading with Bus Pirate + Flashrom:
# Connect Bus Pirate to flash chip pins (in-circuit, device powered off)
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r dump.bin
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M --chip W25Q64BV -r dump.bin

# Raspberry Pi as SPI programmer:
# Connect flash chip to SPI pins (GPIO 10,9,11,8)
# Enable SPI: raspi-config → Interfaces → SPI
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=8000 -r firmware.bin

# Identify chip:
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 --detect

# Write modified firmware:
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -w modified_firmware.bin

# Logic analyzer SPI sniffing (passive):
# Connect logic analyzer to SPI bus while device reads flash
# Decode SPI protocol in PulseView/Sigrok → capture firmware in transit
```

## I2C Bus Attacks

```
# I2C = Inter-Integrated Circuit
# 2-wire: SDA (data), SCL (clock)
# Used for EEPROMs, sensors, real-time clocks

# Enumerate I2C devices:
apt install i2c-tools
i2cdetect -y 1       # scan I2C bus 1 (Raspberry Pi)
# Output shows addresses of connected devices (0x50 = EEPROM common)

# Read EEPROM data:
i2cdump -y 1 0x50 b   # read 256 bytes from address 0x50
i2cget -y 1 0x50 0x00 # read single byte at offset 0x00

# Write to EEPROM (credential/config modification):
i2cset -y 1 0x50 0x00 0x41  # write 0x41 ('A') to offset 0x00

# Sniff I2C with Bus Pirate:
# Set Bus Pirate to I2C mode, sniff mode
# Capture credential exchange between MCU and secure element
```

## UART — Identifying Pins with a Multimeter

When UART pads are unlabelled, use a multimeter to identify each pin before connecting. Connecting VCC to GND will fry the circuit.

```
# UART pinout: TX, RX, VCC (3.3V or 5V), GND
# Most common configuration: 8N1 (8 data bits, no parity, 1 stop bit)

# Step 1 — Find GND:
# Multimeter in continuity mode.
# Black probe on any grounded metal surface on the PCB.
# Red probe on each candidate pad — beep = GND.

# Step 2 — Find VCC:
# Multimeter in DC voltage mode (20V range).
# Black probe on GND. Red probe on each pad. Power on device.
# Constant 3.3V or 5V = VCC.

# Step 3 — Find TX:
# Same DC voltage mode.
# Probe each remaining pad while device boots.
# TX fluctuates for a few seconds during boot (serial output) then stabilizes.
# That's the TX pin.

# Step 4 — RX:
# The remaining pad is RX.
# It has lowest voltage and lowest fluctuation.

# Wiring to USB-UART adapter:
# Device TX  →  Adapter RX
# Device RX  →  Adapter TX
# Device GND →  Adapter GND
# DO NOT connect VCC unless adapter matches device voltage exactly

# Connect and open terminal:
screen /dev/ttyUSB0 115200
minicom -D /dev/ttyUSB0 -b 115200 -8 -N
cu -l /dev/ttyUSB0 -s 115200

# Baud rate not known? Try common rates: 9600, 38400, 57600, 115200
# Or use sigrok-cli to auto-detect from a logic analyzer capture:
sigrok-cli -O ascii -i uart.sr -P uart:baudrate=115200:rx=D0 -B uart=rx
```

## UART — Baud Rate Detection with Logic Analyzer

```
# Connect logic analyzer TX channel to suspected TX pin on device.
# Connect logic analyzer GND to device GND.
# Power on device — capture the boot sequence.

# In PulseView or Saleae Logic:
# 1. Measure the duration of the shortest pulse (= 1 bit period)
# 2. Baud rate = 1 / bit_period
#    Example: bit period = 8.003 µs → baud rate = 1/0.000008003 = 124,953
#    Closest standard rate: 115200

# PulseView: add UART decoder → set baud rate → read decoded text
# Saleae Logic: Analyzers → Async Serial → try known baud rates → read

# Linux: add yourself to dialout group to access /dev/ttyUSB0 without sudo:
sudo usermod -a -G dialout $USER   # Ubuntu/Debian
sudo usermod -a -G uucp $USER      # Arch

# Brute-force UART password with Python:
# import serial, time
# s = serial.Serial('/dev/ttyUSB0', 115200)
# for pwd in open('passwords.txt'):
#     s.write(pwd.strip().encode() + b'\n'); time.sleep(0.5)
#     print(s.readline())
```

## JTAG — Pins and Debug Access

```
# JTAG standard pins:
# TCK — Test Clock       (controls TAP controller speed)
# TMS — Test Mode Select (tells JTAG what to do)
# TDI — Test Data In     (data into the chip)
# TDO — Test Data Out    (data out of the chip)
# TRST— Test Reset       (optional, resets JTAG state)

# What JTAG gives you:
# - Full CPU debug (step, breakpoint, memory read/write)
# - Firmware dump from flash
# - Bypass locked bootloaders (if JTAG is not fused off)
# - Modify code in memory at runtime

# Auto-identify JTAG pinout with JTAGulator:
# JTAGulator is a dedicated tool — tries all combinations of 4 pins
# to find TCK/TMS/TDI/TDO automatically

# Once pins are known — connect with OpenOCD:
# Write a config file (dump_fw.cfg):
#   init
#   reset init
#   halt
#   dump_image firmware.bin 0x00000000 0x00040000
#   exit
sudo openocd -f /usr/share/openocd/scripts/interface/stlink-v2-1.cfg \
  -f /usr/share/openocd/scripts/target/nrf51.cfg \
  -f dump_fw.cfg

# Dump AVR flash with avrdude via JTAG:
avrdude -p m128 -c jtagmkI -P /dev/ttyUSB0 -U flash:r:firmware.bin:r

# Note: Some devices have AVR lock bits set — reading flash is blocked.
# Lock bits can only be cleared by a full chip erase (destroys firmware too).
# In that case, obtain firmware from another source (vendor, OTA, SPI).
```

## IoT Pentest Frameworks

```
# EXPLIoT — IoT pentest framework (like Metasploit for IoT)
# github.com/expliot-framework/expliot

pip3 install expliot
expliot   # launches interactive CLI

# Key plugins:
# - UART/SPI/I2C hardware interface testing
# - Zigbee/BLE/MQTT/CoAP protocol testing
# - Default credential checks for common IoT devices
# - Firmware analysis modules

# FACT — Firmware Analysis and Comparison Tool
# github.com/fkie-cad/FACT_core

# Deploy with Docker:
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core
docker-compose up

# FACT provides:
# - Firmware extraction (recursive unpacking)
# - Static analysis with plugins (crypto, creds, CVEs)
# - Web UI for browsing firmware contents
# - Version comparison to track vulnerability changes

# Routersploit — framework for embedded device exploitation
# github.com/threat9/routersploit

pip3 install routersploit
rsf
# Or: python3 -m routersploit

# Useful modules:
use scanners/autopwn     # auto-scan all modules against target
use exploits/routers/dlink/...
use creds/routers/router_default_creds
show options; set target 192.168.1.1; run

# Killerbee — ZigBee and IEEE 802.15.4 testing
# github.com/riverloopsec/killerbee

pip3 install killerbee
zbdump -f 20 -c 15 dump.pcap   # capture ZigBee on channel 15
zbwireshark -c 15               # live capture to Wireshark
zbstumbler                      # discover ZigBee networks
zbfind                          # direction finding for ZigBee source

# emba — analyze Linux-based firmware of embedded devices
# github.com/e-m-b-a/emba

git clone https://github.com/e-m-b-a/emba
cd emba
sudo ./emba.sh -f firmware.bin -l /tmp/emba-output

# emba checks:
# - Kernel version and CVEs
# - Outdated binaries with known CVEs
# - Hardcoded credentials in configs
# - Crypto issues (weak algorithms, hardcoded keys)
# - Web application vulnerabilities in embedded web UIs
```

## Side-Channel & Fault Injection

```
# ChipWhisperer — side-channel analysis and fault injection
# github.com/newaetech/chipwhisperer

pip3 install chipwhisperer

# Power analysis attack workflow:
import chipwhisperer as cw
scope = cw.scope()
scope.default_setup()
target = cw.target(scope)

# Capture power traces during crypto operation:
scope.arm()
target.simpleserial_write('p', plaintext)
ret = scope.capture()
trace = scope.get_last_trace()

# Analyze with CPA (Correlation Power Analysis):
# Use CW analyzer to find AES key from traces
# Attack recovers 128-bit AES key from ~1000 power traces

# Fault injection (glitch attack):
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'clock_xor'
scope.glitch.trigger_src = 'ext_single'
scope.glitch.width = 10     # glitch width (ns)
scope.glitch.offset = 500   # delay after trigger (ns)
# Proper glitch parameters cause:
# - Skip instructions (bypass authentication check)
# - Corrupt memory reads (bypass signature verification)
# - Reset to known state

# Glasgow Interface Explorer — digital interface debugging
# github.com/GlasgowEmbedded/glasgow
pip3 install glasgow
# Flash firmware: glasgow flash --bitstream glasgow.bit

# Use cases:
glasgow run uart -V 3.3 tty /dev/ttyUSB0  # UART at 3.3V
glasgow run spi-analyzer -V 3.3           # SPI bus analyzer
```

## Wireless IoT Protocols

```
# ZigBee analysis with Killerbee + Wireshark:
zbdump -f 20 -c 11 -w capture.pcap   # capture on ZigBee channel 11
# Open in Wireshark: Edit → Preferences → Protocols → ZigBee → add network key

# Bluetooth Low Energy (BLE) sniffing:
# Equipment: Ubertooth One ($120) or nRF Sniffer dongle ($15)
ubertooth-btle -f -c dump.pcap   # follow BLE connection
# Open in Wireshark for decoding

# MQTT testing (common IoT protocol):
apt install mosquitto-clients
mosquitto_sub -h broker_ip -t '#' -v    # subscribe to ALL topics (wildcard)
mosquitto_pub -h broker_ip -t "device/cmd" -m "{'cmd':'unlock'}"
# Test unauthenticated access: many IoT brokers have no auth

# CoAP testing (Constrained Application Protocol — IoT REST):
pip3 install aiocoap
python3 -m aiocoap.cli.get coap://192.168.1.1/.well-known/core   # discover resources
python3 -m aiocoap.cli.put coap://192.168.1.1/config -f payload.json

# PRET — Printer Exploitation Toolkit
# github.com/RUBi-ZA/PRET

pip3 install pret
python3 pret.py 192.168.1.100 pjl   # connect via PJL
python3 pret.py 192.168.1.100 ps    # connect via PostScript
python3 pret.py 192.168.1.100 pcl   # connect via PCL

# PRET commands:
ls             # list printer filesystem
get /etc/passwd  # read file
put payload.ps   # upload PostScript for code execution
nvram dump       # dump NVRAM (passwords, config)
```

## Tools & Equipment

- Bus Pirate — multi-protocol interface (UART, SPI, I2C, JTAG) — `buspirate.com`
- JTAGulator — auto-detect JTAG/UART pinouts — `github.com/grandideastudio/jtagulator`
- ChipWhisperer — side-channel attack and fault injection platform — `newae.com/chipwhisperer`
- Glasgow Interface Explorer — open source hardware debugger — `github.com/GlasgowEmbedded/glasgow`
- Logic analyzer — Saleae Logic Pro 8, or cheap 24MHz USB analyzer
- PulseView / sigrok — open-source logic analyzer software — `sigrok.org`
- Flashrom — SPI flash programmer — `flashrom.org`
- OpenOCD — JTAG debug server — `openocd.org`
- UART adapters: CP2102, CH340, FTDI USB-to-serial (~$5)
- Ubertooth One — BLE sniffer — `greatscottgadgets.com/ubertoothone`
- ApiMote — ZigBee research hardware (Killerbee compatible)
- HardwareAllTheThings reference — `github.com/swisskyrepo/HardwareAllTheThings`

## Books

- Fotios Chantzis et al. — *Practical IoT Hacking* (No Starch, 2021)
- Jasper van Woudenberg, Colin O'Flynn — *The Hardware Hacking Handbook: Breaking Embedded Security with Hardware Attacks* (No Starch, 2021)
- Yago Hansen — *The Hacker's Hardware Toolkit* (2019)
- Aditya Gupta — *The IoT Hacker's Handbook: A Practical Guide to Hacking the Internet of Things* (2019)
- Aditya Gupta, Aaron Guzman — *IoT Penetration Testing Cookbook* (2017)
- Craig Smith — *The Car Hacker's Handbook: A Guide for the Penetration Tester* (No Starch, 2016)
- Mark Carney — *Pentesting Hardware — A Practical Handbook* (draft, free online)
- Qing Yang, Lin Huang — *Inside Radio: An Attack and Defense Guide* (2018)

## Free Training & Labs

- IoTGoat — deliberately insecure firmware based on OpenWrt — `github.com/OWASP/IoTGoat`
- Microcorruption — embedded security CTF (online, free) — `microcorruption.com`
- RHME hardware CTF challenges (RHME-2015/2016/2017) — various GitHub repos
- Firmware Security blog — `firmwaresecurity.com`
- Attify — IoT pentesting resources — `attify.com`
- OWASP IoT Project — attack surfaces and testing guide — `owasp.org/www-project-internet-of-things/`
