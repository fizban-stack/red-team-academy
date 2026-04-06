---
layout: training-page
title: "Firmware Extraction — Red Team Academy"
module: "IoT Hacking"
tags:
  - firmware
  - binwalk
  - qemu
  - ghidra
  - embedded
page_key: "iot-firmware-extraction"
render_with_liquid: false
---

# Firmware Extraction & Analysis

Firmware analysis is the starting point for IoT security assessments. Extract the firmware image, unpack the filesystem, find hardcoded credentials, exposed APIs, debug interfaces, and vulnerabilities in the application binaries. Tools: binwalk, QEMU, firmwalker, Ghidra.

## Obtaining Firmware

```
# Method 1: Download from vendor (easiest):
# Check manufacturer support page, FTP, or firmware update server
# Intercept OTA update traffic (see OTA attacks page)

# Method 2: Extract via web interface (authenticated):
# Some routers expose firmware download at /backup or /firmware

# Method 3: UART/JTAG (see Hardware Hacking page):
# Boot to bootloader (U-Boot) and dump flash via tftp or serial

# Method 4: Chip-off (destructive — physical flash extraction):
# Desolder NOR/NAND flash chip, use programmer (Bus Pirate, Flashrom):
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin
# Common flash chips: W25Q64, MX25L6406, EN25Q64

# Method 5: Vendor SDK/GPL dump:
# GPL-licensed routers must release source — often includes filesystem hints

# Method 6: Emulation NVRAM (check nvram_get calls):
strings firmware.bin | grep -E "^[a-z_]+=.{3,}" | head -50
```

## Firmware Analysis with Binwalk

```
# Install:
pip3 install binwalk
apt install binwalk

# Identify firmware structure:
binwalk firmware.bin

# Common output:
# DECIMAL   HEXADECIMAL   DESCRIPTION
# 0         0x0           TRX firmware header
# 28        0x1C          LZMA compressed data
# 1441792   0x160000      Squashfs filesystem

# Extract everything (recursive):
binwalk -e firmware.bin
binwalk -Me firmware.bin   # recursive extraction

# Extract specific offset:
dd if=firmware.bin bs=1 skip=1441792 | unsquashfs -f -d squashfs_out -

# List extracted contents:
find _firmware.bin.extracted/ -type f | head -50

# Manual extraction:
# Squashfs:
unsquashfs squashfs.img

# JFFS2:
modprobe jffs2 mtdram mtdblock
dd if=firmware.bin of=/dev/mtdblock0
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2

# CramFS:
mount -o loop cramfs.img /mnt/cramfs
```

## Firmwalker — Automated Sensitive File Hunt

```
# firmwalker searches extracted FS for:
# passwords, SSH keys, SSL certs, config files, hardcoded IPs
git clone https://github.com/craigz28/firmwalker
chmod +x firmwalker/firmwalker.sh
./firmwalker/firmwalker.sh _firmware.bin.extracted/squashfs-root

# Manual sensitive file hunt:
find . -name "*.conf" -o -name "*.cfg" -o -name "*.xml" | xargs grep -li "password\|passwd\|secret\|key"
grep -r "password\|passwd" . --include="*.conf" -l
find . -name "shadow" -o -name "passwd"

# Hardcoded credentials:
strings firmware.bin | grep -E "(admin|root|password|default).*[:=]"
grep -r "password" . 2>/dev/null | grep -v "Binary" | grep -v "\.git"

# SSH keys:
find . -name "id_rsa" -o -name "authorized_keys" -o -name "*.pem"

# SSL certificates:
find . -name "*.crt" -o -name "*.key" -o -name "*.pem" -o -name "*.p12"
# Check for default/self-signed certs with hardcoded private keys

# Interesting paths to check:
# /etc/passwd, /etc/shadow
# /etc/config/* (OpenWRT)
# /usr/sbin/httpd (web server binary)
# /usr/lib/lua/luci/ (LuCI router interface)
```

## QEMU Emulation

```
# Emulate ARM/MIPS firmware without real hardware:
apt install qemu-user-static qemu-system-arm qemu-system-mips

# Determine architecture:
file _firmware.bin.extracted/squashfs-root/bin/busybox
# → ELF 32-bit MSB executable, MIPS (big-endian)

# Userspace emulation (single binary):
cp $(which qemu-mips-static) _firmware.bin.extracted/squashfs-root/usr/bin/
chroot _firmware.bin.extracted/squashfs-root/ /usr/bin/qemu-mips-static /bin/sh

# Full system emulation with Firmadyne:
git clone --recursive https://github.com/firmadyne/firmadyne
cd firmadyne
# Install dependencies, configure DB
./scripts/getArch.sh ./images/1.tar.gz
./scripts/makeImage.sh 1
./scripts/inferNetwork.sh 1
./scripts/run.sh 1

# FAT (Firmware Analysis Toolkit) — easier:
git clone https://github.com/attify/firmware-analysis-toolkit
cd firmware-analysis-toolkit
./setup.sh
./fat.py firmware.bin
```

## Binary Analysis with Ghidra

```
# Install Ghidra:
# Download from https://ghidra-sre.org/
# Run: ./ghidraRun

# Key analysis targets:
# 1. Web server binary (httpd, uhttpd, mini_httpd)
# 2. Firmware update handler
# 3. Authentication modules

# Find interesting strings in binary:
strings httpd | grep -E "(password|admin|secret|eval|system|exec)"

# radare2 for quick analysis:
r2 -A httpd                    # analyze
afl | grep main                # list functions
pdf @ main                     # disassemble main
iz | grep password             # find strings

# Look for:
# - Hardcoded credentials in binary
# - Command injection via system() with user input
# - Buffer overflows in string handling (strcpy, sprintf without bounds)
# - Authentication logic that can be bypassed
```

## Flash Memory Types

```
# Understanding flash type determines which tool and method to use:

# NOR Flash (SOIC-8 package, e.g. W25Q64, MX25L6406, EN25Q64):
# - SPI interface
# - Fast random access — used for execute-in-place firmware
# - Common in routers, IoT, network equipment
# - Dump with: flashrom, Bus Pirate, CH341A programmer

# NAND Flash (TSOP-48 package):
# - Larger capacity but sequential access only
# - Used in consumer electronics, Android devices, NAS
# - Dump requires dedicated NAND programmer

# eMMC Flash (BGA package, soldered directly to PCB):
# - Used in modern routers, smart TVs, embedded Linux boards
# - Can be dumped by soldering to test pads (CLK, CMD, DATA0-7, VCC, GND)
# - Or with eMMC clip adapters without soldering

# Common flash chip identifiers (look for these on the chip):
# W25Q64FV     — 8MB NOR (Winbond)
# MX25L6406E   — 8MB NOR (Macronix)
# GD25Q64      — 8MB NOR (GigaDevice)
# EN25Q64      — 8MB NOR (EON Silicon)
```

## SPI Flash Dump with Flashrom

```
# Install flashrom:
sudo apt install flashrom

# Dump via Bus Pirate (attach to SPI pins: CLK, MOSI, MISO, CS, GND, VCC):
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r firmware.bin

# Dump via Raspberry Pi GPIO (SPI0):
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=512 -r firmware.bin

# Dump via CH341A USB programmer (cheap $5 programmer for SOIC-8 chips):
flashrom -p ch341a_spi -r firmware.bin

# Specify chip if autodetect fails:
flashrom -p ch341a_spi -c "MX25L6406E/MX25L6408E" -r firmware.bin

# Write modified firmware back:
flashrom -p ch341a_spi -w modified_firmware.bin

# Verify write:
flashrom -p ch341a_spi -v firmware.bin
```

## Embedded Filesystem Types

```
# After extracting with binwalk, identify the filesystem type:
# binwalk -Me firmware.bin will attempt to auto-extract known filesystems

# Common filesystems in IoT firmware:
# SquashFS  — read-only, compressed; most common in OpenWrt/Linux routers
#             Magic bytes: sqsh, hsqs, qshs, sqsl
#             Tool: unsquashfs, 7zip
# JFFS2     — journaled, RW, for NAND flash
#             Magic: 0x07C0 (v1), 0x72b6 (v2)
#             Tool: jefferson
# YAFFS2    — designed for NAND, used in Android
#             Magic: 0x5941ff53
#             Tool: unyaffs
# CramFS    — compressed RO, older routers
#             Magic: 0x28cd3d45
#             Tool: uncramfs, 7zip
# UBIFS     — modern NAND, successor to JFFS2
#             Magic: 0x06101831
#             Tool: ubi_reader

# Manual extraction if binwalk misses it:
# SquashFS:
unsquashfs -f -d extracted/ firmware.squashfs

# JFFS2:
pip install jefferson
jefferson filesystem.img -d outdir

# Extract a specific offset from firmware:
dd if=firmware.bin of=chunk.bin bs=1 skip=$((0x200)) count=$((0x400-0x200))
```

## Entropy & Encryption Check

```
# High entropy = encrypted or compressed (cannot extract)
# Low entropy = plaintext / uncompressed (can extract directly)

# Check entropy visually with binwalk:
binwalk -E firmware.bin
# Plot shows entropy per block — high (>0.9) = encrypted, low (<0.7) = readable

# If firmware is encrypted:
# 1. Find the decryption key in bootloader (via UART/JTAG during boot)
# 2. Look for OTA update traffic — may include decrypted version
# 3. Search vendor SDK / GPL source releases for encryption details
# 4. Find older unencrypted firmware version from manufacturer archive

# Quick check for encrypted blocks:
strings -tx firmware.bin | head -30   # low output = likely encrypted
file firmware.bin                      # reports compression/encryption if detectable
```

## Firmware Format Identification

```
# Common firmware file formats:
# SREC (Motorola S-Record)   — all lines start with capital S
# Intel HEX                  — all lines start with a colon :
# TI-TXT (Texas Instruments) — addresses prefixed with @, MSP430 common
# Raw NAND dump              — no header, must identify manually with strings/binwalk

# Convert Intel HEX to binary:
avr-objcopy -I ihex -O elf32-avr dump.hex dump.elf
objcopy -I ihex firmware.hex -O binary firmware.bin

# Quick strings on HEX file (without conversion):
cat firmware.hex | tr -d ":" | tr -d "\n" | xxd -r -p | strings

# Disassemble AVR firmware:
avr-objdump -m avr -D firmware.hex

# Emulate AVR in QEMU:
qemu-system-avr -S -s -nographic \
  -serial tcp::5678,server=on,wait=off \
  -machine uno -bios firmware.bin
```

## Resources

- Binwalk — `github.com/ReFirmLabs/binwalk`
- unblob — modern firmware extractor (Docker) — `github.com/onekey-sec/unblob`
- Firmadyne — firmware emulation framework — `github.com/firmadyne/firmadyne`
- Firmwalker — filesystem credential scanner — `github.com/craigz28/firmwalker`
- jefferson — JFFS2 extractor — `github.com/onekey-sec/jefferson`
- HardwareAllTheThings — firmware dumping reference — `github.com/swisskyrepo/HardwareAllTheThings`
- FAT — `github.com/attify/firmware-analysis-toolkit`
- EMBA — automated firmware security scanner — `github.com/e-m-b-a/emba`
- Flashback Team: Extracting Firmware from SPI NOR Flash (YouTube)
