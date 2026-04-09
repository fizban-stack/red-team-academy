---
layout: training-page
title: "Network Attack Overview — Red Team Academy"
module: "Network Attacks"
tags:
  - network
  - layer2
  - mitm
  - arp
  - llmnr
page_key: "network-overview"
render_with_liquid: false
---

# Network Attack Overview

Network attacks target the underlying infrastructure — Layer 2 and Layer 3 protocols that most organizations never harden. A foothold on a single network segment opens LLMNR poisoning, IPv6 hijacking, VLAN traversal, and credential interception at scale. These techniques frequently achieve domain compromise faster than vulnerability exploitation.

## Attack Surface by Layer

```
Layer 2 — Data Link
  ARP          — no authentication; spoof gateway to MITM traffic
  802.1Q VLAN  — tagging misconfig allows cross-VLAN access
  DTP          — Cisco trunking negotiation; spoof to become trunk port
  STP          — spanning tree; inject superior BPDU to become root bridge
  802.1X       — port-based NAC; bypassable via MAC cloning or EAP relay

Layer 3 — Network
  DHCP         — no auth; starve pool or inject rogue server
  LLMNR/mDNS   — Windows fallback name resolution; poisonable
  NBT-NS       — NetBIOS name resolution; poisonable
  IPv6 SLAAC   — Windows prefers IPv6; inject rogue DHCPv6/RA
  WPAD         — proxy auto-discovery via DNS/DHCP; hijackable

Layer 4+ — Transport / Application
  Cleartext protocols — FTP, HTTP, Telnet, SMTP, LDAP (unencrypted)
  NTLM relay   — relay captured Net-NTLMv2 to authenticate elsewhere
  Kerberos     — AS-REP roasting, kerberoasting (see AD module)
```

## Prerequisites

```
Physical or logical access to the target network segment is required.
Common entry points:

  On-site     — laptop plugged into a wall jack or conference room port
  VPN         — split-tunnel VPN with access to internal segment
  Post-compromise — shell on internal host, pivot from DMZ
  Wi-Fi       — connected to internal SSID (after wireless attack)
```

## Attack Decision Tree

```
Gained network access?
│
├─► Is IPv6 enabled on Windows hosts?      → mitm6 (highest impact)
│
├─► Are LLMNR/NBT-NS enabled?              → Responder (NTLMv2 capture)
│
├─► Is NTLM signing disabled?              → NTLM relay to SMB/LDAP/HTTP
│
├─► Is the port on a trunk or access port? → VLAN hopping if access port
│
├─► Is DHCP authenticated?                 → Rogue DHCP / starvation
│
└─► Are plaintext protocols in use?        → Passive sniffing / credential harvest
```

## Tooling Overview

```
Responder      — LLMNR/NBT-NS/mDNS/WPAD poisoner; NTLMv2 capture
mitm6          — IPv6 rogue DHCPv6 + DNS; Windows IPv6 preference exploit
Bettercap      — modern ARP/MITM framework; credential sniffer
Impacket       — ntlmrelayx, smbclient, secretsdump; the relay toolkit
Yersinia       — Layer 2 attack framework (DTP, STP, DHCP, 802.1Q)
Scapy          — packet crafting for custom protocol attacks
Wireshark      — passive capture and analysis
Pcredz         — credential extraction from live traffic or PCAP
Nmap           — host discovery and service enumeration
Masscan        — fast port scanning across large subnets
```

## MITRE ATT&CK Mapping

```
T1557     — Adversary-in-the-Middle
T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay
T1557.002 — ARP Cache Poisoning
T1040     — Network Sniffing
T1046     — Network Service Discovery
T1200     — Hardware Additions (rogue device on network)
T1556.006 — Multi-Factor Authentication — Network Device Auth Bypass
```

## Resources

- Impacket — `github.com/fortra/impacket`
- Responder — `github.com/lgandx/Responder`
- mitm6 — `github.com/dirkjanm/mitm6`
- Bettercap — `bettercap.org`
- Yersinia — `github.com/tomac/yersinia`
