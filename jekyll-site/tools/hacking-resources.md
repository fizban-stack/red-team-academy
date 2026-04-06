---
layout: training-page
title: "Hacking Learning Resources — Red Team Academy"
module: "Red Team Tools"
tags:
  - resources
  - training
  - ctf
  - learning
  - practice-labs
page_key: "tools-hacking-resources"
render_with_liquid: false
---

# Hacking Learning Resources

A curated collection of platforms, channels, and practice environments for developing offensive security skills. These resources cover everything from beginner concepts to advanced exploit development and CTF challenges.

## Practice Labs & CTF Platforms

Hands-on environments are the most effective way to build practical skills. These platforms provide vulnerable machines, guided challenges, and competitive CTFs.

| Platform | Description | Best For |
| --- | --- | --- |
| Hack The Box | Pen testing labs with 39+ vulnerable machines, new machines added monthly. Requires solving a challenge just to register. | Intermediate–Advanced |
| TryHackMe | Prebuilt cloud-hosted VMs with guided learning paths. Great for beginners with structured rooms covering specific techniques. | Beginner–Intermediate |
| VulnHub | Download and run vulnerable VMs locally. Large library of boot2root machines for offline practice. | All levels |
| PentesterLab | Exercises and bootcamps focused on web vulnerabilities and code review. Excellent for web hacking fundamentals. | Web-focused |
| OverTheWire | Progressive wargames via SSH. Start with Bandit (Linux basics) and advance through Natas (web) and Narnia (binary). | Beginner |
| ROP Emporium | Dedicated Return Oriented Programming challenges. Each challenge focuses on a specific ROP technique. | Binary Exploitation |
| pwnable.kr | Serious CTF challenges covering binary exploitation, pwning, and systems security. | Advanced Binary |
| CTFLearn | Account-based CTF site with a range of user-submitted challenges across categories. | Beginner CTF |
| Google CTF | Source code of Google CTF challenges (2017–2019) for offline practice and study. | All levels |
| PicoCTF | Carnegie Mellon hosted annual CTF, designed for high school and college students but excellent for all beginners. | Beginner CTF |
| Backdoor (SDSLabs) | Pen testing labs with beginner space, practice arena, and competitions. Account required. | Beginner–Intermediate |
| Hack This Site | Classic web-based challenge platform with progressive difficulty. Account required. | Beginner Web |
| Exploit Exercises | Five full vulnerable VMs (Protostar, Fusion, etc.) covering memory corruption, kernel exploits, and more. | Binary Exploitation |
| SmashTheStack | SSH-based wargames similar to OverTheWire, with progressive level system. | Binary Exploitation |
| Crackmes.one | Download crackme challenges to practice reverse engineering and crack checking algorithms. | Reverse Engineering |
| Google XSS Game | Focused XSS challenges with six levels. Good for understanding browser XSS mechanics. | Web — XSS |

## Online Courses & Learning Platforms

```
# Free academic courses (no account required)
MIT OCW 6.858 - Computer Systems Security
  - Full semester, video lectures, labs, readings
  - https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/

FSU Offensive Computer Security
  - 27 lecture videos with slides and assignments

Seed Labs (Syracuse University)
  - Lab videos, tasks, code files, and readings
  - Covers buffer overflows, SQL injection, XSS, TCP/IP attacks

# Account-based platforms
Cybrary       - Large library of video courses, filter by experience level
Hopper's Roppers - Four free self-paced courses: Computing Fundamentals,
                   Security, CTF, and Practical Skills Bootcamp
Hacksplaining  - Clickthrough explanations of web vulnerabilities (beginner-friendly)
SecurityTube   - "Megaprimer" video series covering network security, assembly, etc.
```

## YouTube Channels

The best free video content for practical security learning.

### Top Channels for Practitioners

```
LiveOverflow        - Buffer overflows, CTF writeups, exploit development
                      Regular uploads, beginner to advanced
IPPSec              - HTB retired machine walkthroughs, thorough methodology
John Hammond        - CTF solutions, penetration testing tips and tricks
HackerSploit        - Kali Linux tools, medium-length instructional videos
GynvaelEN           - Google researcher streams: CTFs, security research, coding
Liveoverflow        - Binary exploitation deep-dives
```

### Conference Talks

```
DEFCON Conference   - Iconic DEFCON talks from all years
BlackHat            - Professional conference talks (vulnerability research, tools)
Media.ccc.de        - Chaos Computer Club talks, massive archive
Hack In The Box     - International conference talks
BruCON              - Security and hacker conference, Belgium
DevSecCon           - DevSecOps and making software more secure
LASCON              - OWASP Austin conference talks
```

## Practice Workflow — Recommended Progression

```
# Beginner path
1. OverTheWire: Bandit (Linux command line basics)
   ssh bandit0@bandit.labs.overthewire.org -p 2220

2. TryHackMe beginner rooms
   - "Pre-Security" path
   - "Complete Beginner" path

3. Hacksplaining (web vulnerabilities overview)

4. Google XSS Game (XSS mechanics)
   https://xss-game.appspot.com/

# Intermediate path
5. PentesterLab bootcamps (web vulns with source code)

6. VulnHub machines (Easy/Medium)
   - Download VM, import to VMware/VirtualBox
   - Use nmap → service enum → exploit → privesc workflow

7. TryHackMe: specific technique rooms
   https://tryhackme.com/room/hydra         # Hydra brute force
   https://tryhackme.com/room/sqli          # SQL injection
   https://tryhackme.com/room/crackthehash  # Hash cracking

# Advanced path
8. Hack The Box (active machines — no writeups available)
   - Use methodology: nmap → web enum → exploit → priv esc

9. CTF competitions (team-based)
   - CTFtime.org for upcoming competitions

10. ROP Emporium (binary exploitation)
    https://ropemporium.com/
```

## CTF Writeup Archives

```
# Study past solutions to learn techniques
https://github.com/ctfs          # Collection of writeups by year/competition
https://ctftime.org/writeups     # Aggregated writeup database
IPPSec YouTube channel           # HTB machine walkthroughs (retired machines only)
```

## Cryptography Challenges

```
# Cryptopals — structured crypto attack challenges
https://cryptopals.com/
# Covers: fixed-nonce CTR, CBC padding oracle, RSA attacks, etc.
# Work through sets in order — each builds on the previous

# Ringzer0 — 272+ challenges including crypto
https://ringzer0team.com/challenges
```

## Key Reference Tools Used in Practice

```
# Recon
nmap -sV -sC -p- <target>        # Full version + default scripts scan
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Web exploitation
sqlmap -u "http://<target>/page?id=1" --dbs
burpsuite                          # Intercept and modify HTTP traffic
xsstrike -u "http://<target>/search?q=test"  # XSS scanner

# Password attacks
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> ssh
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt

# Post-exploitation
LinPEAS / WinPEAS                  # Automated privilege escalation enum
msfconsole -q                      # Metasploit console
```

## Community & News

```
Reddit communities:
  r/netsec        - News and technical content
  r/hacking       - General discussion
  r/oscp          - OSCP-specific prep and tips
  r/ctf           - CTF challenges and writeups

News sources:
  The Daily Swig  - portswigger.net/daily-swig
  Troy Hunt blog  - troyhunt.com
  Krebs on Security
```

## Resources

- Awesome Hacking Resources — `github.com/vitalysim/Awesome-Hacking-Resources`
- SecLists — `github.com/danielmiessler/SecLists`
- CTF Writeups Archive — `github.com/ctfs`
- CTFtime — `ctftime.org`
