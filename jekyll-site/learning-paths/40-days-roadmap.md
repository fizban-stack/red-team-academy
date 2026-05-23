---
layout: training-page
title: "40 Days of Offensive Security — Red Team Academy"
module: "Learning Paths"
tags:
  - learning-path
  - roadmap
  - offensive-security
  - beginner
  - structured
  - portswigger
  - hackthebox
page_key: "learning-paths-40-days-roadmap"
render_with_liquid: false
---

# 40 Days of Offensive Security

A structured practice roadmap from the Daily Dark Team (#40DaysOfOffSec). Flexible pacing — 40 days does not mean 40 consecutive days. All resources are freely available unless noted. Platform accounts required: TryHackMe, HackTheBox, PortSwigger Academy, OffSec PG.

**[Download PDF Roadmap](/resources/drt-40-days-offensive-security-roadmap.pdf)**

---

## Phase Structure

| Phase | Days | Focus |
|---|---|---|
| 1 | 1–5 | Foundations — Tools, OS & Networking Basics |
| 2 | 6–14 | Web Exploitation — OWASP, Injections & Auth Flaws |
| 3 | 15–24 | Infrastructure & Active Directory |
| 4 | 25–33 | HTB & Platform Challenges |
| 5 | 34–40 | Advanced Topics, Evasion & Capstone |

---

## Phase 1 — Foundations (Days 1–5)

### Day 01 — OWASP Top 10

Build mental models for all ten vulnerability classes before touching a lab.

**RTA pages:** [Web Hacking Methodology](/web/web-hacking-methodology/), [Fundamentals Methodology](/fundamentals/methodology/)  
**Practice:** TryHackMe – OWASP Top 10 Room, PortSwigger Web Security Academy

---

### Day 02 — OWASP Juice Shop

Deliberately vulnerable Node.js app covering XSS, SQLi, IDOR, broken auth, and more. Aim to solve at least one challenge in every OWASP category.

**Practice:** TryHackMe – OWASP Juice Shop, [Juice Shop Official Docs](https://pwning.owasp-juice.shop)

---

### Day 03 — Linux Fundamentals & Privilege Escalation Basics

File permissions, SUID/SGID bits, cron jobs, writable paths, sudo misconfigurations. GTFOBins for living-off-the-land escalation.

**RTA pages:** [Linux Post-Exploitation](/post-exploitation/linux-post-exploitation/), [Linux PrivEsc](/post-exploitation/privesc-linux/)  
**Practice:** TryHackMe – Linux Fundamentals, GTFOBins — `gtfobins.github.io`

---

### Day 04 — Windows Fundamentals & Registry Essentials

Windows registry, services, scheduled tasks, UAC mechanisms, and common misconfigurations.

**RTA pages:** [Windows PrivEsc](/post-exploitation/privesc-windows/)  
**Practice:** TryHackMe – Windows Fundamentals 1, PayloadsAllTheThings – Windows PrivEsc

---

### Day 05 — Networking Foundations for Pentesters

TCP/IP, DNS, HTTP/S, ICMP, common ports. Practice with Wireshark and tcpdump to read packet captures and identify recon indicators.

**Practice:** TryHackMe – Pre-Security Networking, Wireshark Official Docs, TCPDump Cheat Sheet

---

## Phase 2 — Web Exploitation (Days 6–14)

### Day 06 — Information Disclosure & Version Control Leaks

Sensitive data exposed in error messages, hidden directories, `.git` folders, and debug endpoints. Tools: git-dumper, dirsearch.

**RTA pages:** [Source Code Disclosure](/web/source-code-disclosure/), [Web Recon](/recon/web-recon/)  
**Practice:**
- PortSwigger – Information disclosure in error messages
- PortSwigger – Information disclosure on debug page
- PortSwigger – Source code disclosure via backup files

---

### Day 07 — Cross-Site Scripting (XSS)

All three XSS families: reflected, stored, DOM. Payload filter bypass, cookie exfiltration, DOM sink weaponization.

**RTA page:** [XSS](/web/xss/)  
**Practice:**
- PortSwigger – Reflected XSS into HTML context
- PortSwigger – Stored XSS into HTML context
- PortSwigger – DOM XSS in document.write sink
- PortSwigger – DOM XSS in jQuery href attribute

---

### Day 08 — XXE Injection

Read local files, perform SSRF, exfiltrate via out-of-band channels. XML parser misconfiguration.

**RTA page:** [XXE](/web/xxe/)  
**Practice (labs listed on the page):**
- Exploiting XXE to retrieve files
- Exploiting XXE to perform SSRF
- Exploiting XXE via image file upload

---

### Day 09 — Server-Side Request Forgery (SSRF)

Pivot through the server to internal services, metadata endpoints, cloud credential stores. Filter bypass via open redirects.

**RTA page:** [SSRF](/web/ssrf/)  
**Practice (labs listed on the page):**
- SSRF against backend system
- SSRF against localhost
- SSRF filter bypass via open redirect

---

### Day 10 — OS Command Injection & SSTI

Chain template injection and command injection to RCE. Blind variants using time delays and OOB DNS callbacks.

**RTA pages:** [Command Injection](/web/command-injection/), [SSTI](/web/ssti/)  
**Practice (labs listed on each page):**
- SSTI basic
- OS command injection, simple case
- Blind OS injection with time delay

---

### Day 11 — File Upload Vulnerabilities

Bypass content-type checks, extension filters, race conditions — upload web shells for RCE.

**RTA page:** [File Upload](/web/file-upload/)  
**Practice (labs listed on the page):**
- RCE via web shell upload
- Content-Type restriction bypass
- Race condition upload

---

### Day 12 — JWT Attack Surface

Unverified signatures, weak secrets, JWK/JKU header injection, algorithm confusion (RS256→HS256).

**RTA page:** [JWT Attacks](/web/jwt-attacks/)  
**Practice (labs listed on the page):**
- JWT bypass via unverified signature
- JWT bypass via weak signing key
- JWK header injection
- Algorithm confusion

---

### Day 13 — Insecure Deserialization

Modify serialized objects, inject arbitrary objects, build PHP and Java gadget chains for RCE.

**RTA page:** [Insecure Deserialization](/web/insecure-deserialization/)  
**Practice (labs listed on the page):**
- Modifying serialized data types
- Arbitrary object injection in PHP
- Custom Java gadget chain

---

### Day 14 — SQL Injection — Manual & Automated

UNION-based, error-based, blind boolean, time-based SQLi. sqlmap for automation — understand every flag.

**RTA page:** [SQL Injection](/web/sql-injection/)  
**Practice:** PortSwigger – SQL Injection labs, HackTricks – SQLi Cheat Sheet, sqlmap docs

---

## Phase 3 — Infrastructure & Active Directory (Days 15–24)

### Day 15 — Active Directory Fundamentals

AD objects, trusts, GPOs, Kerberos authentication flow, common attack vectors.

**RTA pages:** [AD Enumeration](/active-directory/ad-enumeration/), [AD Assessment Tools](/active-directory/ad-assessment-tools/)  
**Practice:** TryHackMe – Windows AD Basics, TryHackMe – Breaching Active Directory

---

### Day 16 — Kerberoasting & AS-REP Roasting

Request service tickets for offline cracking (Kerberoasting). Exploit accounts without pre-auth (AS-REP Roasting) using Impacket and Rubeus.

**RTA pages:** [Kerberoasting](/active-directory/kerberoasting/), [AS-REP Roasting](/active-directory/asreproasting/)  
**Practice:** Impacket GetUserSPNs, PayloadsAllTheThings – Kerberoasting

---

### Day 17 — Pass-the-Hash, Pass-the-Ticket & NTLM Relay

Reuse credential material without plaintext. Set up Responder + ntlmrelayx to capture and relay NTLM auth.

**RTA pages:** [Pass-the-Hash](/active-directory/pass-the-hash/), [NTLM Relay](/active-directory/ntlm-relay/)  
**Practice:** Responder GitHub, Impacket ntlmrelayx docs

---

### Day 18 — BloodHound — Attack Path Mapping

Enumerate AD with SharpHound, ingest into BloodHound, find attack paths including shortest-path to Domain Admin.

**RTA page:** [BloodHound](/active-directory/bloodhound/)  
**Practice:** BloodHound GitHub, BloodHound Docs

---

### Day 19 — Buffer Overflow — Windows x86 Stack

EIP control, bad-character identification, JMP ESP selection, shellcode delivery. Immunity Debugger + Mona.py.

**RTA page:** [Stack Overflow](/exploit-dev/stack-overflow/)  
**Practice:** TryHackMe – Buffer Overflow Prep, Mona.py docs, Corelan Tutorial

---

### Day 20 — Buffer Overflow — Linux x86 & ret2libc

Exploit Linux stack overflows with NX enabled using ret2libc and ROP chains. ASLR bypass techniques.

**RTA page:** [ret2libc](/exploit-dev/ret2libc/)  
**Practice:** HackTricks – Return to Libc, LiveOverflow Binary Exploitation playlist

---

### Day 21 — Network Pivoting & Tunneling

sshuttle, chisel, ligolo-ng, and socat to pivot through compromised hosts. Dynamic port forwarding and reverse tunnels.

**RTA pages:** [Chisel SOCKS](/pivoting/chisel-socks/), [ligolo-ng](/pivoting/ligolo-ng/), [sshuttle](/pivoting/sshuttle-rpivot/)  
**Practice:** Chisel GitHub, ligolo-ng GitHub, HackTricks – Tunneling

---

### Day 22 — Credential Hunting & Post-Exploitation

Extract credentials from memory (Mimikatz), files, registry, browser stores, environment variables.

**RTA pages:** [Credential Hunting Tools](/post-exploitation/credential-hunting-tools/), [LSASS Dumping](/post-exploitation/lsass-dumping/), [Browser Credentials](/post-exploitation/browser-credentials/)  
**Practice:** Mimikatz GitHub, LaZagne GitHub

---

### Day 23 — VulnHub Practice — Beginner Linux

Apply recon → enumeration → exploitation → PrivEsc methodology. Focus on note-taking and reproducibility.

**Machines:**
- Rickdiculouslyeasy 1 — vulnhub.com/entry/rickdiculouslyeasy-1,207
- Kioptrix Level 1.3 — vulnhub.com/entry/kioptrix-level-13-4,25

---

### Day 24 — VulnHub Practice — Intermediate CTF

Multi-step machines requiring chained exploits. Document every step as if delivering a client report.

**Machines:**
- Mr. R3b0t — vulnhub.com/entry/mr-robot-1,151
- Bellatrix – Hogwarts — vulnhub.com/entry/hogwarts-bellatrix,609
- Stickyfingers — vulnhub.com/entry/stickyfingers,188

---

## Phase 4 — HTB & Platform Challenges (Days 25–33)

For full attack chain details on each machine, see [HTB Practice Machines](/exploitation/htb-practice-machines/).

| Day | Machine | Tags | Key Techniques |
|---|---|---|---|
| 25 | Busqueda | Linux, Web | Searchor Python eval injection, Docker container escape |
| 26 | OnlyForYou | Linux, Web | Flask LFI, Neo4j Cypher injection, pip install PrivEsc |
| 27 | Escape | Windows, AD | MSSQL NTLM coercion, AD CS ESC1 (Certify + Rubeus) |
| 28 | Flight | Windows, AD | File share NTLM capture, RunasCs lateral movement, IIS pool abuse |
| 29 | Absolute | AD | Kerberos-only enum, AS-REP roasting, DACL abuse, Shadow Credentials, KrbRelay |
| 30 | Mobile challenges | Mobile | APK reverse with jadx, SSL pinning bypass, insecure storage |
| 31 | Web & Crypto challenges | Web, Crypto | Prototype pollution, SSRF chain, hash extension attacks |
| 32 | OffSec PG Linux | Linux | Full methodology — 2 machines per session, clean reproducible notes |
| 33 | OffSec PG Windows | Windows, AD | WinRM, SMB enum, SeImpersonatePrivilege, token manipulation |

---

## Phase 5 — Advanced Topics & Capstone (Days 34–40)

### Day 34 — OSINT & Reconnaissance Methodology

Full target profile using passive and semi-passive techniques: WHOIS, certificate transparency, Shodan, TheHarvester, FOCA metadata extraction.

**RTA pages:** [Passive Recon](/recon/passive-recon/), [OSINT Automation](/recon/osint-automation/), [Email OSINT](/recon/email-osint/)

---

### Day 35 — Wireless & Physical Attack Vectors

WPA2 handshake capture, PMKID attacks, evil twin setups, badge cloning awareness.

**RTA pages:** [WiFi Attacks](/wireless/wifi-attacks/), [RFID Attacks](/wireless/rfid-attacks/)  
**Practice:** Aircrack-ng docs, hcxdumptool GitHub

---

### Day 36 — Cloud Security Fundamentals (AWS/Azure)

Misconfigured S3 buckets, overly permissive IAM roles, IMDS v1 metadata abuse, Azure App Registration exposures.

**RTA pages:** [AWS Attacks](/cloud/aws-attacks/), [Azure Attacks (various)](/active-directory/azure-ad/)  
**Practice:** HackTricks – AWS Pentesting, Pacu – AWS Exploitation Framework, TruffleHog

---

### Day 37 — Antivirus & EDR Evasion Concepts

Signature-based vs behavioral detection. Obfuscation techniques, process hollowing, AMSI bypass, ETW patching (conceptually).

**RTA pages:** [AV/EDR Evasion](/evasion/av-edr-evasion/), [AMSI Bypass](/evasion/amsi-bypass/), [ETW Bypass](/evasion/etw-bypass/)  
**Practice:** HackTricks – AV Bypass, Maldev Academy (intro)

---

### Day 38 — Digital Forensics for Pentesters

Artifact residue left by your own tools. Windows event logs, prefetch, LNK files, memory forensics — improve OPSEC.

**RTA pages:** [Anti-Forensics](/post-exploitation/anti-forensics/), [Modern OPSEC](/fundamentals/modern-opsec-2026/)  
**Practice:** Autopsy Forensics, Volatility Memory Forensics

---

### Day 39 — Custom C2 Infrastructure & Payload Delivery

Set up Sliver or Havoc, configure malleable profiles, stage payloads, establish persistence via scheduled tasks and registry run keys.

**RTA pages:** [Sliver](/c2-frameworks/sliver/), [Havoc](/c2-frameworks/havoc/), [Malleable C2](/c2-frameworks/malleable-c2/), [Persistence](/post-exploitation/persistence/)  
**Practice:** Sliver C2 GitHub, Havoc C2 GitHub

---

### Day 40 — Full-Scope Report Writing & Capstone

Synthesize a complete pentest report from your 40-day notes: executive summary, technical findings, CVSS scoring, remediation recommendations, PoC evidence. Review tooling gaps and plan next 30 days.

**RTA pages:** [Technical Report](/reporting/technical-report/), [Executive Report](/reporting/executive-report/), [Findings](/reporting/findings/)  
**Practice:** PTES Standard, TCM Security Report Writing Guide, OffSec Exam Report Template

---

## After Day 40

| Next Path | Why |
|---|---|
| [OSCP Prep](/learning-paths/oscp-prep/) | Industry-standard cert; validates everything in this roadmap |
| [CRTO Prep](/learning-paths/crto-prep/) | AD and C2 depth — builds directly on Days 15–18, 39 |
| [Bug Bounty](/learning-paths/bug-bounty/) | Apply web skills (Days 6–14) in a legal, paid environment |

---

*Source: Daily Dark Team — 40 Days of Offensive Security (#40DaysOfOffSec). All lab links are for authorized practice only.*
