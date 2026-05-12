---
layout: training-page
title: "Red Team Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - tools
  - reference
  - arsenal
page_key: "tools-overview"
render_with_liquid: false
---

# Red Team Tools Reference

A comprehensive reference covering the modern red team toolkit. Each category covers tool capabilities,
    common usage patterns, detection signatures, and OPSEC considerations. Tools are curated for
    relevance in 2025–2026 engagements.

## // Tool Categories

[01 // RECON
Reconnaissance Tools
Nmap, Masscan, RustScan, Amass, Subfinder, BBOT, Nuclei, theHarvester, Shodan CLI](/tools/recon-tools)
[02 // AD
Active Directory Tools
BloodHound, Impacket, NetExec, Rubeus, Mimikatz, Certipy, PowerView, Kerbrute](/tools/ad-tools)
[03 // EXPLOIT
Exploitation Tools
Metasploit, msfvenom, Responder, Evil-WinRM, SQLMap, Exploit-DB tooling](/tools/exploitation-tools)
[04 // POST
Post-Exploitation Tools
SeatBelt, WinPEAS/LinPEAS, LaZagne, SharpUp, PowerSploit, SharpCollection](/tools/post-exploitation-tools)
[05 // EVASION
Evasion & Obfuscation Tools
Donut, Garble, ScareCrow, Freeze, ConfuserEx, Shellter, AMSI bypass tooling](/tools/evasion-tools)
[06 // NETWORK
Network & Pivoting Tools
Chisel, Ligolo-ng, Socat, FRP, Proxychains, Ncat, SSHuttle](/tools/network-tools)
[07 // CREDS
Password & Credential Tools
Hashcat, John the Ripper, Hydra, Kerbrute, SprayingToolkit, CrackMapExec](/tools/password-tools)
[08 // WEB
Web Hacking Tools
Burp Suite, FFUF, Feroxbuster, Nuclei, Katana, Nikto, Caido](/tools/web-tools)
[09 // WIRELESS
Wireless Attack Tools
Aircrack-ng, Hcxtools, Hostapd-wpe, Bettercap, Kismet, Flipper Zero tooling](/tools/wireless-tools)
[10 // ANDROID
Android Red Team Tools
ADB, Frida, Objection, drozer, apktool, jadx, MobSF, APKLeaks, reFlutter, Burp Android setup](/tools/android-tools)

## // Quick Reference — Tool Selection Matrix

| Phase | Go-To Tool | Alternative | OPSEC Risk |
| --- | --- | --- | --- |
| External Recon | Amass / BBOT | Subfinder + theHarvester | LOW |
| Port Scanning | Nmap (TCP SYN) | Masscan → Nmap version scan | MEDIUM |
| Vuln Scanning | Nuclei | Nmap NSE scripts | MEDIUM |
| AD Enumeration | BloodHound + SharpHound | PowerView / ADRecon | HIGH |
| Lateral Movement | NetExec (SMB/WinRM) | Impacket (wmiexec, psexec) | HIGH |
| Credential Dump | Mimikatz / secretsdump | NanoDump / HandleKatz | HIGH |
| Kerberos Attacks | Rubeus | Impacket GetTGT/GetST | HIGH |
| ADCS Attacks | Certipy | Certify (C#) | HIGH |
| Tunneling | Ligolo-ng | Chisel / SSH -D | MEDIUM |
| Payload Evasion | Donut + Garble | ScareCrow / Freeze | MEDIUM |
| Web Fuzzing | FFUF | Feroxbuster / Gobuster | MEDIUM |
| Password Cracking | Hashcat (GPU) | John (CPU / rules) | LOW |
| Android APK Analysis | MobSF + jadx | APKLeaks + Androguard | LOW |
| Android SSL Bypass | Objection (Frida) | apktool NSC patch | MEDIUM |
| Android Exploitation | drozer | adb am start | LOW |
| Android Traffic Intercept | Burp + Frida | reFlutter (Flutter) | MEDIUM |

## // Installation Notes

Most tools are pre-installed on Kali Linux 2024+. For custom builds:

```
# Go-based tools (most modern red team tools)
go install github.com/<tool>@latest

# Python tools via pipx (isolated envs)
pipx install impacket
pipx install certipy-ad

# Kali meta-packages
sudo apt install kali-tools-post-exploitation
sudo apt install kali-tools-identify
sudo apt install kali-tools-passwords
```
