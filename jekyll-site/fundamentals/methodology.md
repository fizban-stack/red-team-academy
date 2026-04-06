---
layout: training-page
title: "Red Team Methodology — Red Team Academy"
module: "Fundamentals"
tags:
  - methodology
  - planning
  - frameworks
page_key: "fundamentals-methodology"
render_with_liquid: false
---

# Red Team Methodology

## What is Red Teaming?

Red teaming is a goal-oriented adversary simulation. Unlike a penetration test — which aims to enumerate and validate vulnerabilities — a red team engagement emulates a specific threat actor's tactics, techniques, and procedures (TTPs) to test an organization's **detection and response capabilities**, not just their attack surface. The question is not "can you be broken into?" but "will you know when you are?"

![Red team engagement lifecycle: planning, recon, initial access, execution, persistence, lateral movement, objective, then report](/images/fundamentals/redteam-lifecycle.svg)  
*// red team engagement lifecycle — phase sequence from planning to objective*

## Penetration Test vs Red Team vs Purple Team

| Attribute | Pentest | Red Team | Purple Team |
| --- | --- | --- | --- |
| Goal | Find all vulnerabilities | Achieve specific objectives; test detection | Improve detection & response together |
| Scope | Wide — everything in scope | Narrow — specific targets/objectives | Collaborative — red and blue together |
| Blue Team Awareness | Usually unaware | Fully unaware (stealth) | Fully aware and participating |
| Duration | Days to weeks | Weeks to months | Days to weeks (iterative) |
| Primary Output | Vulnerability list with CVSS | Narrative of breach path + detection gaps | Detection rules, response improvements |
| Threat Model | Generic attacker | Specific APT or insider threat | Specific techniques (ATT&CK-driven) |

## Engagement Types

- **External Red Team** — Start from the internet with zero initial access. Simulate an outsider threat. Goal: achieve initial access, move internally, reach objectives.
- **Internal / Assumed Breach** — Start with a shell on a workstation inside the network. Skips the initial access phase to focus on lateral movement, AD attacks, and detection testing. Most value for mature organizations.
- **Physical Red Team** — On-site testing: tailgating, badge cloning, installing rogue hardware, accessing unsecured terminals.
- **Social Engineering Campaign** — Phishing, vishing, smishing. Tests employee awareness and email security controls.
- **Full Adversary Simulation** — End-to-end engagement emulating a specific threat actor (APT29, FIN7, etc.) using their documented TTPs. Highest fidelity — requires a mature blue team to be valuable.

## The Red Team Attack Lifecycle

While no two engagements follow identical paths, a structured methodology guides every operation. This lifecycle maps directly to the MITRE ATT&CK framework.

### Phase 1 — Reconnaissance

Gather intelligence about the target without touching their systems. Everything needed to craft convincing phishing lures, identify attack surfaces, and understand the org structure.

- OSINT: LinkedIn, job postings (technology stack clues), WHOIS, certificate transparency logs
- External footprint: Shodan/Censys scan, subdomain enumeration, email harvesting
- Technology profiling: CDN providers, email security (MX, SPF/DKIM), VPN portals

### Phase 2 — Initial Access

Establish the first foothold. The most common initial access vectors in real-world red teams:

- Spearphishing with malicious attachment or link (T1566)
- Valid accounts with breached/guessed credentials (T1078)
- External-facing application exploitation (T1190)
- Supply chain / trusted relationship abuse (T1195, T1199)
- Physical access / USB drops (T1091, T1200)

### Phase 3 — Establish Persistence & C2

Before moving anywhere, establish a reliable callback and persistence mechanism. If your initial access vector is closed, you need a way back in.

```
# Goals at this phase:
# 1. Deploy a stable C2 beacon
#    Commercial: Cobalt Strike (CS 4.x), Brute Ratel C4 (BRC4)
#    Open-source: Sliver, Havoc C2, Mythic C2
# 2. Establish persistence (scheduled task, registry run key, service)
# 3. Validate C2 callback survives reboot
# 4. Set beacon sleep high (15–60 min) + jitter (20–30%) to avoid
#    behavioral detection and beacon interval fingerprinting

# CS malleable profiles + Sliver implant profiles control beacon behavior.
# Havoc and Mythic are mature open-source alternatives with active development.
# Tool choice depends on client's EDR — profile all tools against the target stack.
```

### Phase 4 — Enumeration & Discovery

Understand the environment you've landed in. Who are you? What can you reach? What does the network look like?

```
# On a Windows foothold:
whoami /all                     # Privileges and group memberships
ipconfig /all                   # Network — what subnets exist?
net user /domain                # Domain users
net group "Domain Admins" /domain
systeminfo | findstr /i "domain\|os"
nltest /domain_trusts           # Forest/domain trusts
```

### Phase 5 — Privilege Escalation

Elevate from a low-privilege user to local admin or SYSTEM. Required before dumping credentials, installing persistence in HKLM, or moving laterally using admin shares.

- Windows: Unquoted service paths, token impersonation, AlwaysInstallElevated, UAC bypass
- Linux: SUID/SGID binaries, sudo misconfigurations, writable cron jobs, kernel exploits

### Phase 6 — Credential Access

Collect credentials for lateral movement. Hashes, tickets, and plaintext passwords enable impersonating privileged accounts.

```
# Windows credential dumping (requires admin/SYSTEM)
# Mimikatz in-memory:
sekurlsa::logonpasswords         # Plaintext/hashes from LSASS
lsadump::sam                     # Local SAM hashes
lsadump::dcsync /user:krbtgt     # DCSync — pull any domain hash

# Linux:
cat /etc/shadow                  # Requires root
find / -name "*.py" -exec grep -l "password" {} \;  # App credentials
```

### Phase 7 — Lateral Movement

Use collected credentials to move to higher-value systems. The goal is to reach the objectives (domain controller, file server, sensitive data store).

```
# Common lateral movement techniques:
# Pass-the-Hash:
crackmapexec smb 10.0.0.0/24 -u admin -H <NTLM_hash> --local-auth

# Evil-WinRM (PTH or password):
evil-winrm -i 10.0.0.5 -u administrator -H <NTLM_hash>

# PSExec:
impacket-psexec domain/admin@10.0.0.5 -hashes :<NTLM_hash>
```

### Phase 8 — Objectives

Accomplish the defined mission objectives. Common objectives depend on the engagement type:

- Achieve Domain Admin / Enterprise Admin
- Access a specific sensitive data repository (HR system, financial data, IP)
- Demonstrate ability to deploy ransomware (without actually deploying it)
- Exfiltrate a predefined "crown jewel" file
- Achieve persistence across the entire domain (Golden Ticket)

### Phase 9 — Reporting & Cleanup

Document every action with timestamps. Remove all artifacts, backdoors, and test accounts. Deliver findings with a clear narrative and remediation guidance.

## Formal Methodology Frameworks

- **PTES (Penetration Testing Execution Standard)** — Seven phases: pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, reporting. `http://www.pentest-standard.org/`
- **TIBER-EU** — European Central Bank framework for financial sector red team testing. Requires dedicated threat intelligence phase with external provider.
- **CBEST** — UK FCA/Bank of England equivalent. Intelligence-led, threat-actor-emulation focused.
- **MITRE ATT&CK** — Not a methodology but the universal taxonomy. Use it to plan, execute, and report every engagement. See the MITRE ATT&CK page for full details.

## Assumed Breach — Operational Checklist

In an assumed breach engagement, you are provided credentials for a domain-joined workstation. The goal is to test detection capability from an insider-threat starting position, not to test perimeter defenses. Treat this as if you've already completed initial access.

```
# Step 1 — Connect via RDP:
xfreerdp /v:<TARGET_IP> /u:<USER> /p:<PASS> /d:<DOMAIN> /dynamic-resolution /cert-ignore /drive:kali,/tmp

# Step 2 — Situational awareness (run immediately after landing):
whoami /all                         # Privileges, group memberships, integrity level
whoami /groups | findstr "Mandatory"   # Look for Medium vs High vs System level
net localgroup Administrators       # Are you a local admin?

# Step 3 — Check UAC configuration:
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
# ConsentPromptBehaviorAdmin = 0x0 → UAC auto-elevates without prompt (trivial bypass)

# Step 4 — Network discovery:
ipconfig /all                       # What subnets exist?
netstat -ano                        # Active connections, listening ports
arp -a                              # Hosts seen recently
nslookup <DOMAIN>                   # Find domain controller IP

# Step 5 — Deploy C2 beacon, escalate to SYSTEM, collect credentials
# (See C2 framework pages for specific steps with Sliver)

# Step 6 — Establish persistence before lateral movement
# (Scheduled tasks, registry Run keys, startup folder — see Sliver persistence section)
```

## Lateral Movement — General Considerations

Lateral movement rarely follows a straight path. Success depends on available credentials, reachable services, and imagination about how services interact within the network.

- **Not all services require admin rights** — PSRemoting, RDP, WMI, DCOM, and SSH all allow non-admin users to execute commands under certain configurations. Test every credential against every reachable service.
- **Network segmentation matters** — Firewalls may block your direct path to a target. Use other compromised machines as stepping stones. Identify Layer 3 boundaries (router, L3 switch, firewall) between segments.
- **Non-default ports** — Administrators change default ports (e.g., RDP on 23389 instead of 3389). Use `netstat -ano` and tasklist to identify what services are running on which ports.
- **IPv6 is often overlooked** — IPv6 is enabled by default on Windows. If IPv4 connections are blocked but IPv6 is not, connect using the IPv6 address in brackets: `[dead:beef::1]`.
- **Repeat the process** — Every new machine is a new starting point. Search for credentials, tokens, and reachable services. Iterate toward your objective.
- **Indirect movement** — When a target can't be reached directly, look for services it connects to: WSUS, SCCM, software deployment tools, network shares, or MSSQL servers. Compromise the intermediary.

```
# Find non-default ports in use:
netstat -ano
tasklist /svc /FI "PID eq <PID>"    # Map port to service name

# Test WinRM with non-admin credentials:
Enter-PSSession -ComputerName <TARGET> -Authentication Negotiate -Credential (Get-Credential)

# Connect to IPv6 WinRM:
Enter-PSSession -ComputerName [dead:beef::647f:620f:3a1a:e978] -Authentication Negotiate

# Test RDP access:
mstsc.exe /v:<TARGET>:23389         # Non-default RDP port
```

## Red Team Operator Mindset

- **Think like a threat actor, not a CTF player** — The goal isn't to solve puzzles. It's to accomplish realistic objectives while remaining undetected.
- **Slow is smooth, smooth is fast** — Noisy scanning and mass exploitation burns your cover. Patience and precision beat speed.
- **Document everything in real time** — Timestamps, screenshots, commands run, files accessed. You cannot reconstruct this after the fact.
- **Know when to stop and deconflict** — If you stumble on evidence of a real attacker, stop immediately and notify the client. Do not compromise an active incident investigation.
- **Leave the environment as you found it** — Remove all tools, close all backdoors, delete all test accounts. Your artifacts could become someone else's attack vector.

## Key Resources

- `https://attack.mitre.org` — MITRE ATT&CK knowledge base
- `http://www.pentest-standard.org` — PTES methodology
- `https://www.tiber.eu` — TIBER-EU framework
- `https://github.com/center-for-threat-informed-defense` — Adversary emulation plans
- *The Hacker Playbook 3* by Peter Kim — Practical red team methodology
- *Red Team Development and Operations* by Joe Vest & James Tubberville
