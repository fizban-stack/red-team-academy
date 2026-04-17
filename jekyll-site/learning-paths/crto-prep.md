---
layout: training-page
title: "CRTO Preparation Path (6 Weeks) — Red Team Academy"
module: "Learning Paths"
tags:
  - crto
  - learning-path
  - certification
  - cobalt-strike
  - red-team
  - active-directory
  - c2
page_key: "learning-paths-crto-prep"
render_with_liquid: false
---

# CRTO Preparation Path — 6 Weeks

The Certified Red Team Operator (CRTO) certification from Zero-Point Security focuses on operational red teaming using Cobalt Strike as the primary C2 framework. Unlike OSCP, which tests individual exploit-find-and-execute skills, CRTO tests your ability to conduct a realistic adversary simulation — moving through a network stealthily, maintaining access, and achieving objectives against a monitored Windows Active Directory environment.

---

## CRTO Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 4 days (96 hours) |
| Format | Fully practical, Cobalt Strike lab environment |
| Objective | Compromise domain, collect flags, demonstrate tradecraft |
| Environment | Windows AD network with Defender and logging enabled |
| Retakes | One free retake included |
| Report | No formal report required (flags-based scoring) |

The exam is structured around a realistic enterprise environment. You will need to use Cobalt Strike throughout — there is no option to switch to Metasploit or manual tools. The flags are collected by completing specific objectives like compromising a domain controller, establishing persistence, or performing a specific attack technique.

**Key difference from OSCP:** CRTO rewards operational tradecraft. Running Mimikatz in the open or triggering EDR detections can cause beacon loss and flag failures. OPSEC discipline is graded implicitly.

---

## Prerequisites Checklist

Before starting week 1:
- [ ] Comfortable with Windows command line and PowerShell
- [ ] Understands Active Directory fundamentals (users, groups, GPOs, OUs, trusts)
- [ ] Has completed at least 10 HTB machines including some Windows AD-focused ones
- [ ] Familiar with Metasploit and basic post-exploitation (not required in CRTO, but foundational)
- [ ] Has read the RTO course material or is enrolled in the course

**Strongly recommended prerequisites:**
- OSCP or equivalent practical pentesting experience
- Completed HTB Forest, Active, Sauna, Mantis

---

## Week 1: C2 Fundamentals and Red Team Infrastructure

**Goal:** Understand the Cobalt Strike architecture, set up a functional team server, and operate beacons across multiple protocols.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/c2-frameworks/cobalt-strike](/c2-frameworks/cobalt-strike) | Cobalt Strike architecture, listeners, payloads, aggressor scripts |
| [/c2-frameworks/metasploit](/c2-frameworks/metasploit) | Baseline C2 understanding; Metasploit → CS pivoting concepts |
| [/infrastructure/overview](/infrastructure/overview) | Red team infrastructure design, OPSEC-aware setup |
| [/infrastructure/redirector-setup](/infrastructure/redirector-setup) | Apache/nginx redirectors, HTTPS C2 fronting, domain categorization |

### Cobalt Strike Architecture

```
Operator (Cobalt Strike Client)
        ↓ (HTTPS management)
Team Server (Linux VPS)
        ↓ (HTTP/HTTPS/DNS C2)
[Redirector / CDN]
        ↓
Target Beacon (Windows)
```

The team server should never be exposed directly. Traffic flows through one or more redirectors that filter non-beacon traffic (direct IP access, scanners, SOC investigators) away from the team server.

### Listener Types for CRTO

| Listener Type | Use Case | OPSEC |
|---|---|---|
| HTTPS | Primary long-haul C2 | High (blends with web traffic) |
| HTTP | Internal pivoting | Medium |
| DNS | Highly restricted egress environments | Very High |
| SMB | Internal lateral movement (no egress needed) | High (internal only) |
| TCP | Lateral movement, bind shells | Medium |

### Malleable C2 Profile Basics

A Malleable C2 profile controls how your beacon traffic looks on the wire. A default Cobalt Strike profile is trivially signatured by most EDR and network monitoring tools. Always use a custom profile.

Key profile sections to understand:
```
set sleeptime "60000";          # 60-second jitter for long-haul beacon
set jitter "30";                # 30% jitter on sleep interval
set useragent "Mozilla/5.0 ..."; # Mimic legitimate browser
http-get { ... }                 # What GET requests look like
http-post { ... }                # What POST (task response) looks like
```

Good starting profiles: [Malleable C2 Profiles GitHub](https://github.com/BC-SECURITY/Malleable-C2-Profiles)

### Lab: Team Server Setup

1. Spin up a VPS (DigitalOcean, Vultr, Linode) with Ubuntu 22.04
2. Install Java 11+ and Cobalt Strike
3. Generate SSL certificate with Let's Encrypt on a categorized domain
4. Configure nginx redirector to filter and proxy to team server
5. Start team server: `./teamserver <external_ip> <password> <profile>`
6. Connect Cobalt Strike client
7. Create HTTP and HTTPS listeners
8. Generate a staged payload and test callback

### Key Concepts

- **Staged vs stageless payloads** — staged are smaller but require two-stage delivery; stageless are larger but self-contained
- **Sleep and jitter** — longer sleep = less detectable; add jitter so beacons don't callback on exact intervals
- **Check-in vs task** — beacons check in on their own schedule; they receive tasks during check-in

---

## Week 2: Initial Access Tradecraft

**Goal:** Deliver a beacon payload to a target through multiple initial access vectors while evading common email/endpoint defenses.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploitation/vba-macro-shellcode](/exploitation/vba-macro-shellcode) | Office macro delivery, VBA shellcode injection, template injection |
| [/exploitation/lnk-weaponization](/exploitation/lnk-weaponization) | LNK file payloads, icon spoofing, delivery via network share |
| [/evasion/amsi-bypass](/evasion/amsi-bypass) | AMSI patching, string obfuscation, reflection-based bypass |

### Initial Access Vectors Covered in CRTO

The exam does not require phishing — you are given initial access. However, understanding these vectors is critical for the course and real operations:

| Vector | RTA Page | Detection Risk |
|---|---|---|
| Office Macro (VBA) | `/exploitation/vba-macro-shellcode` | High without obfuscation |
| LNK file | `/exploitation/lnk-weaponization` | Medium |
| HTML Smuggling | Not covered in CRTO exam | Low |
| ISO/VHD container | Bypasses Mark-of-the-Web | Low |
| Template injection | Via VBA page | Medium |

### AMSI Bypass — Core Concepts

AMSI (Antimalware Scan Interface) sits between PowerShell and Windows Defender. It scans scripts in memory before execution. Bypassing it is required for most PowerShell-based post-exploitation.

Common bypass approaches:
```powershell
# String concatenation to avoid signature (example)
$a = 'Am' + 'si' + 'Utils'
$b = [Ref].Assembly.GetType("System.Management.Automation.$a")

# Force error method (various patching approaches)
# Obfuscation via INVOKE-OBFUSCATION, Chameleon, etc.
```

**In Cobalt Strike:** Use BOF-based AMSI bypass to avoid touching PowerShell entirely when possible. See [/evasion/amsi-bypass](/evasion/amsi-bypass) for the full breakdown.

### OPSEC Discipline for Initial Access

- Do not use `powershell.exe` directly — use `powerpick` (Cobalt Strike's fork-and-run) or inline .NET execution
- Avoid dropping files to disk — use in-memory execution
- Do not spawn `cmd.exe` unnecessarily — use beacon's built-in shell commands
- Stageless payloads are better for initial delivery (no second connection to team server)

---

## Week 3: Active Directory Attacks

**Goal:** Move from initial foothold to domain compromise through the CRTO AD attack chain.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/bloodhound](/active-directory/bloodhound) | BloodHound collection, graph analysis, attack path identification |
| [/active-directory/kerberoasting](/active-directory/kerberoasting) | Ticket harvesting and offline cracking |
| [/active-directory/dcsync](/active-directory/dcsync) | DCSync from DA or with DCSync rights, Mimikatz/Impacket |
| [/active-directory/acl-abuse](/active-directory/acl-abuse) | WriteDACL, GenericAll, GenericWrite, ForceChangePassword |

### CRTO AD Attack Chain

```
Initial Foothold
    ↓
SharpHound Collection (via Cobalt Strike)
    ↓
BloodHound Analysis → Identify shortest path to DA
    ↓
Kerberoast service accounts → Crack offline
    ↓
ACL Abuse / AS-REP Roast / Password Spray → Move laterally
    ↓
Reach Domain Admin account or computer
    ↓
DCSync → Extract all domain hashes
    ↓
Persistence (Golden Ticket, etc.)
```

### BloodHound in Cobalt Strike

```
# Run SharpHound via execute-assembly
execute-assembly /opt/SharpHound.exe -c All --OutputDirectory C:\Windows\Temp

# Compress and exfil
compress beacon output:
download C:\Windows\Temp\<date>_BloodHound.zip
```

Key BloodHound queries for CRTO:
- "Shortest Path to Domain Admins"
- "Find All Domain Admins"
- "Kerberoastable Users"
- "Find AS-REP Roastable Users"
- "Shortest Path from Owned Principals"

### ACL Abuse Workflow

When BloodHound shows you have `GenericWrite` over a user account:
```powershell
# Set SPN for Kerberoasting
Set-DomainObject -Identity <target_user> -Set @{serviceprincipalname='nonexistent/DUMMY'}
# Kerberoast the account
# Remove SPN after
Set-DomainObject -Identity <target_user> -Clear serviceprincipalname
```

When you have `WriteDACL` over a group:
```powershell
# Grant yourself GenericAll to the group
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity <your_user> -Rights All
# Add yourself
Add-DomainGroupMember -Identity "Domain Admins" -Members <your_user>
```

---

## Week 4: Post-Exploitation and Lateral Movement

**Goal:** Move through the network using Cobalt Strike's lateral movement capabilities while maintaining OPSEC discipline.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/post-exploitation/lateral-movement](/post-exploitation/lateral-movement) | Overview of LM techniques, when to use each |
| [/post-exploitation/dcom-lateral](/post-exploitation/dcom-lateral) | DCOM-based lateral movement, MMC20, ShellWindows |
| [/post-exploitation/wmi-lateral](/post-exploitation/wmi-lateral) | WMI process creation, WMIexec, wmic.exe abuse |

### Lateral Movement Decision Matrix

| Technique | Requires | Creates Remote Process? | Network Logon Type | EDR Detection Risk |
|---|---|---|---|---|
| PsExec (CS built-in) | Admin share access | Yes (service) | 3 | High — very signatured |
| WMI | WMI access + local admin | Yes | 3 | Medium |
| DCOM | COM object access | Yes | 3 | Medium-Low |
| SMB Beacon | SMB listener on target | No (existing process) | 3 | Low |
| WinRM | WinRM enabled + creds | Yes | 3 | Medium |

**OPSEC note:** Logon type 3 (network logon) creates logon events in Windows Security logs. This is expected and unavoidable for remote access. What matters is the process lineage and whether your beacon stands out.

### Cobalt Strike Lateral Movement Commands

```
# Jump (built-in lateral movement, spawns beacon)
jump psexec64 <target> <listener>
jump wmi64 <target> <listener>
jump winrm64 <target> <listener>

# Remote execute (does not spawn beacon automatically)
remote-exec wmi <target> <command>
remote-exec winrm <target> <command>

# Spawn SMB beacon on already-compromised host
link <target>  # Connect to SMB listener
```

### Credential Harvesting in Cobalt Strike

Never run `sekurlsa::logonpasswords` directly — it's heavily signatured. Alternatives:
```
# BOF-based LSASS dump
execute-assembly /opt/Nanodump/nanodump.exe --write C:\Windows\Temp\nd.dmp

# Or use CS built-in with sleep mask (less detectable)
logonpasswords  # Runs via fork-and-run (still risky)

# Safer: harvest from registry hives
execute-assembly /opt/Seatbelt.exe WindowsCredentialFiles

# Or target specific credentials
execute-assembly /opt/SharpDPAPI.exe credentials
```

---

## Week 5: Evasion and AV/EDR Bypass

**Goal:** Operate in a Defender-enabled environment without triggering alerts or losing beacons.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/evasion/amsi-bypass](/evasion/amsi-bypass) | All AMSI bypass techniques, BOF-based, reflection, patching |
| [/evasion/av-edr-evasion](/evasion/av-edr-evasion) | EDR hooks, ETW patching, unhooking, syscall-based evasion |
| [/exploitation/shellcode-loaders](/exploitation/shellcode-loaders) | Custom loaders, process injection, encryption |
| [/exploitation/sandbox-evasion](/exploitation/sandbox-evasion) | Sandbox detection, timing checks, environment fingerprinting |

### Cobalt Strike Evasion Features

| Feature | Purpose | How to Enable |
|---|---|---|
| Sleep Mask | Encrypt beacon in memory during sleep | `set sleep_mask "true"` in profile |
| Stack Spoof | Spoof beacon's call stack | Compile with spoofed stack BOF |
| Module Stomping | Load beacon into legitimate DLL | Malleable C2 profile setting |
| PPID Spoof | Set legitimate parent process for beacon | `ppid <explorer_pid>` command |
| Blockdlls | Block non-Microsoft DLLs from injecting | `blockdlls start` in beacon |

### ETW Bypass in Cobalt Strike

ETW (Event Tracing for Windows) sends telemetry to EDR products. Patching ETW:
```
# Cobalt Strike BOF-based ETW patching
execute-assembly /opt/TamperETW.exe  # or similar BOF
```

Alternatively, use fork-and-run operations (Cobalt Strike's default for post-exploitation commands) which execute in a sacrificial process and minimize beacon contamination.

### Testing Evasion Effectiveness

Before the exam:
1. Test your payload against Windows Defender in a controlled lab
2. Run ThreatCheck against your shellcode: `ThreatCheck.exe -f payload.exe`
3. Use PE-sieve to detect injection artifacts
4. Check if your AMSI bypass survives PowerShell 5.1 and 7.x

---

## Week 6: Full Simulation and Debrief

**Goal:** Run a complete red team exercise from initial foothold to domain compromise in the CRTO exam-like environment.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/scenarios/apt29-financial](/scenarios/apt29-financial) | Full APT-style attack chain, mimics exam conditions |
| [/scenarios/supply-chain-attack](/scenarios/supply-chain-attack) | Advanced scenario showing complex attack paths |

### Pre-Exam Checklist

**Infrastructure:**
- [ ] Team server running with HTTPS malleable profile
- [ ] Listeners created: HTTPS (external), SMB (internal pivot)
- [ ] Stageless payload generated and tested
- [ ] Redirectors configured and tested

**Tooling:**
- [ ] SharpHound, BloodHound desktop app ready
- [ ] Seatbelt, SharpDPAPI, Rubeus via execute-assembly
- [ ] BOFs ready: AMSI, ETW, credential BOFs
- [ ] Aggressor scripts loaded

**OPSEC habits:**
- [ ] Using `powerpick` instead of `powershell`
- [ ] Sleeping beacons between tasks (60+ seconds in exam)
- [ ] Using sacrificial processes for fork-and-run operations
- [ ] Not running Mimikatz directly — using BOF alternatives

### Cobalt Strike Features to Master

| Feature | Why It Matters for CRTO |
|---|---|
| Aggressor Scripts | Automate repetitive tasks, custom menu items |
| Beacon Object Files (BOFs) | In-process execution, avoids fork-and-run detection |
| Malleable C2 Profiles | Essential for EDR evasion |
| Sleep Mask | Protects beacon in memory during sleep periods |
| Artifact Kit | Customize payload artifacts (stagers, loaders) |
| Process Injection | PPID spoof + injection into legitimate processes |
| Data Model | Tracking targets, credentials, notes within CS |

### Common CRTO Exam Mistakes

1. **Running everything as SYSTEM** — use least privilege; DA is achievable without always being SYSTEM
2. **Not using sleep/jitter** — noisy fast check-ins will get your beacon flagged
3. **Forgetting to pivot via SMB** — egress-filtered machines need SMB pivot beacons
4. **Skipping BloodHound** — always collect and analyze before manually enumerating
5. **Using default CS profile** — immediately signatured; always use custom malleable profile
6. **Running MimiKatz executable** — use BOF or execute-assembly with obfuscated binary

---

## CRTO Resources

| Resource | Type | Notes |
|---|---|---|
| Zero-Point Security RTO Course | Official course | Required — includes all lab access |
| Cobalt Strike Documentation | Official reference | `help` in CS client is comprehensive |
| CS TLD (Threat Landscape Documentation) | Blog series | Raphael Mudge's original CS blog |
| SpecterOps BloodHound documentation | Reference | AD attack path methodology |
| BC-Security Malleable C2 Profiles | GitHub | Good starter profiles |
| TrustedSec Cobalt Strike arsenal | GitHub | BOF collection |
| RastaMouse blog | Blog | CRTO author's own red team content |
