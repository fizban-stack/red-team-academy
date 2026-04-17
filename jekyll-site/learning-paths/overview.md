---
layout: training-page
title: "Learning Paths Overview — Red Team Academy"
module: "Learning Paths"
tags:
  - learning-paths
  - overview
  - certifications
  - oscp
  - crto
  - crte
  - pnpt
page_key: "learning-paths-overview"
render_with_liquid: false
---

# Learning Paths Overview

Red Team Academy (RTA) content is organized into standalone reference pages covering individual techniques, tools, and concepts. Learning paths stitch those pages together into a structured, sequenced curriculum designed around a specific goal — usually a certification or job role. This page explains how to use the paths, how they map to exams, and how to set up your environment for each one.

---

## How to Use Learning Paths

### Sequential Study vs. Reference Lookup

Learning paths are designed to be followed **week by week** when you are preparing for a certification or building skills from scratch. Each week builds on the previous one, so jumping ahead can leave gaps.

Reference lookup is appropriate when you already have a baseline and need to quickly review a technique before an engagement. In that case, navigate directly to the relevant page rather than following a path.

| Use Case | Approach |
|---|---|
| Preparing for OSCP from scratch | Follow the OSCP path week by week |
| Reviewing Kerberoasting before an exam | Go directly to `/active-directory/kerberoasting` |
| Building an AD lab for the first time | Follow the first week of any AD path, then lab-setup |
| Refreshing on AMSI bypasses | Go directly to `/evasion/amsi-bypass` |
| New to red teaming entirely | Start with Fundamentals, then pick a certification path |

### Recommended Study Cadence

**Daily practice (30–60 min)** is more effective than weekend deep dives. Red team skills require muscle memory — running tools, remembering syntax, recognizing output patterns. Trying to absorb a week of content in one Saturday session produces poor retention.

Suggested daily rhythm:
1. Read one RTA page or tool reference (20 min)
2. Reproduce the technique in your lab (30 min)
3. Add a note to your ops journal (10 min)

Weekend sessions work well for longer labs, HTB machines, or full attack chain simulations where you need 3–4 hours of uninterrupted time.

---

## Tracking Progress

### Notes System

Maintain a notes folder structured by technique category. A simple markdown file per topic works well. Record:
- The command that worked
- Any environment-specific quirks
- What detection/logging triggered (if known)
- The page or source where you learned it

### Ops Journal

Keep a dated ops journal for lab sessions and exam attempts. Each entry should cover:
- What machine or scenario you worked on
- What techniques you attempted
- What failed and why
- What you would do differently

This directly prepares you for exam report writing. OSCP and CRTO both require reports — practice writing them during lab sessions, not just during the exam.

### Progress Tracking Template

```
Week: [1-8]
Date: YYYY-MM-DD
Topic: [e.g., "Windows PrivEsc - Token Impersonation"]
Pages Covered:
  - /post-exploitation/privesc-windows
  - /post-exploitation/token-impersonation
Lab Work:
  - Completed PrintSpoofer on HTB Fuse
  - Token impersonation via service account on lab DC
  - Tested JuicyPotato — failed on Server 2019 (expected)
Notes:
  - PrintSpoofer requires SeImpersonatePrivilege
  - Check whoami /priv before attempting potato attacks
  - JuicyPotato CLSID varies by OS version, look up CLSID list
Open Questions:
  - What is the exact check MDE uses for SeImpersonatePrivilege abuse?
```

---

## Available Learning Paths

| Path | Duration | Target Cert | Skill Level |
|---|---|---|---|
| [OSCP Prep](/learning-paths/oscp-prep) | 8 Weeks | OSCP | Intermediate |
| [CRTO Prep](/learning-paths/crto-prep) | 6 Weeks | CRTO | Intermediate–Advanced |
| [CRTE Prep](/learning-paths/crte-prep) | 6 Weeks | CRTE | Advanced |
| [Bug Bounty Starter](/learning-paths/bug-bounty) | 4 Weeks | N/A (platform) | Beginner–Intermediate |
| [Zero Trust Bypass](/learning-paths/zero-trust-bypass) | 8 Weeks | N/A (skill) | Advanced |

---

## Prerequisites by Path

### OSCP Preparation Path

**Required before starting:**
- Comfortable using Linux at the command line (file system navigation, pipes, redirection, process management)
- Basic networking knowledge (TCP/IP, DNS, HTTP, ports and protocols)
- Familiarity with Python or Bash scripting at a basic level
- Able to stand up a Kali or Parrot OS VM

**Not required:**
- Prior pentesting experience
- Programming/development background
- Windows administration knowledge (taught in the path)

If you are missing Linux fundamentals, spend one week on OverTheWire Bandit (25 levels) before starting the OSCP path.

### CRTO Preparation Path

**Required before starting:**
- Comfortable with basic pentesting (can complete OSCP-level machines)
- Understands Windows Active Directory at a conceptual level
- Has stood up a Windows lab before
- Familiar with Metasploit and basic post-exploitation

**Strongly recommended:**
- Completed or nearly completed OSCP, or equivalent HTB/THM experience
- Read RTA [Fundamentals/Methodology](/fundamentals/methodology) and [Engagement Planning](/fundamentals/engagement-planning)

### CRTE Preparation Path

**Required before starting:**
- Completed CRTO or equivalent Cobalt Strike / AD attack experience
- Deep understanding of Kerberos authentication
- Comfortable reading BloodHound graphs and identifying attack paths
- Experience with PowerView, SharpHound, Rubeus

### Bug Bounty Starter Path

**Required before starting:**
- Comfortable using a web proxy (Burp Suite Community or Pro)
- Understands HTTP request/response cycle
- Basic familiarity with HTML, JavaScript, SQL (reading only)

**Not required:**
- Programming background
- Prior web development experience

### Zero Trust Bypass Path

**Required before starting:**
- Strong Active Directory attack background (CRTO level or equivalent)
- Familiar with Azure AD / Entra ID concepts
- Experience with evasion techniques (AMSI bypass, AV evasion basics)
- Completed at least one simulated engagement or red team exercise

---

## Certification Mapping

### OSCP (Offensive Security Certified Professional)
- **Provider:** OffSec
- **Format:** 24-hour exam, 3 machines + AD set, written report
- **Minimum score:** 70 points
- **Key skills:** Enumeration, exploit identification, manual exploitation, PrivEsc (Windows + Linux), basic AD attacks, report writing
- **RTA Path:** [OSCP Prep](/learning-paths/oscp-prep)
- **Estimated lab hours:** 150–300 hours (PWK labs + HTB + VulnHub)

### CRTO (Certified Red Team Operator)
- **Provider:** Zero-Point Security (RastaMouse)
- **Format:** 4-day practical exam on a Cobalt Strike lab
- **Key skills:** Cobalt Strike tradecraft, malleable C2, OPSEC-conscious pivoting, full AD attack chains
- **RTA Path:** [CRTO Prep](/learning-paths/crto-prep)
- **Estimated lab hours:** 80–120 hours (RTO course labs)

### CRTE (Certified Red Team Expert)
- **Provider:** Altered Security (Nikhil Mittal)
- **Format:** Multi-day lab exam
- **Key skills:** Advanced AD attacks, forest trusts, ADCS, SQL server, lateral movement chains
- **RTA Path:** [CRTE Prep](/learning-paths/crte-prep)
- **Estimated lab hours:** 100–150 hours

### PNPT (Practical Network Penetration Tester)
- **Provider:** TCM Security
- **Format:** 5-day practical exam + 2-day report submission
- **Key skills:** External recon, initial access, AD internal, report writing
- **Recommended RTA content:** Weeks 1–5 of OSCP path cover 90% of PNPT material
- **Note:** PNPT is a good first practical cert before OSCP

### eCPPT (eLearnSecurity Certified Professional Penetration Tester)
- **Provider:** INE / eLearnSecurity
- **Format:** 7-day practical exam
- **Key skills:** Web, network, basic exploit dev, metasploit, pivoting, report writing
- **Recommended RTA content:** OSCP path weeks 1–6

### OSED (Offensive Security Exploit Developer)
- **Provider:** OffSec
- **Format:** 48-hour exam, exploit development only
- **Key skills:** SEH overflows, egghunters, DEP/ASLR bypass, custom shellcode
- **Recommended RTA content:** [/exploit-dev/stack-overflow](/exploit-dev/stack-overflow), [/exploit-dev/seh-exploitation](/exploit-dev/seh-exploitation), plus the full EXP-301 course

### OSEP (Offensive Security Experienced Penetration Tester)
- **Provider:** OffSec
- **Format:** 48-hour practical exam
- **Key skills:** Antivirus evasion, shellcode injection, lateral movement, AMSI bypass, custom C2
- **Recommended RTA content:** CRTO path + evasion pages + exploit-dev shellcode pages

---

## Lab Setup by Path

### OSCP Lab Environment

**Minimum specs:**
- 16 GB RAM host
- 250 GB SSD
- Hypervisor: VMware Workstation or VirtualBox

**VMs needed:**
- Kali Linux (2024.x) — attack machine
- Windows 10 or 11 — target for PrivEsc practice
- Windows Server 2019/2022 — for AD setup
- Ubuntu Server 22.04 — for Linux PrivEsc targets

**External resources:**
- PWK course labs (included with OSCP enrollment)
- [HackTheBox](https://hackthebox.com) — TJ Null's OSCP-like list
- [VulnHub](https://vulnhub.com) — offline downloadable VMs

For setting up an AD lab at home, see [/fundamentals/methodology](/fundamentals/methodology) and the lab-setup pages linked from the OSCP path week 1.

### CRTO Lab Environment

**Additional requirements over OSCP:**
- Cobalt Strike license (team server) — trial or licensed
- Windows Server 2016/2019 as domain controller
- 2–3 Windows 10/11 workstations joined to domain

**Recommended:** Use the Zero-Point Security RTO course lab environment — it comes pre-configured with CS and the target network.

### Bug Bounty Environment

- Kali or any Debian-based distro
- Burp Suite Pro (essential — Community is too limited for active hunting)
- Firefox with FoxyProxy, HackBar, and Wappalyzer extensions
- `amass`, `subfinder`, `httpx`, `nuclei` installed

No local victim VMs required — hunting happens against live bug bounty programs in scope.

---

## Study Advice for Each Path

### Building Sustainable Study Habits

The biggest failure mode for certification candidates is inconsistency. Three weeks of intense study followed by two weeks off resets most of the skill gained. Aim for:

- **Minimum:** 5 days/week, 45 minutes/day
- **Target:** 5 days/week, 90 minutes/day + one 3-hour weekend lab session
- **Avoid:** All-or-nothing sessions; marathon then crash cycles

### When You're Stuck

1. Re-read the RTA page for the technique
2. Try the technique on a different target in your lab
3. Search HTB forums or ippsec walkthroughs for the specific scenario
4. Check the RTA Discord or community resources
5. Move on and come back — sometimes the answer appears after you have more context

### Reporting Practice

Every learning path eventually requires a report. Start writing mock reports from week 1, even if they are brief. Include:
- Finding name
- Severity
- Affected host/service
- Evidence (screenshot or command output)
- Remediation recommendation

This turns into muscle memory by exam time. See [/reporting/findings](/reporting/findings) for full report writing guidance.
