---
layout: training-page
title: "AD Assessment Tools — Red Team Academy"
module: "Active Directory"
tags:
  - active-directory
  - pingcastle
  - adrecon
  - adidnsdump
  - scavenger
  - linwinpwn
page_key: "ad-assessment-tools"
render_with_liquid: false
---

# AD Assessment Tools

## Mapping the Domain Before You Attack It

Attacking Active Directory without understanding the environment is guesswork. You need to know: what's the domain trust structure, which accounts have excessive rights, where are the delegation misconfigurations, what's the Kerberoastable surface area, who has GPO write access, and what legacy protocols are enabled.

These tools answer those questions systematically — mapping the domain, identifying misconfigurations, and revealing attack paths before you commit to an exploitation path.

## PingCastle — AD Security Assessment

PingCastle is the industry-standard Active Directory security assessment tool. It generates a risk-scored report covering 150+ checks across domain health, trusts, privileged accounts, Kerberos configuration, and LAPS deployment. Red teams use it to rapidly identify the highest-value attack paths.

### Installation

```bash
# Download from official site
# https://www.pingcastle.com/download/
# PingCastle is free for use in assessments

# Windows binary — no installation required
```

### Basic Assessment

```powershell
# Run full domain assessment (run as any domain user)
.\PingCastle.exe --healthcheck

# Generate report for specific domain
.\PingCastle.exe --healthcheck --server dc01.target.domain.com

# Output formats
.\PingCastle.exe --healthcheck --xmlOutput   # XML (default)
.\PingCastle.exe --healthcheck --log         # Detailed log

# Run from non-domain-joined machine with explicit creds
.\PingCastle.exe --healthcheck --server dc01.target.com --user DOMAIN\user --password P@ssw0rd
```

### Specific Assessment Modes

```powershell
# Check all trusts and foreign domain relationships
.\PingCastle.exe --healthcheck --explore-trust

# Map all domains in the forest
.\PingCastle.exe --healthcheck --explore-forest-trust

# Privileged account analysis only
.\PingCastle.exe --advanced-graph

# Generate consolidated report across multiple domains
.\PingCastle.exe --consolidation
```

### Key Risk Areas PingCastle Reports

| Category | Common Findings |
|---|---|
| Trusts | Transitive trusts to foreign domains, SID filtering disabled |
| Privileged Accounts | Admincount orphans, nested group anomalies |
| Password Policy | No fine-grained policy, weak default policy |
| Kerberos | Unconstrained delegation, Kerberoastable service accounts |
| LAPS | Machines without LAPS (local admin password sharing) |
| Legacy | NTLM enabled, SMBv1 present, RC4 Kerberos |
| Inactive | Stale accounts, computers not logged in >90 days |

### Reading the Report

PingCastle outputs `*.healthcheck.html` — open in browser. Focus on:
- **Score** — 0 (perfect) to 100 (critical issues). Most enterprise domains score 30-70.
- **Critical** items first — these are direct attack paths
- **Stale objects** — inactive accounts often have passwords that still work

## ADRecon — Active Directory Information Gathering

ADRecon generates a comprehensive Excel report of the Active Directory environment. Unlike PingCastle (risk-focused), ADRecon dumps *everything* — all users, computers, GPOs, ACLs, trusts, groups, and more — into a structured workbook for analysis.

### Installation

```powershell
# Clone or download
git clone https://github.com/sense-of-security/ADRecon

# Import module
Import-Module .\ADRecon.ps1
```

### Running ADRecon

```powershell
# Full domain recon (run as any domain user)
Invoke-ADRecon

# Against specific DC with explicit creds
Invoke-ADRecon -DomainController dc01.target.com -Credential (Get-Credential)

# Specific modules only (faster)
Invoke-ADRecon -Collect "Users,Computers,Groups,GPOs,ACLs"

# Output formats
Invoke-ADRecon -OutputType EXCEL    # Excel workbook (default)
Invoke-ADRecon -OutputType CSV      # CSV files per object type
Invoke-ADRecon -OutputType JSON     # JSON

# Output directory
Invoke-ADRecon -OutputDir C:\temp\adrecon-output\
```

### What ADRecon Collects

```powershell
# Available collection modules:
# Forest          — forest-wide info
# Domain          — domain configuration
# Trusts          — trust relationships
# Sites           — AD sites and subnets
# Subnets         — IP subnets
# PasswordPolicy  — password policies (default + fine-grained)
# DCs             — domain controller details
# Users           — all user accounts + attributes
# UserSPNs        — Kerberoastable accounts
# PasswordAttr    — password attributes per account
# Groups          — security and distribution groups
# GroupMembers    — membership for all groups
# OUs             — organizational unit structure
# ACLs            — access control lists
# GPOs            — Group Policy Objects
# gPLinks         — GPO links to OUs
# Computers       — computer accounts
# ComputerSPNs    — SPNs on computer accounts
# LAPS            — LAPS deployment status
# BitLocker       — BitLocker recovery key presence
# DNSZones        — DNS zones
# Printers        — network printers
```

### Analyzing the Output

```powershell
# High-value sheets in the Excel workbook:
# "UserSPNs" → Kerberoastable accounts
# "Users" filtered by AdminCount=1 → privileged account orphans
# "Computers" filtered by LastLogon > 90 days → stale machines
# "ACLs" → delegation and rights anomalies
# "PasswordPolicy" → weak policy configurations
# "LAPS" → which machines lack LAPS (shared local admin passwords)
```

## adidnsdump — DNS Zone Dumping via LDAP

Active Directory DNS zones are stored in AD itself — meaning any authenticated user can query all DNS records via LDAP, not just via DNS. `adidnsdump` extracts all DNS records from AD using LDAP, often revealing internal infrastructure invisible to external recon.

### Installation

```bash
pip3 install adidnsdump
# or
git clone https://github.com/dirkjanm/adidnsdump
pip3 install -r requirements.txt
```

### Usage

```bash
# Dump all DNS records from the domain
adidnsdump -u 'DOMAIN\user' -p 'password' dc01.domain.com

# Output to CSV
adidnsdump -u 'DOMAIN\user' -p 'password' dc01.domain.com -r -o dns.csv

# Using NTLM hash (pass-the-hash)
adidnsdump -u 'DOMAIN\user' --hashes :NTLM_HASH dc01.domain.com

# Resolve CNAMEs and wildcards
adidnsdump -u 'DOMAIN\user' -p 'password' dc01.domain.com -r

# Target specific zone
adidnsdump -u 'DOMAIN\user' -p 'password' dc01.domain.com --zone internal.domain.com
```

### What DNS Records Reveal

```bash
# After dump, analyze for:

# Web servers and apps
grep -i "web\|www\|http\|portal\|intranet" records.csv

# Management interfaces
grep -i "mgmt\|manage\|admin\|console\|vcenter\|idrac\|ilo\|bmc" records.csv

# Developer infrastructure
grep -i "dev\|staging\|test\|qa\|build\|jenkins\|gitlab\|jira" records.csv

# Database servers
grep -i "db\|sql\|oracle\|postgres\|mongo\|redis" records.csv

# Security tools
grep -i "siem\|splunk\|qualys\|nessus\|tenable\|rapid7" records.csv

# VPN and remote access
grep -i "vpn\|remote\|citrix\|rdg\|rdweb" records.csv
```

## Scavenger — Cross-Domain Privilege Discovery

Scavenger focuses on finding cross-domain privilege escalation paths. In multi-domain forests, accounts from one domain often have privileges in another — Scavenger maps these to identify lateral movement paths across trust boundaries.

### Installation

```bash
git clone https://github.com/0xNinjaCyclone/Scavenger
pip3 install -r requirements.txt
```

### Usage

```bash
# Enumerate cross-domain ACLs and admin rights
python3 scavenger.py -d target.com -u user -p password

# Target specific domain from another domain context
python3 scavenger.py -d target.com -u OTHERDOMAIN\user -p password --dc dc01.target.com

# Find foreign security principals (accounts from other domains with local rights)
python3 scavenger.py -d target.com -u user -p password --foreign-principals

# Enumerate group membership across trusts
python3 scavenger.py -d target.com -u user -p password --cross-domain-groups
```

## linWinPwn — Automated AD Exploitation (Linux-Based)

linWinPwn is a bash script wrapping BloodHound, CrackMapExec, Impacket, Kerbrute, and other tools into an automated AD enumeration pipeline. It runs from a Linux attacker box using only domain credentials.

### Installation

```bash
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn
chmod +x linWinPwn.sh
./install.sh  # installs all dependencies
```

### Usage

```bash
# Full automated enumeration
./linWinPwn.sh -t dc01.target.com -d target.com -u user -p 'P@ssw0rd'

# Using NTLM hash
./linWinPwn.sh -t dc01.target.com -d target.com -u user -H :NTLM_HASH

# Specific modules
./linWinPwn.sh -t dc01.target.com -d target.com -u user -p pass \
  -M kerberoast,asreproast,bloodhound,shares

# Output directory
./linWinPwn.sh -t dc01.target.com -d target.com -u user -p pass -o /tmp/results/
```

### linWinPwn Module Coverage

```bash
# Automated modules include:
# - BloodHound data collection (SharpHound via Impacket)
# - Kerberoasting (GetUserSPNs.py)
# - AS-REP roasting (GetNPUsers.py)
# - Password policy enumeration
# - SMB share enumeration and access checking
# - IPv6 DNS takeover check
# - ADCS (certificate services) enumeration
# - LDAP signing/binding checks
# - Domain trust mapping
# - LAPS reading (if accessible)
# - GPP password finding
# - Printer enumeration (PrintNightmare checks)
```

## Recommended AD Assessment Workflow

```
Phase 1 — Unauthenticated
├── Enumerate domain from DNS (adidnsdump with any domain user)
├── Check LDAP null binds
└── SMB signing status (crackmapexec smb cidr --gen-relay-list)

Phase 2 — Low-Privilege Authenticated
├── PingCastle --healthcheck         → risk overview, attack surface
├── ADRecon (full collection)        → complete environment dump
├── adidnsdump                       → all DNS records → map infrastructure
├── linWinPwn (automated)           → Kerberoast, ASREP, BloodHound
└── Scavenger (if multi-domain)     → cross-domain privilege paths

Phase 3 — Targeted Exploitation
├── BloodHound analysis             → shortest path to DA
├── Kerberoast targeted accounts    → crack service account hashes
├── ADCS exploitation (Certify)     → certificate-based privilege escalation
└── ACL abuse (PowerView)           → GenericWrite/WriteDACL attacks
```
