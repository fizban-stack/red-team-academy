---
layout: training-page
title: "Azure AD Reconnaissance — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - reconnaissance
  - aad-internals
  - roadtools
  - graph-api
  - entra-id
page_key: "ad-azure-recon"
render_with_liquid: false
---

# Azure AD Reconnaissance

Azure AD reconnaissance maps the tenant's attack surface: users, groups, roles, service principals, conditional access policies, application registrations, and external exposure. The primary tools are AADInternals (PowerShell), ROADtools (Python), and direct Microsoft Graph API calls.

## Tenant Discovery (Unauthenticated)

Before obtaining credentials, you can identify tenant information and enumerate external-facing details.

```bash
# Identify tenant ID, federation type, and authentication endpoints
curl "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration"

# Check if domain is federated (on-prem AD → Azure AD sync)
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@victim.com&json=1"

# Enumerate tenant via AADInternals (unauthenticated)
Import-Module .\AADInternals.ps1
Invoke-AADIntReconAsOutsider -DomainName "victim.com" | Format-Table

# Output includes:
# TenantId, Tenant Name, Domains, Federation type
# MDI tenant info, Hybrid join status, Conditional Access hints
```

### Check MX, SPF, DMARC for Mail Infrastructure Recon

```bash
# MX record → mail provider (Exchange Online vs on-prem)
nslookup -type=MX victim.com

# Check for autodiscover (Exchange Online indicator)
nslookup autodiscover.victim.com

# SPF includes indicate cloud services in use
dig TXT victim.com | grep "v=spf1"
```

---

## AADInternals — Authenticated Enumeration

AADInternals is the most comprehensive PowerShell module for Azure AD offensive operations.

### Installation and Authentication

```
# Install from PowerShell Gallery
Install-Module AADInternals -Force

# Or import locally
Import-Module .\AADInternals.ps1

# Authenticate — multiple methods
# Interactive browser login
$token = Get-AADIntAccessTokenForAADGraph

# With credentials
$creds = Get-Credential
$token = Get-AADIntAccessTokenForAADGraph -Credentials $creds

# With existing refresh token
$token = Get-AADIntAccessTokenForAADGraph -RefreshToken "<token>"

# Set the token for subsequent operations
$token | Set-AADIntToken
```

### User and Group Enumeration

```
# List all users in the tenant
Get-AADIntUsers | Select UserPrincipalName, DisplayName, JobTitle, Department

# Get specific user details
Get-AADIntUser -UserPrincipalName "admin@victim.com"

# List all groups
Get-AADIntGroups | Select DisplayName, Id, SecurityEnabled

# Get members of a specific group
Get-AADIntGroupMembers -GroupId "<group-id>"

# List all admin role members (Global Admin, etc.)
Get-AADIntAdminRoles | Format-Table

# Get specific role members
Get-AADIntMSGraphRoleMembers -RoleName "Global Administrator"
```

### Application and Service Principal Enumeration

```
# List all app registrations in the tenant
Get-AADIntApplications | Select DisplayName, AppId, ReplyUrls

# List all service principals
Get-AADIntServicePrincipals | Select DisplayName, AppId, ServicePrincipalType

# Get OAuth2 permission grants (who granted what to which app)
Get-AADIntOAuth2PermissionGrants | Select ClientId, Scope, PrincipalId

# Identify apps with high-risk delegated permissions
Get-AADIntOAuth2PermissionGrants | Where-Object { $_.Scope -match "Mail|Directory|RoleManagement" }
```

### Conditional Access Policy Enumeration

```
# List all conditional access policies
Get-AADIntConditionalAccessPolicies | Select DisplayName, State, Conditions

# Export full policy objects
Get-AADIntConditionalAccessPolicies | ConvertTo-Json -Depth 10 | Out-File ca_policies.json

# Identify policies that exclude certain users/groups (attack opportunity)
Get-AADIntConditionalAccessPolicies | Where-Object {
    $_.Conditions.Users.ExcludeUsers -ne $null -or
    $_.Conditions.Users.ExcludeGroups -ne $null
}
```

### Password Hash Sync and Hybrid Configuration

```
# Check if Password Hash Sync is enabled (critical for cross-prem attacks)
Get-AADIntSyncConfiguration

# Get Azure AD Connect server details
Get-AADIntAADConnectStatus

# Check if Pass-through Authentication is in use
Get-AADIntPassThroughAuthenticationAgents
```

---

## ROADtools — Tenant Graph Exploration

ROADtools (Research Office Automated Discovery) provides a complete dump of the Azure AD tenant into a SQLite database, queryable via CLI or a web interface.

### Installation

```bash
pip install roadtools

# Authenticate and gather all tenant data
roadrecon auth -u user@victim.com -p 'password'

# Or with device code flow
roadrecon auth --device-code

# Or with existing token
roadrecon auth --access-token <token>
```

### Gathering All Tenant Data

```bash
# Gather all available tenant data (users, groups, roles, apps, policies, etc.)
roadrecon gather --all

# Gather with specific scopes
roadrecon gather --users --groups --applications --servicePrincipals

# Output: roadrecon.db (SQLite database)
```

### Querying the Database

```bash
# Launch the ROADweb GUI (browser-based exploration)
roadweb

# Or query directly via SQL
sqlite3 roadrecon.db "SELECT userPrincipalName, displayName FROM users WHERE accountEnabled=1"

# Find users with admin roles
sqlite3 roadrecon.db "SELECT u.userPrincipalName, r.displayName FROM users u 
JOIN rolememberships rm ON u.objectId=rm.memberId 
JOIN roles r ON rm.roleId=r.objectId"
```

---

## Microsoft Graph API Enumeration

Graph API is the unified REST interface for all Microsoft 365 and Azure AD data. Direct API calls provide granular control over what's enumerated.

### Token Acquisition for Graph API

```
# Via AADInternals
Import-Module .\AADInternals.ps1
$token = Get-AADIntAccessTokenForMSGraph

# Via Az PowerShell module
Connect-AzAccount
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token

# Via MSAL Python
import msal
app = msal.PublicClientApplication(client_id="<app_id>", authority="https://login.microsoftonline.com/<tenant>")
result = app.acquire_token_by_username_password("user@victim.com", "Password123", 
         scopes=["https://graph.microsoft.com/.default"])
token = result["access_token"]
```

### Key Graph API Endpoints

```bash
BASE="https://graph.microsoft.com/v1.0"
TOKEN="<access_token>"
H="Authorization: Bearer $TOKEN"

# All users
curl -H "$H" "$BASE/users" | jq '.value[].userPrincipalName'

# All groups
curl -H "$H" "$BASE/groups" | jq '.value[].displayName'

# Directory roles (admin roles)
curl -H "$H" "$BASE/directoryRoles" | jq '.value[].displayName'

# Global Admin members
curl -H "$H" "$BASE/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members"

# All applications
curl -H "$H" "$BASE/applications" | jq '.value[] | {displayName, appId}'

# All service principals
curl -H "$H" "$BASE/servicePrincipals" | jq '.value[] | {displayName, appId, servicePrincipalType}'

# OAuth2 permission grants (consent grants)
curl -H "$H" "$BASE/oauth2PermissionGrants" | jq '.value[] | {clientId, scope, principalId}'

# App role assignments (application permissions)
curl -H "$H" "$BASE/servicePrincipals/<sp-id>/appRoleAssignments"

# Tenant organization info
curl -H "$H" "$BASE/organization" | jq '.value[] | {displayName, tenantType, verifiedDomains}'

# Conditional access policies
curl -H "$H" "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

### Finding High-Value Targets

```bash
# Find users with privileged roles via beta endpoint
curl -H "$H" "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition" \
    | jq '.value[] | {role: .roleDefinition.displayName, user: .principal.userPrincipalName}'

# Find service principals with dangerous app roles
curl -H "$H" "$BASE/servicePrincipals" | jq '.value[] | select(.appRoles[]?.value? | 
    test("RoleManagement|Directory.ReadWrite|AppRoleAssignment"))'

# List apps with credential secrets (certificate or password)
curl -H "$H" "$BASE/applications" | jq '.value[] | select(.passwordCredentials | length > 0) | 
    {displayName, appId, secretExpiry: .passwordCredentials[].endDateTime}'
```

### OPSEC Considerations

Graph API calls generate entries in Azure AD audit logs. To reduce detection:

- Use **read-only** operations (GET requests) — avoid writes during recon
- Use **existing legitimate tokens** rather than creating new app registrations
- Spread enumeration over time — bulk queries appear as anomalies
- Use a service principal with limited but legitimate scope rather than a Global Admin account
- Prefer `select` parameters to limit returned fields (reduces log verbosity)

```bash
# Selective fields reduce data transfer and log footprint
curl -H "$H" "$BASE/users?\$select=userPrincipalName,jobTitle,department&\$top=10"
```

---

## On-Prem Enumeration (PowerView for Hybrid Context)

In hybrid environments, on-prem AD recon feeds into cloud attack paths. Users synced to Azure AD retain their on-prem attributes.

```powershell
# Load PowerView
Import-Module .\PowerView.ps1

# Find all users synced to Azure AD (ImmutableId is set)
Get-DomainUser -Filter {ImmutableId -ne $null} | Select Name, SamAccountName

# Find Azure AD Connect service account
Get-DomainUser -Filter {SamAccountName -like "MSOL_*"} | Select Name, Description

# Find users with adminCount=1 (protected accounts)
Get-DomainUser -AdminCount | Select Name, SamAccountName

# Enumerate AD Connect configuration to find sync scope
Get-ADSyncServerConfiguration
```

---

## Azure Portal Reconnaissance

The Azure portal itself reveals information accessible to any authenticated user with Guest or Member access.

```
# Check your own permissions
curl -H "Authorization: Bearer <token>" https://graph.microsoft.com/v1.0/me/memberOf

# List all resource groups accessible with current token
az group list --query "[].{name:name, location:location}" -o table

# List all subscriptions
az account list --query "[].{name:name, id:id, state:state}" -o table

# List all VMs
az vm list --query "[].{name:name, resourceGroup:resourceGroup, location:location}" -o table

# List all Key Vaults
az keyvault list --query "[].{name:name, resourceGroup:resourceGroup}" -o table

# List storage accounts
az storage account list --query "[].{name:name, resourceGroup:resourceGroup}" -o table
```

---

## Detection and OPSEC

| Enumeration Activity | Log Source | Event/Indicator |
|---------------------|------------|-----------------|
| AADInternals auth | Azure AD Sign-in Logs | App: "AADInternals", unusual service principal |
| Graph API bulk queries | Azure AD Audit Logs | ListUsers, ListGroups operations in short window |
| CA policy read | Azure AD Audit Logs | "Read conditional access policies" |
| roadrecon gather | Azure AD Audit Logs | High-volume read activity |
| Unauthenticated recon | None (public endpoints) | No logging available |

```
// KQL: Detect bulk Graph API enumeration
AuditLogs
| where OperationName in ("List users", "List groups", "List service principals")
| summarize OpCount = count() by InitiatedBy.app.displayName, bin(TimeGenerated, 5m)
| where OpCount > 20
```

## Resources

- AADInternals — `github.com/Gerenios/AADInternals`
- ROADtools — `github.com/dirkjanm/ROADtools`
- Microsoft Graph Explorer — `developer.microsoft.com/en-us/graph/graph-explorer`
- Graph API documentation — `learn.microsoft.com/en-us/graph/overview`
- PowerView — `github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1`
