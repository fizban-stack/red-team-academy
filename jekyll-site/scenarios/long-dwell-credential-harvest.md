---
layout: training-page
title: "Long-Dwell Credential Harvesting — Red Team Academy"
module: "Scenarios"
tags:
  - scenario
  - long-dwell
  - credential-access
  - patience
  - low-and-slow
  - state-aligned
page_key: "scenarios-long-dwell-credential-harvest"
render_with_liquid: false
---

# Long-Dwell Credential Harvesting

## Scenario Overview

This scenario emulates a year-long, low-volume credential harvesting campaign against a fictional mid-sized professional services firm. The objective is durable strategic intelligence collection — not a smash-and-grab. The operator's success metric is "still inside next year," not "popped the DA in six hours." Beacon intervals are measured in days. Whole weeks pass with no operator action at all. The defender debrief at the end of this scenario is the entire point.

This is the cadence of the breaches the public never reads about for two years. Adobe 2013 sat for an estimated three months before public disclosure; the Okta customer-support breach of September 2023 went unnoticed inside Okta for roughly two weeks of active access and was only surfaced when BeyondTrust independently flagged anomalous activity in their own tenant. SolarWinds — the canonical reference — held attacker access for an estimated nine months before FireEye discovered it, and even then the discovery was incidental to a separate forensic investigation. The Storm-0558 Microsoft corporate-email intrusion in 2023 ran for approximately a month against State Department mailboxes before a customer's billing-log anomaly tipped Microsoft. The pattern is consistent: well-disciplined operators do not get caught by SOC analysts; they get caught by accident.

Run this scenario as a 52-week simulated engagement. Operators must respect a hard per-week action budget. Defenders run their normal detection content the entire time — and at week 52, both teams walk through what fired, what should have fired, and what could not fire given the tooling deployed.

---

## Threat Actor Profile — Composite "Patient North"

Patient North is a composite of state-aligned long-dwell operators. The composite captures the shared operational discipline rather than any single group's exact toolset.

**Attribution:** Composite of APT29 (SVR, Russia), Hafnium (MSS, China), APT41 (espionage tasking), and APT10 (MSS contractor groups). All four have documented dwell times exceeding twelve months in publicly reported intrusions.

**Primary motivation:** Strategic intelligence collection. The target is not data the operator can monetize this quarter — it is data the operator's tasking customer will use over a multi-year horizon. Deal terms, client portfolios, communications, travel patterns, advisor relationships.

**Active since:** 2008 onward for the APT29 lineage; 2009 onward for APT10; 2017+ for Hafnium as publicly named. Long-dwell campaigns have been a continuous part of the state-aligned threat landscape for at least fifteen years.

### Known TTPs (composite from public reporting)

| Category | Documented Technique |
| --- | --- |
| Reconnaissance | LinkedIn employee mapping (T1589.003), public records of client engagements, conference attendee lists, court filings naming the firm |
| Initial Access | Spearphishing with a long-lead pretext (T1566.001), password spraying against externally-exposed services (T1110.003), supply chain via a small vendor (T1195.002) |
| Persistence | OAuth app consent with long-lived refresh tokens (T1098.003), scheduled task at user-context level (T1053.005), legitimate-looking registry run key on a single host (T1547.001) |
| Defense Evasion | Beacon sleep measured in hours-to-days (T1029), legitimate cloud service C2 (T1102), in-memory execution only (T1620), no persistent disk tooling on endpoints |
| Credential Access | Browser credential extraction (T1555.003), DPAPI vault decryption on logged-in user (T1555.004), Kerberoasting of single SPN per week (T1558.003) |
| Discovery | Slow, scoped LDAP queries (T1087.002), one share enumeration per session (T1135), email rules to surface deal-related threads (T1564.008) |
| Lateral Movement | One hop per multi-week cycle (T1021), valid accounts only (T1078) |
| Collection | Email collection scoped to specific senders/dates (T1114.002), document collection scoped to keywords matching the tasking (T1119) |
| Command & Control | C2 over legitimate cloud APIs (T1102.002), domain fronting (T1090.004), encrypted channel (T1573) |
| Exfiltration | Exfiltration over the user's own cloud sync (T1567), chunked over weeks (T1030), scheduled transfer (T1029) |

### Operational Characteristics

Patient North is defined by what the operator does not do as much as by what the operator does. The discipline is the tradecraft.

- **Hard per-week action budget.** Operators agree in advance that no more than N discrete actions on objective will occur in any rolling seven-day window. N is small — three to five. Periods of two-to-four weeks with zero actions are normal and expected.
- **Beacon sleep measured in hours-to-days.** Initial beacon: six-hour sleep with twenty-percent jitter. After steady state: twenty-four-hour sleep with thirty-percent jitter. After confidence: seventy-two-hour sleep. This means a beacon may be unreachable for ninety hours by design.
- **Cover activity matches the compromised user.** Operator actions happen during the user's working hours, from a residential proxy in the user's metro, with user-agent strings matching the user's actual browser. Out-of-hours actions are forbidden unless the user themselves works odd hours — and that pattern must be confirmed first.
- **No persistent disk tooling on endpoints.** Everything is in-memory, sourced from BOFs (Beacon Object Files), reflective loaders, or living-off-the-land binaries. The compromised endpoint should be forensically clean within minutes of any action.
- **Credential collection is consumable, not bulk.** Operators take the one credential they need this week, not every credential they can see. A full LSASS dump leaves a forensic trail; a single targeted Kerberoast of a single SPN does not.
- **Cloud telemetry is the C2 substrate, not a tunnel through it.** Operator traffic is structured to look like a legitimate enterprise app calling a legitimate cloud API. The point is not to hide inside encrypted traffic — it is to be indistinguishable from normal SaaS chatter.
- **Anti-forensics is continuous, not periodic.** Operators clean as they go. There is no "cleanup phase" at the end of an engagement because there are no artifacts left to clean by then.

The cumulative effect is that no single action is detectable. Detection has to come from time-series anomaly analysis over months — and very few defenders are tuned for that.

---

## Target Profile — Meridian Strategy Group

**Organization:** Meridian Strategy Group (fictional)
**Industry:** Professional services — management consulting, M&A advisory, regulatory strategy
**Headcount:** ~600 employees plus ~200 contractors, two US offices (DC HQ, NYC), small London satellite
**Crown jewels:**

- Client engagement documents (final reports, working papers, client-confidential financial models)
- Internal Slack channels containing real-time deal-flow chatter between partners
- Contractor timesheet system, which inadvertently reveals every client engagement Meridian holds and how many billable hours flow into each — a complete portfolio map updated weekly
- The CEO's and managing partners' inboxes — calendar invites alone disclose which regulators, government officials, and counterparty executives Meridian engages with

**Why targeted:** Meridian advises on cross-border regulatory matters touching technology export controls. The tasking customer wants a continuous read on which clients Meridian is helping, what advice those clients are receiving, and which government touchpoints are involved.

### Technology Stack

| Layer | Technology |
| --- | --- |
| Identity | Microsoft Entra ID (Azure AD) primary, on-prem AD for legacy file shares only, no third-party IdP |
| Email | Exchange Online (M365 E3) with Defender for Office 365 Plan 1 |
| Endpoints | Windows 11 corporate-managed via Intune, Microsoft Defender for Endpoint (P1) |
| Collaboration | Slack Enterprise Grid, SharePoint Online, OneDrive for Business |
| Code & engineering | Not a major surface — limited GitHub usage, internal R\&D in a separate small tenant |
| Operational systems | Salesforce for CRM, a custom-built timesheet app on Azure App Service, NetSuite for finance |
| Network | Cisco Meraki at offices, Cloudflare WARP for remote workers, no traditional VPN |
| Monitoring | Microsoft Sentinel ingesting Entra sign-in logs, Defender for Endpoint, Defender for O365, partial Slack audit logs (Enterprise Grid tier), AWS CloudTrail for the App Service backend |

### Security Maturity

Mid-tier corporate — better than most firms of this size, weaker than a bank.

- MFA enforced on Entra ID for all users, including contractors. Push notifications via Microsoft Authenticator; no FIDO2 keys deployed.
- Conditional access policies require compliant device for M365 — but the policy has a known gap for OAuth-app token use, which the security team is aware of and has on the roadmap.
- Defender for Endpoint deployed to all corporate Windows 11 hosts. Macs (mostly contractor BYOD) are out of scope.
- A four-person security team — one CISO-equivalent, two SOC analysts on day-shift only, one identity engineer. After-hours coverage is provided by a contracted MSSP that watches Sentinel critical and high alerts and pages on-call.
- No dedicated threat hunting program. Detection content is mostly out-of-box Microsoft analytics rules with a handful of custom KQL queries for known business risks.

Meridian is not a hard target. Patient North is overkill for the access portion. The discipline is in what Patient North does after access — staying invisible for fifty weeks, not in getting in.

---

## Phase Structure — 52 Weeks

The campaign is organized into eight phases spanning a simulated year. Phase boundaries are not crisp; activity overlaps. Time is the dominant resource.

### Phase 1 — Initial Access (week 1–2)

**ATT&CK Tactic:** Initial Access (TA0001), Reconnaissance (TA0043)
**Techniques:** Phishing for Information (T1598), Spearphishing Attachment (T1566.001), Valid Accounts (T1078.004)

#### What the operator does

The operator picks a single mid-tier target: a senior associate on the regulatory strategy team. Not a partner — partners receive too much defender attention. The senior associate has access to the same systems, more time in front of the keyboard, and less email-security white-glove treatment.

Reconnaissance was completed in the four weeks before week 1. The operator already knows the target's name, role, current client engagements (from LinkedIn project bullets), recent conference attendance, and the writing voice of the target's most frequent external counterparty (a partner at an outside law firm).

The lure is a single email impersonating that external counterparty. The pretext is a follow-up to a real meeting the two had three weeks earlier. The attachment is a password-protected ZIP containing a Windows shortcut (`.lnk`) and a decoy PDF. The shortcut runs PowerShell that fetches a small in-memory loader from an Azure Blob Storage URL. The loader establishes the first beacon. There is no second-stage payload on disk.

#### What the defender should see

- Defender for O365 may flag the password-protected ZIP as suspicious — depends on the tenant's Safe Attachments configuration.
- Defender for Endpoint may flag the PowerShell invocation if AMSI is engaged and the loader is not adequately obfuscated.
- Entra ID sign-in logs will show the user's session as normal (no impossible-travel anomaly because the operator is on a residential proxy in the user's metro).

#### What the defender will almost certainly miss

- The Azure Blob Storage URL. To Sentinel, it looks like Outlook telemetry. To Defender for Endpoint, it looks like a legitimate Microsoft cloud endpoint.
- The relationship between the inbound email's "from" domain and a domain registered eleven days earlier. Most orgs do not have domain-age enrichment on inbound mail.

---

### Phase 2 — Dormancy (week 2–6)

**ATT&CK Tactic:** Defense Evasion (TA0005), Discovery (TA0007)
**Techniques:** Application Layer Protocol (T1071), Scheduled Transfer (T1029)

#### What the operator does

For four weeks, the operator does nothing on objective. The beacon checks in every six hours, jitter twenty percent. No commands. No file access. No screenshots. No process listing. The beacon's only job is to confirm it still has connectivity and that the host is still online.

The operator uses this period to confirm the implant survives reboot, weekend power-off, patch cycles, and any host-level investigation that might be triggered by Phase 1 noise. If Defender for Endpoint had something to say about the loader, it would have said it by week 4. Silence at week 4 means the access is durable.

#### What the defender should see

- A new outbound HTTPS pattern from the user's workstation to a CDN-fronted endpoint, repeating every six hours with light jitter. To behavioral analytics this is indistinguishable from any modern SaaS desktop client.
- No process anomalies, because the loader injected into a long-running legitimate process during Phase 1 and that process is now its host.

#### What the defender will almost certainly miss

Everything. A beacon that does nothing is the hardest single thing to detect in modern environments. There is no behavior to flag.

---

### Phase 3 — Low-Touch Enumeration (week 6–12)

**ATT&CK Tactic:** Discovery (TA0007)
**Techniques:** Account Discovery (T1087), Domain Trust Discovery (T1482), File and Directory Discovery (T1083), Cloud Service Discovery (T1526)

#### What the operator does

The operator begins building a target map — slowly. The rule of thumb is one discovery action per session, no more than three sessions per week. A "session" is a beacon callback in which the operator queues exactly one command for the beacon to execute on its next wake.

Activities in this phase include:

- One `whoami /all` to enumerate the user's group memberships and privileges.
- One small LDAP query per week against the on-prem AD to identify the user's OU, the local domain controllers, and the basic forest layout. The query is scoped tightly: ten or fewer attributes, one OU at a time.
- One enumeration of mapped drives and shares the user already has open. No `net view /domain` — too noisy.
- Identification of the user's Slack workspace, M365 tenant, SharePoint sites, and any browser-stored credentials via SharpChrome run inline through the beacon.
- Identification of the user's calendar — specifically, recurring meetings that reveal who the user works with daily.

The total volume of operator actions in this six-week phase is on the order of twenty commands. Twenty.

#### What the defender should see

- Sentinel may show a slight uptick in LDAP query volume from this user's workstation. Without baselining, it is invisible.
- Defender for Endpoint will not flag `whoami` — it is a legitimate command run by every IT person daily.
- Browser credential access from a non-browser process is the one signal that may fire. APT29-style operators use BOFs that read the SQLite database directly via Windows API rather than launching a separate process — this avoids the parent/child process-tree signal that endpoint security relies on.

#### What the defender will almost certainly miss

The shape of the activity. Detection content tuned to "five LDAP queries in five minutes" cannot see "five LDAP queries in five weeks." The signal-to-noise ratio on time-distributed reconnaissance is approximately zero with off-the-shelf SIEM content.

---

### Phase 4 — First Credential Collection (week 12–20)

**ATT&CK Tactic:** Credential Access (TA0006)
**Techniques:** Credentials from Web Browsers (T1555.003), Credentials from Password Stores (T1555), Kerberoasting (T1558.003), Steal Application Access Token (T1528)

#### What the operator does

Eight weeks of enumeration revealed where the credentials live. Now the operator collects them — one at a time, scoped to immediately consumable.

Specific actions in this phase:

- Browser credential extraction via in-process API calls. The operator collects the senior associate's saved passwords for Salesforce, the internal timesheet portal, and a third-party regulatory news site the firm subscribes to.
- DPAPI vault decryption against the logged-in user's master key to recover credentials the user "forgot" but the OS remembers.
- One Kerberoast per fortnight against a single Service Principal Name. The SPN is chosen specifically: a low-privilege service account that the operator's reconnaissance has shown is not actively monitored. The hash is exfiltrated and cracked offline. Most service accounts at Meridian have rotated weak passwords; about thirty percent crack within a week.
- An OAuth consent grant established mid-phase — a malicious app registered in a third-party Entra tenant, with a phishing email asking the user to "authenticate to the shared client deal-room." The user clicks once; the operator gets `Mail.Read` and `Files.Read.All` on a refresh token that survives password changes.

The OAuth grant is the most valuable single artifact the operator obtains in the entire campaign. It is portable, persistent through rotation, and invisible to endpoint security because it lives entirely in Microsoft's cloud.

#### What the defender should see

- Defender for Cloud Apps "Unusual OAuth app consent" may fire on the consent grant. Whether it is triaged depends on the analyst's queue.
- Sentinel may show a Kerberoast detection if the rule is deployed. The default rule looks for high-volume ticket requests; a single ticket request per fortnight will not trip it.
- Browser credential access via direct API calls is invisible without specific detection content — and Defender for Endpoint's default rules focus on process-spawn patterns, not in-process API calls.

#### What the defender will almost certainly miss

- The OAuth consent. Mid-market firms triage Sentinel critical-and-above. "Unusual OAuth app consent" lands as medium. With 150 medium alerts per week in a four-person team's queue, the median time-to-triage is "next week."
- The targeted Kerberoast. Time-distributed Kerberoasting is a known detection gap that has been written about extensively but is structurally hard to fix in product.

---

### Phase 5 — Validation and Quiet Escalation (week 20–32)

**ATT&CK Tactic:** Privilege Escalation (TA0004), Persistence (TA0003)
**Techniques:** Valid Accounts (T1078), Account Manipulation (T1098), Additional Cloud Roles (T1098.003)

#### What the operator does

The cracked service-account password from Phase 4 is validated against the on-prem AD. The operator authenticates from the compromised endpoint — the source machine is the same one the legitimate service typically runs from, so the sign-in does not trip impossible-travel or new-device detections.

The service account has read access to a SharePoint site that aggregates working papers across all active engagements. The operator does nothing with that access for two weeks. The point of the validation is to confirm the credential works without burning it.

Then the operator uses the OAuth refresh token in parallel. Mail.Read against the senior associate's mailbox returns three months of email — but the operator does not download three months of email. The operator runs a Graph query for messages where the subject contains specific deal codenames identified from Phase 3 calendar enumeration. Twenty-eight messages are returned. The operator downloads those twenty-eight, nothing more.

Escalation in this phase is gentle. The operator does not attempt to become Domain Admin. The operator establishes one additional foothold — a second user on the M&A team — by sending an internal-looking lure from the first compromised account. The new account is a clone, not an escalation. If the first account is burned, the second survives.

#### What the defender should see

- A second-factor prompt on the second user that the second user may report as suspicious — depends on whether the lure is convincing enough that the user clicks through without questioning.
- Graph API access patterns from the OAuth refresh token. To Sentinel this is an authenticated app reading mail; without app-allowlist policy, it is normal-looking traffic.

#### What the defender will almost certainly miss

- The lateral foothold. Defenders typically detect lateral movement by network signal (SMB, RDP, WinRM). Lateral movement via "send a convincing email from the first account to the second user" leaves no network signal at all.
- The deliberate restraint. Defenders are trained to look for spikes. A campaign that has no spikes leaves no canonical artifacts.

---

### Phase 6 — Email and Document Collection Pivot (week 32–44)

**ATT&CK Tactic:** Collection (TA0009)
**Techniques:** Email Collection (T1114), Data from Information Repositories (T1213), Data from Cloud Storage (T1530)

#### What the operator does

This is the harvest phase. The operator has two valid user contexts, an OAuth refresh token, a cracked service-account credential, and a complete picture of where the documents live. Now the operator collects.

Collection is structured to look like normal user behavior:

- Email collection happens during the compromised user's working hours, scoped to specific senders, date ranges, and keywords. No bulk export.
- SharePoint document downloads happen one document at a time, with realistic browse-and-read intervals between them. The operator scripts the download cadence to match the user's historical pattern (which was learned in Phase 3 by observing the user's actual telemetry).
- Slack collection is the hardest part. The operator uses the senior associate's session token (extracted via the malicious OAuth app's `Files.Read.All` scope, which on M365 also exposes Slack data when Slack is provisioned through Entra). The operator pulls the contents of three specific channels — the M&A partners' channel, the regulatory strategy channel, and a small private channel that the operator's tasking customer specifically wants.

Total exfiltration volume in this phase is on the order of two gigabytes across twelve weeks. About 170 megabytes per week. Less than the user's normal weekly OneDrive sync delta.

#### What the defender should see

- Sentinel may produce a "large mailbox download" alert if Graph API call volume exceeds a threshold. The operator stays well below threshold by design.
- Defender for Cloud Apps may produce a "mass download" alert. Same problem — threshold tuned for noisy attackers.
- Slack audit logs (Enterprise Grid tier) will show the API access. Whether anyone reads Slack audit logs is the question. At most mid-market firms the answer is no.

#### What the defender will almost certainly miss

The systematic, time-distributed shape of the collection. The aggregated picture — two gigabytes from one user over twelve weeks, with the access pattern matching their actual job description — is normal-looking by every per-event detection.

---

### Phase 7 — Sustained Collection (week 44–52)

**ATT&CK Tactic:** Collection (TA0009), Exfiltration (TA0010)
**Techniques:** Scheduled Transfer (T1029), Exfiltration Over Web Service (T1567)

#### What the operator does

By week 44, the operator has the complete current state of the target's strategic engagements. The remaining eight weeks are about maintaining freshness — keeping the picture current as new engagements come in, new deals close, and new clients sign.

The cadence drops further. The operator collects approximately twenty new documents per week, all keyword-matched to active tasking. New emails are collected weekly from the same three keyword-matched threads. Slack channel deltas are pulled weekly.

The OAuth refresh token is refreshed once before its ninety-day expiry to maintain access into the next year. The operator does not register a new app — that would be a new artifact. The operator simply re-uses the existing app's refresh token via the documented Microsoft refresh flow.

#### What the defender should see

The same per-week pattern as Phase 6. Slightly lower volume. Identical shape. To Sentinel this is now an established baseline — the "anomaly" became the norm twelve weeks ago and any anomaly-detection algorithm has already adjusted to it.

#### What the defender will almost certainly miss

The fact that the baseline itself is the attack. Drift-based anomaly detection cannot detect a slow drift that became the new baseline before any alert fired.

---

### Phase 8 — Detection Avoidance and Cleanup (continuous)

**ATT&CK Tactic:** Defense Evasion (TA0005)
**Techniques:** Indicator Removal (T1070), Account Manipulation (T1098)

#### What the operator does

Cleanup is not a final phase — it is continuous. Throughout the engagement, every session ends with:

- Clearing the PowerShell history file for the session.
- Restoring any modified registry timestamps if the operator touched persistence.
- Confirming that the in-memory implant has not paged anything sensitive to disk.

If the operator's tasking customer indicates the engagement is being wound down — or if defenders begin showing signs of awareness — the cleanup posture changes:

- The malicious OAuth app's refresh tokens are deliberately allowed to expire rather than revoked. Revocation generates an audit-log entry; expiry does not.
- The cloned secondary account's foothold is allowed to lapse via password expiry without renewal.
- The original beacon is sent a `kill` command. The implant unloads itself from memory and exits the host process cleanly.

The point of continuous cleanup is that "cleanup phase" is itself a forensic artifact. APT29-style operators do not have a cleanup phase. There is nothing to clean up because the operator was clean throughout.

---

## Operational Discipline Themes

Beyond the per-phase mechanics, the campaign succeeds or fails on five overarching discipline themes. These are what separate Patient North from the smash-and-grab operators most defenders are trained against.

**Beacon intervals in hours-to-days.** The single most important operational lever. A six-hour sleep means the operator can issue at most four commands per day. A seventy-two-hour sleep means at most two per week. The longer the sleep, the smaller the detection surface. Operators tolerate the inconvenience because the alternative — fast beacons that are detectable — is worse.

**Hard action-budget cap per week.** Operators agree in advance on a numeric cap. For this campaign the cap is five discrete actions per rolling seven-day window across all compromised accounts. The cap is enforced through operator process — daily standups review the week's action count before any new action is authorized.

**Cover activity matching the compromised user.** Every action originates from the user's compromised endpoint or from a residential proxy in the user's metro. Sign-in time matches the user's working hours. User-agent and TLS fingerprint match the user's actual browser. The operator's behavior must be statistically indistinguishable from the user's own behavior.

**Credential collection limited to immediately consumable.** The operator collects credentials when there is a specific consumable target. A full LSASS dump produces dozens of credentials, ninety percent of which the operator will never use — and produces a forensic event that endpoint security will eventually flag. A targeted single-SPN Kerberoast produces one credential, used the same week, with no leftover forensic exposure.

**Living off legitimate cloud telemetry channels.** C2 is not a tunnel through legitimate traffic — it is structured to be legitimate-looking traffic. The operator's HTTPS calls to `graph.microsoft.com` are real Graph API calls. The Azure Blob Storage URLs the loader contacted are real Azure URLs. The point is not to hide; the point is to look identical to a legitimate enterprise app the defender already trusts.

---

## Defender Debrief

This is the section the rest of the scenario exists to set up.

### What instrumentation would have caught this — and when

**Week 6 — the Phase 2 dormancy.** Almost nothing in commercial tooling will catch a beacon that does nothing. The only realistic detection at this stage is JA3/JA4 TLS fingerprinting of outbound HTTPS, combined with first-time-seen analytics. A workstation calling a new CDN endpoint with a never-before-seen JA3 hash, on a regular interval, with no user-driven trigger — that is a hunting query, not an out-of-box alert. Approximately five percent of mid-market firms have this content deployed.

**Week 20 — the Phase 4 OAuth grant.** This is the single highest-confidence detection opportunity in the entire campaign. Defender for Cloud Apps has an out-of-box "Unusual OAuth app consent" alert. It fires. The question is whether anyone reads it. Recommendation: configure an admin-consent workflow that blocks user self-consent for any app requesting `Mail.Read`, `Mail.ReadWrite`, `Files.Read.All`, or any `.All` scope. This blocks Phase 4 entirely and forces the operator into a noisier alternative.

**Week 40 — the Phase 6 collection cadence.** Time-series anomaly detection on per-user Graph API call volume would catch this if baselined per-user over a sufficiently long horizon — but most baselines are tenant-wide and reset every thirty days. A per-user baseline of "API calls per week over the prior twenty-six weeks" would flag the sustained access pattern. Almost no mid-market firm runs this query.

### Why defender ROC tuning is hostile to long-dwell detection

Receiver Operating Characteristic curve tuning — the trade-off between false positives and false negatives — is the structural reason long-dwell campaigns succeed. Defenders tune their detection content to a tolerable false-positive rate. For a four-person SOC handling 150 mediums per week, that rate must be low.

Low false-positive thresholds mean high thresholds for any individual signal. A Kerberoast detection that fires on "twenty ticket requests in five minutes" has a low false-positive rate but also a high false-negative rate — it cannot see one ticket request per fortnight. Lowering the threshold to catch the slow Kerberoast would generate dozens of false positives per day from legitimate service accounts.

The structural answer is to move detection from per-event to time-series. Per-event detection asks "is this one action suspicious?" Time-series detection asks "is the pattern over six months suspicious?" The latter requires a different class of tooling — UEBA platforms, custom KQL queries against thirty-day-plus retention, dedicated threat-hunting time. Most mid-market firms do not have any of these.

### Specific telemetry recommendations

**Entra ID sign-in logs.** Retain at least 365 days. Run a weekly query for per-user OAuth scope-grant changes — any user that granted a new high-privilege scope this week, surfaced as a list.

**Defender for Cloud Apps OAuth alerts.** Configure admin-consent workflow. Tune the "Unusual OAuth app" alert to high severity and route to the on-call queue, not the medium queue.

**Microsoft Graph API call volume per user.** Custom KQL query against Sentinel. Compute per-user weekly call volume; alert on users whose weekly volume exceeds their prior-twenty-six-week mean by more than two standard deviations.

**Service-account ticket-request volume.** Per-account, not aggregate. Alert on any service account whose Kerberos ticket-request volume in the prior 168 hours exceeds the account's prior-eight-week mean by more than two standard deviations.

**Slack audit logs (Enterprise Grid).** Pull every twenty-four hours into Sentinel. Build a query for OAuth-app data access events scoped to a single user across multiple channels in a single session.

**Browser-credential-access events from Defender for Endpoint.** Specifically the `Credential theft via DPAPI` and `Credentials accessed in browser storage` alerts. Route to high-severity regardless of process — including signed Microsoft binaries. APT29-style operators run BOFs in trusted processes specifically to evade parent-process detection.

### Weekly hunt queries

Every week, the SOC should run — by hand if necessary — the following queries.

**Hunt 1: New OAuth app consents granted this week, by app age.** Any newly-registered app receiving any `.All`-scoped permission grant this week is suspicious by default until ruled out.

**Hunt 2: First-time-seen JA3/JA4 hashes on outbound HTTPS from corporate workstations.** Any new TLS fingerprint with a regular periodic callback pattern is investigated.

**Hunt 3: Per-user Graph API call volume drift.** Compute the prior-twenty-six-week mean and standard deviation. Flag any user whose current week exceeds two sigma.

**Hunt 4: Per-service-account Kerberos ticket-request volume drift.** Same statistical approach. Even one cracked-and-used service account will surface if baselined per-account.

**Hunt 5: Email-rule creation events.** Operators frequently create inbox rules to forward or hide email matching specific keywords. Any new rule that forwards externally, deletes on receipt, or marks-as-read on receipt is investigated.

The cumulative effect of these five hunts run weekly is that a long-dwell campaign of this exact shape becomes detectable inside the first sixty days — not because any single alert fires, but because the hunting cadence surfaces the pattern.

---

## Variants

The same operational shape applies to several adjacent target classes. Operators adapt the collection scope; defenders adapt the telemetry priorities.

**Healthcare and pharmaceutical research.** The crown jewels are clinical-trial data, drug-discovery research, and patient registries. Collection focuses on Box, Egnyte, or Veeva Vault rather than SharePoint. The OAuth consent pattern transfers cleanly — Veeva uses Salesforce-backed identity and accepts the same kind of consent phish. Defenders should add specific monitoring for OAuth scopes against Veeva, Box, and Salesforce.

**Defense contractor (cleared environment).** Most cleared work occurs on segregated networks, but the firm's unclassified email and document systems still hold tasking, contract, and personnel data of intelligence value. The campaign shape is identical; the high-value collection target is the contract-bid-and-proposal repository. Defenders should treat any unusual access to bid-related document libraries as critical-priority and route directly to facility security officers, bypassing the normal triage queue.

**Telecommunications carrier.** This variant cross-references the [Salt Typhoon telecom intrusion scenario](/scenarios/telecom-intrusion-salt-typhoon/). Long-dwell credential harvesting is the front half of every Salt Typhoon-style campaign — the credential and lateral-movement work that ultimately enables CALEA-system access. Telco defenders should read this scenario as a prerequisite to the Salt Typhoon walkthrough, and pay particular attention to per-service-account ticket-request baselining inside the OSS/BSS environment.

---

## Resources

- Mandiant SolarWinds / UNC2452 reports — [`mandiant.com/resources/blog/unc2452-merged-into-apt29`](https://www.mandiant.com/resources/blog/unc2452-merged-into-apt29)
- Microsoft Storm-0558 disclosures — [`msrc.microsoft.com/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558`](https://msrc.microsoft.com/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558)
- Microsoft MSTIC NOBELIUM analysis — [`microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset`](https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)
- Adobe 2013 breach post-incident review — public reporting by Krebs on Security and Adobe customer notifications
- Okta October 2023 customer-support breach disclosure — Okta security advisory and BeyondTrust post-incident analysis
- CISA long-dwell campaign advisories — [`cisa.gov/news-events/cybersecurity-advisories`](https://www.cisa.gov/news-events/cybersecurity-advisories)
- FBI/NSA joint advisories on SVR cyber operations — [`media.defense.gov`](https://media.defense.gov/) advisory archive
- APT29 ATT&CK group page — [`attack.mitre.org/groups/G0016`](https://attack.mitre.org/groups/G0016/)
- Hafnium ATT&CK group page — [`attack.mitre.org/groups/G0125`](https://attack.mitre.org/groups/G0125/)
- Microsoft Defender for Cloud Apps OAuth detection guidance — [`learn.microsoft.com/defender-cloud-apps`](https://learn.microsoft.com/defender-cloud-apps/)
- GraphRunner for M365 post-exploitation via Graph API — [`github.com/dafthack/GraphRunner`](https://github.com/dafthack/GraphRunner)
- ROADtools Azure AD enumeration — [`github.com/dirkjanm/ROADtools`](https://github.com/dirkjanm/ROADtools)
