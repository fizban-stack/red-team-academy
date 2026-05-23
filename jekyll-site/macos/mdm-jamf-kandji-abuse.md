---
layout: training-page
title: "MDM Abuse — Jamf, Kandji, Mosyle, Intune for Mac — Red Team Academy"
module: "macOS"
tags:
  - macos
  - mdm
  - jamf
  - kandji
  - mosyle
  - intune
  - admin-abuse
page_key: "macos-mdm-jamf-kandji-abuse"
render_with_liquid: false
---

# MDM Abuse — Jamf, Kandji, Mosyle, Intune for Mac

macOS MDM platforms occupy the same architectural position on a Mac fleet that SCCM/MECM occupies on a Windows fleet: a central management plane with the standing capability to execute arbitrary code, push arbitrary configuration, and read arbitrary inventory against every enrolled device. A compromise of the MDM admin role is functionally equivalent to a compromise of every device under management. The security maturity around MDM platforms, however, lags the Windows-side equivalents by a meaningful margin — a gap defenders need to close and operators need to understand.

This page covers the MDM threat model, the abuse paths that flow from a compromised admin position, the defender controls that contain those paths, and the public-reporting incident patterns that have surfaced MDM-adjacent compromise. The framing throughout is defender-aware: mechanisms and telemetry, not operator chains.

## What MDM Can Do — And Why That Is the Threat

The legitimate capability set of an MDM platform is the threat model. Each capability below is required for normal IT operation; each capability is also a primitive an adversary will use given admin-level access.

| Capability | Legitimate use | Adversary primitive |
|---|---|---|
| Push scripts (root or user context) | Run software install, drift remediation | Arbitrary code execution |
| Push configuration profiles | Enforce settings, push certificates | Grant TCC entitlements, install trust roots |
| Deploy packages (`.pkg`) | Install enterprise software | Deploy implant |
| Push enterprise apps | Distribute internally-developed software | Distribute attacker-developed app |
| Push managed credentials (Wi-Fi, VPN, 802.1X) | Onboarding | Redirect traffic to attacker infrastructure |
| Push SCEP / PKI enrollment | Issue device certs | Enroll attacker certs to a managed identity |
| Remote wipe | Lost-device response | Destructive action against fleet |
| Inventory queries | Asset management | Pre-attack reconnaissance over the fleet |
| Self Service catalog | User-initiated app install | Distribute trojaned package the user runs voluntarily |
| Lock / passcode reset | Helpdesk function | Coerce user, force re-authentication into attacker-controlled flow |
| Activation Lock bypass code retrieval | Recover company device | Bypass a control that would otherwise brick a stolen device |

The point of the table: there is no "exploit" required. MDM admin compromise is the exploit. Every adversary capability above is an authorized use of the platform.

## Jamf Pro

Jamf Pro is the dominant enterprise MDM in tech-sector Mac fleets. It exists as a cloud-hosted (`*.jamfcloud.com`) or self-hosted JSS (Jamf Software Server) deployment. Devices speak to the JSS over HTTPS; commands are delivered through Apple's APNs.

### Architecture

- **JSS** — the central server. Cloud-hosted or self-hosted on-prem.
- **APNs channel** — Apple-mediated push for MDM commands.
- **`jamf` binary on the device** — the agent that pulls policy and runs scripts on schedule or on-demand.
- **Self Service.app** — the user-facing portal for opt-in installs.
- **Inventory database** — every device's hardware, software, configuration, and assignment state.

### Admin Model

Jamf Pro distinguishes between standard accounts and the privileged accounts that can push scripts and policies. Account roles include site-scoped admins, full admins, API-only accounts, and LDAP/SSO-federated identities. The role granularity is good on paper; in practice many Jamf deployments collapse role separation under operational pressure and end up with a handful of "everything" admins.

### Policy vs Configuration Profile

Two distinct artifact types that operators and defenders must keep straight.

- **Policy** — scoped action: run a script, install a package, restart, lock, etc. Triggered on schedule or by check-in.
- **Configuration profile** — declarative settings document (Apple's `.mobileconfig` format). Grants entitlements, installs certificates, configures Wi-Fi/VPN, sets restrictions.

The threat-modeling relevance: a malicious policy is loud (scripts get logged, packages get inventoried). A malicious configuration profile can grant TCC permissions silently because MDM-pushed profiles bypass the user-consent dialog by design.

### Scripts in Jamf

Scripts live in the Jamf script library, are scoped to smart groups or static groups, and execute as root by default. There is no per-device approval gate in default deployments — once scoped, the script runs on next check-in.

### Common Admin-Side Weaknesses

The patterns defenders should treat as MDM-admin-security smells:

- Shared admin credentials in a password manager team vault, no individual attribution
- TOTP-only MFA on Jamf admin login (no FIDO2)
- JSS direct network reachability from corporate VPN with no IP allow-list
- Admin SSO federated to the same identity provider that issues user identity (no admin-tier IdP separation)
- API tokens with long lifetime and broad scope checked into developer machines
- LDAP-bound admin accounts that inherit nested group membership the Jamf admin team doesn't know about

### Public Jamf Abuse Research

Research from Stuart Ashenbrenner (Huntress / Lares), Andy Grant (NCC Group), Calum Hall, and others has covered Jamf-specific abuse paths at high level — abuse of the admin API for command execution, configuration-profile-based TCC grants, and the relationship between a compromised endpoint and the Jamf binary's local capabilities. The research is mechanism-focused and oriented to helping defenders understand what to instrument.

### Local Jamf Binary on the Endpoint

The `jamf` binary on each enrolled device is a privileged process that fetches policy and runs scripts as root. Its on-disk presence and the local databases it maintains (in `/Library/Application Support/JAMF/` and related paths) are also a forensic surface: defenders investigating a suspected MDM-pushed compromise can pull the local Jamf logs (`/var/log/jamf.log`) to reconstruct what policies fired and when. Operators should expect this log to exist and to be collected during incident response.

## Kandji

Kandji is the newer, Apple-platform-only MDM. Cloud-only — there is no self-hosted Kandji. Architecturally cleaner than Jamf in many respects, with a stronger emphasis on out-of-box compliance.

### Architecture and Admin Model

Single-tenant cloud per customer. Admin console is a web app; admins federate via SAML SSO. The Kandji agent on-device pulls blueprint policies.

### Custom Apps and Scripts

Kandji's equivalent of Jamf policies and packages. Custom Apps deploy `.pkg` or `.zip` to devices; Custom Scripts run shell scripts on schedule or on-demand. Both run as root.

### Auto Apps

Kandji-maintained catalog of common applications with automatic updates. The threat-model surface here is Kandji-side rather than customer-side — a Kandji catalog compromise would be a supply-chain-style impact across customers. Defender-side, treat Auto App version pinning the same way you treat any auto-updating software in a managed fleet.

### Liftoff

Kandji's zero-touch enrollment flow integrated with Apple Business Manager. The threat model parallels Jamf's PreStage Enrollment: compromise of the ABM or Kandji admin who controls Liftoff allows the adversary to define what runs on a device at first-boot before the user ever logs in.

### Self Service Considerations

Kandji's Self Service catalog is the same threat-model shape as Jamf's: anything an admin can put in it, a user will run voluntarily. Catalog content is a moderate-trust pathway, not a high-trust one, from the defender's perspective.

### Defender Controls — Kandji-Specific

- Mandatory FIDO2 on Kandji admin SAML
- IP allow-list on the admin console
- Audit log streaming via the Kandji API to SIEM
- Separation of Liftoff admin from day-to-day blueprint admin
- Blueprint change-review workflow — blueprint diffs reviewed before publish, the same way infrastructure-as-code diffs are reviewed before apply
- API token scoping with short TTL and per-purpose tokens rather than long-lived global tokens

## Mosyle

Mosyle Business / Mosyle Fuse / Mosyle Manager are the three product tiers. Cloud-hosted; common in SMB and mid-market Mac fleets and in education (Mosyle Manager). Script execution model and policy push follow the same MDM-primitive shape as Jamf and Kandji.

### Threat-Model Notes

- Mosyle's MDM admin compromise has the same blast radius as any other MDM
- Fuse bundles an EDR-style capability (Mosyle Hardening & Compliance / EDR & Threat Hunting) — an admin who can disable Mosyle's own protection is at a meaningful capability tier
- Education-tier deployments (Mosyle Manager) frequently inherit weaker admin controls than enterprise deployments
- API token model is similar to Jamf and Kandji — long-lived tokens with broad scope are a recurring weakness in customer deployments
- SMB and mid-market deployments often skip the FIDO2 admin requirement that larger enterprises enforce

## Microsoft Intune for Mac

Intune sits inside Microsoft Entra (formerly Azure AD) and the Microsoft 365 admin estate. The Mac MDM capability is a feature of the broader Intune product. This produces a threat-model wrinkle that operators on the Windows side already know and operators new to Mac frequently miss.

### Cross-Platform Admin Surface

One Intune admin role manages Windows endpoints, Mac endpoints, iOS endpoints, and Android endpoints. The same person with the same credentials, in many M365 tenancies, can push a configuration profile to Macs and a Group Policy preference to Windows.

### The Entra-Admin-to-Mac-RCE Pivot

The defender-relevant consequence: an Entra admin compromise — phished MFA, session-token theft, OAuth consent abuse — that the SOC may be modeling as a Windows or cloud incident is, in fact, also a Mac incident because that admin can push scripts and packages to every Intune-enrolled Mac. Mac SOC teams and Windows SOC teams need to be talking to each other; in many enterprises they are not.

### Conditional Access Integration

Intune integrates with Entra Conditional Access — device compliance posture (Mac included) gates access to apps. A compromised MDM that flips a non-compliant device to compliant is also a Conditional Access bypass. This is the bidirectional risk: MDM-compromise enables Conditional-Access bypass; Conditional-Access-bypass enables MDM-admin authentication.

## Common Abuse Paths — Defender Frame

The classes of abuse defenders should be instrumenting for, regardless of which MDM platform is in play.

### MDM Admin Compromise → Push to Enrolled Devices

The canonical case. Adversary obtains MDM admin credentials (phishing, infostealer in a developer's browser, weak MFA, helpdesk social engineering for password reset). The admin then has the standing authority to deploy a payload to every enrolled device. Detection has to happen at the admin-action layer, not at the device layer — by the time the device sees the payload, the action is authorized.

### MDM Server Compromise (Self-Hosted Jamf)

A self-hosted JSS is a network asset like any other. Patching lag, exposed admin interfaces, weak service-account passwords on the underlying database, lack of network segmentation. Public reporting has covered cases where the JSS server itself was the initial pivot point.

### Stolen MDM Enrollment Profile

The MDM enrollment profile contains the trust anchor that binds a device to the MDM. An enrollment profile lifted from a real device (or extracted from an MDM admin's machine, or pulled from a build server that bakes enrollment into a device image) can be used to enroll an attacker-controlled device into the fleet. The attacker device then receives the same configuration, certificates, and Wi-Fi/VPN credentials any legitimate device receives.

### VPP Token Abuse

Apple's Volume Purchase Program token (now part of Apps and Books in ABM) authorizes the MDM to assign paid apps to devices. A stolen VPP token in some configurations allows an adversary MDM to assign apps under the victim organization's licensing — a billing-fraud and traffic-attribution issue more than a device-compromise issue, but worth modeling.

### Apple Business Manager Device Rebind

ABM is the Apple-side directory of devices owned by the organization. Devices in ABM auto-enroll into the MDM at first-boot. An adversary with ABM admin can re-assign a device to a different MDM instance under their control. This is the "device shows up enrolled to attacker" scenario — and it bypasses every protection the legitimate MDM was providing.

### Self Service Catalog Poisoning

The Self Service catalog is admin-curated. A compromised admin who replaces a legitimate package with a trojaned one is using the user's trust in IT against the user. The user opens Self Service, clicks the familiar tile, and installs the payload voluntarily — a path with very low EDR-detection profile because the user-driven launch looks legitimate.

### Cross-Platform Pivot via Shared Admin Identity

In environments where Intune is the MDM and Entra is the identity provider, a single admin identity covers Windows, Mac, and mobile. Compromise of that identity is a cross-platform compromise. Defender modeling that treats Mac MDM as separate from the M365 admin estate misses this — the platforms share a single privileged-access surface.

## MDM Platform Comparison — Defender View

A side-by-side of the management plane controls that matter most to defenders. Capabilities listed reflect current product tiers and may shift with vendor roadmap.

| Property | Jamf Pro | Kandji | Mosyle | Intune for Mac |
|---|---|---|---|---|
| Hosting model | Cloud or self-hosted | Cloud-only | Cloud-only | Cloud (Entra) |
| Native admin MFA | Configurable | SAML SSO | Configurable | Entra Conditional Access |
| FIDO2 admin login | Via federated IdP | Via federated IdP | Via federated IdP | Yes (Entra-native) |
| Audit log API | Yes | Yes | Yes | Yes (Entra audit log) |
| Granular admin scopes | Site-scoped admins | Blueprint scopes | Role-based | Scope tags |
| Cross-platform admin | Mac only | Apple-only | Apple-only | Windows + Mac + mobile |
| EDR coupling | Jamf Protect (add-on) | Endpoint Detections | Fuse bundled | Defender for Endpoint |

The comparison is not a ranking. Each platform has a defensible deployment if the controls are configured. The point is that the controls are not on by default in any of them — a Mac fleet running an MDM out-of-the-box is not, by virtue of running an MDM, protected against MDM admin compromise.

## Real-World Incident Patterns in Public Reporting

References here are kept to threat-actor patterns and mechanisms rather than chains.

- **Scattered Spider / Octo Tempest (UNC3944)** — public reporting from Mandiant, Microsoft Threat Intelligence, and others has covered this actor's heavy use of helpdesk social engineering to reset MFA on privileged accounts, including in MDM-relevant tenant contexts. The takeaway for defenders: helpdesk MFA-reset workflows are a recurring MDM-adjacent compromise vector.
- **Engineering-team-targeted MDM compromise** — multiple public incidents through 2023-2025 referenced compromise of management infrastructure used to administer developer endpoints. Mac-fleet MDMs are increasingly modeled as Tier-0 by mature security teams in tech-sector firms.
- **Supply-chain-style impacts** — MDM platforms have themselves been the subject of supply-chain-style concerns (compromise of a platform vendor, or a vendor employee with customer access). Public reporting in this category is sparse and usually retracted-or-redacted; defenders should track vendor security disclosures and SOC2/ISO27001 attestations as part of MDM vendor due diligence.

Recommended public sources: Mandiant M-Trends annual reports, Microsoft Threat Intelligence blog (Octo Tempest coverage), CrowdStrike Global Threat Report, Huntress / Stuart Ashenbrenner Jamf research, Patrick Wardle / Objective-See platform coverage.

## Defender Controls

The controls that materially reduce MDM-compromise risk. None of these are theoretical — all are implementable in current product tiers of the major MDMs.

### Identity and Authentication

- **FIDO2 strongly recommended on all MDM admin authentication.** Phishing-resistant MFA is the single highest-leverage control. TOTP-only is no longer adequate.
- **Admin-tier identity separation from corporate identity.** Privileged Identity Management (Entra), separate IdP for admin accounts, or at minimum separate admin-only accounts with no email or routine application access.
- **Conditional Access on the MDM admin console.** Restrict admin login to known-IP, known-device, recent-MFA.
- **Helpdesk MFA-reset hardening.** No phone-only MFA reset for privileged accounts. Identity-proofing workflow required.

### Authorization and Workflow

- **Admin role minimization.** Jamf site-scoped admins, Kandji blueprint-scoped admins, Intune scope tags. Day-to-day operators should not have global script-push authority.
- **Change-control workflow on script and configuration profile creation.** "MDM does not deploy code without a ticket." Out-of-process script creation is a detection signal in itself.
- **Per-device or per-group approval for high-risk actions.** Remote wipe, configuration profile install on executive devices, package push to engineering devices.

### Monitoring and Audit

- **Audit log streaming to SIEM.** Every major MDM exposes an audit log API. Streaming it to the same SIEM that ingests endpoint and identity logs lets the SOC correlate admin actions with downstream effects.
- **Detection signals to alert on:**
  - New policy / configuration profile creation outside of change-control window
  - Script execution rate anomalies (sudden spike in scripts pushed)
  - New admin account creation
  - Admin login from new IP or new device
  - ABM device rebinding events
  - VPP token rotation outside the normal cycle
  - Self Service catalog modification

### Architecture and Segmentation

- **ABM admin separation from MDM admin.** Two different roles, two different people, two different authentication paths. The ABM admin can rebind devices; the MDM admin can push payloads. Splitting these capabilities reduces single-account blast radius.
- **Bastion-host MDM admin model.** MDM admin work happens from a hardened workstation, not from a personal laptop. The bastion is the only origin allowed in the admin Conditional Access policy.
- **MDM in a Tier-0 access tier.** Treat MDM platforms with the same protections as Active Directory domain controllers and Entra global admin: privileged access workstations, just-in-time elevation, comprehensive logging.

### Detection Engineering Notes

- **Audit log latency matters.** Some MDM audit APIs lag the actual admin action by minutes to hours. Detection rule design must account for this — alerting on the audit-log event rather than the device-side downstream event allows earlier intervention.
- **Endpoint-side correlation.** The Mac device-side telemetry of an MDM-pushed payload includes `mdmclient` events in Unified Log, configuration profile install events, and (for scripts) the same `ES_EVENT_TYPE_NOTIFY_EXEC` events that any other process produces. The forensic story is reconstructable; the SOC needs the rules to surface it.
- **Correlation across MDM and identity.** The strongest detection posture correlates the MDM audit log with the identity provider's sign-in log. An MDM admin action whose preceding identity sign-in was from an unusual IP, used legacy auth, or completed an MFA challenge that itself looks suspicious (push-bombing pattern, sudden travel) is a stronger signal than either log alone.
- **Baseline what "normal" looks like.** For each MDM admin, the SOC should have a baseline of typical action volume, typical action type, and typical time-of-day. Sudden deviation is the most accessible signal in a low-signal environment.

## Defensive Architecture Patterns

Patterns to argue for when designing or hardening a Mac fleet's management plane.

- **"MDM does not deploy code without a ticket" as a hard policy.** Out-of-band script execution generates an incident, not a question.
- **Separate MDM admin identity from corporate identity admin identity.** Whoever owns Entra global admin should not also own Intune admin. Whoever owns the Jamf admin role should not also be a domain admin.
- **Audit log retention measured in years, not weeks.** MDM compromise is frequently retrospective — discovered months after the action. Short retention defeats the investigation.
- **Configuration baseline review.** Quarterly fleet-wide review of installed configuration profiles, identifying drift from the approved baseline. Profiles that shouldn't exist are a primary signal.
- **MDM-platform vendor security review.** Same diligence as any critical SaaS vendor: SOC2 Type II, breach notification clauses, customer-side audit log access, sub-processor list.

## How MDM Compromise Lands on the Endpoint

A short note on what the device-side picture looks like, so defenders building Mac detection content know what to instrument. None of this is operator chain detail — it is the forensic shape of an MDM-pushed compromise after the fact.

- **Configuration profile install** — surfaces in `profiles list`, in `/Library/Managed Preferences/`, and in Unified Log under `com.apple.ManagedClient`. PPPC profiles in particular show up as TCC entitlement grants without the user-prompt that a locally-installed profile would produce.
- **Script execution via the MDM agent** — runs as root, typically with the parent process being the agent (`jamf`, `kandji-agent`, `mosyleagent`, `IntuneMdmAgent`). Process-creation telemetry from Endpoint Security framework captures the parent-child relationship cleanly.
- **Package install** — produces `installer` invocations and writes to `/var/db/receipts/`. Receipts are a durable artifact and a useful timeline anchor in incident response.
- **MDM command audit** — Apple maintains a device-side MDM command log that pairs with the server-side audit log. Forensic acquisition can pull both sides to reconstruct the command sequence.

## Engagement Considerations

For red teams and the clients who scope them.

- **MDM is high-blast-radius. Scope must be explicit.** "MDM admin compromise in scope" and "MDM admin compromise out of scope" must be a written, signed decision before the engagement starts.
- **Test environment vs production MDM.** If the client has a Jamf or Kandji test tenant, scoping the engagement against the test environment lets the operator demonstrate the threat model without the production blast radius. Many clients do not have a test environment; engagement plan must address this.
- **Recovery if MDM admin is compromised during the engagement.** Procedural step the engagement plan should pre-define: what happens, who calls whom, how the platform is rolled back. The "what if Forge accidentally pushes a payload to 12,000 devices" scenario is not theoretical — it has happened in unrelated incidents, and is what every legal and platform-trust team will ask about.
- **Apple Business Manager scope.** ABM is a separate admin surface from the MDM. If ABM is in scope, surface it explicitly. ABM compromise outside the engagement scope is a contractual and legal problem.
- **Personal Apple ID exposure.** Some Mac fleets allow personal Apple ID on corporate devices. Operator activity that surfaces in a user's personal iCloud (Find My notifications, etc.) is a privacy and engagement-conduct issue. Engagement plan must address.

## Cross-References

- `/macos/persistence-catalog` — what an MDM-pushed persistence artifact looks like on disk
- `/macos/gatekeeper-xprotect` — how MDM-installed binaries interact with first-launch evaluation
- `/macos/tcc-bypass` — how MDM-pushed PPPC profiles grant TCC entitlements
- `/macos/sip-bypass` — what SIP protects regardless of MDM authority
- `/active-directory/sccm-attacks` — sibling Windows topic, same threat-model frame
- `/active-directory/azure-ad` — Entra-side context for Intune integration
- `/post-exploitation/macos-red-team` — operator post-ex broader content

## Resources

- Apple Platform Security Guide — MDM and Apple Business Manager chapters
- Jamf Pro security documentation and Jamf Threat Labs research blog
- Kandji security documentation and engineering blog
- Mosyle security documentation
- Microsoft Intune for macOS official documentation (learn.microsoft.com)
- Patrick Wardle / Objective-See — macOS platform security research
- Stuart Ashenbrenner (Huntress / Lares) — Jamf-specific research
- Andy Grant (NCC Group) — Mac MDM research
- Calum Hall — macOS management plane research
- Mandiant M-Trends annual reports (Scattered Spider / UNC3944 coverage)
- Microsoft Threat Intelligence blog — Octo Tempest coverage
- CrowdStrike Global Threat Report — macOS and management-plane sections
- Objective-See Annual Mac Malware Report
- SpecterOps and TrustedSec public blogs — MDM and management-plane topics
