---
layout: training-page
title: "Ransomware Operator Emulation — Red Team Academy"
module: "Scenarios"
tags:
  - scenario
  - ransomware
  - ransomware-emulation
  - lockbit
  - blackcat
  - alphv
  - akira
  - black-basta
  - extortion
page_key: "scenarios-ransomware-operator-emulation"
render_with_liquid: false
---

# Ransomware Operator Emulation

## Scenario Overview

This scenario emulates a modern ransomware-affiliate intrusion against a fictional manufacturing company. The aim is not encryption — destructive impact is out of scope for any sanctioned engagement — but to walk the full kill chain that a real ransomware operator would walk *up to* the encryption-detonation moment, then demonstrate the impact through tabletop conversation and dry-run telemetry rather than action. Customer defenders see the same TTPs they would face from LockBit, ALPHV/BlackCat (defunct mid-2024 but TTPs persist), Akira, Black Basta, RansomHub, and the long tail of affiliate programs that dominated 2023-2025 reporting.

The simulation is structured as an eight-week campaign mapped against the modern affiliate playbook documented in CISA and Mandiant joint advisories. The defender debrief at the end is where the engagement value lives — by structuring the operator's actions to mirror a real affiliate, the customer's SOC and IR teams get a high-fidelity rehearsal of an event they are statistically likely to face for real.

## Why Run This Scenario

Modern ransomware is no longer the bag-of-script-kiddies it was in 2017. Affiliate programs run structured intrusions with months of preparation, named TTPs, and operator-tier OPSEC. The Initial Access Broker (IAB) market means the first foothold often arrives pre-built. The intrusion phase that follows is methodical, observable, and structurally similar across families. A red team engagement that emulates this gives the customer's blue side something they cannot get from a generic adversary-emulation engagement: rehearsal against the threat their executive board actually fears.

## Threat Model — The Modern Affiliate Playbook

Public IR reporting from 2023-2025 converges on a recognizable shape:

| Phase | Typical Source / TTP |
|---|---|
| Initial access | Edge-device n-day (Ivanti / Fortinet / Citrix / Palo / Cisco), AitM phishing harvested by IAB, infostealer-log credential, MFA-fatigue or helpdesk-vishing |
| Foothold | LSASS dump → credential harvest, Cobalt Strike beacon or Sliver beacon, defender disable via BYOVD or PPL bypass |
| Discovery | Active Directory enumeration (SharpHound), file-share inventory (PingCastle, manual SMB enumeration), critical-system mapping (backup servers, ERP, MES) |
| Privilege escalation | ADCS abuse, Kerberoasting, ACL abuse, DCSync once domain admin is reachable |
| Lateral movement | WMI / WinRM / PsExec / SMB-relay, Cobalt Strike's lateral movement primitives |
| Persistence | Multiple — Group Policy modification, scheduled tasks, AnyDesk/TeamViewer-style RMM deployment |
| Defense evasion | EDR disable via BYOVD, Defender exclusions via GPO, log clearing |
| Collection | Network share enumeration, identifying valuable IP, financial data, HR data |
| Exfiltration | Mega.nz / Rclone to attacker-controlled cloud, MEGAsync, double-extortion staging |
| Impact (the moment NOT emulated) | Encryption deployment via GPO or PsExec |
| Extortion | Leak-site publication, victim-portal communications |

Specific affiliate playbooks (LockBit RaaS toolkit leak, Conti playbook leak of 2022, BlackCat affiliate docs surfaced in 2023) provide page-by-page instruction-set documentation. The TTPs are not secret; their operationalization at scale is what affiliates do.

## Target Profile — "PinnacleManu Industries"

Fictional mid-sized US manufacturing firm.

- Industry: precision-machined components for automotive and aerospace
- Headcount: ~1,800 across HQ and three plants
- Crown jewels: ERP system (financial close), CAD drawings (engineering IP), MES (manufacturing execution system) for the plant floor
- Why ransomware-attractive: revenue-per-hour at the plant floor is high, downtime tolerance is hours not days, IT-OT segmentation is fictional-on-paper

### Tech Stack

| Layer | Technology |
|---|---|
| Identity | On-prem Active Directory (2019 functional level), no Entra Connect (still on-prem-only) |
| Endpoints | Windows 10/11 with CrowdStrike Falcon (Insight + Prevent, no OverWatch) |
| Email | M365 E3 — Exchange Online, Defender for Office 365 Plan 1 |
| Network | Palo Alto NGFW, GlobalProtect VPN, Cisco switching, Aruba wireless |
| Plant floor | Windows-based HMIs, Rockwell PLCs, Wonderware historian (the OT-IT bridge that defines blast radius) |
| Backup | Veeam to on-prem repository + offsite replication (the perennial ransomware-affiliate target) |
| ERP | SAP S/4HANA on-prem |
| RMM (already deployed) | ConnectWise Automate (IT-managed; will be subverted in the scenario) |

### Security Maturity

PinnacleManu sits in the middle of the manufacturing-sector maturity distribution. Falcon catches common Mimikatz and obvious lateral movement. The Defender for Office tier is the baseline that catches mass phishing but not targeted AitM. There is no in-house SOC; alerts route to a 24/7 MSSP with a four-hour SLA. AD has standard hygiene gaps (legacy service accounts with SPN-set, unconstrained delegation on one host, no LAPS). Veeam runs on a server that's domain-joined and accessible from any DA-tier identity. Backup-server access protection is the single most valuable control they don't have.

## Engagement Boundaries

This scenario explicitly excludes:
- Actual encryption or destructive action on customer systems
- Real exfiltration of customer data (synthetic data substituted)
- Any action that affects plant-floor production systems
- Persistence that survives the engagement teardown
- Any leak-site or extortion-channel rehearsal that touches public infrastructure

The engagement plan documents specific abort triggers — any real OT-impacting action, any customer-side IR event unrelated to the engagement, any customer business event (acquisition, financial disclosure window) — and the white-cell escalation tree.

## Phase 1 — Initial Access (Day 1-3)

ATT&CK: TA0001. Technique chosen for this engagement: AitM phishing harvested-token reuse from a contractor account.

The operator team purchases-equivalent (engagement-side: customer-plant) an Okta-or-equivalent stolen credential through a customer-side simulation channel. AitM-style session cookie capture is rehearsed against a non-production tenant; the captured cookie is then transferred to the operator browser. First sign-in to the production-equivalent tenant uses the cookie from a region-matched residential proxy.

The engagement explicitly does *not* run live AitM phishing against the production employee population — the customer either pre-plants the credentials in the operator's hands or supplies them via the white-cell handoff. The substance of the exercise is what the operator does *after* the credential is obtained, which is the part that determines defender catch rate.

## Phase 2 — Foothold (Day 3-7)

Beacon delivery via the contractor's existing software bundle — the engagement-pre-arranged loader is wrapped to look like a legitimate ConnectWise Automate update. The Falcon evasion considerations from `/evasion/crowdstrike-tradecraft` apply:

- Custom syscall stubs for sensitive APIs (LSASS handle open, process injection)
- AMSI bypass via hardware breakpoint at process startup
- Sleep obfuscation against memory scanning
- C2 profile mimicking standard ConnectWise Automate telemetry (the cover story matches the host)

Operator discipline at this phase:
- No second action for 48 hours post-beacon
- Beacon interval slow (30s with 35% jitter)
- No tooling on disk
- No LOLBin chains in the first week

This is where mature operators differentiate from script kiddies. The action budget for week one is essentially zero.

## Phase 3 — Discovery (Day 7-14)

SharpHound collection (via execute-assembly through the beacon, not on-disk). The collection is staged in multiple small runs to avoid the burst-of-LDAP-queries signal. PowerView for targeted enumeration. PingCastle is not run (too loud); instead, manual enumeration of specific high-value identities.

What the operator is looking for:
- DA-tier accounts and where they log on (the lsass-credential-harvest target list)
- Veeam backup-server identity and credentials (the ransomware affiliate's killer move)
- AD certificate authority configuration (ADCS template misconfigurations)
- File shares with bulk-share-read permissions (the data-exfiltration target inventory)
- ERP and MES service accounts (downstream-impact identities)
- Critical-system maintenance windows (when can the operator move loudly without notice)

## Phase 4 — Privilege Escalation (Day 14-21)

The path depends on what discovery surfaced. In this scenario, ADCS template `Workstation Authentication` is configured with `ENROLLEE_SUPPLIES_SUBJECT` and accessible to authenticated users — the standard ESC1 condition. The operator requests a certificate with subject = a DA account, authenticates with the certificate, and lands at DA.

The path could equivalently have been Kerberoasting a domain admin service account (if password was crackable), exploiting unconstrained delegation, abusing a misconfigured ACL on a privileged group, or recovering credentials from a SYSVOL Group Policy preference. The point of an emulation scenario isn't the specific ESC-1; it is that the operator is at DA by week 3 through a misconfiguration that the customer's environment had.

## Phase 5 — Lateral Movement to Backup (Day 21-28)

The most consequential lateral movement is to the Veeam backup server. With DA, this is unsanitized — Veeam is domain-joined, DA has admin on the box.

The operator:
1. Identifies the Veeam configuration files and the encryption keys
2. Maps the backup-job inventory (what is being backed up to where)
3. Identifies the offsite-replication destination (typically a separate offsite Veeam instance)
4. Documents the recovery dependencies (which restore paths would the customer use)

A real ransomware affiliate would at this point destroy backups or encrypt the backup destination — neither is emulated here. The engagement output is the documentation that demonstrates the affiliate could have done so.

## Phase 6 — RMM Subversion (Day 28-35)

ConnectWise Automate is the existing RMM on every endpoint. With DA, the operator pivots into the Automate server (a standard pattern — Automate's database holds credentials and the agent can push code to every managed endpoint). The operator demonstrates:

- Reading the Automate database
- Authoring a custom Automate script that would deploy a payload to every managed endpoint
- *Not* deploying the payload — the script is documented and shown to the white cell as evidence

This is the affiliate's "we own the deployment vehicle" moment.

## Phase 7 — Exfiltration Rehearsal (Day 35-42)

Data exfiltration is rehearsed with synthetic data. The operator:

- Maps the high-value file shares
- Stages synthetic-data copies via Rclone (the affiliate-standard tool) to an attacker-controlled cloud bucket
- Documents the volumetric and timing characteristics that the customer's egress controls would have seen

The synthetic-data approach allows defender telemetry to fire at full fidelity (the SOC sees high-volume egress from a contractor identity) without exfiltrating real customer data.

## Phase 8 — Impact Demonstration (Day 42-50)

The encryption phase is NOT executed. Instead, the operator:

1. Documents the specific deployment mechanism that would have detonated encryption (Automate script + GPO + scheduled task)
2. Demonstrates execution of a benign equivalent payload that touches every endpoint (e.g., writes a small marker file and removes it)
3. Captures the SOC's response in real time
4. Hand-off the impact demonstration to a tabletop conversation with the customer's IR leadership

## Defender Debrief

The blue side typically misses or partially-catches the following:

1. **AitM-captured-token reuse** is invisible without device-binding policies
2. **Initial beacon dormancy** beats most behavioral detection windows
3. **SharpHound staged collection** flies under the burst-LDAP detection threshold
4. **ADCS ESC1** is a known misconfiguration class that customers consistently fail to audit
5. **Veeam access from DA** is universal — virtually no customer applies tier-zero separation to backup infrastructure
6. **RMM subversion** depends on the RMM's audit log being weak — most are

The recommendations that come out of this scenario are consistently:
- Tier-zero separation including backup infrastructure
- ADCS template audit (multiple tools exist: Certipy, PSPKIAudit, ADCSScan)
- Veeam backup hardening (immutable repositories, dedicated identity not in main AD)
- RMM admin separation
- Conditional access for privileged Okta auth requiring managed-device
- Tier-1 SOC detection rules on AitM-source IP anomalies

## Cross-References

- `/threat-actors/lockbit`, `/threat-actors/blackcat` — actor-specific TTPs
- `/scenarios/saas-pivot-iaas` — alternate breach pattern
- `/active-directory/adcs-attacks` — the ESC1 specifics referenced in Phase 4
- `/evasion/crowdstrike-tradecraft` — Falcon-specific evasion considerations
- `/reporting/deconfliction-playbook` — engagement comms during a high-stakes ransomware emulation
- `/reporting/post-engagement-debrief` — the structured debrief framework

## Resources

- CISA / FBI / ASD joint advisories on LockBit, ALPHV / BlackCat, Akira, Black Basta, RansomHub
- Mandiant M-Trends annual reports
- CrowdStrike Global Threat Report — ransomware sections
- Conti playbook leak (2022) — primary-source affiliate documentation
- LockBit RaaS toolkit leak (2022) — primary-source affiliate documentation
- Veeam ransomware-readiness guidance
- The No More Ransom project resources
- DFIR Report — ongoing detailed intrusion-case analyses
