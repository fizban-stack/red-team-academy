---
layout: training-page
title: "OT/ICS/SCADA Red Team Overview — Red Team Academy"
module: "OT/ICS Security"
tags:
  - ot
  - ics
  - scada
  - critical-infrastructure
  - red-team
page_key: "ot-ics-overview"
render_with_liquid: false
---

# OT/ICS/SCADA Red Team Overview

Operational Technology (OT) and Industrial Control Systems (ICS) represent a fundamentally different attack surface than traditional IT environments. These systems control physical processes — power generation, water treatment, oil pipelines, manufacturing assembly lines, and chemical plants. A successful attack doesn't just result in data theft; it can cause equipment destruction, environmental catastrophe, and loss of human life.

This module establishes the foundational knowledge required before engaging in any OT/ICS red team activity.

---

## What Is OT/ICS/SCADA?

| Term | Definition | Examples |
|------|------------|---------|
| **OT** | Operational Technology — hardware/software that monitors/controls physical devices | PLCs, RTUs, DCS |
| **ICS** | Industrial Control Systems — umbrella term for all industrial automation systems | SCADA, DCS, PLC networks |
| **SCADA** | Supervisory Control and Data Acquisition — centralized monitoring of distributed field devices | Power grid management, water system control |
| **DCS** | Distributed Control System — process control used in continuous manufacturing | Refineries, chemical plants |
| **PLC** | Programmable Logic Controller — rugged embedded computers executing control logic | Motor control, valve actuation |
| **RTU** | Remote Terminal Unit — field devices reporting to SCADA | Pipeline pressure sensors |
| **HMI** | Human-Machine Interface — operator interface for monitoring/control | Control room screens |

---

## Attack Surface: IT/OT Convergence Zones

The most significant shift in ICS security over the past decade is the collapse of the air gap. Operational networks that were once physically isolated now connect to enterprise IT networks for:

- **Business justification**: Real-time production data feeds into ERP/MES systems (SAP, Oracle)
- **Remote access**: Vendor VPN connections for maintenance and firmware updates
- **Historian servers**: Data collection systems that bridge IT and OT networks
- **Cloud connectivity**: IoT sensors reporting to cloud analytics platforms
- **Patch management**: Centralized WSUS/SCCM servers pushing updates to OT workstations

### DMZ Bypass Paths

A properly designed ICS network places a DMZ between IT and OT with strict unidirectional data flows. In practice, these controls are frequently misconfigured:

```
Internet → Corporate IT → [DMZ] → OT Network
                               ↑
                          Historian (dual-homed)
                          Vendor VPN (direct to PLC)
                          Jump server (poorly segmented)
                          Wi-Fi AP in control room
```

**Common bypass techniques:**

1. **Historian pivot**: Historian servers typically have one NIC on the IT network and one on the OT network. Compromise the historian, gain OT access.
2. **Vendor VPN abuse**: Maintenance vendors often have direct VPN tunnels into OT networks with minimal authentication. Target the vendor first.
3. **Wireless bridges**: Technicians sometimes install unauthorized wireless access points for convenience. Surveying for 802.11 in industrial facilities often yields results.
4. **USB drop**: When true air gaps exist, physical media delivery is the attack vector. Stuxnet used this method.
5. **Supply chain**: Firmware updates from legitimate vendors can be tampered with upstream.

---

## Threat Landscape: Nation-State Actors Targeting Critical Infrastructure

### Volt Typhoon (China)

Active since at least 2021, Volt Typhoon focuses on **pre-positioning** in US critical infrastructure for potential future disruption rather than immediate data theft. Key TTPs:

- Living off the land (LOLBins) — `wmic`, `ntdsutil`, `netsh`, `net`
- Compromising SOHO routers to proxy traffic (Cisco RV320, Netgear ProSAFE)
- Targeting managed service providers with access to multiple OT environments
- Focus sectors: communications, energy, transportation, water
- **Unique concern**: CISA/FBI assess intent is to pre-position for potential destructive attacks during a conflict scenario

```
Volt Typhoon Kill Chain:
External recon (shodan/censys) → VPN/firewall exploitation → LOLBAS persistence
→ Credential harvesting → Lateral movement to OT → Pre-position/wait
```

### Sandworm (Russia/GRU Unit 74455)

The most technically sophisticated ICS threat actor, responsible for the only confirmed electrical grid attacks:

- **2015 Ukraine power outage**: BlackEnergy 3 + KillDisk, 230,000 customers lost power
- **2016 Ukraine power outage**: Industroyer/Crashoverride — first malware designed to directly manipulate ICS protocols (IEC 104, IEC 61850, IEC 61968-4/GOOSE, OPC DA)
- **2017 NotPetya**: Disrupted Maersk, Merck, Mondelez — $10B+ in damages
- **2022 Industroyer2**: Attempted grid attack during Ukraine invasion, caught before deployment

### XENOTIME / TRITON (Attributed to Russia's CNIIHM institute)

- Deployed **TRITON/TRISIS** malware targeting Schneider Electric Triconex Safety Instrumented Systems (SIS)
- Attacked a petrochemical facility in Saudi Arabia (2017)
- **First malware designed to attack safety systems** — could disable emergency shutdown systems
- MITRE ATT&CK ICS: T0858 (Change Operating Mode), T0816 (Device Restart/Shutdown)

### Lazarus Group (North Korea)

- Focus on financial gain through ransomware and cryptocurrency theft from industrial entities
- Have targeted energy companies for destructive capability alongside financial motivation

---

## Red Team Methodology for ICS Engagements

### Phase 1: Passive Reconnaissance

Unlike IT engagements, active scanning in OT environments carries real risk of device disruption. **Always start passive.**

```bash
# Shodan searches for exposed ICS devices
shodan search "port:102 product:S7"          # Siemens S7 PLCs
shodan search "port:502"                      # Modbus TCP
shodan search "port:20000"                    # DNP3
shodan search "port:44818"                    # EtherNet/IP
shodan search "port:4840 OPC-UA"             # OPC-UA servers

# Censys
censys search "services.port:102"

# OSINT for ICS-specific information
# Search job postings for technology stack (Wonderware, Ignition, PI System)
# Review vendor documentation for default configurations
# Search LinkedIn for "SCADA Engineer" at target + certifications listed
```

### Phase 2: Network Discovery (Passive First)

```bash
# Passive network monitoring with Zeek (formerly Bro)
zeek -i eth0 /opt/zeek/share/zeek/policy/protocols/modbus/main.zeek

# NetworkMiner for passive asset discovery
networkminer -r captured_traffic.pcap

# Passive S7 discovery via pcap analysis
tshark -r industrial.pcap -Y s7comm

# Identify ICS protocols in traffic
tshark -r traffic.pcap -Y "modbus or dnp3 or enip or s7comm or opcua or bacnet"
```

### Phase 3: Protocol Analysis

Understand what protocols are in use before attempting any interaction.

```bash
# Zeek with ICS protocol detection
zeek -C -i eth0 OT-ICS

# Capture and analyze with Wireshark
# Filter strings:
# modbus          - Modbus TCP
# s7comm          - Siemens S7
# enip            - EtherNet/IP
# dnp3            - DNP3
# opcua           - OPC-UA
# mms             - IEC 61850 MMS
```

### Phase 4: Active Enumeration (Low-Risk Probes Only)

```bash
# Nmap with ICS NSE scripts - use carefully, some PLCs crash on port scans
nmap -sV -p 102,502,20000,44818,47808,4840 --script=s7-info,modbus-discover,enip-info,dnp3-info <target>

# Use -T2 timing (polite) — never T4/T5 in OT environments
nmap -T2 -sV -p 102,502 <ot_subnet>
```

### Phase 5: Protocol-Level Exploitation

Covered in detail in subsequent modules. The key principle: **understand before you interact, and know your abort conditions.**

### Phase 6: Impact Assessment (Documentation Only)

In authorized engagements, demonstrate impact through:
- Documenting achievable control actions (what could be changed)
- Showing unauthorized read access to process data
- Identifying pivot paths from IT to OT
- **Never** actually executing control commands against live process equipment

---

## Safety Considerations: Why You NEVER Run Exploits on Live Production OT

This cannot be overstated. OT environments are categorically different from IT:

### Physical Consequences of OT Attacks

| Action | Potential Consequence |
|--------|----------------------|
| Writing wrong value to PLC register | Motor overspeed → mechanical failure, fire |
| Disabling safety interlock | Pressure vessel overpressure → explosion |
| Manipulating valve positions | Toxic chemical release, flooding |
| Disabling conveyor safety systems | Worker injury/death |
| Corrupting PLC firmware | Unrecoverable brick, emergency shutdown |
| Injecting false sensor data | Process running outside safe parameters |

### Rules of Engagement for OT Assessments

1. **Written authorization from asset owner AND operations team** — not just IT security
2. **Change freeze window**: Only test during scheduled maintenance windows
3. **Operations coordinator on call**: A qualified engineer must be available to intervene immediately
4. **Documented rollback procedures**: Every test must have a defined abort/restore procedure
5. **No automated scanning tools without explicit approval**: Even nmap can crash embedded controllers
6. **Passive-only by default**: Assume active testing is prohibited unless explicitly permitted
7. **Impact documentation, not demonstration**: Describe what could be done, don't do it

---

## Lab Setup for Safe Practice

### Conpot — ICS Honeypot/Simulator

```bash
# Install Conpot
pip install conpot

# Start with default ICS profile (simulates Siemens S7-200)
sudo conpot --template default

# Available templates: s7-200, guardian-ast, kamstrup_382, 
#                      IEC 104, ipmi, BACnet
```

Conpot exposes simulated Modbus, S7comm, HTTP, SNMP, and other ICS protocols. Safe to attack aggressively.

### OpenPLC — Open Source PLC Runtime

```bash
# Clone OpenPLC Runtime
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3

# Install (Ubuntu)
./install.sh linux

# Start OpenPLC Runtime
./start_openplc.sh
# Web interface: http://localhost:8080
# Default credentials: openplc / openplc
```

OpenPLC supports Modbus TCP, DNP3, and direct PLC programming via ST/Ladder/FBD. Ideal for testing Modbus and DNP3 attack tools.

### ScadaBR — SCADA/HMI Platform

```bash
# ScadaBR runs on Tomcat
# Download from: https://sourceforge.net/projects/scadabr/
# Or use the Docker image:
docker pull scadabr/scadabr
docker run -d -p 8080:8080 --name scadabr scadabr/scadabr
# Access: http://localhost:8080/ScadaBR
# Default: admin / admin
```

### GRFICSv2 — Full ICS Simulation Environment

```bash
# Full GRFICS (Graphics Realism in ICS) simulation environment
# Simulates a chemical process with real HMI and PLC
git clone https://github.com/Fortiphyd/GRFICSv2.git
# Follow Docker Compose setup instructions
# Provides realistic Modbus-controlled process simulation
```

---

## MITRE ATT&CK for ICS Overview

The MITRE ATT&CK for ICS matrix (https://attack.mitre.org/matrices/ics/) covers 12 tactics specific to industrial environments:

| Tactic | ID | Key Techniques |
|--------|----|----------------|
| Initial Access | TA0108 | T0817 Drive-by Compromise, T0819 Exploit Public-Facing Application, T0866 Exploitation of Remote Services |
| Execution | TA0104 | T0807 Command-Line Interface, T0821 Modify Controller Tasking |
| Persistence | TA0110 | T0839 Module Firmware, T0873 Project File Infection |
| Privilege Escalation | TA0111 | T0890 Exploitation for Privilege Escalation |
| Evasion | TA0103 | T0872 Indicator Removal on Host, T0849 Masquerading |
| Discovery | TA0102 | T0840 Network Connection Enumeration, T0888 Remote System Information Discovery |
| Lateral Movement | TA0109 | T0812 Default Credentials, T0859 Valid Accounts |
| Collection | TA0100 | T0802 Automated Collection, T0811 Data from Information Repositories |
| C2 | TA0101 | T0885 Commonly Used Port, T0884 Connection Proxy |
| Inhibit Response | TA0107 | T0800 Activate Firmware Update Mode, T0803 Block Command Message |
| Impair Process Control | TA0106 | T0836 Modify Parameter, T0855 Unauthorized Command Message |
| Impact | TA0105 | T0826 Loss of Availability, T0828 Loss of Productivity and Revenue, T0831 Manipulation of Control |

---

## Key Differences: OT vs IT Pentesting

| Dimension | IT Pentesting | OT/ICS Pentesting |
|-----------|---------------|-------------------|
| **Priority** | CIA: Confidentiality first | AIC: Availability first — downtime costs millions/hour |
| **Patch cadence** | Regular patching expected | Patches may not be applied for years (validation cost) |
| **OS age** | Modern OS common | Windows XP/7/2003 widespread and intentional |
| **System restarts** | Acceptable | May require 8-hour process shutdown procedure |
| **Scanning risk** | Low | Network scans can crash embedded devices |
| **Authentication** | Usually present | Many ICS protocols have zero authentication |
| **Encryption** | Standard | Legacy protocols: zero encryption (Modbus, DNP3 v0) |
| **Availability requirement** | 99.9% typical | 99.999%+ (nuclear, water) |
| **Scope of harm** | Financial, reputational | Physical harm, environmental damage, death |
| **Recovery time** | Hours to days | Weeks to months (custom firmware, hardware lead times) |
| **Testing windows** | Anytime | Scheduled maintenance windows only |

---

## Recommended Resources

- **ICS-CERT Advisories**: https://www.cisa.gov/uscert/ics/advisories
- **Project Basecamp** (Digital Bond): Research on PLC vulnerabilities
- **S4 Conference**: Premier ICS security conference
- **ICS-ISAC**: Information sharing for industrial operators
- **SANS ICS curriculum**: FOR578 (Cyber Threat Intelligence), ICS515
- **Idaho National Laboratory**: CyberCore training programs
- **NIST SP 800-82**: Guide to ICS Security

---

*Next: [ICS Architecture & Network Segmentation](ics-architecture.md)*
