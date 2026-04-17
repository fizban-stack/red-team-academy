---
layout: training-page
title: "Sandworm ICS/OT Emulation — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - sandworm
  - gru
  - russia
  - ics-ot
  - industroyer
  - critical-infrastructure
  - destructive
page_key: "threat-actors-sandworm"
render_with_liquid: false
---

# Sandworm ICS/OT Emulation

**CRITICAL SAFETY WARNING:** This page covers ICS/OT offensive techniques for educational purposes. **Never execute these techniques against production ICS, OT, or safety systems under any circumstances.** Attacks on ICS can cause physical damage, injury, environmental harm, and loss of life. All emulation exercises involving ICS must use isolated lab environments with air-gapped replica systems.

Sandworm (GRU Unit 74455) is the most destructive nation-state cyber actor in history. They are responsible for the only confirmed attacks that caused physical disruption of electric power grids, the most financially damaging cyberattack ever (NotPetya), and sophisticated attacks on industrial control systems governing critical infrastructure.

## Attribution

| Attribute | Detail |
|---|---|
| Nation-state | Russian Federation |
| Organization | GRU Unit 74455 (Main Centre for Special Technologies / GTsST) |
| MITRE Group ID | G0034 |
| Common aliases | Sandworm, BlackEnergy Group, Voodoo Bear, IRIDIUM (Microsoft), TeleBots |
| Active since | ~2009 |
| Distinction from APT28 | Unit 74455 vs Unit 26165 — destructive missions vs espionage |
| OFAC designation | Sanctioned by US Treasury (2020) — 6 GRU officers named |

## Historical Attacks: Establishing Context

### Ukraine Power Grid Attacks (2015, 2016)

**December 2015:** First confirmed cyberattack to cause power outage
- 230,000 customers lost power in western Ukraine
- BlackEnergy malware used for initial IT access
- KillDisk wiper deployed to cover tracks and hamper recovery
- Operators manually opened breakers via SCADA after disabling protective relays
- Recovery: ~6 hours (utilities had manual override capability)

**December 2016:** More sophisticated — Industroyer/CRASHOVERRIDE
- Targeted Pivnichna substation, Kyiv
- Automated attack via Industroyer — no manual operator needed
- Industroyer protocol modules: IEC 104, IEC 61850, IEC 101, GOOSE messaging
- 75 minutes of power outage in Kyiv
- Deployed to 40+ breakers automatically

### NotPetya (2017) — Most Destructive Cyberattack in History

NotPetya was disguised as ransomware but designed purely for destruction — it had no recovery mechanism. Deployed via trojanized Ukrainian accounting software (MeDoc), it spread globally via EternalBlue + Mimikatz credential theft.

**Financial damage:** ~$10 billion globally
- Maersk (shipping): $300M
- FedEx/TNT: $400M
- Merck (pharmaceutical): $870M
- Mondelez: $188M
- Total: largest cyber insurance payout in history

**NotPetya technical chain:**
```
MeDoc update server compromise → trojanized MeDoc → installed on Ukrainian companies
  → EternalBlue (SMBv1 exploit) for network spread
  → Mimikatz for credential harvesting
  → WMIC/PsExec for lateral movement
  → MBR overwrite + MFT encryption → permanent data destruction (no key)
```

### Industroyer2 (April 2022, Ukraine)

During the Russian invasion of Ukraine, Sandworm deployed Industroyer2 against the Ukrainian national grid operator Ukrenergo:
- Targeted IEC 61850 protocol (standard for substation automation)
- Hardcoded substation-specific IP addresses (intelligence-driven targeting)
- Designed to simultaneously trip multiple high-voltage circuit breakers
- Paired with CaddyWiper (disk wiper) to destroy IT systems concurrently
- Attack was detected and partially mitigated by CERT-UA before full execution

## ICS/OT Targeting Methodology

Sandworm (and sophisticated OT attackers generally) follows a two-phase approach:

```
Phase 1: IT Compromise (standard enterprise attack)
  ├── Initial access via spearphishing or internet-facing vulnerabilities
  ├── Lateral movement through IT network
  ├── Credential theft and privilege escalation
  └── Establish persistence in IT environment

Phase 2: IT-to-OT Pivot (specialized knowledge required)
  ├── Identify data historian (OSIsoft PI, AspenTech IP.21, Honeywell PHD)
  │   ↑ Historians bridge IT and OT networks — critical pivot point
  ├── Enumerate OT network from historian (which PLCs/RTUs connect to it)
  ├── Access Engineering Workstation (EWS) — has ICS software installed
  ├── Reconnaissance of HMI and SCADA server
  ├── Understand the physical process (to cause maximum impact)
  └── Deploy ICS-specific payload (Industroyer, TRITON, PIPEDREAM)
```

### The Historian as IT/OT Bridge

```
IT Network                          OT Network (air-gapped or firewalled)
  |                                    |
  |   OSIsoft PI Server               |   Field devices: PLCs, RTUs, IEDs
  |   (Data Historian)  ←── reads ─── |   Speaks: Modbus, DNP3, IEC 104
  |   ↑                               |   Sends: sensor data (temperature,
  |   |                               |   pressure, flow, voltage, current)
  |   |__ accessible from IT          |
  |       via PI Web API              |

Attack path: IT → historian → OT network segment
  The historian must reach OT devices to collect data.
  An attacker on the historian can reach OT devices.
```

## Industroyer/CRASHOVERRIDE Technical Analysis

Industroyer is a modular malware framework specifically designed to attack industrial control systems. It contains protocol-specific attack modules:

### Architecture

```
Industroyer Core
├── Backdoor (main C2 channel — HTTPS over Tor)
├── Launcher (coordinates timing of attack modules)
├── Data Wiper (KillDisk — destroys after attack)
└── Protocol Attack Modules:
    ├── IEC 60870-5-104 Module (power grid SCADA protocol)
    ├── IEC 60870-5-101 Module (serial link variant)
    ├── IEC 61850 Module (substation automation — Industroyer2)
    ├── GOOSE Module (Generic Object Oriented Substation Events)
    └── OPC DA Module (Windows-based ICS data access)
```

### Industroyer2: IEC 61850 Protocol Attack

Industroyer2 (2022) used the IEC 61850 standard — the modern protocol for digital substation automation — to send unauthorized commands to circuit breakers:

```python
# IEC 61850 attack concept — educational reference for understanding the protocol
# IEC 61850 uses MMS (Manufacturing Message Specification) for control commands
# Real Industroyer2 had HARDCODED IED addresses from pre-attack reconnaissance

# Library: python-iec61850 or libiec61850 (C library with Python bindings)
# pip install python-iec61850

# EDUCATIONAL DEMONSTRATION — DO NOT USE AGAINST ANY REAL SYSTEM

def industroyer2_concept():
    """
    Industroyer2 targeted Intelligent Electronic Devices (IEDs) 
    controlling high-voltage circuit breakers at specific Ukrainian substations.
    
    The attack:
    1. Connected to each hardcoded IED IP address
    2. Used IEC 61850 ACSI services (MMS) to read current state
    3. Sent 'Open' commands to circuit breakers in rapid sequence
    4. Multiple substations hit simultaneously = cascade failure
    
    Why IEC 61850:
    - Modern substations use IEC 61850 for digital protection relay communication
    - Protocol has no authentication in most deployments
    - Commands accepted from any device on the substation LAN
    - Designed for speed (millisecond response times), not security
    """
    
    # Industroyer2 binary contained hardcoded data like:
    HARDCODED_IED_CONFIG = [
        {"ip": "10.10.50.100", "ied_name": "AA1J101", "logical_node": "CSWI1"},
        {"ip": "10.10.50.101", "ied_name": "AA1J102", "logical_node": "CSWI1"},
        # ... 40+ hardcoded IED addresses from prior reconnaissance
    ]
    
    # Each IED "CSWI" (Circuit Breaker Controller) node has:
    # - Pos (Position): OPEN or CLOSED
    # - Oper (Operate): command to open/close
    print("IEC 61850 attack would send 'Open' command to CSWI1.Pos.Oper")
    print("This opens the circuit breaker, disconnecting the power line")
```

### IEC 104 Attack Module (2016 Industroyer)

The original Industroyer used IEC 60870-5-104 (IEC 104), an older SCADA protocol for remote terminal unit (RTU) communication over TCP/IP:

```python
# IEC 104 protocol educational overview
# IEC 104 is used for communication between SCADA servers and RTUs/IEDs
# Port: 2404/TCP
# Key commands:
#   - STARTDT (Start Data Transfer)
#   - ASDU Type 45: Single Command (C_SC_NA_1) — for binary on/off
#   - ASDU Type 46: Double Command (C_DC_NA_1) — more complex state

# The 2016 Industroyer IEC 104 module:
# 1. Scanned for devices listening on 2404/TCP
# 2. Sent STARTDT to initiate communication
# 3. Iterated through Information Object Addresses (IOAs) — each corresponds
#    to a different control point (breaker, disconnect switch, etc.)
# 4. Sent C_SC_NA_1 (Single Command) with state=OFF to each IOA
# 5. Affected: Pivnichna substation, Kyiv

# Detection: Unexpected IEC 104 traffic (port 2404) from IT network segments
# ICS/OT monitoring: Claroty, Dragos, Nozomi Networks, Fortinet OT Security
```

## Tools Used by Sandworm

### KillDisk / CADDYWIPER
Used to destroy evidence and prevent recovery after the primary attack:

```c
// KillDisk/CADDYWIPER concept — MBR overwrite (educational)
// T0829 — Loss of View + Loss of Control via system destruction
// NEVER execute this — educational only

// CaddyWiper (2022) logic:
// 1. If not domain controller: destroy MBR and first N bytes of each disk
// 2. If domain controller: wait (DC destruction would alert defenders too early)
// 3. Overwrite with zeros — no key, no recovery

// Detection: process writing to \\\\.\\PhysicalDrive0 outside of imaging tools
// Monitor: raw disk access from non-system processes
```

### WHISPERGATE (January 2022, Ukraine — attributed)

Deployed days before Russian invasion, WHISPERGATE combined:
- Fake ransomware note (but no decryption key — purely destructive)
- MBR overwriter (Stage 1)
- File corruptor for hundreds of extensions (Stage 2)
- Delivery via compromised Ukrainian government websites (watering hole)

## MITRE ATT&CK for ICS

Standard enterprise ATT&CK covers IT techniques. **ATT&CK for ICS** (attack.mitre.org/matrices/ics/) covers OT-specific techniques:

| ICS Technique | ID | Sandworm Use |
|---|---|---|
| Spearphishing Attachment | T0865 | Initial IT access |
| Remote Services | T0886 | Access engineering workstations |
| Modify Program | T0889 | Alter PLC ladder logic (TRITON concept) |
| Manipulation of Control | T0831 | Industroyer sending open/close commands |
| Device Restart/Shutdown | T0816 | Forcing RTU/IED restart |
| Loss of Safety | T0837 | TRITON targeting safety instrumented system |
| Denial of Control | T0813 | KillDisk destroying HMI, SCADA servers |
| Unauthorized Command Message | T0855 | Rogue IEC 104/IEC 61850 commands |
| Supply Chain Compromise | T0862 | MeDoc (NotPetya delivery) |
| Rootkit | T0851 | BlackEnergy rootkit persistence |
| Program Download | T0843 | Uploading modified PLC programs |

## OT Kill Chain: IT to Physical Impact

```
STAGE 1: IT Compromise
  T1566 — Spearphishing: weaponized Office document to engineering staff
  T1059.001 — PowerShell: download IRONGATE/BlackEnergy dropper
  Persistence: scheduled task, registry key on engineering workstations

STAGE 2: IT Network Recon
  T1082 — System discovery: identify historian, HMI, SCADA servers
  T1016 — Network discovery: map OT-accessible network segments
  T1003 — Credential access: Mimikatz to get historian service accounts

STAGE 3: Historian Pivot
  T1078 — Use historian service credentials to authenticate
  T1021.002 — SMB lateral movement to historian server
  OT network reachable from historian: identify IED IP ranges

STAGE 4: OT Reconnaissance
  Protocol scan: identify IEC 104 (port 2404), IEC 61850, DNP3 (port 20000)
  Enumerate IEDs: connect, query logical nodes, map to physical devices
  Understand process: which breakers control which lines
  Develop attack payload: hardcode target IPs and IOAs

STAGE 5: Pre-Positioning
  Deploy Industroyer/attack modules on EWS or SCADA server
  Stage KillDisk/CADDYWIPER for post-attack IT destruction
  Configure timing: attack executes at scheduled time (Friday night)

STAGE 6: Impact Execution
  Industroyer simultaneously opens all targeted circuit breakers
  KillDisk simultaneously destroys ICS HMI, SCADA, historian
  Operators cannot view system state (HMI destroyed)
  Cannot close breakers remotely (SCADA destroyed)
  Must physically restore: walk to each substation

STAGE 7: Cover Tracks
  KillDisk destroys Windows event logs
  Overwrites attacker tools and malware with random data
  Attempt to make attribution difficult
```

## Lab Setup for Safe ICS Emulation

**Required infrastructure for any ICS/OT emulation exercise:**

```
Isolated Lab Network (NO connections to production ICS or internet):

Engineering Workstation (EWS)
  └── ICS software: OpenPLC, SCADA-LTS, OpenSCADA, or vendor-provided demo
  └── Connects to simulated PLCs/RTUs

Simulated PLC/IED
  └── OpenPLC (openplcproject.com) — free, open-source PLC simulator
  └── ScadaBR — open-source SCADA/HMI
  └── Configured with training ladder logic (NOT production programs)

Traffic generation
  └── Simulate normal ICS traffic: ModbusPal, GNS3 with ICS modules
  └── Verify monitoring tools see "normal" before introducing attack

Monitoring
  └── Nozomi Guardian or Dragos Platform (trial licenses for lab)
  └── Wireshark capture of all ICS protocol traffic
  └── SIEM ingesting ICS events for detection engineering

ISOLATION REQUIREMENT:
  - Air gap: no physical connection to production OT networks
  - VLAN separation is insufficient for sensitive exercises
  - Use dedicated physical hardware or nested hypervisor
```

## Emulation Without Real ICS: IT-Phase Emulation

For organizations without ICS lab infrastructure, emulate the IT-phase of Sandworm's kill chain:

```powershell
# IT-phase Sandworm emulation (safe — no ICS involved)
# Focus: How Sandworm accesses OT from IT through the historian

# 1. Initial access simulation: assume phishing succeeded, have beacon on EWS
#    (Beacon = Cobalt Strike or Sliver running on the engineering workstation role)

# 2. Discover historian from the EWS
Resolve-DnsName historian.corp.example.com
Test-NetConnection -ComputerName historian -Port 443   # PI Web API port
Test-NetConnection -ComputerName historian -Port 5450  # PI Classic port

# 3. Attempt to access PI Web API (historians often have no auth in legacy deployments)
Invoke-RestMethod "http://historian:443/piwebapi/elements" -UseDefaultCredentials

# 4. Enumerate OT-accessible hosts from historian network
# (Test connectivity to OT segment from historian's network position)
$otsegment = "10.10.50"
1..254 | ForEach-Object {
    if (Test-Connection "$otsegment.$_" -Count 1 -Quiet -TimeoutSeconds 1) {
        Write-Host "Host alive: $otsegment.$_"
    }
}

# 5. Detect ICS protocols (port scan for ICS ports — in lab only)
# Port 2404: IEC 60870-5-104
# Port 102:  IEC 61850 MMS
# Port 20000: DNP3
# Port 502:  Modbus TCP
# Port 4840: OPC-UA
```

## Emulation Considerations and Ethics

| Consideration | Guidance |
|---|---|
| Target environment | ONLY isolated lab with replica/simulated ICS |
| Permission scope | Must explicitly include ICS/OT in rules of engagement |
| Safety review | Licensed ICS security professional must review before execution |
| Scope of impact | Never test techniques that could affect safety-critical systems |
| Recovery plan | Full backup of all ICS software/configs before any exercise |
| Deconfliction | Ensure no production systems on the lab network |
| Reporting | ICS-focused finding require different remediation than IT findings |

**REMINDER: Actual Sandworm-level attacks on ICS are complex, require months of reconnaissance, and specific ICS protocol expertise. This page provides educational context, not a deployment guide.**

## Detection Engineering Focus for ICS Defenders

```
1. Historian access from unusual sources (IT workstations not normally accessing it)
2. New connections to historian PI Web API from unexpected IP addresses
3. Outbound connections from historian to OT IP ranges (not normal historian behavior)
4. Engineering workstation running new processes (especially network tools)
5. ICS protocol traffic (Modbus, IEC 104, DNP3) from IT network segments
6. Authentication failures on SCADA server from non-OT sources
7. Mass file write activity on HMI or SCADA server (wiper precursor)
8. New services or scheduled tasks created on OT systems
```

## References

- MITRE ATT&CK G0034 (Sandworm): attack.mitre.org/groups/G0034/
- MITRE ATT&CK for ICS: attack.mitre.org/matrices/ics/
- CISA Advisory AA22-110A (Industroyer2): cisa.gov
- ESET Industroyer/CRASHOVERRIDE analysis (2016 original)
- ESET Industroyer2 analysis (2022): welivesecurity.com
- Dragos CRASHOVERRIDE analysis (2017)
- US-CERT TA17-293A (BlackEnergy)
- Ukraine CERT-UA advisories: cert.gov.ua
- ICS-CERT advisories: ics-cert.cisa.gov
- SANS ICS curricula: sans.org/industrial-control-systems-security/
- OpenPLC runtime (for lab setup): openplcproject.com
- S4 Conference ICS security research: s4xevents.com
