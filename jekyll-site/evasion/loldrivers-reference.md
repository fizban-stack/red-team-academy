---
layout: training-page
title: "LOLDrivers Reference — Red Team Academy"
module: "Evasion"
tags:
  - byovd
  - loldrivers
  - kernel
  - drivers
  - edr-evasion
  - detection
page_key: "evasion-loldrivers-reference"
render_with_liquid: false
---

# LOLDrivers Reference

## What LOLDrivers Is

[LOLDrivers](https://loldrivers.io) (Living Off The Land Drivers) is the authoritative open-source catalog of vulnerable and malicious Windows kernel drivers. It's the LOLBAS of the kernel layer — a practitioner-maintained database that tracks every publicly known driver that can be abused for privilege escalation, EDR termination, arbitrary memory access, or code execution.

**Current database scale (as of May 2026):**

| Metric | Count |
|---|---|
| Total driver entries | 623 |
| Total driver samples (hashes) | 2,133 |
| Vulnerable drivers | 511 |
| Malicious drivers | 112 |
| Unique SHA256 hashes | 1,924+ |
| Drivers bypassing HVCI | 465 (21.8% of samples) |
| Drivers NOT yet on Microsoft blocklist | 730 (34.2% of samples) |
| Cross-signed by third-party CAs | ~81% of all samples |

The database is continuously updated. Sigma, Sysmon, YARA, ClamAV, and WDAC detection artifacts are generated from the YAML source and published alongside each update.

## Database Categories

### Vulnerable Drivers (511 entries)

Legitimate, signed drivers from hardware vendors, OEMs, and software companies that contain exploitable vulnerabilities. These are drivers that:
- Were never intended to be malicious
- Are signed by trusted entities (passes Driver Signature Enforcement)
- Contain IOCTLs or bugs that allow user-mode code to gain kernel-level access

**Why they're useful:** Because they're legitimately signed, they bypass DSE and load without kernel credential requirements. Defenders can't just block "unsigned drivers" to stop BYOVD.

### Malicious Drivers (112 entries)

Kernel drivers specifically created or modified by threat actors for attack operations. Unlike vulnerable drivers, these were deliberately weaponized. Examples include:

- **POORTRY** — malicious driver family tracked by Mandiant and Sophos, signed with stolen/fraudulent WHQL certificates. Used to terminate EDR and AV processes.
- **Daxin** — rootkit drivers used in APT campaign (Symantec, 2022). Files: `daxin_blank5.sys`, `wantd_2.sys`, `ntbios.sys`, `wantd_5.sys`. Sophisticated state-sponsored backdoor with kernel-level stealth.
- **RedDriver** — undocumented malicious driver tracked by Cisco Talos. Multiple variants used for traffic interception.
- **hlpdrv.sys** — Akira ransomware driver, disables Windows Defender by modifying registry settings at the kernel level.
- **burntcigar.sys** — PoorTry variant tracked by Sophos. Multiple driver hashes, used to terminate security processes.

## Driver Capability Matrix

Organized by what the driver allows you to do from user-mode:

### Physical Memory Read/Write

The most versatile capability — arbitrary physical memory access enables: reading any process's memory (including LSASS), writing to kernel structures, removing EDR callbacks, stealing tokens.

| Driver | Vendor | CVE | SHA256 (first 32 chars) |
|---|---|---|---|
| `RTCore64.sys` | MSI Afterburner | CVE-2019-16098 | `01aa278b07b58dc46c84723e8b...` |
| `dbutil_2_3.sys` | Dell BIOS Utility | CVE-2021-21551 | `0296e2ce999e67c76352613a71...` |
| `iqvw64e.sys` | Intel Ethernet Diagnostics | CVE-2015-2291 | `4429f32db1cc705679195ee...` |
| `gdrv.sys` | Gigabyte App Center | CVE-2018-19320 through 19323 | `31f4cfb4c71da4412075...` |
| `LnvMSRIO.sys` | Lenovo Process Management (pre-installed) | CVE-2025-8061 | varies — no DACL, any user can open `\\.\WinMsrDev` |
| `WinRing0x64.sys` | OpenHardwareMonitor / EVGA / Corsair iCUE / NZXT CAM | CVE-2020-14979 | varies |
| `HpPortIox64.sys` | HP OMEN Gaming Hub | CVE-2021-3437 | `c5050a2017490fff7aa5...` |
| `AsrOmgDrv.sys` | ASRock RGB utility | N/A | `950a4c0c772021cee260...` |
| `atillk64.sys` | ATI GPU utility | N/A | varies |

**CVE-2019-16098 (RTCore64.sys — MSI Afterburner):** Allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. The most widely weaponized BYOVD driver — BlackByte ransomware, EDRSandblast, and dozens of other tools use it.

**CVE-2021-21551 (dbutil_2_3.sys — Dell):** Five separate vulnerabilities in Dell's BIOS update utility driver. Affected hundreds of millions of Dell computers. Exploits allow arbitrary kernel memory read/write. Used by Lazarus Group.

**CVE-2015-2291 (iqvw64e.sys — Intel):** Intel Ethernet diagnostics driver, allows local denial-of-service and physical memory mapping. Used by Scattered Spider (UNC3944) in BYOVD attacks.

**CVE-2018-19320 through 19323 (gdrv.sys — Gigabyte):** Multiple CVEs enabling physical memory R/W, I/O port R/W, MSR R/W, and ring0 memcpy-equivalent. Affected GIGABYTE APP Center ≤v1.05.21, AORUS GRAPHICS ENGINE ≤v1.33, XTREME GAMING ENGINE ≤v1.25, OC GURU II ≤v2.08. Used by RobbinHood ransomware.

### Process Termination (EDR/AV Kill)

Drivers that can terminate PPL-protected processes from kernel mode — bypassing tamper protection.

| Driver | Vendor/Source | CVE | Notes |
|---|---|---|---|
| `zam64.sys` / `zamguard64.sys` | Zemana Anti-Logger | N/A | Used by Terminator/SpyBoy EDR killer, sold for $3,000 on dark forums |
| `PROCEXP152.sys` | Sysinternals Process Explorer (Microsoft-signed) | N/A | Used by AuKill (BlackCat/ALPHV affiliates) — legitimately signed by Microsoft |
| `STProcessMonitor.sys` | Safetica | CVE-2025-70795 | Disable security tools / EDR kill |
| `K7RKScan.sys` | K7 Computing AV | CVE-2025-52915 | Process termination → EDR kill |
| `viragt64.sys` | VirIT antivirus | N/A | Used by Kasseika ransomware (2024) — EDR bypass before encryption |
| `BdApiUtil64.sys` | Baidu AntiVirus | CVE-2024-51324 | EDR kill |
| `probmon.sys` | Unknown vendor | N/A | Categorized as EDR Kill in LOLDrivers |
| `BootRepair.sys` | BootRepair | N/A | Unauthenticated IOCTL handler for arbitrary process kill including PPL |
| `mhyprot2.sys` | miHoYo Genshin Impact anti-cheat | N/A | ZwTerminateProcess from ring 0 — widely abused due to game's popularity |

### Direct Kernel Code Execution

| Driver | Notes |
|---|---|
| `capcom.sys` | Capcom game company. Contains a function that disables SMEP and calls a user-supplied function pointer. Most direct BYOVD — gives you a kernel-mode function call. On Microsoft blocklist. |
| `smep_capcom.sys` | Variant of capcom.sys |

### MSR Read/Write

Machine Specific Registers control processor features. MSR access enables: disabling kernel protections, reading security-sensitive CPU state.

- `RTCore64.sys` — MSR R/W alongside physical memory R/W
- `gdrv.sys` — MSR R/W alongside physical memory R/W
- `WinRing0x64.sys` — MSR, port I/O, and physical memory R/W
- `atillk64.sys` — MSR access

### Code Integrity Tampering

| Driver | Notes |
|---|---|
| `termdd.sys` | Microsoft Windows Operating System — documented code integrity tampering capability |
| `vsdatant.sys` | ZoneAlarm — BYOVD kernel privilege escalation/defense evasion |

### 2025 Zero-Days (New)

| Driver | Vendor | CVEs | Notes |
|---|---|---|---|
| `BioNTdrv.sys` | Paragon Partition Manager | CVE-2025-0289 through CVE-2025-0293 | Five vulnerabilities, one exploited as zero-day by ransomware gangs. Versions 1.3.0 and 1.5.1 affected. Privilege escalation to SYSTEM. Active exploitation confirmed 2025. |

## Threat Actor Driver Usage

Documented real-world BYOVD by threat actors:

| Threat Actor | Driver Used | Effect | Source |
|---|---|---|---|
| Lazarus Group (DPRK) | `dbutil_2_3.sys` | Kernel memory R/W for payload delivery | SentinelOne Labs |
| Lazarus Group (DPRK) | `AFD.sys` (Windows built-in, CVE-2024-38193) | FUDModule rootkit — disabled CrowdStrike, Defender, AhnLab V3, HitmanPro | Gen Digital |
| BlackByte ransomware | `RTCore64.sys` | EDR bypass, kernel callbacks removed | Sophos |
| RobbinHood ransomware | `gdrv.sys` | Kernel memory R/W, EDR bypass | |
| Scattered Spider (UNC3944) | `iqvw64e.sys` | BYOVD for detection avoidance | CrowdStrike |
| BlackCat/ALPHV (AuKill) | `PROCEXP152.sys` | Kill EDR/AV processes | Mandiant |
| RansomHub / 7 affiliate groups (EDRKillShifter) | `RentDrv2`, `ThreatFireMonitor` | Shared EDR killer used by BlackSuit, Medusa, Qilin, DragonForce, Crytox, Lynx, INC Ransom | Help Net Security / Arete IR |
| Terminator/SpyBoy (sold) | `zam64.sys` | Kill 24+ EDR/AV products | CrowdStrike |
| Kasseika ransomware (2024) | `viragt64.sys` (VirIT antivirus) | EDR bypass before encryption | Trend Micro |
| Silver Fox APT | vulnerable drivers (unspecified) | Disable EDR before deploying ValleyRAT backdoor | Check Point Research |
| Akira ransomware | `hlpdrv.sys` | Disable Windows Defender via registry | GuidePoint Security |
| APT (state-sponsored) | `daxin_blank5.sys` + variants | Deep rootkit stealth | Symantec |
| Unknown (HiddenGh0st RAT, 2025) | `truesight.sys` (~2,500 hash variants) | EDR bypass — 2,500 PE-modified variants generated to evade blocklist | The Hacker News |
| Multiple ransomware (2025) | `BioNTdrv.sys` | Zero-day privilege escalation | Paragon/Bleeping Computer |

### POORTRY Driver Family

Mandiant-tracked malicious driver family. POORTRY drivers are signed with fraudulent Windows Hardware Quality Labs (WHQL) certificates obtained via Microsoft's signing portal through fake developer accounts. Multiple variants tracked:

- `POORTRY1.sys`, `POORTRY2.sys` — Mandiant classification
- `burntcigar.sys` — Sophos classification
- Multiple `driver_XXXXXXXX.sys` — hash-identified variants without filenames

Used by BlackCat/ALPHV, Cl0p, Cuba, and Hive ransomware affiliates to terminate security products before deploying ransomware.

## Using the LOLDrivers API

The database is queryable as JSON:

```bash
# Full driver database
curl -s https://www.loldrivers.io/api/drivers.json | jq 'length'
# → 623

# List all vulnerable drivers
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq '[.[] | select(.Category == "vulnerable driver")] | length'
# → 511

# Get all SHA256 hashes for vulnerable drivers
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq -r '.[] | select(.Category == "vulnerable driver") | .KnownVulnerableSamples[].SHA256 // empty'

# Find a specific driver by filename tag
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq '.[] | select(.Tags[] | ascii_downcase | contains("rtcore64"))'

# Get all entries with Commands documented
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq '[.[] | select(.Commands != null and .Commands != {})] | length'

# Get drivers with resources referencing specific threat actors
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq '.[] | select(.Resources[] | contains("crowdstrike") or contains("mandiant"))' | \
  jq -r '.Tags[]'
```

### PowerShell API Query

```powershell
# Fetch and query the LOLDrivers database from PowerShell
$db = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json"

# Count by category
$db | Group-Object Category | Select Name, Count

# Find all vulnerable driver SHA256 hashes
$vuln_hashes = $db | 
    Where-Object { $_.Category -eq "vulnerable driver" } |
    ForEach-Object { $_.KnownVulnerableSamples.SHA256 } |
    Where-Object { $_ }

Write-Host "Vulnerable driver hashes: $($vuln_hashes.Count)"

# Find drivers by filename
$db | Where-Object { $_.Tags -contains "RTCore64.sys" }

# Get all malicious driver entries
$malicious = $db | Where-Object { $_.Category -eq "malicious" }
```

## Detection Integration

LOLDrivers publishes ready-to-use detection rules across multiple platforms. All are auto-generated from the YAML database and updated with each new entry.

### Sigma Rules

Six Sigma rules covering driver loads by hash and by filename:

```
github.com/magicsword-io/LOLDrivers/tree/main/detections/sigma/

driver_load_win_vuln_drivers.yml         — hash-based detection, vulnerable drivers
driver_load_win_vuln_drivers_names.yml   — filename-based detection, vulnerable drivers
driver_load_win_vuln_drivers_hvci_load.yml — drivers that load despite HVCI

driver_load_win_mal_drivers.yml          — hash-based detection, malicious drivers
driver_load_win_mal_drivers_names.yml    — filename-based detection, malicious drivers
driver_load_win_mal_drivers_hvci_load.yml — malicious drivers loading despite HVCI
```

MITRE ATT&CK tags: `T1068` (Exploitation for Privilege Escalation), `T1543.003` (Create or Modify System Process: Windows Service).

Log source: `windows/driver_load` — requires Sysmon Event ID 6 or equivalent.

Example Sigma rule structure:

```yaml
title: Vulnerable Driver Load
logsource:
    product: windows
    category: driver_load
detection:
    selection:
        Hashes|contains:
            - 'MD5=3ecd3ca61ffc54b0d93f8b19161b83da'
            - 'SHA256=0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5'
            # ... 1,000s more entries
    condition: selection
```

### Sysmon Integration

Twelve Sysmon XML configs for DriverLoad event monitoring (Event ID 6):

```
detections/sysmon/sysmon_config_vulnerable_hashes.xml       — detect vulnerable driver loads
detections/sysmon/sysmon_config_vulnerable_hashes_block.xml — block vulnerable driver loads
detections/sysmon/sysmon_config_malicious_hashes.xml        — detect malicious driver loads
detections/sysmon/sysmon_config_malicious_hashes_block.xml  — block malicious driver loads
detections/sysmon/sysmon_config_*_hvci_*                    — HVCI-bypass specific configs
```

Deploy the block config to prevent loading of known-bad drivers:

```xml
<!-- From sysmon_config_vulnerable_hashes_block.xml -->
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="Vulnerable Driver Load" groupRelation="or">
            <DriverLoad onmatch="include">
                <Hashes condition="contains">MD5=3ecd3ca61ffc54b0d93f8b19161b83da</Hashes>
                <!-- ... thousands more MD5/SHA256 hashes ... -->
            </DriverLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

### Hash Lists

Pre-generated hash lists for integration with any security tool:

```
detections/hashes/samples_vulnerable.md5    — all MD5 hashes, vulnerable drivers
detections/hashes/samples_vulnerable.sha256 — all SHA256 hashes, vulnerable drivers
detections/hashes/samples_malicious.sha256  — all SHA256 hashes, malicious drivers
detections/hashes/samples_vulnerable.imphash — import hash list

# HVCI-specific (drivers that bypass HVCI):
detections/hashes/LoadsDespiteHVCI.samples_vulnerable.sha256
detections/hashes/LoadsDespiteHVCI.samples_malicious.sha256
```

Import into EDR allowlist/denylist, firewall, or application control:

```bash
# Download vulnerable driver SHA256 list
curl -s https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_vulnerable.sha256 > loldrivers-vulnerable.sha256

# Count hashes
wc -l loldrivers-vulnerable.sha256

# Check if a specific hash is in the database
HASH="0296e2ce999e67c763526..."
grep -i "$HASH" loldrivers-vulnerable.sha256 && echo "FOUND — vulnerable driver"
```

### WDAC Policy

Windows Defender Application Control (WDAC) policy blocking known vulnerable/malicious drivers:

```
detections/wdac/
```

Deploy to prevent kernel from loading cataloged drivers at boot time. Maintained by Florian Stosse and HotCakeX.

### ClamAV Signatures

```
detections/av/LOLDrivers.hdb
```

ClamAV hash database for integration with ClamAV-based scanning pipelines.

## PowerShell LOLDriver Scanner

Community-built PowerShell scanner to check a Windows system for known-bad drivers. Created by [@Oddvarmoe](https://twitter.com/Oddvarmoe), [@M_haggis](https://twitter.com/M_haggis), and [IISResetMe](https://twitter.com/IISResetMe):

```powershell
# Script: https://gist.github.com/IISResetMe/1a8353ae57710868b31b0e8d41683b95
# Scans system directories for drivers matching the LOLDrivers hash database

# Recommended scan directories:
# C:\WINDOWS\inf
# C:\WINDOWS\System32\drivers
# C:\WINDOWS\System32\DriverStore\FileRepository

# Quick one-liner to pull and run (review script before running)
$script = (Invoke-WebRequest -Uri "https://gist.github.com/IISResetMe/1a8353ae57710868b31b0e8d41683b95/raw").Content
# Review $script, then:
# Invoke-Expression $script
```

Use this defensively to check if any enrolled endpoint has known-vulnerable drivers present before a BYOVD attack occurs.

## HVCI and the Microsoft Blocklist

### Hypervisor-Protected Code Integrity (HVCI)

HVCI uses the hypervisor to enforce that only properly signed code runs in kernel mode. When enabled, HVCI prevents loading drivers not meeting signing requirements — and prevents kernel memory modification that would be needed for many BYOVD techniques.

```powershell
# Check HVCI status on a system
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, HypervisorEnforcedCodeIntegrityStatus

# Status codes:
# VirtualizationBasedSecurityStatus: 0=disabled, 1=enabled/not running, 2=running
# HypervisorEnforcedCodeIntegrityStatus: 0=disabled, 1=enabled/not running, 2=running

# Check via registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" |
    Select-Object EnableVirtualizationBasedSecurity, HypervisorEnforcedCodeIntegrity
```

**Critical point for red teams:** HVCI is NOT enabled by default on most enterprise Windows systems. Only enforced when:
- HVCI is explicitly enabled (Surface devices have it by default, most enterprise desktops don't)
- Smart App Control is enabled (consumer feature)
- Windows is in S mode

Check before assuming HVCI is a blocker — most corporate targets will not have it enabled.

### Microsoft Vulnerable Driver Blocklist

Microsoft maintains a WDAC blocklist of known-bad drivers. Location on disk:

```
C:\Windows\System32\CodeIntegrity\driversipolicy.p7b
```

```powershell
# Check if the blocklist is enforced
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName MSFT_VSPolicy

# The blocklist is enforced ONLY when:
# - HVCI is active (VBS + HVCI enabled)
# - Smart App Control is on
# - System is in S mode

# Without HVCI, the blocklist is a reference document, not an enforcement mechanism
```

The LOLDrivers `LoadsDespiteHVCI` hash files specifically track drivers that bypass even HVCI-enforced systems — the most severe class for hardened environments.

### Finding Drivers NOT on the Blocklist

For red team operations against hardened environments (HVCI enabled), you need drivers not in the Microsoft blocklist:

```bash
# Download Microsoft's blocklist (raw policy binary — binary format, hard to parse)
# The LOLDrivers project tracks HVCI-bypass drivers separately:
# detections/hashes/LoadsDespiteHVCI.samples_vulnerable.sha256

# Query LOLDrivers API for entries verified against HVCI
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq '.[] | select(.Verified == "TRUE") | .Tags[]' | head -20

# Cross-reference with KDU supported providers to find operational choices
# KDU (github.com/hfiref0x/KDU) lists 40+ supported providers with HVCI notes
```

## Operational Driver Selection

Quick reference for selecting the right driver based on your objective:

| Objective | Recommended Driver | Reason |
|---|---|---|
| EDR callback removal | `RTCore64.sys` | Arbitrary phys mem R/W; EDRSandblast uses it |
| PPL process termination | `zam64.sys` or `PROCEXP152.sys` | Process kill IOCTLs |
| DSE bypass → load unsigned driver | `RTCore64.sys` + KDU | Physical mem write to ci.dll |
| Kernel code execution | `capcom.sys` | Direct exec, but blocklisted — testing only |
| Low-noise (less signatured) | Use KDU to find less-known providers | Rotate away from RTCore64/dbutil |
| HVCI-enabled target | Check `LoadsDespiteHVCI` hashes in LOLDrivers | Specific drivers bypass HVCI |

## Integration with Red Team Tools

```bash
# KDU — uses LOLDrivers-cataloged vulnerable drivers as providers
# github.com/hfiref0x/KDU

kdu.exe -list          # Lists 40+ supported provider drivers with capabilities
kdu.exe -dse 0         # Disable DSE using default provider (iqvw64e.sys)
kdu.exe -prv 9 -dse 0  # Use specific provider by index number
kdu.exe -map evil.sys  # Map unsigned driver after DSE disable

# EDRSandblast — uses RTCore64.sys
# Automated kernel callback removal
EDRSandblast.exe --kernelmode  # Requires RTCore64.sys in current directory

# Check if target has a vulnerable driver already installed
# (no need to drop a new one — use what's already there)
Get-WmiObject Win32_SystemDriver | Where-Object {
    $_.PathName -match "rtcore|gdrv|iqvw|dbutil|winring|hpport"
}
```

## Resources

| Resource | URL |
|---|---|
| LOLDrivers Website | `loldrivers.io` |
| LOLDrivers GitHub | `github.com/magicsword-io/LOLDrivers` |
| LOLDrivers API | `loldrivers.io/api/drivers.json` |
| Driver submission tool | `loldrivers.streamlit.app` |
| KDU (40+ provider support) | `github.com/hfiref0x/KDU` |
| EDRSandblast | `github.com/wavestone-cdt/EDRSandblast` |
| BYOVD techniques | `/evasion/byovd/` |
| physmem_drivers collection | `github.com/namazso/physmem_drivers` |
