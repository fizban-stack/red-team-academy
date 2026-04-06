---
layout: training-page
title: "Default Credentials Reference — Red Team Academy"
module: "Red Team Tools"
tags:
  - default-credentials
  - passwords
  - initial-access
  - databases
  - network-devices
  - web-applications
  - iot
page_key: "tools-default-credentials"
render_with_liquid: false
---

# Default Credentials Reference

Default and commonly-used credentials for databases, web applications, network devices, cloud infrastructure, IoT, and monitoring tools. Always attempt defaults during initial access testing before password spraying or brute force.

## Databases

```
Service              User            Password(s)
------------------------------------------------------------
PostgreSQL           postgres        postgres / password / admin / (empty)
MySQL / MariaDB      root            (empty) / root / mysql / password / toor
                     mysql           mysql
MongoDB              admin           (empty) / admin / password
                     Note: Often runs with --noauth by default
Redis                (no user)       (empty) / redis / password
                     Note: No authentication by default pre-6.x
MSSQL                sa              (empty) / sa / Password1 / P@ssw0rd / Admin123
Oracle               sys             change_on_install / oracle
                     system          manager / oracle
                     scott           tiger
                     dbsnmp          dbsnmp
Cassandra            cassandra       cassandra
CouchDB              admin           (empty) / admin / password
Elasticsearch        elastic         changeme / elastic
```

## Web Applications & CMS

```
Service              User            Password(s)
------------------------------------------------------------
WordPress            admin           admin / password / 123456
Joomla               admin           admin / password
Drupal               admin           admin / password
Magento              admin           admin123 / password123
phpMyAdmin           root            (empty) / root / admin / password
                     admin           admin / password
Jenkins              admin           admin / password / jenkins
GitLab               root            5iveL!fe
                     Note: Modern versions require setup during install
Grafana              admin           admin
Apache Tomcat        admin           admin / tomcat / s3cret / password
                     tomcat          tomcat / s3cret
                     manager         manager
JBoss / WildFly      admin           admin / jboss
WebLogic             weblogic        weblogic / welcome1 / password
                     admin           password / Password1
                     system          password
IBM WebSphere        websphere       websphere / password
                     admin           admin / password
ActiveMQ             admin           admin
RabbitMQ             guest           guest
                     Note: Only accessible from localhost by default
```

## Network Devices

```
Device               User            Password(s)
------------------------------------------------------------
Cisco IOS / NX-OS    admin           admin / cisco / password / 12345 / (empty)
                     cisco           cisco
                     enable          cisco / (empty)
Juniper              root            (empty) / abc123
                     admin           netscreen / abc123
HP / HPE Switches    admin           admin / (empty)
                     manager         (empty)
Dell iDRAC           root            calvin
Fortinet FortiGate   admin           (empty) / admin
Palo Alto            admin           admin
Ubiquiti             ubnt            ubnt
MikroTik             admin           (empty) / admin
Netgear              admin           password / 1234
TP-Link              admin           admin
```

## Cloud & Virtualization

```
Platform             User                           Password(s)
------------------------------------------------------------
VMware ESXi          root                           vmware / (empty) / password
VMware vCenter       administrator@vsphere.local    (set during install)
Proxmox              root                           (set during install)
Docker Registry      admin                          admin
```

## IoT & Embedded Systems

```
Device               User            Password(s)
------------------------------------------------------------
IP Cameras (Generic) admin           admin / 12345 / password / (empty)
                     root            admin / 12345 / password
Hikvision            admin           12345 / admin
Dahua                admin           admin / (empty)
                     888888          888888
Raspberry Pi         pi              raspberry
```

## Monitoring & Management

```
Service              User            Password(s)
------------------------------------------------------------
Nagios               nagiosadmin     nagios / admin
Zabbix               Admin           zabbix
                     Note: Username is case-sensitive
Splunk               admin           changeme / admin
ELK / Kibana         elastic         changeme
Grafana              admin           admin
```

## Operating Systems

```
OS                   User            Password(s)
------------------------------------------------------------
Linux (Generic)      root            toor / root / password / admin
                     admin           admin / password
Ubuntu / Debian      ubuntu          (SSH key) / ubuntu
                     debian          (SSH key) / debian
Windows              Administrator   Admin / Password1 / P@ssw0rd / admin123
                     Admin           admin / password
```

## Common Default Password Patterns

```
# Top default passwords to try first
(empty)         # No password
admin           # Most common default
password        # Second most common
12345           # Numeric defaults
123456
1234567
12345678
123456789
root            # Linux/Unix devices
toor            # Reverse of root (Kali)
pass
default
guest
changeme
Password1       # Meets complexity requirements
P@ssw0rd        # Complexity-compliant
Admin123
Welcome1
letmein
qwerty

# Pattern-based passwords to construct
<company-name>          # e.g., "acmecorp"
<company-name>2024       # e.g., "acmecorp2024"
<service-name>          # e.g., "mysql", "postgres"
<service-name>123
<hostname>
<hostname>123
Summer2024 / Winter2024  # Seasonal rotation
{service}@{year}         # e.g., "jenkins@2024"
```

## Testing Commands

```
# SSH default credential spray
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
nxc ssh 10.10.10.0/24 -u admin -p admin

# Web application login spray
hydra -L users.txt -P passes.txt http-post-form "//login:user=^USER^&pass=^PASS^:Invalid"

# Database default creds
mysql -h 10.10.10.10 -u root -p                    # (try empty, root, mysql)
psql -h 10.10.10.10 -U postgres -W                 # (try postgres, empty)
mssqlclient.py sa@10.10.10.10                       # (try empty, sa, Password1)

# NetExec spray across network
nxc smb 10.10.10.0/24 -u administrator -p 'Password1' --continue-on-success
nxc ssh 10.10.10.0/24 -u root -p '' --continue-on-success  # Empty password

# Shodan search for default-credential exposed services
# site:shodan.io search: "default password" product:Jenkins
# or use: shodan search --fields ip_str,port "default_credentials: true"
```

## Key Tools

```
Hydra       — github.com/vanhauser-thc/thc-hydra        — Online brute force
Medusa      — github.com/jmk-foofus/medusa              — Parallel login cracker
NetExec     — github.com/Pennyw0rth/NetExec              — Network-aware SMB/SSH/MSSQL spray
CrackMapExec — github.com/byt3bl33d3r/CrackMapExec      — AD credential spray
Patator     — github.com/lanjelot/patator                — Multi-protocol login tester
changeme    — github.com/ztgrace/changeme                — Default credential scanner
```

## Resources

- Default Credentials Cheatsheet — `github.com/ihebski/DefaultCreds-cheat-sheet`
- CIRT Default Passwords DB — `cirt.net/passwords`
- datarecovery.com Default Passwords — `datarecovery.com/rd/default-passwords/`
- Pentest Cheatsheets — `github.com/Kitsun3Sec/Pentest-Cheat-Sheets`
